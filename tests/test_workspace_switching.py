# SPDX-License-Identifier: AGPL-3.0-only
"""Workspace selection rotates the authority context instead of copying local roles."""

import json
import re
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, timedelta
from uuid import UUID, uuid4

import pytest
from console_api_fixtures import API, ORIGIN, console_client, console_config
from fastapi.testclient import TestClient
from sqlalchemy import text
from test_console_api_step_up import stale
from test_execution import registry as registry
from test_execution import world as world
from test_protected_path import connector as connector
from test_protected_path import live_provider as live_provider
from test_runtime import runtime as runtime
from test_workspace_accounts import adopt, enroll, second_membership
from test_workspace_waiting import statements as statements

from execbound import mfa, workspaces
from execbound.access_control import capabilities
from execbound.app import create_app
from execbound.envelope import KeyRing
from execbound.passwords import sign_in_with_password
from execbound.resolution.models import SystemClock
from execbound.surfaces.sessions import SessionError, issue_session, load_session

pytestmark = pytest.mark.integration


def member_pair(db, engine, seeded):
    tenant = seeded["tenants"][0]
    principal, _ = enroll(engine, tenant, kind="ADMIN")
    account = adopt(db, tenant, principal)
    other = second_membership(engine, seeded, account)
    with engine.begin() as conn:
        conn.execute(
            text("INSERT INTO execbound.access_principals(tenant_id,principal_id) VALUES(:t,:p)"),
            {"t": seeded["tenants"][1], "p": other},
        )
        conn.execute(
            text(
                "INSERT INTO execbound.access_role_grants(tenant_id,grant_id,principal_id,role) "
                "VALUES(:t,:g,:p,'viewer')"
            ),
            {"t": seeded["tenants"][1], "p": other, "g": uuid4()},
        )
    grant = issue_session(
        db, sign_in_with_password(db, "member@example.test", "a retained example passphrase")
    )
    return grant, load_session(db, grant.token), account, other


def test_switch_to_viewer_does_not_carry_administrator_role_or_old_session(
    db, admin_engine, seeded
):
    grant, current, _, other = member_pair(db, admin_engine, seeded)
    switched = workspaces.switch_workspace(db, current, grant.account_token, seeded["tenants"][1])
    assert switched.csrf_token != grant.csrf_token
    assert switched.session_id != grant.session_id
    selected = load_session(db, switched.token)
    assert selected.identity.principal_id == other
    with db.transaction(seeded["tenants"][1]) as conn:
        access = capabilities(conn, selected.identity.tenant_id, other)
        assert access["roles"] == ["viewer"]
        assert "access.manage" not in access["permissions"]
        assert "approvals.decide" not in access["permissions"]
    with pytest.raises(SessionError):
        load_session(db, grant.token)


def test_switch_requires_account_cookie_and_current_destination_membership(
    db, admin_engine, seeded
):
    grant, current, account, _ = member_pair(db, admin_engine, seeded)
    with pytest.raises(SessionError):
        workspaces.switch_workspace(db, current, "wrong-account-cookie", seeded["tenants"][1])
    with admin_engine.begin() as conn:
        conn.execute(
            text(
                "UPDATE execbound.workspace_memberships SET active=false,version=version+1 "
                "WHERE account_id=:a AND tenant_id=:t"
            ),
            {"a": account, "t": seeded["tenants"][1]},
        )
    with pytest.raises(SessionError):
        workspaces.switch_workspace(db, current, grant.account_token, seeded["tenants"][1])
    assert load_session(db, grant.token).session_id == grant.session_id


def test_concurrent_switch_consumes_the_previous_generation_once(db, admin_engine, seeded):
    grant, current, _, _ = member_pair(db, admin_engine, seeded)

    def attempt(_):
        try:
            return workspaces.switch_workspace(
                db, current, grant.account_token, seeded["tenants"][1]
            ).session_id
        except SessionError:
            return None

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(attempt, range(2)))
    assert sum(result is not None for result in results) == 1


def test_destination_directory_requirement_cannot_be_bypassed_by_switching(
    db, admin_engine, seeded
):
    from test_directory_store import RING, FixedClock, enabled, person

    from execbound.directory import DirectoryConfig

    grant, current, _, _ = member_pair(db, admin_engine, seeded)
    destination = seeded["tenants"][1]
    directory_admin = person(admin_engine, destination, "ADMIN")
    provider = enabled(
        db,
        DirectoryConfig(RING, "https://app.example"),
        {"tenant": destination, "admin": directory_admin},
        FixedClock(),
    )
    with admin_engine.begin() as conn:
        conn.execute(
            text(
                "UPDATE execbound.identity_providers SET require_sign_in=true "
                "WHERE tenant_id=:t AND provider_id=:p"
            ),
            {"t": destination, "p": provider},
        )
    with pytest.raises(SessionError):
        workspaces.switch_workspace(db, current, grant.account_token, destination)
    assert load_session(db, grant.token).session_id == grant.session_id


def test_directory_only_authentication_cannot_open_account_or_list_workspaces(
    db, admin_engine, seeded
):
    from test_directory_store import RING, FixedClock, account, enabled, person

    from execbound import directory_store
    from execbound.directory import DirectoryConfig

    tenant = seeded["tenants"][0]
    admin = person(admin_engine, tenant, "ADMIN")
    settings, clock = DirectoryConfig(RING, "https://app.example"), FixedClock()
    provider = enabled(db, settings, {"tenant": tenant, "admin": admin}, clock)
    identity = directory_store.sign_in(
        db, settings, directory_store.locate_provider(db, provider), account(), clock=clock
    )
    grant = issue_session(db, identity, clock=clock)
    assert grant.account_token is None
    current = load_session(db, grant.token, clock=clock)
    with pytest.raises(SessionError):
        workspaces.list_workspaces(db, current, "", clock=clock)


def test_optional_workspace_never_keeps_required_workspace_authority_usable(
    db, admin_engine, seeded
):
    grant, current, _, _ = member_pair(db, admin_engine, seeded)
    a, b = seeded["tenants"]
    selected_b = workspaces.switch_workspace(db, current, grant.account_token, b)
    with admin_engine.begin() as conn:
        conn.execute(
            text(
                "INSERT INTO execbound.account_security_policy "
                "(tenant_id,requirement,changed_at,changed_by) VALUES(:t,'all',now(),:p)"
            ),
            {"t": a, "p": current.identity.principal_id},
        )
    selected_a = workspaces.switch_workspace(
        db, load_session(db, selected_b.token), grant.account_token, a
    )
    assert selected_a.mfa_required
    with pytest.raises(SessionError) as refused:
        load_session(db, selected_a.token)
    assert refused.value.code == "MFA_REQUIRED"
    for old in (grant.token, selected_b.token):
        with pytest.raises(SessionError):
            load_session(db, old)


def test_password_revocation_serializes_with_a_concurrent_workspace_switch(
    db, admin_engine, seeded
):
    from threading import Barrier

    from execbound.passwords import change_password

    grant, current, _, _ = member_pair(db, admin_engine, seeded)
    owner_grant = issue_session(
        db, sign_in_with_password(db, "member@example.test", "a retained example passphrase")
    )
    owner = load_session(db, owner_grant.token)
    ready = Barrier(2)

    def switch():
        ready.wait(timeout=5)
        try:
            return workspaces.switch_workspace(
                db, current, grant.account_token, seeded["tenants"][1]
            )
        except SessionError:
            return None

    def change():
        ready.wait(timeout=5)
        change_password(
            db,
            owner.identity,
            "a retained example passphrase",
            "a new global account passphrase",
            session=owner,
        )

    with ThreadPoolExecutor(max_workers=2) as pool:
        switched, changed = pool.submit(switch), pool.submit(change)
        selected = switched.result(timeout=10)
        changed.result(timeout=10)
    for token in [grant.token] + ([selected.token] if selected is not None else []):
        with pytest.raises(SessionError):
            load_session(db, token)
    assert load_session(db, owner_grant.token).account_id == owner.account_id


def test_account_sign_out_other_devices_reaches_other_workspaces(db, admin_engine, seeded):
    from execbound.surfaces.sessions import revoke_other_sessions

    tenant = seeded["tenants"][0]
    principal, _ = enroll(admin_engine, tenant)
    account = adopt(db, tenant, principal)
    second_membership(admin_engine, seeded, account)
    identity = sign_in_with_password(db, "member@example.test", "a retained example passphrase")
    first, second = issue_session(db, identity), issue_session(db, identity)
    moved = workspaces.switch_workspace(
        db, load_session(db, second.token), second.account_token, seeded["tenants"][1]
    )
    assert revoke_other_sessions(db, load_session(db, first.token)) == 1
    with pytest.raises(SessionError):
        load_session(db, moved.token)
    assert load_session(db, first.token)


def test_an_account_session_switches_workspaces_with_no_plugin(
    db, runtime, admin_engine, seeded, world
):
    """Switching between an account's own workspaces is core: `GET /session` reports it for
    every session signed in through an account, and the list answers with no plugin loaded. A
    session signed in with a credential has no account, so it reports no switching."""
    runtime.clock = SystemClock()
    grant, _, _, _ = member_pair(db, admin_engine, seeded)
    with TestClient(
        create_app(db, runtime=runtime, human=console_config()), base_url=ORIGIN
    ) as client:
        client.cookies.set("eb_session", grant.token, domain="127.0.0.1")
        client.cookies.set("eb_csrf", grant.csrf_token, domain="127.0.0.1")
        client.cookies.set("eb_account", grant.account_token, domain="127.0.0.1")
        session = client.get(API + "/session").json()
        listed = client.get(API + "/session/workspaces")
    assert session["can_switch_workspaces"] is True
    assert listed.status_code == 200, listed.text
    assert len(listed.json()["workspaces"]) == 2
    with console_client(db, runtime, admin_engine, world["admin"]) as client:
        credential_session = client.get(API + "/session").json()
    assert credential_session["can_switch_workspaces"] is False


def test_sn10_sign_in_opens_the_last_workspace_used(db, admin_engine, seeded):
    from types import SimpleNamespace

    from test_directory_store import RING, FixedClock, enabled, person

    from execbound.directory import DirectoryConfig
    from execbound.passwords import bind_identity
    from execbound.signin import ExternalAccount
    from execbound.surfaces.sign_in_pages import _link

    older, newer = seeded["tenants"]
    principal, _ = enroll(admin_engine, older, kind="ADMIN")
    bind_identity(
        db,
        older,
        principal,
        provider="google",
        subject="returning",
        email="member@example.test",
        display_name=None,
    )
    account = adopt(db, older, principal)
    other = second_membership(admin_engine, seeded, account)
    with admin_engine.begin() as conn:
        conn.execute(
            text("INSERT INTO execbound.access_principals(tenant_id,principal_id) VALUES(:t,:p)"),
            {"t": newer, "p": other},
        )
        conn.execute(
            text(
                "INSERT INTO execbound.access_role_grants(tenant_id,grant_id,principal_id,role) "
                "VALUES(:t,:g,:p,'viewer')"
            ),
            {"t": newer, "p": other, "g": uuid4()},
        )

    def by_password():
        return sign_in_with_password(db, "member@example.test", "a retained example passphrase")

    def by_provider():
        return _link(
            SimpleNamespace(db=db, clock=SystemClock()),
            ExternalAccount("google", "returning", "member@example.test", None),
        )

    # With no entry recorded anywhere, a sign-in opens the oldest membership, as it always has.
    assert by_password().tenant_id == older
    grant = issue_session(db, by_password())
    workspaces.switch_workspace(db, load_session(db, grant.token), grant.account_token, newer)
    # The newer workspace was entered last, so both kinds of sign-in open it.
    assert by_password().tenant_id == newer
    assert by_provider().tenant_id == newer

    with admin_engine.begin() as conn:
        conn.execute(
            text(
                "UPDATE execbound.workspace_memberships SET active=false,version=version+1 "
                "WHERE account_id=:a AND tenant_id=:t"
            ),
            {"a": account, "t": newer},
        )
    # A membership that is no longer usable is never chosen, however recently it was entered.
    assert by_password().tenant_id == older
    assert by_provider().tenant_id == older

    with admin_engine.begin() as conn:
        conn.execute(
            text(
                "UPDATE execbound.workspace_memberships SET active=true,version=version+1 "
                "WHERE account_id=:a AND tenant_id=:t"
            ),
            {"a": account, "t": newer},
        )
    assert by_password().tenant_id == newer
    provider = enabled(
        db,
        DirectoryConfig(RING, "https://app.example"),
        {"tenant": newer, "admin": person(admin_engine, newer, "ADMIN")},
        FixedClock(),
    )
    with admin_engine.begin() as conn:
        conn.execute(
            text(
                "UPDATE execbound.identity_providers SET require_sign_in=true "
                "WHERE tenant_id=:t AND provider_id=:p"
            ),
            {"t": newer, "p": provider},
        )
    # A workspace that requires its own directory cannot be opened by this sign-in.
    assert by_password().tenant_id == older
    assert by_provider().tenant_id == older


# Carrying a verification across a switch (#678). The injected clock stays inside the five-minute
# fence `account_switch` holds against the database's own clock, so every age is made by moving
# `session_assurance.verified_at` back through the admin engine, as `stale` does.
RING = KeyRing("test", {"test": b"m" * 32})


def verified_pair(db, engine, seeded):
    """`member_pair` with the account's authenticator confirmed on its session in the first
    workspace, which verifies the factor there now. Also returns the recovery codes."""
    grant, current, account, other = member_pair(db, engine, seeded)
    seed = mfa.begin_enrollment(db, current, RING)
    codes = mfa.confirm_enrollment(
        db, current, RING, mfa.totp(seed, int(SystemClock().now().timestamp()) // 30)
    )
    return grant, load_session(db, grant.token), account, other, codes


def assurance_of(engine, tenant, session):
    with engine.begin() as conn:
        return (
            conn.execute(
                text(
                    "SELECT version, verified_at, method FROM execbound.session_assurance "
                    "WHERE tenant_id=:t AND session_id=:s"
                ),
                {"t": tenant, "s": session},
            )
            .mappings()
            .one_or_none()
        )


def carried_events(engine, tenant):
    with engine.begin() as conn:
        return list(
            conn.execute(
                text(
                    "SELECT payload FROM execbound.audit_events WHERE tenant_id=:t "
                    "AND kind='account_security.assurance_carried' ORDER BY sequence"
                ),
                {"t": tenant},
            ).scalars()
        )


def carried_records(engine, account):
    with engine.begin() as conn:
        return [
            dict(row)
            for row in conn.execute(
                text(
                    "SELECT source_tenant_id, source_session_id, destination_tenant_id, "
                    "destination_session_id FROM execbound.user_security_events "
                    "WHERE account_id=:a AND kind='assurance_carried' ORDER BY occurred_at"
                ),
                {"a": account},
            ).mappings()
        ]


def nothing_carried(engine, account, destination, switched):
    assert assurance_of(engine, destination, switched.session_id) is None
    assert carried_events(engine, destination) == []
    assert carried_records(engine, account) == []


def test_sn14_assurance_carries_for_the_same_factor_within_the_window(db, admin_engine, seeded):
    from execbound.accounts import ACCOUNT_NOTICES

    a, b = seeded["tenants"]
    grant, current, account, _, _ = verified_pair(db, admin_engine, seeded)
    stale(admin_engine, a, current.session_id, minutes=10)
    source = assurance_of(admin_engine, a, current.session_id)

    switched = workspaces.switch_workspace(db, current, grant.account_token, b)
    assert not switched.mfa_required
    selected = load_session(db, switched.token)
    assert selected.identity.tenant_id == b
    # The carried row is the source's own: the same version, method and verification time.
    assert assurance_of(admin_engine, b, switched.session_id) == source

    # The destination's chain records the carry and names nothing of the other workspace.
    (event,) = carried_events(admin_engine, b)
    assert event == {
        "session_id": str(switched.session_id),
        "account_session_id": str(current.account_session_id),
        "method": "totp",
        "verified_at": source["verified_at"].astimezone(UTC).isoformat(timespec="microseconds"),
    }
    assert str(a) not in json.dumps(event)
    # The account sign-in it names is already on the destination's own session row.
    with admin_engine.begin() as conn:
        assert (
            str(
                conn.execute(
                    text(
                        "SELECT account_session_id FROM execbound.human_sessions "
                        "WHERE tenant_id=:t AND session_id=:s"
                    ),
                    {"t": b, "s": switched.session_id},
                ).scalar_one()
            )
            == event["account_session_id"]
        )
    # The account's own record names the source and joins the event by the new session.
    assert carried_records(admin_engine, account) == [
        {
            "source_tenant_id": a,
            "source_session_id": current.session_id,
            "destination_tenant_id": b,
            "destination_session_id": UUID(event["session_id"]),
        }
    ]
    # It is a record, not a notice: the security bell never shows it.
    assert "assurance_carried" not in ACCOUNT_NOTICES


def test_sn14_the_window_never_restarts(db, admin_engine, seeded):
    a, b = seeded["tenants"]
    grant, current, _, _, _ = verified_pair(db, admin_engine, seeded)
    stale(admin_engine, a, current.session_id, minutes=10)
    switched = workspaces.switch_workspace(db, current, grant.account_token, b)
    selected = load_session(db, switched.token)
    # Twenty-nine minutes after the code was entered, in the other workspace, the step-up holds.
    stale(admin_engine, b, switched.session_id, minutes=19)
    mfa.require_recent_factor(db, selected)
    # Thirty-one minutes after it, the step-up asks again, as it would have where it was entered.
    stale(admin_engine, b, switched.session_id, minutes=2)
    with pytest.raises(mfa.MfaError) as refused:
        mfa.require_recent_factor(db, selected)
    assert refused.value.code == "RECENT_AUTH_REQUIRED"


def switch_directly(db, current, destination):
    """`account_switch` called as the runtime role, past the session check the Python switch
    makes first: what the function itself carries, for a source the session check would
    already refuse."""
    import hashlib
    import secrets

    def digest():
        return hashlib.sha256(secrets.token_bytes(16)).hexdigest()

    following = uuid4()
    with db.transaction(current.identity.tenant_id) as conn:
        conn.execute(
            text("SELECT set_config('execbound.account_id',:a,true)"),
            {"a": str(current.account_id)},
        )
        result = conn.execute(
            text(
                "SELECT execbound.account_switch(:previous,:destination,:next,"
                ":credential,:token,:csrf,:credential_hash,now())"
            ),
            {
                "previous": current.session_id,
                "destination": destination,
                "next": following,
                "credential": uuid4(),
                "token": digest(),
                "csrf": digest(),
                "credential_hash": digest(),
            },
        ).scalar_one()
    return following, result


def counts_in(seen, tenant):
    """The waiting counts read under this tenant's setting, from `statements`."""
    return [
        statement
        for statement, _, setting in seen
        if "effective_approval_scopes" in statement and setting == str(tenant)
    ]


@pytest.mark.parametrize("case", ["older", "changed", "disabled", "none"])
def test_sn14_an_older_or_changed_factor_still_asks(db, admin_engine, seeded, case, statements):
    from types import SimpleNamespace

    a, b = seeded["tenants"]
    if case == "none":
        grant, current, account, other = member_pair(db, admin_engine, seeded)
    else:
        grant, current, account, other, _ = verified_pair(db, admin_engine, seeded)
    with admin_engine.begin() as conn:
        # The destination asks every member for a second factor, whatever the account holds.
        conn.execute(
            text(
                "INSERT INTO execbound.account_security_policy "
                "(tenant_id,requirement,changed_at,changed_by) VALUES(:t,'all',now(),:p)"
            ),
            {"t": b, "p": other},
        )
        if case == "changed":
            # The factor was enrolled again elsewhere: the verification is of the old one.
            conn.execute(
                text("UPDATE execbound.user_factors SET version=version+1 WHERE account_id=:a"),
                {"a": account},
            )
        if case == "disabled":
            # The factor is gone, its version unchanged: nothing is left to carry.
            conn.execute(
                text(
                    "UPDATE execbound.user_factors SET sealed=NULL,key_id=NULL,enabled_at=NULL "
                    "WHERE account_id=:a"
                ),
                {"a": account},
            )
    if case == "older":
        stale(admin_engine, a, current.session_id, minutes=31)
    if case == "changed":
        # The session check refuses a source verified for a replaced factor before the switch
        # begins; the function's own version condition is what stops it beneath that.
        with pytest.raises(SessionError) as refused:
            load_session(db, grant.token)
        assert refused.value.code == "MFA_REQUIRED"
        following, result = switch_directly(db, current, b)
        assert result["assurance_carried"] is False
        switched = SimpleNamespace(session_id=following)
    else:
        if case in ("none", "disabled"):
            statements.clear()
            listed = workspaces.list_workspaces(db, current, grant.account_token, waiting=True)
            # An account with no factor is sent to set one up, whatever this session verified
            # before the factor was removed; there is nothing to carry, and no count is read.
            entry = {item["tenant_id"]: item for item in listed}[b]
            assert (entry["entry"], entry["waiting_state"]) == ("enrol", "withheld")
            assert counts_in(statements, b) == []
        switched = workspaces.switch_workspace(
            db, load_session(db, grant.token), grant.account_token, b
        )
        assert switched.mfa_required
        with pytest.raises(SessionError) as refused:
            load_session(db, switched.token)
        assert refused.value.code == "MFA_REQUIRED"
    nothing_carried(admin_engine, account, b, switched)


def test_sn14_the_carry_window_is_the_step_up_window(admin_engine):
    with admin_engine.connect() as conn:
        definition = conn.execute(
            text("SELECT pg_get_functiondef('execbound.account_switch'::regproc)")
        ).scalar_one()
    carry = definition[definition.index("INTO carried") :]
    carry = carry[: carry.index(";")]
    (minutes,) = re.findall(r"verified_at>p_now-interval '(\d+) minutes'", carry)
    assert timedelta(minutes=int(minutes)) == mfa.STEP_UP_WINDOW


@pytest.mark.parametrize("case", ["changed", "disabled"])
def test_sn14_carries_answers_for_the_factor_the_account_holds_now(db, admin_engine, seeded, case):
    """A verification of a factor enrolled again, or of one removed, carries nothing however
    recent it is. The version case is out of `list_workspaces`' reach, whose session check
    refuses such a session first, so `carries` is asked directly."""
    from execbound.user_accounts import account_context

    a, b = seeded["tenants"]
    grant, current, account, other, _ = verified_pair(db, admin_engine, seeded)

    def answer():
        with db.transaction(a) as conn:
            account_context(conn, account)
            return workspaces.carries(conn, current, SystemClock().now())

    assert answer()
    with admin_engine.begin() as conn:
        if case == "changed":
            conn.execute(
                text("UPDATE execbound.user_factors SET version=version+1 WHERE account_id=:a"),
                {"a": account},
            )
        else:
            conn.execute(
                text(
                    "UPDATE execbound.user_factors SET sealed=NULL,key_id=NULL,enabled_at=NULL "
                    "WHERE account_id=:a"
                ),
                {"a": account},
            )
        conn.execute(
            text(
                "INSERT INTO execbound.account_security_policy "
                "(tenant_id,requirement,changed_at,changed_by) VALUES(:t,'all',now(),:p)"
            ),
            {"t": b, "p": other},
        )
    assert not answer()
    if case == "disabled":
        # Nor does the entry rule open a workspace on a carry the account holds no factor for.
        with db.transaction(a) as conn:
            account_context(conn, account)
            (item,) = [i for i in workspaces.memberships(conn, account) if i["tenant_id"] == b]
            with workspaces._inside(conn, b):
                entry = workspaces.entry_proof(
                    conn, account, item, "HUMAN_APPROVER", SystemClock().now(), carried=True
                )
        assert entry == "enrol"


def test_sn15_a_switch_and_a_factor_change_serialize(db, admin_engine, seeded):
    """A switch and a factor disable from the same session race on real connections. Each takes
    the account lock first, so one commits before the other reads: the switch either carries the
    factor that is still current, after which the disable finds its session switched away and
    is refused, or finds the factor already gone and carries nothing."""
    from threading import Barrier

    from execbound.mfa import requires_mfa

    a, b = seeded["tenants"]
    grant, current, account, other, _ = verified_pair(db, admin_engine, seeded)
    with admin_engine.begin() as conn:
        conn.execute(
            text(
                "INSERT INTO execbound.account_security_policy "
                "(tenant_id,requirement,changed_at,changed_by) VALUES(:t,'all',now(),:p)"
            ),
            {"t": b, "p": other},
        )
    ready = Barrier(2)

    def switch():
        ready.wait(timeout=5)
        try:
            return workspaces.switch_workspace(db, current, grant.account_token, b)
        except SessionError:
            return None

    def disable():
        ready.wait(timeout=5)
        try:
            mfa.manage_security(db, current, "disable")
            return True
        except (mfa.MfaError, SessionError):
            return False

    with ThreadPoolExecutor(max_workers=2) as pool:
        switching, disabling = pool.submit(switch), pool.submit(disable)
        switched, disabled = switching.result(timeout=20), disabling.result(timeout=20)
    # The switch always goes through; the disable only when it commits first, since otherwise
    # its session has been switched away.
    assert switched is not None
    with admin_engine.begin() as conn:
        factor = (
            conn.execute(
                text("SELECT enabled_at, version FROM execbound.user_factors WHERE account_id=:a"),
                {"a": account},
            )
            .mappings()
            .one()
        )
    assert (factor["enabled_at"] is None) == disabled
    carried = assurance_of(admin_engine, b, switched.session_id)
    # Whatever the order, the destination never holds a factor that is no longer current.
    assert (carried is None) == disabled
    assert carried is None or (
        factor["enabled_at"] is not None and carried["version"] == factor["version"]
    )
    with db.transaction(b) as conn:
        conn.execute(text("SELECT set_config('execbound.account_id',:a,true)"), {"a": str(account)})
        asks = requires_mfa(
            conn,
            {
                "tenant_id": b,
                "principal_id": other,
                "session_id": switched.session_id,
                "kind": "HUMAN_APPROVER",
                "account_id": account,
            },
            SystemClock().now(),
        )
    assert asks == switched.mfa_required == (carried is None)


def test_sn14_entry_proof_matches_the_carry(db, admin_engine, seeded):
    a, b = seeded["tenants"]
    grant, current, _, _, _ = verified_pair(db, admin_engine, seeded)
    stale(admin_engine, a, current.session_id, minutes=10)
    listed = {
        item["tenant_id"]: item
        for item in workspaces.list_workspaces(db, current, grant.account_token, waiting=True)
    }
    # Ten minutes after the code, the other workspace opens with no more proof, and is counted.
    assert (listed[b]["entry"], listed[b]["waiting_state"]) == ("open", "counted")
    switched = workspaces.switch_workspace(db, current, grant.account_token, b)
    assert not switched.mfa_required

    # Thirty-one minutes after it, the way back asks for the factor, and the switch agrees.
    selected = load_session(db, switched.token)
    stale(admin_engine, b, switched.session_id, minutes=21)
    listed = {
        item["tenant_id"]: item
        for item in workspaces.list_workspaces(db, selected, grant.account_token, waiting=True)
    }
    assert (listed[a]["entry"], listed[a]["waiting_state"]) == ("factor", "withheld")
    back = workspaces.switch_workspace(db, selected, grant.account_token, a)
    assert back.mfa_required
