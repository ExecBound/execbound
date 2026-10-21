# SPDX-License-Identifier: AGPL-3.0-only
"""A trusted browser skips the sign-in factor for thirty days, and nothing more (#859).

Trust is an account's, kept in `trusted_browsers` behind definer functions: the runtime reads
its own account's rows and writes none. A sign-in that owes its factor on a browser holding a
live trust gets a `session_assurance` row with method `trusted` and the trust's original
`verified_at`, never now, so the thirty-minute step-up and the database's own `fresh` check
still ask for a code once the verification behind the trust is older than that.

The account sign-in refuses a clock far from the database's own (`account_session_open`), so a
trust is aged by moving its row back, as `test_console_api_step_up.stale` ages an assurance.
"""

import hashlib
import importlib.util
import secrets
from concurrent.futures import ThreadPoolExecutor
from datetime import timedelta
from pathlib import Path
from uuid import UUID, uuid4

import pytest
from alembic import command
from alembic.script import ScriptDirectory
from sqlalchemy import text
from sqlalchemy.exc import DBAPIError
from test_console_api_step_up import stale
from test_dormant_catalog import alembic_config, empty_schema
from test_human_sessions import humans as humans
from test_mfa_sessions import enrolled
from test_workspace_accounts import adopt, enroll
from test_workspace_switching import RING, assurance_of, verified_pair

from execbound import db as database
from execbound import mfa, trusted_browsers, workspaces
from execbound.db import check_runtime
from execbound.passwords import sign_in_with_password
from execbound.resolution.models import SystemClock
from execbound.surfaces.sessions import SessionError, issue_session, load_session
from execbound.user_accounts import account_context

pytestmark = pytest.mark.integration

CLOCK = SystemClock()
EMAIL = "member@example.test"
PASSWORD = "a retained example passphrase"  # nosec B105 - The test fixture's own passphrase.
LABEL = "Chrome on Windows"
BEFORE = "0100_longer_sessions"
TARGET = "0101_trusted_browsers"
# Patched in place so that method `trusted` is never fresh and never carried.
PATCHED = ("account_security_change", "user_security_change", "account_switch")
FUNCTIONS = (
    "trusted_browser_add",
    "trusted_browser_use",
    "trusted_browser_remove",
    "trusted_browser_remove_all",
    "trusted_browser_policy",
    "account_sign_out_others",
)


def verified(db, engine, seeded):
    """An administrator's account with an authenticator confirmed on its session in the first
    workspace, which verified the factor there now."""
    _, current, account, _, codes = verified_pair(db, engine, seeded)
    return current, account, codes


def granted(db, engine, session):
    """Trust this session's browser with the verification the session itself holds."""
    assured = assurance_of(engine, session.identity.tenant_id, session.session_id)
    cookie, expires = trusted_browsers.grant(
        db,
        session,
        method=assured["method"],
        verified_at=assured["verified_at"],
        label=LABEL,
        clock=CLOCK,
    )
    return cookie, expires, assured


def browser_of(cookie):
    return UUID(cookie.split(".")[1])


def signed_in_again(db, email=EMAIL):
    """A new password sign-in of the account, still owing its second factor."""
    grant = issue_session(db, sign_in_with_password(db, email, PASSWORD))
    assert grant.mfa_required
    return grant, load_session(db, grant.token, allow_pending_mfa=True)


def applies_now(db, session, account, cookie):
    tenant = session.identity.tenant_id
    with db.transaction(tenant) as conn:
        return trusted_browsers.applies(conn, account, tenant, cookie, CLOCK.now())


def trust_rows(engine, account):
    with engine.begin() as conn:
        return [
            dict(row)
            for row in conn.execute(
                text(
                    "SELECT * FROM execbound.trusted_browsers WHERE account_id=:a "
                    "ORDER BY created_at, browser_id"
                ),
                {"a": account},
            ).mappings()
        ]


def security_events(engine, account):
    with engine.begin() as conn:
        return list(
            conn.execute(
                text(
                    "SELECT kind FROM execbound.user_security_events WHERE account_id=:a "
                    "AND kind LIKE 'trusted_browser_%' ORDER BY occurred_at, kind"
                ),
                {"a": account},
            ).scalars()
        )


def aged(engine, account, age):
    """Move every trust of the account `age` into the past: granted, verified and expiring
    that much earlier."""
    with engine.begin() as conn:
        conn.execute(
            text(
                "UPDATE execbound.trusted_browsers SET verified_at=verified_at-:d, "
                "created_at=created_at-:d, expires_at=expires_at-:d WHERE account_id=:a"
            ),
            {"d": age, "a": account},
        )


def test_tb_grant_then_apply_skips_the_factor_with_the_original_time(db, admin_engine, seeded):
    assert trusted_browsers.TRUST_LIFETIME == timedelta(days=30)
    assert trusted_browsers.COOKIE_PREFIX == "tb1"
    current, account, _ = verified(db, admin_engine, seeded)
    cookie, expires, assured = granted(db, admin_engine, current)
    assert assured["method"] == "totp"
    prefix, browser, secret = cookie.split(".")
    assert prefix == "tb1" and UUID(browser)
    (row,) = trust_rows(admin_engine, account)
    # Only a digest of the secret is kept, and the trust records the verification behind it.
    assert secret not in repr(row)
    assert row["browser_id"] == UUID(browser)
    assert row["verified_at"] == assured["verified_at"] and row["method"] == "totp"
    assert row["label"] == LABEL
    assert row["expires_at"] == expires == row["created_at"] + timedelta(days=30)
    assert row["last_used_at"] is None and row["revoked_at"] is None

    grant, pending = signed_in_again(db)
    tenant = pending.identity.tenant_id
    assert pending.mfa_required
    # The interstitial's read answers the same as the write, and writes nothing.
    assert applies_now(db, pending, account, cookie)
    assert trust_rows(admin_engine, account)[0]["last_used_at"] is None
    assert assurance_of(admin_engine, tenant, pending.session_id) is None

    rotated = trusted_browsers.apply(db, pending, cookie, clock=CLOCK)
    assert rotated is not None and not rotated.mfa_required
    assert rotated.session_id == pending.session_id and rotated.account_bound
    # The session was rotated with the assurance: the token issued before the factor was
    # satisfied no longer loads, and the new one loads a session that owes nothing.
    assert rotated.token != grant.token and rotated.csrf_token != grant.csrf_token
    with pytest.raises(SessionError):
        load_session(db, grant.token, allow_pending_mfa=True)
    session = load_session(db, rotated.token)
    assert not session.mfa_required
    with db.transaction(tenant) as conn:
        account_context(conn, account)
        row_of_session = {
            "tenant_id": tenant,
            "principal_id": session.identity.principal_id,
            "session_id": session.session_id,
            "kind": session.identity.kind,
            "account_id": account,
        }
        assert not mfa.requires_mfa(conn, row_of_session, CLOCK.now())
    assurance = assurance_of(admin_engine, tenant, pending.session_id)
    assert assurance["method"] == "trusted"
    assert assurance["verified_at"] == assured["verified_at"]
    assert assurance["version"] == assured["version"]
    assert trust_rows(admin_engine, account)[0]["last_used_at"] is not None
    # A session that no longer owes its factor is not trusted again.
    assert trusted_browsers.apply(db, session, cookie, clock=CLOCK) is None
    # Using a trust is not a security event; adding one is.
    assert security_events(admin_engine, account) == ["trusted_browser_added"]


def trusted_sign_in(db, engine, seeded, minutes):
    """A sign-in a trust let through, the trust granted `minutes` ago. Answers the session,
    its account, the sign-in's own grant and the assurance the trust was granted from."""
    current, account, _ = verified(db, engine, seeded)
    cookie, _, assured = granted(db, engine, current)
    aged(engine, account, timedelta(minutes=minutes))
    grant, pending = signed_in_again(db)
    rotated = trusted_browsers.apply(db, pending, cookie, clock=CLOCK)
    assert rotated is not None
    session = load_session(db, rotated.token)
    assert not session.mfa_required
    return session, account, grant, assured


@pytest.mark.parametrize("minutes", [10, 31])
def test_tb_a_trusted_session_still_fails_the_recent_factor_check(
    db, admin_engine, seeded, minutes
):
    """Method `trusted` is never a fresh verification: not ten minutes after the verification
    behind the trust, inside the step-up's thirty, and not after them."""
    session, account, _, assured = trusted_sign_in(db, admin_engine, seeded, minutes)
    assurance = assurance_of(admin_engine, session.identity.tenant_id, session.session_id)
    assert assurance["method"] == "trusted"
    assert assurance["verified_at"] == assured["verified_at"] - timedelta(minutes=minutes)
    with pytest.raises(mfa.MfaError) as refused:
        mfa.require_recent_factor(db, session, clock=CLOCK)
    assert refused.value.code == "RECENT_AUTH_REQUIRED"
    # The database's own `fresh` (`user_security_change`) refuses it beneath the Python check.
    _, retained = mfa.new_recovery_codes(account)
    with pytest.raises(mfa.MfaError):
        with mfa._transaction(db, session, CLOCK) as conn:
            mfa._change(conn, session, CLOCK.now(), "recovery", {"recovery": retained})
    # So does the session rotation a verified code allows.
    with pytest.raises(mfa.MfaError) as refused:
        mfa.rotate_verified_session(db, session, clock=CLOCK)
    assert refused.value.code == "RECENT_AUTH_REQUIRED"


def test_tb_a_trusted_assurance_is_not_fresh_for_a_legacy_session(db, humans, admin_engine):
    """`account_security_change`, the legacy sessions' writer, reads `fresh` the same way. A
    legacy session's verification seconds old passes; the same row as `trusted` does not."""
    clock, grant, _ = enrolled(db, humans)
    session = load_session(db, grant.token, clock=clock)
    _, retained = mfa.new_recovery_codes(session.identity.principal_id)

    def replace_codes():
        with mfa._transaction(db, session, clock) as conn:
            mfa._change(conn, session, clock.now(), "recovery", {"recovery": retained})

    replace_codes()
    with admin_engine.begin() as conn:
        conn.execute(
            text(
                "UPDATE execbound.session_assurance SET method='trusted' "
                "WHERE tenant_id=:t AND session_id=:s"
            ),
            {"t": session.identity.tenant_id, "s": session.session_id},
        )
    with pytest.raises(mfa.MfaError):
        replace_codes()
    with pytest.raises(mfa.MfaError) as refused:
        mfa.require_recent_factor(db, session, clock=clock)
    assert refused.value.code == "RECENT_AUTH_REQUIRED"


def test_tb_a_trusted_session_does_not_carry_into_another_workspace(db, admin_engine, seeded):
    """Ten minutes after the verification behind the trust, inside the carry's thirty, a
    trusted session still carries nothing, even into a workspace that allows trust: there the
    switch owes the factor, which trust may then satisfy through the sign-in's own path."""
    a, b = seeded["tenants"]
    session, account, grant, _ = trusted_sign_in(db, admin_engine, seeded, 10)
    assert session.identity.tenant_id == a
    with db.transaction(a) as conn:
        account_context(conn, account)
        assert trusted_browsers.allowed(conn, b)
        assert not workspaces.carries(conn, session, CLOCK.now())
    switched = workspaces.switch_workspace(db, session, grant.account_token, b)
    assert switched.mfa_required
    assert assurance_of(admin_engine, b, switched.session_id) is None


MALFORMED = (
    None,
    "",
    "tb1",
    "tb1..",
    f"tb1.{uuid4()}",
    f"tb1.not-a-uuid.{secrets.token_urlsafe(32)}",
    f"tb2.{uuid4()}.{secrets.token_urlsafe(32)}",
    f"tb1.{uuid4()}.{secrets.token_urlsafe(32)}.extra",
    f"tb1.{uuid4()}.short",
    f"tb1.{str(uuid4()).upper()}.{secrets.token_urlsafe(32)}",
    f"tb1.{uuid4()}.{'!' * 43}",
    "tb1." + "x" * 5000,
    b"tb1.bytes",
    42,
)


def another_accounts_cookie(db, engine, seeded):
    """A trust of a second account, an administrator of the second workspace."""
    tenant = seeded["tenants"][1]
    principal, _ = enroll(engine, tenant, email="second@example.test", kind="ADMIN")
    adopt(db, tenant, principal)
    grant = issue_session(db, sign_in_with_password(db, "second@example.test", PASSWORD))
    session = load_session(db, grant.token)
    seed = mfa.begin_enrollment(db, session, RING)
    mfa.confirm_enrollment(db, session, RING, mfa.totp(seed, int(CLOCK.now().timestamp()) // 30))
    session = load_session(db, grant.token)
    cookie, _, _ = granted(db, engine, session)
    return cookie


@pytest.mark.parametrize(
    "case",
    [
        "another_account",
        "wrong_secret",
        "malformed",
        "expired",
        "removed",
        "account_version",
        "factor_version",
        "forbidden",
    ],
)
def test_tb_trust_is_refused_when(db, admin_engine, seeded, case):
    current, account, _ = verified(db, admin_engine, seeded)
    cookie, _, _ = granted(db, admin_engine, current)
    cookies = [cookie]
    if case == "another_account":
        cookies = [another_accounts_cookie(db, admin_engine, seeded)]
    elif case == "wrong_secret":
        cookies = [f"tb1.{browser_of(cookie)}.{secrets.token_urlsafe(32)}"]
    elif case == "malformed":
        cookies = list(MALFORMED)
    elif case == "expired":
        aged(admin_engine, account, timedelta(days=30, seconds=1))
    elif case == "removed":
        trusted_browsers.remove(db, current, browser_of(cookie), clock=CLOCK)
    elif case == "account_version":
        with admin_engine.begin() as conn:
            conn.execute(
                text("UPDATE execbound.user_accounts SET version=version+1 WHERE account_id=:a"),
                {"a": account},
            )
    elif case == "factor_version":
        with admin_engine.begin() as conn:
            conn.execute(
                text("UPDATE execbound.user_factors SET version=version+1 WHERE account_id=:a"),
                {"a": account},
            )
    elif case == "forbidden":
        trusted_browsers.set_allowed(db, current, False, clock=CLOCK)

    grant, pending = signed_in_again(db)
    tenant = pending.identity.tenant_id
    assert tenant == current.identity.tenant_id
    for value in cookies:
        assert not applies_now(db, pending, account, value), value
        assert not trusted_browsers.apply(db, pending, value, clock=CLOCK), value
    assert assurance_of(admin_engine, tenant, pending.session_id) is None
    with pytest.raises(SessionError) as refused:
        load_session(db, grant.token)
    assert refused.value.code == "MFA_REQUIRED"
    assert all(row["last_used_at"] is None for row in trust_rows(admin_engine, account))


def account_version(engine, account):
    with engine.begin() as conn:
        return conn.execute(
            text("SELECT version FROM execbound.user_accounts WHERE account_id=:a"), {"a": account}
        ).scalar_one()


def test_tb_sign_out_other_devices_from_a_session_with_no_account_sign_in_ends_trust(
    db, admin_engine, seeded
):
    """ "Sign out other devices" from a session of the same person that has no account sign-in,
    a setup credential's, moves the account's version as the account path does: the trust
    ends, every account sign-in of the account is signed out, and the acting session stays."""
    from execbound.passwords import mint_session_credential
    from execbound.surfaces.sessions import revoke_other_sessions

    grant, current, account, _, codes = verified_pair(db, admin_engine, seeded)
    cookie, _, _ = granted(db, admin_engine, current)
    tenant, principal = current.identity.tenant_id, current.identity.principal_id
    setup = issue_session(db, mint_session_credential(db, tenant, principal, "password"))
    pending = load_session(db, setup.token, allow_pending_mfa=True)
    assert pending.account_id is None
    assert mfa.verify_factor(db, pending, RING, codes[0])
    acting = load_session(db, setup.token)
    before = account_version(admin_engine, account)

    revoke_other_sessions(db, acting, clock=CLOCK)

    assert account_version(admin_engine, account) == before + 1
    # Every account sign-in of the account is signed out, in every workspace.
    with admin_engine.begin() as conn:
        live = conn.execute(
            text(
                "SELECT count(*) FROM execbound.account_sessions "
                "WHERE account_id=:a AND revoked_at IS NULL"
            ),
            {"a": account},
        ).scalar_one()
    assert live == 0
    assert trusted_browsers.listed(db, acting, clock=CLOCK) == []
    _, again = signed_in_again(db)
    assert trusted_browsers.apply(db, again, cookie, clock=CLOCK) is None
    # The account sign-in it was granted on is signed out, everywhere; the acting session
    # stays.
    with pytest.raises(SessionError):
        load_session(db, grant.token, clock=CLOCK)
    assert load_session(db, setup.token).session_id == acting.session_id
    with admin_engine.begin() as conn:
        kinds = list(
            conn.execute(
                text(
                    "SELECT kind FROM execbound.user_security_events WHERE account_id=:a "
                    "AND kind='other_devices_signed_out'"
                ),
                {"a": account},
            ).scalars()
        )
    assert kinds == ["other_devices_signed_out"]


def test_tb_an_eleventh_trust_revokes_the_oldest(db, admin_engine, seeded):
    assert trusted_browsers.MAX_TRUSTED == 10
    current, account, _ = verified(db, admin_engine, seeded)
    cookies = [granted(db, admin_engine, current)[0] for _ in range(11)]
    rows = trust_rows(admin_engine, account)
    assert [row["browser_id"] for row in rows] == [browser_of(cookie) for cookie in cookies]
    assert rows[0]["revoked_at"] is not None
    assert all(row["revoked_at"] is None for row in rows[1:])
    listed = trusted_browsers.listed(db, current, clock=CLOCK)
    assert len(listed) == 10
    assert browser_of(cookies[0]) not in {trust.browser_id for trust in listed}
    events = security_events(admin_engine, account)
    assert events.count("trusted_browser_added") == 11
    assert events.count("trusted_browser_removed") == 1

    _, pending = signed_in_again(db)
    assert not trusted_browsers.apply(db, pending, cookies[0], clock=CLOCK)
    assert trusted_browsers.apply(db, pending, cookies[-1], clock=CLOCK)


def test_tb_listed_and_removed_records_events(db, admin_engine, seeded):
    current, account, _ = verified(db, admin_engine, seeded)
    first, _, _ = granted(db, admin_engine, current)
    second, expires, _ = granted(db, admin_engine, current)
    listed = trusted_browsers.listed(db, current, clock=CLOCK)
    # Newest first.
    assert [trust.browser_id for trust in listed] == [browser_of(second), browser_of(first)]
    newest = listed[0]
    assert isinstance(newest, trusted_browsers.Trust)
    assert newest.label == LABEL and newest.expires_at == expires
    assert newest.last_used_at is None
    assert newest.expires_at - newest.created_at == trusted_browsers.TRUST_LIFETIME
    assert security_events(admin_engine, account) == ["trusted_browser_added"] * 2

    trusted_browsers.remove(db, current, browser_of(first), clock=CLOCK)
    assert [trust.browser_id for trust in trusted_browsers.listed(db, current, clock=CLOCK)] == [
        browser_of(second)
    ]
    # Removing what is already gone, or was never there, changes and records nothing.
    trusted_browsers.remove(db, current, browser_of(first), clock=CLOCK)
    trusted_browsers.remove(db, current, uuid4(), clock=CLOCK)
    assert security_events(admin_engine, account).count("trusted_browser_removed") == 1

    third, _, _ = granted(db, admin_engine, current)
    assert trusted_browsers.remove_all(db, current, clock=CLOCK) == 2
    assert trusted_browsers.listed(db, current, clock=CLOCK) == []
    assert trusted_browsers.remove_all(db, current, clock=CLOCK) == 0
    events = security_events(admin_engine, account)
    assert events.count("trusted_browser_added") == 3
    assert events.count("trusted_browser_removed") == 3
    _, pending = signed_in_again(db)
    for cookie in (first, second, third):
        assert not trusted_browsers.apply(db, pending, cookie, clock=CLOCK)


def test_tb_the_table_is_account_isolated_and_runtime_read_only(db, admin_engine, seeded):
    current, account, _ = verified(db, admin_engine, seeded)
    cookie, _, _ = granted(db, admin_engine, current)
    tenant = current.identity.tenant_id
    count = "SELECT count(*) FROM execbound.trusted_browsers"
    with db.transaction(tenant) as conn:
        check_runtime(conn)
        assert conn.execute(text(count)).scalar_one() == 0
        account_context(conn, uuid4())
        assert conn.execute(text(count)).scalar_one() == 0
        account_context(conn, account)
        assert conn.execute(text(count)).scalar_one() == 1
    for statement in (
        "INSERT INTO execbound.trusted_browsers(account_id,browser_id,token_hash,"
        "account_version,factor_version,verified_at,method,created_at,expires_at) "
        "VALUES(:a,gen_random_uuid(),repeat('0',64),1,1,now(),'totp',now(),now()+interval '1 day')",
        "UPDATE execbound.trusted_browsers SET expires_at=expires_at+interval '1 day'",
        "UPDATE execbound.trusted_browsers SET revoked_at=NULL",
        "DELETE FROM execbound.trusted_browsers",
        "UPDATE execbound.account_security_policy SET allow_trusted_browsers=true",
        "INSERT INTO execbound.session_assurance(tenant_id,session_id,version,verified_at,method) "
        "VALUES(:t,gen_random_uuid(),1,now(),'trusted')",
    ):
        with db.transaction(tenant) as conn:
            account_context(conn, account)
            with pytest.raises(DBAPIError, match="permission denied"):
                conn.execute(text(statement), {"a": account, "t": tenant})
    # The definers act only for the account the transaction is in.
    with db.transaction(tenant) as conn:
        account_context(conn, uuid4())
        with pytest.raises(DBAPIError, match="INVALID_ACCOUNT"):
            conn.execute(
                text("SELECT execbound.trusted_browser_remove(:a,:b,:n)"),
                {"a": account, "b": browser_of(cookie), "n": CLOCK.now()},
            )
    with db.transaction(tenant) as conn:
        account_context(conn, uuid4())
        with pytest.raises(DBAPIError, match="INVALID_ACCOUNT"):
            conn.execute(
                text("SELECT execbound.trusted_browser_remove_all(:a,:n)"),
                {"a": account, "n": CLOCK.now()},
            )
    assert len(trusted_browsers.listed(db, current, clock=CLOCK)) == 1
    # Only the runtime role may call them: PUBLIC holds nothing.
    with admin_engine.connect() as conn:
        acls = dict(
            conn.execute(
                text(
                    "SELECT p.proname, CAST(p.proacl AS text) FROM pg_proc p "
                    "JOIN pg_namespace n ON n.oid=p.pronamespace "
                    "WHERE n.nspname='execbound' AND p.proname=ANY(:names)"
                ),
                {"names": list(FUNCTIONS)},
            ).all()
        )
    assert set(acls) == set(FUNCTIONS)
    for name, acl in acls.items():
        assert "execbound_app=X/" in acl, name
        assert "{=" not in acl and ",=" not in acl, name


def test_tb_only_an_admin_sets_the_policy(db, admin_engine, seeded):
    current, _, _ = verified(db, admin_engine, seeded)
    tenant = current.identity.tenant_id

    def allowed():
        with db.transaction(tenant) as conn:
            return trusted_browsers.allowed(conn, tenant)

    def policy():
        with admin_engine.begin() as conn:
            return (
                conn.execute(
                    text("SELECT * FROM execbound.account_security_policy WHERE tenant_id=:t"),
                    {"t": tenant},
                )
                .mappings()
                .one()
            )

    assert allowed()
    trusted_browsers.set_allowed(db, current, False, clock=CLOCK)
    assert not allowed()
    row = policy()
    # No requirement was set before: the row the switch creates keeps the default one.
    assert row["requirement"] == "optional"
    assert row["changed_by"] == current.identity.principal_id
    assert row["allow_trusted_browsers"] is False
    trusted_browsers.set_allowed(db, current, True, clock=CLOCK)
    assert allowed()
    # The other workspace is unaffected, read from inside this one.
    trusted_browsers.set_allowed(db, current, False, clock=CLOCK)
    with db.transaction(tenant) as conn:
        assert trusted_browsers.allowed(conn, seeded["tenants"][1])
        assert not trusted_browsers.allowed(conn, tenant)
        # The read leaves the transaction in the workspace it was in.
        assert conn.execute(
            text("SELECT current_setting('execbound.tenant_id',true)")
        ).scalar_one() == str(tenant)

    principal, _ = enroll(admin_engine, tenant, email="approver@example.test")
    adopt(db, tenant, principal)
    approver = load_session(
        db,
        issue_session(db, sign_in_with_password(db, "approver@example.test", PASSWORD)).token,
    )
    assert approver.identity.kind == "HUMAN_APPROVER"
    with pytest.raises(mfa.MfaError) as refused:
        trusted_browsers.set_allowed(db, approver, True, clock=CLOCK)
    assert refused.value.code == "INVALID_IDENTITY"
    for actor in (principal, uuid4(), None):
        with db.transaction(tenant) as conn:
            with pytest.raises(DBAPIError, match="INVALID_IDENTITY"):
                conn.execute(
                    text("SELECT execbound.trusted_browser_policy(:t,:p,true,:n)"),
                    {"t": tenant, "p": actor, "n": CLOCK.now()},
                )
    # The function writes only the workspace the transaction is in.
    with db.transaction(tenant) as conn:
        with pytest.raises(DBAPIError, match="INVALID_TENANT"):
            conn.execute(
                text("SELECT execbound.trusted_browser_policy(:t,:p,true,:n)"),
                {
                    "t": seeded["tenants"][1],
                    "p": current.identity.principal_id,
                    "n": CLOCK.now(),
                },
            )
    assert not allowed()
    # Each change is in the workspace's audit chain, with the session that made it.
    assert policy_events(admin_engine, tenant) == [
        {"session_id": str(current.session_id), "allowed": allowed_value}
        for allowed_value in (False, True, False)
    ]
    # Allowing trust loosens every sign-in: an administrator whose factor was verified more
    # than thirty minutes ago steps up first, and nothing changes or is recorded until then.
    stale(admin_engine, tenant, current.session_id)
    with pytest.raises(mfa.MfaError) as refused:
        trusted_browsers.set_allowed(db, current, True, clock=CLOCK)
    assert refused.value.code == "RECENT_AUTH_REQUIRED"
    assert not allowed()
    assert len(policy_events(admin_engine, tenant)) == 3


def policy_events(engine, tenant):
    with engine.begin() as conn:
        return list(
            conn.execute(
                text(
                    "SELECT payload FROM execbound.audit_events WHERE tenant_id=:t "
                    "AND kind='account_security.trusted_browsers_changed' ORDER BY sequence"
                ),
                {"t": tenant},
            ).scalars()
        )


@pytest.mark.parametrize("case", ["trusted", "stale", "method", "earlier", "forbidden"])
def test_tb_grant_is_refused_when(db, admin_engine, seeded, case):
    """A trust records a verification the granting session holds itself, recent and by a real
    factor, in a workspace that allows trust; anything else is refused and nothing is kept."""
    if case == "trusted":
        # A sign-in a trust let through cannot grant another trust, with the original's
        # method and time or as `trusted` itself.
        current, account, _, assured = trusted_sign_in(db, admin_engine, seeded, 0)
    else:
        current, account, _ = verified(db, admin_engine, seeded)
        assured = assurance_of(admin_engine, current.identity.tenant_id, current.session_id)
    tenant = current.identity.tenant_id
    method, verified_at, code = assured["method"], assured["verified_at"], "RECENT_AUTH_REQUIRED"
    if case == "trusted":
        with pytest.raises(mfa.MfaError) as refused:
            trusted_browsers.grant(
                db, current, method="trusted", verified_at=verified_at, label=LABEL, clock=CLOCK
            )
        assert refused.value.code == "INVALID_FACTOR"
    elif case == "stale":
        stale(admin_engine, tenant, current.session_id)
        verified_at = assurance_of(admin_engine, tenant, current.session_id)["verified_at"]
    elif case == "method":
        method = "recovery"
    elif case == "earlier":
        verified_at -= timedelta(seconds=1)
    elif case == "forbidden":
        trusted_browsers.set_allowed(db, current, False, clock=CLOCK)
        code = "TRUST_NOT_ALLOWED"
    before = trust_rows(admin_engine, account)
    events = security_events(admin_engine, account)
    with pytest.raises(mfa.MfaError) as refused:
        trusted_browsers.grant(
            db, current, method=method, verified_at=verified_at, label=LABEL, clock=CLOCK
        )
    assert refused.value.code == code
    assert trust_rows(admin_engine, account) == before
    assert security_events(admin_engine, account) == events


def test_tb_a_session_holding_its_own_verification_keeps_it(db, admin_engine, seeded):
    """`trusted_browser_use` called on a session that already verified the current factor
    answers false and changes nothing: not its assurance, its token or the trust."""
    grant, current, account, _, _ = verified_pair(db, admin_engine, seeded)
    cookie, _, _ = granted(db, admin_engine, current)
    tenant = current.identity.tenant_id
    before = assurance_of(admin_engine, tenant, current.session_id)
    with db.transaction(tenant) as conn:
        account_context(conn, account)
        used = conn.execute(
            text("SELECT execbound.trusted_browser_use(:t,:s,:b,:h,:th,:ch,:n)"),
            {
                "t": tenant,
                "s": current.session_id,
                "b": browser_of(cookie),
                "h": hashlib.sha256(cookie.split(".")[2].encode("ascii")).hexdigest(),
                "th": "a" * 64,
                "ch": "b" * 64,
                "n": CLOCK.now(),
            },
        ).scalar_one()
    assert used is False
    assert assurance_of(admin_engine, tenant, current.session_id) == before
    assert before["method"] == "totp"
    assert load_session(db, grant.token).session_id == current.session_id
    assert trust_rows(admin_engine, account)[0]["last_used_at"] is None


def test_tb_two_grants_at_once_leave_ten_live_trusts(db, admin_engine, seeded):
    """The tenth and eleventh trusts granted at the same moment, on real PostgreSQL: the
    account lock serializes them, so exactly ten stay live and the oldest is removed."""
    current, account, _ = verified(db, admin_engine, seeded)
    for _ in range(9):
        granted(db, admin_engine, current)
    with ThreadPoolExecutor(max_workers=2) as pool:
        cookies = list(pool.map(lambda _: granted(db, admin_engine, current)[0], range(2)))
    rows = trust_rows(admin_engine, account)
    assert len(rows) == 11
    assert [row["revoked_at"] is None for row in rows] == [False] + [True] * 10
    live = {trust.browser_id for trust in trusted_browsers.listed(db, current, clock=CLOCK)}
    assert len(live) == 10 and {browser_of(cookie) for cookie in cookies} <= live
    assert security_events(admin_engine, account).count("trusted_browser_removed") == 1


def migration():
    path = Path(__file__).parents[1] / "migrations" / "versions" / f"{TARGET}.py"
    spec = importlib.util.spec_from_file_location(TARGET, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def catalog(conn):
    """What 0101 adds or changes, as the database holds it."""
    constraints = dict(
        conn.execute(
            text(
                "SELECT conname, pg_get_constraintdef(oid) FROM pg_constraint "
                "WHERE conrelid = ANY(ARRAY['execbound.session_assurance'::regclass, "
                "'execbound.account_security_policy'::regclass, "
                "'execbound.user_security_events'::regclass])"
            )
        ).all()
    )
    columns = set(
        conn.execute(
            text(
                "SELECT table_name || '.' || column_name FROM information_schema.columns "
                "WHERE table_schema='execbound' AND table_name IN "
                "('session_assurance','account_security_policy','user_security_events')"
            )
        ).scalars()
    )
    functions = set(
        conn.execute(
            text(
                "SELECT p.proname FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace "
                "WHERE n.nspname='execbound' AND (p.proname LIKE 'trusted_browser%' "
                "OR p.proname='account_sign_out_others')"
            )
        ).scalars()
    )
    table = conn.execute(text("SELECT to_regclass('execbound.trusted_browsers')")).scalar_one()
    patched = dict(
        conn.execute(
            text(
                "SELECT p.proname, pg_get_functiondef(p.oid) || CAST(p.proacl AS text) "
                "FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace "
                "WHERE n.nspname='execbound' AND p.proname=ANY(:names)"
            ),
            {"names": list(PATCHED)},
        ).all()
    )
    return constraints, columns, functions, table, patched


def test_tb_downgrade_drops_everything_and_restores_the_method_check(db, admin_engine, seeded):
    history = ScriptDirectory.from_config(alembic_config()).iterate_revisions(
        database.SCHEMA_REVISION, "base"
    )
    assert TARGET in {script.revision for script in history}
    assert migration().down_revision == BEFORE
    # A session signed in through trust holds the one method the old check refuses.
    current, account, _ = verified(db, admin_engine, seeded)
    cookie, _, _ = granted(db, admin_engine, current)
    _, pending = signed_in_again(db)
    assert trusted_browsers.apply(db, pending, cookie, clock=CLOCK)
    tenant = pending.identity.tenant_id
    assert assurance_of(admin_engine, tenant, pending.session_id)["method"] == "trusted"
    config = alembic_config()
    with admin_engine.connect() as conn:
        head = catalog(conn)
    assert head[2] == set(FUNCTIONS) and head[3] is not None
    assert "'trusted'::text" in head[0]["session_assurance_method_check"]
    assert "account_security_policy.allow_trusted_browsers" in head[1]
    assert set(head[4]) == set(PATCHED)
    assert all(definition.count("method<>'trusted'") == 1 for definition in head[4].values())
    try:
        command.downgrade(config, BEFORE)
        # The trusted assurance is gone, so that session owes its factor again; the verified
        # one is kept.
        assert assurance_of(admin_engine, tenant, pending.session_id) is None
        assert assurance_of(admin_engine, tenant, current.session_id)["method"] == "totp"
        with admin_engine.connect() as conn:
            before = catalog(conn)
        assert before[0]["session_assurance_method_check"] == (
            "CHECK ((method = ANY (ARRAY['totp'::text, 'recovery'::text, 'passkey'::text])))"
        )
        assert "account_security_policy.allow_trusted_browsers" not in before[1]
        assert before[2] == set() and before[3] is None
        assert all("method<>'trusted'" not in definition for definition in before[4].values())
        command.upgrade(config, TARGET)
        with admin_engine.connect() as conn:
            assert catalog(conn) == head
        command.downgrade(config, BEFORE)
        with admin_engine.connect() as conn:
            assert catalog(conn) == before
    finally:
        empty_schema(admin_engine)
        command.upgrade(config, "head")
