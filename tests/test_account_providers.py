# SPDX-License-Identifier: AGPL-3.0-only
"""A verified email is not permission to attach a new authentication method."""

from types import SimpleNamespace

import pytest
from sqlalchemy import text
from test_workspace_accounts import adopt, enroll, second_membership

from execbound.passwords import bind_identity, sign_in_with_password
from execbound.resolution.models import SystemClock
from execbound.signin import ExternalAccount, SignInRefused, new_flow
from execbound.surfaces.sessions import issue_session, load_session
from execbound.surfaces.sign_in_pages import _link

pytestmark = pytest.mark.integration


@pytest.mark.parametrize("method", ["password", "google"])
def test_directory_required_membership_does_not_block_personal_access_elsewhere(
    db, admin_engine, seeded, method
):
    from test_directory_store import RING, FixedClock, enabled, person

    from execbound.directory import DirectoryConfig

    a, b = seeded["tenants"]
    principal, _ = enroll(admin_engine, a)
    bind_identity(
        db,
        a,
        principal,
        provider="google",
        subject="retained",
        email="member@example.test",
        display_name=None,
    )
    account = adopt(db, a, principal)
    second_membership(admin_engine, seeded, account)
    provider = enabled(
        db,
        DirectoryConfig(RING, "https://app.example"),
        {"tenant": a, "admin": person(admin_engine, a, "ADMIN")},
        FixedClock(),
    )
    with admin_engine.begin() as conn:
        conn.execute(
            text(
                "UPDATE execbound.identity_providers SET require_sign_in=true "
                "WHERE tenant_id=:t AND provider_id=:p"
            ),
            {"t": a, "p": provider},
        )
    identity = (
        sign_in_with_password(db, "member@example.test", "a retained example passphrase")
        if method == "password"
        else _link(
            SimpleNamespace(db=db, clock=SystemClock()),
            ExternalAccount("google", "retained", "member@example.test", None),
        )
    )
    assert identity.tenant_id == b
    assert load_session(db, issue_session(db, identity).token).account_id == account


def test_provider_link_expiring_recent_authentication_is_a_safe_refusal(db, admin_engine, seeded):
    from datetime import timedelta

    from test_human_sessions import FixedClock

    from execbound.account_links import begin_link, finish_link

    tenant = seeded["tenants"][0]
    principal, _ = enroll(admin_engine, tenant)
    account = adopt(db, tenant, principal)
    second_membership(admin_engine, seeded, account)
    clock = FixedClock(SystemClock().now())
    identity = sign_in_with_password(
        db, "member@example.test", "a retained example passphrase", clock=clock
    )
    grant = issue_session(db, identity, clock=clock)
    session = load_session(db, grant.token, clock=clock)
    clock.value += timedelta(minutes=4, seconds=59)
    flow = new_flow()
    token = begin_link(db, session, "google", flow, clock=clock)
    clock.value += timedelta(seconds=2)
    with pytest.raises(SignInRefused) as refused:
        finish_link(
            db,
            token,
            flow,
            ExternalAccount("google", "new", "member@example.test", None),
            clock=clock,
        )
    assert refused.value.code == "LINK_REFUSED"


def test_unknown_provider_cannot_attach_by_matching_email(db, admin_engine, seeded):
    tenant = seeded["tenants"][0]
    principal, _ = enroll(admin_engine, tenant)
    account = adopt(db, tenant, principal)
    runtime = SimpleNamespace(db=db, clock=SystemClock())
    with pytest.raises(SignInRefused):
        _link(runtime, ExternalAccount("google", "new-subject", "member@example.test", None))
    with admin_engine.connect() as conn:
        assert (
            conn.execute(
                text("SELECT count(*) FROM execbound.user_identities WHERE account_id=:a"),
                {"a": account},
            ).scalar_one()
            == 0
        )


def test_bound_provider_authentication_survives_original_workspace_removal(
    db, admin_engine, seeded
):
    a, b = seeded["tenants"]
    principal, _ = enroll(admin_engine, a)
    bind_identity(
        db,
        a,
        principal,
        provider="google",
        subject="retained-subject",
        email="member@example.test",
        display_name="Member",
    )
    account = adopt(db, a, principal)
    second_membership(admin_engine, seeded, account)
    with admin_engine.begin() as conn:
        conn.execute(text("UPDATE execbound.tenants SET active=false WHERE tenant_id=:t"), {"t": a})
    runtime = SimpleNamespace(db=db, clock=SystemClock())
    identity = _link(
        runtime, ExternalAccount("google", "retained-subject", "changed@example.test", "New hint")
    )
    assert identity.tenant_id == b
    assert load_session(db, issue_session(db, identity).token).account_id == account


def test_new_legacy_password_enrollment_enters_account_authentication(db, admin_engine, seeded):
    tenant = seeded["tenants"][0]
    enroll(admin_engine, tenant)
    identity = sign_in_with_password(db, "member@example.test", "a retained example passphrase")
    granted = issue_session(db, identity)
    assert granted.account_token is not None
    assert load_session(db, granted.token).account_id is not None


def test_provider_link_requires_verified_recent_personal_session_and_fresh_bound_proof(
    db, admin_engine, seeded
):
    from execbound.account_links import begin_link, finish_link

    tenant = seeded["tenants"][0]
    principal, _ = enroll(admin_engine, tenant)
    account = adopt(db, tenant, principal)
    identity = sign_in_with_password(db, "member@example.test", "a retained example passphrase")
    grant = issue_session(db, identity)
    session = load_session(db, grant.token)
    flow = new_flow()
    with pytest.raises(SignInRefused):
        begin_link(db, session, "google", flow)
    with admin_engine.begin() as conn:
        conn.execute(
            text("UPDATE execbound.user_accounts SET email_verified_at=now() WHERE account_id=:a"),
            {"a": account},
        )
    token = begin_link(db, session, "google", flow)
    proof = ExternalAccount("google", "explicit-subject", "member@example.test", "Member")
    with pytest.raises(SignInRefused):
        finish_link(db, token, new_flow(), proof)
    finish_link(db, token, flow, proof)
    runtime = SimpleNamespace(db=db, clock=SystemClock())
    assert _link(runtime, proof).principal_id == principal
    with pytest.raises(SignInRefused):
        finish_link(db, token, flow, proof)


def test_provider_link_ends_when_initiating_account_session_is_revoked(db, admin_engine, seeded):
    from execbound.account_links import begin_link, finish_link

    tenant = seeded["tenants"][0]
    principal, _ = enroll(admin_engine, tenant)
    account = adopt(db, tenant, principal)
    second_membership(admin_engine, seeded, account)
    grant = issue_session(
        db, sign_in_with_password(db, "member@example.test", "a retained example passphrase")
    )
    session = load_session(db, grant.token)
    flow = new_flow()
    token = begin_link(db, session, "google", flow)
    with admin_engine.begin() as conn:
        conn.execute(
            text("UPDATE execbound.account_sessions SET revoked_at=now() WHERE account_id=:a"),
            {"a": account},
        )
    with pytest.raises(SignInRefused):
        finish_link(db, token, flow, ExternalAccount("google", "new", "member@example.test", None))


def test_provider_link_waits_for_mutations_in_other_workspaces(db, admin_engine, seeded):
    from concurrent.futures import ThreadPoolExecutor, TimeoutError
    from threading import Event

    from execbound.account_links import begin_link, finish_link
    from execbound.execution.store import fence

    tenant, other = seeded["tenants"]
    principal, _ = enroll(admin_engine, tenant)
    account = adopt(db, tenant, principal)
    second_membership(admin_engine, seeded, account)
    grant = issue_session(
        db, sign_in_with_password(db, "member@example.test", "a retained example passphrase")
    )
    flow = new_flow()
    token = begin_link(db, load_session(db, grant.token), "google", flow)
    started = Event()

    def complete():
        started.set()
        finish_link(db, token, flow, ExternalAccount("google", "new", "member@example.test", None))

    with ThreadPoolExecutor(max_workers=1) as pool:
        with db.transaction(other) as conn:
            fence(conn, other, SystemClock())
            future = pool.submit(complete)
            assert started.wait(5)
            # Linking revokes account-wide authority; an already fenced operation in B
            # must finish before the new global version commits from A.
            with pytest.raises(TimeoutError):
                future.result(timeout=0.5)
        future.result(timeout=5)
