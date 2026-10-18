# SPDX-License-Identifier: AGPL-3.0-only
"""An account with no password sets its first one from Account security (#593).

An account made through Google or GitHub has no password, and `change_password` refuses an
account without one. `set_first_password` lets that account add one under the bar provider
linking already uses: a sign-in within five minutes, a fresh verification when a factor is on,
and a verified address. It never replaces a password, and the database refuses it as well as
the Python check does, so a caller that skips the check cannot use the door either.
"""

from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from uuid import uuid4

import pytest
from signup_fixtures import stack as stack
from sqlalchemy import text
from test_migration_without_bypass import restricted as restricted
from test_workspace_accounts import adopt, enroll

from execbound import mfa
from execbound.envelope import KeyRing
from execbound.identity import AuthenticationFailed
from execbound.passwords import (
    PasswordError,
    set_first_password,
    sign_in_with_password,
    verify_password,
)
from execbound.resolution.models import SystemClock
from execbound.signin import ExternalAccount
from execbound.surfaces.sessions import SessionError, issue_session, load_session
from execbound.surfaces.sign_in_pages import _link
from execbound.user_accounts import password_record

pytestmark = pytest.mark.integration

ADDRESS = "provider@example.test"
CHOSEN = "a first chosen passphrase"


def provider_account(db, admin_engine, tenant):
    """An account that exists only through a Google identity, signed in with it just now."""
    return provider_account_in(db, admin_engine, tenant, uuid4())


def provider_account_in(db, engine, tenant, principal):
    with engine.begin() as conn:
        # Fenced as the product writes: it limits nothing for an owner that bypasses row
        # security, and everything for the restricted owner below, which does not.
        conn.execute(text("SELECT set_config('execbound.tenant_id', :t, true)"), {"t": str(tenant)})
        conn.execute(
            text(
                "INSERT INTO execbound.principals(tenant_id,principal_id,kind,email) "
                "VALUES(:t,:p,'HUMAN_APPROVER',:e)"
            ),
            {"t": tenant, "p": principal, "e": ADDRESS},
        )
        conn.execute(
            text(
                "INSERT INTO execbound.principal_identities(tenant_id,principal_id,"
                "provider,subject,email,created_at) VALUES(:t,:p,'google','subject-1',:e,now())"
            ),
            {"t": tenant, "p": principal, "e": ADDRESS},
        )
    account = adopt(db, tenant, principal)
    identity = _link(
        SimpleNamespace(db=db, clock=SystemClock()),
        ExternalAccount("google", "subject-1", ADDRESS, None),
    )
    return account, identity


def signed_in(db, identity):
    grant = issue_session(db, identity)
    return grant, load_session(db, grant.token)


def events(admin_engine, tenant, kind):
    with admin_engine.connect() as conn:
        return [
            row
            for row in conn.execute(
                text(
                    "SELECT payload FROM execbound.audit_events WHERE tenant_id=:t AND kind=:k "
                    "ORDER BY sequence"
                ),
                {"t": tenant, "k": kind},
            ).scalars()
        ]


def security_kinds(admin_engine, account):
    with admin_engine.connect() as conn:
        return list(
            conn.execute(
                text("SELECT kind FROM execbound.user_security_events WHERE account_id=:a"),
                {"a": account},
            ).scalars()
        )


def write_directly(db, session, record):
    """The database function with no Python check in front of it, as a skipped check would."""
    clock = SystemClock()
    with mfa._transaction(db, session, clock) as conn:
        mfa._change(conn, session, clock.now(), "password_set", record.parameters())


def test_a_provider_account_sets_a_first_password_and_signs_in_with_it(db, admin_engine, seeded):
    tenant = seeded["tenants"][0]
    account, identity = provider_account(db, admin_engine, tenant)
    old, _ = signed_in(db, identity)
    grant, session = signed_in(db, identity)
    assert password_record(db, account) is None
    with pytest.raises(AuthenticationFailed):
        sign_in_with_password(db, ADDRESS, CHOSEN)

    set_first_password(db, session, CHOSEN)

    record = password_record(db, account)
    assert record is not None and record.algorithm == "scrypt"
    assert verify_password(record, CHOSEN)
    assert sign_in_with_password(db, ADDRESS, CHOSEN).principal_id == identity.principal_id
    # Recorded like every other change on the page, and never with the password.
    [payload] = events(admin_engine, tenant, "account_security.password_set")
    assert set(payload) == {"session_id"}
    assert "password_set" in security_kinds(admin_engine, account)
    # The change ends the account's other sessions, as every security change does, and keeps
    # the one that made it.
    with pytest.raises(SessionError):
        load_session(db, old.token)
    assert load_session(db, grant.token).account_id == account


def test_an_account_with_a_password_cannot_set_another_this_way(db, admin_engine, seeded):
    from execbound.passwords import hash_password

    tenant = seeded["tenants"][0]
    principal, _ = enroll(admin_engine, tenant)
    account = adopt(db, tenant, principal)
    _, session = signed_in(
        db, sign_in_with_password(db, "member@example.test", "a retained example passphrase")
    )
    before = password_record(db, account)
    with pytest.raises(PasswordError) as refused:
        set_first_password(db, session, CHOSEN)
    assert refused.value.code == "PASSWORD_EXISTS"
    # The database refuses it too, without the Python check in front.
    with pytest.raises(mfa.MfaError):
        write_directly(db, session, hash_password(CHOSEN))
    assert password_record(db, account) == before
    assert sign_in_with_password(db, "member@example.test", "a retained example passphrase")
    assert events(admin_engine, tenant, "account_security.password_set") == []


def test_a_sign_in_older_than_five_minutes_is_refused(db, admin_engine, seeded):
    from execbound.passwords import hash_password

    tenant = seeded["tenants"][0]
    account, identity = provider_account(db, admin_engine, tenant)
    _, session = signed_in(db, identity)
    with admin_engine.begin() as conn:
        conn.execute(
            text(
                "UPDATE execbound.account_sessions SET created_at=now()-interval '6 minutes' "
                "WHERE account_id=:a"
            ),
            {"a": account},
        )
    with pytest.raises(PasswordError) as refused:
        set_first_password(db, session, CHOSEN)
    assert refused.value.code == "RECENT_AUTH_REQUIRED"
    with pytest.raises(mfa.MfaError):
        write_directly(db, session, hash_password(CHOSEN))
    assert password_record(db, account) is None


def test_an_enabled_factor_must_have_been_verified_recently(db, admin_engine, seeded):
    from execbound.passwords import hash_password

    tenant = seeded["tenants"][0]
    account, identity = provider_account(db, admin_engine, tenant)
    grant, session = signed_in(db, identity)
    ring = KeyRing("test", {"test": b"m" * 32})
    secret = mfa.begin_enrollment(db, session, ring)
    codes = mfa.confirm_enrollment(
        db, session, ring, mfa.totp(secret, int(datetime.now(UTC).timestamp() // 30))
    )
    session = load_session(db, grant.token)
    with admin_engine.begin() as conn:
        conn.execute(
            text("UPDATE execbound.session_assurance SET verified_at=:then WHERE session_id=:s"),
            {"then": datetime.now(UTC) - timedelta(minutes=31), "s": session.session_id},
        )
    with pytest.raises(PasswordError) as refused:
        set_first_password(db, session, CHOSEN)
    assert refused.value.code == "RECENT_AUTH_REQUIRED"
    with pytest.raises(mfa.MfaError):
        write_directly(db, session, hash_password(CHOSEN))
    assert password_record(db, account) is None
    assert mfa.verify_factor(db, session, ring, codes[0])
    set_first_password(db, load_session(db, grant.token), CHOSEN)
    assert verify_password(password_record(db, account), CHOSEN)


def test_a_password_below_the_minimum_is_refused_and_nothing_is_written(db, admin_engine, seeded):
    tenant = seeded["tenants"][0]
    account, identity = provider_account(db, admin_engine, tenant)
    _, session = signed_in(db, identity)
    with pytest.raises(PasswordError) as refused:
        set_first_password(db, session, "too short")
    assert refused.value.code == "INVALID_PASSWORD"
    assert password_record(db, account) is None
    assert events(admin_engine, tenant, "account_security.password_set") == []


def test_a_first_password_is_written_by_an_owner_that_does_not_bypass_row_security(stack):
    """`user_security_change` is `SECURITY DEFINER`. The suite's owner bypasses row security, so
    a switch the function forgot would pass every test above; the hosted owner does not, so the
    insert is proven here under an owner with its attributes, and read back through it fenced
    to the account, exactly as the product reads it."""
    from test_migration_without_bypass import fenced

    engine, db = stack
    tenant, principal = uuid4(), uuid4()
    with engine.begin() as conn:
        fenced(conn, tenant)
        conn.execute(
            text("INSERT INTO execbound.tenants(tenant_id, name, active) VALUES (:t, :n, true)"),
            {"t": tenant, "n": f"tenant-{tenant.hex[:8]}"},
        )
    account, identity = provider_account_in(db, engine, tenant, principal)
    _, session = signed_in(db, identity)
    set_first_password(db, session, CHOSEN)
    with engine.begin() as conn:
        conn.execute(
            text("SELECT set_config('execbound.account_id', :a, true)"), {"a": str(account)}
        )
        stored = conn.execute(
            text("SELECT algorithm FROM execbound.user_passwords WHERE account_id=:a"),
            {"a": account},
        ).scalar_one()
    assert stored == "scrypt"
    assert sign_in_with_password(db, ADDRESS, CHOSEN).principal_id == identity.principal_id
