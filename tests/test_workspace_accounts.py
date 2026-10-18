# SPDX-License-Identifier: AGPL-3.0-only
"""Account ownership must not confer authority outside a current membership."""

import importlib.util
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from uuid import uuid4

import pytest
from sqlalchemy import text

from execbound import mfa
from execbound.db import check_runtime
from execbound.envelope import KeyRing, seal
from execbound.identity import AuthenticationFailed
from execbound.passwords import (
    PasswordError,
    change_password,
    hash_password,
    issue_reset,
    mint_session_credential,
    redeem_reset,
    sign_in_with_password,
)
from execbound.surfaces.sessions import SessionError, issue_session, load_session

pytestmark = pytest.mark.integration


def enroll(engine, tenant, *, email="member@example.test", kind="HUMAN_APPROVER"):
    """A retained password enrollment, independent of new account-store code."""
    principal = uuid4()
    record = hash_password("a retained example passphrase")
    with engine.begin() as conn:
        conn.execute(text("SELECT set_config('execbound.tenant_id', :t, true)"), {"t": str(tenant)})
        conn.execute(
            text(
                "INSERT INTO execbound.principals(tenant_id,principal_id,kind,email) "
                "VALUES(:t,:p,:k,:e)"
            ),
            {"t": tenant, "p": principal, "k": kind, "e": email},
        )
        conn.execute(
            text(
                "INSERT INTO execbound.principal_passwords(tenant_id,principal_id,"
                "algorithm,n,r,p,dklen,salt,hash,created_at,updated_at) "
                "VALUES(:t,:id,:algorithm,:n,:r,:p,:dklen,:salt,:hash,now(),now())"
            ),
            {"t": tenant, "id": principal, **record.parameters()},
        )
    return principal, record


def adopt(db, tenant, principal):
    with db.transaction(tenant) as conn:
        return conn.execute(
            text("SELECT execbound.account_adopt(:p)"), {"p": principal}
        ).scalar_one()


def test_adoption_preserves_hash_and_ids_without_claiming_email_verification(
    db, admin_engine, seeded
):
    tenant = seeded["tenants"][0]
    principal, record = enroll(admin_engine, tenant)
    account = adopt(db, tenant, principal)
    assert account is not None
    assert adopt(db, tenant, principal) == account
    with admin_engine.begin() as conn:
        saved = (
            conn.execute(
                text(
                    "SELECT a.email,a.email_verified_at,w.hash,m.principal_id "
                    "FROM execbound.user_accounts a "
                    "JOIN execbound.user_passwords w USING(account_id) "
                    "JOIN execbound.workspace_memberships m USING(account_id) "
                    "WHERE a.account_id=:a"
                ),
                {"a": account},
            )
            .mappings()
            .one()
        )
        assert dict(saved) == {
            "email": "member@example.test",
            "email_verified_at": None,
            "hash": record.hash,
            "principal_id": principal,
        }


def test_workspace_admin_cannot_reset_an_adopted_account(db, admin_engine, seeded):
    tenant = seeded["tenants"][0]
    principal, _ = enroll(admin_engine, tenant)
    admin, _ = enroll(admin_engine, tenant, email="admin@example.test", kind="ADMIN")
    adopt(db, tenant, principal)
    with pytest.raises(PasswordError) as refused:
        issue_reset(db, tenant, admin, principal)
    assert refused.value.code == "ACCOUNT_OWNER_REQUIRED"


def test_tenant_context_cannot_read_global_authentication_material(db, admin_engine, seeded):
    tenant = seeded["tenants"][0]
    principal, _ = enroll(admin_engine, tenant)
    adopt(db, tenant, principal)
    with db.transaction(tenant) as conn:
        check_runtime(conn)
        assert conn.execute(text("SELECT count(*) FROM execbound.user_accounts")).scalar_one() == 0
        assert conn.execute(text("SELECT count(*) FROM execbound.user_passwords")).scalar_one() == 0
        assert (
            conn.execute(text("SELECT count(*) FROM execbound.workspace_memberships")).scalar_one()
            == 1
        )
    with db.transaction(seeded["tenants"][1]) as conn:
        assert (
            conn.execute(text("SELECT count(*) FROM execbound.workspace_memberships")).scalar_one()
            == 0
        )


def test_unenrolled_human_is_not_silently_a_verified_account(db, admin_engine, seeded):
    tenant = seeded["tenants"][0]
    principal = uuid4()
    with admin_engine.begin() as conn:
        conn.execute(
            text(
                "INSERT INTO execbound.principals(tenant_id,principal_id,kind,email) "
                "VALUES(:t,:p,'ADMIN','operator@example.test')"
            ),
            {"t": tenant, "p": principal},
        )
    assert adopt(db, tenant, principal) is None


def test_adoption_retains_factor_replay_state_and_passkey_handle(db, admin_engine, seeded):
    tenant = seeded["tenants"][0]
    principal, _ = enroll(admin_engine, tenant)
    with admin_engine.begin() as conn:
        conn.execute(
            text(
                "INSERT INTO execbound.account_factors(tenant_id,principal_id,sealed,"
                "key_id,enabled_at,version,last_step,recovery_hashes,failures,locked_until) "
                "VALUES(:t,:p,'retained-ciphertext','key-v1',now(),4,123456,'[\"unused\"]',"
                "5,now()+interval '10 minutes')"
            ),
            {"t": tenant, "p": principal},
        )
        conn.execute(
            text(
                "INSERT INTO execbound.account_passkeys(tenant_id,principal_id,"
                "credential_id,public_key,sign_count,created_at) "
                "VALUES(:t,:p,'ab12','abcd',19,now())"
            ),
            {"t": tenant, "p": principal},
        )
    account = adopt(db, tenant, principal)
    with admin_engine.begin() as conn:
        factor = (
            conn.execute(
                text("SELECT * FROM execbound.user_factors WHERE account_id=:a"), {"a": account}
            )
            .mappings()
            .one()
        )
        assert factor["tenant_id"] == tenant
        assert factor["principal_id"] == principal
        assert factor["sealed"] == "retained-ciphertext"
        assert factor["version"] == 4
        assert factor["last_step"] == 123456
        assert factor["recovery_hashes"] == ["unused"]
        assert factor["failures"] == 5
        assert factor["locked_until"] is not None
        key = conn.execute(
            text("SELECT principal_id,sign_count FROM execbound.user_passkeys WHERE account_id=:a"),
            {"a": account},
        ).one()
        assert key == (principal, 19)


def test_provider_only_enrollment_is_preserved_as_verified_account(db, admin_engine, seeded):
    tenant, principal = seeded["tenants"][0], uuid4()
    with admin_engine.begin() as conn:
        conn.execute(
            text(
                "INSERT INTO execbound.principals(tenant_id,principal_id,kind,email) "
                "VALUES(:t,:p,'HUMAN_APPROVER','provider@example.test')"
            ),
            {"t": tenant, "p": principal},
        )
        conn.execute(
            text(
                "INSERT INTO execbound.principal_identities(tenant_id,principal_id,"
                "provider,subject,email,created_at) "
                "VALUES(:t,:p,'google','existing-subject','provider@example.test',now())"
            ),
            {"t": tenant, "p": principal},
        )
    account = adopt(db, tenant, principal)
    assert account is not None
    with admin_engine.begin() as conn:
        assert (
            conn.execute(
                text("SELECT email_verified_at FROM execbound.user_accounts WHERE account_id=:a"),
                {"a": account},
            ).scalar_one()
            is not None
        )
        assert (
            conn.execute(
                text("SELECT subject FROM execbound.user_identities WHERE account_id=:a"),
                {"a": account},
            ).scalar_one()
            == "existing-subject"
        )


def test_concurrent_adoption_returns_the_same_account(db, admin_engine, seeded):
    tenant = seeded["tenants"][0]
    principal, _ = enroll(admin_engine, tenant)
    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(lambda _: adopt(db, tenant, principal), range(2)))
    assert results[0] == results[1]


def test_existing_community_claimant_consumes_allocation_without_promoting_other_admins(
    db,
    admin_engine,
    seeded,
):
    tenant, unresolved = seeded["tenants"]
    claimant, _ = enroll(admin_engine, tenant, kind="ADMIN")
    promoted, _ = enroll(admin_engine, tenant, kind="ADMIN", email="promoted@example.test")
    account = adopt(db, tenant, claimant)
    other_account = adopt(db, tenant, promoted)
    from execbound.audit import append_event

    with db.transaction(tenant) as conn:
        append_event(
            conn, tenant, claimant, "tenant.claimed", {"principal_id": str(claimant), "slot": 1}
        )
    with admin_engine.begin() as conn:
        for t, slot in ((tenant, 1), (unresolved, 2)):
            conn.execute(
                text(
                    "INSERT INTO execbound.onboarding_slots(tenant_id,slot,seed,"
                    "seeded_at,claimed_at,community_at) VALUES(:t,:s,'account-test',"
                    "now(),now(),now())"
                ),
                {"t": t, "s": slot},
            )
        spec = importlib.util.spec_from_file_location(
            "accounts_migration", Path("migrations/versions/0054_account_memberships.py")
        )
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        module.backfill_ownership(conn)
        module.backfill_ownership(conn)
        rows = conn.execute(
            text(
                "SELECT tenant_id,account_id,state FROM "
                "execbound.community_allocations ORDER BY tenant_id"
            )
        ).all()
        assert set(rows) == {(tenant, account, "consumed"), (unresolved, None, "unresolved")}
        assert other_account not in {row.account_id for row in rows}


@pytest.mark.parametrize(
    "ambiguous",
    [
        {"slot": 1},
        {"principal_id": "invalid", "slot": 1},
        {"slot": 2, "principal_id": "same"},
        {"principal_id": "same"},
        {"slot": 1, "principal_id": "other"},
    ],
)
def test_community_ownership_with_any_ambiguous_claim_stays_unresolved(
    db, admin_engine, seeded, ambiguous
):
    from execbound.audit import append_event

    tenant = seeded["tenants"][0]
    claimant, _ = enroll(admin_engine, tenant, kind="ADMIN")
    adopt(db, tenant, claimant)
    extra = dict(ambiguous)
    if extra.get("principal_id") == "same":
        extra["principal_id"] = str(claimant)
    elif extra.get("principal_id") == "other":
        extra["principal_id"] = str(uuid4())
    with db.transaction(tenant) as conn:
        append_event(
            conn, tenant, claimant, "tenant.claimed", {"principal_id": str(claimant), "slot": 1}
        )
        append_event(conn, tenant, claimant, "tenant.claimed", extra)
    with admin_engine.begin() as conn:
        conn.execute(
            text(
                "INSERT INTO execbound.onboarding_slots(tenant_id,slot,seed,"
                "seeded_at,claimed_at,community_at) "
                "VALUES(:t,1,'ambiguous-test',now(),now(),now())"
            ),
            {"t": tenant},
        )
        spec = importlib.util.spec_from_file_location(
            "accounts_migration", Path("migrations/versions/0054_account_memberships.py")
        )
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        module.backfill_ownership(conn)
        assert conn.execute(
            text("SELECT account_id,state FROM execbound.community_allocations WHERE tenant_id=:t"),
            {"t": tenant},
        ).one() == (None, "unresolved")


def second_membership(engine, seeded, account):
    return membership_in(engine, account, seeded["tenants"][1])


def membership_in(engine, account, tenant, *, principal=None, kind="HUMAN_APPROVER"):
    """A verified account's membership in `tenant`: a new principal of `kind`, or `principal`."""
    with engine.begin() as conn:
        conn.execute(
            text("UPDATE execbound.user_accounts SET email_verified_at=now() WHERE account_id=:a"),
            {"a": account},
        )
        if principal is None:
            principal = uuid4()
            conn.execute(
                text(
                    "INSERT INTO execbound.principals(tenant_id,principal_id,kind) VALUES(:t,:p,:k)"
                ),
                {"t": tenant, "p": principal, "k": kind},
            )
        conn.execute(
            text(
                "INSERT INTO execbound.workspace_memberships(account_id,tenant_id,"
                "principal_id) VALUES(:a,:t,:p)"
            ),
            {"a": account, "t": tenant, "p": principal},
        )
    return principal


def test_password_account_survives_deactivation_of_original_workspace(db, admin_engine, seeded):
    tenant = seeded["tenants"][0]
    principal, _ = enroll(admin_engine, tenant, kind="ADMIN")
    account = adopt(db, tenant, principal)
    other = second_membership(admin_engine, seeded, account)
    with admin_engine.begin() as conn:
        conn.execute(
            text("UPDATE execbound.tenants SET active=false WHERE tenant_id=:t"), {"t": tenant}
        )
    identity = sign_in_with_password(db, "member@example.test", "a retained example passphrase")
    assert identity.tenant_id == seeded["tenants"][1]
    assert identity.principal_id == other
    assert identity.kind == "HUMAN_APPROVER"
    grant = issue_session(db, identity)
    assert grant.account_token.startswith("as1.")
    assert load_session(db, grant.token).account_id == account


def test_account_revocation_ends_existing_and_new_personal_sessions(db, admin_engine, seeded):
    tenant = seeded["tenants"][0]
    principal, _ = enroll(admin_engine, tenant)
    account = adopt(db, tenant, principal)
    grant = issue_session(
        db, sign_in_with_password(db, "member@example.test", "a retained example passphrase")
    )
    with admin_engine.begin() as conn:
        conn.execute(
            text("UPDATE execbound.user_accounts SET active=false WHERE account_id=:a"),
            {"a": account},
        )
    with pytest.raises(SessionError):
        load_session(db, grant.token)
    with pytest.raises(AuthenticationFailed):
        sign_in_with_password(db, "member@example.test", "a retained example passphrase")


def test_legacy_totp_and_recovery_work_in_b_after_a_is_disabled(db, admin_engine, seeded):
    import json
    from datetime import UTC, datetime

    tenant = seeded["tenants"][0]
    principal, _ = enroll(admin_engine, tenant)
    ring = KeyRing("test", {"test": b"m" * 32})
    seed = "JBSWY3DPEHPK3PXP"
    sealed, key = seal(ring, seed, tenant, principal, "authenticator_seed")
    shown, hashes = mfa.new_recovery_codes(principal)
    step = int(datetime.now(UTC).timestamp() // 30)
    with admin_engine.begin() as conn:
        conn.execute(
            text(
                "INSERT INTO execbound.account_factors(tenant_id,principal_id,sealed,"
                "key_id,enabled_at,version,last_step,recovery_hashes) "
                "VALUES(:t,:p,:s,:k,now(),2,:step,CAST(:codes AS jsonb))"
            ),
            {
                "t": tenant,
                "p": principal,
                "s": sealed,
                "k": key,
                "step": step - 1,
                "codes": json.dumps(hashes[1:]),
            },
        )
    account = adopt(db, tenant, principal)
    second_membership(admin_engine, seeded, account)
    with admin_engine.begin() as conn:
        conn.execute(
            text("UPDATE execbound.tenants SET active=false WHERE tenant_id=:t"), {"t": tenant}
        )
    identity = sign_in_with_password(db, "member@example.test", "a retained example passphrase")
    grant = issue_session(db, identity)
    assert grant.mfa_required
    pending = load_session(db, grant.token, allow_pending_mfa=True)
    assert not mfa.verify_factor(db, pending, ring, shown[0])  # consumed before migration
    assert mfa.verify_factor(db, pending, ring, mfa.totp(seed, step))
    assert not load_session(db, grant.token).mfa_required
    again = issue_session(db, identity)
    pending = load_session(db, again.token, allow_pending_mfa=True)
    assert not mfa.verify_factor(db, pending, ring, mfa.totp(seed, step))
    assert mfa.verify_factor(db, pending, ring, shown[1])
    third = issue_session(db, identity)
    assert not mfa.verify_factor(
        db, load_session(db, third.token, allow_pending_mfa=True), ring, shown[1]
    )


def test_new_account_enrollment_is_portable_and_invalidates_other_sessions(
    db, admin_engine, seeded
):
    from datetime import UTC, datetime

    tenant = seeded["tenants"][0]
    principal, _ = enroll(admin_engine, tenant)
    account = adopt(db, tenant, principal)
    identity = sign_in_with_password(db, "member@example.test", "a retained example passphrase")
    old = issue_session(db, identity)
    current = issue_session(db, identity)
    session = load_session(db, current.token)
    ring = KeyRing("test", {"test": b"m" * 32})
    secret = mfa.begin_enrollment(db, session, ring)
    codes = mfa.confirm_enrollment(
        db, session, ring, mfa.totp(secret, int(datetime.now(UTC).timestamp() // 30))
    )
    with pytest.raises(SessionError):
        load_session(db, old.token)
    second_membership(admin_engine, seeded, account)
    with admin_engine.begin() as conn:
        conn.execute(
            text("UPDATE execbound.tenants SET active=false WHERE tenant_id=:t"), {"t": tenant}
        )
    grant = issue_session(
        db, sign_in_with_password(db, "member@example.test", "a retained example passphrase")
    )
    pending = load_session(db, grant.token, allow_pending_mfa=True)
    assert mfa.verify_factor(db, pending, ring, codes[0])
    assert not load_session(db, grant.token).mfa_required


def test_migrated_passkey_keeps_old_user_handle_in_new_workspace(db, admin_engine, seeded):
    from datetime import UTC, datetime

    from test_passkeys import ORIGIN, assertion, b64, registration

    from execbound import passkeys

    tenant = seeded["tenants"][0]
    principal, _ = enroll(admin_engine, tenant)
    identity = mint_session_credential(db, tenant, principal, "password")
    legacy = issue_session(db, identity)
    session = load_session(db, legacy.token)
    ring = KeyRing("test", {"test": b"m" * 32})
    seed = mfa.begin_enrollment(db, session, ring)
    mfa.confirm_enrollment(
        db, session, ring, mfa.totp(seed, int(datetime.now(UTC).timestamp() // 30))
    )
    options = passkeys.begin(db, session, ORIGIN, "register")
    private, credential, response = registration(options)
    assert passkeys.complete(db, session, ORIGIN, "register", response)
    account = adopt(db, tenant, principal)
    second_membership(admin_engine, seeded, account)
    with admin_engine.begin() as conn:
        conn.execute(
            text("UPDATE execbound.tenants SET active=false WHERE tenant_id=:t"), {"t": tenant}
        )
    grant = issue_session(
        db, sign_in_with_password(db, "member@example.test", "a retained example passphrase")
    )
    pending = load_session(db, grant.token, allow_pending_mfa=True)
    options = passkeys.begin(db, pending, ORIGIN, "authenticate")
    proof = assertion(options, private, credential)
    proof["response"]["userHandle"] = b64(principal.bytes)
    assert passkeys.complete(db, pending, ORIGIN, "authenticate", proof)
    assert not load_session(db, grant.token).mfa_required
    assert (
        mfa.security_overview(db, load_session(db, grant.token))["passkeys"][0]["credential_id"]
        == credential.hex()
    )


def test_preexisting_admin_reset_cannot_be_redeemed_after_adoption(db, admin_engine, seeded):
    tenant = seeded["tenants"][0]
    principal, _ = enroll(admin_engine, tenant)
    admin, _ = enroll(admin_engine, tenant, email="admin@example.test", kind="ADMIN")
    reset = issue_reset(db, tenant, admin, principal)
    adopt(db, tenant, principal)
    with pytest.raises(PasswordError):
        redeem_reset(db, reset.code, "a password chosen by an administrator")


def test_new_passkey_uses_account_binding_while_legacy_binding_remains_distinct(
    db, admin_engine, seeded
):
    from datetime import UTC, datetime

    from test_passkeys import ORIGIN, registration

    from execbound import passkeys

    tenant = seeded["tenants"][0]
    principal, _ = enroll(admin_engine, tenant)
    account = adopt(db, tenant, principal)
    grant = issue_session(
        db, sign_in_with_password(db, "member@example.test", "a retained example passphrase")
    )
    session = load_session(db, grant.token)
    ring = KeyRing("test", {"test": b"m" * 32})
    seed = mfa.begin_enrollment(db, session, ring)
    mfa.confirm_enrollment(
        db, session, ring, mfa.totp(seed, int(datetime.now(UTC).timestamp() // 30))
    )
    options = passkeys.begin(db, session, ORIGIN, "register")
    _, credential, response = registration(options)
    assert passkeys.complete(db, session, ORIGIN, "register", response)
    with admin_engine.begin() as conn:
        saved = conn.execute(
            text(
                "SELECT binding_version,principal_id FROM "
                "execbound.user_passkeys WHERE account_id=:a AND credential_id=:c"
            ),
            {"a": account, "c": credential.hex()},
        ).one()
    assert saved == (2, account)


def test_owner_password_change_is_global_and_ends_other_sessions(db, admin_engine, seeded):
    tenant = seeded["tenants"][0]
    principal, _ = enroll(admin_engine, tenant)
    account = adopt(db, tenant, principal)
    second_membership(admin_engine, seeded, account)
    identity = sign_in_with_password(db, "member@example.test", "a retained example passphrase")
    old = issue_session(db, identity)
    grant = issue_session(db, identity)
    current = load_session(db, grant.token)
    change_password(
        db, identity, "a retained example passphrase", "a newly chosen passphrase", session=current
    )
    with pytest.raises(SessionError):
        load_session(db, old.token)
    with pytest.raises(AuthenticationFailed):
        sign_in_with_password(db, "member@example.test", "a retained example passphrase")
    with admin_engine.begin() as conn:
        conn.execute(
            text("UPDATE execbound.tenants SET active=false WHERE tenant_id=:t"), {"t": tenant}
        )
    assert (
        sign_in_with_password(db, "member@example.test", "a newly chosen passphrase").tenant_id
        == seeded["tenants"][1]
    )


def test_legacy_session_cannot_change_shared_factors_and_ends_on_account_change(
    db, admin_engine, seeded
):
    tenant = seeded["tenants"][0]
    principal, _ = enroll(admin_engine, tenant)
    old_identity = mint_session_credential(db, tenant, principal, "password")
    old = issue_session(db, old_identity)
    adopt(db, tenant, principal)
    old_session = load_session(db, old.token)
    ring = KeyRing("test", {"test": b"m" * 32})
    with pytest.raises(mfa.MfaError):
        mfa.begin_enrollment(db, old_session, ring)
    identity = sign_in_with_password(db, "member@example.test", "a retained example passphrase")
    grant = issue_session(db, identity)
    change_password(
        db,
        identity,
        "a retained example passphrase",
        "a newly chosen passphrase",
        session=load_session(db, grant.token),
    )
    with pytest.raises(SessionError):
        load_session(db, old.token)


def test_linked_legacy_session_can_verify_global_factor_but_cannot_change_it(
    db, admin_engine, seeded
):
    from datetime import UTC, datetime

    tenant = seeded["tenants"][0]
    principal, _ = enroll(admin_engine, tenant)
    old = issue_session(db, mint_session_credential(db, tenant, principal, "password"))
    old_session = load_session(db, old.token)
    ring = KeyRing("test", {"test": b"m" * 32})
    secret = mfa.begin_enrollment(db, old_session, ring)
    codes = mfa.confirm_enrollment(
        db, old_session, ring, mfa.totp(secret, int(datetime.now(UTC).timestamp() // 30))
    )
    adopt(db, tenant, principal)
    legacy = issue_session(db, mint_session_credential(db, tenant, principal, "password"))
    pending = load_session(db, legacy.token, allow_pending_mfa=True)
    assert mfa.verify_factor(db, pending, ring, codes[0])
    verified = load_session(db, legacy.token)
    with pytest.raises(mfa.MfaError):
        mfa.manage_security(db, verified, "recovery")


def test_linked_legacy_database_write_doors_cannot_change_account_auth(db, admin_engine, seeded):
    from sqlalchemy.exc import DBAPIError

    from execbound.passwords import bind_identity

    tenant = seeded["tenants"][0]
    principal, _ = enroll(admin_engine, tenant)
    grant = issue_session(db, mint_session_credential(db, tenant, principal, "password"))
    adopt(db, tenant, principal)
    with pytest.raises(DBAPIError):
        with db.transaction(tenant) as conn:
            conn.execute(
                text(
                    "SELECT execbound.account_security_change(:s,now(),'stage', "
                    '\'{"sealed":"bad","key":"bad"}\'::jsonb)'
                ),
                {"s": grant.session_id},
            )
    with pytest.raises(PasswordError):
        bind_identity(
            db,
            tenant,
            principal,
            provider="github",
            subject="unapproved-link",
            email="member@example.test",
            display_name=None,
        )
