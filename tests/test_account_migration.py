# SPDX-License-Identifier: AGPL-3.0-only
"""Populated upgrades use the hosted owner's real forced-RLS privileges."""

import json
from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest
from alembic import command
from sqlalchemy import text
from test_migration_without_bypass import restricted as restricted
from test_workspace_accounts import enroll

from execbound import mfa
from execbound.envelope import KeyRing, seal, unseal

pytestmark = pytest.mark.integration


def test_populated_upgrade_preserves_identity_with_no_owner_rls_bypass(restricted):
    engine, config, _ = restricted
    command.upgrade(config, "0053_persistent_community")
    tenant = uuid4()
    with engine.begin() as conn:
        conn.execute(text("SELECT set_config('execbound.tenant_id',:t,true)"), {"t": str(tenant)})
        conn.execute(
            text("INSERT INTO execbound.tenants(tenant_id,name) VALUES(:t,'Retained')"),
            {"t": tenant},
        )
    principal, password = enroll(engine, tenant)
    ring = KeyRing("retained", {"retained": b"m" * 32})
    seed = "JBSWY3DPEHPK3PXP"
    sealed, key = seal(ring, seed, tenant, principal, "authenticator_seed")
    _, digests = mfa.new_recovery_codes(principal)
    locked = datetime.now(UTC) + timedelta(minutes=2)
    with engine.begin() as conn:
        conn.execute(text("SELECT set_config('execbound.tenant_id',:t,true)"), {"t": str(tenant)})
        conn.execute(
            text("""INSERT INTO execbound.account_factors
            (tenant_id,principal_id,sealed,key_id,enabled_at,version,last_step,
             recovery_hashes,failures,locked_until)
            VALUES(:t,:p,:sealed,:key,now(),4,123456,CAST(:codes AS jsonb),3,:locked)"""),
            {
                "t": tenant,
                "p": principal,
                "sealed": sealed,
                "key": key,
                "codes": json.dumps(digests[1:]),
                "locked": locked,
            },
        )
        conn.execute(
            text("""INSERT INTO execbound.account_passkeys
            (tenant_id,principal_id,credential_id,public_key,sign_count,created_at)
            VALUES(:t,:p,'aabb','ccdd',7,now())"""),
            {"t": tenant, "p": principal},
        )
    command.upgrade(config, "head")
    command.upgrade(config, "head")
    with engine.begin() as conn:
        conn.execute(text("SELECT set_config('execbound.tenant_id',:t,true)"), {"t": str(tenant)})
        member = conn.execute(
            text("SELECT account_id,principal_id FROM execbound.workspace_memberships")
        ).one()
        assert member.principal_id == principal
        conn.execute(
            text("SELECT set_config('execbound.account_id',:a,true)"), {"a": str(member.account_id)}
        )
        assert (
            conn.execute(text("SELECT hash FROM execbound.user_passwords")).scalar_one()
            == password.hash
        )
        assert (
            conn.execute(text("SELECT email_verified_at FROM execbound.user_accounts")).scalar_one()
            is None
        )
        factor = conn.execute(text("SELECT * FROM execbound.user_factors")).mappings().one()
        assert (
            unseal(
                ring,
                factor["sealed"],
                factor["key_id"],
                factor["tenant_id"],
                factor["principal_id"],
                "authenticator_seed",
            )
            == seed
        )
        assert factor["recovery_hashes"] == digests[1:]
        assert (
            factor["version"],
            factor["last_step"],
            factor["failures"],
            factor["locked_until"],
        ) == (4, 123456, 3, locked)
        passkey = conn.execute(
            text("SELECT principal_id,sign_count,binding_version FROM execbound.user_passkeys")
        ).one()
        assert passkey == (principal, 7, 1)
        assert (
            conn.execute(
                text(
                    "SELECT count(*) FROM pg_class WHERE relnamespace='execbound'::regnamespace "
                    "AND relkind='r' AND relname<>'alembic_version' AND NOT relforcerowsecurity"
                )
            ).scalar_one()
            == 0
        )
    with pytest.raises(RuntimeError, match="lossy downgrade refused"):
        command.downgrade(config, "0053_persistent_community")


def test_0055_downgrade_refuses_a_populated_workspace_without_bypass(restricted):
    """VS1d (`test_community_signup.py`) proves this refusal only as the local superuser,
    which bypasses row-level security outright and would pass even with the downgrade's
    `NO FORCE`/`FORCE` lines deleted. The hosted owner does not bypass; prove the refusal
    with that owner's real privileges instead.
    """
    engine, config, _ = restricted
    command.upgrade(config, "head")
    tenant, request = uuid4(), uuid4()
    with engine.begin() as conn:
        conn.execute(text("SELECT set_config('execbound.tenant_id',:t,true)"), {"t": str(tenant)})
        conn.execute(
            text(
                "INSERT INTO execbound.tenants(tenant_id,name,slug) "
                "VALUES(:t,'Retained','retained-workspace-01')"
            ),
            {"t": tenant},
        )
        conn.execute(
            text(
                "INSERT INTO execbound.signup_requests"
                "(tenant_id,request_id,email,domain,consent_version,requested_at,state,"
                " verifying_at) "
                "VALUES(:t,:r,'a@example.com','example.com','v1',now(),'VERIFYING',now())"
            ),
            {"t": tenant, "r": request},
        )
    with pytest.raises(RuntimeError, match="lossy downgrade refused"):
        command.downgrade(config, "0054_account_memberships")


def test_0055_downgrade_deletes_a_stray_verification_message_without_bypass(restricted):
    """The `signup_messages` `NO FORCE`/`FORCE` wrap around the downgrade's cleanup `DELETE`
    is what makes that statement see every tenant's rows as an owner that does not bypass
    row-level security; unfenced and un-wrapped, it would silently delete nothing (the same
    class of bug `test_migration_without_bypass.py` documents for migration 0041), and this
    request/tenant carry nothing else that the downgrade's populated check would refuse.
    """
    engine, config, _ = restricted
    command.upgrade(config, "head")
    tenant, request, message = uuid4(), uuid4(), uuid4()
    with engine.begin() as conn:
        conn.execute(text("SELECT set_config('execbound.tenant_id',:t,true)"), {"t": str(tenant)})
        conn.execute(
            text("INSERT INTO execbound.tenants(tenant_id,name) VALUES(:t,'Plain')"),
            {"t": tenant},
        )
        conn.execute(
            text(
                "INSERT INTO execbound.signup_requests"
                "(tenant_id,request_id,email,domain,consent_version,requested_at,state) "
                "VALUES(:t,:r,'b@example.com','example.com','v1',now(),'QUEUED')"
            ),
            {"t": tenant, "r": request},
        )
        conn.execute(
            text(
                "INSERT INTO execbound.signup_messages"
                "(tenant_id,message_id,request_id,message_class,created_at,next_attempt_at) "
                "VALUES(:t,:m,:r,'verification',now(),now())"
            ),
            {"t": tenant, "r": request, "m": message},
        )
    command.downgrade(config, "0054_account_memberships")
    with engine.begin() as conn:
        conn.execute(text("SELECT set_config('execbound.tenant_id',:t,true)"), {"t": str(tenant)})
        assert (
            conn.execute(
                text("SELECT count(*) FROM execbound.signup_messages WHERE request_id=:r"),
                {"r": request},
            ).scalar_one()
            == 0
        )
