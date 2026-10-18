# SPDX-License-Identifier: AGPL-3.0-only
"""Settle pre-identity endpoint history using its original signed provider journal."""

import hashlib
import json
import os
from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import UUID, uuid4

import httpx
import pytest
from alembic import command
from alembic.config import Config
from sqlalchemy import text

from execbound.audit import canonical_json
from execbound.execution import reconcile, store
from execbound.identity import authenticate, new_token
from execbound.policy.models import BundleContent
from execbound.provider.connector import JournalVerifier, MockConnector
from execbound.provider.models import provider_command
from execbound.resolution.models import binding_hash, intent_hash, plan_hash

pytestmark = pytest.mark.integration


class FixedClock:
    def __init__(self, now):
        self.value = now

    def now(self):
        return self.value


@pytest.mark.parametrize("old_state", ["DISPATCH_COMMITTED", "INDETERMINATE"])
def test_original_endpoint_journal_settles_after_identity_schema_upgrade(
    admin_engine,
    db,
    seeded,
    monkeypatch,
    old_state,
):
    golden = json.loads(
        (Path(__file__).parent / "fixtures" / "endpoint-contract-v1.json").read_text("utf-8")
    )
    dispatch = golden["dispatch"]
    old_intent = dispatch["frozen"]["intent"]
    tenant, principal = UUID(old_intent["tenant_id"]), UUID(old_intent["principal_id"])
    execution, target = UUID(dispatch["execution_id"]), UUID(dispatch["canonical_target_id"])
    bundle_id, operation = UUID(golden["bundle"]["bundle_id"]), UUID(dispatch["operation_id"])
    credential, admin_id, admin_credential = uuid4(), uuid4(), uuid4()
    agent_token, agent_digest = new_token(tenant, credential)
    admin_token, admin_digest = new_token(tenant, admin_credential)
    now = datetime.now(UTC)
    occurred = datetime.fromisoformat(dispatch["frozen"]["resolved_at"])
    clock = FixedClock(now)
    config = Config("alembic.ini")
    # admin_engine validates the owner URL, loopback host and execbound_test name.
    config.attributes["database_url"] = os.environ["TEST_MIGRATION_DATABASE_URL"]

    # Seed original JSON and hashes on the actual prior schema, not freshly
    # regenerated models. Reconciliation then runs only after the 0007 upgrade.
    command.downgrade(config, "0006_human_sessions")
    try:
        with admin_engine.begin() as conn:
            assert (
                conn.execute(
                    text(
                        "SELECT count(*) FROM information_schema.columns "
                        "WHERE table_schema='execbound' AND table_name='resources' "
                        "AND column_name='privilege_class'"
                    )
                ).scalar_one()
                == 0
            )
            conn.execute(
                text(
                    "INSERT INTO execbound.tenants(tenant_id,name) "
                    "VALUES (:t,'Synthetic upgrade fixture')"
                ),
                {"t": tenant},
            )
            for actor, cred, kind, digest in (
                (principal, credential, "AGENT", agent_digest),
                (admin_id, admin_credential, "ADMIN", admin_digest),
            ):
                values = {
                    "t": tenant,
                    "p": actor,
                    "c": cred,
                    "k": kind,
                    "h": digest,
                    "issued": min(occurred, now),
                    "expires": now + timedelta(hours=1),
                }
                conn.execute(
                    text(
                        # Seeded on the 0006 schema, which has no space: migration 0041
                        # gives this tenant its `Default` space and backfills the agent's
                        # own column from it when the upgrade below runs.
                        "INSERT INTO execbound.principals(tenant_id,principal_id,kind) "
                        "VALUES (:t,:p,:k)"
                    ),
                    values,
                )
                conn.execute(
                    text(
                        "INSERT INTO execbound.credentials "
                        "(tenant_id,credential_id,principal_id,token_hash,issued_at,expires_at) "
                        "VALUES (:t,:c,:p,:h,:issued,:expires)"
                    ),
                    values,
                )
            values = {
                "t": tenant,
                "p": principal,
                "c": credential,
                "admin": admin_id,
                "e": execution,
                "target": target,
                "bundle": bundle_id,
                "operation": operation,
                "intent": dispatch["intent_hash"],
                "plan": dispatch["plan_hash"],
                "wire": hashlib.sha256(
                    canonical_json(dispatch["frozen"]["request"]).encode()
                ).hexdigest(),
                "frozen": canonical_json(dispatch["frozen"]),
                "content": golden["bundle_canonical"],
                "hash": golden["bundle_hash"],
                "n": occurred,
                "state": old_state,
            }
            # Every row here is seeded on the 0006 schema, before spaces existed;
            # migration 0041 backfills each one's space from the tenant's `Default` when
            # the upgrade below runs, which is what this fixture is for.
            for statement in (
                "INSERT INTO execbound.canonical_targets VALUES (:t,:target,:n)",
                "INSERT INTO execbound.policy_bundle_contents "
                "(tenant_id,bundle_id,content_hash,content,created_at,created_by) "
                "VALUES (:t,:bundle,:hash,CAST(:content AS jsonb),:n,:admin)",
                "INSERT INTO execbound.policy_bundle_lifecycle "
                "(tenant_id,bundle_id,content_hash,state,changed_at) "
                "VALUES (:t,:bundle,:hash,'RETIRED',:n)",
                "INSERT INTO execbound.executions "
                "(tenant_id,execution_id,principal_id,credential_id,intent_hash,wire_hash,plan_hash,"
                "canonical_target_id,bundle_id,frozen,state,created_at,changed_at,operation_id,"
                "owner_hash,dispatch_attempted_at) "
                "VALUES (:t,:e,:p,:c,:intent,:wire,:plan,:target,:bundle,CAST(:frozen AS jsonb),"
                ":state,:n,:n,:operation,repeat('a',64),:n)",
                "INSERT INTO execbound.execution_keys VALUES (:t,:p,'example',:intent,:wire,:e)",
                "INSERT INTO execbound.execution_impact "
                "(tenant_id,execution_id,principal_id,action,approved,state,created_at) "
                "VALUES (:t,:e,:p,'endpoint.isolate',false,'UNRESOLVED',:n)",
                "INSERT INTO execbound.resource_claims(tenant_id,execution_id,canonical_target_id) "
                "VALUES (:t,:e,:target)",
            ):
                conn.execute(text(statement), values)
    finally:
        command.upgrade(config, "head")

    admin, agent = authenticate(db, admin_token), authenticate(db, agent_token)
    sends = []

    def forbid_provider_send(*args, **kwargs):
        sends.append(True)
        raise AssertionError("Historical reconciliation must not send a provider operation")

    monkeypatch.setattr(MockConnector, "dispatch", forbid_provider_send)
    monkeypatch.setattr(MockConnector, "cancel", forbid_provider_send)
    monkeypatch.setattr(httpx.Client, "send", forbid_provider_send)
    verifier = JournalVerifier(
        tenant,
        UUID(old_intent["account_id"]),
        {golden["signed_journal"]["key_id"]: bytes.fromhex(golden["test_verification_key_hex"])},
    )
    with db.transaction(tenant) as conn:
        before = store.read(conn, tenant, execution)
        retained = store.frozen(before)
        provider = provider_command(store.command(before))
        bundle_row = conn.execute(
            text(
                "SELECT content,content_hash FROM execbound.policy_bundle_contents "
                "WHERE tenant_id=:t AND bundle_id=:b"
            ),
            {"t": tenant, "b": bundle_id},
        ).one()
        bundle = BundleContent.model_validate_json(canonical_json(bundle_row.content))
        assert before["state"] == old_state
        assert canonical_json(retained.model_dump(mode="json")) == golden["resolved_canonical"]
        assert binding_hash(retained) == golden["binding_hash"]
        assert intent_hash(retained.intent) == before["intent_hash"] == dispatch["intent_hash"]
        assert (
            plan_hash(retained, bundle.security_versions)
            == before["plan_hash"]
            == dispatch["plan_hash"]
        )
        assert bundle.content_hash == bundle_row.content_hash == golden["bundle_hash"]
        assert canonical_json(bundle.model_dump(mode="json")) == golden["bundle_canonical"]
        assert canonical_json(provider.model_dump(mode="json")) == golden["command_canonical"]
        assert provider.command_hash == golden["signed_journal"]["record"]["command_hash"]
        assert all(
            item.unresolved_targets == 1
            for item in store.usage(conn, agent, bundle, clock, frozen=retained).counts
        )

    # The captured MAC is verified as-is. No current inventory or active bundle
    # may turn settlement of a previous effect into a new authorization/dispatch.
    evidence = golden["signed_journal_canonical"].encode()
    result = reconcile(
        db,
        admin,
        execution,
        reason="Recover pre-identity journal",
        evidence=evidence,
        verifier=verifier,
        clock=clock,
    )
    assert result.state == "EXECUTED"
    assert result.plan_hash == dispatch["plan_hash"]
    assert (
        reconcile(
            db,
            admin,
            execution,
            reason="Repeat retained proof",
            evidence=evidence,
            verifier=verifier,
            clock=clock,
        )
        == result
    )
    assert sends == []
    with db.transaction(tenant) as conn:
        after = store.read(conn, tenant, execution)
        assert after["frozen"] == before["frozen"]
        assert after["intent_hash"] == before["intent_hash"]
        assert after["plan_hash"] == before["plan_hash"]
        assert after["dispatch_attempted_at"] == occurred
        assert (
            canonical_json(json.loads(after["result"]["authenticated_record"]))
            == golden["signed_journal_canonical"]
        )
        assert conn.execute(
            text(
                "SELECT action,state,approved,confirmed_at FROM execbound.execution_impact "
                "WHERE tenant_id=:t AND execution_id=:e"
            ),
            {"t": tenant, "e": execution},
        ).one() == ("endpoint.isolate", "CONFIRMED", False, now)
        assert all(
            item.confirmed_targets == 1 and item.unresolved_targets == 0
            for item in store.usage(conn, agent, bundle, clock, frozen=retained).counts
        )
        assert (
            conn.execute(
                text(
                    "SELECT released_at FROM execbound.resource_claims "
                    "WHERE tenant_id=:t AND execution_id=:e"
                ),
                {"t": tenant, "e": execution},
            ).scalar_one()
            == now
        )
        assert (
            conn.execute(
                text(
                    "SELECT count(*) FROM execbound.execution_events "
                    "WHERE tenant_id=:t AND execution_id=:e AND to_state='EXECUTED'"
                ),
                {"t": tenant, "e": execution},
            ).scalar_one()
            == 1
        )
