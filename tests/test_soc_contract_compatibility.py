# SPDX-License-Identifier: AGPL-3.0-only
"""The endpoint-recovery and identity-credential executor contracts stay byte-identical (#37).

`endpoint-recovery-contract-v1.json` and `identity-credential-contract-v1.json` are the
executor protocol's conformance vectors for `endpoint.lift_isolation` and
`identity.reset_password`, the two catalog bindings the endpoint and identity contracts do not
cover. They were captured from the server's own models and the reference mocks with the public
test key, and they are frozen history from their first merge exactly as those two are: the
plan, bundle, command and journal bytes must keep reproducing, and the current server must keep
settling each retained journal without sending anything to a provider.
"""

import hashlib
import json
from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import UUID, uuid4

import httpx
import pytest
from sqlalchemy import text

from execbound.audit import canonical_json
from execbound.execution import reconcile, store
from execbound.execution.models import DispatchCommand
from execbound.identity import authenticate, new_token
from execbound.policy.models import BundleContent
from execbound.provider.connector import JournalVerifier, MockConnector
from execbound.provider.models import SignedJournal, provider_command, signature
from execbound.resolution.models import binding_hash, intent_hash, plan_hash

FIXTURES = Path(__file__).parent / "fixtures"
# Each frozen contract file, the one action it holds and the provider that executes it.
CONTRACTS = {
    "endpoint-recovery-contract-v1.json": ("endpoint.lift_isolation", "mock_crowdstrike"),
    "identity-credential-contract-v1.json": ("identity.reset_password", "mock_entra"),
}


def retained_contract(name: str) -> tuple[dict, dict]:
    document = json.loads((FIXTURES / name).read_text(encoding="utf-8"))
    action, _ = CONTRACTS[name]
    assert sorted(document["actions"]) == [action]
    return document, document["actions"][action]


@pytest.mark.parametrize("name", sorted(CONTRACTS))
def test_retained_bundle_bytes(name):
    document, _ = retained_contract(name)
    bundle = BundleContent.model_validate_json(json.dumps(document["bundle"]))
    assert canonical_json(bundle.model_dump(mode="json")) == document["bundle_canonical"]
    assert bundle.content_hash == document["bundle_hash"]


@pytest.mark.parametrize("name", sorted(CONTRACTS))
def test_retained_plan_and_command_bytes(name):
    document, retained = retained_contract(name)
    command = DispatchCommand.model_validate_json(json.dumps(retained["dispatch"]))
    bundle = BundleContent.model_validate_json(json.dumps(document["bundle"]))
    frozen = command.frozen
    assert canonical_json(frozen.model_dump(mode="json")) == retained["resolved_canonical"]
    assert binding_hash(frozen) == retained["binding_hash"]
    assert intent_hash(frozen.intent) == command.intent_hash
    assert plan_hash(frozen, bundle.security_versions) == command.plan_hash
    assert (
        canonical_json(provider_command(command).model_dump(mode="json"))
        == retained["command_canonical"]
    )
    # The arguments are frozen in the intent and carried in the command, which is what makes
    # these two contracts different from the four argument-free ones before them.
    assert frozen.intent.arguments.root
    assert provider_command(command).arguments == frozen.intent.arguments


@pytest.mark.parametrize("name", sorted(CONTRACTS))
def test_retained_journal_signature_and_verification(name):
    document, retained = retained_contract(name)
    _, provider = CONTRACTS[name]
    dispatch = DispatchCommand.model_validate_json(json.dumps(retained["dispatch"]))
    signed = SignedJournal.model_validate_json(json.dumps(retained["signed_journal"]))
    assert canonical_json(signed.model_dump(mode="json")) == retained["signed_journal_canonical"]
    key = bytes.fromhex(document["test_verification_key_hex"])
    assert signature(signed.record, signed.key_id, key) == signed.signature
    verifier = JournalVerifier(
        dispatch.frozen.intent.tenant_id,
        dispatch.frozen.intent.account_id,
        {signed.key_id: key},
        provider=provider,
    )
    evidence = verifier.verify(dispatch, retained["signed_journal_canonical"].encode())
    assert evidence.outcome == "EXECUTED"
    assert evidence.operation_id == dispatch.operation_id
    assert evidence.plan_hash == dispatch.plan_hash


def test_the_reset_contract_carries_no_password():
    """The identity mock never generates or returns a password; only a generation counter
    moves, so nothing secret-shaped is frozen into the vector."""
    _, retained = retained_contract("identity-credential-contract-v1.json")
    record = retained["signed_journal"]["record"]
    assert record["credential_transition"] == {
        "before": {"must_change_password": False, "password_generation": 0},
        "after": {"must_change_password": True, "password_generation": 1},
    }
    assert "password" not in json.dumps(retained["dispatch"]).replace("reset_password", "")


class FixedClock:
    def __init__(self, now):
        self.value = now

    def now(self):
        return self.value


def seed_retained(admin_engine, document, retained, old_state, now):
    """The rows admission and dispatch leave for this contract's execution, on the current
    schema: committed or uncertain, its impact charged and its target claimed."""
    dispatch = retained["dispatch"]
    intent = dispatch["frozen"]["intent"]
    tenant, principal = UUID(intent["tenant_id"]), UUID(intent["principal_id"])
    space, credential, admin_id, admin_credential = uuid4(), uuid4(), uuid4(), uuid4()
    agent_token, agent_digest = new_token(tenant, credential)
    admin_token, admin_digest = new_token(tenant, admin_credential)
    occurred = datetime.fromisoformat(dispatch["frozen"]["resolved_at"])
    frozen = DispatchCommand.model_validate_json(json.dumps(dispatch)).frozen
    with admin_engine.begin() as conn:
        conn.execute(
            text("INSERT INTO execbound.tenants(tenant_id,name) VALUES (:t,'Synthetic contract')"),
            {"t": tenant},
        )
        conn.execute(
            text(
                "INSERT INTO execbound.spaces(tenant_id,space_id,name,created_at,created_by) "
                "VALUES (:t,:s,'Default',:n,:p)"
            ),
            {"t": tenant, "s": space, "n": occurred, "p": admin_id},
        )
        for actor, cred, kind, digest, actor_space in (
            (principal, credential, "AGENT", agent_digest, space),
            (admin_id, admin_credential, "ADMIN", admin_digest, None),
        ):
            conn.execute(
                text(
                    "INSERT INTO execbound.principals(tenant_id,principal_id,kind,space_id) "
                    "VALUES (:t,:p,:k,:s)"
                ),
                {"t": tenant, "p": actor, "k": kind, "s": actor_space},
            )
            conn.execute(
                text(
                    "INSERT INTO execbound.credentials "
                    "(tenant_id,credential_id,principal_id,token_hash,issued_at,expires_at) "
                    "VALUES (:t,:c,:p,:h,:issued,:expires)"
                ),
                {
                    "t": tenant,
                    "c": cred,
                    "p": actor,
                    "h": digest,
                    "issued": occurred,
                    "expires": now + timedelta(hours=1),
                },
            )
        values = {
            "t": tenant,
            "s": space,
            "p": principal,
            "c": credential,
            "admin": admin_id,
            "e": UUID(dispatch["execution_id"]),
            "target": UUID(dispatch["canonical_target_id"]),
            "bundle": UUID(document["bundle"]["bundle_id"]),
            "operation": UUID(dispatch["operation_id"]),
            "intent": dispatch["intent_hash"],
            "plan": dispatch["plan_hash"],
            "wire": hashlib.sha256(
                canonical_json(dispatch["frozen"]["request"]).encode()
            ).hexdigest(),
            "key": dispatch["frozen"]["request"]["idempotency_key"],
            "frozen": canonical_json(dispatch["frozen"]),
            "content": document["bundle_canonical"],
            "hash": document["bundle_hash"],
            "n": occurred,
            "state": old_state,
            "action": intent["action"],
            **store.impact_attributes(frozen, (), space),
        }
        for statement in (
            "INSERT INTO execbound.canonical_targets VALUES (:t,:target,:n)",
            "INSERT INTO execbound.policy_bundle_contents "
            "(tenant_id,bundle_id,content_hash,content,created_at,created_by,space_id) "
            "VALUES (:t,:bundle,:hash,CAST(:content AS jsonb),:n,:admin,:s)",
            "INSERT INTO execbound.policy_bundle_lifecycle "
            "(tenant_id,bundle_id,content_hash,state,changed_at) "
            "VALUES (:t,:bundle,:hash,'RETIRED',:n)",
            "INSERT INTO execbound.executions "
            "(tenant_id,execution_id,principal_id,credential_id,intent_hash,wire_hash,plan_hash,"
            "canonical_target_id,bundle_id,frozen,state,created_at,changed_at,operation_id,"
            "owner_hash,dispatch_attempted_at,space_id,request_number) "
            "VALUES (:t,:e,:p,:c,:intent,:wire,:plan,:target,:bundle,CAST(:frozen AS jsonb),"
            ":state,:n,:n,:operation,repeat('a',64),:n,:s,1)",
            "INSERT INTO execbound.execution_keys VALUES (:t,:p,:key,:intent,:wire,:e)",
            "INSERT INTO execbound.execution_impact "
            "(tenant_id,execution_id,principal_id,action,approved,state,created_at,"
            "account_id,group_ids,facts,space_id) "
            "VALUES (:t,:e,:p,:action,false,'UNRESOLVED',:n,"
            ":account,CAST(:groups AS jsonb),CAST(:facts AS jsonb),:space)",
            "INSERT INTO execbound.resource_claims(tenant_id,execution_id,canonical_target_id) "
            "VALUES (:t,:e,:target)",
        ):
            conn.execute(text(statement), values)
    return admin_token, agent_token


@pytest.mark.integration
@pytest.mark.parametrize("old_state", ["DISPATCH_COMMITTED", "INDETERMINATE"])
@pytest.mark.parametrize("name", sorted(CONTRACTS))
def test_the_retained_journal_settles_on_the_current_server(
    admin_engine, db, seeded, monkeypatch, name, old_state
):
    document, retained = retained_contract(name)
    _, provider = CONTRACTS[name]
    dispatch = retained["dispatch"]
    intent = dispatch["frozen"]["intent"]
    tenant, execution = UUID(intent["tenant_id"]), UUID(dispatch["execution_id"])
    now = datetime.now(UTC)
    clock = FixedClock(now)
    admin_token, _ = seed_retained(admin_engine, document, retained, old_state, now)
    admin = authenticate(db, admin_token)
    sends = []

    def forbid_provider_send(*args, **kwargs):
        sends.append(True)
        raise AssertionError("Settling a retained journal must not send a provider operation")

    monkeypatch.setattr(MockConnector, "dispatch", forbid_provider_send)
    monkeypatch.setattr(MockConnector, "cancel", forbid_provider_send)
    monkeypatch.setattr(httpx.Client, "send", forbid_provider_send)
    verifier = JournalVerifier(
        tenant,
        UUID(intent["account_id"]),
        {
            retained["signed_journal"]["key_id"]: bytes.fromhex(
                document["test_verification_key_hex"]
            )
        },
        provider=provider,
    )
    with db.transaction(tenant) as conn:
        before = store.read(conn, tenant, execution)
        assert before["state"] == old_state
        assert (
            canonical_json(store.frozen(before).model_dump(mode="json"))
            == retained["resolved_canonical"]
        )
        command = provider_command(store.command(before))
        assert canonical_json(command.model_dump(mode="json")) == retained["command_canonical"]

    evidence = retained["signed_journal_canonical"].encode()
    result = reconcile(
        db,
        admin,
        execution,
        reason="Settle the retained contract journal",
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
            reason="Repeat the retained proof",
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
        assert (after["intent_hash"], after["plan_hash"]) == (
            dispatch["intent_hash"],
            dispatch["plan_hash"],
        )
        assert (
            canonical_json(json.loads(after["result"]["authenticated_record"]))
            == retained["signed_journal_canonical"]
        )
        assert conn.execute(
            text(
                "SELECT action,state,approved,confirmed_at FROM execbound.execution_impact "
                "WHERE tenant_id=:t AND execution_id=:e"
            ),
            {"t": tenant, "e": execution},
        ).one() == (intent["action"], "CONFIRMED", False, now)
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
