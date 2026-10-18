# SPDX-License-Identifier: AGPL-3.0-only
"""Protected identity operations require exact commands and durable transition proof."""

import hashlib
import hmac
import json
import sqlite3
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from pathlib import Path
from threading import Barrier
from uuid import uuid4

import httpx
import pytest
from fastapi.testclient import TestClient

from execbound.audit import canonical_json
from execbound.execution.models import DispatchCommand
from execbound.operations import operation
from execbound.provider.connector import ConnectionConfig, JournalVerifier, MockConnector
from execbound.provider.identity_store import IdentityStore
from execbound.provider.mock_app import create_mock_app
from execbound.provider.mock_store import MockStore
from execbound.provider.models import (
    JournalRecord,
    ProviderAccount,
    ProviderCommand,
    ProviderError,
    provider_command,
    sign_record,
)
from execbound.requests import Arguments

ACTIONS = (
    "identity.disable",
    "identity.enable",
    "identity.revoke_sessions",
    "identity.reset_password",
)


def arguments_for(action):
    """Each action carries exactly the catalog's arguments; every other action carries none."""
    if action == "identity.reset_password":
        return Arguments({"require_change_at_next_sign_in": True})
    return Arguments()


@pytest.fixture(params=ACTIONS)
def command(request):
    return ProviderCommand(
        tenant_id=uuid4(),
        account_id=uuid4(),
        canonical_target_id=uuid4(),
        provider="mock_entra",
        action=request.param,
        provider_operation=request.param.removeprefix("identity."),
        arguments=arguments_for(request.param),
        resource_provider_id="synthetic-identity",
        expected_version="security-v1",
        operation_id=uuid4(),
        execution_id=uuid4(),
        intent_hash="a" * 64,
        plan_hash="b" * 64,
    )


@pytest.fixture
def store(tmp_path, command):
    result = IdentityStore(tmp_path / "identity.sqlite3")
    result.provision_resource(command.tenant_id, command.canonical_target_id, "security-v1")
    result.provision_representation(
        command.tenant_id,
        command.account_id,
        command.resource_provider_id,
        command.canonical_target_id,
    )
    return result


@pytest.fixture
def account(command):
    return ProviderAccount(
        command.tenant_id,
        command.account_id,
        hashlib.sha256(b"identity-dispatch-token").hexdigest(),
        hashlib.sha256(b"identity-control-token").hexdigest(),
        b"synthetic-identity-signing-key-32!",
        provider="mock_entra",
    )


def test_provisioning_at_start_creates_and_never_overwrites(store, command):
    """A restart re-reads the resources file; what the mock itself changed has to survive.

    The identity mock's half of #350. Overwriting at start put a disabled account back to
    enabled and its `session_generation` back to the seeded value, so the provider
    contradicted the audit chain's record of what had been done, and the version it held
    no longer matched the one the gateway's inventory expected from the receipt. That
    stranded the target: refused `VERSION_MISMATCH`, settled `STALE_AUTHORIZATION`, and no
    refresh repairs it because no new receipt exists.
    """
    store.dispatch(command)
    acted = store.resource(command.tenant_id, command.canonical_target_id)
    assert acted is not None and acted.version != "security-v1"

    store.provision_resource(command.tenant_id, command.canonical_target_id, "security-v1")

    assert store.resource(command.tenant_id, command.canonical_target_id) == acted
    added = uuid4()
    store.provision_resource(command.tenant_id, added, "security-v1")
    seeded = store.resource(command.tenant_id, added)
    assert seeded is not None and seeded.version == "security-v1" and seeded.account_enabled


@pytest.mark.parametrize("enabled", [True, False])
def test_each_transition_is_atomic_and_retained(store, command, account, enabled):
    # The fixture has already seeded this target, so choosing its starting state is a reset.
    store.reprovision_resource(
        command.tenant_id,
        command.canonical_target_id,
        "security-v1",
        account_enabled=enabled,
        session_generation=7,
    )
    record = store.dispatch(command)
    assert record.outcome == "EXECUTED" and record.mutation_count == 1
    state = store.resource(command.tenant_id, command.canonical_target_id)
    assert state.mutation_count == 1
    assert state.version == record.resulting_version != command.expected_version
    reset = command.action == "identity.reset_password"
    expected_enabled = (
        enabled
        if command.action in {"identity.revoke_sessions", "identity.reset_password"}
        else (command.action == "identity.enable")
    )
    expected_generation = 8 if command.action == "identity.revoke_sessions" else 7
    assert state.account_enabled is expected_enabled
    assert state.session_generation == expected_generation
    assert state.password_generation == (1 if reset else 0)
    assert state.must_change_password is reset
    transition = record.identity_transition
    assert transition.before.account_enabled is enabled
    assert transition.before.session_generation == 7
    assert transition.after.account_enabled is expected_enabled
    assert transition.after.session_generation == expected_generation
    assert store.dispatch(command) == store.lookup(command) == record
    assert IdentityStore(store.path).lookup(command) == record
    signed = sign_record(record, account)
    verifier = JournalVerifier(
        command.tenant_id,
        command.account_id,
        {account.key_id: account.signing_key},
        provider="mock_entra",
    )
    assert verifier.verify_command(command, signed.model_dump_json().encode()).reason == "EXECUTED"


def test_cancellation_prevents_delayed_effect(store, command):
    tombstone = store.cancel(command)
    assert tombstone.outcome == "CANCELLED_NOT_EXECUTED"
    assert tombstone.identity_transition is None
    assert IdentityStore(store.path).dispatch(command) == tombstone
    assert store.resource(command.tenant_id, command.canonical_target_id).mutation_count == 0


def test_expected_version_competitors_share_physical_identity_fence(store, command):
    other = command.model_copy(
        update={
            "operation_id": uuid4(),
            "action": "identity.enable",
            "provider_operation": "enable",
            "arguments": arguments_for("identity.enable"),
        }
    )
    barrier = Barrier(2)

    def dispatch(value):
        independent = IdentityStore(store.path)
        barrier.wait(timeout=10)
        return independent.dispatch(value)

    with ThreadPoolExecutor(max_workers=2) as pool:
        first = pool.submit(dispatch, command)
        second = pool.submit(dispatch, other)
        results = [first.result(timeout=15), second.result(timeout=15)]
    assert {item.outcome for item in results} == {"EXECUTED", "VERSION_MISMATCH"}
    assert store.resource(command.tenant_id, command.canonical_target_id).mutation_count == 1


def test_provider_kind_is_enforced_before_any_store_access(store, command, account, tmp_path):
    endpoint = command.model_copy(
        update={
            "provider": "mock_crowdstrike",
            "action": "endpoint.isolate",
            "provider_operation": "contain",
            "arguments": Arguments(),
        }
    )
    for method in ("dispatch", "lookup", "cancel"):
        with pytest.raises(ProviderError):
            getattr(store, method)(endpoint)
        with pytest.raises(ProviderError):
            getattr(MockStore(tmp_path / "endpoint.sqlite3"), method)(command)
    with pytest.raises(ProviderError):
        MockStore(store.path)
    with pytest.raises(ProviderError):
        create_mock_app(
            store, (replace(account, provider="mock_crowdstrike"),), provider="mock_entra"
        )


def test_service_exposes_only_identity_routes_and_binds_action(store, command, account):
    with TestClient(create_mock_app(store, (account,), provider="mock_entra")) as client:
        headers = {"Authorization": "Bearer identity-dispatch-token"}
        assert (
            client.post(
                "/v1/contain", content=command.model_dump_json(), headers=headers
            ).status_code
            == 404
        )
        wrong_path = "/v1/enable" if command.action != "identity.enable" else "/v1/disable"
        assert (
            client.post(wrong_path, content=command.model_dump_json(), headers=headers).status_code
            == 400
        )
        assert store.lookup(command) is None
        result = client.post(
            "/v1/" + command.provider_operation, content=command.model_dump_json(), headers=headers
        )
        assert result.status_code == 200
        assert result.json()["record"]["command"]["action"] == command.action


@pytest.mark.parametrize("method", ["dispatch", "lookup", "cancel"])
@pytest.mark.parametrize(
    "changed_field", ["action", "expected_version", "execution_id", "plan_hash"]
)
def test_same_operation_id_rejects_changed_full_command(store, command, method, changed_field):
    record = store.dispatch(command)
    if changed_field == "action":
        action = "identity.disable" if command.action != "identity.disable" else "identity.enable"
        update = {
            "action": action,
            "provider_operation": action.removeprefix("identity."),
            "arguments": arguments_for(action),
        }
    else:
        update = {
            changed_field: uuid4()
            if changed_field == "execution_id"
            else ("c" * 64 if changed_field == "plan_hash" else "another-version")
        }
    with pytest.raises(ProviderError) as exc:
        getattr(store, method)(command.model_copy(update=update))
    assert exc.value.code == "OPERATION_CONFLICT"
    assert store.lookup(command) == record
    assert store.resource(command.tenant_id, command.canonical_target_id).mutation_count == 1


@pytest.mark.parametrize("method", ["dispatch", "lookup", "cancel"])
@pytest.mark.parametrize("bypass", ["copy", "construct"])
def test_invalid_action_tuple_cannot_bypass_trust_crossing(store, command, method, bypass):
    values = dict(command) | {"provider_operation": "contain"}
    invalid = (
        command.model_copy(update={"provider_operation": "contain"})
        if bypass == "copy"
        else ProviderCommand.model_construct(**values)
    )
    with pytest.raises(ProviderError):
        getattr(store, method)(invalid)
    assert store.lookup(command) is None
    assert store.resource(command.tenant_id, command.canonical_target_id).mutation_count == 0


@pytest.mark.parametrize(
    "field", ["tenant_id", "account_id", "canonical_target_id", "resource_provider_id"]
)
def test_unknown_representation_does_not_mutate(store, command, field):
    changed = command.model_copy(
        update={field: "unknown" if field == "resource_provider_id" else uuid4()}
    )
    record = store.dispatch(changed)
    assert record.outcome == "TARGET_NOT_FOUND" and record.identity_transition is None
    assert store.resource(command.tenant_id, command.canonical_target_id).mutation_count == 0


def test_version_failure_is_permanently_retained_even_if_state_later_matches(store, command):
    changed = command.model_copy(update={"expected_version": "older-version"})
    record = store.dispatch(changed)
    assert record.outcome == "VERSION_MISMATCH" and record.identity_transition is None
    # State drifting to match afterwards is an external change, so it is a reset.
    store.reprovision_resource(command.tenant_id, command.canonical_target_id, "older-version")
    assert store.dispatch(changed) == record
    assert store.resource(command.tenant_id, command.canonical_target_id).mutation_count == 0


@pytest.mark.parametrize("competitor", ["dispatch", "cancel"])
def test_same_operation_races_have_one_terminal_journal(store, command, competitor):
    barrier = Barrier(2)

    def call(method):
        independent = IdentityStore(store.path)
        barrier.wait(timeout=10)
        return getattr(independent, method)(command)

    with ThreadPoolExecutor(max_workers=2) as pool:
        first = pool.submit(call, "dispatch")
        second = pool.submit(call, competitor)
        records = [first.result(timeout=15), second.result(timeout=15)]
    assert records[0] == records[1] == store.lookup(command)
    assert store.resource(command.tenant_id, command.canonical_target_id).mutation_count == (
        1 if records[0].outcome == "EXECUTED" else 0
    )


def test_inverse_state_and_later_revocation_do_not_replace_operation_proof(store, command, account):
    original = store.dispatch(command)
    original_enabled = original.identity_transition.after.account_enabled
    store.reprovision_resource(
        command.tenant_id, command.canonical_target_id, "external-version", not original_enabled, 23
    )
    later = command.model_copy(
        update={
            "operation_id": uuid4(),
            "execution_id": uuid4(),
            "action": "identity.revoke_sessions",
            "provider_operation": "revoke_sessions",
            "arguments": arguments_for("identity.revoke_sessions"),
            "expected_version": "external-version",
        }
    )
    later_record = store.dispatch(later)
    assert store.cancel(command) == store.dispatch(command) == store.lookup(command) == original
    verifier = JournalVerifier(
        command.tenant_id,
        command.account_id,
        {account.key_id: account.signing_key},
        provider="mock_entra",
    )
    with pytest.raises(ProviderError):
        verifier.verify_command(
            command, sign_record(later_record, account).model_dump_json().encode()
        )
    assert store.resource(command.tenant_id, command.canonical_target_id).session_generation == 24


def test_current_state_without_journal_is_not_terminal_evidence(store, command, account):
    store.reprovision_resource(
        command.tenant_id, command.canonical_target_id, "external-change", False, 42
    )
    assert store.lookup(command) is None
    verifier = JournalVerifier(
        command.tenant_id,
        command.account_id,
        {account.key_id: account.signing_key},
        provider="mock_entra",
    )
    for raw in (b'{"account_enabled":false,"session_generation":42}', b'{"status":"not_found"}'):
        with pytest.raises(ProviderError):
            verifier.verify_command(command, raw)


def test_journal_is_immutable_and_audit_failure_rolls_back_identity_effect(
    store, command, monkeypatch
):
    original_write = store._write_record

    def fail(conn, record):
        original_write(conn, record)
        raise RuntimeError("synthetic journal failure")

    monkeypatch.setattr(store, "_write_record", fail)
    with pytest.raises(RuntimeError, match="synthetic journal failure"):
        store.dispatch(command)
    assert store.lookup(command) is None
    state = store.resource(command.tenant_id, command.canonical_target_id)
    assert state.mutation_count == 0 and state.version == command.expected_version
    monkeypatch.setattr(store, "_write_record", original_write)
    record = store.dispatch(command)
    for sql in ("DELETE FROM journal", "UPDATE journal SET record_json = '{}'"):
        with sqlite3.connect(store.path) as conn:
            with pytest.raises(sqlite3.IntegrityError, match="Immutable journal"):
                conn.execute(sql)
    assert store.lookup(command) == record


@pytest.mark.parametrize(
    "mutation",
    [
        "enabled",
        "generation",
        "before",
        "missing",
        "wrong_action",
        "nonexecution",
        "bool_generation",
        "float_generation",
    ],
)
@pytest.mark.parametrize("resign", [True, False])
def test_action_specific_transition_tampering_is_rejected(
    store, command, account, mutation, resign
):
    signed = sign_record(store.dispatch(command), account).model_dump(mode="json")
    record = signed["record"]
    transition = record["identity_transition"]
    if mutation == "enabled":
        transition["after"]["account_enabled"] = not transition["after"]["account_enabled"]
    elif mutation == "generation":
        transition["after"]["session_generation"] += 2
    elif mutation == "before":
        transition["before"]["session_generation"] += 2
    elif mutation == "missing":
        del record["identity_transition"]
    elif mutation == "wrong_action":
        record["command"]["action"] = (
            "identity.enable" if command.action != "identity.enable" else "identity.disable"
        )
        record["command"]["provider_operation"] = record["command"]["action"].removeprefix(
            "identity."
        )
        record["command_hash"] = hashlib.sha256(
            canonical_json(record["command"]).encode()
        ).hexdigest()
    elif mutation == "nonexecution":
        record["outcome"], record["mutation_count"] = "CANCELLED_NOT_EXECUTED", 0
    elif mutation == "bool_generation":
        transition["after"]["session_generation"] = True
    elif mutation == "float_generation":
        transition["after"]["session_generation"] = 1.0
    if resign:
        signed["signature"] = hmac.new(
            account.signing_key,
            json.dumps(
                {"version": 1, "key_id": account.key_id, "record": record},
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=False,
            ).encode(),
            hashlib.sha256,
        ).hexdigest()
    verifier = JournalVerifier(
        command.tenant_id,
        command.account_id,
        {account.key_id: account.signing_key},
        provider="mock_entra",
    )
    with pytest.raises(ProviderError):
        verifier.verify_command(command, json.dumps(signed).encode())


def test_signer_and_verifier_revalidate_constructed_models_and_provider_kind(
    store, command, account
):
    record = store.dispatch(command)
    invalid_command = command.model_copy(update={"provider_operation": "contain"})
    invalid = record.model_copy(update={"command": invalid_command})
    with pytest.raises(ProviderError):
        sign_record(invalid, account)
    with pytest.raises(ProviderError):
        sign_record(record, replace(account, provider="mock_crowdstrike"))
    signed = sign_record(record, account).model_dump_json().encode()
    verifier = JournalVerifier(
        command.tenant_id,
        command.account_id,
        {account.key_id: account.signing_key},
        provider="mock_entra",
    )
    with pytest.raises(ProviderError):
        verifier.verify_command(invalid_command, signed)
    wrong_provider = JournalVerifier(
        command.tenant_id, command.account_id, {account.key_id: account.signing_key}
    )
    with pytest.raises(ProviderError):
        wrong_provider.verify_command(command, signed)


@pytest.mark.parametrize(
    "credential", [None, "agent-token", "identity-control-token", "endpoint-dispatch-token"]
)
def test_identity_mutation_requires_its_dispatch_credential(store, command, account, credential):
    with TestClient(create_mock_app(store, (account,), provider="mock_entra")) as client:
        response = client.post(
            "/v1/" + command.provider_operation,
            content=command.model_dump_json(),
            headers={} if credential is None else {"Authorization": "Bearer " + credential},
        )
        assert response.status_code == 401
    assert store.lookup(command) is None


@pytest.mark.parametrize("field", ["tenant_id", "account_id", "provider"])
@pytest.mark.parametrize("path", ["dispatch", "journal", "cancel"])
def test_authenticated_account_scope_applies_to_every_provider_route(
    store, command, account, field, path
):
    update = (
        {field: uuid4()}
        if field != "provider"
        else {
            "provider": "mock_crowdstrike",
            "action": "endpoint.isolate",
            "provider_operation": "contain",
            "arguments": Arguments(),
        }
    )
    changed = command.model_copy(update=update)
    token = "identity-control-token" if path == "cancel" else "identity-dispatch-token"
    with TestClient(create_mock_app(store, (account,), provider="mock_entra")) as client:
        response = client.post(
            "/v1/" + (command.provider_operation if path == "dispatch" else path),
            content=changed.model_dump_json(),
            headers={"Authorization": "Bearer " + token},
        )
        assert response.status_code == 403
    assert store.lookup(command) is None


def test_endpoint_and_identity_files_do_not_share_physical_state(store, command, tmp_path):
    endpoint = MockStore(tmp_path / "separate-endpoint.sqlite3")
    endpoint.provision_resource(command.tenant_id, command.canonical_target_id, "security-v1")
    store.dispatch(command)
    assert endpoint.resource(command.tenant_id, command.canonical_target_id).mutation_count == 0
    other = command.model_copy(update={"tenant_id": uuid4()})
    store.provision_resource(other.tenant_id, other.canonical_target_id, "security-v1")
    store.provision_representation(
        other.tenant_id, other.account_id, other.resource_provider_id, other.canonical_target_id
    )
    assert store.lookup(other) is None
    store.cancel(other)
    assert store.resource(other.tenant_id, other.canonical_target_id).mutation_count == 0


def test_explicit_environment_factory_retains_separate_provider_kind(
    store, command, account, tmp_path, monkeypatch
):
    config = tmp_path / "identity-accounts.json"
    config.write_text(
        json.dumps(
            [
                {
                    "tenant_id": str(account.tenant_id),
                    "account_id": str(account.account_id),
                    "dispatch_token_hash": account.dispatch_token_hash,
                    "control_token_hash": account.control_token_hash,
                    "signing_key_hex": account.signing_key.hex(),
                    "key_id": account.key_id,
                    "provider": "mock_entra",
                }
            ]
        )
    )
    monkeypatch.setenv("EXECBOUND_MOCK_PROVIDER", "mock_entra")
    monkeypatch.setenv("EXECBOUND_MOCK_DATABASE_PATH", str(store.path))
    monkeypatch.setenv("EXECBOUND_MOCK_ACCOUNTS_PATH", str(config))
    with TestClient(create_mock_app()) as client:
        result = client.post(
            "/v1/" + command.provider_operation,
            content=command.model_dump_json(),
            headers={"Authorization": "Bearer identity-dispatch-token"},
        )
        assert result.status_code == 200
    monkeypatch.setenv("EXECBOUND_MOCK_PROVIDER", "mock_crowdstrike")
    with pytest.raises(ProviderError):
        create_mock_app()


@pytest.fixture
def dispatch(command):
    retained = json.loads(
        (Path(__file__).parent / "fixtures/endpoint-contract-v1.json").read_text()
    )
    value = retained["dispatch"]
    value.update(
        {
            name: str(getattr(command, name))
            for name in (
                "execution_id",
                "canonical_target_id",
                "operation_id",
                "intent_hash",
                "plan_hash",
            )
        }
    )
    arguments = command.arguments.model_dump(mode="json")
    frozen = value["frozen"]
    frozen["request"]["operation_ref"] = command.action
    frozen["request"]["target"] = {"kind": "canonical", "value": str(command.canonical_target_id)}
    frozen["request"]["arguments"] = arguments
    frozen["intent"].update(
        {
            "tenant_id": str(command.tenant_id),
            "account_id": str(command.account_id),
            "target_id": str(command.canonical_target_id),
            "provider": "mock_entra",
            "resource_type": "identity",
            "action": command.action,
            "provider_operation": command.provider_operation,
            "arguments": arguments,
        }
    )
    frozen.update(
        {
            "context_contract_version": operation(command.action).context_contract_version,
            "resource_version": command.expected_version,
            "resource_provider_id": command.resource_provider_id,
        }
    )
    return DispatchCommand.model_validate_json(json.dumps(value))


@pytest.mark.parametrize("method", ["dispatch", "lookup", "cancel"])
def test_connector_uses_fixed_action_route_and_bound_provider_evidence(
    store, command, account, dispatch, method
):
    seen = []

    def send(request):
        seen.append(request)
        parsed = ProviderCommand.model_validate_json(request.content)
        assert parsed == command
        record = getattr(store, method)(parsed)
        if record is None:
            return httpx.Response(404)
        return httpx.Response(200, json=sign_record(record, account).model_dump(mode="json"))

    config = ConnectionConfig(
        command.tenant_id,
        command.account_id,
        "http://127.0.0.1:8123",
        "identity-dispatch-token",
        "identity-control-token",
        {account.key_id: account.signing_key},
        provider="mock_entra",
    )
    connector = MockConnector(config)
    connector._client.close()
    connector._client = httpx.Client(
        transport=httpx.MockTransport(send), follow_redirects=False, trust_env=False
    )
    try:
        assert provider_command(dispatch) == command
        result = getattr(connector, method)(provider_command(dispatch))
        assert result is None if method == "lookup" else result is not None
        assert len(seen) == 1
        assert (
            seen[0].url.path
            == "/v1/"
            + {"dispatch": command.provider_operation, "lookup": "journal", "cancel": "cancel"}[
                method
            ]
        )
        expected_token = (
            "identity-control-token" if method == "cancel" else "identity-dispatch-token"
        )
        assert seen[0].headers["authorization"] == "Bearer " + expected_token
    finally:
        connector.close()


@pytest.mark.parametrize("method", ["dispatch", "lookup", "cancel"])
def test_wrong_provider_connector_never_attempts_network(command, account, dispatch, method):
    config = ConnectionConfig(
        command.tenant_id,
        command.account_id,
        "http://127.0.0.1:8123",
        "identity-dispatch-token",
        "identity-control-token",
        {account.key_id: account.signing_key},
    )
    connector = MockConnector(config)
    seen = []
    connector._client.close()
    connector._client = httpx.Client(
        transport=httpx.MockTransport(lambda request: seen.append(request))
    )
    try:
        with pytest.raises(ProviderError):
            getattr(connector, method)(provider_command(dispatch))
        assert seen == []
    finally:
        connector.close()


@pytest.mark.parametrize("failure", ["timeout", "redirect", "lost_response"])
def test_transport_never_retries_even_after_identity_effect(
    store, command, account, dispatch, failure
):
    seen = []

    def send(request):
        seen.append(request)
        if failure == "redirect":
            return httpx.Response(307, headers={"Location": "http://127.0.0.1:8124/steal"})
        if failure == "lost_response":
            store.dispatch(command)
        raise httpx.ReadTimeout("synthetic timeout", request=request)

    config = ConnectionConfig(
        command.tenant_id,
        command.account_id,
        "http://127.0.0.1:8123",
        "identity-dispatch-token",
        "identity-control-token",
        {account.key_id: account.signing_key},
        provider="mock_entra",
    )
    connector = MockConnector(config)
    connector._client.close()
    connector._client = httpx.Client(
        transport=httpx.MockTransport(send), follow_redirects=False, trust_env=False
    )
    try:
        with pytest.raises(ProviderError):
            connector.dispatch(provider_command(dispatch))
        assert len(seen) == 1
        assert store.resource(command.tenant_id, command.canonical_target_id).mutation_count == (
            1 if failure == "lost_response" else 0
        )
    finally:
        connector.close()


@pytest.mark.parametrize(
    "outcome", ["VERSION_MISMATCH", "CANCELLED_NOT_EXECUTED", "TARGET_NOT_FOUND"]
)
def test_malformed_nonexecution_evidence_cannot_be_signed(store, command, account, outcome):
    original = store.cancel(command)
    invalid = JournalRecord.model_construct(
        **(
            dict(original)
            | {
                "outcome": outcome,
                "resulting_version": command.expected_version,
            }
        )
    )
    with pytest.raises(ProviderError):
        sign_record(invalid, account)


def test_legacy_endpoint_file_cannot_be_opened_as_identity_store(tmp_path):
    path = tmp_path / "legacy-endpoint.sqlite3"
    MockStore(path)
    with sqlite3.connect(path) as conn:
        conn.execute("DROP TABLE provider_metadata")
    with pytest.raises(ProviderError):
        IdentityStore(path)
    assert MockStore(path).provider == "mock_crowdstrike"
