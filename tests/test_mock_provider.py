# SPDX-License-Identifier: AGPL-3.0-only
"""Independent provider authority, atomicity and durable operation journal."""

import hashlib
import json
import sqlite3
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from pathlib import Path
from threading import Barrier
from uuid import UUID, uuid4

import pytest
from fastapi.testclient import TestClient

from execbound.provider.mock_app import create_mock_app
from execbound.provider.mock_store import MockStore
from execbound.provider.models import (
    MAX_PROVIDER_BYTES,
    JournalRecord,
    ProviderAccount,
    ProviderCommand,
    ProviderError,
    SignedJournal,
    signature,
)


@pytest.fixture
def command() -> ProviderCommand:
    return ProviderCommand(
        tenant_id=uuid4(),
        account_id=uuid4(),
        canonical_target_id=uuid4(),
        resource_provider_id="synthetic-endpoint-1",
        expected_version="resource-v1",
        operation_id=uuid4(),
        execution_id=uuid4(),
        intent_hash="a" * 64,
        plan_hash="b" * 64,
    )


@pytest.fixture
def store(tmp_path: Path, command: ProviderCommand) -> MockStore:
    result = MockStore(tmp_path / "provider.sqlite3")
    result.provision_resource(command.tenant_id, command.canonical_target_id, "resource-v1")
    result.provision_representation(
        command.tenant_id,
        command.account_id,
        command.resource_provider_id,
        command.canonical_target_id,
    )
    return result


def test_provisioning_at_start_creates_and_never_overwrites(
    store: MockStore, command: ProviderCommand
) -> None:
    """A restart re-reads the resources file; what the mock itself changed has to survive it.

    `boot._provision` runs on every start of a mock, so the seeded values arrive again for
    a target an agent has already acted on. Overwriting them put the provider back at the
    seeded version while the gateway's inventory expected the receipt's, and the next
    action on that target was refused `VERSION_MISMATCH` and settled `STALE_AUTHORIZATION`
    with no later refresh able to fix it, because no new receipt exists (#350). A contained
    endpoint also read as uncontained again, so the provider contradicted the audit chain's
    record of what had been done.

    The same call must still seed a target the file has newly named, which is the whole
    reason provisioning runs at start at all.
    """
    store.dispatch(command)
    acted = store.resource(command.tenant_id, command.canonical_target_id)
    assert acted is not None and acted.contained and acted.version != "resource-v1"

    store.provision_resource(command.tenant_id, command.canonical_target_id, "resource-v1")

    assert store.resource(command.tenant_id, command.canonical_target_id) == acted
    added = uuid4()
    store.provision_resource(command.tenant_id, added, "resource-v1")
    seeded = store.resource(command.tenant_id, added)
    assert seeded is not None and seeded.version == "resource-v1" and not seeded.contained


def test_reprovisioning_is_the_explicit_reset_and_touches_one_target(
    store: MockStore, command: ProviderCommand
) -> None:
    """The deliberate reset a stranded target needs, and it says so in its name.

    Provisioning creates; reprovisioning overwrites. They are two methods rather than one
    with a flag because the caller that wants each is different: `boot` seeds, and an
    operator repairing one target asks for the other by name.
    """
    other = uuid4()
    store.provision_resource(command.tenant_id, other, "resource-v1")
    store.dispatch(command)
    untouched = store.resource(command.tenant_id, other)

    store.reprovision_resource(command.tenant_id, command.canonical_target_id, "resource-v9")

    reset = store.resource(command.tenant_id, command.canonical_target_id)
    assert reset is not None and reset.version == "resource-v9" and not reset.contained
    assert store.resource(command.tenant_id, other) == untouched


def test_dispatch_commits_one_effect_and_retains_full_journal(
    store: MockStore, command: ProviderCommand
) -> None:
    result = store.dispatch(command)
    assert result.outcome == "EXECUTED"
    assert result.mutation_count == 1
    assert result.resulting_version != command.expected_version
    assert store.dispatch(command) == result
    assert store.lookup(command) == result
    assert MockStore(store.path).lookup(command) == result
    resource = store.resource(command.tenant_id, command.canonical_target_id)
    assert resource is not None and resource.contained and resource.mutation_count == 1
    assert resource.version == result.resulting_version


def test_version_mismatch_is_retained_terminal_nonexecution(
    store: MockStore, command: ProviderCommand
) -> None:
    changed = command.model_copy(update={"expected_version": "old-version"})
    result = store.dispatch(changed)
    assert result.outcome == "VERSION_MISMATCH" and result.mutation_count == 0
    store.provision_resource(command.tenant_id, command.canonical_target_id, "old-version")
    assert store.dispatch(changed) == result
    resource = store.resource(command.tenant_id, command.canonical_target_id)
    assert resource is not None and not resource.contained and resource.mutation_count == 0


@pytest.mark.parametrize("field", ["canonical_target_id", "resource_provider_id", "account_id"])
def test_unknown_representation_or_mismatched_canonical_target_never_mutates(
    store: MockStore, command: ProviderCommand, field: str
) -> None:
    changed = command.model_copy(
        update={field: "unknown-id" if field == "resource_provider_id" else uuid4()}
    )
    result = store.dispatch(changed)
    assert result.outcome == "TARGET_NOT_FOUND" and result.mutation_count == 0
    assert store.dispatch(changed) == result
    resource = store.resource(command.tenant_id, command.canonical_target_id)
    assert resource is not None and resource.mutation_count == 0


@pytest.mark.parametrize("method", ["dispatch", "lookup", "cancel"])
@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("expected_version", "different-version"),
        ("resource_provider_id", "different-provider-id"),
        ("intent_hash", "c" * 64),
        ("plan_hash", "d" * 64),
        ("canonical_target_id", UUID(int=99)),
        ("execution_id", UUID(int=100)),
    ],
)
def test_same_operation_rejects_changed_complete_command(
    store: MockStore, command: ProviderCommand, method: str, field: str, value: object
) -> None:
    original = store.dispatch(command)
    changed = command.model_copy(update={field: value})
    with pytest.raises(ProviderError) as error:
        getattr(store, method)(changed)
    assert error.value.code == "OPERATION_CONFLICT"
    assert store.lookup(command) == original


def test_failure_after_journal_insert_rolls_back_mutation_and_journal(
    store: MockStore, command: ProviderCommand, monkeypatch: pytest.MonkeyPatch
) -> None:
    original = store._write_record

    def fail(conn: sqlite3.Connection, record: JournalRecord) -> None:
        original(conn, record)
        raise RuntimeError("synthetic failure before commit")

    monkeypatch.setattr(store, "_write_record", fail)
    with pytest.raises(RuntimeError, match="synthetic failure"):
        store.dispatch(command)
    assert store.lookup(command) is None
    resource = store.resource(command.tenant_id, command.canonical_target_id)
    assert resource is not None and not resource.contained and resource.mutation_count == 0
    assert resource.version == command.expected_version


def test_cancellation_tombstone_precedes_resource_and_prevents_late_dispatch(
    tmp_path: Path, command: ProviderCommand
) -> None:
    store = MockStore(tmp_path / "provider.sqlite3")
    assert store.lookup(command) is None
    result = store.cancel(command)
    assert result.outcome == "CANCELLED_NOT_EXECUTED"
    store.provision_resource(command.tenant_id, command.canonical_target_id, "resource-v1")
    store.provision_representation(
        command.tenant_id,
        command.account_id,
        command.resource_provider_id,
        command.canonical_target_id,
    )
    assert MockStore(store.path).dispatch(command) == result
    resource = store.resource(command.tenant_id, command.canonical_target_id)
    assert resource is not None and resource.mutation_count == 0


def test_cancellation_after_effect_and_inverse_state_retains_executed_journal(
    store: MockStore, command: ProviderCommand
) -> None:
    result = store.dispatch(command)
    # Forcing out-of-band state is a reset, and says so now that the two are separate.
    store.reprovision_resource(command.tenant_id, command.canonical_target_id, "inverse-v2", False)
    assert store.cancel(command) == result
    assert store.dispatch(command) == result
    resource = store.resource(command.tenant_id, command.canonical_target_id)
    assert resource is not None and not resource.contained and resource.mutation_count == 1
    assert resource.version == "inverse-v2"


def test_journal_has_no_update_or_delete_path(store: MockStore, command: ProviderCommand) -> None:
    result = store.dispatch(command)
    for sql in ("UPDATE journal SET command_hash = 'changed'", "DELETE FROM journal"):
        with sqlite3.connect(store.path) as conn:
            with pytest.raises(sqlite3.IntegrityError, match="Immutable journal"):
                conn.execute(sql)
    assert store.lookup(command) == result


def test_equal_account_target_and_operation_ids_in_other_tenant_have_independent_state(
    store: MockStore, command: ProviderCommand
) -> None:
    other = command.model_copy(update={"tenant_id": uuid4()})
    store.provision_resource(other.tenant_id, other.canonical_target_id, "resource-v1")
    store.provision_representation(
        other.tenant_id, other.account_id, other.resource_provider_id, other.canonical_target_id
    )
    first = store.dispatch(command)
    assert store.lookup(other) is None
    second = store.cancel(other)
    assert first.outcome == "EXECUTED" and second.outcome == "CANCELLED_NOT_EXECUTED"
    resource = store.resource(other.tenant_id, other.canonical_target_id)
    assert resource is not None and resource.mutation_count == 0


@pytest.mark.parametrize("competitor", ["dispatch", "cancel"])
def test_real_separate_connections_serialize_dispatch_and_cancellation(
    store: MockStore, command: ProviderCommand, competitor: str
) -> None:
    barrier = Barrier(2)

    def call(method: str) -> JournalRecord:
        independent = MockStore(store.path)
        barrier.wait(timeout=10)
        return getattr(independent, method)(command)

    with ThreadPoolExecutor(max_workers=2) as pool:
        first = pool.submit(call, "dispatch")
        second = pool.submit(call, competitor)
        results = [first.result(timeout=15), second.result(timeout=15)]
    assert results[0] == results[1] == store.lookup(command)
    resource = store.resource(command.tenant_id, command.canonical_target_id)
    assert resource is not None
    assert resource.mutation_count == (1 if results[0].outcome == "EXECUTED" else 0)


def test_account_representations_share_atomic_physical_version(
    store: MockStore, command: ProviderCommand
) -> None:
    other = command.model_copy(
        update={
            "account_id": uuid4(),
            "resource_provider_id": "other-name",
            "operation_id": uuid4(),
        }
    )
    store.provision_representation(
        other.tenant_id, other.account_id, other.resource_provider_id, other.canonical_target_id
    )
    barrier = Barrier(2)

    def call(value: ProviderCommand) -> JournalRecord:
        barrier.wait(timeout=10)
        return MockStore(store.path).dispatch(value)

    with ThreadPoolExecutor(max_workers=2) as pool:
        first = pool.submit(call, command)
        second = pool.submit(call, other)
        results = [first.result(timeout=15), second.result(timeout=15)]
    assert {record.outcome for record in results} == {"EXECUTED", "VERSION_MISMATCH"}
    resource = store.resource(command.tenant_id, command.canonical_target_id)
    assert resource is not None and resource.mutation_count == 1


@pytest.fixture
def account(command: ProviderCommand) -> ProviderAccount:
    return ProviderAccount(
        tenant_id=command.tenant_id,
        account_id=command.account_id,
        dispatch_token_hash=hashlib.sha256(b"test-dispatch-token").hexdigest(),
        control_token_hash=hashlib.sha256(b"test-control-token").hexdigest(),
        signing_key=b"synthetic-signing-key-do-not-use!!",
    )


@pytest.fixture
def client(store: MockStore, account: ProviderAccount) -> TestClient:
    return TestClient(create_mock_app(store, (account,)))


def test_service_authenticates_and_signs_only_committed_journal(
    client: TestClient, command: ProviderCommand, account: ProviderAccount, store: MockStore
) -> None:
    response = client.post(
        "/v1/contain",
        content=command.model_dump_json(),
        headers={"Authorization": "Bearer test-dispatch-token"},
    )
    assert response.status_code == 200
    result = SignedJournal.model_validate_json(response.content)
    assert result.record == store.lookup(command)
    assert result.signature == signature(result.record, account.key_id, account.signing_key)
    assert response.headers["cache-control"] == "no-store"
    assert response.headers["x-content-type-options"] == "nosniff"
    assert "test-dispatch-token" not in response.text
    assert "synthetic-signing" not in response.text


@pytest.mark.parametrize("path", ["/v1/contain", "/v1/cancel"])
def test_failed_provider_transaction_never_returns_signed_evidence(
    client: TestClient,
    command: ProviderCommand,
    store: MockStore,
    monkeypatch: pytest.MonkeyPatch,
    path: str,
) -> None:
    original = store._write_record

    def fail(conn: sqlite3.Connection, record: JournalRecord) -> None:
        original(conn, record)
        raise RuntimeError("synthetic-private-database-information")

    monkeypatch.setattr(store, "_write_record", fail)
    token = "test-dispatch-token" if path == "/v1/contain" else "test-control-token"
    response = client.post(
        path, content=command.model_dump_json(), headers={"Authorization": f"Bearer {token}"}
    )
    assert response.status_code == 503
    assert "signature" not in response.text and "synthetic-private" not in response.text
    assert response.headers["cache-control"] == "no-store"
    assert store.lookup(command) is None
    resource = store.resource(command.tenant_id, command.canonical_target_id)
    assert resource is not None and resource.mutation_count == 0


def test_service_rejects_changed_operation_payload_without_leaking_retained_command(
    client: TestClient, command: ProviderCommand
) -> None:
    headers = {"Authorization": "Bearer test-dispatch-token"}
    assert (
        client.post("/v1/contain", content=command.model_dump_json(), headers=headers).status_code
        == 200
    )
    changed = command.model_copy(update={"resource_provider_id": "private-conflicting-id"})
    response = client.post("/v1/contain", content=changed.model_dump_json(), headers=headers)
    assert response.status_code == 409
    assert "private-conflicting-id" not in response.text
    assert command.resource_provider_id not in response.text


@pytest.mark.parametrize(
    "header",
    [
        None,
        "Bearer agent-token",
        "Bearer test-control-token",
        "Basic test-dispatch-token",
        "Bearer  test-dispatch-token",
        "Bearer test-dispatch-token extra",
    ],
)
def test_only_dispatch_credential_can_mutate(
    client: TestClient, command: ProviderCommand, store: MockStore, header: str | None
) -> None:
    response = client.post(
        "/v1/contain",
        content=command.model_dump_json(),
        headers={} if header is None else {"Authorization": header},
    )
    assert response.status_code == 401
    assert store.lookup(command) is None


def test_control_only_cancellation_and_both_credentials_can_read_journal(
    client: TestClient, command: ProviderCommand
) -> None:
    for token in ("test-dispatch-token", "test-control-token"):
        response = client.post(
            "/v1/journal",
            content=command.model_dump_json(),
            headers={"Authorization": f"Bearer {token}"},
        )
        assert response.status_code == 404
    response = client.post(
        "/v1/cancel",
        content=command.model_dump_json(),
        headers={"Authorization": "Bearer test-dispatch-token"},
    )
    assert response.status_code == 401
    response = client.post(
        "/v1/cancel",
        content=command.model_dump_json(),
        headers={"Authorization": "Bearer test-control-token"},
    )
    assert response.status_code == 200
    assert response.json()["record"]["outcome"] == "CANCELLED_NOT_EXECUTED"
    for token in ("test-dispatch-token", "test-control-token"):
        response = client.post(
            "/v1/journal",
            content=command.model_dump_json(),
            headers={"Authorization": f"Bearer {token}"},
        )
        assert response.status_code == 200


@pytest.mark.parametrize("field", ["tenant_id", "account_id"])
def test_credential_scope_cannot_be_replaced_by_command(
    client: TestClient, command: ProviderCommand, field: str
) -> None:
    response = client.post(
        "/v1/contain",
        content=command.model_copy(update={field: uuid4()}).model_dump_json(),
        headers={"Authorization": "Bearer test-dispatch-token"},
    )
    assert response.status_code == 403


@pytest.mark.parametrize(
    "payload",
    [
        b"",
        b"{",
        b'{"operation_id":"one","operation_id":"two"}',
        b'{"version":1.0}',
        b'{"version":NaN}',
        b"x" * (MAX_PROVIDER_BYTES + 1),
    ],
    ids=["empty", "malformed", "duplicate", "float", "nonfinite", "oversize"],
)
def test_invalid_raw_payloads_fail_without_mutation(
    client: TestClient, command: ProviderCommand, store: MockStore, payload: bytes
) -> None:
    response = client.post(
        "/v1/contain", content=payload, headers={"Authorization": "Bearer test-dispatch-token"}
    )
    assert response.status_code == 400
    assert store.lookup(command) is None


def test_unknown_command_fields_are_rejected(client: TestClient, command: ProviderCommand) -> None:
    payload = command.model_dump(mode="json") | {"destination": "https://attacker.invalid"}
    response = client.post(
        "/v1/contain", json=payload, headers={"Authorization": "Bearer test-dispatch-token"}
    )
    assert response.status_code == 400


@pytest.mark.parametrize(
    "path", ["/docs", "/openapi.json", "/admin", "/test-control", "/v1/failure"]
)
def test_no_documentation_or_test_control_routes(client: TestClient, path: str) -> None:
    assert client.get(path).status_code == 404


def test_service_has_exact_post_routes_without_redirects(
    client: TestClient, command: ProviderCommand
) -> None:
    for path in ("/v1/contain", "/v1/journal", "/v1/cancel"):
        assert client.get(path, follow_redirects=False).status_code == 405
        response = client.post(
            path + "/",
            content=command.model_dump_json(),
            headers={"Authorization": "Bearer test-dispatch-token"},
            follow_redirects=False,
        )
        assert response.status_code == 404


@pytest.mark.parametrize("header", ["x-tenant-id", "x-account-id", "x-principal-id", "x-role"])
def test_alternate_identity_headers_rejected(
    client: TestClient, command: ProviderCommand, header: str
) -> None:
    response = client.post(
        "/v1/contain",
        content=command.model_dump_json(),
        headers={"Authorization": "Bearer test-dispatch-token", header: "anything"},
    )
    assert response.status_code == 400


def test_duplicate_authorization_and_query_parameters_are_rejected(
    client: TestClient, command: ProviderCommand
) -> None:
    for path, headers in [
        ("/v1/contain", [("Authorization", "Bearer test-dispatch-token")] * 2),
        ("/v1/contain?account=other", [("Authorization", "Bearer test-dispatch-token")]),
    ]:
        response = client.post(path, content=command.model_dump_json(), headers=headers)
        assert response.status_code == 400


def test_configuration_rejects_ambiguous_cross_account_credentials(
    store: MockStore, account: ProviderAccount
) -> None:
    duplicate = replace(account, account_id=uuid4())
    with pytest.raises(ProviderError):
        create_mock_app(store, (account, duplicate))


def test_environment_config_is_explicit_and_uses_hashes_only(
    tmp_path: Path, account: ProviderAccount, monkeypatch: pytest.MonkeyPatch
) -> None:
    config = tmp_path / "accounts.json"
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
                }
            ]
        ),
        encoding="utf-8",
    )
    monkeypatch.setenv("EXECBOUND_MOCK_ACCOUNTS_PATH", str(config))
    monkeypatch.setenv("EXECBOUND_MOCK_DATABASE_PATH", str(tmp_path / "mock.sqlite3"))
    client = TestClient(create_mock_app())
    assert client.get("/docs").status_code == 404
