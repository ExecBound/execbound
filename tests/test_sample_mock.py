# SPDX-License-Identifier: AGPL-3.0-only
"""The endpoint mock's half of sample targets (#420, SM4).

A mock holding a sample key accepts, beside its configured accounts, any account whose token is
the one the key derives for the tenant and the account its own command names. These run the
real application in process against a real SQLite store; `tests/test_samples_end_to_end.py`
runs it as a process of its own.
"""

import hashlib
import sqlite3
from dataclasses import replace
from pathlib import Path
from uuid import UUID, uuid4

import pytest
from fastapi.testclient import TestClient

from execbound.provider.connector import JournalVerifier
from execbound.provider.identity_store import IdentityStore
from execbound.provider.mock_app import create_mock_app
from execbound.provider.mock_store import MockStore
from execbound.provider.models import (
    ProviderAccount,
    ProviderCommand,
    ProviderError,
    SignedJournal,
)
from execbound.provider.sample_accounts import (
    SAMPLE_KEY_ID,
    SAMPLE_RESOURCE_VERSION,
    sample_material,
)

KEY = bytes(range(32, 64))


@pytest.fixture(autouse=True)
def no_ambient_key(monkeypatch):
    monkeypatch.delenv("EXECBOUND_MOCK_SAMPLE_KEY", raising=False)


@pytest.fixture
def store(tmp_path: Path) -> MockStore:
    return MockStore(tmp_path / "provider.sqlite3")


@pytest.fixture
def configured() -> ProviderAccount:
    return ProviderAccount(
        tenant_id=uuid4(),
        account_id=uuid4(),
        dispatch_token_hash=hashlib.sha256(b"test-dispatch-token").hexdigest(),
        control_token_hash=hashlib.sha256(b"test-control-token").hexdigest(),
        signing_key=b"synthetic-signing-key-do-not-use!!",
    )


def command(
    tenant: UUID,
    account: UUID,
    *,
    target: UUID | None = None,
    version: str = SAMPLE_RESOURCE_VERSION,
) -> ProviderCommand:
    return ProviderCommand(
        tenant_id=tenant,
        account_id=account,
        canonical_target_id=target or uuid4(),
        resource_provider_id="sample-ws-dev-01",
        expected_version=version,
        operation_id=uuid4(),
        execution_id=uuid4(),
        intent_hash="a" * 64,
        plan_hash="b" * 64,
    )


def post(client: TestClient, path: str, sent: ProviderCommand | bytes, token: str):
    content = sent if isinstance(sent, bytes) else sent.model_dump_json()
    return client.post(
        path,
        content=content,
        headers={"Authorization": "Bearer " + token, "Content-Type": "application/json"},
    )


def journal(response) -> SignedJournal:
    assert response.status_code == 200, response.status_code
    return SignedJournal.model_validate_json(response.content)


def resources(store: MockStore) -> int:
    with sqlite3.connect(store.path) as conn:
        return int(conn.execute("SELECT count(*) FROM resources").fetchone()[0])


def test_sm4_a_derived_sample_account_executes_and_signs_with_its_derived_key(store, configured):
    client = TestClient(create_mock_app(store, (configured,), sample_key=KEY))
    tenant, account = uuid4(), uuid4()
    material = sample_material(KEY, tenant, account)
    sent = command(tenant, account)

    response = post(client, "/v1/contain", sent, material.dispatch_token)

    signed = journal(response)
    assert (signed.key_id, signed.record.outcome) == (SAMPLE_KEY_ID, "EXECUTED")
    verified = JournalVerifier(
        tenant, account, {SAMPLE_KEY_ID: material.journal_key}
    ).verify_command(sent, response.content)
    assert verified.outcome == "EXECUTED"
    with pytest.raises(ProviderError):
        JournalVerifier(tenant, account, {SAMPLE_KEY_ID: bytes(32)}).verify_command(
            sent, response.content
        )
    held = store.resource(tenant, sent.canonical_target_id)
    assert held is not None and held.contained and held.mutation_count == 1
    assert held.version == signed.record.resulting_version != SAMPLE_RESOURCE_VERSION
    # The journal answers either token of the account; a cancellation takes the control one.
    for token in (material.dispatch_token, material.control_token):
        assert journal(post(client, "/v1/journal", sent, token)) == signed
    cancelled = journal(
        post(client, "/v1/cancel", command(tenant, account), material.control_token)
    )
    assert cancelled.record.outcome == "CANCELLED_NOT_EXECUTED"


def test_sm4_a_mismatched_tenant_account_key_or_role_answers_401(store, configured):
    client = TestClient(create_mock_app(store, (configured,), sample_key=KEY))
    tenant, account = uuid4(), uuid4()
    material = sample_material(KEY, tenant, account)
    for sent in (command(uuid4(), account), command(tenant, uuid4()), command(account, tenant)):
        assert post(client, "/v1/contain", sent, material.dispatch_token).status_code == 401
    other_key = sample_material(bytes(range(64, 96)), tenant, account)
    assert (
        post(client, "/v1/contain", command(tenant, account), other_key.dispatch_token).status_code
        == 401
    )
    assert (
        post(client, "/v1/contain", command(tenant, account), material.control_token).status_code
        == 401
    )
    assert (
        post(client, "/v1/cancel", command(tenant, account), material.dispatch_token).status_code
        == 401
    )
    assert post(client, "/v1/contain", b"{not json", material.dispatch_token).status_code == 401
    unauthenticated = client.post(
        "/v1/contain",
        content=command(tenant, account).model_dump_json(),
        headers={"Content-Type": "application/json"},
    )
    assert unauthenticated.status_code == 401
    keyless = TestClient(create_mock_app(store, (configured,)))
    assert (
        post(keyless, "/v1/contain", command(tenant, account), material.dispatch_token).status_code
        == 401
    )
    assert resources(store) == 0


def test_sm4_a_sample_token_for_a_configured_accounts_scope_answers_401(store, configured):
    """A sample key must never reach a configured account's scope (#420).

    `_sample` derives a token for whatever tenant and account the command names. Without a
    check against the configured accounts, a sample-key holder who names a configured
    account's own tenant and account would authenticate as `sample-v1` and could dispatch
    and sign against that account's mock targets, contradicting the promise that a leaked
    sample key lets its holder act on a sample workspace's endpoint mock, and on nothing else
    (SM4 in `docs/ACCEPTANCE_TESTS.md`: configured accounts behave exactly as before).
    """
    client = TestClient(create_mock_app(store, (configured,), sample_key=KEY))
    material = sample_material(KEY, configured.tenant_id, configured.account_id)
    sent = command(configured.tenant_id, configured.account_id)

    response = post(client, "/v1/contain", sent, material.dispatch_token)

    assert response.status_code == 401
    assert store.resource(configured.tenant_id, sent.canonical_target_id) is None
    assert store.lookup(sent) is None
    assert resources(store) == 0


def test_sm4_a_sample_token_for_any_account_in_a_configured_tenant_answers_401(store, configured):
    """A sample key must not reach a configured tenant's own targets under a fresh account id.

    `resources` is keyed by `(tenant_id, canonical_target_id)`, and `MockStore.dispatch` joins
    any representation in the tenant regardless of which account holds it. Refusing only a
    configured account's exact `(tenant, account)` pair left a hole: a command naming the
    configured tenant with a fresh, unconfigured account id could still name one of that
    tenant's existing targets, `provision_sample` would seed a representation binding the
    fresh account to that target, and the next dispatch would execute against it (#420,
    tightened after review). The fix refuses the sample path for the whole tenant, whatever
    account id the command names inside it.
    """
    known = command(configured.tenant_id, configured.account_id, version="resource-v1")
    store.provision_resource(known.tenant_id, known.canonical_target_id, "resource-v1")
    store.provision_representation(
        known.tenant_id, known.account_id, known.resource_provider_id, known.canonical_target_id
    )
    client = TestClient(create_mock_app(store, (configured,), sample_key=KEY))
    intruder = uuid4()
    material = sample_material(KEY, configured.tenant_id, intruder)
    forged = command(
        configured.tenant_id, intruder, target=known.canonical_target_id, version="resource-v1"
    )

    response = post(client, "/v1/contain", forged, material.dispatch_token)

    assert response.status_code == 401
    held = store.resource(known.tenant_id, known.canonical_target_id)
    assert held is not None
    assert (held.version, held.contained, held.mutation_count) == ("resource-v1", False, 0)
    assert resources(store) == 1
    assert store.lookup(forged) is None


def test_sm4_a_target_is_created_on_first_sight_only_for_a_sample_account(store, configured):
    client = TestClient(create_mock_app(store, (configured,), sample_key=KEY))
    unknown = command(configured.tenant_id, configured.account_id)
    assert journal(post(client, "/v1/contain", unknown, "test-dispatch-token")).record.outcome == (
        "TARGET_NOT_FOUND"
    )
    assert store.resource(unknown.tenant_id, unknown.canonical_target_id) is None
    tenant, account = uuid4(), uuid4()
    material = sample_material(KEY, tenant, account)
    first = command(tenant, account)
    assert journal(post(client, "/v1/contain", first, material.dispatch_token)).record.outcome == (
        "EXECUTED"
    )
    # Versions then change normally: the same target at the recorded version now mismatches.
    again = command(tenant, account, target=first.canonical_target_id)
    assert journal(post(client, "/v1/contain", again, material.dispatch_token)).record.outcome == (
        "VERSION_MISMATCH"
    )
    # A lookup names nothing new into being.
    looked = command(tenant, account)
    assert post(client, "/v1/journal", looked, material.control_token).status_code == 404
    assert store.resource(tenant, looked.canonical_target_id) is None


def test_sm4_configured_accounts_behave_exactly_as_before(store, configured):
    known = command(configured.tenant_id, configured.account_id, version="resource-v1")
    store.provision_resource(known.tenant_id, known.canonical_target_id, "resource-v1")
    store.provision_representation(
        known.tenant_id, known.account_id, known.resource_provider_id, known.canonical_target_id
    )
    client = TestClient(create_mock_app(store, (configured,), sample_key=KEY))
    signed = journal(post(client, "/v1/contain", known, "test-dispatch-token"))
    assert (signed.key_id, signed.record.outcome) == ("journal-v1", "EXECUTED")
    # A configured token naming another account is refused as it always was, never re-read
    # as a sample account's.
    elsewhere = command(configured.tenant_id, uuid4())
    assert post(client, "/v1/contain", elsewhere, "test-dispatch-token").status_code == 403
    assert post(client, "/v1/contain", known, "test-control-token").status_code == 401
    assert store.resource(elsewhere.tenant_id, elsewhere.canonical_target_id) is None


def test_sm4_a_sample_key_the_mock_cannot_use_refuses_to_start(
    tmp_path, store, configured, monkeypatch
):
    identity = IdentityStore(tmp_path / "identity.sqlite3")
    with pytest.raises(ProviderError):
        create_mock_app(
            identity,
            (replace(configured, provider="mock_entra"),),
            provider="mock_entra",
            sample_key=KEY,
        )
    with pytest.raises(ProviderError):
        create_mock_app(store, (configured,), sample_key=KEY[:16])
    with pytest.raises(ProviderError):
        create_mock_app(store, (configured,), sample_key=configured.signing_key)
    monkeypatch.setenv("EXECBOUND_MOCK_SAMPLE_KEY", "zz" * 32)
    with pytest.raises(ProviderError):
        create_mock_app(store, (configured,))
    tenant, account = uuid4(), uuid4()
    token = sample_material(KEY, tenant, account).dispatch_token
    monkeypatch.setenv("EXECBOUND_MOCK_SAMPLE_KEY", KEY.hex())
    from_environment = TestClient(create_mock_app(store, (configured,)))
    assert journal(
        post(from_environment, "/v1/contain", command(tenant, account), token)
    ).record.outcome == ("EXECUTED")
    monkeypatch.setenv("EXECBOUND_MOCK_SAMPLE_KEY", "")
    empty = TestClient(create_mock_app(store, (configured,)))
    assert post(empty, "/v1/contain", command(tenant, account), token).status_code == 401
