# SPDX-License-Identifier: AGPL-3.0-only
"""Lift-isolation and password-reset mock operations carry arguments and transition proof (SA11)."""

import hashlib
import json
import sqlite3
from datetime import UTC, datetime
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient
from pydantic import ValidationError

from execbound.provider.identity_store import IdentityStore
from execbound.provider.mock_app import create_mock_app
from execbound.provider.mock_store import MockStore
from execbound.provider.models import (
    CredentialState,
    CredentialTransition,
    EndpointState,
    EndpointTransition,
    IdentityState,
    IdentityTransition,
    JournalRecord,
    ProviderAccount,
    ProviderCommand,
    ProviderError,
)
from execbound.requests import Arguments

TRANSITIONS = frozenset({"identity_transition", "endpoint_transition", "credential_transition"})

DISPATCH_TOKEN = "soc-dispatch-token"


def command(action, provider, operation, arguments):
    return ProviderCommand(
        tenant_id=uuid4(),
        account_id=uuid4(),
        canonical_target_id=uuid4(),
        provider=provider,
        action=action,
        provider_operation=operation,
        arguments=Arguments(arguments),
        resource_provider_id="soc-target",
        expected_version="resource-v1",
        operation_id=uuid4(),
        execution_id=uuid4(),
        intent_hash="a" * 64,
        plan_hash="b" * 64,
    )


def lift(reason="false_positive"):
    return command(
        "endpoint.lift_isolation", "mock_crowdstrike", "lift_containment", {"reason": reason}
    )


def reset(require_change=True):
    return command(
        "identity.reset_password",
        "mock_entra",
        "reset_password",
        {"require_change_at_next_sign_in": require_change},
    )


def account(cmd, provider):
    return ProviderAccount(
        cmd.tenant_id,
        cmd.account_id,
        hashlib.sha256(DISPATCH_TOKEN.encode()).hexdigest(),
        hashlib.sha256(b"soc-control-token").hexdigest(),
        b"soc-synthetic-signing-key-32-bytes!!",
        provider=provider,
    )


@pytest.mark.parametrize(
    "changes",
    [
        {"arguments": {"reason": "other"}},
        {"arguments": {}},
        {"arguments": {"reason": "remediated", "extra": True}},
        {"provider_operation": "contain"},
        {"provider": "mock_entra"},
    ],
)
def test_provider_command_rejects_arguments_and_bindings_outside_the_catalog(changes):
    values = lift().model_dump(mode="json")
    values.update(changes)
    with pytest.raises(ValidationError):
        ProviderCommand.model_validate(values)
    with pytest.raises(ValidationError):
        ProviderCommand.model_validate(
            {
                **command("endpoint.isolate", "mock_crowdstrike", "contain", {}).model_dump(
                    mode="json"
                ),
                "arguments": {"reason": "remediated"},
            }
        )


@pytest.mark.parametrize("contained", [True, False])
def test_lift_containment_clears_containment_and_journals_the_transition(tmp_path, contained):
    cmd = lift()
    store = MockStore(tmp_path / "endpoint.sqlite3")
    store.provision_resource(
        cmd.tenant_id, cmd.canonical_target_id, "resource-v1", contained=contained
    )
    store.provision_representation(
        cmd.tenant_id, cmd.account_id, cmd.resource_provider_id, cmd.canonical_target_id
    )
    record = store.dispatch(cmd)
    assert record.outcome == "EXECUTED" and record.mutation_count == 1
    assert record.endpoint_transition == EndpointTransition(
        before=EndpointState(contained=contained), after=EndpointState(contained=False)
    )
    assert record.credential_transition is None and record.identity_transition is None
    state = store.resource(cmd.tenant_id, cmd.canonical_target_id)
    assert state.contained is False and state.mutation_count == 1
    assert state.version == record.resulting_version != "resource-v1"
    assert store.dispatch(cmd) == store.lookup(cmd) == record
    assert store.resource(cmd.tenant_id, cmd.canonical_target_id).mutation_count == 1
    assert record.command.arguments.root == {"reason": "false_positive"}
    assert "endpoint_transition" in record.model_dump(mode="json")


def test_contain_journals_keep_their_original_shape(tmp_path):
    cmd = command("endpoint.isolate", "mock_crowdstrike", "contain", {})
    store = MockStore(tmp_path / "endpoint.sqlite3")
    store.provision_resource(cmd.tenant_id, cmd.canonical_target_id, "resource-v1")
    store.provision_representation(
        cmd.tenant_id, cmd.account_id, cmd.resource_provider_id, cmd.canonical_target_id
    )
    record = store.dispatch(cmd)
    dumped = record.model_dump(mode="json")
    assert record.outcome == "EXECUTED"
    assert set(dumped) == {
        "version",
        "command",
        "command_hash",
        "outcome",
        "occurred_at",
        "resulting_version",
        "mutation_count",
    }
    assert dumped["command"]["arguments"] == {}


@pytest.mark.parametrize("require_change", [True, False])
def test_reset_password_advances_the_generation_without_touching_sessions(tmp_path, require_change):
    cmd = reset(require_change)
    store = IdentityStore(tmp_path / "identity.sqlite3")
    store.provision_resource(
        cmd.tenant_id, cmd.canonical_target_id, "resource-v1", session_generation=4
    )
    store.provision_representation(
        cmd.tenant_id, cmd.account_id, cmd.resource_provider_id, cmd.canonical_target_id
    )
    record = store.dispatch(cmd)
    assert record.outcome == "EXECUTED" and record.mutation_count == 1
    assert record.identity_transition.before == record.identity_transition.after
    assert record.identity_transition.after.session_generation == 4
    assert record.credential_transition == CredentialTransition(
        before=CredentialState(password_generation=0, must_change_password=False),
        after=CredentialState(password_generation=1, must_change_password=require_change),
    )
    state = store.resource(cmd.tenant_id, cmd.canonical_target_id)
    assert (state.password_generation, state.must_change_password) == (1, require_change)
    assert state.account_enabled is True and state.session_generation == 4
    assert store.dispatch(cmd) == record
    repeated = store.resource(cmd.tenant_id, cmd.canonical_target_id)
    assert repeated.password_generation == 1 and repeated.mutation_count == 1
    dumped = record.model_dump(mode="json")
    assert set(dumped["credential_transition"]["after"]) == {
        "password_generation",
        "must_change_password",
    }
    with sqlite3.connect(store.path) as conn:
        columns = {row[1] for row in conn.execute("PRAGMA table_info(resources)")}
    assert {name for name in columns if "password" in name} == {
        "password_generation",
        "must_change_password",
    }


def test_existing_identity_store_gains_the_credential_columns(tmp_path):
    path = tmp_path / "identity.sqlite3"
    with sqlite3.connect(path) as conn:
        conn.execute(
            "CREATE TABLE provider_metadata (singleton INTEGER PRIMARY KEY "
            "CHECK (singleton = 1), provider TEXT NOT NULL)"
        )
        conn.execute("INSERT INTO provider_metadata VALUES (1, 'mock_entra')")
        conn.execute(
            "CREATE TABLE resources (tenant_id TEXT NOT NULL, canonical_target_id TEXT NOT NULL, "
            "version TEXT NOT NULL, "
            "account_enabled INTEGER NOT NULL CHECK (account_enabled IN (0, 1)), "
            "session_generation INTEGER NOT NULL CHECK (session_generation >= 0), "
            "mutation_count INTEGER NOT NULL CHECK (mutation_count >= 0), "
            "PRIMARY KEY (tenant_id, canonical_target_id))"
        )
        conn.execute("INSERT INTO resources VALUES ('t', 'c', 'resource-v1', 1, 2, 0)")
    store = IdentityStore(path)
    with sqlite3.connect(store.path) as conn:
        row = conn.execute(
            "SELECT password_generation, must_change_password FROM resources"
        ).fetchone()
    assert row == (0, 0)


def test_transition_evidence_must_match_the_action():
    store_path_free = lift()
    base = dict(
        command=store_path_free,
        command_hash=store_path_free.command_hash,
        outcome="EXECUTED",
        occurred_at=datetime(2026, 9, 15, tzinfo=UTC),
        resulting_version="resource-v2",
        mutation_count=1,
    )
    lifted = EndpointTransition(
        before=EndpointState(contained=True), after=EndpointState(contained=False)
    )
    JournalRecord(**base, endpoint_transition=lifted)
    with pytest.raises(ValidationError, match="Unexpected transition evidence"):
        JournalRecord(**base)
    with pytest.raises(ValidationError, match="Invalid endpoint transition"):
        JournalRecord(
            **base,
            endpoint_transition=EndpointTransition(
                before=EndpointState(contained=True), after=EndpointState(contained=True)
            ),
        )
    isolate = command("endpoint.isolate", "mock_crowdstrike", "contain", {})
    with pytest.raises(ValidationError, match="Unexpected transition evidence"):
        JournalRecord(
            **{**base, "command": isolate, "command_hash": isolate.command_hash},
            endpoint_transition=lifted,
        )
    reset_command = reset(True)
    unchanged = IdentityTransition(
        before=IdentityState(account_enabled=True, session_generation=1),
        after=IdentityState(account_enabled=True, session_generation=1),
    )
    credential = CredentialTransition(
        before=CredentialState(password_generation=3, must_change_password=False),
        after=CredentialState(password_generation=4, must_change_password=True),
    )
    reset_base = {**base, "command": reset_command, "command_hash": reset_command.command_hash}
    JournalRecord(**reset_base, identity_transition=unchanged, credential_transition=credential)
    with pytest.raises(ValidationError, match="Unexpected transition evidence"):
        JournalRecord(**reset_base, identity_transition=unchanged)
    with pytest.raises(ValidationError, match="Invalid credential transition"):
        JournalRecord(
            **reset_base,
            identity_transition=unchanged,
            credential_transition=CredentialTransition(
                before=credential.before,
                after=CredentialState(password_generation=5, must_change_password=True),
            ),
        )
    with pytest.raises(ValidationError, match="Invalid credential transition"):
        JournalRecord(
            **reset_base,
            identity_transition=unchanged,
            credential_transition=CredentialTransition(
                before=credential.before,
                after=CredentialState(password_generation=4, must_change_password=False),
            ),
        )
    disable = command("identity.disable", "mock_entra", "disable", {})
    disabled = IdentityTransition(
        before=IdentityState(account_enabled=True, session_generation=1),
        after=IdentityState(account_enabled=False, session_generation=1),
    )
    with pytest.raises(ValidationError, match="Unexpected transition evidence"):
        JournalRecord(
            **{**base, "command": disable, "command_hash": disable.command_hash},
            identity_transition=disabled,
            credential_transition=credential,
        )


def test_mock_service_rejects_altered_arguments_before_any_journal(tmp_path):
    cmd = lift()
    store = MockStore(tmp_path / "endpoint.sqlite3")
    store.provision_resource(cmd.tenant_id, cmd.canonical_target_id, "resource-v1", contained=True)
    store.provision_representation(
        cmd.tenant_id, cmd.account_id, cmd.resource_provider_id, cmd.canonical_target_id
    )
    app = create_mock_app(store, (account(cmd, "mock_crowdstrike"),), provider="mock_crowdstrike")
    headers = {"Authorization": "Bearer " + DISPATCH_TOKEN, "Content-Type": "application/json"}
    altered = {**cmd.model_dump(mode="json"), "arguments": {"reason": "other"}}
    with TestClient(app) as client:
        assert (
            client.post(
                "/v1/lift_containment", content=json.dumps(altered), headers=headers
            ).status_code
            == 400
        )
        assert store.lookup(cmd) is None
        assert (
            client.post(
                "/v1/reset_password", content=cmd.model_dump_json(), headers=headers
            ).status_code
            == 404
        )
        good = client.post("/v1/lift_containment", content=cmd.model_dump_json(), headers=headers)
    assert good.status_code == 200 and good.json()["record"]["outcome"] == "EXECUTED"
    assert store.lookup(cmd).endpoint_transition.after.contained is False


def test_cancellation_fences_a_delayed_lift_containment(tmp_path):
    cmd = lift()
    store = MockStore(tmp_path / "endpoint.sqlite3")
    store.provision_resource(cmd.tenant_id, cmd.canonical_target_id, "resource-v1", contained=True)
    store.provision_representation(
        cmd.tenant_id, cmd.account_id, cmd.resource_provider_id, cmd.canonical_target_id
    )
    tombstone = store.cancel(cmd)
    assert tombstone.outcome == "CANCELLED_NOT_EXECUTED" and tombstone.mutation_count == 0
    assert not TRANSITIONS & set(tombstone.model_dump(mode="json"))
    assert store.dispatch(cmd) == store.lookup(cmd) == tombstone
    state = store.resource(cmd.tenant_id, cmd.canonical_target_id)
    assert state.contained is True and state.mutation_count == 0
    assert state.version == "resource-v1"


def test_cancellation_fences_a_delayed_reset_password(tmp_path):
    cmd = reset()
    store = IdentityStore(tmp_path / "identity.sqlite3")
    store.provision_resource(
        cmd.tenant_id, cmd.canonical_target_id, "resource-v1", session_generation=4
    )
    store.provision_representation(
        cmd.tenant_id, cmd.account_id, cmd.resource_provider_id, cmd.canonical_target_id
    )
    tombstone = store.cancel(cmd)
    assert tombstone.outcome == "CANCELLED_NOT_EXECUTED" and tombstone.mutation_count == 0
    assert not TRANSITIONS & set(tombstone.model_dump(mode="json"))
    assert store.dispatch(cmd) == store.lookup(cmd) == tombstone
    state = store.resource(cmd.tenant_id, cmd.canonical_target_id)
    assert (state.password_generation, state.must_change_password) == (0, False)
    assert state.mutation_count == 0 and state.version == "resource-v1"


@pytest.mark.parametrize("failure", ["VERSION_MISMATCH", "TARGET_NOT_FOUND"])
def test_lift_containment_nonexecution_carries_no_transition(tmp_path, failure):
    cmd = lift()
    store = MockStore(tmp_path / "endpoint.sqlite3")
    store.provision_resource(cmd.tenant_id, cmd.canonical_target_id, "resource-v9", contained=True)
    if failure == "VERSION_MISMATCH":
        store.provision_representation(
            cmd.tenant_id, cmd.account_id, cmd.resource_provider_id, cmd.canonical_target_id
        )
    record = store.dispatch(cmd)
    assert record.outcome == failure and record.mutation_count == 0
    assert record.resulting_version == ("resource-v9" if failure == "VERSION_MISMATCH" else None)
    assert not TRANSITIONS & set(record.model_dump(mode="json"))
    state = store.resource(cmd.tenant_id, cmd.canonical_target_id)
    assert state.contained is True and state.mutation_count == 0


@pytest.mark.parametrize("failure", ["VERSION_MISMATCH", "TARGET_NOT_FOUND"])
def test_reset_password_nonexecution_carries_no_transition(tmp_path, failure):
    cmd = reset()
    store = IdentityStore(tmp_path / "identity.sqlite3")
    store.provision_resource(
        cmd.tenant_id, cmd.canonical_target_id, "resource-v9", session_generation=4
    )
    if failure == "VERSION_MISMATCH":
        store.provision_representation(
            cmd.tenant_id, cmd.account_id, cmd.resource_provider_id, cmd.canonical_target_id
        )
    record = store.dispatch(cmd)
    assert record.outcome == failure and record.mutation_count == 0
    assert record.resulting_version == ("resource-v9" if failure == "VERSION_MISMATCH" else None)
    assert not TRANSITIONS & set(record.model_dump(mode="json"))
    state = store.resource(cmd.tenant_id, cmd.canonical_target_id)
    assert (state.password_generation, state.must_change_password) == (0, False)
    assert state.session_generation == 4 and state.mutation_count == 0


def test_store_that_cannot_execute_every_bound_action_is_refused_at_startup(tmp_path):
    class NarrowStore(MockStore):
        dispatch_actions = frozenset({"endpoint.isolate"})

    cmd = lift()
    accounts = (account(cmd, "mock_crowdstrike"),)
    assert create_mock_app(
        MockStore(tmp_path / "endpoint.sqlite3"), accounts, provider="mock_crowdstrike"
    )
    with pytest.raises(ProviderError) as exc:
        create_mock_app(
            NarrowStore(tmp_path / "narrow.sqlite3"), accounts, provider="mock_crowdstrike"
        )
    assert exc.value.code == "INVALID_CONFIGURATION"


def test_identity_service_exposes_reset_password_only(tmp_path):
    cmd = reset()
    store = IdentityStore(tmp_path / "identity.sqlite3")
    store.provision_resource(cmd.tenant_id, cmd.canonical_target_id, "resource-v1")
    store.provision_representation(
        cmd.tenant_id, cmd.account_id, cmd.resource_provider_id, cmd.canonical_target_id
    )
    app = create_mock_app(store, (account(cmd, "mock_entra"),), provider="mock_entra")
    headers = {"Authorization": "Bearer " + DISPATCH_TOKEN, "Content-Type": "application/json"}
    with TestClient(app) as client:
        assert (
            client.post(
                "/v1/lift_containment", content=cmd.model_dump_json(), headers=headers
            ).status_code
            == 404
        )
        response = client.post("/v1/reset_password", content=cmd.model_dump_json(), headers=headers)
    assert response.status_code == 200
    assert response.json()["record"]["credential_transition"]["after"]["password_generation"] == 1
