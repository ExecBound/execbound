# SPDX-License-Identifier: AGPL-3.0-only
"""Real PostgreSQL authority plus independently authenticated identity provider I/O."""

from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from pathlib import Path
from threading import Barrier
from uuid import UUID, uuid4

import pytest
from fastapi.testclient import TestClient
from identity_fixtures import ACTIONS, add_target, identity_request
from identity_fixtures import identity_connector as identity_connector
from identity_fixtures import identity_provider as identity_provider
from identity_fixtures import identity_world as identity_world
from identity_fixtures import registry as registry
from identity_fixtures import world as world
from sqlalchemy import text
from test_execution import activate, admitted_plan
from test_human_surface import credential, form_values

from execbound.app import create_app
from execbound.execution import admit, decide_approval, store, take_dispatch
from execbound.execution.models import ExecutionError
from execbound.operations import PRODUCTION_ACTIONS, operation
from execbound.provider.connector import MockConnector
from execbound.provider.gateway import dispatch_owned, reconcile_operation
from execbound.provider.models import provider_command
from execbound.runtime import Runtime
from execbound.surfaces.human import HumanConfig
from execbound.surfaces.tokens import TokenKeys


@pytest.fixture
def runtime(db, identity_world, identity_connector):
    return Runtime(db, [identity_connector], clock=identity_world["clock"])


@pytest.fixture
def api(db, runtime, seeded):
    with TestClient(create_app(db, runtime=runtime)) as client:
        client.headers["Authorization"] = "Bearer " + seeded["tokens"][0]
        yield client


def ready(db, world, action):
    request = identity_request(world, action)
    admission = admit(db, world["identity"], request, world["clock"])
    if admission.view.state == "PENDING_APPROVAL":
        decide_approval(db, world["human"], admission.view.approval_id, "APPROVE", world["clock"])
        admission = admit(db, world["identity"], request, world["clock"])
    assert admission.ticket is not None
    return admission


def state(provider, world):
    return provider.store.resource(world["identity"].tenant_id, world["canonical"])


def impact(engine, execution_id):
    with engine.connect() as conn:
        return conn.execute(
            text("""SELECT action,state FROM execbound.execution_impact
            WHERE execution_id=:e"""),
            {"e": execution_id},
        ).one()


def invocations(provider):
    path = Path(provider.environment["TEST_PROVIDER_INVOCATIONS"])
    return path.read_text().splitlines() if path.exists() else []


@pytest.mark.parametrize("action", ACTIONS)
def test_http_exact_action_accounting_retry_and_status(
    api, db, identity_world, identity_provider, admin_engine, action
):
    world = identity_world
    body = identity_request(world, action).model_dump(mode="json")
    initial = api.post("/v1/execute", json=body)
    if action == "identity.enable":
        assert initial.status_code == 202
        assert initial.json()["state"] == "PENDING_APPROVAL"
        assert state(identity_provider, world).mutation_count == 0
        decide_approval(
            db, world["human"], UUID(initial.json()["approval_id"]), "APPROVE", world["clock"]
        )
        initial = api.post("/v1/execute", json=body)
    assert initial.status_code == 200 and initial.json()["state"] == "EXECUTED"
    executed = initial.json()
    assert impact(admin_engine, UUID(executed["execution_id"])) == (action, "CONFIRMED")
    assert api.post("/v1/execute", json=body).json() == executed
    assert api.get("/v1/executions/" + executed["execution_id"]).json() == executed
    resource = state(identity_provider, world)
    assert resource.mutation_count == 1
    assert resource.account_enabled == (action != "identity.disable")
    assert resource.session_generation == (1 if action.endswith("revoke_sessions") else 0)
    assert len(invocations(identity_provider)) == 1


@pytest.mark.parametrize("action", ACTIONS)
def test_wrong_provider_configuration_rejects_before_reservation(
    db, identity_world, identity_provider, admin_engine, action
):
    mismatch = MockConnector(replace(identity_provider.config, provider="mock_crowdstrike"))
    try:
        runtime = Runtime(db, [mismatch], clock=identity_world["clock"])
        with pytest.raises(ExecutionError) as error:
            runtime.execute(
                identity_world["identity"],
                identity_request(identity_world, action).model_dump_json().encode(),
            )
        assert error.value.code == "CONNECTOR_UNAVAILABLE"
        with admin_engine.connect() as conn:
            assert conn.execute(text("SELECT count(*) FROM execbound.executions")).scalar_one() == 0
        assert invocations(identity_provider) == []
    finally:
        mismatch.close()


@pytest.mark.parametrize("action", ACTIONS)
def test_human_exact_action_scope_label_and_context(
    db, runtime, identity_world, identity_provider, admin_engine, action
):
    world = identity_world
    with admin_engine.begin() as conn:
        conn.execute(
            text("UPDATE execbound.resources SET environment='production' WHERE resource_id=:r"),
            {"r": world["target"]},
        )
        conn.execute(
            text("UPDATE execbound.approval_scopes SET active=false WHERE action=:a"), {"a": action}
        )
    request = identity_request(world, action)
    pending = runtime.execute(world["identity"], request.model_dump_json().encode())
    assert pending.state == "PENDING_APPROVAL"
    with pytest.raises(ExecutionError):
        decide_approval(db, world["human"], pending.approval_id, "APPROVE", world["clock"])
    config = HumanConfig("http://127.0.0.1", TokenKeys("test-v1", {"test-v1": bytes(range(32))}))
    with TestClient(
        create_app(db, runtime=runtime, human=config),
        base_url=config.origin,
        follow_redirects=False,
    ) as client:
        _, values = form_values(client.get("/login").text, "/session")
        values["credential"] = credential(admin_engine, world["human"])
        assert (
            client.post("/session", data=values, headers={"Origin": config.origin}).status_code
            == 303
        )
        queue = client.get("/api/console/v1/approvals")
        assert queue.status_code == 200 and world["provider_id"] not in queue.text
        with admin_engine.begin() as conn:
            conn.execute(
                text("UPDATE execbound.approval_scopes SET active=true WHERE action=:a"),
                {"a": action},
            )
        queue = client.get("/api/console/v1/approvals")
        assert queue.status_code == 200
        [item] = queue.json()["items"]
        assert item["action_label"] == operation(action).label
        page = client.get(f"/approvals/{item['approval_id']}/classic")
        assert page.status_code == 200
        assert operation(action).label.upper() in page.text
        assert "standard" in page.text and "privilege class" in page.text
        assert "ENDPOINT ISOLATION" not in page.text
        path, values = form_values(page.text, "/decide")
        values["decision"] = "APPROVE"
        assert client.post(path, data=values, headers={"Origin": config.origin}).status_code == 303
        assert client.post(path, data=values, headers={"Origin": config.origin}).status_code == 409
    assert (
        runtime.execute(world["identity"], request.model_dump_json().encode()).state == "EXECUTED"
    )
    assert state(identity_provider, world).mutation_count == 1


@pytest.mark.parametrize("action", ACTIONS)
def test_current_privilege_change_invalidates_pending_approval(
    db, identity_world, identity_provider, admin_engine, action
):
    world = identity_world
    with admin_engine.begin() as conn:
        conn.execute(
            text("UPDATE execbound.resources SET environment='production' WHERE resource_id=:r"),
            {"r": world["target"]},
        )
    request = identity_request(world, action)
    pending = admit(db, world["identity"], request, world["clock"])
    decide_approval(db, world["human"], pending.view.approval_id, "APPROVE", world["clock"])
    with admin_engine.begin() as conn:
        conn.execute(
            text(
                "UPDATE execbound.resources SET privilege_class='tier0',version='promoted-v2' "
                "WHERE resource_id=:r"
            ),
            {"r": world["target"]},
        )
    retried = admit(db, world["identity"], request, world["clock"])
    assert retried.view.state == "STALE_AUTHORIZATION" and retried.ticket is None
    assert invocations(identity_provider) == []


@pytest.mark.parametrize("action", ACTIONS)
def test_lost_response_retains_impact_until_exact_journal_reconciliation(
    db, identity_world, identity_provider, identity_connector, admin_engine, action
):
    world = identity_world
    identity_provider.restart("crash_after_commit")
    admission = ready(db, world, action)
    result = dispatch_owned(db, admission.ticket, identity_connector, world["clock"])
    assert result.state == "INDETERMINATE"
    assert impact(admin_engine, result.execution_id) == (action, "UNRESOLVED")
    assert state(identity_provider, world).mutation_count == 1
    assert (
        admit(db, world["identity"], identity_request(world, action), world["clock"]).ticket is None
    )
    # A later inverse action changes current state but cannot replace this operation's journal.
    with db.transaction(world["identity"].tenant_id) as conn:
        frozen_command = store.command(
            store.read(conn, world["identity"].tenant_id, result.execution_id)
        )
    original = provider_command(frozen_command)
    inverse = "identity.enable" if action == "identity.disable" else "identity.disable"
    inverse_binding = PRODUCTION_ACTIONS.binding(original.provider, inverse)
    later = original.model_copy(
        update={
            "operation_id": uuid4(),
            "execution_id": uuid4(),
            "action": inverse,
            "provider_operation": inverse_binding.provider_operation,
            "expected_version": state(identity_provider, world).version,
        }
    )
    identity_provider.store.dispatch(later)
    assert state(identity_provider, world).mutation_count == 2
    identity_provider.restart()
    recovered = reconcile_operation(
        db,
        world["admin"],
        result.execution_id,
        identity_connector,
        reason="Recover exact synthetic journal",
        clock=world["clock"],
    )
    assert recovered.state == "EXECUTED"
    assert impact(admin_engine, result.execution_id) == (action, "CONFIRMED")
    assert len(invocations(identity_provider)) == 1


@pytest.mark.parametrize("action", ACTIONS)
def test_missing_journal_keeps_guard_then_cancel_fences_delayed_arrival(
    db, identity_world, identity_provider, identity_connector, admin_engine, action
):
    world = identity_world
    admission = ready(db, world, action)
    command = take_dispatch(db, admission.ticket, world["clock"])
    result = reconcile_operation(
        db,
        world["admin"],
        admission.view.execution_id,
        identity_connector,
        reason="Investigate missing dispatch",
        clock=world["clock"],
    )
    assert result.state == "INDETERMINATE"
    assert impact(admin_engine, result.execution_id) == (action, "UNRESOLVED")
    conflicting = "identity.disable" if action != "identity.disable" else "identity.revoke_sessions"
    conflict = admit(db, world["identity"], identity_request(world, conflicting), world["clock"])
    assert conflict.view.state == "DENIED" and conflict.ticket is None
    cancelled = reconcile_operation(
        db,
        world["admin"],
        result.execution_id,
        identity_connector,
        reason="Fence synthetic late arrival",
        cancel_if_missing=True,
        clock=world["clock"],
    )
    assert cancelled.state == "FAILED_NOT_EXECUTED"
    assert impact(admin_engine, result.execution_id) == (action, "NONEXECUTION")
    identity_connector.dispatch(provider_command(command))
    assert state(identity_provider, world).mutation_count == 0


@pytest.mark.parametrize("action", ACTIONS)
def test_concurrent_exact_action_tenant_cap_cannot_be_bypassed_by_approval(
    db, identity_world, identity_provider, identity_connector, admin_engine, action
):
    world = identity_world
    second = add_target(admin_engine, world)
    identity_provider.store.provision_resource(
        world["identity"].tenant_id, second["canonical"], "resource-v1"
    )
    identity_provider.store.provision_representation(
        world["identity"].tenant_id, world["account"], second["provider_id"], second["canonical"]
    )
    limits = tuple(
        rule.model_copy(update={"max_targets": 1})
        if rule.action == action and rule.scope == "tenant"
        else rule
        for rule in world["bundle"].limits
    )
    activate(db, world, limits=limits)
    requests = [
        identity_request(target, action, idempotency_key=str(uuid4())) for target in (world, second)
    ]
    # Production makes every action use assigned approval before the capacity race.
    with admin_engine.begin() as conn:
        conn.execute(
            text("UPDATE execbound.resources SET environment='production' WHERE account_id=:a"),
            {"a": world["account"]},
        )
    for request in requests:
        pending = admit(db, world["identity"], request, world["clock"])
        decide_approval(db, world["human"], pending.view.approval_id, "APPROVE", world["clock"])
    barrier = Barrier(2)

    def run(request):
        barrier.wait(timeout=5)
        return admit(db, world["identity"], request, world["clock"])

    with ThreadPoolExecutor(max_workers=2) as pool:
        admissions = list(pool.map(run, requests))
    assert sorted(item.view.state for item in admissions) == ["DENIED", "DISPATCH_COMMITTED"]
    winner = next(item for item in admissions if item.ticket)
    assert dispatch_owned(db, winner.ticket, identity_connector, world["clock"]).state == "EXECUTED"
    assert len(invocations(identity_provider)) == 1
    with db.transaction(world["identity"].tenant_id) as conn:
        plan = admitted_plan(conn, world, winner)
        usage = store.usage(conn, world["identity"], world["bundle"], world["clock"], frozen=plan)
    counts = {count.rule_id: count for count in usage.counts}
    for rule in world["bundle"].limits:
        expected = 1 if rule.action == action and rule.budget == "total" else 0
        assert counts[rule.rule_id].confirmed_targets == expected


def test_inverse_enable_and_revocation_never_refund_disable_history(
    db, identity_world, identity_provider, identity_connector, admin_engine
):
    world = identity_world
    executions = []
    for action in ACTIONS:
        admission = ready(db, world, action)
        result = dispatch_owned(db, admission.ticket, identity_connector, world["clock"])
        assert result.state == "EXECUTED"
        executions.append((result.execution_id, action))
        with admin_engine.begin() as conn:
            conn.execute(
                text(
                    "UPDATE execbound.resources SET version=:v,observed_at=:n WHERE resource_id=:r"
                ),
                {
                    "v": state(identity_provider, world).version,
                    "n": world["clock"].now(),
                    "r": world["target"],
                },
            )
    assert [impact(admin_engine, execution) for execution, _ in executions] == [
        (action, "CONFIRMED") for _, action in executions
    ]
    assert state(identity_provider, world).account_enabled
    assert state(identity_provider, world).session_generation == 1
    assert state(identity_provider, world).mutation_count == 3
