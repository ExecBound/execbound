# SPDX-License-Identifier: AGPL-3.0-only
"""Sample targets end to end (#420, SM5).

A workspace made through the owner commands' functions, its administrator signed in with a
password, its own agents asking the gateway over HTTP, and the endpoint mock as a real process
holding the sample key. The gateway derives each sample connection from its own copy of the key:
nothing about the workspace is configured anywhere, and every request passes the whole kernel.
"""

from uuid import UUID

import pytest
from fastapi.testclient import TestClient
from sample_fixtures import agent_token, empty_workspace, invocations, password_workspace
from sample_fixtures import sample_key as sample_key
from sample_fixtures import sample_mock as sample_mock
from sample_fixtures import sample_runtime as sample_runtime
from sqlalchemy import text

from execbound import samples
from execbound.app import create_app
from execbound.execution import decide_approval, store
from execbound.identity import authenticate
from execbound.provider.connector import JournalVerifier
from execbound.provider.gateway import reconcile_operation
from execbound.provider.models import ProviderError, SignedJournal
from execbound.provider.sample_accounts import (
    SAMPLE_KEY_ID,
    SAMPLE_RESOURCE_VERSION,
    sample_material,
)
from execbound.replay.export import export_history
from execbound.replay.simulate import simulate
from execbound.replay.verify import verify_export

pytestmark = pytest.mark.integration


def request_for(host, key):
    return {
        "operation_ref": "endpoint.isolate",
        "target": {"kind": "hostname", "value": host.hostname},
        "arguments": {},
        "idempotency_key": key,
        "claimed_context": {"incident_id": str(host.incident_id)},
    }


def by_effect(status):
    return {host.effect: host for host in status.hosts}


def execution_row(admin_engine, tenant, execution_id):
    with admin_engine.begin() as conn:
        conn.execute(text("SELECT set_config('execbound.tenant_id', :t, true)"), {"t": str(tenant)})
        return dict(
            conn.execute(
                text(
                    "SELECT state, result, settlement_tier, precondition_class "
                    "FROM execbound.executions WHERE tenant_id = :t AND execution_id = :e"
                ),
                {"t": tenant, "e": execution_id},
            )
            .mappings()
            .one()
        )


def test_sm5_the_three_sample_requests_run_against_a_real_mock_and_replay(
    db, admin_engine, seeded, tmp_path, sample_mock, sample_runtime, sample_key
):
    workspace = password_workspace(admin_engine, db, tmp_path)
    installed = samples.install(db, workspace.admin, available=True, clock=sample_runtime.clock)
    hosts = by_effect(installed)
    assert set(hosts) == {"allow", "require approval", "deny"}
    assert installed.account_id is not None
    material = sample_material(sample_key, workspace.tenant_id, installed.account_id)
    first_agent = agent_token(admin_engine, workspace)
    second_agent = agent_token(admin_engine, workspace)

    with TestClient(create_app(db, runtime=sample_runtime)) as client:

        def ask(token, host, key):
            return client.post(
                "/v1/execute",
                json=request_for(host, key),
                headers={"Authorization": "Bearer " + token},
            )

        executed = ask(first_agent, hosts["allow"], "sample-dev")
        assert executed.status_code == 200, executed.text
        assert executed.json()["state"] == "EXECUTED"
        denied = ask(first_agent, hosts["deny"], "sample-dc")
        assert denied.status_code == 200 and denied.json()["state"] == "DENIED"
        pending = ask(first_agent, hosts["require approval"], "sample-prod")
        assert pending.status_code == 202 and pending.json()["state"] == "PENDING_APPROVAL"
        # The signed-in person approves it; the agent's retry of the same request executes.
        decide_approval(
            db,
            workspace.admin,
            UUID(pending.json()["approval_id"]),
            "APPROVE",
            sample_runtime.clock,
        )
        approved = ask(first_agent, hosts["require approval"], "sample-prod")
        assert approved.status_code == 200 and approved.json()["state"] == "EXECUTED"

    dev_id = UUID(executed.json()["execution_id"])
    dc_id = UUID(denied.json()["execution_id"])
    prod_id = UUID(approved.json()["execution_id"])

    # The journal the mock signed under the derived key, verified with it and with no other.
    dev = execution_row(admin_engine, workspace.tenant_id, dev_id)
    assert dev["settlement_tier"] is None
    assert dev["precondition_class"] == "ENFORCED_BY_PROVIDER"
    record = dev["result"]["authenticated_record"].encode()
    signed = SignedJournal.model_validate_json(record)
    assert (signed.key_id, signed.record.outcome) == (SAMPLE_KEY_ID, "EXECUTED")
    verifier = JournalVerifier(
        workspace.tenant_id, installed.account_id, {SAMPLE_KEY_ID: material.journal_key}
    )
    assert verifier.verify_command(signed.record.command, record).outcome == "EXECUTED"
    with pytest.raises(ProviderError):
        JournalVerifier(
            workspace.tenant_id, installed.account_id, {SAMPLE_KEY_ID: b"\x07" * 32}
        ).verify_command(signed.record.command, record)

    # The mock acted twice: the development and the approved production workstation.
    mock = sample_mock.store
    held = mock.resource(workspace.tenant_id, hosts["allow"].canonical_target_id)
    assert held is not None and held.contained and held.mutation_count == 1
    assert held.version == signed.record.resulting_version != SAMPLE_RESOURCE_VERSION
    production = mock.resource(workspace.tenant_id, hosts["require approval"].canonical_target_id)
    assert production is not None and production.contained and production.mutation_count == 1
    assert mock.resource(workspace.tenant_id, hosts["deny"].canonical_target_id) is None
    assert len(invocations(sample_mock)) == 2

    # Shared limits count sample requests, across agents of the tenant.
    first, second = authenticate(db, first_agent), authenticate(db, second_agent)
    with db.transaction(workspace.tenant_id) as conn:
        bundle = store.active_bundle(conn, workspace.tenant_id)
        plan = store.frozen(store.read(conn, workspace.tenant_id, dev_id))
        mine = store.usage(conn, first, bundle, sample_runtime.clock, frozen=plan)
        theirs = store.usage(conn, second, bundle, sample_runtime.clock, frozen=plan)
    assert {count.rule_id: count.confirmed_targets for count in mine.counts} == {
        "principal-autonomous-isolation": 1,
        "tenant-total-isolation": 2,
    }
    assert {count.rule_id: count.confirmed_targets for count in theirs.counts} == {
        "principal-autonomous-isolation": 0,
        "tenant-total-isolation": 2,
    }

    # Replay reproduces every decision and touches neither the mock nor its journal.
    before = (
        mock.resource(workspace.tenant_id, hosts["allow"].canonical_target_id),
        invocations(sample_mock),
    )
    history = export_history(db, workspace.admin, sample_runtime.clock)
    report = simulate(verify_export(history, history.head))
    assert report.complete, report.issues
    ours = [d for d in report.decisions if d.execution_id in {dev_id, dc_id, prod_id}]
    assert {d.execution_id for d in ours} == {dev_id, dc_id, prod_id}
    assert all(d.baseline.effect == d.recorded_effect for d in ours)
    last = {d.execution_id: d for d in ours}
    assert last[dev_id].baseline.outcome == "EXECUTED"
    assert last[prod_id].baseline.outcome == "EXECUTED"
    assert last[dc_id].baseline.effect == "DENY"
    assert (
        mock.resource(workspace.tenant_id, hosts["allow"].canonical_target_id),
        invocations(sample_mock),
    ) == before


def test_sm5b_a_lost_sample_response_settles_from_the_mock_journal(
    db, admin_engine, seeded, sample_mock, sample_runtime
):
    workspace = empty_workspace(admin_engine, db)
    installed = samples.install(db, workspace.admin, available=True, clock=sample_runtime.clock)
    assert installed.account_id is not None
    dev = by_effect(installed)["allow"]
    token = agent_token(admin_engine, workspace)
    # The mock commits the effect and dies before it answers.
    sample_mock.restart("crash_after_commit")
    with TestClient(create_app(db, runtime=sample_runtime)) as client:
        lost = client.post(
            "/v1/execute",
            json=request_for(dev, "sample-lost"),
            headers={"Authorization": "Bearer " + token},
        )
    assert lost.json()["state"] == "INDETERMINATE", lost.text
    # An unsettled sample request holds its samples in place.
    with pytest.raises(samples.SampleError) as busy:
        samples.remove(db, workspace.admin, available=True)
    assert busy.value.code == "SAMPLES_BUSY"
    sample_mock.restart()
    with sample_runtime.connection(workspace.tenant_id, installed.account_id) as connector:
        assert connector is not None
        settled = reconcile_operation(
            db,
            workspace.admin,
            UUID(lost.json()["execution_id"]),
            connector,
            reason="The sample mock's answer was lost in transit.",
        )
    assert settled.state == "EXECUTED"
    assert len(invocations(sample_mock)) == 1
    assert samples.remove(db, workspace.admin, available=True).state == "absent"
