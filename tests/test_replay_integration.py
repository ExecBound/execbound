# SPDX-License-Identifier: AGPL-3.0-only
"""Actual captured PostgreSQL and signed HTTP evidence replay without live effects."""

import hashlib
import json
import sqlite3
from pathlib import Path

import pytest
from console_api_fixtures import API, console_client
from identity_fixtures import ACTIONS, identity_request
from identity_fixtures import identity_connector as identity_connector
from identity_fixtures import identity_provider as identity_provider
from identity_fixtures import identity_world as identity_world
from identity_fixtures import registry as registry
from identity_fixtures import world as world
from test_emergency_stop import audit
from test_execution import request
from test_protected_path import connector as connector
from test_protected_path import live_provider as live_provider
from test_replay_export import fingerprint, publish
from test_replay_isolation import isolated_replay
from test_runtime import runtime as runtime

from execbound.execution import admit, decide_approval
from execbound.provider.gateway import dispatch_owned
from execbound.replay.export import export_history
from execbound.replay.simulate import simulate
from execbound.replay.verify import verify_export


def provider_fingerprint(provider):
    database = provider.environment["EXECBOUND_MOCK_DATABASE_PATH"]
    with sqlite3.connect(database) as conn:
        names = [
            row[0] for row in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")
        ]
        rows = [
            (name, sorted(conn.execute('SELECT * FROM "' + name + '"').fetchall(), key=repr))
            for name in sorted(names)
        ]
    for key in ("TEST_PROVIDER_INVOCATIONS", "TEST_PROVIDER_REQUESTS"):
        path = Path(provider.environment[key])
        rows.append((key, path.read_bytes() if path.exists() else None))
    return hashlib.sha256(repr(rows).encode()).hexdigest()


def execute(db, world, body, connector):
    admission = admit(db, world["identity"], body, world["clock"])
    if admission.view.state == "PENDING_APPROVAL":
        decide_approval(db, world["human"], admission.view.approval_id, "APPROVE", world["clock"])
        admission = admit(db, world["identity"], body, world["clock"])
    assert admission.ticket is not None
    assert dispatch_owned(db, admission.ticket, connector, world["clock"]).state == "EXECUTED"
    return admission.view.execution_id


def assert_offline(db, world, provider, admin_engine, tmp_path, execution_id):
    control_before, provider_before = fingerprint(admin_engine), provider_fingerprint(provider)
    history = export_history(db, world["admin"], world["clock"])
    report = simulate(verify_export(history, history.head))
    assert report.complete, report.issues
    decision = report.decisions[-1]
    assert decision.execution_id == execution_id
    assert decision.baseline.effect == "ELIGIBLE"
    assert decision.baseline.outcome == "EXECUTED"
    assert decision.baseline.provenance == "RECORDED_GATEWAY_EVIDENCE"
    output = tmp_path / "export"
    output.mkdir()
    source, checkpoint = publish(db, world, output, history)
    provider.stop()
    result = isolated_replay(source, checkpoint, tmp_path / "offline")
    assert result.returncode == 0, result.stderr
    candidate = world["bundle"].model_copy(
        update={"authorization_policies": "forbid(principal, action, resource);"}
    )
    candidate_file = tmp_path / "candidate.json"
    candidate_file.write_text(candidate.model_dump_json())
    result = isolated_replay(source, checkpoint, tmp_path / "comparison", candidate_file)
    assert result.returncode == 0, result.stderr
    compared = json.loads((tmp_path / "comparison" / "report.json").read_text())
    assert compared["decisions"][-1]["candidate"]["effect"] == "DENY"
    assert fingerprint(admin_engine) == control_before
    assert provider_fingerprint(provider) == provider_before


def test_actual_endpoint_history_and_approval_replay_without_live_access(
    db, world, live_provider, connector, admin_engine, tmp_path
):
    execution_id = execute(db, world, request(world), connector)
    assert_offline(db, world, live_provider, admin_engine, tmp_path, execution_id)


def test_a_named_agent_leaves_every_later_decision_replayable(
    db, world, live_provider, connector, runtime, admin_engine
):
    """Naming an agent in the console appends `principal.labelled`, which decides nothing.

    Replay did not know the kind, so every decision after a tenant's first named agent
    replayed `UNRESOLVED` with `INCOMPLETE_PRIOR_HISTORY`. The hosted Defender signal stage
    found it on October 3, 2026, in a workspace whose people had been named in the console.
    """
    with console_client(db, runtime, admin_engine, world["admin"]) as client:
        named = client.post(
            f"{API}/credentials/issue",
            {"principal": "new:AGENT", "label": "Triage agent", "lifetime": "8"},
        )
        assert named.status_code == 200, named.text
    assert [
        event["label"]
        for event in audit(admin_engine, world["identity"].tenant_id, "principal.labelled")
    ] == ["Triage agent"]
    execution_id = execute(db, world, request(world), connector)
    history = export_history(db, world["admin"], world["clock"])
    verified = verify_export(history, history.head)
    assert "UNKNOWN_EVENT_SEMANTICS" not in verified.issues
    report = simulate(verified)
    assert report.complete, report.issues
    decision = report.decisions[-1]
    assert decision.execution_id == execution_id
    assert decision.baseline.effect == "ELIGIBLE"
    assert decision.baseline.outcome == "EXECUTED"
    assert decision.baseline.provenance == "RECORDED_GATEWAY_EVIDENCE"


@pytest.mark.parametrize("action", ACTIONS)
def test_actual_identity_history_and_approval_replay_without_live_access(
    db, identity_world, identity_provider, identity_connector, admin_engine, tmp_path, action
):
    execution_id = execute(
        db, identity_world, identity_request(identity_world, action), identity_connector
    )
    assert_offline(db, identity_world, identity_provider, admin_engine, tmp_path, execution_id)
