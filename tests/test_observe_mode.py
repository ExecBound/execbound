# SPDX-License-Identifier: AGPL-3.0-only
"""Observe-only mode: OB1 to OB12 on real PostgreSQL, live providers and Chromium."""

import json
import os
import re
import sys
from uuid import UUID, uuid4

import pytest
from alembic import command
from alembic.config import Config
from fastapi.testclient import TestClient
from identity_fixtures import identity_connector as identity_connector
from identity_fixtures import identity_provider as identity_provider
from identity_fixtures import identity_request
from identity_fixtures import identity_world as identity_world
from playwright.sync_api import expect
from replay_fixtures import chain_export, make_capture, replay_case, transition_event
from sqlalchemy import text
from test_browser_surfaces import agent_http as agent_http
from test_browser_surfaces import browser_gateway as browser_gateway
from test_browser_surfaces import chromium as chromium
from test_browser_surfaces import human_page as human_page
from test_browser_surfaces import open_activity, open_record, sign_in
from test_emergency_stop import (
    ROW_TABLES,
    audit,
    autonomous,
    invocations,
    mcp_execute,
    row_counts,
    scoped,
)
from test_execution import activate, request, targets
from test_execution import registry as registry
from test_execution import world as world
from test_human_surface import credential
from test_mcp_surface import gateway as gateway
from test_protected_path import connector as connector
from test_protected_path import live_provider as live_provider
from test_protected_path import resource
from test_runtime import api as api
from test_runtime import runtime as runtime

from execbound.app import create_app
from execbound.cli import main
from execbound.db import UPDATE_COLUMNS, check_runtime
from execbound.execution import (
    activate_stop,
    admit,
    decide_approval,
    enforcement_mode,
    set_enforcement_mode,
    store,
)
from execbound.execution.models import ExecutionError, transition_allowed
from execbound.replay.export import export_history
from execbound.replay.simulate import simulate
from execbound.replay.verify import verify_export
from execbound.runtime import Runtime


def control_mode(engine, tenant):
    with engine.begin() as conn:
        scoped(conn, tenant)
        return conn.execute(
            text("SELECT enforcement_mode FROM execbound.tenant_policy_control WHERE tenant_id=:t"),
            {"t": tenant},
        ).scalar_one()


def impacts(engine, tenant):
    with engine.begin() as conn:
        scoped(conn, tenant)
        return conn.execute(
            text(
                "SELECT state, approved FROM execbound.execution_impact "
                "WHERE tenant_id=:t ORDER BY created_at, execution_id"
            ),
            {"t": tenant},
        ).all()


def approvals(engine, tenant):
    with engine.begin() as conn:
        scoped(conn, tenant)
        return conn.execute(
            text("SELECT state FROM execbound.approvals WHERE tenant_id=:t"), {"t": tenant}
        ).all()


def observe(db, world, mode="OBSERVE", reason="Onboarding"):
    return set_enforcement_mode(db, world["admin"], mode, reason, world["clock"])


def tier_zero(engine, world):
    with engine.begin() as conn:
        conn.execute(
            text(
                "UPDATE execbound.resources SET role='domain_controller' "
                "WHERE tenant_id=:t AND resource_id=:r"
            ),
            {"t": world["identity"].tenant_id, "r": world["target"]},
        )


def test_ob1_an_observed_production_request_records_the_decision_without_any_effect(
    api, gateway, world, seeded, db, admin_engine, live_provider
):
    tenant = world["identity"].tenant_id
    observe(db, world)
    body = request(world).model_dump(mode="json")
    response = api.post("/v1/execute", json=body)
    assert response.status_code == 200, response.text
    payload = response.json()
    assert payload["state"] == "OBSERVED"
    assert payload["approval_id"] is None and payload["approval_state"] is None
    assert "continuation" not in payload and "approval_url" not in payload
    observed = payload["observed"]
    assert observed["effect"] == "REQUIRE_APPROVAL" and observed["mode"] == "tenant"
    assert observed["reasons"] == ["APPROVAL_REQUIRED"]
    assert len(observed["obligation_ids"]) == 1 and observed["obligation_ids"][0].startswith(
        "policy:"
    )
    status = api.get("/v1/executions/" + payload["execution_id"])
    assert status.status_code == 200 and status.json() == payload
    code, message = mcp_execute(gateway, seeded["tokens"][0], world)
    assert code == 200 and message["result"]["structuredContent"] == payload
    counts = row_counts(admin_engine, tenant)
    assert counts["executions"] == 1 and counts["resource_claims"] == 0
    assert approvals(admin_engine, tenant) == []
    assert impacts(admin_engine, tenant) == [("OBSERVED", True)]
    assert invocations(live_provider) == 0
    assert resource(live_provider, world).mutation_count == 0
    [evaluated] = audit(admin_engine, tenant, "execution.evaluated")
    assert evaluated["mode"] == "OBSERVE" and evaluated["decision"]["effect"] == "REQUIRE_APPROVAL"
    transitions = audit(admin_engine, tenant, "execution.transition")
    assert [t["to_state"] for t in transitions] == ["ATTEMPTED", "OBSERVED"]
    assert transitions[-1]["observed"] == observed


def test_ob2_ob3_would_be_eligible_and_denied_requests_are_observed_with_their_reasons(
    api, world, db, admin_engine, live_provider
):
    tenant = world["identity"].tenant_id
    observe(db, world)
    autonomous(admin_engine)
    eligible = api.post("/v1/execute", json=request(world).model_dump(mode="json"))
    assert eligible.status_code == 200 and eligible.json()["state"] == "OBSERVED"
    assert eligible.json()["observed"] == {
        "effect": "ELIGIBLE",
        "reasons": [],
        "obligation_ids": [],
        "mode": "tenant",
    }
    assert impacts(admin_engine, tenant) == [("OBSERVED", False)]
    tier_zero(admin_engine, world)
    denied = api.post(
        "/v1/execute",
        json=request(world, idempotency_key="tier-zero").model_dump(mode="json"),
    )
    assert denied.status_code == 200 and denied.json()["state"] == "OBSERVED"
    assert denied.json()["observed"]["effect"] == "DENY"
    assert "NOT_AUTHORIZED" in denied.json()["observed"]["reasons"]
    assert impacts(admin_engine, tenant) == [("OBSERVED", False)]
    counts = row_counts(admin_engine, tenant)
    assert counts["executions"] == 2 and counts["resource_claims"] == 0
    assert approvals(admin_engine, tenant) == [] and invocations(live_provider) == 0
    assert resource(live_provider, world).mutation_count == 0


def test_ob4_retries_return_the_same_view_and_a_new_key_observes_again(
    api, world, db, admin_engine
):
    tenant = world["identity"].tenant_id
    observe(db, world)
    body = request(world).model_dump(mode="json")
    first = api.post("/v1/execute", json=body).json()
    assert first["state"] == "OBSERVED"
    assert api.post("/v1/execute", json=body).json() == first
    before = row_counts(admin_engine, tenant)
    again = api.post(
        "/v1/execute",
        json=request(
            world,
            idempotency_key="second",
            target={"kind": "canonical", "value": str(world["target"])},
        ).model_dump(mode="json"),
    ).json()
    assert again["state"] == "OBSERVED" and again["execution_id"] != first["execution_id"]
    after = row_counts(admin_engine, tenant)
    assert after["executions"] == before["executions"] + 1
    assert after["execution_keys"] == before["execution_keys"] + 1
    assert after["resource_claims"] == 0 and approvals(admin_engine, tenant) == []


def test_ob5_an_enforcing_tenant_observes_one_mapping_and_enforces_the_rest(
    db, identity_world, identity_provider, identity_connector, seeded, admin_engine
):
    world = identity_world
    tenant = world["identity"].tenant_id
    mappings = tuple(
        m.model_copy(update={"observe_only": True}) if m.operation_ref == "identity.disable" else m
        for m in world["bundle"].mappings
    )
    activate(db, world, mappings=mappings)
    assert control_mode(admin_engine, tenant) == "ENFORCE"
    runtime = Runtime(db, [identity_connector], clock=world["clock"])
    with TestClient(create_app(db, runtime=runtime)) as client:
        client.headers["Authorization"] = "Bearer " + seeded["tokens"][0]
        disabled = client.post(
            "/v1/execute",
            json=identity_request(world, "identity.disable").model_dump(mode="json"),
        )
        assert disabled.status_code == 200 and disabled.json()["state"] == "OBSERVED"
        assert disabled.json()["observed"]["effect"] == "ELIGIBLE"
        assert disabled.json()["observed"]["mode"] == "mapping"
        assert identity_provider.store.resource(tenant, world["canonical"]).mutation_count == 0
        body = identity_request(world, "identity.enable").model_dump(mode="json")
        pending = client.post("/v1/execute", json=body)
        assert pending.status_code == 202 and pending.json()["state"] == "PENDING_APPROVAL"
        decide_approval(
            db, world["human"], UUID(pending.json()["approval_id"]), "APPROVE", world["clock"]
        )
        done = client.post("/v1/execute", json=body)
        assert done.status_code == 200 and done.json()["state"] == "EXECUTED"
    state = identity_provider.store.resource(tenant, world["canonical"])
    assert state.mutation_count == 1 and state.account_enabled
    assert sorted(row.state for row in impacts(admin_engine, tenant)) == ["CONFIRMED", "OBSERVED"]


def test_ob6_observed_decisions_project_limits_only_for_observe_mode(db, world, admin_engine):
    tenant = world["identity"].tenant_id
    observe(db, world)
    requests = targets(admin_engine, world, count=11)
    for req in requests[:10]:
        view = admit(db, world["identity"], req, world["clock"]).view
        assert view.state == "OBSERVED" and view.observed.effect == "ELIGIBLE"
    eleventh = admit(db, world["identity"], requests[10], world["clock"]).view
    assert eleventh.state == "OBSERVED" and eleventh.observed.effect == "REQUIRE_APPROVAL"
    assert eleventh.observed.obligation_ids == ("limit:principal-autonomous-isolation",)
    assert sorted(impacts(admin_engine, tenant)) == [("OBSERVED", False)] * 10 + [
        ("OBSERVED", True)
    ]
    with db.transaction(tenant) as conn:
        plan = store.frozen(store.read(conn, tenant, eleventh.execution_id))
        enforced = store.usage(
            conn, world["identity"], world["bundle"], world["clock"], frozen=plan
        )
        projected = store.usage(
            conn, world["identity"], world["bundle"], world["clock"], frozen=plan, observed=True
        )
    assert {(c.confirmed_targets, c.unresolved_targets) for c in enforced.counts} == {(0, 0)}
    assert sorted((c.confirmed_targets, c.unresolved_targets) for c in projected.counts) == [
        (10, 0),
        (11, 0),
    ]
    # Observed rows retain the attributes every scope counts over, like reservations do.
    with admin_engine.begin() as conn:
        scoped(conn, tenant)
        retained = (
            conn.execute(
                text(
                    "SELECT execution_id, account_id, group_ids, facts "
                    "FROM execbound.execution_impact WHERE tenant_id=:t"
                ),
                {"t": tenant},
            )
            .mappings()
            .all()
        )
    assert len(retained) == 11
    assert all(row["account_id"] == world["account"] and row["group_ids"] == [] for row in retained)
    facts = next(row["facts"] for row in retained if row["execution_id"] == eleventh.execution_id)
    assert {name: (type(value).__name__, value) for name, value in facts.items()} == {
        fact.name: (type(fact.value).__name__, fact.value) for fact in plan.facts
    }
    export = export_history(db, world["admin"], world["clock"])
    report = simulate(verify_export(export, export.head))
    assert report.complete, report.issues
    assert [d.baseline.effect for d in report.decisions] == ["ELIGIBLE"] * 10 + ["REQUIRE_APPROVAL"]
    observe(db, world, "ENFORCE", "Go live")
    [fresh] = targets(admin_engine, world, count=1)
    assert admit(db, world["identity"], fresh, world["clock"]).ticket is not None


def test_ob7_switching_to_enforce_is_audited_and_changes_nothing_retroactively(
    api, world, db, admin_engine
):
    tenant = world["identity"].tenant_id
    body = request(world).model_dump(mode="json")
    pending = api.post("/v1/execute", json=body).json()
    assert pending["state"] == "PENDING_APPROVAL"
    change = observe(db, world, reason="Onboarding <b>7</b>")
    assert (change.previous, change.mode) == ("ENFORCE", "OBSERVE")
    assert change.changed_by == world["admin"].principal_id
    assert control_mode(admin_engine, tenant) == "OBSERVE"
    assert enforcement_mode(db, world["admin"], world["clock"]) == "OBSERVE"
    retry = api.post("/v1/execute", json=body)
    assert retry.status_code == 202
    assert {k: retry.json()[k] for k in ("execution_id", "state", "approval_id")} == {
        k: pending[k] for k in ("execution_id", "state", "approval_id")
    }
    assert [row.state for row in approvals(admin_engine, tenant)] == ["PENDING"]
    [fresh, later] = targets(admin_engine, world, count=2, production=True)
    observed = api.post("/v1/execute", json=fresh.model_dump(mode="json")).json()
    assert observed["state"] == "OBSERVED"
    back = observe(db, world, "ENFORCE", "Go live")
    assert (back.previous, back.mode) == ("OBSERVE", "ENFORCE")
    changes = audit(admin_engine, tenant, "tenant.mode_changed")
    assert [(c["previous"], c["mode"], c["reason"]) for c in changes] == [
        ("ENFORCE", "OBSERVE", "Onboarding <b>7</b>"),
        ("OBSERVE", "ENFORCE", "Go live"),
    ]
    assert {c["principal_id"] for c in changes} == {str(world["admin"].principal_id)}
    enforced = api.post("/v1/execute", json=later.model_dump(mode="json"))
    assert enforced.status_code == 202 and enforced.json()["state"] == "PENDING_APPROVAL"
    assert [row.state for row in approvals(admin_engine, tenant)] == ["PENDING", "PENDING"]
    still = api.get("/v1/executions/" + observed["execution_id"]).json()
    assert still == observed
    with pytest.raises(ExecutionError) as terminal:
        with db.transaction(tenant) as conn:
            row = store.read(conn, tenant, UUID(observed["execution_id"]))
            store.transition(conn, row, world["identity"].principal_id, "RESERVED", world["clock"])
    assert terminal.value.code == "INVALID_STATE"
    assert not any(transition_allowed("OBSERVED", after) for after in ("RESERVED", "EXECUTED"))


def test_ob8_mode_changes_need_an_admin_a_reason_and_a_change_and_a_stop_refuses_observation(
    api, world, db, admin_engine
):
    tenant = world["identity"].tenant_id
    for actor in (world["identity"], world["human"]):
        with pytest.raises(ExecutionError) as forbidden:
            set_enforcement_mode(db, actor, "OBSERVE", "Not allowed", world["clock"])
        assert forbidden.value.code == "INVALID_IDENTITY"
    for reason in ("", " " * 3, "x" * 501):
        with pytest.raises(ExecutionError) as invalid:
            set_enforcement_mode(db, world["admin"], "OBSERVE", reason, world["clock"])
        assert invalid.value.code == "INVALID_REASON"
    with pytest.raises(ExecutionError) as same:
        set_enforcement_mode(db, world["admin"], "ENFORCE", "Already enforcing", world["clock"])
    assert same.value.code == "INVALID_STATE"
    with pytest.raises(ExecutionError) as unknown:
        set_enforcement_mode(db, world["admin"], "AUDIT", "Unknown mode", world["clock"])
    assert unknown.value.code == "INVALID_MODE"
    assert control_mode(admin_engine, tenant) == "ENFORCE"
    assert audit(admin_engine, tenant, "tenant.mode_changed") == []
    observe(db, world)
    activate_stop(db, world["admin"], "Incident 3", world["clock"])
    response = api.post("/v1/execute", json=request(world).model_dump(mode="json"))
    assert response.status_code == 423 and response.json()["code"] == "TENANT_STOPPED"
    assert row_counts(admin_engine, tenant) == dict.fromkeys(ROW_TABLES, 0)
    assert audit(admin_engine, tenant, "execution.evaluated") == []


def test_ob9_human_pages_show_observed_decisions_and_the_mode_without_forms(
    human_page, browser_gateway, agent_http, admin_engine, world, db
):
    observe(db, world)
    response = agent_http.post("/v1/execute", json=request(world).model_dump(mode="json"))
    assert response.status_code == 200 and response.json()["state"] == "OBSERVED"
    sign_in(human_page, admin_engine, world)
    # The mode is the tenant's and the shell says so on every route.
    expect(human_page.get_by_text("Observe only")).to_be_visible()
    # Scoped to the queue: the detail pane beside it renders the same sentence when
    # nothing is selected, so an unscoped match is two elements whenever both panes have
    # settled, which is what a loaded machine makes happen every time.
    expect(
        human_page.get_by_label("Queue").get_by_text("Nothing is waiting for you.")
    ).to_be_visible()
    open_activity(human_page)
    rows = human_page.get_by_role("table", name=re.compile("Activity")).get_by_role("row")
    expect(rows).to_have_count(2)
    expect(rows.nth(1)).to_contain_text("Observed")
    drawer = open_record(human_page)
    expect(drawer).to_contain_text("Observed")
    expect(drawer).to_contain_text("Facts used")
    # Nothing on the page decides or settles: an observed record offers neither.
    expect(drawer.get_by_role("button", name="Reconcile")).to_have_count(0)
    expect(human_page.get_by_role("button", name=re.compile(r"^Approve\b"))).to_have_count(0)


def test_ob10_audit_replay_and_preview_carry_the_mode_and_refuse_an_observed_effect(
    db, world, admin_engine
):
    observe(db, world)
    view = admit(db, world["identity"], request(world), world["clock"]).view
    assert view.state == "OBSERVED"
    export = export_history(db, world["admin"], world["clock"])
    history = verify_export(export, export.head)
    assert history.complete
    [capture] = [e.capture for e in history.events if e.capture is not None]
    assert capture.mode == "OBSERVE" and capture.decision.effect == "REQUIRE_APPROVAL"
    candidate = world["bundle"].model_copy(
        update={
            "bundle_id": uuid4(),
            "authorization_policies": "forbid(principal, action, resource);",
        }
    )
    report = simulate(history, candidate)
    [decision] = [d for d in report.decisions if d.execution_id == view.execution_id]
    assert decision.mode == "OBSERVE"
    assert (
        decision.baseline.effect == "REQUIRE_APPROVAL" and decision.baseline.outcome == "OBSERVED"
    )
    assert decision.candidate is not None and decision.candidate.effect == "DENY"
    case = replay_case()
    observed_capture = make_capture(case, mode="OBSERVE")
    with_claim = chain_export(
        [
            observed_capture,
            transition_event(observed_capture, "ATTEMPTED", "RESERVED", approved=False),
        ],
        [case["bundle"]],
    )
    verified = verify_export(with_claim, with_claim.head)
    assert not verified.complete and "OBSERVED_WITH_EFFECT" in verified.issues
    enforced_capture = make_capture(case)
    without_observation = chain_export(
        [
            enforced_capture,
            transition_event(
                enforced_capture,
                "ATTEMPTED",
                "OBSERVED",
                observed={
                    "effect": enforced_capture.decision.effect,
                    "reasons": list(enforced_capture.decision.reasons),
                    "obligation_ids": list(enforced_capture.decision.obligation_ids),
                    "mode": "tenant",
                },
            ),
        ],
        [case["bundle"]],
    )
    verified = verify_export(without_observation, without_observation.head)
    assert not verified.complete and "OBSERVED_WITH_EFFECT" in verified.issues


def test_ob11_migration_round_trip_and_runtime_catalog(db, world, admin_engine):
    tenant = world["identity"].tenant_id
    assert "enforcement_mode" in UPDATE_COLUMNS["tenant_policy_control"]
    with db.transaction(tenant) as conn:
        check_runtime(conn)
    config = Config("alembic.ini")
    config.attributes["database_url"] = os.environ["TEST_MIGRATION_DATABASE_URL"]
    observe(db, world)
    with pytest.raises(RuntimeError):
        command.downgrade(config, "0018_soc_actions")
    observe(db, world, "ENFORCE", "Round trip")
    command.downgrade(config, "0018_soc_actions")
    command.upgrade(config, "head")
    with db.transaction(tenant) as conn:
        check_runtime(conn)
    assert control_mode(admin_engine, tenant) == "ENFORCE"
    observe(db, world)
    assert admit(db, world["identity"], request(world), world["clock"]).view.state == "OBSERVED"
    observe(db, world, "ENFORCE", "Rows retained")
    with pytest.raises(RuntimeError):
        command.downgrade(config, "0018_soc_actions")
    with db.transaction(tenant) as conn:
        check_runtime(conn)


def test_ob12_cli_sets_and_reports_the_mode_and_summarizes_observed_decisions(
    db, world, admin_engine, api, tmp_path, monkeypatch, capsys
):
    tenant = world["identity"].tenant_id
    monkeypatch.setenv("DATABASE_URL", os.environ["TEST_DATABASE_URL"])
    monkeypatch.setenv("MIGRATION_DATABASE_URL", os.environ["TEST_MIGRATION_DATABASE_URL"])
    admin_file, human_file = tmp_path / "admin.token", tmp_path / "human.token"
    admin_file.write_text(credential(admin_engine, world["admin"]), encoding="utf-8")
    human_file.write_text(credential(admin_engine, world["human"]), encoding="utf-8")

    def run(*argv):
        monkeypatch.setattr(sys, "argv", ["execbound", *argv])
        main()
        return json.loads(capsys.readouterr().out)

    def refused(*argv):
        monkeypatch.setattr(sys, "argv", ["execbound", *argv])
        with pytest.raises(SystemExit) as caught:
            main()
        assert caught.value.code == 2
        return capsys.readouterr().err

    common = ("--tenant", str(tenant), "--credential-file")
    assert "INVALID_IDENTITY" in refused(
        "tenant-mode", *common, str(human_file), "--set", "OBSERVE", "--reason", "No"
    )
    assert control_mode(admin_engine, tenant) == "ENFORCE"
    changed = run("tenant-mode", *common, str(admin_file), "--set", "OBSERVE", "--reason", "Trial")
    assert changed == {
        "tenant_id": str(tenant),
        "enforcement_mode": "OBSERVE",
        "previous": "ENFORCE",
    }
    status = run("tenant-status", *common, str(admin_file))
    assert status["enforcement_mode"] == "OBSERVE" and status["stopped"] is False
    assert "INVALID_STATE" in refused(
        "tenant-mode", *common, str(admin_file), "--set", "OBSERVE", "--reason", "Again"
    )
    production = api.post("/v1/execute", json=request(world).model_dump(mode="json")).json()
    assert production["state"] == "OBSERVED"
    for req in targets(admin_engine, world, count=11):
        assert admit(db, world["identity"], req, world["clock"]).view.state == "OBSERVED"
    assert "INVALID_IDENTITY" in refused("observe-report", *common, str(human_file))
    report = run("observe-report", *common, str(admin_file), "--since-hours", "1")
    assert report["tenant_id"] == str(tenant) and report["since_hours"] == 1
    assert report["observed"] == 12
    assert report["effects"] == {"ELIGIBLE": 10, "REQUIRE_APPROVAL": 2}
    assert report["actions"] == {"endpoint.isolate": {"ELIGIBLE": 10, "REQUIRE_APPROVAL": 2}}
    assert report["reasons"] == {"APPROVAL_REQUIRED": 2}
    assert [p["obligations"] for p in report["projected_limits"]] == [
        ["limit:principal-autonomous-isolation"]
    ]
    evaluated = audit(admin_engine, tenant, "execution.evaluated")
    assert len([p for p in evaluated if p.get("mode") == "OBSERVE"]) == report["observed"]
    assert run("observe-report", *common, str(admin_file), "--since-hours", "0")["observed"] == 0
