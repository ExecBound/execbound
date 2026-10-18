# SPDX-License-Identifier: AGPL-3.0-only
"""The approval deadline is a per-tenant setting bounded by the frozen plan's validity
(#213): AD1 to AD6 and AD11 here; the console, session and client halves live beside the
suites they extend."""

import json
import os
import sys
from dataclasses import replace
from datetime import UTC, timedelta

import pytest
from alembic import command
from alembic.config import Config
from sqlalchemy import text
from test_emergency_stop import audit, scoped
from test_execution import activate, request, targets
from test_execution import registry as registry
from test_execution import world as world
from test_human_surface import credential, form_values, pending
from test_human_surface import human_app as human_app
from test_human_surface import human_client as human_client
from test_human_surface import human_config as human_config
from test_protected_path import connector as connector
from test_protected_path import live_provider as live_provider
from test_runtime import api as api
from test_runtime import runtime as runtime

from execbound.cli import main
from execbound.db import FUNCTIONS, UPDATE_COLUMNS, check_runtime
from execbound.execution import admit, decide_approval
from execbound.execution.models import ExecutionError
from execbound.execution.modes import approval_deadline, set_approval_deadline
from execbound.policy.models import ContextSetting
from execbound.replay.export import export_history
from execbound.replay.simulate import simulate
from execbound.replay.verify import verify_export
from execbound.resolution import resolve_request
from execbound.surfaces import sessions

LONG_FACTS = tuple(
    ContextSetting(
        context_contract_version="endpoint-isolation.v1",
        source_kind=kind,
        max_age_seconds=3600,
        permitted_writers=(writer,),
    )
    for kind, writer in (("inventory", "inventory_sync"), ("incident", "soc_analyst"))
)


def long_facts(db, world):
    """Facts that stay valid for most of an hour, so the deadline is the binding clock."""
    activate(db, world, context_settings=LONG_FACTS)


def deadline(db, world, seconds, reason="Reviewers need time"):
    return set_approval_deadline(db, world["admin"], seconds, reason, world["clock"])


def control_deadline(engine, tenant):
    with engine.begin() as conn:
        scoped(conn, tenant)
        return conn.execute(
            text(
                "SELECT approval_deadline_seconds FROM execbound.tenant_policy_control "
                "WHERE tenant_id=:t"
            ),
            {"t": tenant},
        ).scalar_one()


def expiry(engine, tenant, approval_id):
    with engine.begin() as conn:
        scoped(conn, tenant)
        return conn.execute(
            text("SELECT expires_at FROM execbound.approvals WHERE approval_id=:a"),
            {"a": approval_id},
        ).scalar_one()


def mutations(live_provider, world):
    return live_provider.store.resource(
        world["identity"].tenant_id, world["canonical"]
    ).mutation_count


def test_ad1_a_fresh_tenant_keeps_the_120_second_deadline(db, world, admin_engine):
    tenant = world["identity"].tenant_id
    assert control_deadline(admin_engine, tenant) == 120
    assert approval_deadline(db, world["admin"], world["clock"]) == 120
    pending = admit(db, world["identity"], request(world), world["clock"])
    assert pending.view.state == "PENDING_APPROVAL"
    assert expiry(admin_engine, tenant, pending.view.approval_id) == world["clock"].now() + (
        timedelta(seconds=120)
    )


def test_ad2_a_longer_deadline_lets_a_late_decision_execute_exactly_once(
    api, db, world, admin_engine, live_provider
):
    long_facts(db, world)
    change = deadline(db, world, 900)
    assert (change.previous, change.seconds) == (120, 900)
    body = request(world).model_dump(mode="json")
    first = api.post("/v1/execute", json=body)
    assert first.status_code == 202 and first.json()["state"] == "PENDING_APPROVAL"
    approval_id = first.json()["approval_id"]
    assert expiry(admin_engine, world["identity"].tenant_id, approval_id) == (
        world["clock"].now() + timedelta(seconds=900)
    )
    world["clock"].value += timedelta(seconds=500)
    decide_approval(db, world["human"], approval_id, "APPROVE", world["clock"])
    world["clock"].value += timedelta(seconds=300)
    executed = api.post("/v1/execute", json=body).json()
    assert executed["state"] == "EXECUTED"
    assert executed["execution_id"] == first.json()["execution_id"]
    assert mutations(live_provider, world) == 1
    again = api.post("/v1/execute", json=body).json()
    assert again["state"] == "EXECUTED" and again["execution_id"] == executed["execution_id"]
    assert mutations(live_provider, world) == 1


def test_ad3_off_means_the_plan_clock_and_the_plan_clock_wins(
    db, world, admin_engine, live_provider
):
    long_facts(db, world)
    deadline(db, world, None)
    assert control_deadline(admin_engine, world["identity"].tenant_id) is None
    assert approval_deadline(db, world["admin"], world["clock"]) is None
    resolved = resolve_request(
        db,
        world["identity"],
        request(world),
        world["clock"],
        settings=world["bundle"].context_settings,
    )
    pending = admit(db, world["identity"], request(world), world["clock"])
    assert pending.view.state == "PENDING_APPROVAL"
    recorded = expiry(admin_engine, world["identity"].tenant_id, pending.view.approval_id)
    assert recorded.astimezone(UTC) == resolved.valid_until
    assert recorded > world["clock"].now() + timedelta(seconds=3000)
    # A decision after the facts expired progresses nothing: the plan clock is binding.
    world["clock"].value = resolved.valid_until + timedelta(seconds=1)
    late = decide_approval(db, world["human"], pending.view.approval_id, "APPROVE", world["clock"])
    assert late.state == "STALE_AUTHORIZATION" and late.approval_state == "EXPIRED"
    retry = admit(db, world["identity"], request(world), world["clock"])
    assert retry.view.state == "STALE_AUTHORIZATION" and retry.ticket is None
    assert mutations(live_provider, world) == 0


def test_ad3b_off_still_executes_a_decision_made_while_the_plan_is_valid(
    api, db, world, live_provider
):
    long_facts(db, world)
    deadline(db, world, None)
    body = request(world).model_dump(mode="json")
    first = api.post("/v1/execute", json=body).json()
    world["clock"].value += timedelta(seconds=1500)
    decide_approval(db, world["human"], first["approval_id"], "APPROVE", world["clock"])
    assert api.post("/v1/execute", json=body).json()["state"] == "EXECUTED"
    assert mutations(live_provider, world) == 1


@pytest.mark.parametrize("value", [119, 3601, -1, 0, "900", 900.0, True])
def test_ad4_out_of_range_values_are_refused_and_nothing_changes(db, world, admin_engine, value):
    with pytest.raises(ExecutionError) as refused:
        deadline(db, world, value)
    assert refused.value.code == "INVALID_DEADLINE"
    assert control_deadline(admin_engine, world["identity"].tenant_id) == 120
    tenant = world["identity"].tenant_id
    assert audit(admin_engine, tenant, "tenant.approval_deadline_changed") == []


def test_ad4_changes_need_an_admin_a_reason_and_a_change_and_are_audited(db, world, admin_engine):
    tenant = world["identity"].tenant_id
    with pytest.raises(ExecutionError) as unchanged:
        deadline(db, world, 120)
    assert unchanged.value.code == "INVALID_STATE"
    with pytest.raises(ExecutionError) as no_reason:
        deadline(db, world, 900, " ")
    assert no_reason.value.code == "INVALID_REASON"
    with pytest.raises(ExecutionError) as not_admin:
        set_approval_deadline(db, world["human"], 900, "Reason", world["clock"])
    assert not_admin.value.code == "INVALID_IDENTITY"
    assert control_deadline(admin_engine, tenant) == 120
    deadline(db, world, 900, "Reviewers read context first")
    deadline(db, world, None, "Pilot recording")
    events = audit(admin_engine, tenant, "tenant.approval_deadline_changed")
    assert [(e["previous"], e["seconds"], e["reason"]) for e in events] == [
        (120, 900, "Reviewers read context first"),
        (900, None, "Pilot recording"),
    ]
    assert all(
        e["principal_id"] == str(world["admin"].principal_id)
        and e["credential_id"] == str(world["admin"].credential_id)
        and e["replay"]["version"] == 1
        for e in events
    )


def test_ad5_a_change_applies_to_approvals_created_after_it(db, world, admin_engine):
    long_facts(db, world)
    tenant = world["identity"].tenant_id
    deadline(db, world, 900)
    before = admit(db, world["identity"], request(world), world["clock"])
    assert expiry(admin_engine, tenant, before.view.approval_id) == world["clock"].now() + (
        timedelta(seconds=900)
    )
    deadline(db, world, 300)
    assert expiry(admin_engine, tenant, before.view.approval_id) == world["clock"].now() + (
        timedelta(seconds=900)
    )
    [other] = targets(admin_engine, world, 1, production=True)
    after = admit(db, world["identity"], other, world["clock"])
    assert after.view.state == "PENDING_APPROVAL"
    assert expiry(admin_engine, tenant, after.view.approval_id) == world["clock"].now() + (
        timedelta(seconds=300)
    )


def test_ad6_replay_reproduces_a_decision_made_late_under_a_long_deadline(
    api, db, world, live_provider
):
    long_facts(db, world)
    deadline(db, world, 900)
    body = request(world).model_dump(mode="json")
    first = api.post("/v1/execute", json=body).json()
    world["clock"].value += timedelta(seconds=600)
    decide_approval(db, world["human"], first["approval_id"], "APPROVE", world["clock"])
    assert api.post("/v1/execute", json=body).json()["state"] == "EXECUTED"
    history = export_history(db, world["admin"], world["clock"])
    report = simulate(verify_export(history, history.head))
    assert report.complete and not report.issues
    stages = {(row.stage, row.recorded_effect): row for row in report.decisions}
    assert ("ADMISSION", "REQUIRE_APPROVAL") in stages and ("APPROVAL_REVIEW", "ELIGIBLE") in stages
    for row in report.decisions:
        assert row.baseline.effect == row.recorded_effect
    assert stages[("APPROVAL_REVIEW", "ELIGIBLE")].baseline.outcome == "EXECUTED"


def test_ad4_cli_sets_reads_and_refuses(db, world, admin_engine, tmp_path, monkeypatch, capsys):
    tenant = world["identity"].tenant_id
    monkeypatch.setenv("DATABASE_URL", os.environ["TEST_DATABASE_URL"])
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
        "tenant-approval-deadline", *common, str(human_file), "--set", "900", "--reason", "No"
    )
    assert "INVALID_DEADLINE" in refused(
        "tenant-approval-deadline", *common, str(admin_file), "--set", "60", "--reason", "Short"
    )
    assert "INVALID_DEADLINE" in refused(
        "tenant-approval-deadline", *common, str(admin_file), "--set", "later", "--reason", "Odd"
    )
    assert control_deadline(admin_engine, tenant) == 120
    changed = run(
        "tenant-approval-deadline", *common, str(admin_file), "--set", "900", "--reason", "Read"
    )
    assert changed == {"tenant_id": str(tenant), "approval_deadline_seconds": 900, "previous": 120}
    status = run("tenant-status", *common, str(admin_file))
    assert status["approval_deadline_seconds"] == 900 and status["enforcement_mode"] == "ENFORCE"
    off = run(
        "tenant-approval-deadline", *common, str(admin_file), "--set", "off", "--reason", "Pilot"
    )
    assert off == {"tenant_id": str(tenant), "approval_deadline_seconds": None, "previous": 900}
    assert run("tenant-status", *common, str(admin_file))["approval_deadline_seconds"] is None
    assert "INVALID_STATE" in refused(
        "tenant-approval-deadline", *common, str(admin_file), "--set", "off", "--reason", "Again"
    )


def test_ad11_migration_round_trip_and_runtime_catalog(db, world, admin_engine):
    tenant = world["identity"].tenant_id
    assert "approval_deadline_seconds" in UPDATE_COLUMNS["tenant_policy_control"]
    assert "expires_at" not in UPDATE_COLUMNS["human_sessions"]
    assert "renew_human_session" in {name for name, _ in FUNCTIONS}
    with db.transaction(tenant) as conn:
        check_runtime(conn)
    deadline(db, world, 900)
    config = Config("alembic.ini")
    config.attributes["database_url"] = os.environ["TEST_MIGRATION_DATABASE_URL"]
    command.downgrade(config, "0026_key_compromise")
    command.upgrade(config, "head")
    with db.transaction(tenant) as conn:
        check_runtime(conn)
    # The column came back at its default: every tenant starts at 120 again.
    assert control_deadline(admin_engine, tenant) == 120
    pending = admit(db, world["identity"], request(world), world["clock"])
    assert expiry(admin_engine, tenant, pending.view.approval_id) == world["clock"].now() + (
        timedelta(seconds=120)
    )


def test_ad8_console_labels_the_clock_and_the_form_outlives_two_minutes(
    human_client, runtime, world, db, live_provider
):
    long_facts(db, world)
    deadline(db, world, 900)
    first = pending(runtime, world)
    page = human_client.get(f"/approvals/{first.approval_id}/classic")
    assert page.status_code == 200 and "(approval deadline)" in page.text
    queue = human_client.get("/api/console/v1/approvals")
    assert queue.status_code == 200 and str(first.approval_id) in queue.text
    path, values = form_values(page.text, "/decide")
    values["decision"] = "APPROVE"
    # Four minutes of reading: longer than the old two-minute form token, well inside the
    # session and the deadline.
    world["clock"].value += timedelta(minutes=4)
    decided = human_client.post(path, data=values, headers={"Origin": "http://127.0.0.1"})
    assert decided.status_code == 303
    result = pending(runtime, world)
    assert result.execution_id == first.execution_id and result.state == "EXECUTED"
    assert mutations(live_provider, world) == 1


def test_ad8b_off_is_labelled_as_the_context_clock(human_client, runtime, world, db):
    long_facts(db, world)
    deadline(db, world, None)
    first = pending(runtime, world)
    classic = human_client.get(f"/approvals/{first.approval_id}/classic")
    assert "(context validity)" in classic.text


def test_ad10_sessions_renew_on_activity_within_the_caps(db, world, admin_engine, monkeypatch):
    clock, human = world["clock"], world["human"]
    grant = sessions.issue_session(db, human, clock=clock)
    issued = clock.now()
    assert grant.expires_at == issued + timedelta(minutes=15)
    clock.value = issued + timedelta(minutes=5)
    early = sessions.load_session(db, grant.token, clock=clock)
    assert not early.renewed and early.expires_at == issued + timedelta(minutes=15)
    clock.value = issued + timedelta(minutes=8)
    renewed = sessions.load_session(db, grant.token, clock=clock)
    assert renewed.renewed and renewed.expires_at == issued + timedelta(minutes=23)
    again = sessions.load_session(db, grant.token, clock=clock)
    assert not again.renewed and again.expires_at == renewed.expires_at
    # Reading keeps it alive; walking away does not.
    clock.value = issued + timedelta(minutes=22)
    kept = sessions.load_session(db, grant.token, clock=clock)
    assert kept.renewed and kept.expires_at == issued + timedelta(minutes=37)
    clock.value = issued + timedelta(minutes=38)
    with pytest.raises(sessions.SessionError):
        sessions.load_session(db, grant.token, clock=clock)
    # The absolute cap: no renewal takes a session past it, however active.
    monkeypatch.setattr(sessions, "SESSION_ABSOLUTE", timedelta(minutes=20))
    clock.value = issued + timedelta(minutes=40)
    capped_grant = sessions.issue_session(db, human, clock=clock)
    started = clock.now()
    clock.value = started + timedelta(minutes=8)
    capped = sessions.load_session(db, capped_grant.token, clock=clock)
    assert capped.renewed and capped.expires_at == started + timedelta(minutes=20)
    clock.value = started + timedelta(minutes=14)
    held = sessions.load_session(db, capped_grant.token, clock=clock)
    assert not held.renewed and held.expires_at == started + timedelta(minutes=20)
    clock.value = started + timedelta(minutes=20)
    with pytest.raises(sessions.SessionError):
        sessions.load_session(db, capped_grant.token, clock=clock)
    # The credential's own expiry caps it too, and a revoked session is not renewed.
    monkeypatch.setattr(sessions, "SESSION_ABSOLUTE", timedelta(hours=8))
    clock.value = started + timedelta(minutes=21)
    short = replace(human, expires_at=clock.now() + timedelta(minutes=10))
    with admin_engine.begin() as conn:
        conn.execute(
            text("UPDATE execbound.credentials SET expires_at=:e WHERE credential_id=:c"),
            {"e": short.expires_at, "c": short.credential_id},
        )
    short_grant = sessions.issue_session(db, short, clock=clock)
    assert short_grant.expires_at == short.expires_at
    clock.value += timedelta(minutes=5)
    bounded = sessions.load_session(db, short_grant.token, clock=clock)
    assert not bounded.renewed and bounded.expires_at == short.expires_at
    sessions.revoke_session(db, bounded, clock=clock)
    with pytest.raises(sessions.SessionError):
        sessions.load_session(db, short_grant.token, clock=clock)


def test_ad10b_the_console_reissues_cookies_when_the_session_renews(human_client, world):
    # A console route is a page load like any other: the renewal is the gateway's and
    # happens on the document, not on anything the application asks for afterwards.
    world["clock"].value += timedelta(minutes=5)
    quiet = human_client.get("/activity")
    assert quiet.status_code == 200 and "set-cookie" not in quiet.headers
    world["clock"].value += timedelta(minutes=3)
    renewed = human_client.get("/activity")
    assert renewed.status_code == 200
    cookies = renewed.headers.get_list("set-cookie")
    assert len(cookies) == 2
    assert all("Max-Age=900" in c and "HttpOnly" in c and "SameSite=strict" in c for c in cookies)
    # Fifteen quiet minutes after the renewal end the session as before.
    world["clock"].value += timedelta(minutes=16)
    ended = human_client.get("/activity")
    assert ended.status_code == 303 and ended.headers["location"] == "/login?review=%2Factivity"
    assert human_client.get("/api/console/v1/executions").status_code == 401
