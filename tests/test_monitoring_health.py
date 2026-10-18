# SPDX-License-Identifier: AGPL-3.0-only
"""Persisted monitoring source health and clock-skew detections: SH1 to SH10 on PostgreSQL."""

import json
import os
from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest
from alembic import command
from alembic.config import Config
from sqlalchemy import event as sa_event
from sqlalchemy import text
from test_monitoring_http import monitor_web as monitor_web
from test_monitoring_store import admins as admins
from test_monitoring_store import api as api
from test_monitoring_store import observation
from test_monitoring_store import setup_monitor as setup_monitor
from test_monitoring_worker import deliver_local
from test_monitoring_worker import receiver as receiver

from execbound.db import UPDATE_COLUMNS, check_runtime
from execbound.monitoring import store as monitor_store
from execbound.monitoring import worker
from execbound.surfaces import sessions

HEALTH = "source-health.v1"
SKEW = "clock-skew.v1"


def findings(state, rule=None):
    return [f for f in state["findings"] if rule is None or f["rule_version"] == rule]


def source_state(state, source_id):
    return next(s for s in state["sources"] if s["source_id"] == source_id)


def fresh(store, db, admin, clock):
    """Human sessions last 15 minutes; long clock jumps need a new one to read the snapshot."""
    grant = sessions.issue_session(db, admin, clock=clock)
    return store.snapshot(db, sessions.load_session(db, grant.token, clock=clock), clock=clock)


def test_sh1_missed_heartbeats_become_one_durable_finding_per_episode(db, setup_monitor, admins):
    models, store, clock, source, session = setup_monitor
    assert store.evaluate_health(db, admins[0], clock=clock) == 0
    state = fresh(store, db, admins[0], clock)
    assert source_state(state, source.source_id)["health_state"] == "UNKNOWN"
    clock.value += timedelta(seconds=601)
    assert store.evaluate_health(db, admins[0], clock=clock) == 1
    state = fresh(store, db, admins[0], clock)
    health = source_state(state, source.source_id)
    assert health["health_state"] == "STALE" and health["health_changed_at"] == clock.now()
    [finding] = findings(state, HEALTH)
    assert finding["observation_id"] is None and finding["source_id"] == source.source_id
    assert "never reported" in finding["title"].lower()
    assert [d["finding_id"] for d in state["deliveries"]] == [finding["finding_id"]]
    clock.value += timedelta(seconds=601)
    assert store.evaluate_health(db, admins[0], clock=clock) == 0
    assert len(findings(fresh(store, db, admins[0], clock), HEALTH)) == 1


def test_sh2_recovery_and_a_later_gap_are_separate_episodes(db, setup_monitor, admins):
    models, store, clock, source, session = setup_monitor
    clock.value += timedelta(seconds=601)
    assert store.evaluate_health(db, admins[0], clock=clock) == 1
    store.ingest(
        db,
        source.token,
        observation(
            models,
            clock,
            event_id="beat-1",
            kind="heartbeat",
            action=None,
            target_ref=None,
            outcome=None,
        ),
        clock=clock,
    )
    assert store.evaluate_health(db, admins[0], clock=clock) == 1
    state = fresh(store, db, admins[0], clock)
    assert source_state(state, source.source_id)["health_state"] == "REPORTING"
    assert len(findings(state, HEALTH)) == 1
    clock.value += timedelta(seconds=601)
    assert store.evaluate_health(db, admins[0], clock=clock) == 1
    state = fresh(store, db, admins[0], clock)
    assert source_state(state, source.source_id)["health_state"] == "STALE"
    health = findings(state, HEALTH)
    assert len(health) == 2 and len({f["finding_id"] for f in health}) == 2
    assert "stopped reporting" in health[0]["title"].lower()
    assert len(state["deliveries"]) == 2


def test_sh3_late_and_out_of_order_events_keep_their_reported_time(db, setup_monitor, admins):
    models, store, clock, source, session = setup_monitor
    late = clock.now() - timedelta(hours=1)
    earlier = clock.now() - timedelta(hours=2)
    store.ingest(
        db, source.token, observation(models, clock, event_id="a", occurred_at=late), clock=clock
    )
    clock.value += timedelta(seconds=1)
    store.ingest(
        db, source.token, observation(models, clock, event_id="b", occurred_at=earlier), clock=clock
    )
    assert store.evaluate_pending(db, admins[0], clock=clock) == 2
    state = store.snapshot(db, session, clock=clock)
    by_event = {o["event_id"]: o for o in state["observations"]}
    assert by_event["a"]["occurred_at"] == late and by_event["b"]["occurred_at"] == earlier
    assert by_event["a"]["received_at"] < by_event["b"]["received_at"]
    assert all(o["evaluation_state"] == "COMPLETED" for o in state["observations"])
    assert findings(state, SKEW) == []


def test_sh4_excessive_clock_skew_is_flagged_without_rewriting_external_time(
    db, setup_monitor, admins
):
    models, store, clock, source, session = setup_monitor
    ahead = clock.now() + timedelta(minutes=10)
    behind = clock.now() - timedelta(hours=25)
    store.ingest(
        db,
        source.token,
        observation(models, clock, event_id="ahead", occurred_at=ahead),
        clock=clock,
    )
    store.ingest(
        db,
        source.token,
        observation(models, clock, event_id="behind", occurred_at=behind),
        clock=clock,
    )
    assert store.evaluate_pending(db, admins[0], clock=clock) == 2
    state = store.snapshot(db, session, clock=clock)
    by_event = {o["event_id"]: o for o in state["observations"]}
    assert by_event["ahead"]["occurred_at"] == ahead and by_event["behind"]["occurred_at"] == behind
    assert {o["evaluation_result"] for o in state["observations"]} == {"MATCH"}
    skew = {f["observation_id"]: f for f in findings(state, SKEW)}
    assert set(skew) == {by_event["ahead"]["observation_id"], by_event["behind"]["observation_id"]}
    assert "ahead" in skew[by_event["ahead"]["observation_id"]]["title"].lower()
    assert "behind" in skew[by_event["behind"]["observation_id"]]["title"].lower()
    assert len(findings(state, "sensitive-action.v2")) == 2
    assert len(state["deliveries"]) == 4


def test_sh5_a_crash_between_finding_and_outbox_rolls_the_health_change_back(
    db, setup_monitor, admins
):
    models, store, clock, source, session = setup_monitor
    clock.value += timedelta(seconds=601)

    def fail_outbox(conn, cursor, statement, parameters, context, executemany):
        if "INSERT INTO execbound.monitor_deliveries" in statement:
            raise RuntimeError("injected crash")

    sa_event.listen(db.engine, "before_cursor_execute", fail_outbox)
    try:
        with pytest.raises(RuntimeError, match="injected crash"):
            store.evaluate_health(db, admins[0], clock=clock)
    finally:
        sa_event.remove(db.engine, "before_cursor_execute", fail_outbox)
    state = store.snapshot(db, session, clock=clock)
    assert source_state(state, source.source_id)["health_state"] == "UNKNOWN"
    assert not state["findings"] and not state["deliveries"]
    assert store.evaluate_health(db, admins[0], clock=clock) == 1
    assert len(findings(store.snapshot(db, session, clock=clock), HEALTH)) == 1


def test_sh6_health_findings_deliver_once_through_the_outbox(db, setup_monitor, admins, receiver):
    models, store, clock, source, session = setup_monitor
    local, output = receiver
    clock.value += timedelta(seconds=601)
    assert store.evaluate_health(db, admins[0], clock=clock) == 1
    assert deliver_local(db, admins[0], local, clock) == 1
    assert deliver_local(db, admins[0], local, clock) == 0
    [delivered] = [p for p in output.glob("*.json")]
    payload = json.loads(delivered.read_text(encoding="utf-8"))
    assert payload["rule_version"] == HEALTH and payload["source_id"] == str(source.source_id)
    assert "token" not in json.dumps(payload).lower()
    state = store.snapshot(db, session, clock=clock)
    assert [d["state"] for d in state["deliveries"]] == ["DELIVERED"]


def test_sh7_disabled_expired_and_revoked_sources_are_not_evaluated(db, setup_monitor, admins):
    models, store, clock, source, session = setup_monitor
    short = store.create_source(
        db,
        admins[0],
        label="Short lived",
        story_id="story-2",
        expires_at=clock.now() + timedelta(minutes=5),
        clock=clock,
    )
    store.revoke_source(db, admins[0], source.source_id, clock=clock)
    clock.value += timedelta(minutes=11)
    assert store.evaluate_health(db, admins[0], clock=clock) == 0
    state = store.snapshot(db, session, clock=clock)
    assert findings(state, HEALTH) == []
    assert source_state(state, short.source_id)["health_state"] == "UNKNOWN"
    assert source_state(state, source.source_id)["health_state"] == "UNKNOWN"


def test_sh8_health_evaluation_is_scoped_to_the_tenant(db, setup_monitor, admins, seeded):
    models, store, clock, source, session = setup_monitor
    other = store.create_source(
        db,
        admins[1],
        label="Other tenant",
        story_id="story-9",
        expires_at=clock.now() + timedelta(hours=2),
        clock=clock,
    )
    clock.value += timedelta(seconds=601)
    assert store.evaluate_health(db, admins[1], clock=clock) == 1
    state = store.snapshot(db, session, clock=clock)
    assert findings(state, HEALTH) == []
    assert source_state(state, source.source_id)["health_state"] == "UNKNOWN"
    assert all(s["source_id"] != other.source_id for s in state["sources"])
    assert store.evaluate_health(db, admins[0], clock=clock) == 1
    assert len(findings(store.snapshot(db, session, clock=clock), HEALTH)) == 1


def test_sh9_pages_show_health_and_findings_without_an_observation(monitor_web, db, admin_engine):
    client, admin, source, _ = monitor_web
    with admin_engine.begin() as conn:
        conn.execute(
            text("SELECT set_config('execbound.tenant_id', :t, true)"), {"t": str(admin.tenant_id)}
        )
        conn.execute(
            text(
                "UPDATE execbound.monitor_sources SET created_at=:earlier "
                "WHERE tenant_id=:t AND source_id=:s"
            ),
            {
                "earlier": datetime.now(UTC) - timedelta(hours=1),
                "t": admin.tenant_id,
                "s": source.source_id,
            },
        )
    assert monitor_store.evaluate_health(db, admin) == 1
    view = client.get("/api/console/v1/monitor")
    assert view.status_code == 200
    body = view.json()
    # The source has never sent a heartbeat, so the console says so rather than
    # "Reporting", and the health finding stands beside it with its own rule version.
    assert [row["coverage"] for row in body["sources"]] == ["No heartbeat"]
    assert all(row["health_state"] not in (None, "", "OK") for row in body["sources"])
    assert any(finding["rule_version"] == HEALTH for finding in body["findings"])
    result = worker.process(db, admin)
    assert result["health_changes"] == 0 and result["evaluated"] == 0


def test_sh10_migration_round_trip_refuses_to_drop_health_findings(db, setup_monitor, admins):
    models, store, clock, source, session = setup_monitor
    assert {"health_state", "health_changed_at", "health_checked_at"} <= UPDATE_COLUMNS[
        "monitor_sources"
    ]
    with db.transaction(admins[0].tenant_id) as conn:
        check_runtime(conn)
    clock.value += timedelta(seconds=601)
    assert store.evaluate_health(db, admins[0], clock=clock) == 1
    config = Config("alembic.ini")
    config.attributes["database_url"] = os.environ["TEST_MIGRATION_DATABASE_URL"]
    with pytest.raises(RuntimeError):
        command.downgrade(config, "0012_source_rotation")
    with db.transaction(admins[0].tenant_id) as conn:
        check_runtime(conn)
    assert len(findings(store.snapshot(db, session, clock=clock), HEALTH)) == 1
    assert uuid4() is not None
