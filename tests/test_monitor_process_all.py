# SPDX-License-Identifier: AGPL-3.0-only
"""MC21: monitoring evaluated in every workspace by the scheduled pass (#678), on real PostgreSQL.

`process --all-tenants` holds no workspace credential. In each active workspace it evaluates the
pending observations into findings, raises a source that stopped reporting and derives reach,
as that workspace's scheduled actor under that workspace's fence. One workspace's refusal is
its own line and never the exit code; it delivers nothing and appends no audit event.
"""

import json
import os
import sys
from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest
from sample_fixtures import empty_workspace
from sqlalchemy import text
from test_monitoring_store import FixedClock
from test_monitoring_store import admins as admins
from test_scout_derived import AGENT_ONE, collected, observe

from execbound import jobs
from execbound.execution.scheduled import ScheduledActor
from execbound.monitoring import commands, store, worker
from execbound.monitoring.models import MonitorError, ObservationEvent

pytestmark = pytest.mark.integration


def workspace(db, admin_engine, admin, clock):
    """A stale heartbeat source with a reported consequential action waiting, and a collected
    directory agent observed running a tool, both pending evaluation."""
    tenant = admin.tenant_id
    source = store.create_source(
        db,
        admin,
        label="Phishing triage",
        story_id="story-1",
        expires_at=clock.now() + timedelta(hours=2),
        heartbeat_seconds=60,
        clock=clock,
    )
    store.ingest(
        db,
        source.token,
        ObservationEvent(
            event_id=f"event-{uuid4()}",
            story_id="story-1",
            occurred_at=clock.now(),
            kind="tool_result",
            action="identity.disable",
            target_ref="user-1",
            outcome="success",
        ),
        clock=clock,
    )
    # The last report was an hour ago: twice the heartbeat passed long since.
    with admin_engine.begin() as conn:
        conn.execute(
            text(
                "UPDATE execbound.monitor_sources SET created_at = :old, last_event_at = :late, "
                "last_heartbeat_at = :late WHERE tenant_id = :t AND source_id = :s"
            ),
            {
                "t": tenant,
                "s": source.source_id,
                "old": clock.now() - timedelta(hours=2),
                "late": clock.now() - timedelta(hours=1),
            },
        )
    # One directory per workspace: a directory is connected once across the deployment.
    connection = collected(db, admin, clock, directory=str(uuid4()))
    observe(
        admin_engine,
        tenant,
        connection,
        AGENT_ONE,
        "identity.disable",
        clock.now() - timedelta(minutes=10),
    )
    return source.source_id


def state(admin_engine, tenant):
    """What a pass may change in one workspace, and what it must not."""
    with admin_engine.connect() as conn:
        values = {"t": tenant}
        return {
            "pending": conn.execute(
                text(
                    "SELECT count(*) FROM execbound.monitor_observations "
                    "WHERE tenant_id = :t AND evaluation_state = 'PENDING'"
                ),
                values,
            ).scalar_one(),
            "findings": set(
                conn.execute(
                    text(
                        "SELECT rule_version FROM execbound.monitor_findings WHERE tenant_id = :t"
                    ),
                    values,
                ).scalars()
            ),
            "stale": conn.execute(
                text(
                    "SELECT count(*) FROM execbound.monitor_sources "
                    "WHERE tenant_id = :t AND health_state = 'STALE'"
                ),
                values,
            ).scalar_one(),
            "reach": conn.execute(
                text(
                    "SELECT count(*) FROM execbound.monitor_agent_reach "
                    "WHERE tenant_id = :t AND certainty = 'observed'"
                ),
                values,
            ).scalar_one(),
            "deliveries": sorted(
                tuple(row)
                for row in conn.execute(
                    text(
                        "SELECT state, attempts FROM execbound.monitor_deliveries "
                        "WHERE tenant_id = :t"
                    ),
                    values,
                ).all()
            ),
            "audit": conn.execute(
                text(
                    "SELECT kind, event_hash FROM execbound.audit_events "
                    "WHERE tenant_id = :t ORDER BY sequence"
                ),
                values,
            ).all(),
        }


def run_process(monkeypatch, capsys, *arguments):
    monkeypatch.setenv("DATABASE_URL", os.environ["TEST_DATABASE_URL"])
    monkeypatch.setattr(sys, "argv", ["commands", "process", *arguments])
    commands.main()
    return json.loads(capsys.readouterr().out)


def test_mc21_one_pass_evaluates_every_active_workspace_and_delivers_nothing(
    db, admin_engine, admins, monkeypatch, capsys
):
    clock = FixedClock(datetime.now(UTC))
    first, second = admins
    for admin in admins:
        workspace(db, admin_engine, admin, clock)
    dormant = empty_workspace(admin_engine, db)
    with admin_engine.begin() as conn:
        conn.execute(
            text("UPDATE execbound.tenants SET active = false WHERE tenant_id = :t"),
            {"t": dormant.tenant_id},
        )
    before = {admin.tenant_id: state(admin_engine, admin.tenant_id) for admin in admins}
    for found in before.values():
        assert (found["pending"], found["stale"], found["reach"]) == (2, 0, 0)
    report = run_process(monkeypatch, capsys, "--all-tenants", "--limit", "50")
    # The two active workspaces visited and the deactivated one counted, not visited.
    assert (report["visited"], report["failed"], report["inactive"]) == (2, 0, 1)
    assert set(report["tenants"]) == {str(first.tenant_id), str(second.tenant_id)}
    for admin in admins:
        tenant = admin.tenant_id
        after = state(admin_engine, tenant)
        assert report["tenants"][str(tenant)] == {
            "evaluated": 2,
            "health_changes": 1,
            "reach": 1,
            "actions": 0,
            "purged": 0,
        }
        assert after["pending"] == 0
        # The reported action became a finding and the quiet source a health finding.
        assert {"sensitive-action.v2", "source-health.v1"} <= after["findings"]
        assert (after["stale"], after["reach"]) == (1, 1)
        # Nothing was sent anywhere: every delivery waits, unattempted.
        assert after["deliveries"] and all(row == ("PENDING", 0) for row in after["deliveries"])
        # Evaluation appends nothing to the workspace's audit chain.
        assert after["audit"] == before[tenant]["audit"]
    with admin_engine.connect() as conn:
        # And never made a scheduler principal anywhere.
        assert (
            conn.execute(
                text("SELECT count(*) FROM execbound.principals WHERE kind = 'SYSTEM'")
            ).scalar_one()
            == 0
        )


def test_mc21_a_workspace_deactivated_after_the_walk_checked_it_is_its_own_refused_line(
    db, admin_engine, admins, monkeypatch, capsys
):
    """The walk skips a workspace it already knows is inactive. One deactivated between that
    check and its step is refused by the step's own check, on its own line, and the run
    still exits 0 having evaluated the other."""
    clock = FixedClock(datetime.now(UTC))
    first, second = admins
    for admin in admins:
        workspace(db, admin_engine, admin, clock)
    with admin_engine.begin() as conn:
        conn.execute(
            text("UPDATE execbound.tenants SET active = false WHERE tenant_id = :t"),
            {"t": second.tenant_id},
        )
    monkeypatch.setattr(jobs, "tenant_active", lambda db, tenant: True)
    report = run_process(monkeypatch, capsys, "--all-tenants")
    assert (report["visited"], report["failed"]) == (2, 1)
    assert report["tenants"][str(second.tenant_id)] == {"skipped": "INVALID_ADMIN"}
    assert report["tenants"][str(first.tenant_id)]["evaluated"] == 2
    assert state(admin_engine, second.tenant_id)["pending"] == 2


class Misfenced:
    """A database whose every transaction is fenced to another workspace than it was asked
    for, so only the actor's own check against the fence stands between a pass and the wrong
    workspace's rows."""

    def __init__(self, db, other):
        self.db, self.other = db, other

    def transaction(self, tenant):
        return self.db.transaction(self.other)


def test_mc21_each_workspace_is_evaluated_under_its_own_fence(db, admin_engine, admins):
    clock = FixedClock(datetime.now(UTC))
    first, second = admins
    for admin in admins:
        workspace(db, admin_engine, admin, clock)
    misfenced = Misfenced(db, second.tenant_id)
    for evaluate in (
        lambda: store.evaluate_pending(misfenced, ScheduledActor(first.tenant_id), clock=clock),
        lambda: store.evaluate_health(misfenced, ScheduledActor(first.tenant_id), clock=clock),
        lambda: store.derive_reach(misfenced, ScheduledActor(first.tenant_id), clock=clock),
    ):
        with pytest.raises(MonitorError) as refused:
            evaluate()
        assert refused.value.code == "INVALID_ADMIN"
    untouched = state(admin_engine, second.tenant_id)
    assert (untouched["pending"], untouched["stale"], untouched["reach"]) == (2, 0, 0)
    # Under its own fence the same pass evaluates.
    assert worker.evaluate_scheduled(db, second.tenant_id, clock=clock)["evaluated"] == 2


@pytest.mark.parametrize(
    "arguments,message",
    [
        (["--all-tenants", "--config", "monitor.json"], "--all-tenants takes no --config"),
        (["--all-tenants", "--deliver-local"], "--all-tenants takes no --config"),
        (["--all-tenants", "--deliver", "--deliver-local"], "--deliver takes no --deliver-local"),
        ([], "give --config or --all-tenants"),
        (["--all-tenants", "--limit", "0"], "--limit must be 1 to 50"),
        (["--all-tenants", "--limit", "51"], "--limit must be 1 to 50"),
    ],
)
def test_mc21_all_tenants_is_refused_beside_another_mode_before_any_work(
    db, admin_engine, admins, monkeypatch, capsys, arguments, message
):
    clock = FixedClock(datetime.now(UTC))
    workspace(db, admin_engine, admins[0], clock)
    monkeypatch.setenv("DATABASE_URL", os.environ["TEST_DATABASE_URL"])
    monkeypatch.setattr(sys, "argv", ["commands", "process", *arguments])
    with pytest.raises(SystemExit) as refused:
        commands.main()
    assert refused.value.code == 2
    assert message in capsys.readouterr().err
    assert state(admin_engine, admins[0].tenant_id)["pending"] == 2
