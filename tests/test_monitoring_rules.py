# SPDX-License-Identifier: AGPL-3.0-only
"""M1 detection rule set with per-tenant detection profiles: RS1 to RS12 on real PostgreSQL."""

import json
import os
import sys
from datetime import timedelta

import pytest
from alembic import command
from alembic.config import Config
from sqlalchemy import text
from test_execution import provision_identity
from test_human_surface import credential
from test_monitoring_http import signed_in
from test_monitoring_store import admins as admins
from test_monitoring_store import api as api
from test_monitoring_store import observation
from test_monitoring_store import setup_monitor as setup_monitor
from test_monitoring_worker import receiver as receiver

from execbound.db import TABLES, check_runtime
from execbound.monitoring import commands, worker
from execbound.monitoring import store as monitor_store
from execbound.monitoring.models import DetectionProfile, MonitorError

SENSITIVE = "sensitive-action.v2"
RESTRICTED = "restricted-target.v1"
RATE = "observed-rate.v1"


def findings(state, rule=None):
    return [f for f in state["findings"] if rule is None or f["rule_version"] == rule]


def results(state):
    return {o["event_id"]: o["evaluation_result"] for o in state["observations"]}


def profile(**changes):
    values = {
        "sensitive_actions": ["identity.disable"],
        "restricted_targets": [],
        "burst_threshold": None,
        "burst_window_seconds": None,
    }
    values.update(changes)
    for key in ("sensitive_actions", "restricted_targets"):
        values[key] = tuple(values[key])
    return DetectionProfile.model_validate(values)


def ingest_many(store, db, source, models, clock, specs):
    for event_id, changes in specs:
        store.ingest(
            db, source.token, observation(models, clock, event_id=event_id, **changes), clock=clock
        )


def test_rs1_without_a_profile_the_built_in_set_applies_and_the_other_rules_are_inactive(
    db, setup_monitor, admins
):
    models, store, clock, source, session = setup_monitor
    ingest_many(
        store,
        db,
        source,
        models,
        clock,
        [
            ("sensitive", {"action": "endpoint.isolate"}),
            ("plain", {"action": "ticket.comment"}),
            ("unknown", {"action": "unknown"}),
        ],
    )
    assert store.evaluate_pending(db, admins[0], clock=clock) == 3
    state = store.snapshot(db, session, clock=clock)
    # Without a profile an unlisted action is a coverage limit, not a pass.
    assert results(state) == {
        "sensitive": "MATCH",
        "plain": "INSUFFICIENT_EVIDENCE",
        "unknown": "INSUFFICIENT_EVIDENCE",
    }
    assert [f["rule_version"] for f in findings(state)] == [SENSITIVE]
    assert findings(state)[0]["profile_version"] is None
    assert state["profile"] == []
    assert all(o["rule_version"] == SENSITIVE for o in state["observations"])


def test_rs2_a_profile_replaces_the_built_in_set_and_stamps_its_version(db, setup_monitor, admins):
    models, store, clock, source, session = setup_monitor
    record = store.set_profile(
        db, admins[0], profile(sensitive_actions=["ticket.close"]), clock=clock
    )
    assert record.version == 1
    ingest_many(
        store,
        db,
        source,
        models,
        clock,
        [("built-in", {"action": "identity.disable"}), ("configured", {"action": "ticket.close"})],
    )
    assert store.evaluate_pending(db, admins[0], clock=clock) == 2
    state = store.snapshot(db, session, clock=clock)
    assert results(state) == {"built-in": "NO_MATCH", "configured": "MATCH"}
    [finding] = findings(state, SENSITIVE)
    assert (finding["profile_id"], finding["profile_version"]) == (record.profile_id, 1)
    assert state["profile"][0]["version"] == 1


def test_rs3_listing_unknown_flags_unidentified_actions_without_calling_them_sensitive(
    db, setup_monitor, admins
):
    models, store, clock, source, session = setup_monitor
    store.set_profile(
        db, admins[0], profile(sensitive_actions=["identity.disable", "unknown"]), clock=clock
    )
    ingest_many(store, db, source, models, clock, [("mystery", {"action": "unknown"})])
    assert store.evaluate_pending(db, admins[0], clock=clock) == 1
    state = store.snapshot(db, session, clock=clock)
    assert results(state) == {"mystery": "INSUFFICIENT_EVIDENCE"}
    [finding] = findings(state, SENSITIVE)
    assert "could not identify" in finding["title"].lower()


def test_rs4_restricted_targets_match_exactly_or_by_prefix_without_leaking_the_target(
    db, setup_monitor, admins
):
    models, store, clock, source, session = setup_monitor
    store.set_profile(db, admins[0], profile(restricted_targets=["dc-01", "tier0-*"]), clock=clock)
    ingest_many(
        store,
        db,
        source,
        models,
        clock,
        [
            ("exact", {"action": "ticket.comment", "target_ref": "dc-01"}),
            ("prefix", {"action": "ticket.comment", "target_ref": "tier0-vault"}),
            ("near", {"action": "ticket.comment", "target_ref": "dc-010"}),
            ("none", {"action": "ticket.comment", "target_ref": None}),
        ],
    )
    assert store.evaluate_pending(db, admins[0], clock=clock) == 4
    state = store.snapshot(db, session, clock=clock)
    by_observation = {o["observation_id"]: o["event_id"] for o in state["observations"]}
    hits = sorted(by_observation[f["observation_id"]] for f in findings(state, RESTRICTED))
    assert hits == ["exact", "prefix"]
    for finding in findings(state, RESTRICTED):
        assert "dc-01" not in finding["title"] and "tier0" not in finding["title"]
    assert results(state)["none"] == "NO_MATCH"


def test_rs5_rs6_bursts_count_receipts_per_window_regardless_of_reported_time(
    db, setup_monitor, admins
):
    models, store, clock, source, session = setup_monitor
    store.set_profile(
        db,
        admins[0],
        profile(sensitive_actions=[], burst_threshold=3, burst_window_seconds=60),
        clock=clock,
    )
    # Receipts are counted in fixed windows aligned to the epoch. Start on a window
    # boundary so the four receipts, five seconds apart, never straddle two windows.
    clock.value += timedelta(seconds=60 - clock.value.second, microseconds=-clock.value.microsecond)
    skewed = clock.now() - timedelta(hours=3)
    for index in range(4):
        occurred = skewed if index % 2 else clock.now()
        store.ingest(
            db,
            source.token,
            observation(
                models,
                clock,
                event_id=f"burst-{index}",
                action="ticket.comment",
                occurred_at=occurred,
            ),
            clock=clock,
        )
        clock.value += timedelta(seconds=5)
    assert store.evaluate_pending(db, admins[0], clock=clock) == 4
    state = store.snapshot(db, session, clock=clock)
    by_observation = {o["observation_id"]: o["event_id"] for o in state["observations"]}
    [finding] = findings(state, RATE)
    assert by_observation[finding["observation_id"]] == "burst-2"
    assert "rate" in finding["title"].lower()
    clock.value += timedelta(seconds=61)
    ingest_many(
        store,
        db,
        source,
        models,
        clock,
        [("next-0", {"action": "ticket.comment"}), ("next-1", {"action": "ticket.comment"})],
    )
    assert store.evaluate_pending(db, admins[0], clock=clock) == 2
    assert len(findings(store.snapshot(db, session, clock=clock), RATE)) == 1


def test_rs7_a_profile_change_retires_the_old_version_and_stamps_later_findings(
    db, setup_monitor, admins
):
    models, store, clock, source, session = setup_monitor
    first = store.set_profile(
        db, admins[0], profile(sensitive_actions=["ticket.close"]), clock=clock
    )
    ingest_many(store, db, source, models, clock, [("one", {"action": "ticket.close"})])
    assert store.evaluate_pending(db, admins[0], clock=clock) == 1
    second = store.set_profile(
        db, admins[0], profile(sensitive_actions=["ticket.reopen"]), clock=clock
    )
    assert (second.version, second.profile_id != first.profile_id) == (2, True)
    ingest_many(store, db, source, models, clock, [("two", {"action": "ticket.reopen"})])
    assert store.evaluate_pending(db, admins[0], clock=clock) == 1
    state = store.snapshot(db, session, clock=clock)
    versions = sorted(f["profile_version"] for f in findings(state, SENSITIVE))
    assert versions == [1, 2]
    assert state["profile"][0]["version"] == 2
    assert store.active_profile(db, admins[0], clock=clock).profile_id == second.profile_id
    with db.transaction(admins[0].tenant_id) as conn:
        retired = conn.execute(
            text("SELECT count(*) FROM execbound.monitor_profiles WHERE retired_at IS NOT NULL")
        ).scalar_one()
    assert retired == 1


@pytest.mark.parametrize(
    "changes",
    [
        {"sensitive_actions": ["not a valid action!"]},
        {"restricted_targets": ["*"]},
        {"restricted_targets": ["dc-*-01"]},
        {"burst_threshold": 3},
        {"burst_window_seconds": 60},
        {"burst_threshold": 1, "burst_window_seconds": 60},
        {"restricted_targets": [f"t-{i}" for i in range(257)]},
    ],
)
def test_rs8_invalid_profiles_are_refused_and_change_nothing(
    db, setup_monitor, admins, admin_engine, changes
):
    models, store, clock, source, session = setup_monitor
    with pytest.raises(ValueError):
        profile(**changes)
    assert store.active_profile(db, admins[0], clock=clock) is None
    human = provision_identity(admin_engine, db, admins[0].tenant_id, "HUMAN_APPROVER", clock.now())
    with pytest.raises(MonitorError) as refused:
        store.set_profile(db, human, profile(), clock=clock)
    assert refused.value.code == "INVALID_ADMIN"
    assert store.active_profile(db, admins[0], clock=clock) is None


def test_rs9_profiles_are_tenant_scoped(db, setup_monitor, admins, seeded):
    models, store, clock, source, session = setup_monitor
    store.set_profile(db, admins[1], profile(sensitive_actions=["ticket.close"]), clock=clock)
    assert store.active_profile(db, admins[0], clock=clock) is None
    ingest_many(store, db, source, models, clock, [("close", {"action": "ticket.close"})])
    assert store.evaluate_pending(db, admins[0], clock=clock) == 1
    # Tenant A has no profile, so the other tenant's configured action is only a coverage limit.
    assert results(store.snapshot(db, session, clock=clock)) == {"close": "INSUFFICIENT_EVIDENCE"}
    assert store.active_profile(db, admins[1], clock=clock).version == 1


def test_rs10_duplicates_conflicts_and_out_of_order_receipts_under_the_rate_rule(
    db, setup_monitor, admins
):
    models, store, clock, source, session = setup_monitor
    store.set_profile(
        db,
        admins[0],
        profile(sensitive_actions=[], burst_threshold=3, burst_window_seconds=60),
        clock=clock,
    )
    event = observation(models, clock, event_id="dup", action="ticket.comment")
    store.ingest(db, source.token, event, clock=clock)
    store.ingest(db, source.token, event, clock=clock)
    conflict = observation(models, clock, event_id="dup", action="ticket.close")
    with pytest.raises(MonitorError):
        store.ingest(db, source.token, conflict, clock=clock)
    ingest_many(
        store,
        db,
        source,
        models,
        clock,
        [
            (
                "later",
                {"action": "ticket.comment", "occurred_at": clock.now() + timedelta(seconds=30)},
            ),
            (
                "earlier",
                {"action": "ticket.comment", "occurred_at": clock.now() - timedelta(seconds=30)},
            ),
        ],
    )
    assert store.evaluate_pending(db, admins[0], clock=clock) == 3
    state = store.snapshot(db, session, clock=clock)
    assert len(findings(state, RATE)) == 1
    assert len(findings(state, "source-event-integrity.v1")) == 1


def test_rs11_delivery_and_pages_carry_the_rule_and_profile_versions(
    db, setup_monitor, admins, receiver, seeded, admin_engine
):
    models, store, clock, source, session = setup_monitor
    local, output = receiver
    store.set_profile(db, admins[0], profile(sensitive_actions=["ticket.close"]), clock=clock)
    ingest_many(store, db, source, models, clock, [("close", {"action": "ticket.close"})])
    assert store.evaluate_pending(db, admins[0], clock=clock) == 1
    assert worker.deliver_pending(db, admins[0], local, clock=clock) == 1
    [delivered] = list(output.glob("*.json"))
    payload = json.loads(delivered.read_text(encoding="utf-8"))
    assert payload["rule_version"] == SENSITIVE and payload["profile_version"] == "1"
    # Another administrator of the tenant reads the page; the story already has its source.
    web_admin = provision_identity(admin_engine, db, seeded["tenants"][0], "ADMIN", clock.now())
    with signed_in(db, admin_engine, web_admin) as (client, _):
        pages(client, db, admins, clock)


def pages(client, db, admins, clock):
    view = client.get("/api/console/v1/monitor")
    assert view.status_code == 200
    body = view.json()
    # The web client shares the tenant, so the active profile and its finding are shown.
    assert body["profile"]["version"] == 1
    assert any(finding["profile_version"] == 1 for finding in body["findings"])
    monitor_store.set_profile(
        db, admins[0], profile(sensitive_actions=["ticket.close"]), clock=clock
    )
    assert client.get("/api/console/v1/monitor").json()["profile"]["version"] == 2


def test_rs12_migration_round_trip_and_runtime_catalog(db, setup_monitor, admins):
    models, store, clock, source, session = setup_monitor
    assert "monitor_profiles" in TABLES
    with db.transaction(admins[0].tenant_id) as conn:
        check_runtime(conn)
    record = store.set_profile(db, admins[0], profile(), clock=clock)
    with (
        pytest.raises(Exception, match="permission denied"),
        db.transaction(admins[0].tenant_id) as conn,
    ):
        conn.execute(text("DELETE FROM execbound.monitor_profiles"))
    with (
        pytest.raises(Exception, match="permission denied"),
        db.transaction(admins[0].tenant_id) as conn,
    ):
        conn.execute(text("UPDATE execbound.monitor_profiles SET version=9"))
    config = Config("alembic.ini")
    config.attributes["database_url"] = os.environ["TEST_MIGRATION_DATABASE_URL"]
    with pytest.raises(RuntimeError):
        command.downgrade(config, "0013_source_health")
    with db.transaction(admins[0].tenant_id) as conn:
        check_runtime(conn)
    assert record.version == 1


def test_rs13_cli_sets_and_shows_the_profile_without_printing_values(
    db, setup_monitor, admins, admin_engine, tmp_path, monkeypatch, capsys
):
    models, store, clock, source, session = setup_monitor
    monkeypatch.setenv("DATABASE_URL", os.environ["TEST_DATABASE_URL"])
    admin_file = tmp_path / "admin.token"
    admin_file.write_text(credential(admin_engine, admins[0]), encoding="utf-8")
    good = tmp_path / "profile.json"
    good.write_text(
        json.dumps(
            {
                "sensitive_actions": ["ticket.close"],
                "restricted_targets": ["dc-*"],
                "burst_threshold": 5,
                "burst_window_seconds": 120,
            }
        ),
        encoding="utf-8",
    )
    monkeypatch.setattr(
        sys,
        "argv",
        ["monitoring", "set-profile", "--credential-file", str(admin_file), "--input", str(good)],
    )
    commands.main()
    printed = json.loads(capsys.readouterr().out)
    assert printed["version"] == 1
    monkeypatch.setattr(
        sys, "argv", ["monitoring", "show-profile", "--credential-file", str(admin_file)]
    )
    commands.main()
    shown = json.loads(capsys.readouterr().out)
    assert shown["version"] == 1 and shown["profile"]["burst_threshold"] == 5
    bad = tmp_path / "bad.json"
    bad.write_text(json.dumps({"sensitive_actions": ["secret value here!"]}), encoding="utf-8")
    monkeypatch.setattr(
        sys,
        "argv",
        ["monitoring", "set-profile", "--credential-file", str(admin_file), "--input", str(bad)],
    )
    with pytest.raises(SystemExit) as caught:
        commands.main()
    assert caught.value.code == 2
    err = capsys.readouterr().err
    assert "sensitive_actions" in err and "secret value here" not in err
    assert store.active_profile(db, admins[0], clock=clock).version == 1
