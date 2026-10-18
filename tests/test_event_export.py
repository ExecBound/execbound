# SPDX-License-Identifier: AGPL-3.0-only
"""Security event export through per-destination cursors: SE5 to SE12 on real PostgreSQL."""

import json
import os
import secrets
import sys
from datetime import timedelta
from uuid import UUID

import pytest
from alembic import command
from alembic.config import Config
from sqlalchemy import text
from sqlalchemy.exc import DBAPIError
from test_execution import provision_identity
from test_execution import registry as registry
from test_execution import world as world
from test_human_surface import credential
from test_monitoring_worker import receiver as receiver
from test_protected_path import connector as connector
from test_protected_path import live_provider as live_provider
from test_runtime import api as api
from test_runtime import runtime as runtime
from test_structured_logging import captured as captured
from test_structured_logging import events

from execbound import export as exporter
from execbound.audit import append_event
from execbound.cli import main
from execbound.db import TABLES, check_runtime
from execbound.execution.models import ExecutionError
from execbound.export import export_events, export_status, resume_export
from execbound.notifications import Destination


def destination(world, receiver, destination_id="siem"):
    local, _ = receiver
    return Destination(
        destination_id=destination_id,
        tenant_id=world["identity"].tenant_id,
        url=local.url,
        secret=local.secret,
        kind="security-events",
    )


def append(db, world, count, **payload):
    with db.transaction(world["identity"].tenant_id) as conn:
        for index in range(count):
            append_event(
                conn,
                world["identity"].tenant_id,
                world["identity"].principal_id,
                "test.recorded",
                {"index": index, **payload},
            )


def batches(output):
    files = sorted(
        (p for p in output.glob("*.json") if len(p.stem) == 36 and p.stem.count("-") == 4),
        key=lambda p: p.stat().st_mtime_ns,
    )
    return [json.loads(p.read_text(encoding="utf-8")) for p in files]


def head_sequence(engine, tenant):
    with engine.connect() as conn:
        return int(
            conn.execute(
                text("SELECT sequence FROM execbound.audit_heads WHERE tenant_id=:t"),
                {"t": tenant},
            ).scalar_one()
        )


def cursor(engine, tenant, destination_id):
    with engine.begin() as conn:
        conn.execute(text("SELECT set_config('execbound.tenant_id', :t, true)"), {"t": str(tenant)})
        return dict(
            conn.execute(
                text(
                    "SELECT last_sequence, last_event_hash, attempts, state, last_error "
                    "FROM execbound.export_cursors WHERE tenant_id=:t AND destination_id=:d"
                ),
                {"t": tenant, "d": destination_id},
            )
            .mappings()
            .one()
        )


def test_se5_events_export_in_order_in_bounded_batches_to_every_destination(
    db, world, admin_engine, receiver
):
    tenant = world["identity"].tenant_id
    local, output = receiver
    targets = [destination(world, receiver, "siem"), destination(world, receiver, "archive")]
    append(db, world, 100)
    total = head_sequence(admin_engine, tenant)
    assert total > 100
    exported = {"siem": 0, "archive": 0}
    for _ in range(3):
        result = export_events(db, world["admin"], targets, limit=40, clock=world["clock"])
        for name, value in result.items():
            exported[name] += value["exported"]
    assert exported == {"siem": total, "archive": total}
    assert all(v["state"] == "ACTIVE" and v["lag"] == 0 for v in result.values())
    again = export_events(db, world["admin"], targets, limit=40, clock=world["clock"])
    assert {k: v["exported"] for k, v in again.items()} == {"siem": 0, "archive": 0}
    with admin_engine.connect() as conn:
        head = conn.execute(
            text("SELECT sequence, event_hash FROM execbound.audit_heads WHERE tenant_id=:t"),
            {"t": tenant},
        ).one()
    for name in ("siem", "archive"):
        row = cursor(admin_engine, tenant, name)
        assert (row["last_sequence"], row["last_event_hash"]) == (head[0], head[1])
    delivered = batches(output)
    assert len(delivered) == 6
    sequences = [
        e["sequence"] for b in delivered if b["destination_id"] == "siem" for e in b["events"]
    ]
    assert sequences == sorted(sequences) and len(sequences) == head[0]
    first = delivered[0]
    assert first["kind"] == "audit.events" and first["version"] == 1
    assert first["tenant_id"] == str(tenant) and set(first["events"][0]) >= {
        "sequence",
        "event_id",
        "kind",
        "payload",
        "previous_hash",
        "event_hash",
    }


def test_se6_one_failing_destination_does_not_block_another(
    db, world, admin_engine, receiver, monkeypatch
):
    tenant = world["identity"].tenant_id
    targets = [destination(world, receiver, "siem"), destination(world, receiver, "archive")]
    append(db, world, 10)
    total = head_sequence(admin_engine, tenant)
    genuine = exporter.send_notification

    def flaky(receiver_, delivery_id, payload, client, **kwargs):
        if receiver_.destination_id == "archive":
            return False
        return genuine(receiver_, delivery_id, payload, client, **kwargs)

    monkeypatch.setattr(exporter, "send_notification", flaky)
    result = export_events(db, world["admin"], targets, clock=world["clock"])
    assert result["siem"]["exported"] == total and result["archive"]["exported"] == 0
    archive = cursor(admin_engine, tenant, "archive")
    assert (archive["last_sequence"], archive["attempts"], archive["state"]) == (0, 1, "ACTIVE")
    assert archive["last_error"] == "RECEIVER_UNAVAILABLE"
    assert (
        export_events(db, world["admin"], targets, clock=world["clock"])["archive"]["exported"] == 0
    )
    monkeypatch.setattr(exporter, "send_notification", genuine)
    world["clock"].value += timedelta(seconds=6)
    assert (
        export_events(db, world["admin"], targets, clock=world["clock"])["archive"]["exported"]
        == total
    )


def test_se7_five_failures_fail_the_cursor_visibly_until_resumed(
    db, world, admin_engine, receiver, monkeypatch
):
    tenant = world["identity"].tenant_id
    targets = [destination(world, receiver, "siem")]
    append(db, world, 3)
    total = head_sequence(admin_engine, tenant)
    monkeypatch.setattr(exporter, "send_notification", lambda *a, **k: False)
    for _ in range(5):
        export_events(db, world["admin"], targets, clock=world["clock"])
        # Bring the next attempt forward instead of moving the clock past the credential.
        with admin_engine.begin() as conn:
            conn.execute(
                text("UPDATE execbound.export_cursors SET next_attempt_at=:now"),
                {"now": world["clock"].now()},
            )
    row = cursor(admin_engine, tenant, "siem")
    assert (row["state"], row["attempts"], row["last_sequence"]) == ("FAILED", 5, 0)
    status = export_status(db, world["admin"], targets, clock=world["clock"])
    assert status["siem"]["state"] == "FAILED" and status["siem"]["lag"] == total
    assert export_events(db, world["admin"], targets, clock=world["clock"])["siem"]["exported"] == 0
    monkeypatch.setattr(exporter, "send_notification", lambda *a, **k: True)
    resume_export(db, world["admin"], "siem", clock=world["clock"])
    assert (
        export_events(db, world["admin"], targets, clock=world["clock"])["siem"]["exported"]
        == total
    )
    assert export_status(db, world["admin"], targets, clock=world["clock"])["siem"]["lag"] == 0


def test_se8_a_lost_acknowledgement_resends_the_same_batch_which_the_receiver_deduplicates(
    db, world, admin_engine, receiver, monkeypatch
):
    local, output = receiver
    targets = [destination(world, receiver, "siem")]
    append(db, world, 5)
    genuine = exporter.send_notification
    calls = []

    def lossy(receiver_, delivery_id, payload, client, **kwargs):
        calls.append(delivery_id)
        genuine(receiver_, delivery_id, payload, client, **kwargs)
        return len(calls) > 1

    monkeypatch.setattr(exporter, "send_notification", lossy)
    total = head_sequence(admin_engine, world["identity"].tenant_id)
    assert export_events(db, world["admin"], targets, clock=world["clock"])["siem"]["exported"] == 0
    world["clock"].value += timedelta(seconds=6)
    assert (
        export_events(db, world["admin"], targets, clock=world["clock"])["siem"]["exported"]
        == total
    )
    assert calls[0] == calls[1] and len(batches(output)) == 1


def test_se9_a_payload_that_trips_the_secret_check_stops_the_export_at_that_event(
    db, world, admin_engine, receiver
):
    tenant = world["identity"].tenant_id
    targets = [destination(world, receiver, "siem")]
    append(db, world, 2)
    append(db, world, 1, dispatch_token="leaked-secret-value")
    append(db, world, 2)
    result = export_events(db, world["admin"], targets, clock=world["clock"])
    assert result["siem"]["exported"] == 0 and result["siem"]["state"] == "FAILED"
    row = cursor(admin_engine, tenant, "siem")
    assert row["last_error"] == "PAYLOAD_REFUSED" and row["last_sequence"] == 0
    assert "leaked-secret-value" not in json.dumps(batches(receiver[1]))


def test_se10_authentication_failure_summaries_ride_along_once(
    db, world, api, admin_engine, receiver
):
    local, output = receiver
    targets = [destination(world, receiver, "siem")]
    api.headers.pop("Authorization", None)
    tenant, credential_id = world["identity"].tenant_id, world["identity"].credential_id
    wrong = f"eb1.{tenant}.{credential_id}.{secrets.token_urlsafe(32)}"
    probe = "/v1/executions/" + str(UUID(int=7))
    for _ in range(2):
        assert api.get(probe, headers={"Authorization": "Bearer " + wrong}).status_code == 401
    append(db, world, 1)
    export_events(db, world["admin"], targets, clock=world["clock"])
    [first] = batches(output)
    [summary] = first["authentication_failures"]
    assert (summary["surface"], summary["reason"], summary["count"]) == ("http", "MISMATCH", 2)
    assert summary["subject_id"] == str(credential_id) and wrong not in json.dumps(first)
    append(db, world, 1)
    export_events(db, world["admin"], targets, clock=world["clock"])
    assert batches(output)[-1]["authentication_failures"] == []


def test_se11_only_a_current_admin_exports_and_only_to_its_tenants_destinations(
    db, world, admin_engine, seeded, receiver
):
    other = Destination(
        destination_id="foreign",
        tenant_id=seeded["tenants"][1],
        url=receiver[0].url,
        secret=receiver[0].secret,
        kind="security-events",
    )
    append(db, world, 2)
    for actor in (world["identity"], world["human"]):
        with pytest.raises(ExecutionError) as refused:
            export_events(db, actor, [destination(world, receiver)], clock=world["clock"])
        assert refused.value.code == "INVALID_IDENTITY"
    result = export_events(
        db, world["admin"], [destination(world, receiver), other], clock=world["clock"]
    )
    assert set(result) == {"siem"} and result["siem"]["exported"] >= 2
    other_admin = provision_identity(
        admin_engine, db, seeded["tenants"][1], "ADMIN", world["clock"].now()
    )
    assert export_events(db, other_admin, [other], clock=world["clock"])["foreign"]["exported"] == 0


def test_se12_migration_round_trip_and_runtime_catalog(db, world, admin_engine, receiver):
    tenant = world["identity"].tenant_id
    assert "export_cursors" in TABLES
    with db.transaction(tenant) as conn:
        check_runtime(conn)
    append(db, world, 1)
    export_events(db, world["admin"], [destination(world, receiver)], clock=world["clock"])
    with pytest.raises(DBAPIError, match="permission denied"), db.transaction(tenant) as conn:
        conn.execute(text("DELETE FROM execbound.export_cursors"))
    config = Config("alembic.ini")
    config.attributes["database_url"] = os.environ["TEST_MIGRATION_DATABASE_URL"]
    with pytest.raises(RuntimeError):
        command.downgrade(config, "0015_approval_notifications")
    with db.transaction(tenant) as conn:
        check_runtime(conn)


def test_se13_cli_exports_and_reports_status(
    db, world, admin_engine, receiver, tmp_path, monkeypatch, capsys, connector
):
    tenant = world["identity"].tenant_id
    local, _ = receiver
    config = connector.config
    private = tmp_path / "private.json"
    private.write_text(
        json.dumps(
            {
                "origin": "http://127.0.0.1:8000",
                "active_key_id": "k1",
                "continuation_keys": {"k1": "11" * 32},
                "connectors": [
                    {
                        "tenant_id": str(tenant),
                        "account_id": str(world["account"]),
                        "origin": config.origin,
                        "dispatch_token": config.dispatch_token,
                        "control_token": config.control_token,
                        "evidence_keys": {k: v.hex() for k, v in config.evidence_keys.items()},
                    }
                ],
                "notifications": [
                    {
                        "destination_id": "siem",
                        "tenant_id": str(tenant),
                        "kind": "security-events",
                        "url": local.url,
                        "secret": local.secret,
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    monkeypatch.setenv("EXECBOUND_RUNTIME_CONFIG", str(private))
    monkeypatch.setenv("DATABASE_URL", os.environ["TEST_DATABASE_URL"])
    admin_file = tmp_path / "admin.token"
    admin_file.write_text(credential(admin_engine, world["admin"]), encoding="utf-8")
    append(db, world, 4)
    common = ["--tenant", str(tenant), "--credential-file", str(admin_file)]
    monkeypatch.setattr(sys, "argv", ["execbound", "export-events", *common])
    main()
    printed = json.loads(capsys.readouterr().out)
    assert printed["siem"]["exported"] >= 4
    monkeypatch.setattr(sys, "argv", ["execbound", "export-status", *common])
    main()
    status = json.loads(capsys.readouterr().out)
    assert status["siem"]["lag"] == 0 and UUID(str(tenant))


def test_each_destinations_run_is_logged_with_its_state_count_and_code(
    db, world, admin_engine, receiver, captured, monkeypatch
):
    """One `export.completed` line per destination per run, written after the run's own
    transactions: the state and last error its cursor holds afterwards and the events the run
    exported, never the destination's URL or secret. A failing destination logs at WARNING
    with its code, so a stuck export is visible to a log collector without `export-status`."""
    tenant = world["identity"].tenant_id
    local, _ = receiver
    targets = [destination(world, receiver, "siem"), destination(world, receiver, "archive")]
    append(db, world, 3)
    total = head_sequence(admin_engine, tenant)
    genuine = exporter.send_notification

    def flaky(receiver_, delivery_id, payload, client, **kwargs):
        if receiver_.destination_id == "archive":
            return False
        return genuine(receiver_, delivery_id, payload, client, **kwargs)

    monkeypatch.setattr(exporter, "send_notification", flaky)
    export_events(db, world["admin"], targets, clock=world["clock"])
    lines = {line["destination_id"]: line for line in events(captured, "export.completed")}
    assert set(lines) == {"siem", "archive"}
    for line in lines.values():
        line.pop("ts")
    assert lines["siem"] == {
        "event": "export.completed",
        "level": "INFO",
        "tenant_id": str(tenant),
        "destination_id": "siem",
        "state": "ACTIVE",
        "count": total,
        "code": None,
    }
    assert lines["archive"] == {
        "event": "export.completed",
        "level": "WARNING",
        "tenant_id": str(tenant),
        "destination_id": "archive",
        "state": "ACTIVE",
        "count": 0,
        "code": "RECEIVER_UNAVAILABLE",
    }
    # A cursor the secret check stops is FAILED with its code, and says so on every later run.
    append(db, world, 1, dispatch_token="leaked-secret-value")
    for _ in range(2):
        export_events(db, world["admin"], targets[:1], clock=world["clock"])
    stopped = events(captured, "export.completed")[-2:]
    assert [(line["state"], line["count"], line["code"], line["level"]) for line in stopped] == [
        ("FAILED", 0, "PAYLOAD_REFUSED", "WARNING")
    ] * 2
    text_logged = captured.getvalue()
    assert local.url not in text_logged and local.secret not in text_logged
    assert "leaked-secret-value" not in text_logged
