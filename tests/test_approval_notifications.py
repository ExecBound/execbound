# SPDX-License-Identifier: AGPL-3.0-only
"""Approval notifications through operator destinations: AN1 to AN12 on real PostgreSQL."""

import json
import os
import secrets
import sys
from concurrent.futures import ThreadPoolExecutor
from datetime import timedelta
from uuid import UUID, uuid4

import pytest
from alembic import command
from alembic.config import Config
from conftest import assert_secret_free
from fastapi.testclient import TestClient
from sqlalchemy import event as sa_event
from sqlalchemy import text
from sqlalchemy.exc import DBAPIError
from test_approval_quorum import activate, quorum_bundle, second_approver
from test_execution import registry as registry
from test_execution import request, targets
from test_execution import world as world
from test_human_surface import credential, form_values
from test_human_surface import human_config as human_config
from test_monitoring_worker import receiver as receiver
from test_protected_path import connector as connector
from test_protected_path import live_provider as live_provider
from test_structured_logging import captured as captured
from test_structured_logging import events

from execbound import notifications
from execbound.app import create_app
from execbound.cli import main
from execbound.db import TABLES, check_runtime
from execbound.execution import decide_approval
from execbound.notifications import Destination, deliver_pending, list_notifications
from execbound.recovery_run import recover
from execbound.runtime import Runtime
from execbound.surfaces.configuration import load_runtime
from execbound.surfaces.human import records
from execbound.surfaces.tokens import TokenKeys
from execbound_harness.demo import endpoint_bundle

ORIGIN = {"Origin": "http://127.0.0.1"}
PAYLOAD_KEYS = {
    "version",
    "kind",
    "tenant_id",
    "approval_id",
    "execution_id",
    "action",
    "resource_class",
    "environment",
    "canonical_target_id",
    "expires_at",
    "assigned_approvers",
    "approval_url",
}


def destination(world, receiver, destination_id="soc", approvers=None):
    local, _ = receiver
    return Destination(
        destination_id=destination_id,
        tenant_id=world["identity"].tenant_id,
        url=local.url,
        secret=local.secret,
        approvers=frozenset(approvers) if approvers is not None else None,
    )


@pytest.fixture
def notifying(db, world, connector, receiver):
    filtered = destination(world, receiver, "assigned", [world["human"].principal_id])
    unfiltered = destination(world, receiver, "everyone")
    keys = TokenKeys("pending-v1", {"pending-v1": secrets.token_bytes(32)})
    return Runtime(
        db,
        [connector],
        clock=world["clock"],
        keys=keys,
        approval_url="http://127.0.0.1/approvals",
        notifications=[filtered, unfiltered],
    )


def delivered_files(output):
    """The loopback receiver stores one file per delivery id beside the provider's own files."""
    return sorted(p for p in output.glob("*.json") if len(p.stem) == 36 and p.stem.count("-") == 4)


def rows(engine, tenant):
    with engine.begin() as conn:
        conn.execute(text("SELECT set_config('execbound.tenant_id', :t, true)"), {"t": str(tenant)})
        return [
            dict(r)
            for r in conn.execute(
                text(
                    "SELECT notification_id, approval_id, destination_id, state, attempts, "
                    "last_error FROM execbound.approval_notifications WHERE tenant_id=:t "
                    "ORDER BY destination_id"
                ),
                {"t": tenant},
            ).mappings()
        ]


def widen(admin_engine, approval_id, seconds):
    """Stand in for an approval whose deadline is off and whose facts stay valid this long.

    The drain reads only the stored `expires_at`, so moving it is the whole difference a
    longer window makes to delivery; the owner role writes it, as nothing at runtime can.
    """
    with admin_engine.begin() as conn:
        conn.execute(
            text(
                "UPDATE execbound.approvals "
                "SET expires_at = created_at + make_interval(secs => :s) WHERE approval_id=:a"
            ),
            {"a": approval_id, "s": seconds},
        )


def drain(db, world, runtime, **kw):
    return deliver_pending(
        db,
        world["admin"],
        runtime.notifications,
        approval_url=runtime.approval_url or "",
        clock=world["clock"],
        **kw,
    )


def pending(runtime, world, **changes):
    view = runtime.execute(world["identity"], request(world, **changes).model_dump_json().encode())
    assert view.state == "PENDING_APPROVAL"
    return view


def test_an1_an2_notifications_are_queued_with_the_approval_for_matching_destinations(
    db, world, admin_engine, notifying, receiver
):
    tenant = world["identity"].tenant_id
    view = pending(notifying, world)
    queued = rows(admin_engine, tenant)
    assert [(r["destination_id"], r["state"]) for r in queued] == [
        ("assigned", "PENDING"),
        ("everyone", "PENDING"),
    ]
    assert {r["approval_id"] for r in queued} == {view.approval_id}
    eligible = notifying.execute(
        world["identity"], targets(admin_engine, world, 1)[0].model_dump_json().encode()
    )
    assert eligible.state != "PENDING_APPROVAL" and len(rows(admin_engine, tenant)) == 2
    unassigned = Runtime(
        db,
        list(notifying.connectors.values()),
        clock=world["clock"],
        keys=notifying.keys,
        notifications=[destination(world, receiver, "nobody", [world["admin"].principal_id])],
    )
    with admin_engine.begin() as conn:
        conn.execute(text("UPDATE execbound.executions SET state='DENIED'"))
    second = pending(unassigned, world, idempotency_key="second")
    assert second.approval_id != view.approval_id
    assert [r["destination_id"] for r in rows(admin_engine, tenant)] == ["assigned", "everyone"]


def test_an3_the_drain_delivers_each_notification_once_with_the_documented_payload(
    db, world, admin_engine, notifying, receiver
):
    local, output = receiver
    tenant = world["identity"].tenant_id
    view = pending(notifying, world)
    result = drain(db, world, notifying)
    assert result["delivered"] == 2
    assert drain(db, world, notifying) == {
        "delivered": 0,
        "failed": 0,
        "closed": 0,
    }
    files = delivered_files(output)
    assert len(files) == 2
    for path in files:
        payload = json.loads(path.read_text(encoding="utf-8"))
        assert set(payload) == PAYLOAD_KEYS
        assert payload["kind"] == "approval.pending" and payload["version"] == 1
        assert payload["approval_id"] == str(view.approval_id)
        assert payload["action"] == "endpoint.isolate" and payload["environment"] == "production"
        assert payload["approval_url"] == "http://127.0.0.1/approvals"
        assert payload["assigned_approvers"] == 1
        assert len(path.read_bytes()) <= 4096
    assert {r["state"] for r in rows(admin_engine, tenant)} == {"DELIVERED"}


@pytest.mark.parametrize(
    ("window", "attempts"),
    [
        # Facts valid for hours and the deadline off: every attempt fits, up to MAX_ATTEMPTS.
        pytest.param(7200, 5, id="long-window"),
        # The default 120 s deadline: the third retry would land past it, so the row fails
        # there with the transport's code (#678, AY4).
        pytest.param(None, 3, id="default-window"),
    ],
)
def test_an4_an5_failed_sends_back_off_and_fail_visibly_without_touching_the_approval(
    db, world, admin_engine, notifying, receiver, live_provider, monkeypatch, window, attempts
):
    tenant = world["identity"].tenant_id
    single = Runtime(
        db,
        list(notifying.connectors.values()),
        clock=world["clock"],
        keys=notifying.keys,
        notifications=[destination(world, receiver, "only")],
    )
    view = pending(single, world)
    if window is not None:
        widen(admin_engine, view.approval_id, window)
    outcomes = iter([False, True])
    monkeypatch.setattr(notifications, "send_notification", lambda *args, **kwargs: next(outcomes))
    assert drain(db, world, single) == {
        "delivered": 0,
        "failed": 0,
        "closed": 0,
    }
    [row] = rows(admin_engine, tenant)
    assert (row["state"], row["attempts"], row["last_error"]) == (
        "PENDING",
        1,
        "RECEIVER_UNAVAILABLE",
    )
    # Backoff: nothing is due until the next attempt time passes.
    assert drain(db, world, single)["delivered"] == 0
    world["clock"].value += timedelta(seconds=6)
    assert drain(db, world, single)["delivered"] == 1
    with admin_engine.begin() as conn:
        conn.execute(
            text(
                "UPDATE execbound.approval_notifications SET state='PENDING', attempts=0, "
                "delivered_at=NULL, next_attempt_at=:now, last_error=NULL"
            ),
            {"now": world["clock"].now()},
        )
    monkeypatch.setattr(notifications, "send_notification", lambda *args, **kwargs: False)
    for _ in range(5):
        drain(db, world, single)
        # Bring the next attempt forward instead of moving the clock past the approval window.
        with admin_engine.begin() as conn:
            conn.execute(
                text("UPDATE execbound.approval_notifications SET next_attempt_at=:now"),
                {"now": world["clock"].now()},
            )
    [row] = rows(admin_engine, tenant)
    assert (row["state"], row["attempts"], row["last_error"]) == (
        "FAILED",
        attempts,
        "RECEIVER_UNAVAILABLE",
    )
    if window is not None:
        # Put back the window admission gave it: the plan it was frozen with expires first.
        widen(admin_engine, view.approval_id, 120)
    # A failed notification changes nothing about the approval or the execution.
    decide_approval(db, world["human"], view.approval_id, "APPROVE", world["clock"])
    done = single.execute(world["identity"], request(world).model_dump_json().encode())
    assert done.state == "EXECUTED"


def test_an6_a_closed_approval_is_never_notified(db, world, admin_engine, notifying, monkeypatch):
    tenant = world["identity"].tenant_id
    view = pending(notifying, world)
    decide_approval(db, world["human"], view.approval_id, "DENY", world["clock"])
    monkeypatch.setattr(
        notifications, "send_notification", lambda *args, **kwargs: pytest.fail("sent")
    )
    result = drain(db, world, notifying)
    assert result["closed"] == 2
    assert {(r["state"], r["last_error"]) for r in rows(admin_engine, tenant)} == {
        ("FAILED", "APPROVAL_CLOSED")
    }


def test_an7_a_failed_approval_commit_leaves_no_notification_behind(
    db, world, admin_engine, notifying
):
    tenant = world["identity"].tenant_id

    def fail_outbox(conn, cursor, statement, parameters, context, executemany):
        if "INSERT INTO execbound.approval_notifications" in statement:
            raise RuntimeError("injected crash")

    sa_event.listen(db.engine, "before_cursor_execute", fail_outbox)
    try:
        with pytest.raises(RuntimeError, match="injected crash"):
            notifying.execute(world["identity"], request(world).model_dump_json().encode())
    finally:
        sa_event.remove(db.engine, "before_cursor_execute", fail_outbox)
    assert rows(admin_engine, tenant) == []
    with admin_engine.connect() as conn:
        assert conn.execute(text("SELECT count(*) FROM execbound.approvals")).scalar_one() == 0


def test_an8_payloads_carry_identifiers_labels_and_timestamps_only(
    db, world, admin_engine, notifying, receiver
):
    _, output = receiver
    pending(notifying, world)
    drain(db, world, notifying)
    for path in delivered_files(output):
        raw = path.read_text(encoding="utf-8")
        assert_secret_free(raw)
        assert "WS01" not in raw and "<" not in raw
        payload = json.loads(raw)
        for key in ("tenant_id", "approval_id", "execution_id", "canonical_target_id"):
            UUID(payload[key])


def test_an9_concurrent_drains_deliver_each_notification_once(
    db, world, admin_engine, notifying, monkeypatch
):
    pending(notifying, world)
    sent = []
    monkeypatch.setattr(
        notifications,
        "send_notification",
        lambda receiver, delivery_id, *a, **k: sent.append(delivery_id) or True,
    )
    with ThreadPoolExecutor(max_workers=2) as pool:
        list(
            pool.map(
                lambda _: deliver_pending(
                    db, world["admin"], notifying.notifications, clock=world["clock"]
                ),
                range(2),
            )
        )
    assert sorted(sent) == sorted(set(sent)) and len(sent) == 2
    assert {r["state"] for r in rows(admin_engine, world["identity"].tenant_id)} == {"DELIVERED"}


@pytest.mark.parametrize(
    "bad",
    [
        {"url": "http://10.0.0.5/hook"},
        {"url": "https://user:pw@alerts.example.net/hook"},
        {"url": "https://alerts.example.net/hook?x=1"},
        {"secret": "short"},
        {"destination_id": "everyone"},
        {"approvers": ["not-a-uuid"]},
    ],
)
def test_an10_invalid_destinations_are_refused_at_startup_without_leaking_the_secret(
    tmp_path, world, connector, bad
):
    tenant = world["identity"].tenant_id
    config = connector.config
    good = {
        "destination_id": "soc",
        "tenant_id": str(tenant),
        "kind": "webhook",
        "url": "https://alerts.example.net/hook",
        "secret": "s3cr3t-value-" * 3,
    }
    value = {
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
        "notifications": [good | {"destination_id": "everyone"}, good | bad],
    }
    path = tmp_path / "private.json"
    path.write_text(json.dumps(value), encoding="utf-8")
    from execbound.db import Database

    engine = Database("postgresql+psycopg://invalid:invalid@127.0.0.1:1/execbound")
    try:
        with pytest.raises(ValueError) as refused:
            load_runtime(path, engine)
        assert "s3cr3t" not in str(refused.value)
        del value["notifications"]
        path.write_text(json.dumps(value), encoding="utf-8")
        runtime, human = load_runtime(path, engine)
        assert runtime.notifications == ()
        for c in runtime.connectors.values():
            c.close()
    finally:
        engine.close()


def test_an11_page_and_cli_show_delivery_state_and_refuse_non_admins(
    db, world, admin_engine, notifying, human_config, tmp_path, monkeypatch, capsys
):
    tenant = world["identity"].tenant_id
    view = pending(notifying, world)
    app = create_app(db, runtime=notifying, human=human_config)
    with TestClient(app, base_url="http://127.0.0.1", follow_redirects=False) as client:
        _, values = form_values(client.get("/login").text, "/session")
        values["credential"] = credential(admin_engine, world["human"])
        assert client.post("/session", data=values, headers=ORIGIN).status_code == 303
        queue = client.get("/api/console/v1/approvals")
        assert queue.status_code == 200 and "notification pending" in queue.text
        drain(db, world, notifying)
        queue = client.get("/api/console/v1/approvals")
        assert "notified" in queue.text and "2 of 2" in queue.text
    monkeypatch.setenv("DATABASE_URL", os.environ["TEST_DATABASE_URL"])
    admin_file, human_file = tmp_path / "admin.token", tmp_path / "human.token"
    admin_file.write_text(credential(admin_engine, world["admin"]), encoding="utf-8")
    human_file.write_text(credential(admin_engine, world["human"]), encoding="utf-8")
    listing = list_notifications(db, world["admin"], clock=world["clock"])
    assert {n.approval_id for n in listing} == {view.approval_id}
    command = ["execbound", "notifications", "--tenant", str(tenant), "--credential-file"]
    monkeypatch.setattr(sys, "argv", [*command, str(admin_file), "--state", "DELIVERED"])
    main()
    printed = json.loads(capsys.readouterr().out)
    assert len(printed) == 2 and {p["state"] for p in printed} == {"DELIVERED"}
    monkeypatch.setattr(sys, "argv", [*command, str(human_file)])
    with pytest.raises(SystemExit) as caught:
        main()
    assert caught.value.code == 2


def test_an12_migration_round_trip_and_runtime_catalog(db, world, admin_engine, notifying):
    tenant = world["identity"].tenant_id
    assert "approval_notifications" in TABLES
    with db.transaction(tenant) as conn:
        check_runtime(conn)
    pending(notifying, world)
    with pytest.raises(DBAPIError, match="permission denied"), db.transaction(tenant) as conn:
        conn.execute(text("DELETE FROM execbound.approval_notifications"))
    config = Config("alembic.ini")
    config.attributes["database_url"] = os.environ["TEST_MIGRATION_DATABASE_URL"]
    with pytest.raises(RuntimeError):
        command.downgrade(config, "0014_detection_profiles")
    with db.transaction(tenant) as conn:
        check_runtime(conn)
    assert uuid4() is not None


def test_each_delivery_attempt_is_logged_with_its_state_and_code(
    db, world, admin_engine, notifying, receiver, captured, monkeypatch
):
    """One `notifications.delivered` line per delivery attempt, written after the attempt is
    settled: the state the row is left in, its attempts and the attempt's code. A retry and a
    failure log at WARNING. The destination's URL and secret are never fields."""
    local, _ = receiver
    tenant = world["identity"].tenant_id
    single = Runtime(
        db,
        list(notifying.connectors.values()),
        clock=world["clock"],
        keys=notifying.keys,
        notifications=[destination(world, receiver, "only")],
    )
    view = pending(single, world)
    outcomes = iter([False, True])
    genuine = notifications.send_notification
    monkeypatch.setattr(
        notifications,
        "send_notification",
        lambda *args, **kwargs: next(outcomes) and genuine(*args, **kwargs),
    )
    drain(db, world, single)
    world["clock"].value += timedelta(seconds=6)
    drain(db, world, single)
    lines = events(captured, "notifications.delivered")
    for line in lines:
        line.pop("ts")
    common = {
        "event": "notifications.delivered",
        "tenant_id": str(tenant),
        "approval_id": str(view.approval_id),
        "destination_id": "only",
    }
    assert lines == [
        {
            **common,
            "level": "WARNING",
            "state": "PENDING",
            "attempts": 1,
            "code": "RECEIVER_UNAVAILABLE",
        },
        {**common, "level": "INFO", "state": "DELIVERED", "attempts": 2, "code": None},
    ]
    # A row settled without an attempt (its approval closed) logs nothing here.
    with admin_engine.begin() as conn:
        conn.execute(
            text(
                "UPDATE execbound.approval_notifications SET state='PENDING', attempts=0, "
                "delivered_at=NULL, next_attempt_at=:now"
            ),
            {"now": world["clock"].now()},
        )
    decide_approval(db, world["human"], view.approval_id, "DENY", world["clock"])
    assert drain(db, world, single)["closed"] == 1
    assert len(events(captured, "notifications.delivered")) == 2
    assert local.url not in captured.getvalue() and local.secret not in captured.getvalue()


# What the approvals page says about each announcement (#678): a row the drain closed unsent
# is told apart by how its approval ended, through the real producer on the injected clock.
SWEEP_GRACE = timedelta(seconds=300)


def single_hook(db, world, connector, receiver):
    keys = TokenKeys("pending-v1", {"pending-v1": secrets.token_bytes(32)})
    return Runtime(
        db,
        [connector],
        clock=world["clock"],
        keys=keys,
        approval_url="http://127.0.0.1/approvals",
        notifications=[destination(world, receiver, "soc")],
    )


def sweep(db, world, connector, approval_id, admin_engine):
    """Past the deadline and the recovery run's grace, the run ends the approval."""
    with admin_engine.connect() as conn:
        expires = conn.execute(
            text("SELECT expires_at FROM execbound.approvals WHERE approval_id=:a"),
            {"a": approval_id},
        ).scalar_one()
    world["clock"].value = expires + SWEEP_GRACE + timedelta(seconds=1)
    ring = {(world["identity"].tenant_id, world["account"]): connector}
    assert recover(db, world["admin"], ring, clock=world["clock"]).expired == 1


def approval_state(admin_engine, approval_id):
    with admin_engine.connect() as conn:
        return conn.execute(
            text("SELECT state FROM execbound.approvals WHERE approval_id=:a"),
            {"a": approval_id},
        ).scalar_one()


def counted(db, world, approval_id):
    tenant = world["identity"].tenant_id
    with db.transaction(tenant) as conn:
        return notifications.summary(conn, tenant, approval_id)


def closed_rows(admin_engine, tenant):
    return {(r["state"], r["last_error"]) for r in rows(admin_engine, tenant)}


def test_a_message_the_sweep_beat_reads_as_lapsed_not_failed(
    db, world, admin_engine, connector, receiver
):
    tenant = world["identity"].tenant_id
    single = single_hook(db, world, connector, receiver)
    view = pending(single, world)
    sweep(db, world, connector, view.approval_id, admin_engine)
    assert drain(db, world, single)["closed"] == 1
    assert closed_rows(admin_engine, tenant) == {("FAILED", "APPROVAL_CLOSED")}
    assert approval_state(admin_engine, view.approval_id) == "EXPIRED"
    assert counted(db, world, view.approval_id) == {
        "delivered": 0,
        "pending": 0,
        "failed": 0,
        "lapsed": 1,
        "closed": 0,
        "withdrawn": 0,
    }


def test_a_message_the_sweep_beat_after_one_of_two_approvals_reads_as_lapsed(
    db, world, admin_engine, connector, receiver
):
    tenant = world["identity"].tenant_id
    activate(db, world, quorum_bundle(world))
    second_approver(admin_engine, db, world)
    single = single_hook(db, world, connector, receiver)
    view = pending(single, world)
    decide_approval(db, world["human"], view.approval_id, "APPROVE", world["clock"])
    sweep(db, world, connector, view.approval_id, admin_engine)
    drain(db, world, single)
    assert closed_rows(admin_engine, tenant) == {("FAILED", "APPROVAL_CLOSED")}
    assert approval_state(admin_engine, view.approval_id) == "EXPIRED"
    summary = counted(db, world, view.approval_id)
    assert (summary["lapsed"], summary["closed"], summary["failed"]) == (1, 0, 0)


def test_a_message_a_decision_beat_reads_as_closed(db, world, admin_engine, connector, receiver):
    single = single_hook(db, world, connector, receiver)
    view = pending(single, world)
    decide_approval(db, world["human"], view.approval_id, "DENY", world["clock"])
    drain(db, world, single)
    assert approval_state(admin_engine, view.approval_id) == "DENIED"
    summary = counted(db, world, view.approval_id)
    assert (summary["closed"], summary["failed"], summary["lapsed"]) == (1, 0, 0)
    assert summary["withdrawn"] == 0


def test_an_approved_approval_that_lapsed_unused_reads_as_closed(
    db, world, admin_engine, connector, receiver
):
    single = single_hook(db, world, connector, receiver)
    view = pending(single, world)
    decide_approval(db, world["human"], view.approval_id, "APPROVE", world["clock"])
    sweep(db, world, connector, view.approval_id, admin_engine)
    drain(db, world, single)
    assert approval_state(admin_engine, view.approval_id) == "EXPIRED"
    summary = counted(db, world, view.approval_id)
    assert (summary["closed"], summary["lapsed"], summary["failed"]) == (1, 0, 0)


def test_a_message_for_an_invalidated_approval_reads_as_withdrawn(
    db, world, admin_engine, connector, receiver
):
    single = single_hook(db, world, connector, receiver)
    view = pending(single, world)
    # A policy change before the deadline: sending the request again ends its approval as
    # invalidated, a withdrawal nobody decided.
    activate(
        db,
        world,
        endpoint_bundle(world["identity"].tenant_id, world["account"], mapping_version="map-v1"),
    )
    again = single.execute(world["identity"], request(world).model_dump_json().encode())
    assert again.state == "STALE_AUTHORIZATION"
    drain(db, world, single)
    assert approval_state(admin_engine, view.approval_id) == "INVALIDATED"
    summary = counted(db, world, view.approval_id)
    assert (summary["withdrawn"], summary["closed"], summary["lapsed"]) == (1, 0, 0)
    assert summary["failed"] == 0


def test_the_records_row_carries_the_delivery_times_only_when_asked(
    db, world, admin_engine, connector, receiver
):
    from execbound.surfaces.sessions import issue_session, load_session

    single = single_hook(db, world, connector, receiver)
    view = pending(single, world)
    world["clock"].value += timedelta(seconds=5)
    assert drain(db, world, single)["delivered"] == 1
    session = load_session(
        db, issue_session(db, world["human"], clock=world["clock"]).token, clock=world["clock"]
    )
    [row] = records(single, session, approval_id=view.approval_id, delivery=True)
    assert row["delivery_times"].last_delivered_at == world["clock"].now()
    assert row["notifications"]["delivered"] == 1
    [plain] = records(single, session, approval_id=view.approval_id)
    assert "delivery_times" not in plain
