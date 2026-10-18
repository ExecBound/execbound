# SPDX-License-Identifier: AGPL-3.0-only
"""Notification durability uses real PostgreSQL and a real local HTTP receiver."""

import json
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta
from threading import Event, Thread

import pytest
from sqlalchemy import text
from test_execution import provision_identity
from test_monitoring_store import FixedClock

from execbound.monitoring import store, worker
from execbound.monitoring.delivery import LocalReceiver
from execbound.monitoring.models import MonitorError, ObservationEvent
from execbound.monitoring.receiver import make_receiver


@pytest.fixture
def pending(db, seeded, admin_engine):
    clock = FixedClock(datetime.now(UTC))
    admin = provision_identity(admin_engine, db, seeded["tenants"][0], "ADMIN", clock.now())
    source = store.create_source(
        db,
        admin,
        label="Local lab",
        story_id="story-1",
        expires_at=clock.now() + timedelta(hours=1),
        clock=clock,
    )
    event = ObservationEvent(
        event_id="event-1",
        story_id="story-1",
        occurred_at=clock.now(),
        kind="tool_result",
        action="identity.disable",
        target_ref="lab-user-17",
        outcome="success",
    )
    store.ingest(db, source.token, event, clock=clock)
    assert store.evaluate_pending(db, admin, clock=clock) == 1
    return admin, clock


@pytest.fixture
def receiver(tmp_path):
    server = make_receiver(0, "k" * 32, tmp_path)
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield LocalReceiver(f"http://127.0.0.1:{server.server_port}/alerts", "k" * 32), tmp_path
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=3)


def delivery(db, admin):
    with db.transaction(admin.tenant_id) as conn:
        return dict(
            conn.execute(text("SELECT * FROM execbound.monitor_deliveries")).mappings().one()
        )


def test_receipt_then_worker_crash_recovers_same_delivery(db, pending, receiver, monkeypatch):
    admin, clock = pending
    target, output = receiver
    send = worker.send_notification

    def crash_after_receipt(*args):
        assert send(*args)
        raise RuntimeError("Synthetic crash after receiver acceptance")

    monkeypatch.setattr(worker, "send_notification", crash_after_receipt)
    with pytest.raises(RuntimeError, match="Synthetic crash"):
        worker.deliver_pending(db, admin, target, clock=clock)
    assert delivery(db, admin)["state"] == "IN_FLIGHT"
    assert len(list(output.glob("*.json"))) == 1
    clock.value += timedelta(seconds=31)
    monkeypatch.setattr(worker, "send_notification", send)
    assert worker.deliver_pending(db, admin, target, clock=clock) == 1
    row = delivery(db, admin)
    assert (row["state"], row["attempts"]) == ("DELIVERED", 2)
    assert worker.deliver_pending(db, admin, target, clock=clock) == 0
    files = list(output.glob("*.json"))
    assert len(files) == 1
    payload = json.loads(files[0].read_bytes())
    assert payload["delivery_id"] == str(row["delivery_id"])
    assert set(payload) == {
        "version",
        "kind",
        "delivery_id",
        "profile_version",
        "finding_id",
        "source_id",
        "observation_id",
        "rule_version",
    }
    assert b"lab-user-17" not in files[0].read_bytes()


def test_worker_failure_backoff_and_terminal_bound(db, pending, monkeypatch):
    admin, clock = pending
    calls = []
    monkeypatch.setattr(worker, "send_notification", lambda *args: calls.append(args[1]) or False)
    target = LocalReceiver("http://127.0.0.1:8121/alerts", "k" * 32)
    for attempt in range(1, 6):
        assert worker.deliver_pending(db, admin, target, clock=clock) == 0
        row = delivery(db, admin)
        assert row["attempts"] == attempt
        assert row["last_error"] == "RECEIVER_UNAVAILABLE"
        assert row["state"] == ("FAILED" if attempt == 5 else "PENDING")
        assert worker.deliver_pending(db, admin, target, clock=clock) == 0
        clock.value = row["next_attempt_at"]
    assert len(calls) == 5 and len(set(calls)) == 1


def test_final_expired_lease_is_uncertain_without_another_send(db, pending, monkeypatch):
    admin, clock = pending
    with db.transaction(admin.tenant_id) as conn:
        conn.execute(
            text("""UPDATE execbound.monitor_deliveries SET state='IN_FLIGHT',
            attempts=5,lease_until=:n,lease_token=gen_random_uuid()"""),
            {"n": clock.now()},
        )
    monkeypatch.setattr(worker, "send_notification", lambda *args: pytest.fail("No sixth send"))
    assert (
        worker.deliver_pending(
            db, admin, LocalReceiver("http://127.0.0.1:8121/alerts", "k" * 32), clock=clock
        )
        == 0
    )
    assert delivery(db, admin)["last_error"] == "DELIVERY_UNCERTAIN"
    assert delivery(db, admin)["state"] == "FAILED"


def test_parallel_workers_do_not_claim_live_lease(db, pending, receiver, monkeypatch):
    admin, clock = pending
    target, output = receiver
    entered, release = Event(), Event()
    send = worker.send_notification

    def wait_then_send(*args):
        entered.set()
        assert release.wait(10)
        return send(*args)

    monkeypatch.setattr(worker, "send_notification", wait_then_send)
    with ThreadPoolExecutor(max_workers=2) as pool:
        first = pool.submit(worker.deliver_pending, db, admin, target, clock=clock)
        try:
            assert entered.wait(10)
            assert worker.deliver_pending(db, admin, target, clock=clock) == 0
        finally:
            release.set()
        assert first.result(timeout=10) == 1
    assert len(list(output.glob("*.json"))) == 1
    assert delivery(db, admin)["attempts"] == 1


def test_worker_rechecks_admin_and_scopes_tenant(db, pending, seeded, admin_engine, monkeypatch):
    admin, clock = pending
    other = provision_identity(admin_engine, db, seeded["tenants"][1], "ADMIN", clock.now())
    monkeypatch.setattr(
        worker, "send_notification", lambda *args: pytest.fail("No authorized item")
    )
    target = LocalReceiver("http://127.0.0.1:8121/alerts", "k" * 32)
    assert worker.deliver_pending(db, other, target, clock=clock) == 0
    with admin_engine.begin() as conn:
        conn.execute(
            text("UPDATE execbound.credentials SET revoked_at=:n WHERE credential_id=:c"),
            {"n": clock.now(), "c": admin.credential_id},
        )
    with pytest.raises(MonitorError):
        worker.deliver_pending(db, admin, target, clock=clock)
    assert delivery(db, admin)["attempts"] == 0
