# SPDX-License-Identifier: AGPL-3.0-only
"""Notification durability uses real PostgreSQL and a real local HTTP receiver, which since
findings delivery (#31) is one destination like any other."""

import json
from datetime import UTC, datetime, timedelta
from threading import Thread

import pytest
from sqlalchemy import text
from test_execution import provision_identity
from test_monitoring_store import FixedClock

from execbound.monitoring import store, worker
from execbound.monitoring.delivery import LocalReceiver
from execbound.monitoring.models import MonitorError, ObservationEvent
from execbound.monitoring.receiver import make_receiver

ORIGIN = "http://127.0.0.1:8000"


def deliver_local(db, admin, receiver, clock):
    """Route and drain to the loopback receiver, as `process --deliver-local` does; the count
    the drain delivered."""
    out = worker.local_outbound(receiver, admin.tenant_id, ORIGIN)
    worker.route_findings(db, admin, out.destinations, clock=clock)
    return worker.deliver_findings(db, admin, out, clock=clock)["delivered"]


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
            conn.execute(
                text("SELECT * FROM execbound.monitor_deliveries WHERE destination_id IS NOT NULL")
            )
            .mappings()
            .one()
        )


def test_receipt_then_worker_crash_recovers_same_delivery(db, pending, receiver, monkeypatch):
    admin, clock = pending
    target, output = receiver
    send = worker.post_signed

    def crash_after_receipt(*args, **kwargs):
        assert send(*args, **kwargs).delivered
        raise RuntimeError("Synthetic crash after receiver acceptance")

    out = worker.local_outbound(target, admin.tenant_id, ORIGIN)
    worker.route_findings(db, admin, out.destinations, clock=clock)
    monkeypatch.setattr(worker, "post_signed", crash_after_receipt)
    with pytest.raises(RuntimeError, match="Synthetic crash"):
        worker.deliver_findings(db, admin, out, clock=clock)
    leased = delivery(db, admin)
    # Leased for 60 s, above the worst-case send (ruling 24).
    assert (leased["state"], leased["lease_until"]) == (
        "IN_FLIGHT",
        clock.now() + timedelta(seconds=60),
    )
    assert len(list(output.glob("*.json"))) == 1
    clock.value += worker.LEASE + timedelta(seconds=1)
    monkeypatch.setattr(worker, "post_signed", send)
    assert worker.deliver_findings(db, admin, out, clock=clock)["delivered"] == 1
    row = delivery(db, admin)
    assert (row["state"], row["attempts"]) == ("DELIVERED", 2)
    assert worker.deliver_findings(db, admin, out, clock=clock)["delivered"] == 0
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
        "tenant_id",
        "created_at",
        "finding_url",
    }
    assert b"lab-user-17" not in files[0].read_bytes()


def test_worker_rechecks_admin_and_scopes_tenant(db, pending, seeded, admin_engine, monkeypatch):
    admin, clock = pending
    other = provision_identity(admin_engine, db, seeded["tenants"][1], "ADMIN", clock.now())
    target = LocalReceiver("http://127.0.0.1:8121/alerts", "k" * 32)
    out = worker.local_outbound(target, admin.tenant_id, ORIGIN)
    worker.route_findings(db, admin, out.destinations, clock=clock)
    monkeypatch.setattr(worker, "post_signed", lambda *a, **k: pytest.fail("No authorized item"))
    assert worker.deliver_findings(db, other, out, clock=clock)["delivered"] == 0
    with admin_engine.begin() as conn:
        conn.execute(
            text("UPDATE execbound.credentials SET revoked_at=:n WHERE credential_id=:c"),
            {"n": clock.now(), "c": admin.credential_id},
        )
    with pytest.raises(MonitorError):
        worker.deliver_findings(db, admin, out, clock=clock)
    assert delivery(db, admin)["attempts"] == 0
