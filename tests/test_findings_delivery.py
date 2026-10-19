# SPDX-License-Identifier: AGPL-3.0-only
"""Findings delivery (#31), on real PostgreSQL: the router, the drain and the four kinds.

A finding's intent is routed once, at drain time, to every destination whose `classes` list
`findings` and whose `rules` and `spaces` admit it; each delivery is leased, sent through its
kind and settled by its lease, at most five times, and never touches the finding. Approval
destinations stay apart (FD8). Every kind runs against a local stand-in: the loopback receiver,
the SMTP double with a CA the tests mint, and the Slack and Teams fakes.
"""

import json
import re
import secrets
import time
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta
from email.utils import format_datetime
from functools import partial
from pathlib import Path
from threading import Barrier, Event, Thread, get_ident
from types import SimpleNamespace
from typing import Any
from uuid import uuid4, uuid5

import httpx
import pytest
from chat_fakes import chat_fake
from console_api_fixtures import every_log_line
from secret_shapes import SLACK
from smtp_double import relay
from sqlalchemy import event as sa_event
from sqlalchemy import text
from test_approval_delivery import seed_row, several
from test_approval_notifications import delivered_files, pending, rows
from test_egress import Loopback, Resolver
from test_execution import provision_identity
from test_execution import registry as registry
from test_execution import world as world
from test_findings_messages import message as finding_message
from test_monitoring_store import FixedClock
from test_monitoring_worker import receiver as receiver
from test_notification_email import ADDRESS, relay_mail
from test_protected_path import connector as connector
from test_protected_path import live_provider as live_provider
from test_runtime import runtime as runtime

from execbound import egress, notifications
from execbound.execution.scheduled import ScheduledActor
from execbound.monitoring import store, worker
from execbound.monitoring.delivery import FINDING_RULES
from execbound.monitoring.models import MonitorError, ObservationEvent
from execbound.monitoring.receiver import make_receiver
from execbound.notifications import (
    BACKOFF,
    MAX_ATTEMPTS,
    Destination,
    deliver_pending,
    destination_tenants,
    settle_orphaned,
)
from execbound.runtime import Runtime
from execbound.surfaces.sessions import issue_session, load_session
from execbound.surfaces.settings_pages import tenant_overview
from execbound.surfaces.tokens import TokenKeys
from execbound.transports import DELIVERED, SendResult

APPROVAL_URL = "http://127.0.0.1/approvals"
FINDINGS = frozenset({"findings"})
BOTH = frozenset({"approvals", "findings"})
# The host a Slack destination must name; `SLACK` is the shared placeholder on it.
SLACK_HOST = "hooks.slack.com"


def announcing(db, world, connector, *destinations, mail=None):
    keys = TokenKeys("pending-v1", {"pending-v1": secrets.token_bytes(32)})
    return Runtime(
        db,
        [connector],
        clock=world["clock"],
        keys=keys,
        approval_url=APPROVAL_URL,
        notifications=list(destinations),
        mail=mail,
    )


def test_fd8_a_findings_only_destination_is_never_queued_an_approval(
    db, world, admin_engine, connector, receiver
):
    tenant = world["identity"].tenant_id
    local, _ = receiver
    both = Destination("both", tenant, local.url, local.secret, classes=BOTH)
    only = Destination("findings-only", tenant, local.url, local.secret, classes=FINDINGS)
    pending(announcing(db, world, connector, both, only), world)
    assert [row["destination_id"] for row in rows(admin_engine, tenant)] == ["both"]
    assert destination_tenants([only]) == []
    assert destination_tenants([both, only]) == [tenant]


def test_fd8_a_row_whose_destination_became_findings_only_is_never_sent(
    db, world, admin_engine, connector, receiver, monkeypatch
):
    tenant = world["identity"].tenant_id
    local, _ = receiver
    pending(
        announcing(db, world, connector, Destination("soc", tenant, local.url, local.secret)), world
    )
    # The same id after a restart that left it findings only: to the approval drain it is gone.
    moved = Destination("soc", tenant, local.url, local.secret, classes=FINDINGS)
    monkeypatch.setattr(
        notifications, "send_notification", lambda *a, **k: pytest.fail("No approval sent")
    )
    counts = deliver_pending(
        db, world["admin"], [moved], approval_url=APPROVAL_URL, clock=world["clock"]
    )
    assert counts == {"delivered": 0, "failed": 1, "closed": 0}
    [row] = rows(admin_engine, tenant)
    assert (row["state"], row["last_error"]) == ("FAILED", "DESTINATION_UNKNOWN")


def test_fd8_the_recovery_pass_settles_a_row_whose_destination_became_findings_only(
    db, world, admin_engine, connector, receiver
):
    tenant = world["identity"].tenant_id
    local, _ = receiver
    pending(
        announcing(db, world, connector, Destination("soc", tenant, local.url, local.secret)), world
    )
    with admin_engine.begin() as conn:
        conn.execute(
            text(
                "UPDATE execbound.approval_notifications "
                "SET created_at = created_at - interval '2 days' WHERE tenant_id = :t"
            ),
            {"t": tenant},
        )
    moved = Destination("soc", tenant, local.url, local.secret, classes=FINDINGS)
    assert settle_orphaned(db, ScheduledActor(tenant), [moved], clock=world["clock"]) == 1
    [row] = rows(admin_engine, tenant)
    assert (row["state"], row["last_error"]) == ("FAILED", "DESTINATION_UNKNOWN")


def test_fd8_the_approval_card_lists_approval_destinations_and_the_audit_export(runtime, world):
    tenant = world["identity"].tenant_id
    grant = issue_session(runtime.db, world["admin"], clock=runtime.clock)
    session = load_session(runtime.db, grant.token, clock=runtime.clock)
    url, key = "https://alerts.example.net/hook", "s" * 40
    fake = SimpleNamespace(
        db=runtime.db,
        clock=runtime.clock,
        catalog=runtime.catalog,
        notifications=(
            Destination("both", tenant, url, key, classes=BOTH),
            Destination("findings-only", tenant, url, key, classes=FINDINGS),
            Destination("audit", tenant, url, key, kind="security-events"),
        ),
    )
    data = tenant_overview(fake, session)
    assert [d["destination_id"] for d in data["destinations"]] == ["both", "audit"]
    assert [d["classes"] for d in data["destinations"]] == [["approvals", "findings"], []]


def test_fd12_the_approval_drain_refuses_a_name_that_resolves_to_loopback(
    db, world, admin_engine, connector, receiver, monkeypatch
):
    """The receiver listens on loopback; behind a name, the drain never reaches it, and the
    approval webhook records the attempt as any failed attempt (ruling 5). The resolver's own
    record shows the guard asked it: a real lookup of the name would fail the same way. The
    drain's client stands a recording backend in for the network, so a guard that let the
    loopback answer through would be seen connecting, rather than failing the receiver's TLS
    handshake as any unreachable receiver does."""
    tenant = world["identity"].tenant_id
    local, output = receiver
    named = local.url.replace("http://127.0.0.1", "https://receiver.example")
    runtime = announcing(db, world, connector, Destination("soc", tenant, named, local.secret))
    pending(runtime, world)
    resolver = Resolver("127.0.0.1")
    monkeypatch.setattr(egress, "RESOLVE", resolver)
    network = Loopback()
    monkeypatch.setattr(
        notifications, "guarded_client", lambda: egress.guarded_client(backend=network)
    )
    counts = deliver_pending(
        db, world["admin"], runtime.notifications, approval_url=APPROVAL_URL, clock=world["clock"]
    )
    assert counts["delivered"] == 0 and delivered_files(output) == []
    assert resolver.asked == ["receiver.example"] and network.attempts == []
    [row] = rows(admin_engine, tenant)
    assert (row["state"], row["attempts"], row["last_error"]) == (
        "PENDING",
        1,
        "RECEIVER_UNAVAILABLE",
    )


TARGET = "canary-target-0b0b"
STORY = "canary-story-7f7f"
KEY = "k" * 32
ORIGIN = "https://console.example.net"


@pytest.fixture
def raised(db, seeded, admin_engine):
    """One open `sensitive-action.v2` finding and its intent in the first seeded workspace,
    from a story whose target and story id are canaries no message may carry."""
    clock = FixedClock(datetime.now(UTC))
    admin = provision_identity(admin_engine, db, seeded["tenants"][0], "ADMIN", clock.now())
    source = store.create_source(
        db,
        admin,
        label="Canary source label",
        story_id=STORY,
        expires_at=clock.now() + timedelta(hours=1),
        clock=clock,
    )
    store.ingest(
        db,
        source.token,
        ObservationEvent(
            event_id="event-1",
            story_id=STORY,
            occurred_at=clock.now(),
            kind="tool_result",
            action="identity.disable",
            target_ref=TARGET,
            outcome="success",
        ),
        clock=clock,
    )
    assert store.evaluate_pending(db, admin, clock=clock) == 1
    return admin, clock


def finding_row(admin_engine, tenant):
    with admin_engine.connect() as conn:
        return dict(
            conn.execute(
                text(
                    "SELECT * FROM execbound.monitor_findings "
                    "WHERE tenant_id = :t AND rule_version = 'sensitive-action.v2'"
                ),
                {"t": tenant},
            )
            .mappings()
            .one()
        )


def delivery_rows(admin_engine, tenant):
    """The intent first, then each delivery by destination."""
    with admin_engine.connect() as conn:
        return [
            dict(row)
            for row in conn.execute(
                text(
                    "SELECT * FROM execbound.monitor_deliveries WHERE tenant_id = :t "
                    "ORDER BY destination_id NULLS FIRST, delivery_id"
                ),
                {"t": tenant},
            ).mappings()
        ]


def hook(tenant, url="http://127.0.0.1:9/alerts", destination_id="soc", **changes):
    """A findings webhook destination."""
    classes = changes.pop("classes", FINDINGS)
    return Destination(destination_id, tenant, url, KEY, classes=classes, **changes)


def outbound(*destinations, mail=None, tls_context=None):
    return worker.Outbound(tuple(destinations), ORIGIN, mail=mail, tls_context=tls_context)


def acknowledge(admin_engine, admin, clock):
    with admin_engine.begin() as conn:
        conn.execute(
            text(
                "UPDATE execbound.monitor_findings SET acknowledged_at = :n, acknowledged_by = :a "
                "WHERE tenant_id = :t AND acknowledged_at IS NULL"
            ),
            {"n": clock.now(), "a": admin.principal_id, "t": admin.tenant_id},
        )


def age(admin_engine, tenant, interval, *, deliveries=False):
    """Move the intent's (or the deliveries') creation back by `interval`, an SQL interval."""
    which = "IS NOT NULL" if deliveries else "IS NULL"
    with admin_engine.begin() as conn:
        conn.execute(
            text(
                "UPDATE execbound.monitor_deliveries "
                f"SET created_at = created_at - CAST(:i AS interval) "
                f"WHERE tenant_id = :t AND destination_id {which}"
            ),
            {"i": interval, "t": tenant},
        )


def test_fd1_routing_writes_one_delivery_per_admitted_destination(db, admin_engine, raised):
    admin, clock = raised
    tenant = admin.tenant_id
    found = finding_row(admin_engine, tenant)
    destinations = (
        hook(tenant, destination_id="every"),
        hook(tenant, destination_id="this-rule", rules=frozenset({"sensitive-action.v2"})),
        hook(tenant, destination_id="other-rule", rules=frozenset({"source-health.v1"})),
        hook(tenant, destination_id="this-space", spaces=frozenset({found["space_id"]})),
        hook(tenant, destination_id="other-space", spaces=frozenset({uuid4()})),
        hook(tenant, destination_id="approvals-only", classes=frozenset({"approvals"})),
        hook(uuid4(), destination_id="elsewhere"),
    )
    assert worker.route_findings(db, admin, destinations, clock=clock) == {
        "routed": 1,
        "queued": 3,
        "closed": 0,
    }
    rows = delivery_rows(admin_engine, tenant)
    assert [(row["destination_id"], row["state"]) for row in rows] == [
        (None, "ROUTED"),
        ("every", "PENDING"),
        ("this-rule", "PENDING"),
        ("this-space", "PENDING"),
    ]
    assert rows[0]["delivery_id"] == uuid5(found["finding_id"], "delivery")
    assert [row["delivery_id"] for row in rows[1:]] == [
        uuid5(found["finding_id"], f"{name}#finding")
        for name in ("every", "this-rule", "this-space")
    ]


def test_fd1_a_second_router_or_two_at_once_add_nothing(db, admin_engine, raised):
    admin, clock = raised
    tenant = admin.tenant_id
    found = finding_row(admin_engine, tenant)
    destinations = (hook(tenant),)
    # A delivery already present: the conflict clause writes nothing more. Two routers truly
    # at once are the pause test's.
    with admin_engine.begin() as conn:
        conn.execute(
            text(
                "INSERT INTO execbound.monitor_deliveries "
                "(tenant_id, delivery_id, finding_id, destination_id, created_at, next_attempt_at) "
                "VALUES (:t, :d, :f, 'soc', now(), now())"
            ),
            {"t": tenant, "d": uuid5(found["finding_id"], "soc#finding"), "f": found["finding_id"]},
        )
    gate = Barrier(2)

    def route(_):
        gate.wait(timeout=5)
        return worker.route_findings(db, admin, destinations, clock=clock)

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(route, range(2)))
    assert sorted(result["routed"] for result in results) == [0, 1]
    assert sum(result["queued"] for result in results) == 0
    assert worker.route_findings(db, admin, destinations, clock=clock) == {
        "routed": 0,
        "queued": 0,
        "closed": 0,
    }
    assert [
        (row["destination_id"], row["state"]) for row in delivery_rows(admin_engine, tenant)
    ] == [
        (None, "ROUTED"),
        ("soc", "PENDING"),
    ]


def test_fd1_a_router_passes_by_an_intent_another_router_holds(db, admin_engine, raised):
    """Two routers truly at once: while the first holds the intent, mid-transaction, a second
    runs to its end without waiting and writes nothing (`SKIP LOCKED`); the first then routes
    the intent alone. A router that waited on the lock would time out here instead."""
    admin, clock = raised
    tenant = admin.tenant_id
    destinations = (hook(tenant),)
    holding, release = Event(), Event()

    def pause(conn, cursor, statement, parameters, context, executemany):
        # The first router's first insert waits here, its lock on the intent held.
        if "INSERT INTO execbound.monitor_deliveries" in statement and not holding.is_set():
            holding.set()
            assert release.wait(timeout=10)

    sa_event.listen(db.engine, "before_cursor_execute", pause)
    try:
        with ThreadPoolExecutor(max_workers=1) as pool:
            first = pool.submit(worker.route_findings, db, admin, destinations, clock=clock)
            assert holding.wait(timeout=5)
            assert worker.route_findings(db, admin, destinations, clock=clock) == {
                "routed": 0,
                "queued": 0,
                "closed": 0,
            }
            release.set()
            assert first.result(timeout=10) == {"routed": 1, "queued": 1, "closed": 0}
    finally:
        release.set()
        sa_event.remove(db.engine, "before_cursor_execute", pause)
    assert [
        (row["destination_id"], row["state"]) for row in delivery_rows(admin_engine, tenant)
    ] == [
        (None, "ROUTED"),
        ("soc", "PENDING"),
    ]


def test_fd1_the_scheduled_pass_routes_and_authority_lost_mid_route_writes_nothing(
    db, admin_engine, raised
):
    """The router admits the scheduled pass as the jobs service runs it, and rechecks the
    actor before it commits: authority revoked while it routes rolls every row back."""
    admin, clock = raised
    tenant = admin.tenant_id

    def revoke_during_insert(conn, cursor, statement, parameters, context, executemany):
        if "INSERT INTO execbound.monitor_deliveries" in statement:
            with admin_engine.begin() as owner:
                owner.execute(
                    text(
                        "UPDATE execbound.credentials SET revoked_at = now() WHERE tenant_id = :t"
                    ),
                    {"t": tenant},
                )

    sa_event.listen(db.engine, "before_cursor_execute", revoke_during_insert)
    try:
        with pytest.raises(MonitorError) as refused:
            worker.route_findings(db, admin, (hook(tenant),), clock=clock)
        assert refused.value.code == "INVALID_ADMIN"
    finally:
        sa_event.remove(db.engine, "before_cursor_execute", revoke_during_insert)
    assert [
        (row["destination_id"], row["state"]) for row in delivery_rows(admin_engine, tenant)
    ] == [(None, "PENDING")]
    assert worker.route_findings(db, ScheduledActor(tenant), (hook(tenant),), clock=clock) == {
        "routed": 1,
        "queued": 1,
        "closed": 0,
    }


def test_fd9_no_backfill_an_intent_is_routed_once_to_the_destinations_configured_then(
    db, admin_engine, raised
):
    admin, clock = raised
    tenant = admin.tenant_id
    assert worker.route_findings(db, admin, (), clock=clock)["routed"] == 1
    assert worker.route_findings(db, admin, (hook(tenant),), clock=clock)["queued"] == 0
    assert [
        (row["destination_id"], row["state"]) for row in delivery_rows(admin_engine, tenant)
    ] == [(None, "ROUTED")]


# The intent as the earlier `--deliver-local` worker left it, which sent the intent row itself:
# in flight with its lease long lapsed, sent, or given up on.
LEFT_BY_THE_LOCAL_WORKER = {
    "IN_FLIGHT": (
        "UPDATE execbound.monitor_deliveries SET state = 'IN_FLIGHT', attempts = 1, "
        "lease_token = :token, lease_until = :now - interval '1 hour' "
        "WHERE tenant_id = :t AND destination_id IS NULL"
    ),
    "DELIVERED": (
        "UPDATE execbound.monitor_deliveries SET state = 'DELIVERED', attempts = 1, "
        "delivered_at = :now WHERE tenant_id = :t AND destination_id IS NULL"
    ),
    "FAILED": (
        "UPDATE execbound.monitor_deliveries SET state = 'FAILED', attempts = 5, "
        "last_error = 'RECEIVER_UNAVAILABLE' WHERE tenant_id = :t AND destination_id IS NULL"
    ),
}


@pytest.mark.parametrize("state", sorted(LEFT_BY_THE_LOCAL_WORKER))
def test_ruling_3_an_intent_the_local_worker_left_is_never_routed(db, admin_engine, raised, state):
    """Only a `PENDING` intent is routed (ruling 3). One the earlier `--deliver-local` worker
    left in flight, sent or gave up on was that worker's to send, so the router writes no
    delivery for it and leaves its row exactly as it was, an in-flight one whose lease lapsed
    long ago included."""
    admin, clock = raised
    tenant = admin.tenant_id
    with admin_engine.begin() as conn:
        conn.execute(
            text(LEFT_BY_THE_LOCAL_WORKER[state]),
            {"t": tenant, "now": clock.now(), "token": uuid4()},
        )
    before = delivery_rows(admin_engine, tenant)
    assert [(row["destination_id"], row["state"]) for row in before] == [(None, state)]
    assert worker.route_findings(db, admin, (hook(tenant),), clock=clock) == {
        "routed": 0,
        "queued": 0,
        "closed": 0,
    }
    assert delivery_rows(admin_engine, tenant) == before


@pytest.mark.parametrize(
    "interval,closed",
    # Exactly a day is not more than a day (decision 5), so it is still routed.
    [("23 hours 59 minutes", False), ("24 hours", False), ("24 hours 1 second", True)],
)
def test_fd9_an_intent_more_than_a_day_old_when_first_routed_is_closed_unsent(
    db, admin_engine, raised, interval, closed
):
    admin, clock = raised
    tenant = admin.tenant_id
    age(admin_engine, tenant, interval)
    counts = worker.route_findings(db, admin, (hook(tenant),), clock=clock)
    intent = delivery_rows(admin_engine, tenant)[0]
    if closed:
        assert counts == {"routed": 0, "queued": 0, "closed": 1}
        assert (intent["state"], intent["last_error"], intent["attempts"]) == (
            "FAILED",
            "TOO_OLD_TO_SEND",
            0,
        )
        assert len(delivery_rows(admin_engine, tenant)) == 1
    else:
        assert counts == {"routed": 1, "queued": 1, "closed": 0}


@pytest.mark.parametrize("old", [False, True], ids=["fresh", "old"])
def test_fd10_a_finding_acknowledged_before_routing_is_closed_unsent(db, admin_engine, raised, old):
    """A fresh intent reaches the batch's own acknowledgement check; one more than a day old is
    closed by the stale statement first, and the acknowledgement is still the reason recorded
    (ruling 1)."""
    admin, clock = raised
    tenant = admin.tenant_id
    acknowledge(admin_engine, admin, clock)
    if old:
        age(admin_engine, tenant, "2 days")
    assert worker.route_findings(db, admin, (hook(tenant),), clock=clock) == {
        "routed": 0,
        "queued": 0,
        "closed": 1,
    }
    [intent] = delivery_rows(admin_engine, tenant)
    assert (intent["state"], intent["last_error"]) == ("FAILED", "FINDING_ACKNOWLEDGED")


def test_the_router_reads_its_clock_through_the_monitoring_check(db, admin_engine, raised):
    """A clock with no zone is refused `INVALID_CLOCK`, as every monitoring operation refuses
    it, even for the scheduled pass, whose admission reads no clock; never a raw `TypeError`
    from comparing it with a time the database stored."""
    admin, clock = raised
    tenant = admin.tenant_id
    naive = FixedClock(clock.now().replace(tzinfo=None))
    with pytest.raises(MonitorError) as refused:
        worker.route_findings(db, ScheduledActor(tenant), (hook(tenant),), clock=naive)
    assert refused.value.code == "INVALID_CLOCK"
    assert [
        (row["destination_id"], row["state"]) for row in delivery_rows(admin_engine, tenant)
    ] == [(None, "PENDING")]


def test_the_router_routes_no_more_intents_than_its_limit(db, admin_engine, raised):
    admin, clock = raised
    tenant = admin.tenant_id
    another_finding(db, admin, clock)
    assert worker.route_findings(db, admin, (hook(tenant),), limit=1, clock=clock) == {
        "routed": 1,
        "queued": 1,
        "closed": 0,
    }
    intents = [row["state"] for row in delivery_rows(admin_engine, tenant)]
    assert sorted(intents[:2]) == ["PENDING", "ROUTED"] and intents[2:] == ["PENDING"]


def backlog(admin_engine, admin, clock, count):
    """`count` intents more than a day old, oldest first, each for a health finding on the
    fixture's source, every third one acknowledged; written as the owner. Returns each
    finding's id and whether it was acknowledged, in that order."""
    tenant = admin.tenant_id
    found = finding_row(admin_engine, tenant)
    made: dict[Any, bool] = {}
    with admin_engine.begin() as conn:
        for index in range(count):
            finding = uuid4()
            at = clock.now() - timedelta(days=2, seconds=count - index)
            acknowledged = index % 3 == 0
            conn.execute(
                text(
                    "INSERT INTO execbound.monitor_findings (tenant_id, finding_id, source_id, "
                    "rule_version, title, created_at, space_id, acknowledged_at, acknowledged_by) "
                    "VALUES (:t, :f, :s, 'source-health.v1', 'Backlog', :at, :space, :ack, :by)"
                ),
                {
                    "t": tenant,
                    "f": finding,
                    "s": found["source_id"],
                    "at": at,
                    "space": found["space_id"],
                    "ack": at if acknowledged else None,
                    "by": admin.principal_id if acknowledged else None,
                },
            )
            conn.execute(
                text(
                    "INSERT INTO execbound.monitor_deliveries "
                    "(tenant_id, delivery_id, finding_id, created_at, next_attempt_at) "
                    "VALUES (:t, :d, :f, :at, :at)"
                ),
                {"t": tenant, "d": uuid5(finding, "delivery"), "f": finding, "at": at},
            )
            made[finding] = acknowledged
    return made


def intents_by_finding(admin_engine, tenant):
    return {
        row["finding_id"]: row
        for row in delivery_rows(admin_engine, tenant)
        if row["destination_id"] is None
    }


def test_the_router_closes_a_stale_backlog_before_it_takes_its_batch(db, admin_engine, raised):
    """A backlog larger than a pass's batch never holds a fresh finding back until it too is a
    day old: one bounded statement closes every intent more than a day old before the batch is
    taken, `FINDING_ACKNOWLEDGED` before `TOO_OLD_TO_SEND` as the batch records them (ruling
    1), and the fresh intent is routed in the same pass."""
    admin, clock = raised
    tenant = admin.tenant_id
    fresh = finding_row(admin_engine, tenant)["finding_id"]
    stale = backlog(admin_engine, admin, clock, 60)
    assert worker.route_findings(db, admin, (hook(tenant),), clock=clock) == {
        "routed": 1,
        "queued": 1,
        "closed": 60,
    }
    intents = intents_by_finding(admin_engine, tenant)
    assert {
        finding: (
            intents[finding]["state"],
            intents[finding]["last_error"],
            intents[finding]["attempts"],
        )
        for finding in stale
    } == {
        finding: ("FAILED", "FINDING_ACKNOWLEDGED" if acknowledged else "TOO_OLD_TO_SEND", 0)
        for finding, acknowledged in stale.items()
    }
    assert intents[fresh]["state"] == "ROUTED"
    assert [
        (row["finding_id"], row["destination_id"])
        for row in delivery_rows(admin_engine, tenant)
        if row["destination_id"] is not None
    ] == [(fresh, "soc")]


def test_the_router_closes_at_most_its_stale_batch_a_pass_oldest_first(
    db, admin_engine, raised, monkeypatch
):
    """The closing statement is bounded, so a pass over any backlog stays short: at most
    `STALE_BATCH` stale intents a pass, oldest first, and then the batch as before."""
    admin, clock = raised
    tenant = admin.tenant_id
    assert worker.STALE_BATCH == 5000
    monkeypatch.setattr(worker, "STALE_BATCH", 5)
    stale = list(backlog(admin_engine, admin, clock, 30))
    # Five closed by the bounded statement, then a batch of ten, the oldest left, all stale.
    assert worker.route_findings(db, admin, (hook(tenant),), limit=10, clock=clock) == {
        "routed": 0,
        "queued": 0,
        "closed": 15,
    }
    intents = intents_by_finding(admin_engine, tenant)
    assert [intents[finding]["state"] for finding in stale] == ["FAILED"] * 15 + ["PENDING"] * 15


def test_the_router_passes_by_a_stale_intent_another_transaction_holds(db, admin_engine, raised):
    """The closing statement skips an intent another transaction holds (`SKIP LOCKED`), as the
    batch does, rather than waiting out the lock timeout and failing the pass."""
    admin, clock = raised
    tenant = admin.tenant_id
    fresh = finding_row(admin_engine, tenant)["finding_id"]
    stale = list(backlog(admin_engine, admin, clock, 3))
    with admin_engine.connect() as holder, holder.begin():
        holder.execute(
            text(
                "SELECT 1 FROM execbound.monitor_deliveries "
                "WHERE tenant_id = :t AND delivery_id = :d FOR UPDATE"
            ),
            {"t": tenant, "d": uuid5(stale[1], "delivery")},
        )
        started = time.monotonic()
        counts = worker.route_findings(db, admin, (hook(tenant),), clock=clock)
        assert time.monotonic() - started < 4
    assert counts == {"routed": 1, "queued": 1, "closed": 2}
    intents = intents_by_finding(admin_engine, tenant)
    assert [intents[finding]["state"] for finding in stale] == ["FAILED", "PENDING", "FAILED"]
    assert intents[fresh]["state"] == "ROUTED"


def test_the_router_chooses_its_stale_ids_once(admin_engine, raised):
    """The closing statement's ids are chosen once. Its plan scans the `stale` CTE, planned once,
    rather than an `IN (...)` subquery the planner may rescan for every row it joins, where each
    rescan of a `LIMIT ... FOR UPDATE SKIP LOCKED` could pick rows the last one did not.
    PostgreSQL never inlines a CTE that locks rows, so `MATERIALIZED` states what it does
    anyway; what this pins is the CTE itself."""
    admin, clock = raised
    with admin_engine.connect() as conn:
        ((plan,),) = conn.execute(
            text("EXPLAIN (FORMAT JSON) " + worker._CLOSE_STALE.text),
            {"t": admin.tenant_id, "stale": clock.now() - worker.TOO_OLD, "n": worker.STALE_BATCH},
        ).all()

    def nodes(node):
        yield node
        for child in node.get("Plans", ()):
            yield from nodes(child)

    scans = [node for node in nodes(plan[0]["Plan"]) if node["Node Type"] == "CTE Scan"]
    assert [node["CTE Name"] for node in scans] == ["stale"]


@pytest.mark.parametrize("limit", [0, 51, True, "5"])
def test_the_router_refuses_a_limit_outside_one_to_fifty(db, raised, limit):
    admin, clock = raised
    with pytest.raises(MonitorError) as refused:
        worker.route_findings(db, admin, (), limit=limit, clock=clock)
    assert refused.value.code == "INVALID_LIMIT"


HOSTILE = "<img src=x onerror=alert(1)> @here <!channel>"


def kinds(tenant, local, fake):
    """One findings destination of each kind: the loopback receiver, the relay, the fakes."""
    return (
        hook(tenant, local.url, "hook"),
        Destination("jane", tenant, "", "", kind="email", to=ADDRESS, classes=FINDINGS),
        Destination("slack", tenant, fake.slack_url, "", kind="slack", classes=FINDINGS),
        Destination("teams", tenant, fake.teams_url, "", kind="teams", classes=FINDINGS),
    )


def test_fd7_every_rule_the_database_admits_has_a_label(admin_engine):
    with admin_engine.connect() as conn:
        definition = conn.execute(
            text(
                "SELECT pg_get_constraintdef(oid) FROM pg_constraint "
                "WHERE conname = 'monitor_findings_rule_version_check'"
            )
        ).scalar_one()
    admitted = set(re.findall(r"'([a-z0-9.-]+)'", definition))
    assert len(admitted) == 17 and admitted == set(FINDING_RULES)


def test_fd2_each_kind_is_delivered_once_and_a_second_drain_sends_nothing(
    db, admin_engine, raised, receiver, tmp_path
):
    admin, clock = raised
    tenant = admin.tenant_id
    local, output = receiver
    found = finding_row(admin_engine, tenant)
    (tmp_path / "relay").mkdir()
    with chat_fake() as fake, relay(tmp_path / "relay") as mailbox:
        mail = relay_mail(mailbox.port)
        out = outbound(*kinds(tenant, local, fake), mail=mail, tls_context=mailbox.context)
        assert worker.route_findings(db, admin, out.destinations, clock=clock)["queued"] == 4
        drained = worker.deliver_findings(db, admin, out, clock=clock, sleep=lambda _: None)
        assert drained == {"delivered": 4, "failed": 0, "closed": 0}
        again = worker.deliver_findings(db, admin, out, clock=clock, sleep=lambda _: None)
        assert again == {"delivered": 0, "failed": 0, "closed": 0}
        received = sorted(kind for kind, _ in fake.received)
        [email] = mailbox.messages()
    rows = delivery_rows(admin_engine, tenant)[1:]
    assert [(row["destination_id"], row["state"], row["attempts"]) for row in rows] == [
        ("hook", "DELIVERED", 1),
        ("jane", "DELIVERED", 1),
        ("slack", "DELIVERED", 1),
        ("teams", "DELIVERED", 1),
    ]
    assert received == ["slack", "teams"]
    # The receiver stores a delivery only under a signature it verified.
    [stored] = output.glob("*.json")
    assert stored.name == f"{rows[0]['delivery_id']}.json"
    assert json.loads(stored.read_bytes()) == {
        "version": 1,
        "kind": "monitor.finding",
        "delivery_id": str(rows[0]["delivery_id"]),
        "finding_id": str(found["finding_id"]),
        "source_id": str(found["source_id"]),
        "observation_id": str(found["observation_id"]),
        "rule_version": "sensitive-action.v2",
        "profile_version": None,
        "tenant_id": str(tenant),
        # To the second, as the pinned body writes it (`finding_body`).
        "created_at": found["created_at"].astimezone(UTC).isoformat(timespec="seconds"),
        "finding_url": f"{ORIGIN}/monitor?view=findings&state=all&open={found['finding_id']}",
    }
    assert email["X-ExecBound-Finding"] == str(found["finding_id"])
    assert email["Message-ID"].startswith(f"<{rows[1]['delivery_id']}@")


def test_fd2_email_goes_through_the_relay_and_never_through_the_http_guard(
    db, admin_engine, raised, tmp_path, monkeypatch
):
    """Email goes to the operator's relay by the mail path, verified with the relay's TLS
    context; only the webhook and chat kinds go through the egress guard. The guard's client
    is built with nothing of the relay's, and an email-only drain sends it no request."""
    admin, clock = raised
    tenant = admin.tenant_id
    built: list[dict[str, Any]] = []
    requested: list[httpx.Request] = []

    def recording(**kwargs: Any) -> httpx.Client:
        built.append(kwargs)
        return httpx.Client(
            transport=httpx.MockTransport(
                lambda request: requested.append(request) or httpx.Response(500)
            )
        )

    monkeypatch.setattr(worker, "guarded_client", recording)
    (tmp_path / "relay").mkdir()
    with relay(tmp_path / "relay") as mailbox:
        out = outbound(
            Destination("jane", tenant, "", "", kind="email", to=ADDRESS, classes=FINDINGS),
            mail=relay_mail(mailbox.port),
            tls_context=mailbox.context,
        )
        worker.route_findings(db, admin, out.destinations, clock=clock)
        # The relay's certificate is signed by the CA the test minted: only its context
        # verifies it, so a delivery proves the context reached the mail path.
        assert worker.deliver_findings(db, admin, out, clock=clock)["delivered"] == 1
        [email] = mailbox.messages()
    assert email["X-ExecBound-Finding"] == str(finding_row(admin_engine, tenant)["finding_id"])
    assert requested == []
    assert built and not any(
        value is mailbox.context for kwargs in built for value in kwargs.values()
    )


def test_fd2_an_email_destination_with_no_relay_is_refused_before_anything_is_leased(
    db, admin_engine, raised
):
    """A caller's mistake, refused up front whether or not a delivery is due, and never
    rewritten as a message that could not be rendered."""
    admin, clock = raised
    tenant = admin.tenant_id
    jane = Destination("jane", tenant, "", "", kind="email", to=ADDRESS, classes=FINDINGS)
    out = outbound(jane)
    for routed in (False, True):
        if routed:
            worker.route_findings(db, admin, out.destinations, clock=clock)
        with pytest.raises(MonitorError) as refused:
            worker.deliver_findings(db, admin, out, clock=clock)
        assert refused.value.code == "INVALID_CONFIGURATION"
    [row] = delivery_rows(admin_engine, tenant)[1:]
    assert (row["state"], row["attempts"]) == ("PENDING", 0)
    # The renderer's own check: a `MonitorError` is a `ValueError`, and keeps its code.
    with pytest.raises(MonitorError) as refused:
        worker._render(jane, finding_message(tenant_id=tenant), out)
    assert refused.value.code == "INVALID_CONFIGURATION"


def test_the_drain_reads_its_clock_through_the_monitoring_check(db, admin_engine, raised):
    """A clock with no zone is refused `INVALID_CLOCK` before anything is leased, as every
    monitoring operation refuses it, even for the scheduled pass, whose admission reads no
    clock: the database would otherwise read the time in its own session's zone."""
    admin, clock = raised
    tenant = admin.tenant_id
    out = outbound(hook(tenant))
    worker.route_findings(db, admin, out.destinations, clock=clock)
    naive = FixedClock(clock.now().replace(tzinfo=None))
    with pytest.raises(MonitorError) as refused:
        worker.deliver_findings(db, ScheduledActor(tenant), out, clock=naive)
    assert refused.value.code == "INVALID_CLOCK"
    [row] = delivery_rows(admin_engine, tenant)[1:]
    assert (row["state"], row["attempts"]) == ("PENDING", 0)


def test_fd3_a_500_then_a_200_is_two_attempts_on_the_backoff(db, admin_engine, raised):
    admin, clock = raised
    tenant = admin.tenant_id
    with chat_fake() as fake:
        out = outbound(
            Destination("slack", tenant, fake.slack_url, "", kind="slack", classes=FINDINGS)
        )
        worker.route_findings(db, admin, out.destinations, clock=clock)
        fake.answer(500)
        assert worker.deliver_findings(db, admin, out, clock=clock)["delivered"] == 0
        [row] = delivery_rows(admin_engine, tenant)[1:]
        assert (row["state"], row["attempts"], row["last_error"]) == (
            "PENDING",
            1,
            "RECEIVER_UNAVAILABLE",
        )
        assert row["next_attempt_at"] == clock.now() + timedelta(seconds=5)
        assert worker.deliver_findings(db, admin, out, clock=clock)["delivered"] == 0
        clock.value = row["next_attempt_at"]
        assert worker.deliver_findings(db, admin, out, clock=clock)["delivered"] == 1
        assert len(fake.received) == 2


def test_fd3_a_429_waits_its_retry_after_and_counts_as_an_attempt(db, admin_engine, raised):
    admin, clock = raised
    tenant = admin.tenant_id
    with chat_fake() as fake:
        out = outbound(
            Destination("teams", tenant, fake.teams_url, "", kind="teams", classes=FINDINGS)
        )
        worker.route_findings(db, admin, out.destinations, clock=clock)
        fake.answer(429, **{"Retry-After": "40"})
        worker.deliver_findings(db, admin, out, clock=clock)
    [row] = delivery_rows(admin_engine, tenant)[1:]
    assert (row["state"], row["attempts"], row["last_error"]) == (
        "PENDING",
        1,
        "RECEIVER_RATE_LIMITED",
    )
    assert row["next_attempt_at"] == clock.now() + timedelta(seconds=40)


def dated_retry(clock):
    """A `Retry-After` date forty-five seconds after the drain's moment, in the whole seconds an
    HTTP-date has, with the drain ten minutes ahead of the host: read against the host's clock,
    the wait would be over ten minutes, and a date that could not be read waits thirty."""
    clock.value += timedelta(minutes=10)
    answered = clock.now()
    date = (answered + timedelta(seconds=45)).replace(microsecond=0)
    return answered, format_datetime(date, usegmt=True)


def test_fd3_a_429_with_an_http_date_waits_until_that_date_on_the_drains_clock(
    db, admin_engine, raised
):
    admin, clock = raised
    tenant = admin.tenant_id
    with chat_fake() as fake:
        out = outbound(
            Destination("teams", tenant, fake.teams_url, "", kind="teams", classes=FINDINGS)
        )
        worker.route_findings(db, admin, out.destinations, clock=clock)
        answered, date = dated_retry(clock)
        fake.answer(429, **{"Retry-After": date})
        worker.deliver_findings(db, admin, out, clock=clock)
    [row] = delivery_rows(admin_engine, tenant)[1:]
    assert (row["state"], row["attempts"], row["last_error"]) == (
        "PENDING",
        1,
        "RECEIVER_RATE_LIMITED",
    )
    assert row["next_attempt_at"] == answered + timedelta(seconds=45)


def test_fd3_a_signed_429_with_an_http_date_waits_until_that_date_on_the_drains_clock(
    db, admin_engine, raised, monkeypatch
):
    """The webhook kind's sender is the real one, answered by a stand-in receiver: the drain
    hands it the drain's clock as it hands the chat sender."""
    admin, clock = raised
    tenant = admin.tenant_id
    real = worker.post_signed
    out = outbound(hook(tenant))
    worker.route_findings(db, admin, out.destinations, clock=clock)
    answered, date = dated_retry(clock)

    def limited(request: httpx.Request) -> httpx.Response:
        return httpx.Response(429, headers={"Retry-After": date})

    def send(destination, delivery_id, body, client, **kwargs):
        with httpx.Client(transport=httpx.MockTransport(limited)) as receiver:
            return real(destination, delivery_id, body, receiver, **kwargs)

    monkeypatch.setattr(worker, "post_signed", send)
    worker.deliver_findings(db, admin, out, clock=clock)
    [row] = delivery_rows(admin_engine, tenant)[1:]
    assert (row["state"], row["last_error"]) == ("PENDING", "RECEIVER_RATE_LIMITED")
    assert row["next_attempt_at"] == answered + timedelta(seconds=45)


def test_fd4_five_failures_end_failed_with_the_transports_code_and_leave_the_finding(
    db, admin_engine, raised, monkeypatch
):
    admin, clock = raised
    tenant = admin.tenant_id
    before = finding_row(admin_engine, tenant)
    calls = []

    def refuse(destination, delivery_id, body, client, **kwargs):
        calls.append(delivery_id)
        return SendResult(False, "RECEIVER_REFUSED")

    monkeypatch.setattr(worker, "post_signed", refuse)
    out = outbound(hook(tenant))
    worker.route_findings(db, admin, out.destinations, clock=clock)
    # Four waits between five attempts: the backoff's last entry is never reached.
    for attempt, delay in enumerate((5, 25, 125, 625, None), start=1):
        worker.deliver_findings(db, admin, out, clock=clock)
        [row] = delivery_rows(admin_engine, tenant)[1:]
        assert (row["attempts"], row["last_error"]) == (attempt, "RECEIVER_REFUSED")
        assert row["state"] == ("FAILED" if attempt == 5 else "PENDING")
        if delay is not None:
            assert row["next_attempt_at"] == clock.now() + timedelta(seconds=delay)
            clock.value = row["next_attempt_at"]
    failed = row
    # A drain a day later leases nothing: no sixth send, and the failed row stays as it is. It
    # runs as the scheduled pass, because a day outlasts the administrator's credential.
    clock.value = clock.now() + timedelta(days=1)
    drained = worker.deliver_findings(db, ScheduledActor(tenant), out, clock=clock)
    assert len(calls) == 5 and len(set(calls)) == 1
    assert drained == {"delivered": 0, "failed": 0, "closed": 0}
    assert delivery_rows(admin_engine, tenant)[1:] == [failed]
    assert finding_row(admin_engine, tenant) == before


DOCS = Path(__file__).resolve().parents[1] / "docs"
# The pages that give the delivery retries' waits: both drains', and the threat model's and the
# acceptance inventory's rows for them.
RETRY_PAGES = (
    "NOTIFICATIONS.md",
    "OPERATIONS.md",
    "TINES_MONITORING.md",
    "THREAT_MODEL.md",
    "ACCEPTANCE_TESTS.md",
)


@pytest.mark.docs
def test_the_pages_give_the_four_waits_five_attempts_have():
    """Five attempts have four waits, `BACKOFF[:MAX_ATTEMPTS - 1]`, and both drains take them
    from the one table. Its last value is looked up at a fifth attempt and thrown away, since
    nothing follows a fifth, so no page gives it; the approval drain's pages give the four waits
    the findings drain's do."""
    waits = BACKOFF[: MAX_ATTEMPTS - 1]
    assert waits == (5, 25, 125, 625)
    spoken = f"{', '.join(map(str, waits[:-1]))} and {waits[-1]} seconds apart"
    # The rule both drains' `BACKOFF[min(attempts, MAX_ATTEMPTS) - 1]` relies on.
    assert len(BACKOFF) == MAX_ATTEMPTS
    unused = re.compile(r"\b3,?125\b")
    for page in RETRY_PAGES:
        assert unused.search((DOCS / page).read_text(encoding="utf-8")) is None, page
    notifications = (DOCS / "NOTIFICATIONS.md").read_text(encoding="utf-8")
    [retries] = [line for line in notifications.splitlines() if "after five attempts" in line]
    assert spoken in retries
    operations = (DOCS / "OPERATIONS.md").read_text(encoding="utf-8")
    [approvals] = [
        line for line in operations.splitlines() if line.startswith("When admission creates")
    ]
    assert spoken in approvals
    [findings] = [line for line in operations.splitlines() if line.startswith("**Sending.**")]
    assert spoken in findings


def test_fd4_a_fifth_expired_lease_is_uncertain_with_no_sixth_send(
    db, admin_engine, raised, monkeypatch
):
    admin, clock = raised
    tenant = admin.tenant_id
    out = outbound(hook(tenant))
    worker.route_findings(db, admin, out.destinations, clock=clock)
    with admin_engine.begin() as conn:
        conn.execute(
            text(
                "UPDATE execbound.monitor_deliveries SET state = 'IN_FLIGHT', attempts = 5, "
                "lease_until = :n, lease_token = gen_random_uuid() "
                "WHERE tenant_id = :t AND destination_id IS NOT NULL"
            ),
            {"n": clock.now(), "t": tenant},
        )
    monkeypatch.setattr(worker, "post_signed", lambda *a, **k: pytest.fail("No sixth send"))
    assert worker.deliver_findings(db, admin, out, clock=clock) == {
        "delivered": 0,
        "failed": 1,
        "closed": 0,
    }
    [row] = delivery_rows(admin_engine, tenant)[1:]
    assert (row["state"], row["last_error"]) == ("FAILED", "DELIVERY_UNCERTAIN")


def test_fd5_no_string_a_source_reported_reaches_any_body(
    db, admin_engine, raised, receiver, tmp_path
):
    admin, clock = raised
    tenant = admin.tenant_id
    found = finding_row(admin_engine, tenant)
    with admin_engine.begin() as conn:
        conn.execute(
            text("UPDATE execbound.tenants SET name = :n WHERE tenant_id = :t"),
            {"n": HOSTILE, "t": tenant},
        )
        conn.execute(
            text("UPDATE execbound.spaces SET name = :n WHERE tenant_id = :t AND space_id = :s"),
            {"n": HOSTILE, "t": tenant, "s": found["space_id"]},
        )
    local, output = receiver
    (tmp_path / "relay").mkdir()
    with chat_fake() as fake, relay(tmp_path / "relay") as mailbox:
        out = outbound(
            *kinds(tenant, local, fake), mail=relay_mail(mailbox.port), tls_context=mailbox.context
        )
        worker.route_findings(db, admin, out.destinations, clock=clock)
        assert (
            worker.deliver_findings(db, admin, out, clock=clock, sleep=lambda _: None)["delivered"]
            == 4
        )
        bodies = [stored.read_text() for stored in output.glob("*.json")]
        bodies += [json.dumps(body) for _, body in fake.received]
        bodies += [message.get_content() for message in mailbox.messages()]
        bodies += [str(message["Subject"]) for message in mailbox.messages()]
    for body in bodies:
        for canary in (TARGET, STORY, "identity.disable", "Canary source label", found["title"]):
            assert canary not in body
        assert "<" not in body and "@here" not in body
        assert len(body.encode()) <= 4096


def test_fd6_concurrent_drains_send_each_delivery_once(
    db, admin_engine, raised, receiver, monkeypatch
):
    admin, clock = raised
    local, output = receiver
    out = outbound(hook(admin.tenant_id, local.url))
    worker.route_findings(db, admin, out.destinations, clock=clock)
    entered, release = Event(), Event()
    send = worker.post_signed

    def wait_then_send(*args, **kwargs):
        entered.set()
        assert release.wait(10)
        return send(*args, **kwargs)

    monkeypatch.setattr(worker, "post_signed", wait_then_send)
    with ThreadPoolExecutor(max_workers=2) as pool:
        first = pool.submit(worker.deliver_findings, db, admin, out, clock=clock)
        try:
            assert entered.wait(10)
            assert worker.deliver_findings(db, admin, out, clock=clock)["delivered"] == 0
        finally:
            release.set()
        assert first.result(timeout=10)["delivered"] == 1
    assert len(list(output.glob("*.json"))) == 1
    assert delivery_rows(admin_engine, admin.tenant_id)[1]["attempts"] == 1


def test_fd6_a_settle_after_its_lease_expired_changes_nothing(
    db, admin_engine, raised, monkeypatch
):
    """A drain whose send outlived its lease settles nothing: the row was leased again and
    delivered meanwhile, and only the lease's own token settles it."""
    admin, clock = raised
    out = outbound(hook(admin.tenant_id))
    worker.route_findings(db, admin, out.destinations, clock=clock)
    entered, release = Event(), Event()
    answers = iter([SendResult(False, "RECEIVER_UNAVAILABLE"), DELIVERED])

    def send(*args, **kwargs):
        result = next(answers)
        if not result.delivered:
            entered.set()
            assert release.wait(10)
        return result

    monkeypatch.setattr(worker, "post_signed", send)
    late = FixedClock(clock.now() + worker.LEASE + timedelta(seconds=1))
    with every_log_line() as logged, ThreadPoolExecutor(max_workers=1) as pool:
        first = pool.submit(worker.deliver_findings, db, admin, out, clock=clock)
        try:
            assert entered.wait(10)
            # The lease expired: another drain takes the row and delivers it.
            assert worker.deliver_findings(db, admin, out, clock=late)["delivered"] == 1
        finally:
            release.set()
        assert first.result(timeout=10)["delivered"] == 0
    [row] = delivery_rows(admin_engine, admin.tenant_id)[1:]
    assert (row["state"], row["attempts"], row["last_error"]) == ("DELIVERED", 2, None)
    # The settle that wrote nothing logs nothing: no line says the row was left pending.
    assert logged.holds("monitor.delivered", "DELIVERED")
    assert not logged.holds("monitor.delivered", "PENDING")


def test_fd6_a_late_settle_never_writes_over_the_lease_that_replaced_it(
    db, admin_engine, raised, monkeypatch
):
    """Only the lease's own token settles a row. The first drain's lease expires mid-send and a
    second drain leases the row again; while the second is still sending, the first settles
    and writes nothing, and the second's settle stands. The row's state alone cannot tell the
    two leases apart, since both are `IN_FLIGHT`."""
    admin, clock = raised
    out = outbound(hook(admin.tenant_id))
    worker.route_findings(db, admin, out.destinations, clock=clock)
    first_in, first_go, second_in, second_go = Event(), Event(), Event(), Event()
    sends = iter(
        [
            (first_in, first_go, SendResult(False, "RECEIVER_UNAVAILABLE")),
            (second_in, second_go, DELIVERED),
        ]
    )

    def send(*args, **kwargs):
        entered, go, result = next(sends)
        entered.set()
        assert go.wait(10)
        return result

    monkeypatch.setattr(worker, "post_signed", send)
    late = FixedClock(clock.now() + worker.LEASE + timedelta(seconds=1))
    with ThreadPoolExecutor(max_workers=2) as pool:
        first = pool.submit(worker.deliver_findings, db, admin, out, clock=clock)
        try:
            assert first_in.wait(10)
            second = pool.submit(worker.deliver_findings, db, admin, out, clock=late)
            assert second_in.wait(10)
            first_go.set()
            assert first.result(timeout=10)["delivered"] == 0
            # The second drain's lease is untouched: still in flight, on its own attempt.
            [row] = delivery_rows(admin_engine, admin.tenant_id)[1:]
            assert (row["state"], row["attempts"], row["last_error"]) == ("IN_FLIGHT", 2, None)
        finally:
            first_go.set()
            second_go.set()
        assert second.result(timeout=10)["delivered"] == 1
    [row] = delivery_rows(admin_engine, admin.tenant_id)[1:]
    assert (row["state"], row["attempts"], row["last_error"]) == ("DELIVERED", 2, None)


def test_fd9_a_delivery_whose_destination_is_gone_or_lost_its_class_is_closed_unsent(
    db, admin_engine, raised, monkeypatch
):
    admin, clock = raised
    tenant = admin.tenant_id
    first = outbound(hook(tenant, destination_id="gone"), hook(tenant, destination_id="moved"))
    worker.route_findings(db, admin, first.destinations, clock=clock)
    monkeypatch.setattr(worker, "post_signed", lambda *a, **k: pytest.fail("Nothing is sent"))
    later = outbound(hook(tenant, destination_id="moved", classes=frozenset({"approvals"})))
    assert worker.deliver_findings(db, admin, later, clock=clock) == {
        "delivered": 0,
        "failed": 0,
        "closed": 2,
    }
    assert [
        (row["destination_id"], row["state"], row["last_error"], row["attempts"])
        for row in delivery_rows(admin_engine, tenant)[1:]
    ] == [("gone", "FAILED", "DESTINATION_UNKNOWN", 0), ("moved", "FAILED", "CLASS_OFF", 0)]


def test_fd10_a_finding_acknowledged_after_routing_is_not_sent(
    db, admin_engine, raised, monkeypatch
):
    admin, clock = raised
    out = outbound(hook(admin.tenant_id))
    worker.route_findings(db, admin, out.destinations, clock=clock)
    acknowledge(admin_engine, admin, clock)
    monkeypatch.setattr(worker, "post_signed", lambda *a, **k: pytest.fail("Nothing is sent"))
    assert worker.deliver_findings(db, admin, out, clock=clock)["closed"] == 1
    [row] = delivery_rows(admin_engine, admin.tenant_id)[1:]
    assert (row["state"], row["last_error"]) == ("FAILED", "FINDING_ACKNOWLEDGED")


def test_the_drain_logs_each_settled_attempt_with_identifiers_and_codes_alone(
    db, admin_engine, raised, receiver
):
    admin, clock = raised
    local, _ = receiver
    out = outbound(hook(admin.tenant_id, local.url))
    worker.route_findings(db, admin, out.destinations, clock=clock)
    with every_log_line() as logged:
        worker.deliver_findings(db, admin, out, clock=clock)
    found = finding_row(admin_engine, admin.tenant_id)
    assert logged.holds("monitor.delivered", str(found["finding_id"]), "DELIVERED", "soc")
    for private in (KEY, local.url, TARGET, STORY):
        assert private not in logged()


def another_finding(db, admin, clock):
    """A second `sensitive-action.v2` finding, from a second story."""
    source = store.create_source(
        db,
        admin,
        label="Second source",
        story_id="story-2",
        expires_at=clock.now() + timedelta(hours=1),
        clock=clock,
    )
    store.ingest(
        db,
        source.token,
        ObservationEvent(
            event_id="event-2",
            story_id="story-2",
            occurred_at=clock.now(),
            kind="tool_result",
            action="identity.disable",
            target_ref=TARGET,
            outcome="success",
        ),
        clock=clock,
    )
    assert store.evaluate_pending(db, admin, clock=clock) == 1


def test_fd3_a_chat_destination_gets_at_most_one_message_a_second_within_a_drain(
    db, admin_engine, raised
):
    admin, clock = raised
    another_finding(db, admin, clock)
    slept: list[float] = []
    with chat_fake() as fake:
        slack = Destination(
            "slack", admin.tenant_id, fake.slack_url, "", kind="slack", classes=FINDINGS
        )
        out = outbound(slack)
        assert worker.route_findings(db, admin, out.destinations, clock=clock)["queued"] == 2
        drained = worker.deliver_findings(
            db, admin, out, clock=clock, sleep=slept.append, monotonic=lambda: 100.0
        )
        assert drained["delivered"] == 2 and len(fake.received) == 2
    # The second message waited the whole second, on a clock that never moved.
    assert slept == [1.0]


@pytest.mark.parametrize("kind,host", [("webhook", "receiver.example"), ("slack", SLACK_HOST)])
def test_fd12_the_findings_drain_refuses_a_name_that_resolves_to_loopback(
    db, admin_engine, raised, receiver, monkeypatch, kind, host
):
    """As the approval drain's test, and the findings drain names the refusal. The receiver
    listens on loopback; behind a name, the drain never reaches it. The resolver's own record
    shows the guard asked it, and the drain's client stands a recording backend in for the
    network, so a guard that let the loopback answer through would be seen connecting. A chat
    kind goes through the same guard: a Slack destination must name Slack's own host, and the
    shared Slack-shaped placeholder does, with a stand-in resolver and network behind it."""
    admin, clock = raised
    local, output = receiver
    if kind == "webhook":
        named = local.url.replace("http://127.0.0.1", "https://receiver.example")
        destination = hook(admin.tenant_id, named)
    else:
        destination = Destination("soc", admin.tenant_id, SLACK, "", kind="slack", classes=FINDINGS)
    out = outbound(destination)
    worker.route_findings(db, admin, out.destinations, clock=clock)
    resolver = Resolver("127.0.0.1")
    monkeypatch.setattr(egress, "RESOLVE", resolver)
    network = Loopback()
    monkeypatch.setattr(worker, "guarded_client", lambda: egress.guarded_client(backend=network))
    assert worker.deliver_findings(db, admin, out, clock=clock)["delivered"] == 0
    assert resolver.asked == [host] and network.attempts == []
    assert list(output.glob("*.json")) == []
    [row] = delivery_rows(admin_engine, admin.tenant_id)[1:]
    assert (row["state"], row["attempts"], row["last_error"]) == (
        "PENDING",
        1,
        "DESTINATION_NOT_PUBLIC",
    )


def test_fd5_a_body_that_cannot_be_rendered_spends_no_attempt(
    db, admin_engine, raised, monkeypatch
):
    """Rendered under the lease (ruling 25): the refusal rolls the lease back with it."""
    admin, clock = raised
    out = outbound(hook(admin.tenant_id))
    worker.route_findings(db, admin, out.destinations, clock=clock)

    def unrenderable(message):
        raise ValueError("INVALID_NOTIFICATION")

    monkeypatch.setattr(worker, "finding_body", unrenderable)
    monkeypatch.setattr(worker, "post_signed", lambda *a, **k: pytest.fail("Nothing is sent"))
    with pytest.raises(MonitorError) as refused:
        worker.deliver_findings(db, admin, out, clock=clock)
    assert refused.value.code == "INVALID_NOTIFICATION"
    [row] = delivery_rows(admin_engine, admin.tenant_id)[1:]
    assert (row["state"], row["attempts"]) == ("PENDING", 0)


def test_alert_settings_lists_deliveries_and_unrouted_intents_but_not_a_routed_one(
    db, admin_engine, raised, receiver
):
    admin, clock = raised
    local, _ = receiver
    session = load_session(db, issue_session(db, admin, clock=clock).token, clock=clock)
    assert [
        (d["destination_id"], d["state"])
        for d in store.snapshot(db, session, clock=clock)["deliveries"]
    ] == [(None, "PENDING")]
    out = outbound(hook(admin.tenant_id, local.url))
    worker.route_findings(db, admin, out.destinations, clock=clock)
    worker.deliver_findings(db, admin, out, clock=clock)
    listed = store.snapshot(db, session, clock=clock)["deliveries"]
    assert [(d["destination_id"], d["state"]) for d in listed] == [("soc", "DELIVERED")]


def world_finding(db, world):
    """A `sensitive-action.v2` finding in the world's workspace, raised as `raised` raises one."""
    clock, admin = world["clock"], world["admin"]
    source = store.create_source(
        db,
        admin,
        label="Canary source label",
        story_id=STORY,
        expires_at=clock.now() + timedelta(hours=1),
        clock=clock,
    )
    store.ingest(
        db,
        source.token,
        ObservationEvent(
            event_id="event-1",
            story_id=STORY,
            occurred_at=clock.now(),
            kind="tool_result",
            action="identity.disable",
            target_ref=TARGET,
            outcome="success",
        ),
        clock=clock,
    )
    assert store.evaluate_pending(db, admin, clock=clock) == 1
    return admin, clock


def mailboxes(tenant, count, classes=frozenset({"approvals"})):
    return [
        Destination(
            f"jane-{n}", tenant, "", "", kind="email", to=f"jane{n}@example.com", classes=classes
        )
        for n in range(count)
    ]


def sent(admin_engine, tenant, count, *, approval_id=None, finding_id=None):
    """`count` email deliveries in the last day, to `jane-0` and on, in one outbox."""
    with admin_engine.begin() as conn:
        for n in range(count):
            if approval_id is not None:
                conn.execute(
                    text(
                        "INSERT INTO execbound.approval_notifications (tenant_id, "
                        "notification_id, approval_id, destination_id, created_at, "
                        "next_attempt_at, state, attempts, delivered_at) VALUES (:t, "
                        "gen_random_uuid(), :a, :d, now(), now(), 'DELIVERED', 1, now())"
                    ),
                    {"t": tenant, "a": approval_id, "d": f"jane-{n}"},
                )
            else:
                conn.execute(
                    text(
                        "INSERT INTO execbound.monitor_deliveries (tenant_id, delivery_id, "
                        "finding_id, destination_id, created_at, next_attempt_at, state, attempts, "
                        "delivered_at) VALUES (:t, gen_random_uuid(), :f, :d, now(), now(), "
                        "'DELIVERED', 1, now())"
                    ),
                    {"t": tenant, "f": finding_id, "d": f"jane-{n}"},
                )


def test_fd11_a_findings_email_never_spends_the_announcement_reserve(
    db, world, admin_engine, connector, receiver, tmp_path
):
    admin, clock = world_finding(db, world)
    tenant = admin.tenant_id
    local, _ = receiver
    approval = pending(
        announcing(db, world, connector, Destination("soc", tenant, local.url, local.secret)), world
    ).approval_id
    sent(admin_engine, tenant, 9, approval_id=approval)
    findings_mail = Destination(
        "soc-mail", tenant, "", "", kind="email", to=ADDRESS, classes=FINDINGS
    )
    with relay(tmp_path) as mailbox:
        mail = relay_mail(mailbox.port, daily_limit=10)
        out = outbound(findings_mail, *mailboxes(tenant, 9), mail=mail, tls_context=mailbox.context)
        worker.route_findings(db, admin, out.destinations, clock=clock)
        assert worker.deliver_findings(db, admin, out, clock=clock) == {
            "delivered": 0,
            "failed": 0,
            "closed": 0,
        }
        assert mailbox.raw == []
    [row] = [r for r in delivery_rows(admin_engine, tenant) if r["destination_id"] == "soc-mail"]
    assert (row["state"], row["attempts"], row["last_error"]) == ("PENDING", 0, "RATE_LIMITED")
    assert row["next_attempt_at"] == clock.now() + timedelta(hours=1)
    # Nine of ten leave room for one announcement: the reserve kept it.
    ids = notifications.email_destination_ids(out.destinations, tenant)
    with db.transaction(tenant) as conn:
        assert not notifications.email_capped(conn, tenant, clock.now(), mail, ids)
        assert notifications.email_capped(conn, tenant, clock.now(), mail, ids, reserve=1)


def test_fd11_findings_email_counts_toward_the_approval_cap(
    db, world, admin_engine, connector, tmp_path
):
    admin, clock = world_finding(db, world)
    tenant = admin.tenant_id
    sent(admin_engine, tenant, 10, finding_id=finding_row(admin_engine, tenant)["finding_id"])
    jane = Destination("jane", tenant, "", "", kind="email", to=ADDRESS)
    with relay(tmp_path) as mailbox:
        mail = relay_mail(mailbox.port, daily_limit=10)
        runtime = announcing(
            db, world, connector, jane, *mailboxes(tenant, 10, classes=FINDINGS), mail=mail
        )
        pending(runtime, world)
        counts = deliver_pending(
            db,
            world["admin"],
            runtime.notifications,
            approval_url=APPROVAL_URL,
            clock=world["clock"],
            mail=mail,
            tls_context=mailbox.context,
        )
        assert counts["delivered"] == 0 and mailbox.raw == []
    [row] = rows(admin_engine, tenant)
    assert (row["destination_id"], row["last_error"]) == ("jane", "RATE_LIMITED")


def test_fd11_a_capped_findings_email_fails_once_its_delivery_is_a_day_old(
    db, world, admin_engine, tmp_path
):
    admin, clock = world_finding(db, world)
    tenant = admin.tenant_id
    findings_mail = Destination(
        "soc-mail", tenant, "", "", kind="email", to=ADDRESS, classes=FINDINGS
    )
    with relay(tmp_path) as mailbox:
        # A cap of one keeps its one message for an announcement: a finding is always over.
        out = outbound(
            findings_mail, mail=relay_mail(mailbox.port, daily_limit=1), tls_context=mailbox.context
        )
        worker.route_findings(db, admin, out.destinations, clock=clock)
        age(admin_engine, tenant, "1 day", deliveries=True)
        assert worker.deliver_findings(db, admin, out, clock=clock) == {
            "delivered": 0,
            "failed": 1,
            "closed": 0,
        }
    [row] = delivery_rows(admin_engine, tenant)[1:]
    assert (row["state"], row["last_error"], row["attempts"]) == ("FAILED", "RATE_LIMITED", 0)


FINDINGS_MAIL = "soc-mail"


def findings_mailbox(tenant, destination_id=FINDINGS_MAIL):
    return Destination(destination_id, tenant, "", "", kind="email", to=ADDRESS, classes=FINDINGS)


def by_destination(admin_engine, tenant):
    return {
        row["destination_id"]: row
        for row in delivery_rows(admin_engine, tenant)
        if row["destination_id"] is not None
    }


@pytest.mark.parametrize(
    "interval,gives_up",
    # Once its delivery is a day old, counted from routing: a minute short of it still waits.
    [("23 hours 59 minutes", False), ("24 hours", True)],
)
def test_fd11_a_capped_findings_email_waits_an_hour_until_its_delivery_is_a_day_old(
    db, world, admin_engine, tmp_path, interval, gives_up
):
    admin, clock = world_finding(db, world)
    tenant = admin.tenant_id
    with relay(tmp_path) as mailbox:
        out = outbound(
            findings_mailbox(tenant),
            mail=relay_mail(mailbox.port, daily_limit=1),
            tls_context=mailbox.context,
        )
        worker.route_findings(db, admin, out.destinations, clock=clock)
        age(admin_engine, tenant, interval, deliveries=True)
        with every_log_line() as logged:
            counts = worker.deliver_findings(db, admin, out, clock=clock)
        assert mailbox.raw == []
    row = by_destination(admin_engine, tenant)[FINDINGS_MAIL]
    # Giving up is a terminal closing and writes its line; a deferral is neither and writes none.
    assert logged.holds("monitor.delivered", FINDINGS_MAIL, "RATE_LIMITED") is gives_up
    # An email given up unsent at the cap wants an operator's eye.
    assert levels(logged) == ([(FINDINGS_MAIL, "RATE_LIMITED", "WARNING")] if gives_up else [])
    if gives_up:
        assert counts == {"delivered": 0, "failed": 1, "closed": 0}
        assert (row["state"], row["last_error"], row["attempts"]) == ("FAILED", "RATE_LIMITED", 0)
    else:
        assert counts == {"delivered": 0, "failed": 0, "closed": 0}
        assert (row["state"], row["last_error"], row["attempts"]) == ("PENDING", "RATE_LIMITED", 0)
        assert row["next_attempt_at"] == clock.now() + timedelta(hours=1)
        assert (row["lease_until"], row["lease_token"]) == (None, None)


def out_of_window(admin_engine, tenant):
    """Every email delivered so far, in both outboxes, two days old: out of the cap's day."""
    with admin_engine.begin() as conn:
        for table in ("approval_notifications", "monitor_deliveries"):
            conn.execute(
                text(
                    f"UPDATE execbound.{table} "
                    "SET delivered_at = delivered_at - interval '2 days' "
                    "WHERE tenant_id = :t AND state = 'DELIVERED'"
                ),
                {"t": tenant},
            )


def test_fd11_a_deferral_spends_no_attempt_however_often_it_waits(
    db, world, admin_engine, connector, receiver, tmp_path
):
    """Over its share a findings email waits an hour, before anything is leased, as often as it
    must: more deferrals than `MAX_ATTEMPTS` still leave all five attempts, and the send once
    the cap has room is the delivery's first. The scheduled pass drains, since the hours pass
    an administrator's two-hour credential."""
    admin, clock = world_finding(db, world)
    tenant = admin.tenant_id
    local, _ = receiver
    approval = pending(
        announcing(db, world, connector, Destination("soc", tenant, local.url, local.secret)), world
    ).approval_id
    # Nine sent today in each outbox, so either alone spends the findings' share until both
    # leave the day's window.
    sent(admin_engine, tenant, 9, approval_id=approval)
    sent(admin_engine, tenant, 9, finding_id=finding_row(admin_engine, tenant)["finding_id"])
    scheduled = ScheduledActor(tenant)
    with relay(tmp_path) as mailbox:
        out = outbound(
            findings_mailbox(tenant),
            *mailboxes(tenant, 9),
            mail=relay_mail(mailbox.port, daily_limit=10),
            tls_context=mailbox.context,
        )
        worker.route_findings(db, admin, out.destinations, clock=clock)
        for _ in range(notifications.MAX_ATTEMPTS + 1):
            assert worker.deliver_findings(db, scheduled, out, clock=clock) == {
                "delivered": 0,
                "failed": 0,
                "closed": 0,
            }
            row = by_destination(admin_engine, tenant)[FINDINGS_MAIL]
            assert (row["state"], row["attempts"], row["last_error"]) == (
                "PENDING",
                0,
                "RATE_LIMITED",
            )
            assert row["next_attempt_at"] == clock.now() + timedelta(hours=1)
            clock.value = row["next_attempt_at"]
        # The day's mail leaves the window, in both outboxes, and the cap has room again.
        out_of_window(admin_engine, tenant)
        assert worker.deliver_findings(db, scheduled, out, clock=clock)["delivered"] == 1
        assert len(mailbox.raw) == 1
    row = by_destination(admin_engine, tenant)[FINDINGS_MAIL]
    assert (row["state"], row["attempts"], row["last_error"]) == ("DELIVERED", 1, None)


def test_fd11_with_no_findings_email_the_approval_cap_counts_what_it_did(
    db, world, admin_engine, connector, tmp_path
):
    """With no findings email sent, the approval drain caps exactly where it did before (#678):
    nine of ten leave room for the announcement and the tenth caps the next. Findings deliveries
    that are not email, an intent the earlier local worker delivered, and a findings email
    destination that has sent nothing add nothing to the count; counted, any of them would cap
    the first announcement."""
    admin, clock = world_finding(db, world)
    tenant = admin.tenant_id
    found = finding_row(admin_engine, tenant)
    with admin_engine.begin() as conn:
        conn.execute(
            text(
                "UPDATE execbound.monitor_deliveries SET state = 'DELIVERED', attempts = 1, "
                "delivered_at = now() WHERE tenant_id = :t AND destination_id IS NULL"
            ),
            {"t": tenant},
        )
        for n in range(5):
            conn.execute(
                text(
                    "INSERT INTO execbound.monitor_deliveries (tenant_id, delivery_id, "
                    "finding_id, destination_id, created_at, next_attempt_at, state, attempts, "
                    "delivered_at) VALUES (:t, gen_random_uuid(), :f, :d, now(), now(), "
                    "'DELIVERED', 1, now())"
                ),
                {"t": tenant, "f": found["finding_id"], "d": f"hook-{n}"},
            )
    jane = Destination("jane", tenant, "", "", kind="email", to=ADDRESS)
    hooks = [hook(tenant, destination_id=f"hook-{n}") for n in range(5)]
    with relay(tmp_path) as mailbox:
        mail = relay_mail(mailbox.port, daily_limit=10)
        runtime = announcing(db, world, connector, jane, mail=mail)
        first = pending(runtime, world)
        sent(admin_engine, tenant, 9, approval_id=first.approval_id)
        configured = [jane, *mailboxes(tenant, 9), *hooks, findings_mailbox(tenant)]

        def drain():
            return deliver_pending(
                db,
                world["admin"],
                configured,
                approval_url=APPROVAL_URL,
                clock=clock,
                mail=mail,
                tls_context=mailbox.context,
            )

        assert drain() == {"delivered": 1, "failed": 0, "closed": 0}
        with admin_engine.begin() as conn:
            conn.execute(text("UPDATE execbound.executions SET state='DENIED'"))
        second = pending(runtime, world, idempotency_key="second")
        # The default window is shorter than the hour's deferral, so the cap fails it at once.
        assert drain() == {"delivered": 0, "failed": 1, "closed": 0}
        [received] = mailbox.messages()
    assert received["X-ExecBound-Approval"] == str(first.approval_id)
    capped = [r for r in rows(admin_engine, tenant) if r["approval_id"] == second.approval_id]
    assert [(r["destination_id"], r["state"], r["last_error"]) for r in capped] == [
        ("jane", "FAILED", "RATE_LIMITED")
    ]


def held_once(real, entered, release):
    """`real`, its first call held until `release`, with `entered` set while it waits."""
    calls: list[None] = []

    def send(*args, **kwargs):
        calls.append(None)
        if len(calls) == 1:
            entered.set()
            assert release.wait(10)
        return real(*args, **kwargs)

    return send


def counted_today(db, tenant, clock, mail, destinations, *, reserve=0):
    """Whether the day's email has reached the whole cap, as an announcement reads it, or with
    `reserve`, the share a follow-up or a finding may spend."""
    ids = notifications.email_destination_ids(destinations, tenant)
    with db.transaction(tenant) as conn:
        return notifications.email_capped(conn, tenant, clock.now(), mail, ids, reserve=reserve)


def test_fd11_a_findings_drain_beside_an_announcement_in_flight_never_takes_the_last_slot(
    db, world, admin_engine, connector, tmp_path, monkeypatch
):
    """Two drains at once near the cap, on real PostgreSQL. The approval drain has leased the
    announcement that takes the cap's last slot and is mid-send; the findings drain counts nine
    delivered and that live lease, reads ten, and waits, as nine alone, its whole share, would
    already make it. The announcement lands and the day ends at the cap, not past it."""
    admin, clock = world_finding(db, world)
    tenant = admin.tenant_id
    jane = Destination("jane", tenant, "", "", kind="email", to=ADDRESS)
    entered, release = Event(), Event()
    with relay(tmp_path) as mailbox:
        mail = relay_mail(mailbox.port, daily_limit=10)
        approval = pending(announcing(db, world, connector, jane, mail=mail), world).approval_id
        sent(admin_engine, tenant, 9, approval_id=approval)
        configured = (jane, findings_mailbox(tenant), *mailboxes(tenant, 9))
        out = outbound(*configured, mail=mail, tls_context=mailbox.context)
        worker.route_findings(db, admin, out.destinations, clock=clock)
        monkeypatch.setattr(
            notifications, "send_email", held_once(notifications.send_email, entered, release)
        )
        with ThreadPoolExecutor(max_workers=1) as pool:
            announcement = pool.submit(
                deliver_pending,
                db,
                admin,
                configured,
                approval_url=APPROVAL_URL,
                clock=clock,
                mail=mail,
                tls_context=mailbox.context,
            )
            try:
                assert entered.wait(10)
                assert worker.deliver_findings(db, admin, out, clock=clock) == {
                    "delivered": 0,
                    "failed": 0,
                    "closed": 0,
                }
            finally:
                release.set()
            assert announcement.result(timeout=10)["delivered"] == 1
        [received] = mailbox.messages()
        assert counted_today(db, tenant, clock, mail, configured)
    assert received["X-ExecBound-Approval"] == str(approval)
    row = by_destination(admin_engine, tenant)[FINDINGS_MAIL]
    assert (row["state"], row["attempts"], row["last_error"]) == ("PENDING", 0, "RATE_LIMITED")


def test_fd11_an_announcement_beside_a_findings_send_in_flight_still_has_the_last_slot(
    db, world, admin_engine, connector, tmp_path, monkeypatch
):
    """The other order. The findings drain takes the last slot of its share (eight of ten sent)
    and is mid-send when the approval drain reads nine, eight delivered and the live lease: the
    announcement keeps no reserve and goes, the held send lands, and the day ends at the cap.
    The findings drain's next email, reading ten, waits."""
    admin, clock = world_finding(db, world)
    tenant = admin.tenant_id
    jane = Destination("jane", tenant, "", "", kind="email", to=ADDRESS)
    entered, release = Event(), Event()
    with relay(tmp_path) as mailbox:
        mail = relay_mail(mailbox.port, daily_limit=10)
        approval = pending(announcing(db, world, connector, jane, mail=mail), world).approval_id
        sent(admin_engine, tenant, 8, approval_id=approval)
        configured = (
            jane,
            findings_mailbox(tenant, "soc-mail-a"),
            findings_mailbox(tenant, "soc-mail-b"),
            *mailboxes(tenant, 8),
        )
        out = outbound(*configured, mail=mail, tls_context=mailbox.context)
        assert worker.route_findings(db, admin, out.destinations, clock=clock)["queued"] == 2
        monkeypatch.setattr(
            worker, "deliver_email", held_once(worker.deliver_email, entered, release)
        )
        with ThreadPoolExecutor(max_workers=1) as pool:
            findings = pool.submit(worker.deliver_findings, db, admin, out, clock=clock)
            try:
                assert entered.wait(10)
                announced = deliver_pending(
                    db,
                    admin,
                    configured,
                    approval_url=APPROVAL_URL,
                    clock=clock,
                    mail=mail,
                    tls_context=mailbox.context,
                )
                assert announced["delivered"] == 1
            finally:
                release.set()
            assert findings.result(timeout=10) == {"delivered": 1, "failed": 0, "closed": 0}
        assert len(mailbox.raw) == 2
        assert counted_today(db, tenant, clock, mail, configured)
    states = sorted(
        (row["state"], row["attempts"], row["last_error"])
        for row in by_destination(admin_engine, tenant).values()
    )
    assert states == [("DELIVERED", 1, None), ("PENDING", 0, "RATE_LIMITED")]


def test_fd11_a_leased_row_deferred_at_the_cap_is_pending_again_and_sent_an_hour_later(
    db, world, admin_engine, connector, receiver, tmp_path
):
    """A delivery whose lease lapsed mid-send is due again; at the cap it is deferred like any
    other. The deferral leaves it `PENDING` with no lease and its attempts as they were, due in
    an hour, so the pass an hour later, the cap having room, takes and sends it. A deferral that
    left it `IN_FLIGHT` with no lease would strand it for good, since only a lapsed lease is
    due."""
    admin, clock = world_finding(db, world)
    tenant = admin.tenant_id
    local, _ = receiver
    approval = pending(
        announcing(db, world, connector, Destination("soc", tenant, local.url, local.secret)), world
    ).approval_id
    sent(admin_engine, tenant, 9, approval_id=approval)
    scheduled = ScheduledActor(tenant)
    with relay(tmp_path) as mailbox:
        out = outbound(
            findings_mailbox(tenant),
            *mailboxes(tenant, 9),
            mail=relay_mail(mailbox.port, daily_limit=10),
            tls_context=mailbox.context,
        )
        worker.route_findings(db, admin, out.destinations, clock=clock)
        with admin_engine.begin() as conn:
            conn.execute(
                text(
                    "UPDATE execbound.monitor_deliveries SET state = 'IN_FLIGHT', attempts = 2, "
                    "lease_until = :n, lease_token = gen_random_uuid() "
                    "WHERE tenant_id = :t AND destination_id = :d"
                ),
                {"n": clock.now(), "t": tenant, "d": FINDINGS_MAIL},
            )
        assert worker.deliver_findings(db, scheduled, out, clock=clock) == {
            "delivered": 0,
            "failed": 0,
            "closed": 0,
        }
        row = by_destination(admin_engine, tenant)[FINDINGS_MAIL]
        assert (row["state"], row["attempts"], row["last_error"]) == (
            "PENDING",
            2,
            "RATE_LIMITED",
        )
        assert (row["lease_until"], row["lease_token"]) == (None, None)
        assert row["next_attempt_at"] == clock.now() + timedelta(hours=1)
        clock.value = row["next_attempt_at"]
        out_of_window(admin_engine, tenant)
        assert worker.deliver_findings(db, scheduled, out, clock=clock)["delivered"] == 1
        assert len(mailbox.raw) == 1
    row = by_destination(admin_engine, tenant)[FINDINGS_MAIL]
    assert (row["state"], row["attempts"], row["last_error"]) == ("DELIVERED", 3, None)


@pytest.mark.parametrize("closing", ["FINDING_ACKNOWLEDGED", "DELIVERY_UNCERTAIN"])
def test_fd11_a_delivery_closed_unsent_is_closed_at_the_cap_and_never_deferred(
    db, world, admin_engine, connector, receiver, tmp_path, closing
):
    """The cap defers only a delivery that would be sent. One that would be closed unsent,
    because its finding was acknowledged or its fifth lease lapsed, is closed with that code
    while the cap is reached, never deferred to wait for room it does not need."""
    admin, clock = world_finding(db, world)
    tenant = admin.tenant_id
    local, _ = receiver
    approval = pending(
        announcing(db, world, connector, Destination("soc", tenant, local.url, local.secret)), world
    ).approval_id
    sent(admin_engine, tenant, 9, approval_id=approval)
    with relay(tmp_path) as mailbox:
        out = outbound(
            findings_mailbox(tenant),
            *mailboxes(tenant, 9),
            mail=relay_mail(mailbox.port, daily_limit=10),
            tls_context=mailbox.context,
        )
        worker.route_findings(db, admin, out.destinations, clock=clock)
        if closing == "FINDING_ACKNOWLEDGED":
            acknowledge(admin_engine, admin, clock)
        else:
            with admin_engine.begin() as conn:
                conn.execute(
                    text(
                        "UPDATE execbound.monitor_deliveries SET state = 'IN_FLIGHT', "
                        "attempts = 5, lease_until = :n, lease_token = gen_random_uuid() "
                        "WHERE tenant_id = :t AND destination_id = :d"
                    ),
                    {"n": clock.now(), "t": tenant, "d": FINDINGS_MAIL},
                )
        counts = worker.deliver_findings(db, admin, out, clock=clock)
        assert mailbox.raw == []
    unsent = closing == "FINDING_ACKNOWLEDGED"
    assert counts == {"delivered": 0, "failed": 0 if unsent else 1, "closed": 1 if unsent else 0}
    row = by_destination(admin_engine, tenant)[FINDINGS_MAIL]
    assert (row["state"], row["last_error"]) == ("FAILED", closing)
    assert (row["lease_until"], row["lease_token"]) == (None, None)


class Gates:
    """Where the first of two drains at once is held: between its count under the workspace's
    email-cap lock and its lease (`count`, on what each drain calls after counting and before
    leasing), then in its send (`sent`). Whichever drain reaches `count` first is held; the other
    goes through, and `went_on` says it carried on past its own count."""

    def __init__(self) -> None:
        self.counted, self.lease, self.went_on = Event(), Event(), Event()
        self.sending, self.send = Event(), Event()
        self.first: int | None = None

    def count(self, real):
        def hook(*args, **kwargs):
            if self.first is None:
                self.first = get_ident()
                self.counted.set()
                assert self.lease.wait(10)
            elif get_ident() != self.first:
                self.went_on.set()
            return real(*args, **kwargs)

        return hook

    def sent(self, real):
        def hook(*args, **kwargs):
            if get_ident() == self.first:
                self.sending.set()
                assert self.send.wait(10)
            return real(*args, **kwargs)

        return hook


def gated(monkeypatch):
    """Both drains' steps between count and lease, and both sends, behind one `Gates`."""
    gates = Gates()
    monkeypatch.setattr(worker, "_render", gates.count(worker._render))
    monkeypatch.setattr(
        notifications, "approval_message", gates.count(notifications.approval_message)
    )
    monkeypatch.setattr(worker, "deliver_email", gates.sent(worker.deliver_email))
    monkeypatch.setattr(notifications, "send_email", gates.sent(notifications.send_email))
    return gates


# A drain waiting on a workspace's email-cap lock, as `pg_locks` shows it: a bigint key is split
# across `classid` (its high half) and `objid` (its low half), with `objsubid` 1.
WAITING_ON = text("""
    SELECT count(*) FROM pg_locks
     WHERE locktype = 'advisory' AND NOT granted AND objsubid = 1
       AND database = (SELECT oid FROM pg_database WHERE datname = current_database())
       AND ((classid::bigint << 32) | objid::bigint) = hashtextextended(:key, 0)
""")


def queued_behind(admin_engine, tenant, went_on):
    """Wait until a second drain waits on the workspace's email-cap lock (True) or, where nothing
    holds it back, `went_on` says it carried on past its count (False)."""
    key = notifications.EMAIL_CAP_LOCK.format(tenant=tenant)
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        if went_on.is_set():
            return False
        with admin_engine.connect() as conn:
            if conn.execute(WAITING_ON, {"key": key}).scalar_one():
                return True
        went_on.wait(0.01)
    pytest.fail("The second drain neither waited on the lock nor carried on")


def at_once(admin_engine, tenant, gates, first, second):
    """Two drains at once, on real PostgreSQL, each in its own transactions. `first` counts and
    is held before its lease until `second` waits behind the lock (or, with nothing to hold it
    back, carries on past its count); then `first` leases and its send is held until `second`
    has finished, so `second` counts while `first`'s message is in flight. Both results, and
    whether `second` waited on the lock."""
    with ThreadPoolExecutor(max_workers=2) as pool:
        one = pool.submit(first)
        try:
            assert gates.counted.wait(10)
            two = pool.submit(second)
            waited = queued_behind(admin_engine, tenant, gates.went_on)
            gates.lease.set()
            assert gates.sending.wait(10)
            other = two.result(timeout=10)
        finally:
            gates.lease.set()
            gates.send.set()
        return one.result(timeout=10), other, waited


def test_fd11_two_findings_drains_at_once_never_spend_the_reserve(
    db, world, admin_engine, connector, receiver, tmp_path, monkeypatch
):
    """Ruling 17 with two drains at once. Eight of ten are sent and two findings emails are due,
    one for each drain. The first counts eight under the workspace's email-cap lock and is held
    before its lease; the second, its own row already locked, waits behind the lock. The first
    leases and is held mid-send: the second counts eight delivered and the first's live lease,
    reads nine, which is the findings' whole share, and waits an hour. The day ends at nine, and
    the tenth stays for an announcement. Without the lock, without the live lease in the count,
    or with the count and the lease in two transactions, the second reads eight and sends."""
    admin, clock = world_finding(db, world)
    tenant = admin.tenant_id
    local, _ = receiver
    approval = pending(
        announcing(db, world, connector, Destination("soc", tenant, local.url, local.secret)), world
    ).approval_id
    sent(admin_engine, tenant, 8, approval_id=approval)
    with relay(tmp_path) as mailbox:
        mail = relay_mail(mailbox.port, daily_limit=10)
        configured = (
            findings_mailbox(tenant, "soc-mail-a"),
            findings_mailbox(tenant, "soc-mail-b"),
            *mailboxes(tenant, 8),
        )
        out = outbound(*configured, mail=mail, tls_context=mailbox.context)
        assert worker.route_findings(db, admin, out.destinations, clock=clock)["queued"] == 2
        drain = partial(worker.deliver_findings, db, admin, out, clock=clock)
        first, second, waited = at_once(admin_engine, tenant, gated(monkeypatch), drain, drain)
        assert len(mailbox.raw) == 1
        # Nine of ten: the findings' share is spent, and the reserve's one message is still
        # there for an announcement.
        assert counted_today(db, tenant, clock, mail, configured, reserve=1)
        assert not counted_today(db, tenant, clock, mail, configured)
    assert first == {"delivered": 1, "failed": 0, "closed": 0}
    assert second == {"delivered": 0, "failed": 0, "closed": 0}
    states = sorted(
        (row["state"], row["attempts"], row["last_error"])
        for row in by_destination(admin_engine, tenant).values()
    )
    assert states == [("DELIVERED", 1, None), ("PENDING", 0, "RATE_LIMITED")]
    assert waited


@pytest.mark.parametrize("findings_first", [True, False], ids=["findings-first", "close-out-first"])
def test_fd11_a_findings_drain_and_an_approval_follow_up_at_once_never_spend_the_reserve(
    db, world, admin_engine, connector, tmp_path, monkeypatch, findings_first
):
    """The same proof across the two drains: an approval follow-up keeps the reserve as a
    finding does (#678). Eight of ten are sent; a close-out and a findings email are due.
    Whichever drain counts first under the lock leases first; the other counts that live lease,
    reads nine and leaves the tenth for an announcement: the close-out is refused
    `RATE_LIMITED`, or the finding waits an hour."""
    admin, clock = world_finding(db, world)
    tenant = admin.tenant_id
    jane = Destination(
        "jane", tenant, "", "", kind="email", to=ADDRESS, messages=frozenset({"pending", "closed"})
    )
    with relay(tmp_path) as mailbox:
        mail = relay_mail(mailbox.port, daily_limit=10)
        approval = pending(announcing(db, world, connector, jane, mail=mail), world).approval_id
        # Its announcement, delivered today, is one of the eight.
        with admin_engine.begin() as conn:
            conn.execute(
                text(
                    "UPDATE execbound.approval_notifications SET state = 'DELIVERED', "
                    "attempts = 1, delivered_at = :n WHERE tenant_id = :t"
                ),
                {"n": clock.now(), "t": tenant},
            )
        sent(admin_engine, tenant, 7, approval_id=approval)
        close_out = seed_row(
            admin_engine,
            tenant,
            approval,
            "jane",
            "approval.closed",
            clock.now(),
            next_attempt_at=clock.now() - timedelta(seconds=1),
        )
        configured = (jane, findings_mailbox(tenant), *mailboxes(tenant, 7))
        out = outbound(*configured, mail=mail, tls_context=mailbox.context)
        assert worker.route_findings(db, admin, out.destinations, clock=clock)["queued"] == 1
        findings = partial(worker.deliver_findings, db, admin, out, clock=clock)
        follow_up = partial(
            deliver_pending,
            db,
            admin,
            configured,
            approval_url=APPROVAL_URL,
            clock=clock,
            mail=mail,
            tls_context=mailbox.context,
        )
        drains = (findings, follow_up) if findings_first else (follow_up, findings)
        first, second, waited = at_once(admin_engine, tenant, gated(monkeypatch), *drains)
        [received] = mailbox.messages()
        assert counted_today(db, tenant, clock, mail, configured, reserve=1)
        assert not counted_today(db, tenant, clock, mail, configured)
    finding = by_destination(admin_engine, tenant)[FINDINGS_MAIL]
    [closing] = [r for r in rows(admin_engine, tenant) if r["notification_id"] == close_out]
    if findings_first:
        assert (first, second) == (
            {"delivered": 1, "failed": 0, "closed": 0},
            {"delivered": 0, "failed": 1, "closed": 0},
        )
        assert received["X-ExecBound-Finding"] == str(finding["finding_id"])
        assert (finding["state"], finding["attempts"]) == ("DELIVERED", 1)
        assert (closing["state"], closing["attempts"], closing["last_error"]) == (
            "FAILED",
            0,
            "RATE_LIMITED",
        )
    else:
        assert (first, second) == (
            {"delivered": 1, "failed": 0, "closed": 0},
            {"delivered": 0, "failed": 0, "closed": 0},
        )
        assert received["X-ExecBound-Approval"] == str(approval)
        assert (closing["state"], closing["attempts"]) == ("DELIVERED", 1)
        assert (finding["state"], finding["attempts"], finding["last_error"]) == (
            "PENDING",
            0,
            "RATE_LIMITED",
        )
    assert waited


def test_fd11_two_announcements_at_once_never_pass_the_cap(
    db, world, admin_engine, connector, tmp_path, monkeypatch
):
    """The lock and the live lease hold the whole cap between two approval drains as well, which
    the count of delivered email alone did not: at nine of ten, two drains that each have an
    announcement no longer both send. The second counts the first's live lease, reads ten and,
    the deadline being nearer than the hour's deferral, fails `RATE_LIMITED` at once. The day
    ends at the cap, not past it."""
    tenant = world["identity"].tenant_id
    jane = Destination("jane", tenant, "", "", kind="email", to=ADDRESS)
    with relay(tmp_path) as mailbox:
        mail = relay_mail(mailbox.port, daily_limit=10)
        runtime = announcing(db, world, connector, jane, mail=mail)
        held = several(runtime, world, admin_engine, 2)
        sent(admin_engine, tenant, 9, approval_id=held[0][1].approval_id)
        configured = (jane, *mailboxes(tenant, 9))
        drain = partial(
            deliver_pending,
            db,
            world["admin"],
            configured,
            approval_url=APPROVAL_URL,
            clock=world["clock"],
            mail=mail,
            tls_context=mailbox.context,
        )
        first, second, waited = at_once(admin_engine, tenant, gated(monkeypatch), drain, drain)
        assert len(mailbox.raw) == 1
        assert counted_today(db, tenant, world["clock"], mail, configured)
    assert (first, second) == (
        {"delivered": 1, "failed": 0, "closed": 0},
        {"delivered": 0, "failed": 1, "closed": 0},
    )
    announced = sorted(
        (r["state"], r["attempts"], r["last_error"])
        for r in rows(admin_engine, tenant)
        if r["destination_id"] == "jane"
    )
    assert announced == [("DELIVERED", 1, None), ("FAILED", 0, "RATE_LIMITED")]
    assert waited


def test_fd11_a_lapsed_lease_never_counts_against_its_own_retry(
    db, world, admin_engine, connector, receiver, tmp_path
):
    """A live lease counts toward the cap, so a message in flight is counted; a lapsed one does
    not, because the delivery whose lease lapsed is the one being retried, and counting its own
    row would cap it. Eight of ten are sent and the findings email's first lease lapses at this
    moment: the retry reads eight, not nine, and sends as attempt two."""
    admin, clock = world_finding(db, world)
    tenant = admin.tenant_id
    local, _ = receiver
    approval = pending(
        announcing(db, world, connector, Destination("soc", tenant, local.url, local.secret)), world
    ).approval_id
    sent(admin_engine, tenant, 8, approval_id=approval)
    with relay(tmp_path) as mailbox:
        mail = relay_mail(mailbox.port, daily_limit=10)
        out = outbound(
            findings_mailbox(tenant), *mailboxes(tenant, 8), mail=mail, tls_context=mailbox.context
        )
        worker.route_findings(db, admin, out.destinations, clock=clock)
        with admin_engine.begin() as conn:
            conn.execute(
                text(
                    "UPDATE execbound.monitor_deliveries SET state = 'IN_FLIGHT', attempts = 1, "
                    "lease_until = :n, lease_token = gen_random_uuid() "
                    "WHERE tenant_id = :t AND destination_id = :d"
                ),
                {"n": clock.now(), "t": tenant, "d": FINDINGS_MAIL},
            )
        assert worker.deliver_findings(db, admin, out, clock=clock)["delivered"] == 1
        assert len(mailbox.raw) == 1
    row = by_destination(admin_engine, tenant)[FINDINGS_MAIL]
    assert (row["state"], row["attempts"], row["last_error"]) == ("DELIVERED", 2, None)


def test_fd11_with_no_findings_email_an_announcement_retried_after_its_lease_lapsed_is_sent(
    db, world, admin_engine, connector, tmp_path
):
    """The approval drain with no findings destination at all counts what it did before the cap
    counted leases. At nine of ten, an announcement whose first lease lapses at this moment is
    retried and sent as the tenth: its own lapsed lease is not counted, as no lease was."""
    tenant = world["identity"].tenant_id
    jane = Destination("jane", tenant, "", "", kind="email", to=ADDRESS)
    with relay(tmp_path) as mailbox:
        mail = relay_mail(mailbox.port, daily_limit=10)
        view = pending(announcing(db, world, connector, jane, mail=mail), world)
        sent(admin_engine, tenant, 9, approval_id=view.approval_id)
        with admin_engine.begin() as conn:
            conn.execute(
                text(
                    "UPDATE execbound.approval_notifications SET state = 'IN_FLIGHT', "
                    "attempts = 1, lease_until = :n, lease_token = gen_random_uuid() "
                    "WHERE tenant_id = :t AND destination_id = 'jane'"
                ),
                {"n": world["clock"].now(), "t": tenant},
            )
        counts = deliver_pending(
            db,
            world["admin"],
            (jane, *mailboxes(tenant, 9)),
            approval_url=APPROVAL_URL,
            clock=world["clock"],
            mail=mail,
            tls_context=mailbox.context,
        )
        assert counts == {"delivered": 1, "failed": 0, "closed": 0}
        [received] = mailbox.messages()
    assert received["X-ExecBound-Approval"] == str(view.approval_id)
    [row] = [r for r in rows(admin_engine, tenant) if r["destination_id"] == "jane"]
    assert (row["state"], row["attempts"], row["last_error"]) == ("DELIVERED", 2, None)


@contextmanager
def loopback_receiver(directory):
    """A second loopback receiver, storing into `directory` what is signed with `KEY`."""
    server = make_receiver(0, KEY, directory)
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}/alerts", directory
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=3)


def test_the_drain_sends_only_to_its_own_workspace_s_destination_of_a_shared_id(
    db, admin_engine, raised, receiver, seeded, tmp_path
):
    """Hosted passes every workspace's destinations in one `Outbound`, and two workspaces may
    both name a destination `soc`. The drain reads its own workspace's alone: the other's,
    listed last, where a lookup by id alone would find it, is never sent to."""
    admin, clock = raised
    local, output = receiver
    with loopback_receiver(tmp_path / "other") as (other_url, other_output):
        out = outbound(hook(admin.tenant_id, local.url), hook(seeded["tenants"][1], other_url))
        assert worker.route_findings(db, admin, out.destinations, clock=clock)["queued"] == 1
        assert worker.deliver_findings(db, admin, out, clock=clock)["delivered"] == 1
        assert list(other_output.glob("*.json")) == []
    assert len(list(output.glob("*.json"))) == 1


def test_ruling_4_a_routed_delivery_is_sent_as_its_destination_reads_at_send_time(
    db, admin_engine, raised, receiver, tmp_path
):
    """Ruling 4: a delivery routed before a restart that narrowed its destination's `rules`
    and `spaces` is still sent, and each send reads its destination as configured then, so a
    changed URL takes the next delivery to the new receiver."""
    admin, clock = raised
    tenant = admin.tenant_id
    another_finding(db, admin, clock)
    local, output = receiver
    assert worker.route_findings(db, admin, (hook(tenant, local.url),), clock=clock)["queued"] == 2
    narrowed = {"rules": frozenset({"source-health.v1"}), "spaces": frozenset({uuid4()})}
    first = outbound(hook(tenant, local.url, **narrowed))
    assert worker.deliver_findings(db, admin, first, limit=1, clock=clock)["delivered"] == 1
    with loopback_receiver(tmp_path / "moved") as (moved_url, moved_output):
        moved = outbound(hook(tenant, moved_url, **narrowed))
        assert worker.deliver_findings(db, admin, moved, clock=clock)["delivered"] == 1
        assert len(list(moved_output.glob("*.json"))) == 1
    assert len(list(output.glob("*.json"))) == 1
    assert [
        (row["destination_id"], row["state"])
        for row in delivery_rows(admin_engine, tenant)
        if row["destination_id"] is not None
    ] == [("soc", "DELIVERED"), ("soc", "DELIVERED")]


def levels(logged):
    """Each `monitor.delivered` line's code and level, as the formatter writes it."""
    written = [json.loads(line) for line in logged.written().splitlines() if line.strip()]
    return sorted(
        (line["destination_id"], line["code"], line["level"])
        for line in written
        if line["event"] == "monitor.delivered"
    )


def test_the_drain_logs_a_delivery_it_closes_uncertain_or_unsent(
    db, admin_engine, raised, monkeypatch
):
    """A delivery closed without a send is a settled outcome too, and the uncertain one is the
    line an operator most needs: a fifth lease expired unsettled, so a send may have landed.
    Each closing writes one `monitor.delivered` line with the fields a settled attempt's has.
    The uncertain one is a WARNING; a destination removed or switched off is the operator's own
    choice and an INFO line."""
    admin, clock = raised
    tenant = admin.tenant_id
    worker.route_findings(
        db,
        admin,
        (hook(tenant), hook(tenant, destination_id="gone"), hook(tenant, destination_id="moved")),
        clock=clock,
    )
    with admin_engine.begin() as conn:
        conn.execute(
            text(
                "UPDATE execbound.monitor_deliveries SET state = 'IN_FLIGHT', attempts = 5, "
                "lease_until = :n, lease_token = gen_random_uuid() "
                "WHERE tenant_id = :t AND destination_id = 'soc'"
            ),
            {"n": clock.now(), "t": tenant},
        )
    monkeypatch.setattr(worker, "post_signed", lambda *a, **k: pytest.fail("Nothing is sent"))
    found = str(finding_row(admin_engine, tenant)["finding_id"])
    # `gone` is no longer configured, and `moved` no longer lists findings.
    configured = outbound(
        hook(tenant), hook(tenant, destination_id="moved", classes=frozenset({"approvals"}))
    )
    with every_log_line() as logged:
        assert worker.deliver_findings(db, admin, configured, clock=clock) == {
            "delivered": 0,
            "failed": 1,
            "closed": 2,
        }
    assert logged.holds("monitor.delivered", found, "soc", "FAILED", "DELIVERY_UNCERTAIN")
    assert logged.holds("monitor.delivered", found, "gone", "FAILED", "DESTINATION_UNKNOWN")
    assert logged.holds("monitor.delivered", found, "moved", "FAILED", "CLASS_OFF")
    assert levels(logged) == [
        ("gone", "DESTINATION_UNKNOWN", "INFO"),
        ("moved", "CLASS_OFF", "INFO"),
        ("soc", "DELIVERY_UNCERTAIN", "WARNING"),
    ]


def test_the_drain_logs_a_delivery_closed_for_an_acknowledged_finding_at_info(
    db, admin_engine, raised, monkeypatch
):
    """A delivery closed because a person acknowledged its finding is the expected end of a
    finding someone already dealt with: one INFO line."""
    admin, clock = raised
    tenant = admin.tenant_id
    worker.route_findings(db, admin, (hook(tenant),), clock=clock)
    acknowledge(admin_engine, admin, clock)
    monkeypatch.setattr(worker, "post_signed", lambda *a, **k: pytest.fail("Nothing is sent"))
    with every_log_line() as logged:
        assert worker.deliver_findings(db, admin, outbound(hook(tenant)), clock=clock) == {
            "delivered": 0,
            "failed": 0,
            "closed": 1,
        }
    assert levels(logged) == [("soc", "FINDING_ACKNOWLEDGED", "INFO")]
