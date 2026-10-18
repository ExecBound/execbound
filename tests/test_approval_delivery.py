# SPDX-License-Identifier: AGPL-3.0-only
"""Approval delivery (#678): the AY rows on real PostgreSQL, the clock injected.

The drain never sends, retries or defers a notification once it could not arrive with time
to act. Each approval is created at a fixed `T` under the workspace's default 120-second
deadline, so it expires at `T + 120` and the lapse margin closes delivery at `T + 105`. The
reminder tests change the deadline to 600 s on the audited path, with facts valid for most of
an hour, so a reminder falls due at `T + 300`.
"""

import json
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from datetime import timedelta
from threading import Barrier
from uuid import UUID, uuid4, uuid5

import pytest
from chat_fakes import chat_fake
from smtp_double import relay
from sqlalchemy import event as sa_event
from sqlalchemy import text
from test_approval_deadline import deadline as set_deadline
from test_approval_deadline import long_facts
from test_approval_notifications import PAYLOAD_KEYS, delivered_files, pending, rows, widen
from test_approval_notifications import destination as webhook_destination
from test_approval_quorum import activate, second_approver
from test_execution import registry as registry
from test_execution import targets
from test_execution import world as world
from test_monitoring_worker import receiver as receiver
from test_notification_chat import chat_destination
from test_notification_email import AGENT_LABEL, jane, label_agent, names, relay_mail
from test_protected_path import connector as connector
from test_protected_path import live_provider as live_provider

from execbound import notifications
from execbound.execution import decide_approval
from execbound.execution.scheduled import ScheduledActor
from execbound.notifications import LAPSE_MARGIN, Destination, deliver_pending
from execbound.runtime import Runtime
from execbound.surfaces.tokens import TokenKeys
from execbound.transports import webhook_body
from execbound_harness.demo import endpoint_bundle

pytestmark = pytest.mark.integration


def runtime_with(db, world, connector, *destinations, mail=None):
    return Runtime(
        db,
        [connector],
        clock=world["clock"],
        keys=TokenKeys("pending-v1", {"pending-v1": b"\x01" * 32}),
        approval_url="http://127.0.0.1/approvals",
        notifications=list(destinations),
        mail=mail,
    )


def drain(db, world, runtime, context=None, **kw):
    return deliver_pending(
        db,
        world["admin"],
        runtime.notifications,
        approval_url=runtime.approval_url or "",
        clock=world["clock"],
        mail=runtime.mail,
        tls_context=context,
        **kw,
    )


def expiry(admin_engine, approval_id: UUID):
    with admin_engine.begin() as conn:
        return conn.execute(
            text("SELECT expires_at FROM execbound.approvals WHERE approval_id=:a"),
            {"a": approval_id},
        ).scalar_one()


def snapshot(admin_engine, tenant: UUID):
    """The approval, the execution and the audit chain, to show a drain changed none of them."""
    with admin_engine.begin() as conn:
        return tuple(
            [tuple(r) for r in conn.execute(text(sql), {"t": tenant})]
            for sql in (
                "SELECT * FROM execbound.approvals WHERE tenant_id=:t ORDER BY approval_id",
                "SELECT * FROM execbound.executions WHERE tenant_id=:t ORDER BY execution_id",
                "SELECT * FROM execbound.audit_events WHERE tenant_id=:t ORDER BY sequence",
            )
        )


def test_the_lapse_margin_is_fifteen_seconds():
    assert LAPSE_MARGIN == timedelta(seconds=15)


def every_kind(db, world, connector, receiver, fake, port):
    return runtime_with(
        db,
        world,
        connector,
        webhook_destination(world, receiver, "hook"),
        jane(world),
        chat_destination(world, "slack", fake.slack_url),
        mail=relay_mail(port),
    )


def test_ay1_a_row_inside_the_lapse_margin_is_closed_unsent(
    db, world, admin_engine, connector, receiver, tmp_path
):
    tenant = world["identity"].tenant_id
    _, output = receiver
    with chat_fake() as fake, relay(tmp_path, "tls") as local:
        runtime = every_kind(db, world, connector, receiver, fake, local.port)
        view = pending(runtime, world)
        start = world["clock"].now()
        assert expiry(admin_engine, view.approval_id) == start + timedelta(seconds=120)
        before = snapshot(admin_engine, tenant)
        world["clock"].value = start + timedelta(seconds=106)
        assert drain(db, world, runtime, local.context) == {
            "delivered": 0,
            "failed": 0,
            "closed": 3,
        }
        assert fake.received == [] and local.raw == []
    assert delivered_files(output) == []
    assert [(r["state"], r["attempts"], r["last_error"]) for r in rows(admin_engine, tenant)] == [
        ("FAILED", 0, "LAPSED_BEFORE_DELIVERY")
    ] * 3
    assert snapshot(admin_engine, tenant) == before


def test_ay2_a_row_outside_the_margin_is_sent(
    db, world, admin_engine, connector, receiver, tmp_path
):
    tenant = world["identity"].tenant_id
    _, output = receiver
    with chat_fake() as fake, relay(tmp_path, "tls") as local:
        runtime = every_kind(db, world, connector, receiver, fake, local.port)
        pending(runtime, world)
        world["clock"].value += timedelta(seconds=104)
        assert drain(db, world, runtime, local.context) == {
            "delivered": 3,
            "failed": 0,
            "closed": 0,
        }
        assert drain(db, world, runtime, local.context)["delivered"] == 0
        assert len(fake.received) == 1 and len(local.raw) == 1
    assert len(delivered_files(output)) == 1
    assert {(r["state"], r["attempts"]) for r in rows(admin_engine, tenant)} == {("DELIVERED", 1)}


def test_ay3_a_failed_send_retries_while_the_retry_can_arrive(
    db, world, admin_engine, connector, receiver, monkeypatch
):
    tenant = world["identity"].tenant_id
    runtime = runtime_with(db, world, connector, webhook_destination(world, receiver, "hook"))
    pending(runtime, world)
    start = world["clock"].now()
    world["clock"].value = start + timedelta(seconds=60)
    monkeypatch.setattr(notifications, "send_notification", lambda *a, **k: False)
    assert drain(db, world, runtime) == {"delivered": 0, "failed": 0, "closed": 0}
    [row] = rows(admin_engine, tenant)
    assert (row["state"], row["attempts"], row["last_error"]) == (
        "PENDING",
        1,
        "RECEIVER_UNAVAILABLE",
    )
    with admin_engine.begin() as conn:
        due = conn.execute(
            text("SELECT next_attempt_at FROM execbound.approval_notifications")
        ).scalar_one()
    assert due == start + timedelta(seconds=65)


def test_ay3_no_retry_lands_past_the_deadline(db, world, admin_engine, connector):
    tenant = world["identity"].tenant_id
    with chat_fake() as fake:
        runtime = runtime_with(
            db, world, connector, chat_destination(world, "slack", fake.slack_url)
        )
        pending(runtime, world)
        start = world["clock"].now()
        world["clock"].value = start + timedelta(seconds=90)
        fake.answer(429, **{"Retry-After": "120"})
        assert drain(db, world, runtime) == {"delivered": 0, "failed": 1, "closed": 0}
        [row] = rows(admin_engine, tenant)
        assert (row["state"], row["attempts"], row["last_error"]) == (
            "FAILED",
            1,
            "RECEIVER_RATE_LIMITED",
        )
        world["clock"].value = start + timedelta(seconds=210)
        assert drain(db, world, runtime) == {"delivered": 0, "failed": 0, "closed": 0}
        assert len(fake.received) == 1
    [row] = rows(admin_engine, tenant)
    assert (row["state"], row["attempts"]) == ("FAILED", 1)


def test_ay4_the_email_cap_never_defers_past_the_deadline(
    db, world, admin_engine, connector, tmp_path
):
    tenant = world["identity"].tenant_id
    with relay(tmp_path, "tls") as local:
        runtime = runtime_with(
            db, world, connector, jane(world), mail=relay_mail(local.port, daily_limit=1)
        )
        pending(runtime, world)
        assert drain(db, world, runtime, local.context)["delivered"] == 1
        with admin_engine.begin() as conn:
            conn.execute(text("UPDATE execbound.executions SET state='DENIED'"))
        ten_minutes = pending(runtime, world, idempotency_key="second")
        widen(admin_engine, ten_minutes.approval_id, 600)
        assert drain(db, world, runtime, local.context) == {
            "delivered": 0,
            "failed": 1,
            "closed": 0,
        }
        with admin_engine.begin() as conn:
            conn.execute(text("UPDATE execbound.executions SET state='DENIED'"))
        two_hours = pending(runtime, world, idempotency_key="third")
        widen(admin_engine, two_hours.approval_id, 7200)
        assert drain(db, world, runtime, local.context) == {
            "delivered": 0,
            "failed": 0,
            "closed": 0,
        }
        assert len(local.raw) == 1
    with admin_engine.begin() as conn:
        settled = {
            r["approval_id"]: (r["state"], r["attempts"], r["last_error"], r["next_attempt_at"])
            for r in conn.execute(
                text(
                    "SELECT approval_id, state, attempts, last_error, next_attempt_at "
                    "FROM execbound.approval_notifications WHERE tenant_id=:t"
                ),
                {"t": tenant},
            ).mappings()
        }
    now = world["clock"].now()
    assert settled[ten_minutes.approval_id][:3] == ("FAILED", 0, "RATE_LIMITED")
    assert settled[two_hours.approval_id] == (
        "PENDING",
        0,
        "RATE_LIMITED",
        now + timedelta(hours=1),
    )


# What a pending message says: the drain's names, and the webhook it leaves alone.


def test_ay5_the_drained_webhook_keeps_its_bytes_and_notification_id(
    db, world, admin_engine, connector, receiver
):
    tenant = world["identity"].tenant_id
    _, output = receiver
    runtime = runtime_with(db, world, connector, webhook_destination(world, receiver, "hook"))
    view = pending(runtime, world)
    label_agent(admin_engine, world)
    assert drain(db, world, runtime)["delivered"] == 1
    [row] = rows(admin_engine, tenant)
    assert row["notification_id"] == uuid5(view.approval_id, "hook")
    [delivered] = delivered_files(output)
    assert delivered.stem == str(row["notification_id"])
    with db.transaction(tenant) as conn:
        approval = (
            conn.execute(
                text("SELECT * FROM execbound.approvals WHERE tenant_id=:t AND approval_id=:a"),
                {"t": tenant, "a": view.approval_id},
            )
            .mappings()
            .one()
        )
        named = notifications.approval_message(
            conn, tenant, dict(approval), "http://127.0.0.1/approvals", sent_at=world["clock"].now()
        )
    # The drain now reads the workspace, the space and the handle, and the body still carries
    # none of them: it is the message without them, byte for byte.
    assert None not in (named.workspace, named.space, named.requested_by, named.sent_at)
    bare = replace(named, workspace=None, space=None, requested_by=None, sent_at=None)
    assert delivered.read_bytes() == webhook_body(bare) == webhook_body(named)
    assert set(json.loads(delivered.read_bytes())) == PAYLOAD_KEYS


def test_ay6_the_drain_names_the_agent_by_handle_and_counts_a_partial_quorum(
    db, world, admin_engine, connector, tmp_path
):
    with relay(tmp_path, "tls") as local:
        runtime = runtime_with(db, world, connector, jane(world), mail=relay_mail(local.port))
        view = pending(runtime, world)
        label_agent(admin_engine, world)
        with admin_engine.begin() as conn:
            conn.execute(
                text("UPDATE execbound.approvals SET required_approvers=2 WHERE approval_id=:a"),
                {"a": view.approval_id},
            )
        decide_approval(db, world["human"], view.approval_id, "APPROVE", world["clock"])
        assert drain(db, world, runtime, local.context)["delivered"] == 1
        [received] = local.messages()
    body = received.get_content().replace("\r\n", "\n")
    _, _, handle = names(admin_engine, world, view.execution_id)
    assert f"Requested by: {handle}\nApprovals recorded: 1 of 2\n" in body
    for shown in (str(received["Subject"]), body):
        assert AGENT_LABEL not in shown and "script" not in shown


# Kinds, choices and close-outs.


def hook(world, receiver, destination_id, *messages):
    """A loopback webhook destination that lists `messages` (the default when none given)."""
    found = webhook_destination(world, receiver, destination_id)
    return replace(found, messages=frozenset(messages)) if messages else found


def notification_rows(admin_engine, tenant):
    with admin_engine.begin() as conn:
        return [
            dict(row)
            for row in conn.execute(
                text(
                    "SELECT notification_id, approval_id, destination_id, kind, outcome, "
                    "closed_at, state, attempts, last_error, next_attempt_at, delivered_at "
                    "FROM execbound.approval_notifications WHERE tenant_id=:t "
                    "ORDER BY destination_id, kind, approval_id"
                ),
                {"t": tenant},
            ).mappings()
        ]


SUFFIX = {"approval.pending": "", "approval.reminder": "#reminder", "approval.closed": "#closed"}


def seed_row(admin_engine, tenant, approval_id, destination_id, kind, now, **columns):
    """A notification row written as the owner, as the drain's enqueue would write it."""
    values = {
        "t": tenant,
        "n": uuid5(approval_id, destination_id + SUFFIX[kind]),
        "a": approval_id,
        "d": destination_id,
        "k": kind,
        "o": columns.pop("outcome", "APPROVED" if kind == "approval.closed" else None),
        "c": columns.pop("closed_at", now if kind == "approval.closed" else None),
        "s": columns.pop("state", "PENDING"),
        "now": columns.pop("next_attempt_at", now),
        "created": columns.pop("created_at", now),
        "delivered": columns.pop("delivered_at", None),
    }
    assert not columns
    with admin_engine.begin() as conn:
        conn.execute(
            text(
                "INSERT INTO execbound.approval_notifications (tenant_id, notification_id, "
                "approval_id, destination_id, kind, outcome, closed_at, state, created_at, "
                "next_attempt_at, delivered_at) "
                "VALUES (:t, :n, :a, :d, :k, :o, :c, :s, :created, :now, :delivered)"
            ),
            values,
        )
    return values["n"]


def several(runtime, world, admin_engine, count):
    """`count` held requests on their own production targets, each with its approval."""
    views = []
    for held in targets(admin_engine, world, count, production=True):
        view = runtime.execute(world["identity"], held.model_dump_json().encode())
        assert view.state == "PENDING_APPROVAL"
        views.append((held, view))
    return views


def test_ay16_admission_queues_announcements_only_where_a_destination_lists_them(
    db, world, admin_engine, connector, receiver
):
    tenant = world["identity"].tenant_id
    runtime = runtime_with(
        db,
        world,
        connector,
        hook(world, receiver, "plain"),
        hook(world, receiver, "escalate", "reminder"),
        hook(world, receiver, "outcomes", "pending", "closed"),
    )
    view = pending(runtime, world)
    assert [
        (r["destination_id"], r["kind"], r["notification_id"])
        for r in notification_rows(admin_engine, tenant)
    ] == [
        ("outcomes", "approval.pending", uuid5(view.approval_id, "outcomes")),
        ("plain", "approval.pending", uuid5(view.approval_id, "plain")),
    ]
    # Two admissions racing over the same approval's destinations queue one row each, under
    # the four-column key.
    barrier = Barrier(2)

    def queue(_):
        with db.transaction(tenant) as conn:
            barrier.wait(timeout=10)
            return notifications.queue_notifications(
                conn,
                tenant,
                view.approval_id,
                uuid4(),
                "endpoint.isolate",
                world["clock"].now(),
                runtime.notifications,
            )

    with ThreadPoolExecutor(max_workers=2) as pool:
        assert list(pool.map(queue, range(2))) == [2, 2]
    assert len(notification_rows(admin_engine, tenant)) == 2


def test_ay16_an_announcement_whose_message_was_switched_off_is_never_sent(
    db, world, admin_engine, connector, receiver
):
    tenant = world["identity"].tenant_id
    _, output = receiver
    before = runtime_with(db, world, connector, hook(world, receiver, "hook"))
    pending(before, world)
    # The operator restarted with this destination as an escalation one: the row queued under
    # the old configuration is settled, unsent.
    after = runtime_with(db, world, connector, hook(world, receiver, "hook", "reminder"))
    assert drain(db, world, after) == {"delivered": 0, "failed": 1, "closed": 0}
    [row] = notification_rows(admin_engine, tenant)
    assert (row["state"], row["attempts"], row["last_error"]) == ("FAILED", 0, "MESSAGE_OFF")
    assert delivered_files(output) == []


def test_ay16_the_summary_counts_announcements_and_lapses_apart(
    db, world, admin_engine, connector, receiver
):
    tenant = world["identity"].tenant_id
    runtime = runtime_with(
        db,
        world,
        connector,
        hook(world, receiver, "first", "pending", "closed"),
        hook(world, receiver, "second"),
        hook(world, receiver, "third"),
    )
    view = pending(runtime, world)
    now = world["clock"].now()
    with db.transaction(tenant) as conn:
        assert notifications.summary(conn, tenant, view.approval_id) == {
            "delivered": 0,
            "pending": 3,
            "failed": 0,
            "lapsed": 0,
            "closed": 0,
            "withdrawn": 0,
        }
        assert notifications.delivery_times(
            conn, tenant, view.approval_id
        ) == notifications.DeliveryTimes(now, None)
    with admin_engine.begin() as conn:
        conn.execute(
            text(
                "UPDATE execbound.approval_notifications SET state='DELIVERED', delivered_at=:d "
                "WHERE destination_id='first'"
            ),
            {"d": now + timedelta(seconds=9)},
        )
        conn.execute(
            text(
                "UPDATE execbound.approval_notifications "
                "SET state='FAILED', last_error='LAPSED_BEFORE_DELIVERY' "
                "WHERE destination_id='second'"
            )
        )
        conn.execute(
            text(
                "UPDATE execbound.approval_notifications "
                "SET state='FAILED', last_error='RECEIVER_UNAVAILABLE' "
                "WHERE destination_id='third'"
            )
        )
    seed_row(
        admin_engine,
        tenant,
        view.approval_id,
        "first",
        "approval.closed",
        now,
        state="DELIVERED",
        delivered_at=now + timedelta(seconds=99),
    )
    seed_row(admin_engine, tenant, view.approval_id, "first", "approval.reminder", now)
    with db.transaction(tenant) as conn:
        assert notifications.summary(conn, tenant, view.approval_id) == {
            "delivered": 1,
            "pending": 0,
            "failed": 1,
            "lapsed": 1,
            "closed": 0,
            "withdrawn": 0,
        }
        # The follow-up's later delivery is not the announcement's.
        assert notifications.delivery_times(
            conn, tenant, view.approval_id
        ) == notifications.DeliveryTimes(now, now + timedelta(seconds=9))


def test_ay12_recovery_never_settles_a_close_out_as_closed(
    db, world, admin_engine, connector, receiver
):
    tenant = world["identity"].tenant_id
    _, output = receiver
    runtime = runtime_with(
        db, world, connector, hook(world, receiver, "hook", "pending", "reminder", "closed")
    )
    view = pending(runtime, world)
    now = world["clock"].now()
    seed_row(admin_engine, tenant, view.approval_id, "hook", "approval.reminder", now)
    seed_row(
        admin_engine, tenant, view.approval_id, "hook", "approval.closed", now, outcome="REFUSED"
    )
    decide_approval(db, world["human"], view.approval_id, "DENY", world["clock"])
    settled = notifications.settle_orphaned(
        db, ScheduledActor(tenant), runtime.notifications, clock=world["clock"]
    )
    assert settled == 2
    assert [
        (r["kind"], r["state"], r["last_error"]) for r in notification_rows(admin_engine, tenant)
    ] == [
        ("approval.closed", "PENDING", None),
        ("approval.pending", "FAILED", "APPROVAL_CLOSED"),
        ("approval.reminder", "FAILED", "APPROVAL_CLOSED"),
    ]
    assert drain(db, world, runtime) == {"delivered": 1, "failed": 0, "closed": 0}
    [sent] = delivered_files(output)
    body = json.loads(sent.read_bytes())
    assert body["kind"] == "approval.closed" and body["outcome"] == "refused"


def test_ay8_each_outcome_is_followed_up_once_where_asked(
    db, world, admin_engine, connector, receiver
):
    tenant = world["identity"].tenant_id
    _, output = receiver
    runtime = runtime_with(
        db,
        world,
        connector,
        hook(world, receiver, "both", "pending", "closed"),
        hook(world, receiver, "only"),
        hook(world, receiver, "broken", "pending", "closed"),
    )
    start = world["clock"].now()
    held = several(runtime, world, admin_engine, 5)
    (_, approved), (_, refused), (touch, touched), (_, untouched), (stale, withdrawn) = held
    with admin_engine.begin() as conn:
        conn.execute(
            text(
                "UPDATE execbound.approval_notifications "
                "SET state='FAILED', last_error='RECEIVER_UNAVAILABLE' "
                "WHERE destination_id='broken'"
            )
        )
    world["clock"].value = start + timedelta(seconds=1)
    assert drain(db, world, runtime) == {"delivered": 10, "failed": 0, "closed": 0}
    world["clock"].value = start + timedelta(seconds=10)
    decide_approval(db, world["human"], approved.approval_id, "APPROVE", world["clock"])
    world["clock"].value = start + timedelta(seconds=11)
    decide_approval(db, world["human"], refused.approval_id, "DENY", world["clock"])
    # A policy change before the deadline: sending the request again ends its approval as
    # invalidated, a withdrawal nobody decided.
    world["clock"].value = start + timedelta(seconds=12)
    activate(db, world, endpoint_bundle(tenant, world["account"], mapping_version="map-v1"))
    again = runtime.execute(world["identity"], stale.model_dump_json().encode())
    assert again.state == "STALE_AUTHORIZATION"
    world["clock"].value = start + timedelta(seconds=20)
    assert drain(db, world, runtime) == {"delivered": 3, "failed": 0, "closed": 0}
    # Past the deadline: one is touched by its agent and ends EXPIRED, one nobody touches.
    world["clock"].value = start + timedelta(seconds=125)
    late = runtime.execute(world["identity"], touch.model_dump_json().encode())
    assert late.state == "STALE_AUTHORIZATION"
    world["clock"].value = start + timedelta(seconds=120 + 29)
    assert drain(db, world, runtime) == {"delivered": 1, "failed": 0, "closed": 0}
    world["clock"].value = start + timedelta(seconds=120 + 31)
    assert drain(db, world, runtime) == {"delivered": 1, "failed": 0, "closed": 0}
    assert drain(db, world, runtime) == {"delivered": 0, "failed": 0, "closed": 0}
    with admin_engine.begin() as conn:
        decided = dict(
            conn.execute(
                text("SELECT approval_id, decided_at FROM execbound.approvals WHERE tenant_id=:t"),
                {"t": tenant},
            ).all()
        )
        states = dict(
            conn.execute(
                text("SELECT approval_id, state FROM execbound.approvals WHERE tenant_id=:t"),
                {"t": tenant},
            ).all()
        )
    expires = start + timedelta(seconds=120)
    closes = {
        r["approval_id"]: (r["destination_id"], r["outcome"], r["closed_at"], r["state"])
        for r in notification_rows(admin_engine, tenant)
        if r["kind"] == "approval.closed"
    }
    assert closes == {
        approved.approval_id: ("both", "APPROVED", decided[approved.approval_id], "DELIVERED"),
        refused.approval_id: ("both", "REFUSED", decided[refused.approval_id], "DELIVERED"),
        touched.approval_id: ("both", "LAPSED", expires, "DELIVERED"),
        untouched.approval_id: ("both", "LAPSED", expires, "DELIVERED"),
        withdrawn.approval_id: (
            "both",
            "WITHDRAWN",
            start + timedelta(seconds=20),
            "DELIVERED",
        ),
    }
    assert states[touched.approval_id] == "EXPIRED"
    assert states[untouched.approval_id] == "PENDING"
    assert states[withdrawn.approval_id] == "INVALIDATED"
    bodies = [json.loads(p.read_bytes()) for p in delivered_files(output)]
    outcomes = sorted(b["outcome"] for b in bodies if b["kind"] == "approval.closed")
    assert outcomes == ["approved", "lapsed", "lapsed", "refused", "withdrawn"]
    assert sum(b["kind"] == "approval.pending" for b in bodies) == 10


def test_ay8_a_close_out_whose_message_was_switched_off_is_not_sent(
    db, world, admin_engine, connector, receiver
):
    tenant = world["identity"].tenant_id
    _, output = receiver
    runtime = runtime_with(db, world, connector, hook(world, receiver, "hook"))
    view = pending(runtime, world)
    decide_approval(db, world["human"], view.approval_id, "APPROVE", world["clock"])
    seed_row(
        admin_engine, tenant, view.approval_id, "hook", "approval.closed", world["clock"].now()
    )
    assert drain(db, world, runtime) == {"delivered": 0, "failed": 1, "closed": 1}
    rows_now = {r["kind"]: r for r in notification_rows(admin_engine, tenant)}
    closed = rows_now["approval.closed"]
    assert (closed["state"], closed["attempts"], closed["last_error"]) == (
        "FAILED",
        0,
        "MESSAGE_OFF",
    )
    assert delivered_files(output) == []


def test_ay9_two_drains_send_one_close_out(db, world, admin_engine, connector, monkeypatch):
    tenant = world["identity"].tenant_id
    runtime = runtime_with(
        db,
        world,
        connector,
        Destination(
            "hook",
            tenant,
            "http://127.0.0.1:9/alerts",
            "k" * 32,
            messages=frozenset({"pending", "closed"}),
        ),
    )
    view = pending(runtime, world)
    sent = []
    monkeypatch.setattr(
        notifications,
        "send_notification",
        lambda receiver, delivery_id, body, *a, **k: sent.append((delivery_id, body)) or True,
    )
    assert drain(db, world, runtime)["delivered"] == 1
    decide_approval(db, world["human"], view.approval_id, "DENY", world["clock"])
    # Both drains read the closed approval before either queues its close-out.
    barrier = Barrier(2)

    def both_read(conn, cursor, statement, parameters, context, executemany):
        if "SELECT DISTINCT ON (n.approval_id, n.destination_id)" in statement:
            barrier.wait(timeout=10)

    sa_event.listen(db.engine, "after_cursor_execute", both_read)
    try:
        with ThreadPoolExecutor(max_workers=2) as pool:
            results = list(pool.map(lambda _: drain(db, world, runtime), range(2)))
    finally:
        sa_event.remove(db.engine, "after_cursor_execute", both_read)
    assert sum(r["delivered"] for r in results) == 1
    closes = [r for r in notification_rows(admin_engine, tenant) if r["kind"] == "approval.closed"]
    assert [(c["notification_id"], c["state"]) for c in closes] == [
        (uuid5(view.approval_id, "hook#closed"), "DELIVERED")
    ]
    assert [delivery for delivery, _ in sent[1:]] == [uuid5(view.approval_id, "hook#closed")]
    assert json.loads(sent[1][1])["kind"] == "approval.closed"


def race_once(db, tenant, statement, values):
    """Run `statement` from two transactions at once; return each one's row count."""
    barrier = Barrier(2)

    def queue(_):
        with db.transaction(tenant) as conn:
            barrier.wait(timeout=10)
            return conn.execute(statement, values).rowcount

    with ThreadPoolExecutor(max_workers=2) as pool:
        return sorted(pool.map(queue, range(2)))


def race_one_row(db, tenant, statement, params, rounds=200):
    """Race `statement` `rounds` times over fresh rows: each race queues the row once and
    neither transaction raises."""
    for index in range(rounds):
        assert race_once(db, tenant, statement, params(f"race-{index}")) == [0, 1], index


def test_ay9_racing_close_outs_queue_one_row_and_raise_nothing(db, world, connector):
    # A row's id is fixed, so two drains queueing the same close-out collide on the primary key
    # as well as on the one-per-kind key. A conflict clause naming only the latter raised a
    # unique violation on the former in about one race in sixteen, which the drain reported as
    # "Execution unavailable".
    tenant = world["identity"].tenant_id
    runtime = runtime_with(
        db, world, connector, Destination("hook", tenant, "http://127.0.0.1:9/alerts", "k" * 32)
    )
    approval = pending(runtime, world).approval_id
    now = world["clock"].now()
    race_one_row(
        db,
        tenant,
        notifications._QUEUE_CLOSE_OUT,
        lambda destination: {
            "t": tenant,
            "n": uuid5(approval, destination + "#closed"),
            "a": approval,
            "d": destination,
            "o": "REFUSED",
            "c": now,
            "now": now,
        },
    )


def test_ay16_racing_announcements_queue_one_row_and_raise_nothing(db, world, connector):
    # The same race over an announcement, whose id is fixed by its approval and destination.
    tenant = world["identity"].tenant_id
    runtime = runtime_with(
        db, world, connector, Destination("hook", tenant, "http://127.0.0.1:9/alerts", "k" * 32)
    )
    approval = pending(runtime, world).approval_id
    now = world["clock"].now()
    race_one_row(
        db,
        tenant,
        notifications._QUEUE_ANNOUNCEMENT,
        lambda destination: {
            "t": tenant,
            "n": uuid5(approval, destination),
            "a": approval,
            "d": destination,
            "now": now,
        },
    )


def test_ay10_racing_reminders_queue_one_row_and_raise_nothing(db, world, connector):
    # The same race over a reminder, whose id is fixed by its approval and destination.
    tenant = world["identity"].tenant_id
    runtime = runtime_with(
        db, world, connector, Destination("hook", tenant, "http://127.0.0.1:9/alerts", "k" * 32)
    )
    approval = pending(runtime, world).approval_id
    now = world["clock"].now()
    race_one_row(
        db,
        tenant,
        notifications._QUEUE_REMINDER,
        lambda destination: {
            "t": tenant,
            "n": uuid5(approval, destination + "#reminder"),
            "a": approval,
            "d": destination,
            "now": now,
        },
    )


def test_ay18_follow_ups_never_take_the_last_of_the_email_cap(
    db, world, admin_engine, connector, tmp_path
):
    tenant = world["identity"].tenant_id
    with relay(tmp_path, "tls") as local:
        runtime = runtime_with(
            db,
            world,
            connector,
            replace(jane(world), messages=frozenset({"pending", "closed"})),
            mail=relay_mail(local.port, daily_limit=10),
        )
        start = world["clock"].now()
        held = several(runtime, world, admin_engine, 10)
        spent, fresh = [view for _, view in held[:9]], held[9][1]
        with admin_engine.begin() as conn:
            conn.execute(
                text(
                    "UPDATE execbound.approval_notifications SET state='DELIVERED', "
                    "delivered_at=:d WHERE approval_id = ANY(:a)"
                ),
                {"d": start - timedelta(hours=1), "a": [v.approval_id for v in spent]},
            )
        # Due before the new request's announcement, so it is claimed first.
        due = start - timedelta(seconds=1)
        close_out = seed_row(
            admin_engine,
            tenant,
            spent[0].approval_id,
            "jane",
            "approval.closed",
            start,
            next_attempt_at=due,
        )
        world["clock"].value = start + timedelta(seconds=5)
        assert drain(db, world, runtime, local.context) == {
            "delivered": 1,
            "failed": 1,
            "closed": 0,
        }
        [received] = local.messages()
    assert received["X-ExecBound-Approval"] == str(fresh.approval_id)
    found = {r["notification_id"]: r for r in notification_rows(admin_engine, tenant)}
    refused = found[close_out]
    assert (refused["state"], refused["attempts"], refused["last_error"]) == (
        "FAILED",
        0,
        "RATE_LIMITED",
    )
    assert refused["next_attempt_at"] == due
    assert found[uuid5(fresh.approval_id, "jane")]["state"] == "DELIVERED"


# Reminders: once per approval and destination, and only where the window leaves time for one
# to arrive and be acted on.


class Sender:
    """A stand-in for the signed webhook POST: records each delivery and answers `up`."""

    def __init__(self):
        self.sent: list[tuple[UUID, bytes]] = []
        self.up = True

    def __call__(self, receiver, delivery_id, body, *args, **kwargs):
        self.sent.append((delivery_id, body))
        return self.up


def offline(world, destination_id, *messages, approvers=None):
    """A webhook destination for the `Sender` stand-in; nothing listens at its address."""
    return Destination(
        destination_id,
        world["identity"].tenant_id,
        "http://127.0.0.1:9/alerts",
        "k" * 32,
        approvers=None if approvers is None else frozenset(approvers),
        messages=frozenset(messages),
    )


def reminding(db, world, connector, *destinations, seconds=600, mail=None):
    """A runtime whose new approvals last `seconds`: the workspace deadline changed on the
    audited path, and facts valid for most of an hour, so the deadline is the binding clock.
    `seconds=None` keeps the default 120-second deadline."""
    if seconds is not None:
        long_facts(db, world)
        set_deadline(db, world, seconds)
    return runtime_with(db, world, connector, *destinations, mail=mail)


def reminders(admin_engine, tenant):
    return [r for r in notification_rows(admin_engine, tenant) if r["kind"] == "approval.reminder"]


def test_the_reminder_floor_is_three_minutes():
    assert notifications.REMINDER_FLOOR == timedelta(seconds=180)


def test_ay10_one_reminder_where_it_can_arrive(
    db, world, admin_engine, connector, receiver, tmp_path
):
    tenant = world["identity"].tenant_id
    _, output = receiver
    with relay(tmp_path, "tls") as local:
        runtime = reminding(
            db,
            world,
            connector,
            hook(world, receiver, "remind", "pending", "reminder"),
            hook(world, receiver, "escalate", "reminder"),
            hook(world, receiver, "outcomes", "pending", "closed"),
            replace(jane(world), messages=frozenset({"pending", "reminder"})),
            mail=relay_mail(local.port),
        )
        view = pending(runtime, world)
        start = world["clock"].now()
        assert expiry(admin_engine, view.approval_id) == start + timedelta(seconds=600)
        before = snapshot(admin_engine, tenant)
        world["clock"].value = start + timedelta(seconds=5)
        assert drain(db, world, runtime, local.context) == {
            "delivered": 3,
            "failed": 0,
            "closed": 0,
        }
        # Not yet half the window: nothing is queued.
        world["clock"].value = start + timedelta(seconds=290)
        assert drain(db, world, runtime, local.context) == {
            "delivered": 0,
            "failed": 0,
            "closed": 0,
        }
        assert reminders(admin_engine, tenant) == []
        # Past half the window with more than three minutes left: one reminder for each
        # destination that lists it, the escalation destination among them, and only once; the
        # destination that does not list it gets none.
        world["clock"].value = start + timedelta(seconds=305)
        assert drain(db, world, runtime, local.context) == {
            "delivered": 3,
            "failed": 0,
            "closed": 0,
        }
        world["clock"].value = start + timedelta(seconds=320)
        assert drain(db, world, runtime, local.context) == {
            "delivered": 0,
            "failed": 0,
            "closed": 0,
        }
        announcement, reminder = local.messages()
    assert [
        (r["destination_id"], r["kind"], r["notification_id"], r["state"], r["attempts"])
        for r in notification_rows(admin_engine, tenant)
    ] == [
        (destination, kind, uuid5(view.approval_id, destination + SUFFIX[kind]), "DELIVERED", 1)
        for destination, kind in (
            ("escalate", "approval.reminder"),
            ("jane", "approval.pending"),
            ("jane", "approval.reminder"),
            ("outcomes", "approval.pending"),
            ("remind", "approval.pending"),
            ("remind", "approval.reminder"),
        )
    ]
    # A reminder never moves the deadline or touches the approval, the execution or the chain.
    assert snapshot(admin_engine, tenant) == before
    assert expiry(admin_engine, view.approval_id) == start + timedelta(seconds=600)
    # The webhook body is the announcement's, byte for byte, but for its kind.
    bodies = {path.stem: path.read_bytes() for path in delivered_files(output)}
    pending_body = bodies[str(uuid5(view.approval_id, "remind"))]
    assert json.loads(pending_body)["kind"] == "approval.pending"
    for name in ("remind#reminder", "escalate#reminder"):
        assert bodies[str(uuid5(view.approval_id, name))] == pending_body.replace(
            b'"kind":"approval.pending"', b'"kind":"approval.reminder"'
        )
    assert len(bodies) == 4
    assert str(announcement["Subject"]).split("] ", 1)[1].startswith("Decide by ")
    assert str(reminder["Subject"]).split("] ", 1)[1].startswith("Still waiting, decide by ")
    assert reminder["X-ExecBound-Delivery"] == str(uuid5(view.approval_id, "jane#reminder"))


@pytest.mark.parametrize("seconds", [300, None])
def test_ay10_a_window_too_short_for_a_reminder_gets_none(
    db, world, admin_engine, connector, monkeypatch, seconds
):
    # A 300-second window, which a five-minute context cap gives, and the default 120 s never
    # leave three minutes after their halfway point.
    tenant = world["identity"].tenant_id
    sender = Sender()
    monkeypatch.setattr(notifications, "send_notification", sender)
    runtime = reminding(
        db, world, connector, offline(world, "escalate", "reminder"), seconds=seconds
    )
    view = pending(runtime, world)
    start = world["clock"].now()
    window = (expiry(admin_engine, view.approval_id) - start).total_seconds()
    assert window == (seconds or 120)
    for at in (window // 2 + 1, window // 2 + 10, window - 16):
        world["clock"].value = start + timedelta(seconds=at)
        assert drain(db, world, runtime) == {"delivered": 0, "failed": 0, "closed": 0}
    assert reminders(admin_engine, tenant) == [] and sender.sent == []


def test_ay10_a_reminder_follows_the_closed_and_lapse_rules(
    db, world, admin_engine, connector, monkeypatch
):
    tenant = world["identity"].tenant_id
    sender = Sender()
    monkeypatch.setattr(notifications, "send_notification", sender)
    runtime = reminding(db, world, connector, offline(world, "escalate", "reminder"))
    start = world["clock"].now()
    (_, decided), (_, lapsing) = several(runtime, world, admin_engine, 2)
    # Both reminders are queued on time, and their receiver is down.
    sender.up = False
    world["clock"].value = start + timedelta(seconds=305)
    assert drain(db, world, runtime) == {"delivered": 0, "failed": 0, "closed": 0}
    assert {(r["state"], r["attempts"]) for r in reminders(admin_engine, tenant)} == {
        ("PENDING", 1)
    }
    sender.up = True
    # One approval is decided before the retry, and the other's retry finds 14 s left.
    world["clock"].value = start + timedelta(seconds=306)
    decide_approval(db, world["human"], decided.approval_id, "APPROVE", world["clock"])
    world["clock"].value = start + timedelta(seconds=586)
    assert drain(db, world, runtime) == {"delivered": 0, "failed": 0, "closed": 2}
    assert {
        r["approval_id"]: (r["state"], r["attempts"], r["last_error"])
        for r in reminders(admin_engine, tenant)
    } == {
        decided.approval_id: ("FAILED", 1, "APPROVAL_CLOSED"),
        lapsing.approval_id: ("FAILED", 1, "LAPSED_BEFORE_DELIVERY"),
    }
    assert len(sender.sent) == 2


def test_ay10_a_reminder_whose_message_was_switched_off_is_not_sent(
    db, world, admin_engine, connector, monkeypatch
):
    tenant = world["identity"].tenant_id
    sender = Sender()
    monkeypatch.setattr(notifications, "send_notification", sender)
    before = reminding(db, world, connector, offline(world, "hook", "pending", "reminder"))
    view = pending(before, world)
    start = world["clock"].now()
    assert drain(db, world, before)["delivered"] == 1
    sender.up = False
    world["clock"].value = start + timedelta(seconds=305)
    assert drain(db, world, before) == {"delivered": 0, "failed": 0, "closed": 0}
    sender.up = True
    # The operator restarted with this destination announcing only: the reminder queued under
    # the old configuration is settled, unsent.
    after = runtime_with(db, world, connector, offline(world, "hook", "pending"))
    world["clock"].value = start + timedelta(seconds=311)
    assert drain(db, world, after) == {"delivered": 0, "failed": 1, "closed": 0}
    [row] = reminders(admin_engine, tenant)
    assert (row["notification_id"], row["state"], row["attempts"], row["last_error"]) == (
        uuid5(view.approval_id, "hook#reminder"),
        "FAILED",
        1,
        "MESSAGE_OFF",
    )
    assert [delivery for delivery, _ in sender.sent] == [
        uuid5(view.approval_id, "hook"),
        uuid5(view.approval_id, "hook#reminder"),
    ]


def test_ay10_more_than_fifty_due_reminders_are_all_reached(
    db, world, admin_engine, connector, monkeypatch
):
    tenant = world["identity"].tenant_id
    sender = Sender()
    monkeypatch.setattr(notifications, "send_notification", sender)
    runtime = reminding(db, world, connector, offline(world, "escalate", "reminder"))
    start = world["clock"].now()
    views = []
    # One a second, so each expires a second after the one before.
    for second in range(51):
        world["clock"].value = start + timedelta(seconds=second)
        [(_, view)] = several(runtime, world, admin_engine, 1)
        views.append(view.approval_id)
    world["clock"].value = start + timedelta(seconds=350)
    assert drain(db, world, runtime) == {"delivered": 50, "failed": 0, "closed": 0}
    assert {r["approval_id"] for r in reminders(admin_engine, tenant)} == set(views[:50])
    assert drain(db, world, runtime) == {"delivered": 1, "failed": 0, "closed": 0}
    assert {r["approval_id"] for r in reminders(admin_engine, tenant)} == set(views)
    assert drain(db, world, runtime) == {"delivered": 0, "failed": 0, "closed": 0}
    assert sorted(delivery for delivery, _ in sender.sent) == sorted(
        uuid5(approval, "escalate#reminder") for approval in views
    )


def test_ay10_an_approval_no_reminder_destination_routes_holds_no_other_back(
    db, world, admin_engine, connector, monkeypatch
):
    # The scan takes a bounded batch, soonest deadline first. An approval that no destination
    # listing `reminder` routes gets no row, so it must not be taken again and again ahead of
    # one that is routed: a batch of one shows it.
    tenant = world["identity"].tenant_id
    sender = Sender()
    monkeypatch.setattr(notifications, "send_notification", sender)
    monkeypatch.setattr(notifications, "FOLLOWUP_BATCH", 1)
    lead = second_approver(admin_engine, db, world)
    runtime = reminding(
        db,
        world,
        connector,
        offline(world, "escalate", "reminder", approvers=[lead.principal_id]),
    )
    start = world["clock"].now()
    # Assigned to the world's approver alone, and due first.
    [(_, unrouted)] = several(runtime, world, admin_engine, 1)
    world["clock"].value = start + timedelta(seconds=1)
    # The world's own target, which the lead may decide too.
    routed = pending(runtime, world)
    world["clock"].value = start + timedelta(seconds=302)
    assert drain(db, world, runtime) == {"delivered": 1, "failed": 0, "closed": 0}
    assert [r["approval_id"] for r in reminders(admin_engine, tenant)] == [routed.approval_id]
    assert drain(db, world, runtime) == {"delivered": 0, "failed": 0, "closed": 0}
    assert unrouted.approval_id != routed.approval_id
    assert [delivery for delivery, _ in sender.sent] == [
        uuid5(routed.approval_id, "escalate#reminder")
    ]


def test_ay10_reminders_respect_the_follow_up_cap(db, world, admin_engine, connector, tmp_path):
    tenant = world["identity"].tenant_id
    with relay(tmp_path, "tls") as local:
        runtime = runtime_with(
            db,
            world,
            connector,
            replace(jane(world), messages=frozenset({"pending", "reminder"})),
            mail=relay_mail(local.port, daily_limit=10),
        )
        start = world["clock"].now()
        held = several(runtime, world, admin_engine, 10)
        spent, fresh = [view for _, view in held[:9]], held[9][1]
        with admin_engine.begin() as conn:
            conn.execute(
                text(
                    "UPDATE execbound.approval_notifications SET state='DELIVERED', "
                    "delivered_at=:d WHERE approval_id = ANY(:a)"
                ),
                {"d": start - timedelta(hours=1), "a": [v.approval_id for v in spent]},
            )
        # Due before the new request's announcement, so it is claimed first.
        due = start - timedelta(seconds=1)
        reminder = seed_row(
            admin_engine,
            tenant,
            spent[0].approval_id,
            "jane",
            "approval.reminder",
            start,
            next_attempt_at=due,
        )
        world["clock"].value = start + timedelta(seconds=5)
        assert drain(db, world, runtime, local.context) == {
            "delivered": 1,
            "failed": 1,
            "closed": 0,
        }
        [received] = local.messages()
    assert received["X-ExecBound-Approval"] == str(fresh.approval_id)
    found = {r["notification_id"]: r for r in notification_rows(admin_engine, tenant)}
    refused = found[reminder]
    assert (refused["state"], refused["attempts"], refused["last_error"]) == (
        "FAILED",
        0,
        "RATE_LIMITED",
    )
    assert refused["next_attempt_at"] == due
    assert found[uuid5(fresh.approval_id, "jane")]["state"] == "DELIVERED"
