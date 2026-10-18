# SPDX-License-Identifier: AGPL-3.0-only
"""Scheduled approval notifications with no workspace credential (#503): SJ3.

The signup workspace's case is in the plugin's own tests.
"""

from datetime import timedelta
from types import SimpleNamespace
from uuid import UUID, uuid4

import pytest
from smtp_double import relay
from sqlalchemy import text
from test_approval_notifications import pending, rows
from test_execution import registry as registry
from test_execution import world as world
from test_notification_email import ADDRESS, emailing, jane, relay_mail
from test_protected_path import connector as connector
from test_protected_path import live_provider as live_provider
from test_scheduled_recovery import deactivate, fenced

from execbound import notifications
from execbound.execution import decide_approval
from execbound.execution.models import ExecutionError
from execbound.execution.scheduled import ScheduledActor
from execbound.notifications import (
    ORPHAN_AFTER,
    destination_tenants,
    notify_scheduled,
    settle_orphaned,
)
from execbound.recovery_run import recover_scheduled

pytestmark = pytest.mark.integration


def test_sj3_destination_tenants_are_the_approval_kinds_only():
    a, b = UUID(int=1), UUID(int=2)
    # Each stand-in carries the classes every destination has unless it opts out (#31).
    approvals = frozenset({"approvals"})
    destinations = [
        SimpleNamespace(tenant_id=b, kind="email", classes=approvals),
        SimpleNamespace(tenant_id=a, kind="slack", classes=approvals),
        SimpleNamespace(tenant_id=a, kind="webhook", classes=approvals),
        SimpleNamespace(tenant_id=UUID(int=3), kind="security-events", classes=approvals),
    ]
    assert destination_tenants(destinations) == [a, b]


def test_sj3_the_scheduled_drain_delivers_with_no_administrator(
    db, world, admin_engine, connector, tmp_path
):
    tenant = world["identity"].tenant_id
    with relay(tmp_path, "tls") as local:
        runtime = emailing(db, world, connector, relay_mail(local.port), jane(world))
        view = pending(runtime, world)
        sent = notify_scheduled(
            db,
            tenant,
            runtime.notifications,
            approval_url=runtime.approval_url or "",
            mail=runtime.mail,
            clock=world["clock"],
            tls_context=local.context,
        )
        assert sent == {"delivered": 1, "failed": 0, "closed": 0}
        [received] = local.messages()
    assert received["To"] == ADDRESS
    # With no plugin's path builder, core's own address.
    link = f"http://127.0.0.1/approvals/{view.approval_id}"
    assert f"Open the approval: {link}" in received.get_content().splitlines()
    [row] = rows(admin_engine, tenant)
    assert (row["state"], row["attempts"]) == ("DELIVERED", 1)


def test_sj3_recovery_settles_a_closed_approval_s_row_no_drain_will_reach(
    db, world, admin_engine, connector, monkeypatch
):
    tenant = world["identity"].tenant_id
    runtime = emailing(db, world, connector, relay_mail(2525), jane(world))
    view = pending(runtime, world)
    decide_approval(db, world["human"], view.approval_id, "DENY", world["clock"])
    monkeypatch.setattr(notifications, "send_email", lambda *a, **k: pytest.fail("sent"))
    # The workspace's only destination has since been removed, so no drain visits it again.
    # Run through the pass itself, so what is measured is the settling the pass runs.
    report = recover_scheduled(db, tenant, {}, destinations=[], clock=world["clock"])
    assert report["notifications_settled"] == 1
    [row] = rows(admin_engine, tenant)
    assert (row["state"], row["last_error"]) == ("FAILED", "APPROVAL_CLOSED")
    again = recover_scheduled(db, tenant, {}, destinations=[], clock=world["clock"])
    assert again["notifications_settled"] == 0


def test_sj3_recovery_settles_against_the_destinations_it_is_given(
    db, world, admin_engine, connector
):
    """The pass forwards its configuration to the settling: a row older than `ORPHAN_AFTER`
    is kept while its destination is configured, and settled once it is not."""
    tenant = world["identity"].tenant_id
    runtime = emailing(db, world, connector, relay_mail(2525), jane(world))
    pending(runtime, world)
    with admin_engine.begin() as conn:
        fenced(conn, tenant)
        conn.execute(
            text(
                "UPDATE execbound.approval_notifications "
                "SET created_at = created_at - interval '2 days' WHERE tenant_id = :t"
            ),
            {"t": tenant},
        )
    kept = recover_scheduled(
        db, tenant, {}, destinations=runtime.notifications, clock=world["clock"]
    )
    assert kept["notifications_settled"] == 0
    [row] = rows(admin_engine, tenant)
    assert row["state"] == "PENDING"
    gone = recover_scheduled(db, tenant, {}, destinations=[], clock=world["clock"])
    assert gone["notifications_settled"] == 1
    [row] = rows(admin_engine, tenant)
    assert (row["state"], row["last_error"]) == ("FAILED", "DESTINATION_UNKNOWN")


def test_sj3_a_pending_row_whose_destination_is_gone_is_settled_unknown(
    db, world, admin_engine, connector
):
    tenant = world["identity"].tenant_id
    runtime = emailing(db, world, connector, relay_mail(2525), jane(world))
    pending(runtime, world)
    # Still configured, so the drain will reach it: nothing to settle.
    assert (
        settle_orphaned(db, ScheduledActor(tenant), runtime.notifications, clock=world["clock"])
        == 0
    )
    # Absent from this configuration, but younger than the drain's retry schedule: kept.
    assert settle_orphaned(db, ScheduledActor(tenant), [], clock=world["clock"]) == 0
    world["clock"].value += timedelta(days=1, seconds=1)
    assert settle_orphaned(db, ScheduledActor(tenant), [], clock=world["clock"]) == 1
    [row] = rows(admin_engine, tenant)
    assert (row["state"], row["last_error"]) == ("FAILED", "DESTINATION_UNKNOWN")


def lease(engine, tenant, until):
    """Hold the workspace's one row as a drain does between its lease and its send."""
    with engine.begin() as conn:
        fenced(conn, tenant)
        conn.execute(
            text(
                "UPDATE execbound.approval_notifications SET state = 'IN_FLIGHT', "
                "attempts = attempts + 1, lease_token = :l, lease_until = :u "
                "WHERE tenant_id = :t"
            ),
            {"t": tenant, "l": uuid4(), "u": until},
        )


@pytest.mark.parametrize(
    ("closed", "code"),
    [(True, "APPROVAL_CLOSED"), (False, "DESTINATION_UNKNOWN")],
    ids=["approval-closed", "destination-gone"],
)
def test_sj3_a_row_under_a_live_lease_is_left_to_its_drain(
    db, world, admin_engine, connector, closed, code
):
    tenant = world["identity"].tenant_id
    runtime = emailing(db, world, connector, relay_mail(2525), jane(world))
    view = pending(runtime, world)
    if closed:
        decide_approval(db, world["human"], view.approval_id, "DENY", world["clock"])
    else:
        world["clock"].value += ORPHAN_AFTER + timedelta(seconds=1)
    lease(admin_engine, tenant, world["clock"].now() + timedelta(seconds=30))
    assert settle_orphaned(db, ScheduledActor(tenant), [], clock=world["clock"]) == 0
    [row] = rows(admin_engine, tenant)
    assert row["state"] == "IN_FLIGHT"
    # The lease has run out, so no drain holds the row any more.
    world["clock"].value += timedelta(seconds=31)
    assert settle_orphaned(db, ScheduledActor(tenant), [], clock=world["clock"]) == 1
    [row] = rows(admin_engine, tenant)
    assert (row["state"], row["last_error"]) == ("FAILED", code)


def test_sj3_settling_refuses_a_deactivated_workspace(db, world, admin_engine, connector):
    tenant = world["identity"].tenant_id
    runtime = emailing(db, world, connector, relay_mail(2525), jane(world))
    view = pending(runtime, world)
    decide_approval(db, world["human"], view.approval_id, "DENY", world["clock"])
    deactivate(admin_engine, tenant)
    with pytest.raises(ExecutionError) as refused:
        settle_orphaned(db, ScheduledActor(tenant), [], clock=world["clock"])
    assert refused.value.code == "INVALID_IDENTITY"
    [row] = rows(admin_engine, tenant)
    assert row["state"] == "PENDING"
