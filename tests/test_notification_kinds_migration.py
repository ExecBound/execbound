# SPDX-License-Identifier: AGPL-3.0-only
"""Migration 0080: approval notifications gain a kind, under one key per kind (AY13, #678).

Real PostgreSQL. A row queued before the upgrade reads `approval.pending` and keeps its id;
one message of each kind per approval and destination is a schema fact; a close-out alone
carries an outcome and its time; the runtime can never rewrite any of the three new columns;
and the downgrade refuses while a reminder or a close-out is retained.
"""

from datetime import timedelta
from uuid import uuid5

import pytest
from alembic import command
from sqlalchemy import text
from sqlalchemy.exc import IntegrityError
from test_approval_notifications import notifying as notifying
from test_approval_notifications import pending
from test_dormant_catalog import alembic_config, revision_of
from test_execution import registry as registry
from test_execution import world as world
from test_monitoring_worker import receiver as receiver
from test_protected_path import connector as connector
from test_protected_path import live_provider as live_provider

from execbound import db as db_module
from execbound.db import check_runtime

pytestmark = pytest.mark.integration

BEFORE = "0079_key_last_used"
TARGET = "0080_notification_kinds"
INDEXES = {
    "approval_notifications_followup",
    "approvals_pending_expiry",
    "approval_notifications_pending_created",
}


def indexes(engine) -> set[str]:
    with engine.connect() as conn:
        return set(
            conn.execute(
                text(
                    "SELECT indexname FROM pg_indexes WHERE schemaname='execbound' "
                    "AND indexname = ANY(:names)"
                ),
                {"names": sorted(INDEXES)},
            ).scalars()
        )


def kinds(engine, tenant):
    with engine.connect() as conn:
        return [
            tuple(row)
            for row in conn.execute(
                text(
                    "SELECT notification_id, destination_id, kind, outcome, closed_at "
                    "FROM execbound.approval_notifications WHERE tenant_id=:t "
                    "ORDER BY destination_id, kind"
                ),
                {"t": tenant},
            )
        ]


def insert(conn, tenant, approval_id, destination, kind, outcome=None, closed_at=None, now=None):
    conn.execute(
        text(
            "INSERT INTO execbound.approval_notifications (tenant_id, notification_id, "
            "approval_id, destination_id, kind, outcome, closed_at, created_at, next_attempt_at) "
            "VALUES (:t, :n, :a, :d, :k, :o, :c, :now, :now)"
        ),
        {
            "t": tenant,
            "n": uuid5(approval_id, f"{destination}#{kind}"),
            "a": approval_id,
            "d": destination,
            "k": kind,
            "o": outcome,
            "c": closed_at,
            "now": now,
        },
    )


def test_ay13_the_head_is_the_new_revision_and_the_runtime_cannot_rewrite_a_kind(
    db, world, admin_engine
):
    # Later migrations move the head past this one, so the test holds to the current head.
    assert revision_of(admin_engine) == db_module.SCHEMA_REVISION
    tenant = world["identity"].tenant_id
    with db.transaction(tenant) as conn:
        check_runtime(conn)
        for column in ("kind", "outcome", "closed_at"):
            assert (
                conn.execute(
                    text(
                        "SELECT has_column_privilege('execbound_app', "
                        "'execbound.approval_notifications', :c, 'UPDATE')"
                    ),
                    {"c": column},
                ).scalar_one()
                is False
            ), column
    assert indexes(admin_engine) == INDEXES


def test_ay13_a_row_queued_before_the_upgrade_reads_pending_and_keeps_its_id(
    db, world, admin_engine, notifying
):
    tenant = world["identity"].tenant_id
    view = pending(notifying, world)
    config = alembic_config()
    command.downgrade(config, BEFORE)
    try:
        assert indexes(admin_engine) == set()
        with admin_engine.connect() as conn:
            before = [
                tuple(row)
                for row in conn.execute(
                    text(
                        "SELECT notification_id, destination_id "
                        "FROM execbound.approval_notifications WHERE tenant_id=:t "
                        "ORDER BY destination_id"
                    ),
                    {"t": tenant},
                )
            ]
    finally:
        command.upgrade(config, "head")
    assert [(n, d) for n, d in before] == [
        (uuid5(view.approval_id, d), d) for d in ("assigned", "everyone")
    ]
    assert kinds(admin_engine, tenant) == [
        (n, d, "approval.pending", None, None) for n, d in before
    ]


def test_ay13_one_message_of_each_kind_and_a_close_out_alone_carries_its_outcome(
    db, world, admin_engine, notifying
):
    tenant = world["identity"].tenant_id
    view = pending(notifying, world)
    now = world["clock"].now()
    with pytest.raises(IntegrityError, match="approval_notifications_one_per_kind"):
        with admin_engine.begin() as conn:
            conn.execute(
                text(
                    "INSERT INTO execbound.approval_notifications (tenant_id, notification_id, "
                    "approval_id, destination_id, created_at, next_attempt_at) "
                    "VALUES (:t, gen_random_uuid(), :a, 'everyone', :now, :now)"
                ),
                {"t": tenant, "a": view.approval_id, "now": now},
            )
    with admin_engine.begin() as conn:
        insert(conn, tenant, view.approval_id, "everyone", "approval.closed", "LAPSED", now, now)
        insert(conn, tenant, view.approval_id, "everyone", "approval.reminder", now=now)
    with pytest.raises(IntegrityError, match="approval_notifications_one_per_kind"):
        with admin_engine.begin() as conn:
            conn.execute(
                text(
                    "INSERT INTO execbound.approval_notifications (tenant_id, notification_id, "
                    "approval_id, destination_id, kind, created_at, next_attempt_at) "
                    "VALUES (:t, gen_random_uuid(), :a, 'everyone', 'approval.reminder', "
                    ":now, :now)"
                ),
                {"t": tenant, "a": view.approval_id, "now": now},
            )
    for kind, outcome, closed_at in (
        ("approval.closed", None, None),
        ("approval.closed", "APPROVED", None),
        ("approval.closed", None, now),
        ("approval.pending", "APPROVED", now),
        ("approval.reminder", None, now),
    ):
        with pytest.raises(IntegrityError, match="approval_notifications_closed_fields"):
            with admin_engine.begin() as conn:
                insert(conn, tenant, view.approval_id, "assigned", kind, outcome, closed_at, now)
    with pytest.raises(IntegrityError):
        with admin_engine.begin() as conn:
            insert(conn, tenant, view.approval_id, "assigned", "approval.closed", "RAN", now, now)
    with pytest.raises(IntegrityError):
        with admin_engine.begin() as conn:
            insert(conn, tenant, view.approval_id, "assigned", "approval.later", now=now)


def test_ay13_the_downgrade_refuses_while_a_close_out_is_retained_and_round_trips_without(
    db, world, admin_engine, notifying
):
    tenant = world["identity"].tenant_id
    view = pending(notifying, world)
    now = world["clock"].now()
    with admin_engine.begin() as conn:
        insert(
            conn,
            tenant,
            view.approval_id,
            "everyone",
            "approval.closed",
            "REFUSED",
            now + timedelta(seconds=1),
            now,
        )
    config = alembic_config()
    with pytest.raises(RuntimeError, match="reminders or close-outs are retained"):
        command.downgrade(config, BEFORE)
    assert revision_of(admin_engine) == db_module.SCHEMA_REVISION
    assert indexes(admin_engine) == INDEXES
    with db.transaction(tenant) as conn:
        check_runtime(conn)
    with admin_engine.begin() as conn:
        conn.execute(
            text("DELETE FROM execbound.approval_notifications WHERE kind <> 'approval.pending'")
        )
    command.downgrade(config, BEFORE)
    try:
        assert revision_of(admin_engine) == BEFORE
        with admin_engine.connect() as conn:
            assert (
                conn.execute(
                    text(
                        "SELECT count(*) FROM information_schema.columns "
                        "WHERE table_schema='execbound' AND table_name='approval_notifications' "
                        "AND column_name IN ('kind', 'outcome', 'closed_at')"
                    )
                ).scalar_one()
                == 0
            )
            assert conn.execute(
                text("SELECT pg_get_constraintdef(oid) FROM pg_constraint WHERE conname=:n"),
                {"n": "approval_notifications_tenant_id_approval_id_destination_id_key"},
            ).scalar_one() == ("UNIQUE (tenant_id, approval_id, destination_id)")
    finally:
        command.upgrade(config, "head")
    assert revision_of(admin_engine) == db_module.SCHEMA_REVISION
    with db.transaction(tenant) as conn:
        check_runtime(conn)
    assert [k for _, _, k, _, _ in kinds(admin_engine, tenant)] == ["approval.pending"] * 2
