# SPDX-License-Identifier: AGPL-3.0-only
"""Collection freshness: one rule every surface shares (acceptance MQ7, #678).

A connection's health state is written when a probe or a run completes, and nothing ages it,
so before #678 a collector that stopped kept reading "Collecting" in the allow tone while the
setup's Verify step, with a day-old rule of its own, called the same connection stale. Now
`collection_overdue_since` and `collection_reporting` in the monitoring store decide it, at
request time from server time, and the setup verifier, the snapshot's connection rows and the
counts (through `OVERDUE_CONNECTIONS`, the rule's SQL twin at the same boundary) all ask them.
Every case below is put to all four on one database state.
"""

import inspect
import json
from datetime import timedelta

import pytest
from space_fixtures import default_space, make_space, place
from sqlalchemy import text
from test_execution import registry as registry
from test_execution import world as world
from test_protected_path import connector as connector
from test_protected_path import live_provider as live_provider
from test_runtime import runtime as runtime

from execbound.monitoring import store
from execbound.spaces import set_current_space
from execbound.surfaces import dashboard, settings_pages, value
from execbound.surfaces.console_api import monitoring as monitoring_api
from execbound.surfaces.console_api import monitoring_setup
from execbound.surfaces.sessions import issue_session, load_session

pytestmark = pytest.mark.integration

AVAILABLE = {"audit": {"state": "available", "at": None}}
HOUR = timedelta(hours=1)
DAY = timedelta(days=1)


def fenced(conn, tenant):
    conn.execute(text("SELECT set_config('execbound.tenant_id', :t, true)"), {"t": str(tenant)})


def session_for(db, identity, clock):
    return load_session(db, issue_session(db, identity, clock=clock).token, clock=clock)


def register(db, world, label="Freshness", space=None):
    return store.create_connection(
        db,
        world["admin"],
        label=label,
        base_url="https://fixture.tines.com",
        key_fingerprint="0" * 64,
        clock=world["clock"],
        space=space,
    )


def evidence(admin_engine, tenant, connection, **values):
    """Set a connection's collection evidence directly, as a collector's runs would leave it."""
    row = {
        "created_at": None,
        "active": True,
        "revoked_at": None,
        "last_run_at": None,
        "last_outcome": None,
        "last_error_code": None,
        "last_sync_at": None,
        "capabilities": AVAILABLE,
        **values,
    }
    with admin_engine.begin() as conn:
        fenced(conn, tenant)
        conn.execute(
            text(
                "UPDATE execbound.monitor_connections SET "
                "created_at=COALESCE(:created_at, created_at), active=:active, "
                "revoked_at=:revoked_at, last_run_at=:last_run_at, last_outcome=:last_outcome, "
                "last_error_code=:last_error_code, last_sync_at=:last_sync_at, "
                "capabilities=CAST(:capabilities AS jsonb) "
                "WHERE tenant_id=:t AND connection_id=:c"
            ),
            {
                **row,
                "capabilities": json.dumps(row["capabilities"]),
                "t": tenant,
                "c": connection,
            },
        )


def counted(db, tenant, connection, now):
    """Whether `OVERDUE_CONNECTIONS` counts this one connection."""
    with db.transaction(tenant) as conn:
        return bool(
            conn.execute(
                text(store.OVERDUE_CONNECTIONS + " AND e.connection_id = :c"),
                {"t": tenant, "c": connection, **store.overdue_bounds(now)},
            ).scalar_one()
        )


def stored(db, session, connection, clock):
    rows = store.snapshot(db, session, clock=clock)["connections"]
    return next(row for row in rows if row["connection_id"] == connection)


# (case, evidence relative to now, overdue_since relative to now or None, reporting, verifier)
CASES = [
    (
        "fresh",
        {"last_run": -23 * HOUR, "outcome": "COMPLETE", "sync": -23 * HOUR},
        None,
        True,
        "reporting",
    ),
    (
        "stopped",
        {"last_run": -25 * HOUR, "outcome": "COMPLETE", "sync": -25 * HOUR},
        -25 * HOUR + DAY,
        False,
        "attention",
    ),
    (
        "daily sync just due",
        {"last_run": -HOUR, "outcome": "COMPLETE", "sync": -25 * HOUR},
        None,
        True,
        "reporting",
    ),
    (
        "sync stalled",
        {"last_run": -HOUR, "outcome": "COMPLETE", "sync": -3 * DAY},
        -3 * DAY + 2 * DAY,
        False,
        "attention",
    ),
    (
        "backlog",
        {"last_run": -HOUR, "outcome": "BACKLOG", "sync": -HOUR},
        None,
        False,
        "attention",
    ),
    (
        "recent error",
        {"last_run": -2 * HOUR, "outcome": "ERROR", "error": "COLLECTION_FAILED"},
        None,
        False,
        "attention",
    ),
    (
        "old error",
        {"last_run": -25 * HOUR, "outcome": "ERROR", "error": "COLLECTION_FAILED"},
        -25 * HOUR + DAY,
        False,
        "attention",
    ),
    ("new", {"created": -2 * HOUR}, None, False, "awaiting_sync"),
    ("never ran", {"created": -25 * HOUR}, -25 * HOUR + DAY, False, "attention"),
    (
        "boundary",
        {"last_run": -DAY, "outcome": "COMPLETE", "sync": -DAY},
        timedelta(0),
        False,
        "attention",
    ),
    (
        "revoked",
        {"last_run": -25 * HOUR, "outcome": "COMPLETE", "sync": -25 * HOUR, "revoked": True},
        None,
        False,
        "inactive",
    ),
]


def test_mq7_every_surface_answers_the_same_for_every_case(db, runtime, admin_engine, world):
    tenant, clock = world["admin"].tenant_id, world["clock"]
    connection = register(db, world)
    session = session_for(db, world["admin"], clock)
    now = clock.now()
    for name, case, overdue, reporting, verdict in CASES:
        at = {key: now + value for key, value in case.items() if isinstance(value, timedelta)}
        evidence(
            admin_engine,
            tenant,
            connection,
            created_at=at.get("created", now - 30 * DAY),
            last_run_at=at.get("last_run"),
            last_outcome=case.get("outcome"),
            last_error_code=case.get("error"),
            last_sync_at=at.get("sync"),
            active=not case.get("revoked", False),
            revoked_at=now - HOUR if case.get("revoked") else None,
        )
        row = stored(db, session, connection, clock)
        expected = None if overdue is None else now + overdue
        assert store.collection_overdue_since(row, now) == expected, name
        assert store.collection_reporting(row, now) is reporting, name
        answer = monitoring_setup.verify_setup(runtime, session, "tines", connection)
        assert answer.state == verdict, name
        assert (answer.state == "reporting") is store.collection_reporting(row, now), name
        # The SQL twin counts exactly the connections the rule calls overdue, at the same
        # boundary: evidence exactly a day old is overdue in both.
        assert counted(db, tenant, connection, now) is (expected is not None), name
        # The console API's connection row carries the same two answers.
        api = monitoring_api.read_snapshot(runtime, session)
        [carried] = [item for item in api.connections if item.connection_id == connection]
        assert carried.overdue_since == expected and carried.reporting is reporting, name


def test_mq7_no_surface_keeps_a_rule_of_its_own():
    source = inspect.getsource(monitoring_setup)
    assert "timedelta(days=1)" not in source
    assert "collection_reporting" in source and "collection_overdue_since" in source
    for module in (dashboard, settings_pages, value):
        assert "OVERDUE_CONNECTIONS" in inspect.getsource(module), module.__name__


def test_mq7_overdue_and_source_counts_follow_the_space(db, runtime, admin_engine, world):
    tenant, clock = world["admin"].tenant_id, world["clock"]
    now = clock.now()
    with admin_engine.begin() as conn:
        fenced(conn, tenant)
        own = default_space(conn, tenant)
        other = make_space(conn, tenant, "Customer B")
    here = register(db, world, "Here")
    there = register(db, world, "There", space=other)
    for connection in (here, there):
        evidence(
            admin_engine,
            tenant,
            connection,
            last_run_at=now - 25 * HOUR,
            last_outcome="COMPLETE",
            last_sync_at=now - 25 * HOUR,
        )
    store.create_source(
        db,
        world["admin"],
        label="Elsewhere",
        story_id="4001",
        expires_at=now + timedelta(hours=2),
        clock=clock,
    )
    with admin_engine.begin() as conn:
        fenced(conn, tenant)
        source = conn.execute(
            text("SELECT source_id FROM execbound.monitor_sources WHERE tenant_id=:t"),
            {"t": tenant},
        ).scalar_one()
        conn.execute(
            text(
                "UPDATE execbound.monitor_sources SET health_state='STALE', "
                "health_changed_at=now(), health_checked_at=now() "
                "WHERE tenant_id=:t AND source_id=:s"
            ),
            {"t": tenant, "s": source},
        )
        place(conn, tenant, "monitor_sources", "source_id", source, other)
    session = session_for(db, world["admin"], clock)

    # On "All spaces", the workspace-wide administrator counts both.
    tenant_view = settings_pages.tenant_overview(runtime, session)["monitoring"]
    assert tenant_view["overdue"] == 2 and tenant_view["stale"] == 1
    assert dashboard.overview(runtime, session)["monitoring"]["overdue"] == 2

    with db.transaction(tenant) as conn:
        set_current_space(conn, session, own)
    tenant_view = settings_pages.tenant_overview(runtime, session)["monitoring"]
    overview = dashboard.overview(runtime, session)["monitoring"]
    assert tenant_view["overdue"] == overview["overdue"] == 1
    assert tenant_view["sources"] == tenant_view["stale"] == 0
    assert overview["sources"] == overview["stale"] == 0
    report = value.for_session(runtime, session, timedelta(days=7), timedelta(days=1), None)
    assert report.counts.quiet_sources == overview["stale"] + overview["overdue"] == 1

    with db.transaction(tenant) as conn:
        set_current_space(conn, session, other)
    overview = dashboard.overview(runtime, session)["monitoring"]
    assert overview["overdue"] == 1 and overview["stale"] == 1
    report = value.for_session(runtime, session, timedelta(days=7), timedelta(days=1), None)
    assert report.counts.quiet_sources == overview["stale"] + overview["overdue"] == 2
