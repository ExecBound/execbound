# SPDX-License-Identifier: AGPL-3.0-only
"""MC5 and MC6: when a monitoring connection is due, and one run per connection (#678).

Real PostgreSQL, and the fake Tines API where a run collects. `due_at` is the one rule the
Connections view and `collect-due` both read. A run holds the connection's lease, proves it on
every write to the connection row, and returns it; a run that outlived its lease, or whose
connection was revoked, writes nothing more. The scheduled actor holds no credential and is
admitted only in an active workspace, under that workspace's fence, and only with a lease.
"""

from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta
from threading import Barrier, Event
from uuid import uuid4

import pytest
from sqlalchemy import text
from test_monitoring_store import FixedClock
from test_monitoring_store import admins as admins
from test_samples_schema import blocked_on_a_lock
from test_tines_collection import KEY, client, scenario

from execbound.execution.scheduled import ScheduledActor
from execbound.monitoring import collection, due, graph, store
from execbound.monitoring.models import MonitorError
from execbound.monitoring.tines import TinesConfig
from execbound_harness.fake_graph import CLIENT, DIRECTORY, SECRET
from execbound_harness.fake_tines import BASE_URL, serving

pytestmark = pytest.mark.integration

T = datetime(2026, 10, 12, 9, 0, tzinfo=UTC)
SECOND = timedelta(seconds=1)


def row(**changes):
    """A connection row as `due_at` reads it: active, never run, nothing requested or held."""
    values = {
        "kind": "tines",
        "credential_mode": "key_file",
        "active": True,
        "revoked_at": None,
        "created_at": T - timedelta(days=30),
        "last_run_at": None,
        "collect_interval_seconds": None,
        "activity_interval_seconds": None,
        "collect_requested_at": None,
        "collecting_until": None,
        "last_outcome": None,
        "retry_after_seconds": None,
    }
    values.update(changes)
    return values


# The kind, its intervals as set on the row, and the interval that decides when it is due:
# the activity interval for Tines, whose every run reads audit records, and the collect
# interval for Entra. Null is the kind's default.
SCHEDULES = [
    ("tines", None, None, 900),
    ("tines", 86400, 300, 300),
    ("tines", None, 3600, 3600),
    ("entra_agent_id", None, None, 21600),
    ("entra_agent_id", 3600, None, 3600),
    ("entra_agent_id", 86400, None, 86400),
]


@pytest.mark.parametrize("mode", ["key_file", "sealed", "platform_app"])
@pytest.mark.parametrize("kind,collect,activity,every", SCHEDULES)
def test_mc5_a_connection_is_due_a_whole_interval_after_its_last_run(
    mode, kind, collect, activity, every
):
    """At each interval's edge, in every credential mode: one second before it is not due, at
    it and one second after it is."""
    last = T - timedelta(hours=30)
    connection = row(
        kind=kind,
        credential_mode=mode,
        last_run_at=last,
        collect_interval_seconds=collect,
        activity_interval_seconds=activity,
    )
    edge = last + timedelta(seconds=every)
    assert due.due_at(connection, edge) == edge
    assert not due.is_due(connection, edge - SECOND)
    assert due.is_due(connection, edge)
    assert due.is_due(connection, edge + SECOND)
    assert due.intervals(connection) == (
        collect or due.DEFAULT_COLLECT[kind],
        (activity or due.DEFAULT_ACTIVITY) if kind == "tines" else None,
    )


def test_mc5_a_connection_that_never_ran_is_due_and_a_request_is_due_at_once():
    assert due.due_at(row(), T) == T - timedelta(days=30)
    assert due.is_due(row(), T)
    recent = row(last_run_at=T - timedelta(minutes=1))
    assert not due.is_due(recent, T)
    requested = row(last_run_at=T - timedelta(minutes=1), collect_requested_at=T - SECOND)
    assert due.due_at(requested, T) == T - SECOND
    assert due.is_due(requested, T)
    # A request made after `now` is not yet due.
    assert not due.is_due(row(last_run_at=T, collect_requested_at=T + SECOND), T)


def test_mc5_a_rate_limited_connection_waits_for_the_platforms_retry_after():
    """The platform's Retry-After holds a rate-limited connection past its interval, and past a
    request; a run of any other outcome, or no Retry-After, leaves the interval's rule."""
    last = T - timedelta(minutes=20)
    limited = row(last_run_at=last, last_outcome="RATE_LIMITED", retry_after_seconds=3600)
    assert due.due_at(limited, T) == last + timedelta(hours=1)
    assert not due.is_due(limited, T)
    assert due.is_due(limited, last + timedelta(hours=1))
    asked = row(**{**limited, "collect_requested_at": T - SECOND})
    assert due.due_at(asked, T) == last + timedelta(hours=1)
    # A Retry-After shorter than the interval changes nothing.
    short = row(last_run_at=last, last_outcome="RATE_LIMITED", retry_after_seconds=60)
    assert due.due_at(short, T) == last + timedelta(minutes=15)
    for outcome, retry in (("RATE_LIMITED", None), ("COMPLETE", 3600)):
        other = row(last_run_at=last, last_outcome=outcome, retry_after_seconds=retry)
        assert due.due_at(other, T) == last + timedelta(minutes=15)


def test_mc5_a_held_or_inactive_connection_is_not_due():
    held = row(collecting_until=T + timedelta(minutes=5))
    assert due.due_at(held, T) == T + timedelta(minutes=5)
    assert not due.is_due(held, T)
    # A lease that expired unfinished no longer holds anything back.
    assert due.is_due(row(collecting_until=T - SECOND), T)
    assert due.due_at(row(active=False, revoked_at=T), T) is None
    assert not due.is_due(row(active=False, revoked_at=T), T)


@pytest.fixture
def clock():
    return FixedClock(datetime.now(UTC))


@pytest.fixture
def tines(db, admins, clock):
    return store.create_connection(
        db,
        admins[0],
        label="Synthetic Tines tenant",
        base_url=BASE_URL,
        key_fingerprint=collection.fingerprint(KEY),
        clock=clock,
    )


@pytest.fixture
def entra(db, admins, clock):
    return store.create_connection(
        db,
        admins[0],
        label="Synthetic directory",
        base_url=graph.GRAPH_ORIGIN,
        key_fingerprint=graph.fingerprint(SECRET),
        kind="entra_agent_id",
        directory_ref=DIRECTORY,
        client_ref=CLIENT,
        clock=clock,
    )


def connection_row(admin_engine, tenant, connection):
    with admin_engine.connect() as conn:
        return dict(
            conn.execute(
                text(
                    "SELECT * FROM execbound.monitor_connections "
                    "WHERE tenant_id = :t AND connection_id = :c"
                ),
                {"t": tenant, "c": connection},
            )
            .mappings()
            .one()
        )


def owner_update(admin_engine, tenant, connection, assignments, **values):
    with admin_engine.begin() as conn:
        conn.execute(
            text(
                f"UPDATE execbound.monitor_connections SET {assignments} "  # nosec B608 - test literals
                "WHERE tenant_id = :t AND connection_id = :c"
            ),
            {"t": tenant, "c": connection, **values},
        )


def test_mc6_two_claims_from_two_connections_admit_exactly_one(db, admins, tines):
    """Both transactions call `collector_claim` together; the second waits on the first's row
    lock, which the probe sees, and then finds the lease held."""
    tenant = admins[0].tenant_id
    gate, done = Barrier(2), Event()
    answers = []

    def attempt():
        gate.wait(timeout=5)
        with db.transaction(tenant) as conn:
            answers.append(
                conn.execute(
                    text("SELECT execbound.collector_claim(:c, :l, 600)"),
                    {"c": tines, "l": uuid4()},
                ).scalar_one()
            )
            # Hold the first claim's row lock until the probe has seen the second wait.
            done.wait(timeout=5)

    with ThreadPoolExecutor(max_workers=2) as pool:
        futures = [pool.submit(attempt) for _ in range(2)]
        try:
            blocked_on_a_lock(db.engine)
        finally:
            done.set()
        for future in futures:
            future.result(timeout=10)
    assert sorted(answer["claimed"] for answer in answers) == [False, True]


def test_mc6_a_claim_longer_than_fifteen_minutes_or_shorter_than_one_is_refused(db, admins, tines):
    for seconds in (59, 901):
        with pytest.raises(MonitorError) as refused:
            due.claim(db, admins[0], tines, uuid4(), seconds=seconds)
        assert refused.value.code == "INVALID_INPUT"
    assert due.claim(db, admins[0], tines, uuid4(), seconds=900)
    # Held: a second claim is not admitted while the first's lease runs.
    assert not due.claim(db, admins[0], tines, uuid4())


def test_mc6_an_expired_lease_is_recorded_interrupted_then_claimed(db, admins, admin_engine, tines):
    tenant = admins[0].tenant_id
    first, second = uuid4(), uuid4()
    assert due.claim(db, admins[0], tines, first)
    owner_update(admin_engine, tenant, tines, "collecting_until = now() - interval '1 second'")
    assert due.claim(db, ScheduledActor(tenant), tines, second)
    after = connection_row(admin_engine, tenant, tines)
    assert (after["last_outcome"], after["last_error_code"], after["health_state"]) == (
        "INTERRUPTED",
        "RUN_INTERRUPTED",
        "ERROR",
    )
    assert after["collecting_lease"] == second
    assert after["collecting_until"] > datetime.now(UTC)
    # The run that lost the lease returns nothing to release.
    with pytest.raises(MonitorError) as lost:
        due.release(db, admins[0], tines, first)
    assert lost.value.code == "LEASE_LOST"
    due.release(db, ScheduledActor(tenant), tines, second)
    released = connection_row(admin_engine, tenant, tines)
    assert (released["collecting_until"], released["collecting_lease"]) == (None, None)


def test_mc6_a_run_never_records_its_own_interruption(db, admins, admin_engine, tines):
    """Only a claim that finds a lease expired unfinished records `INTERRUPTED`; a run that
    says so of itself is refused and changes nothing."""
    lease = uuid4()
    assert due.claim(db, admins[0], tines, lease)
    with pytest.raises(MonitorError) as refused:
        store.record_run_outcome(
            db, admins[0], tines, outcome="INTERRUPTED", run_id=uuid4(), lease=lease
        )
    assert refused.value.code == "INVALID_INPUT"
    assert connection_row(admin_engine, admins[0].tenant_id, tines)["last_outcome"] is None
    due.release(db, admins[0], tines, lease)


def writers(entra_connection):
    """Each write a leased run makes to its connection row, as (name, connection, call)."""
    now = datetime.now(UTC)
    return [
        (
            "record_capabilities",
            False,
            lambda db, actor, connection, lease: store.record_capabilities(
                db,
                actor,
                connection,
                {"stories": {"state": "available", "at": now.isoformat()}},
                lease=lease,
            ),
        ),
        (
            "apply_inventory",
            False,
            lambda db, actor, connection, lease: store.apply_inventory(
                db, actor, connection, [], lease=lease
            ),
        ),
        (
            "ingest_collected_page",
            False,
            lambda db, actor, connection, lease: store.ingest_collected_page(
                db, actor, connection, [], lease=lease
            ),
        ),
        (
            "apply_agents",
            True,
            lambda db, actor, connection, lease: store.apply_agents(
                db, actor, connection, [], lease=lease
            ),
        ),
        (
            "record_run_outcome",
            False,
            lambda db, actor, connection, lease: store.record_run_outcome(
                db, actor, connection, outcome="COMPLETE", run_id=uuid4(), lease=lease
            ),
        ),
        # A delta pass's one write to its connection row: the link it advanced, or dropped.
        (
            "record_delta",
            True,
            lambda db, actor, connection, lease: store.record_delta(
                db, actor, connection, None, lease=lease
            ),
        ),
        # A read of the directory's audit log, and a run that does not read it (#355).
        (
            "apply_directory_audit",
            True,
            lambda db, actor, connection, lease: store.apply_directory_audit(
                db, actor, connection, [], cursor=None, lease=lease
            ),
        ),
        (
            "end_audit_episode",
            True,
            lambda db, actor, connection, lease: store.end_audit_episode(
                db, actor, connection, lease=lease
            ),
        ),
    ]


WRITERS = [name for name, _, _ in writers(None)]


def call_writer(name):
    return next((entra, call) for writer, entra, call in writers(None) if writer == name)


@pytest.mark.parametrize("name", WRITERS)
@pytest.mark.parametrize("scheduled", [False, True])
def test_mc6_a_write_with_a_lease_the_connection_no_longer_carries_changes_nothing(
    db, admins, admin_engine, tines, entra, name, scheduled
):
    tenant = admins[0].tenant_id
    on_entra, call = call_writer(name)
    connection = entra if on_entra else tines
    actor = ScheduledActor(tenant) if scheduled else admins[0]
    stale, current = uuid4(), uuid4()
    assert due.claim(db, admins[0], connection, stale)
    owner_update(admin_engine, tenant, connection, "collecting_until = now() - interval '1 second'")
    assert due.claim(db, admins[0], connection, current)
    before = connection_row(admin_engine, tenant, connection)
    with pytest.raises(MonitorError) as lost:
        call(db, actor, connection, stale)
    assert lost.value.code == "LEASE_LOST"
    assert connection_row(admin_engine, tenant, connection) == before
    # The lease the connection carries writes.
    call(db, actor, connection, current)


@pytest.mark.parametrize("name", WRITERS)
def test_mc6_a_revoked_connection_that_still_carries_the_lease_changes_nothing(
    db, admins, admin_engine, tines, entra, name
):
    """Revocation clears the lease too; this row keeps it, written past that, so only the
    write's own `active` condition stands between the run and the revoked connection."""
    tenant = admins[0].tenant_id
    on_entra, call = call_writer(name)
    connection = entra if on_entra else tines
    lease = uuid4()
    assert due.claim(db, admins[0], connection, lease)
    with admin_engine.begin() as conn:
        conn.execute(
            text(
                "ALTER TABLE execbound.monitor_connections "
                "DISABLE TRIGGER monitor_connections_revoked_unleased"
            )
        )
        conn.execute(
            text(
                "UPDATE execbound.monitor_connections SET active = false, revoked_at = now() "
                "WHERE tenant_id = :t AND connection_id = :c"
            ),
            {"t": tenant, "c": connection},
        )
        conn.execute(
            text(
                "ALTER TABLE execbound.monitor_connections "
                "ENABLE TRIGGER monitor_connections_revoked_unleased"
            )
        )
    before = connection_row(admin_engine, tenant, connection)
    assert before["collecting_lease"] == lease
    with pytest.raises(MonitorError) as revoked:
        call(db, ScheduledActor(tenant), connection, lease)
    assert revoked.value.code == "CONNECTION_REVOKED"
    assert connection_row(admin_engine, tenant, connection) == before


def test_mc6_revoking_a_connection_mid_run_clears_the_lease_and_stops_the_run(
    db, admins, admin_engine, tines
):
    tenant = admins[0].tenant_id
    lease = uuid4()
    assert due.claim(db, ScheduledActor(tenant), tines, lease)
    store.revoke_connection(db, admins[0], tines)
    revoked = connection_row(admin_engine, tenant, tines)
    assert (revoked["active"], revoked["collecting_until"], revoked["collecting_lease"]) == (
        False,
        None,
        None,
    )
    with pytest.raises(MonitorError) as stopped:
        store.record_run_outcome(
            db, ScheduledActor(tenant), tines, outcome="COMPLETE", run_id=uuid4(), lease=lease
        )
    assert stopped.value.code == "CONNECTION_REVOKED"
    assert connection_row(admin_engine, tenant, tines) == revoked
    with pytest.raises(MonitorError) as lost:
        due.release(db, ScheduledActor(tenant), tines, lease)
    assert lost.value.code == "LEASE_LOST"


def test_mc5_a_request_made_after_a_claim_survives_that_runs_release(
    db, admins, admin_engine, tines
):
    tenant, actor = admins[0].tenant_id, admins[0].principal_id
    request = "SELECT execbound.admin_request_collection(:a, :c)"
    with db.transaction(tenant) as conn:
        conn.execute(text(request), {"a": actor, "c": tines})
    lease = uuid4()
    # The claim answers the request made before it.
    assert due.claim(db, ScheduledActor(tenant), tines, lease)
    assert connection_row(admin_engine, tenant, tines)["collect_requested_at"] is None
    with db.transaction(tenant) as conn:
        conn.execute(text(request), {"a": actor, "c": tines})
    due.release(db, ScheduledActor(tenant), tines, lease)
    after = connection_row(admin_engine, tenant, tines)
    assert after["collect_requested_at"] is not None
    assert after["collect_requested_by"] == actor
    # So the next pass picks it up.
    assert due.is_due(after, datetime.now(UTC))


def test_mc6_the_scheduled_actor_collects_with_the_key_file_inside_its_lease(
    db, admins, admin_engine, tines, clock, tmp_path
):
    tenant = admins[0].tenant_id
    key_file = tmp_path / f"{tines}.env"
    key_file.write_text(f"TINES_BASE_URL={BASE_URL}\nTINES_API_KEY={KEY}\n", encoding="utf-8")
    key = TinesConfig.from_file(key_file)
    with serving(scenario(clock.now())) as server, client(server) as http:
        result = due.claim_and_run(
            db,
            ScheduledActor(tenant),
            tines,
            lambda lease: collection.run(
                db,
                ScheduledActor(tenant),
                connection_id=tines,
                api_key=key.api_key,
                client=http,
                clock=clock,
                lease=lease,
            ),
        )
    assert result is not None and result["outcome"] == "COMPLETE"
    assert result["audit"]["accepted"] > 0
    after = connection_row(admin_engine, tenant, tines)
    assert after["last_outcome"] == "COMPLETE"
    assert (after["collecting_until"], after["collecting_lease"]) == (None, None)
    with admin_engine.connect() as conn:
        # Collection appends no audit event, so the scheduled pass never made the
        # workspace's scheduler principal.
        assert (
            conn.execute(
                text(
                    "SELECT count(*) FROM execbound.principals "
                    "WHERE tenant_id = :t AND kind = 'SYSTEM'"
                ),
                {"t": tenant},
            ).scalar_one()
            == 0
        )


def test_mc6_the_scheduled_actor_is_refused_without_a_lease_another_fence_or_an_active_workspace(
    db, admins, admin_engine, tines, clock
):
    tenant, other = admins[0].tenant_id, admins[1].tenant_id
    actor = ScheduledActor(tenant)
    # Without a lease, every collection writer refuses it.
    for name in WRITERS:
        with pytest.raises(MonitorError) as refused:
            call_writer(name)[1](db, actor, tines, None)
        assert refused.value.code == "INVALID_ADMIN", name
    # Under another workspace's fence.
    with pytest.raises(MonitorError) as foreign:
        with db.transaction(other) as conn:
            store._check_actor(conn, actor, clock)
    assert foreign.value.code == "INVALID_ADMIN"
    with db.transaction(tenant) as conn:
        store._check_actor(conn, actor, clock)
    # In a workspace that is no longer active, even with the lease it took while it was.
    lease = uuid4()
    assert due.claim(db, actor, tines, lease)
    with admin_engine.begin() as conn:
        conn.execute(
            text("UPDATE execbound.tenants SET active = false WHERE tenant_id = :t"), {"t": tenant}
        )
    with pytest.raises(MonitorError) as inactive:
        store.record_run_outcome(
            db, actor, tines, outcome="COMPLETE", run_id=uuid4(), lease=lease, clock=clock
        )
    assert inactive.value.code == "INVALID_ADMIN"
    with pytest.raises(MonitorError) as unclaimed:
        due.claim(db, actor, tines, uuid4())
    assert unclaimed.value.code == "INVALID_ADMIN"


# The steps of a run that write no connection row prove the lease on the locked row instead.
READERS = {
    "load_connection": (
        False,
        lambda db, actor, connection, lease: store.load_connection(
            db, actor, connection, lease=lease
        ),
    ),
    "reconcile_coverage": (
        False,
        lambda db, actor, connection, lease: store.reconcile_coverage(
            db, actor, connection, lease=lease
        ),
    ),
    "apply_agent_detail": (
        True,
        lambda db, actor, connection, lease: store.apply_agent_detail(
            db, actor, connection, [], lease=lease
        ),
    ),
    "evaluate_agents": (
        True,
        lambda db, actor, connection, lease: store.evaluate_agents(
            db, actor, connection, lease=lease
        ),
    ),
    # What a delta pass reads of the principals it lists, and its changes to them (#355).
    "held_agents": (
        True,
        lambda db, actor, connection, lease: store.held_agents(
            db, actor, connection, [], lease=lease
        ),
    ),
    "apply_agent_changes": (
        True,
        lambda db, actor, connection, lease: store.apply_agent_changes(
            db, actor, connection, [], [], lease=lease
        ),
    ),
}


@pytest.mark.parametrize("name", sorted(READERS))
def test_mc6_every_other_step_of_a_run_refuses_a_lost_lease_and_a_revoked_connection(
    db, admins, admin_engine, tines, entra, name
):
    tenant = admins[0].tenant_id
    on_entra, call = READERS[name]
    connection = entra if on_entra else tines
    actor = ScheduledActor(tenant)
    lease = uuid4()
    assert due.claim(db, actor, connection, lease)
    with pytest.raises(MonitorError) as lost:
        call(db, actor, connection, uuid4())
    assert lost.value.code == "LEASE_LOST"
    with pytest.raises(MonitorError) as unleased:
        call(db, actor, connection, None)
    assert unleased.value.code == "INVALID_ADMIN"
    call(db, actor, connection, lease)
    store.revoke_connection(db, admins[0], connection)
    with pytest.raises(MonitorError) as revoked:
        call(db, actor, connection, lease)
    assert revoked.value.code == "CONNECTION_REVOKED"


# The overdue rule for a connection the scheduled collector opens itself: twice its own
# interval, or a day, whichever is shorter. A `key_file` connection keeps the day, because
# whether the collector holds its file is not something the database knows.
# (credential mode, kind, collect interval, activity interval, when it is overdue)
OVERDUE = [
    ("sealed", "tines", None, None, timedelta(minutes=30)),
    ("sealed", "tines", None, 3600, timedelta(hours=2)),
    ("sealed", "tines", 86400, 300, timedelta(minutes=10)),
    ("key_file", "tines", None, None, timedelta(days=1)),
    ("key_file", "tines", None, 300, timedelta(days=1)),
    ("key_file", "entra_agent_id", None, None, timedelta(days=1)),
    ("key_file", "entra_agent_id", 3600, None, timedelta(days=1)),
    ("platform_app", "entra_agent_id", None, None, timedelta(hours=12)),
    ("platform_app", "entra_agent_id", 86400, None, timedelta(days=1)),
]


def overdue_row(mode, kind, collect, activity, **changes):
    return {
        **row(
            kind=kind,
            credential_mode=mode,
            collect_interval_seconds=collect,
            activity_interval_seconds=activity,
        ),
        "last_sync_at": None,
        **changes,
    }


@pytest.mark.parametrize("mode,kind,collect,activity,after", OVERDUE)
@pytest.mark.parametrize("outcome", ["COMPLETE", "BACKLOG", "ERROR", "RATE_LIMITED"])
def test_mc5_a_scheduled_connection_is_overdue_on_its_own_schedule(
    mode, kind, collect, activity, after, outcome
):
    """After its last run of any outcome, and not one second before; an error inside that
    is an error, not a stalled collector."""
    last = T - timedelta(days=3)
    connection = overdue_row(mode, kind, collect, activity, last_run_at=last, last_outcome=outcome)
    assert store.collection_overdue_since(connection, last + after - SECOND) is None
    assert store.collection_overdue_since(connection, last + after) == last + after
    assert store.collection_overdue_since(connection, last + after + SECOND) == last + after
    # Never ran: from its registration.
    created = T - timedelta(days=2)
    fresh = overdue_row(mode, kind, collect, activity, created_at=created)
    assert store.collection_overdue_since(fresh, created + after - SECOND) is None
    assert store.collection_overdue_since(fresh, created + after) == created + after


def insert_overdue(admin_engine, admin, mode, kind, collect, activity, last_run_at, space):
    """One connection row with this evidence, written by the owner."""
    connection = uuid4()
    entra = kind == "entra_agent_id"
    with admin_engine.begin() as conn:
        conn.execute(
            text("SELECT set_config('execbound.tenant_id', :t, true)"),
            {"t": str(admin.tenant_id)},
        )
        conn.execute(
            text(
                "INSERT INTO execbound.monitor_connections (tenant_id, connection_id, label, "
                "base_url, key_fingerprint, created_at, created_by, space_id, kind, "
                "directory_ref, client_ref, credential_mode, sealed_ct, sealed_key_id, "
                "consented_at, consented_by, "
                "collect_interval_seconds, activity_interval_seconds, last_run_at, last_outcome) "
                "VALUES (:t, :c, 'Overdue', :u, :k, :created, :p, :s, :kind, :dir, :client, "
                ":mode, :ct, :kid, :consented, :consenter, :collect, :activity, :last, "
                "'COMPLETE')"
            ),
            {
                "t": admin.tenant_id,
                "c": connection,
                "u": graph.GRAPH_ORIGIN if entra else BASE_URL,
                # A consented directory is read with the deployment's own app: no key, and
                # the consent it was given.
                "k": None if mode == "platform_app" else "0" * 64,
                "consented": last_run_at - timedelta(days=1) if mode == "platform_app" else None,
                "consenter": admin.principal_id if mode == "platform_app" else None,
                "created": last_run_at - timedelta(days=1),
                "p": admin.principal_id,
                "s": space,
                "kind": kind,
                "dir": DIRECTORY if entra else None,
                "client": CLIENT if entra else None,
                "mode": mode,
                "ct": b"\x01" * 48 if mode == "sealed" else None,
                "kid": "ck1-0123456789abcdef" if mode == "sealed" else None,
                "collect": collect,
                "activity": activity,
                "last": last_run_at,
            },
        )
    return connection


@pytest.mark.parametrize("mode,kind,collect,activity,after", OVERDUE)
def test_mc5_the_overdue_count_and_the_rule_agree_at_every_edge(
    db, admin_engine, admins, mode, kind, collect, activity, after
):
    """`OVERDUE_CONNECTIONS`, which the tenant view and Home count with, calls a connection
    overdue exactly when `collection_overdue_since` does, so the two cannot drift."""
    admin = admins[0]
    last = T - timedelta(days=3)
    with admin_engine.connect() as conn:
        space = conn.execute(
            text(
                "SELECT space_id FROM execbound.spaces WHERE tenant_id = :t "
                "ORDER BY created_at, space_id LIMIT 1"
            ),
            {"t": admin.tenant_id},
        ).scalar_one()
    connection = insert_overdue(admin_engine, admin, mode, kind, collect, activity, last, space)
    with admin_engine.connect() as conn:
        stored = dict(
            conn.execute(
                text(
                    "SELECT * FROM execbound.monitor_connections "
                    "WHERE tenant_id = :t AND connection_id = :c"
                ),
                {"t": admin.tenant_id, "c": connection},
            )
            .mappings()
            .one()
        )
    for now in (last + after - SECOND, last + after, last + after + SECOND):
        with db.transaction(admin.tenant_id) as conn:
            counted = conn.execute(
                text(store.OVERDUE_CONNECTIONS + " AND e.connection_id = :c"),
                {"t": admin.tenant_id, "c": connection, **store.overdue_bounds(now)},
            ).scalar_one()
        overdue = store.collection_overdue_since(stored, now)
        assert bool(counted) is (overdue is not None), now
        assert bool(counted) is (now >= last + after), now


def test_mc5_the_overdue_rules_default_intervals_are_the_schedules():
    """The SQL twin writes the kinds' default intervals as numbers; they are the ones the
    schedule reads."""
    assert due.DEFAULT_ACTIVITY == 900
    assert due.DEFAULT_COLLECT["entra_agent_id"] == 21600
    assert "900" in store.OVERDUE_CONNECTIONS and "21600" in store.OVERDUE_CONNECTIONS
