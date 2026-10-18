# SPDX-License-Identifier: AGPL-3.0-only
"""Retention of directory audit observations and the observation bound (#355): SR24.

Real PostgreSQL and the fake Graph. The scheduled `process` pass purges a Microsoft Entra
connection's audit observations once they are older than the thirty days evidence stays current,
through a definer function the runtime may execute and no `DELETE` grant: never one a finding
cites, never one still to be evaluated, never one current by the database's own clock, never a
baseline actor's earliest baseline observation of an action, and never one whose deletion would
leave an observation that stays the only one its execution accounts for. A connection at its
observation bound reads on: each actor's first current observation of each action is kept, a
principal's repeat when its reach would otherwise lapse, an actor not yet inventoried within the
inventory's limit, and only entries whose absence changes nothing the rules or reach read are
dropped.
"""

import io
import json
import logging
import threading
import time
from datetime import UTC, timedelta
from uuid import uuid4

import httpx
import pytest
from sqlalchemy import text
from sqlalchemy.exc import DBAPIError, OperationalError
from test_monitor_collect_due import key_file
from test_scout_audit import (
    ACTOR,
    OTHER_ACTOR,
    OTHER_TARGET,
    TARGET,
    directory,
    entry,
    executed,
    first_read,
    health,
    later,
    observations,
)
from test_scout_audit import admins as admins
from test_scout_audit import clock as clock
from test_scout_delta import connection_row, findings, full, profile, reaching
from test_scout_run import connect, principal

from execbound import logging_schema
from execbound.execution.scheduled import ScheduledActor
from execbound.monitoring import due, graph, reach, store, worker
from execbound.monitoring.delivery import LocalReceiver
from execbound.monitoring.models import MonitorError
from execbound_harness.fake_graph import serving, transport

pytestmark = pytest.mark.integration

MONTH = timedelta(days=31)
MINUTE = timedelta(minutes=1)
OTHER_DIRECTORY = "22222222-3333-4444-5555-666666666666"
THIRD_DIRECTORY = "33333333-4444-5555-6666-777777777777"
STRANGER = "cccccccc-0000-4000-8000-000000000099"
OTHER_STRANGER = "cccccccc-0000-4000-8000-000000000098"
# A principal created after the connection's last full collection, which the next inventories.
NEWCOMER = principal(11)["id"]
# The new title a bound episode's finding carries (decided on 17 October 2026).
BOUND_TITLE = (
    "Collection reached the connection's observation bound and keeps only each actor's first action"
)


def target(index):
    """A user's object id, apart from `TARGET` and `OTHER_TARGET`."""
    return f"dadadada-0000-4000-8000-{index:012d}"


# The moments a workspace's Scout evidence holds. `elapse` moves them back, so that time passes
# for the evidence while the test's clock and the database's stay where they are. The
# connection's collection record (its cursor, its runs and its schedule) stays: collection kept
# up meanwhile and the directory logged nothing.
CONNECTION_MOMENTS = ("baseline_at", "audit_baseline_at", "audit_behind_since", "audit_bound_since")
EVIDENCE_TABLES = (
    "monitor_observations",
    "monitor_findings",
    "monitor_agents",
    "monitor_agent_grants",
    "monitor_agent_reach",
)


def elapse(admin_engine, tenant, period):
    with admin_engine.begin() as conn:
        for table in (*EVIDENCE_TABLES, "monitor_connections"):
            columns = [
                column
                for column in conn.execute(
                    text(
                        "SELECT column_name FROM information_schema.columns "
                        "WHERE table_schema = 'execbound' AND table_name = :table "
                        "AND data_type = 'timestamp with time zone'"
                    ),
                    {"table": table},
                ).scalars()
                if table != "monitor_connections" or column in CONNECTION_MOMENTS
            ]
            moved = ", ".join(f"{column} = {column} - :period" for column in columns)
            conn.execute(
                text(f"UPDATE execbound.{table} SET {moved} WHERE tenant_id = :t"),
                {"period": period, "t": tenant},
            )


def dump(admin_engine, tenant):
    """Every observation and finding the workspace holds, each row whole, as text."""
    with admin_engine.connect() as conn:
        return {
            table: {
                str(row[key]): json.dumps({k: str(v) for k, v in row.items()}, sort_keys=True)
                for row in conn.execute(
                    text(f"SELECT * FROM execbound.{table} WHERE tenant_id = :t"), {"t": tenant}
                ).mappings()
            }
            for table, key in (
                ("monitor_observations", "observation_id"),
                ("monitor_findings", "finding_id"),
            )
        }


def held(admin_engine, tenant):
    with admin_engine.connect() as conn:
        return set(
            conn.execute(
                text(
                    "SELECT observation_id FROM execbound.monitor_observations "
                    "WHERE tenant_id = :t AND kind = 'entra_audit'"
                ),
                {"t": tenant},
            ).scalars()
        )


def by_ref(db, tenant):
    """The workspace's audit observations, by the entry id each was read from."""
    return {row["external_ref"]: row["observation_id"] for row in observations(db, tenant)}


def purge(db, tenant, clock):
    """The scheduled pass's purge in one workspace."""
    return store.purge_audit_observations(db, ScheduledActor(tenant), clock=clock)["purged"]


def call(db, tenant, connection_id, ids):
    """The definer function, as the runtime calls it, inside `tenant`'s fence."""
    with db.transaction(tenant) as conn:
        return conn.execute(
            text("SELECT execbound.monitor_audit_purge(:c, CAST(:ids AS uuid[]))"),
            {"c": connection_id, "ids": None if ids is None else [str(i) for i in ids]},
        ).scalar_one()


def stored(
    admin_engine, tenant, connection_id, *, age, state="COMPLETED", actor=ACTOR, kind="entra_audit"
):
    """One collected observation, by default of the directory's audit log, written directly,
    `age` before the database's own clock, for what only the function's own conditions decide.
    Only an audit observation names a target."""
    observation, event = uuid4(), f"audit:{uuid4()}"
    with admin_engine.begin() as conn:
        conn.execute(
            text(
                "INSERT INTO execbound.monitor_observations "
                "(tenant_id, observation_id, connection_id, event_id, version, content_hash, "
                " occurred_at, received_at, kind, action, outcome, target_ref, "
                " evaluation_state, evaluation_result, evaluated_at, operation_name, "
                " external_ref, evidence, actor_ref, rule_version, space_id) "
                "SELECT :t, :o, :c, :e, 1, :digest, now() - :age, now() - :age, :kind, "
                " 'identity.disable', 'success', :target, :state, "
                " CASE WHEN :state = 'COMPLETED' THEN 'NO_MATCH' END, "
                " CASE WHEN :state = 'COMPLETED' THEN now() END, "
                " 'entra-audit.v1:disable_account', :ref, 'collected', :actor, "
                " 'sensitive-action.v2', m.space_id "
                "FROM execbound.monitor_connections m WHERE m.connection_id = :c"
            ),
            {
                "t": tenant,
                "o": observation,
                "c": connection_id,
                "e": event,
                "digest": "ab" * 32,
                "age": age,
                "kind": kind,
                "target": target(900) if kind == "entra_audit" else None,
                "state": state,
                "ref": f"Directory_{uuid4()}_ABCDE_12345678",
                "actor": actor,
            },
        )
    return observation


# SR24: the purge


def test_sr24_the_purge_removes_old_uncited_audit_observations_and_nothing_else(
    db, admins, admin_engine, clock
):
    """Once a month has passed, the pass removes what no rule reads any more: a habit's repeats,
    a refused attempt and an action whose first is what the finding cites. It keeps what a
    finding cites and the finding, byte for byte; what is still current; what is still to be
    evaluated; the baseline actor's earliest baseline observation; and every other workspace's.
    """
    admin, other = admins
    profile(db, admin, clock)
    connection_id = connect(db, admin, clock)
    tenant = admin.tenant_id
    hour = timedelta(hours=1)
    habit = [
        entry(clock.value - 3 * hour + index * MINUTE, target=target(index)) for index in (1, 2, 3)
    ]
    refused = entry(clock.value - 2 * hour, result="failure", target=OTHER_TARGET)
    with serving(directory(*habit, refused)) as server:
        first_read(db, admin, clock, connection_id, server)
        news = entry(clock.value + 2 * MINUTE, actor=OTHER_ACTOR, target=OTHER_TARGET)
        repeat = entry(clock.value + 3 * MINUTE, actor=OTHER_ACTOR, target=TARGET)
        later(db, admin, clock, connection_id, server, [news, repeat])
        clock.value += 5 * MINUTE
        result = worker.evaluate_scheduled(db, tenant, clock=clock)
        assert (result["actions"], result["purged"]) == (1, 0)
        elapse(admin_engine, tenant, MONTH)
        acting = entry(clock.value - MINUTE, target=target(4))
        later(db, admin, clock, connection_id, server, [acting])
    waiting = stored(admin_engine, tenant, connection_id, age=MONTH, state="PENDING")
    # Another workspace's own directory, with a month-old habit of its own.
    profile(db, other, clock)
    elsewhere = connect(db, other, clock, directory_ref=OTHER_DIRECTORY)
    theirs = [entry(clock.value - hour + index * MINUTE, target=target(index)) for index in (1, 2)]
    with serving(directory(*theirs, organization=OTHER_DIRECTORY)) as server:
        first_read(db, other, clock, elsewhere, server)
    worker.evaluate_scheduled(db, other.tenant_id, clock=clock)
    elapse(admin_engine, other.tenant_id, MONTH)
    refs = by_ref(db, tenant)
    (raised,) = findings(db, tenant, "first-consequential-action.v1")
    assert raised["observation_id"] == refs[news["id"]]
    before, before_other = dump(admin_engine, tenant), dump(admin_engine, other.tenant_id)
    assert purge(db, tenant, clock) == 4
    after = dump(admin_engine, tenant)
    gone = {refs[record["id"]] for record in (habit[1], habit[2], refused, repeat)}
    assert set(before["monitor_observations"]) - set(after["monitor_observations"]) == {
        str(observation) for observation in gone
    }
    # What stays is unchanged, byte for byte, and so is every finding.
    assert after["monitor_observations"] == {
        key: value
        for key, value in before["monitor_observations"].items()
        if key not in {str(g) for g in gone}
    }
    assert after["monitor_findings"] == before["monitor_findings"]
    kept = held(admin_engine, tenant)
    assert {refs[habit[0]["id"]], refs[news["id"]], refs[acting["id"]], waiting} <= kept
    # Nothing in the other workspace moved, and a second pass finds nothing more.
    assert dump(admin_engine, other.tenant_id) == before_other
    assert purge(db, tenant, clock) == 0


def test_sr24_a_baseline_actor_stays_the_habit_once_its_observations_are_a_month_old(
    db, admins, admin_engine, clock
):
    """The activity baseline survives the purge: the actor's earliest baseline observation of
    each action is kept, so the habit acting again a month later raises nothing, while an actor
    never seen acting raises the rule. Without that one observation the habit would be news."""
    admin = admins[0]
    profile(db, admin, clock)
    connection_id = connect(db, admin, clock)
    tenant = admin.tenant_id
    habit = [
        entry(clock.value - timedelta(hours=2) + index * MINUTE, target=target(index))
        for index in (1, 2, 3)
    ]
    reset = entry(clock.value - timedelta(hours=1), activity="Reset password", target=target(5))
    with serving(directory(*habit, reset)) as server:
        first_read(db, admin, clock, connection_id, server)
        clock.value += MINUTE
        assert worker.evaluate_scheduled(db, tenant, clock=clock)["actions"] == 0
        elapse(admin_engine, tenant, MONTH)
        refs = by_ref(db, tenant)
        assert worker.evaluate_scheduled(db, tenant, clock=clock)["purged"] == 2
        assert held(admin_engine, tenant) == {refs[habit[0]["id"]], refs[reset["id"]]}
        later(
            db,
            admin,
            clock,
            connection_id,
            server,
            [
                entry(clock.value + MINUTE, target=target(6)),
                entry(clock.value + MINUTE, actor=OTHER_ACTOR, target=OTHER_TARGET),
            ],
        )
    clock.value += 2 * MINUTE
    assert worker.evaluate_scheduled(db, tenant, clock=clock)["actions"] == 1
    (raised,) = findings(db, tenant, "first-consequential-action.v1")
    assert raised["platform_ref"] == OTHER_ACTOR
    # The kept observations are what hold the habit: without them it is news.
    with admin_engine.begin() as conn:
        conn.execute(
            text("DELETE FROM execbound.monitor_observations WHERE observation_id = ANY(:o)"),
            {"o": [refs[habit[0]["id"]], refs[reset["id"]]]},
        )
    assert store.evaluate_actions(db, admin, clock=clock)["raised"] == 1


def test_sr24_a_gone_principals_baseline_observation_is_kept_too(db, admins, admin_engine, clock):
    """The keeper covers every principal the connection holds, live or gone: a principal the
    directory has since removed, and that may return from its recycle bin as the same row, keeps
    its earliest baseline observation of each action, and only its later ones are purged."""
    admin = admins[0]
    profile(db, admin, clock)
    connection_id = connect(db, admin, clock)
    tenant = admin.tenant_id
    habit = [
        entry(clock.value - timedelta(hours=2) + index * MINUTE, target=target(index))
        for index in (1, 2)
    ]
    with serving(directory(*habit)) as server:
        first_read(db, admin, clock, connection_id, server)
    clock.value += MINUTE
    assert worker.evaluate_scheduled(db, tenant, clock=clock)["actions"] == 0
    with admin_engine.begin() as conn:
        gone = conn.execute(
            text(
                "UPDATE execbound.monitor_agents SET gone_at = now() "
                "WHERE tenant_id = :t AND platform_ref = :a AND gone_at IS NULL"
            ),
            {"t": tenant, "a": ACTOR},
        ).rowcount
    assert gone == 1
    elapse(admin_engine, tenant, MONTH)
    refs = by_ref(db, tenant)
    assert worker.evaluate_scheduled(db, tenant, clock=clock)["purged"] == 1
    assert held(admin_engine, tenant) == {refs[habit[0]["id"]]}


@pytest.mark.parametrize("current", ["read before the purge", "read after it"])
def test_sr24_an_old_observation_sharing_an_execution_with_a_current_one_is_kept(
    db, admins, admin_engine, clock, current
):
    """Two observations one execution accounts for are both reported, as ruled. Deleting the old
    one would leave the current one the only observation its execution accounts for, taken for
    ExecBound's own execution and its actor's action outside ExecBound hidden, so the purge keeps
    it while the other stays, and while the execution's window reaches into the thirty days,
    whether or not the current one has been read yet."""
    admin = admins[0]
    profile(db, admin, clock)
    connection_id = connect(db, admin, clock)
    tenant = admin.tenant_id
    # The other actor's habit: its earliest, the baseline keeper, and one beside it on TARGET.
    keeper = entry(clock.value - timedelta(hours=3), actor=OTHER_ACTOR, target=OTHER_TARGET)
    beside = entry(clock.value - timedelta(hours=2), actor=OTHER_ACTOR, target=TARGET)
    with serving(directory(keeper, beside)) as server:
        first_read(db, admin, clock, connection_id, server)
        clock.value += MINUTE
        worker.evaluate_scheduled(db, tenant, clock=clock)
        elapse(admin_engine, tenant, MONTH)
        refs = by_ref(db, tenant)
        old = observations(db, tenant)
        (moved,) = [row for row in old if row["observation_id"] == refs[beside["id"]]]
        # An execution whose window runs from before the old entry to now: one that settled a
        # month after its dispatch, as a reconciled one may.
        dispatched = moved["occurred_at"] - MINUTE
        execution = executed(admin_engine, admin, dispatched, target=TARGET)
        with admin_engine.begin() as conn:
            conn.execute(
                text("UPDATE execbound.executions SET changed_at = :s WHERE execution_id = :e"),
                {"s": clock.value, "e": execution},
            )
        acting = entry(clock.value - 5 * MINUTE)
        if current == "read after it":
            assert worker.evaluate_scheduled(db, tenant, clock=clock)["purged"] == 0
        later(db, admin, clock, connection_id, server, [acting])
    clock.value += MINUTE
    result = worker.evaluate_scheduled(db, tenant, clock=clock)
    assert result["actions"] == 1
    (raised,) = findings(db, tenant, "first-consequential-action.v1")
    current = by_ref(db, tenant)[acting["id"]]
    assert (raised["platform_ref"], raised["observation_id"]) == (ACTOR, current)
    # The keeper and the old observation beside the execution both stay.
    assert {refs[keeper["id"]], refs[beside["id"]], current} == held(admin_engine, tenant)
    assert result["purged"] == 0
    assert store.evaluate_actions(db, admin, clock=clock)["closed"] == 0
    # Removed by hand, the current action would be taken for ExecBound's own and its episode
    # would close.
    with admin_engine.begin() as conn:
        conn.execute(
            text("DELETE FROM execbound.monitor_observations WHERE observation_id = :o"),
            {"o": refs[beside["id"]]},
        )
    assert store.evaluate_actions(db, admin, clock=clock)["closed"] == 1


def test_sr24_an_old_observation_sharing_an_old_execution_with_a_keeper_is_kept(
    db, admins, admin_engine, clock
):
    """An execution that settled more than a month ago accounts for two old observations: a
    baseline actor's earliest, which the purge keeps as that actor's baseline, and another
    actor's entry beside it. No open execution's window reaches either, but removing the other
    one would leave the keeper the one observation that execution accounts for, taken for
    ExecBound's own, and the baseline actor's habit then news; so the purge keeps it while the
    keeper stays."""
    admin = admins[0]
    profile(db, admin, clock)
    connection_id = connect(db, admin, clock)
    tenant = admin.tenant_id
    keeper = entry(clock.value - timedelta(hours=2), actor=OTHER_ACTOR)
    beside = entry(clock.value - timedelta(hours=2) + timedelta(seconds=1), actor=STRANGER)
    with serving(directory(keeper, beside)) as server:
        first_read(db, admin, clock, connection_id, server)
        clock.value += MINUTE
        assert worker.evaluate_scheduled(db, tenant, clock=clock)["actions"] == 0
        elapse(admin_engine, tenant, MONTH)
        refs = by_ref(db, tenant)
        # Dispatched a minute before the keeper and settled moments later, a month ago.
        executed(admin_engine, admin, occurred(db, tenant, refs[keeper["id"]]) - MINUTE)
        assert worker.evaluate_scheduled(db, tenant, clock=clock)["purged"] == 0
        assert held(admin_engine, tenant) == {refs[keeper["id"]], refs[beside["id"]]}
        later(
            db,
            admin,
            clock,
            connection_id,
            server,
            [entry(clock.value + MINUTE, actor=OTHER_ACTOR, target=OTHER_TARGET)],
        )
    clock.value += 2 * MINUTE
    assert worker.evaluate_scheduled(db, tenant, clock=clock)["actions"] == 0
    assert findings(db, tenant, "first-consequential-action.v1") == []
    # Removed by hand, the keeper would be the execution's own and the habit news.
    with admin_engine.begin() as conn:
        conn.execute(
            text("DELETE FROM execbound.monitor_observations WHERE observation_id = :o"),
            {"o": refs[beside["id"]]},
        )
    assert store.evaluate_actions(db, admin, clock=clock)["raised"] == 1


def test_sr24_an_old_observation_sharing_an_old_execution_with_one_an_open_one_keeps_is_kept(
    db, admins, admin_engine, clock
):
    """An execution that settled more than a month ago accounts for two old observations: a
    stranger's, which nothing else keeps, and a baseline actor's only baseline observation. A
    second execution, dispatched between them and not yet settled, could account for the
    actor's, so the purge keeps it and it is not the actor's keeper. Removing the stranger's
    would leave the actor's the one observation the settled execution accounts for, taken for
    ExecBound's own, and the actor's habit then news; so the purge keeps it while the other
    stays."""
    admin = admins[0]
    profile(db, admin, clock)
    connection_id = connect(db, admin, clock)
    tenant = admin.tenant_id
    beside = entry(clock.value - timedelta(hours=3), actor=STRANGER)
    habit = entry(clock.value - timedelta(hours=3) + 30 * MINUTE)
    with serving(directory(beside, habit)) as server:
        first_read(db, admin, clock, connection_id, server)
        clock.value += MINUTE
        assert worker.evaluate_scheduled(db, tenant, clock=clock)["actions"] == 0
        elapse(admin_engine, tenant, MONTH)
        refs = by_ref(db, tenant)
        start = occurred(db, tenant, refs[beside["id"]])
        # Dispatched a minute before the stranger's entry and settled a minute after the
        # habit's, a month ago.
        settled = executed(admin_engine, admin, start - MINUTE)
        settle(admin_engine, settled, occurred(db, tenant, refs[habit["id"]]) + MINUTE)
        # Its window, open until it settles, starts after the stranger's entry.
        executed(admin_engine, admin, start + 20 * MINUTE, state="INDETERMINATE")
        assert worker.evaluate_scheduled(db, tenant, clock=clock)["purged"] == 0
        assert held(admin_engine, tenant) == {refs[beside["id"]], refs[habit["id"]]}
        later(
            db, admin, clock, connection_id, server, [entry(clock.value + MINUTE, target=target(6))]
        )
    clock.value += 2 * MINUTE
    assert worker.evaluate_scheduled(db, tenant, clock=clock)["actions"] == 0
    assert findings(db, tenant, "first-consequential-action.v1") == []
    # Removed by hand, the habit's would be the settled execution's own and the habit news.
    with admin_engine.begin() as conn:
        conn.execute(
            text("DELETE FROM execbound.monitor_observations WHERE observation_id = :o"),
            {"o": refs[beside["id"]]},
        )
    assert store.evaluate_actions(db, admin, clock=clock)["raised"] == 1


def settle(admin_engine, execution, at):
    """The execution settles `EXECUTED` at `at`, as reconciliation settles an unsettled one, or
    its settlement is moved to `at`."""
    with admin_engine.begin() as conn:
        conn.execute(
            text(
                "UPDATE execbound.executions SET state = 'EXECUTED', changed_at = :s "
                "WHERE execution_id = :e"
            ),
            {"s": at, "e": execution},
        )


def occurred(db, tenant, observation):
    (row,) = [row for row in observations(db, tenant) if row["observation_id"] == observation]
    return row["occurred_at"]


def test_sr24_an_old_observation_an_unsettled_execution_could_account_for_is_kept(
    db, admins, admin_engine, clock
):
    """An execution still unsettled when the purge runs may settle later, its window then
    reaching from its dispatch to its settlement. The purge keeps every old observation it could
    account for, so once it settles an action another actor takes on its target meanwhile is not
    the one observation it accounts for, and is reported."""
    admin = admins[0]
    profile(db, admin, clock)
    connection_id = connect(db, admin, clock)
    tenant = admin.tenant_id
    keeper = entry(clock.value - timedelta(hours=3), target=OTHER_TARGET)
    own = entry(clock.value - timedelta(hours=2))
    with serving(directory(keeper, own)) as server:
        first_read(db, admin, clock, connection_id, server)
        clock.value += MINUTE
        worker.evaluate_scheduled(db, tenant, clock=clock)
        elapse(admin_engine, tenant, MONTH)
        refs = by_ref(db, tenant)
        dispatched = occurred(db, tenant, refs[own["id"]]) - MINUTE
        execution = executed(admin_engine, admin, dispatched, target=TARGET, state="INDETERMINATE")
        assert worker.evaluate_scheduled(db, tenant, clock=clock)["purged"] == 0
        assert held(admin_engine, tenant) == {refs[keeper["id"]], refs[own["id"]]}
        settle(admin_engine, execution, clock.value)
        theirs = entry(clock.value - 5 * MINUTE, actor=OTHER_ACTOR)
        later(db, admin, clock, connection_id, server, [theirs])
    clock.value += MINUTE
    assert worker.evaluate_scheduled(db, tenant, clock=clock)["actions"] == 1
    (raised,) = findings(db, tenant, "first-consequential-action.v1")
    assert (raised["platform_ref"], raised["observation_id"]) == (
        OTHER_ACTOR,
        by_ref(db, tenant)[theirs["id"]],
    )


def test_sr24_the_baseline_kept_is_one_no_unsettled_execution_could_account_for(
    db, admins, admin_engine, clock
):
    """A baseline actor's earliest baseline observation may be the entry of an execution that
    has not settled; once it settles, that observation is the one it accounts for, ExecBound's
    own and no longer the actor's habit. So the purge keeps that observation while the execution
    is unsettled, and keeps as the actor's baseline the earliest no unsettled execution could
    account for, and the actor is still its habit once the execution settles."""
    admin = admins[0]
    profile(db, admin, clock)
    connection_id = connect(db, admin, clock)
    tenant = admin.tenant_id
    own = entry(clock.value - timedelta(hours=3))
    habit = [
        entry(clock.value - timedelta(hours=2) + index * MINUTE, target=target(index))
        for index in (1, 2)
    ]
    with serving(directory(own, *habit)) as server:
        first_read(db, admin, clock, connection_id, server)
        clock.value += MINUTE
        assert worker.evaluate_scheduled(db, tenant, clock=clock)["actions"] == 0
        elapse(admin_engine, tenant, MONTH)
        refs = by_ref(db, tenant)
        dispatched = occurred(db, tenant, refs[own["id"]]) - MINUTE
        execution = executed(admin_engine, admin, dispatched, target=TARGET, state="INDETERMINATE")
        assert worker.evaluate_scheduled(db, tenant, clock=clock)["purged"] == 1
        assert held(admin_engine, tenant) == {refs[own["id"]], refs[habit[0]["id"]]}
        settle(admin_engine, execution, clock.value)
        later(
            db, admin, clock, connection_id, server, [entry(clock.value + MINUTE, target=target(6))]
        )
    clock.value += 2 * MINUTE
    assert worker.evaluate_scheduled(db, tenant, clock=clock)["actions"] == 0
    assert findings(db, tenant, "first-consequential-action.v1") == []


def waiting_on(admin_engine, pid):
    """Whether a backend comes to wait on a lock the backend `pid` holds, within 30 seconds,
    polled one statement a transaction so each poll reads `pg_stat_activity` afresh."""
    deadline = time.monotonic() + 30
    with admin_engine.connect().execution_options(isolation_level="AUTOCOMMIT") as conn:
        while time.monotonic() < deadline:
            if conn.execute(
                text(
                    "SELECT EXISTS (SELECT 1 FROM pg_stat_activity "
                    "WHERE :pid = ANY(pg_blocking_pids(pid)))"
                ),
                {"pid": pid},
            ).scalar_one():
                return True
            time.sleep(0.02)
    return False


def test_sr24_a_read_waits_for_a_purge_batch_between_its_choice_and_its_delete(
    db, admins, admin_engine, clock, monkeypatch
):
    """The purge chooses and deletes under the connection's row lock, which a read's write takes
    too: a read that comes while a batch is between its choice and its delete waits for the batch
    to commit, so it never stores an observation the choice did not see. Here the read brings
    another actor acting on the target of an execution whose window reaches back past the month,
    beside the old observation that execution accounts for, which the purge keeps: the action is
    reported."""
    admin = admins[0]
    profile(db, admin, clock)
    connection_id = connect(db, admin, clock)
    tenant = admin.tenant_id
    keeper = entry(clock.value - timedelta(hours=3), target=OTHER_TARGET)
    repeat = entry(clock.value - timedelta(hours=3) + MINUTE, target=target(1))
    own = entry(clock.value - timedelta(hours=2))
    with serving(directory(keeper, repeat, own)) as server:
        first_read(db, admin, clock, connection_id, server)
    clock.value += MINUTE
    worker.evaluate_scheduled(db, tenant, clock=clock)
    elapse(admin_engine, tenant, MONTH)
    refs = by_ref(db, tenant)
    execution = executed(
        admin_engine, admin, occurred(db, tenant, refs[own["id"]]) - MINUTE, target=TARGET
    )
    settle(admin_engine, execution, clock.value)
    theirs = entry(clock.value - 5 * MINUTE, actor=OTHER_ACTOR)
    kind, record, _ = graph.parse_directory_audit(theirs)
    assert kind == "mapped"
    chosen, release = threading.Event(), threading.Event()
    purger_pid: list[int] = []
    choose = store._purgeable

    def paused(conn, tenant_id, connection):
        found = choose(conn, tenant_id, connection)
        purger_pid.append(conn.execute(text("SELECT pg_backend_pid()")).scalar_one())
        chosen.set()
        assert release.wait(60)
        return found

    monkeypatch.setattr(store, "_purgeable", paused)
    outcome: dict = {}

    def run(name, call):
        try:
            outcome[name] = call()
        except Exception as error:  # reported by the assertions below, not lost in the thread
            outcome[name] = error

    purging = threading.Thread(target=run, args=("purged", lambda: purge(db, tenant, clock)))
    reading = threading.Thread(
        target=run,
        args=(
            "read",
            lambda: store.apply_directory_audit(
                db, admin, connection_id, [record], cursor=None, clock=clock
            ),
        ),
    )
    purging.start()
    try:
        assert chosen.wait(30)
        reading.start()
        assert waiting_on(admin_engine, purger_pid[0])
        assert reading.is_alive()
    finally:
        release.set()
        purging.join(60)
        if reading.is_alive() or reading.ident is not None:
            reading.join(60)
    assert outcome["purged"] == 1
    assert outcome["read"]["accepted"] == 1
    stored_now = by_ref(db, tenant)
    assert set(stored_now) == {keeper["id"], own["id"], theirs["id"]}
    assert refs[repeat["id"]] not in held(admin_engine, tenant)
    clock.value += MINUTE
    assert worker.evaluate_scheduled(db, tenant, clock=clock)["actions"] == 1
    (raised,) = findings(db, tenant, "first-consequential-action.v1")
    assert (raised["platform_ref"], raised["observation_id"]) == (
        OTHER_ACTOR,
        stored_now[theirs["id"]],
    )


def test_sr24_a_revoked_connection_is_purged_too(db, admins, admin_engine, clock):
    """A revoked connection keeps its row and its findings, and its audit observations age out
    like any other connection's: `process` visits it although `collect-due` never does."""
    admin = admins[0]
    connection_id = connect(db, admin, clock)
    tenant = admin.tenant_id
    habit = [
        entry(clock.value - timedelta(hours=1) + index * MINUTE, target=target(index))
        for index in (1, 2, 3)
    ]
    with serving(directory(*habit)) as server:
        first_read(db, admin, clock, connection_id, server)
    worker.evaluate_scheduled(db, tenant, clock=clock)
    store.revoke_connection(db, admin, connection_id, clock=clock)
    elapse(admin_engine, tenant, MONTH)
    assert purge(db, tenant, clock) == 2
    assert held(admin_engine, tenant) == {by_ref(db, tenant)[habit[0]["id"]]}


@pytest.fixture
def captured():
    """`logging_schema`'s own handler on the `execbound` logger, so a line is read as a
    deployment writes it: one with a field the schema does not know is written suppressed."""
    stream = io.StringIO()
    handler = logging_schema.capture_handler(stream)
    logger = logging.getLogger("execbound")
    logger.addHandler(handler)
    try:
        yield stream
    finally:
        logger.removeHandler(handler)


def purge_lines(stream):
    """The `monitor.audit_purged` lines written since the last call, without their moments, and
    any line the schema suppressed."""
    lines = [json.loads(line) for line in stream.getvalue().splitlines() if line.strip()]
    stream.seek(0)
    stream.truncate()
    return [
        {key: value for key, value in line.items() if key != "ts"}
        for line in lines
        if line["event"] in ("monitor.audit_purged", "log.suppressed")
    ]


def test_sr24_the_purge_is_paced_and_the_next_pass_continues(
    db, admins, admin_engine, clock, monkeypatch, captured
):
    """At most a bounded number of batches a workspace a pass; what is left is purged by the
    passes after it, oldest first, and an operator's `process` purges as the scheduled one does.
    Each pass that removes anything writes one `monitor.audit_purged` line with the workspace
    and its count, and one that removes nothing writes none."""
    admin = admins[0]
    connection_id = connect(db, admin, clock)
    tenant = admin.tenant_id
    habit = [
        entry(clock.value - timedelta(hours=1) + index * MINUTE, target=target(index))
        for index in range(1, 7)
    ]
    with serving(directory(*habit)) as server:
        first_read(db, admin, clock, connection_id, server)
    worker.evaluate_scheduled(db, tenant, clock=clock)
    elapse(admin_engine, tenant, MONTH)
    monkeypatch.setattr(store, "AUDIT_PURGE_BATCH", 2)
    monkeypatch.setattr(store, "AUDIT_PURGE_BATCHES", 1)
    refs = by_ref(db, tenant)
    purge_lines(captured)

    def line(count):
        return {
            "event": "monitor.audit_purged",
            "level": "INFO",
            "tenant_id": str(tenant),
            "count": count,
        }

    assert purge(db, tenant, clock) == 2
    assert purge_lines(captured) == [line(2)]
    assert {refs[habit[1]["id"]], refs[habit[2]["id"]]}.isdisjoint(held(admin_engine, tenant))
    assert purge(db, tenant, clock) == 2
    assert purge_lines(captured) == [line(2)]
    assert worker.process(db, admin)["purged"] == 1
    assert purge_lines(captured) == [line(1)]
    assert purge(db, tenant, clock) == 0
    assert purge_lines(captured) == []
    assert held(admin_engine, tenant) == {refs[habit[0]["id"]]}


@pytest.mark.parametrize(
    "failure",
    [
        pytest.param(lambda: OperationalError("statement", {}, Exception("timeout")), id="timeout"),
        pytest.param(lambda: MonitorError("INVALID_TENANT"), id="workspace-deactivated"),
    ],
)
def test_sr24_a_pass_that_fails_after_a_batch_still_logs_what_it_removed(
    db, admins, admin_engine, clock, monkeypatch, captured, failure
):
    """Each batch commits on its own, so what an earlier batch removed is gone whatever a later
    one does. A pass whose later batch fails, by a statement or lock timeout or the workspace
    deactivated in the middle of it, still writes its `monitor.audit_purged` line with what it
    removed before it fails: the line is the purge's only record."""
    admin = admins[0]
    tenant = admin.tenant_id
    connections = []
    for index in range(2):
        if connections:
            store.revoke_connection(db, admin, connections[-1], clock=clock)
            clock.value += MINUTE
        connection_id = connect(db, admin, clock)
        habit = [
            entry(clock.value - timedelta(hours=1) + n * MINUTE, target=target(10 * index + n))
            for n in (1, 2, 3)
        ]
        with serving(directory(*habit)) as server:
            first_read(db, admin, clock, connection_id, server)
        connections.append(connection_id)
    worker.evaluate_scheduled(db, tenant, clock=clock)
    elapse(admin_engine, tenant, MONTH)
    before = held(admin_engine, tenant)
    original = store._purge_batch

    def failing_second(db, actor, connection_id, clock):
        if connection_id == connections[1]:
            raise failure()
        return original(db, actor, connection_id, clock)

    monkeypatch.setattr(store, "_purge_batch", failing_second)
    purge_lines(captured)
    with pytest.raises(MonitorError):
        purge(db, tenant, clock)
    assert len(before - held(admin_engine, tenant)) == 2
    assert purge_lines(captured) == [
        {"event": "monitor.audit_purged", "level": "INFO", "tenant_id": str(tenant), "count": 2}
    ]


def test_sr24_a_full_batch_is_one_call_the_function_accepts(
    db, admins, admin_engine, clock, monkeypatch
):
    """A batch the store chooses is never longer than the function accepts in one call: a full
    one of `AUDIT_PURGE_BATCH` ids goes from `_purge_batch` to `monitor_audit_purge` and removes
    what it may, so a connection with more to purge than one batch is purged, not refused at
    every pass."""
    admin = admins[0]
    tenant = admin.tenant_id
    connection_id = connect(db, admin, clock)
    old = stored(admin_engine, tenant, connection_id, age=MONTH)
    full = [old, *(uuid4() for _ in range(store.AUDIT_PURGE_BATCH - 1))]
    monkeypatch.setattr(store, "_purgeable", lambda conn, tenant, connection_id: full)
    chosen, removed = store._purge_batch(db, ScheduledActor(tenant), connection_id, clock)
    assert (len(chosen), removed) == (store.AUDIT_PURGE_BATCH, 1)
    assert old not in held(admin_engine, tenant)


def test_sr24_every_connection_is_purged_each_pass_however_many_the_workspace_holds(
    db, admins, admin_engine, clock, monkeypatch
):
    """A workspace may hold more Microsoft Entra connections than a pass has batches: one a Space,
    or a directory revoked and connected again. Every connection gets a batch each pass, oldest
    first, so the one connected last, often the only active one, is purged too; what is left of
    the batches goes to the connections whose batch was full, in turn."""
    admin = admins[0]
    tenant = admin.tenant_id
    keepers, connections = set(), []
    for index in range(3):
        if connections:
            store.revoke_connection(db, admin, connections[-1], clock=clock)
            clock.value += MINUTE
        connection_id = connect(db, admin, clock)
        habit = [
            entry(clock.value - timedelta(hours=1) + n * MINUTE, target=target(10 * index + n))
            for n in (1, 2, 3)
        ]
        with serving(directory(*habit)) as server:
            first_read(db, admin, clock, connection_id, server)
        connections.append(connection_id)
        keepers.add(habit[0]["id"])
    worker.evaluate_scheduled(db, tenant, clock=clock)
    elapse(admin_engine, tenant, MONTH)
    keep = {observation for ref, observation in by_ref(db, tenant).items() if ref in keepers}
    monkeypatch.setattr(store, "AUDIT_PURGE_BATCHES", 1)
    assert purge(db, tenant, clock) == 6
    assert held(admin_engine, tenant) == keep
    # Batches of one: each connection's oldest, then the one batch left over to the oldest
    # connection, whose batch was full, as each one's was.
    repeats = [
        [stored(admin_engine, tenant, connection_id, age=MONTH) for _ in range(2)]
        for connection_id in connections
    ]
    monkeypatch.setattr(store, "AUDIT_PURGE_BATCH", 1)
    monkeypatch.setattr(store, "AUDIT_PURGE_BATCHES", 4)
    assert purge(db, tenant, clock) == 4
    assert held(admin_engine, tenant) - keep == {repeats[1][1], repeats[2][1]}
    assert purge(db, tenant, clock) == 2
    assert held(admin_engine, tenant) == keep


def hold_connection(admin_engine, connection_id):
    """A transaction holding the connection's row, as a collection's write holds it."""
    conn = admin_engine.connect()
    transaction = conn.begin()
    conn.execute(
        text("SELECT 1 FROM execbound.monitor_connections WHERE connection_id = :c FOR UPDATE"),
        {"c": connection_id},
    )
    return conn, transaction


def test_sr24_the_purge_passes_over_a_connection_a_collection_holds(
    db, admins, admin_engine, clock, monkeypatch
):
    """A collection holds its connection's row for its whole write. The purge never waits on it:
    it passes over the connection this pass, purges the rest, and `process` delivers what it
    has queued; the next pass purges the connection."""
    admin = admins[0]
    tenant = admin.tenant_id
    connections = []
    for index in range(2):
        if connections:
            store.revoke_connection(db, admin, connections[-1], clock=clock)
            clock.value += MINUTE
        connection_id = connect(db, admin, clock)
        habit = [
            entry(clock.value - timedelta(hours=1) + n * MINUTE, target=target(10 * index + n))
            for n in (1, 2, 3)
        ]
        with serving(directory(*habit)) as server:
            first_read(db, admin, clock, connection_id, server)
        connections.append(connection_id)
    worker.evaluate_scheduled(db, tenant, clock=clock)
    elapse(admin_engine, tenant, MONTH)
    sent = []
    monkeypatch.setattr(
        worker, "send_notification", lambda receiver, delivery, *rest: sent.append(delivery) or True
    )
    receiver = LocalReceiver("http://127.0.0.1:8121/alerts", "k" * 32)
    conn, transaction = hold_connection(admin_engine, connections[-1])
    try:
        began = time.monotonic()
        result = worker.process(db, admin, receiver)
        waited = time.monotonic() - began
    finally:
        transaction.rollback()
        conn.close()
    assert waited < 5
    assert result["purged"] == 2 and result["delivered"] == len(sent) > 0
    assert purge(db, tenant, clock) == 2


def test_sr24_process_delivers_before_it_purges(db, admins, clock, monkeypatch):
    """The purge is `process`'s last step, after delivery: a purge that fails never keeps a
    finding from its delivery."""
    admin = admins[0]
    connection_id = connect(db, admin, clock)
    with serving(directory(entry(clock.value - timedelta(hours=1)))) as server:
        first_read(db, admin, clock, connection_id, server)
    sent = []
    monkeypatch.setattr(
        worker, "send_notification", lambda receiver, delivery, *rest: sent.append(delivery) or True
    )

    def failing(*args, **kwargs):
        raise MonitorError()

    monkeypatch.setattr(worker, "purge_audit_observations", failing)
    with pytest.raises(MonitorError):
        worker.process(db, admin, LocalReceiver("http://127.0.0.1:8121/alerts", "k" * 32))
    assert sent


def test_sr24_the_function_deletes_only_what_its_own_conditions_admit(
    db, admins, admin_engine, clock
):
    """Whatever the runtime lists, the function removes an evaluated `entra_audit` observation of
    the named Entra connection in the caller's own workspace, a month old by the database's own
    clock and cited by no finding, and nothing else, not one of another kind that is all of the
    rest; it refuses a list too long, no list, another workspace's connection, a Tines
    connection, and no workspace or one that is not active."""
    admin, other = admins
    tenant = admin.tenant_id
    # One active Entra connection per space, so the workspace's second one is an earlier
    # connection it has since revoked; a revoked connection's observations are still purged.
    sibling_connection = connect(db, admin, clock, directory_ref=THIRD_DIRECTORY)
    store.revoke_connection(db, admin, sibling_connection, clock=clock)
    connection_id = connect(db, admin, clock)
    window = reach.EVIDENCE_VALIDITY
    assert window == timedelta(days=30)
    old = stored(admin_engine, tenant, connection_id, age=window + MINUTE)
    current = stored(admin_engine, tenant, connection_id, age=window - MINUTE)
    waiting = stored(admin_engine, tenant, connection_id, age=window + MINUTE, state="PENDING")
    cited = stored(admin_engine, tenant, connection_id, age=window + MINUTE)
    other_kind = stored(
        admin_engine, tenant, connection_id, age=window + MINUTE, kind="ai_tool_run"
    )
    with admin_engine.begin() as conn:
        conn.execute(
            text(
                "INSERT INTO execbound.monitor_findings "
                "(tenant_id, finding_id, connection_id, observation_id, rule_version, title, "
                " created_at, space_id) "
                "SELECT :t, :f, :c, :o, 'clock-skew.v1', 'Cited', now(), m.space_id "
                "FROM execbound.monitor_connections m WHERE m.connection_id = :c"
            ),
            {"t": tenant, "f": uuid4(), "c": connection_id, "o": cited},
        )
    # Another workspace's connection and observation, named from this one's fence.
    elsewhere = connect(db, other, clock, directory_ref=OTHER_DIRECTORY)
    theirs = stored(admin_engine, other.tenant_id, elsewhere, age=window + MINUTE)
    with pytest.raises(DBAPIError, match="INVALID_STATE"):
        call(db, tenant, elsewhere, [theirs])
    # The workspace's earlier, revoked Entra connection: its month-old, evaluated, uncited
    # observation is everything the function deletes, except that it is not the named
    # connection's.
    sibling = stored(admin_engine, tenant, sibling_connection, age=window + MINUTE)
    listed = [theirs, sibling, current, waiting, cited, other_kind, uuid4()]
    assert call(db, tenant, connection_id, listed) == 0
    assert call(db, tenant, connection_id, [old]) == 1
    assert held(admin_engine, tenant) == {sibling, current, waiting, cited}
    with admin_engine.connect() as conn:
        assert (
            conn.execute(
                text("SELECT kind FROM execbound.monitor_observations WHERE observation_id = :o"),
                {"o": other_kind},
            ).scalar_one()
            == "ai_tool_run"
        )
    assert theirs in held(admin_engine, other.tenant_id)
    tines = uuid4()
    with admin_engine.begin() as conn:
        conn.execute(
            text(
                "INSERT INTO execbound.monitor_connections "
                "(tenant_id, connection_id, label, base_url, key_fingerprint, created_at, "
                " created_by, space_id) "
                "SELECT :t, :c, 'Tines', 'https://fixture.tines.com', :f, now(), :a, s.space_id "
                "FROM execbound.spaces s WHERE s.tenant_id = :t LIMIT 1"
            ),
            {"t": tenant, "c": tines, "f": "cd" * 32, "a": admin.principal_id},
        )
    for connection, ids, code in (
        (tines, [old], "INVALID_STATE"),
        (connection_id, None, "INVALID_LIMIT"),
        (connection_id, [uuid4() for _ in range(1001)], "INVALID_LIMIT"),
    ):
        with pytest.raises(DBAPIError, match=code):
            call(db, tenant, connection, ids)
    with db.engine.connect() as conn, pytest.raises(DBAPIError, match="INVALID_TENANT"):
        conn.execute(
            text("SELECT execbound.monitor_audit_purge(:c, CAST(:ids AS uuid[]))"),
            {"c": connection_id, "ids": [str(current)]},
        )
    with admin_engine.begin() as conn:
        conn.execute(
            text("UPDATE execbound.tenants SET active = false WHERE tenant_id = :t"), {"t": tenant}
        )
    with pytest.raises(DBAPIError, match="INVALID_TENANT"):
        call(db, tenant, connection_id, [current])


def sprung_forward(now):
    """A POSIX time zone at UTC in winter and an hour ahead in summer, whose clocks went forward
    fifteen days before `now`: in it, thirty calendar days back from `now` are 719 hours."""
    start = (now - timedelta(days=15)).timetuple().tm_yday - 1
    return f"XST0XDT,{start}/2,{(start + 182) % 365}/2"


def test_sr24_the_thirty_days_are_hours_whatever_the_session_time_zone(
    db, admins, admin_engine, clock
):
    """The purge's thirty days are the rules' own, `reach.EVIDENCE_VALIDITY` of 720 hours back
    from the database's moment, whatever time zone the database session keeps, although thirty
    calendar days back are 719 hours in one whose clocks went forward meanwhile. There, an
    observation 719 and a half hours old, current to the rules, stays, through the store's
    choice and the function alike; so does an old one that an execution settled 719 hours and 55
    minutes ago could account for, since an entry still to be read may fall in that execution's
    window; and one 720 and a half hours old goes."""
    admin = admins[0]
    tenant = admin.tenant_id
    connection_id = connect(db, admin, clock)
    window = reach.EVIDENCE_VALIDITY
    assert window == timedelta(hours=720)
    with admin_engine.connect() as conn:
        now = conn.execute(text("SELECT now()")).scalar_one().astimezone(UTC)
    current = stored(admin_engine, tenant, connection_id, age=window - 30 * MINUTE)
    old = stored(admin_engine, tenant, connection_id, age=window + 30 * MINUTE)
    accounted = stored(admin_engine, tenant, connection_id, age=window + 2 * MINUTE)
    # Dispatched three minutes before `accounted` and settled seven minutes after it, so its
    # window, which ends ten minutes after its settlement, still reaches into the thirty days.
    execution = executed(admin_engine, admin, now - window - 5 * MINUTE, target=target(900))
    settle(admin_engine, execution, now - window + 5 * MINUTE)
    with db.transaction(tenant) as conn:
        conn.execute(
            text("SELECT set_config('TimeZone', :zone, true)"), {"zone": sprung_forward(now)}
        )
        # The zone is what the test needs: thirty calendar days back in it are 719 hours.
        assert conn.execute(
            text("SELECT statement_timestamp() - (statement_timestamp() - interval '30 days')")
        ).scalar_one() == timedelta(hours=719)
        assert store._purgeable(conn, tenant, connection_id) == [old]
        assert (
            conn.execute(
                text("SELECT execbound.monitor_audit_purge(:c, CAST(:ids AS uuid[]))"),
                {"c": connection_id, "ids": [str(current), str(old)]},
            ).scalar_one()
            == 1
        )
    assert held(admin_engine, tenant) == {current, accounted}


def test_sr24_the_runtime_deletes_an_observation_only_through_the_function(db, admins, clock):
    admin = admins[0]
    connect(db, admin, clock)
    with db.transaction(admin.tenant_id) as conn:
        privileges = conn.execute(
            text(
                "SELECT has_table_privilege(current_user, 'execbound.monitor_observations', "
                "'DELETE'), has_function_privilege(current_user, "
                "'execbound.monitor_audit_purge(uuid, uuid[])', 'EXECUTE')"
            )
        ).one()
    assert tuple(privileges) == (False, True)
    with (
        pytest.raises(DBAPIError, match="permission denied"),
        db.transaction(admin.tenant_id) as conn,
    ):
        conn.execute(text("DELETE FROM execbound.monitor_observations"))


# SR24: the bound


def bounded(db, admin, clock, connection_id, server, audits, minutes=5):
    """A delta pass over `audits`, its audit read's counts."""
    return later(db, admin, clock, connection_id, server, audits, minutes=minutes)["audit"]


def test_sr24_one_actors_flood_at_the_bound_never_hides_anothers_first_action(
    db, admins, clock, monkeypatch
):
    """At the bound the read moves on: the flooding actor's repeats are dropped, its first
    action of another kind is kept, and another actor's first action is kept and raises the
    rule, whatever order the log holds them in."""
    admin = admins[0]
    profile(db, admin, clock)
    connection_id = connect(db, admin, clock)
    tenant = admin.tenant_id
    monkeypatch.setattr(store, "MAX_CONNECTION_EVENTS", 3)
    with serving(directory()) as server:
        first_read(db, admin, clock, connection_id, server)
        filling = [entry(clock.value + index * MINUTE, target=target(index)) for index in (1, 2, 3)]
        assert bounded(db, admin, clock, connection_id, server, filling)["accepted"] == 3
        start = clock.value + MINUTE
        flood = [
            entry(start + index * timedelta(seconds=11), target=target(10 + index))
            for index in range(6)
        ]
        first = entry(start + timedelta(seconds=30), actor=OTHER_ACTOR, target=OTHER_TARGET)
        enable = entry(start + timedelta(seconds=40), activity="Enable account", target=target(30))
        read = bounded(db, admin, clock, connection_id, server, [*flood, first, enable])
        assert (read["state"], read["error_code"], read["bounded"]) == ("complete", None, 1)
        assert (read["accepted"], read["kept_at_bound"], read["dropped_at_bound"]) == (2, 2, 6)
        refs = by_ref(db, tenant)
        assert {first["id"], enable["id"]} <= set(refs)
        assert not {record["id"] for record in flood} & set(refs)
    clock.value += MINUTE
    assert worker.evaluate_scheduled(db, tenant, clock=clock)["actions"] == 2
    raised = {
        row["platform_ref"]: row["observation_id"]
        for row in findings(db, tenant, "first-consequential-action.v1")
    }
    assert raised[OTHER_ACTOR] == refs[first["id"]]


def test_sr24_the_executors_action_outside_execbound_is_kept_at_the_bound(
    db, admins, admin_engine, clock, monkeypatch
):
    """ExecBound's own executor holds a current observation its execution accounts for. A second
    execution's entry is kept as that execution's own, which the rule leaves out, and the
    executor's own executions never stand in for its first action outside ExecBound, which is
    kept and raises the rule."""
    admin = admins[0]
    profile(db, admin, clock)
    connection_id = connect(db, admin, clock)
    tenant = admin.tenant_id
    monkeypatch.setattr(store, "MAX_CONNECTION_EVENTS", 1)
    with serving(directory()) as server:
        first_read(db, admin, clock, connection_id, server)
        dispatched = clock.value + MINUTE
        executed(admin_engine, admin, dispatched, target=target(1))
        own = entry(dispatched + timedelta(seconds=1), target=target(1))
        assert bounded(db, admin, clock, connection_id, server, [own])["accepted"] == 1
        dispatched = clock.value + MINUTE
        executed(admin_engine, admin, dispatched, target=target(2))
        again = entry(dispatched + timedelta(seconds=1), target=target(2))
        outside = entry(dispatched + timedelta(minutes=30), target=target(3))
        clock.value += timedelta(minutes=30)
        repeat = entry(dispatched + timedelta(minutes=31), target=target(4))
        read = bounded(db, admin, clock, connection_id, server, [again, outside, repeat])
        assert (read["kept_at_bound"], read["dropped_at_bound"]) == (2, 1)
    clock.value += MINUTE
    assert worker.evaluate_scheduled(db, tenant, clock=clock)["actions"] == 1
    (raised,) = findings(db, tenant, "first-consequential-action.v1")
    assert (raised["platform_ref"], raised["observation_id"]) == (
        ACTOR,
        by_ref(db, tenant)[outside["id"]],
    )


@pytest.mark.parametrize("order", ["executor first", "actor first"])
def test_sr24_an_action_timed_beside_an_execution_is_never_hidden_at_the_bound(
    db, admins, admin_engine, clock, monkeypatch, order
):
    """Another actor acts on the execution's target as it runs. The executor has already acted
    outside ExecBound, so its own entry for that execution is a repeat of its actor's, but
    without it the other actor's would be the one observation the execution accounts for, taken
    for ExecBound's own and never reported: so both are kept, the execution accounts for two,
    and neither is left out."""
    admin = admins[0]
    profile(db, admin, clock)
    connection_id = connect(db, admin, clock)
    tenant = admin.tenant_id
    monkeypatch.setattr(store, "MAX_CONNECTION_EVENTS", 1)
    with serving(directory()) as server:
        first_read(db, admin, clock, connection_id, server)
        # The executor's own action outside ExecBound, current: its next is a repeat.
        outside = entry(clock.value + MINUTE, target=target(1))
        assert bounded(db, admin, clock, connection_id, server, [outside])["accepted"] == 1
        dispatched = clock.value + MINUTE
        executed(admin_engine, admin, dispatched, target=TARGET)
        mine = entry(dispatched + timedelta(seconds=1))
        theirs = entry(dispatched + timedelta(seconds=2), actor=OTHER_ACTOR)
        if order == "actor first":
            mine, theirs = (
                entry(dispatched + timedelta(seconds=2)),
                entry(dispatched + timedelta(seconds=1), actor=OTHER_ACTOR),
            )
        read = bounded(db, admin, clock, connection_id, server, [mine, theirs])
        assert (read["kept_at_bound"], read["dropped_at_bound"]) == (2, 0)
    clock.value += MINUTE
    worker.evaluate_scheduled(db, tenant, clock=clock)
    raised = {row["platform_ref"] for row in findings(db, tenant, "first-consequential-action.v1")}
    assert OTHER_ACTOR in raised


# The executor of an execution whose own entry only the execution keeps at the bound: a
# principal whose action outside ExecBound makes it a repeat, an actor not yet inventoried whose
# own makes it one, or one past the inventory's limit, which the bound drops even as a first.
EXECUTORS = [
    pytest.param(ACTOR, False, id="a repeat"),
    pytest.param(STRANGER, False, id="not a principal, a repeat"),
    pytest.param(STRANGER, True, id="not a principal, past the limit"),
]


def outside_action(db, monkeypatch, tenant, clock, executor, past_limit):
    """The entry stored under the bound before an `EXECUTORS` case's execution: the executor's
    own action outside ExecBound, current, so that its next of the action is a repeat; or, past
    the inventory's limit, which the connection's live principals then fill, a principal's."""
    if not past_limit:
        return entry(clock.value + MINUTE, actor=executor, target=target(1))
    with db.transaction(tenant) as conn:
        live = set(
            conn.execute(
                text("SELECT platform_ref FROM execbound.monitor_agents WHERE gone_at IS NULL")
            ).scalars()
        )
    assert executor not in live
    monkeypatch.setattr(store, "MAX_AGENTS", len(live))
    return entry(clock.value + MINUTE, target=target(1))


@pytest.mark.parametrize(("executor", "past_limit"), EXECUTORS)
def test_sr24_an_executions_own_entry_is_kept_so_a_later_read_cannot_hide_one_beside_it(
    db, admins, admin_engine, clock, monkeypatch, executor, past_limit
):
    """The execution's own entry is read first and the other actor's only by the next read, as a
    backlog's reads find them. The own entry is a repeat of its actor's, which has already acted
    outside ExecBound, a principal of the connection or an actor not yet inventoried, or its
    actor is not yet inventoried and past the inventory's limit, so the bound would drop it on
    any other rule; but without it the other actor's entry would be the one observation that
    execution accounts for, taken for ExecBound's own and never reported: so an entry an
    execution accounts for no other observation yet is kept, ahead of every other rule, and the
    other actor's entry pairs with it when it comes."""
    admin = admins[0]
    profile(db, admin, clock)
    connection_id = connect(db, admin, clock)
    tenant = admin.tenant_id
    monkeypatch.setattr(store, "MAX_CONNECTION_EVENTS", 1)
    with serving(directory()) as server:
        first_read(db, admin, clock, connection_id, server)
        outside = outside_action(db, monkeypatch, tenant, clock, executor, past_limit)
        assert bounded(db, admin, clock, connection_id, server, [outside])["accepted"] == 1
        dispatched = clock.value + MINUTE
        executed(admin_engine, admin, dispatched, target=TARGET)
        mine = entry(dispatched + timedelta(seconds=1), actor=executor)
        read = bounded(db, admin, clock, connection_id, server, [mine])
        assert (read["kept_at_bound"], read["dropped_at_bound"]) == (1, 0)
        theirs = entry(dispatched + timedelta(seconds=2), actor=OTHER_ACTOR)
        read = bounded(db, admin, clock, connection_id, server, [theirs])
        assert (read["kept_at_bound"], read["dropped_at_bound"]) == (1, 0)
    clock.value += MINUTE
    worker.evaluate_scheduled(db, tenant, clock=clock)
    raised = {
        row["platform_ref"]: row["observation_id"]
        for row in findings(db, tenant, "first-consequential-action.v1")
    }
    assert raised[OTHER_ACTOR] == by_ref(db, tenant)[theirs["id"]]


@pytest.mark.parametrize(("executor", "past_limit"), EXECUTORS)
def test_sr24_an_unsettled_executions_entries_are_kept_at_the_bound(
    db, admins, admin_engine, clock, monkeypatch, executor, past_limit
):
    """An execution may still be unsettled when the read that finds its entries comes, its
    provider call timed out, and settle `EXECUTED` later. Its window is open until it settles,
    and its first two entries are kept as a settled execution's are, whoever acted, ahead of
    every other rule: its own, a repeat of its actor's, a principal of the connection or an
    actor not yet inventoried, or by an actor past the inventory's limit, and another actor's
    beside it. Once it settles, the other actor's is not the one observation it accounts for,
    and is reported."""
    admin = admins[0]
    profile(db, admin, clock)
    connection_id = connect(db, admin, clock)
    tenant = admin.tenant_id
    monkeypatch.setattr(store, "MAX_CONNECTION_EVENTS", 1)
    with serving(directory()) as server:
        first_read(db, admin, clock, connection_id, server)
        outside = outside_action(db, monkeypatch, tenant, clock, executor, past_limit)
        assert bounded(db, admin, clock, connection_id, server, [outside])["accepted"] == 1
        dispatched = clock.value + MINUTE
        execution = executed(admin_engine, admin, dispatched, state="INDETERMINATE")
        mine = entry(dispatched + timedelta(seconds=1), actor=executor)
        theirs = entry(dispatched + timedelta(seconds=2), actor=OTHER_ACTOR)
        read = bounded(db, admin, clock, connection_id, server, [mine, theirs])
        assert (read["kept_at_bound"], read["dropped_at_bound"]) == (2, 0)
        settle(admin_engine, execution, clock.value)
    clock.value += MINUTE
    worker.evaluate_scheduled(db, tenant, clock=clock)
    raised = {
        row["platform_ref"]: row["observation_id"]
        for row in findings(db, tenant, "first-consequential-action.v1")
    }
    assert raised[OTHER_ACTOR] == by_ref(db, tenant)[theirs["id"]]


@pytest.mark.parametrize("first", ["EXECUTED", "INDETERMINATE"], ids=["settled", "unsettled"])
def test_sr24_an_entry_one_settled_execution_may_leave_out_is_no_first_at_the_bound(
    db, admins, admin_engine, clock, monkeypatch, first
):
    """The executor's entry for an execution that a second execution, dispatched moments later
    and not yet settled, could also account for. The settled match counts only executions that
    settled `EXECUTED`: with the first settled and the second never settling, or with only the
    first settling later, the entry is the one observation the one settled execution accounts
    for, ExecBound's own, and no action outside ExecBound. So it never makes the executor's
    action outside ExecBound in the same read a repeat: that action is kept and raises the
    rule."""
    admin = admins[0]
    profile(db, admin, clock)
    connection_id = connect(db, admin, clock)
    tenant = admin.tenant_id
    monkeypatch.setattr(store, "MAX_CONNECTION_EVENTS", 1)
    with serving(directory()) as server:
        first_read(db, admin, clock, connection_id, server)
        filling = entry(clock.value + MINUTE, actor=OTHER_ACTOR, target=target(9))
        assert bounded(db, admin, clock, connection_id, server, [filling])["accepted"] == 1
        dispatched = clock.value + MINUTE
        execution = executed(admin_engine, admin, dispatched, target=target(1), state=first)
        executed(
            admin_engine, admin, dispatched + 2 * MINUTE, target=target(1), state="INDETERMINATE"
        )
        own = entry(dispatched + timedelta(seconds=1), target=target(1))
        outside = entry(dispatched + timedelta(hours=1), target=target(2))
        clock.value += timedelta(hours=1)
        read = bounded(db, admin, clock, connection_id, server, [own, outside])
        assert (read["kept_at_bound"], read["dropped_at_bound"]) == (2, 0)
        if first == "INDETERMINATE":
            settle(admin_engine, execution, clock.value)
    clock.value += MINUTE
    worker.evaluate_scheduled(db, tenant, clock=clock)
    raised = {
        row["platform_ref"]: row["observation_id"]
        for row in findings(db, tenant, "first-consequential-action.v1")
    }
    assert raised[ACTOR] == by_ref(db, tenant)[outside["id"]]


@pytest.mark.parametrize(
    ("held_by", "executor", "executions"),
    [
        pytest.param("an earlier read", ACTOR, 1, id="an earlier read, a principal"),
        pytest.param("the same read", ACTOR, 1, id="the same read, a principal"),
        pytest.param("an earlier read", NEWCOMER, 1, id="an earlier read, not yet inventoried"),
        pytest.param("the same read", NEWCOMER, 1, id="the same read, not yet inventoried"),
        pytest.param("an earlier read", ACTOR, 2, id="two unsettled, one settling"),
    ],
)
def test_sr24_a_held_entry_an_unsettled_execution_may_leave_out_is_no_first_at_the_bound(
    db, admins, admin_engine, clock, monkeypatch, held_by, executor, executions
):
    """The executor's own entry for an execution whose provider call timed out is already held
    when the bound reads its action outside ExecBound: an earlier read at the bound kept it as
    the execution's, or the same read stored it before the bound applied. Once the execution
    settles `EXECUTED`, with a second that could also account for it never settling, the entry
    is the one observation the one settled execution accounts for, ExecBound's own. So until
    then it never makes the executor's action outside ExecBound a repeat, whether the executor
    is a principal or an actor not yet inventoried: that action is kept and raises the rule."""
    admin = admins[0]
    profile(db, admin, clock)
    connection_id = connect(db, admin, clock)
    tenant = admin.tenant_id
    monkeypatch.setattr(store, "MAX_CONNECTION_EVENTS", 1 if held_by == "an earlier read" else 2)
    with serving(directory()) as server:
        first_read(db, admin, clock, connection_id, server)
        filling = entry(clock.value + MINUTE, actor=OTHER_ACTOR, target=target(9))
        assert bounded(db, admin, clock, connection_id, server, [filling])["accepted"] == 1
        dispatched = clock.value + MINUTE
        execution, *_ = [
            executed(
                admin_engine,
                admin,
                dispatched + index * MINUTE,
                target=target(1),
                state="INDETERMINATE",
            )
            for index in range(executions)
        ]
        own = entry(dispatched + timedelta(seconds=1), actor=executor, target=target(1))
        outside = entry(dispatched + timedelta(hours=1), actor=executor, target=target(2))
        if held_by == "an earlier read":
            read = bounded(db, admin, clock, connection_id, server, [own])
            assert (read["kept_at_bound"], read["dropped_at_bound"]) == (1, 0)
            clock.value += timedelta(hours=1)
            read = bounded(db, admin, clock, connection_id, server, [outside])
            assert (read["kept_at_bound"], read["dropped_at_bound"]) == (1, 0)
        else:
            clock.value += timedelta(hours=1)
            read = bounded(db, admin, clock, connection_id, server, [own, outside])
            assert (read["accepted"], read["kept_at_bound"], read["dropped_at_bound"]) == (2, 1, 0)
        settle(admin_engine, execution, clock.value)
        if executor == NEWCOMER:
            # The next full collection inventories it.
            acting, assignments = reaching(11)
            server.scenario.principals = [*server.scenario.principals, acting]
            server.scenario.app_role_assignments = {
                **server.scenario.app_role_assignments,
                **assignments,
            }
            server.scenario.audits = []
            clock.value += timedelta(minutes=5)
            assert full(db, admin, clock, connection_id, server)["outcome"] == "COMPLETE"
    clock.value += MINUTE
    worker.evaluate_scheduled(db, tenant, clock=clock)
    raised = {
        row["platform_ref"]: row["observation_id"]
        for row in findings(db, tenant, "first-consequential-action.v1")
    }
    assert raised[executor] == by_ref(db, tenant)[outside["id"]]


@pytest.mark.parametrize("accounted", ["a settled execution's two", "an unsettled execution's two"])
def test_sr24_a_held_entry_the_match_never_leaves_out_makes_the_next_a_repeat_at_the_bound(
    db, admins, admin_engine, clock, monkeypatch, accounted
):
    """The connection holds the actor's entry and another actor's on the same target, and an
    execution could account for both: one that settled, with a second not yet settled that
    could account for the actor's alone, or one not yet settled. However what is unsettled
    settles, the settled match never leaves the actor's entry out, so it is the actor's first
    and its next of the action within fifteen days is a repeat the bound drops: the rule is
    raised from the entry held."""
    admin = admins[0]
    profile(db, admin, clock)
    connection_id = connect(db, admin, clock)
    tenant = admin.tenant_id
    monkeypatch.setattr(store, "MAX_CONNECTION_EVENTS", 2)
    with serving(directory()) as server:
        first_read(db, admin, clock, connection_id, server)
        dispatched = clock.value + MINUTE
        theirs = entry(dispatched + timedelta(seconds=1), actor=OTHER_ACTOR, target=target(1))
        mine = entry(dispatched + 3 * MINUTE, target=target(1))
        if accounted == "a settled execution's two":
            executed(admin_engine, admin, dispatched, target=target(1))
            # Its window opens after the other actor's entry and before the actor's.
            execution = executed(
                admin_engine,
                admin,
                dispatched + 12 * MINUTE,
                target=target(1),
                state="INDETERMINATE",
            )
        else:
            execution = executed(
                admin_engine, admin, dispatched, target=target(1), state="INDETERMINATE"
            )
        read = bounded(db, admin, clock, connection_id, server, [theirs, mine])
        assert (read["accepted"], read["bounded"]) == (2, 0)
        repeat = entry(dispatched + timedelta(hours=1), target=target(2))
        clock.value += timedelta(hours=1)
        read = bounded(db, admin, clock, connection_id, server, [repeat])
        assert (read["kept_at_bound"], read["dropped_at_bound"]) == (0, 1)
        settle(admin_engine, execution, clock.value)
    clock.value += MINUTE
    worker.evaluate_scheduled(db, tenant, clock=clock)
    raised = {
        row["platform_ref"]: row["observation_id"]
        for row in findings(db, tenant, "first-consequential-action.v1")
    }
    refs = by_ref(db, tenant)
    assert repeat["id"] not in refs
    assert (raised[ACTOR], raised[OTHER_ACTOR]) == (refs[mine["id"]], refs[theirs["id"]])


def test_sr24_an_execution_keeps_at_most_two_entries_at_the_bound(
    db, admins, admin_engine, clock, monkeypatch
):
    """However many entries one execution could account for, the bound keeps two of them for
    it, which is all the match needs to leave none of them out; a third, in the same read or a
    later one, is dropped unless its actor's first action keeps it."""
    admin = admins[0]
    profile(db, admin, clock)
    connection_id = connect(db, admin, clock)
    tenant = admin.tenant_id
    monkeypatch.setattr(store, "MAX_CONNECTION_EVENTS", 1)
    with serving(directory()) as server:
        first_read(db, admin, clock, connection_id, server)
        assert (
            bounded(db, admin, clock, connection_id, server, [entry(clock.value + MINUTE)])[
                "accepted"
            ]
            == 1
        )
        dispatched = clock.value + MINUTE
        executed(admin_engine, admin, dispatched, target=OTHER_TARGET)
        beside = [
            entry(dispatched + timedelta(seconds=index), actor=STRANGER, target=OTHER_TARGET)
            for index in (1, 2, 3)
        ]
        read = bounded(db, admin, clock, connection_id, server, beside)
        assert (read["kept_at_bound"], read["dropped_at_bound"]) == (2, 1)
        late = entry(dispatched + timedelta(seconds=4), actor=STRANGER, target=OTHER_TARGET)
        read = bounded(db, admin, clock, connection_id, server, [late])
        assert (read["kept_at_bound"], read["dropped_at_bound"]) == (0, 1)
    assert set(by_ref(db, tenant)) >= {beside[0]["id"], beside[1]["id"]}
    assert not {beside[2]["id"], late["id"]} & set(by_ref(db, tenant))


def test_sr24_at_the_bound_failures_and_repeats_are_dropped(db, admins, clock, monkeypatch):
    """A refused attempt is dropped at the bound, and of an actor's entries no execution could
    account for within fifteen days of each other only its first current observation of each
    action is kept."""
    admin = admins[0]
    profile(db, admin, clock)
    connection_id = connect(db, admin, clock)
    tenant = admin.tenant_id
    monkeypatch.setattr(store, "MAX_CONNECTION_EVENTS", 1)
    with serving(directory()) as server:
        first_read(db, admin, clock, connection_id, server)
        assert (
            bounded(db, admin, clock, connection_id, server, [entry(clock.value + MINUTE)])[
                "accepted"
            ]
            == 1
        )
        start = clock.value + MINUTE
        entries = [
            entry(start, actor=OTHER_ACTOR, target=target(1), result="failure"),
            *(
                entry(
                    start + timedelta(seconds=22 + 11 * index),
                    actor=OTHER_ACTOR,
                    target=target(3 + index),
                )
                for index in range(4)
            ),
        ]
        read = bounded(db, admin, clock, connection_id, server, entries)
        assert (read["kept_at_bound"], read["dropped_at_bound"]) == (1, 4)
    kept = [row for row in observations(db, tenant) if row["actor_ref"] == OTHER_ACTOR]
    assert [row["external_ref"] for row in kept] == [entries[1]["id"]]
    # Nor is an entry from before the thirty days evidence stays current.
    kind, stale, _ = graph.parse_directory_audit(
        entry(
            clock.value - reach.EVIDENCE_VALIDITY - MINUTE,
            actor=OTHER_ACTOR,
            activity="Enable account",
        )
    )
    assert kind == "mapped"
    counts = store.apply_directory_audit(
        db, admin, connection_id, [stale], cursor=None, clock=clock
    )
    assert (counts["accepted"], counts["dropped_at_bound"]) == (0, 1)


def mapped(*records):
    """Directory audit entries as a read hands them to the store."""
    parsed = []
    for record in records:
        kind, value, _ = graph.parse_directory_audit(record)
        assert kind == "mapped"
        parsed.append(value)
    return parsed


def apply(db, admin, clock, connection_id, *records):
    """One read of `records`, handed to the store as the read hands them."""
    return store.apply_directory_audit(
        db, admin, connection_id, mapped(*records), cursor=None, clock=clock
    )


def reach_until(db, tenant, platform_ref, action):
    """Until when the principal's observed reach of `action` is current."""
    with db.transaction(tenant) as conn:
        return conn.execute(
            text(
                "SELECT r.valid_until FROM execbound.monitor_agent_reach r "
                "JOIN execbound.monitor_agents a "
                "  ON a.tenant_id = r.tenant_id AND a.agent_id = r.agent_id "
                "WHERE a.platform_ref = :p AND r.action = :action "
                "  AND r.path_kind = 'observation'"
            ),
            {"p": platform_ref, "action": action},
        ).scalar_one()


@pytest.mark.parametrize("newest", ["outside ExecBound", "ExecBound's own"])
def test_sr24_a_principals_repeat_keeps_its_reach_current_at_the_bound(
    db, admins, admin_engine, clock, monkeypatch, newest
):
    """Observed reach is read from a principal's newest current observation of each action and
    lasts thirty days from it, so at the bound a repeat is kept when that principal and action's
    newest current observation is more than fifteen days older than it, and dropped otherwise
    (ruled on 18 October 2026): reach stays current for a principal that acts at least every
    fifteen days. Fifteen days to the moment is not more. An observation one of ExecBound's
    executions accounts for is observed reach too, so when it is the latest it is the newest,
    and a repeat within fifteen days of it is dropped."""
    admin = admins[0]
    connection_id = connect(db, admin, clock)
    tenant = admin.tenant_id
    with serving(directory()) as server:
        first_read(db, admin, clock, connection_id, server)
    monkeypatch.setattr(store, "MAX_CONNECTION_EVENTS", 1)
    now, day = clock.value, timedelta(days=1)
    # Under the bound, stored as any read's entry is.
    habit = entry(now - 20 * day, target=target(1))
    assert apply(db, admin, clock, connection_id, habit)["bounded"] == 0
    latest = now - 4 * day
    if newest == "ExecBound's own":
        dispatched = now - 10 * day
        executed(admin_engine, admin, dispatched, target=target(2))
        own = entry(dispatched + timedelta(seconds=1), target=target(2))
        assert apply(db, admin, clock, connection_id, own)["kept_at_bound"] == 1
        latest = dispatched + timedelta(seconds=1)
    repeats = [entry(now - days * day, target=target(10 + days)) for days in (8, 5, 4, 1)]
    read = apply(db, admin, clock, connection_id, *repeats)
    renewed = [repeats[2]["id"]] if newest == "outside ExecBound" else []
    assert (read["bounded"], read["kept_at_bound"], read["dropped_at_bound"]) == (
        1,
        len(renewed),
        4 - len(renewed),
    )
    stored_refs = set(by_ref(db, tenant))
    assert {record["id"] for record in repeats} & stored_refs == set(renewed)
    store.derive_reach(db, admin, clock=clock)
    assert reach_until(db, tenant, ACTOR, "identity.disable") == latest + reach.EVIDENCE_VALIDITY


def test_sr24_of_a_daily_habit_the_bound_keeps_two_current_observations(
    db, admins, clock, monkeypatch
):
    """A principal acting every day for a month, none of it current at the bound before: its
    first is kept, then the first more than fifteen days after it, and nothing else, so the
    bound keeps at most two current observations of each principal and action."""
    assert store.BOUND_RENEWAL == timedelta(days=15) == reach.EVIDENCE_VALIDITY / 2
    admin = admins[0]
    connection_id = connect(db, admin, clock)
    tenant = admin.tenant_id
    with serving(directory()) as server:
        first_read(db, admin, clock, connection_id, server)
    monkeypatch.setattr(store, "MAX_CONNECTION_EVENTS", 1)
    now, day = clock.value, timedelta(days=1)
    assert apply(db, admin, clock, connection_id, entry(now - MINUTE))["bounded"] == 0
    daily = [
        entry(
            now - 29 * day + index * day,
            actor=OTHER_ACTOR,
            activity="Enable account",
            target=target(index),
        )
        for index in range(29)
    ]
    read = apply(db, admin, clock, connection_id, *daily)
    assert (read["kept_at_bound"], read["dropped_at_bound"]) == (2, 27)
    kept = [
        row["external_ref"] for row in observations(db, tenant) if row["actor_ref"] == OTHER_ACTOR
    ]
    assert kept == [daily[0]["id"], daily[16]["id"]]


def test_sr24_an_actor_not_yet_inventoried_keeps_its_first_actions_at_the_bound(
    db, admins, clock, monkeypatch
):
    """A principal created since the connection's last full collection acts before the next one
    inventories it. At the bound its first current observation of each action is kept and its
    repeat dropped (ruled on 18 October 2026), so once the next collection inventories it, its
    first consequential action raises the rule rather than being lost for good."""
    admin = admins[0]
    profile(db, admin, clock)
    connection_id = connect(db, admin, clock)
    tenant = admin.tenant_id
    monkeypatch.setattr(store, "MAX_CONNECTION_EVENTS", 1)
    with serving(directory()) as server:
        first_read(db, admin, clock, connection_id, server)
        filling = entry(clock.value + MINUTE, actor=OTHER_ACTOR, target=target(9))
        assert bounded(db, admin, clock, connection_id, server, [filling])["accepted"] == 1
        start = clock.value + MINUTE
        first = entry(start, actor=NEWCOMER, target=target(1))
        repeat = entry(start + timedelta(seconds=11), actor=NEWCOMER, target=target(2))
        enable = entry(
            start + timedelta(seconds=22),
            actor=NEWCOMER,
            activity="Enable account",
            target=target(3),
        )
        read = bounded(db, admin, clock, connection_id, server, [first, repeat, enable])
        assert (read["kept_at_bound"], read["dropped_at_bound"]) == (2, 1)
        # The next full collection inventories it.
        acting, assignments = reaching(11)
        server.scenario.principals = [*server.scenario.principals, acting]
        server.scenario.app_role_assignments = {
            **server.scenario.app_role_assignments,
            **assignments,
        }
        server.scenario.audits = []
        clock.value += timedelta(minutes=5)
        assert full(db, admin, clock, connection_id, server)["outcome"] == "COMPLETE"
    refs = by_ref(db, tenant)
    assert {first["id"], enable["id"]} <= set(refs) and repeat["id"] not in refs
    clock.value += MINUTE
    worker.evaluate_scheduled(db, tenant, clock=clock)
    raised = {
        row["platform_ref"]: row["observation_id"]
        for row in findings(db, tenant, "first-consequential-action.v1")
    }
    assert raised[NEWCOMER] == refs[first["id"]]


def test_sr24_actors_not_yet_inventoried_are_kept_only_within_the_inventory_limit(
    db, admins, clock, monkeypatch
):
    """The actors whose first actions the bound keeps are counted against the inventory's limit
    (`MAX_AGENTS`), the connection's live principals and the actors not yet inventoried
    together (ruled on 18 October 2026). An actor not yet inventoried counts once the bound has
    kept an entry of it in the episode: it keeps its first action of another kind, in the same
    read or a later one, while one past the limit is dropped and counted, however many reads
    come, and a principal's first action is kept as ever. An entry stored before the episode
    began, under the bound, counts for nothing: it is no part of the bound's overshoot."""
    admin = admins[0]
    connection_id = connect(db, admin, clock)
    tenant = admin.tenant_id
    # The directory's three live principals, and room for one actor more.
    monkeypatch.setattr(store, "MAX_AGENTS", 4)
    monkeypatch.setattr(store, "MAX_CONNECTION_EVENTS", 1)
    with serving(directory()) as server:
        first_read(db, admin, clock, connection_id, server)
        with db.transaction(tenant) as conn:
            assert (
                conn.execute(
                    text("SELECT count(*) FROM execbound.monitor_agents WHERE gone_at IS NULL")
                ).scalar_one()
                == 3
            )
        filling = entry(clock.value + MINUTE, actor=OTHER_STRANGER, target=target(9))
        read = bounded(db, admin, clock, connection_id, server, [filling])
        assert (read["accepted"], read["bounded"]) == (1, 0)
        start = clock.value + MINUTE
        counted = entry(start, actor=STRANGER, target=target(1))
        past = entry(
            start + timedelta(seconds=11),
            actor=OTHER_STRANGER,
            activity="Enable account",
            target=target(2),
        )
        another = entry(
            start + timedelta(seconds=22),
            actor=STRANGER,
            activity="Enable account",
            target=target(3),
        )
        read = bounded(db, admin, clock, connection_id, server, [counted, past, another])
        assert (read["kept_at_bound"], read["dropped_at_bound"]) == (2, 1)
        start = clock.value + MINUTE
        still_past = entry(start, actor=OTHER_STRANGER, activity="Reset password", target=target(4))
        later_kind = entry(
            start + timedelta(seconds=11),
            actor=STRANGER,
            activity="Reset password",
            target=target(5),
        )
        principals_first = entry(start + timedelta(seconds=22), target=target(6))
        read = bounded(
            db, admin, clock, connection_id, server, [still_past, later_kind, principals_first]
        )
        assert (read["kept_at_bound"], read["dropped_at_bound"]) == (2, 1)
    # Of an actor not yet inventoried only the first is kept: a repeat renews no reach, which
    # is derived only for the principals the inventory holds.
    now, day = clock.value, timedelta(days=1)
    revoke = "Update StsRefreshTokenValidFrom Timestamp"
    first = entry(now - 20 * day, actor=STRANGER, activity=revoke, target=target(7))
    repeat = entry(now - day, actor=STRANGER, activity=revoke, target=target(8))
    read = apply(db, admin, clock, connection_id, first, repeat)
    assert (read["kept_at_bound"], read["dropped_at_bound"]) == (1, 1)
    refs = set(by_ref(db, tenant))
    assert {counted["id"], another["id"], later_kind["id"], principals_first["id"]} <= refs
    assert first["id"] in refs
    assert not {past["id"], still_past["id"], repeat["id"]} & refs


def test_sr24_the_bound_moves_the_cursor_and_raises_one_finding_an_episode(
    db, admins, admin_engine, clock, monkeypatch
):
    """A first read at the bound still catches up and sets the activity baseline and the cursor.
    The bound's `collection-health.v1` finding is raised once for its episode, under its new
    title, however many reads the episode lasts; a purge that brings the connection under ends
    the episode, and the next time the bound is met is an episode of its own."""
    admin = admins[0]
    connection_id = connect(db, admin, clock)
    tenant = admin.tenant_id
    monkeypatch.setattr(store, "MAX_CONNECTION_EVENTS", 3)
    began = clock.value
    look_back = [
        entry(clock.value - timedelta(hours=2) + index * MINUTE, target=target(index))
        for index in (1, 2, 3, 4)
    ]
    habit = entry(clock.value - timedelta(hours=1), actor=OTHER_ACTOR, target=OTHER_TARGET)
    with serving(directory(*look_back, habit)) as server:
        read = first_read(db, admin, clock, connection_id, server)["audit"]
        assert (read["bounded"], read["kept_at_bound"], read["dropped_at_bound"]) == (1, 1, 1)
        row = connection_row(db, tenant, connection_id)
        assert row["audit_baseline_at"] == began and row["audit_cursor"] is not None
        assert row["audit_bound_since"] == began and row["audit_behind_since"] is None
        # Nor does the bound touch the run's record, which is its inventory's.
        assert (row["last_outcome"], row["last_error_code"]) == ("COMPLETE", None)
        assert store.collection_reporting(row, clock.value)
        (raised,) = health(db, tenant)
        assert raised["title"] == store.HEALTH_TITLES["CAPACITY"] == BOUND_TITLE
        assert raised["delivered"]
        read = bounded(
            db, admin, clock, connection_id, server, [entry(clock.value + MINUTE, target=target(9))]
        )
        assert (read["bounded"], read["dropped_at_bound"]) == (1, 1)
        assert len(health(db, tenant)) == 1
        worker.evaluate_scheduled(db, tenant, clock=clock)
        elapse(admin_engine, tenant, MONTH)
        assert worker.evaluate_scheduled(db, tenant, clock=clock)["purged"] == 2
        read = bounded(db, admin, clock, connection_id, server, [])
        assert read["bounded"] == 0
        assert connection_row(db, tenant, connection_id)["audit_bound_since"] is None
        again = [entry(clock.value + index * MINUTE, target=target(20 + index)) for index in (1, 2)]
        read = bounded(db, admin, clock, connection_id, server, again)
        assert (read["accepted"], read["bounded"]) == (1, 1)
    assert [row["title"] for row in health(db, tenant)] == [BOUND_TITLE, BOUND_TITLE]


def test_sr24_a_connection_hovering_at_the_bound_is_one_episode_and_one_finding(
    db, admins, admin_engine, clock, monkeypatch
):
    """A directory whose month of evidence fills the bound sits at it: each purge brings the
    connection just under and the next reads fill it again. That is one episode and one finding,
    however often it happens, because an episode ends only with a read that leaves the
    connection a tenth of the bound under it. Meeting the bound after that is an episode of its
    own."""
    admin = admins[0]
    connection_id = connect(db, admin, clock)
    tenant = admin.tenant_id
    monkeypatch.setattr(store, "MAX_CONNECTION_EVENTS", 20)
    monkeypatch.setattr(store, "AUDIT_PURGE_BATCH", 2)
    monkeypatch.setattr(store, "AUDIT_PURGE_BATCHES", 1)
    with serving(directory()) as server:
        first_read(db, admin, clock, connection_id, server)
    # Twelve current observations and eight a month old, whose earliest is the actor's baseline.
    for age in [timedelta(days=1)] * 12 + [MONTH] * 8:
        stored(admin_engine, tenant, connection_id, age=age)
    targets = iter(range(100, 200))

    def read(count):
        records = []
        for _ in range(count):
            kind, record, _ = graph.parse_directory_audit(
                entry(clock.value - MINUTE, target=target(next(targets)))
            )
            assert kind == "mapped"
            records.append(record)
        return store.apply_directory_audit(
            db, admin, connection_id, records, cursor=None, clock=clock
        )

    def episode():
        return connection_row(db, tenant, connection_id)["audit_bound_since"]

    assert read(1)["bounded"] == 1
    began = episode()
    assert began is not None and len(health(db, tenant)) == 1
    # A purge brings the connection to 18, under the bound and not a tenth under it.
    assert purge(db, tenant, clock) == 2
    assert read(0)["bounded"] == 0
    assert episode() == began
    # The next read fills it again: the same episode, and no second finding.
    assert (read(3)["accepted"], episode()) == (2, began)
    assert len(health(db, tenant)) == 1
    # Two more purges leave 16, a tenth under the bound: the next read ends the episode.
    assert purge(db, tenant, clock) + purge(db, tenant, clock) == 4
    assert read(0)["bounded"] == 0
    assert episode() is None
    clock.value += MINUTE
    again = read(5)
    assert (again["accepted"], again["bounded"]) == (4, 1)
    assert episode() == clock.value
    assert [row["title"] for row in health(db, tenant)] == [BOUND_TITLE, BOUND_TITLE]


def test_sr24_collect_due_counts_a_read_at_the_bound(db, admins, clock, tmp_path, monkeypatch):
    """A read at the bound is not a refused read: `collect-due` counts it `audit_bounded` and
    not `audit_failed`."""
    admin = admins[0]
    connection_id = connect(db, admin, clock)
    files = tmp_path / "key-files"
    key_file(files, connection_id, entra=True)
    monkeypatch.setattr(store, "MAX_CONNECTION_EVENTS", 1)
    audits = [
        entry(clock.value - timedelta(hours=1) + index * MINUTE, target=target(index))
        for index in (1, 2)
    ]
    with (
        serving(directory(*audits)) as server,
        httpx.Client(transport=transport(server), trust_env=False) as http,
    ):
        report = due.collect_due(db, key_files=files, client=http, clock=clock)
    counts = report["tenants"][str(admin.tenant_id)]
    assert (counts["collected"], counts["audit_failed"], counts["audit_bounded"]) == (1, 0, 1)
