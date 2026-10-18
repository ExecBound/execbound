# SPDX-License-Identifier: AGPL-3.0-only
"""Directory audit-log observations and the reviewed activity map (#355): SR21 to SR23.

Real PostgreSQL and the fake Graph. Every full collection and every delta pass reads the
directory's audit log after its principals are written: Core Directory entries from the cursor,
oldest first, in a bounded number of pages whose next links stay on the pinned read. An entry an
application initiated that the activity map covers becomes one `entra_audit` observation naming
the actor's service principal and its target by object id alone; one a user initiated is
ignored, and an application's activity the map does not cover is counted and never stored. The
read never changes a run's outcome or health. A connection's first complete read is its activity
baseline, and an observation that matches the one execution ExecBound settled for it is never
reported as an action outside ExecBound.
"""

import json
import os
import re
import sys
from datetime import UTC, datetime, timedelta
from uuid import uuid4

import httpx
import pytest
from console_api_fixtures import every_log_line
from sqlalchemy import text
from test_monitor_collect_due import key_file
from test_monitoring_store import FixedClock
from test_scout_delta import admins as admins
from test_scout_delta import agent_row, connection_row, delta, findings, full, profile, reaching
from test_scout_derived import governed_agent, settle_execution
from test_scout_run import connect, detailed_scenario, principal

from execbound.monitoring import activity_map, commands, due, graph, reach, store, worker
from execbound.monitoring.activity_map import Activity, ActivityMap, MapError
from execbound.monitoring.models import ObservationEvent
from execbound.surfaces import board
from execbound_harness.fake_graph import serving, transport

pytestmark = pytest.mark.integration

ACTOR = principal(9)["id"]
OTHER_ACTOR = principal(10)["id"]
TARGET = "d0d0d0d0-0000-4000-8000-000000000001"
OTHER_TARGET = "d0d0d0d0-0000-4000-8000-000000000002"
PERSON = "eeeeeeee-0000-4000-8000-000000000001"
# The application's own id; read only to be dropped.
APP_ID = "abababab-0000-4000-8000-000000000077"
# Nothing in this list may survive into a table, a run result or a log line.
FORBIDDEN = (
    "person@synthetic.invalid",
    "A Person",
    "A Synthetic Automation",
    "automation@synthetic.invalid",
    "198.51.100.7",
    "A reason nobody should keep",
    "Synthetic detail",
    APP_ID,
    PERSON,
)
DISABLED = ("AccountEnabled", "[true]", "[false]")
ENABLED = ("AccountEnabled", "[false]", "[true]")


@pytest.fixture
def clock():
    return FixedClock(datetime.now(UTC))


def moment(value):
    return value.astimezone(UTC).isoformat().replace("+00:00", "Z")


def whole(value):
    """A moment as a read's filter names it: to the second, never later than it."""
    return moment(value.replace(microsecond=0))


def entry(
    when,
    *,
    actor=ACTOR,
    activity="Disable account",
    service="Core Directory",
    target=TARGET,
    target_type="User",
    changes=(),
    result="success",
    correlation=None,
    user=False,
    on_behalf=False,
    ref=None,
):
    """A directory audit entry as Graph writes one, carrying every field Scout must drop: a
    person's own (`user`), an application's acting for a signed-in person (`on_behalf`), or an
    application's own."""
    return {
        "id": ref or f"Directory_{uuid4()}_ABCDE_{uuid4().int % 10**8}",
        "category": "UserManagement",
        "correlationId": correlation or str(uuid4()),
        "result": result,
        "resultReason": "A reason nobody should keep",
        "activityDisplayName": activity,
        "activityDateTime": moment(when),
        "loggedByService": service,
        "operationType": "Update",
        "initiatedBy": {
            "app": None
            if user and not on_behalf
            else {
                "appId": APP_ID,
                "displayName": "A Synthetic Automation",
                "servicePrincipalId": actor,
                "servicePrincipalName": "automation@synthetic.invalid",
            },
            "user": {
                "id": PERSON,
                "displayName": "A Person",
                "userPrincipalName": "person@synthetic.invalid",
                "ipAddress": "198.51.100.7",
            }
            if user or on_behalf
            else None,
        },
        "targetResources": [
            {
                "id": target,
                "displayName": "A Person",
                "type": target_type,
                "userPrincipalName": "person@synthetic.invalid",
                "groupType": None,
                "modifiedProperties": [
                    {"displayName": name, "oldValue": old, "newValue": new}
                    for name, old, new in changes
                ],
            }
        ],
        "additionalDetails": [{"key": "User-Agent", "value": "Synthetic detail"}],
    }


def directory(*audits, **changes):
    """Two classic service principals that can act, and the audit log `audits`."""
    acting, assignments = reaching(9)
    other, more = reaching(10)
    values = {
        "principals": [acting, other],
        "app_role_assignments": {**assignments, **more},
        "audits": list(audits),
    }
    values.update(changes)
    return detailed_scenario(**values)


def observations(db, tenant):
    with db.transaction(tenant) as conn:
        return [
            dict(row)
            for row in conn.execute(
                text(
                    "SELECT * FROM execbound.monitor_observations "
                    "WHERE kind = 'entra_audit' ORDER BY occurred_at, observation_id"
                )
            )
            .mappings()
            .all()
        ]


def audit_reads(server):
    return [query for path, query, _ in server.requests if path == graph.AUDIT_PATH]


def everything(db, tenant):
    """Every row Scout and Monitor keep for this tenant, as text."""
    tables = (
        "monitor_observations",
        "monitor_connections",
        "monitor_findings",
        "monitor_agents",
        "monitor_agent_reach",
    )
    with db.transaction(tenant) as conn:
        return json.dumps(
            {
                table: [
                    {key: str(value) for key, value in row.items()}
                    for row in conn.execute(text(f"SELECT * FROM execbound.{table}")).mappings()
                ]
                for table in tables
            }
        )


def first_read(db, admin, clock, connection_id, server):
    """The connection's first full collection, whose audit read is complete."""
    result = full(db, admin, clock, connection_id, server)
    assert result["outcome"] == "COMPLETE" and result["audit"]["state"] == "complete"
    return result


def read(db, admin, clock, connection_id, *audits, **changes):
    """The connection's first full collection, of a directory whose audit log holds `audits`."""
    with serving(directory(*audits, **changes)) as server:
        return first_read(db, admin, clock, connection_id, server)


def later(db, admin, clock, connection_id, server, audits, minutes=5):
    """A delta pass `minutes` later, over a directory whose audit log now holds `audits`."""
    clock.value += timedelta(minutes=minutes)
    server.scenario.audits = list(audits)
    return delta(db, admin, clock, connection_id, server)


def busy(start, until, step=timedelta(minutes=1)):
    """A person's changes, one every `step` from `start` through `until`: a log kept busy with
    entries no application initiated, which the read still pages through."""
    entries, when = [], start
    while when <= until:
        entries.append(entry(when, user=True))
        when += step
    return entries


def health(db, tenant):
    return findings(db, tenant, store.COLLECTION_HEALTH_RULE)


# What a refused audit read never touches: the run's record, which says whether and when the
# connection is next collected and whether it is reported as collecting.
SCHEDULE = (
    "last_run_at",
    "last_outcome",
    "last_error_code",
    "retry_after_seconds",
    "consecutive_rate_limited",
    "consecutive_backlog",
    "health_state",
)


def schedule(db, tenant, connection_id, now):
    """The connection's run record, when it is next due and whether it is reported."""
    stored = connection_row(db, tenant, connection_id)
    return (
        {column: stored[column] for column in SCHEDULE},
        due.due_at(stored, now),
        store.collection_reporting(stored, now),
    )


def schedule_kept(db, tenant, connection_id, now):
    """A run whose audit read Graph refused, recorded as one whose read succeeded would be: its
    outcome complete with no last refusal and no Retry-After, reported as collecting, and next
    due a whole interval after it, as `collect-due` reads it."""
    record, due_at, reporting = schedule(db, tenant, connection_id, now)
    assert (record["last_outcome"], record["health_state"]) == ("COMPLETE", "COLLECTING")
    assert (record["last_error_code"], record["retry_after_seconds"]) == (None, None)
    assert (record["consecutive_rate_limited"], record["consecutive_backlog"]) == (0, 0)
    assert reporting is True
    collect, _ = due.intervals(connection_row(db, tenant, connection_id))
    assert due_at == record["last_run_at"] + timedelta(seconds=collect)


# SR21: the read, the map and what is kept


def test_sr21_each_mapped_entry_gives_one_observation_for_its_actor_action_and_target(
    db, admins, clock
):
    admin = admins[0]
    connection_id = connect(db, admin, clock)
    when = clock.value - timedelta(hours=2)
    entries = [
        entry(when, activity="Disable account"),
        entry(when + timedelta(seconds=1), activity="Enable account"),
        entry(when + timedelta(seconds=2), activity="Update user", changes=[DISABLED]),
        entry(when + timedelta(seconds=3), activity="Update user", changes=[ENABLED]),
        entry(when + timedelta(seconds=4), activity="Reset password"),
        entry(
            when + timedelta(seconds=5),
            activity="Update StsRefreshTokenValidFrom Timestamp",
            actor=OTHER_ACTOR,
            target=OTHER_TARGET,
        ),
    ]
    result = read(db, admin, clock, connection_id, *entries)
    assert (result["audit"]["accepted"], result["audit"]["mapped"]) == (6, 6)
    rows = observations(db, admin.tenant_id)
    assert [
        (row["actor_ref"], row["action"], row["target_ref"], row["operation_name"]) for row in rows
    ] == [
        (ACTOR, "identity.disable", TARGET, "entra-audit.v1:disable_account"),
        (ACTOR, "identity.enable", TARGET, "entra-audit.v1:enable_account"),
        (ACTOR, "identity.disable", TARGET, "entra-audit.v1:update_user_disabled"),
        (ACTOR, "identity.enable", TARGET, "entra-audit.v1:update_user_enabled"),
        (ACTOR, "identity.reset_password", TARGET, "entra-audit.v1:reset_password"),
        (OTHER_ACTOR, "identity.revoke_sessions", OTHER_TARGET, "entra-audit.v1:revoke_sessions"),
    ]
    for row, source in zip(rows, entries, strict=True):
        assert row["evidence"] == "collected" and row["connection_id"] == connection_id
        assert row["outcome"] == "success" and row["external_ref"] == source["id"]
        assert row["occurred_at"] == datetime.fromisoformat(source["activityDateTime"])
        assert row["source_id"] is None and row["story_id"] is None
        assert row["event_id"].startswith("audit:")


def test_sr21_one_change_logged_twice_under_one_correlation_is_one_observation(db, admins, clock):
    """One Graph request that disables an account may be logged as `Update user` and as
    `Disable account`: one action on one target under one correlation id is one observation."""
    admin = admins[0]
    connection_id = connect(db, admin, clock)
    correlation = str(uuid4())
    when = clock.value - timedelta(hours=1)
    result = read(
        db,
        admin,
        clock,
        connection_id,
        entry(when, activity="Update user", changes=[DISABLED], correlation=correlation),
        entry(
            when + timedelta(milliseconds=20), activity="Disable account", correlation=correlation
        ),
    )
    assert (result["audit"]["accepted"], result["audit"]["duplicates"]) == (1, 1)
    (row,) = observations(db, admin.tenant_id)
    assert (row["action"], row["target_ref"]) == ("identity.disable", TARGET)
    # A duplicate, not a conflict: nothing was flagged.
    assert row["integrity_conflict_at"] is None
    assert findings(db, admin.tenant_id, "source-event-integrity.v1") == []


# How far apart one change's entries may be logged and still be one observation: ten seconds,
# written here rather than read from the store, so a change to the store's constant fails a test.
SAME_CHANGE = timedelta(seconds=10)
EPOCH = datetime(1970, 1, 1, tzinfo=UTC)


@pytest.mark.parametrize(
    "apart, kept",
    [
        (timedelta(milliseconds=20), 1),
        (SAME_CHANGE, 1),
        (SAME_CHANGE + timedelta(milliseconds=1), 2),
        (timedelta(days=1), 2),
    ],
    ids=["either side of a whole ten seconds", "at the window", "past it", "a day apart"],
)
def test_sr21_entries_under_one_correlation_are_one_change_only_when_logged_together(
    db, admins, clock, apart, kept
):
    """A caller chooses its own correlation id and may use it again. The same actor's action on
    the same target with the same outcome under it is one observation only when its entries are
    logged within ten seconds of each other, as one request's are; one logged later is an
    observation of its own, at its own moment, rather than a copy dropped as a duplicate."""
    admin = admins[0]
    connection_id = connect(db, admin, clock)
    correlation = str(uuid4())
    # Ten milliseconds short of a whole ten seconds, so the pair twenty apart lies either side.
    aligned = (clock.value - timedelta(days=2) - EPOCH) // SAME_CHANGE * SAME_CHANGE
    when = EPOCH + aligned - timedelta(milliseconds=10)
    result = read(
        db,
        admin,
        clock,
        connection_id,
        entry(when, activity="Update user", changes=[DISABLED], correlation=correlation),
        entry(when + apart, activity="Disable account", correlation=correlation),
    )
    assert (result["audit"]["accepted"], result["audit"]["duplicates"]) == (kept, 2 - kept)
    moments = [row["occurred_at"] for row in observations(db, admin.tenant_id)]
    assert moments == ([when] if kept == 1 else [when, when + apart])
    assert findings(db, admin.tenant_id, "source-event-integrity.v1") == []


def test_sr21_a_refused_attempt_and_its_retry_under_one_correlation_are_kept_apart(
    db, admins, clock
):
    """A client may retry under the correlation id it chose: the refused attempt and the success
    are two assertions, and the success is neither dropped as a conflicting copy of the attempt
    nor kept from raising the rule. Neither are two actors' entries under one correlation id one
    observation."""
    admin = admins[0]
    profile(db, admin, clock)
    connection_id = connect(db, admin, clock)
    tenant = admin.tenant_id
    correlation = str(uuid4())
    with serving(directory()) as server:
        first_read(db, admin, clock, connection_id, server)
        failed = clock.value + timedelta(minutes=1)
        result = later(
            db,
            admin,
            clock,
            connection_id,
            server,
            [
                entry(failed, result="failure", correlation=correlation),
                entry(failed + timedelta(seconds=5), correlation=correlation),
                entry(failed + timedelta(seconds=6), actor=OTHER_ACTOR, correlation=correlation),
            ],
        )
    assert (result["audit"]["accepted"], result["audit"]["duplicates"]) == (3, 0)
    kept = sorted((row["actor_ref"], row["outcome"]) for row in observations(db, tenant))
    assert kept == sorted([(ACTOR, "error"), (ACTOR, "success"), (OTHER_ACTOR, "success")])
    assert findings(db, tenant, "source-event-integrity.v1") == []
    clock.value += timedelta(minutes=1)
    worker.evaluate_scheduled(db, tenant, clock=clock)
    raised = {row["platform_ref"] for row in findings(db, tenant, "first-consequential-action.v1")}
    assert raised == {ACTOR, OTHER_ACTOR}


@pytest.mark.parametrize("changed", ["result", "actor"])
def test_sr21_an_entry_served_again_asserting_something_else_is_an_observation_of_its_own(
    db, admins, clock, changed
):
    """Graph serves an entry again under its own id, now asserting another result or another
    actor. What an observation asserts is in its identifier, so this is another change: it is
    an observation of its own, beside the first, rather than a conflicting copy of it, and the
    success it asserts raises the rule. Neither is dropped and no integrity finding is raised,
    because no two observations under one identifier can assert different things."""
    admin = admins[0]
    profile(db, admin, clock)
    connection_id = connect(db, admin, clock)
    tenant = admin.tenant_id
    ref = f"Directory_{uuid4()}_ABCDE_12345678"
    correlation = str(uuid4())
    with serving(directory()) as server:
        first_read(db, admin, clock, connection_id, server)
        when = clock.value + timedelta(minutes=1)
        before = {"result": {"result": "failure"}, "actor": {"actor": OTHER_ACTOR}}[changed]
        first = entry(when, ref=ref, correlation=correlation, **before)
        later(db, admin, clock, connection_id, server, [first])
        result = later(
            db, admin, clock, connection_id, server, [entry(when, ref=ref, correlation=correlation)]
        )
    assert (result["audit"]["accepted"], result["audit"]["duplicates"]) == (1, 0)
    rows = observations(db, tenant)
    assert [row["external_ref"] for row in rows] == [ref, ref]
    assert len({row["event_id"] for row in rows}) == 2
    assert findings(db, tenant, "source-event-integrity.v1") == []
    clock.value += timedelta(minutes=1)
    worker.evaluate_scheduled(db, tenant, clock=clock)
    raised = {
        row["platform_ref"]: row["observation_id"]
        for row in findings(db, tenant, "first-consequential-action.v1")
    }
    (second,) = [row for row in rows if row["actor_ref"] == ACTOR and row["outcome"] == "success"]
    assert raised[ACTOR] == second["observation_id"]


def test_sr21_unmapped_application_activity_is_counted_and_never_stored(db, admins, clock):
    admin = admins[0]
    connection_id = connect(db, admin, clock)
    when = clock.value - timedelta(hours=1)
    result = read(
        db,
        admin,
        clock,
        connection_id,
        # Role assignment: the action catalog has no role action.
        entry(when, activity="Add member to role", target_type="Role"),
        # `Update user` that does not change whether the account is enabled.
        entry(when, activity="Update user", changes=[("DisplayName", "[]", "[]")]),
        entry(when, activity="Update user", changes=[("AccountEnabled", "[true]", "[true]")]),
        entry(when, activity="Update user", changes=[("AccountEnabled", "yes", "no")]),
        # A mapped name on something that is not a user.
        entry(when, activity="Disable account", target_type="Device"),
    )
    assert (result["audit"]["unmapped"], result["audit"]["accepted"]) == (5, 0)
    assert observations(db, admin.tenant_id) == []


def test_sr21_an_entry_a_user_initiated_is_ignored_and_one_naming_no_principal_is_counted(
    db, admins, clock
):
    admin = admins[0]
    connection_id = connect(db, admin, clock)
    when = clock.value - timedelta(hours=1)
    result = read(
        db,
        admin,
        clock,
        connection_id,
        entry(when, user=True),
        # An application acting for a signed-in person acts with the person's authority.
        entry(when, on_behalf=True),
        entry(when, actor=None),
    )
    assert (result["audit"]["user"], result["audit"]["unattributed"]) == (2, 1)
    assert observations(db, admin.tenant_id) == []


def scheduled(monkeypatch, capsys, server, *arguments):
    """One run of the monitoring command the jobs service runs, against the fake directory, with
    what it printed."""
    monkeypatch.setenv("DATABASE_URL", os.environ["TEST_DATABASE_URL"])
    monkeypatch.setattr(
        commands,
        "_http_client",
        lambda: httpx.Client(transport=transport(server), trust_env=False, follow_redirects=False),
    )
    monkeypatch.setattr(sys, "argv", ["commands", *arguments])
    commands.main()
    printed = capsys.readouterr()
    return printed.out + printed.err


def parsed(line):
    """A printed line as the JSON object it holds, or an empty one."""
    try:
        value = json.loads(line)
    except ValueError:
        return {}
    return value if isinstance(value, dict) else {}


def test_sr21_nothing_that_identifies_a_person_or_an_application_is_kept(
    db, admins, clock, tmp_path, monkeypatch, capsys
):
    """As the jobs service reads and evaluates the log, and as an operator's run reads it: no
    row, no result, nothing printed and no log line any logger writes (`every_log_line`, since
    ExecBound's own logger does not propagate to `caplog` and keeps its fields off the message)
    holds a value that names a person or the application."""
    admin = admins[0]
    connection_id = connect(db, admin, clock)
    files = tmp_path / "key-files"
    key_file(files, connection_id, entra=True)
    # Inside the overlap, so the operator's run after the scheduled one reads them again.
    when = clock.value - timedelta(minutes=10)
    audits = (
        entry(when, activity="Update user", changes=[DISABLED]),
        entry(when, user=True),
        entry(when, activity="Add member to role"),
        entry(when, result="failure", target=OTHER_TARGET),
    )
    with every_log_line() as logged, serving(directory(*audits)) as server:
        printed = scheduled(
            monkeypatch, capsys, server, "collect-due", "--all-tenants", "--key-files", str(files)
        )
        # The jobs service's pass collected this connection and read its log itself: what the
        # operator's run reads after it is all a copy, so the sweep covers both halves.
        (report,) = [value for value in map(parsed, printed.splitlines()) if "tenants" in value]
        assert report["tenants"][str(admin.tenant_id)]["collected"] == 1
        assert len(observations(db, admin.tenant_id)) == 2
        printed += scheduled(monkeypatch, capsys, server, "process", "--all-tenants")
        # The scheduled runs read the host's clock; the operator's runs after them.
        clock.value = datetime.now(UTC)
        result = full(db, admin, clock, connection_id, server)
    assert (result["audit"]["mapped"], result["audit"]["duplicates"]) == (2, 2)
    # Both halves were captured, so an empty sweep is not a vacuous one.
    assert logged.holds("monitor.collect_due")
    kept = everything(db, admin.tenant_id) + json.dumps(result, default=str) + printed + logged()
    assert len(observations(db, admin.tenant_id)) == 2
    for value in FORBIDDEN:
        assert value not in kept, value


def test_sr21_a_failed_entry_is_kept_as_an_error(db, admins, clock):
    admin = admins[0]
    connection_id = connect(db, admin, clock)
    when = clock.value - timedelta(hours=1)
    read(
        db,
        admin,
        clock,
        connection_id,
        entry(when, result="failure"),
        entry(when, result="timeout", target=OTHER_TARGET),
    )
    outcomes = {row["target_ref"]: row["outcome"] for row in observations(db, admin.tenant_id)}
    assert outcomes == {TARGET: "error", OTHER_TARGET: "unknown"}


def _values(item, **changes):
    return {
        "key": item.key,
        "service": item.service,
        "name": item.name,
        "action": item.action,
        "change": item.change,
        "source": item.source,
        "retrieved": item.retrieved,
        **changes,
    }


def test_sr21_the_map_names_its_sources_and_maps_only_catalog_actions():
    for item in activity_map.PRODUCTION.activities:
        assert item.source == activity_map.REFERENCE and item.retrieved == activity_map.READ_ON
        assert item.service == "Core Directory"
    assert {item.action for item in activity_map.PRODUCTION.activities} == {
        "identity.disable",
        "identity.enable",
        "identity.reset_password",
        "identity.revoke_sessions",
    }
    base = activity_map.PRODUCTION.activities[0]
    # An action the catalog does not hold, such as a role assignment, is refused when built.
    for changed in (
        {"action": "role.assign"},
        {"key": "Not a key"},
        {"key": base.key + "\n"},
        {"source": "http://learn.microsoft.com/"},
        {"change": ("DisplayName", True, False)},
        {"change": ("AccountEnabled", True, True)},
    ):
        with pytest.raises(MapError):
            ActivityMap((Activity(**_values(base, **changed)),))
    # One activity name is one action, or several told apart by the property they change.
    with pytest.raises(MapError):
        ActivityMap((base, Activity(**_values(base, key="again"))))
    production = activity_map.PRODUCTION
    assert production.match("Core Directory", "Update user", {}) is None
    found = production.match("Core Directory", "Update user", {"AccountEnabled": (True, False)})
    assert found is not None and found.action == "identity.disable"
    assert production.match("Self-service Group Management", "Disable account", {}) is None


@pytest.mark.parametrize(
    "value, flag",
    [
        ("[true]", True),
        ("[false]", False),
        ("true", True),
        ('["False"]', False),
        ("[]", None),
        ("[true,false]", None),
        ("maybe", None),
        (None, None),
        (True, True),
    ],
)
def test_sr21_a_modified_value_is_read_as_a_boolean_or_not_at_all(value, flag):
    assert graph.audit_flag(value) is flag


# Values a response may hold where the parser reads a field: unhashable, of another type, out
# of the range a moment can be converted in, longer than any field Graph writes, or an
# identifier ending in a newline, which a pattern read with Python's `re.match` accepts, because
# its `$` matches before a final newline, and the column's check refuses, because PostgreSQL's
# `$` is the end of the value.
HOSTILE = (
    [1],
    [["AccountEnabled"]],
    {"displayName": "AccountEnabled"},
    1,
    -1.5,
    True,
    None,
    "",
    "x" * 5000,
    "0001-01-01T00:00:00+01:00",
    "9999-12-31T23:59:59-01:00",
    TARGET + "\n",
    ACTOR + "\n",
    "Directory_abc\n",
)
# What the columns an audit observation is stored in accept, read as PostgreSQL reads their
# checks: 0094's GUID for the target, and 0023's reference for the actor and the entry id.
STORED_GUID = re.compile(
    r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}"
)
STORED_REF = re.compile(r"[A-Za-z0-9._:-]{1,96}")
READ = (
    ("id",),
    ("activityDateTime",),
    ("activityDisplayName",),
    ("loggedByService",),
    ("result",),
    ("correlationId",),
    ("initiatedBy",),
    ("initiatedBy", "app"),
    ("initiatedBy", "user"),
    ("initiatedBy", "app", "servicePrincipalId"),
    ("targetResources",),
    ("targetResources", 0),
    ("targetResources", 0, "id"),
    ("targetResources", 0, "type"),
    ("targetResources", 0, "modifiedProperties"),
    ("targetResources", 0, "modifiedProperties", 0),
    ("targetResources", 0, "modifiedProperties", 0, "displayName"),
    ("targetResources", 0, "modifiedProperties", 0, "oldValue"),
    ("targetResources", 0, "modifiedProperties", 0, "newValue"),
)


@pytest.mark.parametrize("path", READ, ids=lambda path: ".".join(map(str, path)))
def test_sr21_an_entry_the_parser_cannot_read_is_classified_and_never_raises(path):
    """Whatever a response holds where the parser reads a field, the entry is one of the
    parser's kinds, and one it maps is one the database stores: nothing in it can stop a read,
    a run or the scheduled pass."""
    for value in HOSTILE:
        record = entry(
            datetime.now(UTC) - timedelta(hours=1), activity="Update user", changes=[DISABLED]
        )
        holder = record
        for key in path[:-1]:
            holder = holder[key]
        holder[path[-1]] = value
        kind, found, _ = graph.parse_directory_audit(record)
        assert kind in {"mapped", "user", "unattributed", "unmapped", "dropped"}, value
        assert (found is not None) == (kind == "mapped"), value
        if found is not None:
            assert STORED_GUID.fullmatch(found.target_ref), value
            assert STORED_REF.fullmatch(found.actor_ref), value
            assert STORED_REF.fullmatch(found.entry_ref), value


@pytest.mark.parametrize(
    "stamp, kind",
    [
        ("0001-01-01T00:00:05Z", "dropped"),
        ("0001-01-02T00:00:01Z", "mapped"),
        ("9999-12-30T23:59:58Z", "mapped"),
        ("9999-12-31T23:59:59Z", "dropped"),
    ],
)
def test_sr21_a_moment_within_a_day_of_either_end_of_the_calendar_is_dropped(stamp, kind):
    """An entry the map covers is dropped by the parser itself when it is stamped within a day of
    either end of the calendar, where the collector's own arithmetic on a moment would run off
    the end, and mapped just inside that day: each side of the bound has a failing case."""
    record = entry(
        datetime.now(UTC) - timedelta(hours=1), activity="Update user", changes=[DISABLED]
    )
    record["activityDateTime"] = stamp
    found_kind, found, _ = graph.parse_directory_audit(record)
    assert (found_kind, found is not None) == (kind, kind == "mapped")


def test_sr21_a_read_meeting_entries_it_cannot_read_counts_them_and_the_run_completes(
    db, admins, clock
):
    """An unhashable property name, a moment past the last a clock can name and one at its last
    second, which no arithmetic can step past: the read counts them and goes on, and the run
    records its outcome."""
    admin = admins[0]
    connection_id = connect(db, admin, clock)
    when = clock.value - timedelta(hours=1)
    unhashable = entry(when, activity="Update user", changes=[DISABLED])
    unhashable["targetResources"][0]["modifiedProperties"][0]["displayName"] = ["AccountEnabled"]
    distant = entry(when, target=OTHER_TARGET)
    distant["activityDateTime"] = "9999-12-31T23:59:59-01:00"
    last = entry(when, target=OTHER_TARGET, activity="Reset password")
    last["activityDateTime"] = "9999-12-31T23:59:59Z"
    result = read(db, admin, clock, connection_id, unhashable, entry(when), distant, last)
    assert (result["audit"]["unmapped"], result["audit"]["dropped"]) == (1, 2)
    assert result["audit"]["accepted"] == 1
    stored = connection_row(db, admin.tenant_id, connection_id)
    assert (stored["last_outcome"], stored["last_run_at"]) == ("COMPLETE", clock.value)


@pytest.mark.parametrize(
    "field, kind",
    [("target", "unmapped"), ("actor", "unattributed"), ("entry", "dropped")],
)
def test_sr21_an_identifier_the_database_would_refuse_is_never_mapped_and_the_run_completes(
    db, admins, clock, field, kind
):
    """An identifier ending in a newline passes a pattern Python reads with `re.match` and fails
    the column's check, which would roll the read back and leave the connection due on every
    pass, re-reading the same entry from the same cursor until Graph's retention drops it. The
    parser reads each identifier whole, so the entry is counted and the read goes on past it."""
    admin = admins[0]
    connection_id = connect(db, admin, clock)
    when = clock.value - timedelta(hours=1)
    odd = {
        "target": entry(when, target=TARGET + "\n"),
        "actor": entry(when, actor=ACTOR + "\n"),
        "entry": entry(when, ref="Directory_abc\n"),
    }[field]
    result = read(db, admin, clock, connection_id, odd, entry(when, target=OTHER_TARGET))
    assert (result["audit"][kind], result["audit"]["accepted"]) == (1, 1)
    (row,) = observations(db, admin.tenant_id)
    assert row["target_ref"] == OTHER_TARGET
    stored = connection_row(db, admin.tenant_id, connection_id)
    assert (stored["last_outcome"], stored["last_run_at"]) == ("COMPLETE", clock.value)
    assert stored["audit_baseline_at"] == clock.value


# SR22: the read's bounds, its cursor and what it never changes


def test_sr22_the_read_asks_for_core_directory_entries_oldest_first_from_the_cursor(
    db, admins, clock
):
    admin = admins[0]
    connection_id = connect(db, admin, clock)
    began = clock.value
    with serving(directory()) as server:
        first_read(db, admin, clock, connection_id, server)
        probe, first = audit_reads(server)
        clock.value += timedelta(hours=7)
        first_read(db, admin, clock, connection_id, server)
        second = audit_reads(server)[3]
    assert probe == {"$top": "1"}
    assert first == {
        "$filter": f"activityDateTime ge {whole(began - timedelta(days=30))} "
        "and loggedByService eq 'Core Directory'",
        "$orderby": "activityDateTime asc",
        "$top": "100",
    }
    # Read through the first run's moment, less the overlap that catches a late entry.
    assert second["$filter"].startswith(
        f"activityDateTime ge {whole(began - graph.AUDIT_OVERLAP)} "
    )
    stored = connection_row(db, admin.tenant_id, connection_id)
    # To the second, never later, so the next read names it as it is kept.
    assert stored["audit_cursor"] == (clock.value - graph.AUDIT_OVERLAP).replace(microsecond=0)
    assert stored["audit_baseline_at"] == began


@pytest.mark.parametrize(
    "hostile",
    [
        "https://graph.example.invalid/v1.0/auditLogs/directoryAudits?$skiptoken=1",
        "https://graph.microsoft.com/v1.0/users?$skiptoken=1",
        "http://graph.microsoft.com/v1.0/auditLogs/directoryAudits?$skiptoken=1",
        "https://graph.microsoft.com:8443/v1.0/auditLogs/directoryAudits?$skiptoken=1",
        "https://graph.microsoft.com:99999/v1.0/auditLogs/directoryAudits?$skiptoken=1",
        "https://[graph.microsoft.com/v1.0/auditLogs/directoryAudits?$skiptoken=1",
    ],
)
def test_sr22_a_next_link_off_the_pinned_read_is_never_followed(db, admins, clock, hostile):
    admin = admins[0]
    connection_id = connect(db, admin, clock)
    when = clock.value - timedelta(days=2)
    scenario = directory(
        entry(when),
        entry(when + timedelta(minutes=1), target=OTHER_TARGET),
        max_top=1,
        audit_next_link=hostile,
    )
    with serving(scenario) as server:
        result = full(db, admin, clock, connection_id, server)
        reads = audit_reads(server)
    # The probe and the first page, and never the link.
    assert len(reads) == 2
    assert result["outcome"] == "COMPLETE"
    assert (result["audit"]["state"], result["audit"]["error_code"]) == ("failed", "MALFORMED")
    # What the first page held is kept, and the cursor stops at it.
    (row,) = observations(db, admin.tenant_id)
    assert row["target_ref"] == TARGET
    stored = connection_row(db, admin.tenant_id, connection_id)
    assert stored["audit_cursor"] == when.replace(microsecond=0)
    assert stored["audit_baseline_at"] is None
    schedule_kept(db, admin.tenant_id, connection_id, clock.value)


def test_sr22_a_read_is_bounded_and_the_next_run_continues_where_it_stopped(db, admins, clock):
    admin = admins[0]
    connection_id = connect(db, admin, clock)
    start = clock.value - timedelta(days=3)
    entries = [
        entry(start + timedelta(minutes=index), target=f"d0d0d0d0-0000-4000-8000-{index:012d}")
        for index in range(graph.MAX_AUDIT_PAGES * 2 + 1)
    ]
    with serving(directory(*entries, max_top=2)) as server:
        result = full(db, admin, clock, connection_id, server)
        assert len(audit_reads(server)) == 1 + graph.MAX_AUDIT_PAGES
        assert (result["outcome"], result["audit"]["state"]) == ("COMPLETE", "backlog")
        stored = connection_row(db, admin.tenant_id, connection_id)
        # At the second of the last entry read, and no baseline until a read catches up.
        last = start + timedelta(minutes=graph.MAX_AUDIT_PAGES * 2 - 1)
        assert stored["audit_cursor"] == last.replace(microsecond=0)
        assert stored["audit_baseline_at"] is None
        result = later(db, admin, clock, connection_id, server, entries)
    assert result["audit"]["state"] == "complete"
    # The entry at the cursor is read again and recognised.
    assert (result["audit"]["accepted"], result["audit"]["duplicates"]) == (1, 1)
    assert len(observations(db, admin.tenant_id)) == len(entries)
    assert connection_row(db, admin.tenant_id, connection_id)["audit_baseline_at"] == clock.value


def test_sr22_a_read_repeated_changes_nothing(db, admins, clock):
    admin = admins[0]
    connection_id = connect(db, admin, clock)
    when = clock.value - timedelta(minutes=10)
    entries = [entry(when), entry(when, activity="Reset password")]
    with serving(directory(*entries)) as server:
        first_read(db, admin, clock, connection_id, server)
        before = observations(db, admin.tenant_id)
        result = later(db, admin, clock, connection_id, server, entries)
    # Inside the overlap, so read again, and recognised.
    assert (result["audit"]["accepted"], result["audit"]["duplicates"]) == (0, 2)
    assert observations(db, admin.tenant_id) == before
    assert findings(db, admin.tenant_id, "source-event-integrity.v1") == []


def test_sr22_entries_out_of_order_are_refused(db, admins, clock):
    admin = admins[0]
    connection_id = connect(db, admin, clock)
    when = clock.value - timedelta(hours=3)
    scenario = directory(
        entry(when), entry(when + timedelta(hours=1), target=OTHER_TARGET), audit_descending=True
    )
    with serving(scenario) as server:
        result = full(db, admin, clock, connection_id, server)
    assert (result["audit"]["state"], result["audit"]["error_code"]) == ("failed", "MALFORMED")
    assert observations(db, admin.tenant_id) == []
    assert connection_row(db, admin.tenant_id, connection_id)["audit_cursor"] is None
    schedule_kept(db, admin.tenant_id, connection_id, clock.value)


def test_sr22_a_registration_refused_the_audit_log_completes_and_shows_it(db, admins, clock):
    admin = admins[0]
    connection_id = connect(db, admin, clock)
    entries = [entry(clock.value - timedelta(hours=1))]
    with serving(directory(*entries, status={"audits": 403})) as server:
        result = full(db, admin, clock, connection_id, server)
        # The probe, and no read.
        assert audit_reads(server) == [{"$top": "1"}]
        assert result["outcome"] == "COMPLETE"
        assert result["capabilities"]["audit_log"] == "forbidden"
        assert result["audit"]["state"] == "forbidden"
        stored = connection_row(db, admin.tenant_id, connection_id)
        assert stored["capabilities"]["audit_log"]["state"] == "forbidden"
        # The documented consent includes the audit log, so the connection is not complete
        # without it; it is still collected.
        assert store.collection_reporting(stored, clock.value) is False
        assert stored["last_sync_at"] is not None and stored["baseline_at"] is not None
        # A delta pass does not ask either.
        server.requests.clear()
        result = later(db, admin, clock, connection_id, server, entries)
        assert audit_reads(server) == []
    assert result["outcome"] == "COMPLETE" and result["audit"]["state"] == "forbidden"
    assert observations(db, admin.tenant_id) == []


@pytest.mark.parametrize("status, code", [(429, "RATE_LIMITED"), (500, "UNAVAILABLE")])
def test_sr22_a_refused_read_keeps_the_cursor_and_the_run_as_it_was(
    db, admins, clock, status, code
):
    """Graph throttles the audit read, with a Retry-After, or is unavailable. A delta pass
    leaves the run's record, its schedule and whether it is reported exactly as they were, and
    a full collection records its run as one whose read succeeded: no last refusal, no
    Retry-After, reported, and due a whole interval later."""
    admin = admins[0]
    connection_id = connect(db, admin, clock)
    tenant = admin.tenant_id
    with serving(directory()) as server:
        first_read(db, admin, clock, connection_id, server)
        cursor = connection_row(db, tenant, connection_id)["audit_cursor"]
        server.scenario.audit_status = status
        server.scenario.retry_after = "3600"
        before = schedule(db, tenant, connection_id, clock.value + timedelta(minutes=5))
        result = later(db, admin, clock, connection_id, server, [entry(clock.value)])
        assert result["outcome"] == "COMPLETE" and result["link"] == "advanced"
        assert (result["audit"]["state"], result["audit"]["error_code"]) == ("failed", code)
        assert connection_row(db, tenant, connection_id)["audit_cursor"] == cursor
        assert schedule(db, tenant, connection_id, clock.value) == before
        clock.value += timedelta(hours=7)
        result = full(db, admin, clock, connection_id, server)
    # A full collection's outcome and health are its inventory's.
    assert (result["outcome"], result["audit"]["state"]) == ("COMPLETE", "failed")
    schedule_kept(db, tenant, connection_id, clock.value)
    assert connection_row(db, tenant, connection_id)["audit_cursor"] == cursor
    assert observations(db, tenant) == []


def test_sr22_a_read_refused_part_way_leaves_the_cursor_behind_the_overlap(db, admins, clock):
    """Graph throttles a read at its second page after the first reached an entry two minutes
    old. The cursor stops thirty minutes before the read's moment, not at that entry, so an entry
    Graph makes available late, stamped between the two, is still read by the next run."""
    admin = admins[0]
    connection_id = connect(db, admin, clock)
    with serving(directory(max_top=1)) as server:
        first_read(db, admin, clock, connection_id, server)
        clock.value += timedelta(minutes=5)
        kept, unread = entry(clock.value - timedelta(minutes=2)), entry(clock.value)
        server.scenario.audits = [kept, unread]
        server.scenario.audit_page_status = 429
        server.scenario.retry_after = "3600"
        before = schedule(db, admin.tenant_id, connection_id, clock.value)
        result = delta(db, admin, clock, connection_id, server)
        assert (result["audit"]["state"], result["audit"]["error_code"]) == (
            "failed",
            "RATE_LIMITED",
        )
        assert result["audit"]["accepted"] == 1
        assert schedule(db, admin.tenant_id, connection_id, clock.value) == before
        stored = connection_row(db, admin.tenant_id, connection_id)
        assert stored["audit_cursor"] == (clock.value - graph.AUDIT_OVERLAP).replace(microsecond=0)
        # Published late, after the throttled read had passed its moment.
        published = entry(clock.value - timedelta(minutes=10), target=OTHER_TARGET)
        server.scenario.audit_page_status = None
        server.scenario.max_top = 100
        result = later(db, admin, clock, connection_id, server, [published, kept, unread])
    assert result["audit"]["state"] == "complete"
    assert (result["audit"]["accepted"], result["audit"]["duplicates"]) == (2, 1)
    assert {row["target_ref"] for row in observations(db, admin.tenant_id)} == {
        TARGET,
        OTHER_TARGET,
    }


def test_sr22_the_cursor_never_moves_back_when_the_clock_does(db, admins, clock, monkeypatch):
    """The host's clock is set back an hour, and the next delta pass's read, which catches up,
    then ends thirty minutes before a moment earlier than the cursor. The read never asks the
    store to move the cursor back, and the cursor stays where it was."""
    admin = admins[0]
    connection_id = connect(db, admin, clock)
    asked = []
    apply = store.apply_directory_audit

    def recorded(*args, **kwargs):
        asked.append(kwargs["cursor"])
        return apply(*args, **kwargs)

    with serving(directory()) as server:
        clock.value += timedelta(hours=2)
        first_read(db, admin, clock, connection_id, server)
        cursor = connection_row(db, admin.tenant_id, connection_id)["audit_cursor"]
        monkeypatch.setattr(store, "apply_directory_audit", recorded)
        clock.value -= timedelta(hours=1)
        assert delta(db, admin, clock, connection_id, server)["audit"]["state"] == "complete"
    assert asked == [cursor]
    assert connection_row(db, admin.tenant_id, connection_id)["audit_cursor"] == cursor


def test_sr22_the_store_never_moves_the_cursor_back(db, admins, clock):
    """The store keeps the rule itself, whatever a read hands it: an earlier cursor leaves the
    one it holds, and a later one moves it."""
    admin = admins[0]
    connection_id = connect(db, admin, clock)
    with serving(directory()) as server:
        first_read(db, admin, clock, connection_id, server)
    cursor = connection_row(db, admin.tenant_id, connection_id)["audit_cursor"]
    for offered, kept in (
        (cursor - timedelta(hours=1), cursor),
        (cursor + timedelta(minutes=5), cursor + timedelta(minutes=5)),
    ):
        store.apply_directory_audit(db, admin, connection_id, [], cursor=offered, clock=clock)
        assert connection_row(db, admin.tenant_id, connection_id)["audit_cursor"] == kept


def test_sr22_an_entry_stamped_over_a_day_ahead_of_the_read_waits_for_one_it_is_not(
    db, admins, clock
):
    """An entry Graph stamps more than a day after the read's own moment has not happened by
    any clock the read trusts. The read counts it as dropped and keeps nothing of it; the cursor
    never passes the read's moment less the overlap, so every later read meets it again, and
    the first it is no more than a day ahead of keeps it, at the moment Graph stamped, where
    the clock-skew rule flags it like any entry ahead of its receipt."""
    admin = admins[0]
    connection_id = connect(db, admin, clock)
    stamped = clock.value + timedelta(days=2)
    ahead = entry(stamped)
    with serving(directory(ahead)) as server:
        result = first_read(db, admin, clock, connection_id, server)
        assert (result["audit"]["dropped"], result["audit"]["accepted"]) == (1, 0)
        assert observations(db, admin.tenant_id) == []
        # A day and a minute ahead of the next read: still too far.
        clock.value = stamped - timedelta(days=1, minutes=1)
        result = first_read(db, admin, clock, connection_id, server)
        assert (result["audit"]["dropped"], result["audit"]["accepted"]) == (1, 0)
        assert connection_row(db, admin.tenant_id, connection_id)["audit_cursor"] < stamped
        # A day ahead of this one, and kept.
        clock.value = stamped - timedelta(days=1)
        result = first_read(db, admin, clock, connection_id, server)
    assert (result["audit"]["dropped"], result["audit"]["accepted"]) == (0, 1)
    (row,) = observations(db, admin.tenant_id)
    assert (row["occurred_at"], row["received_at"]) == (stamped, clock.value)
    assert store.evaluate_pending(db, admin, clock=clock) == 1
    assert len(findings(db, admin.tenant_id, "clock-skew.v1")) == 1


def test_sr22_a_delta_pass_reads_the_log_and_changes_no_outcome_or_schedule(db, admins, clock):
    admin = admins[0]
    connection_id = connect(db, admin, clock)
    with serving(directory()) as server:
        first_read(db, admin, clock, connection_id, server)
        before = connection_row(db, admin.tenant_id, connection_id)
        result = later(db, admin, clock, connection_id, server, [entry(clock.value)])
    assert result["audit"]["accepted"] == 1
    after = connection_row(db, admin.tenant_id, connection_id)
    for column in (
        "last_run_at",
        "last_outcome",
        "last_sync_at",
        "health_state",
        "last_error_code",
    ):
        assert after[column] == before[column], column
    assert after["audit_cursor"] == (clock.value - graph.AUDIT_OVERLAP).replace(microsecond=0)


def test_sr22_a_log_busy_past_every_read_still_catches_up_and_sets_the_baseline(db, admins, clock):
    """A directory busy around the clock: no read reaches a page without a next link, but one
    that reads past thirty minutes before its own moment has read the log as far as the next
    read would start, so it has caught up and sets the activity baseline, and what a later read
    finds raises the rule."""
    admin = admins[0]
    profile(db, admin, clock)
    connection_id = connect(db, admin, clock)
    tenant = admin.tenant_id
    with serving(directory(status={"audits": 403}, max_top=2)) as server:
        full(db, admin, clock, connection_id, server)
        server.scenario.status = {}
        clock.value += timedelta(hours=7)
        now = clock.value
        habit = entry(now - timedelta(minutes=32, seconds=30))
        server.scenario.audits = [*busy(now - timedelta(minutes=33), now), habit]
        result = full(db, admin, clock, connection_id, server)
        # Eight entries a run: the habit and seven of the person's, through 27 minutes back.
        assert (result["audit"]["state"], result["audit"]["mapped"]) == ("complete", 1)
        stored = connection_row(db, tenant, connection_id)
        assert stored["audit_baseline_at"] == now
        assert stored["audit_cursor"] == (now - graph.AUDIT_OVERLAP).replace(microsecond=0)
        acted = now - timedelta(minutes=25, seconds=30)
        result = later(
            db,
            admin,
            clock,
            connection_id,
            server,
            [
                *busy(now - timedelta(minutes=33), now + timedelta(minutes=5)),
                habit,
                entry(acted, actor=OTHER_ACTOR, target=OTHER_TARGET),
            ],
        )
        assert result["audit"]["state"] == "complete"
    clock.value += timedelta(minutes=1)
    assert store.evaluate_actions(db, admin, clock=clock)["raised"] == 1
    (raised,) = findings(db, tenant, "first-consequential-action.v1")
    assert raised["platform_ref"] == OTHER_ACTOR


def test_sr22_a_read_moves_on_past_more_entries_than_it_reads_in_one_second(db, admins, clock):
    """A bulk change can log more entries inside one second than a run reads. A read that
    never left the second it started in leaves the cursor at its last entry, to the
    microsecond, so the next reads on rather than reading the same entries again."""
    admin = admins[0]
    connection_id = connect(db, admin, clock)
    second = (clock.value - timedelta(hours=2)).replace(microsecond=0)
    entries = [
        entry(
            second + timedelta(milliseconds=10 * index),
            target=f"d0d0d0d0-0000-4000-8000-{index:012d}",
        )
        for index in range(20)
    ]
    with serving(directory(*entries, max_top=2)) as server:
        states = [full(db, admin, clock, connection_id, server)["audit"]["state"]]
        while states[-1] != "complete" and len(states) < 6:
            states.append(later(db, admin, clock, connection_id, server, entries)["audit"]["state"])
        # Each read's first page; the pages after it carry Graph's skip token.
        filters = [
            query["$filter"]
            for query in audit_reads(server)
            if "$filter" in query and "$skiptoken" not in query
        ]
    assert states == ["backlog", "backlog", "backlog", "complete"]
    assert len(observations(db, admin.tenant_id)) == len(entries)
    # Whole seconds, until a read that never left its second leaves a moment inside it.
    assert [item.split()[2] for item in filters[1:]] == [
        whole(second),
        moment(second + timedelta(milliseconds=70)),
        moment(second + timedelta(milliseconds=140)),
    ]


def test_sr22_a_read_behind_for_a_day_raises_one_health_finding_per_episode(db, admins, clock):
    """The audit read's own lag, and nothing about the run: the run's outcome and the
    connection's health stay its inventory's. One finding an episode, from the first read that
    did not catch up until one that does."""
    admin = admins[0]
    connection_id = connect(db, admin, clock)
    tenant = admin.tenant_id
    began = clock.value
    # A person's change every ten minutes for three days: four a run never catch up.
    entries = busy(began - timedelta(days=3), began, step=timedelta(minutes=10))
    with serving(directory(*entries, max_top=1)) as server:
        assert full(db, admin, clock, connection_id, server)["audit"]["state"] == "backlog"
        assert connection_row(db, tenant, connection_id)["audit_behind_since"] == began
        assert later(db, admin, clock, connection_id, server, entries)["audit"]["state"] == (
            "backlog"
        )
        assert health(db, tenant) == []
        clock.value = began + store.AUDIT_BEHIND_ALERT
        result = full(db, admin, clock, connection_id, server)
        assert (result["outcome"], result["audit"]["state"]) == ("COMPLETE", "backlog")
        (raised,) = health(db, tenant)
        assert raised["title"] == store.HEALTH_TITLES["BACKLOG"]
        assert raised["connection_id"] == connection_id and raised["delivered"]
        stored = connection_row(db, tenant, connection_id)
        assert (stored["last_outcome"], stored["health_state"]) == ("COMPLETE", "COLLECTING")
        assert stored["last_error_code"] is None and stored["audit_behind_since"] == began
        later(db, admin, clock, connection_id, server, entries)
        assert len(health(db, tenant)) == 1
        # Read through: the episode ends.
        assert later(db, admin, clock, connection_id, server, [])["audit"]["state"] == "complete"
        assert connection_row(db, tenant, connection_id)["audit_behind_since"] is None
        # Behind again, and a day later the new episode raises its own.
        again = clock.value + timedelta(minutes=5)
        flood = busy(again - timedelta(minutes=40), again, step=timedelta(seconds=30))
        assert later(db, admin, clock, connection_id, server, flood)["audit"]["state"] == "backlog"
        clock.value = again + store.AUDIT_BEHIND_ALERT
        assert full(db, admin, clock, connection_id, server)["audit"]["state"] == "backlog"
    assert len(health(db, tenant)) == 2


def test_sr22_a_read_refused_for_a_day_raises_the_same_health_finding(db, admins, clock):
    admin = admins[0]
    connection_id = connect(db, admin, clock)
    tenant = admin.tenant_id
    with serving(directory()) as server:
        first_read(db, admin, clock, connection_id, server)
        server.scenario.audit_status = 500
        assert later(db, admin, clock, connection_id, server, [])["audit"]["state"] == "failed"
        began = clock.value
        assert connection_row(db, tenant, connection_id)["audit_behind_since"] == began
        clock.value = began + store.AUDIT_BEHIND_ALERT
        result = full(db, admin, clock, connection_id, server)
    assert (result["outcome"], result["audit"]["state"]) == ("COMPLETE", "failed")
    (raised,) = health(db, tenant)
    assert raised["title"] == store.HEALTH_TITLES["BACKLOG"]
    schedule_kept(db, tenant, connection_id, clock.value)


def test_sr22_a_read_skipped_as_refused_ends_the_episode_a_refused_read_began(
    db, admins, admin_engine, clock
):
    """A connection probed before the audit log was asked for holds no `audit_log` capability,
    so its delta pass reads the log and Graph refuses it: an episode begins. The next full
    collection records the capability `forbidden`, and the log is not read from then on, so no
    read can end that episode; the skipped read ends it. Weeks later the permission is granted,
    and the first read's look-back begins an episode of its own rather than one weeks old."""
    admin = admins[0]
    connection_id = connect(db, admin, clock)
    tenant = admin.tenant_id
    with serving(directory(status={"audits": 403}, max_top=1)) as server:
        full(db, admin, clock, connection_id, server)
        with admin_engine.begin() as conn:
            conn.execute(
                text(
                    "UPDATE execbound.monitor_connections "
                    "SET capabilities = capabilities - 'audit_log' WHERE connection_id = :i"
                ),
                {"i": connection_id},
            )
        result = later(db, admin, clock, connection_id, server, [])
        assert (result["audit"]["state"], result["audit"]["error_code"]) == (
            "failed",
            "FORBIDDEN",
        )
        assert connection_row(db, tenant, connection_id)["audit_behind_since"] == clock.value
        clock.value += timedelta(hours=7)
        assert full(db, admin, clock, connection_id, server)["audit"]["state"] == "forbidden"
        assert connection_row(db, tenant, connection_id)["audit_behind_since"] is None
        assert later(db, admin, clock, connection_id, server, [])["audit"]["state"] == ("forbidden")
        clock.value += timedelta(days=21)
        server.scenario.status = {}
        server.scenario.audits = busy(
            clock.value - timedelta(days=2), clock.value, step=timedelta(hours=1)
        )
        assert full(db, admin, clock, connection_id, server)["audit"]["state"] == "backlog"
        assert connection_row(db, tenant, connection_id)["audit_behind_since"] == clock.value
    assert health(db, tenant) == []


def test_sr22_a_cursor_retention_has_passed_raises_one_retention_gap_finding(
    db, admins, admin_engine, clock
):
    """A cursor further back than the longest retention Graph offers: what lay between it and
    that retention is gone, and the finding says so once for the episode, however many reads
    start from that cursor before one catches up. Here Graph refuses the first two, so each
    run starts from the same old cursor."""
    admin = admins[0]
    connection_id = connect(db, admin, clock)
    tenant = admin.tenant_id
    with serving(directory()) as server:
        first_read(db, admin, clock, connection_id, server)
        old = (clock.value - timedelta(days=31)).replace(microsecond=0)
        with admin_engine.begin() as conn:
            conn.execute(
                text(
                    "UPDATE execbound.monitor_connections SET audit_cursor = :c "
                    "WHERE connection_id = :i"
                ),
                {"c": old, "i": connection_id},
            )
        server.scenario.audit_status = 500
        for _ in range(2):
            assert later(db, admin, clock, connection_id, server, [])["audit"]["state"] == (
                "failed"
            )
            (raised,) = health(db, tenant)
            assert raised["title"] == store.HEALTH_TITLES["RETENTION_GAP"]
            assert connection_row(db, tenant, connection_id)["audit_cursor"] == old
        server.scenario.audit_status = None
        result = later(db, admin, clock, connection_id, server, [])
        assert result["audit"]["state"] == "complete"
        assert len(health(db, tenant)) == 1
        assert connection_row(db, tenant, connection_id)["audit_behind_since"] is None
        later(db, admin, clock, connection_id, server, [])
    assert len(health(db, tenant)) == 1


def test_sr22_a_connection_at_its_observation_bound_keeps_its_cursor_and_its_health(
    db, admins, clock, monkeypatch
):
    """A connection holding as many observations as it may is refused the rest of the read,
    which is counted like any refused read: the cursor stays, and neither a full collection's
    outcome nor the connection's last refusal changes, after a delta pass as after a full one.
    Nothing removes an observation, so no later read gets further, and the first read the bound
    refuses says so at once, in a finding of its own rather than a backlog's a day later; the
    reads after it raise no second."""
    admin = admins[0]
    connection_id = connect(db, admin, clock)
    tenant = admin.tenant_id
    monkeypatch.setattr(store, "MAX_CONNECTION_EVENTS", 2)
    when = clock.value - timedelta(hours=1)
    entries = [
        entry(when + timedelta(minutes=index), target=f"d0d0d0d0-0000-4000-8000-{index:012d}")
        for index in range(3)
    ]
    began = clock.value
    with serving(directory(*entries)) as server:
        result = full(db, admin, clock, connection_id, server)
        assert result["outcome"] == "COMPLETE"
        assert (result["audit"]["state"], result["audit"]["error_code"]) == ("failed", "CAPACITY")
        assert result["audit"]["accepted"] == 2
        (raised,) = health(db, tenant)
        assert raised["title"] == store.HEALTH_TITLES["CAPACITY"]
        assert raised["connection_id"] == connection_id and raised["delivered"]
        result = later(db, admin, clock, connection_id, server, entries)
        assert (result["audit"]["state"], result["audit"]["error_code"]) == (
            "failed",
            "CAPACITY",
        )
        assert (result["audit"]["accepted"], result["audit"]["duplicates"]) == (0, 2)
        stored = connection_row(db, tenant, connection_id)
        assert stored["audit_cursor"] is None and stored["audit_baseline_at"] is None
        assert (stored["last_outcome"], stored["last_error_code"]) == ("COMPLETE", None)
        assert store.collection_reporting(stored, clock.value)
        assert stored["audit_behind_since"] == began
        assert len(health(db, tenant)) == 1
        # A day of it is also a backlog's day, raised once as any is.
        clock.value = began + store.AUDIT_BEHIND_ALERT
        later(db, admin, clock, connection_id, server, entries, minutes=0)
        later(db, admin, clock, connection_id, server, entries)
    titles = [row["title"] for row in health(db, tenant)]
    assert titles == [store.HEALTH_TITLES["CAPACITY"], store.HEALTH_TITLES["BACKLOG"]]
    assert len(observations(db, tenant)) == 2


def test_sr22_collect_due_counts_a_failed_and_a_backlogged_audit_read(db, admins, clock, tmp_path):
    """A failed read and one that has not caught up change no outcome, so the scheduled pass's
    own counts, and its log line, are where each is seen."""
    admin = admins[0]
    connection_id = connect(db, admin, clock)
    files = tmp_path / "key-files"
    key_file(files, connection_id, entra=True)
    with (
        serving(directory(audit_status=429)) as server,
        httpx.Client(transport=transport(server), trust_env=False) as http,
    ):
        first = due.collect_due(db, key_files=files, client=http, clock=clock)
        counts = first["tenants"][str(admin.tenant_id)]
        assert (counts["collected"], counts["audit_failed"]) == (1, 1)
        clock.value += timedelta(minutes=5)
        second = due.collect_due(db, key_files=files, client=http, clock=clock)
        counts = second["tenants"][str(admin.tenant_id)]
        assert (counts["delta"], counts["delta_failed"], counts["audit_failed"]) == (1, 0, 1)
        assert counts["audit_backlog"] == 0
        server.scenario.audit_status = None
        server.scenario.max_top = 1
        server.scenario.audits = busy(clock.value - timedelta(days=1), clock.value)
        clock.value += timedelta(minutes=5)
        third = due.collect_due(db, key_files=files, client=http, clock=clock)
    counts = third["tenants"][str(admin.tenant_id)]
    assert (counts["delta"], counts["audit_failed"], counts["audit_backlog"]) == (1, 0, 1)


# SR23: what an observation raises


def test_sr23_an_audit_entry_then_process_raises_the_first_consequential_action(db, admins, clock):
    admin = admins[0]
    profile(db, admin, clock)
    connection_id = connect(db, admin, clock)
    tenant = admin.tenant_id
    with serving(directory()) as server:
        first_read(db, admin, clock, connection_id, server)
        later(db, admin, clock, connection_id, server, [entry(clock.value + timedelta(minutes=2))])
    clock.value += timedelta(minutes=1)
    result = worker.evaluate_scheduled(db, tenant, clock=clock)
    assert result["actions"] == 1 and result["reach"] >= 1
    (raised,) = findings(db, tenant, "first-consequential-action.v1")
    (observed,) = observations(db, tenant)
    assert raised["platform_ref"] == ACTOR and raised["delivered"]
    assert raised["observation_id"] == observed["observation_id"]
    with db.transaction(tenant) as conn:
        certainty = (
            conn.execute(
                text(
                    "SELECT certainty FROM execbound.monitor_agent_reach "
                    "WHERE path_kind = 'observation' AND action = 'identity.disable'"
                )
            )
            .scalars()
            .all()
        )
    assert certainty == ["observed"]


def test_sr23_observed_reach_is_derived_for_every_actor_and_action_however_many_sort_before(
    db, admins, clock, monkeypatch
):
    """A directory's actors can hold far more observed (actor, action) pairs than one page of
    the derivation: every page is read, so no actor's observed reach goes underived with
    nothing to say so. A page of two stands in for the production page here, so two actors'
    two actions fill two pages and the third is empty."""
    admin = admins[0]
    connection_id = connect(db, admin, clock)
    when = clock.value - timedelta(hours=1)
    read(
        db,
        admin,
        clock,
        connection_id,
        entry(when),
        entry(when + timedelta(seconds=1), activity="Reset password"),
        entry(when + timedelta(seconds=2), actor=OTHER_ACTOR, target=OTHER_TARGET),
        entry(
            when + timedelta(seconds=3),
            actor=OTHER_ACTOR,
            target=OTHER_TARGET,
            activity="Reset password",
        ),
    )
    monkeypatch.setattr(store, "MAX_DERIVED", 2)
    assert store.derive_reach(db, admin, clock=clock)["observed"] == 4
    with db.transaction(admin.tenant_id) as conn:
        derived = set(
            conn.execute(
                text(
                    "SELECT path_ref, action FROM execbound.monitor_agent_reach "
                    "WHERE path_kind = 'observation'"
                )
            ).all()
        )
    assert derived == {
        (actor, action)
        for actor in (ACTOR, OTHER_ACTOR)
        for action in ("identity.disable", "identity.reset_password")
    }


def test_sr23_an_audit_observation_raises_no_finding_of_its_own(db, admins, clock):
    """No per-entry finding, and no clock skew for an entry read long after it happened."""
    admin = admins[0]
    profile(db, admin, clock)
    connection_id = connect(db, admin, clock)
    read(
        db,
        admin,
        clock,
        connection_id,
        entry(clock.value - timedelta(days=3)),
        entry(clock.value - timedelta(days=2), activity="Enable account"),
    )
    clock.value += timedelta(minutes=1)
    assert store.evaluate_pending(db, admin, clock=clock) == 2
    assert {row["rule_version"] for row in findings(db, admin.tenant_id)} <= {
        "initial-inventory.v1",
        "ungoverned-reach.v1",
        "sponsorless-agent.v1",
    }
    results = {row["action"]: row["evaluation_result"] for row in observations(db, admin.tenant_id)}
    assert results == {"identity.disable": "MATCH", "identity.enable": "NO_MATCH"}


def test_sr23_an_entry_ahead_of_its_receipt_still_raises_clock_skew(db, admins, clock):
    admin = admins[0]
    connection_id = connect(db, admin, clock)
    read(db, admin, clock, connection_id, entry(clock.value + timedelta(hours=1)))
    assert store.evaluate_pending(db, admin, clock=clock) == 1
    assert len(findings(db, admin.tenant_id, "clock-skew.v1")) == 1


def test_sr23_an_entry_stamped_near_the_calendar_end_never_stops_the_scheduled_pass(
    db, admins, clock
):
    """Graph stamps a successful entry two weeks before the calendar's end, a moment a parser
    can hold but no evaluation can add the thirty days evidence stays current to. The read
    keeps nothing stamped ahead of it, so the scheduled pass that follows evaluates the
    workspace, derives the reach of what was kept and raises the rule, and stops at nothing."""
    admin = admins[0]
    profile(db, admin, clock)
    connection_id = connect(db, admin, clock)
    tenant = admin.tenant_id
    distant = entry(datetime(9999, 12, 15, tzinfo=UTC))
    with serving(directory()) as server:
        first_read(db, admin, clock, connection_id, server)
        acted = entry(clock.value + timedelta(minutes=2), target=OTHER_TARGET)
        assert later(db, admin, clock, connection_id, server, [acted])["audit"]["accepted"] == 1
        result = later(db, admin, clock, connection_id, server, [distant])
    assert (result["audit"]["dropped"], result["audit"]["accepted"]) == (1, 0)
    (kept,) = observations(db, tenant)
    assert kept["target_ref"] == OTHER_TARGET
    clock.value += timedelta(minutes=1)
    result = worker.evaluate_scheduled(db, tenant, clock=clock)
    assert (result["actions"], result["reach"] >= 1) == (1, True)
    (raised,) = findings(db, tenant, "first-consequential-action.v1")
    assert raised["observation_id"] == kept["observation_id"]


def test_sr23_an_observation_stamped_near_the_calendar_end_never_stops_the_evaluation(
    db, admins, clock
):
    """Whatever moment a stored observation names, no reach derived from it runs off the
    calendar: evidence is current for thirty days from its moment and never from later than
    the derivation's own, so an observation no read keeps, written here by the store itself,
    derives reach current for thirty days from now and the pass completes."""
    admin = admins[0]
    profile(db, admin, clock)
    connection_id = connect(db, admin, clock)
    tenant = admin.tenant_id
    read(db, admin, clock, connection_id)
    kind, distant, _ = graph.parse_directory_audit(entry(datetime(9999, 12, 15, tzinfo=UTC)))
    assert kind == "mapped"
    kept = store.apply_directory_audit(
        db, admin, connection_id, [distant], cursor=None, clock=clock
    )
    assert kept["accepted"] == 1
    clock.value += timedelta(minutes=1)
    worker.evaluate_scheduled(db, tenant, clock=clock)
    with db.transaction(tenant) as conn:
        until = conn.execute(
            text(
                "SELECT valid_until FROM execbound.monitor_agent_reach "
                "WHERE path_kind = 'observation' AND path_ref = :a"
            ),
            {"a": ACTOR},
        ).scalar_one()
    assert until == clock.value + reach.EVIDENCE_VALIDITY


def test_sr23_what_the_first_complete_read_finds_is_the_activity_baseline(db, admins, clock):
    """A connection baselined before its audit log could be read: what the first complete read
    finds is the actor's habit, not news, however long after the directory's baseline it was."""
    admin = admins[0]
    profile(db, admin, clock)
    connection_id = connect(db, admin, clock)
    tenant = admin.tenant_id
    acted = clock.value + timedelta(hours=1)
    with serving(directory(status={"audits": 403})) as server:
        full(db, admin, clock, connection_id, server)
        directory_baseline = connection_row(db, tenant, connection_id)["baseline_at"]
        # The permission is granted: the first complete read finds an action after the baseline.
        server.scenario.status = {}
        server.scenario.audits = [entry(acted)]
        clock.value += timedelta(hours=7)
        first_read(db, admin, clock, connection_id, server)
        stored = connection_row(db, tenant, connection_id)
        assert stored["audit_baseline_at"] == clock.value
        assert clock.value > acted > directory_baseline
        clock.value += timedelta(minutes=1)
        assert store.evaluate_actions(db, admin, clock=clock)["raised"] == 0
        # The same actor acting again is still its habit; another actor's first action is news.
        again = clock.value + timedelta(minutes=1)
        later(
            db,
            admin,
            clock,
            connection_id,
            server,
            [entry(acted), entry(again), entry(again, actor=OTHER_ACTOR, target=OTHER_TARGET)],
        )
    assert store.evaluate_actions(db, admin, clock=clock)["raised"] == 1
    (raised,) = findings(db, tenant, "first-consequential-action.v1")
    assert raised["platform_ref"] == OTHER_ACTOR


def test_sr23_until_a_read_catches_up_no_audit_observation_raises_it(db, admins, clock):
    """A connection baselined before its audit log could be read, whose first read takes more
    than one run: what that read finds after the directory's baseline raises nothing while the
    read is still behind, and nothing once it has caught up, because everything the first read
    found is the actors' habit. What is read after it is news."""
    admin = admins[0]
    profile(db, admin, clock)
    connection_id = connect(db, admin, clock)
    tenant = admin.tenant_id
    with serving(directory(status={"audits": 403}, max_top=2)) as server:
        full(db, admin, clock, connection_id, server)
        directory_baseline = connection_row(db, tenant, connection_id)["baseline_at"]
        server.scenario.status = {}
        acted = clock.value + timedelta(hours=1)
        entries = [
            entry(acted + timedelta(minutes=index), target=f"d0d0d0d0-0000-4000-8000-{index:012d}")
            for index in range(graph.MAX_AUDIT_PAGES * 2 + 1)
        ]
        server.scenario.audits = entries
        clock.value += timedelta(hours=7)
        assert full(db, admin, clock, connection_id, server)["audit"]["state"] == "backlog"
        assert connection_row(db, tenant, connection_id)["audit_baseline_at"] is None
        assert acted > directory_baseline
        clock.value += timedelta(minutes=1)
        assert store.evaluate_actions(db, admin, clock=clock)["raised"] == 0
        # The next run reads the rest and catches up: still the habit.
        assert later(db, admin, clock, connection_id, server, entries)["audit"]["state"] == (
            "complete"
        )
        assert store.evaluate_actions(db, admin, clock=clock)["raised"] == 0
        news = entry(clock.value + timedelta(minutes=1), actor=OTHER_ACTOR, target=OTHER_TARGET)
        later(db, admin, clock, connection_id, server, [*entries, news])
    assert store.evaluate_actions(db, admin, clock=clock)["raised"] == 1
    (raised,) = findings(db, tenant, "first-consequential-action.v1")
    assert raised["platform_ref"] == OTHER_ACTOR


def baselined(db, admin, clock, connection_id, server, audits):
    """A connection baselined before its audit log could be read, whose first read that catches
    up then finds `audits`: the moment of that read."""
    server.scenario.status = {"audits": 403}
    full(db, admin, clock, connection_id, server)
    server.scenario.status = {}
    server.scenario.audits = list(audits)
    clock.value += timedelta(hours=7)
    first_read(db, admin, clock, connection_id, server)
    return clock.value


@pytest.mark.parametrize("caught", ["at the log's end", "past the overlap"])
def test_sr23_an_entry_published_after_the_baseline_read_is_news(db, admins, clock, caught):
    """Graph makes an entry available a while after it happened. One the baseline read did not
    find, because Graph had not yet published it, is read by a later run and raises the rule,
    though it happened before that read: the baseline is what that read found, not whatever
    happened before its moment. The baseline read caught up by reaching the log's end, or by
    reading past thirty minutes before its moment through a log busy with a person's changes,
    the late entry then stamped before the last entry that read found."""
    admin = admins[0]
    profile(db, admin, clock)
    connection_id = connect(db, admin, clock)
    tenant = admin.tenant_id
    busy_log = caught == "past the overlap"
    start = clock.value + timedelta(hours=7)
    with serving(directory(**({"max_top": 2} if busy_log else {}))) as server:
        # Eight entries a run: through 26 minutes before the read's moment.
        noise = busy(start - timedelta(minutes=33), start) if busy_log else []
        now = baselined(db, admin, clock, connection_id, server, noise)
        assert connection_row(db, tenant, connection_id)["audit_baseline_at"] == now
        if busy_log:
            late = entry(now - timedelta(minutes=28, seconds=30))
            log = [*busy(now - timedelta(minutes=33), now + timedelta(minutes=5)), late]
        else:
            late = entry(now - timedelta(minutes=3))
            log = [late]
        result = later(db, admin, clock, connection_id, server, log)
        assert (result["audit"]["state"], result["audit"]["accepted"]) == ("complete", 1)
    clock.value += timedelta(minutes=1)
    assert store.evaluate_actions(db, admin, clock=clock)["raised"] == 1
    (raised,) = findings(db, tenant, "first-consequential-action.v1")
    (observed,) = observations(db, tenant)
    assert raised["platform_ref"] == ACTOR
    assert raised["observation_id"] == observed["observation_id"]
    assert observed["occurred_at"] < now < observed["received_at"]


def test_sr23_without_a_sensitive_action_list_an_entry_published_late_is_counted(db, admins, clock):
    """The count of actors the rule would read reads receipt as the rule does: an entry the
    baseline read did not find, because Graph published it late, is counted, though it was
    stamped before that read."""
    admin = admins[0]
    connection_id = connect(db, admin, clock)
    with serving(directory()) as server:
        now = baselined(db, admin, clock, connection_id, server, [])
        assert store.evaluate_actions(db, admin, clock=clock)["insufficient"] == 0
        later(db, admin, clock, connection_id, server, [entry(now - timedelta(minutes=3))])
    assert store.evaluate_actions(db, admin, clock=clock)["insufficient"] == 1


def test_sr23_an_entry_stamped_before_the_directory_baseline_is_the_habit_however_late_read(
    db, admins, clock
):
    """A connection's first collection sets both its baselines. An entry stamped before it that
    Graph publishes late is read by a later run and is still the habit, as any evidence from
    before the directory's baseline is: its actor's next action raises nothing, while another
    actor's does."""
    admin = admins[0]
    profile(db, admin, clock)
    connection_id = connect(db, admin, clock)
    tenant = admin.tenant_id
    with serving(directory()) as server:
        first_read(db, admin, clock, connection_id, server)
        stored = connection_row(db, tenant, connection_id)
        assert stored["audit_baseline_at"] >= stored["baseline_at"]
        habit = entry(stored["baseline_at"] - timedelta(minutes=3))
        later(db, admin, clock, connection_id, server, [habit])
        (observed,) = observations(db, tenant)
        assert observed["received_at"] > stored["audit_baseline_at"]
        clock.value += timedelta(minutes=1)
        assert store.evaluate_actions(db, admin, clock=clock)["raised"] == 0
        acted = clock.value + timedelta(minutes=1)
        later(
            db,
            admin,
            clock,
            connection_id,
            server,
            [habit, entry(acted), entry(acted, actor=OTHER_ACTOR, target=OTHER_TARGET)],
        )
    assert store.evaluate_actions(db, admin, clock=clock)["raised"] == 1
    (raised,) = findings(db, tenant, "first-consequential-action.v1")
    assert raised["platform_ref"] == OTHER_ACTOR


def test_sr23_an_entry_read_after_the_baseline_is_news_when_the_host_clock_is_set_back(
    db, admins, clock
):
    """The host's clock is set back an hour after the baseline read. An entry a later run reads
    is still received after that read, whatever the clock now says, so it raises the rule."""
    admin = admins[0]
    profile(db, admin, clock)
    connection_id = connect(db, admin, clock)
    tenant = admin.tenant_id
    with serving(directory()) as server:
        now = baselined(db, admin, clock, connection_id, server, [])
        clock.value -= timedelta(hours=1)
        server.scenario.audits = [entry(now - timedelta(minutes=3))]
        result = delta(db, admin, clock, connection_id, server)
        assert (result["audit"]["state"], result["audit"]["accepted"]) == ("complete", 1)
    (observed,) = observations(db, tenant)
    assert observed["received_at"] > now
    clock.value += timedelta(minutes=1)
    assert store.evaluate_actions(db, admin, clock=clock)["raised"] == 1
    (raised,) = findings(db, tenant, "first-consequential-action.v1")
    assert raised["platform_ref"] == ACTOR


def test_sr23_what_reads_before_a_clock_set_back_found_stays_the_baseline(db, admins, clock):
    """A first read still in backlog, then the host's clock set back an hour before the read
    that catches up: what the backlog read found is still the habit, because the baseline is no
    earlier than the receipt of anything the reads before it stored."""
    admin = admins[0]
    profile(db, admin, clock)
    connection_id = connect(db, admin, clock)
    tenant = admin.tenant_id
    with serving(directory(status={"audits": 403}, max_top=2)) as server:
        full(db, admin, clock, connection_id, server)
        server.scenario.status = {}
        acted = clock.value + timedelta(hours=1)
        entries = [
            entry(acted + timedelta(minutes=index), target=f"d0d0d0d0-0000-4000-8000-{index:012d}")
            for index in range(graph.MAX_AUDIT_PAGES * 2 + 1)
        ]
        server.scenario.audits = entries
        clock.value += timedelta(hours=7)
        assert full(db, admin, clock, connection_id, server)["audit"]["state"] == "backlog"
        received = max(row["received_at"] for row in observations(db, tenant))
        clock.value -= timedelta(hours=1)
        assert delta(db, admin, clock, connection_id, server)["audit"]["state"] == "complete"
    assert connection_row(db, tenant, connection_id)["audit_baseline_at"] == received
    clock.value += timedelta(minutes=1)
    assert store.evaluate_actions(db, admin, clock=clock)["raised"] == 0


# The allowance decided on 16 October 2026 (#355): ten minutes either side of an
# execution's dispatch and settlement. Written here rather than read from the store, so a
# change to the store's constant fails a test.
ALLOWANCE = timedelta(minutes=10)
# How long after its dispatch `executed` settles an execution.
SETTLING = timedelta(seconds=1)


def executed(
    admin_engine,
    admin,
    dispatched,
    *,
    action="identity.disable",
    target=TARGET,
    case=str.upper,
    **rest,
):
    """A settled execution through the Graph provider, dispatched at `dispatched` and settled
    `SETTLING` later, its frozen object id written in `case`: by default another case than the
    audit log's."""
    principal_id, credential = governed_agent(admin_engine, admin.tenant_id)
    execution = settle_execution(
        admin_engine, admin.tenant_id, principal_id, credential, action, dispatched
    )
    frozen = {
        "intent": {"action": action, "provider": rest.get("provider", "graph")},
        "resource_provider_id": case(target),
    }
    with admin_engine.begin() as conn:
        conn.execute(
            text(
                "UPDATE execbound.executions SET frozen = CAST(:f AS jsonb), "
                "dispatch_attempted_at = :d, changed_at = :s, state = :state "
                "WHERE execution_id = :e"
            ),
            {
                "f": json.dumps(frozen),
                "d": dispatched,
                "s": dispatched + SETTLING,
                "state": rest.get("state", "EXECUTED"),
                "e": execution,
            },
        )
    return execution


@pytest.mark.parametrize("edge", ["inside", "at the window's start", "at the window's end"])
def test_sr23_the_one_entry_an_execution_execbound_settled_is_not_reported(
    db, admins, admin_engine, clock, edge
):
    """Ten minutes either side of the execution's dispatch and settlement, as ruled, and no
    less: a directory entry stamped by the directory's own clock still matches."""
    admin = admins[0]
    profile(db, admin, clock)
    connection_id = connect(db, admin, clock)
    tenant = admin.tenant_id
    with serving(directory()) as server:
        first_read(db, admin, clock, connection_id, server)
        dispatched = clock.value + timedelta(minutes=15)
        executed(admin_engine, admin, dispatched)
        when = {
            "at the window's start": dispatched - ALLOWANCE,
            "at the window's end": dispatched + SETTLING + ALLOWANCE,
        }.get(edge, dispatched + SETTLING)
        later(db, admin, clock, connection_id, server, [entry(when)], minutes=30)
    clock.value += timedelta(minutes=1)
    assert worker.evaluate_scheduled(db, tenant, clock=clock)["actions"] == 0
    assert findings(db, tenant, "first-consequential-action.v1") == []
    # It is still true, so it still says what the actor can do.
    with db.transaction(tenant) as conn:
        assert (
            conn.execute(
                text(
                    "SELECT count(*) FROM execbound.monitor_agent_reach "
                    "WHERE path_kind = 'observation' AND path_ref = :a"
                ),
                {"a": ACTOR},
            ).scalar_one()
            == 1
        )


@pytest.mark.parametrize("frozen", [str.upper, str.lower], ids=["both upper", "the entry's alone"])
def test_sr23_an_entry_naming_its_target_in_upper_case_still_matches_its_execution(
    db, admins, admin_engine, clock, frozen
):
    """The object ids are compared without regard to case, as ruled, on both sides: Graph may
    write an entry's target in upper case, whichever case the execution froze its own in, and
    the entry ExecBound's own execution accounts for is still left out."""
    admin = admins[0]
    profile(db, admin, clock)
    connection_id = connect(db, admin, clock)
    tenant = admin.tenant_id
    with serving(directory()) as server:
        first_read(db, admin, clock, connection_id, server)
        dispatched = clock.value + timedelta(minutes=15)
        executed(admin_engine, admin, dispatched, case=frozen)
        audits = [entry(dispatched + SETTLING, target=TARGET.upper())]
        later(db, admin, clock, connection_id, server, audits, minutes=30)
    (observed,) = observations(db, tenant)
    assert observed["target_ref"] == TARGET
    clock.value += timedelta(minutes=1)
    worker.evaluate_scheduled(db, tenant, clock=clock)
    assert findings(db, tenant, "first-consequential-action.v1") == []


@pytest.mark.parametrize(
    "case",
    [
        "another target",
        "another action",
        "before the window",
        "after the window",
        "two entries",
        "two executions",
        "a mock provider",
        "not executed",
    ],
)
def test_sr23_an_entry_that_does_not_match_one_settled_execution_is_reported(
    db, admins, admin_engine, clock, case
):
    """Left out only when exactly one execution matches the entry and that execution matches
    no other entry, as ruled: two entries for one execution, or two executions for one entry,
    leave out neither."""
    admin = admins[0]
    profile(db, admin, clock, actions=("identity.disable", "identity.enable"))
    connection_id = connect(db, admin, clock)
    tenant = admin.tenant_id
    with serving(directory()) as server:
        first_read(db, admin, clock, connection_id, server)
        dispatched = clock.value + timedelta(minutes=15)
        executed(
            admin_engine,
            admin,
            dispatched,
            **{
                "another target": {"target": OTHER_TARGET},
                "another action": {"action": "identity.enable"},
                "a mock provider": {"provider": "mock_entra"},
                "not executed": {"state": "FAILED_NOT_EXECUTED"},
            }.get(case, {}),
        )
        if case == "two executions":
            # Another of the same action on the same target, whose window holds the entry too:
            # each execution matches that entry alone, and the entry matches both.
            executed(admin_engine, admin, dispatched + timedelta(minutes=2))
        when = {
            "before the window": dispatched - ALLOWANCE - timedelta(seconds=1),
            "after the window": dispatched + SETTLING + ALLOWANCE + timedelta(seconds=1),
        }.get(case, dispatched + SETTLING)
        audits = [entry(when)]
        if case == "two entries":
            audits.append(entry(when, actor=OTHER_ACTOR))
        later(db, admin, clock, connection_id, server, audits, minutes=30)
    clock.value += timedelta(minutes=1)
    worker.evaluate_scheduled(db, tenant, clock=clock)
    raised = {row["platform_ref"] for row in findings(db, tenant, "first-consequential-action.v1")}
    assert raised == ({ACTOR, OTHER_ACTOR} if case == "two entries" else {ACTOR})


def test_sr23_an_action_under_a_correlation_id_an_execution_accounted_for_is_still_reported(
    db, admins, admin_engine, clock
):
    """An actor that is also an execution's executor, choosing its own correlation id: the entry
    the one settled execution matches is left out of the rule, and the same action on the same
    target under the same correlation id two hours later, outside ExecBound, is an observation
    of its own. It raises the rule rather than being dropped as a copy of the first, is
    recognised when read again, and keeps the actor's observed reach current."""
    admin = admins[0]
    profile(db, admin, clock)
    connection_id = connect(db, admin, clock)
    tenant = admin.tenant_id
    correlation = str(uuid4())
    with serving(directory()) as server:
        first_read(db, admin, clock, connection_id, server)
        dispatched = clock.value + timedelta(minutes=15)
        executed(admin_engine, admin, dispatched)
        settled = entry(dispatched + SETTLING, correlation=correlation)
        later(db, admin, clock, connection_id, server, [settled], minutes=30)
        clock.value += timedelta(minutes=1)
        worker.evaluate_scheduled(db, tenant, clock=clock)
        assert findings(db, tenant, "first-consequential-action.v1") == []
        again = clock.value + timedelta(hours=2)
        audits = [settled, entry(again, correlation=correlation)]
        result = later(db, admin, clock, connection_id, server, audits, minutes=125)
        assert (result["audit"]["accepted"], result["audit"]["duplicates"]) == (1, 1)
        result = later(db, admin, clock, connection_id, server, audits)
        assert (result["audit"]["accepted"], result["audit"]["duplicates"]) == (0, 1)
    first, second = observations(db, tenant)
    assert (first["occurred_at"], second["occurred_at"]) == (dispatched + SETTLING, again)
    clock.value += timedelta(minutes=1)
    worker.evaluate_scheduled(db, tenant, clock=clock)
    (raised,) = findings(db, tenant, "first-consequential-action.v1")
    assert (raised["platform_ref"], raised["observation_id"]) == (ACTOR, second["observation_id"])
    with db.transaction(tenant) as conn:
        until = conn.execute(
            text(
                "SELECT valid_until FROM execbound.monitor_agent_reach "
                "WHERE path_kind = 'observation' AND path_ref = :a"
            ),
            {"a": ACTOR},
        ).scalar_one()
    assert until == again + reach.EVIDENCE_VALIDITY


@pytest.mark.parametrize(
    "settled_at",
    [
        "in the first read's look-back",
        "a month back, in the first read's look-back",
        "after the directory's baseline, before the first read",
    ],
)
def test_sr23_executions_execbound_settled_before_the_activity_baseline_are_not_its_habit(
    db, admins, admin_engine, clock, settled_at
):
    """ExecBound's own executor is a principal in the directory, whose executions the first
    audit read finds when they settled before the activity baseline: in its thirty-day
    look-back, before the directory's baseline too, or between that and a first read that waited
    for its permission. They are left out of the rule there as after it, so they do not make
    their actor part of the baseline: they are not it acting outside ExecBound. The first use of
    its own credential outside ExecBound after the baseline is reported, however long after
    those executions it comes."""
    admin = admins[0]
    profile(db, admin, clock)
    connection_id = connect(db, admin, clock)
    tenant = admin.tenant_id
    waited = settled_at.startswith("after")
    with serving(directory()) as server:
        if waited:
            server.scenario.status = {"audits": 403}
            full(db, admin, clock, connection_id, server)
            dispatched = clock.value + timedelta(hours=1)
        else:
            dispatched = clock.value - timedelta(days=29 if "month" in settled_at else 2)
        executed(admin_engine, admin, dispatched)
        settled = entry(dispatched + SETTLING)
        if waited:
            baselined(db, admin, clock, connection_id, server, [settled])
        else:
            server.scenario.audits = [settled]
            first_read(db, admin, clock, connection_id, server)
        stored = connection_row(db, tenant, connection_id)
        (observed,) = observations(db, tenant)
        assert observed["received_at"] <= stored["audit_baseline_at"]
        assert (observed["occurred_at"] > stored["baseline_at"]) is waited
        clock.value += timedelta(minutes=1)
        worker.evaluate_scheduled(db, tenant, clock=clock)
        assert findings(db, tenant, "first-consequential-action.v1") == []
        # Two days on, the month-old execution is older than anything the rule reads as current.
        minutes = 2 * 24 * 60 if "month" in settled_at else 30
        outside = entry(clock.value + timedelta(minutes=minutes - 5), target=OTHER_TARGET)
        later(db, admin, clock, connection_id, server, [settled, outside], minutes=minutes)
    (news,) = [row for row in observations(db, tenant) if row["target_ref"] == OTHER_TARGET]
    clock.value += timedelta(minutes=1)
    worker.evaluate_scheduled(db, tenant, clock=clock)
    (raised,) = findings(db, tenant, "first-consequential-action.v1")
    assert (raised["platform_ref"], raised["observation_id"]) == (ACTOR, news["observation_id"])


def test_sr23_a_directory_connected_again_holds_copies_of_one_entry_not_two_actions(
    db, admins, admin_engine, clock
):
    """A connection revoked and its directory connected again, as an operator does to move to
    another registration: the new connection's first read finds, in its look-back, the entry the
    revoked one already holds for an execution ExecBound settled. Each connection holds one
    reading of the log, so the two observations are copies of one entry, not two actions acting
    in the execution's window: the execution still accounts for both, neither is reported or
    drawn, and the executor's own credential used outside ExecBound afterwards is."""
    admin = admins[0]
    profile(db, admin, clock)
    first = connect(db, admin, clock)
    tenant = admin.tenant_id
    with serving(directory()) as server:
        first_read(db, admin, clock, first, server)
        dispatched = clock.value + timedelta(minutes=15)
        executed(admin_engine, admin, dispatched)
        settled = entry(dispatched + SETTLING)
        later(db, admin, clock, first, server, [settled], minutes=30)
        clock.value += timedelta(minutes=1)
        worker.evaluate_scheduled(db, tenant, clock=clock)
        assert findings(db, tenant, "first-consequential-action.v1") == []
        store.revoke_connection(db, admin, first, clock=clock)
        clock.value += timedelta(minutes=5)
        second = connect(db, admin, clock)
        first_read(db, admin, clock, second, server)
        copies = observations(db, tenant)
        assert sorted(str(row["connection_id"]) for row in copies) == sorted(
            [str(first), str(second)]
        )
        assert len({row["event_id"] for row in copies}) == 1
        clock.value += timedelta(minutes=1)
        worker.evaluate_scheduled(db, tenant, clock=clock)
        assert findings(db, tenant, "first-consequential-action.v1") == []
        with db.transaction(tenant) as conn:
            drawn = board.read(
                conn, tenant, admin.principal_id, False, clock.value, window=board.WINDOWS["24h"]
            )
        assert drawn.watching and drawn.observations == ()
        outside = entry(clock.value + timedelta(minutes=5), target=OTHER_TARGET)
        later(db, admin, clock, second, server, [settled, outside], minutes=10)
    (news,) = [row for row in observations(db, tenant) if row["target_ref"] == OTHER_TARGET]
    clock.value += timedelta(minutes=1)
    worker.evaluate_scheduled(db, tenant, clock=clock)
    (raised,) = findings(db, tenant, "first-consequential-action.v1")
    assert (raised["platform_ref"], raised["observation_id"]) == (ACTOR, news["observation_id"])
    assert raised["connection_id"] == second


@pytest.mark.parametrize("beside", [False, True], ids=["alone", "beside another actor"])
def test_sr23_home_board_draws_only_what_passed_under_the_checkpoint(
    db, admins, admin_engine, clock, beside
):
    """Home's board draws what monitoring saw pass under the checkpoint. The entry the one
    settled Graph execution accounts for passed through it, and an attempt the directory refused
    changed nothing, so neither is drawn; an actor's own action is. Two entries sharing one
    execution are both drawn, as the rule reports both."""
    admin = admins[0]
    connection_id = connect(db, admin, clock)
    tenant = admin.tenant_id
    with serving(directory()) as server:
        first_read(db, admin, clock, connection_id, server)
        dispatched = clock.value + timedelta(minutes=15)
        executed(admin_engine, admin, dispatched)
        settled = dispatched + SETTLING
        audits = [
            entry(settled),
            entry(settled, actor=OTHER_ACTOR, target=OTHER_TARGET, result="failure"),
            entry(settled + timedelta(minutes=1), actor=OTHER_ACTOR, target=OTHER_TARGET),
        ]
        if beside:
            audits.append(entry(settled, actor=OTHER_ACTOR))
        later(db, admin, clock, connection_id, server, audits, minutes=30)
    assert len(observations(db, tenant)) == len(audits)
    with db.transaction(tenant) as conn:
        drawn = board.read(
            conn, tenant, admin.principal_id, False, clock.value, window=board.WINDOWS["1h"]
        )
    assert drawn.watching
    expected = [OTHER_TARGET] + ([TARGET, TARGET] if beside else [])
    assert sorted(seen.label for seen in drawn.observations) == sorted(expected)


def test_sr23_a_back_filled_audit_log_never_holds_back_what_a_source_reports(db, admins, clock):
    """An audit log's back-fill raises nothing of its own, so it is evaluated beside what a
    source reports, not ahead of it: an action a story reports after a back-fill larger than the
    pass's budget is evaluated, and raised, by the first pass, and the back-fill with it, up to
    as many as one read stores."""
    admin = admins[0]
    profile(db, admin, clock)
    connection_id = connect(db, admin, clock)
    tenant = admin.tenant_id
    when = clock.value - timedelta(days=2)
    backfill = [
        entry(when + timedelta(minutes=index), target=f"d0d0d0d0-0000-4000-8000-{index:012d}")
        for index in range(3)
    ]
    read(db, admin, clock, connection_id, *backfill)
    source = store.create_source(
        db,
        admin,
        label="Synthetic story",
        story_id="story-1",
        expires_at=clock.value + timedelta(hours=2),
        clock=clock,
    )
    clock.value += timedelta(seconds=1)
    reported = ObservationEvent.model_validate(
        {
            "event_id": "event-1",
            "story_id": "story-1",
            "occurred_at": clock.value,
            "kind": "tool_result",
            "action": "identity.disable",
            "target_ref": "user-1",
            "outcome": "success",
        }
    )
    store.ingest(db, source.token, reported, clock=clock)
    assert store.evaluate_pending(db, admin, limit=1, clock=clock) == 1 + len(backfill)
    (raised,) = findings(db, tenant, store.RULE_VERSION)
    assert raised["title"] == "Source reported a consequential action"
    with db.transaction(tenant) as conn:
        assert (
            conn.execute(
                text(
                    "SELECT count(*) FROM execbound.monitor_observations "
                    "WHERE evaluation_state = 'PENDING'"
                )
            ).scalar_one()
            == 0
        )
    assert store.AUDIT_EVALUATIONS == graph.MAX_AUDIT_PAGES * graph.AUDIT_PAGE_SIZE


def test_sr23_without_a_sensitive_action_list_the_actors_the_rule_would_read_are_counted(
    db, admins, admin_engine, clock
):
    """No sensitive-action list, so no subject: the actors the rule would read are counted as
    insufficient evidence instead, under the same conditions. What the first read found, a
    refused attempt and ExecBound's own execution count for nothing; a later action does."""
    admin = admins[0]
    connection_id = connect(db, admin, clock)

    def insufficient():
        return store.evaluate_actions(db, admin, clock=clock)["insufficient"]

    with serving(directory(status={"audits": 403})) as server:
        full(db, admin, clock, connection_id, server)
        server.scenario.status = {}
        habit = entry(clock.value + timedelta(hours=1))
        clock.value += timedelta(hours=7)
        server.scenario.audits = [habit]
        first_read(db, admin, clock, connection_id, server)
        # Found by the first read, though after the directory's baseline.
        assert insufficient() == 0
        attempt = entry(clock.value + timedelta(minutes=1), actor=OTHER_ACTOR, result="failure")
        later(db, admin, clock, connection_id, server, [attempt])
        assert insufficient() == 0
        dispatched = clock.value + timedelta(minutes=15)
        executed(admin_engine, admin, dispatched, target=OTHER_TARGET)
        own = entry(dispatched + SETTLING, actor=OTHER_ACTOR, target=OTHER_TARGET)
        later(db, admin, clock, connection_id, server, [attempt, own], minutes=30)
        assert insufficient() == 0
        acted = entry(clock.value + timedelta(minutes=1), actor=OTHER_ACTOR)
        later(db, admin, clock, connection_id, server, [acted])
    assert insufficient() == 1


def test_sr23_a_failed_attempt_derives_nothing_and_raises_nothing(db, admins, clock):
    admin = admins[0]
    profile(db, admin, clock)
    connection_id = connect(db, admin, clock)
    tenant = admin.tenant_id
    with serving(directory()) as server:
        first_read(db, admin, clock, connection_id, server)
        failed = clock.value + timedelta(minutes=2)
        later(db, admin, clock, connection_id, server, [entry(failed, result="failure")])
        clock.value += timedelta(minutes=1)
        assert worker.evaluate_scheduled(db, tenant, clock=clock)["actions"] == 0
        assert findings(db, tenant, "first-consequential-action.v1") == []
        with db.transaction(tenant) as conn:
            assert (
                conn.execute(
                    text(
                        "SELECT count(*) FROM execbound.monitor_agent_reach "
                        "WHERE path_kind = 'observation'"
                    )
                ).scalar_one()
                == 0
            )
        # A later success by the same actor is still its first consequential action.
        succeeded = clock.value + timedelta(minutes=1)
        later(
            db,
            admin,
            clock,
            connection_id,
            server,
            [entry(failed, result="failure"), entry(succeeded)],
        )
    assert store.evaluate_actions(db, admin, clock=clock)["raised"] == 1
    assert agent_row(db, tenant, ACTOR)["first_action_opened_at"] is not None
