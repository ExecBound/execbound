# SPDX-License-Identifier: AGPL-3.0-only
"""Read-only Tines discovery and collection: TD1 to TD12 on real PostgreSQL and a fake API."""

import importlib
import json
import os
from datetime import UTC, datetime, timedelta
from pathlib import Path

import httpx
import pytest
from alembic import command
from alembic.config import Config
from space_fixtures import make_space
from sqlalchemy import event as sa_event
from sqlalchemy import text
from test_monitoring_store import FixedClock
from test_monitoring_store import admins as admins
from test_monitoring_store import api as api

from execbound.db import TABLES, check_runtime
from execbound.surfaces import sessions
from execbound_harness.fake_tines import BASE_URL, Scenario, serving, transport

FIXTURE = json.loads((Path("tests/fixtures/tines-collection.json")).read_text())
SECRETS = (
    "SYNTHETIC-SECRET-MUST-NOT-BE-RETAINED",
    "synthetic.person@synthetic.invalid",
    "203.0.113.5",
    "Mozilla/5.0 (synthetic)",
    "Synthetic completion text that must never be retained.",
    "Synthetic prompt text that must never be retained.",
    "Synthetic story description that must never be retained.",
)
KEY = "synthetic-collection-key"


@pytest.fixture
def collection():
    return importlib.import_module("execbound.monitoring.collection")


def rebase(records, now):
    """Move recorded times onto the test clock so the suite does not drift into clock skew."""
    moments = [datetime.fromisoformat(record["created_at"]) for record in records]
    delta = (now - timedelta(hours=1)) - max(moments)
    return [
        {**record, "created_at": (moment + delta).isoformat()}
        for record, moment in zip(records, moments, strict=True)
    ]


def occurred(records):
    return {record["id"]: datetime.fromisoformat(record["created_at"]) for record in records}


def scenario(now, **changes):
    audit = changes.pop("audit", FIXTURE["audit"])
    values = {
        "stories": list(FIXTURE["stories"]),
        "actions": {key: list(value) for key, value in FIXTURE["actions"].items()},
        "credentials": list(FIXTURE["credentials"]),
        "audit": rebase(audit, now),
        "tenant_id": FIXTURE["tenant_id"],
    }
    values.update(changes)
    return Scenario(**values)


def client(server):
    return httpx.Client(transport=transport(server), trust_env=False, follow_redirects=False)


@pytest.fixture
def setup_collection(api, db, admins, collection):
    """One tenant with a registered connection, an instrumented story and a stale one."""
    _, store = api
    clock = FixedClock(datetime.now(UTC))
    connection_id = store.create_connection(
        db,
        admins[0],
        label="Synthetic Tines tenant",
        base_url=BASE_URL,
        key_fingerprint=collection.fingerprint(KEY),
        team_id="7",
        clock=clock,
    )
    # Coverage reconciles by the platform story identifier, so a source registers that id.
    store.create_source(
        db,
        admins[0],
        label="Phishing triage",
        story_id="4001",
        expires_at=clock.now() + timedelta(hours=2),
        clock=clock,
    )
    grant = sessions.issue_session(db, admins[0], clock=clock)
    session = sessions.load_session(db, grant.token, clock=clock)
    return store, clock, connection_id, session


def run(collection, db, identity, connection_id, server, clock, **changes):
    options = {"inventory": True, "audit_pages": 20, "key": KEY}
    options.update(changes)
    key = options.pop("key")
    with client(server) as http:
        return collection.run(
            db,
            identity,
            connection_id=connection_id,
            api_key=key,
            client=http,
            clock=clock,
            **options,
        )


def rows(db, tenant, table, where=""):
    with db.transaction(tenant) as conn:
        return [
            dict(row)
            for row in conn.execute(
                text(f"SELECT * FROM execbound.{table} {where} ORDER BY 1, 2")  # nosec B608
            ).mappings()
        ]


def connection_row(db, tenant, connection_id):
    with db.transaction(tenant) as conn:
        return dict(
            conn.execute(
                text("SELECT * FROM execbound.monitor_connections WHERE connection_id=:c"),
                {"c": connection_id},
            )
            .mappings()
            .one()
        )


def test_td1_probe_records_every_capability_and_retains_nothing_else(
    db, setup_collection, admins, collection
):
    store, clock, connection_id, _ = setup_collection
    spec = scenario(clock.value, audit=list(FIXTURE["audit"]) + list(FIXTURE["ai_audit"]))
    with serving(spec) as server, client(server) as http:
        result = collection.probe(
            db, admins[0], connection_id=connection_id, api_key=KEY, client=http, clock=clock
        )
    assert {name: value["state"] for name, value in result.items()} == {
        "stories": "available",
        "actions": "available",
        "credentials": "available",
        "audit": "available",
        "ai_audit": "available",
    }
    row = connection_row(db, admins[0].tenant_id, connection_id)
    assert row["health_state"] == "COLLECTING"
    assert all(value["at"] is not None for value in row["capabilities"].values())
    # A probe is a classification, never a collection.
    assert rows(db, admins[0].tenant_id, "monitor_inventory") == []
    assert rows(db, admins[0].tenant_id, "monitor_observations") == []


def test_td2_inventory_sync_retains_allowlisted_metadata_only(
    db, setup_collection, admins, collection
):
    store, clock, connection_id, session = setup_collection
    # A small server-side page cap forces the pagination walk over three pages of stories.
    with serving(scenario(clock.value, max_per_page=2)) as server:
        result = run(collection, db, admins[0], connection_id, server, clock, audit_pages=0)
    assert result["inventory"]["stories"] == 5
    assert result["inventory"]["actions"] == 6
    assert result["inventory"]["credentials"] == 2
    items = rows(db, admins[0].tenant_id, "monitor_inventory")
    assert len(items) == 13
    stories = {row["external_id"]: row for row in items if row["item_kind"] == "story"}
    assert stories["4001"]["name"] == "Phishing triage"
    assert stories["4004"]["disabled"] is True
    actions = {row["external_id"]: row for row in items if row["item_kind"] == "action"}
    assert actions["9001"]["outbound"] is True and actions["9001"]["story_external_id"] == "4001"
    assert actions["9002"]["outbound"] is False
    # An action type the collector does not recognize is unknown coverage, never "safe".
    assert actions["9006"]["outbound"] is None
    credentials = {row["external_id"]: row for row in items if row["item_kind"] == "credential"}
    assert credentials["301"]["name"] == "okta_api" and credentials["301"]["item_type"] == "TEXT"
    serialized = json.dumps(items, default=str)
    for secret in SECRETS:
        assert secret not in serialized
    snapshot = json.dumps(store.snapshot(db, session, clock=clock), default=str)
    for secret in SECRETS:
        assert secret not in snapshot


def test_td3_audit_page_budget_advances_the_cursor_and_reports_backlog(
    db, setup_collection, admins, collection
):
    store, clock, connection_id, _ = setup_collection
    spec = scenario(clock.value, max_per_page=2)
    times = occurred(spec.audit)
    with serving(spec) as server:
        first = run(collection, db, admins[0], connection_id, server, clock, audit_pages=2)
        assert first["audit"]["accepted"] == 4 and first["audit"]["pages"] == 2
        assert first["outcome"] == "BACKLOG"
        row = connection_row(db, admins[0].tenant_id, connection_id)
        assert row["audit_cursor"] == times[51004]
        observations = rows(db, admins[0].tenant_id, "monitor_observations")
        assert len(observations) == 4
        assert {o["evaluation_state"] for o in observations} == {"PENDING"}
        second = run(collection, db, admins[0], connection_id, server, clock, audit_pages=2)
    assert second["audit"]["accepted"] == 2 and second["audit"]["duplicates"] > 0
    assert second["outcome"] == "COMPLETE"
    assert len(rows(db, admins[0].tenant_id, "monitor_observations")) == 6


def test_td4_the_same_records_again_are_deduplicated_and_a_reused_id_is_a_finding(
    db, setup_collection, admins, collection
):
    store, clock, connection_id, _ = setup_collection
    with serving(scenario(clock.value)) as server:
        run(collection, db, admins[0], connection_id, server, clock)
        # Rewind the cursor so the overlap serves every record a second time.
        with db.transaction(admins[0].tenant_id) as conn:
            conn.execute(
                text(
                    "UPDATE execbound.monitor_connections SET audit_cursor=:v "
                    "WHERE connection_id=:c"
                ),
                {"v": clock.value - timedelta(days=2), "c": connection_id},
            )
        again = run(collection, db, admins[0], connection_id, server, clock)
        assert again["audit"]["accepted"] == 0 and again["audit"]["duplicates"] == 6
        assert len(rows(db, admins[0].tenant_id, "monitor_observations")) == 6
        changed = scenario(
            clock.value,
            audit=[
                {**record, "operation_name": "StoryDeleted"} if index == 0 else record
                for index, record in enumerate(FIXTURE["audit"])
            ],
        )
    with serving(changed) as server:
        with db.transaction(admins[0].tenant_id) as conn:
            conn.execute(
                text(
                    "UPDATE execbound.monitor_connections SET audit_cursor=:v "
                    "WHERE connection_id=:c"
                ),
                {"v": clock.value - timedelta(days=2), "c": connection_id},
            )
        run(collection, db, admins[0], connection_id, server, clock)
    conflicting = [
        row
        for row in rows(db, admins[0].tenant_id, "monitor_observations")
        if row["integrity_conflict_at"] is not None
    ]
    assert len(conflicting) == 1 and conflicting[0]["event_id"] == "audit:51001"
    assert conflicting[0]["operation_name"] == "StoryUpdated"
    findings = rows(db, admins[0].tenant_id, "monitor_findings")
    assert any(f["rule_version"] == "source-event-integrity.v1" for f in findings)


def test_td5_a_failure_before_the_cursor_commits_stores_nothing_twice(
    db, setup_collection, admins, collection
):
    store, clock, connection_id, _ = setup_collection

    def fail_cursor(conn, cursor, statement, parameters, context, executemany):
        if "SET audit_cursor" in statement:
            raise RuntimeError("injected crash")

    # The page, its pending evaluations and the cursor advance share one transaction, so a
    # failure between writing the page and advancing the cursor must roll back both.
    sa_event.listen(db.engine, "before_cursor_execute", fail_cursor)
    with serving(scenario(clock.value, max_per_page=2)) as server:
        try:
            with pytest.raises(RuntimeError, match="injected crash"):
                run(collection, db, admins[0], connection_id, server, clock)
        finally:
            sa_event.remove(db.engine, "before_cursor_execute", fail_cursor)
        assert rows(db, admins[0].tenant_id, "monitor_observations") == []
        assert connection_row(db, admins[0].tenant_id, connection_id)["audit_cursor"] is None
        run(collection, db, admins[0], connection_id, server, clock)
    observations = rows(db, admins[0].tenant_id, "monitor_observations")
    assert len(observations) == 6 and len({o["event_id"] for o in observations}) == 6


@pytest.mark.parametrize(
    ("status", "endpoint", "expected", "state"),
    [
        (429, "audit", "RATE_LIMITED", "RATE_LIMITED"),
        (401, "audit", "AUTH_LOST", "AUTH_LOST"),
        (403, "audit", "AUTH_LOST", "AUTH_LOST"),
    ],
)
def test_td6_refusal_statuses_end_the_run_without_a_retry(
    db, setup_collection, admins, collection, status, endpoint, expected, state
):
    store, clock, connection_id, _ = setup_collection
    spec = scenario(clock.value, status={endpoint: status})
    spec.retry_after = "120"
    with serving(spec) as server:
        result = run(collection, db, admins[0], connection_id, server, clock, inventory=False)
        assert result["outcome"] == expected
        # A refusal ends the run; the collector never retries inside one run.
        assert len([p for p in server.paths() if p.endswith("audit_logs")]) == 1
    row = connection_row(db, admins[0].tenant_id, connection_id)
    assert row["health_state"] == state
    if status == 429:
        assert row["retry_after_seconds"] == 120


def test_td6_one_unsupported_capability_leaves_the_others_available(
    db, setup_collection, admins, collection
):
    store, clock, connection_id, _ = setup_collection
    with (
        serving(scenario(clock.value, status={"credentials": 404})) as server,
        client(server) as http,
    ):
        result = collection.probe(
            db, admins[0], connection_id=connection_id, api_key=KEY, client=http, clock=clock
        )
    assert result["credentials"]["state"] == "unsupported"
    assert result["stories"]["state"] == "available"
    assert result["audit"]["state"] == "available"


def test_td6_repeated_rate_limiting_and_lost_permission_record_health_findings(
    db, setup_collection, admins, collection
):
    store, clock, connection_id, _ = setup_collection
    with serving(scenario(clock.value, status={"audit": 429})) as server:
        for _ in range(3):
            run(collection, db, admins[0], connection_id, server, clock, inventory=False)
    health = [
        f
        for f in rows(db, admins[0].tenant_id, "monitor_findings")
        if f["rule_version"] == "collection-health.v1"
    ]
    assert len(health) == 1 and health[0]["connection_id"] == connection_id
    assert health[0]["observation_id"] is None
    with serving(scenario(clock.value, status={"audit": 403})) as server:
        run(collection, db, admins[0], connection_id, server, clock, inventory=False)
    titles = {
        f["title"]
        for f in rows(db, admins[0].tenant_id, "monitor_findings")
        if f["rule_version"] == "collection-health.v1"
    }
    assert any("permission" in title.lower() for title in titles)


def test_td6_a_feature_the_plan_excludes_is_unsupported_not_unknown(
    db, setup_collection, admins, collection
):
    """A tier-gated endpoint answers 422; the tenant's plan is a fact, not an unknown."""
    store, clock, connection_id, _ = setup_collection
    with serving(scenario(clock.value, gated=frozenset({"audit"}))) as server:
        with client(server) as http:
            capabilities = collection.probe(
                db, admins[0], connection_id=connection_id, api_key=KEY, client=http, clock=clock
            )
        assert capabilities["audit"]["state"] == "unsupported"
        # The AI records come from the same gated endpoint, so they are gated too.
        assert capabilities["ai_audit"]["state"] == "unsupported"
        assert capabilities["stories"]["state"] == "available"
        assert capabilities["actions"]["state"] == "available"
        # Inventory still collects; only the audit half is missing, and it says so.
        result = run(collection, db, admins[0], connection_id, server, clock)
    assert result["outcome"] == "COMPLETE"
    assert result["inventory"]["stories"] == 5
    assert result["audit"]["accepted"] == 0
    row = connection_row(db, admins[0].tenant_id, connection_id)
    assert row["capabilities"]["audit"]["state"] == "unsupported"
    assert row["health_state"] == "COLLECTING"


def test_td7_a_cursor_beyond_retention_or_a_jump_marks_a_retention_gap(
    db, setup_collection, admins, collection
):
    store, clock, connection_id, session = setup_collection
    with db.transaction(admins[0].tenant_id) as conn:
        conn.execute(
            text("UPDATE execbound.monitor_connections SET audit_cursor=:v WHERE connection_id=:c"),
            {"v": datetime(2024, 1, 1, tzinfo=UTC), "c": connection_id},
        )
    with serving(scenario(clock.value)) as server:
        result = run(collection, db, admins[0], connection_id, server, clock, inventory=False)
    assert result["outcome"] == "RETENTION_GAP"
    row = connection_row(db, admins[0].tenant_id, connection_id)
    assert row["health_state"] == "RETENTION_GAP"
    gap = [
        f
        for f in rows(db, admins[0].tenant_id, "monitor_findings")
        if f["rule_version"] == "collection-health.v1"
    ]
    assert len(gap) == 1 and "retention" in gap[0]["title"].lower()
    assert any(
        "retention" in str(item).lower()
        for item in store.snapshot(db, session, clock=clock)["connections"]
    )


def test_td8_configuration_changes_match_only_on_listed_operations(
    db, setup_collection, admins, collection
):
    store, clock, connection_id, _ = setup_collection
    with serving(scenario(clock.value)) as server:
        run(collection, db, admins[0], connection_id, server, clock)
    store.evaluate_pending(db, admins[0], limit=100, clock=clock)
    results = {
        row["event_id"]: row["evaluation_result"]
        for row in rows(db, admins[0].tenant_id, "monitor_observations")
    }
    # A change on an instrumented story and a credential change match; the rest do not.
    assert results["audit:51001"] == "MATCH"
    assert results["audit:51002"] == "MATCH"
    assert results["audit:51004"] == "MATCH"
    assert results["audit:51006"] == "NO_MATCH"
    assert results["audit:51003"] == "NO_MATCH"
    # An operation name outside the versioned mapping is never guessed into a match.
    assert results["audit:51005"] == "INSUFFICIENT_EVIDENCE"
    findings = [
        f
        for f in rows(db, admins[0].tenant_id, "monitor_findings")
        if f["rule_version"] == "monitored-path-change.v1"
    ]
    assert len(findings) == 3
    assert all(f["source_id"] is None and f["connection_id"] == connection_id for f in findings)


def test_td9_a_discovered_story_without_a_source_opens_resolves_and_reopens(
    db, setup_collection, admins, collection
):
    store, clock, connection_id, _ = setup_collection
    with serving(scenario(clock.value)) as server:
        result = run(collection, db, admins[0], connection_id, server, clock, audit_pages=0)
        assert result["coverage"]["discovered_only"] == 1
        assert result["coverage"]["instrumented"] == 1
        assert result["coverage"]["no_outbound"] == 1
        assert result["coverage"]["disabled"] == 1
        assert result["coverage"]["coverage_unknown"] == 1
        gaps = [
            f
            for f in rows(db, admins[0].tenant_id, "monitor_findings")
            if f["rule_version"] == "instrumentation-gap.v1"
        ]
        assert len(gaps) == 1
        source = store.create_source(
            db,
            admins[0],
            label="Account lockdown",
            story_id="4002",
            expires_at=clock.now() + timedelta(hours=2),
            clock=clock,
        )
        second = run(collection, db, admins[0], connection_id, server, clock, audit_pages=0)
        assert second["coverage"]["discovered_only"] == 0
        assert (
            len(
                [
                    f
                    for f in rows(db, admins[0].tenant_id, "monitor_findings")
                    if f["rule_version"] == "instrumentation-gap.v1"
                ]
            )
            == 1
        )
        store.revoke_source(db, admins[0], source.source_id, clock=clock)
        clock.value = clock.value + timedelta(minutes=5)
        run(collection, db, admins[0], connection_id, server, clock, audit_pages=0)
    reopened = [
        f
        for f in rows(db, admins[0].tenant_id, "monitor_findings")
        if f["rule_version"] == "instrumentation-gap.v1"
    ]
    assert len(reopened) == 2


# Two source rows for one story, numbered so that the one coverage must not read sorts last by
# its identifier and is inserted last, so neither an index scan nor a heap scan reaches it first.
LIVE_SOURCE = "00000000-0000-4000-8000-000000000001"
DEAD_SOURCE = "ffffffff-ffff-4fff-bfff-ffffffffffff"


def source_rows(admin_engine, tenant, now, dead):
    """Story 4002's live source, registered a minute ago and not heard from yet, and then an
    earlier source of the same story that was heard from more recently: revoked, or
    (`dead="expired"`) never revoked and expired."""
    with admin_engine.begin() as conn:
        space = conn.execute(
            text(
                "SELECT space_id FROM execbound.spaces WHERE tenant_id = :t "
                "ORDER BY created_at, space_id LIMIT 1"
            ),
            {"t": tenant},
        ).scalar_one()
        for source, digest, active, revoked, expires in (
            (LIVE_SOURCE, "a" * 64, True, None, now + timedelta(days=7)),
            (
                DEAD_SOURCE,
                "b" * 64,
                dead == "expired",
                None if dead == "expired" else now - timedelta(hours=1),
                now - timedelta(hours=1) if dead == "expired" else now + timedelta(days=7),
            ),
        ):
            conn.execute(
                text(
                    "INSERT INTO execbound.monitor_sources (tenant_id, source_id, label, "
                    "story_id, token_hash, created_at, expires_at, heartbeat_seconds, "
                    "rate_window_at, space_id, active, revoked_at, last_heartbeat_at) VALUES "
                    "(:t, :s, 'Account lockdown', '4002', :h, :created, :expires, 300, :created, "
                    ":space, :active, :revoked, :heard)"
                ),
                {
                    "t": tenant,
                    "s": source,
                    "h": digest,
                    "created": now
                    - (timedelta(minutes=1) if source == LIVE_SOURCE else timedelta(days=2)),
                    "expires": expires,
                    "space": space,
                    "active": active,
                    "revoked": revoked,
                    "heard": None if source == LIVE_SOURCE else now - timedelta(minutes=2),
                },
            )


@pytest.mark.parametrize("dead", ["revoked", "expired"])
def test_td9_a_storys_live_source_closes_its_gap_whatever_earlier_source_it_replaced(
    db, admin_engine, setup_collection, admins, collection, dead
):
    """A story keeps its earlier source on record beside the one that replaced it, revoked or
    left to expire. Coverage reads the live source whichever row the database returns last,
    so the gap closes, stays closed on later passes and raises no further finding."""
    _, clock, connection_id, _ = setup_collection
    tenant = admins[0].tenant_id

    def gaps():
        return [
            f
            for f in rows(db, tenant, "monitor_findings")
            if f["rule_version"] == "instrumentation-gap.v1"
        ]

    def story():
        return next(
            row
            for row in rows(db, tenant, "monitor_inventory")
            if row["item_kind"] == "story" and row["external_id"] == "4002"
        )

    with serving(scenario(clock.value)) as server:
        run(collection, db, admins[0], connection_id, server, clock, audit_pages=0)
        assert story()["gap_opened_at"] is not None and len(gaps()) == 1
        source_rows(admin_engine, tenant, clock.now(), dead)
        for heard in (False, True, True):
            clock.value = clock.value + timedelta(seconds=30)
            if not heard:
                # Before its first heartbeat the new source covers the story already.
                result = run(collection, db, admins[0], connection_id, server, clock, audit_pages=0)
                assert result["coverage"]["discovered_only"] == 0
                assert story()["gap_opened_at"] is None
                continue
            with admin_engine.begin() as conn:
                conn.execute(
                    text(
                        "UPDATE execbound.monitor_sources SET last_heartbeat_at = :now "
                        "WHERE tenant_id = :t AND source_id = :s"
                    ),
                    {"now": clock.now(), "t": tenant, "s": LIVE_SOURCE},
                )
            result = run(collection, db, admins[0], connection_id, server, clock, audit_pages=0)
            assert result["coverage"]["discovered_only"] == 0
            assert (story()["coverage_class"], story()["gap_opened_at"]) == ("instrumented", None)
    assert len(gaps()) == 1


@pytest.mark.parametrize("decides", ["heard_from_last", "newest"])
def test_td9_of_two_live_sources_coverage_reads_the_one_heard_from_last_then_the_newest(
    db, admin_engine, setup_collection, admins, collection, decides
):
    """A story registered before `SOURCE_EXISTS` can hold two live sources, and coverage reads
    one of them: the one heard from last, then the newest. In each case the source coverage must
    not read is the one the next term, or the identifier, would choose, and is inserted last, so
    a reconcile that drops or reorders either term reads a source that is not reporting and
    calls the story `registered_stale`.

    `heard_from_last`: an older source heard from two minutes ago, and a newer one registered
    twenty minutes ago and never heard from, past twice its five-minute heartbeat, which also
    sorts first by identifier. `newest`: neither heard from yet, a newer source registered a
    minute ago, and an older one registered a day ago, which sorts first by identifier."""
    _, clock, connection_id, _ = setup_collection
    tenant = admins[0].tenant_id
    now = clock.now()
    lowest, highest = LIVE_SOURCE, DEAD_SOURCE  # identifiers, whatever their tokens' state
    # (source, created, last heard): the source coverage must read, then the one it must not.
    sources = {
        "heard_from_last": (
            (highest, now - timedelta(days=2), now - timedelta(minutes=2)),
            (lowest, now - timedelta(minutes=20), None),
        ),
        "newest": (
            (highest, now - timedelta(minutes=1), None),
            (lowest, now - timedelta(days=1), None),
        ),
    }[decides]

    def story():
        return next(
            row
            for row in rows(db, tenant, "monitor_inventory")
            if row["item_kind"] == "story" and row["external_id"] == "4002"
        )

    with serving(scenario(clock.value)) as server:
        run(collection, db, admins[0], connection_id, server, clock, audit_pages=0)
        assert story()["gap_opened_at"] is not None
        with admin_engine.begin() as conn:
            space = conn.execute(
                text(
                    "SELECT space_id FROM execbound.spaces WHERE tenant_id = :t "
                    "ORDER BY created_at, space_id LIMIT 1"
                ),
                {"t": tenant},
            ).scalar_one()
            for index, (source, created, heard) in enumerate(sources):
                conn.execute(
                    text(
                        "INSERT INTO execbound.monitor_sources (tenant_id, source_id, label, "
                        "story_id, token_hash, created_at, expires_at, heartbeat_seconds, "
                        "rate_window_at, space_id, active, revoked_at, last_heartbeat_at) "
                        "VALUES (:t, :s, 'Account lockdown', '4002', :h, :created, :expires, "
                        "300, :created, :space, true, NULL, :heard)"
                    ),
                    {
                        "t": tenant,
                        "s": source,
                        "h": f"{index + 12:x}" * 64,
                        "created": created,
                        "expires": now + timedelta(days=7),
                        "space": space,
                        "heard": heard,
                    },
                )
        result = run(collection, db, admins[0], connection_id, server, clock, audit_pages=0)
    assert result["coverage"]["registered_stale"] == 0
    assert (story()["coverage_class"], story()["gap_opened_at"]) == ("instrumented", None)


def test_td9_inventory_names_only_a_source_that_still_covers_its_story(
    db, setup_collection, admins, collection
):
    """Inventory names a story's source only while one is unrevoked, so a story whose source was
    revoked shows its gap with no source and can be reported again; its replacement is named,
    and the story's action count does not grow with the sources it has had."""
    store, clock, connection_id, session = setup_collection

    def row():
        coverage = store.snapshot(db, session, clock=clock)["coverage"]
        return next(item for item in coverage if item["external_id"] == "4002")

    with serving(scenario(clock.value)) as server:
        run(collection, db, admins[0], connection_id, server, clock, audit_pages=0)
        actions = row()["action_count"]
        first = store.create_source(
            db,
            admins[0],
            label="Account lockdown",
            story_id="4002",
            expires_at=clock.now() + timedelta(hours=2),
            clock=clock,
        )
        store.revoke_source(db, admins[0], first.source_id, clock=clock)
        clock.value = clock.value + timedelta(minutes=5)
        run(collection, db, admins[0], connection_id, server, clock, audit_pages=0)
        gap = row()
        assert (gap["source_id"], gap["gap_opened_at"] is not None) == (None, True)
        second = store.create_source(
            db,
            admins[0],
            label="Account lockdown",
            story_id="4002",
            expires_at=clock.now() + timedelta(hours=2),
            clock=clock,
        )
        covered = row()
    assert covered["source_id"] == str(second.source_id)
    assert covered["action_count"] == actions


def test_td9_inventory_says_whether_the_source_it_names_reports_now_and_is_seen(
    db, admin_engine, setup_collection, admins, collection
):
    """A story's gap is reassessed only by an inventory pass, so a source registered since the
    last one is named beside a gap that is still open: the row says that source can report now
    (`source_expired` false), never that it no longer covers the story. A source the reader sees
    is named before one they do not, and among those they see a live one before an expired one,
    which is named as expired. A source in a Space the reader does not see is its identifier
    alone (`source_visible` false): the row never says whether its token has expired, and which
    of several such sources it names does not follow their tokens either."""
    store, clock, connection_id, session = setup_collection
    tenant = admins[0].tenant_id

    def row():
        coverage = store.snapshot(db, session, clock=clock)["coverage"]
        found = next(item for item in coverage if item["external_id"] == "4002")
        return (found["source_id"], found["source_expired"], found["source_visible"])

    def expire(source_id, ago):
        with admin_engine.begin() as conn:
            conn.execute(
                text(
                    "UPDATE execbound.monitor_sources SET created_at = :made, expires_at = :past "
                    "WHERE tenant_id = :t AND source_id = :s"
                ),
                {
                    "made": clock.now() - timedelta(hours=2),
                    "past": clock.now() - ago,
                    "t": tenant,
                    "s": source_id,
                },
            )

    def mint(**changes):
        return store.create_source(
            db,
            admins[0],
            label="Account lockdown",
            story_id="4002",
            expires_at=clock.now() + timedelta(hours=2),
            clock=clock,
            **changes,
        ).source_id

    with serving(scenario(clock.value)) as server:
        run(collection, db, admins[0], connection_id, server, clock, audit_pages=0)
    with admin_engine.begin() as conn:
        shown = conn.execute(
            text("SELECT space_id FROM execbound.monitor_connections WHERE connection_id = :c"),
            {"c": connection_id},
        ).scalar_one()
        hidden = make_space(conn, tenant, "Elsewhere", created_by=admins[0].principal_id)
        farther = make_space(conn, tenant, "Farther", created_by=admins[0].principal_id)
        # The reader looks at the connection's Space alone.
        conn.execute(
            text(
                "UPDATE execbound.human_sessions SET current_space_id = :space "
                "WHERE tenant_id = :t AND session_id = :s"
            ),
            {"space": shown, "t": tenant, "s": session.session_id},
        )
    here = mint()
    expire(here, timedelta(minutes=2))
    assert row() == (str(here), True, True)
    # The reader's own expired source is named before a live one they do not see.
    elsewhere = mint(space=hidden)
    assert row() == (str(here), True, True)
    store.revoke_source(db, admins[0], here, clock=clock)
    assert row() == (str(elsewhere), False, False)
    # Its token expiring changes nothing the reader is told.
    expire(elsewhere, timedelta(minutes=1))
    assert row() == (str(elsewhere), False, False)
    # Of two sources the reader does not see, the one named does not follow their tokens: not
    # while one is live and the other expired, nor once the live one has expired first.
    beyond = mint(space=farther)
    named = str(min(elsewhere, beyond))
    assert row() == (named, False, False)
    expire(beyond, timedelta(minutes=2))
    assert row() == (named, False, False)
    # Registered since the last inventory pass: named as able to report, the gap still open.
    fresh = mint()
    assert row() == (str(fresh), False, True)
    coverage = store.snapshot(db, session, clock=clock)["coverage"]
    assert next(i for i in coverage if i["external_id"] == "4002")["gap_opened_at"] is not None
    # A reader who sees every Space: a live source before an expired one, then the latest to
    # expire, each named with its own state.
    with admin_engine.begin() as conn:
        conn.execute(
            text(
                "UPDATE execbound.human_sessions SET current_space_id = NULL "
                "WHERE tenant_id = :t AND session_id = :s"
            ),
            {"t": tenant, "s": session.session_id},
        )
    assert row() == (str(fresh), False, True)
    store.revoke_source(db, admins[0], fresh, clock=clock)
    assert row() == (str(elsewhere), True, True)
    expire(elsewhere, timedelta(minutes=3))
    assert row() == (str(beyond), True, True)


def test_td9_inventory_says_a_revoked_connections_gap_is_never_reassessed(
    db, setup_collection, admins, collection, api
):
    """A story's gap is reassessed only by an inventory pass of its connection, and a revoked
    connection is never collected again, so its stories keep whatever gap they had. The row says
    the connection was revoked (`connection_revoked`), so a source added for the story reads as
    able to report beside a gap no pass will close, rather than one the next pass reassesses."""
    models, _ = api
    store, clock, connection_id, session = setup_collection

    def row():
        coverage = store.snapshot(db, session, clock=clock)["coverage"]
        found = next(item for item in coverage if item["external_id"] == "4002")
        return (found["gap_opened_at"] is not None, found["source_id"], found["connection_revoked"])

    with serving(scenario(clock.value)) as server:
        run(collection, db, admins[0], connection_id, server, clock, audit_pages=0)
        assert row() == (True, None, False)
        source = store.create_source(
            db,
            admins[0],
            label="Account lockdown",
            story_id="4002",
            expires_at=clock.now() + timedelta(hours=2),
            clock=clock,
        ).source_id
        assert row() == (True, str(source), False)
        store.revoke_connection(db, admins[0], connection_id, clock=clock)
        assert row() == (True, str(source), True)
        # No pass runs for it again, so the gap beside the source stays open.
        clock.value = clock.value + timedelta(minutes=5)
        with pytest.raises(models.MonitorError):
            run(collection, db, admins[0], connection_id, server, clock, audit_pages=0)
    assert row() == (True, str(source), True)


def test_td10_a_mapped_ai_tool_run_matches_and_an_unmapped_one_stays_insufficient(
    db, setup_collection, admins, collection, api
):
    models, store = api
    _, clock, connection_id, _ = setup_collection
    store.set_profile(
        db,
        admins[0],
        models.DetectionProfile.model_validate(
            {
                "sensitive_actions": ("identity.disable",),
                "restricted_targets": (),
                "burst_threshold": None,
                "burst_window_seconds": None,
                "ai_tool_actions": {"synthetic_disable_user": "identity.disable"},
            }
        ),
        clock=clock,
    )
    spec = scenario(clock.value, audit=list(FIXTURE["audit"]) + list(FIXTURE["ai_audit"]))
    with serving(spec) as server:
        run(collection, db, admins[0], connection_id, server, clock, inventory=False)
    store.evaluate_pending(db, admins[0], limit=100, clock=clock)
    observations = {
        row["event_id"]: row for row in rows(db, admins[0].tenant_id, "monitor_observations")
    }
    assert observations["audit:52002"]["kind"] == "ai_tool_run"
    assert observations["audit:52002"]["action"] == "synthetic_disable_user"
    assert observations["audit:52002"]["evaluation_result"] == "MATCH"
    assert observations["audit:52003"]["evaluation_result"] == "INSUFFICIENT_EVIDENCE"
    model_run = observations["audit:52001"]
    assert model_run["kind"] == "ai_model_run" and model_run["action"] == "synthetic-model-1"
    assert (model_run["input_tokens"], model_run["output_tokens"]) == (1200, 340)
    serialized = json.dumps(list(observations.values()), default=str)
    for secret in SECRETS:
        assert secret not in serialized


def test_td11_records_stay_in_their_tenant_and_a_foreign_tenant_is_quarantined(
    db, setup_collection, admins, collection, api
):
    _, store = api
    _, clock, connection_id, _ = setup_collection
    other = store.create_connection(
        db,
        admins[1],
        label="Second synthetic tenant",
        base_url=BASE_URL,
        key_fingerprint=collection.fingerprint(KEY),
        team_id="7",
        clock=clock,
    )
    with serving(scenario(clock.value)) as server:
        run(collection, db, admins[0], connection_id, server, clock)
        run(collection, db, admins[1], other, server, clock)
    first = rows(db, admins[0].tenant_id, "monitor_observations")
    second = rows(db, admins[1].tenant_id, "monitor_observations")
    assert len(first) == len(second) == 6
    assert {row["tenant_id"] for row in first} == {admins[0].tenant_id}
    assert {row["tenant_id"] for row in second} == {admins[1].tenant_id}
    foreign = scenario(
        clock.value, audit=[{**record, "tenant_id": 901} for record in FIXTURE["audit"]]
    )
    with db.transaction(admins[0].tenant_id) as conn:
        conn.execute(
            text(
                "UPDATE execbound.monitor_connections SET audit_cursor=NULL WHERE connection_id=:c"
            ),
            {"c": connection_id},
        )
    with serving(foreign) as server:
        result = run(collection, db, admins[0], connection_id, server, clock, inventory=False)
    assert result["audit"]["quarantined"] == 6 and result["audit"]["accepted"] == 0
    assert len(rows(db, admins[0].tenant_id, "monitor_observations")) == 6
    quarantine = [
        f
        for f in rows(db, admins[0].tenant_id, "monitor_findings")
        if f["rule_version"] == "collection-health.v1" and "tenant" in f["title"].lower()
    ]
    assert len(quarantine) == 1


def test_td12_the_migration_round_trip_keeps_the_runtime_catalog_honest(db, admin_engine, admins):
    assert {"monitor_connections", "monitor_inventory"} <= set(TABLES)
    with db.transaction(admins[0].tenant_id) as conn:
        check_runtime(conn)
    with admin_engine.begin() as conn:
        for table in ("monitor_connections", "monitor_inventory"):
            forced = conn.execute(
                text(
                    "SELECT relrowsecurity AND relforcerowsecurity FROM pg_class "
                    "WHERE oid = to_regclass(:name)"
                ),
                {"name": f"execbound.{table}"},
            ).scalar_one()
            assert forced is True
            for privilege in ("DELETE", "TRUNCATE"):
                assert (
                    conn.execute(
                        text("SELECT has_table_privilege('execbound_app', :name, :p)"),
                        {"name": f"execbound.{table}", "p": privilege},
                    ).scalar_one()
                    is False
                )


def test_td12_downgrade_refuses_while_collected_evidence_is_retained(
    db, admin_engine, setup_collection, admins, collection
):
    _, clock, connection_id, _ = setup_collection
    with serving(scenario(clock.value)) as server:
        run(collection, db, admins[0], connection_id, server, clock)
    config = Config("alembic.ini")
    config.attributes["database_url"] = os.environ["TEST_MIGRATION_DATABASE_URL"]
    try:
        with pytest.raises(RuntimeError):
            # Name the revision below the collection migration: a relative step would
            # stop at whichever revision happens to sit above it.
            command.downgrade(config, "0022_limit_scopes")
    finally:
        # The schema is shared with every later test, so restore it even on failure.
        command.upgrade(config, "head")
