# SPDX-License-Identifier: AGPL-3.0-only
"""Acknowledging a monitoring finding, in the store (acceptance MQ1 and MQ2).

Every read of the findings goes through the one helper's space predicate, so a person looks
at the findings of the spaces they see. Before #678, `acknowledge` locked a finding by
tenant and identifier alone: an administrator narrowed to one space, or one looking at one
space, acknowledged a finding of another space by naming it, and silenced it for the people
who own it. Acknowledging also appended nothing, so an acknowledgement through a personal
access token could not be told from one in the browser (T4.42).

Now the lock reads the finding under the same predicate, a finding outside it is refused as
one that does not exist, and each acknowledgement appends one `monitor.finding_acknowledged`
naming the finding, its rule and the credential that acted, with the finding's space on the
row and no observation content in the payload.
"""

from concurrent.futures import ThreadPoolExecutor
from datetime import timedelta
from threading import Barrier
from uuid import uuid4

import pytest
from secret_shapes import FREE_TEXT, FREE_TEXT_IDS
from space_fixtures import default_space, make_space, place
from sqlalchemy import text
from sqlalchemy.exc import DBAPIError
from test_console_api_monitoring import finding_in_another_space, seed_agent, seed_tines
from test_execution import registry as registry
from test_execution import world as world
from test_protected_path import connector as connector
from test_protected_path import live_provider as live_provider
from test_runtime import runtime as runtime
from test_tines_collection import KEY

from execbound.assistant.tools import ToolContext, run_tool
from execbound.monitoring import collection
from execbound.monitoring import store as monitor_store
from execbound.monitoring.store import COLLECTION_HEALTH_RULE as RUN
from execbound.monitoring.store import HEALTH_RULE as HEALTH
from execbound.monitoring.store import MonitorError
from execbound.spaces import set_current_space
from execbound.surfaces.sessions import issue_session, load_session
from execbound_harness.fake_tines import BASE_URL

pytestmark = pytest.mark.integration

KIND = "monitor.finding_acknowledged"


def fenced(conn, tenant):
    conn.execute(text("SELECT set_config('execbound.tenant_id', :t, true)"), {"t": str(tenant)})


def session_for(db, identity, clock):
    return load_session(db, issue_session(db, identity, clock=clock).token, clock=clock)


def finding_state(admin_engine, tenant, finding):
    with admin_engine.begin() as conn:
        fenced(conn, tenant)
        return (
            conn.execute(
                text(
                    "SELECT acknowledged_at, acknowledged_by, rule_version, space_id "
                    "FROM execbound.monitor_findings WHERE tenant_id=:t AND finding_id=:f"
                ),
                {"t": tenant, "f": finding},
            )
            .mappings()
            .one()
        )


def acknowledged_events(admin_engine, tenant):
    with admin_engine.begin() as conn:
        fenced(conn, tenant)
        return [
            dict(row)
            for row in conn.execute(
                text(
                    "SELECT actor_id, payload, space_id FROM execbound.audit_events "
                    "WHERE tenant_id=:t AND kind=:k ORDER BY sequence"
                ),
                {"t": tenant, "k": KIND},
            ).mappings()
        ]


@pytest.fixture
def spaces(db, admin_engine, world):
    """Two spaces, an administrator narrowed to the first, one open finding in each, and a
    browser session for each administrator."""
    built = finding_in_another_space(db, admin_engine, world)
    clock = world["clock"]
    return {
        **built,
        "narrowed": session_for(db, built["narrowed"], clock),
        "workspace": session_for(db, world["admin"], clock),
    }


def refused(db, session, finding, clock):
    with pytest.raises(MonitorError) as refusal:
        monitor_store.acknowledge(db, session, finding, clock=clock)
    assert refusal.value.code == "FINDING_UNAVAILABLE"


def test_mq1_an_administrator_cannot_acknowledge_a_finding_outside_the_spaces_they_see(
    db, admin_engine, world, spaces
):
    tenant, clock = spaces["tenant"], world["clock"]
    # Narrowed to the default space: the other space's finding is refused exactly as an
    # identifier that names nothing is, and the row is untouched.
    refused(db, spaces["narrowed"], spaces["elsewhere"], clock)
    refused(db, spaces["narrowed"], uuid4(), clock)
    assert finding_state(admin_engine, tenant, spaces["elsewhere"])["acknowledged_at"] is None

    # Workspace-wide, but looking at the default space: the same refusal.
    with db.transaction(tenant) as conn:
        set_current_space(conn, spaces["workspace"], spaces["own"])
    refused(db, spaces["workspace"], spaces["elsewhere"], clock)
    state = finding_state(admin_engine, tenant, spaces["elsewhere"])
    assert state["acknowledged_at"] is None and state["acknowledged_by"] is None
    assert acknowledged_events(admin_engine, tenant) == []

    # The narrowed administrator still acknowledges a finding of their own space.
    monitor_store.acknowledge(db, spaces["narrowed"], spaces["here"], clock=clock)
    assert finding_state(admin_engine, tenant, spaces["here"])["acknowledged_at"] is not None

    # Workspace-wide on "All spaces", the other space's finding is acknowledged.
    with db.transaction(tenant) as conn:
        set_current_space(conn, spaces["workspace"], None)
    monitor_store.acknowledge(db, spaces["workspace"], spaces["elsewhere"], clock=clock)
    state = finding_state(admin_engine, tenant, spaces["elsewhere"])
    assert state["acknowledged_at"] is not None
    assert state["acknowledged_by"] == world["admin"].principal_id


def test_mq2_an_acknowledgement_appends_one_event_and_a_repeat_none(
    db, admin_engine, world, spaces
):
    tenant, clock = spaces["tenant"], world["clock"]
    session = spaces["workspace"]
    finding = spaces["elsewhere"]
    monitor_store.acknowledge(db, session, finding, clock=clock)
    state = finding_state(admin_engine, tenant, finding)
    [event] = acknowledged_events(admin_engine, tenant)
    assert event["actor_id"] == world["admin"].principal_id
    # An administrator's decision about a finding: identifiers and the rule, no observation
    # content (story, target reference, outcome or the platform's actor).
    assert event["payload"] == {
        "finding_id": str(finding),
        "rule_version": state["rule_version"],
        "actor_credential_id": str(session.identity.credential_id),
    }
    # The finding's space travels on the row, never in the hashed payload.
    assert event["space_id"] == spaces["other"] == state["space_id"]

    # Acknowledging again changes nothing and appends nothing.
    monitor_store.acknowledge(db, session, finding, clock=clock)
    assert len(acknowledged_events(admin_engine, tenant)) == 1
    assert finding_state(admin_engine, tenant, finding) == state

    # A refusal appends nothing either.
    refused(db, spaces["narrowed"], spaces["elsewhere"], clock)
    assert len(acknowledged_events(admin_engine, tenant)) == 1


# The findings reads (MQ4 to MQ6, MQ10): one reader shared by the snapshot, the findings list
# and the single finding, each under the reads' space predicate.


def raise_finding(db, tenant, at, rule, title, *, source=None, connection=None, agent=None):
    """One finding written by the store's own writer, at `at`; no observation."""
    finding = uuid4()
    with db.transaction(tenant) as conn:
        monitor_store._finding(
            conn,
            tenant,
            source,
            None,
            rule,
            title,
            at,
            finding_id=finding,
            connection=connection,
            agent=agent,
        )
    return finding


def tines_connection(db, world, label="Tines"):
    return monitor_store.create_connection(
        db,
        world["admin"],
        label=label,
        base_url=BASE_URL,
        key_fingerprint=collection.fingerprint(KEY),
        clock=world["clock"],
    )


def acknowledged_directly(admin_engine, tenant, findings, by, at):
    with admin_engine.begin() as conn:
        fenced(conn, tenant)
        conn.execute(
            text(
                "UPDATE execbound.monitor_findings SET acknowledged_at=:at, acknowledged_by=:p "
                "WHERE tenant_id=:t AND finding_id = ANY(CAST(:f AS uuid[]))"
            ),
            {"t": tenant, "p": by, "at": at, "f": [str(item) for item in findings]},
        )


def second_space(admin_engine, tenant):
    with admin_engine.begin() as conn:
        fenced(conn, tenant)
        return default_space(conn, tenant), make_space(conn, tenant, "Customer B")


def move(admin_engine, tenant, table, key, identifiers, space):
    with admin_engine.begin() as conn:
        fenced(conn, tenant)
        for identifier in identifiers:
            place(conn, tenant, table, key, identifier, space)


def looking_at(db, session, space):
    with db.transaction(session.identity.tenant_id) as conn:
        set_current_space(conn, session, space)


def test_mq4_findings_read_by_state_counts_beyond_the_page(db, admin_engine, world):
    tenant, clock = world["admin"].tenant_id, world["clock"]
    now = clock.now()
    connection = tines_connection(db, world)
    raised = [
        raise_finding(
            db,
            tenant,
            now - timedelta(minutes=index),
            RUN,
            f"Finding {index}",
            connection=connection,
        )
        for index in range(250)
    ]
    # The 230 oldest are acknowledged; the 20 newest stay open.
    acknowledged_directly(admin_engine, tenant, raised[20:], world["admin"].principal_id, now)
    session = session_for(db, world["admin"], clock)

    open_view = monitor_store.findings(db, session, "open", clock=clock)
    assert [row["finding_id"] for row in open_view["findings"]] == raised[:20]
    assert open_view["counts"] == {"open": 20, "acknowledged": 230}
    acknowledged = monitor_store.findings(db, session, "acknowledged", clock=clock)
    assert [row["finding_id"] for row in acknowledged["findings"]] == raised[20:220]
    every = monitor_store.findings(db, session, "all", clock=clock)
    assert [row["finding_id"] for row in every["findings"]] == raised[:200]
    assert every["counts"] == {"open": 20, "acknowledged": 230}
    # The snapshot's own count is the same SQL count, right beyond its 200 rows.
    assert monitor_store.snapshot(db, session, clock=clock)["counts"]["open"] == 20
    with pytest.raises(MonitorError):
        monitor_store.findings(db, session, "closed", clock=clock)

    # Counts are per space: ten open findings move to another space, and a session looking
    # at the default one counts the ten that stayed.
    own, other = second_space(admin_engine, tenant)
    move(admin_engine, tenant, "monitor_findings", "finding_id", raised[:10], other)
    looking_at(db, session, own)
    narrowed = monitor_store.findings(db, session, "open", clock=clock)
    assert narrowed["counts"] == {"open": 10, "acknowledged": 230}
    assert [row["finding_id"] for row in narrowed["findings"]] == raised[10:20]


def test_mq5_one_finding_reads_inside_the_space_only(db, admin_engine, world):
    tenant, clock = world["admin"].tenant_id, world["clock"]
    now = clock.now()
    connection = tines_connection(db, world)
    here = raise_finding(db, tenant, now, RUN, "Here", connection=connection)
    elsewhere = raise_finding(db, tenant, now, RUN, "Elsewhere", connection=connection)
    own, other = second_space(admin_engine, tenant)
    move(admin_engine, tenant, "monitor_findings", "finding_id", [elsewhere], other)
    session = session_for(db, world["admin"], clock)
    looking_at(db, session, own)

    assert monitor_store.finding(db, session, here, clock=clock)["finding"]["title"] == "Here"
    for unseen in (elsewhere, uuid4()):
        with pytest.raises(MonitorError) as refusal:
            monitor_store.finding(db, session, unseen, clock=clock)
        assert refusal.value.code == "FINDING_UNAVAILABLE"
    # On "All spaces" the workspace-wide administrator reads it.
    looking_at(db, session, None)
    assert monitor_store.finding(db, session, elsewhere, clock=clock)["finding"]["title"] == (
        "Elsewhere"
    )


def test_mq6_a_finding_names_its_agent_connection_source_and_acknowledger(db, admin_engine, world):
    tenant, clock = world["admin"].tenant_id, world["clock"]
    now = clock.now()
    directory, agent_id = seed_agent(db, world)
    connection = tines_connection(db, world, "Tines <b>tenant</b>")
    monitor_store.create_source(
        db,
        world["admin"],
        label="Triage <i>source</i>",
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
    reach = raise_finding(
        db, tenant, now, "ungoverned-reach.v1", "Reach", connection=directory, agent=agent_id
    )
    health = raise_finding(db, tenant, now, RUN, "Run", connection=connection)
    quiet = raise_finding(db, tenant, now, HEALTH, "Quiet", source=source)
    session = session_for(db, world["admin"], clock)
    monitor_store.acknowledge(db, session, quiet, clock=clock)

    snapshot = monitor_store.snapshot(db, session, clock=clock)
    listed = monitor_store.findings(db, session, "all", clock=clock)
    for rows, principals in (
        (snapshot["findings"], snapshot["acknowledgers"]),
        (listed["findings"], listed["principals"]),
    ):
        by_id = {row["finding_id"]: row for row in rows}
        agent_row = by_id[reach]
        assert agent_row["agent_id"] == agent_id
        assert agent_row["identity_class"] == "agent_identity"
        assert agent_row["sponsor_state"] == "present" and agent_row["sponsor_count"] == 1
        assert "owner_count" in agent_row and "sponsors" not in agent_row
        assert by_id[health]["connection_label"] == "Tines <b>tenant</b>"
        assert by_id[quiet]["source_label"] == "Triage <i>source</i>"
        assert by_id[quiet]["acknowledged_by"] == world["admin"].principal_id
        [named] = [row for row in principals if row["principal_id"] == world["admin"].principal_id]
        assert named["kind"] == "ADMIN" and named["number"] is not None
        assert "@" not in repr(named)
    one = monitor_store.finding(db, session, quiet, clock=clock)
    assert one["finding"]["source_label"] == "Triage <i>source</i>"
    assert [row["principal_id"] for row in one["principals"]] == [world["admin"].principal_id]
    assert monitor_store.finding(db, session, reach, clock=clock)["finding"]["display_name"]


def test_mq10_the_agent_page_lists_only_findings_in_the_space(db, admin_engine, world):
    tenant, clock = world["admin"].tenant_id, world["clock"]
    now = clock.now()
    directory, agent_id = seed_agent(db, world)
    with admin_engine.begin() as conn:
        fenced(conn, tenant)
        conn.execute(
            text("DELETE FROM execbound.monitor_deliveries WHERE tenant_id=:t"), {"t": tenant}
        )
        conn.execute(
            text("DELETE FROM execbound.monitor_findings WHERE tenant_id=:t"), {"t": tenant}
        )
    here = raise_finding(
        db, tenant, now, "ungoverned-reach.v1", "Here", connection=directory, agent=agent_id
    )
    elsewhere = raise_finding(
        db, tenant, now, "sponsorless-agent.v1", "Away", connection=directory, agent=agent_id
    )
    own, other = second_space(admin_engine, tenant)
    move(admin_engine, tenant, "monitor_findings", "finding_id", [elsewhere], other)
    session = session_for(db, world["admin"], clock)
    looking_at(db, session, own)
    detail = monitor_store.agent_detail(db, session, agent_id, clock=clock)
    assert [row["finding_id"] for row in detail["findings"]] == [here]
    looking_at(db, session, None)
    detail = monitor_store.agent_detail(db, session, agent_id, clock=clock)
    assert {row["finding_id"] for row in detail["findings"]} == {here, elsewhere}


def test_mq10_coverage_inventory_and_deliveries_follow_the_space(db, admin_engine, world):
    tenant, clock = world["admin"].tenant_id, world["clock"]
    connection = seed_tines(db, world)
    session = session_for(db, world["admin"], clock)
    before = monitor_store.snapshot(db, session, clock=clock)
    assert before["coverage"] and before["inventory"] and len(before["deliveries"]) >= 2
    findings = sorted(row["finding_id"] for row in before["deliveries"])
    moved = findings[: len(findings) // 2]
    own, other = second_space(admin_engine, tenant)
    move(admin_engine, tenant, "monitor_connections", "connection_id", [connection], other)
    move(admin_engine, tenant, "monitor_findings", "finding_id", moved, other)

    looking_at(db, session, own)
    here = monitor_store.snapshot(db, session, clock=clock)
    assert here["coverage"] == [] and here["inventory"] == []
    assert {row["finding_id"] for row in here["deliveries"]} == set(findings) - set(moved)

    looking_at(db, session, other)
    there = monitor_store.snapshot(db, session, clock=clock)
    assert {row["connection_id"] for row in there["coverage"]} == {connection}
    assert {row["connection_id"] for row in there["inventory"]} == {connection}
    assert {row["finding_id"] for row in there["deliveries"]} == set(moved)


def test_mq10_gap_stories_come_first_beyond_the_page(db, admin_engine, world):
    tenant, clock = world["admin"].tenant_id, world["clock"]
    now = clock.now()
    connection = tines_connection(db, world)
    gaps = {"zz-gap-1": now - timedelta(hours=1), "zz-gap-2": now - timedelta(hours=3)}
    gaps["zz-gap-3"] = now - timedelta(hours=2)
    with admin_engine.begin() as conn:
        fenced(conn, tenant)
        for index in range(247):
            story(conn, tenant, connection, f"a{index:04d}", now, None)
        for external_id, opened in gaps.items():
            story(conn, tenant, connection, external_id, now, opened)
    session = session_for(db, world["admin"], clock)
    coverage = monitor_store.snapshot(db, session, clock=clock)["coverage"]
    assert len(coverage) == 200
    assert [row["external_id"] for row in coverage[:3]] == ["zz-gap-2", "zz-gap-3", "zz-gap-1"]


def story(conn, tenant, connection, external_id, now, gap):
    conn.execute(
        text(
            "INSERT INTO execbound.monitor_inventory (tenant_id, connection_id, item_kind, "
            "external_id, name, first_seen_at, last_seen_at, gap_opened_at) "
            "VALUES (:t, :c, 'story', :e, :n, :now, :now, :g)"
        ),
        {"t": tenant, "c": connection, "e": external_id, "n": external_id, "now": now, "g": gap},
    )


def test_mq10_an_observation_names_the_findings_it_raised(db, admin_engine, world):
    clock = world["clock"]
    seed_tines(db, world)
    session = session_for(db, world["admin"], clock)
    snapshot = monitor_store.snapshot(db, session, clock=clock)
    raised: dict = {}
    for row in snapshot["findings"]:
        if row["observation_id"] is not None:
            raised.setdefault(row["observation_id"], []).append(row["finding_id"])
    assert raised, "the seeded tenant raises findings on observations"
    for row in snapshot["observations"]:
        assert sorted(row["finding_ids"]) == sorted(raised.get(row["observation_id"], []))


# The note and the write-once rule (MQ13, MQ15): an acknowledgement may say why, the note is
# screened like every other piece of people's text, and a finished acknowledgement is final.


def note_of(admin_engine, tenant, finding):
    with admin_engine.begin() as conn:
        fenced(conn, tenant)
        return (
            conn.execute(
                text(
                    "SELECT acknowledged_at, acknowledged_by, acknowledgement_note "
                    "FROM execbound.monitor_findings WHERE tenant_id=:t AND finding_id=:f"
                ),
                {"t": tenant, "f": finding},
            )
            .mappings()
            .one()
        )


def events_for(admin_engine, tenant, finding):
    return [
        event
        for event in acknowledged_events(admin_engine, tenant)
        if event["payload"]["finding_id"] == str(finding)
    ]


def test_mq13_a_note_is_stored_with_the_acknowledgement_and_audited_once(
    db, admin_engine, world, spaces
):
    tenant, clock = spaces["tenant"], world["clock"]
    session = spaces["workspace"]
    noted, plain = spaces["elsewhere"], spaces["here"]
    monitor_store.acknowledge(
        db, session, noted, note="  Checked with the SOC lead.  ", clock=clock
    )
    assert note_of(admin_engine, tenant, noted)["acknowledgement_note"] == (
        "Checked with the SOC lead."
    )
    [event] = events_for(admin_engine, tenant, noted)
    assert set(event["payload"]) == {"finding_id", "rule_version", "note", "actor_credential_id"}
    assert event["payload"]["note"] == "Checked with the SOC lead."
    # Acknowledging again without a note is the idempotent answer it always was.
    monitor_store.acknowledge(db, session, noted, clock=clock)
    assert len(events_for(admin_engine, tenant, noted)) == 1

    # A note of only spaces is no note: stored as nothing, and the event has no `note` key.
    monitor_store.acknowledge(db, session, plain, note="   ", clock=clock)
    assert note_of(admin_engine, tenant, plain)["acknowledgement_note"] is None
    [event] = events_for(admin_engine, tenant, plain)
    assert set(event["payload"]) == {"finding_id", "rule_version", "actor_credential_id"}


@pytest.mark.parametrize(
    "value",
    [*FREE_TEXT, "a\x00b", "x" * 501],
    ids=[*FREE_TEXT_IDS, "control", "too-long"],
)
def test_mq13_a_note_shaped_like_a_secret_is_refused_and_never_quoted(
    db, admin_engine, world, spaces, value
):
    tenant, clock = spaces["tenant"], world["clock"]
    finding = spaces["here"]
    with pytest.raises(MonitorError) as refusal:
        monitor_store.acknowledge(db, spaces["workspace"], finding, note=value, clock=clock)
    assert refusal.value.code == "INVALID_NOTE"
    assert value not in repr(refusal.value) and value not in str(refusal.value)
    state = note_of(admin_engine, tenant, finding)
    assert state["acknowledged_at"] is None and state["acknowledgement_note"] is None
    assert acknowledged_events(admin_engine, tenant) == []


def test_mq13_a_note_on_an_acknowledged_finding_is_a_conflict_and_saves_nothing(
    db, admin_engine, world, spaces
):
    tenant, clock = spaces["tenant"], world["clock"]
    session, finding = spaces["workspace"], spaces["here"]
    monitor_store.acknowledge(db, session, finding, note="First look.", clock=clock)
    before = note_of(admin_engine, tenant, finding)
    with pytest.raises(MonitorError) as refusal:
        monitor_store.acknowledge(db, session, finding, note="A second opinion.", clock=clock)
    assert refusal.value.code == "ACKNOWLEDGED"
    assert note_of(admin_engine, tenant, finding) == before
    assert len(events_for(admin_engine, tenant, finding)) == 1


FINAL = "monitor finding acknowledgement is final"


def changes(other):
    """Each change a finished acknowledgement refuses. Clearing both columns together passes
    the table's `(acknowledged_at IS NULL) = (acknowledged_by IS NULL)` check, so only the
    trigger can refuse it."""
    return [
        ("acknowledged_by=:o", {"o": other}),
        ("acknowledgement_note='x'", {}),
        ("acknowledged_at=NULL, acknowledged_by=NULL", {}),
    ]


def test_mq15_the_database_refuses_to_change_a_finished_acknowledgement(
    db, admin_engine, world, spaces
):
    tenant, clock = spaces["tenant"], world["clock"]
    finding, open_finding = spaces["elsewhere"], spaces["here"]
    monitor_store.acknowledge(db, spaces["workspace"], finding, clock=clock)
    before = note_of(admin_engine, tenant, finding)
    other = spaces["narrowed"].identity.principal_id
    for assignment, values in changes(other):
        with pytest.raises(DBAPIError) as refusal:
            with db.transaction(tenant) as conn:
                conn.execute(
                    text(
                        "UPDATE execbound.monitor_findings SET "
                        + assignment
                        + " WHERE tenant_id=:t AND finding_id=:f"
                    ),
                    {"t": tenant, "f": finding, **values},
                )
        assert refusal.value.orig is not None
        assert getattr(refusal.value.orig, "sqlstate", None) == "23514"
        assert FINAL in str(refusal.value.orig)
    assert note_of(admin_engine, tenant, finding) == before

    # The refusal is the trigger's and nothing else's: with it dropped, inside a transaction
    # that is rolled back, each of the same changes goes through on its own.
    with admin_engine.connect() as conn:
        with conn.begin() as outer:
            fenced(conn, tenant)
            conn.execute(
                text(
                    "DROP TRIGGER monitor_findings_acknowledged_once ON execbound.monitor_findings"
                )
            )
            for assignment, values in changes(other):
                each = conn.begin_nested()
                updated = conn.execute(
                    text(
                        "UPDATE execbound.monitor_findings SET "
                        + assignment
                        + " WHERE tenant_id=:t AND finding_id=:f"
                    ),
                    {"t": tenant, "f": finding, **values},
                ).rowcount
                assert updated == 1
                each.rollback()
            outer.rollback()
    assert note_of(admin_engine, tenant, finding) == before

    # An open finding can still be acknowledged, and with a note.
    monitor_store.acknowledge(db, spaces["workspace"], open_finding, note="Seen.", clock=clock)
    assert note_of(admin_engine, tenant, open_finding)["acknowledgement_note"] == "Seen."


def test_mq13_the_assistant_finding_tool_carries_no_note(db, admin_engine, world, spaces, runtime):
    clock = world["clock"]
    session = spaces["workspace"]
    monitor_store.acknowledge(db, session, spaces["here"], note="Private reasoning.", clock=clock)
    result = run_tool(
        ToolContext(runtime=runtime, session=session), "list_findings", {"state": "all"}
    )
    assert result.data["findings"]
    for row in result.data["findings"]:
        assert "note" not in row and "acknowledgement_note" not in row
        # A real connection's finding, which the synthetic directory's label never marks.
        assert row["synthetic"] is False
    assert "Private reasoning." not in repr(result.data)


# Bulk acknowledgement (MQ14): one answer per finding, in request order, under the same space
# predicate, with the locks taken in one order so overlapping batches cannot deadlock.


def tines_connection_of(admin_engine, tenant):
    with admin_engine.begin() as conn:
        fenced(conn, tenant)
        return conn.execute(
            text(
                "SELECT connection_id FROM execbound.monitor_connections "
                "WHERE tenant_id=:t AND kind='tines'"
            ),
            {"t": tenant},
        ).scalar_one()


def open_findings(db, admin_engine, tenant, clock, count):
    connection = tines_connection_of(admin_engine, tenant)
    return [
        raise_finding(db, tenant, clock.now(), RUN, f"Bulk {index}", connection=connection)
        for index in range(count)
    ]


def test_mq14_bulk_acknowledgement_reports_each_finding(db, admin_engine, world, spaces):
    tenant, clock = spaces["tenant"], world["clock"]
    session = spaces["narrowed"]
    first, second = spaces["here"], *open_findings(db, admin_engine, tenant, clock, 1)
    [done] = open_findings(db, admin_engine, tenant, clock, 1)
    monitor_store.acknowledge(db, session, done, note="Seen earlier.", clock=clock)
    unknown = uuid4()
    ids = [first, second, done, spaces["elsewhere"], unknown]

    results = monitor_store.acknowledge_many(db, session, ids, note="Batch reviewed.", clock=clock)

    assert results == [
        (first, "acknowledged"),
        (second, "acknowledged"),
        (done, "already_acknowledged"),
        (spaces["elsewhere"], "unavailable"),
        (unknown, "unavailable"),
    ]
    for finding in (first, second):
        state = note_of(admin_engine, tenant, finding)
        assert state["acknowledgement_note"] == "Batch reviewed."
        assert state["acknowledged_by"] == session.identity.principal_id
        [event] = events_for(admin_engine, tenant, finding)
        assert event["payload"]["note"] == "Batch reviewed."
    assert note_of(admin_engine, tenant, done)["acknowledgement_note"] == "Seen earlier."
    assert len(events_for(admin_engine, tenant, done)) == 1
    assert note_of(admin_engine, tenant, spaces["elsewhere"])["acknowledged_at"] is None
    assert len(acknowledged_events(admin_engine, tenant)) == 3


@pytest.mark.parametrize("shape", ["duplicate", "too-many", "empty", "not-an-id"])
def test_mq14_a_malformed_batch_is_refused_before_any_write(db, admin_engine, world, spaces, shape):
    tenant, clock = spaces["tenant"], world["clock"]
    here = spaces["here"]
    ids = {
        "duplicate": [here, here],
        "too-many": [here, *(uuid4() for _ in range(50))],
        "empty": [],
        "not-an-id": [here, str(uuid4())],
    }[shape]
    with pytest.raises(MonitorError) as refusal:
        monitor_store.acknowledge_many(db, spaces["workspace"], ids, clock=clock)
    assert refusal.value.code == "INVALID_INPUT"
    assert note_of(admin_engine, tenant, here)["acknowledged_at"] is None
    assert acknowledged_events(admin_engine, tenant) == []


def test_mq14_a_bulk_note_is_screened_before_any_write(db, admin_engine, world, spaces):
    tenant, clock = spaces["tenant"], world["clock"]
    with pytest.raises(MonitorError) as refusal:
        monitor_store.acknowledge_many(
            db, spaces["workspace"], [spaces["here"]], note=FREE_TEXT[0], clock=clock
        )
    assert refusal.value.code == "INVALID_NOTE"
    assert FREE_TEXT[0] not in repr(refusal.value)
    assert acknowledged_events(admin_engine, tenant) == []


def test_mq14_concurrent_bulk_acknowledgements_acknowledge_each_finding_once(
    db, admin_engine, world, spaces
):
    """Two administrators acknowledge overlapping sets at the same moment, twenty times.

    Both batches lock the rows they see in `finding_id` order, so neither can hold one row the
    other is waiting for while waiting on a row the other holds. The race guards that order
    rather than proving it: an interleaving that would deadlock without it is likely across
    twenty rounds, not certain.
    """
    tenant, clock = spaces["tenant"], world["clock"]
    sessions = (spaces["workspace"], spaces["narrowed"])
    for _ in range(20):
        a, b, c, d = open_findings(db, admin_engine, tenant, clock, 4)
        batches = ([a, b, c], [c, b, d])
        barrier = Barrier(2)

        def run(index, batches=batches, barrier=barrier):
            barrier.wait(timeout=10)
            return monitor_store.acknowledge_many(db, sessions[index], batches[index], clock=clock)

        with ThreadPoolExecutor(max_workers=2) as pool:
            first, second = pool.map(run, range(2))
        outcomes: dict = {}
        for finding, outcome in [*first, *second]:
            outcomes.setdefault(finding, []).append(outcome)
        assert sorted(outcomes[a]) == ["acknowledged"]
        assert sorted(outcomes[d]) == ["acknowledged"]
        for shared in (b, c):
            assert sorted(outcomes[shared]) == ["acknowledged", "already_acknowledged"]
        for finding in (a, b, c, d):
            assert note_of(admin_engine, tenant, finding)["acknowledged_at"] is not None
            assert len(events_for(admin_engine, tenant, finding)) == 1
