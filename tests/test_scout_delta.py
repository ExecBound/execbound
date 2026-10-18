# SPDX-License-Identifier: AGPL-3.0-only
"""Delta collection, the baseline and the three new-actor rules (#355): SR15 to SR20.

Real PostgreSQL and the fake Graph. A full collection takes a `servicePrincipals/delta` link
before it reads and, on a connection's first complete collection, sets the baseline and opens
one inventory summary. A delta pass between full collections inserts what it has not seen,
marks what was removed gone, never moves the schedule and drops a link it cannot trust.
`new-actor.v1`, `first-consequential-action.v1` and `new-ai-consent.v1` each raise once per
actor, after the baseline only, and close when their condition ends.
"""

import json
from datetime import UTC, datetime, timedelta
from urllib.parse import parse_qsl, urlsplit
from uuid import uuid4

import httpx
import pytest
from sqlalchemy import text
from sqlalchemy.exc import IntegrityError, ProgrammingError
from test_monitor_collect_due import consented_connection, key_file
from test_monitoring_store import FixedClock
from test_scout_derived import governed_agent, observe
from test_scout_reach import bundle
from test_scout_run import (
    AGENT_ONE,
    DISABLE_ROLE,
    GRAPH_RESOURCE,
    agent,
    client,
    connect,
    detailed_scenario,
    principal,
)
from test_tines_collection import KEY as TINES_KEY

from execbound.execution.scheduled import ScheduledActor
from execbound.identity import authenticate
from execbound.monitoring import ai_publishers, collection, due, graph, store, worker
from execbound.monitoring.models import DetectionProfile, MonitorError
from execbound_harness import fake_graph
from execbound_harness.fake_graph import CLIENT, DIRECTORY, SECRET, serving, transport
from execbound_harness.fake_tines import BASE_URL as TINES_URL

pytestmark = pytest.mark.integration

CONSEQUENTIAL = ("identity.disable",)
PREFIX = "https://graph.microsoft.com/v1.0/servicePrincipals/delta?"
# Each leaves the pinned read in one way: another origin, another path, another scheme, another
# port, and a delta link that carries no delta token.
HOSTILE = (
    "https://graph.example.invalid/v1.0/servicePrincipals/delta?$deltatoken=token1",
    "https://graph.microsoft.com/v1.0/users/delta?$deltatoken=token1",
    "http://graph.microsoft.com/v1.0/servicePrincipals/delta?$deltatoken=token1",
    "https://graph.microsoft.com:8443/v1.0/servicePrincipals/delta?$deltatoken=token1",
    "https://graph.microsoft.com/v1.0/servicePrincipals/delta?$skiptoken=initial.0",
)
ANTHROPIC_SERVER = "07c030f6-5743-41b7-ba00-0a6e85f37c17"


@pytest.fixture
def clock():
    return FixedClock(datetime.now(UTC))


@pytest.fixture
def admins(db, admin_engine, seeded):
    """Both administrators, with credentials that outlive the hours and days these tests span."""
    with admin_engine.begin() as conn:
        conn.execute(text("UPDATE execbound.principals SET kind='ADMIN', space_id = NULL"))
        conn.execute(
            text("UPDATE execbound.credentials SET expires_at = now() + interval '30 days'")
        )
    return [authenticate(db, token) for token in seeded["tokens"]]


def profile(db, admin, clock, actions=CONSEQUENTIAL):
    return store.set_profile(
        db,
        admin,
        DetectionProfile(sensitive_actions=tuple(actions), restricted_targets=()),
        clock=clock,
    )


def reaching(index, **overrides):
    """A classic service principal and the one app role that lets it disable an account."""
    record = principal(index, **overrides)
    assignment = {
        "appRoleId": DISABLE_ROLE,
        "resourceId": GRAPH_RESOURCE,
        "principalId": record["id"],
    }
    return record, {record["id"]: [assignment]}


def findings(db, tenant, rule=None):
    with db.transaction(tenant) as conn:
        rows = (
            conn.execute(
                text(
                    "SELECT f.finding_id, f.rule_version, f.title, f.agent_id, f.connection_id, "
                    "f.observation_id, a.platform_ref, "
                    "EXISTS (SELECT 1 FROM execbound.monitor_deliveries d "
                    "        WHERE d.tenant_id = f.tenant_id AND d.finding_id = f.finding_id) "
                    "  AS delivered "
                    "FROM execbound.monitor_findings f "
                    "LEFT JOIN execbound.monitor_agents a "
                    "  ON a.tenant_id = f.tenant_id AND a.agent_id = f.agent_id "
                    "ORDER BY f.created_at, f.rule_version"
                )
            )
            .mappings()
            .all()
        )
    return [row for row in rows if rule is None or row["rule_version"] == rule]


def connection_row(db, tenant, connection_id):
    with db.transaction(tenant) as conn:
        return dict(
            conn.execute(
                text("SELECT * FROM execbound.monitor_connections WHERE connection_id = :c"),
                {"c": connection_id},
            )
            .mappings()
            .one()
        )


def agent_row(db, tenant, platform_ref):
    with db.transaction(tenant) as conn:
        return dict(
            conn.execute(
                text("SELECT * FROM execbound.monitor_agents WHERE platform_ref = :r"),
                {"r": platform_ref},
            )
            .mappings()
            .one()
        )


def full(db, admin, clock, connection_id, server):
    with client(server) as http:
        return graph.run(
            db, admin, connection_id=connection_id, client_secret=SECRET, client=http, clock=clock
        )


def delta(db, admin, clock, connection_id, server, **kwargs):
    with client(server) as http:
        return graph.run_delta(
            db,
            admin,
            connection_id=connection_id,
            client_secret=SECRET,
            client=http,
            clock=clock,
            **kwargs,
        )


def grants_and_paths(db, tenant, agent_id):
    """An agent's grants and the non-observation paths they establish: (all, still live)."""
    with db.transaction(tenant) as conn:
        grants = conn.execute(
            text(
                "SELECT count(*), count(*) FILTER (WHERE gone_at IS NULL) "
                "FROM execbound.monitor_agent_grants WHERE agent_id = :a"
            ),
            {"a": agent_id},
        ).one()
        paths = conn.execute(
            text(
                "SELECT count(*), count(*) FILTER (WHERE gone_at IS NULL) "
                "FROM execbound.monitor_agent_reach "
                "WHERE agent_id = :a AND path_kind <> 'observation'"
            ),
            {"a": agent_id},
        ).one()
    return {"grants": tuple(grants), "paths": tuple(paths)}


def delta_requests(server):
    return [query for path, query, _ in server.requests if path == graph.DELTA_PATH]


# SR15


def test_sr15_the_first_collection_is_the_baseline_and_opens_one_inventory_summary(
    db, admins, clock
):
    admin = admins[0]
    profile(db, admin, clock)
    connection_id = connect(db, admin, clock)
    unowned, assignments = reaching(9)
    consented = principal(10, appId=ANTHROPIC_SERVER)
    scenario = detailed_scenario(principals=[unowned, consented], app_role_assignments=assignments)
    with serving(scenario) as server:
        result = full(db, admin, clock, connection_id, server)
        assert result["outcome"] == "COMPLETE"
        assert result["delta"] == "taken"
        assert result["findings"]["inventory"] == 1
        # The link is taken before the read, with `latest` and the base type's own fields.
        requested = delta_requests(server)
        assert requested[0]["$deltatoken"] == "latest"
        selected = set(requested[0]["$select"].split(","))
        assert {"id", "appId", "appOwnerOrganizationId", "verifiedPublisher"} <= selected
        assert selected <= graph.AGENT_FIELDS
        assert not {"createdDateTime", "agentIdentityBlueprintId"} & selected
        # Before either principal collection is walked, the agent identities first among them:
        # the probe asks each for one record, and the walk is the first request after it.
        order = [(path, query.get("$top")) for path, query, _ in server.requests]
        walks = [
            order.index((path, str(graph.PAGE_SIZE)))
            for path in (graph.AGENTS_PATH, graph.PRINCIPALS_PATH)
        ]
        assert walks[0] < walks[1]
        assert order.index((graph.DELTA_PATH, None)) < min(walks)

        summary = findings(db, admin.tenant_id, "initial-inventory.v1")
        assert len(summary) == 1
        assert summary[0]["connection_id"] == connection_id
        assert summary[0]["agent_id"] is None and summary[0]["observation_id"] is None
        assert summary[0]["delivered"]
        # The agent identity and the unowned principal both reach `identity.disable` through a
        # path nothing governs; the unowned one has nobody accountable; one consent is to an
        # application from a catalogued AI publisher.
        assert summary[0]["title"] == (
            "Initial inventory: 3 actors, 2 with consequential reach, 2 with an ungoverned "
            "path, 1 with nobody accountable, 1 AI publisher consent"
        )
        # Everything is new on a first collection, so none of the three rules raises.
        for rule in ("new-actor.v1", "new-ai-consent.v1", "first-consequential-action.v1"):
            assert findings(db, admin.tenant_id, rule) == []
        # The episodes it opens are recorded and shown, and the summary is the one message:
        # connecting a directory does not deliver a finding per principal.
        reach = findings(db, admin.tenant_id, "ungoverned-reach.v1")
        sponsorless = findings(db, admin.tenant_id, "sponsorless-agent.v1")
        assert {row["platform_ref"] for row in reach} == {AGENT_ONE, unowned["id"]}
        assert [row["platform_ref"] for row in sponsorless] == [unowned["id"]]
        assert [
            row["rule_version"] for row in findings(db, admin.tenant_id) if row["delivered"]
        ] == ["initial-inventory.v1"]
        row = connection_row(db, admin.tenant_id, connection_id)
        assert row["baseline_at"] == clock.value
        assert row["delta_link"].startswith(PREFIX) and "%24deltatoken=" in row["delta_link"]
        assert row["delta_at"] == clock.value
        assert agent_row(db, admin.tenant_id, consented["id"])["ai_publisher"] == "anthropic"

        clock.value += timedelta(hours=7)
        again = full(db, admin, clock, connection_id, server)
    assert again["findings"]["inventory"] == 0
    assert len(findings(db, admin.tenant_id, "initial-inventory.v1")) == 1
    with db.transaction(admin.tenant_id) as conn:
        assert (
            conn.execute(text("SELECT count(*) FROM execbound.monitor_deliveries")).scalar_one()
            == 1
        )
    # The baseline is set once; a later collection only refreshes the link.
    later = connection_row(db, admin.tenant_id, connection_id)
    assert later["baseline_at"] == row["baseline_at"]
    assert later["delta_at"] == clock.value


def test_sr15_without_a_sensitive_list_the_summary_says_reach_was_not_assessed(db, admins, clock):
    admin = admins[0]
    connection_id = connect(db, admin, clock)
    with serving(detailed_scenario()) as server:
        full(db, admin, clock, connection_id, server)
    (summary,) = findings(db, admin.tenant_id, "initial-inventory.v1")
    assert "1 actor" in summary["title"] and "not assessed" in summary["title"]


def test_sr15_a_service_that_refuses_latest_gets_its_link_from_an_initial_round(db, admins, clock):
    admin = admins[0]
    connection_id = connect(db, admin, clock)
    scenario = detailed_scenario(
        principals=[principal(5), principal(6), principal(7)], delta_latest=False, delta_page=2
    )
    with serving(scenario) as server:
        result = full(db, admin, clock, connection_id, server)
        assert result["delta"] == "taken"
        # Latest refused, then an initial round of two pages, nothing it listed kept twice.
        assert [query.get("$deltatoken") for query in delta_requests(server)][:2] == [
            "latest",
            None,
        ]
    assert connection_row(db, admin.tenant_id, connection_id)["delta_link"].startswith(PREFIX)
    with db.transaction(admin.tenant_id) as conn:
        assert conn.execute(text("SELECT count(*) FROM execbound.monitor_agents")).scalar_one() == 4


def test_sr15_a_baseline_after_episodes_already_opened_still_sends_one_message(db, admins, clock):
    """The first complete collection is the baseline even when a failed run wrote its principals
    first, and the summary is still its only delivery."""
    admin = admins[0]
    profile(db, admin, clock)
    connection_id = connect(db, admin, clock)
    with serving(detailed_scenario(status={"assignments": 503})) as server:
        assert full(db, admin, clock, connection_id, server)["outcome"] == "ERROR"
        server.scenario.status = {}
        clock.value += timedelta(minutes=5)
        assert full(db, admin, clock, connection_id, server)["outcome"] == "COMPLETE"
    assert len(findings(db, admin.tenant_id, "ungoverned-reach.v1")) == 1
    assert [row["rule_version"] for row in findings(db, admin.tenant_id) if row["delivered"]] == [
        "initial-inventory.v1"
    ]


@pytest.mark.parametrize("page", [100, 1])
@pytest.mark.parametrize("collection", ["agents", "principals", "both"])
def test_sr15_a_directory_past_the_principal_bound_is_refused_whole(
    db, admins, clock, monkeypatch, collection, page
):
    """More principals than one collection reads is refused, never read in part: a principal
    beyond a silent cut would be stored for the first time by a later read and called new. That
    holds however short the pages Graph serves are."""
    admin = admins[0]
    profile(db, admin, clock)
    connection_id = connect(db, admin, clock)
    monkeypatch.setattr(graph, "MAX_AGENTS", 2)
    scenario = {
        "agents": detailed_scenario(agents=[agent(1), agent(2), agent(3)], max_top=page),
        "principals": detailed_scenario(
            principals=[principal(5), principal(6), principal(7)], max_top=page
        ),
        # Two in each collection, three once the two are put together.
        "both": detailed_scenario(
            agents=[agent(1), agent(2)], principals=[principal(5)], max_top=page
        ),
    }[collection]
    with serving(scenario) as server:
        result = full(db, admin, clock, connection_id, server)
    assert result["outcome"] == "ERROR"
    row = connection_row(db, admin.tenant_id, connection_id)
    assert (row["last_outcome"], row["last_error_code"]) == ("ERROR", "AGENT_CAPACITY")
    assert (row["baseline_at"], row["delta_link"], row["last_sync_at"]) == (None, None, None)
    with db.transaction(admin.tenant_id) as conn:
        assert conn.execute(text("SELECT count(*) FROM execbound.monitor_agents")).scalar_one() == 0
    assert findings(db, admin.tenant_id) == []


@pytest.mark.parametrize("collection", ["agents", "principals"])
@pytest.mark.parametrize(("listed", "refused"), [(3, True), (2, False)])
def test_sr15_a_directory_in_pages_too_short_to_read_whole_is_refused_rather_than_cut(
    db, admins, clock, monkeypatch, collection, listed, refused
):
    """A run's read is bounded in pages as well as principals, and the page bound assumes the
    hundred records a page it asks for. A directory under the principal bound that Graph serves
    in pages too short for the run to reach its end is refused whole too: the principals past
    its last page would be stored for the first time by a later read, or listed by a delta pass,
    and called new though they were there all along."""
    admin = admins[0]
    profile(db, admin, clock)
    connection_id = connect(db, admin, clock)
    # Five principals is the bound, so a collection is read in at most 6 // 100 + 2 = 2 pages,
    # and Graph serves one record a page.
    monkeypatch.setattr(graph, "MAX_AGENTS", 5)
    if collection == "agents":
        read = graph.AGENTS_PATH
        expected = [agent(index) for index in range(1, listed + 1)]
        scenario = detailed_scenario(agents=expected, max_top=1)
    else:
        read = graph.PRINCIPALS_PATH
        expected = [principal(index) for index in range(5, 5 + listed)]
        scenario = detailed_scenario(principals=expected, max_top=1)
        expected = [*expected, agent(1)]
    with serving(scenario) as server:
        result = full(db, admin, clock, connection_id, server)
        walked = [
            query for path, query, _ in server.requests if path == read and query != {"$top": "1"}
        ]
    # Two pages a collection either way: the run never asks for more than its bound. (The probe
    # asks for one record and no page after it; a continuation carries Graph's skip token.)
    assert len(walked) == 2
    row = connection_row(db, admin.tenant_id, connection_id)
    with db.transaction(admin.tenant_id) as conn:
        stored = set(
            conn.execute(text("SELECT platform_ref FROM execbound.monitor_agents")).scalars()
        )
    if refused:
        assert result["outcome"] == "ERROR"
        assert (row["last_outcome"], row["last_error_code"]) == ("ERROR", "AGENT_CAPACITY")
        assert (row["baseline_at"], row["delta_link"], row["last_sync_at"]) == (None, None, None)
        assert stored == set()
        assert findings(db, admin.tenant_id) == []
    else:
        # The control: a directory whose last page the run reaches is read whole.
        assert result["outcome"] == "COMPLETE"
        assert row["baseline_at"] == clock.value
        assert stored == {record["id"] for record in expected}


@pytest.mark.parametrize(("listed", "refused"), [(12, False), (13, True)])
def test_sr15_a_collection_is_read_in_at_most_twelve_pages(db, admins, clock, listed, refused):
    """The twelve pages the guide and the error codes state, at the real principal bound rather
    than a patched one: a collection Graph serves a record a page is read whole when its
    twelfth page is its last, and refused when the twelfth still offers more."""
    assert graph.MAX_AGENTS == 1000
    admin = admins[0]
    connection_id = connect(db, admin, clock)
    agents = [agent(index) for index in range(1, listed + 1)]
    with serving(detailed_scenario(agents=agents, max_top=1)) as server:
        result = full(db, admin, clock, connection_id, server)
        walked = [
            query
            for path, query, _ in server.requests
            if path == graph.AGENTS_PATH and query != {"$top": "1"}
        ]
    assert len(walked) == 12
    row = connection_row(db, admin.tenant_id, connection_id)
    if refused:
        assert result["outcome"] == "ERROR"
        assert (row["last_outcome"], row["last_error_code"]) == ("ERROR", "AGENT_CAPACITY")
    else:
        assert (result["outcome"], row["last_error_code"]) == ("COMPLETE", None)
        assert result["agents"]["agent_identities"] == listed


def test_sr15_a_failed_collection_takes_no_baseline_and_no_link(db, admins, clock):
    admin = admins[0]
    connection_id = connect(db, admin, clock)
    # The detail pass fails after the principals were written.
    with serving(detailed_scenario(status={"assignments": 503})) as server:
        result = full(db, admin, clock, connection_id, server)
    assert result["outcome"] == "ERROR"
    row = connection_row(db, admin.tenant_id, connection_id)
    assert (row["baseline_at"], row["delta_link"]) == (None, None)
    assert findings(db, admin.tenant_id, "initial-inventory.v1") == []


def delivered(db, tenant):
    return [row["rule_version"] for row in findings(db, tenant) if row["delivered"]]


def test_sr15_a_collection_that_could_not_read_the_service_principals_takes_no_baseline(
    db, admins, clock
):
    """Graph throttles the one-row probe of `/servicePrincipals`, so the collection completes
    having read only the agent identities. It is no baseline: the principals a later read
    stores for the first time were there before, and are never called new."""
    admin = admins[0]
    profile(db, admin, clock)
    connection_id = connect(db, admin, clock)
    present, assignments = reaching(9)
    consented = principal(10, appId=ANTHROPIC_SERVER)
    scenario = detailed_scenario(
        principals=[present, consented],
        app_role_assignments=assignments,
        status={"principals": 429},
    )
    with serving(scenario) as server:
        first = full(db, admin, clock, connection_id, server)
        assert first["outcome"] == "COMPLETE"
        assert first["capabilities"]["service_principals"] == "unknown"
        assert (first["delta"], first["findings"]["inventory"]) == ("unavailable", 0)
        row = connection_row(db, admin.tenant_id, connection_id)
        assert (row["baseline_at"], row["delta_link"]) == (None, None)
        # Still the connection's first collection: what it opens waits for the summary.
        assert delivered(db, admin.tenant_id) == []

        server.scenario.status = {}
        clock.value += timedelta(hours=7)
        second = full(db, admin, clock, connection_id, server)
    assert second["findings"]["inventory"] == 1
    assert (second["findings"]["new_actor"], second["findings"]["ai_consent"]) == (0, 0)
    for rule in ("new-actor.v1", "new-ai-consent.v1"):
        assert findings(db, admin.tenant_id, rule) == []
    # The collection that read both is the baseline, and its summary the one message.
    assert delivered(db, admin.tenant_id) == ["initial-inventory.v1"]
    (summary,) = findings(db, admin.tenant_id, "initial-inventory.v1")
    assert summary["title"].startswith("Initial inventory: 3 actors,")
    row = connection_row(db, admin.tenant_id, connection_id)
    assert row["baseline_at"] == clock.value and row["delta_link"].startswith(PREFIX)


@pytest.mark.parametrize(
    ("status", "state", "waits"),
    [(429, "unknown", True), (400, "unknown", True), (404, "unsupported", False)],
)
def test_sr15_a_collection_that_could_not_read_the_agent_identities_takes_no_link(
    db, admins, clock, status, state, waits
):
    """Graph answers the agent identity probe with something other than 200 or 403 while
    `/servicePrincipals` reads: the collection completes having read the classic principals
    alone. It takes no baseline and asks for no link, and it records its outcome like any
    collection, so the connection is not due again at once to read the whole directory."""
    admin = admins[0]
    profile(db, admin, clock)
    connection_id = connect(db, admin, clock)
    present, assignments = reaching(9)
    scenario = detailed_scenario(
        principals=[present], app_role_assignments=assignments, status={"agents": status}
    )
    with serving(scenario) as server:
        first = full(db, admin, clock, connection_id, server)
        assert first["outcome"] == "COMPLETE"
        assert first["capabilities"]["agent_identities"] == state
        assert first["capabilities"]["service_principals"] == "available"
        assert (first["delta"], first["findings"]["inventory"]) == ("unavailable", 0)
        # No link is asked for when none could be kept.
        assert delta_requests(server) == []
        row = connection_row(db, admin.tenant_id, connection_id)
        assert (row["baseline_at"], row["delta_link"], row["delta_at"]) == (None, None, None)
        assert (row["last_outcome"], row["last_run_at"], row["last_sync_at"]) == (
            "COMPLETE",
            clock.value,
            clock.value,
        )
        assert not due.is_due(row, clock.value)
        # Throttled, what it opens waits for the summary; refused outright, it is heard: the
        # unowned principal reaches `identity.disable` with nobody accountable.
        assert sorted(delivered(db, admin.tenant_id)) == (
            [] if waits else ["sponsorless-agent.v1", "ungoverned-reach.v1"]
        )

        server.scenario.status = {}
        clock.value += timedelta(hours=7)
        second = full(db, admin, clock, connection_id, server)
    assert (second["delta"], second["findings"]["inventory"]) == ("taken", 1)
    assert findings(db, admin.tenant_id, "new-actor.v1") == []
    row = connection_row(db, admin.tenant_id, connection_id)
    assert row["baseline_at"] == clock.value and row["delta_link"].startswith(PREFIX)


def test_sr15_a_later_collection_keeps_the_link_it_had_unless_it_takes_one_whole(db, admins, clock):
    """On a connection with a baseline and a link, a full collection that fails after taking a
    fresh link, one Graph gives no link it can trust and one that could not read both principal
    collections each leave the stored link and its moment as they were; only a collection
    that completes having read both replaces it."""
    admin = admins[0]
    connection_id = connect(db, admin, clock)
    with serving(detailed_scenario()) as server:
        assert full(db, admin, clock, connection_id, server)["delta"] == "taken"
        kept = connection_row(db, admin.tenant_id, connection_id)
        assert kept["delta_link"].startswith(PREFIX) and kept["delta_at"] == clock.value

        def unchanged():
            row = connection_row(db, admin.tenant_id, connection_id)
            return (row["delta_link"], row["delta_at"]) == (kept["delta_link"], kept["delta_at"])

        # Fails after it took a fresh link: the fresh one is not kept.
        server.scenario.status = {"assignments": 503}
        server.requests.clear()
        clock.value += timedelta(hours=7)
        assert full(db, admin, clock, connection_id, server)["outcome"] == "ERROR"
        assert [query.get("$deltatoken") for query in delta_requests(server)] == ["latest"]
        assert unchanged()

        # Completes, but Graph's link leaves the pinned read: the stored one is not dropped.
        server.scenario.status = {}
        server.scenario.delta_link = HOSTILE[0]
        clock.value += timedelta(hours=7)
        result = full(db, admin, clock, connection_id, server)
        assert (result["outcome"], result["delta"]) == ("COMPLETE", "unavailable")
        assert unchanged()

        # Completes without reading the agent identities: it asks for no link at all.
        server.scenario.delta_link = None
        server.scenario.status = {"agents": 429}
        server.requests.clear()
        clock.value += timedelta(hours=7)
        result = full(db, admin, clock, connection_id, server)
        assert (result["outcome"], result["delta"]) == ("COMPLETE", "unavailable")
        assert delta_requests(server) == []
        assert unchanged()

        # Completes having read both: the link it took replaces the stored one.
        server.scenario.status = {}
        clock.value += timedelta(hours=7)
        assert full(db, admin, clock, connection_id, server)["delta"] == "taken"
    row = connection_row(db, admin.tenant_id, connection_id)
    assert row["delta_at"] == clock.value and row["delta_link"] != kept["delta_link"]


def test_sr15_a_registration_refused_the_service_principals_takes_no_baseline_and_stays_heard(
    db, admins, clock
):
    """A registration refused `/servicePrincipals` outright cannot take a baseline until it is
    granted the permission, and a connection that cannot take one sends no summary, so what its
    collections open is delivered one by one rather than never. Once the permission is
    granted, that collection is the baseline, and the principals it reads are not new."""
    admin = admins[0]
    profile(db, admin, clock)
    connection_id = connect(db, admin, clock)
    present, assignments = reaching(9)
    scenario = detailed_scenario(
        principals=[present], app_role_assignments=assignments, status={"principals": 403}
    )
    with serving(scenario) as server:
        first = full(db, admin, clock, connection_id, server)
        assert first["outcome"] == "COMPLETE"
        assert first["capabilities"]["service_principals"] == "forbidden"
        assert connection_row(db, admin.tenant_id, connection_id)["baseline_at"] is None
        assert findings(db, admin.tenant_id, "initial-inventory.v1") == []
        assert delivered(db, admin.tenant_id) == ["ungoverned-reach.v1"]

        server.scenario.status = {}
        clock.value += timedelta(hours=7)
        second = full(db, admin, clock, connection_id, server)
    assert second["findings"]["inventory"] == 1 and second["findings"]["new_actor"] == 0
    assert findings(db, admin.tenant_id, "new-actor.v1") == []
    # The principal it could not read before is part of the baseline: its episodes are counted
    # by the summary, not delivered one by one.
    assert delivered(db, admin.tenant_id) == ["ungoverned-reach.v1", "initial-inventory.v1"]
    assert connection_row(db, admin.tenant_id, connection_id)["baseline_at"] == clock.value


def delivered_for(db, tenant, platform_ref):
    return sorted(
        row["rule_version"]
        for row in findings(db, tenant)
        if row["delivered"] and row["platform_ref"] == platform_ref
    )


def test_sr15_what_waits_for_the_summary_waits_through_the_first_collection_alone(
    db, admins, clock
):
    """Graph answers the agent identity probe with a 400 on every collection, so none reads both
    principal collections and none can take the baseline or send its summary. What the first
    opens waits for the summary the next is expected to send; when the next cannot send it
    either, what waited is delivered, and what any later collection opens is delivered one by
    one. A connection that never reads both is never silent about what it finds."""
    admin = admins[0]
    profile(db, admin, clock)
    connection_id = connect(db, admin, clock)
    present, assignments = reaching(9)
    scenario = detailed_scenario(
        principals=[present], app_role_assignments=assignments, status={"agents": 400}
    )
    with serving(scenario) as server:
        first = full(db, admin, clock, connection_id, server)
        assert first["outcome"] == "COMPLETE"
        assert first["capabilities"]["agent_identities"] == "unknown"
        assert findings(db, admin.tenant_id, "ungoverned-reach.v1") != []
        assert delivered(db, admin.tenant_id) == []

        clock.value += timedelta(hours=7)
        second = full(db, admin, clock, connection_id, server)
        assert (second["outcome"], second["findings"]["inventory"]) == ("COMPLETE", 0)
        # No summary is coming: what waited for one is delivered now, once each.
        assert delivered_for(db, admin.tenant_id, present["id"]) == [
            "sponsorless-agent.v1",
            "ungoverned-reach.v1",
        ]

        # A principal that gains an ungoverned path later is heard at the collection that
        # reads it, and nothing delivered before is delivered again.
        later, more = reaching(11)
        server.scenario.principals = [present, later]
        server.scenario.app_role_assignments = {**assignments, **more}
        clock.value += timedelta(hours=7)
        third = full(db, admin, clock, connection_id, server)
        assert third["outcome"] == "COMPLETE"
    assert delivered_for(db, admin.tenant_id, later["id"]) == [
        "sponsorless-agent.v1",
        "ungoverned-reach.v1",
    ]
    assert delivered_for(db, admin.tenant_id, present["id"]) == [
        "sponsorless-agent.v1",
        "ungoverned-reach.v1",
    ]
    with db.transaction(admin.tenant_id) as conn:
        assert (
            conn.execute(
                text(
                    "SELECT count(*) FROM execbound.monitor_findings f "
                    "WHERE NOT EXISTS (SELECT 1 FROM execbound.monitor_deliveries d "
                    "WHERE d.tenant_id = f.tenant_id AND d.finding_id = f.finding_id)"
                )
            ).scalar_one()
            == 0
        )
    row = connection_row(db, admin.tenant_id, connection_id)
    assert (row["baseline_at"], row["delta_link"]) == (None, None)
    assert findings(db, admin.tenant_id, "initial-inventory.v1") == []
    assert findings(db, admin.tenant_id, "new-actor.v1") == []


def test_sr15_what_waited_and_closed_before_the_summary_is_delivered_with_it(db, admins, clock):
    """An episode the first collection opened while it waited for the summary, and that closed
    before the collection that sends it, is not among what the summary counts. It is delivered
    then rather than never: what waits is either counted by the summary or delivered."""
    admin = admins[0]
    profile(db, admin, clock)
    connection_id = connect(db, admin, clock)
    present, assignments = reaching(9)
    stays, kept = reaching(10)
    scenario = detailed_scenario(
        principals=[present, stays],
        app_role_assignments={**assignments, **kept},
        status={"agents": 429},
    )
    with serving(scenario) as server:
        full(db, admin, clock, connection_id, server)
        assert len(findings(db, admin.tenant_id, "ungoverned-reach.v1")) == 2
        assert delivered(db, admin.tenant_id) == []
        # The grant goes, and the next collection reads both.
        server.scenario.status = {}
        server.scenario.app_role_assignments = kept
        clock.value += timedelta(hours=7)
        second = full(db, admin, clock, connection_id, server)
    assert second["findings"]["inventory"] == 1
    assert delivered_for(db, admin.tenant_id, present["id"]) == [
        "sponsorless-agent.v1",
        "ungoverned-reach.v1",
    ]
    # What still holds is the summary's, as before: it counts the path that stayed.
    assert delivered_for(db, admin.tenant_id, stays["id"]) == []
    (summary,) = findings(db, admin.tenant_id, "initial-inventory.v1")
    assert summary["delivered"]
    assert "2 with an ungoverned path, 1 with nobody accountable" in summary["title"]
    assert findings(db, admin.tenant_id, "new-actor.v1") == []


# SR16


def test_sr16_a_new_principal_with_reach_raises_new_actor_on_the_next_delta_pass(db, admins, clock):
    admin = admins[0]
    profile(db, admin, clock)
    connection_id = connect(db, admin, clock)
    with serving(detailed_scenario()) as server:
        full(db, admin, clock, connection_id, server)
        before = connection_row(db, admin.tenant_id, connection_id)
        newcomer, assignments = reaching(9)
        quiet = principal(10)
        server.scenario.app_role_assignments = {
            **server.scenario.app_role_assignments,
            **assignments,
        }
        server.scenario.delta = [newcomer, quiet]
        server.requests.clear()
        clock.value += timedelta(minutes=5)
        result = delta(db, admin, clock, connection_id, server)
        assert result["outcome"] == "COMPLETE"
        assert result["changes"] == {"listed": 2, "new": 2, "restored": 0, "gone": 0}
        assert result["link"] == "advanced"
        assert result["findings"]["new_actor"] == 1
        raised = findings(db, admin.tenant_id, "new-actor.v1")
        assert len(raised) == 1
        assert raised[0]["platform_ref"] == newcomer["id"] and raised[0]["delivered"]
        assert "service principal" in raised[0]["title"]
        # Its reach episode opens beside it, and `new-actor.v1` is the one message for both.
        (reach,) = [
            row
            for row in findings(db, admin.tenant_id, "ungoverned-reach.v1")
            if row["platform_ref"] == newcomer["id"]
        ]
        assert not reach["delivered"]
        # The pass read the newcomers' grants and nothing else of the directory's.
        assert graph.PRINCIPALS_PATH not in server.paths()
        assert f"{graph.PRINCIPALS_PATH}/{newcomer['id']}/appRoleAssignments" in server.paths()

        # A delta pass never moves the schedule or claims a sync.
        after = connection_row(db, admin.tenant_id, connection_id)
        for column in ("last_run_at", "last_sync_at", "last_outcome", "health_state"):
            assert after[column] == before[column], column
        assert due.due_at(after, clock.value) == due.due_at(before, clock.value)
        assert after["delta_at"] == clock.value and after["delta_link"] != before["delta_link"]
        assert agent_row(db, admin.tenant_id, newcomer["id"])["first_seen_at"] == clock.value

        # Nothing new: no second finding, from a delta pass or a full collection.
        clock.value += timedelta(minutes=5)
        assert delta(db, admin, clock, connection_id, server)["changes"]["listed"] == 0
        server.scenario.principals = [newcomer, quiet]
        clock.value += timedelta(hours=7)
        full(db, admin, clock, connection_id, server)
    assert len(findings(db, admin.tenant_id, "new-actor.v1")) == 1


def test_sr16_the_full_collection_raises_new_actor_and_its_episode_closes_once(db, admins, clock):
    admin = admins[0]
    profile(db, admin, clock)
    connection_id = connect(db, admin, clock)
    with serving(detailed_scenario()) as server:
        full(db, admin, clock, connection_id, server)
        newcomer, assignments = reaching(9)
        server.scenario.principals = [newcomer]
        server.scenario.app_role_assignments = {
            **server.scenario.app_role_assignments,
            **assignments,
        }
        clock.value += timedelta(hours=7)
        assert full(db, admin, clock, connection_id, server)["findings"]["new_actor"] == 1
        assert agent_row(db, admin.tenant_id, newcomer["id"])["new_actor_opened_at"] is not None

        # The grant goes: the episode closes, and the finding stays for a person to read.
        server.scenario.app_role_assignments = {
            key: value
            for key, value in server.scenario.app_role_assignments.items()
            if key != newcomer["id"]
        }
        clock.value += timedelta(hours=7)
        full(db, admin, clock, connection_id, server)
        assert agent_row(db, admin.tenant_id, newcomer["id"])["new_actor_opened_at"] is None

        # It comes back: that is a recurrence, which `ungoverned-reach.v1` reports, not news.
        server.scenario.app_role_assignments.update(assignments)
        clock.value += timedelta(hours=7)
        result = full(db, admin, clock, connection_id, server)
    assert (result["findings"]["new_actor"], result["findings"]["ungoverned"]) == (0, 1)
    assert len(findings(db, admin.tenant_id, "new-actor.v1")) == 1
    assert agent_row(db, admin.tenant_id, newcomer["id"])["new_actor_opened_at"] is None
    # The newcomer's own reach episodes: the first, whose message was `new-actor.v1`, and the
    # recurrence, a second episode of its own, reported and delivered as any recurrence is.
    episodes = [
        row["delivered"]
        for row in findings(db, admin.tenant_id, "ungoverned-reach.v1")
        if row["platform_ref"] == newcomer["id"]
    ]
    assert episodes == [False, True]


@pytest.mark.parametrize(
    ("after", "new"),
    [(timedelta(days=7) - timedelta(hours=1), True), (timedelta(days=7, hours=1), False)],
)
def test_sr16_an_actor_that_gains_reach_after_its_first_week_is_not_new(
    db, admins, clock, after, new
):
    """An actor is new for its first seven days: one that gains reach on its last day still
    raises `new-actor.v1`, and one that gains it after its first week is reported by
    `ungoverned-reach.v1` alone. The days are the documented ones, not the constant's."""
    admin = admins[0]
    profile(db, admin, clock)
    connection_id = connect(db, admin, clock)
    with serving(detailed_scenario()) as server:
        full(db, admin, clock, connection_id, server)
        newcomer, assignments = reaching(9)
        server.scenario.delta = [newcomer]
        clock.value += timedelta(minutes=5)
        assert delta(db, admin, clock, connection_id, server)["findings"]["new_actor"] == 0
        server.scenario.principals = [newcomer]
        server.scenario.app_role_assignments = {
            **server.scenario.app_role_assignments,
            **assignments,
        }
        clock.value += after
        result = full(db, admin, clock, connection_id, server)
    assert result["findings"]["new_actor"] == int(new)
    assert [row["platform_ref"] for row in findings(db, admin.tenant_id, "new-actor.v1")] == (
        [newcomer["id"]] if new else []
    )
    # Its ungoverned reach is reported by the rule for that, and delivered unless
    # `new-actor.v1` is the one message for it.
    (reach,) = [
        row
        for row in findings(db, admin.tenant_id, "ungoverned-reach.v1")
        if row["platform_ref"] == newcomer["id"]
    ]
    assert reach["delivered"] is not new


def test_sr16_new_agent_is_no_longer_raised(db, admins, clock):
    admin = admins[0]
    profile(db, admin, clock)
    connection_id = connect(db, admin, clock)
    with serving(detailed_scenario()) as server:
        full(db, admin, clock, connection_id, server)
        server.scenario.agents = [*server.scenario.agents, agent(2)]
        server.scenario.delta = [principal(11)]
        clock.value += timedelta(minutes=5)
        delta(db, admin, clock, connection_id, server)
        clock.value += timedelta(hours=7)
        full(db, admin, clock, connection_id, server)
    assert findings(db, admin.tenant_id, "new-agent.v1") == []


# SR17


def test_sr17_a_removed_principal_is_marked_gone_and_its_episodes_close(db, admins, clock):
    admin = admins[0]
    profile(db, admin, clock)
    connection_id = connect(db, admin, clock)
    with serving(detailed_scenario()) as server:
        full(db, admin, clock, connection_id, server)
        newcomer, assignments = reaching(9, appId=ANTHROPIC_SERVER)
        server.scenario.app_role_assignments = {
            **server.scenario.app_role_assignments,
            **assignments,
        }
        server.scenario.delta = [newcomer]
        clock.value += timedelta(minutes=5)
        delta(db, admin, clock, connection_id, server)
        opened = agent_row(db, admin.tenant_id, newcomer["id"])
        assert opened["new_actor_opened_at"] is not None
        assert opened["ai_consent_opened_at"] is not None
        held = grants_and_paths(db, admin.tenant_id, opened["agent_id"])
        assert all(total > 0 and live == total for total, live in held.values())
        others = grants_and_paths(
            db, admin.tenant_id, agent_row(db, admin.tenant_id, AGENT_ONE)["agent_id"]
        )

        server.scenario.delta = [{"id": newcomer["id"], "@removed": {"reason": "deleted"}}]
        clock.value += timedelta(minutes=5)
        result = delta(db, admin, clock, connection_id, server)
    assert result["changes"] == {"listed": 0, "new": 0, "restored": 0, "gone": 1}
    gone = agent_row(db, admin.tenant_id, newcomer["id"])
    assert gone["gone_at"] == clock.value
    assert (gone["new_actor_opened_at"], gone["ai_consent_opened_at"]) == (None, None)
    # Its grants and the paths they established stop being live claims, and are kept.
    assert grants_and_paths(db, admin.tenant_id, gone["agent_id"]) == {
        kind: (total, 0) for kind, (total, _) in held.items()
    }
    # Another principal's are untouched.
    assert (
        grants_and_paths(db, admin.tenant_id, agent_row(db, admin.tenant_id, AGENT_ONE)["agent_id"])
        == others
    )
    # Kept, never deleted: that it was here is evidence.
    assert len(findings(db, admin.tenant_id, "new-actor.v1")) == 1


def test_sr17_a_restored_principal_comes_back_without_being_new(db, admins, clock):
    admin = admins[0]
    profile(db, admin, clock)
    connection_id = connect(db, admin, clock)
    with serving(detailed_scenario()) as server:
        full(db, admin, clock, connection_id, server)
        server.scenario.delta = [{"id": AGENT_ONE, "@removed": {"reason": "changed"}}]
        clock.value += timedelta(minutes=5)
        delta(db, admin, clock, connection_id, server)
        assert agent_row(db, admin.tenant_id, AGENT_ONE)["gone_at"] is not None
        # Restored from deleted items: Graph lists it as a new instance, with only some fields.
        server.scenario.delta = [{"id": AGENT_ONE, "displayName": "Renamed"}]
        clock.value += timedelta(minutes=5)
        result = delta(db, admin, clock, connection_id, server)
    assert result["changes"] == {"listed": 1, "new": 0, "restored": 1, "gone": 0}
    row = agent_row(db, admin.tenant_id, AGENT_ONE)
    assert row["gone_at"] is None
    # The class, the blueprint and the name are the store's; a partial entry rewrites none.
    assert (row["identity_class"], row["display_name"]) == ("agent_identity", "Synthetic agent 1")
    assert row["blueprint_ref"] is not None and row["sponsor_state"] == "present"
    assert findings(db, admin.tenant_id, "new-actor.v1") == []


SPONSOR = {"@odata.type": "#microsoft.graph.user", "id": "cccccccc-0000-4000-8000-000000000009"}


def test_sr17_a_principal_whose_entry_states_no_class_waits_for_the_full_collection(
    db, admins, clock
):
    """A delta entry for a principal the store does not hold, carrying neither `@odata.type`
    nor `servicePrincipalType`, does not say whether it is an agent identity. It is left for the
    full collection, whose cast collection says so, rather than stored as a classic principal
    for good, read for owners instead of sponsors, and refused by the blueprint check on every
    full collection after."""
    admin = admins[0]
    profile(db, admin, clock)
    connection_id = connect(db, admin, clock)
    newcomer = agent(2)
    with serving(detailed_scenario()) as server:
        full(db, admin, clock, connection_id, server)
        server.scenario.sponsors = {**server.scenario.sponsors, newcomer["id"]: [SPONSOR]}
        server.scenario.delta = [{"id": newcomer["id"], "displayName": "Synthetic agent 2"}]
        server.requests.clear()
        clock.value += timedelta(minutes=5)
        result = delta(db, admin, clock, connection_id, server)
        assert (result["outcome"], result["link"], result["deferred"]) == (
            "COMPLETE",
            "advanced",
            1,
        )
        assert result["changes"] == {"listed": 0, "new": 0, "restored": 0, "gone": 0}
        # Nothing was read for it under a class it might not have.
        assert not [path for path in server.paths() if newcomer["id"] in path]
        with db.transaction(admin.tenant_id) as conn:
            assert (
                conn.execute(text("SELECT count(*) FROM execbound.monitor_agents")).scalar_one()
                == 1
            )

        server.scenario.agents = [*server.scenario.agents, newcomer]
        clock.value += timedelta(hours=7)
        assert full(db, admin, clock, connection_id, server)["outcome"] == "COMPLETE"
        # And the collections after it complete too.
        clock.value += timedelta(hours=7)
        assert full(db, admin, clock, connection_id, server)["outcome"] == "COMPLETE"
    row = agent_row(db, admin.tenant_id, newcomer["id"])
    assert (row["identity_class"], row["blueprint_ref"]) == (
        "agent_identity",
        newcomer["agentIdentityBlueprintId"],
    )
    assert (row["sponsor_state"], row["sponsors"]) == (
        "present",
        [{"kind": "user", "ref": SPONSOR["id"]}],
    )


def test_sr17_a_principal_whose_entry_states_its_class_is_stored_with_it(db, admins, clock):
    """An agent identity's delta entry that says so is stored as one and read for its sponsors.
    Graph may list a principal twice in one round, the second time with only what changed: the
    class the first entry stated still holds."""
    admin = admins[0]
    profile(db, admin, clock)
    connection_id = connect(db, admin, clock)
    # As `servicePrincipals/delta` would list one: the base type's fields, the discriminator set.
    stated = {**principal(2), "servicePrincipalType": "ServiceIdentity"}
    twice = {**principal(3), "servicePrincipalType": "ServiceIdentity"}
    with serving(detailed_scenario()) as server:
        full(db, admin, clock, connection_id, server)
        server.scenario.sponsors = {
            **server.scenario.sponsors,
            stated["id"]: [SPONSOR],
            twice["id"]: [SPONSOR],
        }
        server.scenario.delta = [
            stated,
            twice,
            {"id": twice["id"], "displayName": "Renamed"},
        ]
        clock.value += timedelta(minutes=5)
        result = delta(db, admin, clock, connection_id, server)
    assert (result["changes"]["new"], result["deferred"]) == (2, 0)
    for ref in (stated["id"], twice["id"]):
        row = agent_row(db, admin.tenant_id, ref)
        assert row["identity_class"] == "agent_identity", ref
        assert row["sponsor_state"] == "present", ref


VENDOR = "dddddddd-0000-4000-8000-000000000017"


def test_sr17_a_principal_listed_again_keeps_what_its_earlier_entry_said(db, admins, clock):
    """Graph may list a principal twice in one round, the second time with only what changed.
    The later entry is laid over the earlier one, so a property it leaves out is not a cleared
    one: a consented vendor application stays another organization's and its publisher's, and
    is never taken for one of this directory's own with nobody accountable for it. A principal
    removed and restored within the round, the restored entry carrying only some properties, is
    still what its first entry said it was."""
    admin = admins[0]
    profile(db, admin, clock)
    connection_id = connect(db, admin, clock)
    consented, assignments = reaching(17, appId=ANTHROPIC_SERVER, appOwnerOrganizationId=VENDOR)
    restored = principal(18, appOwnerOrganizationId=VENDOR)
    with serving(detailed_scenario()) as server:
        full(db, admin, clock, connection_id, server)
        server.scenario.app_role_assignments = {
            **server.scenario.app_role_assignments,
            **assignments,
        }
        server.scenario.delta = [
            consented,
            restored,
            {"id": consented["id"], "tags": ["changed"]},
            {"id": restored["id"], "@removed": {"reason": "changed"}},
            {"id": restored["id"], "displayName": "Restored"},
        ]
        clock.value += timedelta(minutes=5)
        result = delta(db, admin, clock, connection_id, server)
    assert (result["changes"]["new"], result["changes"]["gone"], result["deferred"]) == (2, 0, 0)
    back = agent_row(db, admin.tenant_id, restored["id"])
    assert (back["identity_class"], back["owner_org_ref"], back["display_name"]) == (
        "service_principal",
        VENDOR,
        "Restored",
    )
    assert back["gone_at"] is None
    row = agent_row(db, admin.tenant_id, consented["id"])
    assert {
        column: row[column]
        for column in (
            "identity_class",
            "display_name",
            "enabled",
            "owner_org_ref",
            "ai_publisher",
            "tags",
        )
    } == {
        "identity_class": "service_principal",
        "display_name": consented["displayName"],
        "enabled": True,
        "owner_org_ref": VENDOR,
        "ai_publisher": "anthropic",
        "tags": ["changed"],
    }
    assert [row["platform_ref"] for row in findings(db, admin.tenant_id, "new-ai-consent.v1")] == [
        consented["id"]
    ]
    assert [row["platform_ref"] for row in findings(db, admin.tenant_id, "new-actor.v1")] == [
        consented["id"]
    ]
    assert findings(db, admin.tenant_id, "sponsorless-agent.v1") == []


def test_sr17_a_directory_that_contradicts_a_stored_class_never_stops_the_collection(
    db, admins, clock
):
    """Should the cast collection ever call an agent identity a principal whose delta entry said
    it was a classic one, the full collection keeps the class the store holds, as a delta pass
    does, and completes, rather than failing the blueprint check on every collection after."""
    admin = admins[0]
    profile(db, admin, clock)
    connection_id = connect(db, admin, clock)
    contradicted = agent(2)
    with serving(detailed_scenario()) as server:
        full(db, admin, clock, connection_id, server)
        server.scenario.delta = [principal(2)]
        clock.value += timedelta(minutes=5)
        assert delta(db, admin, clock, connection_id, server)["changes"]["new"] == 1
        server.scenario.agents = [*server.scenario.agents, contradicted]
        clock.value += timedelta(hours=7)
        result = full(db, admin, clock, connection_id, server)
    assert result["outcome"] == "COMPLETE"
    row = agent_row(db, admin.tenant_id, contradicted["id"])
    assert (row["identity_class"], row["blueprint_ref"]) == ("service_principal", None)
    assert row["gone_at"] is None


def test_sr17_a_delta_pass_leaves_the_grants_of_principals_it_did_not_list(db, admins, clock):
    admin = admins[0]
    profile(db, admin, clock)
    connection_id = connect(db, admin, clock)
    with serving(detailed_scenario()) as server:
        full(db, admin, clock, connection_id, server)
        with db.transaction(admin.tenant_id) as conn:
            live = conn.execute(
                text("SELECT count(*) FROM execbound.monitor_agent_reach WHERE gone_at IS NULL")
            ).scalar_one()
        server.scenario.delta = [principal(12)]
        clock.value += timedelta(minutes=5)
        result = delta(db, admin, clock, connection_id, server)
    assert result["detail"]["reach_gone"] == 0 and result["detail"]["gone"] == 0
    with db.transaction(admin.tenant_id) as conn:
        assert (
            conn.execute(
                text("SELECT count(*) FROM execbound.monitor_agent_reach WHERE gone_at IS NULL")
            ).scalar_one()
            == live
        )


# SR18


@pytest.mark.parametrize("hostile", HOSTILE)
def test_sr18_a_delta_link_off_the_pinned_read_is_never_taken(db, admins, clock, hostile):
    admin = admins[0]
    connection_id = connect(db, admin, clock)
    with serving(detailed_scenario(delta_link=hostile)) as server:
        result = full(db, admin, clock, connection_id, server)
        assert result["outcome"] == "COMPLETE"
        assert result["delta"] == "unavailable"
    assert connection_row(db, admin.tenant_id, connection_id)["delta_link"] is None


@pytest.mark.parametrize("hostile", HOSTILE[:4])
def test_sr18_a_next_link_off_the_pinned_read_drops_the_link(db, admins, clock, hostile):
    admin = admins[0]
    connection_id = connect(db, admin, clock)
    with serving(detailed_scenario()) as server:
        full(db, admin, clock, connection_id, server)
        server.scenario.delta = [principal(13), principal(14)]
        server.scenario.delta_page = 1
        server.scenario.delta_next_link = hostile
        server.requests.clear()
        clock.value += timedelta(minutes=5)
        result = delta(db, admin, clock, connection_id, server)
        # The stored link's page, and nothing after the refused continuation.
        assert len(delta_requests(server)) == 1
    assert (result["outcome"], result["error_code"], result["link"]) == (
        "RESYNC",
        "MALFORMED",
        "dropped",
    )
    row = connection_row(db, admin.tenant_id, connection_id)
    assert row["delta_link"] is None
    assert (row["health_state"], row["last_outcome"]) == ("COLLECTING", "COMPLETE")
    # Nothing a refused round listed was kept.
    with db.transaction(admin.tenant_id) as conn:
        assert conn.execute(text("SELECT count(*) FROM execbound.monitor_agents")).scalar_one() == 1


@pytest.mark.parametrize("hostile", HOSTILE)
def test_sr18_a_delta_pass_refuses_a_response_link_off_the_pinned_read(db, admins, clock, hostile):
    admin = admins[0]
    connection_id = connect(db, admin, clock)
    with serving(detailed_scenario()) as server:
        full(db, admin, clock, connection_id, server)
        server.scenario.delta_link = hostile
        clock.value += timedelta(minutes=5)
        result = delta(db, admin, clock, connection_id, server)
    assert (result["outcome"], result["error_code"], result["link"]) == (
        "RESYNC",
        "MALFORMED",
        "dropped",
    )
    assert connection_row(db, admin.tenant_id, connection_id)["delta_link"] is None


@pytest.mark.parametrize("hostile", HOSTILE[:4])
def test_sr18_the_database_refuses_a_stored_link_off_the_pinned_read(
    db, admins, admin_engine, clock, hostile
):
    admin = admins[0]
    connection_id = connect(db, admin, clock)
    with serving(detailed_scenario()) as server:
        full(db, admin, clock, connection_id, server)
    with pytest.raises(IntegrityError), admin_engine.begin() as conn:
        conn.execute(
            text("UPDATE execbound.monitor_connections SET delta_link = :l"), {"l": hostile}
        )


def test_sr18_the_database_refuses_a_link_too_long_or_without_a_baseline(
    db, admins, admin_engine, clock
):
    """The rest of the database's copy of the rule: a link over 4,096 characters, and a link on
    a connection that has no baseline, are refused however they are written."""
    admin = admins[0]
    baselined = connect(db, admin, clock)
    with serving(detailed_scenario()) as server:
        full(db, admin, clock, baselined, server)
    link = connection_row(db, admin.tenant_id, baselined)["delta_link"]
    head = PREFIX + "%24deltatoken="
    longest = head + "x" * (4096 - len(head))
    with pytest.raises(IntegrityError), admin_engine.begin() as conn:
        conn.execute(
            text(
                "UPDATE execbound.monitor_connections SET delta_link = :l WHERE connection_id = :c"
            ),
            {"l": longest + "x", "c": baselined},
        )
    # The longest link the rule admits is stored.
    with admin_engine.begin() as conn:
        conn.execute(
            text(
                "UPDATE execbound.monitor_connections SET delta_link = :l WHERE connection_id = :c"
            ),
            {"l": longest, "c": baselined},
        )
    # A link, valid in every other way, on a connection whose first collection is still to come.
    with admin_engine.begin() as conn:
        conn.execute(
            text(
                "UPDATE execbound.monitor_connections SET active = false, revoked_at = now() "
                "WHERE connection_id = :c"
            ),
            {"c": baselined},
        )
    unbaselined = connect(db, admin, clock)
    with pytest.raises(IntegrityError), admin_engine.begin() as conn:
        conn.execute(
            text(
                "UPDATE execbound.monitor_connections SET delta_link = :l WHERE connection_id = :c"
            ),
            {"l": link, "c": unbaselined},
        )
    with pytest.raises(MonitorError) as refused:
        store.record_delta(db, admin, unbaselined, link, clock=clock)
    assert refused.value.code == "INVALID_STATE"


def test_sr18_a_stored_link_is_validated_again_before_it_is_used(db, admins, admin_engine, clock):
    admin = admins[0]
    connection_id = connect(db, admin, clock)
    with serving(detailed_scenario()) as server:
        full(db, admin, clock, connection_id, server)
        # Past the database's prefix, and still not a link the collector would have stored.
        with admin_engine.begin() as conn:
            conn.execute(
                text("UPDATE execbound.monitor_connections SET delta_link = :l"),
                {"l": PREFIX + "%24skiptoken=initial.0"},
            )
        server.requests.clear()
        clock.value += timedelta(minutes=5)
        result = delta(db, admin, clock, connection_id, server)
        assert delta_requests(server) == []
    assert (result["outcome"], result["link"]) == ("RESYNC", "dropped")
    assert connection_row(db, admin.tenant_id, connection_id)["delta_link"] is None


def test_sr18_a_stored_link_is_sent_only_to_the_pinned_origin_and_path(db, admins, clock):
    admin = admins[0]
    connection_id = connect(db, admin, clock)
    with serving(detailed_scenario()) as server:
        full(db, admin, clock, connection_id, server)
        stored = connection_row(db, admin.tenant_id, connection_id)["delta_link"]
        server.requests.clear()
        clock.value += timedelta(minutes=5)
        delta(db, admin, clock, connection_id, server)
        sent = delta_requests(server)
    assert sent == [dict(parse_qsl(urlsplit(stored).query))]


@pytest.mark.parametrize("status", [410, 400])
def test_sr18_a_resync_drops_the_link_and_leaves_the_connection_healthy(db, admins, clock, status):
    admin = admins[0]
    connection_id = connect(db, admin, clock)
    with serving(detailed_scenario()) as server:
        full(db, admin, clock, connection_id, server)
        server.scenario.status = {"delta": status}
        clock.value += timedelta(minutes=5)
        result = delta(db, admin, clock, connection_id, server)
        assert (result["outcome"], result["error_code"], result["link"]) == (
            "RESYNC",
            "RESYNC_REQUIRED",
            "dropped",
        )
        row = connection_row(db, admin.tenant_id, connection_id)
        assert row["delta_link"] is None
        assert (row["health_state"], row["last_outcome"], row["last_error_code"]) == (
            "COLLECTING",
            "COMPLETE",
            None,
        )
        # The next full collection takes a fresh one.
        server.scenario.status = {}
        clock.value += timedelta(hours=7)
        full(db, admin, clock, connection_id, server)
    assert connection_row(db, admin.tenant_id, connection_id)["delta_link"].startswith(PREFIX)


def test_sr18_an_expired_token_is_a_resync_too(db, admins, clock):
    admin = admins[0]
    connection_id = connect(db, admin, clock)
    with serving(detailed_scenario()) as server:
        full(db, admin, clock, connection_id, server)
        server.issued.clear()
        clock.value += timedelta(minutes=5)
        result = delta(db, admin, clock, connection_id, server)
    assert (result["outcome"], result["error_code"], result["link"]) == (
        "RESYNC",
        "RESYNC_REQUIRED",
        "dropped",
    )


@pytest.mark.parametrize(("status", "outcome"), [(503, "ERROR"), (429, "RATE_LIMITED")])
def test_sr18_any_other_failure_keeps_the_link_and_writes_nothing(
    db, admins, clock, status, outcome
):
    admin = admins[0]
    connection_id = connect(db, admin, clock)
    with serving(detailed_scenario()) as server:
        full(db, admin, clock, connection_id, server)
        before = connection_row(db, admin.tenant_id, connection_id)
        server.scenario.status = {"delta": status}
        server.scenario.delta = [principal(15)]
        clock.value += timedelta(minutes=5)
        result = delta(db, admin, clock, connection_id, server)
        assert (result["outcome"], result["link"]) == (outcome, "kept")
        assert result["error_code"] == {503: "UNAVAILABLE", 429: "RATE_LIMITED"}[status]
        assert connection_row(db, admin.tenant_id, connection_id) == before
        # The same changes are read again on the next pass.
        server.scenario.status = {}
        clock.value += timedelta(minutes=5)
        assert delta(db, admin, clock, connection_id, server)["changes"]["new"] == 1


@pytest.mark.parametrize(
    ("malformed", "at"),
    [("body", 0), ("value", 0), ("both", 0), ("neither", 0), ("body", 1), ("neither", 1)],
)
def test_sr18_a_round_page_that_cannot_be_read_keeps_the_link(db, admins, clock, malformed, at):
    """A page of the round that is not JSON, whose `value` is not a list, or that carries both
    continuation links or neither, the round's first page or a later one, is refused like any
    answer from Graph that cannot be read: `MALFORMED`, the link kept and nothing written, so
    the next pass reads the same round. Only a link off the pinned read drops it."""
    admin = admins[0]
    connection_id = connect(db, admin, clock)
    round_ = [principal(15), principal(16)]
    with serving(detailed_scenario()) as server:
        full(db, admin, clock, connection_id, server)
        before = connection_row(db, admin.tenant_id, connection_id)
        held = directory_state(db, admin.tenant_id)
        server.scenario.delta = list(round_)
        server.scenario.delta_page = 1
        server.scenario.delta_malformed = malformed
        server.scenario.delta_malformed_at = at
        server.requests.clear()
        clock.value += timedelta(minutes=5)
        result = delta(db, admin, clock, connection_id, server)
        assert len(delta_requests(server)) == at + 1
        assert (result["outcome"], result["error_code"], result["link"]) == (
            "ERROR",
            "MALFORMED",
            "kept",
        )
        assert connection_row(db, admin.tenant_id, connection_id) == before
        assert directory_state(db, admin.tenant_id) == held
        # The kept link reads the same round again, and this time it lands.
        server.scenario.delta_malformed = None
        clock.value += timedelta(minutes=5)
        again = delta(db, admin, clock, connection_id, server)
    assert (again["outcome"], again["link"]) == ("COMPLETE", "advanced")
    assert again["changes"]["new"] == 2


def directory_state(db, tenant):
    """Every principal, grant and path a connection holds, as a delta pass could change them."""
    with db.transaction(tenant) as conn:
        return {
            table: sorted(
                tuple(str(value) for value in row)
                for row in conn.execute(
                    text(f"SELECT * FROM execbound.{table}")  # nosec B608 - test literals
                ).all()
            )
            for table in ("monitor_agents", "monitor_agent_grants", "monitor_agent_reach")
        }


@pytest.mark.parametrize(
    ("path", "status", "code"),
    [
        ("assignments", 503, "UNAVAILABLE"),
        ("assignments", 429, "RATE_LIMITED"),
        ("owners", 503, "UNAVAILABLE"),
    ],
)
def test_sr18_a_failure_reading_the_listed_principals_writes_nothing(
    db, admins, clock, path, status, code
):
    """Graph fails after the round was read, while the pass reads what its principals hold: the
    principal it lists is not inserted and the one it removes is not marked gone."""
    admin = admins[0]
    profile(db, admin, clock)
    connection_id = connect(db, admin, clock)
    newcomer, assignments = reaching(9)
    round_ = [newcomer, {"id": AGENT_ONE, "@removed": {"reason": "deleted"}}]
    with serving(detailed_scenario()) as server:
        full(db, admin, clock, connection_id, server)
        before = connection_row(db, admin.tenant_id, connection_id)
        held = directory_state(db, admin.tenant_id)
        server.scenario.app_role_assignments = {
            **server.scenario.app_role_assignments,
            **assignments,
        }
        server.scenario.delta = list(round_)
        server.scenario.status = {path: status}
        clock.value += timedelta(minutes=5)
        result = delta(db, admin, clock, connection_id, server)
        assert (result["outcome"], result["error_code"], result["link"]) == (
            "RATE_LIMITED" if status == 429 else "ERROR",
            code,
            "kept",
        )
        assert result["changes"] == {"listed": 0, "new": 0, "restored": 0, "gone": 0}
        assert connection_row(db, admin.tenant_id, connection_id) == before
        assert directory_state(db, admin.tenant_id) == held
        assert findings(db, admin.tenant_id, "new-actor.v1") == []
        # The kept link reads the same round again, and this time it lands.
        server.scenario.status = {}
        server.scenario.delta = list(round_)
        clock.value += timedelta(minutes=5)
        again = delta(db, admin, clock, connection_id, server)
    assert again["changes"] == {"listed": 1, "new": 1, "restored": 0, "gone": 1}
    assert len(findings(db, admin.tenant_id, "new-actor.v1")) == 1


@pytest.mark.parametrize("bound", ["pages", "entries"])
def test_sr18_a_round_past_its_bounds_drops_the_link(db, admins, clock, monkeypatch, bound):
    admin = admins[0]
    connection_id = connect(db, admin, clock)
    # Three changes: past two pages of one, or past two changes on one page.
    monkeypatch.setattr(graph, "MAX_DELTA_PAGES" if bound == "pages" else "MAX_DELTA_ENTRIES", 2)
    with serving(detailed_scenario()) as server:
        full(db, admin, clock, connection_id, server)
        server.scenario.delta = [principal(20 + index) for index in range(3)]
        server.scenario.delta_page = 1 if bound == "pages" else 100
        server.requests.clear()
        clock.value += timedelta(minutes=5)
        result = delta(db, admin, clock, connection_id, server)
        # Two pages and no third, or the one page whose third change is past the bound.
        assert len(delta_requests(server)) == (2 if bound == "pages" else 1)
    assert (result["outcome"], result["error_code"], result["link"]) == (
        "RESYNC",
        "DELTA_OVERFLOW",
        "dropped",
    )
    assert connection_row(db, admin.tenant_id, connection_id)["delta_link"] is None
    with db.transaction(admin.tenant_id) as conn:
        assert conn.execute(text("SELECT count(*) FROM execbound.monitor_agents")).scalar_one() == 1


def removed(index):
    """A delta entry saying a principal the store never held was removed: one change that
    writes nothing, so a round of them meets a bound and nothing else."""
    return {"id": f"0b9f0a3e-0000-4000-8000-{index:012d}", "@removed": {"reason": "deleted"}}


@pytest.mark.parametrize(
    ("bound", "changes", "page", "within"),
    [
        ("pages", 20, 1, True),
        ("pages", 21, 1, False),
        ("changes", 1000, 1000, True),
        ("changes", 1001, 1001, False),
    ],
)
def test_sr18_a_round_is_bounded_at_twenty_pages_and_a_thousand_changes(
    db, admins, clock, bound, changes, page, within
):
    """The bounds the guide, the error codes and the threat model state, at their own values
    rather than the constants': a round of 20 pages or 1,000 changes is read, one more is not.
    The directory bound they sit beside, 1,000 principals, is the same in both modules."""
    assert graph.MAX_AGENTS == store.MAX_AGENTS == 1000
    admin = admins[0]
    connection_id = connect(db, admin, clock)
    with serving(detailed_scenario()) as server:
        full(db, admin, clock, connection_id, server)
        server.scenario.delta = [removed(index) for index in range(changes)]
        server.scenario.delta_page = page
        server.requests.clear()
        clock.value += timedelta(minutes=5)
        result = delta(db, admin, clock, connection_id, server)
        # Every page up to the bound is read, and none past it.
        assert len(delta_requests(server)) == (20 if bound == "pages" else 1)
    if within:
        assert (result["outcome"], result["link"]) == ("COMPLETE", "advanced")
    else:
        assert (result["outcome"], result["error_code"]) == ("RESYNC", "DELTA_OVERFLOW")
        assert connection_row(db, admin.tenant_id, connection_id)["delta_link"] is None


def test_sr18_a_delta_pass_never_carries_a_directory_past_the_principal_bound(
    db, admins, clock, monkeypatch
):
    """A full collection refuses a directory past the bound whole, so no principal is cut in
    silence; a delta pass that would take the directory past it is refused the same way, writes
    nothing from its round and drops its link, and the next full collection refuses the
    directory where the Connections view shows it."""
    admin = admins[0]
    profile(db, admin, clock)
    connection_id = connect(db, admin, clock)
    for module in (graph, store):
        monkeypatch.setattr(module, "MAX_AGENTS", 2)
    newcomer, assignments = reaching(9)
    with serving(detailed_scenario(principals=[principal(5)])) as server:
        assert full(db, admin, clock, connection_id, server)["outcome"] == "COMPLETE"
        held = directory_state(db, admin.tenant_id)
        server.scenario.app_role_assignments = {
            **server.scenario.app_role_assignments,
            **assignments,
        }
        # A third principal: one past the bound once it is added to the two already held.
        server.scenario.delta = [newcomer]
        clock.value += timedelta(minutes=5)
        result = delta(db, admin, clock, connection_id, server)
        assert (result["outcome"], result["error_code"], result["link"]) == (
            "RESYNC",
            "AGENT_CAPACITY",
            "dropped",
        )
        assert directory_state(db, admin.tenant_id) == held
        row = connection_row(db, admin.tenant_id, connection_id)
        assert row["delta_link"] is None
        assert (row["health_state"], row["last_outcome"]) == ("COLLECTING", "COMPLETE")
        assert findings(db, admin.tenant_id, "new-actor.v1") == []

        server.scenario.principals = [principal(5), newcomer]
        clock.value += timedelta(hours=7)
        assert full(db, admin, clock, connection_id, server)["outcome"] == "ERROR"
    row = connection_row(db, admin.tenant_id, connection_id)
    assert (row["last_outcome"], row["last_error_code"]) == ("ERROR", "AGENT_CAPACITY")


def test_sr18_the_rules_refuse_a_connection_past_the_bound_rather_than_cut_it(
    db, admins, clock, monkeypatch
):
    """The agent rules read every principal a connection holds or none: past the bound they are
    refused, never evaluated for the first thousand by object identifier and silent on the rest."""
    admin = admins[0]
    profile(db, admin, clock)
    connection_id = connect(db, admin, clock)
    with serving(detailed_scenario(principals=[principal(5), principal(6)])) as server:
        full(db, admin, clock, connection_id, server)
    monkeypatch.setattr(store, "MAX_AGENTS", 2)
    with pytest.raises(MonitorError) as refused:
        store.evaluate_agents(db, admin, connection_id, full=False, clock=clock)
    assert refused.value.code == "AGENT_CAPACITY"


# SR19


def test_sr19_collect_due_runs_a_delta_pass_between_full_collections(
    db, admins, admin_engine, clock, tmp_path
):
    admin = admins[0]
    profile(db, admin, clock)
    connection_id = connect(db, admin, clock)
    files = tmp_path / "key-files"
    key_file(files, connection_id, entra=True)
    with (
        serving(detailed_scenario()) as server,
        httpx.Client(transport=transport(server), trust_env=False) as http,
    ):
        first = due.collect_due(db, key_files=files, client=http, clock=clock)
        assert first["tenants"][str(admin.tenant_id)]["collected"] == 1
        before = connection_row(db, admin.tenant_id, connection_id)
        newcomer, assignments = reaching(9)
        server.scenario.app_role_assignments = {
            **server.scenario.app_role_assignments,
            **assignments,
        }
        server.scenario.delta = [newcomer]
        clock.value += timedelta(minutes=5)
        second = due.collect_due(db, key_files=files, client=http, clock=clock)
    counts = second["tenants"][str(admin.tenant_id)]
    assert (counts["collected"], counts["delta"], counts["delta_failed"]) == (0, 1, 0)
    after = connection_row(db, admin.tenant_id, connection_id)
    for column in ("last_run_at", "last_run_id", "last_sync_at", "collect_requested_at"):
        assert after[column] == before[column], column
    assert (after["collecting_until"], after["collecting_lease"]) == (None, None)
    assert after["delta_at"] == clock.value
    assert len(findings(db, admin.tenant_id, "new-actor.v1")) == 1


def test_sr19_a_waiting_request_is_answered_by_a_full_collection_never_a_delta_pass(
    db, admins, admin_engine, clock, tmp_path
):
    admin = admins[0]
    connection_id = connect(db, admin, clock)
    files = tmp_path / "key-files"
    key_file(files, connection_id, entra=True)
    actor = ScheduledActor(admin.tenant_id)
    with (
        serving(detailed_scenario()) as server,
        httpx.Client(transport=transport(server), trust_env=False) as http,
    ):
        due.collect_due(db, key_files=files, client=http, clock=clock)
        with admin_engine.begin() as conn:
            conn.execute(
                text(
                    "UPDATE execbound.monitor_connections SET collect_requested_at = now(), "
                    "collect_requested_by = :p WHERE connection_id = :c"
                ),
                {"p": admin.principal_id, "c": connection_id},
            )
        # The delta claim itself refuses while a request waits, and leaves the request.
        assert not due.claim_delta(db, actor, connection_id, uuid4(), clock=clock)
        assert connection_row(db, admin.tenant_id, connection_id)["collect_requested_at"]
        before = connection_row(db, admin.tenant_id, connection_id)
        clock.value += timedelta(minutes=5)
        report = due.collect_due(db, key_files=files, client=http, clock=clock)
    counts = report["tenants"][str(admin.tenant_id)]
    assert (counts["collected"], counts["delta"]) == (1, 0)
    after = connection_row(db, admin.tenant_id, connection_id)
    assert after["collect_requested_at"] is None
    assert after["last_run_id"] != before["last_run_id"]


def test_sr19_a_delta_claim_respects_a_held_lease_and_the_schedule(
    db, admins, admin_engine, clock, tmp_path
):
    admin = admins[0]
    connection_id = connect(db, admin, clock)
    actor = ScheduledActor(admin.tenant_id)
    with serving(detailed_scenario()) as server:
        full(db, admin, clock, connection_id, server)
    lease = uuid4()
    assert due.claim(db, actor, connection_id, lease)
    # Held by a run: no delta claim.
    assert not due.claim_delta(db, actor, connection_id, uuid4(), clock=clock)
    due.release(db, actor, connection_id, lease)
    row = connection_row(db, admin.tenant_id, connection_id)
    assert due.delta_eligible(row, clock.value)
    # Due for a full collection: that, not a delta pass.
    assert not due.delta_eligible(row, clock.value + timedelta(hours=7))
    # A connection whose last full run failed waits for the next one to succeed.
    assert not due.delta_eligible({**row, "last_outcome": "ERROR"}, clock.value)
    assert not due.delta_eligible({**row, "delta_link": None}, clock.value)
    held = uuid4()
    assert due.claim_delta(db, actor, connection_id, held, clock=clock)
    assert connection_row(db, admin.tenant_id, connection_id)["collecting_lease"] == held
    due.release(db, actor, connection_id, held)


def test_sr19_the_delta_claim_itself_refuses_a_failed_or_due_connection(
    db, admins, admin_engine, clock
):
    """`collect_workspace` chooses eligible connections from a read made before any claim, and
    a full run can fail, or the schedule come due, before the claim lands. The claim checks
    both again in the transaction that takes the lease, so neither gets a delta pass."""
    admin = admins[0]
    connection_id = connect(db, admin, clock)
    actor = ScheduledActor(admin.tenant_id)
    with serving(detailed_scenario()) as server:
        full(db, admin, clock, connection_id, server)

    def outcome(value):
        with admin_engine.begin() as conn:
            conn.execute(
                text(
                    "UPDATE execbound.monitor_connections SET last_outcome = :o "
                    "WHERE connection_id = :c"
                ),
                {"o": value, "c": connection_id},
            )

    # The last full run failed after the pass chose the connection.
    outcome("ERROR")
    assert not due.claim_delta(db, actor, connection_id, uuid4(), clock=clock)
    assert connection_row(db, admin.tenant_id, connection_id)["collecting_lease"] is None
    outcome("COMPLETE")
    # The schedule came due: a full collection, not a delta pass.
    later = FixedClock(clock.value + timedelta(hours=7))
    assert not due.claim_delta(db, actor, connection_id, uuid4(), clock=later)
    assert connection_row(db, admin.tenant_id, connection_id)["collecting_lease"] is None
    # Neither, and the claim lands.
    lease = uuid4()
    assert due.claim_delta(db, actor, connection_id, lease, clock=clock)
    due.release(db, actor, connection_id, lease)


def expire_lease(admin_engine, connection_id):
    """The lease's holder died: its expiry passes and nothing released it."""
    with admin_engine.begin() as conn:
        conn.execute(
            text(
                "UPDATE execbound.monitor_connections "
                "SET collecting_until = now() - interval '1 second' WHERE connection_id = :c"
            ),
            {"c": connection_id},
        )


HEALTH = ("last_outcome", "last_error_code", "health_state", "health_changed_at", "last_run_at")


def test_sr19_an_interrupted_delta_pass_is_not_an_interrupted_run(
    db, admins, admin_engine, clock, tmp_path
):
    """A delta pass that dies holding the lease records no outcome: the next delta pass and the
    next full collection each take the lease without calling the connection interrupted."""
    admin = admins[0]
    connection_id = connect(db, admin, clock)
    actor = ScheduledActor(admin.tenant_id)
    files = tmp_path / "key-files"
    key_file(files, connection_id, entra=True)
    with (
        serving(detailed_scenario()) as server,
        httpx.Client(transport=transport(server), trust_env=False) as http,
    ):
        due.collect_due(db, key_files=files, client=http, clock=clock)
        before = connection_row(db, admin.tenant_id, connection_id)
        assert due.claim_delta(db, actor, connection_id, uuid4(), clock=clock)
        expire_lease(admin_engine, connection_id)
        # The next pass gives it another delta pass, and its health is the full collection's.
        server.scenario.delta = [principal(30)]
        clock.value += timedelta(minutes=10)
        counts = due.collect_due(db, key_files=files, client=http, clock=clock)["tenants"][
            str(admin.tenant_id)
        ]
        assert (counts["delta"], counts["delta_failed"]) == (1, 0)
        after = connection_row(db, admin.tenant_id, connection_id)
        assert {column: after[column] for column in HEALTH} == {
            column: before[column] for column in HEALTH
        }
        # A full collection that finds a delta pass's lease expired calls nothing interrupted.
        assert due.claim_delta(db, actor, connection_id, uuid4(), clock=clock)
        expire_lease(admin_engine, connection_id)
        lease = uuid4()
        assert due.claim(db, actor, connection_id, lease)
        held = connection_row(db, admin.tenant_id, connection_id)
        assert {column: held[column] for column in HEALTH} == {
            column: before[column] for column in HEALTH
        }
        assert held["collecting_lease"] == lease
        due.release(db, actor, connection_id, lease)


def test_sr19_a_delta_claim_records_an_interrupted_full_run_and_takes_nothing(
    db, admins, admin_engine, clock
):
    """A full collection that dies holding the lease is still recorded as interrupted when the
    next claim is a delta pass's, and no delta pass follows an interrupted run."""
    admin = admins[0]
    connection_id = connect(db, admin, clock)
    actor = ScheduledActor(admin.tenant_id)
    with serving(detailed_scenario()) as server:
        full(db, admin, clock, connection_id, server)
    assert due.claim(db, actor, connection_id, uuid4())
    expire_lease(admin_engine, connection_id)
    clock.value += timedelta(minutes=1)
    assert not due.claim_delta(db, actor, connection_id, uuid4(), clock=clock)
    row = connection_row(db, admin.tenant_id, connection_id)
    assert (row["last_outcome"], row["last_error_code"], row["health_state"]) == (
        "INTERRUPTED",
        "RUN_INTERRUPTED",
        "ERROR",
    )
    assert (row["collecting_until"], row["collecting_lease"]) == (None, None)
    assert not due.delta_eligible(row, clock.value)
    # The full collection that follows takes the lease and records nothing twice.
    lease = uuid4()
    assert due.claim(db, actor, connection_id, lease)
    assert (
        connection_row(db, admin.tenant_id, connection_id)["health_changed_at"]
        == (row["health_changed_at"])
    )
    due.release(db, actor, connection_id, lease)


def test_sr19_the_database_never_lets_a_delta_claim_answer_or_skip_a_request(
    db, admins, admin_engine, clock
):
    """The delta claim's own function refuses a connection with a request waiting, one with no
    link or baseline and one that is not a directory, whatever its caller checked first."""
    admin = admins[0]
    connection_id = connect(db, admin, clock)
    tines = store.create_connection(
        db,
        admin,
        label="Synthetic Tines tenant",
        base_url=TINES_URL,
        key_fingerprint=collection.fingerprint(TINES_KEY),
        clock=clock,
    )

    def claim(connection):
        with db.transaction(admin.tenant_id) as conn:
            return conn.execute(
                text("SELECT execbound.collector_claim_delta(:c, :l, 600)"),
                {"c": connection, "l": uuid4()},
            ).scalar_one()

    # No link and no baseline yet; and a Tines connection never has either.
    assert claim(connection_id) == {"claimed": False}
    assert claim(tines) == {"claimed": False}
    with serving(detailed_scenario()) as server:
        full(db, admin, clock, connection_id, server)
    with admin_engine.begin() as conn:
        conn.execute(
            text(
                "UPDATE execbound.monitor_connections SET collect_requested_at = now(), "
                "collect_requested_by = :p WHERE connection_id = :c"
            ),
            {"p": admin.principal_id, "c": connection_id},
        )
    assert claim(connection_id) == {"claimed": False}
    row = connection_row(db, admin.tenant_id, connection_id)
    assert row["collect_requested_at"] is not None and row["collecting_lease"] is None


def test_sr19_only_the_delta_claim_marks_a_lease_and_the_runtime_writes_no_mark(
    db, admins, admin_engine, clock
):
    admin = admins[0]
    connection_id = connect(db, admin, clock)
    actor = ScheduledActor(admin.tenant_id)
    with serving(detailed_scenario()) as server:
        full(db, admin, clock, connection_id, server)
    lease = uuid4()
    assert due.claim_delta(db, actor, connection_id, lease, clock=clock)
    assert connection_row(db, admin.tenant_id, connection_id)["collecting_delta"] is True
    due.release(db, actor, connection_id, lease)
    assert connection_row(db, admin.tenant_id, connection_id)["collecting_delta"] is False
    # A full run's claim never carries the mark, even over an expired delta pass's lease.
    assert due.claim_delta(db, actor, connection_id, uuid4(), clock=clock)
    expire_lease(admin_engine, connection_id)
    lease = uuid4()
    assert due.claim(db, actor, connection_id, lease)
    assert connection_row(db, admin.tenant_id, connection_id)["collecting_delta"] is False
    due.release(db, actor, connection_id, lease)
    # Revoking a connection ends a delta pass's lease with its mark.
    assert due.claim_delta(db, actor, connection_id, uuid4(), clock=clock)
    with pytest.raises(ProgrammingError), db.transaction(admin.tenant_id) as conn:
        conn.execute(text("UPDATE execbound.monitor_connections SET collecting_delta = false"))
    with pytest.raises(IntegrityError), admin_engine.begin() as conn:
        conn.execute(
            text(
                "UPDATE execbound.monitor_connections SET collecting_until = NULL, "
                "collecting_lease = NULL WHERE connection_id = :c"
            ),
            {"c": connection_id},
        )
    store.revoke_connection(db, admin, connection_id)
    revoked = connection_row(db, admin.tenant_id, connection_id)
    assert (revoked["collecting_lease"], revoked["collecting_delta"]) == (None, False)


def test_sr19_a_failed_delta_pass_is_counted_and_changes_no_health(
    db, admins, admin_engine, clock, tmp_path
):
    admin = admins[0]
    connection_id = connect(db, admin, clock)
    files = tmp_path / "key-files"
    key_file(files, connection_id, entra=True)
    with (
        serving(detailed_scenario()) as server,
        httpx.Client(transport=transport(server), trust_env=False) as http,
    ):
        due.collect_due(db, key_files=files, client=http, clock=clock)
        before = connection_row(db, admin.tenant_id, connection_id)
        # Throttled: the link is kept for the next pass.
        server.scenario.status = {"delta": 429}
        clock.value += timedelta(minutes=5)
        throttled = due.collect_due(db, key_files=files, client=http, clock=clock)
        # Refused as expired: the link is dropped for the next full collection.
        server.scenario.status = {"delta": 410}
        clock.value += timedelta(minutes=5)
        resynced = due.collect_due(db, key_files=files, client=http, clock=clock)
    for report in (throttled, resynced):
        counts = report["tenants"][str(admin.tenant_id)]
        assert (counts["collected"], counts["delta"], counts["delta_failed"]) == (0, 0, 1)
    after = connection_row(db, admin.tenant_id, connection_id)
    assert after["delta_link"] is None
    assert {column: after[column] for column in HEALTH} == {
        column: before[column] for column in HEALTH
    }


ANOTHER_APP = "99999999-8888-7777-6666-555555555555"


@pytest.mark.parametrize(
    "refusal", ["KEY_MISMATCH", "KEY_FILE_INVALID", "COLLECTOR_KEY_UNAVAILABLE", "CLIENT_MISMATCH"]
)
def test_sr19_a_delta_pass_refused_its_credential_records_nothing(
    db, admins, admin_engine, clock, tmp_path, refusal
):
    """A key file replaced with the wrong key or with no key at all, or a collector without the
    platform app or with another one: the delta pass is refused before any request, counted
    `delta_failed`, and records nothing on the connection, not its outcome, `last_run_at` or
    health, and not its link. The full collection, when it comes due, meets the same refusal
    and records it."""
    admin = admins[0]
    files = tmp_path / "key-files"
    credential = fake_graph.platform_app()
    consented = refusal in {"COLLECTOR_KEY_UNAVAILABLE", "CLIENT_MISMATCH"}
    app = graph.PlatformApp.from_text(json.dumps(credential)) if consented else None
    if consented:
        connection_id = consented_connection(admin_engine, admin, clock)
    else:
        connection_id = connect(db, admin, clock)
        key_file(files, connection_id, entra=True)
    scenario = detailed_scenario()
    scenario.certificate = credential["certificate_pem"]
    with (
        serving(scenario) as server,
        httpx.Client(transport=transport(server), trust_env=False) as http,
    ):
        first = due.collect_due(db, key_files=files, platform_app=app, client=http, clock=clock)
        assert first["tenants"][str(admin.tenant_id)]["collected"] == 1
        before = connection_row(db, admin.tenant_id, connection_id)
        assert before["delta_link"] is not None
        assert due.delta_eligible(before, clock.value + timedelta(minutes=5))
        if refusal == "KEY_MISMATCH":
            (files / f"{connection_id}.env").write_text(
                f"ENTRA_DIRECTORY_ID={DIRECTORY}\nENTRA_CLIENT_ID={CLIENT}\n"
                "ENTRA_CLIENT_SECRET=a-different-secret\n",
                encoding="utf-8",
            )
        elif refusal == "KEY_FILE_INVALID":
            (files / f"{connection_id}.env").write_text("not a key file at all\n", encoding="utf-8")
        elif refusal == "CLIENT_MISMATCH":
            app = graph.PlatformApp.from_text(json.dumps(fake_graph.platform_app(ANOTHER_APP)))
        else:
            app = None
        sent = len(server.requests)
        clock.value += timedelta(minutes=5)
        report = due.collect_due(db, key_files=files, platform_app=app, client=http, clock=clock)
        # Refused before any request, the token request among them.
        assert len(server.requests) == sent
        counts = report["tenants"][str(admin.tenant_id)]
        assert (counts["collected"], counts["failed"], counts["delta"], counts["delta_failed"]) == (
            0,
            0,
            0,
            1,
        )
        after = connection_row(db, admin.tenant_id, connection_id)
        for column in (*HEALTH, "last_run_id", "last_sync_at", "delta_link", "delta_at"):
            assert after[column] == before[column], column
        assert (after["collecting_lease"], after["collecting_delta"]) == (None, False)
        # Due for a full collection: that run records the refusal where the page shows it.
        clock.value += timedelta(hours=7)
        report = due.collect_due(db, key_files=files, platform_app=app, client=http, clock=clock)
        assert len(server.requests) == sent
    assert report["tenants"][str(admin.tenant_id)]["failed"] == 1
    recorded = connection_row(db, admin.tenant_id, connection_id)
    assert (recorded["last_outcome"], recorded["last_error_code"]) == ("ERROR", refusal)


def test_sr19_a_delta_pass_proves_its_lease(db, admins, clock):
    admin = admins[0]
    connection_id = connect(db, admin, clock)
    actor = ScheduledActor(admin.tenant_id)
    with serving(detailed_scenario()) as server:
        full(db, admin, clock, connection_id, server)
        server.scenario.delta = [principal(16)]
        lease = uuid4()
        assert due.claim_delta(db, actor, connection_id, lease, clock=clock)
        with client(server) as http:
            with pytest.raises(MonitorError) as unleased:
                graph.run_delta(
                    db,
                    actor,
                    connection_id=connection_id,
                    client_secret=SECRET,
                    client=http,
                    clock=clock,
                )
            assert unleased.value.code == "INVALID_ADMIN"
            with pytest.raises(MonitorError) as lost:
                graph.run_delta(
                    db,
                    actor,
                    connection_id=connection_id,
                    client_secret=SECRET,
                    client=http,
                    clock=clock,
                    lease=uuid4(),
                )
            assert lost.value.code == "LEASE_LOST"
            result = graph.run_delta(
                db,
                actor,
                connection_id=connection_id,
                client_secret=SECRET,
                client=http,
                clock=clock,
                lease=lease,
            )
        due.release(db, actor, connection_id, lease)
    assert result["changes"]["new"] == 1


# SR20


def test_sr20_new_ai_consent_is_raised_once_and_closes_when_the_consent_goes(db, admins, clock):
    admin = admins[0]
    connection_id = connect(db, admin, clock)
    with serving(detailed_scenario()) as server:
        full(db, admin, clock, connection_id, server)
        consented = principal(17, appId=ANTHROPIC_SERVER)
        server.scenario.delta = [consented]
        clock.value += timedelta(minutes=5)
        result = delta(db, admin, clock, connection_id, server)
        assert result["findings"]["ai_consent"] == 1
        (raised,) = findings(db, admin.tenant_id, "new-ai-consent.v1")
        assert raised["platform_ref"] == consented["id"] and raised["delivered"]
        assert "Anthropic" in raised["title"]
        row = agent_row(db, admin.tenant_id, consented["id"])
        assert row["ai_publisher"] == "anthropic" and row["ai_consent_opened_at"] is not None
        # Replayed by the next round and seen again by a full collection: still one.
        server.scenario.delta = [consented]
        clock.value += timedelta(minutes=5)
        delta(db, admin, clock, connection_id, server)
        server.scenario.principals = [consented]
        clock.value += timedelta(hours=7)
        full(db, admin, clock, connection_id, server)
        assert len(findings(db, admin.tenant_id, "new-ai-consent.v1")) == 1
        # The consent is removed: the principal leaves the directory and the episode closes.
        server.scenario.principals = []
        clock.value += timedelta(hours=7)
        full(db, admin, clock, connection_id, server)
    row = agent_row(db, admin.tenant_id, consented["id"])
    assert row["gone_at"] is not None and row["ai_consent_opened_at"] is None
    assert len(findings(db, admin.tenant_id, "new-ai-consent.v1")) == 1


def test_sr20_a_principal_from_no_catalogued_publisher_raises_nothing(db, admins, clock):
    admin = admins[0]
    connection_id = connect(db, admin, clock)
    with serving(detailed_scenario()) as server:
        full(db, admin, clock, connection_id, server)
        server.scenario.delta = [
            principal(18, appId="0b9f0a3e-0000-4000-8000-000000000001"),
            principal(19, verifiedPublisher={"verifiedPublisherId": "1234567"}),
        ]
        clock.value += timedelta(minutes=5)
        delta(db, admin, clock, connection_id, server)
    assert findings(db, admin.tenant_id, "new-ai-consent.v1") == []


def test_sr20_the_catalog_matches_each_identifier_kind_and_keeps_only_its_key():
    catalog = ai_publishers.Catalog(
        (
            ai_publishers.Publisher(
                key="synthetic",
                label="Synthetic",
                app_refs=("0b9f0a3e-0000-4000-8000-000000000001",),
                owner_refs=("0b9f0a3e-0000-4000-8000-000000000002",),
                publisher_refs=("1234567",),
                source="https://publisher.example/docs",
                retrieved=ai_publishers.READ_ON,
            ),
        )
    )
    assert catalog.match(app_ref="0B9F0A3E-0000-4000-8000-000000000001") == "synthetic"
    assert catalog.match(owner_ref="0b9f0a3e-0000-4000-8000-000000000002") == "synthetic"
    assert catalog.match(publisher_ref="1234567") == "synthetic"
    assert catalog.match(app_ref="0b9f0a3e-0000-4000-8000-000000000009") is None
    assert catalog.match() is None
    parsed = graph.parse_agent(
        principal(21, appId=ANTHROPIC_SERVER, verifiedPublisher={"displayName": "Anthropic"})
    )
    assert parsed is not None and parsed.ai_publisher == "anthropic"


def test_sr20_every_catalog_entry_names_a_primary_source_and_its_date():
    for publisher in ai_publishers.PRODUCTION.publishers:
        assert publisher.source.startswith("https://")
        assert publisher.retrieved <= datetime.now(UTC).date()
        assert publisher.app_refs or publisher.owner_refs or publisher.publisher_refs
    # The gaps are named rather than guessed.
    assert "OpenAI" in ai_publishers.__doc__
    for invalid in (
        {"key": "Not A Key"},
        # Read whole: a final newline passes a pattern read with `re.match`.
        {"key": "synthetic\n"},
        {"app_refs": ("not-a-guid",)},
        {"app_refs": ("0b9f0a3e-0000-4000-8000-000000000001\n",)},
        {"publisher_refs": ("12a",)},
        {"publisher_refs": ("12\n",)},
        {"source": "http://publisher.example/docs"},
        {"app_refs": (), "owner_refs": (), "publisher_refs": ()},
    ):
        values = {
            "key": "synthetic",
            "label": "Synthetic",
            "app_refs": ("0b9f0a3e-0000-4000-8000-000000000001",),
            "owner_refs": (),
            "publisher_refs": (),
            "source": "https://publisher.example/docs",
            "retrieved": ai_publishers.READ_ON,
            **invalid,
        }
        with pytest.raises(ai_publishers.CatalogError):
            ai_publishers.Catalog((ai_publishers.Publisher(**values),))


# The third rule: first-consequential-action.v1


def test_sr20_a_first_consequential_action_is_raised_once_per_actor(
    db, admins, admin_engine, clock
):
    admin = admins[0]
    profile(db, admin, clock)
    connection_id = connect(db, admin, clock)
    with serving(detailed_scenario()) as server:
        full(db, admin, clock, connection_id, server)
        newcomer, assignments = reaching(9)
        server.scenario.delta = [newcomer]
        clock.value += timedelta(minutes=5)
        delta(db, admin, clock, connection_id, server)
    tenant = admin.tenant_id
    # Before any observation: nothing to raise.
    assert store.evaluate_actions(db, admin, clock=clock)["raised"] == 0
    clock.value += timedelta(minutes=10)
    acted = clock.value - timedelta(minutes=3)
    # Recorded out of order, so neither the order they arrived in nor a tie decides.
    later = observe(
        admin_engine,
        tenant,
        connection_id,
        newcomer["id"],
        "identity.disable",
        acted + timedelta(minutes=2),
    )
    earliest = observe(
        admin_engine, tenant, connection_id, newcomer["id"], "identity.disable", acted
    )
    # A non-consequential action, before either, is not the rule's subject.
    observe(
        admin_engine,
        tenant,
        connection_id,
        newcomer["id"],
        "identity.read",
        acted - timedelta(minutes=1),
    )
    clock.value += timedelta(minutes=1)
    result = worker.evaluate_scheduled(db, tenant, clock=clock)
    assert result["actions"] == 1
    (raised,) = findings(db, tenant, "first-consequential-action.v1")
    assert raised["platform_ref"] == newcomer["id"] and raised["delivered"]
    # It carries the earliest consequential observation, and names that observation's action.
    assert raised["observation_id"] == earliest != later
    assert raised["connection_id"] == connection_id
    assert raised["title"] == "First consequential action outside ExecBound: identity.disable"
    # A second action, and a second evaluation: still one finding for this actor.
    observe(
        admin_engine,
        tenant,
        connection_id,
        newcomer["id"],
        "identity.disable",
        clock.value + timedelta(seconds=5),
    )
    clock.value += timedelta(minutes=1)
    assert store.evaluate_actions(db, admin, clock=clock)["raised"] == 0
    assert len(findings(db, tenant, "first-consequential-action.v1")) == 1


def test_sr20_every_actor_is_evaluated_however_many_precede_it(
    db, admins, admin_engine, clock, monkeypatch
):
    """The candidates are read a page at a time, and every page is read: an actor that sorts
    after a full page of open episodes still raises the rule, and every episode still closes.
    A page of three stands in for the production page here."""
    admin = admins[0]
    profile(db, admin, clock)
    connection_id = connect(db, admin, clock)
    tenant = admin.tenant_id
    scenario = detailed_scenario(principals=[principal(9), principal(10), principal(11)])
    with serving(scenario) as server:
        full(db, admin, clock, connection_id, server)
    with db.transaction(tenant) as conn:
        actors = list(
            conn.execute(
                text(
                    "SELECT platform_ref FROM execbound.monitor_agents "
                    "WHERE connection_id = :c AND gone_at IS NULL ORDER BY agent_id"
                ),
                {"c": connection_id},
            ).scalars()
        )
    assert len(actors) == 4
    for actor in actors:
        observe(
            admin_engine,
            tenant,
            connection_id,
            actor,
            "identity.disable",
            clock.value + timedelta(minutes=1),
        )
    monkeypatch.setattr(store, "MAX_DERIVED", 3)
    clock.value += timedelta(minutes=2)
    assert store.evaluate_actions(db, admin, clock=clock)["raised"] == 4
    raised = findings(db, tenant, "first-consequential-action.v1")
    assert sorted(row["platform_ref"] for row in raised) == sorted(actors)
    assert all(row["delivered"] for row in raised)
    # Every episode stays open while its evidence is current, and the next page is still read.
    assert store.evaluate_actions(db, admin, clock=clock) == {
        "raised": 0,
        "closed": 0,
        "insufficient": 0,
    }
    # Once the evidence is no longer current, every episode closes, past the first page too.
    clock.value += timedelta(days=31)
    result = store.evaluate_actions(db, ScheduledActor(tenant), clock=clock)
    assert (result["raised"], result["closed"]) == (0, 4)
    for actor in actors:
        assert agent_row(db, tenant, actor)["first_action_opened_at"] is None


def test_sr20_an_actor_that_acted_before_the_baseline_never_raises_it(
    db, admins, admin_engine, clock
):
    admin = admins[0]
    profile(db, admin, clock)
    connection_id = connect(db, admin, clock)
    tenant = admin.tenant_id
    with serving(detailed_scenario()) as server:
        full(db, admin, clock, connection_id, server)
    # Evidence from before the baseline, then after it.
    observe(
        admin_engine,
        tenant,
        connection_id,
        AGENT_ONE,
        "identity.disable",
        clock.value - timedelta(hours=1),
    )
    observe(
        admin_engine,
        tenant,
        connection_id,
        AGENT_ONE,
        "identity.disable",
        clock.value + timedelta(minutes=1),
    )
    clock.value += timedelta(minutes=2)
    assert store.evaluate_actions(db, admin, clock=clock)["raised"] == 0
    assert findings(db, tenant, "first-consequential-action.v1") == []


def execbound_path_is_live(db, tenant, platform_ref, now, action="identity.disable"):
    """Whether the actor holds a live ExecBound path for `action`: a governed route."""
    agent_id = agent_row(db, tenant, platform_ref)["agent_id"]
    with db.transaction(tenant) as conn:
        return conn.execute(
            text(
                "SELECT EXISTS (SELECT 1 FROM execbound.monitor_agent_reach WHERE agent_id = :a "
                "AND action = :action AND path_kind = 'execbound' AND gone_at IS NULL "
                "AND valid_until > :now)"
            ),
            {"a": agent_id, "action": action, "now": now},
        ).scalar_one()


def govern(db, admin, admin_engine, clock, connection_id, record):
    """Link the actor to a governed principal whose bundle governs `identity.disable`, and take
    the full collection that derives its ExecBound path for that action."""
    tenant = admin.tenant_id
    bundle(
        admin_engine,
        tenant,
        admin.principal_id,
        [{"operation_ref": "identity.disable", "action": "identity.disable"}],
    )
    store.link_agent(
        db,
        admin,
        connection_id=connection_id,
        platform_ref=record["id"],
        principal_id=governed_agent(admin_engine, tenant)[0],
        clock=clock,
    )
    with serving(detailed_scenario(principals=[record])) as server:
        clock.value += timedelta(hours=7)
        full(db, admin, clock, connection_id, server)
    assert execbound_path_is_live(db, tenant, record["id"], clock.value)


def newcomer_after_the_baseline(db, admin, clock, connection_id):
    """A principal the first delta pass after the baseline lists."""
    with serving(detailed_scenario()) as server:
        full(db, admin, clock, connection_id, server)
        newcomer, _ = reaching(9)
        server.scenario.delta = [newcomer]
        clock.value += timedelta(minutes=5)
        delta(db, admin, clock, connection_id, server)
    return newcomer


def test_sr20_a_linked_actor_acting_with_its_own_credential_raises_the_first_action(
    db, admins, admin_engine, clock
):
    """An observation attributed to the actor's own directory principal was taken with that
    principal's own credential, outside ExecBound, so a governed route for the same action
    does not make it governed: the rule is raised whether or not the actor is linked."""
    admin = admins[0]
    profile(db, admin, clock)
    connection_id = connect(db, admin, clock)
    tenant = admin.tenant_id
    newcomer = newcomer_after_the_baseline(db, admin, clock, connection_id)
    govern(db, admin, admin_engine, clock, connection_id, newcomer)
    observed = observe(
        admin_engine, tenant, connection_id, newcomer["id"], "identity.disable", clock.value
    )
    clock.value += timedelta(minutes=1)
    assert store.evaluate_actions(db, admin, clock=clock)["raised"] == 1
    (raised,) = findings(db, tenant, "first-consequential-action.v1")
    assert raised["platform_ref"] == newcomer["id"] and raised["delivered"]
    assert raised["observation_id"] == observed
    assert raised["title"] == "First consequential action outside ExecBound: identity.disable"
    assert agent_row(db, tenant, newcomer["id"])["first_action_opened_at"] is not None


def test_sr20_a_governed_path_leaves_the_first_action_episode_open(db, admins, admin_engine, clock):
    admin = admins[0]
    profile(db, admin, clock)
    connection_id = connect(db, admin, clock)
    tenant = admin.tenant_id
    newcomer = newcomer_after_the_baseline(db, admin, clock, connection_id)
    observe(admin_engine, tenant, connection_id, newcomer["id"], "identity.disable", clock.value)
    clock.value += timedelta(minutes=1)
    assert store.evaluate_actions(db, admin, clock=clock)["raised"] == 1
    assert agent_row(db, tenant, newcomer["id"])["first_action_opened_at"] is not None

    # Linking the actor gives it a governed route for the action it took. The action was still
    # taken outside ExecBound, and its observation is still current: the episode stays open.
    govern(db, admin, admin_engine, clock, connection_id, newcomer)
    clock.value += timedelta(minutes=1)
    assert store.evaluate_actions(db, admin, clock=clock) == {
        "raised": 0,
        "closed": 0,
        "insufficient": 0,
    }
    assert agent_row(db, tenant, newcomer["id"])["first_action_opened_at"] is not None

    # It closes only once no qualifying observation is current.
    clock.value += timedelta(days=31)
    result = store.evaluate_actions(db, ScheduledActor(tenant), clock=clock)
    assert (result["raised"], result["closed"]) == (0, 1)
    assert agent_row(db, tenant, newcomer["id"])["first_action_opened_at"] is None

    # The linked actor acts again with its own credential: the condition holds once more, and
    # the episode still never reopens.
    observe(
        admin_engine,
        tenant,
        connection_id,
        newcomer["id"],
        "identity.disable",
        clock.value + timedelta(seconds=1),
    )
    clock.value += timedelta(minutes=1)
    assert store.evaluate_actions(db, ScheduledActor(tenant), clock=clock)["raised"] == 0
    assert agent_row(db, tenant, newcomer["id"])["first_action_opened_at"] is None
    assert len(findings(db, tenant, "first-consequential-action.v1")) == 1


def test_sr20_the_first_action_episode_closes_when_the_actor_leaves(
    db, admins, admin_engine, clock
):
    admin = admins[0]
    profile(db, admin, clock)
    connection_id = connect(db, admin, clock)
    tenant = admin.tenant_id
    with serving(detailed_scenario()) as server:
        full(db, admin, clock, connection_id, server)
        newcomer, _ = reaching(9)
        server.scenario.delta = [newcomer]
        clock.value += timedelta(minutes=5)
        delta(db, admin, clock, connection_id, server)
        observe(
            admin_engine, tenant, connection_id, newcomer["id"], "identity.disable", clock.value
        )
        clock.value += timedelta(minutes=1)
        assert store.evaluate_actions(db, admin, clock=clock)["raised"] == 1
        server.scenario.delta = [{"id": newcomer["id"], "@removed": {"reason": "deleted"}}]
        clock.value += timedelta(minutes=5)
        delta(db, admin, clock, connection_id, server)
    gone = agent_row(db, tenant, newcomer["id"])
    assert gone["gone_at"] is not None and gone["first_action_opened_at"] is None
    # Its observation is still current, and an actor that left raises nothing again.
    clock.value += timedelta(minutes=1)
    assert store.evaluate_actions(db, admin, clock=clock)["raised"] == 0
    assert len(findings(db, tenant, "first-consequential-action.v1")) == 1


def test_sr20_without_a_sensitive_list_no_action_rule_runs(db, admins, admin_engine, clock):
    admin = admins[0]
    connection_id = connect(db, admin, clock)
    tenant = admin.tenant_id
    with serving(detailed_scenario()) as server:
        full(db, admin, clock, connection_id, server)
        server.scenario.delta = [principal(9)]
        clock.value += timedelta(minutes=5)
        delta(db, admin, clock, connection_id, server)
    observe(
        admin_engine, tenant, connection_id, principal(9)["id"], "identity.disable", clock.value
    )
    clock.value += timedelta(minutes=1)
    result = store.evaluate_actions(db, admin, clock=clock)
    assert (result["raised"], result["insufficient"]) == (0, 1)


def test_sr20_an_upgraded_connection_raises_nothing_retroactively(db, admins, admin_engine, clock):
    """What the upgrade does to a connection that has already synchronized: its baseline is the
    upgrade, so neither its principals nor its observations are news, and no summary opens."""
    admin = admins[0]
    profile(db, admin, clock)
    connection_id = connect(db, admin, clock)
    tenant = admin.tenant_id
    newcomer, assignments = reaching(9)
    scenario = detailed_scenario(principals=[newcomer], app_role_assignments=assignments)
    with serving(scenario) as server:
        full(db, admin, clock, connection_id, server)
        with admin_engine.begin() as conn:
            conn.execute(text("DELETE FROM execbound.monitor_deliveries"))
            conn.execute(text("DELETE FROM execbound.monitor_findings"))
            # As the code before this change left it, then as the upgrade backfills it.
            conn.execute(
                text(
                    "UPDATE execbound.monitor_agents SET first_seen_at = :old, "
                    "new_actor_opened_at = NULL, ai_consent_opened_at = NULL"
                ),
                {"old": clock.value - timedelta(days=3)},
            )
            conn.execute(
                text(
                    "UPDATE execbound.monitor_connections SET delta_link = NULL, "
                    "delta_at = NULL, baseline_at = :upgrade, last_sync_at = :old"
                ),
                {"upgrade": clock.value, "old": clock.value - timedelta(days=3)},
            )
        observe(
            admin_engine,
            tenant,
            connection_id,
            newcomer["id"],
            "identity.disable",
            clock.value - timedelta(days=1),
        )
        clock.value += timedelta(hours=7)
        result = full(db, admin, clock, connection_id, server)
    assert result["findings"]["inventory"] == 0 and result["findings"]["new_actor"] == 0
    assert store.evaluate_actions(db, admin, clock=clock)["raised"] == 0
    rules = {row["rule_version"] for row in findings(db, tenant)}
    assert not rules & {
        "initial-inventory.v1",
        "new-actor.v1",
        "new-ai-consent.v1",
        "first-consequential-action.v1",
    }
