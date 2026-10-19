# SPDX-License-Identifier: AGPL-3.0-only
"""Scout's Agents page as the to-do list, and the synthetic directory (#355, step 4): SR28 to SR32.

Real PostgreSQL, the fake Graph for a real directory and the synthetic directory's own in-process
transport for the synthetic one. An actor's class moves within the classic family as its stated
type and its consents do, and an agent identity never moves. The Agents page lists the actors in
the order of a to-do list, with what each did outside ExecBound, its open and accepted paths and
its strongest driver, cut after ordering. An acceptance renews and withdraws through the one
writer, with its history and its audit events. The synthetic directory is read in process, never
shares a workspace with a real directory, is never sent anywhere, governed or bound, and is
labelled wherever it is shown.
"""

import json
import os
import socket
import sys
from datetime import UTC, datetime, timedelta
from uuid import uuid4

import httpx
import pytest
from space_fixtures import default_space, make_space, place, seat, unseat
from sqlalchemy import text
from sqlalchemy.exc import DBAPIError
from test_context_provisioning import statements
from test_monitoring_store import FixedClock
from test_scout_audit import directory as audit_directory
from test_scout_audit import entry, executed, first_read, later
from test_scout_audit_retention import MONTH, elapse, purge
from test_scout_delta import admins as admins
from test_scout_delta import agent_row, delta, findings, full, profile, reaching
from test_scout_run import (
    AGENT_ONE,
    DISABLE_ROLE,
    GRAPH_RESOURCE,
    agent,
    connect,
    detailed_scenario,
    principal,
)

from execbound import administration, bindings
from execbound.administration import AdministrationError
from execbound.execution.scheduled import ScheduledActor
from execbound.identity import authenticate
from execbound.monitoring import collection, commands, consent, due, graph, store, synthetic, worker
from execbound.monitoring import connect as connecting
from execbound.monitoring.models import MonitorError
from execbound.notifications import Destination
from execbound.spaces import set_current_space
from execbound.surfaces import board
from execbound.surfaces.console_api.monitoring import removal
from execbound.surfaces.sessions import issue_session, load_session
from execbound_harness.fake_graph import serving
from execbound_harness.fake_tines import BASE_URL as TINES_URL

pytestmark = pytest.mark.integration

VENDOR = "0e0e0e0e-0000-4000-8000-000000000001"
APP = "a1a1a1a1-0000-4000-8000-000000000001"
SYNTHETIC_ACTIONS = ("identity.disable", "identity.revoke_sessions")
HOUR = timedelta(hours=1)


@pytest.fixture
def clock():
    return FixedClock(datetime.now(UTC))


def session_of(db, identity, clock):
    return load_session(db, issue_session(db, identity, clock=clock).token, clock=clock)


def classes(db, tenant):
    with db.transaction(tenant) as conn:
        return {
            row[0]: row[1]
            for row in conn.execute(
                text(
                    "SELECT platform_ref, identity_class FROM execbound.monitor_agents "
                    "WHERE gone_at IS NULL"
                )
            ).all()
        }


def consenting(*refs):
    """A delegated consent to read users for each of `refs`, which reaches nothing consequential."""
    return {
        ref: [{"clientId": ref, "resourceId": GRAPH_RESOURCE, "scope": "User.Read"}] for ref in refs
    }


def managed_identity(index):
    record = principal(index)
    record["servicePrincipalType"] = "ManagedIdentity"
    return record


def classic_directory(**changes):
    """An agent identity, one principal registered here, a managed identity, another
    organization's application holding a delegated consent and another's holding none."""
    values = {
        "agents": [agent(1)],
        "principals": [
            principal(11, appId=APP),
            managed_identity(12),
            principal(13, appOwnerOrganizationId=VENDOR),
            principal(14, appOwnerOrganizationId=VENDOR),
        ],
        "app_role_assignments": {},
        "delegated_grants": consenting(principal(13)["id"]),
        "member_of": {},
    }
    values.update(changes)
    return detailed_scenario(**values)


def run_synthetic(db, actor, clock, connection_id):
    """One collection of the synthetic directory. The client given is never used for it."""
    with httpx.Client() as unused:
        return graph.run(db, actor, connection_id=connection_id, client=unused, clock=clock)


@pytest.fixture
def no_network(monkeypatch):
    """Every way a process opens a socket, refused: the synthetic directory needs none."""
    attempts = []

    def refused(*args, **kwargs):
        attempts.append(args)
        raise OSError("SR31: no socket may be opened")

    monkeypatch.setattr(socket.socket, "connect", refused)
    monkeypatch.setattr(socket, "create_connection", refused)
    monkeypatch.setattr(socket, "getaddrinfo", refused)
    return attempts


def synthetic_workspace(db, admin, clock, actions=SYNTHETIC_ACTIONS):
    """A workspace with a detection profile (none for `actions` None) and its synthetic
    directory added and collected twice, an hour apart: its baseline, then the late principal."""
    if actions is not None:
        profile(db, admin, clock, actions=actions)
    connection_id = synthetic.add(db, session_of(db, admin, clock), clock=clock)
    first = run_synthetic(db, admin, clock, connection_id)
    clock.value += timedelta(hours=1)
    second = run_synthetic(db, admin, clock, connection_id)
    return connection_id, first, second


def snapshot(db, admin, clock):
    return store.agents_snapshot(db, session_of(db, admin, clock), clock=clock)


def by_ref(rows):
    return {row["platform_ref"]: row for row in rows}


# SR28: the identity classes.


def test_sr28_each_class_is_what_the_directory_states_and_consent_moves_it(db, admins, clock):
    admin = admins[0]
    connection_id = connect(db, admin, clock)
    owned, managed, consented, foreign = (principal(n)["id"] for n in (11, 12, 13, 14))
    with serving(classic_directory()) as server:
        assert full(db, admin, clock, connection_id, server)["outcome"] == "COMPLETE"
        assert classes(db, admin.tenant_id) == {
            AGENT_ONE: "agent_identity",
            owned: "service_principal",
            managed: "managed_identity",
            consented: "consented_app",
            # Another organization's application with no consent here is a classic principal.
            foreign: "service_principal",
        }
        # The application id is kept for the removal guidance, and only as a GUID.
        assert agent_row(db, admin.tenant_id, owned)["app_ref"] == APP
        assert agent_row(db, admin.tenant_id, managed)["app_ref"] is None
        # The consent moves from one application to the other: each class follows it.
        server.scenario.delegated_grants = consenting(foreign)
        clock.value += timedelta(minutes=5)
        full(db, admin, clock, connection_id, server)
    found = classes(db, admin.tenant_id)
    assert (found[consented], found[foreign]) == ("service_principal", "consented_app")
    assert (found[AGENT_ONE], found[managed]) == ("agent_identity", "managed_identity")


def test_sr28_an_agent_identity_never_moves_and_a_record_stating_no_type_keeps_the_class(
    db, admins, clock
):
    admin = admins[0]
    connection_id = connect(db, admin, clock)
    managed, consented = principal(12)["id"], principal(13)["id"]
    with serving(classic_directory()) as server:
        full(db, admin, clock, connection_id, server)
        # A delta entry carrying only what changed states no type: the class stays.
        server.scenario.delta = [
            {"id": managed, "displayName": "Renamed managed identity"},
            {"id": consented, "displayName": "Renamed consented app"},
        ]
        clock.value += timedelta(minutes=5)
        assert delta(db, admin, clock, connection_id, server)["outcome"] == "COMPLETE"
        assert classes(db, admin.tenant_id)[managed] == "managed_identity"
        assert classes(db, admin.tenant_id)[consented] == "consented_app"
        held = agent_row(db, admin.tenant_id, AGENT_ONE)
        assert held["blueprint_ref"] is not None and held["blueprint_object_ref"] is not None
        # The directory once calling an agent identity a classic principal moves nothing: the
        # collection completes, and the agent identity keeps its class and its blueprint.
        server.scenario.agents = []
        server.scenario.principals = [
            *server.scenario.principals,
            principal(1),
        ]
        clock.value += timedelta(minutes=5)
        assert full(db, admin, clock, connection_id, server)["outcome"] == "COMPLETE"
    assert classes(db, admin.tenant_id)[AGENT_ONE] == "agent_identity"
    kept = agent_row(db, admin.tenant_id, AGENT_ONE)
    assert (kept["blueprint_ref"], kept["blueprint_object_ref"]) == (
        held["blueprint_ref"],
        held["blueprint_object_ref"],
    )
    assert kept["observed_at"] > held["observed_at"]


def test_sr28_a_new_consented_app_with_ungoverned_reach_is_named_by_its_class(db, admins, clock):
    """New findings name the new classes; the rules themselves are unchanged (14 October ruling
    4: `new-actor.v1` and `ungoverned-reach.v1` both)."""
    admin = admins[0]
    profile(db, admin, clock)
    connection_id = connect(db, admin, clock)
    with serving(classic_directory()) as server:
        full(db, admin, clock, connection_id, server)
        newcomer, assignments = reaching(15, appOwnerOrganizationId=VENDOR)
        server.scenario.principals = [*server.scenario.principals, newcomer]
        server.scenario.app_role_assignments = assignments
        clock.value += timedelta(minutes=5)
        full(db, admin, clock, connection_id, server)
    assert classes(db, admin.tenant_id)[newcomer["id"]] == "consented_app"
    [announced] = findings(db, admin.tenant_id, "new-actor.v1")
    assert announced["platform_ref"] == newcomer["id"]
    assert announced["title"] == (
        "New consented app reaches a consequential action through a path nothing governs"
    )
    assert [
        row["platform_ref"] for row in findings(db, admin.tenant_id, "ungoverned-reach.v1")
    ] == [newcomer["id"]]


def test_sr28_an_application_id_that_is_not_a_guid_is_never_kept(db, admins, clock):
    assert graph.parse_agent(principal(11, appId="not-a-guid")).app_ref is None
    assert graph.parse_agent(principal(11, appId=APP)).app_ref == APP
    # The column refuses one too.
    admin = admins[0]
    connection_id = connect(db, admin, clock)
    with serving(classic_directory()) as server:
        full(db, admin, clock, connection_id, server)
    with pytest.raises(DBAPIError), db.transaction(admin.tenant_id) as conn:
        conn.execute(text("UPDATE execbound.monitor_agents SET app_ref = 'https://evil.invalid/x'"))


def test_sr28_a_principal_first_seen_by_a_delta_pass_keeps_its_application_id(db, admins, clock):
    """Most newcomers are first seen between full collections: the delta pass that inserts one
    keeps its application id as the full collection does, so its row names what to filter the
    enterprise applications by at once, and a restored principal gains one it lacked."""
    admin = admins[0]
    connection_id = connect(db, admin, clock)
    newcomer = principal(21, appId=APP)
    # Principal 14 was stored with no application id.
    lacking = principal(14)["id"]
    other = "b2b2b2b2-0000-4000-8000-000000000002"
    with serving(classic_directory()) as server:
        full(db, admin, clock, connection_id, server)
        assert agent_row(db, admin.tenant_id, lacking)["app_ref"] is None
        server.scenario.delta = [newcomer, {"id": lacking, "@removed": {"reason": "changed"}}]
        clock.value += timedelta(minutes=5)
        assert delta(db, admin, clock, connection_id, server)["changes"]["new"] == 1
        server.scenario.delta = [{"id": lacking, "appId": other}]
        clock.value += timedelta(minutes=5)
        assert delta(db, admin, clock, connection_id, server)["changes"]["restored"] == 1
    row = agent_row(db, admin.tenant_id, newcomer["id"])
    assert row["app_ref"] == APP
    assert agent_row(db, admin.tenant_id, lacking)["app_ref"] == other
    listed = by_ref(snapshot(db, admin, clock)["agents"])[newcomer["id"]]
    assert listed["app_ref"] == APP
    assert removal(listed["identity_class"], listed["source"]) == "entra"


# SR29: Did, the order and the tenant line.


def test_sr29_did_counts_successes_outside_execbound_and_the_order_puts_it_first(
    db, admins, admin_engine, clock
):
    """Did counts an actor's successful consequential observations of the last thirty days,
    baseline-era ones included; a failure and the one entry an execution ExecBound settled are
    left out (16 October Q4)."""
    admin = admins[0]
    profile(db, admin, clock)
    connection_id = connect(db, admin, clock)
    acting, other = principal(9)["id"], principal(10)["id"]
    before = clock.value - timedelta(days=2)
    with serving(audit_directory(entry(before))) as server:
        first_read(db, admin, clock, connection_id, server)
        dispatched = clock.value + timedelta(minutes=15)
        executed(admin_engine, admin, dispatched)
        later(
            db,
            admin,
            clock,
            connection_id,
            server,
            [
                entry(before),
                entry(dispatched + timedelta(seconds=1)),
                entry(clock.value + timedelta(minutes=20), result="failure"),
                entry(clock.value + timedelta(minutes=21), target=str(uuid4())),
            ],
            minutes=30,
        )
    clock.value += timedelta(minutes=1)
    rows = snapshot(db, admin, clock)
    found = by_ref(rows["agents"])
    assert found[acting]["did"] == 2 and found[acting]["did_at_least"] is False
    assert found[other]["did"] == 0 and found[other]["open_paths"] == 1
    assert rows["agents"][0]["platform_ref"] == acting

    session = session_of(db, admin, clock)

    def at_least():
        rows = store.agents_snapshot(db, session, clock=clock)["agents"]
        return by_ref(rows)[acting]["did_at_least"]

    def health(title, age):
        """A `collection-health.v1` finding on the connection, raised `age` ago."""
        finding = uuid4()
        with admin_engine.begin() as conn:
            conn.execute(
                text(
                    "INSERT INTO execbound.monitor_findings (tenant_id, finding_id, "
                    "connection_id, rule_version, title, created_at, space_id) "
                    "SELECT :t, :f, :c, 'collection-health.v1', :title, :at, m.space_id "
                    "FROM execbound.monitor_connections m WHERE m.connection_id = :c"
                ),
                {
                    "t": admin.tenant_id,
                    "f": finding,
                    "c": connection_id,
                    "title": title,
                    "at": clock.value - age,
                },
            )
        return finding

    # Repeats were dropped while a recent `CAPACITY` finding says the bound was met, under the
    # title it has now or the one it was raised with before 0095: never for an older one or
    # another health finding.
    health(store.HEALTH_TITLES["CAPACITY"], timedelta(days=31))
    health(store.HEALTH_TITLES["BACKLOG"], timedelta(days=1))
    assert at_least() is False
    recent = health(store.HEALTH_TITLES["CAPACITY"], timedelta(days=29))
    assert at_least() is True
    with admin_engine.begin() as conn:
        conn.execute(
            text("DELETE FROM execbound.monitor_findings WHERE finding_id = :f"), {"f": recent}
        )
    health("Collection reached the connection's observation bound and records no more", HOUR)
    assert at_least() is True
    with admin_engine.begin() as conn:
        conn.execute(
            text(
                "DELETE FROM execbound.monitor_findings WHERE rule_version = 'collection-health.v1'"
            )
        )
    assert at_least() is False
    # Without the bound, no count is "at least"; at it, every count of the connection is.
    with admin_engine.begin() as conn:
        conn.execute(
            text("UPDATE execbound.monitor_connections SET audit_bound_since = :n"),
            {"n": clock.value},
        )
    assert at_least() is True


def test_sr29_the_limit_is_applied_after_ordering_so_a_to_do_is_never_cut_by_its_name(
    db, admins, admin_engine, clock
):
    admin = admins[0]
    profile(db, admin, clock)
    connection_id = connect(db, admin, clock)
    tines = store.create_connection(
        db,
        admin,
        label="Tines tenant",
        base_url=TINES_URL,
        key_fingerprint=collection.fingerprint("tines-" + "k" * 32),
        clock=clock,
    )
    tenant = admin.tenant_id
    with admin_engine.begin() as conn:
        for index in range(store.AGENTS_SHOWN + 5):
            conn.execute(
                text(
                    "INSERT INTO execbound.monitor_agents (tenant_id, agent_id, connection_id, "
                    "platform_ref, identity_class, display_name, sponsors, sponsor_state, "
                    "first_seen_at, observed_at) VALUES (:t, :a, :c, :ref, 'service_principal', "
                    ":name, '[]'::jsonb, 'not_read', now(), now())"
                ),
                {
                    "t": tenant,
                    "a": uuid4(),
                    "c": connection_id,
                    "ref": f"aaaaaaaa-0000-4000-8000-{index:012d}",
                    "name": f"Actor {index:03d}" if index else "Zulu, which can act",
                },
            )
        conn.execute(
            text(
                "INSERT INTO execbound.monitor_agent_reach (tenant_id, agent_id, action, "
                "path_kind, path_ref, certainty, enforcement_mode, catalog_version, computed_at, "
                "valid_until) SELECT tenant_id, agent_id, 'identity.disable', 'grant', "
                "platform_ref, 'inferred', 'advisory', 'grants.1', now(), "
                "now() + interval '7 days' "
                "FROM execbound.monitor_agents WHERE display_name = 'Zulu, which can act'"
            )
        )
        # A Tines story with no driver row either: an actor, and never an unattributed one.
        conn.execute(
            text(
                "INSERT INTO execbound.monitor_agents (tenant_id, agent_id, connection_id, "
                "platform_ref, identity_class, display_name, sponsors, sponsor_state, "
                "first_seen_at, observed_at) VALUES (:t, :a, :c, '4001', 'tines_story', "
                "'A story', '[]'::jsonb, 'not_read', now(), now())"
            ),
            {"t": tenant, "a": uuid4(), "c": tines},
        )
    rows = snapshot(db, admin, clock)
    assert len(rows["agents"]) == store.AGENTS_SHOWN
    assert rows["agents"][0]["display_name"] == "Zulu, which can act"
    assert rows["agents"][0]["open_paths"] == 1
    assert rows["tenant"]["enumerated"] == store.AGENTS_SHOWN + 6
    assert rows["tenant"]["per_source"] == {
        "entra": store.AGENTS_SHOWN + 5,
        "tines": 1,
        "synthetic": 0,
    }
    # Counted over every directory actor, the ones past the page's cut among them.
    assert rows["tenant"]["unattributed"] == store.AGENTS_SHOWN + 5


def test_sr29_a_tines_row_attributes_and_points_only_where_its_space_is_seen(
    db, admins, admin_engine, clock
):
    """A Tines connection is its Space's: a session that does not see it reads an actor only it
    attributes as unattributed in the tenant line's figure as in the row, so the figure never
    tells it that something it cannot see attributes one. An actor whose strongest row is
    declared and which also has a live Tines row is Tines-driven, for the recipe's pointer,
    exactly where that row is seen, as on the agent page."""
    admin = admins[0]
    tenant = admin.tenant_id
    connection_id = connect(db, admin, clock)
    tines = store.create_connection(
        db,
        admin,
        label="Tines tenant",
        base_url=TINES_URL,
        key_fingerprint=collection.fingerprint("tines-" + "k" * 32),
        clock=clock,
    )
    only_tines, declared_too = uuid4(), uuid4()
    with admin_engine.begin() as conn:
        here = default_space(conn, tenant)
        other = make_space(conn, tenant, "Customer B")
        place(conn, tenant, "monitor_connections", "connection_id", tines, other)
        for index, agent_id in enumerate((only_tines, declared_too)):
            conn.execute(
                text(
                    "INSERT INTO execbound.monitor_agents (tenant_id, agent_id, connection_id, "
                    "platform_ref, identity_class, display_name, sponsors, sponsor_state, "
                    "first_seen_at, observed_at) VALUES (:t, :a, :c, :ref, 'service_principal', "
                    ":name, '[]'::jsonb, 'not_read', now(), now())"
                ),
                {
                    "t": tenant,
                    "a": agent_id,
                    "c": connection_id,
                    "ref": f"cccccccc-0000-4000-8000-{index:012d}",
                    "name": f"Driven {index}",
                },
            )
        for agent_id, evidence, ref in (
            (only_tines, "network", f"tines:{tines}"),
            (declared_too, "declared", "publisher:anthropic"),
            (declared_too, "network", f"tines:{tines}"),
        ):
            conn.execute(
                text(
                    "INSERT INTO execbound.monitor_actor_drivers (tenant_id, agent_id, evidence, "
                    "platform_ref, source_connection_id, first_seen_at, last_seen_at) "
                    "VALUES (:t, :a, :e, :p, :c, now(), now())"
                ),
                {"t": tenant, "a": agent_id, "e": evidence, "p": ref, "c": connection_id},
            )
    session = session_of(db, admin, clock)

    def looking_at(space):
        with db.transaction(tenant) as conn:
            set_current_space(conn, session, space)
        rows = store.agents_snapshot(db, session, clock=clock)
        found = {row["agent_id"]: row for row in rows["agents"]}
        unattributed = sum(1 for row in rows["agents"] if row["driver"] is None)
        return rows["tenant"]["unattributed"], unattributed, found

    # Looking at the Space the Tines connection is not in: neither row is seen.
    figure, labelled, found = looking_at(here)
    assert figure == labelled == 1
    assert found[only_tines]["driver"] is None and found[only_tines]["tines_driven"] is False
    assert found[declared_too]["driver"]["kind"] == "publisher"
    assert found[declared_too]["drivers_more"] == 0
    assert found[declared_too]["tines_driven"] is False
    # Looking at its Space: both are seen.
    figure, labelled, found = looking_at(other)
    assert figure == labelled == 0
    assert found[only_tines]["driver"]["kind"] == "tines"
    assert found[only_tines]["tines_driven"] is True
    assert found[declared_too]["driver"]["kind"] == "publisher"
    assert found[declared_too]["drivers_more"] == 1
    assert found[declared_too]["tines_driven"] is True
    # Revoking the Tines connection ends its rows: nothing it named drives either actor.
    store.revoke_connection(db, admin, tines, clock=clock)
    figure, labelled, found = looking_at(other)
    assert figure == labelled == 1
    assert found[declared_too]["tines_driven"] is False


def test_sr29_without_a_profile_nothing_is_done_or_open_and_the_line_says_so(db, admins, clock):
    admin = admins[0]
    connection_id = connect(db, admin, clock)
    with serving(audit_directory(entry(clock.value - timedelta(days=1)))) as server:
        first_read(db, admin, clock, connection_id, server)
    rows = snapshot(db, admin, clock)
    assert rows["tenant"]["assessed"] is False
    assert all(row["did"] == 0 and row["open_paths"] == 0 for row in rows["agents"])


# SR30: accepting a path, renewing and withdrawing it.


def acceptances(db, tenant):
    with db.transaction(tenant) as conn:
        return [
            dict(row)
            for row in conn.execute(
                text(
                    "SELECT change, action, path_kind, path_ref, reason_code, expires_at, "
                    "recorded_by, recorded_at FROM execbound.monitor_reach_acceptances "
                    "ORDER BY recorded_at"
                )
            ).mappings()
        ]


def exception_row(db, tenant):
    with db.transaction(tenant) as conn:
        return dict(
            conn.execute(text("SELECT * FROM execbound.monitor_reach_exceptions")).mappings().one()
        )


def events(admin_engine, tenant, *kinds):
    with admin_engine.connect() as conn:
        return [
            dict(row)
            for row in conn.execute(
                text(
                    "SELECT kind, payload FROM execbound.audit_events WHERE tenant_id = :t "
                    "AND kind = ANY(:k) ORDER BY sequence"
                ),
                {"t": tenant, "k": list(kinds)},
            ).mappings()
        ]


def one_reaching(db, admin, clock):
    """A directory with one classic principal that can disable users, collected."""
    profile(db, admin, clock)
    connection_id = connect(db, admin, clock)
    acting, assignments = reaching(9)
    scenario = detailed_scenario(
        agents=[],
        principals=[acting],
        app_role_assignments=assignments,
        delegated_grants={},
        member_of={},
    )
    with serving(scenario) as server:
        full(db, admin, clock, connection_id, server)
    with db.transaction(admin.tenant_id) as conn:
        path = (
            conn.execute(
                text(
                    "SELECT a.agent_id, r.action, r.path_kind, r.path_ref "
                    "FROM execbound.monitor_agent_reach r JOIN execbound.monitor_agents a "
                    "ON a.tenant_id = r.tenant_id AND a.agent_id = r.agent_id "
                    "WHERE r.action = 'identity.disable'"
                )
            )
            .mappings()
            .one()
        )
    return connection_id, acting["id"], dict(path), scenario


def colleague(db, admin_engine, admin, tmp_path):
    """Another workspace administrator of `admin`'s workspace, signed in with a credential of
    their own."""
    principal_id = uuid4()
    with admin_engine.begin() as conn:
        conn.execute(
            text(
                "INSERT INTO execbound.principals (tenant_id, principal_id, kind, label) "
                "VALUES (:t, :p, 'ADMIN', 'Second administrator')"
            ),
            {"t": admin.tenant_id, "p": principal_id},
        )
    issued = tmp_path / "colleague.token"
    administration.issue_credential(
        admin_engine,
        admin.tenant_id,
        principal_id,
        admin.principal_id,
        lifetime=timedelta(days=30),
        output=issued,
    )
    return authenticate(db, issued.read_text(encoding="utf-8").strip())


def test_sr30_a_renewal_after_expiry_renews_and_each_change_is_kept_and_audited(
    db, admins, admin_engine, clock, tmp_path
):
    """A renewal is a new decision: its reason, expiry, author and moment replace the first
    acceptance's, and both are kept in the history and the audit chain."""
    admin = admins[0]
    connection_id, ref, path, _ = one_reaching(db, admin, clock)
    second = colleague(db, admin_engine, admin, tmp_path)
    values = {
        "connection_id": connection_id,
        "platform_ref": ref,
        "action": path["action"],
        "path_kind": path["path_kind"],
        "path_ref": path["path_ref"],
    }
    store.accept_reach(
        db,
        admin,
        **values,
        reason_code="REVIEW_PENDING",
        expires_at=clock.value + timedelta(days=1),
        clock=clock,
    )
    assert by_ref(snapshot(db, admin, clock)["agents"])[ref]["open_paths"] == 0
    first = exception_row(db, admin.tenant_id)
    assert first["accepted_by"] == admin.principal_id
    clock.value += timedelta(days=2)
    # Expired: the path is open again.
    assert by_ref(snapshot(db, admin, clock)["agents"])[ref]["open_paths"] == 1
    # Renewed by another administrator.
    store.accept_reach(
        db,
        second,
        **values,
        reason_code="VENDOR_MANAGED",
        expires_at=clock.value + timedelta(days=90),
        clock=clock,
    )
    renewed = exception_row(db, admin.tenant_id)
    assert renewed["reason_code"] == "VENDOR_MANAGED"
    assert renewed["expires_at"] == clock.value + timedelta(days=90)
    assert renewed["withdrawn_at"] is None
    # Its author and moment replace the first's: the renewal's own, as its history row says.
    assert renewed["accepted_by"] == second.principal_id
    assert renewed["accepted_at"] > first["accepted_at"]
    row = by_ref(snapshot(db, admin, clock)["agents"])[ref]
    assert (row["open_paths"], row["accepted"]) == (0, 1)
    assert row["accepted_until"] == clock.value + timedelta(days=90)
    history = acceptances(db, admin.tenant_id)
    assert [(h["change"], h["reason_code"], h["recorded_by"]) for h in history] == [
        ("accepted", "REVIEW_PENDING", admin.principal_id),
        ("accepted", "VENDOR_MANAGED", second.principal_id),
    ]
    assert [h["recorded_at"] for h in history] == [first["accepted_at"], renewed["accepted_at"]]
    recorded = events(admin_engine, admin.tenant_id, "monitor.reach_accepted")
    assert [e["payload"]["reason_code"] for e in recorded] == ["REVIEW_PENDING", "VENDOR_MANAGED"]
    assert recorded[0]["payload"]["path_ref"] == path["path_ref"]


def test_sr30_a_withdrawal_reopens_the_path_and_the_episode_and_a_second_is_refused(
    db, admins, admin_engine, clock
):
    admin = admins[0]
    connection_id, ref, path, scenario = one_reaching(db, admin, clock)
    values = {
        "connection_id": connection_id,
        "platform_ref": ref,
        "action": path["action"],
        "path_kind": path["path_kind"],
        "path_ref": path["path_ref"],
    }
    assert len(findings(db, admin.tenant_id, "ungoverned-reach.v1")) == 1
    store.accept_reach(db, admin, **values, reason_code="BUSINESS_REQUIRED", clock=clock)
    with serving(scenario) as server:
        clock.value += timedelta(minutes=5)
        assert full(db, admin, clock, connection_id, server)["findings"]["resolved"] == 1
        store.withdraw_reach(db, admin, **values, clock=clock)
        assert by_ref(snapshot(db, admin, clock)["agents"])[ref]["open_paths"] == 1
        clock.value += timedelta(minutes=5)
        assert full(db, admin, clock, connection_id, server)["findings"]["ungoverned"] == 1
    assert len(findings(db, admin.tenant_id, "ungoverned-reach.v1")) == 2
    with pytest.raises(MonitorError) as refused:
        store.withdraw_reach(db, admin, **values, clock=clock)
    assert refused.value.code == "NOT_ACCEPTED"
    assert [h["change"] for h in acceptances(db, admin.tenant_id)] == ["accepted", "withdrawn"]
    [withdrawn] = events(admin_engine, admin.tenant_id, "monitor.reach_withdrawn")
    assert "reason_code" not in withdrawn["payload"]
    assert withdrawn["payload"]["agent_id"] == str(path["agent_id"])


def test_sr30_the_console_accepts_open_paths_only_for_a_listed_reason_and_period(
    db, admins, admin_engine, clock
):
    """Accept takes only open paths: live, to an action the profile calls consequential, and
    with no acceptance in force. A lapsed path, one the profile does not name and one already
    accepted are refused like a path the actor does not hold, and nothing is recorded."""
    admin = admins[0]
    _, ref, path, _ = one_reaching(db, admin, clock)
    session = session_of(db, admin, clock)
    held = (path["action"], path["path_kind"], path["path_ref"])

    def refused_with(paths=None, **changes):
        values = {"paths": paths or [held], "reason_code": "BREAK_GLASS", "days": 30, **changes}
        with pytest.raises(MonitorError) as refused:
            store.accept_paths(db, session, path["agent_id"], clock=clock, **values)
        return refused.value.code

    for changes in (
        {"reason_code": "NOT_IN_THE_LIST"},
        {"days": 7},
        {"paths": []},
        {"paths": [held, held]},
        {"paths": [("identity.disable", "grant", "a-path-it-does-not-hold")]},
    ):
        values = {"paths": [held], "reason_code": "BREAK_GLASS", "days": 30, **changes}
        with pytest.raises(MonitorError) as refused:
            store.accept_paths(db, session, path["agent_id"], clock=clock, **values)
        assert refused.value.code == "INVALID_INPUT", changes

    one = {"action": path["action"], "kind": path["path_kind"], "p": path["path_ref"]}

    def proof(computed, until):
        with admin_engine.begin() as conn:
            conn.execute(
                text(
                    "UPDATE execbound.monitor_agent_reach SET computed_at = :c, valid_until = :v "
                    "WHERE tenant_id = :t AND agent_id = :a AND action = :action "
                    "AND path_kind = :kind AND path_ref = :p"
                ),
                {"c": computed, "v": until, "t": admin.tenant_id, "a": path["agent_id"], **one},
            )

    # A lapsed path is not open.
    with admin_engine.connect() as conn:
        live = conn.execute(
            text(
                "SELECT computed_at, valid_until FROM execbound.monitor_agent_reach "
                "WHERE agent_id = :a AND action = :action AND path_kind = :kind AND path_ref = :p"
            ),
            {"a": path["agent_id"], **one},
        ).one()
    proof(clock.value - timedelta(hours=2), clock.value - timedelta(minutes=1))
    assert refused_with() == "INVALID_INPUT"
    proof(*live)
    # Nor is a path to an action the profile no longer calls consequential.
    profile(db, admin, clock, actions=("identity.revoke_sessions",))
    assert refused_with() == "INVALID_INPUT"
    profile(db, admin, clock)
    assert acceptances(db, admin.tenant_id) == []
    store.accept_paths(
        db, session, path["agent_id"], [held], reason_code="BREAK_GLASS", days=30, clock=clock
    )
    assert exception_row(db, admin.tenant_id)["expires_at"] == clock.value + timedelta(days=30)
    # Nor is one whose acceptance is in force: it is withdrawn first, or renewed once it expires.
    assert refused_with(reason_code="VENDOR_MANAGED") == "INVALID_INPUT"
    assert len(acceptances(db, admin.tenant_id)) == 1
    store.withdraw_path(db, session, path["agent_id"], held, clock=clock)
    assert exception_row(db, admin.tenant_id)["withdrawn_at"] is not None
    store.accept_paths(
        db, session, path["agent_id"], [held], reason_code="VENDOR_MANAGED", days=90, clock=clock
    )
    assert exception_row(db, admin.tenant_id)["reason_code"] == "VENDOR_MANAGED"
    with pytest.raises(MonitorError) as unknown:
        store.accept_paths(
            db, session, uuid4(), [held], reason_code="BREAK_GLASS", days=30, clock=clock
        )
    assert unknown.value.code == "AGENT_UNAVAILABLE"

    # Nor is any path of an actor gone from its directory, whatever its row still says: the
    # page reads none open, so it offers no Accept the store refuses.
    def open_paths():
        detail = store.agent_detail(db, session, path["agent_id"], clock=clock)
        return [(r["action"], r["path_kind"], r["path_ref"]) for r in detail["reach"] if r["open"]]

    store.withdraw_path(db, session, path["agent_id"], held, clock=clock)
    assert open_paths() == [held]
    with admin_engine.begin() as conn:
        conn.execute(
            text(
                "UPDATE execbound.monitor_agents SET gone_at = GREATEST(now(), first_seen_at) "
                "WHERE agent_id = :a"
            ),
            {"a": path["agent_id"]},
        )
    assert open_paths() == []
    with pytest.raises(MonitorError) as gone:
        store.accept_paths(
            db, session, path["agent_id"], [held], reason_code="BREAK_GLASS", days=30, clock=clock
        )
    assert gone.value.code == "AGENT_UNAVAILABLE"


def test_sr30_accept_and_withdraw_are_offered_only_where_the_session_may_make_them(
    db, admins, admin_engine, clock
):
    """The Agents page and an actor's page are the workspace's, but an acceptance is made in the
    Space of the actor's connection, by an administrator of that Space, and is refused elsewhere.
    Each row and each actor's page say whether this session may accept or withdraw there
    (`administered`), so no page offers Accept or Withdraw the store refuses: not to an
    administrator a membership narrows to other Spaces, and not to one who only approves in the
    actor's. The Space a session looks at is a view and changes neither."""
    admin = admins[0]
    tenant = admin.tenant_id
    _, ref, path, _ = one_reaching(db, admin, clock)
    agent_id = path["agent_id"]
    held = (path["action"], path["path_kind"], path["path_ref"])
    with admin_engine.connect() as conn:
        here = default_space(conn, tenant)
    with admin_engine.begin() as conn:
        elsewhere = make_space(conn, tenant, "Elsewhere")

    def offered(session):
        row = by_ref(store.agents_snapshot(db, session, clock=clock)["agents"])[ref]
        assert row["open_paths"] == 1
        detail = store.agent_detail(db, session, agent_id, clock=clock)["agent"]
        assert row["administered"] is detail["administered"]
        return row["administered"]

    def accept_refused(session):
        with pytest.raises(MonitorError) as refused:
            store.accept_paths(
                db, session, agent_id, [held], reason_code="BREAK_GLASS", days=30, clock=clock
            )
        return refused.value.code

    # A workspace administrator, whichever Space the session looks at.
    session = session_of(db, admin, clock)
    assert offered(session) is True
    with db.transaction(tenant) as conn:
        set_current_space(conn, session, elsewhere)
    assert offered(session) is True
    # Narrowed to another Space: the actor is listed, its Space is not one the session holds.
    with admin_engine.begin() as conn:
        seat(conn, tenant, elsewhere, admin.principal_id, "ADMIN")
    session = session_of(db, admin, clock)
    assert offered(session) is False
    assert accept_refused(session) == "AGENT_UNAVAILABLE"
    # Approving in the actor's Space reads it and administers nothing there.
    with admin_engine.begin() as conn:
        seat(conn, tenant, here, admin.principal_id, "HUMAN_APPROVER")
    session = session_of(db, admin, clock)
    assert offered(session) is False
    assert accept_refused(session) == "INVALID_ADMIN"
    # Seated as an administrator in the actor's Space, they accept and withdraw there.
    with admin_engine.begin() as conn:
        seat(conn, tenant, here, admin.principal_id, "ADMIN")
    session = session_of(db, admin, clock)
    assert offered(session) is True
    store.accept_paths(
        db, session, agent_id, [held], reason_code="BREAK_GLASS", days=30, clock=clock
    )
    store.withdraw_path(db, session, agent_id, held, clock=clock)
    assert [h["change"] for h in acceptances(db, tenant)] == ["accepted", "withdrawn"]


def test_sr30_the_runtime_writes_no_acceptance_but_through_its_functions(
    db, admins, admin_engine, clock
):
    admin = admins[0]
    _, ref, path, _ = one_reaching(db, admin, clock)
    for statement in (
        "INSERT INTO execbound.monitor_reach_exceptions (tenant_id, agent_id, action, path_kind, "
        "path_ref, accepted_by, accepted_at, reason_code) VALUES (:t, :a, 'identity.disable', "
        "'grant', :p, :by, now(), 'X')",
        "UPDATE execbound.monitor_reach_exceptions SET withdrawn_at = now()",
        "INSERT INTO execbound.monitor_reach_acceptances (tenant_id, acceptance_id, agent_id, "
        "action, path_kind, path_ref, change, reason_code, recorded_by, recorded_at) VALUES "
        "(:t, gen_random_uuid(), :a, 'identity.disable', 'grant', :p, 'accepted', 'X', :by, "
        "now())",
        "UPDATE execbound.monitor_reach_acceptances SET reason_code = 'Y'",
        "DELETE FROM execbound.monitor_reach_acceptances",
    ):
        with pytest.raises(DBAPIError) as refused, db.transaction(admin.tenant_id) as conn:
            conn.execute(
                text(statement),
                {
                    "t": admin.tenant_id,
                    "a": path["agent_id"],
                    "p": path["path_ref"],
                    "by": admin.principal_id,
                },
            )
        assert "permission denied" in str(refused.value.orig), statement
    # A workspace's fence holds the functions to its own actors.
    other = admins[1]
    with pytest.raises(MonitorError) as fenced:
        store.accept_paths(
            db,
            session_of(db, other, clock),
            path["agent_id"],
            [(path["action"], path["path_kind"], path["path_ref"])],
            reason_code="BREAK_GLASS",
            days=30,
            clock=clock,
        )
    assert fenced.value.code == "AGENT_UNAVAILABLE"


def callers(admin_engine, db, tenant, here):
    """Who calls a definer function directly: an approver, an agent, the scheduler, an
    administrator no longer active, one a membership narrows to another Space, one seated in
    `here` as an approver and one seated in `here` as an administrator."""
    with admin_engine.begin() as conn:
        elsewhere = make_space(conn, tenant, "Elsewhere")
        actors = {}
        for name, kind, active, space in (
            ("approver", "HUMAN_APPROVER", True, None),
            ("agent", "AGENT", True, here),
            ("inactive", "ADMIN", False, None),
            ("narrowed", "ADMIN", True, None),
            ("approving here", "ADMIN", True, None),
            ("seated", "ADMIN", True, None),
        ):
            actors[name] = uuid4()
            conn.execute(
                text(
                    "INSERT INTO execbound.principals "
                    "(tenant_id, principal_id, kind, active, space_id) "
                    "VALUES (:t, :p, :k, :a, :s)"
                ),
                {"t": tenant, "p": actors[name], "k": kind, "a": active, "s": space},
            )
        seat(conn, tenant, elsewhere, actors["narrowed"], "ADMIN")
        seat(conn, tenant, here, actors["approving here"], "HUMAN_APPROVER")
        seat(conn, tenant, here, actors["seated"], "ADMIN")
    with db.transaction(tenant) as conn:
        actors["scheduler"] = conn.execute(
            text("SELECT execbound.scheduler_actor() ->> 'principal_id'")
        ).scalar_one()
    return actors


def refusal(db, tenant, statement, params):
    """What a definer function raises when called directly, or None."""
    try:
        with db.transaction(tenant) as conn:
            conn.execute(text(statement), params)
    except DBAPIError as exc:
        return exc.orig.diag.message_primary
    return None


ACCEPT = (
    "SELECT execbound.admin_accept_reach(:a, :agent, :action, :kind, :path, 'BREAK_GLASS', NULL)"
)
WITHDRAW = "SELECT execbound.admin_withdraw_reach(:a, :agent, :action, :kind, :path)"


def test_sr30_the_acceptance_functions_check_the_actor_whatever_their_caller_checked(
    db, admins, admin_engine, clock
):
    """`accept-reach` reaches `admin_accept_reach` after the store's own administrator check
    alone, so the functions hold the rule themselves: called directly, each refuses an approver,
    an agent, the scheduler, an administrator no longer active, one narrowed to another Space and
    one seated in the actor's Space as an approver, and records for one seated there as an
    administrator. Accepting refuses an actor that is gone; a withdrawal is still recorded for
    one, so no acceptance outlives the record of it if the actor comes back."""
    admin = admins[0]
    tenant = admin.tenant_id
    connection_id, ref, path, _ = one_reaching(db, admin, clock)
    with admin_engine.connect() as conn:
        here = conn.execute(
            text(
                "SELECT space_id FROM execbound.monitor_connections "
                "WHERE tenant_id = :t AND connection_id = :c"
            ),
            {"t": tenant, "c": connection_id},
        ).scalar_one()
    actors = callers(admin_engine, db, tenant, here)
    params = {
        "agent": path["agent_id"],
        "action": path["action"],
        "kind": path["path_kind"],
        "path": path["path_ref"],
    }
    refused = ("approver", "agent", "scheduler", "inactive", "narrowed", "approving here")
    for name in refused:
        assert refusal(db, tenant, ACCEPT, {"a": actors[name], **params}) == "INVALID_ACTOR", name
    assert acceptances(db, tenant) == []
    assert refusal(db, tenant, ACCEPT, {"a": actors["seated"], **params}) is None
    for name in refused:
        assert refusal(db, tenant, WITHDRAW, {"a": actors[name], **params}) == "INVALID_ACTOR"
    assert [h["change"] for h in acceptances(db, tenant)] == ["accepted"]
    # The store's calls, narrowed to another Space, are refused before the functions are asked.
    with admin_engine.begin() as conn:
        seat(conn, tenant, make_space(conn, tenant, "Narrowing"), admin.principal_id, "ADMIN")
    for call in (store.accept_reach, store.withdraw_reach):
        reason = {"reason_code": "BREAK_GLASS"} if call is store.accept_reach else {}
        with pytest.raises(MonitorError) as narrowed:
            call(
                db,
                admin,
                connection_id=connection_id,
                platform_ref=ref,
                action=path["action"],
                path_kind=path["path_kind"],
                path_ref=path["path_ref"],
                clock=clock,
                **reason,
            )
        assert narrowed.value.code == "INVALID_ADMIN", call
    assert [h["change"] for h in acceptances(db, tenant)] == ["accepted"]
    # Gone from its directory: nothing new is accepted for it, and what stands is withdrawn.
    with admin_engine.begin() as conn:
        conn.execute(
            text("UPDATE execbound.monitor_agents SET gone_at = now() WHERE agent_id = :a"),
            {"a": path["agent_id"]},
        )
    accepting = {"a": actors["seated"], **params}
    assert refusal(db, tenant, ACCEPT, accepting) == "INVALID_AGENT"
    assert refusal(db, tenant, WITHDRAW, accepting) is None
    assert [h["change"] for h in acceptances(db, tenant)] == ["accepted", "withdrawn"]
    assert {h["recorded_by"] for h in acceptances(db, tenant)} == {actors["seated"]}


def command(monkeypatch, *argv):
    monkeypatch.setenv("DATABASE_URL", os.environ["TEST_DATABASE_URL"])
    monkeypatch.setattr(sys, "argv", ["commands", *argv])
    commands.main()


def test_sr30_the_accept_and_withdraw_commands_record_and_refuse_a_narrowed_administrator(
    db, admins, admin_engine, seeded, clock, tmp_path, monkeypatch, capsys
):
    """`accept-reach` and `withdraw-reach` record an acceptance and its withdrawal through the
    one writer, with their events. An administrator a membership narrows to another Space is
    refused `INVALID_ADMIN` by both, the command line says only that the command is unavailable,
    and nothing is recorded."""
    admin = admins[0]
    tenant = admin.tenant_id
    connection_id, ref, path, _ = one_reaching(db, admin, clock)
    credential = tmp_path / "admin.token"
    credential.write_text(seeded["tokens"][0] + "\n", encoding="utf-8")
    held = [
        *("--credential-file", str(credential), "--connection", str(connection_id)),
        *("--agent", ref, "--action", path["action"], "--path-kind", path["path_kind"]),
        *("--path", path["path_ref"]),
    ]
    accepting = ("accept-reach", *held, "--reason", "BREAK_GLASS", "--days", "30")
    withdrawing = ("withdraw-reach", *held)
    refused = []

    def watched(call):
        def wrapped(*args, **kwargs):
            try:
                return call(*args, **kwargs)
            except MonitorError as exc:
                refused.append(exc.code)
                raise

        return wrapped

    for name in ("accept_reach", "withdraw_reach"):
        monkeypatch.setattr(commands, name, watched(getattr(commands, name)))
    with admin_engine.begin() as conn:
        narrowing = make_space(conn, tenant, "Narrowing")
        seat(conn, tenant, narrowing, admin.principal_id, "ADMIN")
    for argv in (accepting, withdrawing):
        with pytest.raises(SystemExit) as exited:
            command(monkeypatch, *argv)
        assert exited.value.code == 2, argv[0]
        assert capsys.readouterr().err == (
            "Monitoring command unavailable. Check configuration, access and local services.\n"
        )
    assert refused == ["INVALID_ADMIN", "INVALID_ADMIN"]
    assert acceptances(db, tenant) == []
    with admin_engine.begin() as conn:
        unseat(conn, tenant, narrowing, admin.principal_id)
    command(monkeypatch, *accepting)
    assert "Acceptance recorded" in capsys.readouterr().out
    accepted = exception_row(db, tenant)
    assert accepted["reason_code"] == "BREAK_GLASS" and accepted["expires_at"] is not None
    command(monkeypatch, *withdrawing)
    assert "Acceptance withdrawn" in capsys.readouterr().out
    assert exception_row(db, tenant)["withdrawn_at"] is not None
    history = acceptances(db, tenant)
    assert [(h["change"], h["path_ref"], h["recorded_by"]) for h in history] == [
        ("accepted", path["path_ref"], admin.principal_id),
        ("withdrawn", path["path_ref"], admin.principal_id),
    ]
    kinds = ("monitor.reach_accepted", "monitor.reach_withdrawn")
    assert [e["kind"] for e in events(admin_engine, tenant, *kinds)] == list(kinds)
    assert refused == ["INVALID_ADMIN", "INVALID_ADMIN"]


def test_sr31_only_a_workspace_administrator_adds_it_since_it_holds_for_every_space(
    db, admins, admin_engine, clock
):
    """While it is present no Space connects Microsoft Entra, and adding it asks whether any
    Space ever did, so the synthetic directory is the whole workspace's: an administrator a
    membership narrows to their Spaces is refused, by the store before the function is asked and
    by the function called directly, as are an approver, an agent, the scheduler and an
    administrator no longer active. A workspace administrator adds it."""
    admin = admins[0]
    tenant = admin.tenant_id
    with admin_engine.connect() as conn:
        here = default_space(conn, tenant)
    actors = callers(admin_engine, db, tenant, here)
    add = "SELECT execbound.admin_add_synthetic_directory(:a, :s, :c)"
    for name in ("approver", "agent", "scheduler", "inactive", "narrowed", "seated"):
        found = refusal(db, tenant, add, {"a": actors[name], "s": here, "c": uuid4()})
        assert found == "INVALID_ACTOR", name
    with admin_engine.begin() as conn:
        customer = make_space(conn, tenant, "Customer A")
        seat(conn, tenant, customer, admin.principal_id, "ADMIN")
    with statements(db.engine) as sent, pytest.raises(MonitorError) as refused:
        synthetic.add(db, session_of(db, admin, clock), clock=clock)
    assert refused.value.code == "INVALID_ADMIN"
    assert not any("admin_add_synthetic_directory" in statement for statement in sent)
    with admin_engine.begin() as conn:
        unseat(conn, tenant, customer, admin.principal_id)
    # The workspace now has several Spaces: it lands in the one the session looks at.
    session = session_of(db, admin, clock)
    with db.transaction(tenant) as conn:
        set_current_space(conn, session, here)
    assert synthetic.add(db, session, clock=clock) is not None


# SR31: the synthetic directory.


def test_sr31_the_synthetic_directory_is_created_only_by_its_function(
    db, admins, admin_engine, clock
):
    """Its function is its one writer, and adding it appends `monitor.connection_created` with
    its kind, its credential mode and its fixed label, once: a refused add appends nothing."""
    admin = admins[0]
    with pytest.raises(MonitorError) as refused:
        store.create_connection(
            db,
            admin,
            label=synthetic.LABEL,
            base_url=synthetic.BASE_URL,
            key_fingerprint="ab" * 32,
            kind=synthetic.KIND,
            directory_ref=synthetic.DIRECTORY,
            client_ref=synthetic.CLIENT,
            clock=clock,
        )
    assert refused.value.code == "INVALID_INPUT"
    with pytest.raises(DBAPIError), db.transaction(admin.tenant_id) as conn:
        conn.execute(
            text(
                "INSERT INTO execbound.monitor_connections (tenant_id, connection_id, label, "
                "base_url, key_fingerprint, created_at, created_by, kind, directory_ref, "
                "client_ref, space_id) VALUES (:t, gen_random_uuid(), :label, :url, :f, now(), "
                ":by, 'fixture', :d, :c, (SELECT space_id FROM execbound.spaces LIMIT 1))"
            ),
            {
                "t": admin.tenant_id,
                "label": synthetic.LABEL,
                "url": synthetic.BASE_URL,
                "f": "ab" * 32,
                "by": admin.principal_id,
                "d": synthetic.DIRECTORY,
                "c": synthetic.CLIENT,
            },
        )
    connection_id = synthetic.add(db, session_of(db, admin, clock), clock=clock)
    with db.transaction(admin.tenant_id) as conn:
        row = (
            conn.execute(
                text("SELECT * FROM execbound.monitor_connections WHERE connection_id = :c"),
                {"c": connection_id},
            )
            .mappings()
            .one()
        )
    assert (row["kind"], row["credential_mode"], row["key_fingerprint"]) == (
        "fixture",
        "synthetic",
        None,
    )
    assert (row["label"], row["base_url"]) == (synthetic.LABEL, synthetic.BASE_URL)
    assert row["collect_requested_by"] == admin.principal_id
    [created] = events(admin_engine, admin.tenant_id, "monitor.connection_created")
    assert {
        key: created["payload"][key]
        for key in ("connection_id", "space_id", "kind", "credential_mode", "label")
    } == {
        "connection_id": str(connection_id),
        "space_id": str(row["space_id"]),
        "kind": "fixture",
        "credential_mode": "synthetic",
        "label": "Synthetic directory",
    }
    with pytest.raises(MonitorError) as again:
        synthetic.add(db, session_of(db, admin, clock), clock=clock)
    assert again.value.code == "CONNECTION_EXISTS"
    assert len(events(admin_engine, admin.tenant_id, "monitor.connection_created")) == 1


def inserted_synthetic(conn, admin, space):
    """A synthetic directory of its fixed shape inserted directly into `space`, as no writer but
    its function does."""
    conn.execute(
        text("SELECT set_config('execbound.tenant_id', :t, true)"), {"t": str(admin.tenant_id)}
    )
    conn.execute(
        text(
            "INSERT INTO execbound.monitor_connections (tenant_id, connection_id, label, "
            "base_url, created_at, created_by, kind, directory_ref, client_ref, space_id, "
            "credential_mode) VALUES (:t, gen_random_uuid(), :label, :url, now(), :by, "
            "'fixture', :d, :c, :s, 'synthetic')"
        ),
        {
            "t": admin.tenant_id,
            "s": space,
            "label": synthetic.LABEL,
            "url": synthetic.BASE_URL,
            "by": admin.principal_id,
            "d": synthetic.DIRECTORY,
            "c": synthetic.CLIENT,
        },
    )


def test_sr31_a_synthetic_directory_never_shares_a_workspace_with_a_real_one(
    db, admins, admin_engine, clock
):
    first, second = admins
    # A workspace that ever connected Microsoft Entra, even one revoked since, takes none.
    directory = connect(db, first, clock)
    with pytest.raises(MonitorError) as refused:
        synthetic.add(db, session_of(db, first, clock), clock=clock)
    assert refused.value.code == "DIRECTORY_CONNECTED"
    store.revoke_connection(db, first, directory, clock=clock)
    with pytest.raises(MonitorError) as still:
        synthetic.add(db, session_of(db, first, clock), clock=clock)
    assert still.value.code == "DIRECTORY_CONNECTED"
    # The other workspace adds one, and then may connect no directory until it is removed.
    added = synthetic.add(db, session_of(db, second, clock), clock=clock)
    with pytest.raises(MonitorError) as present:
        connect(db, second, clock)
    assert present.value.code == "SYNTHETIC_DIRECTORY_PRESENT"
    with pytest.raises(MonitorError) as consenting_refused:
        consent.start(
            db,
            session_of(db, second, clock),
            client_id=synthetic.CLIENT,
            authority="https://login.microsoftonline.com/organizations",
            origin="https://console.invalid",
            label="Our directory",
            clock=clock,
        )
    assert consenting_refused.value.code == "SYNTHETIC_DIRECTORY_PRESENT"
    # Whichever path inserts, the database refuses it too.
    with pytest.raises(DBAPIError) as trigger, admin_engine.begin() as conn:
        conn.execute(
            text("SELECT set_config('execbound.tenant_id', :t, true)"), {"t": str(second.tenant_id)}
        )
        conn.execute(
            text(
                "INSERT INTO execbound.monitor_connections (tenant_id, connection_id, label, "
                "base_url, key_fingerprint, created_at, created_by, kind, directory_ref, "
                "client_ref, space_id) VALUES (:t, gen_random_uuid(), 'Real', "
                "'https://graph.microsoft.com', :f, now(), :by, 'entra_agent_id', :d, :d, "
                "(SELECT space_id FROM execbound.spaces WHERE tenant_id = :t LIMIT 1))"
            ),
            {
                "t": second.tenant_id,
                "f": "ab" * 32,
                "by": second.principal_id,
                "d": str(uuid4()),
            },
        )
    assert trigger.value.orig.diag.message_primary == "SYNTHETIC_DIRECTORY_PRESENT"
    # Nor does the database take a synthetic directory beside a directory ever connected, or a
    # second beside one in another of the workspace's Spaces, however it is inserted: the
    # trigger and the index, not the function.
    with pytest.raises(DBAPIError) as beside, admin_engine.begin() as conn:
        inserted_synthetic(conn, first, default_space(conn, first.tenant_id))
    assert beside.value.orig.diag.message_primary == "DIRECTORY_CONNECTED"
    with pytest.raises(DBAPIError) as twice, admin_engine.begin() as conn:
        inserted_synthetic(conn, second, make_space(conn, second.tenant_id, "Customer B"))
    assert twice.value.orig.diag.constraint_name == "monitor_connections_one_synthetic"
    store.revoke_connection(db, second, added, clock=clock)
    assert connect(db, second, clock) is not None


def test_sr31_it_is_collected_in_process_and_shows_a_new_actor_after_its_baseline(
    db, admins, clock, no_network
):
    admin = admins[0]
    tenant = admin.tenant_id
    connection_id, first, second = synthetic_workspace(db, admin, clock)
    assert first["outcome"] == second["outcome"] == "COMPLETE"
    assert first["delta"] == "unavailable"
    assert first["findings"]["inventory"] == 1 and first["findings"]["new_actor"] == 0
    assert second["findings"]["new_actor"] == 1
    assert no_network == []
    row = by_ref(snapshot(db, admin, clock)["agents"])
    assert row[synthetic.LATE]["first_seen_at"] > row[synthetic.OFFBOARDING]["first_seen_at"]
    assert [f["platform_ref"] for f in findings(db, tenant, "new-actor.v1")] == [synthetic.LATE]
    assert synthetic.LATE in {
        f["platform_ref"] for f in findings(db, tenant, "ungoverned-reach.v1")
    }
    clock.value += timedelta(minutes=1)
    assert worker.evaluate_scheduled(db, tenant, clock=clock)["actions"] == 1
    [acted] = findings(db, tenant, "first-consequential-action.v1")
    assert acted["platform_ref"] == synthetic.LATE
    # The collection takes no delta link, and the connection gets no delta pass.
    with db.transaction(tenant) as conn:
        connection = dict(
            conn.execute(
                text("SELECT * FROM execbound.monitor_connections WHERE connection_id = :c"),
                {"c": connection_id},
            )
            .mappings()
            .one()
        )
    assert connection["delta_link"] is None and connection["baseline_at"] is not None
    assert not due.delta_eligible(connection, clock.value)


def test_sr31_one_click_is_enough_it_is_assessed_against_the_built_in_set_without_a_profile(
    db, admins, clock
):
    """Added with nothing else set, as the console's one click adds it, the synthetic directory
    is assessed against the built-in sensitive action set: the late actor's three findings, Did,
    open paths and Accept, and the page says which list it read. A profile, once set, decides for
    it too, and a real directory connected after it is removed is not assessed without one."""
    admin = admins[0]
    tenant = admin.tenant_id
    _, first, second = synthetic_workspace(db, admin, clock, actions=None)
    assert first["findings"]["inventory"] == 1 and second["findings"]["new_actor"] == 1
    assert [f["platform_ref"] for f in findings(db, tenant, "new-actor.v1")] == [synthetic.LATE]
    assert synthetic.LATE in {
        f["platform_ref"] for f in findings(db, tenant, "ungoverned-reach.v1")
    }
    clock.value += timedelta(minutes=1)
    assert worker.evaluate_scheduled(db, tenant, clock=clock)["actions"] == 1
    [acted] = findings(db, tenant, "first-consequential-action.v1")
    assert acted["platform_ref"] == synthetic.LATE
    rows = snapshot(db, admin, clock)
    assert (rows["tenant"]["assessed"], rows["tenant"]["built_in"]) == (True, True)
    assert rows["consequential"] == sorted(store.SENSITIVE_ACTIONS)
    found = by_ref(rows["agents"])
    assert found[synthetic.OFFBOARDING]["did"] >= synthetic.DAYS
    assert found[synthetic.REPORTING]["open_paths"] >= 1
    session = session_of(db, admin, clock)
    reporting = found[synthetic.REPORTING]["agent_id"]
    detail = store.agent_detail(db, session, reporting, clock=clock)
    paths = [(r["action"], r["path_kind"], r["path_ref"]) for r in detail["reach"] if r["open"]]
    assert paths
    store.accept_paths(
        db, session, reporting, paths, reason_code="GOVERNANCE_PLANNED", days=30, clock=clock
    )
    assert by_ref(snapshot(db, admin, clock)["agents"])[synthetic.REPORTING]["open_paths"] == 0
    # A profile decides once one is set, for the synthetic directory as for any.
    profile(db, admin, clock, actions=("identity.revoke_sessions",))
    rows = snapshot(db, admin, clock)
    assert rows["tenant"]["built_in"] is False
    assert rows["consequential"] == ["identity.revoke_sessions"]
    assert by_ref(rows["agents"])[synthetic.OFFBOARDING]["did"] == 0

    # Another workspace adds it, removes it and connects a real directory, with no profile.
    other = admins[1]
    added = synthetic.add(db, session_of(db, other, clock), clock=clock)
    store.revoke_connection(db, other, added, clock=clock)
    real = connect(db, other, clock)
    with serving(classic_directory()) as server:
        outcome = full(db, other, clock, real, server)
        assert outcome["outcome"] == "COMPLETE", outcome
    (summary,) = findings(db, other.tenant_id, "initial-inventory.v1")
    assert "not assessed" in summary["title"]
    rows = snapshot(db, other, clock)
    assert (rows["tenant"]["assessed"], rows["tenant"]["built_in"]) == (False, False)
    assert rows["consequential"] == []


def test_sr31_its_schedule_is_a_directory_s_and_one_out_of_range_is_refused_as_such(
    db, admins, admin_engine, clock
):
    """Collected as a real directory is, every one to twenty-four hours with no activity
    interval: anything else is refused `INVALID_SCHEDULE` by the function that sets it, before
    the table's check would refuse it, and nothing is written."""
    admin = admins[0]
    connection_id = synthetic.add(db, session_of(db, admin, clock), clock=clock)
    session = session_of(db, admin, clock)
    connecting.set_schedule(db, session, connection_id, collect=7200, activity=None, clock=clock)
    for collect, activity in ((1800, None), (90000, None), (None, 900), (7200, 300)):
        with pytest.raises(MonitorError) as refused:
            connecting.set_schedule(
                db, session, connection_id, collect=collect, activity=activity, clock=clock
            )
        assert refused.value.code == "INVALID_SCHEDULE", (collect, activity)
    with admin_engine.connect() as conn:
        assert conn.execute(
            text(
                "SELECT collect_interval_seconds, activity_interval_seconds "
                "FROM execbound.monitor_connections WHERE connection_id = :c"
            ),
            {"c": connection_id},
        ).one() == (7200, None)


def test_sr31_the_scheduled_collector_reads_it_without_a_key_file(db, admins, clock, no_network):
    admin = admins[0]
    profile(db, admin, clock, actions=SYNTHETIC_ACTIONS)
    synthetic.add(db, session_of(db, admin, clock), clock=clock)
    # Asked for when it was added, by the database's clock.
    clock.value = datetime.now(UTC) + timedelta(seconds=1)
    with httpx.Client() as unused:
        counts = due.collect_workspace(
            db, ScheduledActor(admin.tenant_id), key_files=None, client=unused, clock=clock
        )
    assert counts["collected"] == 1 and counts["no_key_file"] == 0 and counts["failed"] == 0
    assert no_network == []


def test_sr31_its_actors_classes_drivers_and_actions_appear_labelled(db, admins, clock):
    admin = admins[0]
    synthetic_workspace(db, admin, clock)
    rows = snapshot(db, admin, clock)
    found = by_ref(rows["agents"])
    assert {ref: row["identity_class"] for ref, row in found.items()} == {
        synthetic.AGENT: "agent_identity",
        synthetic.CONSENTED: "consented_app",
        synthetic.OFFBOARDING: "service_principal",
        synthetic.MANAGED: "managed_identity",
        synthetic.REPORTING: "service_principal",
        synthetic.LATE: "service_principal",
    }
    assert all(row["synthetic"] and row["source"] == "fixture" for row in rows["agents"])
    assert found[synthetic.OFFBOARDING]["driver"] == {
        "evidence": "network",
        "kind": "egress",
        "label": "Anthropic",
    }
    assert found[synthetic.CONSENTED]["driver"]["kind"] == "publisher"
    assert found[synthetic.AGENT]["driver"]["kind"] == "blueprint"
    assert found[synthetic.REPORTING]["driver"] is None
    assert found[synthetic.OFFBOARDING]["did"] >= synthetic.DAYS
    # What did the most comes first, then what is open.
    assert rows["agents"][0]["platform_ref"] == synthetic.OFFBOARDING
    assert rows["tenant"]["per_source"] == {"entra": 0, "tines": 0, "synthetic": 6}
    assert rows["tenant"]["unattributed"] == 3
    detail = store.agent_detail(
        db, session_of(db, admin, clock), found[synthetic.OFFBOARDING]["agent_id"], clock=clock
    )
    assert detail["agent"]["synthetic"] is True and detail["agent"]["source"] == "fixture"
    assert detail["agent"]["user_agent_hint"] == "python-requests/2.32.3"
    assert any(row["open"] for row in detail["reach"])


def test_sr31_its_findings_are_never_sent_and_a_delivery_of_one_is_refused(
    db, admins, admin_engine, clock
):
    admin = admins[0]
    tenant = admin.tenant_id
    synthetic_workspace(db, admin, clock)
    destination = Destination(
        "findings-chat",
        tenant,
        "https://alerts.example.net/execbound/findings",
        "f1nd-" + "w" * 32,
        classes=frozenset({"findings"}),
    )
    counts = worker.route_findings(db, admin, [destination], clock=clock)
    assert counts["queued"] == 0 and counts["closed"] >= 1
    with db.transaction(tenant) as conn:
        states = conn.execute(
            text("SELECT state, last_error, destination_id FROM execbound.monitor_deliveries")
        ).all()
    assert states and all(
        (state, error, sent) == ("FAILED", "SYNTHETIC_DIRECTORY", None)
        for state, error, sent in states
    )
    with pytest.raises(DBAPIError) as refused, db.transaction(tenant) as conn:
        conn.execute(
            text(
                "INSERT INTO execbound.monitor_deliveries (tenant_id, delivery_id, finding_id, "
                "destination_id, created_at, next_attempt_at) SELECT tenant_id, gen_random_uuid(), "
                "finding_id, 'findings-chat', now(), now() FROM execbound.monitor_findings LIMIT 1"
            )
        )
    assert refused.value.orig.diag.message_primary == "SYNTHETIC_DIRECTORY"
    rows = store.findings(db, session_of(db, admin, clock), "all", clock=clock)["findings"]
    assert rows and all(row["synthetic"] for row in rows)


def test_sr31_its_actors_are_never_governed_or_bound(db, admins, admin_engine, clock):
    from test_scout_derived import governed_agent

    admin = admins[0]
    tenant = admin.tenant_id
    connection_id, _, _ = synthetic_workspace(db, admin, clock)
    principal_id, _ = governed_agent(admin_engine, tenant)
    with pytest.raises(MonitorError) as linked:
        store.link_agent(
            db,
            admin,
            connection_id=connection_id,
            platform_ref=synthetic.OFFBOARDING,
            principal_id=principal_id,
            clock=clock,
        )
    assert linked.value.code == "SYNTHETIC_ACTOR"
    actor = agent_row(db, tenant, synthetic.OFFBOARDING)["agent_id"]
    with pytest.raises(AdministrationError) as bound, db.transaction(tenant) as conn:
        bindings.bind(conn, admin, actor, principal_id)
    assert bound.value.code == "SYNTHETIC_ACTOR"
    with db.transaction(tenant) as conn:
        assert conn.execute(text("SELECT count(*) FROM execbound.agent_bindings")).scalar_one() == 0


def audit_rows(admin_engine, tenant):
    """The workspace's directory audit observations: each one's actor, action and moment."""
    with admin_engine.connect() as conn:
        return {
            row["observation_id"]: (row["actor_ref"], row["action"], row["occurred_at"])
            for row in conn.execute(
                text(
                    "SELECT observation_id, actor_ref, action, occurred_at "
                    "FROM execbound.monitor_observations "
                    "WHERE tenant_id = :t AND kind = 'entra_audit'"
                ),
                {"t": tenant},
            ).mappings()
        }


def test_sr31_its_audit_observations_age_out_as_a_directory_s(db, admins, admin_engine, clock):
    """`process` ends by purging the synthetic directory's audit observations as it purges a
    Microsoft Entra directory's: the store visits both kinds and 0099 widens
    `monitor_audit_purge` to both. Once a month has passed, an actor's daily repeats go, its
    first action and what a finding cites stay, and the next pass finds nothing more."""
    admin = admins[0]
    tenant = admin.tenant_id
    synthetic_workspace(db, admin, clock)
    assert worker.evaluate_scheduled(db, tenant, clock=clock)["purged"] == 0
    before = audit_rows(admin_engine, tenant)
    repeats = [ref for ref, (actor, _, _) in before.items() if actor == synthetic.OFFBOARDING]
    assert len(repeats) >= synthetic.DAYS
    elapse(admin_engine, tenant, MONTH)
    removed = purge(db, tenant, clock)
    after = audit_rows(admin_engine, tenant)
    assert removed == len(before) - len(after) >= synthetic.DAYS - 1
    assert set(after) < set(before)
    # Each actor keeps its first action, the habit's first among them.
    firsts = {}
    for ref, (actor, action, _) in sorted(before.items(), key=lambda item: item[1][2]):
        firsts.setdefault((actor, action), ref)
    assert set(firsts.values()) <= set(after)
    assert purge(db, tenant, clock) == 0


def test_sr31_removing_it_takes_its_actors_off_the_lists_and_keeps_its_findings(db, admins, clock):
    """Removed, its actors are gone as a full collection leaves a principal it no longer lists:
    their drivers, grants and the paths those grants established stop being live claims, so no
    page reads an open path for one or offers to accept it, and what it raised stays."""
    admin = admins[0]
    tenant = admin.tenant_id
    connection_id, _, _ = synthetic_workspace(db, admin, clock)
    raised = len(findings(db, tenant))
    reporting = agent_row(db, tenant, synthetic.REPORTING)["agent_id"]
    before = store.agent_detail(db, session_of(db, admin, clock), reporting, clock=clock)
    assert any(row["open"] for row in before["reach"])
    store.revoke_connection(db, admin, connection_id, clock=clock)
    rows = snapshot(db, admin, clock)
    assert rows["agents"] == [] and rows["tenant"]["per_source"]["synthetic"] == 0
    live = {
        "drivers": "SELECT count(*) FROM execbound.monitor_actor_drivers WHERE gone_at IS NULL",
        "grants": "SELECT count(*) FROM execbound.monitor_agent_grants WHERE gone_at IS NULL",
        "paths": (
            "SELECT count(*) FROM execbound.monitor_agent_reach "
            "WHERE gone_at IS NULL AND path_kind <> 'observation'"
        ),
    }
    with db.transaction(tenant) as conn:
        assert {name: conn.execute(text(sql)).scalar_one() for name, sql in live.items()} == {
            "drivers": 0,
            "grants": 0,
            "paths": 0,
        }
    after = store.agent_detail(db, session_of(db, admin, clock), reporting, clock=clock)
    assert after["reach"] and not any(row["open"] for row in after["reach"])
    assert len(findings(db, tenant)) == raised
    # Removed, it no longer stands in the way of a real directory.
    assert connect(db, admin, clock) is not None


def test_sr31_home_neither_counts_it_as_watching_nor_draws_its_observations(db, admins, clock):
    admin = admins[0]
    tenant = admin.tenant_id
    synthetic_workspace(db, admin, clock)
    with db.transaction(tenant) as conn:
        watching = conn.execute(
            text(board._WATCHING), {"t": tenant, "scoped": False, "read_spaces": []}
        ).scalar_one()
        drawn = conn.execute(
            text(board._OBSERVATIONS),
            {
                "t": tenant,
                "since": clock.value - timedelta(days=30),
                "scoped": False,
                "read_spaces": [],
                "observations": 100,
                "allowance": store.SETTLED_ALLOWANCE,
                "settled_since": None,
            },
        ).all()
    assert watching is False and drawn == []


def test_sr31_nothing_but_the_dataset_s_names_and_hints_is_kept_or_shown(db, admins, clock):
    admin = admins[0]
    synthetic_workspace(db, admin, clock)
    with db.transaction(admin.tenant_id) as conn:
        kept = json.dumps(
            {
                table: [
                    {key: str(value) for key, value in row.items()}
                    for row in conn.execute(text(f"SELECT * FROM execbound.{table}")).mappings()
                ]
                for table in (
                    "monitor_agents",
                    "monitor_connections",
                    "monitor_observations",
                    "monitor_actor_drivers",
                    "monitor_findings",
                )
            }
        )
    for forbidden in (
        synthetic.ANTHROPIC_ADDRESS,
        synthetic.NOBODY_ADDRESS,
        synthetic.SECRET,
        synthetic.TOKEN,
        "signInEventTypes",
    ):
        assert forbidden not in kept, forbidden


# SR32: where an actor's access is removed.


def test_sr32_the_removal_guidance_is_the_classes_and_only_a_real_directory_s(db, admins, clock):
    assert removal("service_principal", "entra_agent_id") == "entra"
    assert removal("consented_app", "entra_agent_id") == "entra"
    assert removal("managed_identity", "entra_agent_id") == "azure_resource"
    assert removal("agent_identity", "entra_agent_id") == "blueprint"
    assert removal("service_principal", "fixture") is None
    assert removal("tines_story", "tines") is None
    assert removal("an invented class", "entra_agent_id") is None


def test_sr32_the_synthetic_dataset_holds_the_catalogued_ids_it_claims():
    """The dataset's own claims, held to the catalogs it names, so a catalog change fails here."""
    from execbound.monitoring import ai_publishers, egress

    assert ai_publishers.PRODUCTION.match(app_ref=synthetic.ANTHROPIC_APP) == "anthropic"
    platform = egress.PRODUCTION.match(synthetic.ANTHROPIC_ADDRESS)
    assert platform is not None and platform.key == "anthropic"
    assert egress.PRODUCTION.match(synthetic.NOBODY_ADDRESS) is None
    assert store.SYNTHETIC_KIND == synthetic.KIND
    assert DISABLE_ROLE != synthetic.DISABLE_ROLE
