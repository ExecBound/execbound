# SPDX-License-Identifier: AGPL-3.0-only
"""The three agent rules: SR4, SR5's finding half, SR6, SR7 and SR10.

The governed path is the one that matters here. Registering a mapping adds a route; it does
not remove the agent's own grant, so the finding stays open until that grant is gone or an
ADMIN says the organization accepts it.
"""

from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import text
from test_monitoring_store import FixedClock
from test_monitoring_store import admins as admins
from test_scout_derived import governed_agent
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

from execbound.identity import authenticate
from execbound.monitoring import graph, store
from execbound.monitoring.models import DetectionProfile, MonitorError
from execbound_harness.fake_graph import SECRET, serving

pytestmark = pytest.mark.integration

CONSEQUENTIAL = ("identity.disable", "identity.revoke_sessions")
DISABLE_ROLE_PATH = AGENT_ONE


@pytest.fixture
def clock():
    return FixedClock(datetime.now(UTC))


def profile(db, admin, clock, actions=CONSEQUENTIAL):
    return store.set_profile(
        db,
        admin,
        DetectionProfile(sensitive_actions=tuple(actions), restricted_targets=()),
        clock=clock,
    )


def findings(db, tenant, rule=None):
    with db.transaction(tenant) as conn:
        rows = (
            conn.execute(
                text(
                    "SELECT rule_version, title, agent_id, connection_id FROM "
                    "execbound.monitor_findings ORDER BY created_at, rule_version"
                )
            )
            .mappings()
            .all()
        )
    return [row for row in rows if rule is None or row["rule_version"] == rule]


def collect(db, admin, clock, connection_id, scenario=None, server=None):
    with serving(scenario or detailed_scenario()) as running, client(running) as http:
        return graph.run(
            db,
            admin,
            connection_id=connection_id,
            client_secret=SECRET,
            client=http,
            clock=clock,
        ), running


def test_an_agent_with_ungoverned_consequential_reach_raises_one_finding(db, admins, clock):
    admin = admins[0]
    profile(db, admin, clock)
    connection_id = connect(db, admin, clock)
    result, _ = collect(db, admin, clock, connection_id)
    assert result["findings"]["ungoverned"] == 1
    raised = findings(db, admin.tenant_id, "ungoverned-reach.v1")
    assert len(raised) == 1
    assert raised[0]["agent_id"] is not None
    # The finding names the agent, which is what carries the sponsor that has to act.
    with db.transaction(admin.tenant_id) as conn:
        sponsors = conn.execute(
            text(
                "SELECT a.sponsors FROM execbound.monitor_agents a "
                "JOIN execbound.monitor_findings f ON f.agent_id = a.agent_id "
                "WHERE f.rule_version = 'ungoverned-reach.v1'"
            )
        ).scalar_one()
    assert sponsors == [{"kind": "user", "ref": "cccccccc-0000-4000-8000-000000000001"}]


def test_a_tenant_with_no_sensitive_list_reports_insufficient_evidence(db, admins, clock):
    """Without a list of what matters, the rule has no subject. It says so rather than
    matching every action in the catalog."""
    admin = admins[0]
    connection_id = connect(db, admin, clock)
    result, _ = collect(db, admin, clock, connection_id)
    assert result["findings"]["ungoverned"] == 0
    assert result["findings"]["insufficient"] >= 1
    assert findings(db, admin.tenant_id, "ungoverned-reach.v1") == []

    # An empty list is the same answer as no list at all.
    profile(db, admin, clock, actions=())
    clock.value += timedelta(minutes=5)
    result, _ = collect(db, admin, clock, connection_id)
    assert result["findings"]["ungoverned"] == 0
    assert findings(db, admin.tenant_id, "ungoverned-reach.v1") == []


def test_registering_a_governed_path_does_not_close_the_finding(db, admins, admin_engine, clock):
    admin = admins[0]
    profile(db, admin, clock)
    connection_id = connect(db, admin, clock)
    collect(db, admin, clock, connection_id)
    assert len(findings(db, admin.tenant_id, "ungoverned-reach.v1")) == 1

    bundle(
        admin_engine,
        admin.tenant_id,
        admin.principal_id,
        [{"operation_ref": "identity.disable", "action": "identity.disable"}],
    )
    store.link_agent(
        db,
        admin,
        connection_id=connection_id,
        platform_ref=AGENT_ONE,
        principal_id=governed_agent(admin_engine, admin.tenant_id)[0],
        clock=clock,
    )
    clock.value += timedelta(minutes=5)
    result, _ = collect(db, admin, clock, connection_id)
    # A governed route is an additional path, not the removal of the one the agent had.
    assert result["findings"]["resolved"] == 0
    assert len(findings(db, admin.tenant_id, "ungoverned-reach.v1")) == 1
    with db.transaction(admin.tenant_id) as conn:
        assert (
            conn.execute(
                text("SELECT reach_gap_opened_at FROM execbound.monitor_agents")
            ).scalar_one()
            is not None
        )


def test_losing_the_grant_closes_the_episode(db, admins, clock):
    admin = admins[0]
    # One consequential action, so what closes the episode is unambiguous.
    profile(db, admin, clock, actions=("identity.disable",))
    connection_id = connect(db, admin, clock)
    scenario = detailed_scenario()
    with serving(scenario) as server, client(server) as http:
        graph.run(
            db, admin, connection_id=connection_id, client_secret=SECRET, client=http, clock=clock
        )
        assert len(findings(db, admin.tenant_id, "ungoverned-reach.v1")) == 1
        server.scenario.app_role_assignments = {AGENT_ONE: []}
        server.scenario.member_of = {AGENT_ONE: []}
        clock.value += timedelta(minutes=5)
        result = graph.run(
            db, admin, connection_id=connection_id, client_secret=SECRET, client=http, clock=clock
        )
    assert result["findings"]["resolved"] == 1
    with db.transaction(admin.tenant_id) as conn:
        assert (
            conn.execute(
                text("SELECT reach_gap_opened_at FROM execbound.monitor_agents")
            ).scalar_one()
            is None
        )
    # The finding stays for a person to read; what closed is the episode.
    assert len(findings(db, admin.tenant_id, "ungoverned-reach.v1")) == 1


def test_an_accepted_path_closes_the_episode_and_stays_on_the_record(db, admins, clock):
    admin = admins[0]
    profile(db, admin, clock)
    connection_id = connect(db, admin, clock)
    collect(db, admin, clock, connection_id)
    with db.transaction(admin.tenant_id) as conn:
        paths = (
            conn.execute(
                text(
                    "SELECT action, path_kind, path_ref FROM execbound.monitor_agent_reach "
                    "WHERE action = ANY(:a) AND path_kind IN ('grant','role')"
                ),
                {"a": list(CONSEQUENTIAL)},
            )
            .mappings()
            .all()
        )
    for path in paths:
        store.accept_reach(
            db,
            admin,
            connection_id=connection_id,
            platform_ref=AGENT_ONE,
            action=path["action"],
            path_kind=path["path_kind"],
            path_ref=path["path_ref"],
            reason_code="BUSINESS_ACCEPTED",
            clock=clock,
        )
    clock.value += timedelta(minutes=5)
    result, _ = collect(db, admin, clock, connection_id)
    assert result["findings"]["resolved"] == 1
    # Every accepted route is still there, still live: an acceptance is a decision to live
    # with the path, not a claim that it closed.
    with db.transaction(admin.tenant_id) as conn:
        live = conn.execute(
            text(
                "SELECT count(*) FROM execbound.monitor_agent_reach "
                "WHERE gone_at IS NULL AND path_kind IN ('grant','role') "
                "AND action = ANY(:a)"
            ),
            {"a": list(CONSEQUENTIAL)},
        ).scalar_one()
    assert live == len(paths)


def test_an_expired_acceptance_reopens_a_new_episode(db, admins, admin_engine, seeded, clock):
    # The acceptance has to outlive a day, so the ADMIN credential has to as well; the
    # identity carries the expiry it was issued with, so it is taken again afterwards.
    with admin_engine.begin() as conn:
        conn.execute(
            text("UPDATE execbound.credentials SET expires_at = now() + interval '30 days'")
        )
    admin = authenticate(db, seeded["tokens"][0])
    profile(db, admin, clock, actions=("identity.disable",))
    connection_id = connect(db, admin, clock)
    collect(db, admin, clock, connection_id)
    with db.transaction(admin.tenant_id) as conn:
        paths = (
            conn.execute(
                text(
                    "SELECT action, path_kind, path_ref FROM execbound.monitor_agent_reach "
                    "WHERE action = 'identity.disable' AND path_kind IN ('grant','role')"
                )
            )
            .mappings()
            .all()
        )
    for path in paths:
        store.accept_reach(
            db,
            admin,
            connection_id=connection_id,
            platform_ref=AGENT_ONE,
            action=path["action"],
            path_kind=path["path_kind"],
            path_ref=path["path_ref"],
            reason_code="REVIEW_PENDING",
            expires_at=clock.value + timedelta(days=1),
            clock=clock,
        )
    clock.value += timedelta(minutes=5)
    collect(db, admin, clock, connection_id)
    assert len(findings(db, admin.tenant_id, "ungoverned-reach.v1")) == 1

    clock.value += timedelta(days=2)
    result, _ = collect(db, admin, clock, connection_id)
    assert result["findings"]["ungoverned"] == 1
    # A second episode, so the reviewer sees the acceptance lapsed rather than nothing.
    assert len(findings(db, admin.tenant_id, "ungoverned-reach.v1")) == 2


def test_an_agent_with_no_sponsor_is_a_finding_and_a_refused_read_is_not(db, admins, clock):
    admin = admins[0]
    # The rule only speaks about principals that reach something the tenant calls
    # consequential; without that it degenerates into "this tenant has service principals".
    profile(db, admin, clock)
    connection_id = connect(db, admin, clock)
    scenario = detailed_scenario(sponsors={})
    result, _ = collect(db, admin, clock, connection_id, scenario=scenario)
    assert result["findings"]["sponsorless"] == 1
    assert len(findings(db, admin.tenant_id, "sponsorless-agent.v1")) == 1

    # The directory now refuses the read. That is not the agent acquiring a sponsor, and it
    # is not the agent lacking one either.
    scenario = detailed_scenario(sponsors={}, status={"sponsors": 403})
    clock.value += timedelta(minutes=5)
    result, _ = collect(db, admin, clock, connection_id, scenario=scenario)
    assert result["findings"]["sponsorless"] == 0
    assert result["findings"]["insufficient"] >= 1
    assert len(findings(db, admin.tenant_id, "sponsorless-agent.v1")) == 1


def test_a_classic_principal_with_no_owner_is_the_same_gap(db, admins, clock):
    admin = admins[0]
    profile(db, admin, clock)
    connection_id = connect(db, admin, clock)
    classic = principal(9)
    scenario = detailed_scenario(
        agents=[],
        principals=[classic],
        owners={},
        sponsors={},
        # Reach is what makes an unowned principal worth reporting, and a classic service
        # principal is where consequential reach actually lives in a real directory.
        app_role_assignments={
            classic["id"]: [
                {
                    "appRoleId": DISABLE_ROLE,
                    "resourceId": GRAPH_RESOURCE,
                    "principalId": classic["id"],
                }
            ]
        },
        member_of={},
    )
    result, _ = collect(db, admin, clock, connection_id, scenario=scenario)
    assert result["findings"]["sponsorless"] == 1


def test_a_principal_another_organization_owns_is_not_ours_to_sponsor(db, admins, clock):
    """A live directory holds two dozen of Microsoft's own service principals, none owned.
    Asking anyone to take accountability for the Workload Identity Control Plane is how
    people are taught to ignore findings."""
    admin = admins[0]
    profile(db, admin, clock)
    connection_id = connect(db, admin, clock)
    foreign = principal(9, appOwnerOrganizationId="f8cdef31-a31e-4b4a-93e4-5f571e91255a")
    scenario = detailed_scenario(
        agents=[],
        principals=[foreign],
        owners={},
        sponsors={},
        app_role_assignments={
            foreign["id"]: [
                {
                    "appRoleId": DISABLE_ROLE,
                    "resourceId": GRAPH_RESOURCE,
                    "principalId": foreign["id"],
                }
            ]
        },
        member_of={},
    )
    result, _ = collect(db, admin, clock, connection_id, scenario=scenario)
    assert result["findings"]["sponsorless"] == 0
    assert findings(db, admin.tenant_id, "sponsorless-agent.v1") == []
    # It is not hidden: the principal and its reach are still collected and shown.
    with db.transaction(admin.tenant_id) as conn:
        row = conn.execute(text("SELECT owner_org_ref FROM execbound.monitor_agents")).scalar_one()
        reach = conn.execute(
            text("SELECT count(*) FROM execbound.monitor_agent_reach WHERE gone_at IS NULL")
        ).scalar_one()
    assert row == "f8cdef31-a31e-4b4a-93e4-5f571e91255a"
    assert reach > 0


def test_an_unowned_principal_that_reaches_nothing_is_not_worth_reporting(db, admins, clock):
    admin = admins[0]
    profile(db, admin, clock)
    connection_id = connect(db, admin, clock)
    quiet = principal(9)
    scenario = detailed_scenario(
        agents=[],
        principals=[quiet],
        owners={},
        sponsors={},
        app_role_assignments={},
        delegated_grants={},
        member_of={},
    )
    result, _ = collect(db, admin, clock, connection_id, scenario=scenario)
    assert result["findings"]["sponsorless"] == 0


def test_a_principal_first_seen_after_the_baseline_is_news_only_when_it_can_act(db, admins, clock):
    """`new-agent.v1` reported every principal first seen since the last run, whatever it could
    do; `new-actor.v1` replaces it and reports one only when it reaches a consequential action
    through a path nothing governs (#355). That a retained `new-agent.v1` finding stays readable
    is shown across the migration, over HTTP and in the console's findings list (SR16)."""
    admin = admins[0]
    profile(db, admin, clock)
    connection_id = connect(db, admin, clock)
    # The first run is the baseline, so nothing is "new since" anything.
    result, _ = collect(db, admin, clock, connection_id)
    assert result["findings"]["new_actor"] == 0

    scenario = detailed_scenario()
    reaching = principal(9)
    scenario.agents = [*scenario.agents, agent(2)]
    scenario.principals = [reaching]
    scenario.app_role_assignments = {
        **scenario.app_role_assignments,
        reaching["id"]: [
            {"appRoleId": DISABLE_ROLE, "resourceId": GRAPH_RESOURCE, "principalId": reaching["id"]}
        ],
    }
    clock.value += timedelta(minutes=5)
    result, _ = collect(db, admin, clock, connection_id, scenario=scenario)
    assert result["findings"]["new_actor"] == 1
    assert findings(db, admin.tenant_id, "new-agent.v1") == []
    raised = findings(db, admin.tenant_id, "new-actor.v1")
    assert len(raised) == 1
    assert "service principal" in raised[0]["title"]


def test_accepting_a_path_refuses_an_agent_or_a_reason_it_cannot_record(db, admins, clock):
    admin = admins[0]
    connection_id = connect(db, admin, clock)
    collect(db, admin, clock, connection_id)
    for changes, code in (
        ({"platform_ref": "aaaaaaaa-0000-4000-8000-000000009999"}, "AGENT_UNAVAILABLE"),
        ({"reason_code": "lower case"}, "INVALID_INPUT"),
        ({"action": "not-an-action"}, "INVALID_INPUT"),
        ({"path_kind": "invented"}, "INVALID_INPUT"),
        ({"expires_at": clock.value - timedelta(days=1)}, "INVALID_INPUT"),
    ):
        values = {
            "connection_id": connection_id,
            "platform_ref": AGENT_ONE,
            "action": "identity.disable",
            "path_kind": "grant",
            "path_ref": DISABLE_ROLE_PATH,
            "reason_code": "BUSINESS_ACCEPTED",
        }
        values.update(changes)
        with pytest.raises(MonitorError) as failure:
            store.accept_reach(db, admin, clock=clock, **values)
        assert failure.value.code == code
