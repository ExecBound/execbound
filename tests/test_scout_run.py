# SPDX-License-Identifier: AGPL-3.0-only
"""One bounded Entra collection run against a fake directory, on real PostgreSQL.

SR1, the store half of SR2, SR12 and the run half of SR13: what registration accepts, what
a probe records, what a sync retains, and what happens when the directory disagrees.
"""

from datetime import UTC, datetime, timedelta

import httpx
import pytest
from sqlalchemy import text
from test_monitoring_store import FixedClock
from test_monitoring_store import admins as admins

from execbound.monitoring import graph, store
from execbound.monitoring.models import MonitorError
from execbound_harness.fake_graph import CLIENT, DIRECTORY, SECRET, Scenario, serving, transport

GRAPH_URL = "https://graph.microsoft.com"
TINES_URL = "https://fixture.tines.com"
BLUEPRINT_APP = "bbbbbbbb-0000-4000-8000-0000000000ff"
OTHER_DIRECTORY = "99999999-8888-7777-6666-555555555555"
# Nothing in this list may survive into a table, a log line or a run result.
FORBIDDEN = (
    "person@synthetic.invalid",
    "A Person",
    SECRET,
    "an undocumented property",
)


def agent(index, **overrides):
    return {
        "@odata.type": "#microsoft.graph.agentIdentity",
        "id": f"aaaaaaaa-0000-4000-8000-{index:012d}",
        "displayName": f"Synthetic agent {index}",
        "accountEnabled": True,
        "createdDateTime": "2026-09-01T10:00:00Z",
        "agentIdentityBlueprintId": BLUEPRINT_APP,
        "servicePrincipalType": "ServiceIdentity",
        "tags": [],
        **overrides,
    }


def principal(index, **overrides):
    """A classic service principal as a live directory returns one: no blueprint, and
    servicePrincipalType 'Application' rather than the agent discriminator."""
    record = agent(index, **overrides)
    del record["@odata.type"]
    del record["agentIdentityBlueprintId"]
    record["servicePrincipalType"] = "Application"
    return record


def client(server):
    return httpx.Client(transport=transport(server), trust_env=False, follow_redirects=False)


def connect(db, admin, clock, **overrides):
    values = {
        "label": "Synthetic directory",
        "base_url": GRAPH_URL,
        "key_fingerprint": graph.fingerprint(SECRET),
        "kind": "entra_agent_id",
        "directory_ref": DIRECTORY,
        "client_ref": CLIENT,
    }
    values.update(overrides)
    return store.create_connection(db, admin, clock=clock, **values)


@pytest.fixture
def clock():
    return FixedClock(datetime.now(UTC))


def test_registration_refuses_a_connection_whose_shape_is_not_its_platform(db, admins, clock):
    admin = admins[0]
    for overrides in (
        # A Graph origin under the Tines kind, and the reverse.
        {"kind": "tines"},
        {"base_url": TINES_URL},
        # The token request needs both identifiers before any read is possible.
        {"directory_ref": None},
        {"client_ref": None},
        {"directory_ref": "not-a-guid"},
        # A team scope is a Tines concept with no equivalent on this connection.
        {"team_id": "team-4"},
    ):
        with pytest.raises(MonitorError) as failure:
            connect(db, admin, clock, **overrides)
        assert failure.value.code == "INVALID_INPUT"


def test_a_tenant_registers_one_connection_per_platform(db, admins, clock):
    admin = admins[0]
    connect(db, admin, clock)
    with pytest.raises(MonitorError) as failure:
        connect(db, admin, clock)
    assert failure.value.code == "CONNECTION_EXISTS"
    # A Tines connection beside it is the point of the kind.
    store.create_connection(
        db,
        admin,
        label="Synthetic tenant",
        base_url=TINES_URL,
        key_fingerprint="ab" * 32,
        clock=clock,
    )


def test_a_secret_that_is_not_the_registered_one_never_reaches_the_platform(db, admins, clock):
    admin = admins[0]
    connection_id = connect(db, admin, clock)
    with serving(Scenario(agents=[agent(1)])) as server, client(server) as http:
        with pytest.raises(graph.GraphError) as failure:
            graph.run(
                db,
                admin,
                connection_id=connection_id,
                client_secret="a-different-secret",
                client=http,
                clock=clock,
            )
        assert failure.value.code == "KEY_MISMATCH"
        assert server.requests == []


def test_a_run_probes_records_and_retains_only_allowlisted_metadata(db, admins, clock, caplog):
    admin = admins[0]
    connection_id = connect(db, admin, clock)
    scenario = Scenario(
        agents=[
            agent(1, notes="an undocumented property", ownerMail="person@synthetic.invalid"),
            agent(2, displayName="A Person"),
        ],
        principals=[principal(3), agent(1)],
        max_top=1,
    )
    with serving(scenario) as server, client(server) as http:
        result = graph.run(
            db, admin, connection_id=connection_id, client_secret=SECRET, client=http, clock=clock
        )
    assert result["outcome"] == "COMPLETE"
    assert result["directory"] == "verified"
    assert result["capabilities"]["agent_identities"] == "available"
    # The agent listed in both collections is one agent, and the directory's own class wins.
    assert result["agents"]["agents"] == 3
    assert result["agents"]["agent_identities"] == 2
    assert result["agents"]["service_principals"] == 1

    with db.transaction(admin.tenant_id) as conn:
        rows = (
            conn.execute(text("SELECT * FROM execbound.monitor_agents ORDER BY platform_ref"))
            .mappings()
            .all()
        )
    assert [row["identity_class"] for row in rows] == [
        "agent_identity",
        "agent_identity",
        "service_principal",
    ]
    # The directory served no sponsors and let us read that, which is "absent" — the
    # answer a refused read must never be recorded as.
    assert {row["sponsor_state"] for row in rows} == {"absent"}
    assert rows[1]["display_name"] == "A Person"  # an agent's own name, not a person's
    retained = "".join(str(dict(row)) for row in rows) + str(result) + caplog.text
    for secret in FORBIDDEN:
        if secret == "A Person":
            continue
        assert secret not in retained


def test_a_directory_that_disagrees_with_the_registration_is_refused(db, admins, clock):
    """The registration names a directory; only the platform can confirm it speaks for it."""
    admin = admins[0]
    connection_id = connect(db, admin, clock)
    scenario = Scenario(agents=[agent(1)], organization=OTHER_DIRECTORY)
    with serving(scenario) as server, client(server) as http:
        result = graph.run(
            db, admin, connection_id=connection_id, client_secret=SECRET, client=http, clock=clock
        )
    assert result["outcome"] == "ERROR"
    assert result["agents"]["agents"] == 0
    with db.transaction(admin.tenant_id) as conn:
        assert conn.execute(text("SELECT count(*) FROM execbound.monitor_agents")).scalar_one() == 0
        row = (
            conn.execute(text("SELECT last_error_code FROM execbound.monitor_connections"))
            .mappings()
            .one()
        )
    assert row["last_error_code"] == "DIRECTORY_MISMATCH"


def test_a_directory_that_will_not_say_leaves_it_unverified_rather_than_assumed(db, admins, clock):
    admin = admins[0]
    connection_id = connect(db, admin, clock)
    with (
        serving(Scenario(agents=[agent(1)], organization=None)) as server,
        client(server) as http,
    ):
        result = graph.run(
            db, admin, connection_id=connection_id, client_secret=SECRET, client=http, clock=clock
        )
    assert result["outcome"] == "COMPLETE"
    assert result["directory"] == "unverified"
    assert result["agents"]["agents"] == 1


def test_a_principal_no_longer_listed_is_marked_gone_and_not_deleted(db, admins, clock):
    admin = admins[0]
    connection_id = connect(db, admin, clock)
    with serving(Scenario(agents=[agent(1), agent(2)])) as server, client(server) as http:
        graph.run(
            db, admin, connection_id=connection_id, client_secret=SECRET, client=http, clock=clock
        )
        clock.value = clock.value + timedelta(minutes=5)
        server.scenario.agents = [agent(1)]
        result = graph.run(
            db, admin, connection_id=connection_id, client_secret=SECRET, client=http, clock=clock
        )
    assert result["agents"]["gone"] == 1
    with db.transaction(admin.tenant_id) as conn:
        rows = (
            conn.execute(
                text(
                    "SELECT platform_ref, gone_at FROM execbound.monitor_agents "
                    "ORDER BY platform_ref"
                )
            )
            .mappings()
            .all()
        )
    # The history stays; only the sighting ends.
    assert len(rows) == 2
    assert rows[0]["gone_at"] is None and rows[1]["gone_at"] is not None


def test_losing_permission_to_read_agents_ends_the_run_rather_than_reporting_none(
    db, admins, clock
):
    admin = admins[0]
    connection_id = connect(db, admin, clock)
    scenario = Scenario(agents=[agent(1)], status={"agents": 403})
    with serving(scenario) as server, client(server) as http:
        result = graph.run(
            db, admin, connection_id=connection_id, client_secret=SECRET, client=http, clock=clock
        )
    assert result["outcome"] == "AUTH_LOST"
    assert result["capabilities"]["agent_identities"] == "forbidden"
    assert result["agents"]["agents"] == 0
    with db.transaction(admin.tenant_id) as conn:
        assert conn.execute(text("SELECT count(*) FROM execbound.monitor_agents")).scalar_one() == 0


def test_two_tenants_reading_directories_that_share_identifiers_stay_apart(db, admins, clock):
    first, second = admins
    # Two directories, because a directory is connected once across the deployment.
    directories = (DIRECTORY, "22222222-3333-4444-5555-666666666666")
    connections = [
        connect(db, admin, clock, directory_ref=directory)
        for admin, directory in zip(admins, directories, strict=True)
    ]
    # Both directories serve an agent with the very same object identifier.
    for admin, connection_id, directory in zip(admins, connections, directories, strict=True):
        with (
            serving(Scenario(agents=[agent(1)], organization=directory)) as server,
            client(server) as http,
        ):
            graph.run(
                db,
                admin,
                connection_id=connection_id,
                client_secret=SECRET,
                client=http,
                clock=clock,
            )
    for admin, other in ((first, second), (second, first)):
        with db.transaction(admin.tenant_id) as conn:
            rows = (
                conn.execute(text("SELECT tenant_id FROM execbound.monitor_agents")).scalars().all()
            )
            assert rows == [admin.tenant_id]
            assert (
                conn.execute(
                    text("SELECT count(*) FROM execbound.monitor_agents WHERE tenant_id = :o"),
                    {"o": other.tenant_id},
                ).scalar_one()
                == 0
            )


GRAPH_RESOURCE = "ffffffff-0000-4000-8000-000000000001"
MICROSOFT_GRAPH = "00000003-0000-0000-c000-000000000000"
DISABLE_ROLE = "3011c876-62b7-4ada-afa2-506cbbecc68c"
AUTH_ADMIN = "c4e39bd9-1100-46d3-8c65-fb160da0071f"
BLUEPRINT_OBJECT = "bbbbbbbb-0000-4000-8000-000000000001"
AGENT_ONE = "aaaaaaaa-0000-4000-8000-000000000001"


def detailed_scenario(**changes):
    """One agent identity with a direct role, a delegated scope, a sponsor and a blueprint."""
    values = {
        "agents": [agent(1)],
        "blueprints": [
            {
                "id": BLUEPRINT_OBJECT,
                "appId": BLUEPRINT_APP,
                "keyCredentials": [{"keyId": "k1", "key": "BASE64=="}],
                "passwordCredentials": [],
            }
        ],
        "inheritable": {
            BLUEPRINT_OBJECT: [
                {
                    "resourceAppId": MICROSOFT_GRAPH,
                    "inheritableRoles": {"kind": "allAllowed"},
                    "inheritableScopes": {"kind": "none"},
                }
            ]
        },
        "app_role_assignments": {
            AGENT_ONE: [
                {
                    "id": "assignment-1",
                    "appRoleId": DISABLE_ROLE,
                    "principalId": AGENT_ONE,
                    "principalDisplayName": "payroll-agent",
                    "resourceId": GRAPH_RESOURCE,
                    "resourceDisplayName": "Microsoft Graph",
                }
            ]
        },
        "delegated_grants": {
            AGENT_ONE: [
                {
                    "clientId": AGENT_ONE,
                    "resourceId": GRAPH_RESOURCE,
                    "scope": "User.RevokeSessions.All",
                }
            ]
        },
        "member_of": {
            AGENT_ONE: [
                {
                    "@odata.type": "#microsoft.graph.directoryRole",
                    "id": "dddddddd-0000-4000-8000-000000000001",
                    "roleTemplateId": AUTH_ADMIN,
                    "displayName": "Authentication Administrator",
                }
            ]
        },
        "sponsors": {
            AGENT_ONE: [
                {
                    "@odata.type": "#microsoft.graph.user",
                    "id": "cccccccc-0000-4000-8000-000000000001",
                    "displayName": "A Person",
                    "mail": "person@synthetic.invalid",
                }
            ]
        },
        "owners": {AGENT_ONE: [{"id": "cccccccc-0000-4000-8000-000000000002"}]},
        "resources": {
            GRAPH_RESOURCE: {
                "appId": MICROSOFT_GRAPH,
                "appRoles": [{"id": DISABLE_ROLE, "value": "User.EnableDisableAccount.All"}],
            }
        },
    }
    values.update(changes)
    return Scenario(**values)


def grants_of(db, tenant):
    with db.transaction(tenant) as conn:
        return (
            conn.execute(
                text(
                    "SELECT grant_kind, resource_ref, value, inherited, path_ref, gone_at "
                    "FROM execbound.monitor_agent_grants ORDER BY grant_kind, value"
                )
            )
            .mappings()
            .all()
        )


def test_a_run_records_direct_delegated_role_and_inherited_grants(db, admins, clock, caplog):
    admin = admins[0]
    connection_id = connect(db, admin, clock)
    with serving(detailed_scenario()) as server, client(server) as http:
        result = graph.run(
            db, admin, connection_id=connection_id, client_secret=SECRET, client=http, clock=clock
        )
    assert result["outcome"] == "COMPLETE"
    assert result["detail"]["grants"] == 4
    assert result["detail"]["inherited"] == 1
    rows = grants_of(db, admin.tenant_id)
    assert [(row["grant_kind"], row["value"]) for row in rows] == [
        ("directory_role", AUTH_ADMIN),
        ("graph_role", "User.EnableDisableAccount.All"),
        ("graph_scope", "User.RevokeSessions.All"),
        ("inherited_roles", "allAllowed"),
    ]
    # The app role identifier was resolved to its published name by the directory itself.
    assert rows[1]["resource_ref"] == MICROSOFT_GRAPH
    # An inherited permission points at the blueprint, which is where it has to be removed.
    assert rows[3]["inherited"] is True and rows[3]["path_ref"] == BLUEPRINT_APP
    assert rows[0]["path_ref"] == AGENT_ONE
    assert "BASE64" not in caplog.text and "person@synthetic.invalid" not in caplog.text


def test_a_blueprint_is_read_once_however_many_agents_share_it(db, admins, clock):
    admin = admins[0]
    connection_id = connect(db, admin, clock)
    scenario = detailed_scenario(agents=[agent(1), agent(2), agent(3)])
    with serving(scenario) as server, client(server) as http:
        graph.run(
            db, admin, connection_id=connection_id, client_secret=SECRET, client=http, clock=clock
        )
    reads = [path for path, _, _ in server.requests if path.endswith("/inheritablePermissions")]
    assert len(reads) == 1
    with db.transaction(admin.tenant_id) as conn:
        kinds = (
            conn.execute(text("SELECT DISTINCT credential_kinds FROM execbound.monitor_agents"))
            .scalars()
            .all()
        )
    # Every agent under the blueprint carries the credential kinds the blueprint holds.
    assert kinds == [["certificate"]]


def test_a_sponsor_is_recorded_as_an_identifier_and_a_refused_read_is_not_absence(
    db, admins, clock
):
    admin = admins[0]
    connection_id = connect(db, admin, clock)
    with serving(detailed_scenario()) as server, client(server) as http:
        result = graph.run(
            db, admin, connection_id=connection_id, client_secret=SECRET, client=http, clock=clock
        )
        assert result["detail"]["sponsored"] == 1
        with db.transaction(admin.tenant_id) as conn:
            row = conn.execute(text("SELECT * FROM execbound.monitor_agents")).mappings().one()
        assert row["sponsor_state"] == "present"
        assert row["sponsors"] == [{"kind": "user", "ref": "cccccccc-0000-4000-8000-000000000001"}]
        assert row["sponsor_group_count"] == 0 and row["owner_count"] == 1
        assert "A Person" not in str(dict(row)) and "synthetic.invalid" not in str(dict(row))

        # The directory now refuses the sponsors read; that is not "this agent has none".
        server.scenario.status = {"sponsors": 403}
        clock.value = clock.value + timedelta(minutes=5)
        result = graph.run(
            db, admin, connection_id=connection_id, client_secret=SECRET, client=http, clock=clock
        )
    assert result["detail"]["unreadable"] == 1
    assert result["detail"]["sponsored"] == 0
    with db.transaction(admin.tenant_id) as conn:
        row = conn.execute(text("SELECT * FROM execbound.monitor_agents")).mappings().one()
    assert row["sponsor_state"] == "unreadable"
    assert row["sponsors"] == []


def test_a_classic_service_principal_keeps_its_class_and_its_owners(db, admins, clock):
    admin = admins[0]
    connection_id = connect(db, admin, clock)
    classic = principal(9, tags=["AgenticInstance"])
    scenario = detailed_scenario(
        agents=[],
        principals=[classic],
        owners={classic["id"]: [{"id": "cccccccc-0000-4000-8000-000000000003"}]},
        app_role_assignments={
            classic["id"]: [
                {
                    "appRoleId": DISABLE_ROLE,
                    "resourceId": GRAPH_RESOURCE,
                    "principalId": classic["id"],
                }
            ]
        },
        delegated_grants={},
        member_of={},
        sponsors={},
    )
    with serving(scenario) as server, client(server) as http:
        graph.run(
            db, admin, connection_id=connection_id, client_secret=SECRET, client=http, clock=clock
        )
    with db.transaction(admin.tenant_id) as conn:
        row = conn.execute(text("SELECT * FROM execbound.monitor_agents")).mappings().one()
    assert row["identity_class"] == "service_principal"
    # The tag is evidence and is shown; it is never a reason to call this an agent.
    assert row["tags"] == ["AgenticInstance"]
    assert row["sponsor_state"] == "absent" and row["owner_count"] == 1
    assert row["blueprint_ref"] is None
    assert [row["value"] for row in grants_of(db, admin.tenant_id)] == [
        "User.EnableDisableAccount.All"
    ]


def test_a_grant_no_longer_held_is_marked_gone_and_kept(db, admins, clock):
    admin = admins[0]
    connection_id = connect(db, admin, clock)
    with serving(detailed_scenario()) as server, client(server) as http:
        graph.run(
            db, admin, connection_id=connection_id, client_secret=SECRET, client=http, clock=clock
        )
        server.scenario.app_role_assignments = {AGENT_ONE: []}
        clock.value = clock.value + timedelta(minutes=5)
        result = graph.run(
            db, admin, connection_id=connection_id, client_secret=SECRET, client=http, clock=clock
        )
    assert result["detail"]["gone"] == 1
    rows = grants_of(db, admin.tenant_id)
    assert len(rows) == 4
    gone = [row for row in rows if row["gone_at"] is not None]
    assert [row["value"] for row in gone] == ["User.EnableDisableAccount.All"]


def test_an_unresolvable_role_identifier_stays_an_identifier(db, admins, clock):
    """An identifier the tenant will not resolve is unknown reach, never absent reach."""
    admin = admins[0]
    connection_id = connect(db, admin, clock)
    scenario = detailed_scenario(resources={}, delegated_grants={}, member_of={})
    with serving(scenario) as server, client(server) as http:
        graph.run(
            db, admin, connection_id=connection_id, client_secret=SECRET, client=http, clock=clock
        )
    rows = [row for row in grants_of(db, admin.tenant_id) if row["grant_kind"] == "graph_role"]
    assert [row["value"] for row in rows] == [DISABLE_ROLE]
    assert rows[0]["resource_ref"] == GRAPH_RESOURCE
