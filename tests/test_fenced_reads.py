# SPDX-License-Identifier: AGPL-3.0-only
"""The tenant fence on twenty-two tables, read as the runtime role (#155).

Each test writes through the product for one workspace, reads the table itself as the runtime
role under the other workspace's fence and finds nothing, then reads it under its own fence and
finds exactly what it wrote. Where the product lets the test choose an identifier (a group or
source name, a story, a destination, a Tines or directory object), the other workspace then
writes the very same one, and each reads only its own row; a principal group's member collides
too, the other workspace holding an agent under the same principal id.

What a row is checked against is either the key the product returned or, where a run wrote
many rows, the owner's read of that workspace's rows by an explicit `tenant_id`, which row
security does not shape. These are the tables whose isolation rested on the policy body alone:
the catalog test holds every body exactly, and these tests show PostgreSQL applying it to each.
With a table's `tenant_isolation` policy widened to `USING (true)`, its test fails at the other
workspace's read.
"""

import importlib
from datetime import UTC, datetime, timedelta

import pytest
from scope_fixtures import owner as owner
from space_fixtures import default_space
from sqlalchemy import text
from test_directory_store import RING as DIRECTORY_RING
from test_directory_store import enabled
from test_execution import provision_identity, request
from test_execution import registry as registry
from test_execution import world as world
from test_mfa_sessions import enrolled
from test_monitoring_store import FixedClock
from test_monitoring_store import admins as admins
from test_monitoring_worker import receiver as receiver
from test_passkeys import ORIGIN, registration
from test_scout_rules import collect, profile
from test_scout_run import AGENT_ONE, client, detailed_scenario
from test_scout_run import connect as connect_directory
from test_tines_collection import KEY, scenario
from test_tines_collection import run as collect_tines

from execbound import access_control, accounts, administration, approval_rules, mfa, passkeys
from execbound import directory_store as directory
from execbound.directory import DirectoryConfig
from execbound.execution import admit, decide_approval
from execbound.export import export_events
from execbound.monitoring import graph
from execbound.monitoring import store as monitoring
from execbound.notifications import Destination
from execbound.passwords import issue_reset, redeem_reset, set_email
from execbound.resolution import issue_run
from execbound.runtime import Runtime
from execbound.surfaces.sessions import issue_session, load_session
from execbound_harness.fake_graph import SECRET, serving
from execbound_harness.fake_tines import BASE_URL
from execbound_harness.fake_tines import serving as serving_tines

pytestmark = pytest.mark.integration

PASSWORD = "a decent passphrase"


# Reading a table as the runtime role.


def rows(db, tenant, table, columns):
    """Every row of `table` the runtime role reads under `tenant`'s fence: its tenant, then
    `columns`, sorted. The table and column names are this module's literals."""
    names = ", ".join(("tenant_id", *columns))
    with db.transaction(tenant) as conn:
        found = conn.execute(text(f"SELECT {names} FROM execbound.{table}"))  # nosec B608
        return sorted(tuple(row) for row in found)


def owned(admin_engine, tenant, table, columns):
    """The same rows read by the owner, which bypasses row security, naming the tenant in the
    statement: what the workspace holds whatever its fence admits."""
    names = ", ".join(("tenant_id", *columns))
    with admin_engine.connect() as conn:
        found = conn.execute(
            text(f"SELECT {names} FROM execbound.{table} WHERE tenant_id = :t"),  # nosec B608
            {"t": tenant},
        )
        return sorted(tuple(row) for row in found)


def fenced(db, table, columns, owner_tenant, other_tenant, keys):
    """Under `other_tenant`'s fence the runtime reads no row of `table`; under
    `owner_tenant`'s it reads exactly `keys`, each a tuple of `columns`."""
    assert rows(db, other_tenant, table, columns) == [], table
    expected = sorted((owner_tenant, *key) for key in keys)
    assert expected, table
    assert rows(db, owner_tenant, table, columns) == expected, table


def apart(db, table, columns, holdings):
    """Each tenant of `holdings` reads exactly its own keys of `table`, which collide."""
    for tenant, keys in holdings.items():
        assert rows(db, tenant, table, columns) == sorted((tenant, *key) for key in keys), table
    assert len({tuple(sorted(keys)) for keys in holdings.values()}) == 1, "the keys collide"


def held(admin_engine, tenant, table, columns):
    """The keys of the owner's read of one tenant's rows, without the tenant."""
    return [row[1:] for row in owned(admin_engine, tenant, table, columns)]


# The two workspaces.


def tenant_of(world):
    return world["identity"].tenant_id


def other_of(world, seeded):
    return next(tenant for tenant in seeded["tenants"] if tenant != tenant_of(world))


def person(admin_engine, db, tenant, kind, world):
    return provision_identity(admin_engine, db, tenant, kind, world["clock"].now())


def session_of(db, identity, clock):
    return load_session(db, issue_session(db, identity, clock=clock).token, clock=clock)


# Sign-in: passkeys, factors, requests, passwords and directory invitations.


def test_another_tenant_reads_no_account_passkeys(db, world, seeded):
    clock, grant, _ = enrolled(db, [world["human"]])
    session = load_session(db, grant.token, clock=clock)
    options = passkeys.begin(db, session, ORIGIN, "register", clock=clock)
    _, credential, response = registration(options)
    assert passkeys.complete(db, session, ORIGIN, "register", response, clock=clock)
    fenced(
        db,
        "account_passkeys",
        ("credential_id", "principal_id"),
        tenant_of(world),
        other_of(world, seeded),
        [(credential.hex(), world["human"].principal_id)],
    )


def test_another_tenant_reads_no_passkey_challenges(db, world, seeded):
    clock, grant, _ = enrolled(db, [world["human"]])
    session = load_session(db, grant.token, clock=clock)
    passkeys.begin(db, session, ORIGIN, "register", clock=clock)
    fenced(
        db,
        "passkey_challenges",
        ("session_id", "kind"),
        tenant_of(world),
        other_of(world, seeded),
        [(session.session_id, "register")],
    )


def test_another_tenant_reads_no_account_requests(db, world, seeded, admin_engine):
    tenant, other = tenant_of(world), other_of(world, seeded)
    accounts.change(
        db, session_of(db, world["human"], world["clock"]), "request", {"kind": "data_access"}
    )
    columns = ("principal_id", "kind")
    fenced(
        db,
        "account_requests",
        columns,
        tenant,
        other,
        [(world["human"].principal_id, "data_access")],
    )
    # The other workspace's approver asks for the same thing; each reads only its own request.
    stranger = person(admin_engine, db, other, "HUMAN_APPROVER", world)
    accounts.change(
        db, session_of(db, stranger, world["clock"]), "request", {"kind": "data_access"}
    )
    for owner_tenant, asker in ((tenant, world["human"]), (other, stranger)):
        assert rows(db, owner_tenant, "account_requests", columns) == [
            (owner_tenant, asker.principal_id, "data_access")
        ]


def test_another_tenant_reads_no_account_security_policy(db, world, seeded, admin_engine):
    tenant, other = tenant_of(world), other_of(world, seeded)
    clock, grant, _ = enrolled(db, [world["admin"]])
    mfa.manage_security(
        db, load_session(db, grant.token, clock=clock), "policy", "all", clock=clock
    )
    fenced(db, "account_security_policy", ("requirement",), tenant, other, [("all",)])
    # The other workspace sets its own requirement; the one row each holds is its own.
    stranger = person(admin_engine, db, other, "ADMIN", world)
    clock, grant, _ = enrolled(db, [stranger])
    mfa.manage_security(
        db, load_session(db, grant.token, clock=clock), "policy", "admins", clock=clock
    )
    assert rows(db, tenant, "account_security_policy", ("requirement",)) == [(tenant, "all")]
    assert rows(db, other, "account_security_policy", ("requirement",)) == [(other, "admins")]


def reset_for(db, world, admin_engine):
    """A set-password code the world's administrator issued for a new approver, who is given
    an address first, as a reset needs one."""
    tenant, actor = tenant_of(world), world["admin"].principal_id
    target = person(admin_engine, db, tenant, "HUMAN_APPROVER", world)
    set_email(db, tenant, actor, target.principal_id, "dana@example.com")
    return target, issue_reset(db, tenant, actor, target.principal_id, clock=world["clock"])


def test_another_tenant_reads_no_password_resets(db, world, seeded, admin_engine):
    target, reset = reset_for(db, world, admin_engine)
    fenced(
        db,
        "password_resets",
        ("reset_id", "principal_id"),
        tenant_of(world),
        other_of(world, seeded),
        [(reset.reset_id, target.principal_id)],
    )


def test_another_tenant_reads_no_principal_passwords(db, world, seeded, admin_engine):
    target, reset = reset_for(db, world, admin_engine)
    assert redeem_reset(db, reset.code, PASSWORD, clock=world["clock"]) == target.principal_id
    fenced(
        db,
        "principal_passwords",
        ("principal_id",),
        tenant_of(world),
        other_of(world, seeded),
        [(target.principal_id,)],
    )


def test_another_tenant_reads_no_identity_invitations(db, world, seeded):
    tenant = tenant_of(world)
    cast = {"tenant": tenant, "admin": world["admin"].principal_id}
    provider = enabled(
        db, DirectoryConfig(DIRECTORY_RING, "https://app.example"), cast, world["clock"]
    )
    minted = directory.invite(
        db, tenant, world["admin"].principal_id, world["human"].principal_id, provider
    )
    fenced(
        db,
        "identity_invitations",
        ("invitation_id", "principal_id", "provider_id"),
        tenant,
        other_of(world, seeded),
        [(minted.invitation_id, world["human"].principal_id, provider)],
    )


# Access: groups, their members, and the approval rules that route to them.


def responders(db, world, admin, members, *, name="Incident responders"):
    """A reviewer group made through the access functions by `admin`, holding `members`."""
    runtime = Runtime(db, [], clock=world["clock"])
    session = session_of(db, admin, world["clock"])
    group = access_control.create_group(
        runtime, session, name, "Review endpoint actions", "Set up the response team"
    )
    access_control.set_group_members(
        runtime, session, group, [member.principal_id for member in members], "Add the reviewer"
    )
    return runtime, session, group


def routed(db, world, admin_engine):
    """One approval rule saved through `approval_rules.change_rule`, routing the world's
    canonical target to a group that holds the world's approver."""
    runtime, session, group = responders(db, world, world["admin"], [world["human"]])
    access_control.set_group_roles(
        runtime, session, group, [{"role": "approver", "space_id": None}], "Allow reviewing"
    )
    with admin_engine.connect() as conn:
        space = default_space(conn, tenant_of(world))
    rule = approval_rules.change_rule(
        runtime,
        session,
        None,
        {
            "operation": "save",
            "name": "Endpoint response",
            "group_id": str(group),
            "space_id": str(space),
            "actions": ["endpoint.isolate"],
            "targets": [str(world["canonical"])],
        },
        "Route endpoint requests to the response team",
    )
    return group, rule


def test_another_tenant_reads_no_approval_rules(db, world, seeded, admin_engine):
    group, rule = routed(db, world, admin_engine)
    fenced(
        db,
        "approval_rules",
        ("rule_id", "group_id"),
        tenant_of(world),
        other_of(world, seeded),
        [(rule, group)],
    )


def test_another_tenant_reads_no_approval_rule_actions(db, world, seeded, admin_engine):
    _, rule = routed(db, world, admin_engine)
    fenced(
        db,
        "approval_rule_actions",
        ("rule_id", "action"),
        tenant_of(world),
        other_of(world, seeded),
        [(rule, "endpoint.isolate")],
    )


def test_another_tenant_reads_no_approval_rule_targets(db, world, seeded, admin_engine):
    _, rule = routed(db, world, admin_engine)
    fenced(
        db,
        "approval_rule_targets",
        ("rule_id", "canonical_target_id"),
        tenant_of(world),
        other_of(world, seeded),
        [(rule, world["canonical"])],
    )


def test_another_tenant_reads_no_access_groups(db, world, seeded, admin_engine):
    tenant, other = tenant_of(world), other_of(world, seeded)
    _, _, group = responders(db, world, world["admin"], [world["human"]])
    columns = ("group_id", "name")
    fenced(db, "access_groups", columns, tenant, other, [(group, "Incident responders")])
    # The other workspace's administrator names a group the very same way.
    stranger = person(admin_engine, db, other, "ADMIN", world)
    _, _, theirs = responders(db, world, stranger, [stranger])
    for owner_tenant, found in ((tenant, group), (other, theirs)):
        assert rows(db, owner_tenant, "access_groups", columns) == [
            (owner_tenant, found, "Incident responders")
        ]


def test_another_tenant_reads_no_access_group_members(db, world, seeded, admin_engine):
    tenant, other = tenant_of(world), other_of(world, seeded)
    _, _, group = responders(db, world, world["admin"], [world["human"]])
    columns = ("group_id", "principal_id")
    fenced(
        db, "access_group_members", columns, tenant, other, [(group, world["human"].principal_id)]
    )
    stranger = person(admin_engine, db, other, "ADMIN", world)
    reviewer = person(admin_engine, db, other, "HUMAN_APPROVER", world)
    _, _, theirs = responders(db, world, stranger, [reviewer])
    assert rows(db, other, "access_group_members", columns) == [
        (other, theirs, reviewer.principal_id)
    ]
    assert rows(db, tenant, "access_group_members", columns) == [
        (tenant, group, world["human"].principal_id)
    ]


# Owner-provisioned principal groups.


def test_another_tenant_reads_no_principal_groups(db, world, seeded, admin_engine, owner):
    tenant, other = tenant_of(world), other_of(world, seeded)
    group = administration.create_group(owner, tenant, "triage", world["admin"].principal_id)
    columns = ("group_id", "name")
    fenced(db, "principal_groups", columns, tenant, other, [(group, "triage")])
    stranger = person(admin_engine, db, other, "ADMIN", world)
    theirs = administration.create_group(owner, other, "triage", stranger.principal_id)
    for owner_tenant, found in ((tenant, group), (other, theirs)):
        assert rows(db, owner_tenant, "principal_groups", columns) == [
            (owner_tenant, found, "triage")
        ]


def test_another_tenant_reads_no_principal_group_members(db, world, seeded, admin_engine, owner):
    tenant, other = tenant_of(world), other_of(world, seeded)
    actor = world["admin"].principal_id
    group = administration.create_group(owner, tenant, "triage", actor)
    administration.assign_group(owner, tenant, group, world["identity"].principal_id, actor)
    columns = ("group_id", "principal_id")
    fenced(
        db,
        "principal_group_members",
        columns,
        tenant,
        other,
        [(group, world["identity"].principal_id)],
    )
    # The other workspace holds an agent under the very same principal id, seated the way the
    # suite's fixtures seat one (the product chooses ids itself), and that agent joins the
    # other workspace's own group of the same name through the owner's command.
    member = world["identity"].principal_id
    with admin_engine.begin() as conn:
        conn.execute(
            text(
                "INSERT INTO execbound.principals (tenant_id, principal_id, kind, space_id) "
                "VALUES (:t, :p, 'AGENT', (SELECT space_id FROM execbound.spaces "
                "WHERE tenant_id = :t))"
            ),
            {"t": other, "p": member},
        )
    stranger = person(admin_engine, db, other, "ADMIN", world)
    theirs = administration.create_group(owner, other, "triage", stranger.principal_id)
    administration.assign_group(owner, other, theirs, member, stranger.principal_id)
    assert rows(db, other, "principal_group_members", columns) == [(other, theirs, member)]
    assert rows(db, tenant, "principal_group_members", columns) == [(tenant, group, member)]


# Execution: runs, decisions, notifications and the export cursor.


def test_another_tenant_reads_no_agent_runs(db, world, seeded):
    run = issue_run(db, world["identity"], world["clock"])
    fenced(
        db,
        "agent_runs",
        ("run_id", "principal_id"),
        tenant_of(world),
        other_of(world, seeded),
        [(run, world["identity"].principal_id)],
    )


def test_another_tenant_reads_no_approval_decisions(db, world, seeded):
    pending = admit(db, world["identity"], request(world), world["clock"])
    assert pending.view.state == "PENDING_APPROVAL"
    decide_approval(db, world["human"], pending.view.approval_id, "APPROVE", world["clock"])
    fenced(
        db,
        "approval_decisions",
        ("approval_id", "principal_id", "decision"),
        tenant_of(world),
        other_of(world, seeded),
        [(pending.view.approval_id, world["human"].principal_id, "APPROVE")],
    )


def test_another_tenant_reads_no_approval_notifications(db, world, seeded):
    tenant = tenant_of(world)
    hook = Destination("soc", tenant, "http://127.0.0.1:9/approvals", "k" * 32)
    pending = admit(db, world["identity"], request(world), world["clock"], notifications=[hook])
    assert pending.view.state == "PENDING_APPROVAL"
    fenced(
        db,
        "approval_notifications",
        ("approval_id", "destination_id"),
        tenant,
        other_of(world, seeded),
        [(pending.view.approval_id, "soc")],
    )


def test_another_tenant_reads_no_export_cursors(db, world, seeded, admin_engine, receiver):
    tenant, other = tenant_of(world), other_of(world, seeded)
    local, _ = receiver

    def siem(owner_tenant):
        return Destination("siem", owner_tenant, local.url, local.secret, kind="security-events")

    export_events(db, world["admin"], [siem(tenant)], clock=world["clock"])
    fenced(db, "export_cursors", ("destination_id",), tenant, other, [("siem",)])
    # The other workspace exports to a destination of the same name.
    stranger = person(admin_engine, db, other, "ADMIN", world)
    export_events(db, stranger, [siem(other)], clock=world["clock"])
    apart(db, "export_cursors", ("destination_id",), {tenant: [("siem",)], other: [("siem",)]})


# Monitoring: sources, the Tines inventory and the Entra directory's grants and exceptions.


def test_another_tenant_reads_no_monitor_sources(db, admins):
    first, second = admins
    clock = FixedClock(datetime.now(UTC))
    columns = ("source_id", "story_id")

    def source(admin):
        return monitoring.create_source(
            db,
            admin,
            label="Synthetic story",
            story_id="story-1",
            expires_at=clock.now() + timedelta(hours=2),
            clock=clock,
        ).source_id

    mine = source(first)
    fenced(db, "monitor_sources", columns, first.tenant_id, second.tenant_id, [(mine, "story-1")])
    theirs = source(second)
    for admin, found in ((first, mine), (second, theirs)):
        assert rows(db, admin.tenant_id, "monitor_sources", columns) == [
            (admin.tenant_id, found, "story-1")
        ]


def test_another_tenant_reads_no_monitor_inventory(db, admins, admin_engine):
    collection = importlib.import_module("execbound.monitoring.collection")
    first, second = admins
    clock = FixedClock(datetime.now(UTC))
    columns = ("item_kind", "external_id", "name")

    def inventory(admin):
        connection = monitoring.create_connection(
            db,
            admin,
            label="Synthetic Tines tenant",
            base_url=BASE_URL,
            key_fingerprint=collection.fingerprint(KEY),
            team_id="7",
            clock=clock,
        )
        with serving_tines(scenario(clock.value)) as server:
            result = collect_tines(collection, db, admin, connection, server, clock, audit_pages=0)
        assert result["inventory"]["stories"] == 5
        return held(admin_engine, admin.tenant_id, "monitor_inventory", columns)

    mine = inventory(first)
    assert len(mine) == 13
    fenced(db, "monitor_inventory", columns, first.tenant_id, second.tenant_id, mine)
    # The same Tines records collected for the other workspace: identical external ids.
    theirs = inventory(second)
    apart(db, "monitor_inventory", columns, {first.tenant_id: mine, second.tenant_id: theirs})


def test_another_tenant_reads_no_monitor_agent_grants(db, admins, admin_engine):
    first, second = admins
    clock = FixedClock(datetime.now(UTC))
    columns = ("grant_kind", "resource_ref", "value", "path_ref")
    # Two directories, because a directory is connected once across the deployment; both
    # serve the same agent, with the same identifiers and the same grants.
    directories = ("11111111-2222-4333-8444-555555555555", "22222222-3333-4444-8555-666666666666")

    def grants(admin, directory_ref):
        connection = connect_directory(db, admin, clock, directory_ref=directory_ref)
        with (
            serving(detailed_scenario(organization=directory_ref)) as server,
            client(server) as http,
        ):
            result = graph.run(
                db,
                admin,
                connection_id=connection,
                client_secret=SECRET,
                client=http,
                clock=clock,
            )
        assert result["outcome"] == "COMPLETE"
        return held(admin_engine, admin.tenant_id, "monitor_agent_grants", columns)

    mine = grants(first, directories[0])
    assert len(mine) == 4
    fenced(db, "monitor_agent_grants", columns, first.tenant_id, second.tenant_id, mine)
    theirs = grants(second, directories[1])
    apart(db, "monitor_agent_grants", columns, {first.tenant_id: mine, second.tenant_id: theirs})


def test_another_tenant_reads_no_monitor_reach_exceptions(db, admins):
    first, second = admins
    clock = FixedClock(datetime.now(UTC))
    profile(db, first, clock)
    connection = connect_directory(db, first, clock)
    collect(db, first, clock, connection)
    with db.transaction(first.tenant_id) as conn:
        path = (
            conn.execute(
                text(
                    "SELECT action, path_kind, path_ref FROM execbound.monitor_agent_reach "
                    "WHERE path_kind IN ('grant', 'role') ORDER BY action, path_kind, path_ref "
                    "LIMIT 1"
                )
            )
            .mappings()
            .one()
        )
    monitoring.accept_reach(
        db,
        first,
        connection_id=connection,
        platform_ref=AGENT_ONE,
        action=path["action"],
        path_kind=path["path_kind"],
        path_ref=path["path_ref"],
        reason_code="BUSINESS_ACCEPTED",
        clock=clock,
    )
    fenced(
        db,
        "monitor_reach_exceptions",
        ("action", "path_kind", "path_ref", "reason_code"),
        first.tenant_id,
        second.tenant_id,
        [(path["action"], path["path_kind"], path["path_ref"], "BUSINESS_ACCEPTED")],
    )
