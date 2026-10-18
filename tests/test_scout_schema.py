# SPDX-License-Identifier: AGPL-3.0-only
"""Migrations 0030 and 0031: the Scout agent, grant, reach and exception tables, the connection kind
that decides which origin a connection may hold, and the guarded downgrade."""

import os
from uuid import uuid4

import pytest
from alembic import command
from alembic.config import Config
from sqlalchemy import text
from sqlalchemy.exc import DBAPIError

from execbound.db import SCHEMA_REVISION, TABLES, UPDATE_COLUMNS, check_runtime

pytestmark = pytest.mark.integration

PREVIOUS = "0029_claim_clock"
SCOUT = (
    "monitor_agents",
    "monitor_agent_grants",
    "monitor_agent_reach",
    "monitor_reach_exceptions",
)
TINES_URL = "https://fixture.tines.com"
GRAPH_URL = "https://graph.microsoft.com"
DIRECTORY = "11111111-2222-3333-4444-555555555555"
CLIENT = "66666666-7777-8888-9999-aaaaaaaaaaaa"
FINGERPRINT = "ab" * 32
UNFORCED = (
    "SELECT count(*) FROM pg_class WHERE relnamespace='execbound'::regnamespace "
    "AND relkind='r' AND relname<>'alembic_version' "
    "AND (NOT relrowsecurity OR NOT relforcerowsecurity)"
)
CONNECTION = (
    "INSERT INTO execbound.monitor_connections "
    "(tenant_id, connection_id, label, base_url, key_fingerprint, created_at, created_by, "
    " kind, directory_ref, client_ref, team_id, space_id) "
    "VALUES (:t, :c, 'Fixture', :u, :f, now(), :p, :k, :d, :cl, :team, "
    "(SELECT space_id FROM execbound.spaces WHERE tenant_id = :t))"
)
# Distinguishes "the caller did not say" from "the caller said none", which is exactly
# what the directory and client columns are checked for.
UNSET = object()

AGENT = (
    "INSERT INTO execbound.monitor_agents "
    "(tenant_id, agent_id, connection_id, platform_ref, identity_class, display_name, "
    " sponsors, sponsor_state, first_seen_at, observed_at) "
    "VALUES (:t, :a, :c, :ref, :cls, 'Synthetic agent', :sponsors, :state, now(), now())"
)


def migration_config():
    config = Config("alembic.ini")
    config.attributes["database_url"] = os.environ["TEST_MIGRATION_DATABASE_URL"]
    return config


def revision(engine):
    with engine.connect() as conn:
        return conn.execute(text("SELECT version_num FROM execbound.alembic_version")).scalar_one()


def connect(
    engine,
    tenant,
    principal,
    *,
    kind="tines",
    url=None,
    directory=UNSET,
    client=UNSET,
    team=None,
    connection=None,
):
    """Insert one connection row as the owner and return its identifier."""
    connection_id = connection or uuid4()
    if url is None:
        url = TINES_URL if kind == "tines" else GRAPH_URL
    entra = kind == "entra_agent_id"
    if directory is UNSET:
        directory = DIRECTORY if entra else None
    if client is UNSET:
        client = CLIENT if entra else None
    with engine.begin() as conn:
        conn.execute(
            text(CONNECTION),
            {
                "t": tenant,
                "c": connection_id,
                "u": url,
                "f": FINGERPRINT,
                "p": principal,
                "k": kind,
                "d": directory,
                "cl": client,
                "team": team,
            },
        )
    return connection_id


def add_agent(
    engine,
    tenant,
    connection_id,
    *,
    ref="agent-1",
    identity_class="agent_identity",
    sponsors='[{"kind": "user", "ref": "sponsor-1"}]',
    state="present",
):
    agent_id = uuid4()
    with engine.begin() as conn:
        conn.execute(
            text(AGENT),
            {
                "t": tenant,
                "a": agent_id,
                "c": connection_id,
                "ref": ref,
                "cls": identity_class,
                "sponsors": sponsors,
                "state": state,
            },
        )
    return agent_id


def test_runtime_catalog_carries_the_four_scout_tables(db, seeded):
    assert set(SCOUT) <= set(TABLES)
    # What the collector may move, and nothing that would let it rewrite an identity or
    # backdate the moment a claim was computed.
    # The link to a governed principal moves only through the binding functions (0037).
    assert "linked_principal_id" not in UPDATE_COLUMNS["monitor_agents"]
    assert "platform_ref" not in UPDATE_COLUMNS["monitor_agents"]
    assert "first_seen_at" not in UPDATE_COLUMNS["monitor_agents"]
    assert "value" not in UPDATE_COLUMNS["monitor_agent_grants"]
    assert UPDATE_COLUMNS["monitor_reach_exceptions"] == {"withdrawn_at"}
    with db.transaction(seeded["tenants"][0]) as conn:
        check_runtime(conn)


@pytest.mark.parametrize("table", SCOUT)
def test_the_runtime_cannot_delete_collected_agent_evidence(db, seeded, admin_engine, table):
    tenant, principal = seeded["tenants"][0], seeded["principals"][0]
    connect(admin_engine, tenant, principal)
    with pytest.raises(DBAPIError), db.transaction(tenant) as conn:
        conn.execute(text(f"DELETE FROM execbound.{table}"))


@pytest.mark.parametrize(
    "statement",
    [
        "UPDATE execbound.monitor_agents SET platform_ref = 'moved'",
        "UPDATE execbound.monitor_agents SET identity_class = 'service_principal'",
        "UPDATE execbound.monitor_agents SET first_seen_at = now()",
        "UPDATE execbound.monitor_agent_reach SET action = 'identity.enable'",
    ],
)
def test_the_runtime_cannot_rewrite_an_identity_or_its_history(db, seeded, admin_engine, statement):
    tenant, principal = seeded["tenants"][0], seeded["principals"][0]
    connection_id = connect(admin_engine, tenant, principal)
    add_agent(admin_engine, tenant, connection_id)
    with pytest.raises(DBAPIError), db.transaction(tenant) as conn:
        conn.execute(text(statement))


def test_each_tenant_reads_only_its_own_agents(db, seeded, admin_engine):
    """The policy body, which check_runtime never reads: only the flags are in the catalog."""
    first, second = seeded["tenants"]
    for tenant, principal in zip(seeded["tenants"], seeded["principals"], strict=True):
        connection_id = connect(admin_engine, tenant, principal)
        # The same directory object identifier in both tenants, so a widened policy shows.
        add_agent(admin_engine, tenant, connection_id, ref="shared-object-id")
    with admin_engine.connect() as conn:
        assert conn.execute(text("SELECT count(*) FROM execbound.monitor_agents")).scalar_one() == 2
    for tenant in (first, second):
        other = second if tenant == first else first
        with db.transaction(tenant) as conn:
            rows = conn.execute(text("SELECT tenant_id FROM execbound.monitor_agents")).all()
            assert [row[0] for row in rows] == [tenant]
            assert (
                conn.execute(
                    text("SELECT count(*) FROM execbound.monitor_agents WHERE tenant_id = :o"),
                    {"o": other},
                ).scalar_one()
                == 0
            )


@pytest.mark.parametrize(
    ("identity_class", "accepted"),
    [
        ("agent_identity", True),
        ("service_principal", True),
        ("tines_story", True),
        ("agent", False),
        ("AGENT_IDENTITY", False),
        ("", False),
    ],
)
def test_identity_class_admits_only_the_three_classes(
    seeded, admin_engine, identity_class, accepted
):
    """PostgreSQL validates a CHECK at insert, not at definition, so each form is tried."""
    tenant, principal = seeded["tenants"][0], seeded["principals"][0]
    connection_id = connect(admin_engine, tenant, principal)
    if not accepted:
        with pytest.raises(DBAPIError):
            add_agent(admin_engine, tenant, connection_id, identity_class=identity_class)
        return
    add_agent(admin_engine, tenant, connection_id, identity_class=identity_class)


@pytest.mark.parametrize(
    ("state", "sponsors", "accepted"),
    [
        ("present", '[{"kind": "user", "ref": "sponsor-1"}]', True),
        ("absent", "[]", True),
        # A refused read is neither of the other two answers, and it carries no sponsors.
        ("unreadable", "[]", True),
        # A run that has not looked yet is neither of the other answers either.
        ("not_read", "[]", True),
        ("present", "[]", False),
        ("absent", '[{"kind": "user", "ref": "sponsor-1"}]', False),
        ("unreadable", '[{"kind": "user", "ref": "sponsor-1"}]', False),
        ("missing", "[]", False),
    ],
)
def test_sponsor_state_and_the_sponsor_set_cannot_disagree(
    seeded, admin_engine, state, sponsors, accepted
):
    tenant, principal = seeded["tenants"][0], seeded["principals"][0]
    connection_id = connect(admin_engine, tenant, principal)
    if not accepted:
        with pytest.raises(DBAPIError):
            add_agent(admin_engine, tenant, connection_id, sponsors=sponsors, state=state)
        return
    add_agent(admin_engine, tenant, connection_id, sponsors=sponsors, state=state)


def test_a_blueprint_belongs_only_to_an_agent_identity(seeded, admin_engine):
    tenant, principal = seeded["tenants"][0], seeded["principals"][0]
    connection_id = connect(admin_engine, tenant, principal)
    agent_id = add_agent(
        admin_engine,
        tenant,
        connection_id,
        identity_class="service_principal",
        sponsors="[]",
        state="absent",
    )
    with pytest.raises(DBAPIError), admin_engine.begin() as conn:
        conn.execute(
            text("UPDATE execbound.monitor_agents SET blueprint_ref = :b WHERE agent_id = :a"),
            {"b": CLIENT, "a": agent_id},
        )


@pytest.mark.parametrize(
    ("path_kind", "certainty", "mode", "accepted"),
    [
        ("grant", "inferred", "unknown", True),
        ("grant", "inferred", "advisory", True),
        ("role", "unknown", "unknown", True),
        ("inherited", "inferred", "unknown", True),
        ("observation", "observed", "observed", True),
        ("execbound", "verified", "native", True),
        ("execbound", "inferred", "native", True),
        # A grant is not a proof that anything ran, and it is not a control either.
        ("grant", "verified", "unknown", False),
        ("grant", "observed", "unknown", False),
        ("grant", "inferred", "native", False),
        ("role", "inferred", "observed", False),
        # Telemetry is visibility, never prevention.
        ("observation", "observed", "native", False),
        ("observation", "verified", "observed", False),
        # An ExecBound path that could not be established is not an ExecBound path at all.
        ("execbound", "unknown", "native", False),
        ("execbound", "verified", "advisory", False),
    ],
)
def test_a_reach_path_can_only_claim_what_it_establishes(
    seeded, admin_engine, path_kind, certainty, mode, accepted
):
    tenant, principal = seeded["tenants"][0], seeded["principals"][0]
    connection_id = connect(admin_engine, tenant, principal)
    agent_id = add_agent(admin_engine, tenant, connection_id)
    statement = text(
        "INSERT INTO execbound.monitor_agent_reach "
        "(tenant_id, agent_id, action, path_kind, path_ref, certainty, enforcement_mode, "
        " catalog_version, computed_at, valid_until) "
        "VALUES (:t, :a, 'identity.disable', :pk, 'path-1', :cert, :mode, 'entra.v1', "
        " now(), now() + interval '7 days')"
    )
    values = {"t": tenant, "a": agent_id, "pk": path_kind, "cert": certainty, "mode": mode}
    if not accepted:
        with pytest.raises(DBAPIError), admin_engine.begin() as conn:
            conn.execute(statement, values)
        return
    with admin_engine.begin() as conn:
        conn.execute(statement, values)


def test_a_reach_claim_cannot_expire_before_it_was_computed(seeded, admin_engine):
    tenant, principal = seeded["tenants"][0], seeded["principals"][0]
    connection_id = connect(admin_engine, tenant, principal)
    agent_id = add_agent(admin_engine, tenant, connection_id)
    with pytest.raises(DBAPIError), admin_engine.begin() as conn:
        conn.execute(
            text(
                "INSERT INTO execbound.monitor_agent_reach "
                "(tenant_id, agent_id, action, path_kind, path_ref, certainty, enforcement_mode, "
                " catalog_version, computed_at, valid_until) "
                "VALUES (:t, :a, 'identity.disable', 'grant', 'path-1', 'inferred', 'unknown', "
                " 'entra.v1', now(), now() - interval '1 hour')"
            ),
            {"t": tenant, "a": agent_id},
        )


@pytest.mark.parametrize(
    ("grant_kind", "inherited", "accepted"),
    [
        ("graph_role", False, True),
        ("graph_scope", False, True),
        ("directory_role", False, True),
        ("inherited_roles", True, True),
        ("inherited_scopes", True, True),
        # An inherited grant that did not say so would hide the blueprint it came from.
        ("inherited_roles", False, False),
        ("graph_role", True, False),
        ("azure_rbac", False, False),
    ],
)
def test_an_inherited_grant_must_say_that_it_is_inherited(
    seeded, admin_engine, grant_kind, inherited, accepted
):
    tenant, principal = seeded["tenants"][0], seeded["principals"][0]
    connection_id = connect(admin_engine, tenant, principal)
    agent_id = add_agent(admin_engine, tenant, connection_id)
    statement = text(
        "INSERT INTO execbound.monitor_agent_grants "
        "(tenant_id, agent_id, grant_kind, resource_ref, value, inherited, path_ref, observed_at) "
        "VALUES (:t, :a, :k, '', 'User.Read.All', :i, 'agent-1', now())"
    )
    values = {"t": tenant, "a": agent_id, "k": grant_kind, "i": inherited}
    if not accepted:
        with pytest.raises(DBAPIError), admin_engine.begin() as conn:
            conn.execute(statement, values)
        return
    with admin_engine.begin() as conn:
        conn.execute(statement, values)


@pytest.mark.parametrize(
    ("kind", "url", "directory", "client", "team", "accepted"),
    [
        ("tines", TINES_URL, None, None, None, True),
        ("tines", TINES_URL, None, None, "team-4", True),
        ("entra_agent_id", GRAPH_URL, DIRECTORY, CLIENT, None, True),
        # The origin belongs to the kind, in both directions.
        ("tines", GRAPH_URL, None, None, None, False),
        ("entra_agent_id", TINES_URL, DIRECTORY, CLIENT, None, False),
        ("entra_agent_id", "https://graph.microsoft.com/v1.0", DIRECTORY, CLIENT, None, False),
        # The token request needs both identifiers before any read can be made.
        ("entra_agent_id", GRAPH_URL, None, None, None, False),
        ("entra_agent_id", GRAPH_URL, DIRECTORY, None, None, False),
        ("tines", TINES_URL, DIRECTORY, CLIENT, None, False),
        # A team scope is a Tines concept; Graph has no equivalent here.
        ("entra_agent_id", GRAPH_URL, DIRECTORY, CLIENT, "team-4", False),
        ("foundry", GRAPH_URL, None, None, None, False),
    ],
)
def test_a_connection_origin_is_checked_against_its_kind(
    seeded, admin_engine, kind, url, directory, client, team, accepted
):
    tenant, principal = seeded["tenants"][0], seeded["principals"][0]
    if not accepted:
        with pytest.raises(DBAPIError):
            connect(
                admin_engine,
                tenant,
                principal,
                kind=kind,
                url=url,
                directory=directory,
                client=client,
                team=team,
            )
        return
    connect(
        admin_engine,
        tenant,
        principal,
        kind=kind,
        url=url,
        directory=directory,
        client=client,
        team=team,
    )


def test_a_tenant_runs_one_active_connection_per_platform(seeded, admin_engine):
    tenant, principal = seeded["tenants"][0], seeded["principals"][0]
    connect(admin_engine, tenant, principal)
    # A second Tines connection is still refused while the first is active.
    with pytest.raises(DBAPIError):
        connect(admin_engine, tenant, principal, url="https://second.tines.com")
    # An Entra connection beside it is the point of the column.
    connect(admin_engine, tenant, principal, kind="entra_agent_id")
    with pytest.raises(DBAPIError):
        connect(admin_engine, tenant, principal, kind="entra_agent_id")


def test_downgrade_refuses_while_agent_evidence_is_retained(db, seeded, admin_engine):
    tenant, principal = seeded["tenants"][0], seeded["principals"][0]
    connection_id = connect(admin_engine, tenant, principal, kind="entra_agent_id")
    agent_id = add_agent(admin_engine, tenant, connection_id)
    with pytest.raises(RuntimeError, match="collected agent evidence"):
        command.downgrade(migration_config(), PREVIOUS)
    assert revision(admin_engine) == SCHEMA_REVISION
    with admin_engine.connect() as conn:
        assert conn.execute(text(UNFORCED)).scalar_one() == 0
    with db.transaction(tenant) as conn:
        check_runtime(conn)

    with admin_engine.begin() as conn:
        conn.execute(
            text("DELETE FROM execbound.monitor_agents WHERE agent_id = :a"), {"a": agent_id}
        )
    # An Entra connection has no representation in 0027 either, so it refuses on its own.
    with pytest.raises(RuntimeError, match="collected agent evidence"):
        command.downgrade(migration_config(), PREVIOUS)
    with admin_engine.begin() as conn:
        conn.execute(
            text("DELETE FROM execbound.monitor_connections WHERE connection_id = :c"),
            {"c": connection_id},
        )

    command.downgrade(migration_config(), PREVIOUS)
    assert revision(admin_engine) == PREVIOUS
    with admin_engine.connect() as conn:
        assert conn.execute(text(UNFORCED)).scalar_one() == 0
        assert (
            conn.execute(
                text(
                    "SELECT count(*) FROM pg_class WHERE relnamespace='execbound'::regnamespace "
                    "AND relname = ANY(:tables)"
                ),
                {"tables": list(SCOUT)},
            ).scalar_one()
            == 0
        )
    command.upgrade(migration_config(), SCHEMA_REVISION)
    assert revision(admin_engine) == SCHEMA_REVISION
    with admin_engine.connect() as conn:
        assert conn.execute(text(UNFORCED)).scalar_one() == 0
