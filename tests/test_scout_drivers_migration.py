# SPDX-License-Identifier: AGPL-3.0-only
"""Migration 0098: Scout's driver evidence (#355), SR25 to SR27.

Real PostgreSQL. The upgrade adds `monitor_actor_drivers` under forced row security, with no
runtime `DELETE`; a directory's sign-in cursor, which the runtime updates and never inserts; a
Tines tenant's egress addresses, which only `admin_set_egress_addresses` writes; a credential's
host scope and story references; and an actor's user agent hint. The downgrade refuses while any
driver row or recorded egress address is retained, and otherwise removes everything it added.
Under an owner that does not bypass row security, as the hosted owner does not, the function
admits only the caller's own workspace's Tines connection.
"""

from datetime import UTC, datetime
from uuid import uuid4

import pytest
from alembic import command
from sqlalchemy import text
from sqlalchemy.exc import DBAPIError
from test_dormant_catalog import alembic_config, empty_schema
from test_max_agents_migration import fenced, workspace
from test_migration_without_bypass import restricted as restricted
from test_scout_delta_migration import entra

from execbound.db import FUNCTIONS, INSERT_COLUMNS, TABLES, UPDATE_COLUMNS

pytestmark = pytest.mark.integration

BEFORE = "0097_findings_destinations"
TARGET = "0098_scout_drivers"
DIRECTORY = "11111111-2222-3333-4444-555555555555"
SIGNATURE = "execbound.admin_set_egress_addresses(uuid, uuid, inet[])"
COLUMNS = (
    ("monitor_connections", "sign_in_cursor"),
    ("monitor_connections", "egress_addresses"),
    ("monitor_connections", "egress_recorded_at"),
    ("monitor_connections", "egress_recorded_by"),
    ("monitor_inventory", "host_scope"),
    ("monitor_inventory", "story_refs"),
    ("monitor_inventory", "references_capped"),
    ("monitor_agents", "user_agent_hint"),
    ("monitor_agents", "user_agent_seen_at"),
)
SCHEMA = """
    SELECT
        to_regclass('execbound.monitor_actor_drivers') IS NOT NULL AS drivers,
        to_regprocedure(:signature) IS NOT NULL AS function,
        (SELECT count(*) FROM information_schema.columns
          WHERE table_schema = 'execbound'
            AND (table_name, column_name) IN (
                ('monitor_connections', 'sign_in_cursor'),
                ('monitor_connections', 'egress_addresses'),
                ('monitor_connections', 'egress_recorded_at'),
                ('monitor_connections', 'egress_recorded_by'),
                ('monitor_inventory', 'host_scope'),
                ('monitor_inventory', 'story_refs'),
                ('monitor_inventory', 'references_capped'),
                ('monitor_agents', 'user_agent_hint'),
                ('monitor_agents', 'user_agent_seen_at'))) AS columns
"""
FORCED = (
    "SELECT count(*) FROM pg_class WHERE relnamespace = 'execbound'::regnamespace "
    "AND relkind = 'r' AND relforcerowsecurity"
)


def present(engine):
    with engine.connect() as conn:
        return tuple(conn.execute(text(SCHEMA), {"signature": SIGNATURE}).one())


def tines(conn, tenant, space, admin):
    connection = uuid4()
    conn.execute(
        text(
            "INSERT INTO execbound.monitor_connections "
            "(tenant_id, connection_id, label, base_url, key_fingerprint, created_at, "
            " created_by, space_id) "
            "VALUES (:t, :c, 'Tines', 'https://fixture.tines.com', :f, now(), :a, :s)"
        ),
        {"t": tenant, "c": connection, "f": "cd" * 32, "a": admin, "s": space},
    )
    return connection


def agent(conn, tenant, connection):
    agent_id = uuid4()
    conn.execute(
        text(
            "INSERT INTO execbound.monitor_agents "
            "(tenant_id, agent_id, connection_id, platform_ref, identity_class, display_name, "
            " sponsors, sponsor_state, first_seen_at, observed_at) "
            "VALUES (:t, :a, :c, :ref, 'service_principal', 'Synthetic', '[]'::jsonb, "
            " 'not_read', now(), now())"
        ),
        {"t": tenant, "a": agent_id, "c": connection, "ref": str(uuid4())},
    )
    return agent_id


def refusal(config):
    try:
        command.downgrade(config, BEFORE)
    except RuntimeError as exc:
        return str(exc).split(":", 1)[0]
    return None


def test_sr25_the_upgrade_adds_the_driver_evidence_and_the_downgrade_refuses_while_it_is_retained(
    admin_engine,
):
    empty_schema(admin_engine)
    config = alembic_config()
    command.downgrade(config, BEFORE)
    try:
        assert present(admin_engine) == (False, False, 0)
        with admin_engine.connect() as conn:
            forced = conn.execute(text(FORCED)).scalar_one()
        command.upgrade(config, TARGET)
        assert present(admin_engine) == (True, True, len(COLUMNS))
        with admin_engine.connect() as conn:
            assert conn.execute(text(FORCED)).scalar_one() == forced + 1
        tenant, space, admin = workspace(admin_engine, "team")
        with admin_engine.begin() as conn:
            directory = entra(
                conn, tenant, space, admin, directory=DIRECTORY, synced=datetime.now(UTC)
            )
            actor = agent(conn, tenant, directory)
            conn.execute(
                text(
                    "INSERT INTO execbound.monitor_actor_drivers (tenant_id, agent_id, "
                    "evidence, platform_ref, source_connection_id, first_seen_at, last_seen_at) "
                    "VALUES (:t, :a, 'network', 'egress:anthropic', :c, now(), now())"
                ),
                {"t": tenant, "a": actor, "c": directory},
            )
            tenant_tines = tines(conn, tenant, space, admin)
        # Driver evidence is retained: the earlier schema cannot hold it.
        assert refusal(config) == "SCOUT_DRIVERS_RETAINED"
        with admin_engine.begin() as conn:
            conn.execute(text("DELETE FROM execbound.monitor_actor_drivers"))
            conn.execute(
                text(
                    "UPDATE execbound.monitor_connections SET "
                    "egress_addresses = ARRAY['18.200.10.20']::inet[], egress_recorded_at = now(), "
                    "egress_recorded_by = :a WHERE connection_id = :c"
                ),
                {"a": admin, "c": tenant_tines},
            )
        # So is a recorded egress address.
        assert refusal(config) == "SCOUT_DRIVERS_RETAINED"
        with admin_engine.begin() as conn:
            conn.execute(
                text(
                    "UPDATE execbound.monitor_connections SET egress_addresses = NULL "
                    "WHERE connection_id = :c"
                ),
                {"c": tenant_tines},
            )
            conn.execute(
                text(
                    "UPDATE execbound.monitor_connections SET sign_in_cursor = now() "
                    "WHERE connection_id = :c"
                ),
                {"c": directory},
            )
        # A cursor, a scope and a hint are state, not evidence: they go with their columns.
        assert refusal(config) is None
        assert present(admin_engine) == (False, False, 0)
        command.upgrade(config, TARGET)
        assert present(admin_engine) == (True, True, len(COLUMNS))
    finally:
        empty_schema(admin_engine)
        command.upgrade(config, "head")


FORCED_HERE = (
    "SELECT relname, relforcerowsecurity FROM pg_class "
    "WHERE relnamespace = 'execbound'::regnamespace "
    "AND relname IN ('monitor_actor_drivers', 'monitor_connections')"
)


def test_sr25_the_downgrade_sees_every_tenant_as_the_hosted_owner(restricted):
    """The hosted owner does not bypass row security, so unfenced it sees no tenant's rows: the
    downgrade refuses only because its look lifts FORCE, and it puts FORCE back whether it
    refuses or proceeds."""
    engine, config, _ = restricted
    command.upgrade(config, BEFORE)
    tenant, space, admin = workspace(engine, "team")
    command.upgrade(config, TARGET)
    with engine.begin() as conn:
        fenced(conn, tenant)
        directory = entra(conn, tenant, space, admin, directory=DIRECTORY, synced=None)
        actor = agent(conn, tenant, directory)
        conn.execute(
            text(
                "INSERT INTO execbound.monitor_actor_drivers (tenant_id, agent_id, "
                "evidence, platform_ref, source_connection_id, first_seen_at, last_seen_at) "
                "VALUES (:t, :a, 'network', 'egress:anthropic', :c, now(), now())"
            ),
            {"t": tenant, "a": actor, "c": directory},
        )
        tenant_tines = tines(conn, tenant, space, admin)
    with engine.connect() as conn:
        # Unfenced, this owner sees nothing: only a look with row security lifted finds the row.
        assert (
            conn.execute(text("SELECT count(*) FROM execbound.monitor_actor_drivers")).scalar_one()
            == 0
        )
    assert refusal(config) == "SCOUT_DRIVERS_RETAINED"
    with engine.connect() as conn:
        assert all(forced for _, forced in conn.execute(text(FORCED_HERE)).all())
    with engine.begin() as conn:
        fenced(conn, tenant)
        conn.execute(text("DELETE FROM execbound.monitor_actor_drivers"))
        conn.execute(
            text(
                "UPDATE execbound.monitor_connections SET "
                "egress_addresses = ARRAY['18.200.10.20']::inet[], egress_recorded_at = now(), "
                "egress_recorded_by = :a WHERE connection_id = :c"
            ),
            {"a": admin, "c": tenant_tines},
        )
    assert refusal(config) == "SCOUT_DRIVERS_RETAINED"
    with engine.begin() as conn:
        fenced(conn, tenant)
        conn.execute(
            text(
                "UPDATE execbound.monitor_connections SET egress_addresses = NULL "
                "WHERE connection_id = :c"
            ),
            {"c": tenant_tines},
        )
    assert refusal(config) is None
    with engine.connect() as conn:
        assert conn.execute(text(FORCED_HERE)).all() == [("monitor_connections", True)]


def test_sr25_the_runtime_reads_inserts_and_updates_driver_rows_and_deletes_none(admin_engine):
    assert "monitor_actor_drivers" in TABLES
    assert UPDATE_COLUMNS["monitor_actor_drivers"] == {
        "first_seen_at",
        "last_seen_at",
        "gone_at",
        "detail_refs",
        "detail_capped",
        "catalog_version",
    }
    with admin_engine.connect() as conn:
        table = {
            privilege: conn.execute(
                text(
                    "SELECT has_table_privilege('execbound_app', "
                    "'execbound.monitor_actor_drivers', :p)"
                ),
                {"p": privilege},
            ).scalar_one()
            for privilege in ("SELECT", "INSERT", "DELETE", "TRUNCATE")
        }
        flags = conn.execute(
            text(
                "SELECT relrowsecurity, relforcerowsecurity FROM pg_class "
                "WHERE oid = 'execbound.monitor_actor_drivers'::regclass"
            )
        ).one()
        moving = {
            column
            for column in (
                "tenant_id",
                "agent_id",
                "evidence",
                "platform_ref",
                "source_connection_id",
                *UPDATE_COLUMNS["monitor_actor_drivers"],
            )
            if conn.execute(
                text(
                    "SELECT has_column_privilege('execbound_app', "
                    "'execbound.monitor_actor_drivers', :c, 'UPDATE')"
                ),
                {"c": column},
            ).scalar_one()
        }
    assert table == {"SELECT": True, "INSERT": True, "DELETE": False, "TRUNCATE": False}
    assert tuple(flags) == (True, True)
    assert moving == UPDATE_COLUMNS["monitor_actor_drivers"]


@pytest.mark.parametrize(
    ("table", "column", "update"),
    [
        ("monitor_connections", "sign_in_cursor", True),
        ("monitor_connections", "egress_addresses", False),
        ("monitor_connections", "egress_recorded_at", False),
        ("monitor_connections", "egress_recorded_by", False),
        ("monitor_inventory", "host_scope", True),
        ("monitor_inventory", "story_refs", True),
        ("monitor_inventory", "references_capped", True),
        ("monitor_agents", "user_agent_hint", True),
        ("monitor_agents", "user_agent_seen_at", True),
    ],
)
def test_sr26_what_the_runtime_may_write_of_each_new_column(admin_engine, table, column, update):
    with admin_engine.connect() as conn:
        held = {
            privilege: conn.execute(
                text("SELECT has_column_privilege('execbound_app', :t, :c, :p)"),
                {"t": f"execbound.{table}", "c": column, "p": privilege},
            ).scalar_one()
            for privilege in ("UPDATE", "INSERT")
        }
    assert held["UPDATE"] is update
    # The connection's insertable set is unchanged; the other two tables insert by table grant.
    assert held["INSERT"] is (table != "monitor_connections")
    assert column not in INSERT_COLUMNS["monitor_connections"]
    assert (column in UPDATE_COLUMNS[table]) is update


def test_sr27_the_egress_function_runs_as_its_owner_on_a_fixed_path_for_the_runtime_alone(
    admin_engine,
):
    assert (
        "admin_set_egress_addresses",
        "p_actor uuid, p_connection uuid, p_addresses inet[]",
    ) in (FUNCTIONS)
    with admin_engine.connect() as conn:
        row = (
            conn.execute(
                text(
                    "SELECT p.prosecdef, p.proconfig, r.rolname AS owner, "
                    "has_function_privilege('execbound_app', p.oid, 'EXECUTE') AS runtime, "
                    "EXISTS (SELECT 1 FROM aclexplode(p.proacl) a WHERE a.grantee = 0) "
                    "  AS public, "
                    "(SELECT array_agg(a.grantee::regrole::text ORDER BY 1) "
                    "   FROM aclexplode(p.proacl) a WHERE a.grantee <> p.proowner) AS grantees "
                    "FROM pg_proc p JOIN pg_roles r ON r.oid = p.proowner "
                    "WHERE p.oid = to_regprocedure(:signature)"
                ),
                {"signature": SIGNATURE},
            )
            .mappings()
            .one()
        )
    assert row["prosecdef"] is True
    assert row["proconfig"] == ["search_path=pg_catalog, pg_temp"]
    assert row["owner"] != "execbound_app"
    assert (row["runtime"], row["public"]) == (True, False)
    assert row["grantees"] == ["execbound_app"]


def test_sr27_the_egress_function_admits_only_the_caller_s_own_tines_connection_without_bypass(
    restricted,
):
    """The hosted owner does not bypass row security, and the function runs as its owner. Under
    such an owner it records the caller's own workspace's Tines connection, and refuses another
    workspace's, an Entra connection, an actor that is not an active administrator and no
    workspace at all."""
    engine, config, _ = restricted
    command.upgrade(config, TARGET)
    made = {}
    for name in ("one", "two"):
        tenant, space, admin = workspace(engine, "team")
        with engine.begin() as conn:
            fenced(conn, tenant)
            made[name] = (tenant, admin, tines(conn, tenant, space, admin))
    tenant, admin, mine = made["one"]
    _, _, theirs = made["two"]
    with engine.begin() as conn:
        fenced(conn, tenant)
        directory = entra(
            conn,
            tenant,
            conn.execute(
                text("SELECT space_id FROM execbound.spaces WHERE tenant_id = :t"), {"t": tenant}
            ).scalar_one(),
            admin,
            directory=DIRECTORY,
            synced=None,
        )

    def call(fence, actor, connection, addresses):
        try:
            with engine.begin() as conn:
                if fence is not None:
                    fenced(conn, fence)
                conn.execute(
                    text("SELECT execbound.admin_set_egress_addresses(:a, :c, CAST(:v AS inet[]))"),
                    {"a": actor, "c": connection, "v": addresses},
                )
        except DBAPIError as exc:
            return exc.orig.diag.message_primary
        return None

    assert call(tenant, admin, mine, ["18.200.10.20"]) is None
    with engine.begin() as conn:
        fenced(conn, tenant)
        recorded = conn.execute(
            text(
                "SELECT host(egress_addresses[1]), egress_recorded_by "
                "FROM execbound.monitor_connections WHERE connection_id = :c"
            ),
            {"c": mine},
        ).one()
    assert tuple(recorded) == ("18.200.10.20", admin)
    assert call(tenant, admin, theirs, ["18.200.10.20"]) == "INVALID_STATE"
    assert call(tenant, admin, directory, ["18.200.10.20"]) == "INVALID_STATE"
    assert call(tenant, uuid4(), mine, ["18.200.10.20"]) == "INVALID_ACTOR"
    assert call(None, admin, mine, ["18.200.10.20"]) == "INVALID_TENANT"
    assert call(tenant, admin, mine, ["10.1.2.3"]) == "INVALID_EGRESS"
    assert call(tenant, admin, mine, []) is None
