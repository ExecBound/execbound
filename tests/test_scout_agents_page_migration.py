# SPDX-License-Identifier: AGPL-3.0-only
"""Migration 0099: the Agents page as the to-do list, and the synthetic directory (#355, step 4).

Real PostgreSQL. The upgrade widens the identity classes and lets the runtime move them, keeps a
principal's application id, admits the synthetic directory's one shape beside no Microsoft Entra
connection, adds the append-only acceptance history, makes two definer functions the only writers
of an acceptance, refuses to bind a synthetic actor or to send its findings, and lets the purge
read both directory kinds. The downgrade refuses while a synthetic directory or an acceptance's
history is retained, and otherwise maps the new classes back and removes what it added. Under an
owner that does not bypass row security, as the hosted owner does not, it still sees every
tenant, and the functions admit only the caller's own workspace.
"""

from uuid import uuid4

import pytest
from alembic import command
from sqlalchemy import text
from sqlalchemy.exc import DBAPIError
from test_dormant_catalog import alembic_config, empty_schema
from test_max_agents_migration import fenced, workspace
from test_migration_without_bypass import restricted as restricted
from test_scout_delta_migration import entra

from execbound.db import FUNCTIONS, TABLES, UPDATE_COLUMNS
from execbound.monitoring import synthetic

pytestmark = pytest.mark.integration

BEFORE = "0098_scout_drivers"
TARGET = "0099_scout_agents_page"
DIRECTORY = "11111111-2222-3333-4444-555555555555"
SIGNATURES = (
    "execbound.admin_add_synthetic_directory(uuid, uuid, uuid)",
    "execbound.admin_accept_reach(uuid, uuid, text, text, text, text, timestamp with time zone)",
    "execbound.admin_withdraw_reach(uuid, uuid, text, text, text)",
)
TRIGGERS = (
    "monitor_connections_directory_coexist",
    "agent_bindings_not_synthetic",
    "monitor_deliveries_not_synthetic",
    "monitor_agents_class_family",
)
SCHEMA = """
    SELECT
        to_regclass('execbound.monitor_reach_acceptances') IS NOT NULL AS history,
        (SELECT count(*) FROM unnest(CAST(:signatures AS text[])) s
          WHERE to_regprocedure(s) IS NOT NULL) AS functions,
        (SELECT count(*) FROM pg_trigger WHERE NOT tgisinternal
          AND tgname = ANY(CAST(:triggers AS text[]))) AS triggers,
        EXISTS (SELECT 1 FROM information_schema.columns WHERE table_schema = 'execbound'
          AND table_name = 'monitor_agents' AND column_name = 'app_ref') AS app_ref
"""
FORCED = (
    "SELECT count(*) FROM pg_class WHERE relnamespace = 'execbound'::regnamespace "
    "AND relkind = 'r' AND relforcerowsecurity"
)


def present(engine):
    with engine.connect() as conn:
        return tuple(
            conn.execute(
                text(SCHEMA), {"signatures": list(SIGNATURES), "triggers": list(TRIGGERS)}
            ).one()
        )


def synthetic_row(conn, tenant, space, admin):
    connection = uuid4()
    conn.execute(
        text(
            "INSERT INTO execbound.monitor_connections (tenant_id, connection_id, label, "
            "base_url, created_at, created_by, kind, directory_ref, client_ref, space_id, "
            "credential_mode) VALUES (:t, :c, :label, :url, now(), :a, 'fixture', :d, :cl, :s, "
            "'synthetic')"
        ),
        {
            "t": tenant,
            "c": connection,
            "label": synthetic.LABEL,
            "url": synthetic.BASE_URL,
            "a": admin,
            "d": synthetic.DIRECTORY,
            "cl": synthetic.CLIENT,
            "s": space,
        },
    )
    return connection


def actor(conn, tenant, connection, identity_class="service_principal"):
    agent_id = uuid4()
    conn.execute(
        text(
            "INSERT INTO execbound.monitor_agents (tenant_id, agent_id, connection_id, "
            "platform_ref, identity_class, display_name, sponsors, sponsor_state, first_seen_at, "
            "observed_at) VALUES (:t, :a, :c, :ref, :class, 'Synthetic', '[]'::jsonb, "
            "'not_read', now(), now())"
        ),
        {"t": tenant, "a": agent_id, "c": connection, "ref": str(uuid4()), "class": identity_class},
    )
    return agent_id


def history(conn, tenant, agent_id, admin):
    conn.execute(
        text(
            "INSERT INTO execbound.monitor_reach_acceptances (tenant_id, acceptance_id, agent_id, "
            "action, path_kind, path_ref, change, reason_code, recorded_by, recorded_at) VALUES "
            "(:t, gen_random_uuid(), :a, 'identity.disable', 'grant', 'path', 'accepted', "
            "'BREAK_GLASS', :by, now())"
        ),
        {"t": tenant, "a": agent_id, "by": admin},
    )


def refusal(config):
    try:
        command.downgrade(config, BEFORE)
    except RuntimeError as exc:
        return str(exc).split(":", 1)[0]
    return None


def test_sr31_the_upgrade_adds_the_page_s_schema_and_the_downgrade_refuses_while_it_is_retained(
    admin_engine,
):
    empty_schema(admin_engine)
    config = alembic_config()
    command.downgrade(config, BEFORE)
    try:
        assert present(admin_engine) == (False, 0, 0, False)
        with admin_engine.connect() as conn:
            forced = conn.execute(text(FORCED)).scalar_one()
        command.upgrade(config, TARGET)
        assert present(admin_engine) == (True, len(SIGNATURES), len(TRIGGERS), True)
        with admin_engine.connect() as conn:
            assert conn.execute(text(FORCED)).scalar_one() == forced + 1
        tenant, space, admin = workspace(admin_engine, "team")
        with admin_engine.begin() as conn:
            fixture = synthetic_row(conn, tenant, space, admin)
        # A synthetic directory is retained: the earlier schema cannot hold it.
        assert refusal(config) == "SCOUT_AGENTS_PAGE_RETAINED"
        with admin_engine.begin() as conn:
            conn.execute(text("DELETE FROM execbound.monitor_connections WHERE kind = 'fixture'"))
            directory = entra(conn, tenant, space, admin, directory=DIRECTORY, synced=None)
            managed = actor(conn, tenant, directory, "managed_identity")
            consented = actor(conn, tenant, directory, "consented_app")
            conn.execute(
                text("UPDATE execbound.monitor_agents SET app_ref = :app WHERE agent_id = :a"),
                {"app": str(uuid4()), "a": managed},
            )
            history(conn, tenant, managed, admin)
        assert fixture is not None
        # So is an acceptance's history.
        assert refusal(config) == "SCOUT_AGENTS_PAGE_RETAINED"
        with admin_engine.begin() as conn:
            conn.execute(text("DELETE FROM execbound.monitor_reach_acceptances"))
        # The classes and the application id are derived again: they go with their columns.
        assert refusal(config) is None
        assert present(admin_engine) == (False, 0, 0, False)
        with admin_engine.connect() as conn:
            assert set(
                conn.execute(
                    text(
                        "SELECT identity_class FROM execbound.monitor_agents "
                        "WHERE agent_id = ANY(:a)"
                    ),
                    {"a": [managed, consented]},
                ).scalars()
            ) == {"service_principal"}
        command.upgrade(config, TARGET)
        assert present(admin_engine) == (True, len(SIGNATURES), len(TRIGGERS), True)
    finally:
        empty_schema(admin_engine)
        command.upgrade(config, "head")


FORCED_HERE = (
    "SELECT relname, relforcerowsecurity FROM pg_class "
    "WHERE relnamespace = 'execbound'::regnamespace "
    "AND relname IN ('monitor_connections', 'monitor_agents', 'monitor_reach_acceptances')"
)


def test_sr31_the_downgrade_sees_every_tenant_as_the_hosted_owner(restricted):
    """The hosted owner does not bypass row security, so unfenced it sees no tenant's rows: the
    downgrade refuses a retained synthetic directory, and then a retained acceptance's history,
    only because its look lifts FORCE, maps the classes of every tenant, and puts FORCE back
    whether it refuses or proceeds."""
    engine, config, _ = restricted
    command.upgrade(config, BEFORE)
    tenant, space, admin = workspace(engine, "team")
    command.upgrade(config, TARGET)
    with engine.begin() as conn:
        fenced(conn, tenant)
        synthetic_row(conn, tenant, space, admin)
    with engine.connect() as conn:
        assert (
            conn.execute(
                text("SELECT count(*) FROM execbound.monitor_connections WHERE kind = 'fixture'")
            ).scalar_one()
            == 0
        )
    assert refusal(config) == "SCOUT_AGENTS_PAGE_RETAINED"
    with engine.connect() as conn:
        assert all(forced for _, forced in conn.execute(text(FORCED_HERE)).all())
    with engine.begin() as conn:
        fenced(conn, tenant)
        conn.execute(text("DELETE FROM execbound.monitor_connections WHERE kind = 'fixture'"))
        directory = entra(conn, tenant, space, admin, directory=DIRECTORY, synced=None)
        managed = actor(conn, tenant, directory, "managed_identity")
        history(conn, tenant, managed, admin)
    with engine.connect() as conn:
        assert (
            conn.execute(
                text("SELECT count(*) FROM execbound.monitor_reach_acceptances")
            ).scalar_one()
            == 0
        )
    # An acceptance's history is retained too, and is seen as unfenced as the directory was.
    assert refusal(config) == "SCOUT_AGENTS_PAGE_RETAINED"
    with engine.connect() as conn:
        assert all(forced for _, forced in conn.execute(text(FORCED_HERE)).all())
    with engine.begin() as conn:
        fenced(conn, tenant)
        conn.execute(text("DELETE FROM execbound.monitor_reach_acceptances"))
    assert refusal(config) is None
    with engine.connect() as conn:
        assert conn.execute(text(FORCED_HERE)).all() and all(
            forced for _, forced in conn.execute(text(FORCED_HERE)).all()
        )
    with engine.begin() as conn:
        fenced(conn, tenant)
        assert (
            conn.execute(
                text("SELECT identity_class FROM execbound.monitor_agents WHERE agent_id = :a"),
                {"a": managed},
            ).scalar_one()
            == "service_principal"
        )


def test_sr30_the_runtime_reads_the_history_and_writes_an_acceptance_only_through_its_functions(
    admin_engine,
):
    assert "monitor_reach_acceptances" in TABLES
    assert "monitor_reach_exceptions" not in UPDATE_COLUMNS
    assert {"identity_class", "app_ref"} <= UPDATE_COLUMNS["monitor_agents"]
    with admin_engine.connect() as conn:

        def held(table, privilege):
            return conn.execute(
                text("SELECT has_table_privilege('execbound_app', :t, :p)"),
                {"t": f"execbound.{table}", "p": privilege},
            ).scalar_one()

        def column(table, name, privilege):
            return conn.execute(
                text("SELECT has_column_privilege('execbound_app', :t, :c, :p)"),
                {"t": f"execbound.{table}", "c": name, "p": privilege},
            ).scalar_one()

        assert [held("monitor_reach_acceptances", p) for p in ("SELECT", "INSERT", "DELETE")] == [
            True,
            False,
            False,
        ]
        assert not any(
            column("monitor_reach_acceptances", name, "UPDATE")
            for name in ("reason_code", "expires_at", "change")
        )
        assert (
            held("monitor_reach_exceptions", "SELECT"),
            held("monitor_reach_exceptions", "INSERT"),
        ) == (
            True,
            False,
        )
        assert not column("monitor_reach_exceptions", "withdrawn_at", "UPDATE")
        assert column("monitor_agents", "identity_class", "UPDATE")
        assert column("monitor_agents", "app_ref", "UPDATE")
        flags = conn.execute(
            text(
                "SELECT relrowsecurity, relforcerowsecurity FROM pg_class "
                "WHERE oid = 'execbound.monitor_reach_acceptances'::regclass"
            )
        ).one()
        assert tuple(flags) == (True, True)
        for signature in SIGNATURES:
            row = (
                conn.execute(
                    text(
                        "SELECT p.prosecdef, p.proconfig, r.rolname AS owner, "
                        "has_function_privilege('execbound_app', p.oid, 'EXECUTE') AS runtime, "
                        "EXISTS (SELECT 1 FROM aclexplode(p.proacl) a WHERE a.grantee = 0) "
                        "  AS public "
                        "FROM pg_proc p JOIN pg_roles r ON r.oid = p.proowner "
                        "WHERE p.oid = to_regprocedure(:signature)"
                    ),
                    {"signature": signature},
                )
                .mappings()
                .one()
            )
            assert row["prosecdef"] is True, signature
            assert row["proconfig"] == ["search_path=pg_catalog, pg_temp"], signature
            assert row["owner"] != "execbound_app", signature
            assert (row["runtime"], row["public"]) == (True, False), signature
        for name in TRIGGERS:
            definer = conn.execute(
                text("SELECT prosecdef FROM pg_proc WHERE proname = :n"), {"n": name}
            ).scalar_one()
            # They run as their invoker: the runtime's own fence and privileges apply.
            assert definer is False, name
    names = {name for name, _ in FUNCTIONS}
    assert {"admin_add_synthetic_directory", "admin_accept_reach", "admin_withdraw_reach"} <= names


def test_sr31_the_functions_admit_only_the_caller_s_own_workspace_without_bypass(restricted):
    engine, config, _ = restricted
    command.upgrade(config, TARGET)
    made = {}
    for name in ("one", "two"):
        tenant, space, admin = workspace(engine, "team")
        made[name] = (tenant, space, admin)
    tenant, space, admin = made["one"]
    other_tenant, other_space, other_admin = made["two"]
    with engine.begin() as conn:
        fenced(conn, other_tenant)
        directory = entra(
            conn, other_tenant, other_space, other_admin, directory=DIRECTORY, synced=None
        )
        theirs = actor(conn, other_tenant, directory)

    def call(fence, statement, params):
        try:
            with engine.begin() as conn:
                if fence is not None:
                    fenced(conn, fence)
                conn.execute(text(statement), params)
        except DBAPIError as exc:
            return exc.orig.diag.message_primary
        return None

    add = "SELECT execbound.admin_add_synthetic_directory(:a, :s, :c)"
    accept = (
        "SELECT execbound.admin_accept_reach(:a, :agent, 'identity.disable', 'grant', 'path', "
        "'BREAK_GLASS', NULL)"
    )
    assert call(tenant, add, {"a": admin, "s": space, "c": uuid4()}) is None
    assert call(tenant, add, {"a": admin, "s": space, "c": uuid4()}) == "CONNECTION_EXISTS"
    assert call(None, add, {"a": admin, "s": space, "c": uuid4()}) == "INVALID_TENANT"
    assert call(tenant, add, {"a": uuid4(), "s": space, "c": uuid4()}) == "INVALID_ACTOR"
    # Another workspace's actor does not exist for this one; that workspace holds a directory.
    assert call(tenant, accept, {"a": admin, "agent": theirs}) == "INVALID_AGENT"
    assert call(other_tenant, add, {"a": other_admin, "s": other_space, "c": uuid4()}) == (
        "DIRECTORY_CONNECTED"
    )
    assert call(other_tenant, accept, {"a": other_admin, "agent": theirs}) is None
    with engine.begin() as conn:
        fenced(conn, other_tenant)
        assert (
            conn.execute(
                text("SELECT count(*) FROM execbound.monitor_reach_acceptances")
            ).scalar_one()
            == 1
        )
