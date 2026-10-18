# SPDX-License-Identifier: AGPL-3.0-only
"""Identity context migration against the guarded, exclusive local test database."""

import importlib.util
import os
from uuid import uuid4

import pytest
from alembic import command
from alembic.config import Config
from alembic.migration import MigrationContext
from alembic.operations import Operations
from sqlalchemy import text
from sqlalchemy.exc import DBAPIError
from test_execution_database import execution_storage as execution_storage

from execbound.db import SCHEMA_REVISION, TABLES, check_runtime

pytestmark = pytest.mark.integration

ACTIONS = ("endpoint.isolate", "identity.disable", "identity.enable", "identity.revoke_sessions")


def migration_config():
    config = Config("alembic.ini")
    config.attributes["database_url"] = os.environ["TEST_MIGRATION_DATABASE_URL"]
    return config


@pytest.fixture
def inventory(admin_engine, execution_storage, seeded):
    account, source, resource = uuid4(), uuid4(), uuid4()
    with admin_engine.begin() as conn:
        for tenant in seeded["tenants"]:
            values = {"t": tenant, "a": account, "s": source, "r": resource}
            conn.execute(
                text(
                    "INSERT INTO execbound.connector_accounts(tenant_id,account_id,provider, "
                    "space_id) "
                    "VALUES (:t,:a,'mock_entra', "
                    "(SELECT space_id FROM execbound.spaces WHERE tenant_id = :t))"
                ),
                values,
            )
            conn.execute(
                text(
                    "INSERT INTO execbound.context_sources "
                    "(tenant_id,account_id,source_id,kind,allowed_writers) "
                    "VALUES (:t,:a,:s,'inventory',ARRAY['inventory_sync'])"
                ),
                values,
            )
            conn.execute(
                text(
                    "INSERT INTO execbound.resources "
                    "(tenant_id,account_id,provider,resource_type,resource_id,provider_id,"
                    "version,source_id,environment,criticality,privilege_class,observed_at) "
                    "VALUES (:t,:a,'mock_entra','identity',:r,'user-01','v1',:s,"
                    "'production',2,'standard',now())"
                ),
                values,
            )
    return {"account": account, "source": source, "resource": resource}


@pytest.mark.parametrize("privilege", [None, "standard", "privileged", "tier0"])
def test_owner_can_provision_bounded_privilege(admin_engine, inventory, seeded, privilege):
    with admin_engine.begin() as conn:
        conn.execute(
            text("UPDATE execbound.resources SET privilege_class=:p WHERE account_id=:a"),
            {"p": privilege, "a": inventory["account"]},
        )
        assert (
            conn.execute(
                text(
                    "SELECT privilege_class FROM execbound.resources "
                    "WHERE tenant_id=:t AND account_id=:a"
                ),
                {"t": seeded["tenants"][0], "a": inventory["account"]},
            ).scalar_one()
            == privilege
        )


@pytest.mark.parametrize("privilege", ["", "unknown", "STANDARD", "tier1", "administrator"])
def test_unknown_privilege_is_rejected(admin_engine, inventory, privilege):
    with (
        pytest.raises(DBAPIError, match="resources_privilege_class_check"),
        admin_engine.begin() as conn,
    ):
        conn.execute(text("UPDATE execbound.resources SET privilege_class=:p"), {"p": privilege})


@pytest.mark.parametrize("action", ACTIONS)
def test_both_action_constraints_accept_catalog_actions(admin_engine, execution_storage, action):
    with admin_engine.begin() as conn:
        conn.execute(text("UPDATE execbound.approval_scopes SET action=:a"), {"a": action})
        conn.execute(text("UPDATE execbound.execution_impact SET action=:a"), {"a": action})


@pytest.mark.parametrize("table", ["approval_scopes", "execution_impact"])
@pytest.mark.parametrize(
    "action", ["identity.delete", "identity.*", "endpoint.disable", "", "IDENTITY.ENABLE"]
)
def test_unknown_action_is_rejected(admin_engine, execution_storage, table, action):
    with pytest.raises(DBAPIError, match=f"{table}_action_check"), admin_engine.begin() as conn:
        conn.execute(text(f"UPDATE execbound.{table} SET action=:a"), {"a": action})


def test_identity_inventory_is_read_only_and_tenant_isolated(db, inventory, seeded, admin_engine):
    with db.engine.connect() as conn:
        assert conn.execute(text("SELECT count(*) FROM execbound.resources")).scalar_one() == 0
    for tenant in seeded["tenants"]:
        with db.transaction(tenant) as conn:
            check_runtime(conn)
            assert conn.execute(
                text(
                    "SELECT tenant_id,privilege_class FROM execbound.resources "
                    "WHERE resource_type='identity'"
                )
            ).all() == [(tenant, "standard")]
        for statement in (
            "UPDATE execbound.resources SET privilege_class='tier0'",
            "INSERT INTO execbound.resources SELECT * FROM execbound.resources",
            "DELETE FROM execbound.resources",
        ):
            with (
                pytest.raises(DBAPIError, match="permission denied"),
                db.transaction(tenant) as conn,
            ):
                conn.execute(text(statement))
    with admin_engine.connect() as conn:
        assert conn.execute(
            text(
                "SELECT relrowsecurity,relforcerowsecurity FROM pg_class "
                "WHERE oid='execbound.resources'::regclass"
            )
        ).one() == (True, True)
        assert (
            conn.execute(
                text(
                    "SELECT has_column_privilege('execbound_app', "
                    "'execbound.resources','privilege_class','UPDATE')"
                )
            ).scalar_one()
            is False
        )


@pytest.mark.parametrize("mismatch", ["tenant", "account", "provider", "source"])
def test_identity_inventory_requires_matching_tenant_account_source(
    admin_engine,
    inventory,
    seeded,
    mismatch,
):
    values = {
        "t": seeded["tenants"][0],
        "a": inventory["account"],
        "s": inventory["source"],
        "p": "mock_entra",
    }
    values[{"tenant": "t", "account": "a", "provider": "p", "source": "s"}[mismatch]] = (
        "mock_crowdstrike" if mismatch == "provider" else uuid4()
    )
    with pytest.raises(DBAPIError, match="foreign key constraint"), admin_engine.begin() as conn:
        conn.execute(
            text(
                "INSERT INTO execbound.resources "
                "(tenant_id,account_id,provider,resource_type,resource_id,provider_id,"
                "version,source_id,privilege_class,observed_at) "
                "VALUES (:t,:a,:p,'identity',gen_random_uuid(),'foreign','v1',:s,"
                "'standard',now())"
            ),
            values,
        )


def assert_downgrade_refused(admin_engine):
    with pytest.raises(RuntimeError, match="identity data or history"):
        command.downgrade(migration_config(), "0006_human_sessions")
    with admin_engine.connect() as conn:
        assert (
            conn.execute(text("SELECT version_num FROM execbound.alembic_version")).scalar_one()
            == SCHEMA_REVISION
        )
        assert (
            conn.execute(
                text(
                    "SELECT count(*) FROM pg_class WHERE relnamespace='execbound'::regnamespace "
                    "AND relkind='r' AND relname<>'alembic_version' "
                    "AND (NOT relrowsecurity OR NOT relforcerowsecurity)"
                )
            ).scalar_one()
            == 0
        )


def test_downgrade_refuses_identity_inventory(admin_engine, inventory):
    assert_downgrade_refused(admin_engine)


def test_non_bypass_owner_refuses_other_tenant_history_without_tenant_context(
    admin_engine,
    inventory,
    seeded,
):
    spec = importlib.util.spec_from_file_location(
        "identity_migration", "migrations/versions/0007_identity_context.py"
    )
    migration = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(migration)
    probe_role = "identity_migration_probe_" + uuid4().hex
    with admin_engine.connect() as conn, conn.begin() as outer:
        # Everything, including the temporary role and ownership, rolls back.
        # This is required because the local provisioning owner is a superuser,
        # whereas the hosted migration owner cannot bypass forced RLS.
        conn.execute(text(f"CREATE ROLE {probe_role} NOLOGIN NOSUPERUSER NOBYPASSRLS"))
        conn.execute(text(f"GRANT USAGE ON SCHEMA execbound TO {probe_role}"))
        for table in migration.HISTORY_TABLES:
            conn.execute(text(f"ALTER TABLE execbound.{table} OWNER TO {probe_role}"))
        conn.execute(text(f"SET LOCAL ROLE {probe_role}"))
        conn.execute(text("SELECT set_config('execbound.tenant_id', '', true)"))
        assert conn.execute(text("SELECT count(*) FROM execbound.resources")).scalar_one() == 0
        with pytest.raises(RuntimeError, match="identity data or history"), conn.begin_nested():
            with Operations.context(MigrationContext.configure(conn)):
                migration.downgrade()
        assert (
            conn.execute(
                text(
                    "SELECT count(*) FROM pg_class "
                    "WHERE relnamespace='execbound'::regnamespace "
                    "AND relkind='r' AND relname=ANY(:tables) "
                    "AND (NOT relrowsecurity OR NOT relforcerowsecurity)"
                ),
                {"tables": list(migration.HISTORY_TABLES)},
            ).scalar_one()
            == 0
        )
        assert conn.execute(text("SELECT count(*) FROM execbound.resources")).scalar_one() == 0
        conn.execute(
            text("SELECT set_config('execbound.tenant_id', :t, true)"),
            {"t": str(seeded["tenants"][1])},
        )
        assert (
            conn.execute(
                text(
                    "SELECT privilege_class FROM execbound.resources WHERE resource_type='identity'"
                )
            ).scalar_one()
            == "standard"
        )
        outer.rollback()


def test_downgrade_refuses_privilege_evidence_on_endpoint(admin_engine, execution_storage):
    with admin_engine.begin() as conn:
        conn.execute(text("UPDATE execbound.resources SET privilege_class='standard'"))
    assert_downgrade_refused(admin_engine)


@pytest.mark.parametrize("table", ["approval_scopes", "execution_impact"])
def test_downgrade_refuses_identity_action_even_if_inactive(admin_engine, execution_storage, table):
    with admin_engine.begin() as conn:
        conn.execute(text(f"UPDATE execbound.{table} SET action='identity.enable'"))
        if table == "approval_scopes":
            conn.execute(text("UPDATE execbound.approval_scopes SET active=false"))
    assert_downgrade_refused(admin_engine)


def test_downgrade_refuses_inactive_identity_mapping(admin_engine, execution_storage, seeded):
    with admin_engine.begin() as conn:
        conn.execute(
            text(
                "INSERT INTO execbound.operation_mappings "
                "(tenant_id,operation_ref,account_id,provider,resource_type,action,"
                "provider_operation,mapping_version,schema_version,"
                "context_contract_version,active) "
                "VALUES (:t,'identity.enable',:a,'mock_crowdstrike','identity',"
                "'identity.enable','enable','v1','action.v1','identity-control.v1',false)"
            ),
            {"t": seeded["tenants"][0], "a": execution_storage["account"]},
        )
    assert_downgrade_refused(admin_engine)


@pytest.mark.parametrize(
    "table,column,document",
    [
        ("executions", "frozen", '{"resolved":{"intent":{"action":"identity.disable"}}}'),
        ("executions", "result", '{"provider":"mock_entra"}'),
        ("execution_events", "payload", '{"operation":{"action":"identity.revoke_sessions"}}'),
        (
            "policy_bundle_contents",
            "content",
            '{"policy":"permit(action == Action::\\"identity.enable\\");"}',
        ),
    ],
)
def test_downgrade_refuses_retained_identity_history(
    admin_engine,
    execution_storage,
    table,
    column,
    document,
):
    with admin_engine.begin() as conn:
        conn.execute(
            text(f"UPDATE execbound.{table} SET {column}=CAST(:d AS jsonb)"), {"d": document}
        )
    assert_downgrade_refused(admin_engine)


def test_endpoint_rows_and_permissions_survive_migration_round_trip(
    admin_engine,
    execution_storage,
    seeded,
):
    with admin_engine.connect() as conn:
        before = (
            conn.execute(
                text(
                    "SELECT to_jsonb(r)-'privilege_class'-'demo_fixture' "
                    "FROM execbound.resources r "
                    "ORDER BY tenant_id"
                )
            )
            .scalars()
            .all()
        )
        grants = conn.execute(
            text("SELECT relacl::text FROM pg_class WHERE oid='execbound.resources'::regclass")
        ).scalar_one()
    try:
        command.downgrade(migration_config(), "0006_human_sessions")
        with admin_engine.connect() as conn:
            assert (
                conn.execute(
                    text("SELECT to_jsonb(r) FROM execbound.resources r ORDER BY tenant_id")
                )
                .scalars()
                .all()
                == before
            )
    finally:
        command.upgrade(migration_config(), "head")
    with admin_engine.connect() as conn:
        assert (
            conn.execute(
                text(
                    "SELECT to_jsonb(r)-'privilege_class'-'demo_fixture' "
                    "FROM execbound.resources r "
                    "ORDER BY tenant_id"
                )
            )
            .scalars()
            .all()
            == before
        )
        assert (
            conn.execute(
                text("SELECT relacl::text FROM pg_class WHERE oid='execbound.resources'::regclass")
            ).scalar_one()
            == grants
        )


def test_empty_database_round_trip(admin_engine):
    # admin_engine independently validates loopback, database name and owner.
    with admin_engine.begin() as conn:
        conn.execute(text("TRUNCATE " + ", ".join(f"execbound.{table}" for table in TABLES)))
    try:
        command.downgrade(migration_config(), "base")
    finally:
        command.upgrade(migration_config(), "head")
