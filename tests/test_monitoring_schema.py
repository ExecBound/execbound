# SPDX-License-Identifier: AGPL-3.0-only
"""Real PostgreSQL isolation, immutable evidence grants and downgrade retention."""

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
from test_monitoring_store import admins as admins
from test_monitoring_store import api as api
from test_monitoring_store import observation
from test_monitoring_store import setup_monitor as setup_monitor

from execbound.db import SCHEMA_REVISION, UnsafeDatabaseRole, check_runtime
from execbound.monitoring.models import DetectionProfile

TABLES = (
    "monitor_sources",
    "monitor_observations",
    "monitor_findings",
    "monitor_deliveries",
    "monitor_profiles",
)


@pytest.fixture
def history(db, setup_monitor, admins):
    models, store, clock, source, session = setup_monitor
    store.set_profile(
        db,
        admins[0],
        DetectionProfile(sensitive_actions=("identity.disable",), restricted_targets=()),
        clock=clock,
    )
    store.ingest(db, source.token, observation(models, clock), clock=clock)
    store.evaluate_pending(db, admins[0], clock=clock)
    return source, store.snapshot(db, session, clock=clock)


def test_every_monitor_table_forces_rls_and_no_context_has_no_rows(
    db, history, seeded, admin_engine
):
    source, state = history
    with db.engine.connect() as conn:
        for table in TABLES:
            assert conn.execute(text(f"SELECT count(*) FROM execbound.{table}")).scalar_one() == 0
    for tenant, count in ((source.tenant_id, 1), (seeded["tenants"][1], 0)):
        with db.transaction(tenant) as conn:
            check_runtime(conn)
            for table in TABLES:
                assert (
                    conn.execute(text(f"SELECT count(*) FROM execbound.{table}")).scalar_one()
                    == count
                )
    with admin_engine.connect() as conn:
        for table in TABLES:
            assert conn.execute(
                text("""
                SELECT relrowsecurity, relforcerowsecurity FROM pg_class WHERE oid=to_regclass(:t)
            """),
                {"t": f"execbound.{table}"},
            ).one() == (True, True)


@pytest.mark.parametrize(
    "table,column,value",
    [
        ("monitor_sources", "token_hash", "'" + "0" * 64 + "'"),
        ("monitor_sources", "story_id", "'other-story'"),
        ("monitor_observations", "action", "'identity.enable'"),
        ("monitor_observations", "outcome", "'error'"),
        ("monitor_observations", "content_hash", "'" + "0" * 64 + "'"),
        ("monitor_findings", "title", "'changed'"),
        ("monitor_findings", "observation_id", "gen_random_uuid()"),
        ("monitor_deliveries", "finding_id", "gen_random_uuid()"),
    ],
)
def test_runtime_cannot_replace_original_evidence(db, history, table, column, value):
    source, _ = history
    with (
        pytest.raises(DBAPIError, match="permission denied"),
        db.transaction(source.tenant_id) as conn,
    ):
        conn.execute(text(f"UPDATE execbound.{table} SET {column}={value}"))


@pytest.mark.parametrize("table", TABLES)
@pytest.mark.parametrize("operation", ["DELETE FROM", "TRUNCATE"])
def test_runtime_cannot_erase_monitor_history(db, history, table, operation):
    source, _ = history
    with (
        pytest.raises(DBAPIError, match="permission denied"),
        db.transaction(source.tenant_id) as conn,
    ):
        conn.execute(text(f"{operation} execbound.{table}"))


def test_cross_tenant_insert_and_cross_source_finding_are_rejected(
    db, history, seeded, admin_engine
):
    source, state = history
    with (
        pytest.raises(DBAPIError, match="row-level security"),
        db.transaction(seeded["tenants"][1]) as conn,
    ):
        conn.execute(
            text("""
            INSERT INTO execbound.monitor_deliveries
                (tenant_id, delivery_id, finding_id, created_at, next_attempt_at)
            VALUES (:t, :d, :f, now(), now())
        """),
            {"t": source.tenant_id, "d": uuid4(), "f": state["findings"][0]["finding_id"]},
        )
    with pytest.raises(DBAPIError, match="foreign key constraint"), admin_engine.begin() as conn:
        conn.execute(
            text("""
            UPDATE execbound.monitor_findings SET source_id=:s WHERE tenant_id=:t
        """),
            {"s": uuid4(), "t": source.tenant_id},
        )


@pytest.mark.parametrize(
    "assignment",
    [
        "evaluation_state='COMPLETED'",
        "evaluation_result='MATCH'",
        "kind='heartbeat'",
        "action=NULL",
        "outcome='authorized'",
        "version=2",
        "target_ref='https://example.org'",
    ],
)
def test_database_checks_reject_partial_or_forged_observations(
    admin_engine, setup_monitor, assignment, db
):
    models, store, clock, source, _ = setup_monitor
    store.ingest(db, source.token, observation(models, clock), clock=clock)
    with pytest.raises(DBAPIError, match="check constraint"), admin_engine.begin() as conn:
        conn.execute(text(f"UPDATE execbound.monitor_observations SET {assignment}"))


@pytest.mark.parametrize(
    "assignment",
    [
        "attempts=6",
        "attempts=-1",
        "state='IN_FLIGHT'",
        "state='DELIVERED'",
        "lease_token=gen_random_uuid()",
        "last_error='https://credentials.example'",
        "destination_id='not an id#'",
        "state='ROUTED', destination_id='soc'",
    ],
)
def test_database_checks_reject_inconsistent_delivery_state(admin_engine, history, assignment):
    with pytest.raises(DBAPIError, match="check constraint"), admin_engine.begin() as conn:
        conn.execute(text(f"UPDATE execbound.monitor_deliveries SET {assignment}"))


def test_downgrade_preserves_all_monitoring_history_and_force_rls(admin_engine, history):
    config = Config("alembic.ini")
    config.attributes["database_url"] = os.environ["TEST_MIGRATION_DATABASE_URL"]
    with pytest.raises(RuntimeError, match="monitoring data or history"):
        command.downgrade(config, "0007_identity_context")
    with admin_engine.connect() as conn:
        assert (
            conn.execute(text("SELECT version_num FROM execbound.alembic_version")).scalar_one()
            == SCHEMA_REVISION
        )
        for table in TABLES:
            assert conn.execute(text(f"SELECT count(*) FROM execbound.{table}")).scalar_one() == 1
            assert (
                conn.execute(
                    text("""
                SELECT relforcerowsecurity FROM pg_class WHERE oid=to_regclass(:t)
            """),
                    {"t": f"execbound.{table}"},
                ).scalar_one()
                is True
            )


def test_non_bypass_owner_cannot_miss_history_behind_forced_rls(admin_engine, history):
    spec = importlib.util.spec_from_file_location(
        "monitor_migration", "migrations/versions/0008_monitoring.py"
    )
    migration = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(migration)
    probe_role = "monitor_migration_probe_" + uuid4().hex
    with admin_engine.connect() as conn, conn.begin() as outer:
        conn.execute(text(f"CREATE ROLE {probe_role} NOLOGIN NOSUPERUSER NOBYPASSRLS"))
        conn.execute(text(f"GRANT USAGE ON SCHEMA execbound TO {probe_role}"))
        for table in TABLES:
            conn.execute(text(f"ALTER TABLE execbound.{table} OWNER TO {probe_role}"))
        conn.execute(text(f"SET LOCAL ROLE {probe_role}"))
        conn.execute(text("SELECT set_config('execbound.tenant_id', '', true)"))
        assert (
            conn.execute(text("SELECT count(*) FROM execbound.monitor_sources")).scalar_one() == 0
        )
        with pytest.raises(RuntimeError, match="monitoring data or history"), conn.begin_nested():
            with Operations.context(MigrationContext.configure(conn)):
                migration.downgrade()
        assert (
            conn.execute(
                text("""
            SELECT count(*) FROM pg_class WHERE relnamespace='execbound'::regnamespace
            AND relname=ANY(:tables) AND (NOT relrowsecurity OR NOT relforcerowsecurity)
        """),
                {"tables": list(TABLES)},
            ).scalar_one()
            == 0
        )
        outer.rollback()


def test_fd15_the_runtime_inserts_a_destination_and_never_updates_one(db, history):
    source, state = history
    finding = state["findings"][0]["finding_id"]
    with db.transaction(source.tenant_id) as conn:
        conn.execute(
            text(
                "INSERT INTO execbound.monitor_deliveries "
                "(tenant_id, delivery_id, finding_id, destination_id, created_at, next_attempt_at) "
                "VALUES (:t, :d, :f, 'soc', now(), now())"
            ),
            {"t": source.tenant_id, "d": uuid4(), "f": finding},
        )
    with (
        pytest.raises(DBAPIError, match="permission denied"),
        db.transaction(source.tenant_id) as conn,
    ):
        conn.execute(
            text(
                "UPDATE execbound.monitor_deliveries SET destination_id = 'other' "
                "WHERE tenant_id = :t"
            ),
            {"t": source.tenant_id},
        )


def test_fd15_one_intent_per_finding_and_one_delivery_per_destination(admin_engine, history):
    source, state = history
    finding = state["findings"][0]["finding_id"]
    insert = text(
        "INSERT INTO execbound.monitor_deliveries "
        "(tenant_id, delivery_id, finding_id, destination_id, created_at, next_attempt_at) "
        "VALUES (:t, gen_random_uuid(), :f, :dest, now(), now())"
    )
    with admin_engine.begin() as conn:
        conn.execute(insert, {"t": source.tenant_id, "f": finding, "dest": "soc"})
    for destination in (None, "soc"):
        with pytest.raises(DBAPIError, match="duplicate key"), admin_engine.begin() as conn:
            conn.execute(insert, {"t": source.tenant_id, "f": finding, "dest": destination})


def test_fd15_check_runtime_refuses_a_grant_of_the_destination(db, admin_engine, history):
    source, _ = history
    with admin_engine.begin() as conn:
        conn.execute(
            text("GRANT UPDATE (destination_id) ON execbound.monitor_deliveries TO execbound_app")
        )
    try:
        with pytest.raises(UnsafeDatabaseRole), db.transaction(source.tenant_id) as conn:
            check_runtime(conn)
    finally:
        with admin_engine.begin() as conn:
            conn.execute(
                text(
                    "REVOKE UPDATE (destination_id) ON execbound.monitor_deliveries "
                    "FROM execbound_app"
                )
            )
    with db.transaction(source.tenant_id) as conn:
        check_runtime(conn)
