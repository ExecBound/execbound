# SPDX-License-Identifier: AGPL-3.0-only
"""Action checks admit the six catalog actions; downgrade refuses retained rows (SA13)."""

import os
from datetime import UTC, datetime
from uuid import UUID, uuid4

import pytest
from alembic import command
from alembic.config import Config
from soc_fixtures import lift_scenario
from sqlalchemy import text
from sqlalchemy.exc import IntegrityError
from test_execution_database import execution_storage as execution_storage
from test_resource_facts_schema import history_documents, store_history

from execbound.audit import canonical_json
from execbound.db import SCHEMA_REVISION, TABLES
from execbound.operations import PRODUCTION_ACTIONS
from execbound_harness.soc_demo import soc_bundle

ACCOUNT = UUID(int=91)
ACTION_TABLES = ("approval_scopes", "execution_impact")
# Each JSON location keys the one document in `history_documents` the guard must inspect.
JSON_LOCATIONS = {
    "executions": "frozen",
    "execution_events": "event",
    "audit_events": "audit",
}


def migration_config():
    config = Config("alembic.ini")
    config.attributes["database_url"] = os.environ["TEST_MIGRATION_DATABASE_URL"]
    return config


def scope_row(conn, tenant, principal, action):
    canonical = uuid4()
    conn.execute(
        text("INSERT INTO execbound.canonical_targets VALUES (:t, :c, :n)"),
        {"t": tenant, "c": canonical, "n": datetime.now(UTC)},
    )
    conn.execute(
        text(
            "INSERT INTO execbound.approval_scopes "
            "(tenant_id, approver_id, canonical_target_id, action, "
            "space_id) VALUES (:t, :p, :c, :a, "
            "(SELECT space_id FROM execbound.spaces WHERE tenant_id = :t))"
        ),
        {"t": tenant, "p": principal, "c": canonical, "a": action},
    )


def test_new_actions_pass_the_checks_and_unknown_actions_fail(admin_engine, seeded):
    # Driven by the catalog, not by literals: an action added to the catalog without
    # widening the check constraint fails here instead of drifting silently.
    tenant, principal = seeded["tenants"][0], seeded["principals"][0]
    with admin_engine.begin() as conn:
        for action in sorted(PRODUCTION_ACTIONS.names):
            scope_row(conn, tenant, principal, action)
    with pytest.raises(IntegrityError), admin_engine.begin() as conn:
        scope_row(conn, tenant, principal, "endpoint.purge")


def lift_documents(tenant, location):
    """v1 history for one tenant with the named location naming a new SOC action."""
    plan = lift_scenario()["resolved"].model_dump(mode="json", exclude={"request"})
    document = {
        "frozen": plan,
        "event": {"frozen": plan},
        "audit": {"stage": "ADMISSION", "frozen": plan},
    }[JSON_LOCATIONS[location]]
    return history_documents(tenant) | {JSON_LOCATIONS[location]: canonical_json(document)}


def retain(engine, storage, tenant, principal, location):
    if location in JSON_LOCATIONS:
        store_history(engine, storage, tenant, principal, lift_documents(tenant, location))
        return
    with engine.begin() as conn:
        if location == "mapping":
            conn.execute(
                text(
                    "INSERT INTO execbound.connector_accounts(tenant_id, account_id, provider, "
                    "space_id) "
                    "VALUES (:t, :a, 'mock_crowdstrike', "
                    "(SELECT space_id FROM execbound.spaces WHERE tenant_id = :t))"
                ),
                {"t": tenant, "a": ACCOUNT},
            )
            conn.execute(
                text(
                    "INSERT INTO execbound.operation_mappings "
                    "(tenant_id, operation_ref, account_id, provider, resource_type, action, "
                    "provider_operation, mapping_version, schema_version, "
                    "context_contract_version) "
                    "VALUES (:t, 'endpoint.lift_isolation', :a, 'mock_crowdstrike', 'endpoint', "
                    "'endpoint.lift_isolation', 'lift_containment', 'map-v1', 'action.v1', "
                    "'endpoint-recovery.v1')"
                ),
                {"t": tenant, "a": ACCOUNT},
            )
        elif location == "scope":
            scope_row(conn, tenant, principal, "identity.reset_password")
        else:
            bundle = soc_bundle(tenant, uuid4(), uuid4(), mapping_version="map-v1")
            conn.execute(
                text(
                    "INSERT INTO execbound.policy_bundle_contents "
                    "(tenant_id, bundle_id, content_hash, content, created_at, created_by, "
                    "space_id) "
                    "VALUES (:t, :b, :h, CAST(:c AS jsonb), :n, :p, "
                    "(SELECT space_id FROM execbound.spaces WHERE tenant_id = :t))"
                ),
                {
                    "t": tenant,
                    "b": bundle.bundle_id,
                    "h": bundle.content_hash,
                    "c": bundle.model_dump_json(),
                    "n": datetime.now(UTC),
                    "p": principal,
                },
            )


@pytest.mark.parametrize("location", ["mapping", "scope", "bundle", *JSON_LOCATIONS])
def test_downgrade_refuses_retained_new_action_rows(
    admin_engine, seeded, execution_storage, location
):
    # The migration connection sets no tenant context, so retaining the row only in the
    # second tenant proves the inspection is not filtered by a tenant setting. The first
    # tenant keeps v1-only history, which the guard must not mistake for retained evidence.
    if location in JSON_LOCATIONS:
        store_history(
            admin_engine,
            execution_storage,
            seeded["tenants"][0],
            seeded["principals"][0],
            history_documents(seeded["tenants"][0]),
        )
    retain(
        admin_engine,
        execution_storage,
        seeded["tenants"][1],
        seeded["principals"][1],
        location,
    )
    config = migration_config()
    try:
        with pytest.raises(RuntimeError, match="SOC action"):
            command.downgrade(config, "0013_source_health")
        with admin_engine.connect() as conn:
            revision = conn.execute(text("SELECT version_num FROM execbound.alembic_version"))
            assert revision.scalar_one() == SCHEMA_REVISION
            unforced = conn.execute(
                text(
                    "SELECT count(*) FROM pg_class WHERE relnamespace='execbound'::regnamespace "
                    "AND relkind='r' AND relname<>'alembic_version' "
                    "AND (NOT relrowsecurity OR NOT relforcerowsecurity)"
                )
            )
            assert unforced.scalar_one() == 0
    finally:
        command.upgrade(config, "head")


def action_check_definitions(engine):
    with engine.connect() as conn:
        return {
            table: conn.execute(
                text(
                    "SELECT pg_get_constraintdef(oid) FROM pg_constraint "
                    "WHERE conname = :name AND conrelid = CAST(:table AS regclass)"
                ),
                {"name": f"{table}_action_check", "table": f"execbound.{table}"},
            ).scalar_one()
            for table in ACTION_TABLES
        }


def test_round_trip_narrows_and_rewidens_the_action_checks(admin_engine, seeded):
    with admin_engine.begin() as conn:
        conn.execute(text("TRUNCATE " + ", ".join(f"execbound.{table}" for table in TABLES)))
    config = migration_config()
    try:
        command.downgrade(config, "0013_source_health")
        with admin_engine.connect() as conn:
            revision = conn.execute(text("SELECT version_num FROM execbound.alembic_version"))
            assert revision.scalar_one() == "0013_source_health"
        for definition in action_check_definitions(admin_engine).values():
            assert "lift_isolation" not in definition
            assert "reset_password" not in definition
    finally:
        command.upgrade(config, "head")
    for definition in action_check_definitions(admin_engine).values():
        assert "lift_isolation" in definition
        assert "reset_password" in definition
