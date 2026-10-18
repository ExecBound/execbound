# SPDX-License-Identifier: AGPL-3.0-only
"""resource_facts isolation, grants, value bounds and guarded downgrade (CC8, CC9)."""

import os
from datetime import UTC, datetime
from uuid import UUID

import pytest
from alembic import command
from alembic.config import Config
from context_fixtures import SYNTHETIC_VERSION, synthetic_bundle
from replay_fixtures import replay_case
from sqlalchemy import text
from sqlalchemy.exc import DBAPIError, IntegrityError
from test_execution_database import execution_storage as execution_storage

from execbound.audit import canonical_json
from execbound.db import SCHEMA_REVISION, TABLES, check_runtime
from execbound.policy.models import ContextSetting
from execbound_harness.demo import endpoint_bundle

ACCOUNT, SOURCE, RESOURCE = UUID(int=0x10), UUID(int=0x20), UUID(int=0x30)
OBSERVED = datetime(2026, 9, 14, 12, 0, tzinfo=UTC)
FACT_INSERT = (
    "INSERT INTO execbound.resource_facts "
    "(tenant_id, account_id, provider, resource_type, resource_id, fact_name, value, "
    "source_id, version, observed_at) "
    "VALUES (:t, :a, 'mock_crowdstrike', 'endpoint', :r, :name, CAST(:v AS jsonb), :s, "
    "'fact-v1', :n)"
)


def params(tenant, **changes):
    return {
        "t": tenant,
        "a": ACCOUNT,
        "s": SOURCE,
        "r": RESOURCE,
        "n": OBSERVED,
        "name": "exposure",
        "v": '"internal"',
        **changes,
    }


def seed_resource(engine, tenant, *, value='"internal"'):
    p = params(tenant, v=value)
    with engine.begin() as conn:
        conn.execute(
            text(
                "INSERT INTO execbound.connector_accounts(tenant_id, account_id, provider, "
                "space_id) "
                "VALUES (:t, :a, 'mock_crowdstrike', "
                "(SELECT space_id FROM execbound.spaces WHERE tenant_id = :t))"
            ),
            p,
        )
        conn.execute(
            text(
                "INSERT INTO execbound.context_sources "
                "(tenant_id, account_id, source_id, kind, allowed_writers) "
                "VALUES (:t, :a, :s, 'inventory', ARRAY['inventory_sync'])"
            ),
            p,
        )
        conn.execute(
            text(
                "INSERT INTO execbound.resources "
                "(tenant_id, account_id, provider, resource_type, resource_id, provider_id, "
                "version, source_id, role, environment, criticality, observed_at) "
                "VALUES (:t, :a, 'mock_crowdstrike', 'endpoint', :r, 'device-01', "
                "'resource-v1', :s, 'workstation', 'development', 1, :n)"
            ),
            p,
        )
        conn.execute(text(FACT_INSERT), p)


def migration_config():
    config = Config("alembic.ini")
    config.attributes["database_url"] = os.environ["TEST_MIGRATION_DATABASE_URL"]
    return config


def test_runtime_catalog_includes_resource_facts(db, seeded):
    assert "resource_facts" in TABLES
    with db.transaction(seeded["tenants"][0]) as conn:
        check_runtime(conn)


def test_colliding_tenants_see_only_their_facts(db, admin_engine, seeded):
    first, second = seeded["tenants"]
    seed_resource(admin_engine, first, value='"internal"')
    seed_resource(admin_engine, second, value='"external"')
    for tenant, expected in ((first, "internal"), (second, "external")):
        with db.transaction(tenant) as conn:
            values = conn.execute(
                text("SELECT value #>> '{}' FROM execbound.resource_facts")
            ).scalars()
            assert values.all() == [expected]
    with db.engine.connect() as conn:
        assert conn.execute(text("SELECT count(*) FROM execbound.resource_facts")).scalar_one() == 0


@pytest.mark.parametrize(
    "statement",
    [
        "INSERT INTO execbound.resource_facts SELECT * FROM execbound.resource_facts",
        "UPDATE execbound.resource_facts SET version = 'forged'",
        "DELETE FROM execbound.resource_facts",
        "TRUNCATE execbound.resource_facts",
    ],
)
def test_runtime_cannot_write_resource_facts(db, admin_engine, seeded, statement):
    seed_resource(admin_engine, seeded["tenants"][0])
    with pytest.raises(DBAPIError), db.transaction(seeded["tenants"][0]) as conn:
        conn.execute(text(statement))


@pytest.mark.parametrize(
    "value",
    [
        "1.5",
        '""',
        '{"nested": true}',
        "null",
        "9223372036854775808",
        "-9223372036854775809",
        "12345678901234567890",
    ],
)
def test_fact_values_are_bounded_scalars(admin_engine, seeded, value):
    tenant = seeded["tenants"][0]
    seed_resource(admin_engine, tenant)
    with pytest.raises(IntegrityError), admin_engine.begin() as conn:
        conn.execute(text(FACT_INSERT), params(tenant, name="risk_score", v=value))


@pytest.mark.parametrize(
    "value", ["9223372036854775807", "-9223372036854775808", "1000000000000000000", "0", "-1"]
)
def test_fact_values_accept_the_full_long_range(admin_engine, seeded, value):
    """Cedar Long is a signed 64-bit integer; storage must not stop short of it (#20)."""
    tenant = seeded["tenants"][0]
    seed_resource(admin_engine, tenant)
    with admin_engine.begin() as conn:
        conn.execute(text(FACT_INSERT), params(tenant, name="risk_score", v=value))
        stored = conn.execute(
            text(
                "SELECT value FROM execbound.resource_facts "
                "WHERE tenant_id=:t AND fact_name='risk_score'"
            ),
            {"t": tenant},
        ).scalar_one()
    assert stored == int(value)


def test_downgrade_refuses_retained_long_facts_beyond_eighteen_digits(admin_engine, seeded):
    tenant = seeded["tenants"][0]
    seed_resource(admin_engine, tenant)
    with admin_engine.begin() as conn:
        conn.execute(text(FACT_INSERT), params(tenant, name="risk_score", v="9223372036854775807"))
    with pytest.raises(RuntimeError):
        command.downgrade(migration_config(), "0019_observe_mode")
    with admin_engine.begin() as conn:
        conn.execute(text("DELETE FROM execbound.resource_facts WHERE tenant_id=:t"), {"t": tenant})
        conn.execute(text("DELETE FROM execbound.resources WHERE tenant_id=:t"), {"t": tenant})
    command.downgrade(migration_config(), "0019_observe_mode")
    command.upgrade(migration_config(), "head")
    with admin_engine.begin() as conn:
        with pytest.raises(IntegrityError):
            with conn.begin_nested():
                conn.execute(
                    text(FACT_INSERT), params(tenant, name="risk_score", v="9223372036854775808")
                )


def test_downgrade_refuses_retained_resource_facts(admin_engine, seeded):
    seed_resource(admin_engine, seeded["tenants"][0])
    config = migration_config()
    try:
        with pytest.raises(RuntimeError):
            command.downgrade(config, "0008_monitoring")
    finally:
        command.upgrade(config, "head")
    with admin_engine.connect() as conn:
        revision = conn.execute(text("SELECT version_num FROM execbound.alembic_version"))
        assert revision.scalar_one() == SCHEMA_REVISION


def test_downgrade_refuses_non_v1_mapping(admin_engine, seeded):
    tenant = seeded["tenants"][0]
    with admin_engine.begin() as conn:
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
                "provider_operation, mapping_version, schema_version, context_contract_version) "
                "VALUES (:t, 'endpoint.isolate.facts', :a, 'mock_crowdstrike', 'endpoint', "
                "'endpoint.isolate', 'contain', 'map-v1', 'action.v1', 'endpoint-facts.test')"
            ),
            {"t": tenant, "a": ACCOUNT},
        )
    config = migration_config()
    try:
        with pytest.raises(RuntimeError):
            command.downgrade(config, "0008_monitoring")
    finally:
        command.upgrade(config, "head")


V1_SETTING = ContextSetting(
    context_contract_version="endpoint-isolation.v1",
    source_kind="inventory",
    max_age_seconds=600,
    permitted_writers=("inventory_sync",),
)


def frozen_plan(version):
    resolved = replay_case()["resolved"].model_copy(update={"context_contract_version": version})
    return resolved.model_dump(mode="json", exclude={"request"})


def history_documents(tenant, retained=None):
    """Stored JSON for one tenant; `retained` swaps one location to post-v1 content."""
    v1_bundle = endpoint_bundle(tenant, ACCOUNT, mapping_version="map-v1")
    version = {"execution frozen": SYNTHETIC_VERSION}.get(retained, "endpoint-isolation.v1")
    documents = {
        "bundle": v1_bundle.model_dump_json(),
        "frozen": canonical_json(frozen_plan(version)),
        "event": canonical_json({"frozen": frozen_plan("endpoint-isolation.v1")}),
        "audit": canonical_json(
            {"stage": "ADMISSION", "frozen": frozen_plan("endpoint-isolation.v1")}
        ),
    }
    if retained == "bundle mapping":
        documents["bundle"] = synthetic_bundle(tenant, ACCOUNT).model_dump_json()
    elif retained == "bundle settings":
        documents["bundle"] = v1_bundle.model_copy(
            update={"context_settings": (V1_SETTING,)}
        ).model_dump_json()
    elif retained == "execution event":
        documents["event"] = canonical_json({"frozen": frozen_plan(SYNTHETIC_VERSION)})
    elif retained == "audit event":
        documents["audit"] = canonical_json(
            {"stage": "ADMISSION", "frozen": frozen_plan(SYNTHETIC_VERSION)}
        )
    return documents


def store_history(admin_engine, storage, tenant, principal, documents):
    values = {
        **documents,
        "t": tenant,
        "p": principal,
        "b": storage["bundle"],
        "e": storage["execution"],
    }
    with admin_engine.begin() as conn:
        for statement in (
            "UPDATE execbound.policy_bundle_contents SET content=CAST(:bundle AS jsonb) "
            "WHERE tenant_id=:t AND bundle_id=:b",
            "UPDATE execbound.executions SET frozen=CAST(:frozen AS jsonb) "
            "WHERE tenant_id=:t AND execution_id=:e",
            "UPDATE execbound.execution_events SET payload=CAST(:event AS jsonb) "
            "WHERE tenant_id=:t AND execution_id=:e",
            "INSERT INTO execbound.audit_events "
            "(tenant_id, sequence, event_id, actor_id, kind, occurred_at, payload, "
            "previous_hash, event_hash) VALUES (:t, 1, gen_random_uuid(), :p, "
            "'execution.evaluated', now(), CAST(:audit AS jsonb), repeat('0', 64), "
            "repeat('1', 64))",
        ):
            conn.execute(text(statement), values)


def assert_downgrade_refused(admin_engine):
    config = migration_config()
    try:
        with pytest.raises(RuntimeError, match="context contract data or history"):
            command.downgrade(config, "0008_monitoring")
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


@pytest.mark.parametrize(
    "retained",
    ["bundle mapping", "bundle settings", "execution frozen", "execution event", "audit event"],
)
def test_downgrade_refuses_retained_post_v1_history(
    admin_engine, seeded, execution_storage, retained
):
    # Only the second tenant retains it, so inspection cannot rely on a tenant context.
    for index, location in ((0, None), (1, retained)):
        tenant = seeded["tenants"][index]
        store_history(
            admin_engine,
            execution_storage,
            tenant,
            seeded["principals"][index],
            history_documents(tenant, location),
        )
    assert_downgrade_refused(admin_engine)


def test_downgrade_accepts_v1_only_history(admin_engine, seeded, execution_storage):
    for tenant, principal in zip(seeded["tenants"], seeded["principals"], strict=True):
        store_history(admin_engine, execution_storage, tenant, principal, history_documents(tenant))
    config = migration_config()
    try:
        command.downgrade(config, "0008_monitoring")
    finally:
        command.upgrade(config, "head")
