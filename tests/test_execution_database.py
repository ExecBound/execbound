# SPDX-License-Identifier: AGPL-3.0-only
"""Real PostgreSQL constraints for tenant execution storage and restricted grants."""

from uuid import uuid4

import pytest
from sqlalchemy import text
from sqlalchemy.exc import DBAPIError

pytestmark = pytest.mark.integration

EXECUTION_TABLES = (
    "canonical_targets",
    "resource_identities",
    "approval_scopes",
    "executions",
    "execution_keys",
    "execution_events",
    "approvals",
    "execution_impact",
    "resource_claims",
)


@pytest.fixture
def execution_storage(seeded, admin_engine):
    # Matching object IDs deliberately exist in both tenants. These are storage
    # fixtures, not validated policy or resolver objects used to authorize work.
    fixture = {
        name: uuid4()
        for name in ("account", "source", "resource", "target", "bundle", "execution", "operation")
    }
    with admin_engine.begin() as conn:
        for tenant, principal, credential in zip(
            seeded["tenants"], seeded["principals"], seeded["credentials"], strict=True
        ):
            values = {**fixture, "tenant": tenant, "principal": principal, "credential": credential}
            for statement in (
                "INSERT INTO execbound.canonical_targets VALUES (:tenant, :target, now())",
                "INSERT INTO execbound.connector_accounts (tenant_id, account_id, provider, "
                "space_id) "
                "VALUES (:tenant, :account, 'mock_crowdstrike', "
                "(SELECT space_id FROM execbound.spaces WHERE tenant_id = :tenant))",
                "INSERT INTO execbound.context_sources "
                "(tenant_id, account_id, source_id, kind, allowed_writers) "
                "VALUES (:tenant, :account, :source, 'inventory', ARRAY['inventory_sync'])",
                "INSERT INTO execbound.resources "
                "(tenant_id, account_id, provider, resource_type, resource_id, provider_id, "
                "version, source_id, observed_at) "
                "VALUES (:tenant, :account, 'mock_crowdstrike', 'endpoint', :resource, "
                "'synthetic-endpoint', 'v1', :source, now())",
                "INSERT INTO execbound.resource_identities VALUES "
                "(:tenant, :account, 'mock_crowdstrike', 'endpoint', :resource, :target)",
                "INSERT INTO execbound.approval_scopes "
                "(tenant_id, approver_id, canonical_target_id, action, space_id) "
                "VALUES (:tenant, :principal, :target, 'endpoint.isolate', "
                "(SELECT space_id FROM execbound.spaces WHERE tenant_id = :tenant))",
                "INSERT INTO execbound.policy_bundle_contents "
                "(tenant_id, bundle_id, content_hash, content, created_at, created_by, space_id) "
                "VALUES (:tenant, :bundle, repeat('0', 64), '{}'::jsonb, now(), :principal, "
                "(SELECT space_id FROM execbound.spaces WHERE tenant_id = :tenant))",
                "INSERT INTO execbound.executions "
                "(tenant_id, execution_id, principal_id, credential_id, intent_hash, wire_hash, "
                "plan_hash, canonical_target_id, bundle_id, frozen, state, created_at, changed_at, "
                "operation_id, request_number, space_id) "
                "VALUES (:tenant, :execution, :principal, :credential, "
                "repeat('0', 64), repeat('1', 64), repeat('2', 64), :target, :bundle, '{}'::jsonb, "
                "'PENDING_APPROVAL', now(), now(), :operation, 1, "
                "(SELECT space_id FROM execbound.spaces WHERE tenant_id = :tenant))",
                "INSERT INTO execbound.execution_keys VALUES "
                "(:tenant, :principal, 'key', repeat('0', 64), repeat('1', 64), :execution)",
                "INSERT INTO execbound.execution_events "
                "(tenant_id, event_id, execution_id, actor_id, to_state, created_at, payload) "
                "VALUES (:tenant, gen_random_uuid(), :execution, :principal, "
                "'ATTEMPTED', now(), '{}'::jsonb)",
                "INSERT INTO execbound.approvals "
                "(tenant_id, approval_id, execution_id, principal_id, plan_hash, bundle_id, "
                "obligation_ids, expires_at, created_at, state, space_id) VALUES (:tenant, "
                "gen_random_uuid(), :execution, :principal, repeat('2', 64), :bundle, "
                "'[]'::jsonb, now() + interval '5 minutes', now(), 'PENDING', "
                "(SELECT space_id FROM execbound.spaces WHERE tenant_id = :tenant))",
                "INSERT INTO execbound.execution_impact "
                "(tenant_id, execution_id, principal_id, action, approved, state, created_at, "
                "space_id) "
                "VALUES (:tenant, :execution, :principal, 'endpoint.isolate', false, "
                "'UNRESOLVED', now(), "
                "(SELECT space_id FROM execbound.spaces WHERE tenant_id = :tenant))",
                "INSERT INTO execbound.resource_claims "
                "(tenant_id, execution_id, canonical_target_id) "
                "VALUES (:tenant, :execution, :target)",
            ):
                conn.execute(text(statement), values)
    return fixture


def copy_execution(conn, fixture, tenant, *, intent="0" * 64, operation=None):
    execution = uuid4()
    conn.execute(
        text("""
            INSERT INTO execbound.executions
                (tenant_id, execution_id, principal_id, credential_id, intent_hash, wire_hash,
                 plan_hash, canonical_target_id, bundle_id, frozen, state, created_at,
                 changed_at, operation_id, request_number, space_id)
            SELECT tenant_id, :execution, principal_id, credential_id, :intent, wire_hash,
                   plan_hash, canonical_target_id, bundle_id, frozen, 'ATTEMPTED', now(),
                   now(), :operation, (SELECT coalesce(max(request_number),0)+1
                       FROM execbound.executions WHERE tenant_id=:tenant), space_id
            FROM execbound.executions WHERE tenant_id = :tenant AND execution_id = :original
        """),
        {
            "execution": execution,
            "intent": intent,
            "operation": operation or uuid4(),
            "tenant": tenant,
            "original": fixture["execution"],
        },
    )
    return execution


def test_all_execution_tables_isolate_colliding_tenant_objects(db, seeded, execution_storage):
    for tenant in seeded["tenants"]:
        with db.transaction(tenant) as conn:
            for table in EXECUTION_TABLES:
                assert conn.execute(
                    text(f"SELECT tenant_id FROM execbound.{table}")
                ).scalars().all() == [tenant]
    with db.engine.connect() as conn:
        for table in EXECUTION_TABLES:
            assert conn.execute(text(f"SELECT count(*) FROM execbound.{table}")).scalar_one() == 0


@pytest.mark.parametrize(
    "table",
    [
        "canonical_targets",
        "resource_identities",
        "approval_scopes",
        "principal_groups",
        "principal_group_members",
        "executor_keys",
    ],
)
def test_runtime_cannot_provision_execution_authority(db, seeded, execution_storage, table):
    with pytest.raises(DBAPIError), db.transaction(seeded["tenants"][0]) as conn:
        conn.execute(text(f"INSERT INTO execbound.{table} SELECT * FROM execbound.{table}"))


def test_execution_rls_denies_cross_tenant_insert_and_projection_update(
    db, seeded, execution_storage
):
    first, second = seeded["tenants"]
    with db.transaction(first) as conn:
        for table, assignment in (
            ("executions", "state = 'DENIED'"),
            ("approvals", "state = 'DENIED'"),
            ("execution_impact", "state = 'NONEXECUTION'"),
            ("resource_claims", "released_at = now()"),
        ):
            assert (
                conn.execute(
                    text(f"UPDATE execbound.{table} SET {assignment} WHERE tenant_id = :tenant"),
                    {"tenant": second},
                ).rowcount
                == 0
            )
    with pytest.raises(DBAPIError), db.transaction(first) as conn:
        conn.execute(
            text("INSERT INTO execbound.execution_keys VALUES (:t, :p, 'foreign', :h, :h, :e)"),
            {
                "t": second,
                "p": seeded["principals"][1],
                "h": "0" * 64,
                "e": execution_storage["execution"],
            },
        )


def test_execution_tables_force_rls_and_exclude_supabase_api_roles(admin_engine, execution_storage):
    with admin_engine.connect() as conn:
        assert (
            conn.execute(
                text("""
                SELECT c.relname FROM pg_class c
                WHERE c.relnamespace = 'execbound'::regnamespace AND c.relname = ANY(:tables)
                  AND (NOT c.relrowsecurity OR NOT c.relforcerowsecurity)
            """),
                {"tables": list(EXECUTION_TABLES)},
            ).all()
            == []
        )
        assert (
            conn.execute(
                text("""
                SELECT c.relname, acl.grantee FROM pg_class c
                CROSS JOIN LATERAL aclexplode(c.relacl) acl
                WHERE c.relnamespace = 'execbound'::regnamespace AND c.relname = ANY(:tables)
                  AND (acl.grantee = 0 OR acl.grantee IN (
                      SELECT oid FROM pg_roles
                      WHERE rolname IN ('anon', 'authenticated', 'service_role')
                  ))
            """),
                {"tables": list(EXECUTION_TABLES)},
            ).all()
            == []
        )


@pytest.mark.parametrize(
    "state", ["ATTEMPTED", "PENDING_APPROVAL", "RESERVED", "DISPATCH_COMMITTED", "INDETERMINATE"]
)
def test_database_prevents_duplicate_unresolved_intent(db, seeded, execution_storage, state):
    tenant = seeded["tenants"][0]
    with db.transaction(tenant) as conn:
        conn.execute(text("UPDATE execbound.executions SET state = :state"), {"state": state})
    with pytest.raises(DBAPIError), db.transaction(tenant) as conn:
        copy_execution(conn, execution_storage, tenant)


def test_completed_intent_can_be_repeated_as_new_execution(db, seeded, execution_storage):
    tenant = seeded["tenants"][0]
    with db.transaction(tenant) as conn:
        conn.execute(text("UPDATE execbound.executions SET state = 'EXECUTED'"))
        execution = copy_execution(conn, execution_storage, tenant)
        assert execution != execution_storage["execution"]
        assert conn.execute(text("SELECT count(*) FROM execbound.executions")).scalar_one() == 2


def test_operation_id_cannot_be_reused_by_another_intent(db, seeded, execution_storage):
    with pytest.raises(DBAPIError), db.transaction(seeded["tenants"][0]) as conn:
        copy_execution(
            conn,
            execution_storage,
            seeded["tenants"][0],
            intent="3" * 64,
            operation=execution_storage["operation"],
        )


def test_idempotency_key_cannot_attach_to_another_principals_execution(
    db, seeded, execution_storage, admin_engine
):
    tenant, principal = seeded["tenants"][0], uuid4()
    with admin_engine.begin() as conn:
        conn.execute(
            text(
                "INSERT INTO execbound.principals (tenant_id, principal_id, kind, active, "
                "space_id) VALUES (:t, :p, 'AGENT', true, "
                "(SELECT space_id FROM execbound.spaces WHERE tenant_id = :t))"
            ),
            {"t": tenant, "p": principal},
        )
    with pytest.raises(DBAPIError), db.transaction(tenant) as conn:
        conn.execute(
            text("INSERT INTO execbound.execution_keys VALUES (:t, :p, 'other', :h, :h, :e)"),
            {"t": tenant, "p": principal, "h": "0" * 64, "e": execution_storage["execution"]},
        )


def test_one_approval_per_frozen_execution(db, seeded, execution_storage):
    with pytest.raises(DBAPIError), db.transaction(seeded["tenants"][0]) as conn:
        conn.execute(
            text("""
            INSERT INTO execbound.approvals
                (tenant_id, approval_id, execution_id, principal_id, plan_hash, bundle_id,
                 obligation_ids, expires_at, created_at, state, space_id)
            SELECT tenant_id, gen_random_uuid(), execution_id, principal_id, plan_hash, bundle_id,
                   obligation_ids, expires_at, created_at, state, space_id
              FROM execbound.approvals
        """)
        )


@pytest.mark.parametrize(
    "assignment", ["state = 'CONFIRMED'", "confirmed_at = now()", "state = 'REFUNDED'"]
)
def test_impact_requires_consistent_confirmation_evidence(
    db, seeded, execution_storage, assignment
):
    with pytest.raises(DBAPIError), db.transaction(seeded["tenants"][0]) as conn:
        conn.execute(text(f"UPDATE execbound.execution_impact SET {assignment}"))


def test_resource_guard_is_exclusive_until_explicit_release(db, seeded, execution_storage):
    tenant = seeded["tenants"][0]
    with db.transaction(tenant) as conn:
        execution = copy_execution(conn, execution_storage, tenant, intent="3" * 64)
    values = {"t": tenant, "e": execution, "target": execution_storage["target"]}
    claim = text(
        "INSERT INTO execbound.resource_claims (tenant_id, execution_id, canonical_target_id) "
        "VALUES (:t, :e, :target)"
    )
    with pytest.raises(DBAPIError), db.transaction(tenant) as conn:
        conn.execute(claim, values)
    with db.transaction(tenant) as conn:
        conn.execute(text("UPDATE execbound.resource_claims SET released_at = now()"))
        conn.execute(claim, values)
        assert (
            conn.execute(
                text("SELECT execution_id FROM execbound.resource_claims WHERE released_at IS NULL")
            ).scalar_one()
            == execution
        )
