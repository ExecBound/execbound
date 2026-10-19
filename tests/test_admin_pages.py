# SPDX-License-Identifier: AGPL-3.0-only
"""Credential and approver administration pages (CA1 to CA9)."""

import os
import re
from contextlib import contextmanager
from uuid import uuid4

import pytest
from alembic import command
from fastapi.testclient import TestClient
from sqlalchemy import text
from sqlalchemy.exc import DBAPIError
from test_execution import registry as registry
from test_execution import world as world
from test_human_surface import form_values
from test_human_surface import human_app as human_app
from test_human_surface import human_client as human_client
from test_human_surface import human_config as human_config
from test_ops_console import ORIGIN
from test_protected_path import connector as connector
from test_protected_path import live_provider as live_provider
from test_resource_facts_schema import migration_config
from test_runtime import runtime as runtime

from execbound import administration as admin
from execbound.app import create_app
from execbound.db import FUNCTIONS, UnsafeDatabaseRole, check_runtime
from execbound.identity import authenticate
from execbound.spaces import default_space

AUTHORITY_TABLES = ("principals", "credentials", "approval_scopes")
TOKEN = re.compile(r'id="token"[^>]*value="([^"]+)"')
# Since migration 0041 the function takes the space an agent is owned by, or the one a
# person is seated in; NULL is "no space named", which only a person may be.
CREATE = "SELECT execbound.admin_create_principal(:a, :k, NULL)"


def default_space_of(db, tenant):
    """The tenant's one space; an approver scope belongs to one since migration 0041."""
    with db.transaction(tenant) as conn:
        return default_space(conn, tenant)


def issue(client, principal, lifetime="8"):
    action, values = form_values(client.get("/admin/credentials").text, "/admin/credentials/issue")
    return client.post(
        action, data={**values, "principal": principal, "lifetime": lifetime}, headers=ORIGIN
    )


def token_of(response):
    assert response.status_code == 200, response.text
    return TOKEN.search(response.text).group(1)


@contextmanager
def signed_in(db, runtime, human_config, token):
    app = create_app(db, runtime=runtime, human=human_config)
    with TestClient(app, base_url="http://127.0.0.1", follow_redirects=False) as client:
        _, values = form_values(client.get("/login").text, "/session")
        values["credential"] = token
        assert client.post("/session", data=values, headers=ORIGIN).status_code == 303
        yield client


def rows(engine, tenant, statement):
    with engine.begin() as conn:
        conn.execute(text("SELECT set_config('execbound.tenant_id', :t, true)"), {"t": str(tenant)})
        return conn.execute(text(statement), {"t": tenant}).scalar_one()


def principal_count(engine, tenant):
    return rows(engine, tenant, "SELECT count(*) FROM execbound.principals WHERE tenant_id=:t")


def event_count(engine, tenant):
    return rows(engine, tenant, "SELECT count(*) FROM execbound.audit_events WHERE tenant_id=:t")


def test_ca7_functions_refuse_other_tenants_and_missing_context(db, world, seeded, admin_engine):
    tenant = world["identity"].tenant_id
    other = next(candidate for candidate in seeded["tenants"] if candidate != tenant)
    counts = principal_count(admin_engine, tenant), principal_count(admin_engine, other)
    actor = world["admin"].principal_id
    with pytest.raises(DBAPIError, match="INVALID_ACTOR"), db.transaction(other) as conn:
        conn.execute(text(CREATE), {"a": actor, "k": "AGENT"})
    with pytest.raises(DBAPIError, match="INVALID_TENANT"), db.engine.begin() as conn:
        conn.execute(text(CREATE), {"a": actor, "k": "AGENT"})
    with pytest.raises(DBAPIError, match="INVALID_ACTOR"), db.transaction(tenant) as conn:
        conn.execute(text(CREATE), {"a": world["human"].principal_id, "k": "AGENT"})
    with pytest.raises(DBAPIError, match="INVALID_ACTOR"), db.transaction(tenant) as conn:
        conn.execute(text(CREATE), {"a": uuid4(), "k": "AGENT"})
    with pytest.raises(DBAPIError, match="INVALID_CREDENTIAL"), db.transaction(tenant) as conn:
        conn.execute(
            text("SELECT execbound.admin_revoke_credential(:a, :c, now())"),
            {"a": actor, "c": seeded["credentials"][1]},
        )
    with pytest.raises(DBAPIError, match="INVALID_TARGET"), db.transaction(tenant) as conn:
        conn.execute(
            text("SELECT execbound.admin_assign_approver(:a, :p, :t, 'endpoint.isolate', :s)"),
            {
                "a": actor,
                "p": world["human"].principal_id,
                "t": uuid4(),
                "s": default_space_of(db, tenant),
            },
        )
    with pytest.raises(DBAPIError, match="INVALID_ACTION"), db.transaction(tenant) as conn:
        conn.execute(
            text("SELECT execbound.admin_assign_approver(:a, :p, :t, 'endpoint.explode', :s)"),
            {
                "a": actor,
                "p": world["human"].principal_id,
                "t": world["canonical"],
                "s": default_space_of(db, tenant),
            },
        )
    assert (principal_count(admin_engine, tenant), principal_count(admin_engine, other)) == counts
    assert authenticate(db, seeded["tokens"][1]).credential_id == seeded["credentials"][1]


def test_ca8_runtime_role_holds_execute_and_no_table_write(db, world, admin_engine):
    tenant = world["identity"].tenant_id
    with db.transaction(tenant) as conn:
        check_runtime(conn)
    statements = {
        "principals": "INSERT INTO execbound.principals (tenant_id, principal_id, kind, space_id) "
        "VALUES (:t, gen_random_uuid(), 'AGENT', "
        "(SELECT space_id FROM execbound.spaces WHERE tenant_id = :t))",
        "credentials": "INSERT INTO execbound.credentials "
        "(tenant_id, credential_id, principal_id, token_hash, expires_at) "
        "VALUES (:t, gen_random_uuid(), :p, repeat('0', 64), now() + interval '1 hour')",
        "approval_scopes": "INSERT INTO execbound.approval_scopes "
        "(tenant_id, approver_id, canonical_target_id, action, space_id) "
        "VALUES (:t, :p, :c, 'endpoint.isolate', "
        "(SELECT space_id FROM execbound.spaces WHERE tenant_id = :t))",
    }
    params = {"t": tenant, "p": world["human"].principal_id, "c": world["canonical"]}
    for table in AUTHORITY_TABLES:
        for statement in (
            statements[table],
            f"UPDATE execbound.{table} SET tenant_id = tenant_id",
            f"DELETE FROM execbound.{table}",
        ):
            with pytest.raises(DBAPIError), db.transaction(tenant) as conn:
                conn.execute(text(statement), params)
    name, args = FUNCTIONS[0]
    signature = f"execbound.{name}({args})"
    with admin_engine.begin() as conn:
        conn.execute(text(f"REVOKE EXECUTE ON FUNCTION {signature} FROM execbound_app"))
    try:
        with pytest.raises(UnsafeDatabaseRole), db.transaction(tenant) as conn:
            check_runtime(conn)
    finally:
        with admin_engine.begin() as conn:
            conn.execute(text(f"GRANT EXECUTE ON FUNCTION {signature} TO execbound_app"))
    with admin_engine.begin() as conn:
        conn.execute(text("GRANT INSERT ON execbound.principals TO execbound_app"))
    try:
        with pytest.raises(UnsafeDatabaseRole), db.transaction(tenant) as conn:
            check_runtime(conn)
    finally:
        with admin_engine.begin() as conn:
            conn.execute(text("REVOKE INSERT ON execbound.principals FROM execbound_app"))
    with admin_engine.begin() as conn:
        conn.execute(
            text("CREATE FUNCTION execbound.stray() RETURNS int LANGUAGE sql AS 'SELECT 1'")
        )
    try:
        with pytest.raises(UnsafeDatabaseRole), db.transaction(tenant) as conn:
            check_runtime(conn)
    finally:
        with admin_engine.begin() as conn:
            conn.execute(text("DROP FUNCTION execbound.stray()"))
    with db.transaction(tenant) as conn:
        check_runtime(conn)


def functions_in_schema(engine):
    """Every callable function the schema holds, which is every definer function and no more.

    A trigger function is excluded because nothing can call one: it is reached only by the
    trigger that fires it, `check_runtime` says so where it refuses every other executable
    function, and `0039_signups` adds the first of them to keep a claimed slot's expiry.
    """
    with engine.connect() as conn:
        return sorted(
            conn.execute(
                text(
                    "SELECT p.proname FROM pg_proc p JOIN pg_namespace n "
                    "ON n.oid = p.pronamespace WHERE n.nspname = 'execbound' "
                    "AND p.prorettype <> 'trigger'::regtype"
                )
            ).scalars()
        )


# The trigger functions, which are not definer functions and never run as one. The synthetic
# directory's four (#355, step 4) keep its actors unbound, its findings unsent, its kind apart
# from Microsoft Entra's and an agent identity's class fixed.
TRIGGER_FUNCTIONS = [
    "access_protect_last_admin",
    "agent_bindings_not_synthetic",
    "job_tenants_enroll",
    "monitor_agents_class_family",
    "monitor_connections_directory_coexist",
    "monitor_connections_revoked_unleased",
    "monitor_deliveries_not_synthetic",
    "monitor_findings_acknowledged_once",
    "number_agent_key",
    "number_principal",
    "onboarding_slot_expiry",
    "principal_guard",
    "principals_system_frozen",
]


def trigger_functions_in_schema(engine):
    with engine.connect() as conn:
        return sorted(
            conn.execute(
                text(
                    "SELECT p.proname FROM pg_proc p JOIN pg_namespace n "
                    "ON n.oid = p.pronamespace WHERE n.nspname = 'execbound' "
                    "AND p.prorettype = 'trigger'::regtype AND NOT p.prosecdef"
                )
            ).scalars()
        )


def test_ca9_migration_round_trip_keeps_owner_commands_working(db, admin_engine, seeded):
    expected = sorted(name for name, _ in FUNCTIONS)
    assert functions_in_schema(admin_engine) == expected
    assert trigger_functions_in_schema(admin_engine) == TRIGGER_FUNCTIONS
    config = migration_config()
    command.downgrade(config, "0020_resource_facts_long")
    try:
        assert functions_in_schema(admin_engine) == []
        assert trigger_functions_in_schema(admin_engine) == []
    finally:
        command.upgrade(config, "head")
    assert functions_in_schema(admin_engine) == expected
    assert trigger_functions_in_schema(admin_engine) == TRIGGER_FUNCTIONS
    # The owner commands run after the round trip rather than inside it: every tenant has
    # a space from migration 0041, and an agent principal carries one, so the owner path
    # writes a column the schema of twenty revisions ago does not have. What this test is
    # for is that the round trip leaves the owner path working, which it still says.
    owner = admin.owner_engine(os.environ["TEST_MIGRATION_DATABASE_URL"])
    try:
        tenant = admin.create_tenant(owner, "Round trip")
        first = admin.create_principal(owner, tenant, "ADMIN")
        assert admin.create_principal(owner, tenant, "AGENT", actor=first)
    finally:
        owner.dispose()
    with db.transaction(seeded["tenants"][0]) as conn:
        check_runtime(conn)
