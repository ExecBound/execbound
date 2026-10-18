# SPDX-License-Identifier: AGPL-3.0-only
"""Migration 0066: the agent limit becomes `tenants.max_agents` (#257, #496).

Real PostgreSQL. The backfill must reproduce every decision the plan cap made, the downgrade
must restore every function it patched byte for byte, and both must see every tenant as an
owner that does not bypass row security.
"""

from uuid import uuid4

import pytest
from alembic import command
from sqlalchemy import text
from sqlalchemy.exc import DBAPIError
from test_dormant_catalog import alembic_config, empty_schema
from test_migration_without_bypass import restricted as restricted

pytestmark = pytest.mark.integration

BEFORE = "0065_dormant_grants"
TARGET = "0066_max_agents"
PATCHED = (
    "admin_create_principal",
    "admin_reactivate_principal",
    "community_provision",
    "onboarding_claim",
    "sandbox_fallback",
)
# The two core functions keep the runtime's EXECUTE; the three dormant ones hold nothing
# beyond their owner's own (0065), since the tests at the root run as core.
CORE = ("admin_create_principal", "admin_reactivate_principal")
CREATE = "SELECT execbound.admin_create_principal(:a, 'AGENT', :s)"
DEACTIVATE = "SELECT execbound.admin_deactivate_principal(:a, :p, 'switched off by hand')"
REACTIVATE = "SELECT execbound.admin_reactivate_principal(:a, :p)"


def fenced(conn, tenant):
    # Limits nothing on an `admin_engine` connection, whose owner bypasses row security
    # (see tenant_fence); on the `restricted` owner's, which has no bypass, it does.
    conn.execute(text("SELECT set_config('execbound.tenant_id', :t, true)"), {"t": str(tenant)})


def workspace(engine, plan):
    """A tenant on ``plan``, written the way every revision before 0066 could write it."""
    tenant, space, admin = uuid4(), uuid4(), uuid4()
    with engine.begin() as conn:
        fenced(conn, tenant)
        conn.execute(
            text(
                "INSERT INTO execbound.tenants(tenant_id, name, active, plan) "
                "VALUES (:t, :n, true, :p)"
            ),
            {"t": tenant, "n": f"limit-{tenant.hex[:8]}", "p": plan},
        )
        conn.execute(
            text(
                "INSERT INTO execbound.spaces(tenant_id, space_id, name, created_at, created_by) "
                "VALUES (:t, :s, 'Default', now(), :a)"
            ),
            {"t": tenant, "s": space, "a": admin},
        )
        conn.execute(
            text(
                "INSERT INTO execbound.principals(tenant_id, principal_id, kind) "
                "VALUES (:t, :a, 'ADMIN')"
            ),
            {"t": tenant, "a": admin},
        )
    return tenant, space, admin


def script(db, engine, tenant, space, admin):
    """Every allowance decision a tenant can ask for around its limit, as each call answered:
    four creations, a hand deactivation, a creation, the hand reactivation, a sleep, a
    creation and the wake."""
    decisions = []

    def run(statement, params):
        try:
            with db.transaction(tenant) as conn:
                value = conn.execute(text(statement), params).scalar()
        except DBAPIError as error:
            diagnostic = getattr(error.orig, "diag", None)
            decisions.append(getattr(diagnostic, "message_primary", None))
            return None
        decisions.append("ok")
        return value

    agents = [run(CREATE, {"a": admin, "s": space}) for _ in range(4)]
    run(DEACTIVATE, {"a": admin, "p": agents[0]})
    run(CREATE, {"a": admin, "s": space})
    run(REACTIVATE, {"a": admin, "p": agents[0]})
    with engine.begin() as conn:
        fenced(conn, tenant)
        conn.execute(
            text(
                "UPDATE execbound.principals SET active = false, dormant_at = now() "
                "WHERE tenant_id = :t AND principal_id = :p"
            ),
            {"t": tenant, "p": agents[1]},
        )
    run(CREATE, {"a": admin, "s": space})
    run(REACTIVATE, {"a": admin, "p": agents[1]})
    return decisions


def definitions(conn):
    return dict(
        conn.execute(
            text(
                "SELECT p.proname, pg_get_functiondef(p.oid) FROM pg_proc p "
                "JOIN pg_namespace n ON n.oid = p.pronamespace "
                "WHERE n.nspname = 'execbound' AND p.proname = ANY(:names)"
            ),
            {"names": list(PATCHED)},
        ).all()
    )


def grants(conn):
    """Each patched function's ACL as the catalog holds it. A function dropped and created
    again keeps its text but loses its grants to a null ACL, which lets PUBLIC execute it."""
    return dict(
        conn.execute(
            text(
                "SELECT p.proname, CAST(p.proacl AS text) FROM pg_proc p "
                "JOIN pg_namespace n ON n.oid = p.pronamespace "
                "WHERE n.nspname = 'execbound' AND p.proname = ANY(:names)"
            ),
            {"names": list(PATCHED)},
        ).all()
    )


def forced(conn):
    return conn.execute(
        text("SELECT relforcerowsecurity FROM pg_class WHERE oid = 'execbound.tenants'::regclass")
    ).scalar_one()


def limit_of(engine, tenant):
    with engine.begin() as conn:
        fenced(conn, tenant)
        return conn.execute(
            text("SELECT max_agents FROM execbound.tenants WHERE tenant_id = :t"), {"t": tenant}
        ).scalar_one()


def has_column(conn):
    return conn.execute(
        text(
            "SELECT count(*) FROM information_schema.columns WHERE table_schema = 'execbound' "
            "AND table_name = 'tenants' AND column_name = 'max_agents'"
        )
    ).scalar_one()


def test_ac6_the_limit_reproduces_every_decision_the_plan_cap_made(db, admin_engine):
    empty_schema(admin_engine)
    config = alembic_config()
    command.downgrade(config, BEFORE)
    try:
        before, waiting = {}, {}
        for plan in ("sandbox", "free", "team"):
            before[plan] = script(db, admin_engine, *workspace(admin_engine, plan))
            waiting[plan] = workspace(admin_engine, plan)
        command.upgrade(config, TARGET)
        for plan, (tenant, space, admin) in waiting.items():
            assert limit_of(admin_engine, tenant) == (3 if plan == "free" else None)
            assert script(db, admin_engine, tenant, space, admin) == before[plan], plan
        # The script is not trivially equal: the plan cap refused three times on `free`.
        assert before["free"] == [
            "ok",
            "ok",
            "ok",
            "PLAN_LIMIT",
            "ok",
            "ok",
            "PLAN_LIMIT",
            "PLAN_LIMIT",
            "ok",
        ]
        assert before["team"] == before["sandbox"] == ["ok"] * 9
    finally:
        empty_schema(admin_engine)
        command.upgrade(config, "head")


def test_ac7_the_downgrade_refuses_a_hand_set_limit_and_otherwise_restores_everything(
    admin_engine,
):
    empty_schema(admin_engine)
    config = alembic_config()
    command.downgrade(config, BEFORE)
    try:
        with admin_engine.connect() as conn:
            at_before = definitions(conn)
            granted = grants(conn)
        owner_only = "{execbound_owner=X/execbound_owner}"
        assert granted == {
            name: (
                "{execbound_owner=X/execbound_owner,execbound_app=X/execbound_owner}"
                if name in CORE
                else owner_only
            )
            for name in PATCHED
        }
        command.upgrade(config, TARGET)
        # The patches keep each function's grants: core's stays, a dormant one has none.
        with admin_engine.connect() as conn:
            assert grants(conn) == granted
        tenant, _, _ = workspace(admin_engine, "team")
        with admin_engine.begin() as conn:
            fenced(conn, tenant)
            conn.execute(
                text("UPDATE execbound.tenants SET max_agents = 7 WHERE tenant_id = :t"),
                {"t": tenant},
            )
        with pytest.raises(RuntimeError, match="An agent limit differs from its plan"):
            command.downgrade(config, BEFORE)
        with admin_engine.begin() as conn:
            fenced(conn, tenant)
            conn.execute(
                text("UPDATE execbound.tenants SET max_agents = NULL WHERE tenant_id = :t"),
                {"t": tenant},
            )
        command.downgrade(config, BEFORE)
        with admin_engine.connect() as conn:
            assert definitions(conn) == at_before
            assert grants(conn) == granted
            assert has_column(conn) == 0
    finally:
        empty_schema(admin_engine)
        command.upgrade(config, "head")


def test_ac8_the_backfill_and_the_downgrade_see_every_tenant_as_the_hosted_owner(restricted):
    engine, config, _ = restricted
    command.upgrade(config, BEFORE)
    tenants = {}
    with engine.begin() as conn:
        for plan in ("sandbox", "free", "team"):
            tenant = uuid4()
            fenced(conn, tenant)
            conn.execute(
                text("INSERT INTO execbound.tenants(tenant_id, name, plan) VALUES (:t, :n, :p)"),
                {"t": tenant, "n": f"owner-{tenant.hex[:8]}", "p": plan},
            )
            tenants[plan] = tenant
    command.upgrade(config, TARGET)
    # The backfill lifted FORCE to see every tenant, and put it back before committing.
    with engine.connect() as conn:
        assert forced(conn)
    for plan, tenant in tenants.items():
        assert limit_of(engine, tenant) == (3 if plan == "free" else None)
    with engine.begin() as conn:
        fenced(conn, tenants["team"])
        conn.execute(
            text("UPDATE execbound.tenants SET max_agents = 10 WHERE tenant_id = :t"),
            {"t": tenants["team"]},
        )
    # This owner sees no tenant unfenced, so the refusal proves the downgrade lifted FORCE to
    # read every tenant.
    with pytest.raises(RuntimeError, match="An agent limit differs from its plan"):
        command.downgrade(config, BEFORE)
    with engine.begin() as conn:
        fenced(conn, tenants["team"])
        conn.execute(
            text("UPDATE execbound.tenants SET max_agents = NULL WHERE tenant_id = :t"),
            {"t": tenants["team"]},
        )
    # A downgrade that commits must put FORCE back itself.
    command.downgrade(config, BEFORE)
    with engine.connect() as conn:
        assert has_column(conn) == 0
        assert forced(conn)
