# SPDX-License-Identifier: AGPL-3.0-only
"""Agent bindings (AB1 and AB2): the definer functions, the grants and the audit chain.

AB3 to AB9 drove the Jinja Agents pages, which the console replaced (#333);
`tests/test_console_api_agents.py` holds the same behaviour over the routes the console
reads — the three populations and their filters, a bound agent's id answering with its
principal, binding from either side, unbinding with a reason, `Govern this agent` all or
nothing, and a deactivated bound agent keeping its binding — and
`tests/test_browser_console_directory.py` holds the pages in Chromium.
"""

from uuid import uuid4

import pytest
from monitoring_fixtures import collect
from sqlalchemy import text
from sqlalchemy.exc import DBAPIError
from test_emergency_stop import audit
from test_execution import registry as registry
from test_execution import world as world
from test_human_surface import human_app as human_app
from test_human_surface import human_client as human_client
from test_human_surface import human_config as human_config
from test_people_pages import admin_client as admin_client
from test_people_pages import call, refused
from test_protected_path import connector as connector
from test_protected_path import live_provider as live_provider
from test_runtime import runtime as runtime
from test_scout_run import agent, detailed_scenario

from execbound.monitoring import store as monitor_store
from execbound.monitoring.models import MonitorError

BIND = "SELECT execbound.admin_bind_agent(:a, :g, :p)"
UNBIND = "SELECT execbound.admin_unbind_agent(:a, :b, :r)"
LONG_NAME = "Quarterly access review agent for the finance and payroll systems, EMEA region" + (
    " x" * 8
)


@pytest.fixture
def found(db, world):
    """Three agents the fake Graph API lists, one with a name longer than a label holds."""
    scenario = detailed_scenario(agents=[agent(1), agent(2), agent(3, displayName=LONG_NAME)])
    connection = collect(db, world["admin"], world["clock"], scenario=scenario)
    with db.transaction(world["identity"].tenant_id) as conn:
        rows = conn.execute(
            text(
                "SELECT agent_id, platform_ref, display_name FROM execbound.monitor_agents "
                "ORDER BY platform_ref"
            )
        ).mappings()
        agents = [dict(row) for row in rows]
    assert len(agents) == 3 and len(LONG_NAME) > 80
    return {"connection": connection, "agents": agents}


def linked(admin_engine, agent_id):
    with admin_engine.connect() as conn:
        return conn.execute(
            text("SELECT linked_principal_id FROM execbound.monitor_agents WHERE agent_id = :a"),
            {"a": agent_id},
        ).scalar_one()


def binding_rows(admin_engine, tenant):
    with admin_engine.connect() as conn:
        return [
            dict(row)
            for row in conn.execute(
                text(
                    "SELECT * FROM execbound.agent_bindings WHERE tenant_id = :t ORDER BY bound_at"
                ),
                {"t": tenant},
            ).mappings()
        ]


def new_agent_principal(admin_engine, tenant):
    principal = uuid4()
    with admin_engine.begin() as conn:
        conn.execute(
            text(
                "INSERT INTO execbound.principals (tenant_id, principal_id, kind, space_id) "
                "VALUES (:t, :p, 'AGENT', "
                "(SELECT space_id FROM execbound.spaces WHERE tenant_id = :t))"
            ),
            {"t": tenant, "p": principal},
        )
    return principal


def test_ab1_the_functions_bind_one_to_one_and_refuse_everything_else(
    db, world, found, admin_engine
):
    tenant = world["identity"].tenant_id
    admin, human = world["admin"].principal_id, world["human"].principal_id
    mine = world["identity"].principal_id
    first, second, third = (row["agent_id"] for row in found["agents"])
    for principal in (admin, human, uuid4()):
        assert refused(admin_engine, tenant, BIND, {"a": admin, "g": first, "p": principal}) == (
            "INVALID_PRINCIPAL"
        )
    assert refused(admin_engine, tenant, BIND, {"a": admin, "g": uuid4(), "p": mine}) == (
        "INVALID_AGENT"
    )
    assert refused(admin_engine, tenant, BIND, {"a": human, "g": first, "p": mine}) == (
        "INVALID_ACTOR"
    )
    assert refused(admin_engine, world["other"], BIND, {"a": admin, "g": first, "p": mine}) in {
        "INVALID_TENANT",
        "INVALID_ACTOR",
    }
    binding = call(admin_engine, tenant, BIND, {"a": admin, "g": first, "p": mine})
    assert linked(admin_engine, first) == mine
    # One to one while active: neither side can be bound twice.
    assert refused(admin_engine, tenant, BIND, {"a": admin, "g": first, "p": mine}) == (
        "INVALID_STATE"
    )
    assert refused(admin_engine, tenant, BIND, {"a": admin, "g": second, "p": mine}) == (
        "INVALID_STATE"
    )
    other = new_agent_principal(admin_engine, tenant)
    assert refused(admin_engine, tenant, BIND, {"a": admin, "g": first, "p": other}) == (
        "INVALID_STATE"
    )
    # A deactivated principal and an agent gone from its source are not bindable.
    with admin_engine.begin() as conn:
        conn.execute(
            text(
                "UPDATE execbound.principals SET active = false, deactivated_at = now() "
                "WHERE principal_id = :p"
            ),
            {"p": other},
        )
        conn.execute(
            text("UPDATE execbound.monitor_agents SET gone_at = observed_at WHERE agent_id = :a"),
            {"a": third},
        )
    assert refused(admin_engine, tenant, BIND, {"a": admin, "g": second, "p": other}) == (
        "INVALID_PRINCIPAL"
    )
    fresh = new_agent_principal(admin_engine, tenant)
    assert refused(admin_engine, tenant, BIND, {"a": admin, "g": third, "p": fresh}) == (
        "INVALID_AGENT"
    )
    # Unbinding needs a reason and an active binding, and clears the link with it.
    assert refused(admin_engine, tenant, UNBIND, {"a": admin, "b": binding, "r": "  "}) == (
        "INVALID_REASON"
    )
    assert refused(admin_engine, tenant, UNBIND, {"a": admin, "b": uuid4(), "r": "x"}) == (
        "INVALID_STATE"
    )
    released = call(admin_engine, tenant, UNBIND, {"a": admin, "b": binding, "r": " Retired "})
    assert released == {"agent_id": str(first), "principal_id": str(mine)}
    assert linked(admin_engine, first) is None
    [row] = binding_rows(admin_engine, tenant)
    assert row["unbound_by"] == admin and row["unbound_reason"] == "Retired"
    assert refused(admin_engine, tenant, UNBIND, {"a": admin, "b": binding, "r": "x"}) == (
        "INVALID_STATE"
    )
    # The same pair can be bound again; history keeps the first binding.
    call(admin_engine, tenant, BIND, {"a": admin, "g": first, "p": mine})
    assert len(binding_rows(admin_engine, tenant)) == 2


def test_ab1_the_runtime_role_cannot_move_a_link_or_write_a_binding(db, world, found):
    tenant = world["identity"].tenant_id
    first = found["agents"][0]["agent_id"]
    with pytest.raises(DBAPIError, match="permission denied"):
        with db.transaction(tenant) as conn:
            conn.execute(
                text("UPDATE execbound.monitor_agents SET linked_principal_id = :p"),
                {"p": world["identity"].principal_id},
            )
    with pytest.raises(DBAPIError, match="permission denied"):
        with db.transaction(tenant) as conn:
            conn.execute(
                text(
                    "INSERT INTO execbound.agent_bindings "
                    "(tenant_id, binding_id, agent_id, principal_id, bound_at) "
                    "VALUES (:t, :b, :a, :p, now())"
                ),
                {"t": tenant, "b": uuid4(), "a": first, "p": world["identity"].principal_id},
            )


def test_ab2_the_link_command_binds_through_the_same_functions(db, world, found, admin_engine):
    tenant, admin = world["identity"].tenant_id, world["admin"]
    platform = found["agents"][0]["platform_ref"]
    link = {"connection_id": found["connection"], "platform_ref": platform, "clock": world["clock"]}
    with pytest.raises(MonitorError) as failure:
        monitor_store.link_agent(db, admin, principal_id=admin.principal_id, **link)
    assert failure.value.code == "PRINCIPAL_UNAVAILABLE"
    monitor_store.link_agent(db, admin, principal_id=world["identity"].principal_id, **link)
    # Linking the same pair again changes nothing; another principal needs an unlink first.
    monitor_store.link_agent(db, admin, principal_id=world["identity"].principal_id, **link)
    other = new_agent_principal(admin_engine, tenant)
    with pytest.raises(MonitorError) as failure:
        monitor_store.link_agent(db, admin, principal_id=other, **link)
    assert failure.value.code == "LINK_CONFLICT"
    [row] = binding_rows(admin_engine, tenant)
    assert row["bound_by"] == admin.principal_id and row["unbound_at"] is None
    bound = audit(admin_engine, tenant, "agent.bound")
    assert len(bound) == 1 and bound[0]["binding_id"] == str(row["binding_id"])
    monitor_store.link_agent(db, admin, principal_id=None, **link)
    assert linked(admin_engine, found["agents"][0]["agent_id"]) is None
    unbound = audit(admin_engine, tenant, "agent.unbound")[-1]
    assert unbound["reason"] == "withdrawn with unlink-agent"
