# SPDX-License-Identifier: AGPL-3.0-only
"""Agents page, step 3 (AT1 to AT3): the tenant line, per source, in Monitoring's own terms."""

from datetime import timedelta

from sqlalchemy import text
from test_agents_bindings import BIND
from test_agents_bindings import found as found
from test_execution import registry as registry
from test_execution import world as world
from test_human_surface import human_config as human_config
from test_people_pages import admin_client as admin_client
from test_people_pages import call
from test_protected_path import connector as connector
from test_protected_path import live_provider as live_provider
from test_runtime import runtime as runtime

from execbound.execution import store
from execbound.monitoring import store as monitor_store
from execbound.monitoring.models import DetectionProfile
from execbound.replay.verify import reject_secrets
from execbound.surfaces.agents_pages import tenant_line
from execbound.surfaces.sessions import issue_session, load_session


def line(db, world):
    tenant = world["identity"].tenant_id
    with db.transaction(tenant) as conn:
        store.fence(conn, tenant, world["clock"])
        return tenant_line(conn, tenant, world["clock"].now())


def monitoring(db, world):
    """Monitoring's own tenant figures for the same rows."""
    grant = issue_session(db, world["admin"], clock=world["clock"])
    session = load_session(db, grant.token, clock=world["clock"])
    return monitor_store.agents_snapshot(db, session, clock=world["clock"])["tenant"]


def shown(admin_client):
    """The tenant line as the console reads it, over the Agents list route."""
    answer = admin_client.get("/api/console/v1/agents")
    assert answer.status_code == 200, answer.text
    reject_secrets(answer.json())
    return answer.json()["line"]


def source_row(admin_client, label):
    """The tenant line's row for one connection, by its label."""
    [row] = [item for item in shown(admin_client)["sources"] if item["label"] == label]
    return row


def test_at1_with_no_source_the_line_says_so_and_counts_the_governed(admin_client, world):
    line = shown(admin_client)
    # No connection lists anything, so the line names no source rather than showing zeros.
    assert line["sources"] == []
    # The governed side still counts: the fixture's one agent principal, nothing bound.
    assert line["principals"] == 1 and line["bound"] == 0


def test_at2_each_source_is_counted_as_monitoring_counts_it(
    admin_client, db, world, found, admin_engine
):
    tenant, admin = world["identity"].tenant_id, world["admin"].principal_id
    monitor_store.set_profile(
        db,
        world["admin"],
        DetectionProfile(sensitive_actions=("identity.disable",), restricted_targets=()),
        clock=world["clock"],
    )
    ours, theirs = line(db, world), monitoring(db, world)
    [source] = ours["sources"]
    assert source["kind"] == "entra_agent_id" and source["listed"] == 3
    assert ours["totals"]["listed"] == theirs["enumerated"]
    assert ours["totals"]["consequential"] == theirs["with_reach"]
    assert ours["totals"]["unestablished"] == theirs["unestablished"]
    assert ours["profiled"] and ours["totals"]["consequential"] >= 1
    call(
        admin_engine,
        tenant,
        BIND,
        {"a": admin, "g": found["agents"][0]["agent_id"], "p": world["identity"].principal_id},
    )
    row = source_row(admin_client, "Synthetic directory")
    assert row["listed"] == 3 and row["bound"] == 1
    assert row["consequential"] == ours["totals"]["consequential"]
    assert shown(admin_client)["bound"] == 1
    assert shown(admin_client)["profiled"] is True


def test_at3_gone_agents_and_lapsed_claims_move_the_line_with_monitoring(
    admin_client, db, world, found, admin_engine
):
    monitor_store.set_profile(
        db,
        world["admin"],
        DetectionProfile(sensitive_actions=("identity.disable",), restricted_targets=()),
        clock=world["clock"],
    )
    before = line(db, world)["totals"]
    assert before["consequential"] >= 1 and before["unestablished"] >= 1
    with admin_engine.begin() as conn:
        conn.execute(
            text("UPDATE execbound.monitor_agents SET gone_at = observed_at WHERE agent_id = :a"),
            {"a": found["agents"][2]["agent_id"]},
        )
    ours, theirs = line(db, world), monitoring(db, world)
    assert ours["totals"]["listed"] == before["listed"] - 1 == theirs["enumerated"]
    assert ours["totals"]["unestablished"] == theirs["unestablished"]
    # The only agent with grants: once its claims pass their validity, nothing it holds is
    # consequential reach any more, and the claim itself reads as not established.
    with admin_engine.begin() as conn:
        conn.execute(
            text(
                "UPDATE execbound.monitor_agent_reach SET computed_at = computed_at - :d, "
                "valid_until = computed_at - :d + interval '1 second' WHERE agent_id = :a"
            ),
            {"a": found["agents"][0]["agent_id"], "d": timedelta(days=30)},
        )
    ours, theirs = line(db, world), monitoring(db, world)
    assert ours["totals"]["consequential"] == 0 == theirs["with_reach"]
    assert ours["totals"]["unestablished"] == theirs["unestablished"] >= 1
    row = source_row(admin_client, "Synthetic directory")
    assert row["listed"] == 2 and row["consequential"] == 0
