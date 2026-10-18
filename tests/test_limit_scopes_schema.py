# SPDX-License-Identifier: AGPL-3.0-only
"""Migration 0021: backfill round trip, guarded downgrade and group grants (SL10, part one)."""

import os
from uuid import uuid4

import pytest
from alembic import command
from alembic.config import Config
from sqlalchemy import text
from sqlalchemy.exc import DBAPIError
from test_execution import finish, targets
from test_execution import registry as registry
from test_execution import world as world

from execbound.db import SCHEMA_REVISION, TABLES, UPDATE_COLUMNS, check_runtime
from execbound.execution import admit, decide_approval, store
from execbound.policy.models import LimitRule
from execbound.policy.store import create_bundle

PREVIOUS = "0021_admin_functions"
GROUP_TABLES = ("principal_groups", "principal_group_members")
IMPACT_COLUMNS = {"account_id", "group_ids", "facts"}
FACT_NAMES = {
    "role",
    "environment",
    "criticality",
    "is_production",
    "incident_status",
    "incident_severity",
}
UNFORCED = (
    "SELECT count(*) FROM pg_class WHERE relnamespace='execbound'::regnamespace "
    "AND relkind='r' AND relname<>'alembic_version' "
    "AND (NOT relrowsecurity OR NOT relforcerowsecurity)"
)


def migration_config():
    config = Config("alembic.ini")
    config.attributes["database_url"] = os.environ["TEST_MIGRATION_DATABASE_URL"]
    return config


def revision(engine):
    with engine.connect() as conn:
        return conn.execute(text("SELECT version_num FROM execbound.alembic_version")).scalar_one()


def impact_rows(engine, tenant):
    with engine.connect() as conn:
        rows = (
            conn.execute(
                text(
                    "SELECT execution_id, state, account_id, group_ids, facts "
                    "FROM execbound.execution_impact WHERE tenant_id=:t"
                ),
                {"t": tenant},
            )
            .mappings()
            .all()
        )
    return {row["execution_id"]: dict(row) for row in rows}


def frozen_attributes(engine, tenant):
    """What the backfill must derive: each frozen intent's account and its facts by name."""
    with engine.connect() as conn:
        rows = (
            conn.execute(
                text("SELECT execution_id, frozen FROM execbound.executions WHERE tenant_id=:t"),
                {"t": tenant},
            )
            .mappings()
            .all()
        )
    expected = {}
    for row in rows:
        plan = store.frozen(dict(row))
        expected[row["execution_id"]] = (
            plan.intent.account_id,
            {fact.name: fact.value for fact in plan.facts},
        )
    return expected


def typed(facts):
    """Pair each value with its type so a JSON boolean can never pass as a number."""
    return {name: (type(value).__name__, value) for name, value in facts.items()}


def assert_schema_intact(db, engine, tenant):
    assert revision(engine) == SCHEMA_REVISION
    with engine.connect() as conn:
        assert conn.execute(text(UNFORCED)).scalar_one() == 0
    with db.transaction(tenant) as conn:
        check_runtime(conn)


def assert_downgrade_refused(db, engine, tenant):
    with pytest.raises(RuntimeError, match="groups or scoped limit rules"):
        command.downgrade(migration_config(), PREVIOUS)
    assert_schema_intact(db, engine, tenant)


def test_runtime_catalog_includes_groups_and_impact_attributes(db, seeded):
    assert all(table in TABLES for table in GROUP_TABLES)
    assert UPDATE_COLUMNS["execution_impact"] == {"state", "confirmed_at"}
    with db.transaction(seeded["tenants"][0]) as conn:
        check_runtime(conn)


def test_backfill_derives_account_and_facts_from_frozen_plans(db, world, admin_engine):
    tenant = world["identity"].tenant_id
    # One development and one production target, so the rows are distinguishable and a
    # backfill that fanned out or crossed executions would be caught per row.
    requests = targets(admin_engine, world, count=1) + targets(
        admin_engine, world, count=1, production=True
    )
    for req in requests:
        admission = admit(db, world["identity"], req, world["clock"])
        if admission.view.state == "PENDING_APPROVAL":
            # The demo pack escalates production targets; approve and retry.
            decide_approval(
                db, world["human"], admission.view.approval_id, "APPROVE", world["clock"]
            )
            admission = admit(db, world["identity"], req, world["clock"])
        assert admission.ticket is not None
        assert finish(db, world, admission).state == "EXECUTED"
    expected = frozen_attributes(admin_engine, tenant)
    assert len(expected) == 2
    environments = set()
    for account_id, facts in expected.values():
        assert account_id == world["account"] and set(facts) == FACT_NAMES
        assert facts["criticality"] == 2
        assert facts["is_production"] is (facts["environment"] == "production")
        environments.add(facts["environment"])
    assert environments == {"development", "production"}
    # Fresh rows carry the frozen account, an empty membership and the facts object with
    # JSON types preserved, so the round trip below must reproduce what admission wrote.
    fresh = impact_rows(admin_engine, tenant)
    assert fresh.keys() == expected.keys()
    for execution_id, (account_id, facts) in expected.items():
        row = fresh[execution_id]
        assert row["state"] == "CONFIRMED"
        assert row["account_id"] == account_id
        assert row["group_ids"] == []
        assert typed(row["facts"]) == typed(facts)
    config = migration_config()
    try:
        command.downgrade(config, PREVIOUS)
        assert revision(admin_engine) == PREVIOUS
        with admin_engine.connect() as conn:
            for table in GROUP_TABLES:
                assert (
                    conn.execute(
                        text("SELECT to_regclass(:table)"), {"table": f"execbound.{table}"}
                    ).scalar_one()
                    is None
                )
            columns = conn.execute(
                text(
                    "SELECT column_name FROM information_schema.columns "
                    "WHERE table_schema='execbound' AND table_name='execution_impact'"
                )
            ).scalars()
            assert IMPACT_COLUMNS.isdisjoint(columns.all())
    finally:
        command.upgrade(config, "head")
    backfilled = impact_rows(admin_engine, tenant)
    assert backfilled.keys() == expected.keys()
    for execution_id, (account_id, facts) in expected.items():
        row = backfilled[execution_id]
        assert row["account_id"] == account_id
        assert typed(row["facts"]) == typed(facts)
        assert row["group_ids"] is None
    assert_schema_intact(db, admin_engine, tenant)


def test_downgrade_refuses_while_groups_or_scoped_rules_exist(db, world, admin_engine):
    tenant, group = world["identity"].tenant_id, uuid4()
    params = {
        "t": tenant,
        "g": group,
        "p": world["identity"].principal_id,
        "n": world["clock"].now(),
    }
    with admin_engine.begin() as conn:
        conn.execute(
            text(
                "INSERT INTO execbound.principal_groups (tenant_id, group_id, name, created_at) "
                "VALUES (:t, :g, 'responders', :n)"
            ),
            params,
        )
        conn.execute(
            text(
                "INSERT INTO execbound.principal_group_members "
                "(tenant_id, group_id, principal_id, assigned_at) VALUES (:t, :g, :p, :n)"
            ),
            params,
        )
    assert_downgrade_refused(db, admin_engine, tenant)
    with admin_engine.begin() as conn:
        conn.execute(text("DELETE FROM execbound.principal_group_members"))
    assert_downgrade_refused(db, admin_engine, tenant)
    with admin_engine.begin() as conn:
        # A signal source may name a principal group (0068), so its table, and the records
        # that point at it, are truncated with the groups.
        conn.execute(
            text(
                "TRUNCATE execbound.principal_group_members, execbound.principal_groups, "
                "execbound.signal_sources, execbound.security_signals"
            )
        )
    # A DRAFT is enough: the guard reads content, not lifecycle state.
    paired = LimitRule(
        rule_id="paired-isolation",
        action="endpoint.isolate",
        scope="principal",
        window_seconds=3600,
        max_targets=10,
        budget="autonomous",
        on_exceed="REQUIRE_APPROVAL",
        actions=("endpoint.isolate",),
    )
    draft = world["bundle"].model_copy(
        update={"bundle_id": uuid4(), "limits": (*world["bundle"].limits, paired)}
    )
    assert create_bundle(db, world["admin"], draft, world["clock"]).state == "DRAFT"
    assert_downgrade_refused(db, admin_engine, tenant)
    with admin_engine.begin() as conn:
        for table in ("policy_bundle_lifecycle", "policy_bundle_contents"):
            conn.execute(
                text(f"DELETE FROM execbound.{table} WHERE tenant_id=:t AND bundle_id=:b"),
                {"t": tenant, "b": draft.bundle_id},
            )
    config = migration_config()
    try:
        command.downgrade(config, PREVIOUS)
        assert revision(admin_engine) == PREVIOUS
    finally:
        command.upgrade(config, "head")
    assert_schema_intact(db, admin_engine, tenant)


@pytest.mark.parametrize(
    "statement",
    [
        "INSERT INTO execbound.principal_groups (tenant_id, group_id, name, created_at) "
        "VALUES (:t, gen_random_uuid(), 'responders', now())",
        "INSERT INTO execbound.principal_group_members "
        "(tenant_id, group_id, principal_id, assigned_at) "
        "VALUES (:t, gen_random_uuid(), :p, now())",
        "UPDATE execbound.principal_groups SET name = 'renamed'",
        "UPDATE execbound.principal_group_members SET assigned_at = now()",
        "DELETE FROM execbound.principal_groups",
        "DELETE FROM execbound.principal_group_members",
    ],
)
def test_runtime_cannot_write_group_tables(db, seeded, statement):
    with pytest.raises(DBAPIError), db.transaction(seeded["tenants"][0]) as conn:
        conn.execute(text(statement), {"t": seeded["tenants"][0], "p": seeded["principals"][0]})
