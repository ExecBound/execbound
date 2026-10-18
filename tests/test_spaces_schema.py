# SPDX-License-Identifier: AGPL-3.0-only
"""Migration 0041: the three tables, the runtime's grants and the guarded round trip (SP10).

A space is a column plus a membership check and **never a second fence**, so the first
thing this file holds is that no policy in the schema mentions a space setting and that
every `tenant_isolation` policy is still forced and still tenant-keyed.
"""

import importlib.util
import os
from pathlib import Path
from uuid import uuid4

import pytest
from alembic import command
from alembic.config import Config
from sqlalchemy import text
from sqlalchemy.exc import DBAPIError
from test_execution import registry as registry
from test_execution import world as world

from execbound.db import SCHEMA_REVISION, TABLES, UPDATE_COLUMNS, check_runtime

pytestmark = pytest.mark.integration

PREVIOUS = "0040_sign_in"
SPACE_TABLES = ("spaces", "space_members", "space_policy_selection")


def load_migration():
    """The migration module itself, so its column lists are this file's parameter lists."""
    path = Path(__file__).resolve().parents[1] / "migrations" / "versions" / "0041_spaces.py"
    spec = importlib.util.spec_from_file_location("spaces_migration", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


# Every table the migration gives a space column, read from the migration's own lists so a
# table added later cannot be added without a case here.
MIGRATION = load_migration()
OWNED_TABLES = MIGRATION.OWNED_TABLES
OFFERABLE = MIGRATION.OFFERABLE

UNFORCED = (
    "SELECT count(*) FROM pg_class WHERE relnamespace='execbound'::regnamespace "
    "AND relkind='r' AND relname<>'alembic_version' "
    "AND (NOT relrowsecurity OR NOT relforcerowsecurity)"
)
# A policy that read a space setting would be forced RLS doing a space's work: a space is a
# column plus a membership check, never a second row-level-security fence.
SPACE_IN_A_POLICY = (
    "SELECT count(*) FROM pg_policies WHERE schemaname='execbound' "
    "AND (COALESCE(qual, '') LIKE '%%space%%' OR COALESCE(with_check, '') LIKE '%%space%%')"
)


def migration_config():
    config = Config("alembic.ini")
    config.attributes["database_url"] = os.environ["TEST_MIGRATION_DATABASE_URL"]
    return config


def revision(engine):
    with engine.connect() as conn:
        return conn.execute(text("SELECT version_num FROM execbound.alembic_version")).scalar_one()


def test_the_runtime_catalog_names_the_three_tables_and_their_one_writable_row(db, world):
    for table in SPACE_TABLES:
        assert table in TABLES
    # `spaces` and `space_members` are written by definer functions alone; the selection is
    # the one exception, because activation is already a fenced store function.
    assert "spaces" not in UPDATE_COLUMNS and "space_members" not in UPDATE_COLUMNS
    assert UPDATE_COLUMNS["space_policy_selection"] == {"bundle_id", "changed_at", "changed_by"}
    # The selection moved off the control row, so the runtime no longer writes it there.
    assert "active_bundle_id" not in UPDATE_COLUMNS["tenant_policy_control"]
    with db.transaction(world["identity"].tenant_id) as conn:
        check_runtime(conn)


def test_every_table_is_forced_and_no_policy_reads_a_space_setting(db, world):
    with db.transaction(world["identity"].tenant_id) as conn:
        assert conn.execute(text(UNFORCED)).scalar_one() == 0
        assert conn.execute(text(SPACE_IN_A_POLICY)).scalar_one() == 0


@pytest.mark.parametrize("table", ["spaces", "space_members"])
@pytest.mark.parametrize("statement", ["INSERT", "UPDATE", "DELETE"])
def test_the_runtime_cannot_write_a_space_or_a_membership(db, world, table, statement):
    tenant = world["identity"].tenant_id
    space = uuid4()
    bodies = {
        "INSERT": {
            "spaces": (
                "INSERT INTO execbound.spaces"
                "(tenant_id, space_id, name, created_at, created_by) "
                "VALUES (:t, :s, 'Forged', now(), :t)"
            ),
            "space_members": (
                "INSERT INTO execbound.space_members"
                "(tenant_id, space_id, principal_id, role, assigned_at) "
                "VALUES (:t, :s, :t, 'ADMIN', now())"
            ),
        },
        "UPDATE": {
            "spaces": "UPDATE execbound.spaces SET name='Forged' WHERE tenant_id=:t",
            "space_members": "UPDATE execbound.space_members SET role='ADMIN' WHERE tenant_id=:t",
        },
        "DELETE": {
            "spaces": "DELETE FROM execbound.spaces WHERE tenant_id=:t",
            "space_members": "DELETE FROM execbound.space_members WHERE tenant_id=:t",
        },
    }
    with pytest.raises(DBAPIError), db.transaction(tenant) as conn:
        conn.execute(text(bodies[statement][table]), {"t": tenant, "s": space})


def test_every_tenant_has_exactly_one_default_space_and_every_owned_row_names_it(
    admin_engine, world
):
    tenant = world["identity"].tenant_id
    with admin_engine.begin() as conn:
        conn.execute(text("SELECT set_config('execbound.tenant_id', :t, true)"), {"t": str(tenant)})
        spaces = (
            conn.execute(
                text("SELECT space_id, name FROM execbound.spaces WHERE tenant_id=:t"),
                {"t": tenant},
            )
            .mappings()
            .all()
        )
        assert len(spaces) == 1
        space = spaces[0]["space_id"]
        for table in OWNED_TABLES:
            stray = conn.execute(
                # The table is this module's own literal, from the migration's list.
                text(  # nosec B608 - a literal from the migration's own column list
                    f"SELECT count(*) FROM execbound.{table} WHERE tenant_id=:t AND space_id <> :s"
                ),
                {"t": tenant, "s": space},
            ).scalar_one()
            assert stray == 0, table
        # A person is a member, never owned; an agent is owned and never a member.
        assert (
            conn.execute(
                text(
                    "SELECT count(*) FROM execbound.principals "
                    "WHERE tenant_id=:t AND ((kind='AGENT') <> (space_id IS NOT NULL))"
                ),
                {"t": tenant},
            ).scalar_one()
            == 0
        )


def test_an_approver_is_seated_and_an_administrator_is_not(admin_engine, world):
    """Every existing administrator stays a tenant administrator, so nothing they can do
    today becomes unreachable when a second space appears."""
    tenant = world["identity"].tenant_id
    with admin_engine.begin() as conn:
        conn.execute(text("SELECT set_config('execbound.tenant_id', :t, true)"), {"t": str(tenant)})
        rows = (
            conn.execute(
                text(
                    "SELECT p.kind, count(m.principal_id) AS seats "
                    "FROM execbound.principals p "
                    "LEFT JOIN execbound.space_members m USING (tenant_id, principal_id) "
                    "WHERE p.tenant_id=:t GROUP BY p.kind, p.principal_id"
                ),
                {"t": tenant},
            )
            .mappings()
            .all()
        )
    seats = {row["kind"]: row["seats"] for row in rows}
    assert seats.get("ADMIN", 0) == 0
    assert seats.get("HUMAN_APPROVER", 1) >= 1


def test_the_offer_is_a_second_column_and_defaults_to_not_offered(admin_engine, world):
    tenant = world["identity"].tenant_id
    with admin_engine.begin() as conn:
        conn.execute(text("SELECT set_config('execbound.tenant_id', :t, true)"), {"t": str(tenant)})
        for table in OFFERABLE:
            offered = conn.execute(
                text(  # nosec B608 - a literal from the migration's own list
                    f"SELECT count(*) FROM execbound.{table} "
                    "WHERE tenant_id=:t AND offered_tenant_wide"
                ),
                {"t": tenant},
            ).scalar_one()
            assert offered == 0, table


def test_sp10_round_trip_restores_the_control_row_and_refuses_with_two_spaces(
    admin_engine, world, db
):
    """The downgrade refuses while any tenant holds more than one space, because merging
    would be a decision about which customer's objects become whose."""
    tenant = world["identity"].tenant_id
    config = migration_config()
    assert revision(admin_engine) == SCHEMA_REVISION
    with admin_engine.begin() as conn:
        conn.execute(text("SELECT set_config('execbound.tenant_id', :t, true)"), {"t": str(tenant)})
        conn.execute(
            text(
                "INSERT INTO execbound.spaces"
                "(tenant_id, space_id, name, created_at, created_by) "
                "VALUES (:t, :s, 'Second', now(), :t)"
            ),
            {"t": tenant, "s": uuid4()},
        )
    with pytest.raises(RuntimeError, match="more than one space"):
        command.downgrade(config, PREVIOUS)
    assert revision(admin_engine) == SCHEMA_REVISION
    with admin_engine.begin() as conn:
        conn.execute(text("SELECT set_config('execbound.tenant_id', :t, true)"), {"t": str(tenant)})
        conn.execute(
            text("DELETE FROM execbound.spaces WHERE tenant_id=:t AND name='Second'"),
            {"t": tenant},
        )
    command.downgrade(config, PREVIOUS)
    assert revision(admin_engine) == PREVIOUS
    with admin_engine.connect() as conn:
        restored = conn.execute(
            text(
                "SELECT count(*) FROM information_schema.columns "
                "WHERE table_schema='execbound' AND table_name='tenant_policy_control' "
                "AND column_name='active_bundle_id'"
            )
        ).scalar_one()
        index = conn.execute(
            text(
                "SELECT count(*) FROM pg_indexes WHERE schemaname='execbound' "
                "AND indexname='policy_bundle_one_active'"
            )
        ).scalar_one()
        gone = conn.execute(
            text(
                "SELECT count(*) FROM pg_tables WHERE schemaname='execbound' "
                "AND tablename = ANY(CAST(:names AS text[]))"
            ),
            {"names": list(SPACE_TABLES)},
        ).scalar_one()
    assert (restored, index, gone) == (1, 1, 0)
    command.upgrade(config, SCHEMA_REVISION)
    assert revision(admin_engine) == SCHEMA_REVISION
    with db.transaction(tenant) as conn:
        check_runtime(conn)
