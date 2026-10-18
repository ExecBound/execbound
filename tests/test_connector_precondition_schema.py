# SPDX-License-Identifier: AGPL-3.0-only
"""Migration 0032: what each dispatch's precondition was worth, and its guarded downgrade."""

import os

import pytest
from alembic import command
from alembic.config import Config
from sqlalchemy import text
from sqlalchemy.exc import DBAPIError
from test_execution import registry as registry
from test_execution import world as world
from test_execution_database import execution_storage as execution_storage

from execbound.db import SCHEMA_REVISION, UPDATE_COLUMNS, check_runtime

pytestmark = pytest.mark.integration

PREVIOUS = "0031_scout_rules"


def migration_config():
    config = Config("alembic.ini")
    config.attributes["database_url"] = os.environ["TEST_MIGRATION_DATABASE_URL"]
    return config


def revision(engine):
    with engine.connect() as conn:
        return conn.execute(text("SELECT version_num FROM execbound.alembic_version")).scalar_one()


def forced(engine):
    with engine.connect() as conn:
        return conn.execute(
            text(
                "SELECT relforcerowsecurity FROM pg_class c JOIN pg_namespace n "
                "ON n.oid = c.relnamespace WHERE n.nspname = 'execbound' "
                "AND c.relname = 'executions'"
            )
        ).scalar_one()


def test_the_runtime_catalog_names_the_revision_and_both_columns(db):
    # The dispatch path writes both in the statement that records the attempt; nothing else
    # about this table's writable surface changes.
    assert {"precondition_class", "precondition_window_ms"} <= UPDATE_COLUMNS["executions"]
    with db.engine.connect() as conn:
        check_runtime(conn)


def test_a_class_outside_the_union_is_refused_by_the_database(admin_engine, execution_storage):
    """The union lives in two places, and the one that survives a rogue UPDATE is this one."""
    execution = execution_storage["execution"]
    with pytest.raises(DBAPIError):
        with admin_engine.begin() as conn:
            conn.execute(
                text(
                    "UPDATE execbound.executions SET precondition_class = 'ATOMIC_ISH' "
                    "WHERE execution_id = :e"
                ),
                {"e": execution},
            )


@pytest.mark.parametrize(
    "klass,window",
    [
        # Only CHECKED_BY_CONNECTOR measures a window, because it is the one class where
        # ExecBound reads, compares and writes and so owns the gap between them.
        ("ENFORCED_BY_PROVIDER", 10),
        ("ASSERTED_BY_EXECUTOR", 10),
        ("UNAVAILABLE", 10),
        (None, 10),
        # A window is a measurement, and these are not measurements.
        ("CHECKED_BY_CONNECTOR", -1),
        ("CHECKED_BY_CONNECTOR", 3600001),
    ],
    ids=[
        "enforced-with-a-window",
        "asserted-with-a-window",
        "unavailable-with-a-window",
        "undeclared-with-a-window",
        "negative-window",
        "window-beyond-an-hour",
    ],
)
def test_a_window_belongs_only_to_the_class_that_measures_one(
    admin_engine, execution_storage, klass, window
):
    execution = execution_storage["execution"]
    with pytest.raises(DBAPIError):
        with admin_engine.begin() as conn:
            conn.execute(
                text(
                    "UPDATE execbound.executions SET precondition_class = :c, "
                    "precondition_window_ms = :w WHERE execution_id = :e"
                ),
                {"c": klass, "w": window, "e": execution},
            )


def test_a_measured_window_under_the_connector_class_is_accepted(admin_engine, execution_storage):
    execution = execution_storage["execution"]
    with admin_engine.begin() as conn:
        conn.execute(
            text(
                "UPDATE execbound.executions SET precondition_class = 'CHECKED_BY_CONNECTOR', "
                "precondition_window_ms = 0 WHERE execution_id = :e"
            ),
            {"e": execution},
        )
    with admin_engine.begin() as conn:
        conn.execute(
            text(
                "UPDATE execbound.executions SET precondition_window_ms = 3600000 "
                "WHERE execution_id = :e"
            ),
            {"e": execution},
        )
        conn.execute(
            text(
                "UPDATE execbound.executions SET precondition_class = NULL, "
                "precondition_window_ms = NULL WHERE execution_id = :e"
            ),
            {"e": execution},
        )


def test_downgrade_refuses_while_a_dispatch_records_its_class(db, admin_engine, execution_storage):
    """A recorded class is evidence of how strong the precondition behind a dispatch was.

    0031 cannot express it, so dropping the column discards it, and a downgrade that
    deleted evidence to make itself succeed is exactly what the development guide forbids.
    """
    execution = execution_storage["execution"]
    with admin_engine.begin() as conn:
        conn.execute(
            text(
                "UPDATE execbound.executions SET precondition_class = 'CHECKED_BY_CONNECTOR', "
                "precondition_window_ms = 12 WHERE execution_id = :e"
            ),
            {"e": execution},
        )
    with pytest.raises(RuntimeError, match="connector-side check"):
        command.downgrade(migration_config(), PREVIOUS)
    assert revision(admin_engine) == SCHEMA_REVISION
    # The guard lifts row security to read every tenant's rows and must put it back, or a
    # refused downgrade would leave the table readable across tenants.
    assert forced(admin_engine) is True

    with admin_engine.begin() as conn:
        conn.execute(
            text(
                "UPDATE execbound.executions SET precondition_class = NULL, "
                "precondition_window_ms = NULL"
            )
        )
    config = migration_config()
    try:
        command.downgrade(config, PREVIOUS)
        assert revision(admin_engine) == PREVIOUS
        with admin_engine.connect() as conn:
            columns = (
                conn.execute(
                    text(
                        "SELECT column_name FROM information_schema.columns "
                        "WHERE table_schema = 'execbound' AND table_name = 'executions' "
                        "AND column_name LIKE 'precondition%'"
                    )
                )
                .scalars()
                .all()
            )
        assert columns == []
    finally:
        command.upgrade(config, SCHEMA_REVISION)
    assert revision(admin_engine) == SCHEMA_REVISION
    assert forced(admin_engine) is True


def test_an_ordinary_dispatchs_class_does_not_block_the_downgrade(
    db, admin_engine, execution_storage
):
    """A guard that fires on any recorded class is a wall, not a guard.

    Native dispatch records a class on every attempt, so once this column exists every
    database where anything has been dispatched holds one. Blocking on that would make the
    downgrade impossible in any used database, which is how this was first written and what
    `test_limit_scopes_schema.py`'s legitimate backfill downgrade caught. Only
    CHECKED_BY_CONNECTOR, and the window measured under it, describe something 0031 cannot
    express and a reader would misread as the atomic default.
    """
    execution = execution_storage["execution"]
    for klass in ("UNAVAILABLE", "ENFORCED_BY_PROVIDER", "ASSERTED_BY_EXECUTOR"):
        with admin_engine.begin() as conn:
            conn.execute(
                text(
                    "UPDATE execbound.executions SET precondition_class = :c "
                    "WHERE execution_id = :e"
                ),
                {"c": klass, "e": execution},
            )
        config = migration_config()
        try:
            command.downgrade(config, PREVIOUS)
            assert revision(admin_engine) == PREVIOUS
        finally:
            command.upgrade(config, SCHEMA_REVISION)
        assert revision(admin_engine) == SCHEMA_REVISION
        assert forced(admin_engine) is True
