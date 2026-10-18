# SPDX-License-Identifier: AGPL-3.0-only
import os
from pathlib import Path

from alembic import command
from alembic.config import Config
from alembic.script import ScriptDirectory
from sqlalchemy import text

from execbound.db import SCHEMA_REVISION, TABLES

ALEMBIC_INI = Path(__file__).resolve().parents[1] / "alembic.ini"


def test_schema_revision_is_the_one_alembic_head():
    """The revision the runtime requires is where the migration files end, and they end once.

    `check_runtime` refuses a database at any revision but `SCHEMA_REVISION`, so a migration
    added without moving it, or a constant moved without a migration, leaves every process
    refusing the database the migrations build; two heads leave `alembic upgrade head` with
    nowhere to go. The schema tests read the constant rather than repeat its value, so a new
    migration moves `SCHEMA_REVISION` in `db.py` and no test's copy of it.
    """
    heads = ScriptDirectory.from_config(Config(str(ALEMBIC_INI))).get_heads()
    assert heads == [SCHEMA_REVISION], f"alembic heads {heads}, SCHEMA_REVISION {SCHEMA_REVISION}"


def test_migrations_round_trip_on_dedicated_test_database(admin_engine):
    # The guarded fixture only opens loopback execbound_test. This full teardown
    # test requires an empty schema; 0007 intentionally refuses retained identity history.
    with admin_engine.begin() as conn:
        conn.execute(text("TRUNCATE " + ", ".join(f"execbound.{table}" for table in TABLES)))
    config = Config("alembic.ini")
    config.attributes["database_url"] = os.environ["TEST_MIGRATION_DATABASE_URL"]
    try:
        command.downgrade(config, "base")
        with admin_engine.connect() as conn:
            for table in TABLES:
                assert (
                    conn.execute(
                        text("SELECT to_regclass(:table)"), {"table": f"execbound.{table}"}
                    ).scalar_one()
                    is None
                )
    finally:
        command.upgrade(config, "head")
    with admin_engine.connect() as conn:
        assert (
            conn.execute(text("SELECT version_num FROM execbound.alembic_version")).scalar_one()
            == SCHEMA_REVISION
        )
