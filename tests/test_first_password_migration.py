# SPDX-License-Identifier: AGPL-3.0-only
"""Migration 0070: `user_security_change` gains `password_set`, and the downgrade takes it away.

Real PostgreSQL. The upgrade adds the one branch and the one rotation entry and nothing else,
keeps the function's owner and grants, and the downgrade restores its body byte for byte.
"""

import importlib.util
from pathlib import Path

import pytest
from alembic import command
from sqlalchemy import text
from test_dormant_catalog import alembic_config, empty_schema

pytestmark = pytest.mark.integration

BEFORE = "0069_provider_signup"
TARGET = "0070_first_password"
_FILE = Path(__file__).resolve().parents[1] / "migrations" / "versions" / f"{TARGET}.py"
_spec = importlib.util.spec_from_file_location("first_password_migration", _FILE)
assert _spec is not None and _spec.loader is not None
migration = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(migration)


def definition(conn):
    return conn.execute(
        text(
            "SELECT pg_get_functiondef(p.oid), CAST(p.proacl AS text) FROM pg_proc p "
            "JOIN pg_namespace n ON n.oid = p.pronamespace "
            "WHERE n.nspname = 'execbound' AND p.proname = 'user_security_change'"
        )
    ).one()


def test_the_upgrade_adds_one_branch_and_the_downgrade_restores_the_function(admin_engine):
    empty_schema(admin_engine)
    config = alembic_config()
    command.downgrade(config, BEFORE)
    try:
        with admin_engine.connect() as conn:
            old, acl = definition(conn)
        assert "password_set" not in old
        command.upgrade(config, TARGET)
        with admin_engine.connect() as conn:
            new, kept = definition(conn)
        assert kept == acl
        assert "execbound_app=X/execbound_owner" in kept
        assert new == old.replace(migration.BRANCH_BEFORE, migration.BRANCH_AFTER).replace(
            migration.ROTATION_BEFORE, migration.ROTATION_AFTER
        )
        # It inserts only, and only where nothing is: it can never replace a password.
        branch = new[new.index("p_operation='password_set'") : new.index("p_operation='password'")]
        assert "ON CONFLICT(account_id) DO NOTHING" in branch
        assert "UPDATE execbound.user_passwords" not in branch
        command.downgrade(config, BEFORE)
        with admin_engine.connect() as conn:
            assert definition(conn) == (old, acl)
    finally:
        empty_schema(admin_engine)
        command.upgrade(config, "head")
