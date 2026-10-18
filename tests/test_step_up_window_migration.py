# SPDX-License-Identifier: AGPL-3.0-only
"""Migration 0067: the database's own recent-factor check moves to thirty minutes.

Real PostgreSQL. The upgrade changes the one `fresh` interval in each security function and
nothing else, keeps each function's owner and grants, and the downgrade restores both bodies
byte for byte.
"""

import pytest
from alembic import command
from sqlalchemy import text
from test_dormant_catalog import alembic_config, empty_schema

from execbound import mfa

pytestmark = pytest.mark.integration

BEFORE = "0066_max_agents"
TARGET = "0067_step_up_window"
PATCHED = ("account_security_change", "user_security_change")


def catalog(conn):
    """Each patched function's definition and ACL, as the catalog holds them."""
    return {
        name: (definition, acl)
        for name, definition, acl in conn.execute(
            text(
                "SELECT p.proname, pg_get_functiondef(p.oid), CAST(p.proacl AS text) "
                "FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace "
                "WHERE n.nspname = 'execbound' AND p.proname = ANY(:names)"
            ),
            {"names": list(PATCHED)},
        ).all()
    }


def test_only_the_recent_factor_interval_moves_and_the_downgrade_restores_it(admin_engine):
    assert mfa.STEP_UP_WINDOW.total_seconds() == 30 * 60
    empty_schema(admin_engine)
    config = alembic_config()
    command.downgrade(config, BEFORE)
    try:
        with admin_engine.connect() as conn:
            before = catalog(conn)
        command.upgrade(config, TARGET)
        with admin_engine.connect() as conn:
            after = catalog(conn)
        assert set(before) == set(after) == set(PATCHED)
        for name in PATCHED:
            old, acl = before[name]
            new, kept = after[name]
            assert kept == acl, name
            assert "execbound_app=X/execbound_owner" in kept, name
            assert new == old.replace(
                "a.verified_at>p_now-interval '5 minutes'",
                "a.verified_at>p_now-interval '30 minutes'",
            ), name
            # The sign-in's own age and the lifetimes of a staged factor, a passkey challenge
            # and a provider link are other windows, and stay where they were.
            assert new.count("interval '5 minutes'") == old.count("interval '5 minutes'") - 1
        command.downgrade(config, BEFORE)
        with admin_engine.connect() as conn:
            assert catalog(conn) == before
    finally:
        empty_schema(admin_engine)
        command.upgrade(config, "head")
