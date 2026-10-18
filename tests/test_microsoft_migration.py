# SPDX-License-Identifier: AGPL-3.0-only
"""Migration 0091: Microsoft joins the provider and method lists, and the downgrade takes it away.

Real PostgreSQL. The upgrade adds `'microsoft'` to five column checks and to the lists in two
definer functions and changes nothing else: every constraint keeps its name, every function its
owner, `SECURITY DEFINER` and grants. The downgrade runs with nothing the upgrade recorded, and
derives each earlier definition from the live one, so it is checked from a fresh connection and
a fresh load of the module. It refuses while any row holds `microsoft`. Both run again under an
owner that does not bypass row security, as the hosted owner does not.
"""

import importlib.util
from pathlib import Path
from uuid import uuid4

import pytest
from alembic import command
from sqlalchemy import text
from sqlalchemy.exc import IntegrityError
from test_dormant_catalog import alembic_config, empty_schema
from test_migration_without_bypass import restricted as restricted

pytestmark = pytest.mark.integration

BEFORE = "0090_monitor_source_creator"
TARGET = "0091_microsoft_sign_in"
CHECKED = (
    ("user_identities", "provider"),
    ("account_login_proofs", "method"),
    ("account_sessions", "method"),
    ("account_provider_links", "provider"),
    ("signup_requests", "completion_provider"),
)
PATCHED = ("sign_in_credential", "signup_provider_attach")
# The lists that stay as they are: bindings made before accounts existed, which no Microsoft
# binding can be.
UNCHANGED = ("identity_sign_in",)


def migration():
    """A fresh load of the module, so nothing one direction keeps can reach the other."""
    path = Path(__file__).parents[1] / "migrations" / "versions" / f"{TARGET}.py"
    spec = importlib.util.spec_from_file_location(f"{TARGET}_{uuid4().hex}", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def catalog(conn):
    """Every value the revision may touch, as the catalog holds it."""
    constraints = {
        (table, column): conn.execute(
            text(
                "SELECT c.conname, pg_get_constraintdef(c.oid) FROM pg_constraint c "
                "JOIN pg_class r ON r.oid = c.conrelid "
                "JOIN pg_namespace n ON n.oid = r.relnamespace "
                "JOIN pg_attribute a ON a.attrelid = r.oid AND a.attnum = ANY(c.conkey) "
                "WHERE n.nspname = 'execbound' AND r.relname = :t AND a.attname = :c "
                "AND c.contype = 'c' AND pg_get_constraintdef(c.oid) LIKE '%google%'"
            ),
            {"t": table, "c": column},
        ).one()
        for table, column in CHECKED
    }
    functions = {
        name: (definition, acl, owner, definer)
        for name, definition, acl, owner, definer in conn.execute(
            text(
                "SELECT p.proname, pg_get_functiondef(p.oid), CAST(p.proacl AS text), "
                "pg_get_userbyid(p.proowner), p.prosecdef "
                "FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace "
                "WHERE n.nspname = 'execbound' AND p.proname = ANY(:names)"
            ),
            {"names": list(PATCHED + UNCHANGED)},
        ).all()
    }
    forced = dict(
        conn.execute(
            text(
                "SELECT r.relname, r.relforcerowsecurity FROM pg_class r "
                "JOIN pg_namespace n ON n.oid = r.relnamespace "
                "WHERE n.nspname = 'execbound' AND r.relname = ANY(:names)"
            ),
            {"names": [table for table, _ in CHECKED]},
        ).all()
    )
    return constraints, functions, forced


def account(conn, *, provider: str) -> None:
    """One account with one binding, written under the account's own setting, so an owner that
    does not bypass row security admits the rows."""
    owner = uuid4()
    conn.execute(text("SELECT set_config('execbound.account_id', :a, true)"), {"a": str(owner)})
    conn.execute(
        text("INSERT INTO execbound.user_accounts(account_id, email) VALUES (:a, :e)"),
        {"a": owner, "e": f"{owner.hex[:12]}@example.test"},
    )
    conn.execute(
        text(
            "INSERT INTO execbound.user_identities(account_id, provider, subject, created_at) "
            "VALUES (:a, :p, :s, now())"
        ),
        {"a": owner, "p": provider, "s": f"{uuid4()}:{uuid4()}"},
    )


def widened(before, after) -> None:
    constraints, functions, forced = before
    new_constraints, new_functions, new_forced = after
    assert new_forced == forced
    for key, (name, definition) in constraints.items():
        kept, changed = new_constraints[key]
        assert kept == name, key
        widen = ("'github'::text]", "'github'::text, 'microsoft'::text]")
        assert changed == definition.replace(*widen), key
        assert changed != definition, key
    for name in PATCHED:
        old, acl, owner, definer = functions[name]
        new, kept, kept_owner, kept_definer = new_functions[name]
        assert (kept, kept_owner, kept_definer) == (acl, owner, definer), name
        assert definer is True, name
        assert new.count("'microsoft'") == 1, name
        assert new.replace(", 'microsoft'", "") == old, name
    for name in UNCHANGED:
        assert new_functions[name] == functions[name], name


def test_mi4_only_the_lists_widen_and_the_downgrade_restores_them(admin_engine):
    assert migration().down_revision == BEFORE
    empty_schema(admin_engine)
    config = alembic_config()
    command.downgrade(config, BEFORE)
    try:
        with admin_engine.connect() as conn:
            before = catalog(conn)
        assert all("microsoft" not in d for _, d in before[0].values())
        command.upgrade(config, TARGET)
        with admin_engine.connect() as conn:
            after = catalog(conn)
        widened(before, after)
        with admin_engine.begin() as conn:
            account(conn, provider="microsoft")
        with pytest.raises(IntegrityError), admin_engine.begin() as conn:
            account(conn, provider="outlook")
        with admin_engine.begin() as conn:
            conn.execute(text("DELETE FROM execbound.user_identities"))
            conn.execute(text("DELETE FROM execbound.user_accounts"))
        # A fresh module and fresh connections: the downgrade reads only the live catalog.
        migration()
        command.downgrade(alembic_config(), BEFORE)
        with admin_engine.connect() as conn:
            assert catalog(conn) == before
    finally:
        empty_schema(admin_engine)
        command.upgrade(config, "head")


def test_mi4_a_downgrade_with_microsoft_rows_refuses(admin_engine):
    empty_schema(admin_engine)
    config = alembic_config()
    # From this revision, not from the head: a later revision's own downgrade would otherwise
    # run first, in the same transaction, and the refusal would leave the head in place.
    command.downgrade(config, TARGET)
    try:
        with admin_engine.begin() as conn:
            account(conn, provider="microsoft")
        with pytest.raises(RuntimeError, match="MICROSOFT_ROWS_PRESENT"):
            command.downgrade(config, BEFORE)
        with admin_engine.connect() as conn:
            assert (
                conn.execute(text("SELECT version_num FROM execbound.alembic_version")).scalar_one()
                == TARGET
            )
            # The refusal left every table as it found it, forced row security included.
            assert all(catalog(conn)[2].values())
    finally:
        empty_schema(admin_engine)
        command.upgrade(config, "head")


def test_mi4_an_owner_without_bypass_widens_restores_and_refuses(restricted):
    """The hosted owner does not bypass row security, so the downgrade's look for Microsoft
    rows must see rows a forced policy would hide from it, and the upgrade must still keep
    every name and grant."""
    engine, config, _ = restricted
    command.upgrade(config, BEFORE)
    with engine.connect() as conn:
        before = catalog(conn)
    command.upgrade(config, TARGET)
    with engine.connect() as conn:
        widened(before, catalog(conn))
    with engine.begin() as conn:
        account(conn, provider="microsoft")
    with pytest.raises(RuntimeError, match="MICROSOFT_ROWS_PRESENT"):
        command.downgrade(config, BEFORE)
    with engine.begin() as conn:
        conn.execute(text("SET LOCAL row_security = off"))
        conn.execute(text("ALTER TABLE execbound.user_identities NO FORCE ROW LEVEL SECURITY"))
        conn.execute(text("DELETE FROM execbound.user_identities"))
        conn.execute(text("ALTER TABLE execbound.user_identities FORCE ROW LEVEL SECURITY"))
    command.downgrade(config, BEFORE)
    with engine.connect() as conn:
        assert catalog(conn) == before
