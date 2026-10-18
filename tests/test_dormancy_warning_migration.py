# SPDX-License-Identifier: AGPL-3.0-only
"""Migration 0092: the dormancy warning's outbox is dormant until a plugin claims it (hosted: DW10).

Real PostgreSQL. One table under forced row level security, fenced to its tenant, and three
definer functions, none granted to anyone but the owner, so a database with no plugin can
neither read a warning nor queue, list or count one, and `check_runtime` refuses one that grants
any of them. The functions' own behaviour is the hosted plugin's to test; this file reads only
the catalog and the table's own checks.
"""

import secrets

import pytest
from alembic import command
from sqlalchemy import text
from sqlalchemy.exc import IntegrityError
from test_account_recovery_migration import platform_role as platform_role
from test_account_recovery_migration import signature
from test_dormant_catalog import alembic_config, empty_schema, revision_of

from execbound.db import (
    EMPTY_CLAIMS,
    DormantGrantsRefused,
    check_dormant,
    check_runtime,
    grant_dormant,
)

pytestmark = pytest.mark.integration

BEFORE = "0091_microsoft_sign_in"
TARGET = "0092_dormancy_warning"
TABLES = ("dormancy_warnings",)
FUNCTIONS = ("dormancy_warn", "dormancy_warnings_due", "dormancy_warnings_sent")


def present(conn) -> set[str]:
    tables = set(
        conn.execute(
            text(
                "SELECT tablename FROM pg_tables WHERE schemaname='execbound' AND tablename=ANY(:t)"
            ),
            {"t": list(TABLES)},
        ).scalars()
    )
    functions = set(
        conn.execute(
            text(
                "SELECT p.proname FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace "
                "WHERE n.nspname='execbound' AND p.proname=ANY(:f)"
            ),
            {"f": list(FUNCTIONS)},
        ).scalars()
    )
    return tables | functions


def grantees(conn) -> set[str]:
    """Every role other than the owner holding anything on the four objects."""
    rows = conn.execute(
        text("""
        SELECT coalesce(r.rolname, 'PUBLIC') FROM pg_class c
          JOIN pg_namespace n ON n.oid = c.relnamespace, aclexplode(c.relacl) a
          LEFT JOIN pg_roles r ON r.oid = a.grantee
         WHERE n.nspname = 'execbound' AND c.relname = ANY(:t) AND a.grantee <> c.relowner
        UNION
        SELECT coalesce(r.rolname, 'PUBLIC') FROM pg_proc p
          JOIN pg_namespace n ON n.oid = p.pronamespace, aclexplode(p.proacl) a
          LEFT JOIN pg_roles r ON r.oid = a.grantee
         WHERE n.nspname = 'execbound' AND p.proname = ANY(:f) AND a.grantee <> p.proowner
        """),
        {"t": list(TABLES), "f": list(FUNCTIONS)},
    ).scalars()
    return set(rows)


def test_dw10_dormant_until_claimed(db, admin_engine):
    empty_schema(admin_engine)
    config = alembic_config()
    command.downgrade(config, BEFORE)
    try:
        with admin_engine.connect() as conn:
            assert present(conn) == set()
        command.upgrade(config, TARGET)
        assert revision_of(admin_engine) == TARGET
        with admin_engine.connect() as conn:
            assert present(conn) == set(TABLES) | set(FUNCTIONS)
            security = conn.execute(
                text(
                    "SELECT c.relname, c.relrowsecurity, c.relforcerowsecurity, "
                    "(SELECT array_agg(polname ORDER BY polname) FROM pg_policy "
                    "WHERE polrelid = c.oid) "
                    "FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace "
                    "WHERE n.nspname = 'execbound' AND c.relname = ANY(:t)"
                ),
                {"t": list(TABLES)},
            ).all()
            assert [tuple(row) for row in security] == [
                ("dormancy_warnings", True, True, ["owner_drain", "tenant_isolation"]),
            ]
            definers = conn.execute(
                text(
                    "SELECT p.proname, p.prosecdef, p.proconfig FROM pg_proc p "
                    "JOIN pg_namespace n ON n.oid = p.pronamespace "
                    "WHERE n.nspname = 'execbound' AND p.proname = ANY(:f)"
                ),
                {"f": list(FUNCTIONS)},
            ).all()
            assert len(definers) == len(FUNCTIONS)
            assert all(
                secure and config_ == ["search_path=pg_catalog, pg_temp"]
                for _, secure, config_ in definers
            )
            # Born dormant: nobody but the owner holds anything, PUBLIC included.
            assert grantees(conn) == set()
        # The runtime check expects the head's catalog, which later revisions extend.
        command.upgrade(config, "head")
        # A database with no plugin passes the runtime check; one grant on any of them fails it.
        with db.engine.connect() as conn:
            check_runtime(conn)
        for grant in (
            "SELECT ON execbound.dormancy_warnings",
            "EXECUTE ON FUNCTION execbound.dormancy_warnings_sent(timestamptz, timestamptz)",
        ):
            with admin_engine.begin() as conn:
                conn.execute(text(f"GRANT {grant} TO execbound_app"))
            try:
                with db.engine.connect() as conn, pytest.raises(DormantGrantsRefused):
                    check_runtime(conn)
            finally:
                with admin_engine.begin() as conn:
                    grant_dormant(conn, EMPTY_CLAIMS)
        # The row's own checks: a sleep moment after the anchor, a known state, a code-shaped
        # error, and one warning per administrator per approach.
        tenant, principal = secrets.token_hex(16), secrets.token_hex(16)
        with admin_engine.begin() as conn:
            conn.execute(
                text(
                    "INSERT INTO execbound.tenants(tenant_id, name) "
                    "VALUES (CAST(:t AS uuid), 'Warning checks')"
                ),
                {"t": tenant},
            )
            conn.execute(
                text(
                    "INSERT INTO execbound.principals(tenant_id, principal_id, kind) "
                    "VALUES (CAST(:t AS uuid), CAST(:p AS uuid), 'ADMIN')"
                ),
                {"t": tenant, "p": principal},
            )
        insert = (
            "INSERT INTO execbound.dormancy_warnings(tenant_id, warning_id, principal_id, "
            "silent_since, sleeps_at, created_at, next_attempt_at, state, last_error) VALUES "
            "(CAST(:t AS uuid), gen_random_uuid(), CAST(:p AS uuid), "
            "timestamptz '2026-07-01 00:00Z', {sleeps}, now(), now(), {state}, {error})"
        )
        good = {"sleeps": "timestamptz '2026-09-29 00:00Z'", "state": "'PENDING'", "error": "NULL"}
        for change in (
            {"sleeps": "timestamptz '2026-07-01 00:00Z'"},
            {"state": "'SENT'"},
            {"error": "'not a code'"},
        ):
            with pytest.raises(IntegrityError), admin_engine.begin() as conn:
                conn.execute(
                    text(insert.format(**{**good, **change})), {"t": tenant, "p": principal}
                )
        with admin_engine.begin() as conn:
            conn.execute(text(insert.format(**good)), {"t": tenant, "p": principal})
        with pytest.raises(IntegrityError), admin_engine.begin() as conn:
            conn.execute(text(insert.format(**good)), {"t": tenant, "p": principal})
        with admin_engine.begin() as conn:
            conn.execute(
                text("DELETE FROM execbound.dormancy_warnings WHERE tenant_id = :t"), {"t": tenant}
            )
            conn.execute(
                text("DELETE FROM execbound.principals WHERE tenant_id = :t"), {"t": tenant}
            )
            conn.execute(text("DELETE FROM execbound.tenants WHERE tenant_id = :t"), {"t": tenant})
        command.downgrade(config, BEFORE)
        with admin_engine.connect() as conn:
            assert present(conn) == set()
    finally:
        command.upgrade(config, "head")


def test_dw10_a_platform_role_holds_nothing(admin_engine, platform_role):
    role = platform_role
    with admin_engine.connect() as conn:
        warn = signature(conn, "dormancy_warn")
    with admin_engine.begin() as conn:
        conn.execute(text(f"GRANT SELECT ON execbound.dormancy_warnings TO {role}"))
        conn.execute(text(f"GRANT EXECUTE ON FUNCTION {warn} TO {role}"))
        grant_dormant(conn, EMPTY_CLAIMS)
        held = conn.execute(
            text(
                "SELECT has_table_privilege(:r, 'execbound.dormancy_warnings', "
                "'SELECT, INSERT, UPDATE, DELETE')"
            ),
            {"r": role},
        ).scalar_one()
        executes = [
            conn.execute(
                text("SELECT has_function_privilege(:r, :f, 'EXECUTE')"),
                {"r": role, "f": signature(conn, name)},
            ).scalar_one()
            for name in FUNCTIONS
        ]
        assert held is False
        assert executes == [False] * len(FUNCTIONS)
        check_dormant(conn, EMPTY_CLAIMS)
    with admin_engine.begin() as conn:
        conn.execute(text(f"GRANT EXECUTE ON FUNCTION {warn} TO {role}"))
        with pytest.raises(DormantGrantsRefused):
            check_dormant(conn, EMPTY_CLAIMS)
