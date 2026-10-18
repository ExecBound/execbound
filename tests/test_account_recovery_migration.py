# SPDX-License-Identifier: AGPL-3.0-only
"""Migration 0085: password reset by email is dormant until a plugin claims it (RP10).

Real PostgreSQL. Two tables under forced row level security and five definer functions, none
granted to anyone but the owner, so a database with no plugin can neither read a reset row nor
call a reset function, and `check_runtime` refuses one that grants any of them. The functions'
own behaviour is the hosted plugin's to test; this file reads only the catalog.
"""

import secrets

import pytest
from alembic import command
from sqlalchemy import text
from sqlalchemy.exc import IntegrityError
from test_dormant_catalog import (
    alembic_config,
    can_create_roles,
    empty_schema,
    revision_of,
)

from execbound.db import (
    EMPTY_CLAIMS,
    DormantGrantsRefused,
    check_dormant,
    check_runtime,
    grant_dormant,
)

pytestmark = pytest.mark.integration

BEFORE = "0084_reviewers_at_hold"
TARGET = "0085_account_recovery"
TABLES = ("account_recoveries", "account_messages")
FUNCTIONS = (
    "account_recovery_request",
    "account_recovery_rekey",
    "account_recovery_check",
    "account_password_recover",
    "account_recovery_lapse",
)


def signature(conn, name: str) -> str:
    """The function's regprocedure text: its name and argument types, as GRANT reads them."""
    return conn.execute(
        text(
            "SELECT CAST(CAST(p.oid AS regprocedure) AS text) FROM pg_proc p "
            "JOIN pg_namespace n ON n.oid = p.pronamespace "
            "WHERE n.nspname = 'execbound' AND p.proname = :f"
        ),
        {"f": name},
    ).scalar_one()


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
    """Every role other than the owner holding anything on the seven objects."""
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


def test_rp10_dormant_until_claimed(db, admin_engine):
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
                    "(SELECT array_agg(polname) FROM pg_policy WHERE polrelid = c.oid) "
                    "FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace "
                    "WHERE n.nspname = 'execbound' AND c.relname = ANY(:t)"
                ),
                {"t": list(TABLES)},
            ).all()
            assert sorted(tuple(row) for row in security) == [
                ("account_messages", True, True, ["tenant_isolation"]),
                ("account_recoveries", True, True, ["tenant_isolation"]),
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
        with admin_engine.begin() as conn:
            conn.execute(text("GRANT SELECT ON execbound.account_recoveries TO execbound_app"))
        try:
            with db.engine.connect() as conn, pytest.raises(DormantGrantsRefused):
                check_runtime(conn)
        finally:
            with admin_engine.begin() as conn:
                grant_dormant(conn, EMPTY_CLAIMS)
        # The row checks: a live link has its send and at most thirty minutes from it, and an
        # outcome that mails nothing holds no account.
        tenant, account = secrets.token_hex(16), secrets.token_hex(16)
        with admin_engine.begin() as conn:
            conn.execute(
                text(
                    "INSERT INTO execbound.tenants(tenant_id, name) "
                    "VALUES (CAST(:t AS uuid), 'Reset checks')"
                ),
                {"t": tenant},
            )
            conn.execute(
                text(
                    "INSERT INTO execbound.user_accounts(account_id, email, active, version, "
                    "created_at) VALUES (CAST(:a AS uuid), 'checks@example.test', true, 1, now())"
                ),
                {"a": account},
            )
        rows = (
            "(CAST(:t AS uuid), gen_random_uuid(), CAST(:a AS uuid), 'checks@example.test', 1, "
            "now(), 'SENT', '" + "a" * 64 + "', NULL, now() + interval '10 minutes')",
            "(CAST(:t AS uuid), gen_random_uuid(), CAST(:a AS uuid), 'checks@example.test', 1, "
            "now(), 'SENT', '" + "a" * 64 + "', now(), now() + interval '31 minutes')",
            "(CAST(:t AS uuid), gen_random_uuid(), CAST(:a AS uuid), NULL, NULL, now(), "
            "'NO_ACCOUNT', NULL, NULL, NULL)",
        )
        for row in rows:
            with pytest.raises(IntegrityError), admin_engine.begin() as conn:
                conn.execute(text("SET LOCAL row_security = off"))
                conn.execute(
                    text(
                        "INSERT INTO execbound.account_recoveries(tenant_id, recovery_id, "
                        "account_id, email, account_version, requested_at, state, token_hash, "
                        f"sent_at, expires_at) VALUES {row}"
                    ),
                    {"t": tenant, "a": account},
                )
        with pytest.raises(IntegrityError), admin_engine.begin() as conn:
            conn.execute(
                text(
                    "INSERT INTO execbound.account_recoveries(tenant_id, recovery_id, "
                    "account_id, requested_at, state, refusal_code) VALUES "
                    "(CAST(:t AS uuid), gen_random_uuid(), CAST(:a AS uuid), now(), 'REFUSED', "
                    "'HONEYPOT')"
                ),
                {"t": tenant, "a": account},
            )
        with admin_engine.begin() as conn:
            conn.execute(
                text("DELETE FROM execbound.user_accounts WHERE account_id = :a"), {"a": account}
            )
            conn.execute(text("DELETE FROM execbound.tenants WHERE tenant_id = :t"), {"t": tenant})
        command.downgrade(config, BEFORE)
        with admin_engine.connect() as conn:
            assert present(conn) == set()
    finally:
        command.upgrade(config, "head")


@pytest.fixture
def platform_role(admin_engine, monkeypatch):
    """A stand-in for Supabase's platform roles, which no local or CI database has."""
    if not can_create_roles(admin_engine):
        pytest.skip("the test owner cannot create a role here")
    role = f"eb_platform_{secrets.token_hex(4)}"
    monkeypatch.setattr("execbound.db._PLATFORM_ROLES", (role,))
    with admin_engine.begin() as conn:
        conn.execute(text(f"CREATE ROLE {role} NOLOGIN"))
    try:
        yield role
    finally:
        with admin_engine.begin() as conn:
            grant_dormant(conn, EMPTY_CLAIMS)
            conn.execute(text(f"DROP OWNED BY {role}"))
            conn.execute(text(f"DROP ROLE {role}"))


def test_rp10_a_platform_role_holds_nothing(admin_engine, platform_role):
    role = platform_role
    with admin_engine.connect() as conn:
        recover = signature(conn, "account_password_recover")
    with admin_engine.begin() as conn:
        conn.execute(text(f"GRANT SELECT ON execbound.account_recoveries TO {role}"))
        conn.execute(text(f"GRANT EXECUTE ON FUNCTION {recover} TO {role}"))
        grant_dormant(conn, EMPTY_CLAIMS)
        held = conn.execute(
            text(
                "SELECT bool_or(has_table_privilege(:r, 'execbound.' || t, "
                "'SELECT, INSERT, UPDATE, DELETE')) FROM unnest(CAST(:t AS text[])) t"
            ),
            {"r": role, "t": list(TABLES)},
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
    # A grant to the platform role on one of them, after `grant_dormant`, is refused.
    with admin_engine.begin() as conn:
        conn.execute(text(f"GRANT EXECUTE ON FUNCTION {recover} TO {role}"))
        with pytest.raises(DormantGrantsRefused):
            check_dormant(conn, EMPTY_CLAIMS)
