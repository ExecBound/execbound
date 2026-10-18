# SPDX-License-Identifier: AGPL-3.0-only
"""Migration 0096: approval emails' opt-in and outbox are dormant until a plugin claims them
(hosted: AM11).

Real PostgreSQL. Two tables under forced row level security, fenced to their tenant, and six
definer functions, none granted to anyone but the owner, so a database with no plugin can
neither read a subscription or a message nor change, queue, list, count or end one, and
`check_runtime` refuses one that grants any of them. The functions' behaviour is the plugin's to
test; this file reads the catalog and the subscription's own checks.
"""

import secrets
from uuid import uuid4

import pytest
from alembic import command
from sqlalchemy import text
from sqlalchemy.exc import IntegrityError
from test_account_recovery_migration import platform_role as platform_role
from test_account_recovery_migration import signature
from test_dormant_catalog import alembic_config, empty_schema, revision_of
from test_migration_without_bypass import fenced
from test_migration_without_bypass import restricted as restricted

from execbound.db import (
    EMPTY_CLAIMS,
    DormantGrantsRefused,
    check_dormant,
    check_runtime,
    grant_dormant,
)

pytestmark = pytest.mark.integration

BEFORE = "0095_scout_audit_retention"
TARGET = "0096_approval_email"
TABLES = ("approval_email_subscriptions", "approval_emails")
FUNCTIONS = (
    "approval_email_change",
    "approval_email_queue",
    "approval_email_tenants",
    "approval_email_due",
    "approval_email_sent",
    "approval_email_unsubscribe",
)
# What a message row holds: no address, no name, nothing a person or an agent typed.
MESSAGE_COLUMNS = {
    "tenant_id",
    "email_id",
    "approval_id",
    "principal_id",
    "decide_by",
    "created_at",
    "state",
    "attempts",
    "next_attempt_at",
    "lease_until",
    "lease_token",
    "delivered_at",
    "last_error",
    "unsubscribe_hash",
}


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
    """Every role other than the owner holding anything on the eight objects."""
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


def test_am11_dormant_until_claimed(db, admin_engine):
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
                    "WHERE n.nspname = 'execbound' AND c.relname = ANY(:t) ORDER BY c.relname"
                ),
                {"t": list(TABLES)},
            ).all()
            assert [tuple(row) for row in security] == [
                ("approval_email_subscriptions", True, True, ["owner_drain", "tenant_isolation"]),
                ("approval_emails", True, True, ["owner_drain", "tenant_isolation"]),
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
                secure and setting == ["search_path=pg_catalog, pg_temp"]
                for _, secure, setting in definers
            )
            # Born dormant: nobody but the owner holds anything, PUBLIC included.
            assert grantees(conn) == set()
            columns = set(
                conn.execute(
                    text(
                        "SELECT column_name FROM information_schema.columns "
                        "WHERE table_schema = 'execbound' AND table_name = 'approval_emails'"
                    )
                ).scalars()
            )
            assert columns == MESSAGE_COLUMNS
        # The runtime check expects the head's catalog, which later revisions extend.
        command.upgrade(config, "head")
        with db.engine.connect() as conn:
            check_runtime(conn)
        for grant in (
            "SELECT ON execbound.approval_email_subscriptions",
            "SELECT ON execbound.approval_emails",
        ):
            with admin_engine.begin() as conn:
                conn.execute(text(f"GRANT {grant} TO execbound_app"))
            try:
                with db.engine.connect() as conn, pytest.raises(DormantGrantsRefused):
                    check_runtime(conn)
            finally:
                with admin_engine.begin() as conn:
                    grant_dormant(conn, EMPTY_CLAIMS)
        # The subscription's own checks: a known way of ending, and an end time exactly when it
        # has a way of ending.
        tenant, principal = secrets.token_hex(16), secrets.token_hex(16)
        with admin_engine.begin() as conn:
            conn.execute(
                text(
                    "INSERT INTO execbound.tenants(tenant_id, name) "
                    "VALUES (CAST(:t AS uuid), 'Approval email checks')"
                ),
                {"t": tenant},
            )
            conn.execute(
                text(
                    "INSERT INTO execbound.principals(tenant_id, principal_id, kind) "
                    "VALUES (CAST(:t AS uuid), CAST(:p AS uuid), 'HUMAN_APPROVER')"
                ),
                {"t": tenant, "p": principal},
            )
        insert = (
            "INSERT INTO execbound.approval_email_subscriptions(tenant_id, principal_id, "
            "subscribed_at, ended_at, ended_via) VALUES (CAST(:t AS uuid), CAST(:p AS uuid), "
            "now(), {ended}, {via})"
        )
        for bad in (
            {"ended": "now()", "via": "'EMAIL'"},
            {"ended": "now()", "via": "NULL"},
            {"ended": "NULL", "via": "'LINK'"},
        ):
            with pytest.raises(IntegrityError), admin_engine.begin() as conn:
                conn.execute(text(insert.format(**bad)), {"t": tenant, "p": principal})
        with admin_engine.begin() as conn:
            conn.execute(
                text(insert.format(ended="NULL", via="NULL")), {"t": tenant, "p": principal}
            )
        # A retained subscription refuses the downgrade, and nothing is dropped.
        with pytest.raises(RuntimeError, match="lossy downgrade refused"):
            command.downgrade(config, BEFORE)
        with admin_engine.connect() as conn:
            assert present(conn) == set(TABLES) | set(FUNCTIONS)
        with admin_engine.begin() as conn:
            for table in ("approval_email_subscriptions", "principals", "tenants"):
                conn.execute(
                    text(f"DELETE FROM execbound.{table} WHERE tenant_id = CAST(:t AS uuid)"),  # nosec B608
                    {"t": tenant},
                )
        command.downgrade(config, BEFORE)
        with admin_engine.connect() as conn:
            assert present(conn) == set()
    finally:
        command.upgrade(config, "head")


def test_am11_the_downgrade_refuses_a_retained_subscription_without_bypass(restricted):
    """The dormant test above proves the refusal only as the local superuser, which bypasses row
    security outright. The hosted owner does not; prove the refusal with that owner's own
    privileges, a live subscription written inside its workspace's fence."""
    engine, config, _ = restricted
    command.upgrade(config, "head")
    tenant, principal = uuid4(), uuid4()
    with engine.begin() as conn:
        fenced(conn, tenant)
        conn.execute(
            text(
                "INSERT INTO execbound.tenants(tenant_id, name) "
                "VALUES (:t, 'Retained approval email')"
            ),
            {"t": tenant},
        )
        conn.execute(
            text(
                "INSERT INTO execbound.principals(tenant_id, principal_id, kind) "
                "VALUES (:t, :p, 'HUMAN_APPROVER')"
            ),
            {"t": tenant, "p": principal},
        )
        conn.execute(
            text(
                "INSERT INTO execbound.approval_email_subscriptions"
                "(tenant_id, principal_id, subscribed_at) VALUES (:t, :p, now())"
            ),
            {"t": tenant, "p": principal},
        )
    head = revision_of(engine)
    with pytest.raises(RuntimeError, match="lossy downgrade refused"):
        command.downgrade(config, BEFORE)
    # Refused before anything was dropped: still at the head.
    assert revision_of(engine) == head


def test_am11_a_platform_role_holds_nothing(admin_engine, platform_role):
    role = platform_role
    with admin_engine.begin() as conn:
        for table in TABLES:
            conn.execute(text(f"GRANT SELECT ON execbound.{table} TO {role}"))
        queue = signature(conn, "approval_email_queue")
        conn.execute(text(f"GRANT EXECUTE ON FUNCTION {queue} TO {role}"))
        grant_dormant(conn, EMPTY_CLAIMS)
        for table in TABLES:
            held = conn.execute(
                text("SELECT has_table_privilege(:r, :t, 'SELECT, INSERT, UPDATE, DELETE')"),
                {"r": role, "t": f"execbound.{table}"},
            ).scalar_one()
            assert held is False, table
        executes = conn.execute(
            text("SELECT has_function_privilege(:r, :f, 'EXECUTE')"), {"r": role, "f": queue}
        ).scalar_one()
        assert executes is False
        check_dormant(conn, EMPTY_CLAIMS)
    with admin_engine.begin() as conn:
        conn.execute(text(f"GRANT SELECT ON execbound.approval_emails TO {role}"))
        with pytest.raises(DormantGrantsRefused):
            check_dormant(conn, EMPTY_CLAIMS)
