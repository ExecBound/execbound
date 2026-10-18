# SPDX-License-Identifier: AGPL-3.0-only
"""Migrations as a managed PostgreSQL host runs them: an owner that does not bypass row
security.

Every other migration test runs as a test owner that, on the machines this suite runs on,
is a superuser with BYPASSRLS. Managed hosts often give the schema owner neither. Under
FORCE ROW LEVEL SECURITY that difference is invisible to schema changes and decisive for
data changes: an unfenced backfill run by an owner who does not bypass reads no tenant and
writes nothing, silently, so a migration that moves data creates nothing and can then fail
a constraint on the first row it should have filled.

This module builds a separate database owned by a role with such an owner's attributes
(no superuser, no BYPASSRLS), migrates it to the revision before a data-moving migration
as that role, seeds tenant rows the way the product does (inside a tenant fence), and then
runs the migration up and down as that same role.
"""

import base64
import hashlib
import hmac
import os
import secrets
from uuid import uuid4

import pytest
from alembic import command
from alembic.config import Config
from conftest import remember_secret
from sqlalchemy import create_engine, text
from sqlalchemy.engine import make_url
from sqlalchemy.pool import NullPool

from execbound.connection import connect_args

pytestmark = pytest.mark.integration

BEFORE = "0040_sign_in"
TARGET = "0041_spaces"
LOOPBACK = {"127.0.0.1", "localhost", "::1"}
# The tables 0041 lifts FORCE on and must put back.
RESTORED = (
    "tenants",
    "principals",
    "tenant_policy_control",
    "policy_bundle_contents",
    "executions",
    "audit_events",
    "human_sessions",
    "spaces",
    "space_members",
    "space_policy_selection",
)


def scram_verifier(password: str, iterations: int = 4096) -> str:
    """The SCRAM-SHA-256 verifier PostgreSQL stores for a password (RFC 5802, RFC 7677)."""
    salt = secrets.token_bytes(16)
    salted = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, iterations)
    client_key = hmac.new(salted, b"Client Key", hashlib.sha256).digest()
    server_key = hmac.new(salted, b"Server Key", hashlib.sha256).digest()
    stored_key = hashlib.sha256(client_key).digest()
    encode = base64.b64encode
    return (
        f"SCRAM-SHA-256${iterations}:{encode(salt).decode()}"
        f"${encode(stored_key).decode()}:{encode(server_key).decode()}"
    )


@pytest.fixture
def restricted(admin_engine):
    """A fresh database owned by a role with a managed host's owner attributes."""
    with admin_engine.connect() as conn:
        is_super = conn.execute(
            text("SELECT rolsuper FROM pg_roles WHERE rolname = current_user")
        ).scalar_one()
    if not is_super:
        pytest.skip(
            "the test owner does not bypass here, so every migration test runs as such an owner"
        )
    admin_url = make_url(os.environ["TEST_MIGRATION_DATABASE_URL"])
    assert admin_url.host in LOOPBACK, "a restricted database is only ever built on loopback"
    suffix = secrets.token_hex(4)
    role = f"eb_nobypass_{suffix}"
    database = f"{admin_url.database}_nobypass_{suffix}"
    password = remember_secret(secrets.token_urlsafe(24))
    autocommit = admin_engine.execution_options(isolation_level="AUTOCOMMIT")
    with autocommit.connect() as conn:
        # A utility statement takes no bind parameter, so the role is given a SCRAM verifier
        # rather than the password: the password never appears in any SQL text or error.
        # Straight to the driver: a verifier holds colons, which `text()` reads as parameters.
        conn.exec_driver_sql(
            f'CREATE ROLE "{role}" LOGIN NOSUPERUSER NOBYPASSRLS NOCREATEDB '
            f"NOCREATEROLE NOREPLICATION PASSWORD '{scram_verifier(password)}'"
        )
        conn.execute(text(f'CREATE DATABASE "{database}" OWNER "{role}"'))
    url = admin_url.set(username=role, password=password, database=database)
    engine = create_engine(
        url, poolclass=NullPool, hide_parameters=True, connect_args=connect_args(url)
    )
    config = Config("alembic.ini")
    config.attributes["database_url"] = url
    try:
        yield engine, config, role
    finally:
        engine.dispose()
        with autocommit.connect() as conn:
            conn.execute(text(f'DROP DATABASE IF EXISTS "{database}" WITH (FORCE)'))
            conn.execute(text(f'DROP ROLE IF EXISTS "{role}"'))


def fenced(conn, tenant):
    # Limits nothing on an `admin_engine` connection, whose owner bypasses row security
    # (see tenant_fence); on the `restricted` owner's, which has no bypass, it does.
    conn.execute(text("SELECT set_config('execbound.tenant_id', :t, true)"), {"t": str(tenant)})


def seed(engine):
    """One tenant as the product leaves it at 0040: every kind of principal, an active policy."""
    tenant, admin, agent, approver, bundle = (uuid4() for _ in range(5))
    digest = "a" * 64
    with engine.begin() as conn:
        fenced(conn, tenant)
        conn.execute(
            text("INSERT INTO execbound.tenants(tenant_id, name, active) VALUES (:t, :n, true)"),
            {"t": tenant, "n": f"tenant-{tenant.hex[:8]}"},
        )
        for principal, kind in ((admin, "ADMIN"), (agent, "AGENT"), (approver, "HUMAN_APPROVER")):
            conn.execute(
                text(
                    "INSERT INTO execbound.principals(tenant_id, principal_id, kind) "
                    "VALUES (:t, :p, :k)"
                ),
                {"t": tenant, "p": principal, "k": kind},
            )
        conn.execute(
            text(
                "INSERT INTO execbound.policy_bundle_contents"
                "(tenant_id, bundle_id, content_hash, content, created_at, created_by) "
                "VALUES (:t, :b, :h, CAST('{}' AS jsonb), now(), :a)"
            ),
            {"t": tenant, "b": bundle, "h": digest, "a": admin},
        )
        conn.execute(
            text(
                "INSERT INTO execbound.policy_bundle_lifecycle"
                "(tenant_id, bundle_id, content_hash, state, changed_at) "
                "VALUES (:t, :b, :h, 'ACTIVE', now())"
            ),
            {"t": tenant, "b": bundle, "h": digest},
        )
        conn.execute(
            text(
                "INSERT INTO execbound.tenant_policy_control"
                "(tenant_id, changed_at, active_bundle_id) "
                "VALUES (:t, now(), :b) ON CONFLICT (tenant_id) "
                "DO UPDATE SET active_bundle_id = excluded.active_bundle_id"
            ),
            {"t": tenant, "b": bundle},
        )
    return tenant, agent, approver, bundle


def test_0041_moves_every_tenant_into_its_default_space_without_bypass(restricted):
    engine, config, role = restricted
    command.upgrade(config, BEFORE)
    with engine.connect() as conn:
        owner = conn.execute(
            text("SELECT rolsuper, rolbypassrls FROM pg_roles WHERE rolname = current_user")
        ).one()
    assert tuple(owner) == (False, False), (
        "the database must be migrated as a managed host's owner is"
    )
    tenant, agent, approver, bundle = seed(engine)

    # Before the fix this raised CheckViolation on principals_space_kind_check: the backfill
    # saw no tenant, created no space and gave the AGENT principal none.
    command.upgrade(config, TARGET)

    with engine.begin() as conn:
        fenced(conn, tenant)
        spaces = conn.execute(text("SELECT space_id, name FROM execbound.spaces")).all()
        assert [name for _, name in spaces] == ["Default"]
        space = spaces[0][0]
        assert (
            conn.execute(
                text("SELECT space_id FROM execbound.principals WHERE principal_id = :p"),
                {"p": agent},
            ).scalar_one()
            == space
        )
        assert conn.execute(
            text("SELECT principal_id FROM execbound.space_members WHERE space_id = :s"),
            {"s": space},
        ).scalars().all() == [approver]
        assert (
            conn.execute(
                text("SELECT bundle_id FROM execbound.space_policy_selection WHERE space_id = :s"),
                {"s": space},
            ).scalar_one()
            == bundle
        )
        still_forced = dict(
            conn.execute(
                text(
                    "SELECT relname, relforcerowsecurity FROM pg_class "
                    "WHERE relnamespace = 'execbound'::regnamespace "
                    "AND relname = ANY(CAST(:names AS text[]))"
                ),
                {"names": list(RESTORED)},
            ).all()
        )
    assert still_forced == dict.fromkeys(RESTORED, True)


def test_0041_downgrade_sees_every_tenant_without_bypass(restricted):
    """The downgrade's refusal and its move back both have to see rows they are not fenced to."""
    engine, config, role = restricted
    command.upgrade(config, BEFORE)
    tenant, _, _, bundle = seed(engine)
    command.upgrade(config, TARGET)
    second = uuid4()
    with engine.begin() as conn:
        fenced(conn, tenant)
        conn.execute(
            text(
                "INSERT INTO execbound.spaces(tenant_id, space_id, name, created_at, created_by) "
                "VALUES (:t, :s, 'Second', now(), :t)"
            ),
            {"t": tenant, "s": second},
        )
    # Unfenced, an owner without bypass counted no space here and let the downgrade through.
    with pytest.raises(RuntimeError, match="more than one space"):
        command.downgrade(config, BEFORE)
    with engine.begin() as conn:
        fenced(conn, tenant)
        conn.execute(text("DELETE FROM execbound.spaces WHERE space_id = :s"), {"s": second})
    command.downgrade(config, BEFORE)
    with engine.begin() as conn:
        fenced(conn, tenant)
        assert (
            conn.execute(
                text("SELECT active_bundle_id FROM execbound.tenant_policy_control")
            ).scalar_one()
            == bundle
        )
        # What the downgrade lifted to see every tenant, it put back.
        assert conn.execute(
            text(
                "SELECT bool_and(relforcerowsecurity) FROM pg_class "
                "WHERE relnamespace = 'execbound'::regnamespace "
                "AND relname IN ('tenant_policy_control', 'policy_bundle_lifecycle')"
            )
        ).scalar_one()
