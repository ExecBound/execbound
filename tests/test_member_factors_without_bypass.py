# SPDX-License-Identifier: AGPL-3.0-only
"""`admin_member_factors` as a managed PostgreSQL host runs it: an owner without bypass.

A `SECURITY DEFINER` function runs with its owner's row security. On the machines this suite
usually runs on the owner is a superuser, so a definer function that forgot to set
`execbound.account_id` before reading the account-scoped `user_factors` would still see every
row and the ordinary tests would pass. On a managed host the owner bypasses nothing, and the
same function would read no factor and call everyone unenrolled. This module migrates a
separate database as such an owner, seeds it inside the fences the product sets, and calls
the function as the runtime role.
"""

import os
from uuid import uuid4

import pytest
from alembic import command
from sqlalchemy import create_engine, text
from sqlalchemy.engine import make_url
from sqlalchemy.pool import NullPool
from test_migration_without_bypass import fenced
from test_migration_without_bypass import restricted as restricted

from execbound.connection import connect_args

pytestmark = pytest.mark.integration


def seed(engine):
    tenant, space, admin, person, account = (uuid4() for _ in range(5))
    with engine.begin() as conn:
        fenced(conn, tenant)
        conn.execute(
            text("SELECT set_config('execbound.account_id', :a, true)"), {"a": str(account)}
        )
        conn.execute(
            text("INSERT INTO execbound.tenants(tenant_id, name, active) VALUES (:t, :n, true)"),
            {"t": tenant, "n": f"tenant-{tenant.hex[:8]}"},
        )
        conn.execute(
            text(
                "INSERT INTO execbound.spaces(tenant_id, space_id, name, created_at, created_by) "
                "VALUES (:t, :s, 'Default', now(), :t)"
            ),
            {"t": tenant, "s": space},
        )
        for principal, kind in ((admin, "ADMIN"), (person, "HUMAN_APPROVER")):
            conn.execute(
                text(
                    "INSERT INTO execbound.principals(tenant_id, principal_id, kind) "
                    "VALUES (:t, :p, :k)"
                ),
                {"t": tenant, "p": principal, "k": kind},
            )
        conn.execute(
            text("INSERT INTO execbound.user_accounts(account_id, email) VALUES (:a, :e)"),
            {"a": account, "e": f"{account.hex}@example.test"},
        )
        conn.execute(
            text(
                "INSERT INTO execbound.workspace_memberships(account_id, tenant_id, principal_id) "
                "VALUES (:a, :t, :p)"
            ),
            {"a": account, "t": tenant, "p": person},
        )
        conn.execute(
            text(
                "INSERT INTO execbound.user_factors"
                "(account_id, tenant_id, principal_id, sealed, key_id, enabled_at) "
                "VALUES (:a, :t, :p, 'sealed', 'key', now())"
            ),
            {"a": account, "t": tenant, "p": person},
        )
    return tenant, admin, person


def test_ak9_member_factors_reads_account_factors_without_bypass(restricted):
    engine, config, _ = restricted
    command.upgrade(config, "head")
    with engine.connect() as conn:
        owner = conn.execute(
            text("SELECT rolsuper, rolbypassrls FROM pg_roles WHERE rolname = current_user")
        ).one()
    assert tuple(owner) == (False, False)
    tenant, admin, person = seed(engine)

    runtime_url = make_url(os.environ["TEST_DATABASE_URL"]).set(database=engine.url.database)
    runtime = create_engine(
        runtime_url,
        poolclass=NullPool,
        hide_parameters=True,
        connect_args=connect_args(runtime_url),
    )
    try:
        with runtime.begin() as conn:
            assert conn.execute(text("SELECT current_user")).scalar_one() == "execbound_app"
            fenced(conn, tenant)
            rows = conn.execute(
                text(
                    "SELECT principal_id, enrolled FROM "
                    "execbound.admin_member_factors(:a, CAST(:ids AS uuid[]))"
                ),
                {"a": admin, "ids": [str(person)]},
            ).all()
    finally:
        runtime.dispose()
    assert [tuple(row) for row in rows] == [(person, True)]
