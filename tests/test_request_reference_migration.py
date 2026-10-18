# SPDX-License-Identifier: AGPL-3.0-only
"""Historical numbers backfill through the hosted owner's non-bypass RLS path."""

import os

from alembic import command
from alembic.config import Config
from sqlalchemy import text
from test_execution_database import execution_storage as execution_storage

from execbound.db import check_runtime


def test_backfill_numbers_each_tenant_and_restores_forced_rls(
    db, seeded, admin_engine, execution_storage
):
    config = Config("alembic.ini")
    config.attributes["database_url"] = os.environ["TEST_MIGRATION_DATABASE_URL"]
    try:
        command.downgrade(config, "0045_review_permissions")
        command.upgrade(config, "head")
        for tenant in seeded["tenants"]:
            with db.transaction(tenant) as conn:
                check_runtime(conn)
                assert conn.execute(
                    text("SELECT request_number FROM execbound.executions")
                ).scalars().all() == [1]
                assert (
                    conn.execute(
                        text(
                            "SELECT relforcerowsecurity FROM pg_class "
                            "WHERE oid='execbound.executions'::regclass"
                        )
                    ).scalar_one()
                    is True
                )
    finally:
        command.upgrade(config, "head")
