# SPDX-License-Identifier: AGPL-3.0-only
"""Migration 0084: the count of people who could decide a request when it was held (AR14).

Real PostgreSQL. The upgrade adds `approvals.reviewers_at_hold`, which the runtime may insert and
never update, and the `executions_created` index the coverage read's window uses. The downgrade
drops both.
"""

import pytest
from alembic import command
from sqlalchemy import text
from sqlalchemy.exc import ProgrammingError
from test_dormant_catalog import alembic_config, empty_schema

import execbound.db
from execbound.db import UnsafeDatabaseRole, check_runtime

pytestmark = pytest.mark.integration

BEFORE = "0083_invitation_reviewer_group"
TARGET = "0084_reviewers_at_hold"


def shape(conn):
    column = conn.execute(
        text(
            "SELECT data_type, is_nullable FROM information_schema.columns "
            "WHERE table_schema='execbound' AND table_name='approvals' "
            "AND column_name='reviewers_at_hold'"
        )
    ).one_or_none()
    index = conn.execute(
        text(
            "SELECT indexdef FROM pg_indexes WHERE schemaname='execbound' "
            "AND indexname='executions_created'"
        )
    ).scalar_one_or_none()
    return column, index


def test_ar14_the_runtime_inserts_the_hold_count_and_cannot_update_it(db):
    assert "reviewers_at_hold" not in execbound.db.UPDATE_COLUMNS["approvals"]
    with db.engine.begin() as conn:
        # Privileges are checked when the statement is planned, so neither needs a row.
        conn.execute(
            text("INSERT INTO execbound.approvals (reviewers_at_hold) SELECT 1 WHERE false")
        )
    with pytest.raises(ProgrammingError) as refused, db.engine.begin() as conn:
        conn.execute(text("UPDATE execbound.approvals SET reviewers_at_hold = 0 WHERE false"))
    assert type(refused.value.orig).__name__ == "InsufficientPrivilege"
    with db.engine.connect() as conn:
        check_runtime(conn)


def test_ar14_check_runtime_refuses_an_update_grant_on_the_count(db, admin_engine):
    with admin_engine.begin() as conn:
        conn.execute(
            text("GRANT UPDATE (reviewers_at_hold) ON execbound.approvals TO execbound_app")
        )
    try:
        with (
            pytest.raises(UnsafeDatabaseRole, match="column privileges"),
            db.engine.connect() as conn,
        ):
            check_runtime(conn)
    finally:
        with admin_engine.begin() as conn:
            conn.execute(
                text("REVOKE UPDATE (reviewers_at_hold) ON execbound.approvals FROM execbound_app")
            )
    with db.engine.connect() as conn:
        check_runtime(conn)


def test_ar14_the_index_exists_and_the_downgrade_drops_both(admin_engine):
    with admin_engine.connect() as conn:
        column, index = shape(conn)
        bounds = conn.execute(
            text(
                "SELECT pg_get_constraintdef(oid) FROM pg_constraint "
                "WHERE conrelid='execbound.approvals'::regclass "
                "AND conname='approvals_reviewers_at_hold_count'"
            )
        ).scalar_one()
    assert column == ("integer", "YES")
    assert index is not None and index.endswith("(tenant_id, created_at)")
    assert "reviewers_at_hold >= 0" in bounds
    empty_schema(admin_engine)
    config = alembic_config()
    command.downgrade(config, TARGET)
    try:
        command.downgrade(config, BEFORE)
        with admin_engine.connect() as conn:
            assert shape(conn) == (None, None)
        command.upgrade(config, TARGET)
        with admin_engine.connect() as conn:
            column, index = shape(conn)
        assert column == ("integer", "YES") and index is not None
    finally:
        empty_schema(admin_engine)
        command.upgrade(config, "head")
