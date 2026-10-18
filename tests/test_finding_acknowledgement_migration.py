# SPDX-License-Identifier: AGPL-3.0-only
"""Migration 0081: a monitoring finding's acknowledgement takes a note and becomes final (MQ15).

Real PostgreSQL. The upgrade adds a bounded `acknowledgement_note`, the runtime's update grant
on it, a partial index for the open queue and a trigger that refuses any change to a finished
acknowledgement. The downgrade refuses while a note is kept and otherwise restores the previous
schema, keeping the `acknowledged_at, acknowledged_by` grant.
"""

from uuid import uuid4

import pytest
from alembic import command
from sqlalchemy import text
from test_dormant_catalog import alembic_config, empty_schema

import execbound.db
from execbound.db import check_runtime

pytestmark = pytest.mark.integration

BEFORE = "0080_notification_kinds"
TARGET = "0081_finding_acknowledgement"
FUNCTION = "monitor_findings_acknowledged_once"


def shape(conn):
    """What the migration adds, as the catalog holds it."""
    column = conn.execute(
        text(
            "SELECT data_type, is_nullable FROM information_schema.columns "
            "WHERE table_schema='execbound' AND table_name='monitor_findings' "
            "AND column_name='acknowledgement_note'"
        )
    ).one_or_none()
    granted = set(
        conn.execute(
            text(
                "SELECT column_name FROM information_schema.column_privileges "
                "WHERE table_schema='execbound' AND table_name='monitor_findings' "
                "AND grantee='execbound_app' AND privilege_type='UPDATE'"
            )
        ).scalars()
    )
    index = conn.execute(
        text(
            "SELECT indexdef FROM pg_indexes WHERE schemaname='execbound' "
            "AND indexname='monitor_findings_open'"
        )
    ).scalar_one_or_none()
    trigger = conn.execute(
        text(
            "SELECT count(*) FROM pg_trigger WHERE tgname=:n "
            "AND tgrelid='execbound.monitor_findings'::regclass"
        ),
        {"n": FUNCTION},
    ).scalar_one()
    function = conn.execute(
        text(
            "SELECT CAST(p.proacl AS text) AS acl, p.proconfig, p.prosecdef FROM pg_proc p "
            "JOIN pg_namespace n ON n.oid=p.pronamespace "
            "WHERE n.nspname='execbound' AND p.proname=:n"
        ),
        {"n": FUNCTION},
    ).one_or_none()
    return column, granted, index, trigger, function


def seed_finding(engine, note):
    """One acknowledged finding with `note`, in a tenant made for this test alone."""
    tenant, space, admin, connection = uuid4(), uuid4(), uuid4(), uuid4()
    finding = uuid4()
    with engine.begin() as conn:
        conn.execute(text("SELECT set_config('execbound.tenant_id', :t, true)"), {"t": str(tenant)})
        conn.execute(
            text("INSERT INTO execbound.tenants(tenant_id, name) VALUES (:t, :n)"),
            {"t": tenant, "n": f"Migration {tenant}"},
        )
        conn.execute(
            text(
                "INSERT INTO execbound.spaces(tenant_id, space_id, name, created_at, created_by) "
                "VALUES (:t, :s, 'Default', now(), :p)"
            ),
            {"t": tenant, "s": space, "p": admin},
        )
        conn.execute(
            text(
                "INSERT INTO execbound.principals(tenant_id, principal_id, kind) "
                "VALUES (:t, :p, 'ADMIN')"
            ),
            {"t": tenant, "p": admin},
        )
        conn.execute(
            text(
                "INSERT INTO execbound.monitor_connections(tenant_id, connection_id, label, "
                "base_url, key_fingerprint, created_at, created_by, space_id) "
                "VALUES (:t, :c, 'Tines', 'https://synthetic.tines.com', :k, now(), :p, :s)"
            ),
            {"t": tenant, "c": connection, "k": "0" * 64, "p": admin, "s": space},
        )
        conn.execute(
            text(
                "INSERT INTO execbound.monitor_findings(tenant_id, finding_id, connection_id, "
                "rule_version, title, created_at, acknowledged_at, acknowledged_by, "
                "acknowledgement_note, space_id) VALUES (:t, :f, :c, 'collection-health.v1', "
                "'Collection stopped', now(), now(), :p, :note, :s)"
            ),
            {"t": tenant, "f": finding, "c": connection, "p": admin, "note": note, "s": space},
        )
    return tenant, finding


def test_mq15_upgrade_adds_a_bounded_note_its_grant_an_index_and_a_trigger(admin_engine):
    with admin_engine.connect() as conn:
        column, granted, index, trigger, function = shape(conn)
        bounds = set(
            conn.execute(
                text(
                    "SELECT pg_get_constraintdef(oid) FROM pg_constraint "
                    "WHERE conrelid='execbound.monitor_findings'::regclass "
                    "AND conname IN ('monitor_findings_note_length', "
                    "'monitor_findings_note_acknowledged')"
                )
            ).scalars()
        )
    assert column == ("text", "YES")
    assert granted == {"acknowledged_at", "acknowledged_by", "acknowledgement_note"}
    assert index is not None and index.endswith("WHERE (acknowledged_at IS NULL)")
    assert "(tenant_id, created_at DESC)" in index
    assert trigger == 1
    assert function is not None
    acl, config, definer = function
    # Callable by no one but its owner (no PUBLIC entry, no runtime entry), never with the
    # owner's rights, and with a fixed search path.
    assert acl is not None
    assert [entry.split("=")[0] for entry in acl.strip("{}").split(",")] == ["execbound_owner"]
    assert config == ["search_path=pg_catalog, pg_temp"]
    assert definer is False
    assert len(bounds) == 2
    assert any("length(acknowledgement_note) >= 1" in bound for bound in bounds)
    assert any("acknowledged_at IS NOT NULL" in bound for bound in bounds)


def test_mq15_downgrade_refuses_while_a_note_is_kept_and_otherwise_restores(admin_engine):
    empty_schema(admin_engine)
    config = alembic_config()
    command.downgrade(config, TARGET)
    try:
        tenant, finding = seed_finding(admin_engine, "Checked with the SOC lead.")
        with pytest.raises(RuntimeError, match="acknowledgement notes are retained"):
            command.downgrade(config, BEFORE)
        with admin_engine.connect() as conn:
            assert shape(conn)[0] is not None
        with admin_engine.begin() as conn:
            # The trigger keeps a finished acknowledgement's note from being cleared, so the
            # retained note leaves with its finding.
            conn.execute(
                text("DELETE FROM execbound.monitor_findings WHERE tenant_id=:t AND finding_id=:f"),
                {"t": tenant, "f": finding},
            )
        command.downgrade(config, BEFORE)
        with admin_engine.connect() as conn:
            column, granted, index, trigger, function = shape(conn)
            forced = conn.execute(
                text(
                    "SELECT relforcerowsecurity FROM pg_class "
                    "WHERE oid='execbound.monitor_findings'::regclass"
                )
            ).scalar_one()
        assert (column, index, trigger, function) == (None, None, 0, None)
        assert granted == {"acknowledged_at", "acknowledged_by"}
        assert forced is True
    finally:
        empty_schema(admin_engine)
        command.upgrade(config, "head")


def test_mq15_check_runtime_expects_the_new_grant(db):
    assert execbound.db.UPDATE_COLUMNS["monitor_findings"] == {
        "acknowledged_at",
        "acknowledged_by",
        "acknowledgement_note",
    }
    with db.engine.connect() as conn:
        check_runtime(conn)
