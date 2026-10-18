# SPDX-License-Identifier: AGPL-3.0-only
"""Migration 0097: a destination for each monitoring delivery (#31, FD15).

Real PostgreSQL. Before it a finding holds one delivery row; after it that intent keeps its id
and state, a delivery per finding and destination is admitted once, `ROUTED` is an intent's
alone, and forced row security still holds. The downgrade refuses while a delivery or a routed
intent is retained, under an owner that does not bypass row security as under one that does,
and otherwise restores 0008's key and states.
"""

from uuid import uuid4, uuid5

import pytest
from alembic import command
from sqlalchemy import text
from sqlalchemy.exc import IntegrityError
from test_dormant_catalog import alembic_config, empty_schema
from test_max_agents_migration import fenced, workspace
from test_migration_without_bypass import restricted as restricted

pytestmark = pytest.mark.integration

BEFORE = "0096_approval_email"
TARGET = "0097_findings_destinations"
FORCED = (
    "SELECT relforcerowsecurity FROM pg_class "
    "WHERE relnamespace = 'execbound'::regnamespace AND relname = 'monitor_deliveries'"
)
INSERT = text(
    "INSERT INTO execbound.monitor_deliveries "
    "(tenant_id, delivery_id, finding_id, destination_id, state, created_at, next_attempt_at) "
    "VALUES (:t, :d, :f, :dest, :state, now(), now())"
)
VERSION = "SELECT version_num FROM execbound.alembic_version"


def shape(conn) -> tuple[list[str], list[tuple[str, str]], list[str]]:
    """The table as the catalog reads it: every index's definition, every constraint's name
    and definition, and the columns in their order. The downgrade must leave exactly 0096's."""
    indexes = conn.execute(
        text(
            "SELECT pg_get_indexdef(indexrelid) FROM pg_index "
            "WHERE indrelid = 'execbound.monitor_deliveries'::regclass"
        )
    ).scalars()
    constraints = conn.execute(
        text(
            "SELECT conname, pg_get_constraintdef(oid) FROM pg_constraint "
            "WHERE conrelid = 'execbound.monitor_deliveries'::regclass"
        )
    ).all()
    columns = conn.execute(
        text(
            "SELECT column_name FROM information_schema.columns "
            "WHERE table_schema = 'execbound' AND table_name = 'monitor_deliveries' "
            "ORDER BY ordinal_position"
        )
    ).scalars()
    return (
        sorted(indexes),
        sorted((name, definition) for name, definition in constraints),
        list(columns),
    )


def finding(conn, tenant, space, admin):
    """A collection-health finding on a fresh Tines connection, with its intent, written the
    way every release before this one writes them."""
    connection, found = uuid4(), uuid4()
    conn.execute(
        text(
            "INSERT INTO execbound.monitor_connections "
            "(tenant_id, connection_id, label, base_url, key_fingerprint, created_at, "
            " created_by, space_id) "
            "VALUES (:t, :c, 'Tines', 'https://fixture.tines.com', :f, now(), :a, :s)"
        ),
        {"t": tenant, "c": connection, "f": "cd" * 32, "a": admin, "s": space},
    )
    conn.execute(
        text(
            "INSERT INTO execbound.monitor_findings "
            "(tenant_id, finding_id, connection_id, rule_version, title, created_at, space_id) "
            "VALUES (:t, :f, :c, 'collection-health.v1', 'Collection', now(), :s)"
        ),
        {"t": tenant, "f": found, "c": connection, "s": space},
    )
    conn.execute(
        text(
            "INSERT INTO execbound.monitor_deliveries "
            "(tenant_id, delivery_id, finding_id, created_at, next_attempt_at) "
            "VALUES (:t, :d, :f, now(), now())"
        ),
        {"t": tenant, "d": uuid5(found, "delivery"), "f": found},
    )
    return found


def delivery(conn, tenant, found, destination, state="PENDING", delivery_id=None):
    conn.execute(
        INSERT,
        {
            "t": tenant,
            "d": delivery_id or uuid5(found, (destination or "delivery") + "#finding"),
            "f": found,
            "dest": destination,
            "state": state,
        },
    )


def test_fd15_the_intent_keeps_its_row_and_a_delivery_per_destination_is_admitted_once(
    admin_engine,
):
    empty_schema(admin_engine)
    config = alembic_config()
    command.downgrade(config, BEFORE)
    try:
        tenant, space, admin = workspace(admin_engine, "team")
        with admin_engine.begin() as conn:
            found = finding(conn, tenant, space, admin)
        command.upgrade(config, TARGET)
        with admin_engine.begin() as conn:
            intent = conn.execute(
                text(
                    "SELECT delivery_id, destination_id, state FROM execbound.monitor_deliveries "
                    "WHERE tenant_id = :t"
                ),
                {"t": tenant},
            ).one()
            assert tuple(intent) == (uuid5(found, "delivery"), None, "PENDING")
            delivery(conn, tenant, found, "soc")
            delivery(conn, tenant, found, "oncall")
            conn.execute(
                text(
                    "UPDATE execbound.monitor_deliveries SET state = 'ROUTED' "
                    "WHERE tenant_id = :t AND destination_id IS NULL"
                ),
                {"t": tenant},
            )
            assert conn.execute(text(FORCED)).scalar_one() is True
        for refused in (
            {"destination": None, "delivery_id": uuid4()},
            {"destination": "soc", "delivery_id": uuid4()},
            {"destination": "pager", "state": "ROUTED"},
            {"destination": "not an id#", "delivery_id": uuid4()},
        ):
            with pytest.raises(IntegrityError), admin_engine.begin() as conn:
                delivery(conn, tenant, found, **refused)
        with pytest.raises(IntegrityError), admin_engine.begin() as conn:
            conn.execute(
                text(
                    "UPDATE execbound.monitor_deliveries SET state = 'ARCHIVED' "
                    "WHERE tenant_id = :t"
                ),
                {"t": tenant},
            )
        # Retained, so the downgrade refuses and leaves the revision where it is.
        with pytest.raises(RuntimeError, match="FINDINGS_DELIVERIES_RETAINED"):
            command.downgrade(config, BEFORE)
        with admin_engine.connect() as conn:
            assert conn.execute(text(VERSION)).scalar_one() == TARGET
            assert conn.execute(text(FORCED)).scalar_one() is True
        with admin_engine.begin() as conn:
            conn.execute(
                text(
                    "DELETE FROM execbound.monitor_deliveries "
                    "WHERE tenant_id = :t AND destination_id IS NOT NULL"
                ),
                {"t": tenant},
            )
        # A routed intent alone is retained history too.
        with pytest.raises(RuntimeError, match="FINDINGS_DELIVERIES_RETAINED"):
            command.downgrade(config, BEFORE)
        with admin_engine.begin() as conn:
            conn.execute(
                text(
                    "UPDATE execbound.monitor_deliveries SET state = 'PENDING' WHERE tenant_id = :t"
                ),
                {"t": tenant},
            )
        command.downgrade(config, BEFORE)
        with admin_engine.begin() as conn:
            # 0008's key is back: a second intent for the finding is refused.
            with pytest.raises(IntegrityError), conn.begin_nested():
                conn.execute(
                    text(
                        "INSERT INTO execbound.monitor_deliveries "
                        "(tenant_id, delivery_id, finding_id, created_at, next_attempt_at) "
                        "VALUES (:t, :d, :f, now(), now())"
                    ),
                    {"t": tenant, "d": uuid4(), "f": found},
                )
            assert conn.execute(text(FORCED)).scalar_one() is True
    finally:
        empty_schema(admin_engine)
        command.upgrade(config, "head")


def test_fd15_the_downgrade_sees_every_tenant_as_the_hosted_owner(restricted):
    """This database is built from nothing to 0096, so the shape read there is 0096's own and
    not a downgrade's, and the downgrade must leave exactly that: every index, constraint and
    column, the state check among them."""
    engine, config, _ = restricted
    command.upgrade(config, BEFORE)
    with engine.connect() as conn:
        before = shape(conn)
    tenant, space, admin = workspace(engine, "team")
    with engine.begin() as conn:
        fenced(conn, tenant)
        found = finding(conn, tenant, space, admin)
    command.upgrade(config, TARGET)
    with engine.begin() as conn:
        fenced(conn, tenant)
        delivery(conn, tenant, found, "soc")
    # This owner sees no tenant unfenced, so the refusal proves the look lifted FORCE.
    with pytest.raises(RuntimeError, match="FINDINGS_DELIVERIES_RETAINED"):
        command.downgrade(config, BEFORE)
    with engine.begin() as conn:
        fenced(conn, tenant)
        conn.execute(text("DELETE FROM execbound.monitor_deliveries WHERE destination_id = 'soc'"))
    command.downgrade(config, BEFORE)
    with engine.connect() as conn:
        assert conn.execute(text(FORCED)).scalar_one() is True
        assert shape(conn) == before
