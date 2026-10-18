# SPDX-License-Identifier: AGPL-3.0-only
"""Migration 0094: directory audit-log observations and the activity baseline (#355).

Real PostgreSQL. The upgrade admits an `entra_audit` observation: collected, naming an action, an
outcome and a target by object id, and nothing else a collected record may not carry. An Entra
connection gains `audit_baseline_at` and `audit_behind_since`, which the runtime may update and
not insert. The downgrade
refuses while an `entra_audit` observation is retained, under an owner that does not bypass row
security as under one that does, and otherwise restores the earlier checks.
"""

import hashlib
from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest
from alembic import command
from sqlalchemy import text
from sqlalchemy.exc import IntegrityError
from test_dormant_catalog import alembic_config, empty_schema
from test_max_agents_migration import fenced, workspace
from test_migration_without_bypass import restricted as restricted
from test_scout_delta_migration import entra

from execbound.db import INSERT_COLUMNS, UPDATE_COLUMNS

pytestmark = pytest.mark.integration

BEFORE = "0093_scout_delta"
TARGET = "0094_scout_audit"
DIRECTORY = "11111111-2222-3333-4444-555555555555"
ACTOR = "aaaaaaaa-0000-4000-8000-000000000009"
USER = "dddddddd-0000-4000-8000-000000000001"
FORCED = (
    "SELECT relname, relforcerowsecurity FROM pg_class "
    "WHERE relnamespace = 'execbound'::regnamespace "
    "AND relname IN ('monitor_connections', 'monitor_observations')"
)


def observation(conn, tenant, space, connection, **changes):
    """One collected observation of the directory's audit log; `changes` replaces a column."""
    event = f"audit:{uuid4()}"
    values = {
        "t": tenant,
        "o": uuid4(),
        "c": connection,
        "event": event,
        "digest": hashlib.sha256(event.encode()).hexdigest(),
        "when": datetime.now(UTC) - timedelta(minutes=5),
        "kind": "entra_audit",
        "action": "identity.disable",
        "outcome": "success",
        "target": USER,
        "operation": "entra-audit.v1:disable_account",
        "external": f"Directory_{uuid4()}_ABCDE_12345678",
        "actor": ACTOR,
        "s": space,
        **changes,
    }
    conn.execute(
        text(
            "INSERT INTO execbound.monitor_observations "
            "(tenant_id, observation_id, connection_id, event_id, version, content_hash, "
            " occurred_at, received_at, kind, action, outcome, target_ref, evaluation_state, "
            " operation_name, external_ref, evidence, actor_ref, rule_version, space_id) "
            "VALUES (:t, :o, :c, :event, 1, :digest, :when, now(), :kind, :action, :outcome, "
            " :target, 'PENDING', :operation, :external, 'collected', :actor, "
            " 'sensitive-action.v2', :s)"
        ),
        values,
    )
    return values["o"]


def test_sr21_an_audit_observation_is_admitted_with_its_target_and_nothing_less(admin_engine):
    empty_schema(admin_engine)
    config = alembic_config()
    command.downgrade(config, BEFORE)
    try:
        tenant, space, admin = workspace(admin_engine, "team")
        with admin_engine.begin() as conn:
            connection = entra(
                conn,
                tenant,
                space,
                admin,
                directory=DIRECTORY,
                synced=datetime.now(UTC) - timedelta(days=1),
            )
        # Before it, no collected record names a target, and no kind is the audit log's.
        with pytest.raises(IntegrityError), admin_engine.begin() as conn:
            observation(conn, tenant, space, connection)
        command.upgrade(config, TARGET)
        with admin_engine.begin() as conn:
            observation(conn, tenant, space, connection)
            # An entry id as Microsoft writes one, underscores and all, which the reference
            # check has admitted since 0023.
            observation(conn, tenant, space, connection, external="SSGM_b662f17a_MCDC4_88453290")
        for refused in (
            {"target": None},
            {"target": "not-an-object-id"},
            {"action": None},
            {"outcome": None},
        ):
            with pytest.raises(IntegrityError), admin_engine.begin() as conn:
                observation(conn, tenant, space, connection, **refused)
        # Another collected kind still names no target.
        with pytest.raises(IntegrityError), admin_engine.begin() as conn:
            observation(conn, tenant, space, connection, kind="ai_tool_run")
        # The activity baseline and the read's lag are an Entra connection's alone.
        with admin_engine.begin() as conn:
            conn.execute(
                text(
                    "UPDATE execbound.monitor_connections "
                    "SET audit_baseline_at = now(), audit_behind_since = now() "
                    "WHERE connection_id = :c"
                ),
                {"c": connection},
            )
            assert all(forced for _, forced in conn.execute(text(FORCED)).all())
        tines_tenant, tines_space, tines_admin = workspace(admin_engine, "team")
        tines = uuid4()
        with admin_engine.begin() as conn:
            conn.execute(
                text(
                    "INSERT INTO execbound.monitor_connections "
                    "(tenant_id, connection_id, label, base_url, key_fingerprint, created_at, "
                    " created_by, space_id) "
                    "VALUES (:t, :c, 'Tines', 'https://fixture.tines.com', :f, now(), :a, :s)"
                ),
                {"t": tines_tenant, "c": tines, "f": "cd" * 32, "a": tines_admin, "s": tines_space},
            )
        for column in ("audit_baseline_at", "audit_behind_since"):
            with pytest.raises(IntegrityError), admin_engine.begin() as conn:
                conn.execute(
                    text(
                        f"UPDATE execbound.monitor_connections SET {column} = now() "
                        "WHERE connection_id = :c"
                    ),
                    {"c": tines},
                )
        # A retained audit observation is evidence the earlier checks cannot hold.
        with pytest.raises(RuntimeError, match="SCOUT_AUDIT_OBSERVATIONS_RETAINED"):
            command.downgrade(alembic_config(), BEFORE)
        with admin_engine.connect() as conn:
            assert (
                conn.execute(text("SELECT version_num FROM execbound.alembic_version")).scalar_one()
                == TARGET
            )
            assert all(forced for _, forced in conn.execute(text(FORCED)).all())
        with admin_engine.begin() as conn:
            conn.execute(text("DELETE FROM execbound.monitor_observations"))
        command.downgrade(alembic_config(), BEFORE)
        with admin_engine.connect() as conn:
            columns = set(
                conn.execute(
                    text(
                        "SELECT column_name FROM information_schema.columns "
                        "WHERE table_schema = 'execbound' AND table_name = 'monitor_connections'"
                    )
                ).scalars()
            )
            assert not {"audit_baseline_at", "audit_behind_since"} & columns
            assert all(forced for _, forced in conn.execute(text(FORCED)).all())
        # The earlier checks are back.
        with pytest.raises(IntegrityError), admin_engine.begin() as conn:
            observation(conn, tenant, space, connection)
    finally:
        empty_schema(admin_engine)
        command.upgrade(config, "head")


@pytest.mark.parametrize("column", ["audit_baseline_at", "audit_behind_since"])
def test_sr21_the_runtime_updates_the_activity_baseline_and_inserts_it_never(admin_engine, column):
    assert column in UPDATE_COLUMNS["monitor_connections"]
    assert column not in INSERT_COLUMNS["monitor_connections"]
    with admin_engine.connect() as conn:

        def holds(privilege):
            return bool(
                conn.execute(
                    text(
                        "SELECT has_column_privilege('execbound_app', "
                        "'execbound.monitor_connections', :c, :p)"
                    ),
                    {"c": column, "p": privilege},
                ).scalar_one()
            )

        assert holds("UPDATE")
        assert not holds("INSERT")


def test_sr21_the_downgrade_sees_every_tenant_as_the_hosted_owner(restricted):
    engine, config, _ = restricted
    command.upgrade(config, BEFORE)
    tenant, space, admin = workspace(engine, "team")
    command.upgrade(config, TARGET)
    with engine.begin() as conn:
        fenced(conn, tenant)
        connection = entra(
            conn,
            tenant,
            space,
            admin,
            directory=DIRECTORY,
            synced=datetime.now(UTC) - timedelta(hours=1),
        )
        observation(conn, tenant, space, connection)
    # This owner sees no tenant unfenced, so the refusal proves the look lifted FORCE.
    with pytest.raises(RuntimeError, match="SCOUT_AUDIT_OBSERVATIONS_RETAINED"):
        command.downgrade(config, BEFORE)
    with engine.begin() as conn:
        fenced(conn, tenant)
        conn.execute(text("DELETE FROM execbound.monitor_observations"))
    command.downgrade(config, BEFORE)
    with engine.connect() as conn:
        assert all(forced for _, forced in conn.execute(text(FORCED)).all())
