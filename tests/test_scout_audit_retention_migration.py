# SPDX-License-Identifier: AGPL-3.0-only
"""Migration 0095: the retention of directory audit observations and the bound's episode (#355).

Real PostgreSQL. The upgrade adds the one definer function the runtime removes an observation
through, executable by the runtime and by no one else; a partial index over a directory's audit
observations by actor and action; and `audit_bound_since`, an Entra connection's alone, which
the runtime may update and not insert. The downgrade removes all three; what the purge removed
is gone, so nothing refuses. Under an owner that does not bypass row security, as the hosted
owner does not, the function still removes what the caller's own fence admits and nothing else.
"""

from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest
from alembic import command
from sqlalchemy import text
from sqlalchemy.exc import DBAPIError, IntegrityError
from test_dormant_catalog import alembic_config, empty_schema
from test_max_agents_migration import fenced, workspace
from test_migration_without_bypass import restricted as restricted
from test_scout_audit_migration import observation
from test_scout_delta_migration import entra

from execbound.db import FUNCTIONS, INSERT_COLUMNS, UPDATE_COLUMNS

pytestmark = pytest.mark.integration

BEFORE = "0094_scout_audit"
TARGET = "0095_scout_audit_retention"
DIRECTORY = "11111111-2222-3333-4444-555555555555"
SIGNATURE = "execbound.monitor_audit_purge(uuid, uuid[])"
SCHEMA = """
    SELECT
        to_regprocedure(:signature) IS NOT NULL AS function,
        to_regclass('execbound.monitor_observations_entra_actor') IS NOT NULL AS index,
        EXISTS (SELECT 1 FROM information_schema.columns
                WHERE table_schema = 'execbound' AND table_name = 'monitor_connections'
                  AND column_name = 'audit_bound_since') AS column
"""
FORCED = (
    "SELECT count(*) FROM pg_class WHERE relnamespace = 'execbound'::regnamespace "
    "AND relkind = 'r' AND relforcerowsecurity"
)


def present(engine):
    with engine.connect() as conn:
        return tuple(conn.execute(text(SCHEMA), {"signature": SIGNATURE}).one())


def old(conn, tenant, space, connection, *, days=60, **changes):
    """An evaluated audit observation, two months old by the database's clock unless `days`
    says otherwise; `changes` replaces a column, as `observation`'s do."""
    made = observation(
        conn,
        tenant,
        space,
        connection,
        when=datetime.now(UTC) - timedelta(days=days),
        **changes,
    )
    conn.execute(
        text(
            "UPDATE execbound.monitor_observations SET evaluation_state = 'COMPLETED', "
            "evaluation_result = 'NO_MATCH', evaluated_at = now() WHERE observation_id = :o"
        ),
        {"o": made},
    )
    return made


def test_sr24_the_upgrade_adds_the_function_the_index_and_the_column_and_the_downgrade_removes_them(
    admin_engine,
):
    empty_schema(admin_engine)
    config = alembic_config()
    command.downgrade(config, BEFORE)
    try:
        assert present(admin_engine) == (False, False, False)
        with admin_engine.connect() as conn:
            forced = conn.execute(text(FORCED)).scalar_one()
        command.upgrade(config, TARGET)
        assert present(admin_engine) == (True, True, True)
        with admin_engine.connect() as conn:
            # No table and no policy: the forced count is the one before.
            assert conn.execute(text(FORCED)).scalar_one() == forced
            definition = conn.execute(
                text(
                    "SELECT indexdef FROM pg_indexes WHERE schemaname = 'execbound' "
                    "AND indexname = 'monitor_observations_entra_actor'"
                )
            ).scalar_one()
        assert "(tenant_id, connection_id, actor_ref, action, occurred_at)" in definition
        assert "WHERE (kind = 'entra_audit'::text)" in definition
        tenant, space, admin = workspace(admin_engine, "team")
        with admin_engine.begin() as conn:
            connection = entra(
                conn, tenant, space, admin, directory=DIRECTORY, synced=datetime.now(UTC)
            )
            conn.execute(
                text(
                    "UPDATE execbound.monitor_connections SET audit_bound_since = now() "
                    "WHERE connection_id = :c"
                ),
                {"c": connection},
            )
            removed = old(conn, tenant, space, connection)
        # The bound's episode is an Entra connection's alone.
        tines = uuid4()
        with admin_engine.begin() as conn:
            conn.execute(
                text(
                    "INSERT INTO execbound.monitor_connections "
                    "(tenant_id, connection_id, label, base_url, key_fingerprint, created_at, "
                    " created_by, space_id) "
                    "VALUES (:t, :c, 'Tines', 'https://fixture.tines.com', :f, now(), :a, :s)"
                ),
                {"t": tenant, "c": tines, "f": "cd" * 32, "a": admin, "s": space},
            )
        with pytest.raises(IntegrityError), admin_engine.begin() as conn:
            conn.execute(
                text(
                    "UPDATE execbound.monitor_connections SET audit_bound_since = now() "
                    "WHERE connection_id = :c"
                ),
                {"c": tines},
            )
        with admin_engine.begin() as conn:
            fenced(conn, tenant)
            assert (
                conn.execute(
                    text("SELECT execbound.monitor_audit_purge(:c, ARRAY[CAST(:o AS uuid)])"),
                    {"c": connection, "o": str(removed)},
                ).scalar_one()
                == 1
            )
        # Nothing the purge removed can be restored, so nothing refuses.
        command.downgrade(config, BEFORE)
        assert present(admin_engine) == (False, False, False)
        command.upgrade(config, TARGET)
        assert present(admin_engine) == (True, True, True)
    finally:
        empty_schema(admin_engine)
        command.upgrade(config, "head")


def test_sr24_the_function_runs_as_its_owner_on_a_fixed_path_for_the_runtime_alone(admin_engine):
    assert ("monitor_audit_purge", "p_connection uuid, p_observations uuid[]") in FUNCTIONS
    with admin_engine.connect() as conn:
        row = (
            conn.execute(
                text(
                    "SELECT p.prosecdef, p.proconfig, r.rolname AS owner, "
                    "has_function_privilege('execbound_app', p.oid, 'EXECUTE') AS runtime, "
                    "EXISTS (SELECT 1 FROM aclexplode(p.proacl) a WHERE a.grantee = 0) "
                    "  AS public, "
                    "(SELECT array_agg(a.grantee::regrole::text ORDER BY 1) "
                    "   FROM aclexplode(p.proacl) a WHERE a.grantee <> p.proowner) AS grantees "
                    "FROM pg_proc p JOIN pg_roles r ON r.oid = p.proowner "
                    "WHERE p.oid = to_regprocedure(:signature)"
                ),
                {"signature": SIGNATURE},
            )
            .mappings()
            .one()
        )
    assert row["prosecdef"] is True
    assert row["proconfig"] == ["search_path=pg_catalog, pg_temp"]
    assert row["owner"] != "execbound_app"
    assert (row["runtime"], row["public"]) == (True, False)
    assert row["grantees"] == ["execbound_app"]


def test_sr24_the_runtime_updates_the_bound_episode_and_inserts_it_never(admin_engine):
    assert "audit_bound_since" in UPDATE_COLUMNS["monitor_connections"]
    assert "audit_bound_since" not in INSERT_COLUMNS["monitor_connections"]
    with admin_engine.connect() as conn:
        held = {
            privilege: conn.execute(
                text(
                    "SELECT has_column_privilege('execbound_app', "
                    "'execbound.monitor_connections', 'audit_bound_since', :p)"
                ),
                {"p": privilege},
            ).scalar_one()
            for privilege in ("UPDATE", "INSERT")
        }
    assert held == {"UPDATE": True, "INSERT": False}


def test_sr24_the_function_admits_and_refuses_alike_under_an_owner_without_bypass(
    restricted,
):
    """The hosted owner does not bypass row security, and the function runs as its owner. Under
    such an owner it removes, of what it is handed, only the caller's evaluated, uncited directory
    audit observation a month old, and leaves a current one, an unevaluated one, a cited one, one
    of another kind and another workspace's; and it refuses as it does anywhere else: another
    workspace's connection and a Tines connection (`INVALID_STATE`), no list and one too long
    (`INVALID_LIMIT`), and no workspace or one that is not active (`INVALID_TENANT`). Another
    workspace's observation stays by the function's own fence on the workspace and the
    connection, which row security repeats under this owner; this test cannot tell the two
    apart."""
    engine, config, _ = restricted
    command.upgrade(config, TARGET)
    made = {}
    for name, directory in (("one", DIRECTORY), ("two", "22222222-3333-4444-5555-666666666666")):
        tenant, space, admin = workspace(engine, "team")
        with engine.begin() as conn:
            fenced(conn, tenant)
            connection = entra(
                conn, tenant, space, admin, directory=directory, synced=datetime.now(UTC)
            )
            made[name] = (tenant, space, admin, connection, old(conn, tenant, space, connection))
    tenant, space, admin, connection, mine = made["one"]
    _, _, _, elsewhere, theirs = made["two"]
    tines = uuid4()
    with engine.begin() as conn:
        fenced(conn, tenant)
        current = old(conn, tenant, space, connection, days=29)
        waiting = observation(
            conn, tenant, space, connection, when=datetime.now(UTC) - timedelta(days=60)
        )
        cited = old(conn, tenant, space, connection)
        conn.execute(
            text(
                "INSERT INTO execbound.monitor_findings "
                "(tenant_id, finding_id, connection_id, observation_id, rule_version, title, "
                " created_at, space_id) "
                "VALUES (:t, :f, :c, :o, 'clock-skew.v1', 'Cited', now(), :s)"
            ),
            {"t": tenant, "f": uuid4(), "c": connection, "o": cited, "s": space},
        )
        other_kind = old(conn, tenant, space, connection, kind="ai_tool_run", target=None)
        conn.execute(
            text(
                "INSERT INTO execbound.monitor_connections "
                "(tenant_id, connection_id, label, base_url, key_fingerprint, created_at, "
                " created_by, space_id) "
                "VALUES (:t, :c, 'Tines', 'https://fixture.tines.com', :f, now(), :a, :s)"
            ),
            {"t": tenant, "c": tines, "f": "cd" * 32, "a": admin, "s": space},
        )

    def call(fence, connection_id, ids):
        with engine.begin() as conn:
            if fence is not None:
                fenced(conn, fence)
            return conn.execute(
                text("SELECT execbound.monitor_audit_purge(:c, CAST(:o AS uuid[]))"),
                {"c": connection_id, "o": None if ids is None else [str(i) for i in ids]},
            ).scalar_one()

    def remaining(fence):
        with engine.begin() as conn:
            fenced(conn, fence)
            return set(
                conn.execute(
                    text("SELECT observation_id FROM execbound.monitor_observations")
                ).scalars()
            )

    listed = [mine, theirs, current, waiting, cited, other_kind, uuid4()]
    assert call(tenant, connection, listed) == 1
    assert remaining(tenant) == {current, waiting, cited, other_kind}
    assert remaining(made["two"][0]) == {theirs}
    for fence, connection_id, ids, code in (
        (tenant, elsewhere, [theirs], "INVALID_STATE"),
        (tenant, tines, [current], "INVALID_STATE"),
        (tenant, connection, None, "INVALID_LIMIT"),
        (tenant, connection, [uuid4() for _ in range(1001)], "INVALID_LIMIT"),
        (None, connection, [current], "INVALID_TENANT"),
    ):
        with pytest.raises(DBAPIError, match=code):
            call(fence, connection_id, ids)
    with engine.begin() as conn:
        fenced(conn, tenant)
        conn.execute(
            text("UPDATE execbound.tenants SET active = false WHERE tenant_id = :t"), {"t": tenant}
        )
    with pytest.raises(DBAPIError, match="INVALID_TENANT"):
        call(tenant, connection, [current])
    assert remaining(tenant) == {current, waiting, cited, other_kind}
    assert remaining(made["two"][0]) == {theirs}
