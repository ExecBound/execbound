# SPDX-License-Identifier: AGPL-3.0-only
"""Migration 0093: the delta link, the baseline, the episode markers and the four rules (#355).

Real PostgreSQL. The upgrade baselines every Entra connection that has synchronized and holds
a classic service principal, so has read the service principals, at the moment of the upgrade,
whatever its latest collection's outcome, so nothing it collected before becomes news. It leaves
any other to take its baseline at its first collection that reads both principal collections.
The checks hold the link to the pinned read and the rules to their subjects. The downgrade
refuses while a finding of the four rules is retained and otherwise restores the earlier checks;
it runs again under an owner that does not bypass row security, as the hosted owner does not.
"""

import json
from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest
from alembic import command
from sqlalchemy import text
from sqlalchemy.exc import IntegrityError
from test_dormant_catalog import alembic_config, empty_schema
from test_max_agents_migration import fenced, workspace
from test_migration_without_bypass import restricted as restricted

from execbound.db import UPDATE_COLUMNS

pytestmark = pytest.mark.integration

BEFORE = "0092_dormancy_warning"
TARGET = "0093_scout_delta"
DIRECTORY = "11111111-2222-3333-4444-555555555555"
OTHER_DIRECTORY = "22222222-3333-4444-5555-666666666666"
CLIENT = "66666666-7777-8888-9999-aaaaaaaaaaaa"
LINK = "https://graph.microsoft.com/v1.0/servicePrincipals/delta?%24deltatoken=token1"
NEW_RULES = (
    "new-actor.v1",
    "first-consequential-action.v1",
    "new-ai-consent.v1",
    "initial-inventory.v1",
)
FORCED = (
    "SELECT relname, relforcerowsecurity FROM pg_class "
    "WHERE relnamespace = 'execbound'::regnamespace "
    "AND relname IN ('monitor_connections', 'monitor_agents', 'monitor_findings')"
)


def entra(conn, tenant, space, admin, *, directory, synced, outcome="COMPLETE", **states):
    """An Entra connection as the release before this one left it. A synchronized one's latest
    collection ended with `outcome` and its probe found each principal collection available
    unless `states` says otherwise, as `agent_identities="unknown"` does."""
    connection = uuid4()
    probed = {"state": "available", "at": synced.isoformat()} if synced else None
    capabilities = (
        {
            name: {**probed, "state": states.get(name, "available")}
            for name in ("agent_identities", "service_principals")
        }
        if probed
        else {}
    )
    conn.execute(
        text(
            "INSERT INTO execbound.monitor_connections "
            "(tenant_id, connection_id, label, base_url, key_fingerprint, created_at, created_by, "
            " kind, directory_ref, client_ref, space_id, last_sync_at, last_run_at, last_outcome, "
            " capabilities) "
            "VALUES (:t, :c, 'Directory', 'https://graph.microsoft.com', :f, now(), :a, "
            " 'entra_agent_id', :d, :cl, :s, :synced, :ran, :outcome, CAST(:caps AS jsonb))"
        ),
        {
            "t": tenant,
            "c": connection,
            "f": "ab" * 32,
            "a": admin,
            "d": directory,
            "cl": CLIENT,
            "s": space,
            "synced": synced,
            "ran": synced,
            "outcome": outcome if synced else None,
            "caps": json.dumps(capabilities),
        },
    )
    return connection


def holds(conn, tenant, connection, identity_class="service_principal", *, gone=False):
    """A principal an earlier release's collection stored for `connection`; one `gone` was not
    listed by the collection after, as one that could not read its collection leaves it."""
    conn.execute(
        text(
            "INSERT INTO execbound.monitor_agents "
            "(tenant_id, agent_id, connection_id, platform_ref, identity_class, display_name, "
            " sponsors, sponsor_state, first_seen_at, observed_at, gone_at) "
            "VALUES (:t, :a, :c, :ref, :class, 'Synthetic', '[]'::jsonb, 'not_read', "
            " now() - interval '9 days', now() - interval '1 day', "
            " CASE WHEN :gone THEN now() - interval '1 hour' END)"
        ),
        {
            "t": tenant,
            "a": uuid4(),
            "c": connection,
            "ref": str(uuid4()),
            "class": identity_class,
            "gone": gone,
        },
    )


def baselines(conn):
    return dict(
        conn.execute(
            text("SELECT connection_id, baseline_at FROM execbound.monitor_connections")
        ).all()
    )


def test_sr15_the_upgrade_baselines_what_already_synchronized(admin_engine):
    empty_schema(admin_engine)
    config = alembic_config()
    command.downgrade(config, BEFORE)
    try:
        tenant, space, admin = workspace(admin_engine, "team")
        # One active Entra connection per space, so the second lives in another workspace.
        elsewhere = workspace(admin_engine, "team")
        then = datetime.now(UTC) - timedelta(days=3)
        # Each synchronized and holds the service principals it read, whatever its latest
        # collection could read or however it ended: the store is what that read left.
        read = {
            "complete": ({}, False),
            "failed": ({"outcome": "RATE_LIMITED"}, False),
            "interrupted": ({"outcome": "INTERRUPTED"}, False),
            "errored": ({"outcome": "ERROR"}, False),
            "auth lost": ({"outcome": "AUTH_LOST", "agent_identities": "forbidden"}, False),
            # A collection that could not read them marked them gone; they are still held.
            "throttled": ({"service_principals": "unknown"}, True),
            "refused since": ({"service_principals": "forbidden"}, True),
            "agents throttled": ({"agent_identities": "unknown"}, False),
            "agents unsupported": ({"agent_identities": "unsupported"}, False),
        }
        # Each synchronized without ever reading the service principals, so holds no classic
        # principal: what it has not read would be stored for the first time later.
        unread = {
            "refused": ({"service_principals": "forbidden"}, "agent_identity"),
            "throttled throughout": ({"service_principals": "unknown"}, "agent_identity"),
            "empty": ({}, None),
        }
        spaces = {name: workspace(admin_engine, "team") for name in (*read, *unread)}
        with admin_engine.begin() as conn:
            never = entra(conn, *elsewhere, directory=OTHER_DIRECTORY, synced=None)
            baselined = {}
            for name, (values, gone) in read.items():
                connection = entra(
                    conn, *spaces[name], directory=str(uuid4()), synced=then, **values
                )
                holds(conn, spaces[name][0], connection, gone=gone)
                holds(conn, spaces[name][0], connection, "agent_identity")
                baselined[name] = connection
            waiting = {}
            for name, (values, held) in unread.items():
                connection = entra(
                    conn, *spaces[name], directory=str(uuid4()), synced=then, **values
                )
                if held is not None:
                    holds(conn, spaces[name][0], connection, held)
                waiting[name] = connection
            synced = entra(conn, tenant, space, admin, directory=DIRECTORY, synced=then)
            holds(conn, tenant, synced)
        before = datetime.now(UTC)
        command.upgrade(config, TARGET)
        with admin_engine.begin() as conn:
            found = baselines(conn)
            # Already synchronized: baselined at the upgrade, so nothing it collected before is
            # news, and a principal that appears after it is.
            assert {
                name: found[connection] is not None and found[connection] >= before
                for name, connection in {**baselined, "synced": synced}.items()
            } == dict.fromkeys([*read, "synced"], True)
            # Never synchronized: its baseline is its own first complete collection.
            assert found[never] is None
            # A principal the store never held was there all along: each waits for its first
            # collection that reads both, rather than calling every such principal new.
            assert {
                name: found[connection] for name, connection in waiting.items()
            } == dict.fromkeys(unread)
            assert all(forced for _, forced in conn.execute(text(FORCED)).all())
        # A link needs a baseline, and stays on the pinned read.
        with pytest.raises(IntegrityError), admin_engine.begin() as conn:
            conn.execute(
                text(
                    "UPDATE execbound.monitor_connections SET delta_link = :l "
                    "WHERE connection_id = :c"
                ),
                {"l": LINK, "c": never},
            )
        with admin_engine.begin() as conn:
            conn.execute(
                text(
                    "UPDATE execbound.monitor_connections SET delta_link = :l, delta_at = now() "
                    "WHERE connection_id = :c"
                ),
                {"l": LINK, "c": synced},
            )
        with pytest.raises(IntegrityError), admin_engine.begin() as conn:
            conn.execute(
                text(
                    "UPDATE execbound.monitor_connections SET delta_link = :l "
                    "WHERE connection_id = :c"
                ),
                {"l": LINK + "x" * 4096, "c": synced},
            )
        # A catalog key, never an identifier the collector matched on.
        with pytest.raises(IntegrityError), admin_engine.begin() as conn:
            conn.execute(
                text(
                    "INSERT INTO execbound.monitor_agents "
                    "(tenant_id, agent_id, connection_id, platform_ref, identity_class, "
                    " display_name, sponsors, sponsor_state, first_seen_at, observed_at, "
                    " ai_publisher) "
                    "VALUES (:t, :a, :c, :ref, 'service_principal', 'Synthetic', '[]'::jsonb, "
                    " 'not_read', now(), now(), :publisher)"
                ),
                {
                    "t": tenant,
                    "a": uuid4(),
                    "c": synced,
                    "ref": "aaaaaaaa-0000-4000-8000-000000000001",
                    "publisher": "07c030f6-5743-41b7-ba00-0a6e85f37c17",
                },
            )
        # The inventory names a connection and nothing else; the agent rules name an agent.
        with pytest.raises(IntegrityError), admin_engine.begin() as conn:
            conn.execute(
                text(
                    "INSERT INTO execbound.monitor_findings "
                    "(tenant_id, finding_id, connection_id, rule_version, title, created_at, "
                    " space_id) VALUES (:t, :f, :c, 'new-actor.v1', 'No agent', now(), :s)"
                ),
                {"t": tenant, "f": uuid4(), "c": synced, "s": space},
            )
        with admin_engine.begin() as conn:
            conn.execute(
                text(
                    "INSERT INTO execbound.monitor_findings "
                    "(tenant_id, finding_id, connection_id, rule_version, title, created_at, "
                    " space_id) VALUES (:t, :f, :c, 'initial-inventory.v1', 'Inventory', now(), :s)"
                ),
                {"t": tenant, "f": uuid4(), "c": synced, "s": space},
            )
        # A retained finding of the four rules is evidence the earlier checks cannot hold.
        with pytest.raises(RuntimeError, match="SCOUT_DELTA_FINDINGS_RETAINED"):
            command.downgrade(alembic_config(), BEFORE)
        with admin_engine.connect() as conn:
            assert (
                conn.execute(text("SELECT version_num FROM execbound.alembic_version")).scalar_one()
                == TARGET
            )
            assert all(forced for _, forced in conn.execute(text(FORCED)).all())
        with admin_engine.begin() as conn:
            conn.execute(text("DELETE FROM execbound.monitor_deliveries"))
            conn.execute(text("DELETE FROM execbound.monitor_findings"))
        command.downgrade(alembic_config(), BEFORE)
        with admin_engine.connect() as conn:
            columns = set(
                conn.execute(
                    text(
                        "SELECT column_name FROM information_schema.columns "
                        "WHERE table_schema = 'execbound' "
                        "AND table_name IN ('monitor_connections', 'monitor_agents')"
                    )
                ).scalars()
            )
            assert not columns & {
                "delta_link",
                "delta_at",
                "baseline_at",
                "collecting_delta",
                "ai_publisher",
                "new_actor_opened_at",
                "first_action_opened_at",
                "ai_consent_opened_at",
            }
            assert all(forced for _, forced in conn.execute(text(FORCED)).all())
            # The delta claim is gone, and the lease functions are 0086's again.
            functions = dict(
                conn.execute(
                    text(
                        "SELECT proname, prosrc FROM pg_proc "
                        "WHERE pronamespace = 'execbound'::regnamespace AND proname IN "
                        "('collector_claim', 'collector_claim_delta', 'collector_release', "
                        "'monitor_connections_revoked_unleased')"
                    )
                ).all()
            )
            assert set(functions) == {
                "collector_claim",
                "collector_release",
                "monitor_connections_revoked_unleased",
            }
            assert not any("collecting_delta" in body for body in functions.values())
    finally:
        empty_schema(admin_engine)
        command.upgrade(config, "head")


def retained_new_agent(conn, tenant, space, connection):
    """A principal and the `new-agent.v1` finding an earlier release raised for it."""
    agent, finding = uuid4(), uuid4()
    conn.execute(
        text(
            "INSERT INTO execbound.monitor_agents "
            "(tenant_id, agent_id, connection_id, platform_ref, identity_class, display_name, "
            " sponsors, sponsor_state, first_seen_at, observed_at) "
            "VALUES (:t, :a, :c, :ref, 'agent_identity', 'Synthetic agent', '[]'::jsonb, "
            " 'not_read', now(), now())"
        ),
        {"t": tenant, "a": agent, "c": connection, "ref": str(uuid4())},
    )
    conn.execute(
        text(
            "INSERT INTO execbound.monitor_findings "
            "(tenant_id, finding_id, connection_id, agent_id, rule_version, title, created_at, "
            " space_id) VALUES (:t, :f, :c, :a, 'new-agent.v1', 'New agent identity', now(), :s)"
        ),
        {"t": tenant, "f": finding, "c": connection, "a": agent, "s": space},
    )
    return finding


def test_sr16_a_retained_new_agent_finding_survives_the_upgrade_and_the_downgrade(admin_engine):
    """`new-agent.v1` is raised no more, and every finding it raised stays: the upgrade admits a
    database holding them, and the downgrade keeps them as well."""
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
                synced=datetime.now(UTC) - timedelta(days=3),
            )
            before = retained_new_agent(conn, tenant, space, connection)
        command.upgrade(config, TARGET)
        with admin_engine.begin() as conn:
            # Still admitted at this revision, under an agent, with no observation.
            after = retained_new_agent(conn, tenant, space, connection)
        command.downgrade(alembic_config(), BEFORE)
        with admin_engine.connect() as conn:
            kept = set(
                conn.execute(
                    text(
                        "SELECT finding_id FROM execbound.monitor_findings "
                        "WHERE rule_version = 'new-agent.v1' AND agent_id IS NOT NULL"
                    )
                ).scalars()
            )
        assert kept == {before, after}
    finally:
        empty_schema(admin_engine)
        command.upgrade(config, "head")


def test_sr15_the_runtime_holds_exactly_these_privileges_on_the_new_columns(admin_engine):
    """The runtime updates the seven new columns and writes no part of the delta lease mark,
    which only the claim functions set. It inserts none of the connection columns, so a
    connection is never created holding a link or a baseline. It may insert the four agent
    columns, because 0030 granted INSERT on `monitor_agents` whole. A collection inserts
    `ai_publisher` with the principal and none of the episode markers; withholding INSERT on a
    marker would bound nothing, since the runtime may update it, and the SR16 and SR20 tests
    each raise their rule for a principal a collection or a delta pass has just inserted."""
    connection_columns = {"delta_link", "delta_at", "baseline_at"}
    agent_columns = {
        "ai_publisher",
        "new_actor_opened_at",
        "first_action_opened_at",
        "ai_consent_opened_at",
    }
    assert connection_columns <= UPDATE_COLUMNS["monitor_connections"]
    assert "collecting_delta" not in UPDATE_COLUMNS["monitor_connections"]
    assert agent_columns <= UPDATE_COLUMNS["monitor_agents"]
    with admin_engine.connect() as conn:

        def holds(table, column, privilege):
            return bool(
                conn.execute(
                    text("SELECT has_column_privilege('execbound_app', :t, :c, :p)"),
                    {"t": f"execbound.{table}", "c": column, "p": privilege},
                ).scalar_one()
            )

        for column in connection_columns:
            assert holds("monitor_connections", column, "UPDATE"), column
            assert not holds("monitor_connections", column, "INSERT"), column
        for privilege in ("INSERT", "UPDATE"):
            assert not holds("monitor_connections", "collecting_delta", privilege), privilege
        for column in agent_columns:
            assert holds("monitor_agents", column, "UPDATE"), column
            assert holds("monitor_agents", column, "INSERT"), column


def test_sr15_the_backfill_and_the_downgrade_see_every_tenant_as_the_hosted_owner(restricted):
    engine, config, _ = restricted
    command.upgrade(config, BEFORE)
    tenant, space, admin = workspace(engine, "team")
    with engine.begin() as conn:
        fenced(conn, tenant)
        # Synchronized, its latest collection throttled: what the store holds decides, and this
        # owner sees it only with row security lifted on the principals as well.
        connection = entra(
            conn,
            tenant,
            space,
            admin,
            directory=DIRECTORY,
            synced=datetime.now(UTC) - timedelta(hours=1),
            outcome="RATE_LIMITED",
        )
        holds(conn, tenant, connection)
    command.upgrade(config, TARGET)
    with engine.begin() as conn:
        fenced(conn, tenant)
        assert baselines(conn)[connection] is not None
        assert all(forced for _, forced in conn.execute(text(FORCED)).all())
        conn.execute(
            text(
                "INSERT INTO execbound.monitor_findings "
                "(tenant_id, finding_id, connection_id, rule_version, title, created_at, "
                " space_id) VALUES (:t, :f, :c, 'initial-inventory.v1', 'Inventory', now(), :s)"
            ),
            {"t": tenant, "f": uuid4(), "c": connection, "s": space},
        )
    # This owner sees no tenant unfenced, so the refusal proves the look lifted FORCE.
    with pytest.raises(RuntimeError, match="SCOUT_DELTA_FINDINGS_RETAINED"):
        command.downgrade(config, BEFORE)
    with engine.begin() as conn:
        fenced(conn, tenant)
        conn.execute(text("DELETE FROM execbound.monitor_deliveries"))
        conn.execute(text("DELETE FROM execbound.monitor_findings"))
    command.downgrade(config, BEFORE)
    with engine.connect() as conn:
        assert all(forced for _, forced in conn.execute(text(FORCED)).all())
