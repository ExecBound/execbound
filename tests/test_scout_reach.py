# SPDX-License-Identifier: AGPL-3.0-only
"""Reach per agent, action and path: what each path can claim, and what it cannot.

SR4's rows, SR5's row half, and the freshness half of SR11.
"""

import hashlib
import json
from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest
from sqlalchemy import text
from test_monitoring_store import FixedClock
from test_monitoring_store import admins as admins
from test_scout_run import (
    AUTH_ADMIN,
    BLUEPRINT_APP,
    MICROSOFT_GRAPH,
    client,
    connect,
    detailed_scenario,
)

from execbound.monitoring import graph, reach
from execbound_harness.fake_graph import SECRET, serving

pytestmark = pytest.mark.integration

AGENT_ONE = "aaaaaaaa-0000-4000-8000-000000000001"


class Grant:
    def __init__(self, grant_kind, resource_ref, value, path_ref):
        self.grant_kind = grant_kind
        self.resource_ref = resource_ref
        self.value = value
        self.path_ref = path_ref


@pytest.fixture
def clock():
    return FixedClock(datetime.now(UTC))


def bundle(admin_engine, tenant, principal, mappings):
    """Insert an active bundle and its operation mappings to exercise the governed query.

    The rows go in through the owner connection rather than the policy lifecycle: what is
    under test is which mappings count as a governed path, not how a bundle is activated.
    """
    bundle_id = uuid4()
    content = {"mappings": mappings}
    digest = hashlib.sha256(json.dumps(content, sort_keys=True).encode()).hexdigest()
    account_id = uuid4()
    with admin_engine.begin() as conn:
        conn.execute(
            text(
                "INSERT INTO execbound.connector_accounts "
                "(tenant_id, account_id, provider, active, "
                "space_id) VALUES (:t, :a, 'mock_entra', true, "
                "(SELECT space_id FROM execbound.spaces WHERE tenant_id = :t))"
            ),
            {"t": tenant, "a": account_id},
        )
        for mapping in mappings:
            conn.execute(
                text("""
                INSERT INTO execbound.operation_mappings
                (tenant_id, operation_ref, account_id, provider, resource_type, action,
                 provider_operation, mapping_version, schema_version,
                 context_contract_version, active)
                VALUES (:t, :ref, :a, 'mock_entra', 'identity', :action, :operation,
                        'v1', 'action.v1', 'identity-control.v1', true)
            """),
                {
                    "t": tenant,
                    "ref": mapping["operation_ref"],
                    "a": account_id,
                    "action": mapping["action"],
                    "operation": mapping["action"].split(".")[1],
                },
            )
        conn.execute(
            text(
                "INSERT INTO execbound.policy_bundle_contents "
                "(tenant_id, bundle_id, content_hash, content, created_at, created_by, space_id) "
                "VALUES (:t, :b, :h, CAST(:c AS jsonb), now(), :p, "
                "(SELECT space_id FROM execbound.spaces WHERE tenant_id = :t))"
            ),
            {"t": tenant, "b": bundle_id, "h": digest, "c": json.dumps(content), "p": principal},
        )
        conn.execute(
            text(
                "INSERT INTO execbound.policy_bundle_lifecycle "
                "(tenant_id, bundle_id, content_hash, state, changed_at) "
                "VALUES (:t, :b, :h, 'ACTIVE', now())"
            ),
            {"t": tenant, "b": bundle_id, "h": digest},
        )
        conn.execute(
            text(
                "INSERT INTO execbound.tenant_policy_control (tenant_id, changed_at) "
                "VALUES (:t, now()) ON CONFLICT (tenant_id) DO NOTHING"
            ),
            {"t": tenant},
        )
        # The selection is per space since migration 0041; every space of the tenant
        # selects the fixture's bundle.
        conn.execute(
            text(
                "INSERT INTO execbound.space_policy_selection "
                "(tenant_id, space_id, bundle_id, changed_at, changed_by) "
                "SELECT :t, s.space_id, :b, now(), :t FROM execbound.spaces s "
                "WHERE s.tenant_id = :t "
                "ON CONFLICT (tenant_id, space_id) DO UPDATE SET bundle_id = excluded.bundle_id"
            ),
            {"t": tenant, "b": bundle_id},
        )
    return bundle_id


def reach_rows(db, tenant):
    with db.transaction(tenant) as conn:
        return (
            conn.execute(
                text(
                    "SELECT action, path_kind, path_ref, certainty, enforcement_mode, "
                    "catalog_version, computed_at, valid_until, gone_at "
                    "FROM execbound.monitor_agent_reach ORDER BY action, path_kind, path_ref"
                )
            )
            .mappings()
            .all()
        )


def test_a_mapped_grant_infers_reach_and_an_unmapped_one_is_counted_instead():
    rows, unresolved = reach.from_grants(
        [
            Grant("graph_role", MICROSOFT_GRAPH, "User.EnableDisableAccount.All", AGENT_ONE),
            Grant("directory_role", "", AUTH_ADMIN, AGENT_ONE),
            # Nothing in the catalog names either of these, so neither may name an action.
            Grant("graph_role", MICROSOFT_GRAPH, "Mail.Read", AGENT_ONE),
            Grant("inherited_roles", MICROSOFT_GRAPH, "allAllowed", BLUEPRINT_APP),
        ]
    )
    assert unresolved == 2
    assert {(row.action, row.path_kind) for row in rows} == {
        ("identity.disable", "grant"),
        ("identity.enable", "grant"),
        ("identity.disable", "role"),
        ("identity.enable", "role"),
        ("identity.revoke_sessions", "role"),
        ("identity.reset_password", "role"),
    }
    # Nothing ExecBound operates stands between an agent and its own grant.
    assert {row.enforcement_mode for row in rows} == {"unknown"}
    assert {row.certainty for row in rows} == {"inferred"}


def test_an_unresolved_grant_never_borrows_a_nearby_action():
    rows, unresolved = reach.from_grants(
        [Grant("graph_role", MICROSOFT_GRAPH, "User.Enable", AGENT_ONE)]
    )
    assert rows == () and unresolved == 1


def test_a_governed_path_exists_only_once_an_agent_is_linked_to_a_principal():
    modes = {"identity.disable": "native"}
    assert reach.execbound_paths(modes, None) == ()
    principal = uuid4()
    rows = reach.execbound_paths(modes, principal)
    assert [(row.path_kind, row.path_ref, row.enforcement_mode) for row in rows] == [
        ("execbound", str(principal), "native")
    ]


def test_an_observe_only_mapping_governs_nothing(db, admins, admin_engine):
    admin = admins[0]
    bundle(
        admin_engine,
        admin.tenant_id,
        admin.principal_id,
        [
            {"operation_ref": "identity.disable", "action": "identity.disable"},
            {
                "operation_ref": "identity.enable",
                "action": "identity.enable",
                "observe_only": True,
            },
            {
                "operation_ref": "identity.revoke_sessions",
                "action": "identity.revoke_sessions",
                "external_executor": True,
            },
        ],
    )
    with db.transaction(admin.tenant_id) as conn:
        modes = reach.governed(conn, admin.tenant_id)
    # Observing watches and returns; it is not a path that can be claimed as governed.
    assert modes == {
        "identity.disable": "native",
        # The act goes to the customer's own executor, so the claim is the integration's.
        "identity.revoke_sessions": "integrated",
    }


def test_a_collection_writes_reach_with_its_grants(db, admins, admin_engine, clock):
    admin = admins[0]
    connection_id = connect(db, admin, clock)
    with serving(detailed_scenario()) as server, client(server) as http:
        result = graph.run(
            db, admin, connection_id=connection_id, client_secret=SECRET, client=http, clock=clock
        )
    assert result["detail"]["unresolved"] == 1  # the allAllowed declaration
    rows = reach_rows(db, admin.tenant_id)
    assert {row["path_kind"] for row in rows} == {"grant", "role"}
    assert {row["certainty"] for row in rows} == {"inferred"}
    assert {row["enforcement_mode"] for row in rows} == {"unknown"}
    assert {row["catalog_version"] for row in rows} == {"entra.v1"}
    # Seven days from the moment the directory was read, not from now.
    assert {row["valid_until"] - row["computed_at"] for row in rows} == {timedelta(days=7)}


def test_registering_a_governed_path_adds_a_row_and_alters_no_other(
    db, admins, admin_engine, clock
):
    admin = admins[0]
    connection_id = connect(db, admin, clock)
    with serving(detailed_scenario()) as server, client(server) as http:
        graph.run(
            db, admin, connection_id=connection_id, client_secret=SECRET, client=http, clock=clock
        )
        before = reach_rows(db, admin.tenant_id)

        bundle(
            admin_engine,
            admin.tenant_id,
            admin.principal_id,
            [{"operation_ref": "identity.disable", "action": "identity.disable"}],
        )
        with admin_engine.begin() as conn:
            conn.execute(
                text(
                    "UPDATE execbound.monitor_agents SET linked_principal_id = :p "
                    "WHERE tenant_id = :t"
                ),
                {"p": admin.principal_id, "t": admin.tenant_id},
            )
        clock.value = clock.value + timedelta(minutes=5)
        graph.run(
            db, admin, connection_id=connection_id, client_secret=SECRET, client=http, clock=clock
        )
    after = reach_rows(db, admin.tenant_id)
    governed = [row for row in after if row["path_kind"] == "execbound"]
    assert len(governed) == 1
    assert governed[0]["action"] == "identity.disable"
    assert governed[0]["enforcement_mode"] == "native"
    # The direct grant is untouched: a governed route is an additional path, not the
    # removal of the one the agent already had.
    grants_before = [row for row in before if row["path_kind"] == "grant"]
    grants_after = [row for row in after if row["path_kind"] == "grant"]
    assert len(grants_after) == len(grants_before)
    assert all(row["enforcement_mode"] == "unknown" for row in grants_after)
    assert all(row["gone_at"] is None for row in grants_after)


def test_a_path_whose_basis_is_gone_stops_being_a_live_claim_and_is_kept(
    db, admins, admin_engine, clock
):
    admin = admins[0]
    connection_id = connect(db, admin, clock)
    with serving(detailed_scenario()) as server, client(server) as http:
        graph.run(
            db, admin, connection_id=connection_id, client_secret=SECRET, client=http, clock=clock
        )
        server.scenario.member_of = {AGENT_ONE: []}
        clock.value = clock.value + timedelta(minutes=5)
        graph.run(
            db, admin, connection_id=connection_id, client_secret=SECRET, client=http, clock=clock
        )
    rows = reach_rows(db, admin.tenant_id)
    live = [row for row in rows if row["gone_at"] is None]
    gone = [row for row in rows if row["gone_at"] is not None]
    assert {row["path_kind"] for row in live} == {"grant"}
    assert {row["path_kind"] for row in gone} == {"role"}
    # Nothing was deleted; the claim ended, the record did not.
    assert len(gone) == 4


def test_an_expired_claim_reads_as_unknown_rather_than_going_on_asserting(db, admins, clock):
    admin = admins[0]
    connection_id = connect(db, admin, clock)
    with serving(detailed_scenario()) as server, client(server) as http:
        graph.run(
            db, admin, connection_id=connection_id, client_secret=SECRET, client=http, clock=clock
        )
    row = reach_rows(db, admin.tenant_id)[0]
    assert reach.effective(row, clock.value) == "inferred"
    assert reach.effective(row, row["valid_until"]) == "unknown"
    assert reach.effective(row, row["valid_until"] + timedelta(seconds=1)) == "unknown"
