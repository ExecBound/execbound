# SPDX-License-Identifier: AGPL-3.0-only
"""Observed and verified reach, and the link that makes either attributable.

SR11, and the half of SR5 that only an execution can establish.
"""

import hashlib
import json
from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import uuid4

import pytest
from sqlalchemy import text
from test_monitoring_store import FixedClock
from test_monitoring_store import admins as admins
from test_scout_reach import bundle, reach_rows
from test_scout_run import client, connect, detailed_scenario

from execbound.monitoring import graph, store
from execbound.monitoring.models import MonitorError
from execbound_harness.fake_graph import DIRECTORY, SECRET, serving

pytestmark = pytest.mark.integration

AGENT_ONE = "aaaaaaaa-0000-4000-8000-000000000001"


@pytest.fixture
def clock():
    return FixedClock(datetime.now(UTC))


def collected(db, admin, clock, *, directory=DIRECTORY):
    """One collection, so there is an agent to attribute anything to. A directory is connected
    once across the deployment, so a test collecting in several workspaces names one each."""
    connection_id = connect(db, admin, clock, directory_ref=directory)
    with serving(detailed_scenario(organization=directory)) as server, client(server) as http:
        graph.run(
            db, admin, connection_id=connection_id, client_secret=SECRET, client=http, clock=clock
        )
    return connection_id


def governed_agent(admin_engine, tenant):
    """An AGENT principal with its own credential: what a link names since bindings (0037)."""
    principal, credential = uuid4(), uuid4()
    with admin_engine.begin() as conn:
        conn.execute(
            text(
                "INSERT INTO execbound.principals (tenant_id, principal_id, kind, space_id) "
                "VALUES (:t, :p, 'AGENT', "
                "(SELECT space_id FROM execbound.spaces WHERE tenant_id = :t))"
            ),
            {"t": tenant, "p": principal},
        )
        conn.execute(
            text(
                "INSERT INTO execbound.credentials "
                "(tenant_id, credential_id, principal_id, token_hash, expires_at) "
                "VALUES (:t, :c, :p, :h, :e)"
            ),
            {
                "t": tenant,
                "c": credential,
                "p": principal,
                "h": hashlib.sha256(uuid4().bytes).hexdigest(),
                "e": datetime.now(UTC) + timedelta(hours=1),
            },
        )
    return principal, credential


def settle_execution(admin_engine, tenant, principal, credential, action, when):
    """Insert one settled execution directly; what is under test is the derivation."""
    target_id, bundle_id, execution_id = uuid4(), uuid4(), uuid4()
    content = {"mappings": []}
    digest = hashlib.sha256(json.dumps(content, sort_keys=True).encode()).hexdigest()
    frozen = {"intent": {"action": action}}
    with admin_engine.begin() as conn:
        conn.execute(
            text(
                "INSERT INTO execbound.canonical_targets "
                "(tenant_id, canonical_target_id, created_at) VALUES (:t, :g, now())"
            ),
            {"t": tenant, "g": target_id},
        )
        conn.execute(
            text(
                "INSERT INTO execbound.policy_bundle_contents "
                "(tenant_id, bundle_id, content_hash, content, created_at, created_by, space_id) "
                "VALUES (:t, :b, :h, CAST(:c AS jsonb), now(), :p, "
                "(SELECT space_id FROM execbound.spaces WHERE tenant_id = :t)) "
                "ON CONFLICT DO NOTHING"
            ),
            {"t": tenant, "b": bundle_id, "h": digest, "c": json.dumps(content), "p": principal},
        )
        conn.execute(
            text("""
            INSERT INTO execbound.executions
            (tenant_id, execution_id, principal_id, credential_id, intent_hash, wire_hash,
             plan_hash, canonical_target_id, bundle_id, frozen, state, created_at, changed_at,
             operation_id, request_number, space_id)
            VALUES (:t, :e, :p, :c, :h, :h, :h, :g, :b, CAST(:f AS jsonb), 'EXECUTED',
                    :when, :when, :o, (SELECT coalesce(max(request_number),0)+1
                        FROM execbound.executions WHERE tenant_id=:t),
                    (SELECT space_id FROM execbound.spaces WHERE tenant_id = :t))
        """),
            {
                "t": tenant,
                "e": execution_id,
                "p": principal,
                "c": credential,
                "h": "aa" * 32,
                "g": target_id,
                "b": bundle_id,
                "f": json.dumps(frozen),
                "when": when,
                "o": uuid4(),
            },
        )
    return execution_id


def observe(admin_engine, tenant, connection_id, actor_ref, action, when):
    """One collected observation of `actor_ref` taking `action` at `when`; its identifier."""
    observation = uuid4()
    with admin_engine.begin() as conn:
        conn.execute(
            text("""
            INSERT INTO execbound.monitor_observations
            (tenant_id, observation_id, connection_id, event_id, version, content_hash,
             occurred_at, received_at, kind, action, outcome, evaluation_state,
             operation_name, external_ref, evidence, actor_ref, rule_version, space_id)
            VALUES (:t, :o, :c, :event, 1, :digest, :when, :when, 'ai_tool_run', :action,
                    'success', 'PENDING', 'AiToolRun', :event, 'collected', :actor,
                    'sensitive-action.v2', 
                        (SELECT space_id FROM execbound.spaces WHERE tenant_id = :t))
        """),
            {
                "t": tenant,
                "o": observation,
                "c": connection_id,
                "event": f"audit:{uuid4()}",
                "when": when,
                "action": action,
                "actor": actor_ref,
                "digest": hashlib.sha256(f"{actor_ref}{action}{when}".encode()).hexdigest(),
            },
        )
    return observation


def test_a_link_names_a_principal_and_refuses_anything_else(
    db, admins, admin_engine, clock, seeded
):
    admin, other = admins
    governed, _ = governed_agent(admin_engine, admin.tenant_id)
    connection_id = collected(db, admin, clock)
    # A principal of another tenant is not this tenant's to link.
    with pytest.raises(MonitorError) as failure:
        store.link_agent(
            db,
            admin,
            connection_id=connection_id,
            platform_ref=AGENT_ONE,
            principal_id=other.principal_id,
            clock=clock,
        )
    assert failure.value.code == "PRINCIPAL_UNAVAILABLE"
    # An agent this connection never collected is not this connection's to link.
    with pytest.raises(MonitorError) as failure:
        store.link_agent(
            db,
            admin,
            connection_id=connection_id,
            platform_ref="aaaaaaaa-0000-4000-8000-000000009999",
            principal_id=admin.principal_id,
            clock=clock,
        )
    assert failure.value.code == "AGENT_UNAVAILABLE"

    store.link_agent(
        db,
        admin,
        connection_id=connection_id,
        platform_ref=AGENT_ONE,
        principal_id=governed,
        clock=clock,
    )
    with db.transaction(admin.tenant_id) as conn:
        assert (
            conn.execute(
                text("SELECT linked_principal_id FROM execbound.monitor_agents")
            ).scalar_one()
            == governed
        )
    # Withdrawing the statement is the same act with no principal.
    store.link_agent(
        db,
        admin,
        connection_id=connection_id,
        platform_ref=AGENT_ONE,
        principal_id=None,
        clock=clock,
    )
    with db.transaction(admin.tenant_id) as conn:
        assert (
            conn.execute(
                text("SELECT linked_principal_id FROM execbound.monitor_agents")
            ).scalar_one()
            is None
        )


def test_an_observation_gives_observed_and_an_execution_gives_verified(
    db, admins, admin_engine, seeded, clock
):
    admin = admins[0]
    governed, credential = governed_agent(admin_engine, admin.tenant_id)
    connection_id = collected(db, admin, clock)
    observe(
        admin_engine,
        admin.tenant_id,
        connection_id,
        AGENT_ONE,
        "identity.disable",
        clock.value - timedelta(hours=1),
    )
    counts = store.derive_reach(db, admin, clock=clock)
    assert counts == {"verified": 0, "observed": 1}
    observed = [row for row in reach_rows(db, admin.tenant_id) if row["path_kind"] == "observation"]
    assert len(observed) == 1
    assert observed[0]["certainty"] == "observed"
    # Telemetry is visibility; it never proves anything stood in the way.
    assert observed[0]["enforcement_mode"] == "observed"

    bundle(
        admin_engine,
        admin.tenant_id,
        admin.principal_id,
        [{"operation_ref": "identity.disable", "action": "identity.disable"}],
    )
    store.link_agent(
        db,
        admin,
        connection_id=connection_id,
        platform_ref=AGENT_ONE,
        principal_id=governed,
        clock=clock,
    )
    settle_execution(
        admin_engine,
        admin.tenant_id,
        governed,
        credential,
        "identity.disable",
        clock.value - timedelta(minutes=30),
    )
    counts = store.derive_reach(db, admin, clock=clock)
    assert counts == {"verified": 1, "observed": 1}
    rows = {
        (row["path_kind"], row["certainty"], row["enforcement_mode"])
        for row in reach_rows(db, admin.tenant_id)
        if row["action"] == "identity.disable"
    }
    # Four different answers to "through which path", all true at once.
    assert ("execbound", "verified", "native") in rows
    assert ("observation", "observed", "observed") in rows
    assert ("grant", "inferred", "unknown") in rows
    assert ("role", "inferred", "unknown") in rows


def test_deriving_twice_changes_nothing(db, admins, admin_engine, seeded, clock):
    admin = admins[0]
    connection_id = collected(db, admin, clock)
    observe(
        admin_engine,
        admin.tenant_id,
        connection_id,
        AGENT_ONE,
        "identity.disable",
        clock.value - timedelta(hours=1),
    )
    store.derive_reach(db, admin, clock=clock)
    first = reach_rows(db, admin.tenant_id)
    store.derive_reach(db, admin, clock=clock)
    assert reach_rows(db, admin.tenant_id) == first


def test_evidence_older_than_its_currency_is_not_revived(db, admins, admin_engine, seeded, clock):
    admin = admins[0]
    connection_id = collected(db, admin, clock)
    observe(
        admin_engine,
        admin.tenant_id,
        connection_id,
        AGENT_ONE,
        "identity.disable",
        clock.value - timedelta(days=45),
    )
    assert store.derive_reach(db, admin, clock=clock) == {"verified": 0, "observed": 0}
    assert [
        row for row in reach_rows(db, admin.tenant_id) if row["path_kind"] == "observation"
    ] == []


def test_an_observation_by_another_actor_is_not_this_agent(db, admins, admin_engine, seeded, clock):
    admin = admins[0]
    connection_id = collected(db, admin, clock)
    observe(
        admin_engine,
        admin.tenant_id,
        connection_id,
        "aaaaaaaa-0000-4000-8000-000000009999",
        "identity.disable",
        clock.value - timedelta(hours=1),
    )
    # Attribution is an identifier match, never a resemblance.
    assert store.derive_reach(db, admin, clock=clock) == {"verified": 0, "observed": 0}


def test_an_unlinked_agent_gets_no_verified_row_however_many_executions_settle(
    db, admins, admin_engine, seeded, clock
):
    admin = admins[0]
    collected(db, admin, clock)
    settle_execution(
        admin_engine,
        admin.tenant_id,
        admin.principal_id,
        seeded["credentials"][0],
        "identity.disable",
        clock.value - timedelta(minutes=30),
    )
    assert store.derive_reach(db, admin, clock=clock) == {"verified": 0, "observed": 0}


def test_the_execution_path_owns_no_monitoring_row():
    """Settlement must not write monitoring state; the worker reads it instead."""
    execution = Path("src/execbound/execution")
    offenders = [
        path.name
        for path in execution.rglob("*.py")
        if "monitor_agent" in path.read_text() or "monitoring" in path.read_text()
    ]
    assert offenders == []


def test_every_verified_and_observed_reach_is_derived_however_many_sort_before_it(
    db, admins, admin_engine, seeded, clock, monkeypatch
):
    """Verified and observed reach are each read a page at a time, in agent and action order,
    and every page is read: never the first page and silence on the rest, which would leave the
    reach of every agent and action past it underived, with nothing to say so. A page of two
    stands in for the production page here, so three actions fill one page and part of the next.
    """
    admin = admins[0]
    governed, credential = governed_agent(admin_engine, admin.tenant_id)
    connection_id = collected(db, admin, clock)
    store.link_agent(
        db,
        admin,
        connection_id=connection_id,
        platform_ref=AGENT_ONE,
        principal_id=governed,
        clock=clock,
    )
    actions = ("identity.disable", "identity.enable", "identity.revoke_sessions")
    for action in actions:
        observe(
            admin_engine,
            admin.tenant_id,
            connection_id,
            AGENT_ONE,
            action,
            clock.value - timedelta(hours=1),
        )
        settle_execution(
            admin_engine,
            admin.tenant_id,
            governed,
            credential,
            action,
            clock.value - timedelta(minutes=30),
        )
    monkeypatch.setattr(store, "MAX_DERIVED", 2)
    assert store.derive_reach(db, admin, clock=clock) == {"verified": 3, "observed": 3}
    derived = {
        (row["path_kind"], row["action"])
        for row in reach_rows(db, admin.tenant_id)
        if row["path_kind"] in {"execbound", "observation"}
    }
    assert derived == {
        (kind, action) for kind in ("execbound", "observation") for action in actions
    }
