# SPDX-License-Identifier: AGPL-3.0-only
"""Resolution under versioned context contracts (CC3 resolution, CC4, CC5, CC6)."""

import json
from datetime import timedelta
from uuid import uuid4

import pytest
from context_fixtures import CATALOG, SYNTHETIC_OPERATION, SYNTHETIC_VERSION, seed_synthetic
from sqlalchemy import text
from test_execution import world as world
from test_resolution import registry as registry

from execbound.contracts import PRODUCTION_CATALOG
from execbound.execution.snapshot import resolve_snapshot
from execbound.policy.models import ContextSetting
from execbound.requests import parse_request
from execbound.resolution import ResolutionError, resolve_request


@pytest.fixture
def facts_world(world, admin_engine):
    seed_synthetic(
        admin_engine,
        tenant=world["identity"].tenant_id,
        account=world["account"],
        source=world["inventory"],
        resource=world["target"],
        observed=world["clock"].now() - timedelta(seconds=60),
    )
    return world


def facts_request(world, **changes):
    wire = {
        "operation_ref": SYNTHETIC_OPERATION,
        "target": {"kind": "canonical", "value": str(world["target"])},
        "arguments": {},
        "idempotency_key": "facts-1",
    }
    wire.update(changes)
    return parse_request(json.dumps(wire).encode())


def resolve(db, world, *, settings=None, catalog=CATALOG, **changes):
    return resolve_request(
        db,
        world["identity"],
        facts_request(world, **changes),
        world["clock"],
        settings=settings,
        catalog=catalog,
    )


def fact_setting(max_age=300, writers=("inventory_sync",)):
    return ContextSetting(
        context_contract_version=SYNTHETIC_VERSION,
        source_kind="inventory",
        max_age_seconds=max_age,
        permitted_writers=writers,
    )


def test_row_backed_contract_resolves_without_incident(db, facts_world):
    resolved = resolve(db, facts_world)
    assert resolved.context_contract_version == SYNTHETIC_VERSION
    assert [(f.name, f.value, f.origin) for f in resolved.facts] == [
        ("exposure", "internal", "RESOLVED"),
        ("risk_score", 70, "RESOLVED"),
        ("edr_managed", True, "RESOLVED"),
        ("is_external", False, "DERIVED"),
    ]
    assert {f.source_version for f in resolved.facts} == {"fact-v1"}
    assert {f.source_object_id for f in resolved.facts} == {"device-01"}
    assert resolved.valid_until == facts_world["clock"].now() + timedelta(seconds=240)
    with db.transaction(facts_world["identity"].tenant_id) as conn:
        snapshot, _ = resolve_snapshot(
            conn,
            facts_world["identity"],
            facts_request(facts_world),
            facts_world["clock"],
            catalog=CATALOG,
            signals=None,
        )
    assert snapshot.model_dump(mode="json") == resolved.model_dump(mode="json")


def test_claimed_incident_without_contract_incident_stays_a_claim(db, facts_world):
    resolved = resolve(
        db, facts_world, claimed_context={"incident_id": str(facts_world["incident"])}
    )
    assert all(f.source_kind == "inventory" for f in resolved.facts)
    assert resolved.request.claimed_context.incident_id == facts_world["incident"]


def test_unserved_contract_is_invalid_operation(db, facts_world, admin_engine):
    with pytest.raises(ResolutionError) as production:
        resolve(db, facts_world, catalog=PRODUCTION_CATALOG)
    assert production.value.code == "INVALID_OPERATION"
    with admin_engine.begin() as conn:
        conn.execute(
            text(
                "UPDATE execbound.operation_mappings SET context_contract_version='missing.v1' "
                "WHERE operation_ref=:op"
            ),
            {"op": SYNTHETIC_OPERATION},
        )
    with pytest.raises(ResolutionError) as missing:
        resolve(db, facts_world)
    assert missing.value.code == "INVALID_OPERATION"


@pytest.mark.parametrize(
    "age,max_age,accepted",
    [(60, None, True), (600, None, False), (200, 120, False), (60, 120, True), (600, 900, True)],
)
def test_settings_bound_resolved_validity(db, facts_world, admin_engine, age, max_age, accepted):
    now = facts_world["clock"].now()
    with admin_engine.begin() as conn:
        conn.execute(
            text("UPDATE execbound.resource_facts SET observed_at=:n"),
            {"n": now - timedelta(seconds=age)},
        )
    settings = None if max_age is None else (fact_setting(max_age),)
    if not accepted:
        with pytest.raises(ResolutionError):
            resolve(db, facts_world, settings=settings)
        return
    resolved = resolve(db, facts_world, settings=settings)
    expected = now - timedelta(seconds=age) + timedelta(seconds=max_age or 300)
    assert {f.valid_until for f in resolved.facts} == {expected}


def test_source_writers_must_be_within_effective_allowlist(db, facts_world, admin_engine):
    with admin_engine.begin() as conn:
        conn.execute(
            text(
                "UPDATE execbound.context_sources "
                "SET allowed_writers=ARRAY['agent','inventory_sync'] "
                "WHERE source_id=:s"
            ),
            {"s": facts_world["inventory"]},
        )
    with pytest.raises(ResolutionError):
        resolve(db, facts_world)
    resolved = resolve(
        db, facts_world, settings=(fact_setting(writers=("agent", "inventory_sync")),)
    )
    assert resolved.fact("exposure").permitted_writers == ("agent", "inventory_sync")


def move_row_fact_to_new_source(admin_engine, world, *, kind, writers, active):
    """Provision `risk_score` under a second source distinct from the resource's own."""
    source = uuid4()
    values = {
        "t": world["identity"].tenant_id,
        "a": world["account"],
        "s": source,
        "kind": kind,
        "writers": list(writers),
        "active": active,
    }
    with admin_engine.begin() as conn:
        conn.execute(
            text(
                "INSERT INTO execbound.context_sources "
                "(tenant_id, account_id, source_id, kind, allowed_writers, active) "
                "VALUES (:t, :a, :s, :kind, :writers, :active)"
            ),
            values,
        )
        conn.execute(
            text(
                "UPDATE execbound.resource_facts SET source_id=:s "
                "WHERE tenant_id=:t AND fact_name='risk_score'"
            ),
            values,
        )
    return source


def snapshot(db, world, *, settings=None):
    with db.transaction(world["identity"].tenant_id) as conn:
        resolved, _ = resolve_snapshot(
            conn,
            world["identity"],
            facts_request(world),
            world["clock"],
            settings=settings,
            catalog=CATALOG,
            signals=None,
        )
    return resolved


def test_row_fact_is_trusted_through_its_own_source(db, facts_world, admin_engine):
    source = move_row_fact_to_new_source(
        admin_engine, facts_world, kind="inventory", writers=("cmdb_sync",), active=True
    )
    settings = (fact_setting(writers=("cmdb_sync", "inventory_sync")),)
    resolved = resolve(db, facts_world, settings=settings)
    snapshotted = snapshot(db, facts_world, settings=settings)
    for result in (resolved, snapshotted):
        moved, kept = result.fact("risk_score"), result.fact("exposure")
        assert (moved.source_id, moved.permitted_writers) == (source, ("cmdb_sync",))
        assert (kept.source_id, kept.permitted_writers) == (
            facts_world["inventory"],
            ("inventory_sync",),
        )
    assert snapshotted.model_dump(mode="json") == resolved.model_dump(mode="json")


ROW_SOURCE_DEFECTS = {
    "inactive": {"kind": "inventory", "writers": ("inventory_sync",), "active": False},
    "incident kind": {"kind": "incident", "writers": ("inventory_sync",), "active": True},
    "writer outside allowlist": {"kind": "inventory", "writers": ("agent",), "active": True},
}


@pytest.mark.parametrize("defect", sorted(ROW_SOURCE_DEFECTS))
def test_row_fact_source_is_checked_while_resource_source_is_valid(
    db, facts_world, admin_engine, defect
):
    assert resolve(db, facts_world).fact("risk_score").source_id == facts_world["inventory"]
    move_row_fact_to_new_source(admin_engine, facts_world, **ROW_SOURCE_DEFECTS[defect])
    with pytest.raises(ResolutionError):
        resolve(db, facts_world)
    with pytest.raises(ResolutionError):
        snapshot(db, facts_world)


@pytest.mark.parametrize(
    "statement",
    [
        "DELETE FROM execbound.resource_facts WHERE fact_name='risk_score'",
        "UPDATE execbound.resource_facts SET value='101'::jsonb WHERE fact_name='risk_score'",
        "UPDATE execbound.resource_facts SET value='\"70\"'::jsonb WHERE fact_name='risk_score'",
        "UPDATE execbound.resource_facts SET value='\"unknown\"'::jsonb WHERE fact_name='exposure'",
    ],
)
def test_missing_or_invalid_fact_rows_fail_closed(db, facts_world, admin_engine, statement):
    with admin_engine.begin() as conn:
        conn.execute(text(statement))
    with pytest.raises(ResolutionError):
        resolve(db, facts_world)
