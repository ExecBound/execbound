# SPDX-License-Identifier: AGPL-3.0-only
"""Coordinator, runtime and approval surface under context contracts (CC3, CC11, CC12)."""

import json
import secrets
from datetime import timedelta
from pathlib import Path

import pytest
from context_fixtures import (
    CATALOG,
    SYNTHETIC_OPERATION,
    SYNTHETIC_VERSION,
    seed_synthetic,
    synthetic_bundle,
)
from fastapi.testclient import TestClient
from sqlalchemy import text
from test_execution import world as world
from test_human_surface import credential, form_values
from test_protected_path import connector as connector
from test_protected_path import live_provider as live_provider
from test_resolution import registry as registry

from execbound.app import create_app
from execbound.contracts import PRODUCTION_CATALOG
from execbound.execution import admit, decide_approval
from execbound.execution.models import ExecutionError
from execbound.policy.models import ContextSetting
from execbound.policy.store import activate_bundle, create_bundle, validate_bundle
from execbound.requests import parse_request
from execbound.resolution import resolve_request
from execbound.resolution.models import ResolvedRequest
from execbound.runtime import Runtime
from execbound.surfaces.human import HumanConfig, environment_label, resource_class
from execbound.surfaces.tokens import TokenKeys

GOLDEN = Path(__file__).parent / "fixtures" / "context-contracts-v1-parity.json"
APPROVE_RISKY = (
    'permit(principal, action == ExecBound::Action::"endpoint.isolate", resource) '
    "when { resource.risk_score >= 60 };"
)
ORIGIN = "http://127.0.0.1"
NOTHING_ADMITTED = {"executions": 0, "approvals": 0, "execution_impact": 0}


def inventory_setting(max_age, writers=("inventory_sync",)):
    return (
        ContextSetting(
            context_contract_version=SYNTHETIC_VERSION,
            source_kind="inventory",
            max_age_seconds=max_age,
            permitted_writers=writers,
        ),
    )


def install(db, world, admin_engine, *, age=60, **bundle_changes):
    seed_synthetic(
        admin_engine,
        tenant=world["identity"].tenant_id,
        account=world["account"],
        source=world["inventory"],
        resource=world["target"],
        observed=world["clock"].now() - timedelta(seconds=age),
    )
    bundle = synthetic_bundle(world["identity"].tenant_id, world["account"], **bundle_changes)
    create_bundle(db, world["admin"], bundle, world["clock"])
    validate_bundle(db, world["admin"], bundle.bundle_id, world["clock"], catalog=CATALOG)
    activate_bundle(db, world["admin"], bundle.bundle_id, world["clock"], catalog=CATALOG)
    return bundle


def wire(world, key="facts-1"):
    return json.dumps(
        {
            "operation_ref": SYNTHETIC_OPERATION,
            "target": {"kind": "canonical", "value": str(world["target"])},
            "arguments": {},
            "idempotency_key": key,
        }
    ).encode()


def impact_rows(engine, world):
    with engine.connect() as conn:
        return conn.execute(
            text("SELECT count(*) FROM execbound.execution_impact WHERE tenant_id=:t"),
            {"t": world["identity"].tenant_id},
        ).scalar_one()


def authority_rows(engine, world):
    with engine.connect() as conn:
        return {
            table: conn.execute(
                text(f"SELECT count(*) FROM execbound.{table} WHERE tenant_id=:t"),
                {"t": world["identity"].tenant_id},
            ).scalar_one()
            for table in NOTHING_ADMITTED
        }


def test_synthetic_contract_executes_once_through_runtime(db, world, admin_engine, connector):
    install(db, world, admin_engine)
    runtime = Runtime(db, [connector], clock=world["clock"], catalog=CATALOG)
    assert runtime.execute(world["identity"], wire(world)).state == "EXECUTED"
    assert impact_rows(admin_engine, world) == 1


def test_synthetic_contract_denial_never_dispatches(db, world, admin_engine, connector):
    install(db, world, admin_engine)
    with admin_engine.begin() as conn:
        conn.execute(
            text(
                "UPDATE execbound.resource_facts SET value='10'::jsonb WHERE fact_name='risk_score'"
            )
        )
    runtime = Runtime(db, [connector], clock=world["clock"], catalog=CATALOG)
    assert runtime.execute(world["identity"], wire(world)).state == "DENIED"
    assert impact_rows(admin_engine, world) == 0


def test_changed_fact_row_invalidates_pending_approval(db, world, admin_engine):
    install(db, world, admin_engine, approval_policies=APPROVE_RISKY)
    request = parse_request(wire(world))
    pending = admit(db, world["identity"], request, world["clock"], catalog=CATALOG)
    assert pending.view.state == "PENDING_APPROVAL"
    # Control: an unchanged retry re-attests under the catalog and stays pending, so the
    # stale outcome below comes from the changed fact row, not from an unknown contract.
    unchanged = admit(db, world["identity"], request, world["clock"], catalog=CATALOG)
    assert unchanged.view.state == "PENDING_APPROVAL"
    with admin_engine.begin() as conn:
        conn.execute(
            text(
                "UPDATE execbound.resource_facts SET version='fact-v2' WHERE fact_name='risk_score'"
            )
        )
    retried = admit(db, world["identity"], request, world["clock"], catalog=CATALOG)
    assert retried.view.state == "STALE_AUTHORIZATION"


def test_display_fact_follows_each_contract(db, world, admin_engine):
    golden = json.loads(GOLDEN.read_text(encoding="utf-8"))
    endpoint = ResolvedRequest.model_validate_json(json.dumps(golden["ws-dev"]["resolved"]))
    identity = ResolvedRequest.model_validate_json(json.dumps(golden["user-dev"]["resolved"]))
    assert (resource_class(endpoint, CATALOG), environment_label(endpoint)) == (
        "workstation",
        "development",
    )
    assert (resource_class(identity, CATALOG), environment_label(identity)) == (
        "standard",
        "development",
    )
    install(db, world, admin_engine)
    synthetic = resolve_request(
        db, world["identity"], parse_request(wire(world)), world["clock"], catalog=CATALOG
    )
    assert (resource_class(synthetic, CATALOG), environment_label(synthetic)) == ("internal", None)


def test_default_setting_rejects_fact_older_than_default_age(db, world, admin_engine, connector):
    install(db, world, admin_engine, age=400)
    runtime = Runtime(db, [connector], clock=world["clock"], catalog=CATALOG)
    with pytest.raises(ExecutionError):
        runtime.execute(world["identity"], wire(world))
    assert authority_rows(admin_engine, world) == NOTHING_ADMITTED


def test_widened_setting_admits_fact_older_than_default_age(db, world, admin_engine, connector):
    install(db, world, admin_engine, age=400, context_settings=inventory_setting(900))
    runtime = Runtime(db, [connector], clock=world["clock"], catalog=CATALOG)
    assert runtime.execute(world["identity"], wire(world)).state == "EXECUTED"
    assert impact_rows(admin_engine, world) == 1


@pytest.mark.parametrize("approval_policies", ["", APPROVE_RISKY], ids=["autonomous", "approval"])
@pytest.mark.parametrize(
    "settings",
    [inventory_setting(30), inventory_setting(300, ("asset_feed",))],
    ids=["max_age", "writers"],
)
def test_narrowed_setting_rejects_fact_the_defaults_accept(
    db, world, admin_engine, connector, settings, approval_policies
):
    install(db, world, admin_engine, approval_policies=approval_policies, context_settings=settings)
    runtime = Runtime(db, [connector], clock=world["clock"], catalog=CATALOG)
    with pytest.raises(ExecutionError):
        runtime.execute(world["identity"], wire(world))
    assert authority_rows(admin_engine, world) == NOTHING_ADMITTED


def test_approval_under_widened_setting_proceeds(db, world, admin_engine, connector):
    install(
        db,
        world,
        admin_engine,
        age=400,
        approval_policies=APPROVE_RISKY,
        context_settings=inventory_setting(900),
    )
    runtime = Runtime(db, [connector], clock=world["clock"], catalog=CATALOG)
    pending = runtime.execute(world["identity"], wire(world))
    assert pending.state == "PENDING_APPROVAL"
    decided = decide_approval(
        db, world["human"], pending.approval_id, "APPROVE", world["clock"], catalog=CATALOG
    )
    assert (decided.state, decided.approval_state) == ("PENDING_APPROVAL", "APPROVED")
    result = runtime.execute(world["identity"], wire(world))
    assert (result.execution_id, result.state) == (pending.execution_id, "EXECUTED")
    assert impact_rows(admin_engine, world) == 1


@pytest.mark.parametrize(
    "catalog,outcome",
    [
        (CATALOG, ("PENDING_APPROVAL", "APPROVED")),
        (PRODUCTION_CATALOG, ("STALE_AUTHORIZATION", "INVALIDATED")),
    ],
    ids=["synthetic_catalog", "production_catalog"],
)
def test_approval_decision_resolves_through_supplied_catalog(
    db, world, admin_engine, catalog, outcome
):
    install(db, world, admin_engine, approval_policies=APPROVE_RISKY)
    pending = admit(
        db, world["identity"], parse_request(wire(world)), world["clock"], catalog=CATALOG
    )
    decided = decide_approval(
        db, world["human"], pending.view.approval_id, "APPROVE", world["clock"], catalog=catalog
    )
    assert (decided.state, decided.approval_state) == outcome


@pytest.fixture
def synthetic_surface(db, world, admin_engine, connector):
    install(db, world, admin_engine, approval_policies=APPROVE_RISKY)
    runtime = Runtime(db, [connector], clock=world["clock"], catalog=CATALOG)
    config = HumanConfig(ORIGIN, TokenKeys("state-v1", {"state-v1": secrets.token_bytes(32)}))
    app = create_app(db, runtime=runtime, human=config)
    with TestClient(app, base_url=ORIGIN, follow_redirects=False) as client:
        _, login = form_values(client.get("/login").text, "/session")
        login["credential"] = credential(admin_engine, world["human"])
        assert client.post("/session", data=login, headers={"Origin": ORIGIN}).status_code == 303
        yield runtime, client


def test_router_decides_synthetic_approval_with_runtime_catalog(
    synthetic_surface, world, admin_engine
):
    runtime, client = synthetic_surface
    first = runtime.execute(world["identity"], wire(world))
    assert first.state == "PENDING_APPROVAL"
    path, values = form_values(
        client.get(f"/approvals/{first.approval_id}/classic").text, "/decide"
    )
    values["decision"] = "APPROVE"
    assert client.post(path, data=values, headers={"Origin": ORIGIN}).status_code == 303
    result = runtime.execute(world["identity"], wire(world))
    assert (result.execution_id, result.state) == (first.execution_id, "EXECUTED")
    assert impact_rows(admin_engine, world) == 1


def test_approval_page_shows_display_fact_and_escapes_provider_text(
    synthetic_surface, world, admin_engine
):
    runtime, client = synthetic_surface
    injected = "<script>alert(1)</script>"
    with admin_engine.begin() as conn:
        conn.execute(
            text(
                "UPDATE execbound.resources SET provider_id=:v "
                "WHERE tenant_id=:t AND resource_id=:r"
            ),
            {"v": injected, "t": world["identity"].tenant_id, "r": world["target"]},
        )
    view = runtime.execute(world["identity"], wire(world))
    assert view.state == "PENDING_APPROVAL"
    page = client.get(f"/approvals/{view.approval_id}/classic")
    assert page.status_code == 200
    assert "internal" in page.text
    assert injected not in page.text
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in page.text
