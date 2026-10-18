# SPDX-License-Identifier: AGPL-3.0-only
"""Both new actions through admission, approval, dispatch and settlement (SA4 to SA8, SA12)."""

import json
import secrets
import sqlite3
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient
from identity_fixtures import add_target
from identity_fixtures import identity_connector as identity_connector
from identity_fixtures import identity_provider as identity_provider
from identity_fixtures import identity_world as identity_world
from sqlalchemy import text
from test_execution import world as world
from test_human_surface import credential, form_values
from test_human_surface import human_config as human_config
from test_protected_path import connector as connector
from test_protected_path import live_provider as live_provider
from test_resolution import registry as registry

from execbound.app import create_app
from execbound.execution import admit, decide_approval
from execbound.execution.models import ExecutionError
from execbound.operations import PRODUCTION_ACTIONS
from execbound.policy.store import activate_bundle, create_bundle, validate_bundle
from execbound.provider.models import CredentialState, JournalRecord
from execbound.requests import parse_request
from execbound.runtime import Runtime
from execbound.surfaces.tokens import TokenKeys
from execbound_harness.soc_demo import soc_bundle


@pytest.fixture
def soc_world(identity_world, admin_engine, db):
    world = identity_world
    endpoint = world["endpoint_world"]
    tenant = world["identity"].tenant_id
    with admin_engine.begin() as conn:
        for action, account, provider, resource_type in (
            ("endpoint.lift_isolation", endpoint["account"], "mock_crowdstrike", "endpoint"),
            ("identity.reset_password", world["account"], "mock_entra", "identity"),
        ):
            spec = PRODUCTION_ACTIONS.bound(provider, action)
            conn.execute(
                text(
                    "INSERT INTO execbound.operation_mappings "
                    "(tenant_id,operation_ref,account_id,provider,resource_type,action,"
                    "provider_operation,mapping_version,schema_version,context_contract_version) "
                    "VALUES (:t,:action,:a,:provider,:resource_type,:action,:operation,"
                    "'map-v1','action.v1',:contract)"
                ),
                {
                    "t": tenant,
                    "action": action,
                    "a": account,
                    "provider": provider,
                    "resource_type": resource_type,
                    "operation": spec.provider_operation,
                    "contract": spec.context_contract_version,
                },
            )
        for canonical, action in (
            (endpoint["canonical"], "endpoint.lift_isolation"),
            (world["canonical"], "identity.reset_password"),
        ):
            conn.execute(
                text(
                    "INSERT INTO execbound.approval_scopes "
                    "(tenant_id,approver_id,canonical_target_id,action, "
                    "space_id) VALUES (:t,:p,:c,:a, "
                    "(SELECT space_id FROM execbound.spaces WHERE tenant_id = :t))"
                ),
                {"t": tenant, "p": world["human"].principal_id, "c": canonical, "a": action},
            )
    bundle = soc_bundle(tenant, endpoint["account"], world["account"], mapping_version="map-v1")
    create_bundle(db, endpoint["admin"], bundle, world["clock"])
    validate_bundle(db, endpoint["admin"], bundle.bundle_id, world["clock"])
    activate_bundle(db, endpoint["admin"], bundle.bundle_id, world["clock"])
    return {**world, "endpoint": endpoint, "soc_bundle": bundle}


@pytest.fixture
def soc_runtime(db, soc_world, connector, identity_connector):
    keys = TokenKeys("pending-v1", {"pending-v1": secrets.token_bytes(32)})
    return Runtime(db, [connector, identity_connector], clock=soc_world["clock"], keys=keys)


def add_endpoint(
    engine,
    live_provider,
    world,
    *,
    environment="development",
    incident_status="CLOSED",
    contained=True,
):
    """A workstation with a linked CRITICAL incident, scoped to the reviewer and provisioned."""
    endpoint = world["endpoint"]
    tenant = world["identity"].tenant_id
    resource, incident, canonical = uuid4(), uuid4(), uuid4()
    p = {
        "t": tenant,
        "a": endpoint["account"],
        "r": resource,
        "i": incident,
        "c": canonical,
        "s": endpoint["inventory"],
        "z": endpoint["incident_source"],
        "p": world["human"].principal_id,
        "n": world["clock"].now(),
        "environment": environment,
        "status": incident_status,
        "provider_id": str(resource),
    }
    with engine.begin() as conn:
        conn.execute(text("INSERT INTO execbound.canonical_targets VALUES (:t,:c,:n)"), p)
        conn.execute(
            text(
                "INSERT INTO execbound.resources "
                "(tenant_id,account_id,provider,resource_type,resource_id,provider_id,"
                "version,source_id,role,environment,criticality,observed_at) "
                "VALUES (:t,:a,'mock_crowdstrike','endpoint',:r,:provider_id,'resource-v1',:s,"
                "'workstation',:environment,2,:n)"
            ),
            p,
        )
        conn.execute(
            text(
                "INSERT INTO execbound.resource_identities "
                "VALUES (:t,:a,'mock_crowdstrike','endpoint',:r,:c)"
            ),
            p,
        )
        conn.execute(
            text(
                "INSERT INTO execbound.incidents "
                "(tenant_id,account_id,provider,resource_type,incident_id,resource_id,"
                "source_id,version,status,severity,observed_at) "
                "VALUES (:t,:a,'mock_crowdstrike','endpoint',:i,:r,:z,'incident-v1',:status,"
                "'CRITICAL',:n)"
            ),
            p,
        )
        for action in ("endpoint.isolate", "endpoint.lift_isolation"):
            conn.execute(
                text(
                    "INSERT INTO execbound.approval_scopes "
                    "(tenant_id,approver_id,canonical_target_id,action, "
                    "space_id) VALUES (:t,:p,:c,:action, "
                    "(SELECT space_id FROM execbound.spaces WHERE tenant_id = :t))"
                ),
                {**p, "action": action},
            )
    live_provider.store.provision_resource(tenant, canonical, "resource-v1", contained=contained)
    live_provider.store.provision_representation(
        tenant, endpoint["account"], str(resource), canonical
    )
    return {"resource": resource, "incident": incident, "canonical": canonical}


def lift(target, *, reason, key):
    return json.dumps(
        {
            "operation_ref": "endpoint.lift_isolation",
            "target": {"kind": "canonical", "value": str(target["resource"])},
            "arguments": {"reason": reason},
            "idempotency_key": key,
            "claimed_context": {"incident_id": str(target["incident"])},
        }
    ).encode()


def isolate(target, *, key):
    return json.dumps(
        {
            "operation_ref": "endpoint.isolate",
            "target": {"kind": "canonical", "value": str(target["resource"])},
            "arguments": {},
            "idempotency_key": key,
            "claimed_context": {"incident_id": str(target["incident"])},
        }
    ).encode()


def reset(target, *, require_change, key):
    return json.dumps(
        {
            "operation_ref": "identity.reset_password",
            "target": {"kind": "canonical", "value": str(target["target"])},
            "arguments": {"require_change_at_next_sign_in": require_change},
            "idempotency_key": key,
            "claimed_context": {"incident_id": str(target["incident"])},
        }
    ).encode()


def journals(store, action):
    with sqlite3.connect(store.path) as conn:
        rows = conn.execute("SELECT record_json FROM journal").fetchall()
    records = [JournalRecord.model_validate_json(row[0]) for row in rows]
    return [record for record in records if record.command.action == action]


def impact(engine, world):
    with engine.connect() as conn:
        return conn.execute(
            text("SELECT count(*) FROM execbound.execution_impact WHERE tenant_id=:t"),
            {"t": world["identity"].tenant_id},
        ).scalar_one()


def sync_version(engine, world, target, live_provider):
    """The inventory source would observe the provider's new version after a mutation."""
    tenant = world["identity"].tenant_id
    version = live_provider.store.resource(tenant, target["canonical"]).version
    with engine.begin() as conn:
        conn.execute(
            text(
                "UPDATE execbound.resources SET version=:v,observed_at=:n "
                "WHERE tenant_id=:t AND resource_id=:r"
            ),
            {"v": version, "n": world["clock"].now(), "t": tenant, "r": target["resource"]},
        )


def test_false_positive_lift_on_closed_incident_executes_once(
    soc_runtime, soc_world, live_provider, admin_engine
):
    target = add_endpoint(admin_engine, live_provider, soc_world)
    view = soc_runtime.execute(
        soc_world["identity"], lift(target, reason="false_positive", key="lift-1")
    )
    assert view.state == "EXECUTED"
    state = live_provider.store.resource(soc_world["identity"].tenant_id, target["canonical"])
    assert state.contained is False and state.mutation_count == 1
    [record] = journals(live_provider.store, "endpoint.lift_isolation")
    assert record.endpoint_transition.before.contained is True
    assert record.endpoint_transition.after.contained is False
    assert record.command.arguments.root == {"reason": "false_positive"}
    assert impact(admin_engine, soc_world) == 1


def test_remediated_lift_needs_approval_and_the_page_shows_the_argument(
    db, soc_runtime, soc_world, live_provider, admin_engine, human_config
):
    target = add_endpoint(admin_engine, live_provider, soc_world)
    wire = lift(target, reason="remediated", key="lift-2")
    pending = soc_runtime.execute(soc_world["identity"], wire)
    assert pending.state == "PENDING_APPROVAL"
    app = create_app(db, runtime=soc_runtime, human=human_config)
    with TestClient(app, base_url="http://127.0.0.1", follow_redirects=False) as client:
        _, values = form_values(client.get("/login").text, "/session")
        values["credential"] = credential(admin_engine, soc_world["human"])
        login = client.post("/session", data=values, headers={"Origin": "http://127.0.0.1"})
        assert login.status_code == 303
        [item] = client.get("/api/console/v1/approvals").json()["items"]
        page = client.get(f"/approvals/{item['approval_id']}/classic").text
        # The argument the agent asked for is on the page a person decides from: the
        # console's own approval detail, where the arguments are their own section.
        detail = client.get(f"/api/console/v1/approvals/{item['approval_id']}").json()
    assert "Lift endpoint isolation".upper() in page
    assert {"reason": "remediated"} == {a["name"]: a["value"] for a in detail["arguments"]}
    decide_approval(db, soc_world["human"], pending.approval_id, "APPROVE", soc_world["clock"])
    assert soc_runtime.execute(soc_world["identity"], wire).state == "EXECUTED"
    tenant = soc_world["identity"].tenant_id
    assert live_provider.store.resource(tenant, target["canonical"]).mutation_count == 1


def test_reset_password_executes_with_forced_change_and_exposes_no_secret(
    soc_runtime, soc_world, identity_provider, admin_engine
):
    view = soc_runtime.execute(
        soc_world["identity"], reset(soc_world, require_change=True, key="reset-1")
    )
    assert view.state == "EXECUTED"
    state = identity_provider.store.resource(
        soc_world["identity"].tenant_id, soc_world["canonical"]
    )
    assert (state.password_generation, state.must_change_password) == (1, True)
    assert state.account_enabled is True and state.session_generation == 0
    [record] = journals(identity_provider.store, "identity.reset_password")
    assert record.credential_transition.after == CredentialState(
        password_generation=1, must_change_password=True
    )
    dumped = record.model_dump(mode="json")
    assert set(dumped["credential_transition"]["after"]) == {
        "password_generation",
        "must_change_password",
    }
    assert impact(admin_engine, soc_world) == 1


def test_reset_without_forced_change_needs_approval_and_privileged_is_denied(
    db, soc_runtime, soc_world, identity_provider, admin_engine, human_config
):
    tenant = soc_world["identity"].tenant_id
    pending = soc_runtime.execute(
        soc_world["identity"], reset(soc_world, require_change=False, key="reset-2")
    )
    assert pending.state == "PENDING_APPROVAL"
    app = create_app(db, runtime=soc_runtime, human=human_config)
    with TestClient(app, base_url="http://127.0.0.1", follow_redirects=False) as client:
        _, values = form_values(client.get("/login").text, "/session")
        values["credential"] = credential(admin_engine, soc_world["human"])
        login = client.post("/session", data=values, headers={"Origin": "http://127.0.0.1"})
        assert login.status_code == 303
        [item] = client.get("/api/console/v1/approvals").json()["items"]
        page = client.get(f"/approvals/{item['approval_id']}/classic").text
        detail = client.get(f"/api/console/v1/approvals/{item['approval_id']}").json()
    assert "Reset identity password".upper() in page
    assert {a["name"]: a["value"] for a in detail["arguments"]} == {
        "require_change_at_next_sign_in": False
    }
    privileged = add_target(admin_engine, soc_world, provider_id="identity-02")
    with admin_engine.begin() as conn:
        conn.execute(
            text(
                "UPDATE execbound.resources SET privilege_class='privileged' "
                "WHERE tenant_id=:t AND resource_id=:r"
            ),
            {"t": tenant, "r": privileged["target"]},
        )
    identity_provider.store.provision_resource(tenant, privileged["canonical"], "resource-v1")
    identity_provider.store.provision_representation(
        tenant, soc_world["account"], "identity-02", privileged["canonical"]
    )
    denied = soc_runtime.execute(
        soc_world["identity"], reset(privileged, require_change=True, key="reset-3")
    )
    assert denied.state == "DENIED"
    assert identity_provider.store.resource(tenant, privileged["canonical"]).mutation_count == 0
    assert journals(identity_provider.store, "identity.reset_password") == []


def test_same_key_with_changed_argument_conflicts_and_new_key_attaches(
    db, soc_world, live_provider, admin_engine, connector
):
    target = add_endpoint(admin_engine, live_provider, soc_world)
    identity, clock = soc_world["identity"], soc_world["clock"]
    first = admit(
        db, identity, parse_request(lift(target, reason="remediated", key="lift-3")), clock
    )
    assert first.view.state == "PENDING_APPROVAL"
    with pytest.raises(ExecutionError) as failure:
        admit(
            db, identity, parse_request(lift(target, reason="false_positive", key="lift-3")), clock
        )
    assert failure.value.code == "IDEMPOTENCY_CONFLICT"
    attached = admit(
        db, identity, parse_request(lift(target, reason="remediated", key="lift-4")), clock
    )
    assert attached.view == first.view


def test_isolate_then_lift_charges_twice_and_a_busy_target_rejects_lift(
    db, soc_runtime, soc_world, live_provider, admin_engine
):
    identity, clock = soc_world["identity"], soc_world["clock"]
    target = add_endpoint(
        admin_engine, live_provider, soc_world, incident_status="OPEN", contained=False
    )
    assert soc_runtime.execute(identity, isolate(target, key="iso-1")).state == "EXECUTED"
    sync_version(admin_engine, soc_world, target, live_provider)
    assert (
        soc_runtime.execute(identity, lift(target, reason="false_positive", key="lift-5")).state
        == "EXECUTED"
    )
    assert impact(admin_engine, soc_world) == 2
    assert live_provider.store.resource(identity.tenant_id, target["canonical"]).contained is False
    busy = add_endpoint(
        admin_engine, live_provider, soc_world, incident_status="OPEN", contained=False
    )
    committed = admit(db, identity, parse_request(isolate(busy, key="iso-2")), clock)
    assert committed.view.state == "DISPATCH_COMMITTED" and committed.ticket is not None
    held = admit(
        db, identity, parse_request(lift(busy, reason="false_positive", key="lift-6")), clock
    )
    assert held.view.state == "DENIED" and held.ticket is None
    with admin_engine.connect() as conn:
        reason = conn.execute(
            text(
                "SELECT payload->>'reason' FROM execbound.execution_events "
                "WHERE tenant_id=:t AND execution_id=:e AND to_state='DENIED'"
            ),
            {"t": identity.tenant_id, "e": held.view.execution_id},
        ).scalar_one()
    assert reason == "RESOURCE_BUSY"
