# SPDX-License-Identifier: AGPL-3.0-only
"""Signing and evidence key rotation: KR1 to KR7 on real PostgreSQL and a live provider."""

import base64
import json
import os
import secrets
import sys

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import text
from test_execution import registry as registry
from test_execution import request
from test_execution import world as world
from test_human_surface import credential, form_values
from test_human_surface import human_app as human_app
from test_human_surface import human_client as human_client
from test_human_surface import human_config as human_config
from test_human_surface import pending as pending_human
from test_protected_path import connector as connector
from test_protected_path import live_provider as live_provider
from test_runtime import api as api
from test_runtime import runtime as runtime

from execbound.app import create_app
from execbound.cli import main
from execbound.execution import (
    admit,
    decide_approval,
    mark_indeterminate,
    reconcile,
    record_outcome,
    take_dispatch,
)
from execbound.execution.models import ExecutionError
from execbound.provider.models import provider_command
from execbound.provider.verifiers import verifier_for
from execbound.rotation import rotation_readiness
from execbound.surfaces.console import packaged_edition
from execbound.surfaces.tokens import TokenKeys

ORIGIN = {"Origin": "http://127.0.0.1"}


def key_id_of(token):
    header = token.split(".")[0]
    payload = base64.urlsafe_b64decode(header + "=" * (-len(header) % 4))
    return json.loads(payload)["key_id"]


def autonomous(engine):
    with engine.begin() as conn:
        conn.execute(text("UPDATE execbound.resources SET environment='development'"))


def evidence_ring(runtime, world, connector, **extra):
    return {
        (world["identity"].tenant_id, world["account"]): {**connector.config.evidence_keys, **extra}
    }


def test_kr1_kr2_outstanding_continuations_survive_rotation_until_retirement(
    api, runtime, world, connector
):
    first = api.post("/v1/execute", json=request(world).model_dump(mode="json")).json()
    assert first["state"] == "PENDING_APPROVAL"
    assert key_id_of(first["continuation"]) == "pending-v1"
    path = "/v1/executions/" + first["execution_id"]
    old = {"X-Execution-Continuation": first["continuation"]}
    v1, v2 = runtime.keys.keys["pending-v1"], secrets.token_bytes(32)
    runtime.rotate(
        TokenKeys("pending-v2", {"pending-v1": v1, "pending-v2": v2}),
        evidence_ring(runtime, world, connector),
    )
    assert api.get(path, headers=old).status_code == 202
    second = api.post(
        "/v1/execute", json=request(world, idempotency_key="retry-2").model_dump(mode="json")
    ).json()
    assert second["execution_id"] == first["execution_id"]
    assert key_id_of(second["continuation"]) == "pending-v2"
    new = {"X-Execution-Continuation": second["continuation"]}
    # Retiring the old key is the operator's decision; anything signed with it stops verifying.
    runtime.rotate(
        TokenKeys("pending-v2", {"pending-v2": v2}), evidence_ring(runtime, world, connector)
    )
    assert api.get(path, headers=old).status_code == 400
    assert api.get(path, headers=new).status_code == 202


def test_kr3_evidence_keys_rotate_without_losing_settlement(
    db, world, admin_engine, connector, live_provider
):
    autonomous(admin_engine)
    original = dict(connector.config.evidence_keys)
    successor = secrets.token_bytes(32)
    admission = admit(db, world["identity"], request(world), world["clock"])
    command = take_dispatch(db, admission.ticket, world["clock"])
    evidence = connector.dispatch(provider_command(command))
    # A successor key joins the ring before the provider starts using it: the proof the
    # provider just signed with the current key still verifies.
    connector.rotate_keys({**original, "journal-v2": successor})
    assert verifier_for(connector.config).verify(command, evidence).outcome == "EXECUTED"
    # Retiring the provider's current key too early leaves the operation uncertain, not lost.
    connector.rotate_keys({"journal-v2": successor})
    with pytest.raises(ExecutionError) as refused:
        record_outcome(
            db, admission.ticket, evidence, verifier_for(connector.config), world["clock"]
        )
    assert refused.value.code == "INVALID_EVIDENCE"
    assert mark_indeterminate(db, admission.ticket, world["clock"]).state == "INDETERMINATE"
    connector.rotate_keys({**original, "journal-v2": successor})
    recovered = reconcile(
        db,
        world["admin"],
        admission.view.execution_id,
        reason="Verification key restored after premature retirement",
        evidence=evidence,
        verifier=verifier_for(connector.config),
        clock=world["clock"],
    )
    assert recovered.state == "EXECUTED"
    resource = live_provider.store.resource(world["identity"].tenant_id, world["canonical"])
    assert resource.mutation_count == 1


def test_kr4_rotation_keeps_key_independence_and_covers_every_account(runtime, world, connector):
    tenant, account = world["identity"].tenant_id, world["account"]
    before, original = runtime.keys, dict(connector.config.evidence_keys)
    provider_key = next(iter(original.values()))
    fresh = TokenKeys("pending-v2", {"pending-v2": secrets.token_bytes(32)})
    with pytest.raises(ValueError):
        runtime.rotate(TokenKeys("shared", {"shared": provider_key}), {(tenant, account): original})
    with pytest.raises(ValueError):
        runtime.rotate(fresh, {})
    with pytest.raises(ValueError):
        runtime.rotate(fresh, {(tenant, account): {"weak": b"short"}})
    with pytest.raises(ValueError):
        runtime.rotate(
            fresh, {(tenant, account): original, (tenant, account.int and tenant): original}
        )
    assert runtime.keys is before and dict(connector.config.evidence_keys) == original


def test_kr5_kr6_private_configuration_reload_rotates_keys_and_refuses_other_changes(
    tmp_path, monkeypatch, world, seeded, live_provider
):
    tenant, account = world["identity"].tenant_id, world["account"]
    v1, v2 = secrets.token_bytes(32).hex(), secrets.token_bytes(32).hex()
    evidence = {name: key.hex() for name, key in live_provider.config.evidence_keys.items()}

    def configuration(active, keys, **changes):
        value = {
            "origin": "http://127.0.0.1:8000",
            "active_key_id": active,
            "continuation_keys": keys,
            "connectors": [
                {
                    "tenant_id": str(tenant),
                    "account_id": str(account),
                    "origin": live_provider.config.origin,
                    "dispatch_token": live_provider.config.dispatch_token,
                    "control_token": live_provider.config.control_token,
                    "evidence_keys": evidence,
                }
            ],
            "key_reload_seconds": 1,
        }
        value.update(changes)
        return json.dumps(value)

    both = {"continuation-v1": v1, "continuation-v2": v2}
    path = tmp_path / "private.json"
    path.write_text(configuration("continuation-v1", {"continuation-v1": v1}), encoding="utf-8")
    monkeypatch.setenv("EXECBOUND_RUNTIME_CONFIG", str(path))
    monkeypatch.setenv("DATABASE_URL", os.environ["TEST_DATABASE_URL"])
    app = create_app()
    with TestClient(app, base_url="http://127.0.0.1:8000") as client:
        headers = {"Authorization": "Bearer " + seeded["tokens"][0]}
        body = request(world).model_dump(mode="json")
        response = client.post("/v1/execute", json=body, headers=headers)
        assert response.status_code == 202, response.text
        first = response.json()
        assert first["state"] == "PENDING_APPROVAL"
        assert key_id_of(first["continuation"]) == "continuation-v1"
        status = "/v1/executions/" + first["execution_id"]
        old = {**headers, "X-Execution-Continuation": first["continuation"]}
        ready = client.get("/health/ready").json()
        assert ready["keys"] == "current" and ready["status"] == "ready"
        # A human surface also reports the console edition the packaged build names, where the
        # package carries one (#496); of the keys, readiness reports the state alone.
        assert ready.get("console") == packaged_edition()
        assert set(ready) - {"console"} == {"status", "keys", "version", "commit"}
        assert app.state.reload_keys().state == "current"

        path.write_text(configuration("continuation-v2", both), encoding="utf-8")
        outcome = app.state.reload_keys()
        assert outcome.state == "current" and outcome.rotated
        assert client.get(status, headers=old).status_code == 202
        retry = {**body, "idempotency_key": "retry-2"}
        second = client.post("/v1/execute", json=retry, headers=headers).json()
        assert key_id_of(second["continuation"]) == "continuation-v2"
        new = {**headers, "X-Execution-Continuation": second["continuation"]}

        # Only keys rotate at runtime; any other change needs a restart and is refused whole.
        path.write_text(
            configuration("continuation-v2", both, origin="http://127.0.0.1:9000"), encoding="utf-8"
        )
        outcome = app.state.reload_keys()
        assert (outcome.state, outcome.code) == ("refused", "CONFIGURATION_CHANGED")
        assert client.get("/health/ready").json()["keys"] == "refused"
        assert client.get(status, headers=old).status_code == 202
        path.write_text("{not json", encoding="utf-8")
        assert app.state.reload_keys().state == "failed"
        assert client.get("/health/ready").json()["keys"] == "failed"
        assert client.get(status, headers=new).status_code == 202

        path.write_text(configuration("continuation-v2", {"continuation-v2": v2}), encoding="utf-8")
        assert app.state.reload_keys().rotated
        assert client.get("/health/ready").json()["keys"] == "current"
        assert client.get(status, headers=old).status_code == 400
        assert client.get(status, headers=new).status_code == 202
        assert not app.state.reload_keys().rotated


def test_kr7_human_form_state_survives_continuation_key_rotation(
    human_client, runtime, world, human_config, live_provider
):
    view = pending_human(runtime, world)
    page = human_client.get(f"/approvals/{view.approval_id}/classic")
    path, values = form_values(page.text, "/decide")
    values["decision"] = "APPROVE"
    old_key = human_config.keys.keys["state-v1"]
    human_config.rotate(
        TokenKeys("state-v2", {"state-v1": old_key, "state-v2": secrets.token_bytes(32)})
    )
    assert human_client.post(path, data=values, headers=ORIGIN).status_code == 303
    assert human_config.keys.active_key_id == "state-v2"
    assert pending_human(runtime, world).state == "EXECUTED"


def test_kr8_rotation_readiness_lists_what_still_needs_the_current_keys(
    human_client, runtime, world, admin_engine, tmp_path, monkeypatch, capsys
):
    tenant, account = world["identity"].tenant_id, world["account"]
    idle = rotation_readiness(runtime.db, world["admin"], world["clock"])
    assert idle.unsettled == () and idle.latest_approval_expiry is None
    assert idle.latest_session_expiry is not None
    pending = pending_human(runtime, world)
    waiting = rotation_readiness(runtime.db, world["admin"], world["clock"])
    assert waiting.unsettled == () and waiting.latest_approval_expiry is not None
    decide_approval(runtime.db, world["human"], pending.approval_id, "APPROVE", world["clock"])
    committed = admit(runtime.db, world["identity"], request(world), world["clock"])
    assert committed.view.state == "DISPATCH_COMMITTED"
    held = rotation_readiness(runtime.db, world["admin"], world["clock"])
    assert held.unsettled == ((account, 1),) and held.latest_approval_expiry is None
    for actor in (world["identity"], world["human"]):
        with pytest.raises(ExecutionError) as refused:
            rotation_readiness(runtime.db, actor, world["clock"])
        assert refused.value.code == "INVALID_IDENTITY"
    monkeypatch.setenv("DATABASE_URL", os.environ["TEST_DATABASE_URL"])
    admin_file, human_file = tmp_path / "admin.token", tmp_path / "human.token"
    admin_file.write_text(credential(admin_engine, world["admin"]), encoding="utf-8")
    human_file.write_text(credential(admin_engine, world["human"]), encoding="utf-8")
    command = ["execbound", "rotation-readiness", "--tenant", str(tenant), "--credential-file"]
    monkeypatch.setattr(sys, "argv", [*command, str(admin_file)])
    main()
    printed = json.loads(capsys.readouterr().out)
    assert printed["unsettled"] == [{"account_id": str(account), "count": 1}]
    assert printed["latest_approval_expiry"] is None and printed["latest_session_expiry"]
    monkeypatch.setattr(sys, "argv", [*command, str(human_file)])
    with pytest.raises(SystemExit) as caught:
        main()
    assert caught.value.code == 2 and "INVALID_IDENTITY" in capsys.readouterr().err
