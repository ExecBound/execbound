# SPDX-License-Identifier: AGPL-3.0-only
"""External HTTP path shares the durable coordinator and separate provider."""

import secrets
from concurrent.futures import ThreadPoolExecutor

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import text
from test_protected_path import connector as connector
from test_protected_path import live_provider as live_provider
from test_protected_path import registry as registry
from test_protected_path import request
from test_protected_path import world as world

from execbound.app import create_app
from execbound.execution import decide_approval
from execbound.runtime import Runtime
from execbound.surfaces.tokens import TokenKeys


@pytest.fixture
def runtime(db, world, connector):
    keys = TokenKeys("pending-v1", {"pending-v1": secrets.token_bytes(32)})
    return Runtime(db, [connector], clock=world["clock"], keys=keys)


@pytest.fixture
def api(db, runtime, seeded):
    with TestClient(create_app(db, runtime=runtime)) as client:
        client.headers["Authorization"] = "Bearer " + seeded["tokens"][0]
        yield client


def test_http_approval_dispatch_retry_status(api, db, world, live_provider):
    body = request(world).model_dump(mode="json")
    first = api.post("/v1/execute", json=body)
    assert first.status_code == 202
    pending = first.json()
    assert pending["state"] == "PENDING_APPROVAL"
    from uuid import UUID

    decide_approval(db, world["human"], UUID(pending["approval_id"]), "APPROVE", world["clock"])
    executed = api.post("/v1/execute", json=body)
    assert executed.status_code == 200
    assert executed.json()["state"] == "EXECUTED"
    assert api.post("/v1/execute", json=body).json() == executed.json()
    assert api.get("/v1/executions/" + pending["execution_id"]).json() == executed.json()
    assert (
        live_provider.store.resource(world["identity"].tenant_id, world["canonical"]).mutation_count
        == 1
    )
    assert set(executed.json()) <= {
        "request_ref",
        "execution_id",
        "state",
        "plan_hash",
        "approval_id",
        "approval_state",
        "continuation",
    }


@pytest.mark.parametrize("extra", ["tenant_id", "approved", "connector_url", "inputResponses"])
def test_http_unknown_authority_fields_rejected_and_audited(api, world, admin_engine, extra):
    body = request(world).model_dump(mode="json")
    body[extra] = "untrusted"
    response = api.post("/v1/execute", json=body)
    assert response.status_code == 400
    with admin_engine.connect() as conn:
        assert conn.execute(text("SELECT count(*) FROM execbound.executions")).scalar_one() == 0
        assert (
            conn.execute(
                text("SELECT count(*) FROM execbound.audit_events WHERE kind='execution.rejected'")
            ).scalar_one()
            > 0
        )


@pytest.mark.parametrize("case", ["duplicate", "oversize", "query", "tenant_header", "compressed"])
def test_http_wire_rejects_before_admission(api, world, admin_engine, case):
    raw = request(world).model_dump_json()
    path, headers = "/v1/execute", {"Content-Type": "application/json"}
    if case == "duplicate":
        raw = raw[:-1] + ',"idempotency_key":"override"}'
    elif case == "oversize":
        raw = " " * 17000 + raw
    elif case == "query":
        path += "?tenant_id=override"
    elif case == "tenant_header":
        headers["x-tenant-id"] = "override"
    elif case == "compressed":
        headers["content-encoding"] = "gzip"
    response = api.post(path, content=raw, headers=headers)
    assert response.status_code == 400
    with admin_engine.connect() as conn:
        assert conn.execute(text("SELECT count(*) FROM execbound.executions")).scalar_one() == 0


def test_http_foreign_status_and_bad_identity_are_opaque(api, world, seeded):
    pending = api.post("/v1/execute", json=request(world).model_dump(mode="json")).json()
    api.headers["Authorization"] = "Bearer " + seeded["tokens"][1]
    assert api.get("/v1/executions/" + pending["execution_id"]).status_code == 404
    api.headers["Authorization"] = "Bearer invalid"
    assert api.post("/v1/execute", json={}).status_code == 401


def test_http_concurrent_retry_sends_once(api, world, admin_engine, live_provider):
    with admin_engine.begin() as conn:
        conn.execute(
            text("UPDATE execbound.resources SET environment='development' WHERE resource_id=:r"),
            {"r": world["target"]},
        )
    body = request(world).model_dump(mode="json")
    with ThreadPoolExecutor(max_workers=2) as pool:
        responses = list(pool.map(lambda _: api.post("/v1/execute", json=body), range(2)))
    assert all(r.status_code in {200, 202} for r in responses)
    assert len({r.json()["execution_id"] for r in responses}) == 1
    assert (
        live_provider.store.resource(world["identity"].tenant_id, world["canonical"]).mutation_count
        == 1
    )


def test_missing_config_prevents_reservation(db, world, admin_engine):
    from execbound.execution.models import ExecutionError

    runtime = Runtime(db, [], clock=world["clock"])
    with pytest.raises(ExecutionError, match="Execution unavailable"):
        runtime.execute(world["identity"], request(world).model_dump_json().encode())
    with admin_engine.connect() as conn:
        assert conn.execute(text("SELECT count(*) FROM execbound.executions")).scalar_one() == 0


def test_http_continuation_is_scoped_status_metadata(api, world):
    from datetime import timedelta

    result = api.post("/v1/execute", json=request(world).model_dump(mode="json")).json()
    token = result["continuation"]
    path = "/v1/executions/" + result["execution_id"]
    assert api.get(path, headers={"X-Execution-Continuation": token}).status_code == 202
    assert api.get(path, headers={"X-Execution-Continuation": token + "0"}).status_code == 400
    world["clock"].value += timedelta(seconds=121)
    assert api.get(path, headers={"X-Execution-Continuation": token}).status_code == 400


def test_execute_keeps_token_claims_and_identical_status_bytes(api, db, world, live_provider):
    """An ordinary execution gets a request label, never an external execution grant.

    The checkpoint object and its act grant are added by the presenter for a Gate
    admission alone. The additive request reference is present on every admitted record,
    but a checkpoint grant reaching an ordinary execution or status read fails here.

    The continuation carries a fresh nonce on every answer, so the token's own bytes are
    checked where they can be: its signed claims must keep exactly the members they had,
    which keeps every continuation issued before the Gate checkpoint existed valid. An
    operation identifier reaching a status token, by losing its ``exclude_if`` or by being set
    on another audience, changes those bytes and fails here.
    """
    import base64
    import json
    from uuid import UUID

    body = request(world).model_dump(mode="json")
    pending = api.post("/v1/execute", json=body).json()
    encoded = pending["continuation"].split(".")[0]
    claims = json.loads(base64.urlsafe_b64decode(encoded + "=" * (-len(encoded) % 4)))["claims"]
    assert set(claims) == {
        "tenant_id",
        "principal_id",
        "credential_id",
        "audience",
        "execution_id",
        "approval_id",
        "plan_hash",
        "expires_at",
        "nonce",
    }
    assert set(pending) == {
        "request_ref",
        "execution_id",
        "state",
        "plan_hash",
        "approval_id",
        "approval_state",
        "continuation",
    }
    assert (pending["state"], pending["approval_state"]) == ("PENDING_APPROVAL", "PENDING")
    assert pending["request_ref"] == "EB-1"
    decide_approval(db, world["human"], UUID(pending["approval_id"]), "APPROVE", world["clock"])
    executed = api.post("/v1/execute", json=body)
    assert executed.json() == {
        "request_ref": pending["request_ref"],
        "execution_id": pending["execution_id"],
        "state": "EXECUTED",
        "plan_hash": pending["plan_hash"],
        "approval_id": pending["approval_id"],
        "approval_state": "CONSUMED",
    }
    assert api.get("/v1/executions/" + pending["execution_id"]).content == executed.content
