# SPDX-License-Identifier: AGPL-3.0-only
"""Real HTTP MCP transport; raw security validation precedes SDK decoding."""

import asyncio
import json
import socket
import threading
import time

import httpx2
import pytest
import uvicorn
from mcp import Client
from mcp.client.streamable_http import streamable_http_client
from test_runtime import connector as connector
from test_runtime import live_provider as live_provider
from test_runtime import registry as registry
from test_runtime import request
from test_runtime import runtime as runtime
from test_runtime import world as world
from test_structured_logging import captured as captured
from test_structured_logging import events

from execbound.app import create_app
from execbound.surfaces.mcp import TOOLS as mcp_tools
from execbound.surfaces.mcp import validate_envelope


def test_advertised_execute_schema_resolves_its_references():
    import jsonschema

    from execbound.surfaces.mcp import EXECUTE_SCHEMA

    jsonschema.validate(
        {
            "request": {
                "operation_ref": "isolate",
                "target": {"kind": "provider_id", "value": "device-01"},
                "arguments": {},
                "idempotency_key": "one",
            }
        },
        EXECUTE_SCHEMA,
    )
    # The model-driven alternative (#251): the ticket instead of a key, described beside it.
    jsonschema.validate(
        {
            "request": {
                "operation_ref": "isolate",
                "target": {"kind": "provider_id", "value": "device-01"},
                "arguments": {},
                "reference": "INC-4711",
            }
        },
        EXECUTE_SCHEMA,
    )
    properties = EXECUTE_SCHEMA["$defs"]["ActionRequest"]["properties"]
    assert "reference" in properties and "derived" in properties["reference"]["description"]
    assert "idempotency_key" not in EXECUTE_SCHEMA["$defs"]["ActionRequest"].get("required", [])
    (execute,) = [tool for tool in mcp_tools if tool.name == "execute"]
    assert execute.description is not None and "Pass reference" in execute.description
    assert "never change the reference or the key" in execute.description


def test_the_execute_tool_says_a_grant_is_neither_an_execution_nor_an_approval():
    """`docs/CHECKPOINT.md` ("The workflow contract") says a grant is neither an execution nor
    an approval, and the `execute` tool description says exactly this.

    An agent reading a 202 with a checkpoint object has been told the budget is charged
    and the target claimed, and nothing was sent; the two things that answer looks like
    are an execution and a pending approval, so the description names both. The live
    listing below asserts that these are the objects a client actually receives.
    """
    from execbound.surfaces.mcp import TOOLS

    (execute,) = [tool for tool in TOOLS if tool.name == "execute"]
    assert execute.description is not None
    assert "neither an execution nor an approval" in execute.description
    assert "A pending approval is not execution" in execute.description


@pytest.fixture
def gateway(db, runtime):
    app = create_app(db, runtime=runtime)
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        port = sock.getsockname()[1]
        server = uvicorn.Server(uvicorn.Config(app, log_level="critical", access_log=False))
        thread = threading.Thread(target=server.run, kwargs={"sockets": [sock]}, daemon=True)
        thread.start()
        deadline = time.monotonic() + 10
        while not server.started and time.monotonic() < deadline:
            time.sleep(0.02)
        assert server.started
        try:
            yield f"http://127.0.0.1:{port}"
        finally:
            server.should_exit = True
            thread.join(timeout=10)
            assert not thread.is_alive()


def test_current_mcp_pending_identity_switch_and_http_retry(
    gateway, world, seeded, db, live_provider
):
    from uuid import UUID

    import httpx

    from execbound.execution import decide_approval

    async def check():
        async with httpx2.AsyncClient(
            headers={"Authorization": "Bearer " + seeded["tokens"][0]}, trust_env=False
        ) as http:
            async with Client(
                streamable_http_client(gateway + "/mcp/", http_client=http)
            ) as client:
                listed = await client.list_tools()
                assert {tool.name for tool in listed.tools} == {
                    "execute",
                    "execution_status",
                    "list_actions",
                }
                # What a client is told, over the real transport, is exactly what the
                # module advertises, so the description test above is about this listing
                # and not about a constant nothing serves.
                assert {(tool.name, tool.description) for tool in listed.tools} == {
                    (tool.name, tool.description) for tool in mcp_tools
                }
                result = await client.call_tool(
                    "execute", {"request": request(world).model_dump(mode="json")}
                )
                assert not result.is_error
                pending = result.structured_content
                assert pending["state"] == "PENDING_APPROVAL"
                http.headers["Authorization"] = "Bearer " + seeded["tokens"][1]
                foreign = await client.call_tool(
                    "execution_status", {"execution_id": pending["execution_id"]}
                )
                assert foreign.is_error and foreign.structured_content["code"] == "NOT_FOUND"
                http.headers["Authorization"] = "Bearer " + seeded["tokens"][0]
                decide_approval(
                    db, world["human"], UUID(pending["approval_id"]), "APPROVE", world["clock"]
                )
                with httpx.Client(trust_env=False) as rest:
                    response = rest.post(
                        gateway + "/v1/execute",
                        json=request(world).model_dump(mode="json"),
                        headers={"Authorization": "Bearer " + seeded["tokens"][0]},
                    )
                    assert response.json()["state"] == "EXECUTED"
                retried = await client.call_tool(
                    "execute", {"request": request(world).model_dump(mode="json")}
                )
                assert retried.structured_content["state"] == "EXECUTED"
                assert retried.structured_content["execution_id"] == pending["execution_id"]
                assert client.protocol_version == "2026-07-28"

    asyncio.run(check())
    assert (
        live_provider.store.resource(world["identity"].tenant_id, world["canonical"]).mutation_count
        == 1
    )


def test_the_same_reference_over_http_and_mcp_is_one_intent(
    gateway, world, seeded, db, live_provider
):
    """A Python client and an MCP host given the same ticket land on the same intent, so a
    retry through either path progresses it (#251)."""
    import httpx

    body = request(world).model_dump(mode="json")
    del body["idempotency_key"]
    body["reference"] = "INC-4711 / step 2"

    async def check():
        with httpx.Client(trust_env=False) as rest:
            first = rest.post(
                gateway + "/v1/execute",
                json=body,
                headers={"Authorization": "Bearer " + seeded["tokens"][0]},
            )
            assert first.status_code == 202, first.text
            assert first.json()["state"] == "PENDING_APPROVAL"
        async with httpx2.AsyncClient(
            headers={"Authorization": "Bearer " + seeded["tokens"][0]}, trust_env=False
        ) as http:
            async with Client(
                streamable_http_client(gateway + "/mcp/", http_client=http)
            ) as client:
                again = await client.call_tool("execute", {"request": body})
                assert not again.is_error
                assert again.structured_content["execution_id"] == first.json()["execution_id"]
                both = await client.call_tool(
                    "execute", {"request": {**body, "idempotency_key": "also"}}
                )
                assert both.is_error and both.structured_content["code"] == "INVALID_REQUEST"

    asyncio.run(check())


@pytest.mark.parametrize(
    "raw",
    [
        b'{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"execute","arguments":{},"inputResponses":[]}}',
        b'{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"execute","arguments":{"request":{"approved":true,"approved":false}}}}',
        b'{"jsonrpc":"2.0","id":true,"method":"tools/list"}',
        # `arguments` may be left out, but when it is sent it is an object.
        b'{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"list_actions","arguments":null}}',
        b'{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"list_actions","arguments":[]}}',
        b'{"jsonrpc":"2.0","id":1,"method":"tools/list","tenant_id":"other"}',
        b"[]",
    ],
)
def test_raw_mcp_invalid_envelope(raw):
    with pytest.raises(ValueError):
        validate_envelope(raw)


def test_raw_mcp_a_tool_call_may_leave_its_arguments_out():
    raw = b'{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"list_actions"}}'
    assert validate_envelope(raw)["params"] == {"name": "list_actions"}


def test_raw_mcp_tampering_rejected_before_decode(gateway, world, seeded, admin_engine):
    import httpx
    from sqlalchemy import text

    rpc = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {
            "name": "execute",
            "arguments": {"request": request(world).model_dump(mode="json")},
        },
    }
    raw = json.dumps(rpc)
    raw = raw.replace('"idempotency_key":', '"idempotency_key":"other","idempotency_key":')
    response = httpx.post(
        gateway + "/mcp/",
        content=raw,
        headers={
            "Authorization": "Bearer " + seeded["tokens"][0],
            "Content-Type": "application/json",
            "Accept": "application/json, text/event-stream",
            "MCP-Protocol-Version": "2026-07-28",
        },
        trust_env=False,
    )
    assert response.status_code == 400
    with admin_engine.connect() as conn:
        assert conn.execute(text("SELECT count(*) FROM execbound.executions")).scalar_one() == 0


def test_mcp_rejects_nested_arguments_exactly_as_http_does(gateway, world, seeded, admin_engine):
    import httpx
    from sqlalchemy import text

    # Arguments are scalars only. The MCP adapter must answer the same bounded error as
    # the HTTP surface, with no diagnostic and no execution row behind it.
    body = request(world).model_dump(mode="json")
    body["arguments"] = {"reason": {"nested": True}}

    async def check():
        async with httpx2.AsyncClient(
            headers={"Authorization": "Bearer " + seeded["tokens"][0]}, trust_env=False
        ) as http:
            async with Client(
                streamable_http_client(gateway + "/mcp/", http_client=http)
            ) as client:
                return await client.call_tool("execute", {"request": body})

    result = asyncio.run(check())
    with httpx.Client(trust_env=False) as rest:
        response = rest.post(
            gateway + "/v1/execute",
            json=body,
            headers={"Authorization": "Bearer " + seeded["tokens"][0]},
        )
    assert response.status_code == 400
    assert result.is_error
    assert result.structured_content == response.json()
    assert result.structured_content == {
        "detail": "Execution unavailable",
        "code": "INVALID_REQUEST",
    }
    with admin_engine.connect() as conn:
        assert conn.execute(text("SELECT count(*) FROM execbound.executions")).scalar_one() == 0


def test_actual_maintained_mcp_client(
    gateway, world, seeded, admin_engine, live_provider, captured
):
    import os
    import subprocess
    import sys

    from sqlalchemy import text

    # The older SDK executes an autonomous action, retries it, then changes
    # identity while retaining its tool list. Count effects in the provider DB.
    with admin_engine.begin() as conn:
        conn.execute(text("UPDATE execbound.resources SET environment='development'"))
    result = subprocess.run(
        [sys.executable, "tests/mcp_legacy_probe.py"],
        input=json.dumps(
            {
                "url": gateway + "/mcp/",
                "token": seeded["tokens"][0],
                "other_token": seeded["tokens"][1],
                "request": request(world).model_dump(mode="json"),
            }
        ),
        capture_output=True,
        text=True,
        timeout=30,
        creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0,
    )
    assert result.returncode == 0, "Older MCP compatibility probe failed"
    value = json.loads(result.stdout)
    assert value["protocol"] == "2025-11-25"
    assert set(value["tools"]) == {"execute", "execution_status", "list_actions"}
    # The older revision's calls are logged with the revision they carried (#251).
    calls = events(captured, "mcp.call")
    assert calls and {call["protocol_version"] for call in calls} == {"2025-11-25"}
    assert {call["tool"] for call in calls} <= {"execute", "execution_status"}
    assert value["first"]["state"] == "EXECUTED"
    assert value["retry"] == value["first"]
    assert value["foreign_error"] and value["foreign"]["code"] == "NOT_FOUND"
    assert (
        live_provider.store.resource(world["identity"].tenant_id, world["canonical"]).mutation_count
        == 1
    )


def test_http_mcp_concurrent_tenant_budget(gateway, db, world, seeded, admin_engine, live_provider):
    from concurrent.futures import ThreadPoolExecutor
    from uuid import UUID

    import httpx
    from sqlalchemy import text
    from test_execution import activate, targets

    from execbound.policy.models import LimitRule

    activate(
        db,
        world,
        limits=(
            LimitRule(
                rule_id="shared-cap",
                action="endpoint.isolate",
                scope="tenant",
                window_seconds=900,
                max_targets=1,
                budget="total",
                on_exceed="DENY",
            ),
        ),
    )
    requests = targets(admin_engine, world, 2)
    canonical_ids = []
    with admin_engine.connect() as conn:
        for request in requests:
            canonical = conn.execute(
                text(
                    "SELECT canonical_target_id FROM execbound.resource_identities "
                    "WHERE resource_id=:r"
                ),
                {"r": UUID(request.target.value)},
            ).scalar_one()
            canonical_ids.append(canonical)
            live_provider.store.provision_resource(world["identity"].tenant_id, canonical, "v1")
            live_provider.store.provision_representation(
                world["identity"].tenant_id, world["account"], request.target.value, canonical
            )

    def call(index):
        headers = {"Authorization": "Bearer " + seeded["tokens"][0]}
        with httpx.Client(trust_env=False, timeout=15) as client:
            if index == 0:
                return client.post(
                    gateway + "/v1/execute",
                    json=requests[index].model_dump(mode="json"),
                    headers=headers,
                ).json()["state"]
            headers.update(
                {
                    "MCP-Protocol-Version": "2026-07-28",
                    "MCP-Method": "tools/call",
                    "MCP-Name": "execute",
                    "Accept": "application/json, text/event-stream",
                }
            )
            response = client.post(
                gateway + "/mcp/",
                json={
                    "jsonrpc": "2.0",
                    "id": "budget",
                    "method": "tools/call",
                    "params": {
                        "_meta": {
                            "io.modelcontextprotocol/protocolVersion": "2026-07-28",
                            "io.modelcontextprotocol/clientCapabilities": {},
                        },
                        "name": "execute",
                        "arguments": {"request": requests[index].model_dump(mode="json")},
                    },
                },
                headers=headers,
            )
            return response.json()["result"]["structuredContent"]["state"]

    with ThreadPoolExecutor(max_workers=2) as pool:
        assert sorted(pool.map(call, range(2))) == ["DENIED", "EXECUTED"]
    assert (
        sum(
            live_provider.store.resource(world["identity"].tenant_id, target).mutation_count
            for target in canonical_ids
        )
        == 1
    )
