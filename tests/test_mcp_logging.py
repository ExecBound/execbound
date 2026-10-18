# SPDX-License-Identifier: AGPL-3.0-only
"""Every MCP tool call leaves one identifier-only record, so a trial can cite what the
server talked to: the tool, the protocol revision the request carried, and the client's
own name and version (#251). Never arguments, never results."""

import asyncio
import json

import httpx2
from mcp import Client, types
from mcp.client.streamable_http import streamable_http_client
from test_mcp_surface import gateway as gateway
from test_runtime import connector as connector
from test_runtime import live_provider as live_provider
from test_runtime import registry as registry
from test_runtime import request
from test_runtime import runtime as runtime
from test_runtime import world as world
from test_structured_logging import captured as captured
from test_structured_logging import events, records

from execbound import logging_schema


def test_an_mcp_call_is_logged_with_its_protocol_and_client_and_nothing_else(
    gateway, world, seeded, captured
):
    body = request(world).model_dump(mode="json")
    body["idempotency_key"] = "logged-1"

    async def check():
        async with httpx2.AsyncClient(
            headers={"Authorization": "Bearer " + seeded["tokens"][0]}, trust_env=False
        ) as http:
            client = Client(
                streamable_http_client(gateway + "/mcp/", http_client=http),
                client_info=types.Implementation(name="trial-host", version="9.9.9"),
            )
            async with client:
                await client.list_tools()
                result = await client.call_tool("execute", {"request": body})
                assert not result.is_error
                refused = await client.call_tool("execution_status", {"execution_id": "nope"})
                assert refused.is_error

    asyncio.run(check())
    calls = events(captured, "mcp.call")
    assert [call["tool"] for call in calls] == ["execute", "execution_status"]
    for call in calls:
        assert call["protocol_version"] == "2026-07-28"
        assert call["client_name"] == "trial-host" and call["client_version"] == "9.9.9"
        assert call["request_id"] and set(call) <= logging_schema.FIELDS
    stream = captured.getvalue()
    assert "logged-1" not in stream and "workstation" not in stream and "nope" not in stream
    assert json.dumps(body["target"]["value"]) not in stream
    for record in records(captured):
        assert record["event"] in logging_schema.EVENTS
