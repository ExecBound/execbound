# SPDX-License-Identifier: AGPL-3.0-only
"""The MCP example and the client's MCP helper behave correctly against a real gateway, and
a stand-in MCP server answers what the gateway never would where that is the point; the HTTP
client is covered by tests/test_client_package.py."""

import asyncio
import importlib
import json
import socket
import sys
import threading
import time
from contextlib import asynccontextmanager, contextmanager
from datetime import timedelta
from pathlib import Path

import pytest
import uvicorn
from execbound_client import mcp as client_mcp
from execbound_client import summarize_listing
from mcp import types
from mcp.server import Server
from sqlalchemy import text
from starlette.applications import Starlette
from starlette.routing import Mount
from test_action_listing import LISTED_ISOLATE, archive_the_agents_space
from test_approval_deadline import deadline, long_facts
from test_mcp_surface import gateway as gateway
from test_runtime import connector as connector
from test_runtime import live_provider as live_provider
from test_runtime import registry as registry
from test_runtime import request
from test_runtime import runtime as runtime
from test_runtime import world as world

from execbound.execution import decide_approval

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "examples"))
mcp_agent = importlib.import_module("mcp_agent")


def approve_pending(db, world):
    """Record the human decision for the tenant's pending approval, once."""
    tenant = world["identity"].tenant_id
    with db.transaction(tenant) as conn:
        approval_id = conn.execute(
            text(
                "SELECT approval_id FROM execbound.approvals "
                "WHERE tenant_id=:t AND state='PENDING' ORDER BY created_at DESC LIMIT 1"
            ),
            {"t": tenant},
        ).scalar_one_or_none()
    if approval_id is not None:
        decide_approval(db, world["human"], approval_id, "APPROVE", world["clock"])
    return approval_id


def mutation_count(live_provider, world):
    return live_provider.store.resource(
        world["identity"].tenant_id, world["canonical"]
    ).mutation_count


def test_mcp_example_completes_the_same_flow_through_the_sdk(
    gateway, db, world, seeded, live_provider
):
    body = request(world).model_dump(mode="json")
    approvals = []

    async def after_poll(view):
        assert view["state"] == "PENDING_APPROVAL"
        if not approvals:
            approvals.append(await asyncio.to_thread(approve_pending, db, world))

    view = asyncio.run(
        mcp_agent.run_action(
            gateway, seeded["tokens"][0], body, poll_seconds=0.01, after_poll=after_poll
        )
    )
    assert view["state"] == "EXECUTED" and approvals[0] is not None
    assert mutation_count(live_provider, world) == 1
    body["operation_ref"] = "Not-A-Valid-Reference"
    with pytest.raises(mcp_agent.McpRefused) as refused:
        asyncio.run(mcp_agent.run_action(gateway, seeded["tokens"][0], body))
    assert refused.value.tool == "execute" and refused.value.code == "INVALID_REQUEST"


def test_mcp_example_keeps_polling_past_a_void_continuation(
    gateway, db, world, seeded, live_provider
):
    """#213: under a long tenant deadline the status continuation dies at two minutes; the
    example resends the same intent and keeps polling instead of handing back a pending view."""
    long_facts(db, world)
    deadline(db, world, 900)
    body = request(world).model_dump(mode="json")
    steps = []

    async def after_poll(view):
        assert view["state"] == "PENDING_APPROVAL"
        if not steps:
            world["clock"].value += timedelta(seconds=121)
            steps.append("void")
        elif len(steps) == 1:
            steps.append(await asyncio.to_thread(approve_pending, db, world))

    view = asyncio.run(
        mcp_agent.run_action(
            gateway, seeded["tokens"][0], body, poll_seconds=0.01, after_poll=after_poll
        )
    )
    assert view["state"] == "EXECUTED" and steps[1] is not None
    assert mutation_count(live_provider, world) == 1


def test_the_mcp_helper_lists_the_actions_the_agents_space_offers(gateway, seeded):
    listing = asyncio.run(client_mcp.list_actions(gateway, seeded["tokens"][0]))
    # The gateway's own answer, the one GET /v1/actions gives; the model reads its summary.
    assert listing == {"actions": [LISTED_ISOLATE]}
    assert summarize_listing(listing) == {"outcome": "listed", "actions": [LISTED_ISOLATE]}


def test_the_mcp_helper_raises_a_refused_listing_with_its_code(
    gateway, seeded, db, world, admin_engine
):
    archive_the_agents_space(db, admin_engine, world)
    with pytest.raises(client_mcp.McpRefused) as refused:
        asyncio.run(client_mcp.list_actions(gateway, seeded["tokens"][0]))
    assert (refused.value.tool, refused.value.code) == ("list_actions", "SPACE_ARCHIVED")


def demonstration(private, origin, token):
    """A demonstration's private directory as the example reads it: the gateway's port and the
    agent's credential under one tenant, with no target, since a listing names none."""
    (private / "fixture.json").write_text(
        json.dumps(
            {
                "ports": {"gateway": int(origin.rsplit(":", 1)[1])},
                "tenants": [{"tenant_id": "tenant-0", "targets": []}],
            }
        ),
        encoding="utf-8",
    )
    (private / "credentials.json").write_text(
        json.dumps({"tenant-0": [{"label": "agent-0", "token": token}]}), encoding="utf-8"
    )
    return str(private)


def test_mcp_example_lists_the_actions_the_agents_space_offers(gateway, seeded, tmp_path, capsys):
    private = demonstration(tmp_path, gateway, seeded["tokens"][0])
    assert mcp_agent.main(["--private", private, "--list"]) == 0
    # The gateway's listing as sent, as the action path prints the view as sent.
    assert json.loads(capsys.readouterr().out) == {"actions": [LISTED_ISOLATE]}


def test_mcp_example_prints_a_refused_listing_with_its_code(
    gateway, seeded, db, world, admin_engine, tmp_path, capsys
):
    archive_the_agents_space(db, admin_engine, world)
    private = demonstration(tmp_path, gateway, seeded["tokens"][0])
    assert mcp_agent.main(["--private", private, "--list"]) == 2
    assert json.loads(capsys.readouterr().out) == {
        "outcome": "refused",
        "tool": "list_actions",
        "code": "SPACE_ARCHIVED",
    }


@pytest.mark.parametrize(
    "argv",
    [
        ["--list", "--action", "endpoint.isolate"],
        ["--list", "--target", "workstation-01", "--key", "ticket-4712"],
        ["--target", "workstation-01", "--action", "endpoint.isolate"],
        [],
    ],
    ids=["list-and-act", "list-with-a-target", "act-without-a-key", "neither"],
)
def test_mcp_example_either_lists_or_acts_on_one_whole_action(argv, tmp_path, capsys):
    with pytest.raises(SystemExit) as stopped:
        mcp_agent.main(["--private", str(tmp_path), *argv])
    # A usage error, before any file is read or any call is made.
    assert stopped.value.code == 2
    assert "usage:" in capsys.readouterr().err


CREDENTIAL = "eb1.t.c.s"  # nosec B105 - a placeholder no gateway issued
GATEWAY_TOOLS = ("execute", "execution_status", "list_actions")


@contextmanager
def stand_in(tools, answer):
    """A stand-in MCP server that offers `tools` and answers every call with `answer` as its
    structured content, recording each call's tool, arguments and credential."""
    seen = []

    async def list_tools(ctx, params):
        offered = [types.Tool(name=name, input_schema={"type": "object"}) for name in tools]
        return types.ListToolsResult(tools=offered)

    async def call_tool(ctx, params):
        seen.append((params.name, params.arguments, ctx.request.headers.get("authorization")))
        return types.CallToolResult(
            content=[types.TextContent(type="text", text=json.dumps(answer))],
            structured_content=answer,
            is_error=False,
        )

    server = Server("stand-in", on_list_tools=list_tools, on_call_tool=call_tool)
    mounted = server.streamable_http_app(
        streamable_http_path="/", stateless_http=True, json_response=True
    )

    @asynccontextmanager
    async def lifespan(app):
        async with server.session_manager.run():
            yield

    app = Starlette(routes=[Mount("/mcp", app=mounted)], lifespan=lifespan)
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        port = sock.getsockname()[1]
        served = uvicorn.Server(uvicorn.Config(app, log_level="critical", access_log=False))
        thread = threading.Thread(target=served.run, kwargs={"sockets": [sock]}, daemon=True)
        thread.start()
        deadline = time.monotonic() + 10
        while not served.started and time.monotonic() < deadline:
            time.sleep(0.02)
        assert served.started
        try:
            yield f"http://127.0.0.1:{port}", seen
        finally:
            served.should_exit = True
            thread.join(timeout=10)
            assert not thread.is_alive()


def test_the_mcp_helper_returns_the_listing_as_sent_and_sends_only_the_credential():
    later = {"actions": [{**LISTED_ISOLATE, "note": "a field a later gateway adds"}], "next": "x"}
    with stand_in(GATEWAY_TOOLS, later) as (origin, seen):
        listing = asyncio.run(client_mcp.list_actions(origin, CREDENTIAL))
    # As run_action returns the view, unknown fields included; the summary drops them.
    assert listing == later
    assert summarize_listing(listing) == {"outcome": "listed", "actions": [LISTED_ISOLATE]}
    assert seen == [("list_actions", {}, "Bearer " + CREDENTIAL)]


NOT_A_LISTING = [
    None,
    {},
    {"actions": "endpoint.isolate"},
    {"actions": ["endpoint.isolate"]},
    {"actions": [{"action": "endpoint.isolate"}]},
    {"actions": [{"operation_ref": 1}]},
    {"actions": [{"operation_ref": "endpoint.isolate", "arguments": {}}]},
    {"actions": [{"operation_ref": "endpoint.isolate", "arguments": ["reason"]}]},
    {"execution_id": "00000000-0000-0000-0000-000000000000", "state": "EXECUTED"},
]


@pytest.mark.parametrize("answer", NOT_A_LISTING, ids=range(len(NOT_A_LISTING)))
def test_the_mcp_helper_refuses_an_answer_that_is_not_a_listing(answer):
    with stand_in(GATEWAY_TOOLS, answer) as (origin, seen):
        with pytest.raises(client_mcp.McpRefused) as refused:
            asyncio.run(client_mcp.list_actions(origin, CREDENTIAL))
    assert (refused.value.tool, refused.value.code) == ("list_actions", "UNEXPECTED_RESPONSE")
    assert len(seen) == 1


def test_the_mcp_helper_refuses_a_server_that_offers_no_listing():
    with stand_in(("execute", "execution_status"), {"actions": []}) as (origin, seen):
        with pytest.raises(client_mcp.McpRefused) as refused:
            asyncio.run(client_mcp.list_actions(origin, CREDENTIAL))
    assert (refused.value.tool, refused.value.code) == ("tools/list", "UNEXPECTED_TOOLS")
    assert seen == []
