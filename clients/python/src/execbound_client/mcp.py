# SPDX-License-Identifier: Apache-2.0
"""List the agent's actions and drive one through the gateway's MCP surface with the
official Python SDK.

Requires the ``mcp`` extra (``pip install "execbound-client[mcp]"``). The gateway exposes
three tools. ``list_actions`` here calls the tool of that name, which lists the actions the
agent's space offers; ``run_action`` drives one action with the other two, ``execute`` and
``execution_status``. Every call authenticates with the bearer credential, and client
metadata never establishes identity. A pending approval is polled through
``execution_status`` with the returned continuation, then ``execute`` is called again with
the same request to progress it. A continuation lasts two minutes; under a longer tenant
deadline the same resend renews it and polling continues.
"""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator, Awaitable, Callable, Iterator
from contextlib import asynccontextmanager
from typing import Any

import httpx2
from mcp import Client
from mcp.client.streamable_http import streamable_http_client

from ._core import PENDING_STATES, is_listing

Hook = Callable[[dict[str, Any]], Awaitable[None]]


class McpRefused(Exception):
    """A tool call the gateway refused, with the tool's name and the stable code."""

    def __init__(self, tool: str, code: str) -> None:
        self.tool, self.code = tool, code
        super().__init__(f"MCP tool {tool} refused: {code}")


async def _call(client: Client, name: str, arguments: dict[str, Any]) -> dict[str, Any]:
    result = await client.call_tool(name, arguments)
    payload: Any = result.structured_content
    if result.is_error or not isinstance(payload, dict) or "state" not in payload:
        code = payload.get("code") if isinstance(payload, dict) else None
        raise McpRefused(name, str(code or "UNKNOWN"))
    return payload


async def list_actions(origin: str, token: str) -> dict[str, Any]:
    """List the actions the agent's space offers: each ``operation_ref``, its arguments and
    the target kinds it accepts, and never a target. Returns the gateway's listing as sent,
    unknown fields included, as ``run_action`` returns its view; hand a model
    ``summarize_listing`` of it, which keeps only the fields the gateway defines. A refusal
    raises ``McpRefused`` with the stable code, and an answer that is not a listing raises it
    with ``UNEXPECTED_RESPONSE``. A listed action is not permission: every request is still
    decided."""
    try:
        return await _list(origin, token)
    except BaseExceptionGroup as group:
        refused = _refusal_in(group)
        if refused is None:
            raise
        raise refused from None


async def run_action(
    origin: str,
    token: str,
    request: dict[str, Any],
    *,
    approval_wait_seconds: float = 120.0,
    poll_seconds: float = 2.0,
    after_poll: Hook | None = None,
) -> dict[str, Any]:
    """Execute over MCP, wait for a decision if required, then progress the same intent."""
    try:
        return await _run(origin, token, request, approval_wait_seconds, poll_seconds, after_poll)
    except BaseExceptionGroup as group:
        refused = _refusal_in(group)
        if refused is None:
            raise
        raise refused from None


def _refusal_in(group: BaseExceptionGroup[BaseException]) -> McpRefused | None:
    """The SDK runs its transport in nested task groups, which wrap our refusal: the refusal
    when it is the group's one leaf, and otherwise nothing, so the group is raised as it is."""
    leaves = list(_leaves(group))
    if len(leaves) == 1 and isinstance(leaves[0], McpRefused):
        return leaves[0]
    return None


def _leaves(group: BaseExceptionGroup[BaseException]) -> Iterator[BaseException]:
    for exc in group.exceptions:
        if isinstance(exc, BaseExceptionGroup):
            yield from _leaves(exc)
        else:
            yield exc


@asynccontextmanager
async def _session(origin: str, token: str, needed: set[str]) -> AsyncIterator[Client]:
    """A client of the gateway's MCP surface that offers at least the `needed` tools."""
    async with httpx2.AsyncClient(
        headers={"Authorization": "Bearer " + token}, trust_env=False, timeout=10
    ) as http:
        async with Client(streamable_http_client(origin + "/mcp/", http_client=http)) as client:
            tools = {tool.name for tool in (await client.list_tools()).tools}
            if not needed <= tools:
                raise McpRefused("tools/list", "UNEXPECTED_TOOLS")
            yield client


async def _list(origin: str, token: str) -> dict[str, Any]:
    async with _session(origin, token, {"list_actions"}) as client:
        result = await client.call_tool("list_actions", {})
        listing: Any = result.structured_content
        if result.is_error:
            code = listing.get("code") if isinstance(listing, dict) else None
            raise McpRefused("list_actions", str(code or "UNKNOWN"))
        if not is_listing(listing):
            raise McpRefused("list_actions", "UNEXPECTED_RESPONSE")
        return listing


async def _run(
    origin: str,
    token: str,
    request: dict[str, Any],
    approval_wait_seconds: float,
    poll_seconds: float,
    after_poll: Hook | None,
) -> dict[str, Any]:
    async with _session(origin, token, {"execute", "execution_status"}) as client:
        view = await _call(client, "execute", {"request": request})
        loop = asyncio.get_running_loop()
        deadline = loop.time() + approval_wait_seconds
        while view["state"] in PENDING_STATES and loop.time() < deadline:
            await asyncio.sleep(poll_seconds)
            if after_poll is not None:
                await after_poll(view)
            arguments: dict[str, Any] = {"execution_id": view["execution_id"]}
            if view.get("continuation"):
                arguments["continuation"] = view["continuation"]
            try:
                latest: dict[str, Any] | None = await _call(client, "execution_status", arguments)
            except McpRefused as refused:
                if refused.code != "INVALID_CONTINUATION":
                    raise
                # The continuation is void: decided, expired, or simply two minutes old
                # under a longer tenant deadline. Resending the same intent tells which.
                latest = None
            if (
                latest is not None
                and latest["state"] in PENDING_STATES
                and latest.get("approval_state") == "PENDING"
            ):
                continue
            view = await _call(client, "execute", {"request": request})
            # Still pending under the same intent means a renewed continuation; the
            # loop keeps polling until the caller's wait runs out.
        return view
