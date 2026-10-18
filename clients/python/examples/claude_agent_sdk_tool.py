# SPDX-License-Identifier: Apache-2.0
"""Expose ExecBound as tools to an agent built on the Claude Agent SDK.

The SDK hosts tools on an in-process MCP server. The model calls ``execbound_list_actions``
to learn the actions its space offers, each ``operation_ref`` with its arguments and the
target kinds it accepts, then ``execbound_action`` with the action, the target and the
ticket it is working, and reads the JSON summary back. A listed action is not permission:
every request is still decided. The SDK runs the tools on the agent's event loop, so they
use the asynchronous client: a held action waits for a person without stopping everything
else the agent is doing. Requires ``pip install claude-agent-sdk execbound-client`` and the
two environment variables ``EXECBOUND_URL`` and ``EXECBOUND_CREDENTIAL`` (or
``EXECBOUND_CREDENTIAL_FILE``).
"""

from typing import Any

from claude_agent_sdk import create_sdk_mcp_server, tool
from execbound_client import (
    AsyncExecBoundClient,
    execbound_action_async,
    execbound_list_actions_async,
    intent_key,
)

client = AsyncExecBoundClient.from_environment()
SCHEMA = {
    "operation_ref": str,
    "target_kind": str,
    "target_value": str,
    "ticket": str,
    "incident_id": str,
}


@tool(
    "execbound_list_actions",
    "List the actions your space offers: each operation_ref, its arguments and the target "
    "kinds it accepts. A listed action is not permission; targets are never listed.",
    {},
)
async def execbound_list_tool(args: dict[str, Any]) -> dict[str, Any]:
    return {"content": [{"type": "text", "text": await execbound_list_actions_async(client)}]}


@tool(
    "execbound_action",
    "Request a consequential action; returns the decision. "
    "On a denial, stop and give the person its request_ref.",
    SCHEMA,
)
async def execbound_tool(args: dict[str, Any]) -> dict[str, Any]:
    key = intent_key(
        args["operation_ref"], args["target_kind"], args["target_value"], args["ticket"]
    )
    summary = await execbound_action_async(
        client,
        args["operation_ref"],
        args["target_kind"],
        args["target_value"],
        key,
        incident_id=args.get("incident_id"),
    )
    return {"content": [{"type": "text", "text": summary}]}


server = create_sdk_mcp_server(name="execbound", tools=[execbound_list_tool, execbound_tool])
