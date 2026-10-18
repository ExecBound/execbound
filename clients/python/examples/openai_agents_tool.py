# SPDX-License-Identifier: Apache-2.0
"""Expose ExecBound as function tools to an agent built on the OpenAI Agents SDK.

The agent lists the actions its space offers with ``execbound_list_actions_tool``, then
requests one with ``execbound_action_tool``; a listed action is not permission, and every
request is still decided. Requires ``pip install openai-agents execbound-client`` and the
two environment variables ``EXECBOUND_URL`` and ``EXECBOUND_CREDENTIAL`` (or
``EXECBOUND_CREDENTIAL_FILE``).
"""

from agents import Agent, function_tool
from execbound_client import (
    ExecBoundClient,
    execbound_action,
    execbound_list_actions,
    intent_key,
)

client = ExecBoundClient.from_environment()


@function_tool
def execbound_list_actions_tool() -> str:
    """List the actions your space offers as JSON: each operation_ref, its arguments and the
    target kinds it accepts. A listed action is not permission; targets are never listed.
    """
    return execbound_list_actions(client)


@function_tool
def execbound_action_tool(
    operation_ref: str,
    target_kind: str,
    target_value: str,
    ticket: str,
    incident_id: str | None = None,
) -> str:
    """Request a consequential action through ExecBound and return its decision as JSON.

    The ticket names the case being worked; the idempotency key is derived from it, so
    retries of the same intent never act twice.
    """
    key = intent_key(operation_ref, target_kind, target_value, ticket)
    return execbound_action(
        client, operation_ref, target_kind, target_value, key, incident_id=incident_id
    )


agent = Agent(
    name="responder",
    instructions=(
        "Call execbound_list_actions_tool for the operation_ref values your space offers. "
        "Act only through execbound_action_tool; put uncertain outcomes in front of a person. "
        "On a denial, stop and give the person its request_ref."
    ),
    tools=[execbound_list_actions_tool, execbound_action_tool],
)
