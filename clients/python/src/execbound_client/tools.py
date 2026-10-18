# SPDX-License-Identifier: Apache-2.0
"""Framework-neutral tool functions: string arguments in, a short JSON summary out.

Wrap one of these in your framework's tool abstraction. Derive the idempotency key from
the ticket, case or run behind the action with `intent_key`, never from the model's
wording, and surface `uncertain` outcomes to a person. `execbound_list_actions` tells the
model which actions it can name, so it need not guess an `operation_ref`.
"""

from __future__ import annotations

import json
from typing import Any

from ._core import (
    ExecBoundError,
    ExecBoundUncertain,
    action_request,
    summarize,
    summarize_listing,
)
from .aio import AsyncExecBoundClient
from .sync import ExecBoundClient


def _refused(refused: ExecBoundError) -> str:
    return json.dumps({"outcome": "refused", "status": refused.status, "code": refused.code})


def _uncertain(uncertain: ExecBoundUncertain) -> str:
    summary = {
        "outcome": "uncertain",
        "execution_id": uncertain.view.get("execution_id"),
        "state": uncertain.view.get("state"),
        "next": "An administrator must reconcile this execution; do not resend.",
    }
    if uncertain.view.get("request_ref") is not None:
        summary["request_ref"] = uncertain.view["request_ref"]
    return json.dumps(summary)


def execbound_action(
    client: ExecBoundClient,
    operation_ref: str,
    target_kind: str,
    target_value: str,
    idempotency_key: str,
    incident_id: str | None = None,
    *,
    arguments: dict[str, Any] | None = None,
    external_case: dict[str, Any] | None = None,
    approval_wait_seconds: float = 120.0,
    poll_seconds: float = 2.0,
) -> str:
    """Request one action and wait for its outcome; returns a JSON summary for the model."""
    request = action_request(
        operation_ref,
        target_kind,
        target_value,
        idempotency_key,
        incident_id=incident_id,
        arguments=arguments,
        external_case=external_case,
    )
    try:
        outcome = client.run_to_completion(
            request, approval_wait_seconds=approval_wait_seconds, poll_seconds=poll_seconds
        )
    except ExecBoundUncertain as uncertain:
        return _uncertain(uncertain)
    except ExecBoundError as refused:
        return _refused(refused)
    return json.dumps(summarize(outcome))


async def execbound_action_async(
    client: AsyncExecBoundClient,
    operation_ref: str,
    target_kind: str,
    target_value: str,
    idempotency_key: str,
    incident_id: str | None = None,
    *,
    arguments: dict[str, Any] | None = None,
    external_case: dict[str, Any] | None = None,
    approval_wait_seconds: float = 120.0,
    poll_seconds: float = 2.0,
) -> str:
    """The asynchronous twin of `execbound_action`."""
    request = action_request(
        operation_ref,
        target_kind,
        target_value,
        idempotency_key,
        incident_id=incident_id,
        arguments=arguments,
        external_case=external_case,
    )
    try:
        outcome = await client.run_to_completion(
            request, approval_wait_seconds=approval_wait_seconds, poll_seconds=poll_seconds
        )
    except ExecBoundUncertain as uncertain:
        return _uncertain(uncertain)
    except ExecBoundError as refused:
        return _refused(refused)
    return json.dumps(summarize(outcome))


def execbound_list_actions(client: ExecBoundClient) -> str:
    """List the actions the agent's space offers; returns a JSON summary for the model. A
    refusal, a 429 `RATE_LIMITED` included, is reported as it came: the listing is not retried."""
    try:
        listing = client.list_actions()
    except ExecBoundError as refused:
        return _refused(refused)
    return json.dumps(summarize_listing(listing))


async def execbound_list_actions_async(client: AsyncExecBoundClient) -> str:
    """The asynchronous twin of `execbound_list_actions`."""
    try:
        listing = await client.list_actions()
    except ExecBoundError as refused:
        return _refused(refused)
    return json.dumps(summarize_listing(listing))
