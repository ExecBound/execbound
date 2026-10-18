# SPDX-License-Identifier: Apache-2.0
"""ExecBound client: request consequential actions through the gateway with the retry,
approval and uncertainty semantics it expects."""

from ._core import (
    CONTINUATION_HEADER,
    KEY_PATTERN,
    PENDING_STATES,
    TERMINAL_STATES,
    UNCERTAIN_STATES,
    ConfigurationError,
    ExecBoundError,
    ExecBoundUncertain,
    Outcome,
    Settings,
    action_request,
    intent_key,
    summarize,
    summarize_listing,
)
from .aio import AsyncExecBoundClient
from .sync import ExecBoundClient
from .tools import (
    execbound_action,
    execbound_action_async,
    execbound_list_actions,
    execbound_list_actions_async,
)

__all__ = [
    "CONTINUATION_HEADER",
    "KEY_PATTERN",
    "PENDING_STATES",
    "TERMINAL_STATES",
    "UNCERTAIN_STATES",
    "AsyncExecBoundClient",
    "ConfigurationError",
    "ExecBoundClient",
    "ExecBoundError",
    "ExecBoundUncertain",
    "Outcome",
    "Settings",
    "action_request",
    "execbound_action",
    "execbound_action_async",
    "execbound_list_actions",
    "execbound_list_actions_async",
    "intent_key",
    "summarize",
    "summarize_listing",
]
