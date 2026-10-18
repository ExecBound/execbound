# SPDX-License-Identifier: AGPL-3.0-only
"""The Messages API over `httpx`, behind one seam, and the scripted fake every test uses.

One request shape, built here and nowhere else: the fixed instructions with a cache
breakpoint, the tools with closed schemas and `strict`, automatic tool choice, the answer
constrained by `output_config.format`, a token ceiling, no assistant prefill. `Transport` is
the seam: `HttpTransport` sends the body to the provider; `ScriptedTransport` replays a
script and records what it was sent, which is how a test asserts that a secret never left
the process rather than trusting the code path that should have stopped it.
"""

from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any, Protocol

import httpx

from execbound.assistant.config import API_VERSION, AssistantConfig


class ModelError(Exception):
    """A provider call that did not produce a message; `code` says how, never what was sent."""

    RETRYABLE = frozenset({"RATE_LIMITED", "SERVER_ERROR"})

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


@dataclass(frozen=True)
class ToolSpec:
    """One tool the model may call: a closed schema, so arguments always match it."""

    name: str
    description: str
    parameters: Mapping[str, Any]
    required: tuple[str, ...] = ()

    def wire(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "description": self.description,
            "strict": True,
            "input_schema": {
                "type": "object",
                "properties": dict(self.parameters),
                "required": list(self.required),
                "additionalProperties": False,
            },
        }


@dataclass(frozen=True)
class Usage:
    input_tokens: int = 0
    output_tokens: int = 0
    cache_read_input_tokens: int = 0
    cache_creation_input_tokens: int = 0

    def __add__(self, other: "Usage") -> "Usage":
        return Usage(
            self.input_tokens + other.input_tokens,
            self.output_tokens + other.output_tokens,
            self.cache_read_input_tokens + other.cache_read_input_tokens,
            self.cache_creation_input_tokens + other.cache_creation_input_tokens,
        )


@dataclass(frozen=True)
class ToolCall:
    id: str
    name: str
    arguments: Mapping[str, Any]


@dataclass(frozen=True)
class ModelResponse:
    stop_reason: str
    text: str
    tool_calls: tuple[ToolCall, ...]
    usage: Usage
    content: tuple[dict[str, Any], ...] = field(default=(), repr=False)


def build_request(
    config: AssistantConfig,
    *,
    fixed_instructions: str,
    catalog_digest: str,
    tools: Sequence[ToolSpec],
    messages: Sequence[Mapping[str, Any]],
    answer_schema: Mapping[str, Any],
) -> dict[str, Any]:
    """The one request body. The fixed part ends with the cache breakpoint; everything that
    varies by turn comes after it, so two turns share the prefix byte for byte."""
    return {
        "model": config.model,
        "max_tokens": config.max_output_tokens,
        "system": [
            {"type": "text", "text": fixed_instructions},
            {
                "type": "text",
                "text": catalog_digest,
                "cache_control": {"type": "ephemeral"},
            },
        ],
        "tools": [tool.wire() for tool in tools],
        "tool_choice": {"type": "auto"},
        "output_config": {
            "effort": config.effort,
            "format": {"type": "json_schema", "schema": dict(answer_schema)},
        },
        "messages": list(messages),
    }


def parse_response(body: Mapping[str, Any]) -> ModelResponse:
    """A message from the provider, or `ModelError("INVALID_RESPONSE")` for anything else."""
    try:
        content = body["content"]
        stop_reason = str(body["stop_reason"])
        usage = body.get("usage") or {}
        if not isinstance(content, list):
            raise TypeError
        text_parts: list[str] = []
        calls: list[ToolCall] = []
        for block in content:
            if block.get("type") == "text":
                text_parts.append(str(block["text"]))
            elif block.get("type") == "tool_use":
                arguments = block["input"]
                if not isinstance(arguments, dict):
                    raise TypeError
                calls.append(ToolCall(str(block["id"]), str(block["name"]), arguments))
        return ModelResponse(
            stop_reason=stop_reason,
            text="".join(text_parts),
            tool_calls=tuple(calls),
            usage=Usage(
                int(usage.get("input_tokens") or 0),
                int(usage.get("output_tokens") or 0),
                int(usage.get("cache_read_input_tokens") or 0),
                int(usage.get("cache_creation_input_tokens") or 0),
            ),
            content=tuple(dict(block) for block in content if isinstance(block, dict)),
        )
    except (KeyError, TypeError, ValueError):
        raise ModelError("INVALID_RESPONSE") from None


class Transport(Protocol):
    def send(self, body: Mapping[str, Any]) -> Mapping[str, Any]: ...


class HttpTransport:
    """`POST /v1/messages` with the key in a header and a per-call timeout; nothing else."""

    def __init__(
        self, config: AssistantConfig, *, transport: httpx.BaseTransport | None = None
    ) -> None:
        self._url = config.base_url.rstrip("/") + "/v1/messages"
        self._headers = {
            "x-api-key": config.api_key,
            "anthropic-version": API_VERSION,
            "content-type": "application/json",
        }
        self._timeout = config.call_timeout_seconds
        # Tests hand in `httpx.MockTransport`; the process never does.
        self._transport = transport

    def send(self, body: Mapping[str, Any]) -> Mapping[str, Any]:
        try:
            with httpx.Client(
                trust_env=False,
                follow_redirects=False,
                timeout=self._timeout,
                transport=self._transport,
            ) as c:
                response = c.post(self._url, json=dict(body), headers=self._headers)
        except httpx.TimeoutException:
            raise ModelError("TIMEOUT") from None
        except httpx.HTTPError:
            raise ModelError("TRANSPORT") from None
        if response.status_code == 429:
            raise ModelError("RATE_LIMITED")
        if response.status_code >= 500:
            raise ModelError("SERVER_ERROR")
        if response.status_code != 200:
            # The body may quote the request; it is never logged or stored.
            raise ModelError("BAD_REQUEST")
        try:
            parsed = response.json()
        except ValueError:
            raise ModelError("INVALID_RESPONSE") from None
        if not isinstance(parsed, dict):
            raise ModelError("INVALID_RESPONSE")
        return parsed


Step = Mapping[str, Any] | Exception | Callable[[Mapping[str, Any]], Mapping[str, Any]]


class ScriptedTransport:
    """Replays a script: a response body, an exception to raise, or a callable that sees the
    request (to sleep, or to answer from it). Records every body it was sent."""

    def __init__(self, steps: Sequence[Step]) -> None:
        self._steps = list(steps)
        self.sent: list[dict[str, Any]] = []

    def send(self, body: Mapping[str, Any]) -> Mapping[str, Any]:
        self.sent.append(dict(body))
        if not self._steps:
            raise ModelError("SCRIPT_EXHAUSTED")
        step = self._steps.pop(0)
        if isinstance(step, Exception):
            raise step
        if callable(step):
            return step(body)
        return step


def text_message(text: str) -> dict[str, Any]:
    return {"type": "text", "text": text}


def tool_use(call_id: str, name: str, arguments: Mapping[str, Any]) -> dict[str, Any]:
    return {"type": "tool_use", "id": call_id, "name": name, "input": dict(arguments)}


def scripted_message(
    *blocks: Mapping[str, Any], stop_reason: str = "end_turn", output_tokens: int = 50
) -> dict[str, Any]:
    """A provider response body for a script, with the fields the loop reads."""
    return {
        "type": "message",
        "role": "assistant",
        "model": "scripted",
        "content": [dict(block) for block in blocks],
        "stop_reason": stop_reason,
        "usage": {
            "input_tokens": 100,
            "output_tokens": output_tokens,
            "cache_read_input_tokens": 0,
            "cache_creation_input_tokens": 0,
        },
    }
