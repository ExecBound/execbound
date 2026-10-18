# SPDX-License-Identifier: Apache-2.0
"""The asynchronous client; the same semantics as the synchronous one."""

from __future__ import annotations

import asyncio
import json
import time
from collections.abc import Awaitable, Callable
from typing import Any

import httpx

from ._core import (
    CONTINUATION_HEADER,
    PENDING_STATES,
    UNCERTAIN_STATES,
    ExecBoundError,
    ExecBoundUncertain,
    Outcome,
    Settings,
    interpret,
    interpret_listing,
)


class AsyncExecBoundClient:
    """Call the gateway over HTTP from asynchronous code."""

    def __init__(
        self,
        origin: str,
        credential: str,
        *,
        client: httpx.AsyncClient | None = None,
        timeout: float = 10.0,
    ) -> None:
        self._origin = origin.rstrip("/")
        self._headers = {"Authorization": "Bearer " + credential}
        self._client = client or httpx.AsyncClient(timeout=timeout, trust_env=False)

    @classmethod
    def from_environment(cls, *, timeout: float = 10.0) -> AsyncExecBoundClient:
        settings = Settings.from_environment()
        return cls(settings.url, settings.credential, timeout=timeout)

    async def aclose(self) -> None:
        await self._client.aclose()

    async def __aenter__(self) -> AsyncExecBoundClient:
        return self

    async def __aexit__(self, *exc: object) -> None:
        await self.aclose()

    async def execute(self, request: dict[str, Any]) -> dict[str, Any]:
        response = await self._client.post(
            self._origin + "/v1/execute",
            content=json.dumps(request).encode("utf-8"),
            headers={**self._headers, "Content-Type": "application/json"},
        )
        return interpret(response)

    async def status(self, execution_id: str, continuation: str | None = None) -> dict[str, Any]:
        headers = dict(self._headers)
        if continuation:
            headers[CONTINUATION_HEADER] = continuation
        response = await self._client.get(
            self._origin + "/v1/executions/" + execution_id, headers=headers
        )
        return interpret(response)

    async def list_actions(self) -> dict[str, Any]:
        """See `ExecBoundClient.list_actions`."""
        response = await self._client.get(self._origin + "/v1/actions", headers=self._headers)
        return interpret_listing(response)

    async def run_to_completion(
        self,
        request: dict[str, Any],
        *,
        approval_wait_seconds: float = 120.0,
        poll_seconds: float = 2.0,
        max_rate_retries: int = 5,
        sleep: Callable[[float], Awaitable[None]] = asyncio.sleep,
    ) -> Outcome:
        """See `ExecBoundClient.run_to_completion`; identical semantics."""
        polls = retries = 0
        deadline = time.monotonic() + approval_wait_seconds
        view = await self._send_with_backoff(request, sleep, max_rate_retries)
        while view["state"] in PENDING_STATES:
            if time.monotonic() >= deadline:
                return Outcome(view, polls, retries)
            await sleep(poll_seconds)
            polls += 1
            try:
                latest: dict[str, Any] | None = await self.status(
                    str(view["execution_id"]), view.get("continuation")
                )
            except ExecBoundError as refused:
                if refused.code != "INVALID_CONTINUATION":
                    raise
                latest = None
            if (
                latest is not None
                and latest["state"] in PENDING_STATES
                and latest.get("approval_state") == "PENDING"
            ):
                view = {**latest, "continuation": view.get("continuation")}
                continue
            # The same intent still pending after a resend is a renewed continuation
            # under a tenant deadline longer than two minutes: keep waiting.
            retries += 1
            view = await self._send_with_backoff(request, sleep, max_rate_retries)
        if view["state"] in UNCERTAIN_STATES:
            raise ExecBoundUncertain(view)
        return Outcome(view, polls, retries)

    async def _send_with_backoff(
        self,
        request: dict[str, Any],
        sleep: Callable[[float], Awaitable[None]],
        budget: int,
    ) -> dict[str, Any]:
        for attempt in range(budget + 1):
            try:
                return await self.execute(request)
            except ExecBoundError as refused:
                if refused.code != "RATE_LIMITED" or attempt == budget:
                    raise
                await sleep(float(refused.retry_after or 1))
        raise AssertionError("unreachable")
