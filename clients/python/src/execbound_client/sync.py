# SPDX-License-Identifier: Apache-2.0
"""The synchronous client."""

from __future__ import annotations

import json
import time
from collections.abc import Callable
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


class ExecBoundClient:
    """Call the gateway over HTTP with the semantics it expects from an agent."""

    def __init__(
        self,
        origin: str,
        credential: str,
        *,
        client: httpx.Client | None = None,
        timeout: float = 10.0,
    ) -> None:
        self._origin = origin.rstrip("/")
        self._headers = {"Authorization": "Bearer " + credential}
        self._client = client or httpx.Client(timeout=timeout, trust_env=False)

    @classmethod
    def from_environment(cls, *, timeout: float = 10.0) -> ExecBoundClient:
        settings = Settings.from_environment()
        return cls(settings.url, settings.credential, timeout=timeout)

    def close(self) -> None:
        self._client.close()

    def __enter__(self) -> ExecBoundClient:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    def execute(self, request: dict[str, Any]) -> dict[str, Any]:
        """Send one intent. 200 and 202 both return the execution view."""
        response = self._client.post(
            self._origin + "/v1/execute",
            content=json.dumps(request).encode("utf-8"),
            headers={**self._headers, "Content-Type": "application/json"},
        )
        return interpret(response)

    def status(self, execution_id: str, continuation: str | None = None) -> dict[str, Any]:
        """Read an execution the credential owns; never progresses it."""
        headers = dict(self._headers)
        if continuation:
            headers[CONTINUATION_HEADER] = continuation
        response = self._client.get(
            self._origin + "/v1/executions/" + execution_id, headers=headers
        )
        return interpret(response)

    def list_actions(self) -> dict[str, Any]:
        """Read the operations the agent's own space offers: each `operation_ref`, its
        catalog action and label, its arguments and the target kinds it takes. A listed
        action is not permission, and listed does not mean connected: the gateway still
        decides every request and refuses a listed action whose provider is not connected."""
        response = self._client.get(self._origin + "/v1/actions", headers=self._headers)
        return interpret_listing(response)

    def run_to_completion(
        self,
        request: dict[str, Any],
        *,
        approval_wait_seconds: float = 120.0,
        poll_seconds: float = 2.0,
        max_rate_retries: int = 5,
        sleep: Callable[[float], None] = time.sleep,
    ) -> Outcome:
        """Execute, wait for a human decision if one is required, then progress the same
        intent.

        A pending approval that outlives `approval_wait_seconds` is returned as is while
        it is still pending; the caller can resume with the same request and key. Once a
        decision is made the client resends the same request within the gateway's retry
        window. Once an approval expires the intent is over: the gateway answers
        `STALE_AUTHORIZATION` with `approval_state: EXPIRED`, which is returned, never
        raised, and a new key is needed for a new intent. Uncertain outcomes raise
        `ExecBoundUncertain` and must be reconciled by an administrator, not resent.
        """
        polls = retries = 0
        deadline = time.monotonic() + approval_wait_seconds
        view = self._send_with_backoff(request, sleep, max_rate_retries)
        while view["state"] in PENDING_STATES:
            if time.monotonic() >= deadline:
                return Outcome(view, polls, retries)
            sleep(poll_seconds)
            polls += 1
            try:
                latest: dict[str, Any] | None = self.status(
                    str(view["execution_id"]), view.get("continuation")
                )
            except ExecBoundError as refused:
                if refused.code != "INVALID_CONTINUATION":
                    raise
                # The continuation is void because the approval was decided or expired.
                latest = None
            if (
                latest is not None
                and latest["state"] in PENDING_STATES
                and latest.get("approval_state") == "PENDING"
            ):
                view = {**latest, "continuation": view.get("continuation")}
                continue
            # Only a retry of the same request progresses a decided intent, and the same
            # retry returns the terminal view of an expired one. The same intent still
            # pending means the continuation was renewed (the tenant's deadline outlasts
            # a continuation's two minutes): keep waiting until the caller's own limit.
            retries += 1
            view = self._send_with_backoff(request, sleep, max_rate_retries)
        if view["state"] in UNCERTAIN_STATES:
            raise ExecBoundUncertain(view)
        return Outcome(view, polls, retries)

    def _send_with_backoff(
        self, request: dict[str, Any], sleep: Callable[[float], None], budget: int
    ) -> dict[str, Any]:
        for attempt in range(budget + 1):
            try:
                return self.execute(request)
            except ExecBoundError as refused:
                if refused.code != "RATE_LIMITED" or attempt == budget:
                    raise
                sleep(float(refused.retry_after or 1))
        raise AssertionError("unreachable")
