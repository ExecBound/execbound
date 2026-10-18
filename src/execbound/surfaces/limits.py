# SPDX-License-Identifier: AGPL-3.0-only
"""In-process request limits evaluated before admission; a refusal consumes nothing."""

import math
import threading
from dataclasses import dataclass
from typing import Literal
from uuid import UUID

from execbound.execution.models import ExecutionError
from execbound.resolution.models import Clock, SystemClock

Namespace = Literal["agent", "login", "client", "token"]
_MAX_WINDOW_SECONDS = 3600
_MAX_COUNT = 1_000_000


@dataclass(frozen=True, slots=True)
class RequestLimits:
    """Fixed-window request counts per key.

    ``agent`` limits every authenticated agent credential across the HTTP and MCP
    adapters. ``login`` limits human sign-in attempts per credential selector before
    any database lookup. ``client`` limits requests per direct peer address on the
    agent and sign-in routes; behind a reverse proxy every request shares one peer,
    so size it for the proxy rather than for a single caller. ``token`` limits every
    personal access token on the console API, as ``agent`` limits an API key.
    """

    agent_requests: int = 300
    agent_window_seconds: int = 60
    login_attempts: int = 10
    login_window_seconds: int = 60
    client_requests: int = 1000
    client_window_seconds: int = 60
    token_requests: int = 300
    token_window_seconds: int = 60
    max_tracked_keys: int = 10000

    def __post_init__(self) -> None:
        for name in (
            "agent_requests",
            "login_attempts",
            "client_requests",
            "token_requests",
            "max_tracked_keys",
        ):
            value = getattr(self, name)
            if type(value) is not int or not 1 <= value <= _MAX_COUNT:
                raise ValueError("Invalid request limits")
        for name in (
            "agent_window_seconds",
            "login_window_seconds",
            "client_window_seconds",
            "token_window_seconds",
        ):
            value = getattr(self, name)
            if type(value) is not int or not 1 <= value <= _MAX_WINDOW_SECONDS:
                raise ValueError("Invalid request limits")

    def policy(self, namespace: Namespace) -> tuple[int, int]:
        return {
            "agent": (self.agent_requests, self.agent_window_seconds),
            "login": (self.login_attempts, self.login_window_seconds),
            "client": (self.client_requests, self.client_window_seconds),
            "token": (self.token_requests, self.token_window_seconds),
        }[namespace]


class RateLimited(ExecutionError):
    """Refused before parsing, resolution, reservation or audit; retry after the window."""

    def __init__(self, retry_after: int) -> None:
        super().__init__("RATE_LIMITED")
        self.retry_after = retry_after


def credential_selector(token: object) -> str | None:
    """The tenant and credential a token names, read without any lookup or comparison."""
    if type(token) is not str or len(token) > 160:
        return None
    parts = token.split(".")
    if len(parts) != 4 or parts[0] != "eb1":
        return None
    try:
        tenant, credential = UUID(parts[1]), UUID(parts[2])
    except ValueError:
        return None
    if (str(tenant), str(credential)) != (parts[1], parts[2]):
        return None
    return f"{tenant}:{credential}"


class RequestLimiter:
    """Thread-safe fixed windows keyed by namespace and caller key, bounded in memory."""

    def __init__(self, limits: RequestLimits | None = None, clock: Clock | None = None) -> None:
        self.limits = limits or RequestLimits()
        self._clock = clock or SystemClock()
        self._lock = threading.Lock()
        self._windows: dict[tuple[str, str], tuple[float, int]] = {}

    def __len__(self) -> int:
        with self._lock:
            return len(self._windows)

    def check(self, namespace: Namespace, key: str) -> int | None:
        """Count one request; return None when allowed, else whole seconds until the window ends."""
        limit, window = self.limits.policy(namespace)
        now = self._clock.now().timestamp()
        entry = (namespace, key)
        with self._lock:
            start, count = self._windows.get(entry, (now, 0))
            if now - start >= window:
                start, count = now, 0
            if count >= limit:
                return max(1, math.ceil(start + window - now))
            if entry not in self._windows and len(self._windows) >= self.limits.max_tracked_keys:
                self._evict(now)
            self._windows[entry] = (start, count + 1)
            return None

    def refuse(self, namespace: Namespace, key: str) -> None:
        """Raise RateLimited when the key has exhausted its window."""
        retry_after = self.check(namespace, key)
        if retry_after is not None:
            raise RateLimited(retry_after)

    def _evict(self, now: float) -> None:
        # Drop expired windows first; a flood of distinct keys then loses its oldest
        # windows in one batch so memory stays bounded without a per-request scan.
        for entry, (start, _) in list(self._windows.items()):
            if now - start >= self.limits.policy(entry[0])[1]:  # type: ignore[arg-type]
                del self._windows[entry]
        if len(self._windows) >= self.limits.max_tracked_keys:
            oldest = sorted(self._windows, key=lambda entry: self._windows[entry][0])
            for entry in oldest[: max(1, len(oldest) // 16)]:
                del self._windows[entry]
