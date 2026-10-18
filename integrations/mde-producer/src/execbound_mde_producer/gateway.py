# SPDX-License-Identifier: Apache-2.0
"""Post one envelope to ExecBound and read its answer. The token never leaves the header."""

import json
import urllib.error
import urllib.request
from collections.abc import Callable
from dataclasses import dataclass
from http.client import HTTPException
from typing import Any

from execbound_mde_producer.transport import open_direct

Opener = Callable[..., Any]
# Only protocol codes are suitable for logs. Never repeat arbitrary gateway body text.
CODES = frozenset(
    {
        "INVALID_SOURCE",
        "INVALID_ENVELOPE",
        "SOURCE_RATE_LIMIT",
        "CONFLICTING_DUPLICATE",
        "CAPABILITY_REFUSED",
        "SUBJECT_REFUSED",
        "INCOMPATIBLE_PRODUCER",
        "FUTURE_OBSERVATION",
        "STALE_ON_ARRIVAL",
        "INVALID_SIGNAL",
        "INVALID_SUBJECT",
        "SOURCE_CAPACITY",
    }
)


@dataclass(frozen=True)
class Answer:
    status: int
    code: str | None


def _code(error: urllib.error.HTTPError) -> str | None:
    try:
        body = json.loads(error.read(4096) or b"{}")
    except (ValueError, OSError, HTTPException, RecursionError):
        return None
    code = body.get("code") if isinstance(body, dict) else None
    return code if isinstance(code, str) and code in CODES else None


def post(
    gateway: str,
    token: str,
    envelope: dict[str, Any],
    *,
    opener: Opener = open_direct,
) -> Answer:
    request = urllib.request.Request(
        f"{gateway.rstrip('/')}/v1/signals",
        data=json.dumps(envelope, separators=(",", ":")).encode(),
        method="POST",
        headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
    )
    try:
        with opener(request, timeout=10) as response:
            return Answer(response.status, None)
    except urllib.error.HTTPError as error:
        try:
            return Answer(error.code, _code(error))
        finally:
            error.close()
    except (urllib.error.URLError, TimeoutError, OSError, HTTPException):
        return Answer(0, "GATEWAY_UNREACHABLE")
