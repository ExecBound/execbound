# SPDX-License-Identifier: AGPL-3.0-only
"""Bounded notification transport to an explicitly configured local test receiver."""

import hashlib
import hmac
from dataclasses import dataclass, field
from typing import Protocol
from urllib.parse import urlsplit
from uuid import UUID

import httpx

from execbound.monitoring.models import MonitorError


@dataclass(frozen=True)
class LocalReceiver:
    url: str
    secret: str = field(repr=False)

    def __post_init__(self) -> None:
        try:
            parsed = urlsplit(self.url)
            if (
                parsed.scheme != "http"
                or parsed.hostname != "127.0.0.1"
                or not parsed.port
                or parsed.username
                or parsed.password
                or parsed.path != "/alerts"
                or parsed.query
                or parsed.fragment
                or self.url != f"http://127.0.0.1:{parsed.port}/alerts"
                or not 32 <= len(self.secret) <= 256
                or not self.secret.isascii()
            ):
                raise ValueError
        except ValueError:
            raise MonitorError("INVALID_RECEIVER") from None


class SignedReceiver(Protocol):
    @property
    def url(self) -> str: ...

    @property
    def secret(self) -> str: ...


def send_notification(
    receiver: SignedReceiver,
    delivery_id: UUID,
    payload: bytes,
    client: httpx.Client,
    *,
    max_bytes: int = 4096,
) -> bool:
    if len(payload) > max_bytes:
        raise MonitorError("INVALID_NOTIFICATION")
    try:
        with client.stream(
            "POST",
            receiver.url,
            content=payload,
            headers={
                "Content-Type": "application/json",
                "X-ExecBound-Delivery": str(delivery_id),
                "X-ExecBound-Signature": hmac.new(
                    receiver.secret.encode("ascii"),
                    str(delivery_id).encode("ascii") + b"\n" + payload,
                    hashlib.sha256,
                ).hexdigest(),
            },
            follow_redirects=False,
            timeout=5,
        ) as response:
            return response.status_code in {200, 204}
    except httpx.HTTPError:
        return False
