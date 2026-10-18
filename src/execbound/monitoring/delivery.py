# SPDX-License-Identifier: AGPL-3.0-only
"""Signed notification transport, and the loopback test receiver's configuration."""

import hashlib
import hmac
from dataclasses import dataclass, field
from typing import Protocol
from urllib.parse import urlsplit
from uuid import UUID

import httpx

from execbound.egress import NOT_PUBLIC, refused
from execbound.monitoring.models import MonitorError
from execbound.transports import DELIVERED, SendResult, retry_after_seconds

# Every rule a finding can carry (`monitor_findings_rule_version_check`, migration 0093), with
# the fixed label a finding message names it by (#31). A message carries this label and never
# the finding's stored title, which can quote what a source reported. A rule no longer raised
# keeps its label, because the findings it raised stay readable. A test reads the database's
# own list and fails on a rule with no label here.
FINDING_RULES: dict[str, str] = {
    "sensitive-action.v1": "Sensitive action reported",
    "sensitive-action.v2": "Sensitive action reported",
    "source-event-integrity.v1": "Source event integrity",
    "source-health.v1": "Source stopped reporting",
    "clock-skew.v1": "Reported time out of bounds",
    "restricted-target.v1": "Restricted target reported",
    "observed-rate.v1": "Observed rate exceeded",
    "monitored-path-change.v1": "Monitored path changed",
    "instrumentation-gap.v1": "Instrumentation gap",
    "collection-health.v1": "Collection health",
    "ungoverned-reach.v1": "Ungoverned reach",
    "sponsorless-agent.v1": "Agent without a sponsor",
    "new-agent.v1": "New agent",
    "new-actor.v1": "New actor that can act",
    "first-consequential-action.v1": "First consequential action outside ExecBound",
    "new-ai-consent.v1": "New AI publisher consent",
    "initial-inventory.v1": "Initial inventory",
}


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


# The statuses a signed webhook delivery counts as delivered (#31, decision 8): common
# receivers, Tines among them, answer 201 or 202. The security event export keeps the two it
# always counted, because decision 8 covers approvals and findings only.
ACCEPTED = frozenset({200, 201, 202, 204})
EXPORT_ACCEPTED = frozenset({200, 204})


def post_signed(
    receiver: SignedReceiver,
    delivery_id: UUID,
    payload: bytes,
    client: httpx.Client,
    *,
    max_bytes: int = 4096,
    accepted: frozenset[int] = ACCEPTED,
) -> SendResult:
    """One signed POST, read only for its status and `Retry-After`; never its body, and no
    error's text, which could quote the URL."""
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
            status = response.status_code
            retry = response.headers.get("Retry-After")
    except httpx.HTTPError as error:
        return SendResult(False, NOT_PUBLIC if refused(error) else "RECEIVER_UNAVAILABLE")
    if status in accepted:
        return DELIVERED
    if status == 429:
        return SendResult(False, "RECEIVER_RATE_LIMITED", retry_after_seconds(retry))
    if 400 <= status < 500:
        return SendResult(False, "RECEIVER_REFUSED")
    return SendResult(False, "RECEIVER_UNAVAILABLE")


def send_notification(
    receiver: SignedReceiver,
    delivery_id: UUID,
    payload: bytes,
    client: httpx.Client,
    *,
    max_bytes: int = 4096,
    accepted: frozenset[int] = ACCEPTED,
) -> bool:
    """Whether one signed POST was delivered, for a caller that records every failure alike: the
    approval webhook (`notifications._send`), which records `RECEIVER_UNAVAILABLE` (ruling 5 of
    the findings plan), and the security event export, which counts only 200 and 204 and passes
    `EXPORT_ACCEPTED`. The findings drain (`monitoring.worker._send`) calls `post_signed` itself,
    for each attempt's own code."""
    return post_signed(
        receiver, delivery_id, payload, client, max_bytes=max_bytes, accepted=accepted
    ).delivered
