# SPDX-License-Identifier: AGPL-3.0-only
"""Bounded continuation metadata; current authentication and stored decisions still govern."""

import base64
import hashlib
import hmac
import json
import re
from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from types import MappingProxyType
from typing import Annotated, Literal, Self
from uuid import UUID

from pydantic import AwareDatetime, Field, field_validator, model_validator

from execbound.audit import canonical_json
from execbound.requests import StrictModel, _reject_number, _unique_object

MAX_TOKEN_LENGTH = 4096
MAX_TOKEN_TTL = timedelta(minutes=15)
Audience = Literal[
    "execution.status",
    "approval.decide",
    "execution.reconcile",
    # The act window of an external execution checkpoint. It names what the token is for
    # and not what the caller does with its own vendor, and no existing verifier call site
    # accepts it: a grant confers no authority to read status, decide an approval or
    # reconcile. The act window is exactly MAX_TOKEN_TTL, so the deadline is one a
    # continuation can express without raising the ceiling the other three share.
    "execution.checkpoint_outcome",
]
_KEY_ID = re.compile(r"[A-Za-z0-9_.-]{1,64}")
_WIRE_TOKEN = re.compile(r"([A-Za-z0-9_-]+)\.([0-9a-f]{64})")


class InvalidContinuation(ValueError):
    def __init__(self) -> None:
        super().__init__("Invalid continuation")


@dataclass(frozen=True)
class TokenKeys:
    """Trusted independent signing configuration, copied against later mutation."""

    active_key_id: str
    keys: Mapping[str, bytes] = field(repr=False)

    def __post_init__(self) -> None:
        if (
            type(self.active_key_id) is not str
            or not _KEY_ID.fullmatch(self.active_key_id)
            or not isinstance(self.keys, Mapping)
        ):
            raise ValueError("Invalid continuation keys")
        copied = dict(self.keys)
        if self.active_key_id not in copied or any(
            type(key_id) is not str
            or not _KEY_ID.fullmatch(key_id)
            or type(key) is not bytes
            or len(key) < 32
            for key_id, key in copied.items()
        ):
            raise ValueError("Invalid continuation keys")
        object.__setattr__(self, "keys", MappingProxyType(copied))


class Continuation(StrictModel):
    """Authenticated bindings, with a caller-generated cryptographic random nonce."""

    tenant_id: UUID
    principal_id: UUID
    credential_id: UUID
    audience: Audience
    execution_id: UUID
    approval_id: UUID | None = None
    # The operation an act grant names, serialized only when set so every continuation of
    # the other three audiences keeps the exact bytes it has today and stays valid.
    operation_id: UUID | None = Field(default=None, exclude_if=lambda value: value is None)
    plan_hash: Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]
    expires_at: AwareDatetime
    nonce: Annotated[str, Field(pattern=r"^[A-Za-z0-9_-]{22,128}$")]

    @field_validator("expires_at")
    @classmethod
    def utc_expiry(cls, value: datetime) -> datetime:
        return value.astimezone(UTC)

    @model_validator(mode="after")
    def approval_binding(self) -> Self:
        if self.audience == "approval.decide" and self.approval_id is None:
            raise ValueError("Approval continuation requires an approval ID")
        return self

    @model_validator(mode="after")
    def outcome_binding(self) -> Self:
        # An act grant names exactly one operation, and no other audience names any: the
        # field belongs to the checkpoint alone, so it cannot be attached to a status,
        # approval or reconcile token to make it look like authority over an operation.
        checkpoint = self.audience == "execution.checkpoint_outcome"
        if checkpoint and self.operation_id is None:
            raise ValueError("A checkpoint continuation requires its operation ID")
        if not checkpoint and self.operation_id is not None:
            raise ValueError("An operation ID belongs to no audience but the checkpoint")
        return self


class _Envelope(StrictModel):
    version: Literal[1]
    algorithm: Literal["HS256"]
    key_id: Annotated[str, Field(pattern=r"^[A-Za-z0-9_.-]{1,64}$")]
    claims: Continuation

    @field_validator("version", mode="before")
    @classmethod
    def integer_version(cls, value: object) -> object:
        # Literal[1] accepts True without this check, even in strict mode.
        if type(value) is not int:
            raise ValueError("Invalid continuation version")
        return value


def _payload(envelope: _Envelope) -> bytes:
    return canonical_json(envelope.model_dump(mode="json")).encode("utf-8")


def _encoded(payload: bytes) -> str:
    return base64.urlsafe_b64encode(payload).rstrip(b"=").decode("ascii")


def sign(claims: Continuation, keys: TokenKeys) -> str:
    """Sign one bounded canonical envelope with the active trusted key."""
    try:
        if not isinstance(claims, Continuation):
            raise ValueError()
        # Revalidate model_copy/model_construct results before adding authority.
        checked = Continuation.model_validate(claims.model_dump())
        payload = _payload(
            _Envelope(version=1, algorithm="HS256", key_id=keys.active_key_id, claims=checked)
        )
        mac = hmac.new(keys.keys[keys.active_key_id], payload, hashlib.sha256).hexdigest()
        token = f"{_encoded(payload)}.{mac}"
        if len(token) > MAX_TOKEN_LENGTH:
            raise ValueError()
        return token
    except (ValueError, TypeError, RecursionError):
        pass
    raise InvalidContinuation()


def verify(
    token: str,
    keys: TokenKeys,
    *,
    tenant_id: UUID,
    principal_id: UUID,
    credential_id: UUID,
    audience: Audience,
    now: datetime,
) -> Continuation:
    """Authenticate exact canonical state before lookup; never approve or dispatch."""
    try:
        if type(token) is not str or not 0 < len(token) <= MAX_TOKEN_LENGTH:
            raise ValueError()
        match = _WIRE_TOKEN.fullmatch(token)
        if match is None:
            raise ValueError()
        encoded, supplied_mac = match.groups()
        payload = base64.b64decode(
            encoded + "=" * (-len(encoded) % 4), altchars=b"-_", validate=True
        )
        if _encoded(payload) != encoded:
            raise ValueError()
        # Check original JSON before Pydantic can discard duplicate keys or
        # normalize numbers, UUID spellings, timezone offsets and defaults.
        json.loads(
            payload.decode("utf-8"),
            object_pairs_hook=_unique_object,
            parse_constant=_reject_number,
            parse_float=_reject_number,
        )
        envelope = _Envelope.model_validate_json(payload)
        if _payload(envelope) != payload:
            raise ValueError()
        key = keys.keys.get(envelope.key_id)
        if key is None:
            raise ValueError()
        expected_mac = hmac.new(key, payload, hashlib.sha256).hexdigest()
        if not hmac.compare_digest(supplied_mac, expected_mac):
            raise ValueError()
        checked = envelope.claims
        if (
            checked.tenant_id != tenant_id
            or checked.principal_id != principal_id
            or checked.credential_id != credential_id
            or checked.audience != audience
            or type(now) is not datetime
            or now.utcoffset() is None
            or not now < checked.expires_at <= now + MAX_TOKEN_TTL
        ):
            raise ValueError()
        return checked
    except (ValueError, TypeError, OverflowError, RecursionError):
        pass
    # Do not retain untrusted payloads in exception context or client messages.
    raise InvalidContinuation()
