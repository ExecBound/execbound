# SPDX-License-Identifier: AGPL-3.0-only
"""Bounded caller intent; validated claims do not establish trusted authority."""

import hashlib
import ipaddress
import json
import re
from typing import Literal, Self
from urllib.parse import unquote, urlsplit
from uuid import UUID

# The strict model, the bounded JSON parsing and the arguments are the protocol's (#496): a
# provider command carries the same arguments a request does.
from execbound_protocol.arguments import ArgumentName as ArgumentName
from execbound_protocol.arguments import Arguments as Arguments
from execbound_protocol.arguments import ArgumentValue as ArgumentValue
from execbound_protocol.strict import StrictModel as StrictModel
from execbound_protocol.strict import _reject_number as _reject_number
from execbound_protocol.strict import _unique_object as _unique_object
from pydantic import (
    Field,
    ValidationInfo,
    field_validator,
    model_validator,
)

MAX_REQUEST_BYTES = 16 * 1024
_CANONICAL_UUID = re.compile(r"[0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}")
_DNS_LABEL = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?")
_PROVIDER_ID = re.compile(r"[A-Za-z0-9._:-]{1,128}")


class InvalidRequest(ValueError):
    pass


class ResourceSelector(StrictModel):
    kind: Literal["canonical", "hostname", "provider_id"]
    value: str = Field(min_length=1, max_length=254)

    @field_validator("value")
    @classmethod
    def normalize_value(cls, value: str, info: ValidationInfo) -> str:
        kind = info.data.get("kind")
        if kind == "canonical" and _CANONICAL_UUID.fullmatch(value):
            return value.lower()
        if kind == "provider_id" and _PROVIDER_ID.fullmatch(value):
            return value
        if kind == "hostname" and value.isascii():
            hostname = value.lower().removesuffix(".")
            if len(hostname) <= 253 and all(
                _DNS_LABEL.fullmatch(label) for label in hostname.split(".")
            ):
                return hostname
        raise ValueError("Invalid resource selector")


class ClaimedContext(StrictModel):
    incident_id: UUID | None = None
    severity: Literal["LOW", "MEDIUM", "HIGH", "CRITICAL"] | None = None
    environment: Literal["development", "staging", "production"] | None = None
    role: Literal["workstation", "server", "domain_controller"] | None = None
    criticality: int | None = Field(default=None, ge=0, le=4)


_UNSAFE = re.compile(r"[^A-Za-z0-9._:-]+")


def derive_key(operation_ref: str, target_kind: str, target_value: str, reference: str) -> str:
    """The client's ``intent_key``, byte for byte: the same ticket lands on the same intent
    whichever surface carries it, so a retry through either path progresses it."""
    digest = hashlib.sha256(
        json.dumps([operation_ref, target_kind, target_value, reference]).encode()
    ).hexdigest()
    slug = _UNSAFE.sub("-", reference).strip("-")[:40] or "intent"
    return f"{slug}-{digest[:32]}"


class ExternalCase(StrictModel):
    """Unverified caller-supplied navigation, never trusted incident context."""

    source: str = Field(pattern=r"^[a-z][a-z0-9_-]{0,39}$")
    case_id: str = Field(min_length=1, max_length=80, pattern=r"^[A-Za-z0-9][A-Za-z0-9 ._:/()-]*$")
    url: str | None = Field(default=None, max_length=512)

    @field_validator("url")
    @classmethod
    def safe_link(cls, value: str | None) -> str | None:
        if value is None:
            return None
        parsed = urlsplit(value)
        host = parsed.hostname or ""
        if (
            parsed.scheme != "https"
            or not host.isascii()
            or "." not in host
            or len(host) > 253
            or not re.search(r"[a-z]", host.rsplit(".", 1)[-1])
            or not all(_DNS_LABEL.fullmatch(label) for label in host.split("."))
            or host.endswith((".localhost", ".local", ".internal"))
            or parsed.username is not None
            or parsed.password is not None
            or parsed.port not in (None, 443)
            or parsed.query
            or parsed.fragment
            or any(ord(char) <= 32 or ord(char) >= 127 for char in unquote(value))
            or "\\" in unquote(value)
        ):
            raise ValueError("Invalid case link")
        try:
            ipaddress.ip_address(host)
        except ValueError:
            return value
        raise ValueError("Invalid case link")


class ActionRequest(StrictModel):
    operation_ref: str = Field(min_length=1, max_length=80, pattern=r"^[a-z][a-z0-9_.-]{0,79}$")
    target: ResourceSelector
    arguments: Arguments
    # Exactly one of the two: a caller with its own key management sends the key; a
    # model-driven host sends the ticket, case or run id and the gateway derives the key.
    idempotency_key: str = Field(
        default="",
        max_length=128,
        pattern=r"^[A-Za-z0-9._:-]{1,128}$",
        description=(
            "Your own key for this intent, reused on every retry. Omit it and pass "
            "reference instead to have the gateway derive one."
        ),
    )
    # Absent from every serialization when unset, so the frozen plans, contract fixtures and
    # journals recorded before this field existed keep their bytes.
    reference: str | None = Field(
        default=None,
        min_length=1,
        max_length=200,
        exclude_if=lambda value: value is None,
        description=(
            "The ticket, case or run id this action responds to; the idempotency key is "
            "derived from it, so the same reference always means the same intent."
        ),
    )
    run_id: UUID | None = None
    external_case: ExternalCase | None = Field(
        default=None,
        exclude_if=lambda value: value is None,
        description="Source-reported case metadata; not retry identity or authority.",
    )
    synthetic_demo: bool = Field(
        default=False,
        exclude_if=lambda value: value is False,
        description=(
            "Restrict this request to an entirely synthetic fixture workspace. "
            "Never grants authority."
        ),
    )
    claimed_context: ClaimedContext = Field(default_factory=ClaimedContext)

    @model_validator(mode="after")
    def one_key(self) -> Self:
        # The empty default is never validated against the pattern; an explicit empty
        # string still is. Either way the request must carry exactly one of the two.
        if self.reference is not None:
            reference = self.reference.strip()
            if not reference:
                raise ValueError("Exactly one of idempotency_key and reference")
            derived = derive_key(self.operation_ref, self.target.kind, self.target.value, reference)
            # A key beside a reference is refused unless it is the derived one, which is
            # what the gateway's own serialization of a parsed request carries.
            if self.idempotency_key and self.idempotency_key != derived:
                raise ValueError("Exactly one of idempotency_key and reference")
            object.__setattr__(self, "reference", reference)
            object.__setattr__(self, "idempotency_key", derived)
        elif not self.idempotency_key:
            raise ValueError("Exactly one of idempotency_key and reference")
        return self


def parse_request(raw: bytes) -> ActionRequest:
    """Validate the original JSON, retaining strict JSON support for UUID strings."""
    if not isinstance(raw, bytes) or not 0 < len(raw) <= MAX_REQUEST_BYTES:
        raise InvalidRequest("Invalid request")
    try:
        # Pydantic's parser accepts duplicate keys and nonfinite numbers. Check
        # syntax first, then validate the same bytes through its strict JSON path.
        json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=_unique_object,
            parse_constant=_reject_number,
            parse_float=_reject_number,
        )
        return ActionRequest.model_validate_json(raw)
    except (ValueError, RecursionError):
        pass
    # Raising outside the handler also drops the underlying exception context,
    # whose validation details could otherwise retain untrusted caller content.
    raise InvalidRequest("Invalid request")
