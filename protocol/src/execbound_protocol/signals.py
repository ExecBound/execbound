# SPDX-License-Identifier: Apache-2.0
"""The `execbound.security-signal.v1` envelope and its byte parser.

`docs/SIGNALS.md` describes what a producer sends. This module imports only the standard
library and pydantic, and it carries its own strict-model config and canonical JSON so that
the envelopes it accepts never change. There is no field for a prompt, a tool result or a
reasoning trace, and the bounds leave no room to smuggle one through `attributes`.
"""

import hashlib
import json
import re
from datetime import UTC, datetime
from typing import Annotated, Any, Literal, Self
from uuid import UUID

from pydantic import (
    AwareDatetime,
    BaseModel,
    BeforeValidator,
    ConfigDict,
    Field,
    StrictBool,
    ValidationError,
    WithJsonSchema,
    field_validator,
    model_validator,
)

SCHEMA_VERSION = "execbound.security-signal.v1"
MAX_ENVELOPE_BYTES = 8192
MAX_ATTRIBUTES = 16
LONG_MIN, LONG_MAX = -(2**63), 2**63 - 1
# A time is RFC 3339 as `datetime.isoformat()` writes it, or with `Z`, and nothing a lax parser
# would read as a count of seconds. The offset keeps RFC 3339's ranges, so `+05:60` is not read
# as `+06:00`. Converted to UTC, every instant has one spelling. Python's jsonschema lets `$`
# match before a final newline, so its check of this pattern can accept a trailing newline that
# the parser refuses; the difference only ever runs that way.
TIME = (
    r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}"
    r"(?:\.[0-9]{1,6})?(?:Z|[+-](?:[01][0-9]|2[0-3]):[0-5][0-9])$"
)
# An identifier has one spelling too: the canonical UUID, lowercase and hyphenated.
UUID_TEXT = r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"
# Free text is visible text: no C0 or C1 control or DEL, and none of the invisible format
# characters that hide or reorder text on a page (the soft hyphen, the combining grapheme
# joiner, the Arabic letter mark, the Mongolian vowel separator, zero-width and directional
# marks, line and paragraph separators, embeddings and overrides, the word joiner, invisible
# operators, isolates and the deprecated format controls, the byte order mark, and the
# interlinear annotation controls).
VISIBLE = (
    r"[^\x00-\x1f\x7f-\x9f\u00ad\u034f\u061c\u180e\u200b-\u200f\u2028-\u202e"
    r"\u2060-\u206f\ufeff\ufff9-\ufffb]"
)


class EnvelopeError(ValueError):
    """The body is not a valid envelope. The message never quotes any part of it."""


class _Strict(BaseModel):
    model_config = ConfigDict(strict=True, extra="forbid", frozen=True, hide_input_in_errors=True)


Name = Annotated[str, Field(pattern=r"^[a-z][a-z0-9_]{0,63}$")]
ProducerName = Annotated[str, Field(pattern=r"^[a-z][a-z0-9_.-]{0,63}$")]
ProducerVersion = Annotated[
    str, Field(pattern=r"^(0|[1-9][0-9]{0,5})\.(0|[1-9][0-9]{0,5})\.(0|[1-9][0-9]{0,5})$")
]
# The verdict: 1 to 64 characters, never starting or ending with a space, exactly as the
# `SignalRecord` a plan freezes requires it.
Label = Annotated[
    str, Field(pattern=r"^[A-Za-z0-9_.:-](?:[A-Za-z0-9 _.:-]{0,62}[A-Za-z0-9_.:-])?$")
]
Severity = Annotated[str, Field(pattern=r"^[A-Za-z0-9 _.:-]{1,32}$")]
EventId = Annotated[str, Field(pattern=r"^[A-Za-z0-9._:-]{1,128}$")]
Action = Annotated[str, Field(pattern=r"^[a-z][a-z0-9_.-]{0,79}$")]
ProviderId = Annotated[str, Field(pattern=rf"^{VISIBLE}{{1,128}}$")]
Reference = Annotated[str, Field(pattern=rf"^{VISIBLE}{{1,200}}$")]
EvidenceRef = Annotated[str, Field(pattern=rf"^{VISIBLE}{{1,256}}$")]
Digest = Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]
AttributeName = Annotated[str, Field(pattern=r"^[a-z][a-z0-9_]{0,62}$")]
AttributeText = Annotated[str, Field(pattern=rf"^{VISIBLE}{{0,254}}$")]
AttributeLong = Annotated[int, Field(ge=LONG_MIN, le=LONG_MAX)]


def _time(value: object) -> datetime:
    """An RFC 3339 string, or an aware `datetime` from a producer building one in Python, held
    in UTC; never a number, a naive time or another spelling. JSON never yields a `datetime`,
    so the wire accepts the string alone."""
    try:
        if type(value) is datetime:
            if value.utcoffset() is None:
                raise ValueError
            parsed = value
        elif type(value) is str and re.fullmatch(TIME, value) is not None:
            parsed = datetime.fromisoformat(value)
        else:
            raise ValueError
        # A date the calendar lacks is a ValueError; an offset that carries an instant past
        # year 1 or 9999 on its way to UTC is an OverflowError, which pydantic would not catch.
        return parsed.astimezone(UTC)
    except (ValueError, OverflowError):
        raise ValueError("Invalid time") from None


def _identifier(value: object) -> UUID:
    """The canonical UUID spelling, or a `UUID` from a producer building one in Python."""
    if type(value) is UUID:
        return value
    if type(value) is not str or re.fullmatch(UUID_TEXT, value) is None:
        raise ValueError("Invalid identifier")
    return UUID(value)


# Strict mode takes the parsed value these return and would refuse a string.
Time = Annotated[
    AwareDatetime,
    BeforeValidator(_time),
    WithJsonSchema({"type": "string", "format": "date-time", "pattern": TIME}),
]
Identifier = Annotated[
    UUID,
    BeforeValidator(_identifier),
    WithJsonSchema({"type": "string", "format": "uuid", "pattern": UUID_TEXT}),
]


class Producer(_Strict):
    name: ProducerName
    version: ProducerVersion


class ResourceSubject(_Strict):
    """The correlation keys of a resource subject; the tenant is the credential's."""

    kind: Literal["resource"]
    account_id: Identifier
    provider: Name
    resource_type: Name
    provider_id: ProviderId


class SecuritySignal(_Strict):
    """One producer's verdict about one subject at one instant.

    The parser also refuses what this schema cannot express: a body that is not UTF-8, that
    opens with a byte order mark or that is longer than 8,192 bytes; an object that repeats a
    key; a number written with a fraction or an exponent, even one of integral value; a time
    that is not a real instant between the years 1 and 9999 once converted to UTC; and an
    `expires_at` that is not later than `observed_at`.

    Bytes come in through `parse_signal`. A producer building one from Python values may also
    give a time as an aware `datetime` and the account as a `UUID`.
    """

    schema_version: Literal["execbound.security-signal.v1"]
    source_event_id: EventId
    producer: Producer
    capability: Literal["resource_compromise.v1"]
    verdict: Label
    confidence: int = Field(ge=0, le=1000)
    # Recorded, and never an input to authority.
    severity: Severity | None = None
    subject: ResourceSubject
    action: Action | None = None
    # The envelope parses it and the server's intake refuses it: a capability rule, not the
    # envelope's. The description says so to a producer that reads only the schema.
    request_reference: Reference | None = Field(
        default=None,
        description=(
            "Refused today. `resource_compromise.v1`, the only capability, takes no "
            "request-scoped record, so the intake refuses an envelope carrying this field as "
            "INVALID_ENVELOPE: a request's reference is the agent's own string, and a record "
            "scoped by it could be claimed by any agent that names it."
        ),
    )
    observed_at: Time
    # May shorten the freshness window, never lengthen it.
    expires_at: Time | None = None
    # `additionalProperties` closes the published schema to the names the parser refuses;
    # pydantic's own schema for a pattern-keyed dict lists `patternProperties` alone.
    attributes: dict[AttributeName, AttributeText | AttributeLong | StrictBool] = Field(
        default_factory=dict,
        max_length=MAX_ATTRIBUTES,
        json_schema_extra={"additionalProperties": False},
    )
    # Opaque: never fetched and never rendered as a link.
    evidence_ref: EvidenceRef | None = None
    evidence_digest: Digest | None = None

    @field_validator("confidence", mode="before")
    @classmethod
    def integer_confidence(cls, value: object) -> object:
        if type(value) is not int:
            raise ValueError("Invalid confidence")
        return value

    @model_validator(mode="after")
    def expires_after_observation(self) -> Self:
        # The stored record's own rule (`security_signals_expiry_order`).
        if self.expires_at is not None and self.expires_at <= self.observed_at:
            raise ValueError("Invalid expiry")
        return self


def canonical_json(value: Any) -> str:
    """Sorted keys, no whitespace, no NaN: the protocol's canonical form."""
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False
    )


def record_digest(signal: SecuritySignal) -> str:
    """SHA-256 of the normalized envelope: equal for equal content however it was spelled."""
    return hashlib.sha256(canonical_json(signal.model_dump(mode="json")).encode()).hexdigest()


def _unique(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    if len({key for key, _ in pairs}) != len(pairs):
        raise ValueError
    return dict(pairs)


def _refuse(value: str) -> Any:
    raise ValueError


def parse_signal(raw: bytes) -> SecuritySignal:
    """One envelope from at most 8 KiB of UTF-8 JSON with no float, constant or repeated key."""
    try:
        if type(raw) is not bytes or len(raw) > MAX_ENVELOPE_BYTES:
            raise ValueError
        decoded = raw.decode("utf-8")
        value = json.loads(
            decoded, object_pairs_hook=_unique, parse_constant=_refuse, parse_float=_refuse
        )
        if not isinstance(value, dict):
            raise ValueError
        return SecuritySignal.model_validate_json(decoded)
    except (ValueError, ValidationError, RecursionError):
        raise EnvelopeError("Invalid envelope") from None
