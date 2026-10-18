# SPDX-License-Identifier: Apache-2.0
"""The external executor's signed outcome record, as an executor writes it.

An external executor holds its own vendor credential and acts outside ExecBound, so its
report is authenticated rather than dispatched: the executor signs this record with its own
private key, and ExecBound, holding only the public half, verifies it. The verifier is the
server's; this is the record, its envelope and the message the signature covers, so an
executor can produce one with the protocol alone (#496).

The record is the executor's own model with its own signing envelope. The provider
journal is untouched: `JournalRecord`, `SignedJournal` and `ProviderCommand` describe an
operation ExecBound dispatched through a connector, and nothing here may be mistaken for
one. The envelope is versioned and canonical-JSON exactly as the journal's is, carries its
own domain separator so the two message shapes can never coincide, and the signature is
asymmetric rather than a shared-secret MAC.

An ES256 key signs a compact JWS instead, which is what a workflow platform that cannot
do Ed25519 produces (Tines' JWT_SIGN among them). Its claims carry the same domain
separator, version and record fields, and its header names the key and nothing else. It
is retained in RFC 7515 flattened JSON serialization rather than as the compact token it
arrived as: the same three segments as separate JSON strings, so what settled is still
exactly the bytes that were signed, and no dot-joined token that the export secret check
would refuse ever reaches retained history (see `SignedOutcomeJws`).
"""

import base64
import json
import re
from dataclasses import dataclass
from typing import Annotated, Literal, Protocol, Self
from uuid import UUID

from pydantic import AwareDatetime, Field, field_validator, model_validator

from execbound_protocol.canonical import canonical_json
from execbound_protocol.outcomes import TerminalOutcome, TerminalReason, consistent_terminal
from execbound_protocol.provider import KeyId, ProtocolModel, ProviderError, parse_provider
from execbound_protocol.strict import Digest, StrictModel, _reject_number, _unique_object

# An Ed25519 signature is 64 bytes, carried as lowercase hex.
Ed25519Signature = Annotated[str, Field(pattern=r"^[0-9a-f]{128}$")]
_KEY_ID = re.compile(r"[a-zA-Z0-9_.-]{1,64}")

# What this protocol's signatures are for. It is inside the signed bytes, so an executor's
# envelope and the provider journal's HMAC envelope — which shapes its message the same
# way, `{"version", "key_id", "record"}` — cannot be confused for one another even if a
# future record model happened to serialize identically.
OUTCOME_DOMAIN = "execbound.executor.outcome"


class Signer(Protocol):
    """What signs an outcome: an Ed25519 private key, such as `cryptography`'s, held by
    the executor and never by ExecBound."""

    def sign(self, data: bytes) -> bytes: ...


class ExecutorRecord(ProtocolModel):
    """What the executor states about one authorized operation.

    It binds the four fields settlement checks against the frozen command — the
    operation, the account, the intent hash and the plan hash — so a record can settle
    exactly the operation it names and no other, and it cannot be replayed onto a second
    grant. `reported_at` is the executor's own clock and is retained as a reported time.
    """

    operation_id: UUID
    account_id: UUID
    intent_hash: Digest
    plan_hash: Digest
    outcome: TerminalOutcome
    reason: TerminalReason
    reported_at: AwareDatetime

    @model_validator(mode="after")
    def consistent_outcome(self) -> Self:
        if not consistent_terminal(self.outcome, self.reason):
            raise ValueError("Invalid terminal reason")
        return self


class SignedOutcome(ProtocolModel):
    """The executor's envelope: the key that signed, the record, and the signature."""

    key_id: KeyId
    record: ExecutorRecord
    signature: Ed25519Signature


def outcome_message(signed: SignedOutcome) -> bytes:
    """The signed bytes, taken from the envelope that carries them.

    The domain separator is inside them, so no other protocol's message can ever be the
    same bytes. The key id is inside them, so a signature cannot be re-labelled as another
    registered key's. The version is read from the envelope rather than written here as a
    literal, so a version 2 envelope signs a different message than a version 1 one even
    if every other field is identical.
    """
    return canonical_json(
        {
            "domain": OUTCOME_DOMAIN,
            "version": signed.version,
            "key_id": signed.key_id,
            "record": signed.record.model_dump(mode="json"),
        }
    ).encode()


def sign_outcome(record: ExecutorRecord, key_id: str, private_key: Signer) -> SignedOutcome:
    """Sign a record as an external executor would.

    ExecBound never holds an executor's private key; this exists for the protected mocks
    and the tests that act as an external executor, and it takes the key as an argument
    so nothing here stores or generates one.
    """
    record = parse_provider(record.model_dump_json().encode(), ExecutorRecord)
    if not _KEY_ID.fullmatch(key_id):
        raise ProviderError("INVALID_SCOPE")
    # The envelope is built before it is signed so the message covers the version the
    # envelope actually declares; the placeholder signature is not part of the message.
    draft = SignedOutcome(key_id=key_id, record=record, signature="0" * 128)
    return SignedOutcome(
        key_id=key_id, record=record, signature=private_key.sign(outcome_message(draft)).hex()
    )


JWS_FORMAT: Literal["jws-es256"] = "jws-es256"
MAX_JWS_BYTES = 4096
_SEGMENT = re.compile(r"[A-Za-z0-9_-]+")


class JwsHeader(StrictModel):
    """The only header an ES256 attestation may carry.

    Exactly the two fields Tines' JWT_SIGN writes, as observed against a live Tines tenant,
    so a `typ`, a key URL or any other header field is refused like every field the envelope
    does not name.
    """

    alg: Literal["ES256"]
    kid: KeyId


class JwsClaims(StrictModel):
    """The signed claims: the domain, the version and the executor record, nothing else.

    JWT_SIGN adds nothing to the claims its formula supplies, as observed against a live
    Tines tenant, so an `iat` is refused like any other extra claim.
    """

    domain: Literal["execbound.executor.outcome"]
    version: Literal[1]
    operation_id: UUID
    account_id: UUID
    intent_hash: Digest
    plan_hash: Digest
    outcome: TerminalOutcome
    reason: TerminalReason
    reported_at: AwareDatetime

    @field_validator("version", mode="before")
    @classmethod
    def integer_version(cls, value: object) -> object:
        # `true` equals 1 to a Literal. The canonical envelope refuses it as
        # `ProtocolModel` does, and so does this.
        if type(value) is not int:
            raise ValueError("Invalid protocol version")
        return value

    @model_validator(mode="after")
    def consistent_outcome(self) -> Self:
        # Refused at the parser, as `ExecutorRecord` refuses it, so `jws_record` is total
        # over parsed claims and never raises after the parse has succeeded.
        if not consistent_terminal(self.outcome, self.reason):
            raise ValueError("Invalid terminal reason")
        return self


# One flattened-serialization segment: unpadded base64url, bounded the way the whole
# compact token was bounded before retention stopped joining the three with dots.
JwsSegment = Annotated[str, Field(min_length=1, max_length=MAX_JWS_BYTES)]


class SignedOutcomeJws(ProtocolModel):
    """How an ES256 attestation is retained: RFC 7515 flattened JSON serialization.

    Not the compact token `<protected>.<payload>.<signature>`: that string is exactly the
    shape `execbound.secrets.SECRET_TEXT` refuses as a three-part JWT (any JSON object
    header base64-encodes to a string starting `eyJ`, so every compact ES256 attestation
    would match it), and a retained record must survive the export secret check unchanged.
    Splitting the same three segments into their own JSON string fields carries identical
    information with no literal dot-joined token anywhere in the retained bytes. The
    signing input is unaffected either way: `protected + "." + payload` is still exactly
    what ES256 signed, and `flattened_jws` rebuilds it before verifying or reading either
    form back.

    `format` has no default, unlike most of this envelope's siblings: retained evidence is
    read back through `recorded_outcome` and `ExecutorVerifier.verify`, never authored by a
    literal standing in for a caller's own choice, so nothing is lost by requiring it on
    every input.
    """

    format: Literal["jws-es256"]
    key_id: KeyId
    protected: JwsSegment
    payload: JwsSegment
    signature: JwsSegment


@dataclass(frozen=True)
class ParsedJws:
    header: JwsHeader
    claims: JwsClaims
    signing_input: bytes
    signature: bytes


def _segment(value: str) -> bytes:
    """One base64url segment, unpadded and canonical, or a refusal."""
    if not _SEGMENT.fullmatch(value):
        raise ValueError()
    decoded = base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
    if base64.urlsafe_b64encode(decoded).rstrip(b"=").decode("ascii") != value:
        raise ValueError()
    return decoded


def _encode_segment(value: bytes) -> str:
    """The canonical base64url spelling of one segment; the inverse of `_segment`."""
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def _strict_json(raw: bytes) -> str:
    text = raw.decode("utf-8")
    json.loads(
        text,
        object_pairs_hook=_unique_object,
        parse_constant=_reject_number,
        parse_float=_reject_number,
    )
    return text


def _parsed_segments(head: str, body: str, signed: str) -> ParsedJws:
    """Parse three raw base64url segments, whichever wire form handed them over.

    A compact token's three dot-separated parts and a flattened wrapper's `protected`,
    `payload` and `signature` fields carry the same three strings, so both `parse_jws` and
    `flattened_jws` reduce to this. The signing input is `head + "." + body`, exactly the
    bytes ES256 signs, regardless of whether that dot ever appears in retained storage.
    """
    header = JwsHeader.model_validate_json(_strict_json(_segment(head)))
    claims = JwsClaims.model_validate_json(_strict_json(_segment(body)))
    signature = _segment(signed)
    if len(signature) != 64:
        raise ValueError()
    return ParsedJws(header, claims, f"{head}.{body}".encode("ascii"), signature)


def flattened_jws(protected: str, payload: str, signature: str) -> ParsedJws:
    """Parse the RFC 7515 flattened serialization's three segments into a `ParsedJws`.

    What `ExecutorVerifier.verify` checks a presented `SignedOutcomeJws` against, and what
    `recorded_outcome` reads a retained one back through is the same shape `parse_jws`
    produces from a compact token's three dot-separated parts.
    """
    try:
        return _parsed_segments(protected, payload, signature)
    except (ValueError, UnicodeError, RecursionError):
        raise ProviderError("INVALID_MESSAGE") from None


def parse_jws(token: str) -> ParsedJws:
    """Split and parse a compact ES256 JWS without trusting any of it yet."""
    if type(token) is not str or not 0 < len(token) <= MAX_JWS_BYTES:
        raise ProviderError("INVALID_MESSAGE")
    try:
        head, body, signed = token.split(".")
    except ValueError:
        raise ProviderError("INVALID_MESSAGE") from None
    return flattened_jws(head, body, signed)


def flattened_wrapper(parsed: ParsedJws, key_id: str) -> SignedOutcomeJws:
    """The retained form of a checked JWS: the flattened serialization, never the token.

    Rebuilt from the parsed pieces rather than kept from whatever bytes arrived, so a
    wrapper built from a freshly presented compact token and one built from a retained
    wrapper presented again are the same bytes. Splitting `signing_input` on its one dot is
    unambiguous because `_SEGMENT`'s charset excludes it, so a segment can never contain
    one; re-encoding the decoded signature reproduces the original base64 exactly, since
    `_segment` already refused any non-canonical spelling of it.
    """
    protected, payload = parsed.signing_input.decode("ascii").split(".")
    return SignedOutcomeJws(
        format=JWS_FORMAT,
        key_id=key_id,
        protected=protected,
        payload=payload,
        signature=_encode_segment(parsed.signature),
    )


def jws_record(claims: JwsClaims) -> ExecutorRecord:
    """The executor record a JWS's claims state, as the Ed25519 envelope carries one."""
    return ExecutorRecord(
        operation_id=claims.operation_id,
        account_id=claims.account_id,
        intent_hash=claims.intent_hash,
        plan_hash=claims.plan_hash,
        outcome=claims.outcome,
        reason=claims.reason,
        reported_at=claims.reported_at,
    )


def recorded_outcome(authenticated_record: str) -> ExecutorRecord:
    """The executor record an ATTESTED settlement retained, from either envelope."""
    raw = authenticated_record.encode()
    try:
        wrapped = parse_provider(raw, SignedOutcomeJws)
    except ProviderError:
        return parse_provider(raw, SignedOutcome).record
    return jws_record(flattened_jws(wrapped.protected, wrapped.payload, wrapped.signature).claims)
