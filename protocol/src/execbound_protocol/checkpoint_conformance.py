# SPDX-License-Identifier: Apache-2.0
"""Conformance for the checkpoint report, version 1: read an executor's reports as the route does.

An external executor holds its own vendor credential. It asks ExecBound for a grant, acts once at
its vendor and reports what happened on `POST /v1/executions/{execution_id}/outcome`; chapter 2
of the executor protocol (`docs/protocol/EXECUTOR_PROTOCOL.md`) is the normative text, and its
section 2.8 says what each report settles. This module is how anyone building such an executor
shows that its reports say what version 1 requires (section 2.10).

Each published vector is one grant as ExecBound answered it, one thing that happened at the
vendor, the report the vectors' own executor sent for it, and what that report settles. A caller
hands its executor a vector's grant and scenario, captures the report body the executor would
send, and `check` reads that body as the outcome route reads it: strict JSON of the bounded size,
exactly one piece of evidence, an outcome paired with its reason, the published report model,
the grant's report secret, and signed evidence that verifies under the caller's key ring, binds
the grant and states what the body states. It then asks what the report would settle, through
`settlement`, which is section 2.8 as a pure function, and compares that with the vector.

It needs, from the caller:

- the report body its executor produced for each vector's grant and scenario;
- the executor's key ring: for each key id the tenant registered, the key's scheme and a function
  that says whether a signature over a message is that key's (`RingKey`). The protocol package
  holds no cryptographic library, so the caller builds these with its own, exactly as
  `execbound_protocol.executor.sign_outcome` takes the caller's signer. An executor under test
  can sign with the vectors' own test keys, whose private halves the vector file publishes, or
  with keys of its own that the caller puts in the ring;
- optionally, the provider journal keys a journal verifies under. They are HMAC keys, which this
  module checks itself, and by default they are the vectors' own.

What it does not check: anything that needs the exchange itself (the agent credential, the
content type, the execution id the route is addressed to), whether a key was registered by the
grant and not revoked before it or reported compromised, which the ring the caller passes must
already reflect, anything after a first report (a settled execution's restatement rule, the
administrator's settlement and the correction), and when the executor acted, which is
cooperative. Every check raises `Nonconformance` naming itself, and none is an `assert`
statement, so the module checks the same under `python -O`.

It imports the protocol package and the standard library only, so a vendor can install
`execbound-protocol` and run it without the server.
"""

import hmac
import json
import re
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from datetime import datetime
from types import MappingProxyType
from typing import Any, Literal, get_args
from uuid import UUID

from execbound_protocol.canonical import canonical_json
from execbound_protocol.executor import (
    ExecutorRecord,
    SignedOutcome,
    jws_record,
    outcome_message,
    parse_jws,
)
from execbound_protocol.outcomes import TERMINAL_PAIRS, TerminalReason, consistent_terminal
from execbound_protocol.provider import (
    ProviderCommand,
    ProviderError,
    SignedJournal,
    parse_provider,
    signature,
)
from execbound_protocol.report import MAX_REPORT_BYTES, OutcomeReport
from execbound_protocol.strict import _reject_number, _unique_object

# Every check, in the order `check` runs them. The specification's conformance table for the
# checkpoint report names the same ids in the same order, and a test holds the two equal.
CHECKS: tuple[str, ...] = (
    "body",
    "evidence",
    "pairing",
    "model",
    "secret",
    "signature",
    "binding",
    "agreement",
    "tier",
    "settlement",
    "statement",
)

# The checks the outcome route refuses a report at, and the code it refuses with. A report
# failing any of the last three is accepted by the route and settles otherwise than its scenario
# says, which no refusal can tell the executor.
REFUSED_AS: Mapping[str, str] = MappingProxyType(
    {
        "body": "INVALID_REQUEST",
        "evidence": "INVALID_REQUEST",
        "pairing": "INVALID_REQUEST",
        "model": "INVALID_REQUEST",
        "secret": "INVALID_REPORT",  # nosec B105 - a refusal code, not a credential
        "signature": "INVALID_RECORD",
        "binding": "INVALID_RECORD",
        "agreement": "INVALID_RECORD",
    }
)

# The four fields of a report that are evidence, in the order the specification lists them.
EVIDENCE: tuple[str, ...] = ("reported_at", "record", "attestation", "journal")
SIGNED: frozenset[str] = frozenset({"record", "attestation", "journal"})
ALGORITHMS: frozenset[str] = frozenset({"ED25519", "ES256"})

# What a first report can leave behind, in the specification's own vocabulary.
STATES: frozenset[str] = frozenset(
    {
        "EXECUTED",
        "STALE_AUTHORIZATION",
        "FAILED_NOT_EXECUTED",
        "FAILED_EFFECT_UNKNOWN",
        "INDETERMINATE",
    }
)
TIERS: frozenset[str] = frozenset({"ATTESTED", "PROVIDER_VERIFIED", "ASSERTED"})
Impact = Literal["CONFIRMED", "RELEASED", "CHARGED"]
Claim = Literal["RELEASED", "HELD"]

# The outcomes a terminal report may name, each the outcome of at least one reason.
_TERMINAL = frozenset(TERMINAL_PAIRS.values())
_SIGNABLE = frozenset(get_args(TerminalReason))
# `report.ReportSecret`, restated because this module validates a grant without the model layer.
_REPORT_SECRET = re.compile(r"[A-Za-z0-9_-]{32,128}")
_DIGEST = re.compile(r"[0-9a-f]{64}")
_NAME = re.compile(r"[a-z0-9][a-z0-9-]{0,62}")


class Nonconformance(AssertionError):
    """A report says other than version 1 requires; `check` names which check found it."""

    def __init__(self, check: str, detail: str) -> None:
        self.check = check
        super().__init__(f"{check}: {detail}")

    @property
    def code(self) -> str | None:
        """The code the outcome route refuses such a report with, or None when it accepts it."""
        return REFUSED_AS.get(self.check)


class VectorError(ValueError):
    """A vector file is malformed, or a vector does not hold together on its own."""


# Whether `signature` is this key's signature over `message`. For an Ed25519 key the signature
# is the 64 raw bytes and the message the signed outcome's canonical bytes; for an ES256 key the
# signature is the JWS's raw 64-byte r and s and the message its signing input.
Verify = Callable[[bytes, bytes], bool]


@dataclass(frozen=True)
class RingKey:
    """One key the tenant registered for its executor: the scheme it verifies, and how."""

    algorithm: Literal["ED25519", "ES256"]
    verify: Verify = field(repr=False)

    def __post_init__(self) -> None:
        if self.algorithm not in ALGORITHMS or not callable(self.verify):
            raise ValueError("Invalid ring key")


@dataclass(frozen=True)
class VectorKey:
    """A key the vectors sign with: public test material that authenticates nothing anywhere.

    An Ed25519 key's public half is its 32 raw bytes and its private half the 32-byte seed; an
    ES256 key's public half is its 33-byte compressed point and its private half the 32-byte
    scalar, big-endian. The private half is published so that an executor under test can sign
    as the vectors' executor did; ExecBound never holds an executor's private key.
    """

    key_id: str
    algorithm: Literal["ED25519", "ES256"]
    public_key: bytes
    private_key: bytes = field(repr=False)


@dataclass(frozen=True)
class Settlement:
    """What a report settles: the execution's state, the tier, the reserved impact, the claim.

    `impact` is CONFIRMED (charged as an act that happened), RELEASED (refunded as a
    non-execution) or CHARGED (still reserved, as an uncertain grant leaves it); `claim` is the
    canonical target claim, RELEASED or HELD. A held claim after an asserted settlement is
    released by a recovery run once the act window has passed, which is not this report's doing.
    """

    state: str
    tier: str | None
    impact: Impact
    claim: Claim

    def __post_init__(self) -> None:
        if (
            self.state not in STATES
            or (self.tier is not None and self.tier not in TIERS)
            or self.impact not in get_args(Impact)
            or self.claim not in get_args(Claim)
        ):
            raise ValueError("Invalid settlement")


def claimed_tier(report: OutcomeReport) -> str | None:
    """The most a report could settle at, from the field its evidence arrived in.

    A record or an attestation is the executor's own signature, a journal the provider's, and a
    reported time the executor's bare word; an unknown result names no tier. Signed evidence
    that does not verify, or that verifies as another tier than its field names, is refused
    rather than demoted, so this is a claim the route checks and never a settlement.
    """
    if report.outcome == "UNKNOWN":
        return None
    if report.journal is not None:
        return "PROVIDER_VERIFIED"
    return "ATTESTED" if report.signed else "ASSERTED"


def settlement(report: OutcomeReport, verified: bool) -> Settlement | None:
    """What a first report on an unsettled grant settles, exactly as section 2.8 states it.

    `verified` says whether the report's signed evidence verified under the ring, binds the grant
    and states what the body states. Signed evidence that did not is refused with
    `INVALID_RECORD` and settles nothing, which is None: the grant stays as it was. A report with
    no evidence has nothing to verify, so `verified` is False for it.

    Verified evidence settles at the outcome it states, a version mismatch as stale authority,
    confirms the impact of an act and releases the impact of a non-execution, and releases the
    claim either way. The executor's bare word confirms an execution or a reported failure and
    frees nothing, and a bare non-execution, like an unknown result, settles nothing: the grant
    is left uncertain, still charged and still holding its target.
    """
    if type(verified) is not bool:
        raise TypeError("Whether the evidence verified is a bool")
    if not report.signed:
        if verified:
            raise ValueError("A report with no evidence has nothing to verify")
        if report.outcome in {"EXECUTED", "FAILED_EFFECT_UNKNOWN"}:
            return Settlement(report.outcome, "ASSERTED", "CONFIRMED", "HELD")
        return Settlement("INDETERMINATE", None, "CHARGED", "HELD")
    if not verified:
        return None
    # The model admits signed evidence only beside a terminal outcome with a reason signed
    # evidence may carry, so the outcome here is EXECUTED or FAILED_NOT_EXECUTED.
    state = "STALE_AUTHORIZATION" if report.reason == "VERSION_MISMATCH" else report.outcome
    impact: Impact = "CONFIRMED" if report.outcome == "EXECUTED" else "RELEASED"
    return Settlement(state, claimed_tier(report), impact, "RELEASED")


@dataclass(frozen=True)
class Binding:
    """The four values a signed report binds, as `grant.binding` names them."""

    operation_id: UUID
    account_id: UUID
    intent_hash: str
    plan_hash: str


@dataclass(frozen=True)
class Grant:
    """A grant as ExecBound answered it (section 2.2), the execution it settles, and its instant.

    `granted_at` is when ExecBound issued it, which the answer does not carry: a signed
    statement may not be dated before that second, and a provider journal not before that
    instant. `wire` is the `grant` object exactly as the answer carried it, for a harness that
    hands it to the executor under test; the other fields are read from it.
    """

    execution_id: UUID
    granted_at: datetime
    binding: Binding
    report_secret: str = field(repr=False)
    provider_command: ProviderCommand | None
    wire: Mapping[str, Any] = field(repr=False)

    @classmethod
    def read(
        cls, execution_id: str | UUID, grant: Mapping[str, Any], granted_at: datetime
    ) -> "Grant":
        """Read a first grant's answer, refusing one that does not describe one operation."""
        try:
            execution = execution_id if type(execution_id) is UUID else _uuid(execution_id)
            bound = grant["binding"]
            if not isinstance(bound, dict) or set(bound) != {
                "operation_id",
                "account_id",
                "intent_hash",
                "plan_hash",
            }:
                raise ValueError()
            binding = Binding(
                _uuid(bound["operation_id"]),
                _uuid(bound["account_id"]),
                _digest(bound["intent_hash"]),
                _digest(bound["plan_hash"]),
            )
            secret = grant["report_secret"]
            versioned = grant.get("expected_version") is not None
            if (
                _uuid(grant["operation_id"]) != binding.operation_id
                or type(secret) is not str
                or not _REPORT_SECRET.fullmatch(secret)
                or grant.get("regranted") is not False
                # A version, and the provider command that carries it, accompany exactly a
                # class that is not UNAVAILABLE.
                or versioned != (grant.get("precondition_class") != "UNAVAILABLE")
                or versioned != (grant.get("provider_command") is not None)
            ):
                raise ValueError()
            if not isinstance(granted_at, datetime) or granted_at.utcoffset() is None:
                raise ValueError()
            command = None
            if grant.get("provider_command") is not None:
                command = parse_provider(
                    canonical_json(grant["provider_command"]).encode(), ProviderCommand
                )
                if (
                    command.operation_id != binding.operation_id
                    or command.account_id != binding.account_id
                    or command.intent_hash != binding.intent_hash
                    or command.plan_hash != binding.plan_hash
                    or command.execution_id != execution
                    or command.expected_version != grant.get("expected_version")
                    # The act the grant describes is the act its command would perform.
                    or command.provider != grant.get("provider")
                    or command.provider_operation != grant.get("provider_operation")
                    or command.action != grant.get("action")
                    or command.resource_provider_id != grant.get("resource_provider_id")
                ):
                    raise ValueError()
        except (KeyError, TypeError, ValueError):
            raise VectorError("Not a first grant that names one operation") from None
        return cls(execution, granted_at, binding, secret, command, MappingProxyType(dict(grant)))


def _uuid(value: object) -> UUID:
    """A UUID in its one canonical spelling, as every protocol object writes it."""
    if type(value) is not str:
        raise ValueError()
    parsed = UUID(value)
    if str(parsed) != value:
        raise ValueError()
    return parsed


def _digest(value: object) -> str:
    if type(value) is not str or not _DIGEST.fullmatch(value):
        raise ValueError()
    return value


@dataclass(frozen=True)
class Vector:
    """One published vector: a grant, what happened, the report sent for it, what it settles.

    `row` is the row of section 2.8's table the vector is, in that table's own words. `report`
    is the report body the vectors' executor sent, as canonical JSON.
    """

    name: str
    row: str
    scenario: str
    grant: Grant
    report: bytes = field(repr=False)
    settles: Settlement
    journal_keys: Mapping[str, bytes] = field(repr=False)

    @property
    def statement(self) -> OutcomeReport:
        """The vector's own report, parsed: the outcome, reason and evidence its scenario takes."""
        return OutcomeReport.model_validate_json(self.report)


@dataclass(frozen=True)
class Refusal:
    """One published refusal: a report the route refuses with `code`, the fault it carries, and
    `check`, the check of this module that names that fault."""

    name: str
    fault: str
    code: Literal["INVALID_REQUEST", "INVALID_RECORD"]
    check: str
    grant: Grant
    report: bytes = field(repr=False)
    journal_keys: Mapping[str, bytes] = field(repr=False)


@dataclass(frozen=True)
class Vectors:
    """A loaded vector file: its keys, its vectors in name order, and its refusals."""

    executor_keys: Mapping[str, VectorKey] = field(repr=False)
    journal_keys: Mapping[str, bytes] = field(repr=False)
    vectors: tuple[Vector, ...]
    refusals: tuple[Refusal, ...]


class _Reading:
    """One report read against one grant, check by check, as the outcome route reads it.

    `keys` None reads everything but an executor's own signature, which is how a vector file is
    checked to hold together: the module has no way to verify an Ed25519 or ES256 signature of
    its own, and the file's signatures are checked by `check` under the caller's ring.
    """

    def __init__(
        self,
        grant: Grant,
        keys: Mapping[str, RingKey] | None,
        journal_keys: Mapping[str, bytes],
    ) -> None:
        self.grant, self.keys, self.journal_keys = grant, keys, journal_keys

    def read(self, raw: bytes) -> OutcomeReport:
        check = "body"
        if type(raw) is not bytes:
            raise Nonconformance(check, "is not bytes")
        if not 0 < len(raw) <= MAX_REPORT_BYTES:
            raise Nonconformance(check, f"is {len(raw):,} bytes; a report is 1 to 16,384")
        try:
            document = json.loads(
                raw.decode("utf-8"),
                object_pairs_hook=_unique_object,
                parse_constant=_reject_number,
                parse_float=_reject_number,
            )
        except (ValueError, RecursionError):
            raise Nonconformance(
                check,
                "is not strict UTF-8 JSON: no repeated key, and no number but an integer",
            ) from None
        if not isinstance(document, dict):
            raise Nonconformance(check, "is not a JSON object")

        check = "evidence"
        carried = [name for name in EVIDENCE if document.get(name) is not None]
        if len(carried) != 1:
            raise Nonconformance(
                check,
                f"carries {', '.join(carried) or 'none of them'}; a report carries exactly one of "
                "reported_at, record, attestation and journal",
            )
        signed = carried[0] in SIGNED

        check = "pairing"
        outcome, reason = document.get("outcome"), document.get("reason")
        if outcome == "UNKNOWN":
            if reason is not None or signed:
                raise Nonconformance(
                    check,
                    "an UNKNOWN report is not terminal: it carries no reason and nothing signed",
                )
        elif type(outcome) is not str or outcome not in _TERMINAL:
            raise Nonconformance(check, f"states the outcome {outcome!r}, which no report states")
        elif type(reason) is not str or not consistent_terminal(outcome, reason):
            paired = sorted(name for name, value in TERMINAL_PAIRS.items() if value == outcome)
            raise Nonconformance(
                check,
                f"pairs {outcome} with the reason {reason!r}; {outcome} is reported with "
                + " or ".join(paired),
            )
        elif signed and reason not in _SIGNABLE:
            raise Nonconformance(
                check, f"carries signed evidence beside {reason}, which no signed evidence states"
            )

        check = "model"
        try:
            report = OutcomeReport.model_validate_json(raw)
        except ValueError:
            raise Nonconformance(
                check,
                "is not a report the published model admits: a field it does not name, "
                "or a field of the wrong shape",
            ) from None

        check = "secret"
        if not hmac.compare_digest(
            report.report_secret.encode(), self.grant.report_secret.encode()
        ):
            raise Nonconformance(check, "presents another report secret than the grant's")

        if report.record is not None:
            self._record(report)
        elif report.attestation is not None:
            self._attestation(report)
        elif report.journal is not None:
            self._journal(report)
        return report

    def _statement(self, report: OutcomeReport, record: ExecutorRecord) -> None:
        """The binding and agreement checks every executor statement passes, either envelope."""
        check = "binding"
        binding = self.grant.binding
        if (
            record.operation_id != binding.operation_id
            or record.account_id != binding.account_id
            or record.intent_hash != binding.intent_hash
            or record.plan_hash != binding.plan_hash
        ):
            raise Nonconformance(check, "the signed statement binds another grant than this one")
        if record.reported_at < self.grant.granted_at.replace(microsecond=0):
            raise Nonconformance(check, "the signed statement is dated before the grant's second")
        check = "agreement"
        if (record.outcome, record.reason) != (report.outcome, report.reason):
            raise Nonconformance(
                check,
                f"the body says {report.outcome} {report.reason} and the signed statement "
                f"{record.outcome} {record.reason}",
            )

    def _key(self, key_id: str, algorithm: str) -> RingKey | None:
        if self.keys is None:
            return None
        key = self.keys.get(key_id)
        if key is None:
            raise Nonconformance("signature", f"signed under key id {key_id!r}, outside the ring")
        if key.algorithm != algorithm:
            raise Nonconformance(
                "signature",
                f"{key_id!r} is an {key.algorithm} key; a key verifies only its own scheme",
            )
        return key

    def _record(self, report: OutcomeReport) -> None:
        check = "signature"
        evidence = report.evidence
        try:
            signed = parse_provider(evidence or b"", SignedOutcome)
        except ProviderError:
            raise Nonconformance(check, "the record is not an Ed25519 signed outcome") from None
        key = self._key(signed.key_id, "ED25519")
        if key is not None and not _verifies(
            key, bytes.fromhex(signed.signature), outcome_message(signed)
        ):
            raise Nonconformance(check, "the record's signature does not verify")
        self._statement(report, signed.record)

    def _attestation(self, report: OutcomeReport) -> None:
        check = "signature"
        try:
            parsed = parse_jws(report.attestation or "")
        except ProviderError:
            raise Nonconformance(
                check,
                "the attestation is not an ES256 compact JWS of the published header and claims",
            ) from None
        key = self._key(parsed.header.kid, "ES256")
        if key is not None and not _verifies(key, parsed.signature, parsed.signing_input):
            raise Nonconformance(check, "the attestation's signature does not verify")
        self._statement(report, jws_record(parsed.claims))

    def _journal(self, report: OutcomeReport) -> None:
        check = "signature"
        try:
            signed = parse_provider(report.evidence or b"", SignedJournal)
        except ProviderError:
            raise Nonconformance(check, "the journal is not a provider's signed journal") from None
        key = self.journal_keys.get(signed.key_id)
        if key is None:
            raise Nonconformance(
                check, f"the journal is signed under key id {signed.key_id!r}, outside the ring"
            )
        if not hmac.compare_digest(signed.signature, signature(signed.record, signed.key_id, key)):
            raise Nonconformance(check, "the journal's signature does not verify")
        check = "binding"
        if self.grant.provider_command is None:
            raise Nonconformance(
                check, "the grant carries no provider command for a journal to bind"
            )
        if signed.record.command != self.grant.provider_command:
            raise Nonconformance(check, "the journal binds another command than the grant's")
        if signed.record.occurred_at < self.grant.granted_at:
            raise Nonconformance(check, "the journal is dated before the grant")
        check = "agreement"
        outcome = "EXECUTED" if signed.record.outcome == "EXECUTED" else "FAILED_NOT_EXECUTED"
        if (outcome, signed.record.outcome) != (report.outcome, report.reason):
            raise Nonconformance(
                check,
                f"the body says {report.outcome} {report.reason} and the journal "
                f"{signed.record.outcome}",
            )


def _verifies(key: RingKey, signed: bytes, message: bytes) -> bool:
    """The caller's verifier, whose only admitted answer is True; anything else is a failure."""
    try:
        return key.verify(signed, message) is True
    except Exception:  # a verifier that raises on a bad signature, as `cryptography`'s do
        return False


def read_report(
    grant: Grant,
    report: bytes,
    keys: Mapping[str, RingKey],
    journal_keys: Mapping[str, bytes],
) -> OutcomeReport:
    """Read a report as the outcome route reads it, from `body` to `agreement`, or refuse it.

    What passes is a report the route accepts for this grant. What it settles is `settlement`'s
    to say: a report that passes carries either no evidence or evidence that verified.
    """
    if not isinstance(keys, Mapping):
        raise TypeError("The executor's key ring is a mapping of key id to RingKey")
    return _Reading(grant, keys, journal_keys).read(report)


def check(
    vector: Vector,
    report: bytes,
    keys: Mapping[str, RingKey],
    journal_keys: Mapping[str, bytes] | None = None,
) -> tuple[str, ...]:
    """Run every check of one executor's report for one vector, in order; the ids it passed.

    `keys` is the executor's ring, and `journal_keys` the provider journal keys, by default the
    vector's own. The report must be for the vector's grant, so a harness that issues its own
    grant passes the vector with that grant in its place (`dataclasses.replace`).
    """
    journal = vector.journal_keys if journal_keys is None else journal_keys
    found = read_report(vector.grant, report, keys, journal)
    expected = vector.statement

    if claimed_tier(found) != claimed_tier(expected):
        raise Nonconformance(
            "tier",
            f"presents {', '.join(found.signed) or 'no signed evidence'}, which settles at tier "
            f"{claimed_tier(found) or 'none'}; the scenario's report settles at "
            f"{claimed_tier(expected) or 'none'}",
        )
    settled = settlement(found, verified=bool(found.signed))
    if settled != vector.settles:
        raise Nonconformance("settlement", f"would settle {settled}, not {vector.settles}")
    if (found.outcome, found.reason) != (expected.outcome, expected.reason):
        raise Nonconformance(
            "statement",
            f"states {found.outcome} {found.reason}; the scenario is {expected.outcome} "
            f"{expected.reason}",
        )
    return CHECKS


def refused(
    refusal: Refusal,
    keys: Mapping[str, RingKey],
    journal_keys: Mapping[str, bytes] | None = None,
) -> Nonconformance:
    """The nonconformance this module finds in a refusal's report, at the refusal's own check."""
    journal = refusal.journal_keys if journal_keys is None else journal_keys
    try:
        read_report(refusal.grant, refusal.report, keys, journal)
    except Nonconformance as found:
        if found.check != refusal.check or found.code != refusal.code:
            raise VectorError(
                f"{refusal.name}: refused at {found.check}, not at {refusal.check}"
            ) from None
        return found
    raise VectorError(f"{refusal.name}: the report is admitted, so it is no refusal")


def _strict(raw: bytes) -> Any:
    try:
        return json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=_unique_object,
            parse_constant=_reject_number,
            parse_float=_reject_number,
        )
    except (ValueError, RecursionError):
        raise VectorError("The vector file is not strict JSON") from None


def _instant(value: object) -> datetime:
    if type(value) is not str:
        raise ValueError()
    parsed = datetime.fromisoformat(value)
    if parsed.utcoffset() is None:
        raise ValueError()
    return parsed


def _report(value: Any) -> bytes:
    """A report as the file writes it, in canonical bytes.

    An attestation is written as its three segments, `{"protected", "payload", "signature"}`,
    and joined here into the compact token the report carries, so no dot-joined token appears in
    the file itself. A body the route refuses before it is parsed is written as `report_text`.
    """
    if not isinstance(value, dict):
        raise ValueError()
    report = dict(value)
    segments = report.get("attestation")
    if isinstance(segments, dict):
        if set(segments) != {"protected", "payload", "signature"} or not all(
            type(part) is str for part in segments.values()
        ):
            raise ValueError()
        report["attestation"] = ".".join(
            segments[part] for part in ("protected", "payload", "signature")
        )
    return canonical_json(report).encode()


def _vector_key(key_id: str, value: Any) -> VectorKey:
    if not isinstance(value, dict) or set(value) != {"algorithm", "public_key", "test_private_key"}:
        raise ValueError()
    algorithm = value["algorithm"]
    public, private = bytes.fromhex(value["public_key"]), bytes.fromhex(value["test_private_key"])
    if algorithm not in ALGORITHMS or len(private) != 32:
        raise ValueError()
    if len(public) != (32 if algorithm == "ED25519" else 33):
        raise ValueError()
    return VectorKey(key_id, algorithm, public, private)


# The keys a vector, the shared refusal grant and a refusal with a grant of its own name a grant by.
_GRANT_KEYS = frozenset({"execution_id", "granted_at", "grant"})


def _grant(entry: Mapping[str, Any]) -> Grant:
    return Grant.read(entry["execution_id"], entry["grant"], _instant(entry["granted_at"]))


def _body(entry: Mapping[str, Any]) -> bytes:
    if ("report" in entry) == ("report_text" in entry):
        raise ValueError()
    if "report_text" in entry:
        text = entry["report_text"]
        if type(text) is not str:
            raise ValueError()
        return text.encode()
    return _report(entry["report"])


def _settles(value: Any) -> Settlement:
    if not isinstance(value, dict) or set(value) != {"state", "tier", "impact", "claim"}:
        raise ValueError()
    return Settlement(value["state"], value["tier"], value["impact"], value["claim"])


def load_vectors(raw: bytes) -> Vectors:
    """Every vector and refusal in one published file, each checked to hold together.

    A vector's report must be one the route reads for its grant, in every check but the
    executor's own signature, which needs the caller's ring, and it must settle by `settlement`
    exactly as the vector says; a refusal must be refused before or at the checks its code
    names. Both are refused as `VectorError` otherwise.
    """
    document = _strict(raw)
    if not isinstance(document, dict):
        raise VectorError("A vector file is a JSON object")
    try:
        if document["version"] != 1 or type(document["version"]) is not int:
            raise ValueError()
        executor_keys = {
            key_id: _vector_key(key_id, value)
            for key_id, value in document["executor_keys"].items()
        }
        journal_keys = {
            key_id: bytes.fromhex(value) for key_id, value in document["journal_keys"].items()
        }
        if not executor_keys or not journal_keys or any(len(k) < 32 for k in journal_keys.values()):
            raise ValueError()
        entries, refusals = document["vectors"], document["refusals"]
        if not isinstance(entries, dict) or not entries or not isinstance(refusals, dict):
            raise ValueError()
    except (KeyError, TypeError, ValueError, AttributeError):
        raise VectorError("The vector file names no keys, vectors or refusals") from None
    journal = MappingProxyType(journal_keys)

    found: list[Vector] = []
    for name in sorted(entries):
        entry = entries[name]
        try:
            if not _NAME.fullmatch(name) or set(entry) != {
                "row",
                "scenario",
                "execution_id",
                "granted_at",
                "grant",
                "report",
                "settles",
            }:
                raise ValueError()
            vector = Vector(
                name,
                entry["row"],
                entry["scenario"],
                _grant(entry),
                _body(entry),
                _settles(entry["settles"]),
                journal,
            )
            if type(vector.row) is not str or type(vector.scenario) is not str:
                raise ValueError()
        except (KeyError, TypeError, ValueError, AttributeError, VectorError):
            raise VectorError(f"{name}: not a grant, a report and a settlement") from None
        try:
            report = _Reading(vector.grant, None, journal).read(vector.report)
        except Nonconformance as fault:
            raise VectorError(f"{name}: the vector's own report fails {fault}") from None
        if settlement(report, verified=bool(report.signed)) != vector.settles:
            raise VectorError(f"{name}: the report does not settle as the vector says")
        found.append(vector)

    # The refusals share one grant: a refused report leaves its grant as it was, so the same
    # grant can be sent every one of them and still settle afterwards. A refusal whose fault
    # needs a grant of another kind, such as a journal under an UNAVAILABLE grant, carries its
    # own grant beside its report, under the three keys a vector names its grant with, and a
    # file in which no refusal does so reads as it always did.
    try:
        if set(refusals) != {"execution_id", "granted_at", "grant", "reports"}:
            raise ValueError()
        shared = _grant(refusals)
        reports = refusals["reports"]
        if not isinstance(reports, dict) or not reports:
            raise ValueError()
    except (KeyError, TypeError, ValueError, AttributeError, VectorError):
        raise VectorError("The refusals name no grant or no reports") from None
    held: list[Refusal] = []
    for name in sorted(reports):
        entry = reports[name]
        try:
            own = set(entry) & _GRANT_KEYS
            if (
                not _NAME.fullmatch(name)
                or set(entry) - {"report", "report_text"} - own != {"fault", "code", "check"}
                or own not in (set(), _GRANT_KEYS)
            ):
                raise ValueError()
            if entry["code"] not in {"INVALID_REQUEST", "INVALID_RECORD"} or (
                REFUSED_AS.get(entry["check"]) != entry["code"]
            ):
                raise ValueError()
            grant = _grant(entry) if own else shared
            refusal = Refusal(
                name, entry["fault"], entry["code"], entry["check"], grant, _body(entry), journal
            )
            if type(refusal.fault) is not str:
                raise ValueError()
        except (KeyError, TypeError, ValueError, AttributeError, VectorError):
            raise VectorError(f"{name}: not a fault, a code and a report") from None
        try:
            _Reading(refusal.grant, None, journal).read(refusal.report)
        except Nonconformance as fault:
            if fault.check != refusal.check:
                raise VectorError(
                    f"{name}: refused at {fault.check}, not at {refusal.check}"
                ) from None
        else:
            if refusal.check != "signature":
                # Only an executor's own signature is left unread here, so only a signature
                # refusal can need the ring to be found.
                raise VectorError(f"{name}: the report is admitted, so it is no refusal")
        held.append(refusal)
    return Vectors(MappingProxyType(executor_keys), journal, tuple(found), tuple(held))
