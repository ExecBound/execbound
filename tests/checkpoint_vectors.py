# SPDX-License-Identifier: AGPL-3.0-only
"""The checkpoint report vectors, written from one definition, and the executor that wrote them.

`protocol/executor/v1/vectors/checkpoint-report-v1.json` is `document_bytes()` byte for byte;
`tests/test_executor_protocol_v1.py` holds the two equal and rewrites the file. Each vector is a
scenario for one grant, and `Scenario.report` is the vectors' own executor: given any grant and a
key set, it writes the report that scenario calls for, signed with those keys. The file holds
what it wrote for the vectors' fixed grants with the published test keys, and
`tests/test_checkpoint_report_server.py` hands it grants a real gateway issued and keys of the
test's own, so the reports the file publishes and the reports the server is shown settling come
from one function. The refusals are built the same way, each a fault applied to a report for
whichever grant and keys it is given.

The settlements here are written out from section 2.8 of the specification, not computed: the
protocol package's `settlement` function, the server and this table are three statements of it,
and the tests hold all three equal.

Every key is public test material, published in the file, that authenticates nothing anywhere,
and ExecBound refuses every one of them wherever a key is registered or configured
(`tests/test_published_test_keys.py`), which is why the server is shown other keys. ES256 signs
deterministically (RFC 6979), so the file regenerates byte for byte.
"""

import base64
import dataclasses
import hashlib
import json
import secrets
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any
from uuid import UUID

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.asymmetric.utils import (
    decode_dss_signature,
    encode_dss_signature,
)
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from execbound_protocol.canonical import canonical_json
from execbound_protocol.checkpoint_conformance import Grant, RingKey, Vectors, load_vectors
from execbound_protocol.executor import (
    OUTCOME_DOMAIN,
    ExecutorRecord,
    flattened_wrapper,
    parse_jws,
    sign_outcome,
)
from execbound_protocol.provider import JournalRecord, ProviderCommand, sign_journal

ROOT = Path(__file__).resolve().parents[1]
PUBLISHED = ROOT / "protocol" / "executor" / "v1" / "vectors" / "checkpoint-report-v1.json"

ED25519_KEY_ID = "conformance-ed25519"
ES256_KEY_ID = "conformance-es256"
JOURNAL_KEY_ID = "conformance-journal"
# A key id no ring holds.
UNREGISTERED_KEY_ID = "conformance-unregistered"

# Recognizable byte runs rather than random ones, so nobody mistakes them for real keys.
ED25519_SEED = bytes(range(0x40, 0x60))
ES256_SCALAR = bytes(range(0x60, 0x80))
JOURNAL_KEY = bytes(range(0xC0, 0xE0))
# Keys outside every ring, for what must not verify.
OUTSIDE_ED25519_SEED = bytes(range(0x80, 0xA0))
OUTSIDE_ES256_SCALAR = bytes(range(0xA0, 0xC0))
OUTSIDE_JOURNAL_KEY = bytes(range(0xE0, 0x100))

TENANT = UUID("00000000-0000-4000-8000-000000000201")
ACCOUNT = UUID("00000000-0000-4000-8000-000000000202")
TARGET = UUID("00000000-0000-4000-8000-000000000203")
DEVICE = "conformance-device-01"
EXPECTED_VERSION = "resource-v7"
# The version the vendor's write produced, and the one a refused conditional write found.
EXECUTED_VERSION = "resource-v8"
FOUND_VERSION = "resource-v9"
# With microseconds, so a statement signed in the grant's own second but before its exact
# instant is a case the vectors state: such a statement is admitted, and a journal is not.
GRANTED_AT = datetime(2026, 10, 15, 9, 0, 0, 250_000, tzinfo=UTC)
# Another operation, for a statement that binds some other grant.
ANOTHER_OPERATION = UUID("00000000-0000-4000-8000-0000000003ff")


def ed25519(seed: bytes = ED25519_SEED) -> Ed25519PrivateKey:
    return Ed25519PrivateKey.from_private_bytes(seed)


def es256(scalar: bytes = ES256_SCALAR) -> ec.EllipticCurvePrivateKey:
    return ec.derive_private_key(int.from_bytes(scalar, "big"), ec.SECP256R1())


def ed25519_public(seed: bytes = ED25519_SEED) -> bytes:
    return ed25519(seed).public_key().public_bytes_raw()


def es256_public(scalar: bytes = ES256_SCALAR) -> bytes:
    return es256(scalar).public_key().public_bytes(Encoding.X962, PublicFormat.CompressedPoint)


def instant(value: datetime) -> str:
    """A time as the protocol's models write one: UTC, with `Z`."""
    return value.astimezone(UTC).isoformat().replace("+00:00", "Z")


def _digest(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()


def _command(operation: UUID, execution: UUID, intent_hash: str, plan_hash: str) -> ProviderCommand:
    """The command ExecBound would send for one of the vectors' grants, at the frozen version."""
    return ProviderCommand(
        tenant_id=TENANT,
        account_id=ACCOUNT,
        canonical_target_id=TARGET,
        provider="mock_crowdstrike",
        action="endpoint.isolate",
        provider_operation="contain",
        resource_provider_id=DEVICE,
        expected_version=EXPECTED_VERSION,
        operation_id=operation,
        execution_id=execution,
        intent_hash=intent_hash,
        plan_hash=plan_hash,
    )


def fixed_grant(index: int, label: str, precondition_class: str = "ENFORCED_BY_PROVIDER") -> Grant:
    """A grant as ExecBound would answer it, with made-up, fixed ids for one vector.

    Every grant is for `endpoint.isolate` on one target of one account. Most are under the
    class that carries the frozen version and the provider command, so a provider's journal can
    bind them; a grant under `UNAVAILABLE` carries neither, as the presenter writes one.
    """
    operation = UUID(f"00000000-0000-4000-8000-{0x300 + index:012x}")
    execution = UUID(f"00000000-0000-4000-8000-{0x400 + index:012x}")
    binding = {
        "operation_id": str(operation),
        "account_id": str(ACCOUNT),
        "intent_hash": _digest(f"checkpoint-report-v1:{label}:intent"),
        "plan_hash": _digest(f"checkpoint-report-v1:{label}:plan"),
    }
    command = _command(operation, execution, binding["intent_hash"], binding["plan_hash"])
    versioned = precondition_class != "UNAVAILABLE"
    wire: dict[str, Any] = {
        "operation_id": str(operation),
        "provider": "mock_crowdstrike",
        "provider_operation": "contain",
        "resource_provider_id": DEVICE,
        "action": "endpoint.isolate",
        "arguments": {},
        "precondition_class": precondition_class,
        "expected_version": EXPECTED_VERSION if versioned else None,
        "act_expires_at": instant(GRANTED_AT + timedelta(minutes=15)),
        "report_expires_at": instant(GRANTED_AT + timedelta(hours=24)),
        "regranted": False,
        "report_secret": f"vector-{index:02d}-report-secret-" + "0" * 24,
        "binding": binding,
    }
    if versioned:
        wire["provider_command"] = command.model_dump(mode="json")
    return Grant.read(execution, wire, GRANTED_AT)


def unsent_command(grant: Grant) -> ProviderCommand:
    """The command ExecBound would have sent for one of the vectors' own grants.

    A grant under `UNAVAILABLE` carries no provider command, but its plan froze one: the same
    operation, execution and hashes at the frozen version. A provider handed it some other way
    would sign a journal of exactly this, which the outcome route and the module refuse all the
    same, because the grant never carried it. For a grant the gateway issued the command is the
    gateway's own, read from the execution it froze.
    """
    binding = grant.binding
    return _command(
        binding.operation_id, grant.execution_id, binding.intent_hash, binding.plan_hash
    )


def relaying(grant: Grant, command: ProviderCommand) -> Grant:
    """The grant as an executor relaying a journal of `command` would hold it: with that command
    where the grant's own provider command would be. Nothing else about the grant changes."""
    return dataclasses.replace(grant, provider_command=command)


def reported_at(grant: Grant) -> datetime:
    """When the vectors' executor reports: two minutes after the grant's second."""
    return grant.granted_at.replace(microsecond=0) + timedelta(minutes=2)


def grants_second(grant: Grant) -> datetime:
    """The start of the second the grant was issued in, which is before its exact instant."""
    return grant.granted_at.replace(microsecond=0)


# The evidence an executor can present, each built for any grant.


def record(
    grant: Grant,
    outcome: str,
    reason: str,
    *,
    seed: bytes = ED25519_SEED,
    key_id: str = ED25519_KEY_ID,
    operation: UUID | None = None,
    at: datetime | None = None,
) -> dict[str, Any]:
    """An Ed25519 signed outcome, as `sign_outcome` writes it."""
    statement = ExecutorRecord(
        operation_id=operation or grant.binding.operation_id,
        account_id=grant.binding.account_id,
        intent_hash=grant.binding.intent_hash,
        plan_hash=grant.binding.plan_hash,
        outcome=outcome,
        reason=reason,
        reported_at=at or reported_at(grant),
    )
    return sign_outcome(statement, key_id, ed25519(seed)).model_dump(mode="json")


def _segment(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def attestation(
    grant: Grant,
    outcome: str,
    reason: str,
    *,
    scalar: bytes = ES256_SCALAR,
    key_id: str = ES256_KEY_ID,
    operation: UUID | None = None,
    at: datetime | None = None,
) -> str:
    """An ES256 compact JWS of the same statement: a canonical header and claims, raw r and s."""
    header = {"alg": "ES256", "kid": key_id}
    claims = {
        "domain": OUTCOME_DOMAIN,
        "version": 1,
        "operation_id": str(operation or grant.binding.operation_id),
        "account_id": str(grant.binding.account_id),
        "intent_hash": grant.binding.intent_hash,
        "plan_hash": grant.binding.plan_hash,
        "outcome": outcome,
        "reason": reason,
        "reported_at": instant(at or reported_at(grant)),
    }
    head = _segment(canonical_json(header).encode())
    body = _segment(canonical_json(claims).encode())
    der = es256(scalar).sign(
        f"{head}.{body}".encode("ascii"), ec.ECDSA(hashes.SHA256(), deterministic_signing=True)
    )
    r, s = decode_dss_signature(der)
    return f"{head}.{body}.{_segment(r.to_bytes(32, 'big') + s.to_bytes(32, 'big'))}"


def stored_attestation(token: str) -> dict[str, Any]:
    """An attestation in the form a settlement stores it: RFC 7515 flattened JSON, three
    segments and the key id, as the protocol's own `flattened_wrapper` writes it.

    An administrator's settlement may present this form again. The outcome route never takes
    it: ES256 arrives there only as `attestation`, and a `record` is an Ed25519 signed outcome.
    """
    parsed = parse_jws(token)
    return flattened_wrapper(parsed, parsed.header.kid).model_dump(mode="json")


def journal(
    grant: Grant,
    outcome: str,
    *,
    key: bytes = JOURNAL_KEY,
    key_id: str = JOURNAL_KEY_ID,
    expected_version: str | None = None,
    at: datetime | None = None,
) -> dict[str, Any]:
    """The signed journal a chapter 1 provider writes for exactly the grant's provider command.

    `outcome` is the journal's own vocabulary, which is the report's reason.
    """
    command = grant.provider_command
    assert command is not None, "a journal binds a grant that carries a provider command"
    if expected_version is not None:
        command = command.model_copy(update={"expected_version": expected_version})
    entry = JournalRecord(
        command=command,
        command_hash=command.command_hash,
        outcome=outcome,
        occurred_at=at or grants_second(grant) + timedelta(minutes=1),
        resulting_version={"EXECUTED": EXECUTED_VERSION, "VERSION_MISMATCH": FOUND_VERSION}.get(
            outcome
        ),
        mutation_count=1 if outcome == "EXECUTED" else 0,
    )
    return sign_journal(entry, key_id, key).model_dump(mode="json")


@dataclass(frozen=True)
class Keys:
    """The keys the vectors' executor signs with: its Ed25519 and ES256 keys, and the
    provider's journal key, each under the vectors' own key id.

    The file is written with the published ones, `PUBLISHED_KEYS`. ExecBound refuses those
    wherever a key is registered or configured (#37), so a test that shows the server settling
    the vectors gives it keys of its own, `Keys.generate()`, and the same executor writes the
    same scenarios with them. Each method is the module function of the same name with this
    set's key as its default, and a key passed explicitly, such as one outside every ring,
    still wins.
    """

    ed25519_seed: bytes = field(repr=False)
    es256_scalar: bytes = field(repr=False)
    journal_key: bytes = field(repr=False)

    @classmethod
    def generate(cls) -> "Keys":
        """Fresh keys nobody else holds."""
        scalar = ec.generate_private_key(ec.SECP256R1()).private_numbers().private_value
        return cls(secrets.token_bytes(32), scalar.to_bytes(32, "big"), secrets.token_bytes(32))

    def record(self, grant: Grant, outcome: str, reason: str, **changes: Any) -> dict[str, Any]:
        return record(grant, outcome, reason, **({"seed": self.ed25519_seed} | changes))

    def attestation(self, grant: Grant, outcome: str, reason: str, **changes: Any) -> str:
        return attestation(grant, outcome, reason, **({"scalar": self.es256_scalar} | changes))

    def journal(self, grant: Grant, outcome: str, **changes: Any) -> dict[str, Any]:
        return journal(grant, outcome, **({"key": self.journal_key} | changes))

    def public_keys(self) -> dict[str, tuple[str, bytes]]:
        """Each executor key id with its scheme and public half, as an administrator registers
        them."""
        return {
            ED25519_KEY_ID: ("ED25519", ed25519_public(self.ed25519_seed)),
            ES256_KEY_ID: ("ES256", es256_public(self.es256_scalar)),
        }

    def ring(self) -> dict[str, RingKey]:
        """The executor ring the conformance module checks these keys' reports against."""
        return {
            key_id: ring_key(algorithm, public)
            for key_id, (algorithm, public) in self.public_keys().items()
        }

    def journal_keys(self) -> dict[str, bytes]:
        return {JOURNAL_KEY_ID: self.journal_key}


PUBLISHED_KEYS = Keys(ED25519_SEED, ES256_SCALAR, JOURNAL_KEY)

EVIDENCE = ("record", "attestation", "journal", "reported_at")


def evidence(
    kind: str,
    grant: Grant,
    outcome: str,
    reason: str | None,
    *,
    at: datetime | None = None,
    keys: Keys = PUBLISHED_KEYS,
) -> dict[str, Any]:
    """The one piece of evidence of `kind` for this statement, as a report field."""
    if kind == "reported_at":
        return {"reported_at": instant(at or reported_at(grant))}
    assert reason is not None, "signed evidence states a terminal reason"
    if kind == "record":
        return {"record": keys.record(grant, outcome, reason, at=at)}
    if kind == "attestation":
        return {"attestation": keys.attestation(grant, outcome, reason, at=at)}
    return {"journal": keys.journal(grant, reason, at=at)}


@dataclass(frozen=True)
class Scenario:
    """One vector before it is written: what happened, how it is reported, what it settles."""

    name: str
    row: str
    scenario: str
    outcome: str
    reason: str | None
    evidence: str
    settles: dict[str, str | None]
    # The class the grant is issued under, which a harness or a gateway must declare.
    precondition_class: str = "ENFORCED_BY_PROVIDER"
    # Whether the executor signs the start of the grant's own second, as one that can sign
    # only whole seconds does, rather than a time after it.
    whole_second: bool = False

    def report(self, grant: Grant, keys: Keys = PUBLISHED_KEYS) -> dict[str, Any]:
        """The report the vectors' executor sends for this scenario on `grant`, signed with
        `keys`."""
        body: dict[str, Any] = {"report_secret": grant.report_secret, "outcome": self.outcome}
        if self.reason is not None:
            body["reason"] = self.reason
        at = grants_second(grant) if self.whole_second else None
        return body | evidence(self.evidence, grant, self.outcome, self.reason, at=at, keys=keys)


def settles(state: str, tier: str | None, impact: str, claim: str) -> dict[str, str | None]:
    return {"state": state, "tier": tier, "impact": impact, "claim": claim}


_SIGNERS = {
    "record": "the executor signs a record with its Ed25519 key",
    "attestation": "the executor signs an ES256 attestation",
    "journal": "the vendor speaks chapter 1 and answered the grant's provider command with its "
    "signed journal, which the executor relays",
}
_HAPPENED = {
    "EXECUTED": "The vendor performed the action",
    "VERSION_MISMATCH": "The vendor refused the conditional write: the target was no longer at "
    "the expected version",
    "CANCELLED_NOT_EXECUTED": "The executor decided not to act and never called the vendor",
    "TARGET_NOT_FOUND": "The vendor holds no such target",
}
_ROWS = {
    "EXECUTED": "Signed EXECUTED",
    "VERSION_MISMATCH": "Signed VERSION_MISMATCH",
    "CANCELLED_NOT_EXECUTED": "Signed CANCELLED_NOT_EXECUTED or TARGET_NOT_FOUND",
    "TARGET_NOT_FOUND": "Signed CANCELLED_NOT_EXECUTED or TARGET_NOT_FOUND",
}
_SIGNED_SETTLES = {
    "EXECUTED": ("EXECUTED", "CONFIRMED"),
    "VERSION_MISMATCH": ("STALE_AUTHORIZATION", "RELEASED"),
    "CANCELLED_NOT_EXECUTED": ("FAILED_NOT_EXECUTED", "RELEASED"),
    "TARGET_NOT_FOUND": ("FAILED_NOT_EXECUTED", "RELEASED"),
}
_SLUGS = {
    "EXECUTED": "executed",
    "VERSION_MISMATCH": "version-mismatch",
    "CANCELLED_NOT_EXECUTED": "cancelled",
    "TARGET_NOT_FOUND": "target-not-found",
}


def _signed() -> list[Scenario]:
    found = []
    for kind, tier in (
        ("record", "ATTESTED"),
        ("attestation", "ATTESTED"),
        ("journal", "PROVIDER_VERIFIED"),
    ):
        for reason, (state, impact) in _SIGNED_SETTLES.items():
            outcome = "EXECUTED" if reason == "EXECUTED" else "FAILED_NOT_EXECUTED"
            text = f"{_HAPPENED[reason]}, and {_SIGNERS[kind]}."
            if (kind, reason) == ("journal", "CANCELLED_NOT_EXECUTED"):
                # A provider records a cancellation only when it is asked for one, so this
                # executor did reach the vendor: to cancel, never to act.
                text = (
                    "The executor cancelled the operation at the vendor before dispatching it, "
                    "and relays the provider's cancellation tombstone: its signed journal of "
                    "the grant's provider command, recording that nothing was executed."
                )
            found.append(
                Scenario(
                    name=f"{kind}-{_SLUGS[reason]}",
                    row="A provider's journal" if kind == "journal" else _ROWS[reason],
                    scenario=text,
                    outcome=outcome,
                    reason=reason,
                    evidence=kind,
                    settles=settles(state, tier, impact, "RELEASED"),
                )
            )
    return found


SCENARIOS: tuple[Scenario, ...] = (
    *_signed(),
    Scenario(
        "asserted-executed",
        "Unsigned EXECUTED",
        "The vendor performed the action, and the executor says so without signing.",
        "EXECUTED",
        "EXECUTED",
        "reported_at",
        settles("EXECUTED", "ASSERTED", "CONFIRMED", "HELD"),
    ),
    Scenario(
        "asserted-reported-failure",
        "Unsigned REPORTED_FAILURE",
        "The vendor call failed, and whether the vendor acted is not established.",
        "FAILED_EFFECT_UNKNOWN",
        "REPORTED_FAILURE",
        "reported_at",
        settles("FAILED_EFFECT_UNKNOWN", "ASSERTED", "CONFIRMED", "HELD"),
    ),
    *(
        Scenario(
            f"asserted-{_SLUGS[reason]}",
            "Unsigned non-execution",
            f"{_HAPPENED[reason]}, and the executor says so without signing.",
            "FAILED_NOT_EXECUTED",
            reason,
            "reported_at",
            settles("INDETERMINATE", None, "CHARGED", "HELD"),
        )
        for reason in ("VERSION_MISMATCH", "CANCELLED_NOT_EXECUTED", "TARGET_NOT_FOUND")
    ),
    Scenario(
        "unknown",
        "UNKNOWN",
        "The vendor call timed out, and the executor does not know whether the vendor acted.",
        "UNKNOWN",
        None,
        "reported_at",
        settles("INDETERMINATE", None, "CHARGED", "HELD"),
    ),
    # A statement signed in the grant's own second, before its exact instant, as an executor
    # that signs whole seconds writes one: admitted, because a signed time is compared with
    # the grant at one-second precision.
    *(
        Scenario(
            f"{kind}-executed-in-the-grants-second",
            "Signed EXECUTED",
            "The vendor performed the action, and the executor, which signs whole seconds "
            f"only, {_SIGNERS[kind].removeprefix('the executor ')} dated at the start of the "
            "second the grant was issued in, before the grant's exact instant.",
            "EXECUTED",
            "EXECUTED",
            kind,
            settles("EXECUTED", "ATTESTED", "CONFIRMED", "RELEASED"),
            whole_second=True,
        )
        for kind in ("record", "attestation")
    ),
    # The two other classes a grant can be issued under. Section 2.8 does not vary by class.
    Scenario(
        "class-unavailable-attestation-executed",
        "Signed EXECUTED",
        "The grant's class is UNAVAILABLE, so it carries no version and no provider command; "
        "the vendor performed the action, and the executor signs an ES256 attestation.",
        "EXECUTED",
        "EXECUTED",
        "attestation",
        settles("EXECUTED", "ATTESTED", "CONFIRMED", "RELEASED"),
        precondition_class="UNAVAILABLE",
    ),
    Scenario(
        "class-unavailable-asserted-executed",
        "Unsigned EXECUTED",
        "The grant's class is UNAVAILABLE; the vendor performed the action, and the executor "
        "says so without signing.",
        "EXECUTED",
        "EXECUTED",
        "reported_at",
        settles("EXECUTED", "ASSERTED", "CONFIRMED", "HELD"),
        precondition_class="UNAVAILABLE",
    ),
    Scenario(
        "class-asserted-by-executor-record-version-mismatch",
        "Signed VERSION_MISMATCH",
        "The grant's class is ASSERTED_BY_EXECUTOR: the executor read the target, found it no "
        "longer at the expected version and did not act, and signs that with its Ed25519 key.",
        "FAILED_NOT_EXECUTED",
        "VERSION_MISMATCH",
        "record",
        settles("STALE_AUTHORIZATION", "ATTESTED", "RELEASED", "RELEASED"),
        precondition_class="ASSERTED_BY_EXECUTOR",
    ),
    Scenario(
        "class-asserted-by-executor-asserted-version-mismatch",
        "Unsigned non-execution",
        "The grant's class is ASSERTED_BY_EXECUTOR: the executor found the target no longer at "
        "the expected version and did not act, and says so without signing.",
        "FAILED_NOT_EXECUTED",
        "VERSION_MISMATCH",
        "reported_at",
        settles("INDETERMINATE", None, "CHARGED", "HELD"),
        precondition_class="ASSERTED_BY_EXECUTOR",
    ),
)
BY_NAME = {scenario.name: scenario for scenario in SCENARIOS}
# The grant each vector is written for: a fixed index, so a vector's ids never move.
INDEX = {scenario.name: index for index, scenario in enumerate(SCENARIOS, start=1)}
REFUSAL_INDEX = 0x80
# The grant a refusal under another class than the shared grant's is written for, by class.
OWN_REFUSAL_INDEX = {"UNAVAILABLE": REFUSAL_INDEX + 0x10}


@dataclass(frozen=True)
class Fault:
    """One refusal before it is written: a fault, its code, the conformance check that names
    it, and the report that carries it.

    `build` returns a report object, or text for a body the route refuses before parsing it,
    signed where it signs with the keys it is given.

    `precondition_class` is the class of the grant the fault is shown under. A fault under the
    shared grant's class is written for the shared grant; one under another class is written
    for a grant of its own, which the file carries beside it. A fault that relays a journal
    under `UNAVAILABLE` relays one of the command ExecBound would have sent, which the grant
    does not carry, so `report` hands `build` the grant with that command in its place.
    """

    name: str
    fault: str
    code: str
    check: str
    build: Callable[[Grant, Keys], dict[str, Any] | str]
    precondition_class: str = "ENFORCED_BY_PROVIDER"

    def report(
        self,
        grant: Grant,
        keys: Keys = PUBLISHED_KEYS,
        unsent: ProviderCommand | None = None,
    ) -> dict[str, Any] | str:
        """The report carrying this fault for `grant`, signed with `keys`.

        `unsent` is the command ExecBound would have sent, for a grant that carries no provider
        command; for one of the vectors' own grants it defaults to `unsent_command`'s.
        """
        if grant.provider_command is None:
            grant = relaying(grant, unsent or unsent_command(grant))
        return self.build(grant, keys)


def _base(grant: Grant, outcome: str = "EXECUTED", reason: str | None = "EXECUTED") -> dict:
    body: dict[str, Any] = {"report_secret": grant.report_secret, "outcome": outcome}
    if reason is not None:
        body["reason"] = reason
    return body


def _asserted(grant: Grant, outcome: str = "EXECUTED", reason: str | None = "EXECUTED") -> dict:
    return _base(grant, outcome, reason) | {"reported_at": instant(reported_at(grant))}


def _text(fields: list[tuple[str, str]]) -> str:
    return "{" + ",".join(f'"{name}":{value}' for name, value in fields) + "}"


FAULTS: tuple[Fault, ...] = (
    Fault(
        "repeated-key",
        "The body repeats a key.",
        "INVALID_REQUEST",
        "body",
        lambda grant, keys: _text(
            [
                ("outcome", '"UNKNOWN"'),
                ("outcome", '"UNKNOWN"'),
                ("report_secret", json.dumps(grant.report_secret)),
                ("reported_at", json.dumps(instant(reported_at(grant)))),
            ]
        ),
    ),
    Fault(
        "fractional-number",
        "The body writes a number with a fraction.",
        "INVALID_REQUEST",
        "body",
        lambda grant, keys: _text(
            [
                ("outcome", '"UNKNOWN"'),
                ("report_secret", json.dumps(grant.report_secret)),
                ("reported_at", "1792054920.5"),
            ]
        ),
    ),
    Fault(
        "unknown-field",
        "The body names a field the report does not, a tier of its own choosing.",
        "INVALID_REQUEST",
        "model",
        lambda grant, keys: _asserted(grant) | {"tier": "ATTESTED"},
    ),
    Fault(
        "no-evidence",
        "A terminal outcome with neither a reported time nor signed evidence.",
        "INVALID_REQUEST",
        "evidence",
        lambda grant, keys: _base(grant),
    ),
    Fault(
        "two-pieces-of-evidence",
        "A signed record and an attestation of the same statement, together.",
        "INVALID_REQUEST",
        "evidence",
        lambda grant, keys: (
            _base(grant)
            | {
                "record": keys.record(grant, "EXECUTED", "EXECUTED"),
                "attestation": keys.attestation(grant, "EXECUTED", "EXECUTED"),
            }
        ),
    ),
    Fault(
        "time-beside-evidence",
        "A reported time beside a signed record.",
        "INVALID_REQUEST",
        "evidence",
        lambda grant, keys: (
            _asserted(grant) | {"record": keys.record(grant, "EXECUTED", "EXECUTED")}
        ),
    ),
    Fault(
        "reported-failure-refunding",
        "REPORTED_FAILURE beside FAILED_NOT_EXECUTED, the outcome that refunds.",
        "INVALID_REQUEST",
        "pairing",
        lambda grant, keys: _asserted(grant, "FAILED_NOT_EXECUTED", "REPORTED_FAILURE"),
    ),
    Fault(
        "unknown-with-a-reason",
        "UNKNOWN reported as though it were terminal, with a reason.",
        "INVALID_REQUEST",
        "pairing",
        lambda grant, keys: _asserted(grant, "UNKNOWN", "REPORTED_FAILURE"),
    ),
    Fault(
        "unknown-with-evidence",
        "UNKNOWN beside a signed record.",
        "INVALID_REQUEST",
        "pairing",
        lambda grant, keys: (
            _base(grant, "UNKNOWN", None) | {"record": keys.record(grant, "EXECUTED", "EXECUTED")}
        ),
    ),
    Fault(
        "signed-reported-failure",
        "REPORTED_FAILURE beside signed evidence, which can state no such reason.",
        "INVALID_REQUEST",
        "pairing",
        lambda grant, keys: (
            _base(grant, "FAILED_EFFECT_UNKNOWN", "REPORTED_FAILURE")
            | {"record": keys.record(grant, "EXECUTED", "EXECUTED")}
        ),
    ),
    Fault(
        "record-outside-the-ring",
        "A record signed by a key the ring does not hold, under a key id it does.",
        "INVALID_RECORD",
        "signature",
        lambda grant, keys: (
            _base(grant)
            | {"record": keys.record(grant, "EXECUTED", "EXECUTED", seed=OUTSIDE_ED25519_SEED)}
        ),
    ),
    Fault(
        "record-unregistered-key-id",
        "A record signed under a key id the ring does not hold.",
        "INVALID_RECORD",
        "signature",
        lambda grant, keys: (
            _base(grant)
            | {
                "record": keys.record(
                    grant,
                    "EXECUTED",
                    "EXECUTED",
                    seed=OUTSIDE_ED25519_SEED,
                    key_id=UNREGISTERED_KEY_ID,
                )
            }
        ),
    ),
    Fault(
        "record-altered-after-signing",
        "A record whose statement was changed after it was signed.",
        "INVALID_RECORD",
        "signature",
        lambda grant, keys: (
            _base(grant, "FAILED_NOT_EXECUTED", "TARGET_NOT_FOUND")
            | {
                "record": _altered(
                    keys.record(grant, "FAILED_NOT_EXECUTED", "CANCELLED_NOT_EXECUTED")
                )
            }
        ),
    ),
    Fault(
        "record-under-the-es256-key",
        "An Ed25519 record naming the ring's ES256 key, which verifies only its own scheme.",
        "INVALID_RECORD",
        "signature",
        lambda grant, keys: (
            _base(grant)
            | {"record": keys.record(grant, "EXECUTED", "EXECUTED", key_id=ES256_KEY_ID)}
        ),
    ),
    Fault(
        "record-for-another-operation",
        "A record that binds another operation than the grant's.",
        "INVALID_RECORD",
        "binding",
        lambda grant, keys: (
            _base(grant)
            | {"record": keys.record(grant, "EXECUTED", "EXECUTED", operation=ANOTHER_OPERATION)}
        ),
    ),
    Fault(
        "record-before-the-grant",
        "A record dated a second before the second the grant was issued in.",
        "INVALID_RECORD",
        "binding",
        lambda grant, keys: (
            _base(grant)
            | {
                "record": keys.record(
                    grant,
                    "EXECUTED",
                    "EXECUTED",
                    at=grant.granted_at.replace(microsecond=0) - timedelta(seconds=1),
                )
            }
        ),
    ),
    Fault(
        "record-contradicts-the-body",
        "The body says EXECUTED and its signed record says the target was not found.",
        "INVALID_RECORD",
        "agreement",
        lambda grant, keys: (
            _base(grant) | {"record": keys.record(grant, "FAILED_NOT_EXECUTED", "TARGET_NOT_FOUND")}
        ),
    ),
    Fault(
        "attestation-outside-the-ring",
        "An attestation signed by a key the ring does not hold, under a key id it does.",
        "INVALID_RECORD",
        "signature",
        lambda grant, keys: (
            _base(grant)
            | {
                "attestation": keys.attestation(
                    grant, "EXECUTED", "EXECUTED", scalar=OUTSIDE_ES256_SCALAR
                )
            }
        ),
    ),
    Fault(
        "attestation-under-the-ed25519-key",
        "An attestation naming the ring's Ed25519 key, which verifies only its own scheme.",
        "INVALID_RECORD",
        "signature",
        lambda grant, keys: (
            _base(grant)
            | {
                "attestation": keys.attestation(
                    grant, "EXECUTED", "EXECUTED", key_id=ED25519_KEY_ID
                )
            }
        ),
    ),
    Fault(
        "attestation-contradicts-the-body",
        "The body says the executor cancelled and its attestation says the vendor executed.",
        "INVALID_RECORD",
        "agreement",
        lambda grant, keys: (
            _base(grant, "FAILED_NOT_EXECUTED", "CANCELLED_NOT_EXECUTED")
            | {"attestation": keys.attestation(grant, "EXECUTED", "EXECUTED")}
        ),
    ),
    Fault(
        "journal-under-another-key",
        "A journal signed under a journal key nobody configured.",
        "INVALID_RECORD",
        "signature",
        lambda grant, keys: (
            _base(grant)
            | {
                "journal": keys.journal(
                    grant, "EXECUTED", key=OUTSIDE_JOURNAL_KEY, key_id=UNREGISTERED_KEY_ID
                )
            }
        ),
    ),
    Fault(
        "journal-for-another-command",
        "A journal of a command at another expected version than the grant's.",
        "INVALID_RECORD",
        "binding",
        lambda grant, keys: (
            _base(grant)
            | {"journal": keys.journal(grant, "EXECUTED", expected_version="resource-v6")}
        ),
    ),
    Fault(
        "journal-contradicts-the-body",
        "The body says EXECUTED and the provider's journal says the target was not found.",
        "INVALID_RECORD",
        "agreement",
        lambda grant, keys: _base(grant) | {"journal": keys.journal(grant, "TARGET_NOT_FOUND")},
    ),
    Fault(
        "journal-as-a-record",
        "A provider's journal presented as the executor's own record.",
        "INVALID_RECORD",
        "signature",
        lambda grant, keys: _base(grant) | {"record": keys.journal(grant, "EXECUTED")},
    ),
    Fault(
        "record-as-a-journal",
        "The executor's own record presented as a provider's journal.",
        "INVALID_RECORD",
        "signature",
        lambda grant, keys: _base(grant) | {"journal": keys.record(grant, "EXECUTED", "EXECUTED")},
    ),
)
FAULTS += (
    Fault(
        "attestation-for-another-operation",
        "An attestation that binds another operation than the grant's.",
        "INVALID_RECORD",
        "binding",
        lambda grant, keys: (
            _base(grant)
            | {
                "attestation": keys.attestation(
                    grant, "EXECUTED", "EXECUTED", operation=ANOTHER_OPERATION
                )
            }
        ),
    ),
    Fault(
        "attestation-before-the-grant",
        "An attestation dated a second before the second the grant was issued in.",
        "INVALID_RECORD",
        "binding",
        lambda grant, keys: (
            _base(grant)
            | {
                "attestation": keys.attestation(
                    grant, "EXECUTED", "EXECUTED", at=grants_second(grant) - timedelta(seconds=1)
                )
            }
        ),
    ),
    Fault(
        "attestation-altered-after-signing",
        "An attestation whose claims were changed after they were signed.",
        "INVALID_RECORD",
        "signature",
        lambda grant, keys: (
            _base(grant, "FAILED_NOT_EXECUTED", "TARGET_NOT_FOUND")
            | {
                "attestation": _altered_token(
                    keys.attestation(grant, "FAILED_NOT_EXECUTED", "CANCELLED_NOT_EXECUTED")
                )
            }
        ),
    ),
    Fault(
        "journal-before-the-grant",
        "A journal dated a microsecond before the grant, inside the second it was issued in: "
        "a journal is compared with the grant's exact instant, not its second.",
        "INVALID_RECORD",
        "binding",
        lambda grant, keys: (
            _base(grant)
            | {
                "journal": keys.journal(
                    grant, "EXECUTED", at=grant.granted_at - timedelta(microseconds=1)
                )
            }
        ),
    ),
    Fault(
        "stored-attestation-as-a-record",
        "An ES256 attestation in the flattened form a settlement stores, presented as a record: "
        "a record is an Ed25519 signed outcome, and ES256 arrives only as an attestation.",
        "INVALID_RECORD",
        "signature",
        lambda grant, keys: (
            _base(grant)
            | {"record": stored_attestation(keys.attestation(grant, "EXECUTED", "EXECUTED"))}
        ),
    ),
    Fault(
        "journal-under-an-unavailable-grant",
        "A provider's journal of the command ExecBound would have sent, for a grant under "
        "UNAVAILABLE: such a grant carries no provider command, so no journal binds it.",
        "INVALID_RECORD",
        "binding",
        lambda grant, keys: _base(grant) | {"journal": keys.journal(grant, "EXECUTED")},
        precondition_class="UNAVAILABLE",
    ),
)
FAULTS_BY_NAME = {fault.name: fault for fault in FAULTS}


def _altered(signed: dict[str, Any]) -> dict[str, Any]:
    """The same envelope with its statement's reason changed and its signature kept."""
    return {**signed, "record": {**signed["record"], "reason": "TARGET_NOT_FOUND"}}


def _altered_token(token: str) -> str:
    """The same compact JWS with its claims' reason changed and its signature kept."""
    head, payload, signed = token.split(".")
    claims = json.loads(base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4)))
    claims["reason"] = "TARGET_NOT_FOUND"
    return f"{head}.{_segment(canonical_json(claims).encode())}.{signed}"


def split(report: dict[str, Any]) -> dict[str, Any]:
    """A report as the file writes it: an attestation as its three segments, never a token."""
    token = report.get("attestation")
    if not isinstance(token, str):
        return report
    protected, payload, signature = token.split(".")
    return {
        **report,
        "attestation": {"protected": protected, "payload": payload, "signature": signature},
    }


def body(report: dict[str, Any] | str) -> bytes:
    """A report's bytes as the vectors' executor sends them: canonical JSON, or the text."""
    return report.encode() if isinstance(report, str) else canonical_json(report).encode()


def _entry(grant: Grant) -> dict[str, Any]:
    return {
        "execution_id": str(grant.execution_id),
        "granted_at": instant(grant.granted_at),
        "grant": dict(grant.wire),
    }


def refusal_grant(fault: Fault) -> Grant:
    """The grant a refusal is written for: the shared one, or one of its own under its class."""
    if fault.precondition_class == "ENFORCED_BY_PROVIDER":
        return fixed_grant(REFUSAL_INDEX, "refusals")
    label = f"refusals-{fault.precondition_class.lower().replace('_', '-')}"
    return fixed_grant(OWN_REFUSAL_INDEX[fault.precondition_class], label, fault.precondition_class)


def document() -> dict[str, Any]:
    """The vector file's content."""
    shared = fixed_grant(REFUSAL_INDEX, "refusals")
    reports: dict[str, Any] = {}
    for fault in FAULTS:
        grant = refusal_grant(fault)
        built = fault.report(grant)
        reports[fault.name] = (
            {"fault": fault.fault, "code": fault.code, "check": fault.check}
            | ({"report_text": built} if isinstance(built, str) else {"report": split(built)})
            | ({} if grant == shared else _entry(grant))
        )
    vectors: dict[str, Any] = {}
    for scenario in SCENARIOS:
        grant = fixed_grant(INDEX[scenario.name], scenario.name, scenario.precondition_class)
        vectors[scenario.name] = {
            "row": scenario.row,
            "scenario": scenario.scenario,
            **_entry(grant),
            "report": split(scenario.report(grant)),
            "settles": scenario.settles,
        }
    return {
        "description": (
            "Synthetic checkpoint report vectors for chapter 2 of the executor protocol: one "
            "grant, one scenario, the report sent for it and what it settles, for every row of "
            "section 2.8, and reports section 2.9 refuses. Every id is made up and every key is "
            "public test material that authenticates nothing anywhere."
        ),
        "version": 1,
        "executor_keys": {
            ED25519_KEY_ID: {
                "algorithm": "ED25519",
                "public_key": ed25519_public().hex(),
                "test_private_key": ED25519_SEED.hex(),
            },
            ES256_KEY_ID: {
                "algorithm": "ES256",
                "public_key": es256_public().hex(),
                "test_private_key": ES256_SCALAR.hex(),
            },
        },
        "journal_keys": {JOURNAL_KEY_ID: JOURNAL_KEY.hex()},
        "vectors": vectors,
        "refusals": _entry(shared) | {"reports": reports},
    }


def document_bytes() -> bytes:
    return (json.dumps(document(), indent=2, sort_keys=True, ensure_ascii=False) + "\n").encode()


def published() -> Vectors:
    """The committed vector file, loaded by the protocol package's own loader."""
    return load_vectors(PUBLISHED.read_bytes())


def ring_key(algorithm: str, public: bytes) -> RingKey:
    """A registered public key as the conformance module asks for one, verified with
    `cryptography`, the library the server verifies with."""
    if algorithm == "ED25519":
        ed_key = Ed25519PublicKey.from_public_bytes(public)

        def verify_ed25519(signed: bytes, message: bytes) -> bool:
            try:
                ed_key.verify(signed, message)
            except InvalidSignature:
                return False
            return True

        return RingKey("ED25519", verify_ed25519)
    point = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), public)

    def verify_es256(signed: bytes, message: bytes) -> bool:
        if len(signed) != 64:
            return False
        der = encode_dss_signature(
            int.from_bytes(signed[:32], "big"), int.from_bytes(signed[32:], "big")
        )
        try:
            point.verify(der, message, ec.ECDSA(hashes.SHA256()))
        except InvalidSignature:
            return False
        return True

    return RingKey("ES256", verify_es256)


def ring(vectors: Vectors) -> dict[str, RingKey]:
    """The vectors' own executor ring: each published test key, verified as its scheme says."""
    return {
        key_id: ring_key(key.algorithm, key.public_key)
        for key_id, key in vectors.executor_keys.items()
    }
