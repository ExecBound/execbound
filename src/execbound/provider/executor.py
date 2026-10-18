# SPDX-License-Identifier: AGPL-3.0-only
"""The verifier that attests an external executor's signed outcome record.

An external executor holds its own vendor credential and acts outside ExecBound, so its
report is authenticated rather than dispatched. ExecBound holds only the executor's
public key, Ed25519 or ES256: an administrator registers it in `executor_keys`, the
runtime may read it and nothing more, and no signing material for this protocol exists at
rest. Read access to the control store therefore cannot forge the attested tier, which is
the one tier replay treats as verified.

The record, its envelope and the JWS form are `execbound_protocol.executor`'s, which an
executor signs with (#496); they are named here where they always were.

A registered public key must be a high-order point. Nothing about the hex shape of an
encoding says whether it is one, so `SMALL_ORDER_PUBLIC_KEYS` and the field-prime check
below are the control; without them a small-order key makes the attested tier forgeable by
anyone.
"""

import base64
import hashlib
import json
import re
from collections.abc import Iterable
from dataclasses import dataclass
from datetime import datetime
from typing import Any
from uuid import UUID

from cryptography.exceptions import InvalidSignature, UnsupportedAlgorithm
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature
from execbound_protocol.executor import _KEY_ID as _KEY_ID
from execbound_protocol.executor import JWS_FORMAT as JWS_FORMAT
from execbound_protocol.executor import MAX_JWS_BYTES as MAX_JWS_BYTES
from execbound_protocol.executor import OUTCOME_DOMAIN as OUTCOME_DOMAIN
from execbound_protocol.executor import Ed25519Signature as Ed25519Signature
from execbound_protocol.executor import ExecutorRecord as ExecutorRecord
from execbound_protocol.executor import JwsClaims as JwsClaims
from execbound_protocol.executor import JwsHeader as JwsHeader
from execbound_protocol.executor import JwsSegment as JwsSegment
from execbound_protocol.executor import ParsedJws as ParsedJws
from execbound_protocol.executor import SignedOutcome as SignedOutcome
from execbound_protocol.executor import SignedOutcomeJws as SignedOutcomeJws
from execbound_protocol.executor import Signer as Signer
from execbound_protocol.executor import flattened_jws as flattened_jws
from execbound_protocol.executor import flattened_wrapper as flattened_wrapper
from execbound_protocol.executor import jws_record as jws_record
from execbound_protocol.executor import outcome_message as outcome_message
from execbound_protocol.executor import parse_jws as parse_jws
from execbound_protocol.executor import recorded_outcome as recorded_outcome
from execbound_protocol.executor import sign_outcome as sign_outcome

from execbound.execution import store
from execbound.execution.models import (
    DispatchCommand,
    TerminalEvidence,
    VerifiedTier,
)
from execbound.provider.models import ProviderError, parse_provider
from execbound.provider.published_keys import published_executor_key
from execbound.requests import _unique_object

# An Ed25519 public key is 32 bytes, carried as lowercase hex (the signature's pattern is
# the protocol's `Ed25519Signature`). The key pattern restates the CHECK constraint of
# migration 0025 so a value this verifier accepts is exactly a value the column can hold.
_PUBLIC_KEY = re.compile(r"[0-9a-f]{64}")

# Why a registered key was revoked, as `executor_keys.revocation_reason` records it. The
# two are not the same statement about the key's past. RETIRED is an ordinary rotation or
# retirement and is backward-permissive: a proof for a grant issued while the key was
# current still verifies, which is what makes rotating safe.
# COMPROMISED says the private half is in someone else's hands, and is retroactive: the
# verifier below refuses the key whatever the grant instant, so the moment an operator
# records it the key attests nothing it was holding. Migration 0026's CHECK constraint
# holds a reason exactly when the row carries a revocation.
RETIRED = "RETIRED"
COMPROMISED = "COMPROMISED"
REVOCATION_REASONS: frozenset[str] = frozenset({RETIRED, COMPROMISED})

# The two signature schemes an executor key may use, as `executor_keys.algorithm` records
# them. Ed25519 signs the canonical-JSON envelope; ES256 signs a compact JWS, which is what
# a workflow platform that cannot do Ed25519 (Tines among them) can produce. A key verifies
# only its own scheme's envelope, and the scheme comes from the registered row, never from
# anything the message says about itself.
ED25519, ES256 = "ED25519", "ES256"
ALGORITHMS: frozenset[str] = frozenset({ED25519, ES256})
_ES256_KEY = re.compile(r"0[23][0-9a-f]{64}")


# The Ed25519 field prime, and the mask that takes the y coordinate out of an encoding:
# the low 255 bits are y and the top bit is the sign of x. A y at or above the prime is a
# second spelling of a point that already has a canonical one — `edff..ff7f` is another
# way to write `0000..0000`, the order-four point — so it would walk straight past a
# blocklist written in canonical bytes. `cryptography` loads all thirty-eight of them.
_FIELD_PRIME = 2**255 - 19
_Y_COORDINATE = (1 << 255) - 1

# Every Ed25519 encoding whose point has order dividing eight: the eight small-order
# points, plus the sign-bit spelling of the two whose x is zero. A point of small order is
# not a public key at all, because no private scalar produces it and anyone can sign for
# it. The identity is the worst case: the fixed signature `01` + thirty-one `00` bytes +
# thirty-two `00` bytes verifies ANY message against it, so one registered identity key
# would make the attested tier — the one tier replay treats as verified — forgeable by a
# stranger holding nothing. For the other seven a forgery needs only to guess which of the
# eight values [k]A takes, which succeeds in a handful of tries. `cryptography` loads all
# ten of these as valid public keys.
#
# A regular expression cannot express this. The CHECK constraint of migration 0025 and
# `_PUBLIC_KEY` above say "thirty-two bytes of lowercase hex", and every entry below
# satisfies that; whether those bytes decode to a small-order point, or to a y that is not
# a canonical field element, is a fact about curve arithmetic modulo the field prime and
# not about the shape of the string. The pattern stays a shape check and this is the
# control.
SMALL_ORDER_PUBLIC_KEYS: frozenset[str] = frozenset(
    {
        # The identity (0, 1), order 1, and the same point spelled with the sign bit set.
        "0100000000000000000000000000000000000000000000000000000000000000",
        "0100000000000000000000000000000000000000000000000000000000000080",
        # (0, -1), order 2, and the same point spelled with the sign bit set.
        "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
        "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        # The two order-4 points, y = 0 and x = ±sqrt(-1); here both sign bits are real,
        # distinct points rather than two spellings of one.
        "0000000000000000000000000000000000000000000000000000000000000000",
        "0000000000000000000000000000000000000000000000000000000000000080",
        # The four order-8 points, two y values with both signs of x, all distinct points.
        "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05",
        "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc85",
        "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a",
        "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa",
    }
)


def forgeable_public_key(value: str) -> bool:
    """Whether this encoding is one no executor could hold the private half of.

    Both call sites refuse on this before any signature is checked: `_public_key` in
    administration, so a forgeable key is never stored, and `ExecutorKey`, so one already
    at rest can never be used. The argument must already have passed the hex shape check.
    """
    key = value.lower()
    if key in SMALL_ORDER_PUBLIC_KEYS:
        return True
    return (int.from_bytes(bytes.fromhex(key), "little") & _Y_COORDINATE) >= _FIELD_PRIME


def _instant(value: Any) -> bool:
    """An aware timestamp, as every column this model mirrors holds."""
    return type(value) is datetime and value.tzinfo is not None and value.utcoffset() is not None


def usable_public_key(algorithm: str, public_key: str) -> bool:
    """Whether this registered material is a key some executor holds the private half of."""
    if type(public_key) is not str:
        return False
    if algorithm == ED25519:
        return bool(_PUBLIC_KEY.fullmatch(public_key)) and not forgeable_public_key(public_key)
    if algorithm == ES256 and _ES256_KEY.fullmatch(public_key):
        try:
            ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), bytes.fromhex(public_key))
        except ValueError:
            return False
        return True
    return False


_JWK_FIELDS = frozenset({"kty", "crv", "x", "y", "kid", "use", "alg", "key_ops"})


def _jwk_coordinate(value: object) -> bytes:
    if type(value) is not str or not re.fullmatch(r"[A-Za-z0-9_-]{43}", value):
        raise ValueError()
    return base64.urlsafe_b64decode(value + "=")


def es256_public_key(value: str) -> str:
    """A P-256 public key as SPKI PEM, a JWK or compressed SEC1 hex, normalized to hex.

    Everything else is refused: a private key in any spelling, another curve, a point not
    on P-256, and a JWK carrying any field beyond the public ones. Normalizing to one
    spelling is what lets the live-material check compare keys at all, because a PEM, a JWK
    and a hex string of one key are three different strings.
    """
    if type(value) is not str:
        raise ValueError("Invalid ES256 public key")
    candidate = value.strip()
    if "PRIVATE KEY" in candidate:
        # Private material is refused wherever it sits in the input, not only as the first
        # block: `load_pem_public_key` reads the first PEM block and ignores the rest, so a
        # public block followed by its private one would otherwise register.
        raise ValueError("Invalid ES256 public key")
    try:
        if candidate.startswith("-----BEGIN PUBLIC KEY-----"):
            loaded = serialization.load_pem_public_key(candidate.encode("ascii"))
        elif candidate.startswith("{"):
            jwk = json.loads(candidate, object_pairs_hook=_unique_object)
            if (
                not isinstance(jwk, dict)
                or set(jwk) - _JWK_FIELDS
                or jwk.get("kty") != "EC"
                or jwk.get("crv") != "P-256"
            ):
                raise ValueError()
            point = b"\x04" + _jwk_coordinate(jwk.get("x")) + _jwk_coordinate(jwk.get("y"))
            loaded = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), point)
        elif _ES256_KEY.fullmatch(candidate.lower()):
            loaded = ec.EllipticCurvePublicKey.from_encoded_point(
                ec.SECP256R1(), bytes.fromhex(candidate)
            )
        else:
            raise ValueError()
    except (ValueError, TypeError, UnicodeError, UnsupportedAlgorithm):
        raise ValueError("Invalid ES256 public key") from None
    if not isinstance(loaded, ec.EllipticCurvePublicKey) or loaded.curve.name != "secp256r1":
        raise ValueError("Invalid ES256 public key")
    return loaded.public_bytes(
        serialization.Encoding.X962, serialization.PublicFormat.CompressedPoint
    ).hex()


@dataclass(frozen=True)
class ExecutorKey:
    """One registered public key, with both instants the verifier weighs against a grant.

    `created_at` and `revoked_at` are the registration and revocation the `executor_keys`
    row carries, and they bound the key's authority at both ends: a grant issued before
    the key was registered was never covered by it, and one issued while it was current
    stays covered after it retires. `revocation_reason` says which kind of revocation it
    was, and a compromise overrides that window entirely. Two of the rules below restate
    what the row's own CHECK constraints enforce — a revocation at or after the
    registration, and a reason present exactly when the key is revoked — so a ring this
    model accepts is a ring the table could have held; requiring both instants to be aware
    is this model's own, because a naive one would make the comparison against the grant
    raise rather than decide. A revocation that reached this model with no reason would be
    read as an ordinary retirement, which is the permissive answer, so it is refused
    rather than defaulted.
    """

    key_id: str
    public_key: str
    created_at: datetime
    revoked_at: datetime | None = None
    revocation_reason: str | None = None
    algorithm: str = ED25519

    def __post_init__(self) -> None:
        if (
            type(self.key_id) is not str
            or not _KEY_ID.fullmatch(self.key_id)
            # The shape check runs first and short-circuits, so this only ever sees hex.
            # A key registered before this guard existed is refused here rather than
            # attesting, so nothing at rest can settle an operation it could not sign.
            or not usable_public_key(self.algorithm, self.public_key)
            or not _instant(self.created_at)
            or (self.revoked_at is None) != (self.revocation_reason is None)
            or (
                self.revocation_reason is not None
                and self.revocation_reason not in REVOCATION_REASONS
            )
            or (
                self.revoked_at is not None
                and (not _instant(self.revoked_at) or self.revoked_at < self.created_at)
            )
        ):
            raise ValueError("Invalid executor key")


class ExecutorVerifier:
    """Attests an executor's report against the tenant's registered keys.

    `granted_at` is the instant ExecBound issued the grant being settled, supplied by the
    caller that read the execution rather than inferred here, because it is what decides
    which of the tenant's keys speak for this proof: rotating or revoking a key must never
    invalidate evidence for a grant issued while that key was current, and neither a key
    revoked before the grant existed nor one registered after it may settle it. Build one
    through `verifier_for_grant` rather than choosing that instant by hand.
    """

    # What tells this verifier apart from a provider's journal verifier, which satisfies
    # the same `EvidenceVerifier` protocol. The kernel's two settlement guards read it,
    # `execution.reconciliation._executor_evidence_only` and
    # `execution.outcomes._never_executor_evidence`: a checkpoint settles from its own
    # executor's signed record and never from a connector's evidence about an operation
    # ExecBound never dispatched, and what this verifier attests settles no operation
    # ExecBound did dispatch.
    attests_external_execution = True

    def __init__(
        self,
        tenant_id: UUID,
        account_id: UUID,
        keys: Iterable[ExecutorKey],
        *,
        granted_at: datetime,
    ) -> None:
        ring = tuple(keys)
        for key in ring:
            key.__post_init__()
        if not ring or len({key.key_id for key in ring}) != len(ring) or not _instant(granted_at):
            raise ValueError("Invalid executor keys")
        self.tenant_id, self.account_id = tenant_id, account_id
        self.granted_at = granted_at
        self._keys = {key.key_id: key for key in ring}

    def _current(self, key: ExecutorKey) -> bool:
        """A key the tenant already held when the grant was issued and had not retired.

        The rule is symmetric about an ordinary retirement. It is deliberately
        backward-permissive, so a key retired after the grant still attests it and a
        rotation invalidates nothing. Registration is the same statement from the other
        end: a key the tenant registered after the grant never spoke for it, so rotating
        after a compromise hands the replacement no retroactive authority over the grants
        it never covered, which is exactly what the ATTESTED tier's non-repudiation is
        worth.

        A compromise is the one revocation that is not backward-permissive, and it is
        refused here rather than by any state the report route already tolerates. The
        window above is precisely what leaves a stolen key attesting every grant it was
        holding for the rest of each report window, and an attested non-execution on that
        route refunds the reservation and releases the canonical claim; sweeping those
        grants to INDETERMINATE closes nothing, because that state is still reportable.
        Refusing the key is what ends its authority, and this is where it is asked: the
        two paths that can settle a grant on attested evidence — the outcome route and
        the administrator's ``reconcile`` — both reach a verifier through
        ``outcomes._proof``, and the third call site of that helper is the dispatch path,
        which refuses a checkpoint outright. Held by
        `test_a_key_revoked_as_compromised_attests_nothing_whatever_the_grant_instant`
        and, through the route, by `test_a_compromised_key_attests_nothing_it_was_holding`.

        A published test key is refused the same way and for the same reason: its private
        half is in everyone's hands, from the moment the protocol published it. Registration
        refuses one now, so what reaches here is a row registered before that guard, or
        written over the owner connection. It is refused key by key rather than failing the
        ring, because it is a real point a real private key signs for, and the ring's other
        keys are what an administrator registered; a report signed with it is INVALID_RECORD
        and settles nothing. Held through the route by
        `test_a_stored_published_key_attests_none_of_the_vectors_signed_reports`.
        """
        if key.revocation_reason == COMPROMISED or published_executor_key(key.public_key):
            return False
        return key.created_at <= self.granted_at and (
            key.revoked_at is None or key.revoked_at > self.granted_at
        )

    def verify(self, command: DispatchCommand, evidence: bytes) -> TerminalEvidence:
        """Check either envelope against the frozen command and the key it names.

        A JSON object is an Ed25519 envelope or the flattened wrapper a settlement retains
        and a reconcile may present again; anything else is a compact JWS, the shape the
        report route's own `attestation` field carries and an administrator may paste
        fresh. The report route never hands this the wrapper: a `record` is an Ed25519
        signed outcome and a `journal` a provider's journal, and
        `execution.outcomes._reported` refuses either field in the wrapper's form before
        verifying it, so the wrapper branch below serves the administrator's settlement and
        correction alone. Which scheme a key verifies comes from its registered row, never
        from the evidence. The object is recognized after leading whitespace, which JSON
        admits and an administrator's pasted envelope may carry; a compact JWS never begins
        with either. ASCII whitespace around a compact JWS is stripped before it is parsed,
        for the same reason: it is outside the signing input, a pasted token commonly ends
        in a newline, and the console hands the pasted text over unstripped. Whitespace
        inside the token is still refused by the segment parser.
        """
        command = parse_provider(command.model_dump_json().encode(), DispatchCommand)
        if type(evidence) is not bytes:
            raise ProviderError("INVALID_MESSAGE")
        if evidence.lstrip()[:1] == b"{":
            try:
                wrapped = parse_provider(evidence, SignedOutcomeJws)
            except ProviderError:
                return self._ed25519(command, evidence)
            return self._es256(
                command, flattened_jws(wrapped.protected, wrapped.payload, wrapped.signature)
            )
        try:
            token = evidence.strip().decode("ascii")
        except UnicodeError:
            raise ProviderError("INVALID_EVIDENCE") from None
        return self._es256(command, parse_jws(token))

    def verified_tier(self, proof: TerminalEvidence) -> VerifiedTier:
        # Everything this verifier returns is an executor's own signed record, in either
        # envelope. The runtime hands the kernel a `CheckpointVerifier`, which delegates
        # executor evidence here and answers the tier itself.
        return "ATTESTED"

    def _binds(self, command: DispatchCommand, record: ExecutorRecord) -> bool:
        return (
            command.frozen.intent.tenant_id == self.tenant_id
            and command.frozen.intent.account_id == self.account_id
            and record.operation_id == command.operation_id
            and record.account_id == command.frozen.intent.account_id
            and record.intent_hash == command.intent_hash
            and record.plan_hash == command.plan_hash
            # A report from before the grant existed is nonsense, and the verifier holds
            # both instants, so it is refused here rather than retained as a reported time
            # that predates the only attempt it could describe. The grant instant is
            # compared at one-second precision because some executors can only sign whole
            # seconds: Tines stamps `reported_at` with `DATE(NOW(), "%Y-%m-%dT%H:%M:%S%:z")`,
            # while `dispatch_attempted_at` carries microseconds, so a non-execution signed
            # in the grant's own wall-clock second would otherwise read as earlier than the
            # grant and strand it. Anything earlier than that second is still refused.
            and record.reported_at >= self.granted_at.replace(microsecond=0)
        )

    def _ed25519(self, command: DispatchCommand, evidence: bytes) -> TerminalEvidence:
        signed = parse_provider(evidence, SignedOutcome)
        key = self._keys.get(signed.key_id)
        if (
            key is None
            or key.algorithm != ED25519
            or not self._binds(command, signed.record)
            or not self._current(key)
            or not _signed_by(key, signed)
        ):
            raise ProviderError("INVALID_EVIDENCE")
        return self._evidence(signed.record, signed.model_dump_json())

    def _es256(self, command: DispatchCommand, parsed: ParsedJws) -> TerminalEvidence:
        key = self._keys.get(parsed.header.kid)
        record = jws_record(parsed.claims)
        if (
            key is None
            or key.algorithm != ES256
            or not self._binds(command, record)
            or not self._current(key)
            or not _es256_signed(key, parsed)
        ):
            raise ProviderError("INVALID_EVIDENCE")
        wrapped = flattened_wrapper(parsed, parsed.header.kid)
        return self._evidence(record, wrapped.model_dump_json())

    @staticmethod
    def _evidence(record: ExecutorRecord, authenticated_record: str) -> TerminalEvidence:
        return TerminalEvidence(
            operation_id=record.operation_id,
            account_id=record.account_id,
            intent_hash=record.intent_hash,
            plan_hash=record.plan_hash,
            outcome=record.outcome,
            reason=record.reason,
            proof_digest=hashlib.sha256(authenticated_record.encode()).hexdigest(),
            authenticated_record=authenticated_record,
        )


def verifier_for_grant(row: dict[str, Any], keys: Iterable[ExecutorKey]) -> ExecutorVerifier:
    """Build the verifier for one granted execution out of the execution row itself.

    The grant instant is `dispatch_attempted_at`, the column that marks the single attempt
    as consumed, and the tenant and account come from the same row. It is deliberately not
    `created_at`: on the approval path the row is inserted when the request is first
    admitted and answered PENDING_APPROVAL, and the attempt is stamped only in the reserve
    tail that runs on the retry after a human decides, so the two are as far apart as the
    decision took and a key revoked in between would otherwise attest a grant it had already
    stopped covering. No call site picks a datetime by hand, so none can accidentally pass a
    time the executor influenced — its own `reported_at`, say — and hand the executor the
    revocation window that decides which retired keys still speak for this grant. A row with
    no grant has nothing to attest.
    """
    granted_at = row.get("dispatch_attempted_at")
    if granted_at is None:
        raise ValueError("Invalid executor grant")
    return ExecutorVerifier(
        row["tenant_id"], store.frozen(row).intent.account_id, keys, granted_at=granted_at
    )


def _signed_by(key: ExecutorKey, signed: SignedOutcome) -> bool:
    try:
        Ed25519PublicKey.from_public_bytes(bytes.fromhex(key.public_key)).verify(
            bytes.fromhex(signed.signature), outcome_message(signed)
        )
    except (InvalidSignature, ValueError):
        return False
    return True


def _es256_signed(key: ExecutorKey, parsed: ParsedJws) -> bool:
    try:
        public = ec.EllipticCurvePublicKey.from_encoded_point(
            ec.SECP256R1(), bytes.fromhex(key.public_key)
        )
        der = encode_dss_signature(
            int.from_bytes(parsed.signature[:32], "big"),
            int.from_bytes(parsed.signature[32:], "big"),
        )
        public.verify(der, parsed.signing_input, ec.ECDSA(hashes.SHA256()))
    except (InvalidSignature, ValueError):
        return False
    return True
