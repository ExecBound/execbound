# SPDX-License-Identifier: AGPL-3.0-only
"""The published keys a replay regression fixture's retained evidence is re-signed under.

A fixture replaces every identifier and label in the evidence a history retained, so the
signature that evidence carried no longer covers its bytes, and kept as it was it would let
anyone holding the signer's public key test guesses of the original identifiers. Replay
checks no signature offline (`replay/verify.py`: each is retained provenance), so a fixture
re-signs each kind under a key published here instead:

- a provider's journal and ExecBound's own connector record, both HMAC-SHA256, under
  `FIXTURE_JOURNAL_KEY`;
- an external executor's Ed25519 record under the key `FIXTURE_ED25519_SEED` makes;
- an external executor's ES256 attestation under the key `FIXTURE_ES256_SCALAR` makes, with
  deterministic ECDSA (RFC 6979), so building the same history twice writes the same bytes.

The private halves are published because these keys must authenticate nobody: the runtime
refuses each one wherever a key becomes authority (`provider.published_keys`), so evidence
signed under one settles nothing. Reading a fixture checks that every retained signature is
one of these (`signed_by_fixture_keys`), so a fixture never carries a real signer's
signature.
"""

import base64
import hmac
import json
from typing import Any

from cryptography.exceptions import InvalidSignature, UnsupportedAlgorithm
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.utils import (
    decode_dss_signature,
    encode_dss_signature,
)

from execbound.audit import canonical_json
from execbound.provider.connector_record import (
    ConnectorExchange,
    ConnectorRecord,
    record_signature,
    sign_exchange,
)
from execbound.provider.executor import (
    ExecutorRecord,
    JwsClaims,
    SignedOutcome,
    SignedOutcomeJws,
    outcome_message,
    sign_outcome,
)
from execbound.provider.models import (
    JournalRecord,
    ProviderError,
    SignedJournal,
    parse_provider,
    sign_journal,
    signature,
)

# Published on purpose: see the module's description.
FIXTURE_JOURNAL_KEY = b"execbound-replay-fixture-journal-key-v1"
FIXTURE_KEY_ID = "replay-fixture"
FIXTURE_ED25519_SEED = bytes.fromhex(
    "1d1e45a78dfc5fdf35643402fd29b02405fcf5123894e8bdb03019ada607bd1a"
)
FIXTURE_ES256_SCALAR = bytes.fromhex(
    "f08e0f9681e61132ca6704332d1ce1a2e873567991acb8667072d275e7b7e131"
)
# The names a version 2 fixture declares for the key each kind of evidence is signed under.
SIGNERS = {
    "journal": FIXTURE_KEY_ID,
    "connector": FIXTURE_KEY_ID,
    "executor-ed25519": "replay-fixture-ed25519",
    "executor-es256": "replay-fixture-es256",
}


class SigningUnavailable(Exception):
    """This interpreter's cryptography cannot sign ES256 deterministically."""


def _ed25519() -> Ed25519PrivateKey:
    return Ed25519PrivateKey.from_private_bytes(FIXTURE_ED25519_SEED)


def _es256() -> ec.EllipticCurvePrivateKey:
    return ec.derive_private_key(int.from_bytes(FIXTURE_ES256_SCALAR, "big"), ec.SECP256R1())


def _segment(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def _decoded(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def journal(record: JournalRecord) -> str:
    return sign_journal(record, FIXTURE_KEY_ID, FIXTURE_JOURNAL_KEY).model_dump_json()


def connector(exchange: ConnectorExchange, key_id: str) -> str:
    return sign_exchange(exchange, key_id, FIXTURE_JOURNAL_KEY).decode()


def executor_record(record: ExecutorRecord, key_id: str) -> str:
    return sign_outcome(record, key_id, _ed25519()).model_dump_json()


def attestation(kid: str, claims: JwsClaims, key_id: str) -> str:
    """An ES256 attestation retained as its flattened wrapper, signed deterministically."""
    head = _segment(canonical_json({"alg": "ES256", "kid": kid}).encode())
    body = _segment(canonical_json(claims.model_dump(mode="json")).encode())
    try:
        der = _es256().sign(
            f"{head}.{body}".encode("ascii"),
            ec.ECDSA(hashes.SHA256(), deterministic_signing=True),
        )
    except UnsupportedAlgorithm:
        raise SigningUnavailable() from None
    r, s = decode_dss_signature(der)
    return SignedOutcomeJws(
        format="jws-es256",
        key_id=key_id,
        protected=head,
        payload=body,
        signature=_segment(r.to_bytes(32, "big") + s.to_bytes(32, "big")),
    ).model_dump_json()


def opened_attestation(signed: SignedOutcomeJws) -> dict[str, Any]:
    """A retained attestation with its header and claims as JSON, so text can be read in it."""
    return {
        "format": signed.format,
        "key_id": signed.key_id,
        "protected": json.loads(_decoded(signed.protected)),
        "payload": json.loads(_decoded(signed.payload)),
        "signature": signed.signature,
    }


def _signed_record(raw: str) -> bool:
    """Whether one retained record's signature is a fixture key's, by its own envelope.

    A record that does not parse, or whose segments do not decode, is not one."""
    try:
        return _signed_by_fixture_key(raw)
    except (ValueError, UnicodeError, TypeError):
        return False


def _signed_by_fixture_key(raw: str) -> bool:
    data = raw.encode()
    try:
        journal_record = parse_provider(data, SignedJournal)
    except ProviderError:
        pass
    else:
        expected = signature(journal_record.record, journal_record.key_id, FIXTURE_JOURNAL_KEY)
        return hmac.compare_digest(journal_record.signature.encode(), expected.encode())
    try:
        record = parse_provider(data, ConnectorRecord)
    except ProviderError:
        pass
    else:
        expected = record_signature(record.record, record.key_id, FIXTURE_JOURNAL_KEY)
        return hmac.compare_digest(record.signature.encode(), expected.encode())
    try:
        wrapped = parse_provider(data, SignedOutcomeJws)
    except ProviderError:
        pass
    else:
        raw_signature = _decoded(wrapped.signature)
        der = encode_dss_signature(
            int.from_bytes(raw_signature[:32], "big"), int.from_bytes(raw_signature[32:], "big")
        )
        try:
            _es256().public_key().verify(
                der,
                f"{wrapped.protected}.{wrapped.payload}".encode("ascii"),
                ec.ECDSA(hashes.SHA256()),
            )
        except InvalidSignature:
            return False
        return True
    try:
        outcome = parse_provider(data, SignedOutcome)
    except ProviderError:
        return False
    try:
        _ed25519().public_key().verify(bytes.fromhex(outcome.signature), outcome_message(outcome))
    except (InvalidSignature, ValueError):
        return False
    return True


def signed_by_fixture_keys(document: Any) -> bool:
    """Whether every record a fixture's export retains is signed under a fixture key."""
    for event in document["export"]["events"]:
        evidence = event.get("payload", {}).get("evidence")
        if event.get("kind") != "execution.transition" or not isinstance(evidence, dict):
            continue
        record = evidence.get("authenticated_record")
        if not isinstance(record, str) or not _signed_record(record):
            return False
    return True


def _kind(raw: str) -> str | None:
    """Which signed envelope a retained record is, as `SIGNERS` names it."""
    data = raw.encode()
    for kind, model in (
        ("journal", SignedJournal),
        ("connector", ConnectorRecord),
        ("executor-es256", SignedOutcomeJws),
        ("executor-ed25519", SignedOutcome),
    ):
        try:
            parse_provider(data, model)
        except ProviderError:
            continue
        return kind
    return None


def evidence_kinds(document: Any) -> tuple[set[str], bool]:
    """The kinds of signed record a fixture's export retains, and whether it holds anything
    version 1 never wrote: a settlement tier, an executor's word, or a record that is not a
    provider's journal."""
    kinds: set[str] = set()
    external = False
    for event in document["export"]["events"]:
        payload = event.get("payload", {})
        if event.get("kind") != "execution.transition" or not isinstance(payload, dict):
            continue
        if "tier" in payload or "asserted" in payload:
            external = True
        evidence = payload.get("evidence")
        if isinstance(evidence, dict) and isinstance(evidence.get("authenticated_record"), str):
            kind = _kind(evidence["authenticated_record"])
            if kind is not None:
                kinds.add(kind)
    return kinds, external or bool(kinds - {"journal"})
