# SPDX-License-Identifier: AGPL-3.0-only
"""Evidence tiers: what an executor can prove, and what it can only assert.

These tests need no database. They fix the boundary between the two tiers: an attested
outcome is an Ed25519 signature ExecBound checks against a key an administrator
registered, and an asserted outcome is a model that structurally cannot be mistaken for
provider proof.
"""

import json
from datetime import UTC, datetime, timedelta
from typing import get_args
from uuid import uuid4

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from pydantic import ValidationError

from execbound.administration import AdministrationError, _public_key
from execbound.audit import canonical_json
from execbound.execution.models import (
    AssertedOutcome,
    DispatchCommand,
    ExecutionError,
    TerminalEvidence,
    TerminalOutcome,
    TerminalReason,
)
from execbound.execution.outcomes import _proof
from execbound.provider.executor import (
    ED25519,
    SMALL_ORDER_PUBLIC_KEYS,
    ExecutorKey,
    ExecutorRecord,
    ExecutorVerifier,
    SignedOutcome,
    outcome_message,
    sign_outcome,
    verifier_for_grant,
)
from execbound.provider.models import ProviderError
from execbound.requests import ActionRequest, Arguments, ResourceSelector
from execbound.resolution.models import CanonicalIntent, ResolvedRequest

KEY_ID = "executor-v1"
NOW = datetime.now(UTC)
GRANTED_AT = NOW - timedelta(minutes=5)
# The registration instant of every key in these rings: before the grant, because a key
# registered after one never attests it.
REGISTERED_AT = GRANTED_AT - timedelta(hours=1)
# What the execution row carries beside the attempt. A real row always has one and it is
# not the grant instant, so the synthetic row below carries a distinct earlier value.
CREATED_AT = GRANTED_AT - timedelta(minutes=30)
# The Ed25519 identity point, and the one signature that verifies every message against it.
IDENTITY_KEY = "01" + "00" * 31
UNIVERSAL_SIGNATURE = "01" + "00" * 31 + "00" * 32
# A non-canonical spelling of the order-four point: y is the field prime, which reduces to
# zero, so it is a small-order key that no blocklist of canonical bytes would catch.
NON_CANONICAL_KEY = "ed" + "ff" * 30 + "7f"


def public_hex(private_key):
    return private_key.public_key().public_bytes_raw().hex()


def key_at_rest(public_key):
    """An `ExecutorKey` that skipped construction, standing in for a row already stored."""
    key = object.__new__(ExecutorKey)
    for field, value in (
        ("key_id", KEY_ID),
        ("public_key", public_key),
        ("created_at", REGISTERED_AT),
        ("revoked_at", None),
        ("revocation_reason", None),
    ):
        object.__setattr__(key, field, value)
    return key


@pytest.fixture
def grant():
    """One granted operation, its executor key pair, and a verifier for that grant."""
    tenant, principal, account, target = (uuid4() for _ in range(4))
    frozen = ResolvedRequest(
        request=ActionRequest(
            operation_ref="endpoint.isolate",
            target=ResourceSelector(kind="canonical", value=str(target)),
            arguments=Arguments(),
            idempotency_key="checkpoint-evidence",
        ),
        intent=CanonicalIntent(
            tenant_id=tenant,
            principal_id=principal,
            account_id=account,
            target_id=target,
            arguments=Arguments(),
        ),
        resource_provider_id="synthetic-device",
        resource_version="resource-v1",
        mapping_version="map-v1",
        facts=(),
        resolved_at=GRANTED_AT,
        valid_until=NOW + timedelta(minutes=10),
    )
    command = DispatchCommand(
        execution_id=uuid4(),
        canonical_target_id=target,
        operation_id=uuid4(),
        intent_hash="a" * 64,
        plan_hash="b" * 64,
        frozen=frozen,
    )
    private_key = Ed25519PrivateKey.generate()
    key = ExecutorKey(KEY_ID, public_hex(private_key), REGISTERED_AT)
    verifier = ExecutorVerifier(tenant, account, (key,), granted_at=GRANTED_AT)
    return command, private_key, verifier


def executor_record(command, **changes):
    fields = {
        "operation_id": command.operation_id,
        "account_id": command.frozen.intent.account_id,
        "intent_hash": command.intent_hash,
        "plan_hash": command.plan_hash,
        "outcome": "EXECUTED",
        "reason": "EXECUTED",
        "reported_at": NOW,
    }
    return ExecutorRecord(**(fields | changes))


def signed_bytes(command, private_key, *, key_id=KEY_ID, **changes):
    return sign_outcome(executor_record(command, **changes), key_id, private_key).model_dump_json()


def test_executor_signature_attests_the_operation_it_names(grant):
    command, private_key, verifier = grant
    evidence = signed_bytes(command, private_key).encode()
    proof = verifier.verify(command, evidence)
    assert type(proof) is TerminalEvidence
    assert (proof.operation_id, proof.account_id) == (
        command.operation_id,
        command.frozen.intent.account_id,
    )
    assert (proof.intent_hash, proof.plan_hash) == (command.intent_hash, command.plan_hash)
    assert (proof.outcome, proof.reason) == ("EXECUTED", "EXECUTED")
    assert proof.authenticated_record == evidence.decode()
    # The same four-way binding settlement checks, through the settlement boundary itself.
    assert _proof(command, evidence, verifier) == proof


@pytest.mark.parametrize(
    "field,value",
    [
        ("operation_id", uuid4()),
        ("account_id", uuid4()),
        ("intent_hash", "c" * 64),
        ("plan_hash", "d" * 64),
    ],
)
def test_a_record_naming_another_operation_cannot_settle_this_one(grant, field, value):
    """Each of the four bound fields is checked; a validly signed record for a different
    operation, account, intent or plan is refused rather than settling this grant."""
    command, private_key, verifier = grant
    evidence = signed_bytes(command, private_key, **{field: value}).encode()
    with pytest.raises(ProviderError):
        verifier.verify(command, evidence)
    with pytest.raises(ExecutionError):
        _proof(command, evidence, verifier)


def test_a_foreign_key_cannot_attest_an_outcome(grant):
    """A signature from a key the tenant never registered, and a valid signature
    relabelled with a registered key id, are both refused."""
    command, _, verifier = grant
    foreign = Ed25519PrivateKey.generate()
    with pytest.raises(ProviderError):
        verifier.verify(command, signed_bytes(command, foreign).encode())
    with pytest.raises(ProviderError):
        verifier.verify(command, signed_bytes(command, foreign, key_id="executor-v2").encode())


def test_a_signature_cannot_be_relabelled_as_another_registered_key(grant):
    """The key id is inside the signed bytes. Nothing stops an operator registering one
    public key under two ids, so a signature made under the id revoked before the grant
    must not settle it by being presented under the live one."""
    command, private_key, _ = grant
    ring = (
        ExecutorKey(
            KEY_ID,
            public_hex(private_key),
            REGISTERED_AT,
            revoked_at=GRANTED_AT - timedelta(minutes=1),
            revocation_reason="RETIRED",
        ),
        ExecutorKey("executor-v2", public_hex(private_key), REGISTERED_AT),
    )
    verifier = ExecutorVerifier(
        command.frozen.intent.tenant_id,
        command.frozen.intent.account_id,
        ring,
        granted_at=GRANTED_AT,
    )
    envelope = json.loads(signed_bytes(command, private_key))
    envelope["key_id"] = "executor-v2"
    with pytest.raises(ProviderError):
        verifier.verify(command, json.dumps(envelope).encode())
    # The live id attests once the executor actually signs under it.
    assert (
        verifier.verify(
            command, signed_bytes(command, private_key, key_id="executor-v2").encode()
        ).reason
        == "EXECUTED"
    )


@pytest.mark.parametrize(
    "change",
    [
        "empty",
        "duplicate_id",
        "naive_grant",
        "naive_revocation",
        "naive_registration",
        "revoked_before_registered",
        "revoked_without_reason",
        "reason_without_revocation",
        "unknown_reason",
        "short_key",
        "uppercase_key",
    ],
)
def test_a_verifier_refuses_a_key_ring_the_column_could_not_hold(grant, change):
    """Configuration is checked before any evidence is. A naive timestamp on either
    instant would make its comparison against the grant raise rather than decide, a key
    revoked before it was registered is a row the column's own CHECK constraint refuses,
    a revocation with no reason or a reason with no revocation is the shape migration
    0026's CHECK constraint refuses, and a key this accepted but those constraints would
    not could never have been registered at all."""
    command, private_key, _ = grant
    tenant, account = command.frozen.intent.tenant_id, command.frozen.intent.account_id
    valid = public_hex(private_key)
    keys, granted_at = (ExecutorKey(KEY_ID, valid, REGISTERED_AT),), GRANTED_AT
    if change == "empty":
        keys = ()
    elif change == "duplicate_id":
        keys = (
            ExecutorKey(KEY_ID, valid, REGISTERED_AT),
            ExecutorKey(KEY_ID, valid, REGISTERED_AT),
        )
    elif change == "naive_grant":
        granted_at = GRANTED_AT.replace(tzinfo=None)
    with pytest.raises(ValueError):
        if change == "naive_revocation":
            ExecutorKey(
                KEY_ID,
                valid,
                REGISTERED_AT,
                revoked_at=NOW.replace(tzinfo=None),
                revocation_reason="RETIRED",
            )
        elif change == "naive_registration":
            ExecutorKey(KEY_ID, valid, REGISTERED_AT.replace(tzinfo=None))
        elif change == "revoked_before_registered":
            ExecutorKey(
                KEY_ID,
                valid,
                REGISTERED_AT,
                revoked_at=REGISTERED_AT - timedelta(seconds=1),
                revocation_reason="RETIRED",
            )
        elif change == "revoked_without_reason":
            ExecutorKey(KEY_ID, valid, REGISTERED_AT, revoked_at=NOW)
        elif change == "reason_without_revocation":
            ExecutorKey(KEY_ID, valid, REGISTERED_AT, revocation_reason="RETIRED")
        elif change == "unknown_reason":
            ExecutorKey(KEY_ID, valid, REGISTERED_AT, revoked_at=NOW, revocation_reason="ROTATED")
        elif change == "short_key":
            ExecutorKey(KEY_ID, valid[:63], REGISTERED_AT)
        elif change == "uppercase_key":
            ExecutorKey(KEY_ID, valid.upper(), REGISTERED_AT)
        else:
            ExecutorVerifier(tenant, account, keys, granted_at=granted_at)


def test_revocation_after_a_grant_still_attests_it_and_revocation_before_it_does_not(grant):
    """An ordinary retirement never invalidates a proof for a grant issued while that key
    was current; a key already revoked when the grant was issued settles nothing. This is
    the backward-permissive retirement rule `docs/CHECKPOINT.md` describes under "Executor
    keys", and the test below is the compromise that deliberately does not follow it, so the
    two together are what keep the distinction from collapsing either way."""
    command, private_key, verifier = grant
    evidence = signed_bytes(command, private_key).encode()
    tenant = command.frozen.intent.tenant_id
    account = command.frozen.intent.account_id
    for revoked_at, attests in (
        (GRANTED_AT + timedelta(seconds=1), True),
        (GRANTED_AT - timedelta(seconds=1), False),
        (GRANTED_AT, False),
    ):
        key = ExecutorKey(
            KEY_ID,
            public_hex(private_key),
            REGISTERED_AT,
            revoked_at=revoked_at,
            revocation_reason="RETIRED",
        )
        rotated = ExecutorVerifier(tenant, account, (key,), granted_at=GRANTED_AT)
        if attests:
            assert rotated.verify(command, evidence).reason == "EXECUTED"
        else:
            with pytest.raises(ProviderError):
                rotated.verify(command, evidence)


def test_a_key_revoked_as_compromised_attests_nothing_whatever_the_grant_instant(grant):
    """The retroactive half of the rule, and the only half that closes a stolen key.

    An ordinary retirement is deliberately backward-permissive, so the test above holds
    that a key revoked after the grant still attests it. That is exactly what leaves a
    stolen key attesting every grant it was holding for the rest of each report window,
    and an attested non-execution refunds the reservation and releases the claim. A
    revocation recorded as a compromise is therefore refused whatever the grant instant:
    before, at and after it, the same signature that attests under RETIRED attests
    nothing under COMPROMISED.
    """
    command, private_key, _ = grant
    evidence = signed_bytes(command, private_key).encode()
    tenant = command.frozen.intent.tenant_id
    account = command.frozen.intent.account_id
    for revoked_at in (
        GRANTED_AT + timedelta(hours=23),
        GRANTED_AT + timedelta(seconds=1),
        GRANTED_AT,
        GRANTED_AT - timedelta(seconds=1),
    ):
        for reason, attests in (("RETIRED", revoked_at > GRANTED_AT), ("COMPROMISED", False)):
            key = ExecutorKey(
                KEY_ID,
                public_hex(private_key),
                REGISTERED_AT,
                revoked_at=revoked_at,
                revocation_reason=reason,
            )
            ring = ExecutorVerifier(tenant, account, (key,), granted_at=GRANTED_AT)
            if attests:
                assert ring.verify(command, evidence).reason == "EXECUTED"
            else:
                with pytest.raises(ProviderError):
                    ring.verify(command, evidence)


def test_a_key_registered_after_a_grant_never_attests_it(grant):
    """The other end of the retirement rule. A key the tenant did not hold when the grant was
    issued never spoke for it, so registering one afterwards — the ordinary response to a
    compromise — confers no authority over the grants the retired key covered. Without
    this the attested tier would say "this executor signed it" about a key that did not
    exist at the time, which is the one thing non-repudiation is supposed to rule out."""
    command, private_key, _ = grant
    evidence = signed_bytes(command, private_key).encode()
    tenant = command.frozen.intent.tenant_id
    account = command.frozen.intent.account_id
    for created_at, attests in (
        (GRANTED_AT - timedelta(seconds=1), True),
        (GRANTED_AT, True),
        (GRANTED_AT + timedelta(seconds=1), False),
    ):
        key = ExecutorKey(KEY_ID, public_hex(private_key), created_at)
        ring = ExecutorVerifier(tenant, account, (key,), granted_at=GRANTED_AT)
        if attests:
            assert ring.verify(command, evidence).reason == "EXECUTED"
        else:
            with pytest.raises(ProviderError):
                ring.verify(command, evidence)


@pytest.mark.parametrize(
    "change", ["signature", "outcome", "reported_at", "key_id", "version", "duplicate", "truncated"]
)
def test_a_tampered_envelope_is_refused(grant, change):
    """Every field is inside the signed message, so no edit survives verification, and a
    malformed envelope is refused by the protocol parser before any key is consulted."""
    command, private_key, verifier = grant
    envelope = json.loads(signed_bytes(command, private_key))
    if change == "signature":
        envelope["signature"] = "0" * 128
    elif change == "outcome":
        envelope["record"]["outcome"] = "FAILED_NOT_EXECUTED"
        envelope["record"]["reason"] = "CANCELLED_NOT_EXECUTED"
    elif change == "reported_at":
        envelope["record"]["reported_at"] = (NOW + timedelta(hours=1)).isoformat()
    elif change == "key_id":
        envelope["key_id"] = "executor-v2"
    elif change == "version":
        envelope["version"] = 2
    raw = json.dumps(envelope).encode()
    if change == "duplicate":
        raw = raw.replace(b'"version": 1', b'"version": 1, "version": 1', 1)
    if change == "truncated":
        raw = raw[: len(raw) // 2]
    with pytest.raises(ProviderError):
        verifier.verify(command, raw)


def test_an_asserted_outcome_cannot_carry_proof(grant):
    """The model refuses the two proof fields outright, so no caller and no future code
    path can build an assertion that looks like verified evidence."""
    command, private_key, verifier = grant
    proof = verifier.verify(command, signed_bytes(command, private_key).encode())
    assert "proof_digest" not in AssertedOutcome.model_fields
    assert "authenticated_record" not in AssertedOutcome.model_fields
    for field, value in (
        ("proof_digest", proof.proof_digest),
        ("authenticated_record", proof.authenticated_record),
    ):
        with pytest.raises(ValidationError):
            AssertedOutcome(
                operation_id=command.operation_id,
                account_id=command.frozen.intent.account_id,
                intent_hash=command.intent_hash,
                plan_hash=command.plan_hash,
                outcome="EXECUTED",
                reason="EXECUTED",
                reported_at=NOW,
                **{field: value},
            )


@pytest.mark.parametrize("outcome", ["EXECUTED", "FAILED_NOT_EXECUTED"])
@pytest.mark.parametrize(
    "reason", ["EXECUTED", "VERSION_MISMATCH", "CANCELLED_NOT_EXECUTED", "TARGET_NOT_FOUND"]
)
def test_an_outcome_and_its_reason_must_agree_in_both_new_models(grant, outcome, reason):
    """Over these four reasons and two outcomes the two models answer alike, which is now
    an agreement on a subset rather than a shared vocabulary.

    `ExecutorRecord` takes what a verifier could return and `AssertedOutcome` what an
    unverifiable statement may say, and the settlement vocabulary's split parted them: the
    assertion takes REPORTED_FAILURE beside FAILED_EFFECT_UNKNOWN and the record refuses
    each of those. So the literals parametrized below still enumerate `ExecutorRecord`'s
    own and no longer enumerate `AssertedOutcome`'s, and within them one reason names an
    execution and the rest name a non-execution in both models. The pairing the two
    disagree about is asserted in `tests/test_arcade.py`, where the record is asked for
    each new member and raises."""
    command, _, _ = grant
    fields = {
        "operation_id": command.operation_id,
        "account_id": command.frozen.intent.account_id,
        "intent_hash": command.intent_hash,
        "plan_hash": command.plan_hash,
        "outcome": outcome,
        "reason": reason,
        "reported_at": NOW,
    }
    if (reason == "EXECUTED") == (outcome == "EXECUTED"):
        assert AssertedOutcome(**fields).reason == ExecutorRecord(**fields).reason == reason
    else:
        for model in (AssertedOutcome, ExecutorRecord):
            with pytest.raises(ValidationError):
                model(**fields)


def test_an_asserted_outcome_serializes_distinguishably_from_proof(grant):
    """Neither model validates the other's bytes, so a retained assertion can never be
    read back as terminal evidence and terminal evidence never loses its proof."""
    command, private_key, verifier = grant
    proof = verifier.verify(command, signed_bytes(command, private_key).encode())
    asserted = AssertedOutcome(
        operation_id=command.operation_id,
        account_id=command.frozen.intent.account_id,
        intent_hash=command.intent_hash,
        plan_hash=command.plan_hash,
        outcome="EXECUTED",
        reason="EXECUTED",
        reported_at=NOW,
    )
    assert set(asserted.model_dump(mode="json")) == {
        "operation_id",
        "account_id",
        "intent_hash",
        "plan_hash",
        "outcome",
        "reason",
        "reported_at",
    }
    assert "reported_at" not in proof.model_dump(mode="json")
    with pytest.raises(ValidationError):
        TerminalEvidence.model_validate(asserted.model_dump(mode="json"))
    with pytest.raises(ValidationError):
        AssertedOutcome.model_validate(proof.model_dump(mode="json"))


@pytest.mark.parametrize("shape", ["asserted", "unvalidated", "inconsistent"])
def test_the_settlement_boundary_refuses_anything_a_verifier_did_not_validate(grant, shape):
    """`_proof` re-validates what a verifier hands it, so neither an asserted outcome nor
    a `model_construct` object that skipped validation can settle an operation."""
    command, private_key, verifier = grant
    proof = verifier.verify(command, signed_bytes(command, private_key).encode())
    if shape == "asserted":
        returned = AssertedOutcome(
            operation_id=proof.operation_id,
            account_id=proof.account_id,
            intent_hash=proof.intent_hash,
            plan_hash=proof.plan_hash,
            outcome="EXECUTED",
            reason="EXECUTED",
            reported_at=NOW,
        )
    elif shape == "unvalidated":
        returned = TerminalEvidence.model_construct(
            **(proof.model_dump() | {"authenticated_record": ""})
        )
    else:
        returned = TerminalEvidence.model_construct(
            **(proof.model_dump() | {"reason": "CANCELLED_NOT_EXECUTED"})
        )

    class Untrusted:
        def verify(self, command, evidence):
            return returned

    with pytest.raises(ExecutionError) as refusal:
        _proof(command, b"{}", Untrusted())
    assert refusal.value.code == "INVALID_EVIDENCE"


def test_a_small_order_key_verifies_every_message_and_is_refused_everywhere():
    """The blocker this guard exists for.

    `cryptography` loads the Ed25519 identity encoding as a public key, and the fixed
    signature below then verifies any message at all against it. A registered small-order
    point would therefore make the attested tier — the one tier replay treats as verified
    — forgeable by a stranger holding no private key. The library behaviour is asserted
    here so the guard's reason stays visible, then refused at both call sites.
    """
    loaded = Ed25519PublicKey.from_public_bytes(bytes.fromhex(IDENTITY_KEY))
    for message in (b"one message", b"a completely different message"):
        loaded.verify(bytes.fromhex(UNIVERSAL_SIGNATURE), message)
    with pytest.raises(AdministrationError) as refusal:
        _public_key(IDENTITY_KEY, ED25519)
    assert refusal.value.code == "INVALID_KEY"
    with pytest.raises(ValueError):
        ExecutorKey(KEY_ID, IDENTITY_KEY, REGISTERED_AT)


@pytest.mark.parametrize("encoding", sorted(SMALL_ORDER_PUBLIC_KEYS) + [NON_CANONICAL_KEY])
def test_a_forgeable_encoding_is_refused_at_registration_and_at_key_construction(encoding):
    """Every blocked encoding is thirty-two bytes of hex, so the column's CHECK constraint
    and the shape patterns admit all of them. Registration refuses each one, in either
    case, so nothing malformed is stored; the key model refuses each one, so a key already
    at rest cannot be used; and the verifier re-checks the ring, so neither can a row that
    reached the database before this guard existed."""
    with pytest.raises(AdministrationError):
        _public_key(encoding, ED25519)
    with pytest.raises(AdministrationError):
        _public_key(encoding.upper(), ED25519)
    with pytest.raises(ValueError):
        ExecutorKey(KEY_ID, encoding, REGISTERED_AT)
    with pytest.raises(ValueError):
        ExecutorVerifier(uuid4(), uuid4(), (key_at_rest(encoding),), granted_at=GRANTED_AT)


def test_a_forged_envelope_under_a_small_order_key_never_reaches_verification(grant):
    """Built end to end: the forger registers the identity point, signs nothing, and
    presents the universal signature over a record naming this grant. No ring carrying that
    key can be constructed, so the forgery is refused before any signature is checked."""
    command, _, _ = grant
    envelope = SignedOutcome(
        key_id=KEY_ID,
        record=executor_record(command),
        signature=UNIVERSAL_SIGNATURE,
    )
    tenant, account = command.frozen.intent.tenant_id, command.frozen.intent.account_id
    with pytest.raises(ValueError):
        ExecutorVerifier(
            tenant, account, (key_at_rest(IDENTITY_KEY),), granted_at=GRANTED_AT
        ).verify(command, envelope.model_dump_json().encode())


def test_a_genuine_key_is_still_accepted():
    """The guard refuses forgeable encodings and nothing else: a real Ed25519 key, in
    either case, registers and constructs."""
    valid = public_hex(Ed25519PrivateKey.generate())
    assert _public_key(valid, ED25519) == valid
    assert _public_key(valid.upper(), ED25519) == valid
    assert ExecutorKey(KEY_ID, valid, REGISTERED_AT).public_key == valid


@pytest.mark.parametrize("scope", ["tenant", "account"])
def test_a_verifier_bound_to_another_tenant_or_account_refuses_a_valid_command(grant, scope):
    """The key ring is per tenant and the grant is per account, so a verifier built for
    one must never attest another's command however good the signature is."""
    command, private_key, _ = grant
    tenant, account = command.frozen.intent.tenant_id, command.frozen.intent.account_id
    if scope == "tenant":
        tenant = uuid4()
    else:
        account = uuid4()
    foreign = ExecutorVerifier(
        tenant,
        account,
        (ExecutorKey(KEY_ID, public_hex(private_key), REGISTERED_AT),),
        granted_at=GRANTED_AT,
    )
    with pytest.raises(ProviderError):
        foreign.verify(command, signed_bytes(command, private_key).encode())


def test_a_report_dated_before_the_grant_settles_nothing(grant):
    """A report from before the grant existed describes an attempt that had not been
    authorized yet. The verifier holds both instants, so it refuses rather than retaining
    a reported time that predates the only attempt it could be about."""
    command, private_key, verifier = grant
    for reported_at, attests in (
        (GRANTED_AT + timedelta(seconds=1), True),
        (GRANTED_AT, True),
        (GRANTED_AT - timedelta(seconds=1), False),
    ):
        evidence = signed_bytes(command, private_key, reported_at=reported_at).encode()
        if attests:
            assert verifier.verify(command, evidence).reason == "EXECUTED"
        else:
            with pytest.raises(ProviderError):
                verifier.verify(command, evidence)


def execution_row(command, granted_at=GRANTED_AT):
    """The columns `verifier_for_grant` reads, as a real execution row carries them.

    `created_at` is here because every row has one and it is the wrong column: reading it
    instead of the attempt is the mutation this fixture must be able to see, so it holds a
    distinct earlier instant rather than being absent and refused as a null grant.
    """
    return {
        "tenant_id": command.frozen.intent.tenant_id,
        "frozen": json.loads(command.frozen.model_dump_json()),
        "created_at": CREATED_AT,
        "dispatch_attempted_at": granted_at,
    }


def test_the_grant_instant_comes_from_the_row_and_never_from_the_report(grant):
    """`verifier_for_grant` is the only way a caller should build one, so no call site ever
    chooses a datetime by hand and none can pass a time the executor influenced. It takes
    the tenant, the account and the grant instant from the execution row itself, and the
    grant instant is the attempt and never the insert: the row carries both, they are the
    same value only when nothing made the request wait, and `tests/test_checkpoint.py`
    holds the approval path where a revocation falls between them."""
    command, private_key, _ = grant
    ring = (ExecutorKey(KEY_ID, public_hex(private_key), REGISTERED_AT),)
    verifier = verifier_for_grant(execution_row(command), ring)
    assert verifier.granted_at == GRANTED_AT
    assert execution_row(command)["created_at"] == CREATED_AT != GRANTED_AT
    assert verifier.tenant_id == command.frozen.intent.tenant_id
    assert verifier.account_id == command.frozen.intent.account_id
    assert (
        verifier.verify(command, signed_bytes(command, private_key).encode()).reason == "EXECUTED"
    )
    # A row with no grant has nothing to attest, and a grant the report predates refuses,
    # which is what a verifier built from the executor's own clock would have accepted.
    # The message is pinned because the ring guard would refuse a null grant anyway; this
    # branch is what names the condition rather than blaming the key ring for it.
    with pytest.raises(ValueError, match="Invalid executor grant"):
        verifier_for_grant(execution_row(command, granted_at=None), ring)
    later = verifier_for_grant(execution_row(command, granted_at=NOW + timedelta(hours=1)), ring)
    with pytest.raises(ProviderError):
        later.verify(command, signed_bytes(command, private_key).encode())


def test_the_signed_message_is_domain_separated_and_carries_the_envelope_version(grant):
    """The provider journal shapes its HMAC message as `{version, key_id, record}`. The
    executor's message carries a domain separator as well, so the two can never be the same
    bytes, and its version is read from the envelope rather than written as a literal, so a
    future envelope version signs a different message than this one."""
    command, private_key, verifier = grant
    envelope = sign_outcome(executor_record(command), KEY_ID, private_key)
    message = json.loads(outcome_message(envelope))
    assert message["domain"] == "execbound.executor.outcome"
    assert message["version"] == envelope.version
    assert set(message) == {"domain", "version", "key_id", "record"}
    # The version travels from the envelope into the message, so a future envelope version
    # signs different bytes than this one even when every other field is identical.
    future = envelope.model_copy(update={"version": 2})
    assert json.loads(outcome_message(future))["version"] == 2
    assert outcome_message(future) != outcome_message(envelope)
    # A signature over the journal's envelope shape does not attest an executor's outcome.
    journal_shaped = canonical_json(
        {
            "version": envelope.version,
            "key_id": KEY_ID,
            "record": envelope.record.model_dump(mode="json"),
        }
    ).encode()
    relayed = SignedOutcome(
        key_id=KEY_ID,
        record=envelope.record,
        signature=private_key.sign(journal_shaped).hex(),
    )
    with pytest.raises(ProviderError):
        verifier.verify(command, relayed.model_dump_json().encode())


@pytest.mark.parametrize("key_id", ["", "a" * 65, "executor v1", "executor/v1", "exec:v1"])
def test_the_signing_helper_refuses_a_key_id_the_column_could_not_hold(grant, key_id):
    """A key id the `executor_keys` CHECK constraint would refuse names no registered key,
    so the helper refuses to sign under it rather than producing an envelope nothing can
    ever verify."""
    command, private_key, _ = grant
    with pytest.raises(ProviderError) as refusal:
        sign_outcome(executor_record(command), key_id, private_key)
    assert refusal.value.code == "INVALID_SCOPE"


def test_the_terminal_aliases_are_the_evidence_literals():
    """Terminal evidence, the executor's record and an assertion bind one set. The aliases
    replaced literals that were written out inline, so this pins both that the sets stay
    equal and that the serialized schema did not move when they did."""
    schema = TerminalEvidence.model_json_schema()["properties"]
    assert tuple(schema["outcome"]["enum"]) == get_args(TerminalOutcome)
    assert tuple(schema["reason"]["enum"]) == get_args(TerminalReason)
    assert get_args(TerminalOutcome) == ("EXECUTED", "FAILED_NOT_EXECUTED")
    assert get_args(TerminalReason) == (
        "EXECUTED",
        "VERSION_MISMATCH",
        "CANCELLED_NOT_EXECUTED",
        "TARGET_NOT_FOUND",
    )
