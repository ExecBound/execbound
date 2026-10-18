# SPDX-License-Identifier: AGPL-3.0-only
"""The Tines Gate qualification's kernel acceptance: TG1 to TG11 on real PostgreSQL."""

import base64
import json
from datetime import timedelta
from uuid import UUID, uuid4

import pytest
from alembic import command as alembic
from checkpoint_fixtures import (
    CONTAIN,
    JOURNAL_KEY_ID,
    TINES_KEY_ID,
    attestation_claims,
    audit_kinds,
    checkpoint,
    connected_account,
    force_state,
    frozen_command,
    gate_bundle,
    gate_journal,
    gate_runtime,
    grant_row,
    journal_provider,
    journal_verifier,
    jws,
    long_lived_admin,
    register_es256,
    report,
    report_body,
    retained,
    signed_record,
)
from checkpoint_fixtures import gate_world as gate_world
from checkpoint_fixtures import owner as owner
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from sqlalchemy import text
from test_execution import registry as registry
from test_execution import targets
from test_execution import world as world
from test_migration_without_bypass import restricted as restricted

from execbound import administration
from execbound.administration import AdministrationError
from execbound.execution import record_outcome, store, take_dispatch
from execbound.execution.models import (
    TERMINAL_PAIRS,
    CheckpointBinding,
    ExecutionError,
    PreconditionConfig,
)
from execbound.execution.reconciliation import reconcile
from execbound.provider.checkpoint_evidence import CheckpointProvider
from execbound.provider.connector import ConnectionConfig, MockConnector
from execbound.provider.models import provider_command
from execbound.runtime import Runtime, executor_verifier
from execbound.surfaces.configuration import load_runtime, read_configuration
from execbound.surfaces.tokens import TokenKeys

ENFORCED = PreconditionConfig({CONTAIN: "ENFORCED_BY_PROVIDER"})


def journaled(db, world, **changes):
    """A grant a provider's journal can speak for: one under a class that carries its command.

    Section 2.6 makes a journal the provider's record of exactly the grant's
    `provider_command`. The fixtures' default grant is UNAVAILABLE and carries none, and the
    outcome route refuses every journal for such a grant before it reads one
    (`tests/test_checkpoint_journal_class.py`), so a test of what a journal settles, or of
    what refuses one, asks for a grant under ENFORCED_BY_PROVIDER, where only the journal
    itself can decide.
    """
    return checkpoint(db, world, preconditions=ENFORCED, **changes)


def test_tg1_a_grant_carries_its_binding_and_the_frozen_command(db, gate_world, admin_engine):
    world = gate_world
    view = checkpoint(db, world, preconditions=ENFORCED).view
    grant = view.checkpoint
    assert grant is not None
    command = frozen_command(db, world, view.execution_id)
    assert grant.binding == CheckpointBinding(
        operation_id=command.operation_id,
        account_id=command.frozen.intent.account_id,
        intent_hash=command.intent_hash,
        plan_hash=command.plan_hash,
    )
    assert grant.command == command
    assert "command" not in grant.model_dump(mode="json")
    described = gate_runtime(db, world, preconditions=ENFORCED).present(world["identity"], view)
    wire = described["checkpoint"]["grant"]
    assert wire["binding"] == grant.binding.model_dump(mode="json")
    assert wire["provider_command"] == provider_command(command).model_dump(mode="json")
    assert wire["provider_command"]["expected_version"] == wire["expected_version"]
    again = checkpoint(db, world, preconditions=ENFORCED).view.checkpoint
    assert again is not None and again.regranted
    assert (again.binding, again.command) == (grant.binding, grant.command)


def test_tg1_an_unavailable_class_carries_a_binding_and_no_provider_command(
    db, gate_world, admin_engine
):
    world = gate_world
    (action,) = targets(admin_engine, world, count=1)
    view = checkpoint(db, world, action=action).view
    assert view.checkpoint is not None and view.checkpoint.expected_version is None
    wire = gate_runtime(db, world).present(world["identity"], view)["checkpoint"]["grant"]
    assert "binding" in wire
    assert "provider_command" not in wire


def _p256_compressed():
    public = ec.generate_private_key(ec.SECP256R1()).public_key()
    return public.public_bytes(Encoding.X962, PublicFormat.CompressedPoint).hex()


@pytest.mark.integration
def test_tg9_the_key_algorithm_and_the_tier_migrate_with_no_owner_bypass(restricted):
    engine, config, _ = restricted
    alembic.upgrade(config, "0055_community_signup")
    tenant = uuid4()
    ed25519 = Ed25519PrivateKey.generate().public_key().public_bytes_raw().hex()

    def scoped(conn):
        conn.execute(text("SELECT set_config('execbound.tenant_id',:t,true)"), {"t": str(tenant)})

    with engine.begin() as conn:
        scoped(conn)
        conn.execute(
            text("INSERT INTO execbound.tenants(tenant_id,name) VALUES(:t,'Keys')"), {"t": tenant}
        )
        conn.execute(
            text(
                "INSERT INTO execbound.executor_keys(tenant_id,key_id,public_key,created_at) "
                "VALUES(:t,'old',:k,now())"
            ),
            {"t": tenant, "k": ed25519},
        )
    alembic.upgrade(config, "0056_gate_evidence")
    with engine.begin() as conn:
        scoped(conn)
        row = conn.execute(
            text("SELECT algorithm, public_key FROM execbound.executor_keys WHERE key_id='old'")
        ).one()
        assert tuple(row) == ("ED25519", ed25519)
        conn.execute(
            text(
                "INSERT INTO execbound.executor_keys"
                "(tenant_id,key_id,algorithm,public_key,created_at) "
                "VALUES(:t,'new','ES256',:k,now())"
            ),
            {"t": tenant, "k": _p256_compressed()},
        )
        tier = conn.execute(
            text(
                "SELECT pg_get_constraintdef(oid) FROM pg_constraint "
                "WHERE conname = 'executions_settlement_tier'"
            )
        ).scalar_one()
        assert "PROVIDER_VERIFIED" in tier
    for algorithm, key in (("ES256", ed25519), ("ED25519", _p256_compressed()), ("RS256", ed25519)):
        with pytest.raises(Exception), engine.begin() as conn:  # noqa: B017 - the driver's own class
            scoped(conn)
            conn.execute(
                text(
                    "INSERT INTO execbound.executor_keys"
                    "(tenant_id,key_id,algorithm,public_key,created_at) "
                    "VALUES(:t,'bad',:a,:k,now())"
                ),
                {"t": tenant, "a": algorithm, "k": key},
            )
    with pytest.raises(RuntimeError):
        alembic.downgrade(config, "0055_community_signup")
    with engine.begin() as conn:
        scoped(conn)
        conn.execute(text("DELETE FROM execbound.executor_keys WHERE key_id='new'"))
    alembic.downgrade(config, "0055_community_signup")
    with engine.begin() as conn:
        scoped(conn)
        columns = conn.execute(
            text(
                "SELECT column_name FROM information_schema.columns "
                "WHERE table_schema='execbound' AND table_name='executor_keys'"
            )
        ).scalars()
        assert "algorithm" not in set(columns)
    alembic.upgrade(config, "head")


def _jwk(public, **extra):
    numbers = public.public_numbers()
    size = (public.curve.key_size + 7) // 8

    def b64(value: int) -> str:
        import base64

        return base64.urlsafe_b64encode(value.to_bytes(size, "big")).rstrip(b"=").decode()

    return json.dumps(
        {"kty": "EC", "crv": "P-256", "x": b64(numbers.x), "y": b64(numbers.y), **extra}
    )


def test_tg6_es256_keys_register_from_pem_jwk_and_hex_and_store_compressed(owner, gate_world):
    world = gate_world
    tenant, actor = world["identity"].tenant_id, world["admin"].principal_id
    keys = [ec.generate_private_key(ec.SECP256R1()).public_key() for _ in range(3)]
    spellings = (
        keys[0].public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo).decode(),
        _jwk(keys[1]),
        keys[2].public_bytes(Encoding.X962, PublicFormat.CompressedPoint).hex(),
    )
    for index, spelling in enumerate(spellings):
        administration.register_executor_key(
            owner,
            tenant,
            f"tines-{index}",
            spelling,
            actor,
            algorithm="ES256",
            now=world["clock"].now(),
        )
    listed = {item.key_id: item for item in administration.list_executor_keys(owner, tenant)}
    for index, key in enumerate(keys):
        item = listed[f"tines-{index}"]
        assert item.algorithm == "ES256"
        assert (
            item.public_key == key.public_bytes(Encoding.X962, PublicFormat.CompressedPoint).hex()
        )
    assert listed["executor-v1"].algorithm == "ED25519"


def _refused_es256_inputs():
    p384 = ec.generate_private_key(ec.SECP384R1())
    p256 = ec.generate_private_key(ec.SECP256R1())
    return {
        "x beyond the field": "02" + "ff" * 32,
        "uncompressed hex": p256.public_key()
        .public_bytes(Encoding.X962, PublicFormat.UncompressedPoint)
        .hex(),
        "P-384 PEM": p384.public_key()
        .public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)
        .decode(),
        "private PEM": p256.private_bytes(
            Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
        ).decode(),
        # `load_pem_public_key` reads the first block and ignores the rest, so without a
        # check of its own this would register the key from input that also carries the
        # private half, which registration refuses in any spelling.
        "public PEM followed by its private PEM": p256.public_key()
        .public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)
        .decode()
        + p256.private_bytes(
            Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
        ).decode(),
        "Ed25519 PEM": Ed25519PrivateKey.generate()
        .public_key()
        .public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)
        .decode(),
        "JWK with d": _jwk(p256.public_key(), d="AAAA"),
        "JWK on P-384": _jwk(p384.public_key()).replace("P-256", "P-384"),
        "not a key": "hello",
    }


@pytest.mark.parametrize("label", sorted(_refused_es256_inputs()))
def test_tg6_material_nobody_can_sign_for_is_refused(owner, gate_world, label):
    world = gate_world
    with pytest.raises(AdministrationError) as refused:
        administration.register_executor_key(
            owner,
            world["identity"].tenant_id,
            "tines-bad",
            _refused_es256_inputs()[label],
            world["admin"].principal_id,
            algorithm="ES256",
            now=world["clock"].now(),
        )
    assert refused.value.code == "INVALID_KEY"


def test_tg6_live_and_compromised_es256_material_is_refused(owner, gate_world):
    world = gate_world
    tenant, actor, now = (
        world["identity"].tenant_id,
        world["admin"].principal_id,
        world["clock"].now(),
    )
    compressed = _p256_compressed()
    administration.register_executor_key(
        owner, tenant, "a", compressed, actor, algorithm="ES256", now=now
    )
    with pytest.raises(AdministrationError):
        administration.register_executor_key(
            owner, tenant, "b", compressed, actor, algorithm="ES256", now=now
        )
    administration.report_executor_key_compromise(owner, tenant, "a", actor, now=now)
    with pytest.raises(AdministrationError):
        administration.register_executor_key(
            owner, tenant, "c", compressed, actor, algorithm="ES256", now=now
        )
    with pytest.raises(AdministrationError):
        administration.register_executor_key(
            owner, tenant, "d", compressed, actor, algorithm="RS256", now=now
        )


P256_ORDER = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
HEADER = {"alg": "ES256", "kid": TINES_KEY_ID}


@pytest.mark.parametrize(
    ("outcome", "reason", "state", "impact"),
    [
        ("EXECUTED", "EXECUTED", "EXECUTED", "CONFIRMED"),
        ("FAILED_NOT_EXECUTED", "CANCELLED_NOT_EXECUTED", "FAILED_NOT_EXECUTED", "NONEXECUTION"),
        ("FAILED_NOT_EXECUTED", "VERSION_MISMATCH", "STALE_AUTHORIZATION", "NONEXECUTION"),
    ],
)
def test_tg7_an_es256_attestation_settles_attested(
    db, gate_world, owner, admin_engine, outcome, reason, state, impact
):
    world = gate_world
    tines = register_es256(owner, world)
    granted = checkpoint(db, world).view
    token = jws(
        tines,
        HEADER,
        attestation_claims(db, world, granted.execution_id, outcome=outcome, reason=reason),
    )
    body = report_body(
        world, granted.checkpoint.report_secret, attestation=token, outcome=outcome, reason=reason
    )
    assert report(db, world, granted.execution_id, body=body).state == state
    row = retained(admin_engine, world["identity"].tenant_id, granted.execution_id)
    assert (row.state, row.tier, row.impact) == (state, "ATTESTED", impact)
    assert row.released_at is not None
    protected, payload, signature = token.split(".")
    assert json.loads(row.result["authenticated_record"]) == {
        "version": 1,
        "format": "jws-es256",
        "key_id": TINES_KEY_ID,
        "protected": protected,
        "payload": payload,
        "signature": signature,
    }


def test_tg7_a_second_distinct_jws_restating_the_outcome_is_a_no_op(
    db, gate_world, owner, admin_engine
):
    world = gate_world
    tines = register_es256(owner, world)
    granted = checkpoint(db, world).view
    secret = granted.checkpoint.report_secret
    claims = attestation_claims(db, world, granted.execution_id)
    first = jws(tines, HEADER, claims)
    report(db, world, granted.execution_id, body=report_body(world, secret, attestation=first))
    before = len(audit_kinds(admin_engine, world["identity"].tenant_id))
    _, _, signature = first.split(".")
    raw = base64.urlsafe_b64decode(signature + "=" * (-len(signature) % 4))
    s = int.from_bytes(raw[32:], "big")
    malleated = jws(
        tines, HEADER, claims, signature=raw[:32] + (P256_ORDER - s).to_bytes(32, "big")
    )
    world["clock"].value += timedelta(seconds=1)
    later = jws(tines, HEADER, {**claims, "reported_at": world["clock"].now().isoformat()})
    for token in (malleated, later):
        view = report(
            db, world, granted.execution_id, body=report_body(world, secret, attestation=token)
        )
        assert view.state == "EXECUTED"
    assert len(audit_kinds(admin_engine, world["identity"].tenant_id)) == before


JWS_REFUSALS = (
    "alg none",
    "alg HS256",
    "alg RS256",
    "alg EdDSA",
    "unknown kid",
    "kid names the Ed25519 key",
    "extra header",
    "typ header",
    "extra claim",
    "iat claim",
    "missing claim",
    "wrong domain",
    "version 2",
    "version true",
    "other operation",
    "altered intent",
    "before the grant",
    "signed by another key",
    "Ed25519 envelope names the ES256 key",
)


def _jws_refusal(label, claims, tines, now):
    """One attestation that must not settle; None for the Ed25519-envelope case."""
    earlier = (now - timedelta(minutes=5)).isoformat()
    build = {
        "alg none": lambda: jws(
            tines, {"alg": "none", "kid": TINES_KEY_ID}, claims, signature=b"\x00" * 64
        ),
        "alg HS256": lambda: jws(tines, {"alg": "HS256", "kid": TINES_KEY_ID}, claims),
        "alg RS256": lambda: jws(tines, {"alg": "RS256", "kid": TINES_KEY_ID}, claims),
        "alg EdDSA": lambda: jws(tines, {"alg": "EdDSA", "kid": TINES_KEY_ID}, claims),
        "unknown kid": lambda: jws(tines, {"alg": "ES256", "kid": "nobody"}, claims),
        "kid names the Ed25519 key": lambda: jws(
            tines, {"alg": "ES256", "kid": "executor-v1"}, claims
        ),
        "extra header": lambda: jws(tines, {**HEADER, "x5u": "https://example.invalid"}, claims),
        # Tines' JWT_SIGN writes no `typ` and adds no `iat` (as observed from its output),
        # so neither is admitted: each is refused like any other field the envelope does not
        # name.
        "typ header": lambda: jws(tines, {**HEADER, "typ": "JWT"}, claims),
        "extra claim": lambda: jws(tines, HEADER, {**claims, "admin": True}),
        "iat claim": lambda: jws(tines, HEADER, {**claims, "iat": 1790000000}),
        "missing claim": lambda: jws(
            tines, HEADER, {k: v for k, v in claims.items() if k != "reported_at"}
        ),
        "wrong domain": lambda: jws(tines, HEADER, {**claims, "domain": "execbound.other"}),
        "version 2": lambda: jws(tines, HEADER, {**claims, "version": 2}),
        # `true` equals 1 to a Literal, and the canonical envelope refuses it too.
        "version true": lambda: jws(tines, HEADER, {**claims, "version": True}),
        "other operation": lambda: jws(tines, HEADER, {**claims, "operation_id": str(uuid4())}),
        "altered intent": lambda: jws(tines, HEADER, {**claims, "intent_hash": "0" * 64}),
        "before the grant": lambda: jws(tines, HEADER, {**claims, "reported_at": earlier}),
        "signed by another key": lambda: jws(
            ec.generate_private_key(ec.SECP256R1()), HEADER, claims
        ),
        "Ed25519 envelope names the ES256 key": lambda: None,
    }
    return build[label]()


@pytest.mark.parametrize("label", JWS_REFUSALS)
def test_tg8_attestations_that_must_not_settle_are_refused(
    db, gate_world, owner, admin_engine, label
):
    world = gate_world
    tines = register_es256(owner, world)
    tenant = world["identity"].tenant_id
    granted = checkpoint(db, world).view
    claims = attestation_claims(db, world, granted.execution_id)
    token = _jws_refusal(label, claims, tines, world["clock"].now())
    if token is None:
        # The Ed25519 envelope naming the ES256 key: the right shape for the wrong scheme.
        record = signed_record(db, world, granted.execution_id, key_id=TINES_KEY_ID)
        body = report_body(world, granted.checkpoint.report_secret, record=record)
    else:
        body = report_body(world, granted.checkpoint.report_secret, attestation=token)
    with pytest.raises(ExecutionError) as refused:
        report(db, world, granted.execution_id, body=body)
    assert refused.value.code == "INVALID_RECORD"
    row = retained(admin_engine, tenant, granted.execution_id)
    assert (row.state, row.tier) == ("DISPATCH_COMMITTED", None)


def test_tg8_keys_outside_the_grant_window_attest_nothing(db, gate_world, owner, admin_engine):
    world = gate_world
    granted = checkpoint(db, world).view
    world["clock"].value += timedelta(seconds=5)
    late = register_es256(owner, world, key_id="late-v1")
    token = jws(
        late,
        {"alg": "ES256", "kid": "late-v1"},
        attestation_claims(db, world, granted.execution_id),
    )
    with pytest.raises(ExecutionError) as refused:
        report(
            db,
            world,
            granted.execution_id,
            body=report_body(world, granted.checkpoint.report_secret, attestation=token),
        )
    assert refused.value.code == "INVALID_RECORD"
    tines = register_es256(owner, world, key_id="cut-v1")
    (action,) = targets(admin_engine, world, count=1)
    second = checkpoint(db, world, action=action).view
    administration.report_executor_key_compromise(
        owner,
        world["identity"].tenant_id,
        "cut-v1",
        world["admin"].principal_id,
        now=world["clock"].now(),
    )
    token = jws(
        tines, {"alg": "ES256", "kid": "cut-v1"}, attestation_claims(db, world, second.execution_id)
    )
    with pytest.raises(ExecutionError) as refused:
        report(
            db,
            world,
            second.execution_id,
            body=report_body(world, second.checkpoint.report_secret, attestation=token),
        )
    assert refused.value.code == "INVALID_RECORD"


def _granted_within_a_second(db, world, admin_engine):
    """A grant whose instant falls half way through a wall-clock second.

    The clock is moved forward to the next half second first, so the grant instant carries
    microseconds whatever the world's clock started at, and the second it falls in is read
    back from the stored row rather than assumed.
    """
    now = world["clock"].now()
    world["clock"].value = now.replace(microsecond=500000) + timedelta(seconds=1)
    granted = checkpoint(db, world).view
    stamped = grant_row(admin_engine, world["identity"].tenant_id, granted.execution_id)
    granted_at = stamped["dispatch_attempted_at"]
    assert granted_at.microsecond != 0
    return granted, granted_at.replace(microsecond=0)


def _non_execution_signed_at(db, world, tines, granted, envelope, reported_at):
    """A signed non-execution whose `reported_at` is the given instant, in either envelope."""
    signed = {"outcome": "FAILED_NOT_EXECUTED", "reason": "CANCELLED_NOT_EXECUTED"}
    secret = granted.checkpoint.report_secret
    if envelope == "ES256 attestation":
        claims = attestation_claims(
            db, world, granted.execution_id, reported_at=reported_at.isoformat(), **signed
        )
        return report_body(world, secret, attestation=jws(tines, HEADER, claims), **signed)
    record = signed_record(db, world, granted.execution_id, reported_at=reported_at, **signed)
    return report_body(world, secret, record=record, **signed)


@pytest.mark.parametrize("envelope", ["ES256 attestation", "Ed25519 record"])
def test_tg8_a_report_signed_in_the_grants_own_second_settles(
    db, gate_world, owner, admin_engine, envelope
):
    """Tines signs whole seconds, and the grant instant does not.

    The Gate story stamps `reported_at` with `DATE(NOW(), "%Y-%m-%dT%H:%M:%S%:z")`, which
    has one-second precision, while the grant instant is `dispatch_attempted_at` with its
    microseconds. A non-execution signed in the same wall-clock second as the grant reads
    as earlier than the grant unless the grant instant is truncated to its second first,
    and refusing it would strand the grant with nothing but an administrator to settle it.
    """
    world = gate_world
    tines = register_es256(owner, world)
    granted, second = _granted_within_a_second(db, world, admin_engine)
    body = _non_execution_signed_at(db, world, tines, granted, envelope, second)
    assert report(db, world, granted.execution_id, body=body).state == "FAILED_NOT_EXECUTED"
    row = retained(admin_engine, world["identity"].tenant_id, granted.execution_id)
    assert (row.state, row.tier, row.impact) == ("FAILED_NOT_EXECUTED", "ATTESTED", "NONEXECUTION")
    assert row.released_at is not None


@pytest.mark.parametrize("envelope", ["ES256 attestation", "Ed25519 record"])
def test_tg8_a_report_signed_a_second_before_the_grants_second_is_refused(
    db, gate_world, owner, admin_engine, envelope
):
    """The one-second tolerance reaches back to the grant's own second and no further."""
    world = gate_world
    tines = register_es256(owner, world)
    granted, second = _granted_within_a_second(db, world, admin_engine)
    earlier = second - timedelta(seconds=1)
    body = _non_execution_signed_at(db, world, tines, granted, envelope, earlier)
    with pytest.raises(ExecutionError) as refused:
        report(db, world, granted.execution_id, body=body)
    assert refused.value.code == "INVALID_RECORD"
    row = retained(admin_engine, world["identity"].tenant_id, granted.execution_id)
    assert (row.state, row.tier, row.released_at) == ("DISPATCH_COMMITTED", None, None)


@pytest.mark.parametrize("envelope", ["Ed25519 record", "ES256 wrapper"])
def test_tg8_the_field_evidence_arrives_in_cannot_choose_the_tier(
    db, gate_world, owner, admin_engine, envelope
):
    """A verifiable executor envelope presented as a journal is refused, not settled.

    The field names the kind of evidence and so the tier it claims: a journal claims
    PROVIDER_VERIFIED. What checked an Ed25519 record says ATTESTED, and `_reported`'s
    `proved != tier` guard is what refuses the difference. Without it the report settles, at
    a tier the caller's choice of field picked rather than the verifier. The ES256 wrapper
    never reaches the verifier at all: `_stored_attestation` refuses it in any field but
    `attestation` first, which the test below holds.
    """
    world = gate_world
    tines = register_es256(owner, world)
    tenant = world["identity"].tenant_id
    granted = journaled(db, world).view
    if envelope == "Ed25519 record":
        journal = signed_record(db, world, granted.execution_id)
    else:
        token = jws(tines, HEADER, attestation_claims(db, world, granted.execution_id))
        protected, payload, signature = token.split(".")
        journal = {
            "format": "jws-es256",
            "key_id": TINES_KEY_ID,
            "protected": protected,
            "payload": payload,
            "signature": signature,
        }
    body = report_body(world, granted.checkpoint.report_secret, journal=journal)
    with pytest.raises(ExecutionError) as refused:
        report(db, world, granted.execution_id, body=body)
    assert refused.value.code == "INVALID_RECORD"
    row = retained(admin_engine, tenant, granted.execution_id)
    assert (row.state, row.tier) == ("DISPATCH_COMMITTED", None)
    assert row.released_at is None


class CountingVerifier:
    """The deployment's own verifier, counting the evidence it is asked to check."""

    attests_external_execution = True

    def __init__(self, verifier, checked):
        self._verifier, self._checked = verifier, checked

    def verify(self, command, evidence):
        self._checked.append(evidence)
        return self._verifier.verify(command, evidence)

    def verified_tier(self, proof):
        return self._verifier.verified_tier(proof)


@pytest.mark.parametrize("field", ["record", "journal"])
def test_tg8_an_attestation_in_its_stored_form_is_refused_before_any_signature_is_checked(
    db, gate_world, owner, admin_engine, field
):
    """ES256 arrives on the route only as `attestation` (section 2.6). In its stored form, the
    flattened wrapper a settlement retains, it is refused in `record` and in `journal` alike,
    before the verifier is asked anything; the same statement as the compact token settles."""
    world = gate_world
    tines = register_es256(owner, world)
    tenant = world["identity"].tenant_id
    granted = journaled(db, world).view
    token = jws(tines, HEADER, attestation_claims(db, world, granted.execution_id))
    protected, payload, signature = token.split(".")
    stored = {
        "format": "jws-es256",
        "key_id": TINES_KEY_ID,
        "protected": protected,
        "payload": payload,
        "signature": signature,
    }
    checked: list[bytes] = []

    def counting(conn, row):
        return CountingVerifier(journal_verifier(world)(conn, row), checked)

    secret = granted.checkpoint.report_secret
    with pytest.raises(ExecutionError) as refused:
        report(
            db,
            world,
            granted.execution_id,
            body=report_body(world, secret, **{field: stored}),
            verifier_for=counting,
        )
    assert refused.value.code == "INVALID_RECORD"
    assert checked == []
    row = retained(admin_engine, tenant, granted.execution_id)
    assert (row.state, row.tier, row.released_at) == ("DISPATCH_COMMITTED", None, None)

    settled = report(
        db,
        world,
        granted.execution_id,
        body=report_body(world, secret, attestation=token),
        verifier_for=counting,
    )
    assert settled.state == "EXECUTED" and checked
    assert retained(admin_engine, tenant, granted.execution_id).tier == "ATTESTED"


def test_tg8_a_provider_journal_presented_as_a_record_is_refused(db, gate_world, admin_engine):
    """The reverse of the guard above: a genuine journal in the executor's own field.

    The journal verifies under the configured journal key, so what refuses it is the tier
    its field claims. `record` claims ATTESTED, the verifier answers PROVIDER_VERIFIED, and
    `_reported` refuses the difference rather than settling at a tier the caller's choice of
    field picked. The same journal in its own field then settles, which is what says the
    refusal was the field and not the journal.
    """
    world = gate_world
    tenant = world["identity"].tenant_id
    granted = journaled(db, world).view
    secret = granted.checkpoint.report_secret
    journal = gate_journal(db, world, granted.execution_id)
    with pytest.raises(ExecutionError) as refused:
        report(
            db,
            world,
            granted.execution_id,
            body=report_body(world, secret, record=journal),
            verifier_for=journal_verifier(world),
        )
    assert refused.value.code == "INVALID_RECORD"
    row = retained(admin_engine, tenant, granted.execution_id)
    assert (row.state, row.tier, row.released_at) == ("DISPATCH_COMMITTED", None, None)
    settled = report(
        db,
        world,
        granted.execution_id,
        body=_journal_report(world, secret, journal),
        verifier_for=journal_verifier(world),
    )
    assert settled.state == "EXECUTED"
    assert retained(admin_engine, tenant, granted.execution_id).tier == "PROVIDER_VERIFIED"


@pytest.mark.parametrize(
    "padding",
    [("", ""), ("", "\n"), (" \t", "\r\n")],
    ids=["as sent", "trailing newline", "surrounding whitespace"],
)
def test_tg7_an_administrator_settles_a_grant_from_a_compact_jws(
    db, gate_world, owner, admin_engine, padding
):
    """The administrator exit takes the attestation as the executor sent it.

    `reconcile` hands the evidence bytes to the same verifier the report route uses, so a
    compact JWS settles an unsettled grant at ATTESTED and releases the claim, exactly as
    an Ed25519 record does there. A pasted token commonly arrives with a trailing newline,
    and the console passes the pasted text through unstripped; whitespace around the
    compact form is outside the signing input, so it is tolerated as a JSON envelope's
    is, and the retained wrapper is the same bytes either way.
    """
    world = gate_world
    tines = register_es256(owner, world)
    tenant = world["identity"].tenant_id
    admin = long_lived_admin(admin_engine, db, world)
    granted = checkpoint(db, world).view
    token = jws(tines, HEADER, attestation_claims(db, world, granted.execution_id))
    before, after = padding
    with db.transaction(tenant) as conn:
        verifier = executor_verifier(conn, store.read(conn, tenant, granted.execution_id))
    view = reconcile(
        db,
        admin,
        granted.execution_id,
        reason="settled from the executor's ES256 attestation",
        evidence=(before + token + after).encode("ascii"),
        verifier=verifier,
        verifier_for=executor_verifier,
        clock=world["clock"],
    )
    assert view.state == "EXECUTED"
    row = retained(admin_engine, tenant, granted.execution_id)
    assert (row.state, row.tier, row.impact) == ("EXECUTED", "ATTESTED", "CONFIRMED")
    assert row.released_at == world["clock"].now()
    retained_record = json.loads(row.result["authenticated_record"])
    protected, payload, signature = token.split(".")
    assert retained_record == {
        "version": 1,
        "format": "jws-es256",
        "key_id": TINES_KEY_ID,
        "protected": protected,
        "payload": payload,
        "signature": signature,
    }


def test_tg7_an_administrator_settles_a_grant_from_its_flattened_wrapper(
    db, gate_world, owner, admin_engine
):
    """The second accepted input form: a retained record pasted back whole.

    `ExecutorVerifier.verify` recognizes a JSON object first and tries it as the RFC 7515
    flattened wrapper `SignedOutcomeJws` retains before falling back to an Ed25519 record,
    so an administrator presenting the flattened JSON a settlement would have retained --
    built here from a compact token exactly the way `flattened_wrapper` builds one, rather
    than the compact token itself -- settles an unsettled grant at ATTESTED and releases the
    claim just as the compact token does in the test beside this one, and the retained
    record is the same bytes either form arrived as.
    """
    world = gate_world
    tines = register_es256(owner, world)
    tenant = world["identity"].tenant_id
    admin = long_lived_admin(admin_engine, db, world)
    granted = checkpoint(db, world).view
    token = jws(tines, HEADER, attestation_claims(db, world, granted.execution_id))
    protected, payload, signature = token.split(".")
    wrapper = {
        "format": "jws-es256",
        "key_id": TINES_KEY_ID,
        "protected": protected,
        "payload": payload,
        "signature": signature,
    }
    with db.transaction(tenant) as conn:
        verifier = executor_verifier(conn, store.read(conn, tenant, granted.execution_id))
    view = reconcile(
        db,
        admin,
        granted.execution_id,
        reason="settled from the flattened ES256 wrapper",
        evidence=json.dumps(wrapper).encode(),
        verifier=verifier,
        verifier_for=executor_verifier,
        clock=world["clock"],
    )
    assert view.state == "EXECUTED"
    row = retained(admin_engine, tenant, granted.execution_id)
    assert (row.state, row.tier, row.impact) == ("EXECUTED", "ATTESTED", "CONFIRMED")
    assert row.released_at == world["clock"].now()
    retained_record = json.loads(row.result["authenticated_record"])
    assert retained_record == {"version": 1, **wrapper}


@pytest.mark.parametrize(
    "token",
    ["a.b", "a.b.c.d", "a=.b.c", "a.b." + "c" * 5000, ""],
)
def test_tg8_malformed_tokens_are_refused_at_the_parser(db, gate_world, token):
    world = gate_world
    granted = checkpoint(db, world).view
    with pytest.raises(ExecutionError) as refused:
        report(
            db,
            world,
            granted.execution_id,
            body=report_body(world, granted.checkpoint.report_secret, attestation=token),
        )
    assert refused.value.code == "INVALID_REQUEST"


def _journal_report(world, secret, journal):
    reason = journal["record"]["outcome"]
    return report_body(
        world, secret, journal=journal, outcome=TERMINAL_PAIRS[reason], reason=reason
    )


@pytest.mark.parametrize(
    ("outcome", "state", "impact"),
    [
        ("EXECUTED", "EXECUTED", "CONFIRMED"),
        ("VERSION_MISMATCH", "STALE_AUTHORIZATION", "NONEXECUTION"),
        ("TARGET_NOT_FOUND", "FAILED_NOT_EXECUTED", "NONEXECUTION"),
        ("CANCELLED_NOT_EXECUTED", "FAILED_NOT_EXECUTED", "NONEXECUTION"),
    ],
)
def test_tg2_a_provider_journal_settles_provider_verified(
    db, gate_world, admin_engine, outcome, state, impact
):
    world = gate_world
    granted = journaled(db, world).view
    journal = gate_journal(db, world, granted.execution_id, outcome=outcome)
    body = _journal_report(world, granted.checkpoint.report_secret, journal)
    view = report(db, world, granted.execution_id, body=body, verifier_for=journal_verifier(world))
    assert view.state == state
    row = retained(admin_engine, world["identity"].tenant_id, granted.execution_id)
    assert (row.state, row.tier, row.impact) == (state, "PROVIDER_VERIFIED", impact)
    assert row.released_at is not None
    again = report(db, world, granted.execution_id, body=body, verifier_for=journal_verifier(world))
    assert again.state == state


JOURNAL_REFUSALS = (
    "no journal key configured",
    "unknown key id",
    "wrong key",
    "another execution",
    "altered version",
    "altered target",
    "altered intent",
    "dated before the grant",
)


def _journal_refusal(label, db, world, execution_id, other_id):
    """One journal that must not settle, and the verifier factory it is presented to."""
    earlier = world["clock"].now() - timedelta(minutes=5)
    configured = journal_verifier(world)
    build = {
        "no journal key configured": lambda: (
            gate_journal(db, world, execution_id),
            executor_verifier,
        ),
        "unknown key id": lambda: (
            gate_journal(db, world, execution_id, key_id="other-v1"),
            configured,
        ),
        "wrong key": lambda: (gate_journal(db, world, execution_id, key=b"x" * 40), configured),
        "another execution": lambda: (gate_journal(db, world, other_id), configured),
        "altered version": lambda: (
            gate_journal(db, world, execution_id, expected_version="moved"),
            configured,
        ),
        "altered target": lambda: (
            gate_journal(db, world, execution_id, resource_provider_id="elsewhere"),
            configured,
        ),
        "altered intent": lambda: (
            gate_journal(db, world, execution_id, intent_hash="0" * 64),
            configured,
        ),
        "dated before the grant": lambda: (
            gate_journal(db, world, execution_id, occurred_at=earlier),
            configured,
        ),
    }
    return build[label]()


@pytest.mark.parametrize("label", JOURNAL_REFUSALS)
def test_tg3_journals_that_must_not_settle_are_refused(db, gate_world, admin_engine, label):
    world = gate_world
    tenant = world["identity"].tenant_id
    other_action, action = targets(admin_engine, world, count=2)
    other = journaled(db, world, action=other_action).view
    granted = journaled(db, world, action=action).view
    journal, verifier_for = _journal_refusal(
        label, db, world, granted.execution_id, other.execution_id
    )
    body = _journal_report(world, granted.checkpoint.report_secret, journal)
    with pytest.raises(ExecutionError) as refused:
        report(db, world, granted.execution_id, body=body, verifier_for=verifier_for)
    assert refused.value.code == "INVALID_RECORD"
    row = retained(admin_engine, tenant, granted.execution_id)
    assert (row.state, row.tier) == ("DISPATCH_COMMITTED", None)


def test_tg3_a_body_contradicting_its_journal_and_mixed_evidence_are_refused(db, gate_world):
    world = gate_world
    granted = journaled(db, world).view
    secret = granted.checkpoint.report_secret
    journal = gate_journal(db, world, granted.execution_id)
    contradicting = report_body(
        world,
        secret,
        journal=journal,
        outcome="FAILED_NOT_EXECUTED",
        reason="CANCELLED_NOT_EXECUTED",
    )
    with pytest.raises(ExecutionError) as refused:
        report(
            db,
            world,
            granted.execution_id,
            body=contradicting,
            verifier_for=journal_verifier(world),
        )
    assert refused.value.code == "INVALID_RECORD"
    for extra in (
        {"reported_at": world["clock"].now().isoformat()},
        {"record": signed_record(db, world, granted.execution_id)},
    ):
        mixed = {**_journal_report(world, secret, journal), **extra}
        with pytest.raises(ExecutionError) as refused:
            report(
                db, world, granted.execution_id, body=mixed, verifier_for=journal_verifier(world)
            )
        assert refused.value.code == "INVALID_REQUEST"


def test_tg4_the_administrator_exit_accepts_a_journal_and_corrects_a_statement(
    db, gate_world, admin_engine
):
    world = gate_world
    tenant = world["identity"].tenant_id
    admin = long_lived_admin(admin_engine, db, world)
    first, second, third, fourth, fifth = targets(admin_engine, world, count=5)

    def settle(execution_id, journal):
        verifier_for = journal_verifier(world)
        with db.transaction(tenant) as conn:
            verifier = verifier_for(conn, store.read(conn, tenant, execution_id))
        return reconcile(
            db,
            admin,
            execution_id,
            reason="provider journal",
            evidence=json.dumps(journal).encode(),
            verifier=verifier,
            verifier_for=verifier_for,
            clock=world["clock"],
        )

    unsettled = journaled(db, world, action=first).view.execution_id
    assert settle(unsettled, gate_journal(db, world, unsettled)).state == "EXECUTED"
    assert retained(admin_engine, tenant, unsettled).tier == "PROVIDER_VERIFIED"
    swept = journaled(db, world, action=second).view.execution_id
    force_state(db, world, swept, "INDETERMINATE")
    assert settle(swept, gate_journal(db, world, swept)).state == "EXECUTED"
    stated = journaled(db, world, action=third).view
    report(
        db,
        world,
        stated.execution_id,
        body=report_body(
            world,
            stated.checkpoint.report_secret,
            outcome="FAILED_EFFECT_UNKNOWN",
            reason="REPORTED_FAILURE",
        ),
    )
    corrected = settle(
        stated.execution_id,
        gate_journal(db, world, stated.execution_id, outcome="CANCELLED_NOT_EXECUTED"),
    )
    row = retained(admin_engine, tenant, stated.execution_id)
    assert (corrected.state, row.tier, row.impact) == (
        "FAILED_NOT_EXECUTED",
        "PROVIDER_VERIFIED",
        "NONEXECUTION",
    )
    promoted = journaled(db, world, action=fourth).view
    report(
        db,
        world,
        promoted.execution_id,
        body=report_body(
            world,
            promoted.checkpoint.report_secret,
            outcome="FAILED_EFFECT_UNKNOWN",
            reason="REPORTED_FAILURE",
        ),
    )
    with pytest.raises(ExecutionError) as refused:
        settle(promoted.execution_id, gate_journal(db, world, promoted.execution_id))
    assert refused.value.code == "INVALID_STATE"
    asserted = journaled(db, world, action=fifth).view
    report(db, world, asserted.execution_id, asserted.checkpoint.report_secret)
    with pytest.raises(ExecutionError) as refused:
        settle(asserted.execution_id, gate_journal(db, world, asserted.execution_id))
    assert refused.value.code == "INVALID_STATE"
    with pytest.raises(ExecutionError) as refused:
        report(
            db,
            world,
            asserted.execution_id,
            body=_journal_report(
                world,
                asserted.checkpoint.report_secret,
                gate_journal(db, world, asserted.execution_id),
            ),
            verifier_for=journal_verifier(world),
        )
    assert refused.value.code == "INVALID_STATE"


def test_tg5_a_journal_key_is_never_a_connector_or_a_shared_key(db, gate_world):
    world = gate_world
    tenant, account = world["identity"].tenant_id, world["account"]
    provider = journal_provider(world)
    with pytest.raises(ValueError):
        Runtime(db, [], clock=world["clock"], checkpoint_providers=[provider, provider])
    shared = TokenKeys("k", {"k": provider.evidence_keys[JOURNAL_KEY_ID]})
    with pytest.raises(ValueError):
        Runtime(db, [], clock=world["clock"], keys=shared, checkpoint_providers=[provider])
    with pytest.raises(ValueError):
        CheckpointProvider(tenant, account, "graph", {JOURNAL_KEY_ID: b"k" * 32})
    with pytest.raises(ValueError):
        CheckpointProvider(tenant, account, "mock_crowdstrike", {JOURNAL_KEY_ID: b"short"})


def test_tg5_the_configuration_refuses_a_journal_key_on_a_connector_account(tmp_path, db):
    tenant, account = str(uuid4()), str(uuid4())
    connector = {
        "tenant_id": tenant,
        "account_id": account,
        "origin": "http://127.0.0.1:8101",
        "dispatch_token": "d" * 32,
        "control_token": "c" * 32,
        "evidence_keys": {"journal-v1": "ab" * 32},
    }
    config = {
        "origin": "http://127.0.0.1:8100",
        "active_key_id": "k",
        "continuation_keys": {"k": "cd" * 32},
        "connectors": [connector],
        "checkpoint_providers": [
            {
                "tenant_id": tenant,
                "account_id": account,
                "provider": "mock_crowdstrike",
                "evidence_keys": {"gate-v1": "ef" * 32},
            }
        ],
    }
    path = tmp_path / "gateway.json"
    path.write_text(json.dumps(config))
    with pytest.raises(ValueError):
        load_runtime(path, db)


@pytest.mark.parametrize("defect", ["duplicate entry", "graph account", "non-hex key"])
def test_tg5_the_configuration_refuses_a_duplicate_colliding_or_malformed_journal_entry(
    tmp_path, db, defect
):
    """Refused at load, through the same `load_runtime` a deployment boots from.

    Each file is first loaded without its defect, so what refuses the second load is the
    defect and nothing else about the file. A second entry for the same Gate account is
    refused even under a different key id, because one account has one journal key ring. An
    entry naming a Graph connection's account is refused as one naming a mock connector's
    is, since a checkpoint provider is never an account the deployment dispatches through.
    A journal key that is not hex never reaches a verifier. Every refusal is the same
    opaque error, quoting nothing from the file.
    """
    tenant, gate_account, graph_account = (str(uuid4()) for _ in range(3))
    gate = {
        "tenant_id": tenant,
        "account_id": gate_account,
        "provider": "mock_crowdstrike",
        "evidence_keys": {"gate-v1": "ef" * 32},
    }
    config = {
        "origin": "http://127.0.0.1:8100",
        "active_key_id": "k",
        "continuation_keys": {"k": "cd" * 32},
        "graph_connectors": [
            {
                "tenant_id": tenant,
                "account_id": graph_account,
                "directory": "00000000-0000-0000-0000-0000000000aa",
                "client_id": "00000000-0000-0000-0000-0000000000bb",
                "client_secret": "graph-client-secret-value",
                "signing_key_id": "connector-v1",
                "evidence_keys": {"connector-v1": "41" * 32},
            }
        ],
        "preconditions": [
            {
                "provider": "graph",
                "provider_operation": "disable",
                "precondition_class": "CHECKED_BY_CONNECTOR",
            }
        ],
        "checkpoint_providers": [gate],
    }
    path = tmp_path / "gateway.json"
    path.write_text(json.dumps(config))
    runtime, _ = load_runtime(path, db)
    for opened in runtime.connectors.values():
        opened.close()
    assert set(runtime.checkpoint_providers) == {(UUID(tenant), UUID(gate_account))}
    if defect == "duplicate entry":
        config["checkpoint_providers"] = [gate, {**gate, "evidence_keys": {"gate-v2": "12" * 32}}]
    elif defect == "graph account":
        config["checkpoint_providers"] = [{**gate, "account_id": graph_account}]
    else:
        config["checkpoint_providers"] = [{**gate, "evidence_keys": {"gate-v1": "zz" * 32}}]
    path.write_text(json.dumps(config))
    with pytest.raises(ValueError, match="^Invalid runtime configuration$") as refused:
        load_runtime(path, db)
    assert refused.value.__context__ is None


def test_tg5_a_journal_key_for_a_gate_account_loads_from_the_configuration(tmp_path, db):
    """The control for the refusal above: the same block naming a Gate account loads.

    A file with no connector at all loads too, because a deployment that only grants
    checkpoints dispatches nothing and has no connector account to declare. The block is
    part of the shape a reload may not change, since `Runtime.rotate` never touches it.
    """
    tenant, account = uuid4(), uuid4()
    gate = {
        "tenant_id": str(tenant),
        "account_id": str(account),
        "provider": "mock_crowdstrike",
        "evidence_keys": {"gate-v1": "ef" * 32},
    }
    connector = {
        "tenant_id": str(tenant),
        "account_id": str(uuid4()),
        "origin": "http://127.0.0.1:8101",
        "dispatch_token": "d" * 32,
        "control_token": "c" * 32,
        "evidence_keys": {"journal-v1": "ab" * 32},
    }
    base = {
        "origin": "http://127.0.0.1:8100",
        "active_key_id": "k",
        "continuation_keys": {"k": "cd" * 32},
        "checkpoint_providers": [gate],
    }
    path = tmp_path / "gateway.json"
    for connectors in ([connector], []):
        path.write_text(json.dumps({**base, "connectors": connectors}))
        runtime, _ = load_runtime(path, db)
        for opened in runtime.connectors.values():
            opened.close()
        assert len(runtime.connectors) == len(connectors)
        (provider,) = runtime.checkpoint_providers.values()
        assert (provider.tenant_id, provider.account_id) == (tenant, account)
        assert dict(provider.evidence_keys) == {"gate-v1": bytes.fromhex("ef" * 32)}
    shape = read_configuration(path).shape()
    moved = {**gate, "evidence_keys": {"gate-v2": "ef" * 32}}
    path.write_text(json.dumps({**base, "checkpoint_providers": [moved]}))
    assert read_configuration(path).shape() != shape


def test_tg5_a_journal_key_stays_apart_from_connectors_at_construction_and_rotation(db, gate_world):
    """A connector account never holds a journal key, and a live reload hands none over.

    Construction refuses a journal provider naming a connector's own account, which the
    configuration file refuses too but the constructor does not rely on. A rotation holds
    the journal key apart from both rotated rings exactly as construction does.
    """
    world = gate_world
    provider = journal_provider(world)
    journal_key = provider.evidence_keys[JOURNAL_KEY_ID]
    other = (world["identity"].tenant_id, uuid4())
    connector = MockConnector(
        ConnectionConfig(*other, "http://127.0.0.1:8101", "d" * 32, "c" * 32, {"p": b"p" * 32})
    )
    try:
        same = CheckpointProvider(*other, "mock_crowdstrike", {"g": b"g" * 32})
        with pytest.raises(ValueError):
            Runtime(db, [connector], clock=world["clock"], checkpoint_providers=[same])
        runtime = Runtime(
            db,
            [connector],
            clock=world["clock"],
            keys=TokenKeys("k", {"k": b"k" * 32}),
            checkpoint_providers=[provider],
        )
        with pytest.raises(ValueError):
            runtime.rotate(TokenKeys("j", {"j": journal_key}), {other: {"p": b"p" * 32}})
        with pytest.raises(ValueError):
            runtime.rotate(TokenKeys("k", {"k": b"k" * 32}), {other: {"j": journal_key}})
        assert runtime.keys.keys == {"k": b"k" * 32}
        assert dict(connector.config.evidence_keys) == {"p": b"p" * 32}
        runtime.rotate(TokenKeys("n", {"n": b"n" * 32}), {other: {"q": b"q" * 32}})
        assert runtime.keys.active_key_id == "n"
    finally:
        connector.close()


@pytest.mark.parametrize("path", ["reconcile", "record_outcome"])
def test_tg5_an_operation_execbound_dispatched_never_settles_from_a_journal(
    db, gate_world, admin_engine, path
):
    """Every dispatch path refuses checkpoint evidence, however genuine.

    The journal is signed under the configured journal key for this execution's own frozen
    command, so nothing about it is forged. What is wrong is the row: ExecBound dispatched
    it, and the verifier that checks checkpoint evidence says so of itself.
    """
    world = gate_world
    tenant = world["identity"].tenant_id
    gate_bundle(db, world, external_executor=False)
    ordinary = checkpoint(db, world, accounts=connected_account(world))
    assert ordinary.ticket is not None
    take_dispatch(db, ordinary.ticket, world["clock"])
    execution_id = ordinary.view.execution_id
    journal = json.dumps(gate_journal(db, world, execution_id)).encode()
    with db.transaction(tenant) as conn:
        verifier = journal_verifier(world)(conn, store.read(conn, tenant, execution_id))
    with pytest.raises(ExecutionError) as refused:
        if path == "reconcile":
            reconcile(
                db,
                world["admin"],
                execution_id,
                reason="a provider journal for an operation ExecBound dispatched",
                evidence=journal,
                verifier=verifier,
                clock=world["clock"],
            )
        else:
            record_outcome(db, ordinary.ticket, journal, verifier, world["clock"])
    assert refused.value.code == "INVALID_STATE"
    row = retained(admin_engine, tenant, execution_id)
    assert (row.state, row.tier, row.released_at) == ("DISPATCH_COMMITTED", None, None)


def test_an_attested_and_provider_verified_history_exports_with_the_secret_check_in_force(
    db, gate_world, owner, admin_engine
):
    """The regression the flattened-serialization retention exists to prevent.

    A compact JWS is three base64url segments joined by dots, and any JSON object header
    base64-encodes to a string starting `eyJ`, so a retained ES256 attestation kept as the
    compact token would always match `execbound.secrets.SECRET_TEXT`'s three-part-JWT
    pattern, and `export_history`'s own `reject_secrets` call would refuse every tenant
    history that ever held one. Retaining RFC 7515 flattened JSON serialization instead
    (`protected`, `payload` and `signature` as separate JSON strings, never joined by a
    literal dot) means the exported bytes never contain that shape, so the check stays
    exactly as strict as it is and still runs on every export. This exercises the real
    export path, with the check in force and nothing stubbed.
    """
    from execbound.replay.export import export_history
    from execbound.secrets import SECRET_TEXT

    world = gate_world
    tines = register_es256(owner, world)
    first, second = targets(admin_engine, world, count=2)
    signed = checkpoint(db, world, action=first).view
    token = jws(tines, HEADER, attestation_claims(db, world, signed.execution_id))
    report(
        db,
        world,
        signed.execution_id,
        body=report_body(world, signed.checkpoint.report_secret, attestation=token),
    )
    proven = journaled(db, world, action=second).view
    report(
        db,
        world,
        proven.execution_id,
        body=_journal_report(
            world, proven.checkpoint.report_secret, gate_journal(db, world, proven.execution_id)
        ),
        verifier_for=journal_verifier(world),
    )
    history = export_history(db, world["admin"], world["clock"])
    encoded = history.model_dump_json()
    assert not SECRET_TEXT.search(encoded)
    assert str(signed.execution_id) in encoded
    assert str(proven.execution_id) in encoded


def test_tg10_every_tier_replays_as_what_its_evidence_supports(db, gate_world, owner, admin_engine):
    from checkpoint_fixtures import settled_gate_world

    from execbound.replay.export import export_history
    from execbound.replay.report import render_report, report_json
    from execbound.replay.simulate import simulate
    from execbound.replay.verify import verify_export

    world = gate_world
    world["admin"] = long_lived_admin(admin_engine, db, world)
    settled = settled_gate_world(db, world, admin_engine)
    tines = register_es256(owner, world)
    first, second = targets(admin_engine, world, count=2)
    signed = checkpoint(db, world, action=first).view
    token = jws(tines, HEADER, attestation_claims(db, world, signed.execution_id))
    report(
        db,
        world,
        signed.execution_id,
        body=report_body(world, signed.checkpoint.report_secret, attestation=token),
    )
    proven = journaled(db, world, action=second).view
    report(
        db,
        world,
        proven.execution_id,
        body=_journal_report(
            world, proven.checkpoint.report_secret, gate_journal(db, world, proven.execution_id)
        ),
        verifier_for=journal_verifier(world),
    )
    history = export_history(db, world["admin"], world["clock"])
    verified = verify_export(history, history.head)
    assert verified.complete, verified.issues
    replayed = simulate(verified)
    rows = {row.execution_id: row for row in replayed.decisions}
    assert (
        rows[signed.execution_id].baseline.provenance,
        rows[signed.execution_id].settlement_tier,
    ) == (
        "RECORDED_EXECUTOR_EVIDENCE",
        "ATTESTED",
    )
    assert (
        rows[proven.execution_id].baseline.provenance,
        rows[proven.execution_id].settlement_tier,
    ) == (
        "RECORDED_PROVIDER_EVIDENCE",
        "PROVIDER_VERIFIED",
    )
    assert rows[settled.asserted].baseline.provenance == "RECORDED_TRANSITION"
    assert report_json(simulate(verify_export(history, history.head))) == report_json(replayed)
    assert "a provider-signed journal" in render_report(replayed)


def test_tg11_the_record_page_names_the_provider_tier_as_inert_text():
    from execbound.surfaces.human import _TIER_TEXT

    text_ = _TIER_TEXT["PROVIDER_VERIFIED"]
    assert text_.startswith("Provider verified:")
    assert "<" not in text_
