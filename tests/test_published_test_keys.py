# SPDX-License-Identifier: AGPL-3.0-only
"""ExecBound refuses the executor protocol's published test keys (#37).

The protocol publishes key material that anyone holds, so that an executor can be checked
without a key of its own: chapter 1's contract vectors are signed under one journal key,
`test_verification_key_hex`, and chapter 2's checkpoint report vectors publish an Ed25519 and an
ES256 executor key, private halves included, and a journal key. The vectors' executor
(`tests/checkpoint_vectors.py`) also signs the refusals with three keys outside every ring,
written as byte runs, and replay's regression fixtures are re-signed under a journal key their
source publishes (`replay.sanitize.FIXTURE_JOURNAL_KEY`). A key anyone holds authenticates
nobody, so on real PostgreSQL:

- registration and rotation refuse a published executor key in every spelling they accept,
  with the refusal every unusable key gets, `INVALID_KEY`, and store nothing;
- a published key already in a tenant's ring, as one registered before this guard would be,
  attests nothing: over the real outcome route every vector the executor signs is
  `INVALID_RECORD` and settles nothing, an administrator's settlement and correction from
  its record are refused, while the ring's own key goes on settling the same grant; admission,
  bundle validation and the revocation guard do not count it as a live key, and the key list
  marks it;
- a deployment that configures a published journal key, for a connector or for a Gate
  account, or a published sample key, in any form HMAC reads as the same key, is refused when
  it loads and when it reloads, and no runtime can be built holding one, so no journal
  verified under one settles anything; and every independence rule between rings is asked of
  the key HMAC uses rather than of the bytes it was written in.

The set refused is held equal to every key the vector files publish, every byte-run key the
vectors' executor signs with and every journal key the fixture source publishes, so none of them
can publish a key ExecBound would accept.
"""

import base64
import hashlib
import hmac
import json
import os
import secrets
import sys
from contextlib import ExitStack
from datetime import timedelta
from pathlib import Path
from uuid import uuid4

import checkpoint_vectors
import pytest
from checkpoint_fixtures import (
    GATE_KEY_ID,
    attestation_claims,
    audit_kinds,
    checkpoint,
    gate_bundle,
    grant_row,
    jws,
    register_keypair,
    report,
    retained,
    signed_record,
)
from checkpoint_fixtures import gate_world as gate_world
from checkpoint_fixtures import owner as owner
from checkpoint_vectors import (
    BY_NAME,
    ED25519_KEY_ID,
    ED25519_SEED,
    ES256_KEY_ID,
    ES256_SCALAR,
    JOURNAL_KEY_ID,
    PUBLISHED_KEYS,
    Keys,
    body,
    ed25519,
    ed25519_public,
    es256,
    es256_public,
    record,
)
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from execbound_protocol.checkpoint_conformance import Grant
from fastapi.testclient import TestClient
from sqlalchemy import text
from test_execution import provision_credential, targets
from test_execution import registry as registry
from test_execution import world as world

from execbound import administration
from execbound.administration import AdministrationError
from execbound.app import create_app
from execbound.cli import main
from execbound.execution import reconcile, store
from execbound.execution.models import NO_PRECONDITIONS, ExecutionError, PreconditionConfig
from execbound.policy.store import PolicyStoreError
from execbound.provider.checkpoint_evidence import CheckpointProvider
from execbound.provider.connector import ConnectionConfig, MockConnector
from execbound.provider.sample_accounts import SampleProvider
from execbound.replay import sanitize
from execbound.runtime import Runtime, attestable_ring, executor_verifier
from execbound.surfaces.configuration import load_runtime, read_configuration, reload_keys
from execbound.surfaces.tokens import TokenKeys

ROOT = Path(__file__).resolve().parents[1]
# Every vector directory of every protocol version, so a v2 beside v1 is read too.
VECTOR_FILES = sorted(ROOT.glob("protocol/**/vectors/*.json"))
# Every field of a vector file whose name says "key": the three that carry key material, and
# the four that name or hold it inside them. A field outside these is new key material, or a
# new name for it, which the refused set has to be taught.
MATERIAL_FIELDS = frozenset({"test_verification_key_hex", "executor_keys", "journal_keys"})
NAMING_FIELDS = frozenset({"key_id", "idempotency_key", "public_key", "test_private_key"})
# The maps whose keys are names a file chose (a vector's, a refusal's, an action's), not fields.
NAME_MAPS = frozenset({"vectors", "reports", "actions"})
# The vectors' executor writes its keys as byte runs named for what they are.
BYTE_RUN_SUFFIXES = ("_SEED", "_SCALAR", "_KEY")

CONTAIN = ("mock_crowdstrike", "contain")
DECLARED = {
    "UNAVAILABLE": NO_PRECONDITIONS,
    "ASSERTED_BY_EXECUTOR": PreconditionConfig({CONTAIN: "ASSERTED_BY_EXECUTOR"}),
    "ENFORCED_BY_PROVIDER": PreconditionConfig({CONTAIN: "ENFORCED_BY_PROVIDER"}),
}
# The vectors the executor signs itself. The journal vectors are signed under the published
# journal key, which no runtime can be given (`test_no_runtime_holds_a_published_journal_key`),
# so they are not sent over the route here.
EXECUTOR_SIGNED_VECTORS = sorted(
    name for name, scenario in BY_NAME.items() if scenario.evidence in {"record", "attestation"}
)
CHAPTER_1_JOURNAL_KEY = bytes(range(32))


def _key_fields(value: object, *, names: bool = False) -> set[str]:
    """Every field name containing "key" anywhere in a vector document."""
    found: set[str] = set()
    if isinstance(value, dict):
        for name, inner in value.items():
            if not names and "key" in name.lower():
                found.add(name)
            found |= _key_fields(inner, names=name in NAME_MAPS)
    elif isinstance(value, list):
        for inner in value:
            found |= _key_fields(inner)
    return found


def _material(value: object, executor: set[str], journal: set[bytes]) -> None:
    """Collect the key material a vector document carries, at whatever depth it sits."""
    if isinstance(value, dict):
        for name, inner in value.items():
            if name == "test_verification_key_hex":
                journal.add(bytes.fromhex(inner))
            elif name == "executor_keys":
                executor.update(entry["public_key"] for entry in inner.values())
            elif name == "journal_keys":
                journal.update(bytes.fromhex(key) for key in inner.values())
            _material(inner, executor, journal)
    elif isinstance(value, list):
        for inner in value:
            _material(inner, executor, journal)


def published_in_vector_files() -> tuple[set[str], set[bytes]]:
    """The executor public keys and the journal keys every vector file publishes."""
    executor: set[str] = set()
    journal: set[bytes] = set()
    for path in VECTOR_FILES:
        document = json.loads(path.read_text(encoding="utf-8"))
        unknown = _key_fields(document) - MATERIAL_FIELDS - NAMING_FIELDS
        assert not unknown, f"{path.name} names key material in {sorted(unknown)}"
        _material(document, executor, journal)
    return executor, journal


def byte_run_keys() -> tuple[set[str], set[bytes], set[str]]:
    """Every key the vectors' executor writes as a byte run: the public halves of its executor
    keys, its journal keys, and the names it found them under."""
    executor: set[str] = set()
    journal: set[bytes] = set()
    names: set[str] = set()
    for name in dir(checkpoint_vectors):
        value = getattr(checkpoint_vectors, name)
        if not name.endswith(BYTE_RUN_SUFFIXES) or type(value) is not bytes:
            continue
        names.add(name)
        if name.endswith("_SEED"):
            executor.add(ed25519_public(value).hex())
        elif name.endswith("_SCALAR"):
            executor.add(es256_public(value).hex())
        else:
            journal.add(value)
    return executor, journal, names


def fixture_keys() -> tuple[set[bytes], set[str]]:
    """Every journal key replay's fixture source publishes, and the names it holds them under."""
    keys: set[bytes] = set()
    names: set[str] = set()
    for name in dir(sanitize):
        value = getattr(sanitize, name)
        if name.endswith("_KEY") and type(value) is bytes:
            keys.add(value)
            names.add(name)
    return keys, names


def test_the_refused_keys_are_exactly_the_keys_the_vectors_publish():
    """One source of truth: the server's set is every key a vector file publishes, at any depth
    and in any version's directory, every byte-run key the vectors' executor signs with, and the
    journal key replay's fixtures are re-signed under, and only those, for both chapters and both
    kinds of key."""
    from execbound.provider.published_keys import PUBLISHED_EXECUTOR_KEYS, PUBLISHED_JOURNAL_KEYS

    assert VECTOR_FILES and {path.parent for path in VECTOR_FILES} == {
        ROOT / "protocol" / "executor" / "v1" / "vectors"
    }
    executor, journal = published_in_vector_files()
    assert len(executor) == 2 and len(journal) == 2
    assert CHAPTER_1_JOURNAL_KEY in journal
    run_executor, run_journal, names = byte_run_keys()
    assert names == {
        "ED25519_SEED",
        "ES256_SCALAR",
        "JOURNAL_KEY",
        "OUTSIDE_ED25519_SEED",
        "OUTSIDE_ES256_SCALAR",
        "OUTSIDE_JOURNAL_KEY",
    }
    assert executor <= run_executor and journal - {CHAPTER_1_JOURNAL_KEY} <= run_journal
    fixture, fixture_names = fixture_keys()
    assert fixture_names == {"FIXTURE_JOURNAL_KEY"}
    assert PUBLISHED_EXECUTOR_KEYS == executor | run_executor
    assert PUBLISHED_JOURNAL_KEYS == journal | run_journal | fixture


def test_anyone_can_sign_for_each_published_executor_key():
    """What makes these keys worthless: the file that publishes each public half publishes the
    private half it comes from."""
    document = json.loads(
        (ROOT / "protocol/executor/v1/vectors/checkpoint-report-v1.json").read_text(
            encoding="utf-8"
        )
    )
    keys = document["executor_keys"]
    assert {key["test_private_key"] for key in keys.values()} == {
        ED25519_SEED.hex(),
        ES256_SCALAR.hex(),
    }
    assert {key_id: (key["algorithm"], key["public_key"]) for key_id, key in keys.items()} == {
        key_id: (algorithm, public.hex())
        for key_id, (algorithm, public) in PUBLISHED_KEYS.public_keys().items()
    }


def test_a_published_journal_key_is_refused_in_every_form_hmac_reads_as_it():
    """HMAC-SHA256 pads a key shorter than its 64-byte block with zero bytes and hashes one
    longer, so a published key with zero bytes appended verifies every journal signed under
    it. Each such form is refused, and a key that differs in a byte is not."""
    from execbound.provider.published_keys import (
        PUBLISHED_JOURNAL_KEYS,
        hmac_key,
        published_journal_key,
    )

    message = b"a journal anyone could sign"
    for key in PUBLISHED_JOURNAL_KEYS:
        signed = hmac.new(key, message, hashlib.sha256).digest()
        for form in (key, key + b"\x00", key.ljust(64, b"\x00"), bytearray(key + b"\x00")):
            assert hmac.new(bytes(form), message, hashlib.sha256).digest() == signed
            assert published_journal_key(form)
        assert not published_journal_key(key[:-1] + bytes([key[-1] ^ 1]))
        assert not published_journal_key(key.ljust(65, b"\x00"))
    # A key longer than the block is used as its SHA-256, which is what the form compares.
    long = secrets.token_bytes(100)
    assert hmac_key(long) == hmac_key(hashlib.sha256(long).digest())
    assert (
        hmac.new(long, message, hashlib.sha256).digest()
        == hmac.new(hashlib.sha256(long).digest(), message, hashlib.sha256).digest()
    )


# Registration.


def _segment(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def spellings(keys: Keys) -> dict[str, tuple[str, str]]:
    """Every spelling registration reads of one key set's executor keys: (algorithm, input)."""
    ed25519_hex = ed25519_public(keys.ed25519_seed).hex()
    point = es256(keys.es256_scalar).public_key()
    numbers = point.public_numbers()
    jwk = {
        "kty": "EC",
        "crv": "P-256",
        "x": _segment(numbers.x.to_bytes(32, "big")),
        "y": _segment(numbers.y.to_bytes(32, "big")),
    }
    # Every optional public member a JWK may carry beside the point.
    full = jwk | {"kid": "executor-2026", "use": "sig", "alg": "ES256", "key_ops": ["verify"]}
    compressed = es256_public(keys.es256_scalar).hex()
    return {
        "ed25519-hex": ("ED25519", ed25519_hex),
        "ed25519-upper-hex": ("ED25519", ed25519_hex.upper()),
        "es256-hex": ("ES256", compressed),
        "es256-upper-hex": ("ES256", compressed.upper()),
        "es256-pem": (
            "ES256",
            point.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo).decode(),
        ),
        "es256-jwk": ("ES256", json.dumps(jwk)),
        "es256-jwk-with-public-members": ("ES256", json.dumps(full)),
    }


SPELLINGS = sorted(spellings(PUBLISHED_KEYS))


def registered_kinds(admin_engine, tenant):
    return [kind for kind, _ in audit_kinds(admin_engine, tenant) if kind.startswith("executor")]


@pytest.mark.parametrize("spelling", SPELLINGS)
def test_registration_refuses_a_published_key_in_every_spelling(
    owner, admin_engine, gate_world, spelling
):
    """Refused as every unusable key is, storing and auditing nothing; the same spelling of a
    key nobody published registers, so what is refused is the material."""
    world = gate_world
    tenant, actor = world["identity"].tenant_id, world["admin"].principal_id
    ring, kinds = (
        administration.list_executor_keys(owner, tenant),
        registered_kinds(admin_engine, tenant),
    )
    algorithm, value = spellings(PUBLISHED_KEYS)[spelling]
    with pytest.raises(AdministrationError) as refusal:
        administration.register_executor_key(
            owner, tenant, "published", value, actor, algorithm=algorithm
        )
    assert refusal.value.code == "INVALID_KEY"
    assert administration.list_executor_keys(owner, tenant) == ring
    assert registered_kinds(admin_engine, tenant) == kinds

    algorithm, value = spellings(Keys.generate())[spelling]
    administration.register_executor_key(owner, tenant, "own", value, actor, algorithm=algorithm)
    assert [key.key_id for key in administration.list_executor_keys(owner, tenant)] == [
        GATE_KEY_ID,
        "own",
    ]


@pytest.mark.parametrize("spelling", ["ed25519-hex", "es256-pem"])
def test_rotation_refuses_a_published_key_and_retires_nothing(owner, gate_world, spelling):
    world = gate_world
    tenant, actor = world["identity"].tenant_id, world["admin"].principal_id
    algorithm, value = spellings(PUBLISHED_KEYS)[spelling]
    with pytest.raises(AdministrationError) as refusal:
        administration.rotate_executor_key(
            owner, tenant, GATE_KEY_ID, "published", value, actor, algorithm=algorithm
        )
    assert refusal.value.code == "INVALID_KEY"
    (key,) = administration.list_executor_keys(owner, tenant)
    assert (key.key_id, key.revoked_at) == (GATE_KEY_ID, None)


def test_the_cli_refuses_to_register_a_published_key(
    owner, gate_world, monkeypatch, capsys, tmp_path
):
    """The operator's command, from a value and from a file, answers the bare refusal and
    never echoes the key it was given."""
    monkeypatch.setenv("DATABASE_URL", os.environ["TEST_DATABASE_URL"])
    monkeypatch.setenv("MIGRATION_DATABASE_URL", os.environ["TEST_MIGRATION_DATABASE_URL"])
    world = gate_world
    tenant, actor = str(world["identity"].tenant_id), str(world["admin"].principal_id)
    _, ed25519_hex = spellings(PUBLISHED_KEYS)["ed25519-hex"]
    _, pem = spellings(PUBLISHED_KEYS)["es256-pem"]
    pem_file = tmp_path / "published.pem"
    pem_file.write_text(pem)
    for material, given in (
        (["--public-key", ed25519_hex], ed25519_hex),
        (["--public-key-file", str(pem_file), "--algorithm", "ES256"], pem.strip()),
    ):
        argv = ["executor-key-register", "--tenant", tenant, "--key-id", "published"]
        monkeypatch.setattr(sys, "argv", ["execbound", *argv, *material, "--actor", actor])
        with pytest.raises(SystemExit) as caught:
            main()
        assert caught.value.code == 2
        refused = capsys.readouterr()
        assert "Administration refused: INVALID_KEY." in refused.err
        echoed = refused.out + refused.err
        assert given not in echoed
        # Not even the PEM's base64 body, line by line.
        assert not any(
            line in echoed for line in given.splitlines() if line and not line.startswith("-----")
        )
    assert [
        key.key_id for key in administration.list_executor_keys(owner, world["identity"].tenant_id)
    ] == [GATE_KEY_ID]


# A ring holding the published keys, as one registered before this guard would.


def store_published_keys(admin_engine, world):
    """Write the published executor keys into the tenant's ring under the vectors' own key
    ids, straight into the table: registration refuses them now, and a row this guard
    predates is exactly such a row."""
    tenant = world["identity"].tenant_id
    with admin_engine.begin() as conn:
        for key_id, (algorithm, public_key) in PUBLISHED_KEYS.public_keys().items():
            conn.execute(
                text(
                    "INSERT INTO execbound.executor_keys "
                    "(tenant_id, key_id, algorithm, public_key, created_at) "
                    "VALUES (:t, :k, :a, :p, :n)"
                ),
                {
                    "t": tenant,
                    "k": key_id,
                    "a": algorithm,
                    "p": public_key.hex(),
                    "n": world["clock"].now(),
                },
            )


def test_the_key_list_marks_a_stored_published_key(owner, admin_engine, gate_world):
    """So an operator can tell which row to revoke; the tenant's own key is not marked."""
    world = gate_world
    store_published_keys(admin_engine, world)
    listed = administration.list_executor_keys(owner, world["identity"].tenant_id)
    assert {key.key_id: key.published for key in listed} == {
        GATE_KEY_ID: False,
        ED25519_KEY_ID: True,
        ES256_KEY_ID: True,
    }


class Gateway:
    """A Gate deployment's HTTP surface over one tenant and one clock."""

    def __init__(self, admin_engine, world, client):
        self.admin_engine, self.world, self.client = admin_engine, world, client
        self.tenant = world["identity"].tenant_id

    def execute(self):
        (action,) = targets(self.admin_engine, self.world, count=1)
        return self.client.post("/v1/execute", json=action.model_dump(mode="json"))

    def grant(self, precondition_class: str) -> Grant:
        answered = self.execute()
        assert answered.status_code == 202, answered.text
        answer = answered.json()
        assert answer["state"] == "DISPATCH_COMMITTED"
        wire = answer["checkpoint"]["grant"]
        assert wire["precondition_class"] == precondition_class
        row = grant_row(self.admin_engine, self.tenant, answer["execution_id"])
        return Grant.read(answer["execution_id"], wire, row["dispatch_attempted_at"])

    def report(self, grant: Grant, raw: bytes):
        return self.client.post(
            f"/v1/executions/{grant.execution_id}/outcome",
            content=raw,
            headers={"Content-Type": "application/json"},
        )

    def held(self, grant: Grant) -> tuple[str, str | None, str, bool]:
        """State, tier, impact and whether the target is still claimed, as stored."""
        row = retained(self.admin_engine, self.tenant, grant.execution_id)
        return (row.state, row.tier, row.impact, row.released_at is None)


@pytest.fixture
def gateways(db, gate_world, admin_engine):
    """A Gate tenant whose ring holds its own key and, beside it, the published executor keys
    under the vectors' key ids."""
    world = gate_world
    store_published_keys(admin_engine, world)
    # A grant instant a second after every key's registration, with microseconds, as the
    # vectors' grants carry.
    world["clock"].value = (world["clock"].now() + timedelta(seconds=1)).replace(
        microsecond=250_000
    )
    identity = world["identity"]
    with admin_engine.begin() as conn:
        token = provision_credential(
            conn, identity.tenant_id, identity.principal_id, world["clock"].now(), timedelta(days=2)
        )
    with ExitStack() as stack:

        def open_gateway(precondition_class: str) -> Gateway:
            runtime = Runtime(
                db, [], clock=world["clock"], preconditions=DECLARED[precondition_class]
            )
            client = stack.enter_context(TestClient(create_app(db, runtime=runtime)))
            client.headers["Authorization"] = "Bearer " + token
            return Gateway(admin_engine, world, client)

        yield open_gateway


@pytest.mark.parametrize("name", EXECUTOR_SIGNED_VECTORS)
def test_a_stored_published_key_attests_none_of_the_vectors_executor_signed_reports(
    gateways, gate_world, name
):
    """Every vector the executor signs, a record or an attestation signed as the file signs
    it, is refused as signed evidence that does not verify and leaves its grant exactly as it
    was; the tenant's own key then settles that same grant, so the rest of the ring is
    untouched."""
    scenario = BY_NAME[name]
    gateway = gateways(scenario.precondition_class)
    grant = gateway.grant(scenario.precondition_class)
    before = gateway.held(grant)
    assert before == ("DISPATCH_COMMITTED", None, "UNRESOLVED", True)

    answered = gateway.report(grant, body(scenario.report(grant)))
    assert answered.status_code == 400, answered.text
    assert answered.json()["code"] == "INVALID_RECORD"
    assert gateway.held(grant) == before

    own = gate_world["executor_key"].private_bytes_raw()
    settles = gateway.report(
        grant,
        body(
            {
                "report_secret": grant.report_secret,
                "outcome": "EXECUTED",
                "reason": "EXECUTED",
                "record": record(grant, "EXECUTED", "EXECUTED", seed=own, key_id=GATE_KEY_ID),
            }
        ),
    )
    assert settles.status_code == 200, settles.text
    assert gateway.held(grant) == ("EXECUTED", "ATTESTED", "CONFIRMED", False)


def test_admission_does_not_count_a_published_key_as_one_a_grant_could_be_attested_by(
    owner, db, admin_engine, gateways, gate_world
):
    """A ring whose only live keys are published could attest no grant, so admission refuses
    to issue one, as it does for a ring that will not load; while the tenant's own key is live,
    grants issue. The revocation guard keeps a tenant out of that state, so it is reached as an
    operator reaches it, by reporting the tenant's own key compromised."""
    world = gate_world
    tenant = world["identity"].tenant_id
    gateway = gateways("ENFORCED_BY_PROVIDER")
    gateway.grant("ENFORCED_BY_PROVIDER")
    with db.transaction(tenant) as conn:
        assert attestable_ring(conn, tenant)

    administration.report_executor_key_compromise(
        owner, tenant, GATE_KEY_ID, world["admin"].principal_id, now=world["clock"].now()
    )
    with db.transaction(tenant) as conn:
        assert not attestable_ring(conn, tenant)
    refused = gateway.execute()
    assert refused.status_code == 409, refused.text
    assert refused.json()["code"] == "INVALID_BUNDLE"


def test_the_tenants_own_last_key_is_not_retired_beside_published_ones(
    owner, db, admin_engine, gate_world
):
    """The revocation guard counts what admission counts: with the tenant's active bundle
    declaring an external executor, its own last key is not retired while only published keys
    would be left, and bundle validation does not accept a published key as the live key it
    asks for. A second key of the tenant's own makes the same retirement allowed."""
    world = gate_world
    tenant, actor = world["identity"].tenant_id, world["admin"].principal_id
    store_published_keys(admin_engine, world)
    with pytest.raises(AdministrationError) as refusal:
        administration.revoke_executor_key(owner, tenant, GATE_KEY_ID, actor)
    assert refusal.value.code == "INVALID_STATE"
    live = {
        key.key_id
        for key in administration.list_executor_keys(owner, tenant)
        if key.revoked_at is None
    }
    assert live == {GATE_KEY_ID, ED25519_KEY_ID, ES256_KEY_ID}

    administration.report_executor_key_compromise(owner, tenant, GATE_KEY_ID, actor)
    with pytest.raises(PolicyStoreError) as invalid:
        gate_bundle(db, world)
    assert (invalid.value.code, invalid.value.location) == (
        "INVALID_COMPONENT",
        "mappings.0.external_executor",
    )

    register_keypair(owner, world, key_id="executor-v2")
    gate_bundle(db, world)
    register_keypair(owner, world, key_id="executor-v3")
    administration.revoke_executor_key(owner, tenant, "executor-v2", actor)


def published_evidence(db, world, execution_id, scheme, **changes) -> bytes:
    """Evidence an executor signs with a published key, as an administrator would paste it."""
    if scheme == "ED25519":
        signed = signed_record(
            db,
            world,
            execution_id,
            private_key=ed25519(ED25519_SEED),
            key_id=ED25519_KEY_ID,
            **changes,
        )
        return json.dumps(signed).encode()
    claims = attestation_claims(db, world, execution_id, **changes)
    return jws(es256(ES256_SCALAR), {"alg": "ES256", "kid": ES256_KEY_ID}, claims).encode()


def administrators_settlement(db, world, execution_id, evidence: bytes):
    """The administrator's settlement as the runtime runs it: the verifier the outcome route
    builds, and the runtime's factory for the fenced read."""
    tenant = world["identity"].tenant_id
    with db.transaction(tenant) as conn:
        verifier = executor_verifier(conn, store.read(conn, tenant, execution_id))
    return reconcile(
        db,
        world["admin"],
        execution_id,
        reason="settled from the executor's signed record",
        evidence=evidence,
        verifier=verifier,
        verifier_for=executor_verifier,
        clock=world["clock"],
    )


@pytest.mark.parametrize("scheme", ["ED25519", "ES256"])
def test_an_administrator_settles_nothing_from_evidence_a_published_key_signed(
    db, admin_engine, gate_world, scheme
):
    """`reconcile`, the administrator's exit, weighs evidence at the same verifier: a record or
    an attestation a published key signed is refused and the grant stays as it was, and the
    tenant's own record then settles it."""
    world = gate_world
    tenant = world["identity"].tenant_id
    store_published_keys(admin_engine, world)
    granted = checkpoint(db, world)
    execution_id = granted.view.execution_id
    with pytest.raises(ExecutionError) as refused:
        administrators_settlement(
            db, world, execution_id, published_evidence(db, world, execution_id, scheme)
        )
    assert refused.value.code == "INVALID_EVIDENCE"
    row = retained(admin_engine, tenant, execution_id)
    assert (row.state, row.tier, row.released_at) == ("DISPATCH_COMMITTED", None, None)

    own = json.dumps(signed_record(db, world, execution_id)).encode()
    assert administrators_settlement(db, world, execution_id, own).state == "EXECUTED"
    row = retained(admin_engine, tenant, execution_id)
    assert (row.state, row.tier, row.impact) == ("EXECUTED", "ATTESTED", "CONFIRMED")


@pytest.mark.parametrize("scheme", ["ED25519", "ES256"])
def test_a_published_key_corrects_no_reported_failure(db, admin_engine, gate_world, scheme):
    """The correction, an administrator's signed non-execution over the executor's unsigned
    REPORTED_FAILURE, refunds and releases on verified evidence alone. Signed with a published
    key it is refused and the charge stands; signed with the tenant's own key it corrects."""
    world = gate_world
    tenant = world["identity"].tenant_id
    store_published_keys(admin_engine, world)
    granted = checkpoint(db, world)
    grant = granted.view.checkpoint
    assert grant is not None
    execution_id = granted.view.execution_id
    stated = report(
        db,
        world,
        execution_id,
        grant.report_secret,
        outcome="FAILED_EFFECT_UNKNOWN",
        reason="REPORTED_FAILURE",
    )
    assert stated.state == "FAILED_EFFECT_UNKNOWN"
    charged = ("FAILED_EFFECT_UNKNOWN", "ASSERTED", "CONFIRMED", None)
    non_execution = {"outcome": "FAILED_NOT_EXECUTED", "reason": "CANCELLED_NOT_EXECUTED"}

    with pytest.raises(ExecutionError) as refused:
        administrators_settlement(
            db,
            world,
            execution_id,
            published_evidence(db, world, execution_id, scheme, **non_execution),
        )
    assert refused.value.code == "INVALID_EVIDENCE"
    row = retained(admin_engine, tenant, execution_id)
    assert (row.state, row.tier, row.impact, row.released_at) == charged

    own = json.dumps(signed_record(db, world, execution_id, **non_execution)).encode()
    assert administrators_settlement(db, world, execution_id, own).state == "FAILED_NOT_EXECUTED"
    row = retained(admin_engine, tenant, execution_id)
    assert (row.state, row.tier, row.impact) == ("FAILED_NOT_EXECUTED", "ATTESTED", "NONEXECUTION")


# A published journal key, or a published sample key, in a deployment's configuration.

PUBLISHED_JOURNAL_KEYS = {
    "chapter-1": CHAPTER_1_JOURNAL_KEY,
    "chapter-2": PUBLISHED_KEYS.journal_key,
    "replay-fixture": sanitize.FIXTURE_JOURNAL_KEY,
}
# What a file may write a published key as and HMAC still read as that key.
FORMS = {
    "lower": lambda key: key.hex(),
    "upper": lambda key: key.hex().upper(),
    "zero-padded": lambda key: (key + b"\x00").hex(),
}


def configuration(block: str, extra: dict[str, str]) -> dict:
    """A deployment holding one provider configuration of `block`, its ring a key of its own
    with `extra` beside it; for `sample_providers`, `extra` holds the sample key."""
    tenant, account = str(uuid4()), str(uuid4())
    own = {"journal-v1": secrets.token_hex(32)}
    config: dict = {
        "origin": "http://127.0.0.1:8100",
        "active_key_id": "k",
        "continuation_keys": {"k": secrets.token_hex(32)},
    }
    if block == "connectors":
        config["connectors"] = [
            {
                "tenant_id": tenant,
                "account_id": account,
                "origin": "http://127.0.0.1:8101",
                "dispatch_token": secrets.token_urlsafe(32),
                "control_token": secrets.token_urlsafe(32),
                "evidence_keys": own | extra,
            }
        ]
    elif block == "graph_connectors":
        config["graph_connectors"] = [
            {
                "tenant_id": tenant,
                "account_id": account,
                "directory": "00000000-0000-0000-0000-0000000000aa",
                "client_id": "00000000-0000-0000-0000-0000000000bb",
                "client_secret": "graph-client-secret-value",
                "signing_key_id": "journal-v1",
                "evidence_keys": own | extra,
            }
        ]
        config["preconditions"] = [
            {
                "provider": "graph",
                "provider_operation": "disable",
                "precondition_class": "CHECKED_BY_CONNECTOR",
            }
        ]
    elif block == "sample_providers":
        config["sample_providers"] = {
            "mock_crowdstrike": {
                "origin": "http://127.0.0.1:8102",
                "sample_key": extra.get("published-v1", secrets.token_hex(32)),
            }
        }
    else:
        config["checkpoint_providers"] = [
            {
                "tenant_id": tenant,
                "account_id": account,
                "provider": "mock_crowdstrike",
                "evidence_keys": own | extra,
            }
        ]
    return config


def loaded(path, db):
    runtime, human = load_runtime(path, db)
    for opened in runtime.connectors.values():
        opened.close()
    return runtime, human


# A sample key is lower-case hex only, so an upper-case one is refused as malformed whatever
# it holds, and is no evidence of this refusal.
CONFIGURED = [
    (block, published, form)
    for block in ("connectors", "graph_connectors", "checkpoint_providers", "sample_providers")
    for published in sorted(PUBLISHED_JOURNAL_KEYS)
    for form in sorted(FORMS)
    if (block, form) != ("sample_providers", "upper")
]


@pytest.mark.parametrize(("block", "published", "form"), CONFIGURED)
def test_the_configuration_refuses_a_published_journal_key(tmp_path, db, block, published, form):
    """Through the `load_runtime` a deployment boots from: the file loads with its own key, and
    the same file with a published key beside it, in either case of hex or with a zero byte
    appended, is refused whole with the opaque error every refused file gets. A sample key is
    refused too, since it derives every sample account's journal key."""
    key = FORMS[form](PUBLISHED_JOURNAL_KEYS[published])
    path = tmp_path / "gateway.json"
    path.write_text(json.dumps(configuration(block, {})))
    loaded(path, db)
    path.write_text(json.dumps(configuration(block, {"published-v1": key})))
    with pytest.raises(ValueError, match="^Invalid runtime configuration$"):
        load_runtime(path, db)


@pytest.mark.parametrize("published", sorted(PUBLISHED_JOURNAL_KEYS))
def test_no_runtime_holds_a_published_journal_key(db, gate_world, published):
    """The composition boundary refuses one however the configuration was built: as a Gate
    account's journal key under the vectors' own key id, which is what a gateway settling the
    journal vectors would need, as a connector's evidence key, and as a sample key, in the form
    written and with a zero byte appended. So nothing a deployment holds verifies a journal under
    it."""
    world = gate_world
    tenant, account = world["identity"].tenant_id, world["account"]
    for key in (PUBLISHED_JOURNAL_KEYS[published], PUBLISHED_JOURNAL_KEYS[published] + b"\x00"):
        with pytest.raises(ValueError):
            Runtime(
                db,
                [],
                clock=world["clock"],
                checkpoint_providers=[
                    CheckpointProvider(tenant, account, "mock_crowdstrike", {JOURNAL_KEY_ID: key})
                ],
            )
        connector = MockConnector(
            ConnectionConfig(
                tenant,
                uuid4(),
                "http://127.0.0.1:8101",
                secrets.token_urlsafe(32),
                secrets.token_urlsafe(32),
                {"journal-v1": secrets.token_bytes(32), "published-v1": key},
                5.0,
            )
        )
        try:
            with pytest.raises(ValueError):
                Runtime(db, [connector], clock=world["clock"])
        finally:
            connector.close()
        with pytest.raises(ValueError):
            Runtime(
                db,
                [],
                clock=world["clock"],
                sample_providers=[SampleProvider("mock_crowdstrike", "http://127.0.0.1:8102", key)],
            )
    Runtime(
        db,
        [],
        clock=world["clock"],
        checkpoint_providers=[
            CheckpointProvider(
                tenant, account, "mock_crowdstrike", {JOURNAL_KEY_ID: secrets.token_bytes(32)}
            )
        ],
        sample_providers=[
            SampleProvider("mock_crowdstrike", "http://127.0.0.1:8102", secrets.token_bytes(32))
        ],
    )


@pytest.mark.parametrize("published", sorted(PUBLISHED_JOURNAL_KEYS))
def test_a_reload_refuses_a_published_journal_key_and_keeps_the_running_ring(
    tmp_path, db, published
):
    """A key reload is a configuration too: a connector ring that takes up a published key, as
    written or zero-padded, is refused as invalid keys and the running ring stays as it was,
    both through the file and through `Runtime.rotate`."""
    key = PUBLISHED_JOURNAL_KEYS[published]
    config = configuration("connectors", {})
    path = tmp_path / "gateway.json"
    path.write_text(json.dumps(config))
    runtime, human = loaded(path, db)
    baseline = read_configuration(path)
    (account,) = runtime.connectors
    running = dict(runtime.connectors[account].config.evidence_keys)

    for written in (key, key + b"\x00"):
        config["connectors"][0]["evidence_keys"]["published-v1"] = written.hex()
        path.write_text(json.dumps(config))
        outcome = reload_keys(path, runtime, human, baseline)
        assert (outcome.state, outcome.code) == ("refused", "INVALID_KEYS")
        assert dict(runtime.connectors[account].config.evidence_keys) == running

        with pytest.raises(ValueError):
            runtime.rotate(runtime.keys, {account: {**running, "published-v1": written}})
        assert dict(runtime.connectors[account].config.evidence_keys) == running


# Independence between rings, asked of the key HMAC uses.


def _connector(tenant, key: bytes, *, provider="mock_crowdstrike") -> MockConnector:
    return MockConnector(
        ConnectionConfig(
            tenant,
            uuid4(),
            "http://127.0.0.1:8101",
            secrets.token_urlsafe(32),
            secrets.token_urlsafe(32),
            {"journal-v1": key},
            5.0,
            provider=provider,
        )
    )


def test_independence_between_rings_is_asked_of_the_key_hmac_uses(db, gate_world):
    """Every ring is an HMAC-SHA256 ring, so a key and the same key with a zero byte appended,
    or a long key and its SHA-256, are one key: each rule that keeps two rings apart refuses
    such a pair, as it refuses the same bytes twice, and accepts two keys that differ."""
    world = gate_world
    tenant, account = world["identity"].tenant_id, world["account"]
    key = secrets.token_bytes(32)
    padded = key + b"\x00"
    opened: list[MockConnector] = []

    def connector(written, **kwargs):
        built = _connector(tenant, written, **kwargs)
        opened.append(built)
        return built

    try:
        # Two provider families (`_independent`).
        with pytest.raises(ValueError, match="independent credentials and keys"):
            Runtime(db, [connector(key), connector(padded, provider="mock_entra")])
        # A continuation key and a connector's evidence key (`_independent`).
        with pytest.raises(ValueError, match="Continuation keys"):
            Runtime(db, [connector(padded)], keys=TokenKeys("k", {"k": key}))
        # A Gate account's journal key and a connector's (`_journal_independent`).
        with pytest.raises(ValueError, match="journal keys must be independent"):
            Runtime(
                db,
                [connector(padded)],
                checkpoint_providers=[
                    CheckpointProvider(tenant, account, "mock_crowdstrike", {JOURNAL_KEY_ID: key})
                ],
            )
        # A sample key longer than the block and a connector key that is its SHA-256
        # (`_samples_independent`).
        long = secrets.token_bytes(100)
        with pytest.raises(ValueError, match="Sample keys must be independent"):
            Runtime(
                db,
                [connector(hashlib.sha256(long).digest())],
                sample_providers=[
                    SampleProvider("mock_crowdstrike", "http://127.0.0.1:8102", long)
                ],
            )
        # Keys that differ are independent.
        Runtime(
            db,
            [connector(key), connector(secrets.token_bytes(32), provider="mock_entra")],
            keys=TokenKeys("k", {"k": secrets.token_bytes(32)}),
            checkpoint_providers=[
                CheckpointProvider(
                    tenant, account, "mock_crowdstrike", {JOURNAL_KEY_ID: secrets.token_bytes(32)}
                )
            ],
            sample_providers=[
                SampleProvider("mock_crowdstrike", "http://127.0.0.1:8102", secrets.token_bytes(32))
            ],
        )
    finally:
        for built in opened:
            built.close()
