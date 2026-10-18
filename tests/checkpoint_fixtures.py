# SPDX-License-Identifier: AGPL-3.0-only
"""A Gate world: an externally executed mapping, a registered executor key and readers.

Every helper provisions through the path an administrator would use, and every checkpoint
request is admitted with no connector configured for that account, which is the Gate
placement `docs/CHECKPOINT.md` describes: the executor holds the vendor credential and
ExecBound dispatches nothing. Nothing here selects Gate from a request; the mapping is
bundle content.
"""

import base64
import hashlib
import json
from datetime import timedelta
from types import SimpleNamespace
from uuid import uuid4

import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from scope_fixtures import owner as owner
from sqlalchemy import text
from test_execution import activate, provision_credential, provision_identity, targets
from test_resolution import request

from execbound import administration
from execbound.execution import admit, report_outcome, store
from execbound.execution.models import NO_PRECONDITIONS
from execbound.identity import authenticate
from execbound.policy.models import MappingRef
from execbound.provider.checkpoint_evidence import CheckpointProvider
from execbound.provider.executor import ExecutorRecord, sign_outcome
from execbound.provider.models import (
    JournalRecord,
    ProviderAccount,
    ProviderCommand,
    provider_command,
    sign_record,
)
from execbound.runtime import Runtime, attestable_ring, checkpoint_verifier_for, executor_verifier

GATE_KEY_ID = "executor-v1"
# What the runtime offers admission when no connector is configured for the tenant.
NO_CONNECTOR = frozenset()
# The provider binding the world's isolation operation resolves to: the key a precondition
# class is declared against, and the tuple every grant for this world names.
CONTAIN = ("mock_crowdstrike", "contain")


def executor_public_key():
    """A genuine Ed25519 public key; the executor keeps the private half, and so do we."""
    return Ed25519PrivateKey.generate().public_key().public_bytes_raw().hex()


def register_keypair(owner_engine, world, key_id=GATE_KEY_ID):
    """Register one executor key and keep the private half the executor would hold.

    ExecBound stores only the public key, so a scenario that must produce an attested
    report has to generate the pair itself and sign with it, exactly as the external
    executor does.
    """
    private_key = Ed25519PrivateKey.generate()
    administration.register_executor_key(
        owner_engine,
        world["identity"].tenant_id,
        key_id,
        private_key.public_key().public_bytes_raw().hex(),
        world["admin"].principal_id,
        # The world's clock, so a scenario that revokes a key at an instant it chose is
        # never refused by the column's own "revoked at or after created" rule.
        now=world["clock"].now(),
    )
    return private_key


def register_key(owner_engine, world, key_id=GATE_KEY_ID):
    register_keypair(owner_engine, world, key_id)


def gate_bundle(db, world, *, external_executor=True, approval_policies="", **changes):
    """Activate a copy of the world's bundle whose mapping is (or is not) externally executed.

    The approval policy is emptied by default so the decision is ELIGIBLE: the approval
    branch of a checkpoint is unchanged from the agent path and belongs to its own
    scenario, which passes the world's own policy back in to reach it.
    """
    reference = world["bundle"].mappings[0]
    mapping = MappingRef(
        operation_ref=reference.operation_ref,
        account_id=reference.account_id,
        mapping_version=reference.mapping_version,
        schema_version=reference.schema_version,
        context_contract_version=reference.context_contract_version,
        external_executor=external_executor,
    )
    return activate(db, world, mappings=(mapping,), approval_policies=approval_policies, **changes)


@pytest.fixture
def gate_world(db, world, owner):
    """The world's isolation operation, externally executed, with one registered key.

    ``executor_key`` is the private half of that key: the world's external executor,
    ready to sign the attested reports of the outcome route.
    """
    world["executor_key"] = register_keypair(owner, world)
    gate_bundle(db, world)
    return world


def again(action):
    """The same target and context under a new idempotency key: a decision, not a retry.

    A retry is answered from the execution it already has, and a fresh key on an intent
    with nothing pending is a new request that meets the canonical claim like any other.
    """
    return action.model_copy(update={"idempotency_key": str(uuid4())})


def connected_account(world):
    """What the runtime offers admission when the world's account does have a connector."""
    return frozenset({(world["account"], "mock_crowdstrike")})


def checkpoint(
    db,
    world,
    identity=None,
    *,
    accounts=NO_CONNECTOR,
    action=None,
    preconditions=NO_PRECONDITIONS,
    **changes,
):
    """One checkpoint request, admitted as the runtime admits one: no connector available.

    ``action`` is a prepared request and ``changes`` are the fields one is built from, so
    passing both would silently drop the changes; a scenario that means to vary a prepared
    request builds it with ``request`` itself.

    ``preconditions`` is the deployment configuration the runtime holds; the default is a
    deployment that has declared nothing, which is what every scenario about something
    else should see.

    The key ring check is the runtime's own, for the same reason the verifier factory of
    ``report`` is: admission asks the composition boundary whether the tenant's ring could
    attest the grant it is about to issue, and a scenario must not get to answer that for
    it.
    """
    if action is not None and changes:
        raise TypeError("Pass a prepared action or the changes that build one, not both")
    return admit(
        db,
        identity or world["identity"],
        action if action is not None else request(world, **changes),
        world["clock"],
        available_accounts=accounts,
        preconditions=preconditions,
        attestable=attestable_ring,
    )


def gate_runtime(db, world, *, keys=None, preconditions=NO_PRECONDITIONS, checkpoint_providers=()):
    """The runtime a Gate deployment runs: no connector configured for any account.

    Indexing the connector table for one of these executions raises rather than
    dispatches, which is what makes the runtime's checkpoint branch provable rather than
    merely asserted.
    """
    return Runtime(
        db,
        [],
        clock=world["clock"],
        keys=keys,
        preconditions=preconditions,
        checkpoint_providers=checkpoint_providers,
    )


def frozen_plan(db, world, execution_id):
    """The plan the execution was frozen under, as the grant's version must match."""
    tenant = world["identity"].tenant_id
    with db.transaction(tenant) as conn:
        return store.frozen(store.read(conn, tenant, execution_id))


def long_lived_agent(admin_engine, db, world, *, lifetime=timedelta(days=2)):
    """An AGENT of the world's tenant whose credential outlives the whole report window."""
    return provision_identity(
        admin_engine, db, world["identity"].tenant_id, "AGENT", world["clock"].now(), lifetime
    )


def long_lived_admin(admin_engine, db, world, *, lifetime=timedelta(days=2)):
    """An ADMIN of the world's tenant whose credential outlives the whole report window.

    The world's own administrator lives two hours, which is less than a grant's report
    window, so a scenario that runs the sweep after the window closed needs an
    administrator whose authority is still current when the run reads the row.
    """
    return provision_identity(
        admin_engine, db, world["identity"].tenant_id, "ADMIN", world["clock"].now(), lifetime
    )


def second_credential(admin_engine, db, world, *, lifetime=timedelta(hours=2)):
    """Another live credential of the SAME principal, as a redeployed story would hold.

    The principal is what an execution key, a pending intent and a grant are all scoped to,
    so this is the identity that reaches an existing grant's retry route without being the
    credential that was answered with the secret.
    """
    identity = world["identity"]
    with admin_engine.begin() as conn:
        token = provision_credential(
            conn, identity.tenant_id, identity.principal_id, world["clock"].now(), lifetime
        )
    return authenticate(db, token)


def force_state(db, world, execution_id, state):
    """Move a grant to a state by the kernel's own state machine and nothing else.

    Two states are asked for. INDETERMINATE without a report is the shape the report-window
    sweep leaves. EXECUTED is a settled state with no settlement behind it, which is what
    makes it useful and what makes it synthetic: only `_settle` writes `result` and
    `settlement_tier`, so a forced row has neither, and a report against it restates nothing
    and is refused for that rather than for contradicting a settled outcome. A test that
    means a real settlement reports one.

    Nothing else about the row is touched: the impact stays UNRESOLVED and the claim stays
    held, which is exactly the state an asserted non-execution and an unreported sweep
    both leave behind.
    """
    tenant = world["identity"].tenant_id
    with db.transaction(tenant) as conn:
        row = store.read(conn, tenant, execution_id)
        store.transition(conn, row, world["identity"].principal_id, state, world["clock"])


def scoped(conn, tenant):
    # Limits nothing on an `admin_engine` connection, whose owner bypasses row security
    # (see tenant_fence).
    conn.execute(text("SELECT set_config('execbound.tenant_id', :t, true)"), {"t": str(tenant)})


def grant_row(engine, tenant, execution_id):
    """The stored execution: every column a grant writes, and every one its settlement does."""
    with engine.begin() as conn:
        scoped(conn, tenant)
        return dict(
            conn.execute(
                text(
                    "SELECT state, owner_hash, created_at, dispatch_attempted_at, "
                    "report_expires_at, settlement_tier, result, operation_id "
                    "FROM execbound.executions WHERE tenant_id=:t AND execution_id=:e"
                ),
                {"t": tenant, "e": execution_id},
            )
            .mappings()
            .one()
        )


def execution_states(engine, tenant):
    """Every execution the tenant retains, oldest first; a refusal must leave none."""
    with engine.begin() as conn:
        scoped(conn, tenant)
        return [
            row
            for row in conn.execute(
                text(
                    "SELECT state FROM execbound.executions WHERE tenant_id=:t "
                    "ORDER BY created_at, execution_id"
                ),
                {"t": tenant},
            ).scalars()
        ]


def impact_rows(engine, tenant):
    with engine.begin() as conn:
        scoped(conn, tenant)
        return [
            dict(row)
            for row in conn.execute(
                text(
                    "SELECT execution_id, state, approved, confirmed_at "
                    "FROM execbound.execution_impact "
                    "WHERE tenant_id=:t ORDER BY created_at, execution_id"
                ),
                {"t": tenant},
            ).mappings()
        ]


def retained(engine, tenant, execution_id):
    """What one execution retains once a report has been weighed: state, tier, impact, claim.

    Filtered to the execution rather than read for the tenant, so what it answers is a
    property of that grant and not of a tenant that happens to hold only one.
    """
    row = grant_row(engine, tenant, execution_id)
    (impact,) = [
        item for item in impact_rows(engine, tenant) if item["execution_id"] == execution_id
    ]
    (claim,) = [item for item in claim_rows(engine, tenant) if item["execution_id"] == execution_id]
    return SimpleNamespace(
        state=row["state"],
        tier=row["settlement_tier"],
        result=row["result"],
        impact=impact["state"],
        confirmed_at=impact["confirmed_at"],
        released_at=claim["released_at"],
    )


def claim_rows(engine, tenant):
    with engine.begin() as conn:
        scoped(conn, tenant)
        return [
            dict(row)
            for row in conn.execute(
                text(
                    "SELECT execution_id, released_at FROM execbound.resource_claims "
                    "WHERE tenant_id=:t ORDER BY execution_id"
                ),
                {"t": tenant},
            ).mappings()
        ]


def move_resource_version(engine, tenant, version):
    """Change the live version of the tenant's resources, as the vendor's own console would.

    A grant hands the executor the version the plan froze and never a live read, so a test
    that moves this is what tells a hardcoded fixture version from a frozen one.
    """
    with engine.begin() as conn:
        scoped(conn, tenant)
        conn.execute(
            text("UPDATE execbound.resources SET version=:v WHERE tenant_id=:t"),
            {"v": version, "t": tenant},
        )


def clear_attempt(engine, tenant, execution_id):
    """Drop the attempt stamp over the owner connection; the runtime holds no such grant."""
    with engine.begin() as conn:
        scoped(conn, tenant)
        conn.execute(
            text(
                "UPDATE execbound.executions SET dispatch_attempted_at=NULL "
                "WHERE tenant_id=:t AND execution_id=:e"
            ),
            {"t": tenant, "e": execution_id},
        )


def set_report_window(engine, tenant, execution_id, value):
    """Write the checkpoint marker over the owner connection, as no runtime statement can.

    The column is written once, at the insert, and the runtime holds no UPDATE privilege
    on it, so this is the only way to make the row's marker and the frozen mapping it was
    written under disagree — which is what tells one of the outcome route's two checkpoint
    guards from the other.
    """
    with engine.begin() as conn:
        scoped(conn, tenant)
        conn.execute(
            text(
                "UPDATE execbound.executions SET report_expires_at=:v "
                "WHERE tenant_id=:t AND execution_id=:e"
            ),
            {"v": value, "t": tenant, "e": execution_id},
        )


def set_settlement_tier(engine, tenant, execution_id, value):
    """Write the tier column alone, over the owner connection, leaving the state where it is.

    No kernel path writes this shape: `_settle` writes the tier and a settled state in one
    transaction, so a tier beside an unsettled state exists only here. It is what tells the
    page's pairing of the tier with a state from a check the tier alone would pass, and the
    runtime holds UPDATE on the column, so a future settlement that wrote one without the
    other would reach every reader that trusted the tier by itself.
    """
    with engine.begin() as conn:
        scoped(conn, tenant)
        conn.execute(
            text(
                "UPDATE execbound.executions SET settlement_tier=:v "
                "WHERE tenant_id=:t AND execution_id=:e"
            ),
            {"v": value, "t": tenant, "e": execution_id},
        )


def frozen_command(db, world, execution_id):
    """The frozen command the executor's record must bind: operation, account, both hashes."""
    tenant = world["identity"].tenant_id
    with db.transaction(tenant) as conn:
        return store.command(store.read(conn, tenant, execution_id))


def signed_record(db, world, execution_id, *, private_key=None, key_id=GATE_KEY_ID, **changes):
    """One executor-signed outcome record, as the wire carries it.

    The four bound fields come from the frozen command, so a record is about the operation
    it names by default and a scenario that means to break a binding says which one.
    """
    command = frozen_command(db, world, execution_id)
    fields = {
        "operation_id": command.operation_id,
        "account_id": command.frozen.intent.account_id,
        "intent_hash": command.intent_hash,
        "plan_hash": command.plan_hash,
        "outcome": "EXECUTED",
        "reason": "EXECUTED",
        "reported_at": world["clock"].now(),
    }
    record = ExecutorRecord(**{**fields, **changes})
    signed = sign_outcome(record, key_id, private_key or world["executor_key"])
    return signed.model_dump(mode="json")


def report_body(world, secret, *, record=None, attestation=None, journal=None, **changes):
    """The outcome report an executor sends: a terminal execution unless a scenario says else.

    A reported time accompanies exactly a report with no evidence, because a signed
    report's time is inside the bytes that were signed.
    """
    body = {"report_secret": secret, "outcome": "EXECUTED", "reason": "EXECUTED"}
    evidence = {"record": record, "attestation": attestation, "journal": journal}
    signed = {key: value for key, value in evidence.items() if value is not None}
    if not signed:
        body["reported_at"] = world["clock"].now().isoformat()
    body.update(signed)
    return {**body, **changes}


def report(
    db,
    world,
    execution_id,
    secret=None,
    identity=None,
    *,
    body=None,
    verifier_for=executor_verifier,
    **changes,
):
    """One outcome report delivered to the kernel exactly as the runtime delivers one.

    The verifier factory is the runtime's own, so a test never chooses the key ring or the
    grant instant that decides which revoked keys still speak for this grant. A scenario
    whose deployment holds a journal key passes the factory that deployment builds, which
    is `journal_verifier` below.
    """
    payload = report_body(world, secret, **changes) if body is None else body
    return report_outcome(
        db,
        identity or world["identity"],
        execution_id,
        json.dumps(payload).encode(),
        verifier_for=verifier_for,
        clock=world["clock"],
    )


def settled_gate_world(db, world, admin_engine):
    """One tenant holding an attested settlement, an asserted one and an unreported grant.

    The three rows `docs/CHECKPOINT.md` distinguishes under "What each report settles",
    produced by the routes that produce them rather than forced: an executor-signed record,
    the executor's bare word, and a grant nobody reported.
    """
    first, second, third = targets(admin_engine, world, count=3)
    attested = checkpoint(db, world, action=first).view
    assert attested.checkpoint is not None
    assert (
        report(
            db,
            world,
            attested.execution_id,
            attested.checkpoint.report_secret,
            record=signed_record(db, world, attested.execution_id),
        ).state
        == "EXECUTED"
    )
    asserted = checkpoint(db, world, action=second).view
    assert asserted.checkpoint is not None
    assert (
        report(db, world, asserted.execution_id, asserted.checkpoint.report_secret).state
        == "EXECUTED"
    )
    unreported = checkpoint(db, world, action=third).view
    assert unreported.checkpoint is not None
    tenant = world["identity"].tenant_id
    assert [
        retained(admin_engine, tenant, row.execution_id).tier
        for row in (attested, asserted, unreported)
    ] == [
        "ATTESTED",
        "ASSERTED",
        None,
    ]
    return SimpleNamespace(
        attested=attested.execution_id,
        asserted=asserted.execution_id,
        unreported=unreported.execution_id,
    )


def audit_kinds(engine, tenant):
    """Every audit payload the tenant retains, with its kind, oldest first."""
    with engine.begin() as conn:
        scoped(conn, tenant)
        return [
            (row["kind"], row["payload"])
            for row in conn.execute(
                text(
                    "SELECT kind, payload FROM execbound.audit_events "
                    "WHERE tenant_id=:t ORDER BY sequence"
                ),
                {"t": tenant},
            ).mappings()
        ]


def secret_digest(secret):
    return hashlib.sha256(secret.encode()).hexdigest()


TINES_KEY_ID = "tines-v1"


def register_es256(owner_engine, world, key_id=TINES_KEY_ID):
    """Register an ES256 executor key and keep its private half, as Tines would hold it."""
    private_key = ec.generate_private_key(ec.SECP256R1())
    administration.register_executor_key(
        owner_engine,
        world["identity"].tenant_id,
        key_id,
        private_key.public_key()
        .public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)
        .decode(),
        world["admin"].principal_id,
        algorithm="ES256",
        now=world["clock"].now(),
    )
    return private_key


def _b64(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def jws(private_key, header, claims, *, signature=None):
    """A compact JWS exactly as JWT_SIGN emits one: two JSON segments and a raw r||s."""
    head = _b64(json.dumps(header, separators=(",", ":")).encode())
    body = _b64(json.dumps(claims, separators=(",", ":")).encode())
    if signature is None:
        r, s = decode_dss_signature(
            private_key.sign(f"{head}.{body}".encode(), ec.ECDSA(hashes.SHA256()))
        )
        signature = r.to_bytes(32, "big") + s.to_bytes(32, "big")
    return f"{head}.{body}.{_b64(signature)}"


def attestation_claims(db, world, execution_id, **changes):
    """The claims an executor signs: domain, version and the record, bound to this grant."""
    command = frozen_command(db, world, execution_id)
    claims = {
        "domain": "execbound.executor.outcome",
        "version": 1,
        "operation_id": str(command.operation_id),
        "account_id": str(command.frozen.intent.account_id),
        "intent_hash": command.intent_hash,
        "plan_hash": command.plan_hash,
        "outcome": "EXECUTED",
        "reason": "EXECUTED",
        "reported_at": world["clock"].now().isoformat(),
    }
    return {**claims, **changes}


JOURNAL_KEY_ID = "gate-journal-v1"
JOURNAL_KEY = b"gate-journal-key-for-tests-only-32bytes"


def journal_provider(world, key=JOURNAL_KEY, key_id=JOURNAL_KEY_ID):
    """The deployment's journal key for the world's Gate account."""
    return CheckpointProvider(
        world["identity"].tenant_id, world["account"], "mock_crowdstrike", {key_id: key}
    )


def journal_verifier(world):
    return checkpoint_verifier_for(
        {(world["identity"].tenant_id, world["account"]): journal_provider(world)}
    )


def gate_journal(
    db,
    world,
    execution_id,
    *,
    outcome="EXECUTED",
    key=JOURNAL_KEY,
    key_id=JOURNAL_KEY_ID,
    occurred_at=None,
    **command_changes,
):
    """A journal the provider signed for this execution's frozen command, as the mock signs one."""
    command = provider_command(frozen_command(db, world, execution_id))
    if command_changes:
        # Through the JSON path, as the wire carries it: the strict model takes a UUID
        # instance from Python and its string spelling only from JSON.
        command = ProviderCommand.model_validate_json(
            json.dumps({**command.model_dump(mode="json"), **command_changes})
        )
    changed = outcome in {"EXECUTED", "VERSION_MISMATCH"}
    record = JournalRecord(
        command=command,
        command_hash=command.command_hash,
        outcome=outcome,
        occurred_at=occurred_at or world["clock"].now(),
        resulting_version="result-v2" if changed else None,
        mutation_count=1 if outcome == "EXECUTED" else 0,
    )
    account = ProviderAccount(
        command.tenant_id, command.account_id, "a" * 64, "b" * 64, key, key_id=key_id
    )
    return sign_record(record, account).model_dump(mode="json")
