# SPDX-License-Identifier: AGPL-3.0-only
"""Durable authority and race tests against the guarded PostgreSQL database."""

import json
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta
from threading import Barrier, Event
from uuid import uuid4

import pytest
from space_fixtures import seat_in_default
from sqlalchemy import event, text
from test_resolution import registry as registry
from test_resolution import request

from execbound.execution import (
    admit,
    decide_approval,
    get_execution,
    mark_indeterminate,
    reconcile,
    record_outcome,
    store,
    take_dispatch,
)
from execbound.execution.models import (
    DispatchTicket,
    ExecutionError,
    PreconditionConfig,
    TerminalEvidence,
    transition_allowed,
)
from execbound.identity import authenticate, new_token
from execbound.policy.models import LimitRule, LimitSelector, MappingRef
from execbound.policy.rulesets import Rule, ruleset_bundle
from execbound.policy.store import activate_bundle, create_bundle, validate_bundle
from execbound.resolution import issue_run
from execbound.resolution.models import scalar_facts
from execbound_harness.demo import ENDPOINT_RULESET, endpoint_bundle, fact


def provision_credential(conn, tenant, principal, now, lifetime):
    """One live credential for an existing principal; returns its bearer token."""
    credential = uuid4()
    token, digest = new_token(tenant, credential)
    conn.execute(
        text(
            "INSERT INTO execbound.credentials "
            "(tenant_id,principal_id,credential_id,token_hash,issued_at,expires_at) "
            "VALUES (:t,:p,:c,:h,:n,:e)"
        ),
        {
            "t": tenant,
            "p": principal,
            "c": credential,
            "h": digest,
            "n": now,
            "e": now + lifetime,
        },
    )
    return token


def provision_identity(engine, db, tenant, kind, now, lifetime=timedelta(hours=2)):
    principal = uuid4()
    with engine.begin() as conn:
        conn.execute(
            text(
                "INSERT INTO execbound.principals(tenant_id,principal_id,kind,space_id) "
                "VALUES (:t,:p,:k, CASE WHEN :k = 'AGENT' THEN "
                "(SELECT space_id FROM execbound.spaces WHERE tenant_id = :t) END)"
            ),
            {"t": tenant, "p": principal, "k": kind},
        )
        if kind == "HUMAN_APPROVER":
            # `admin_create_principal` seats an approver itself; a fixture that inserts
            # the row directly has to, because membership is the authority for a read.
            seat_in_default(conn, tenant, principal)
        token = provision_credential(conn, tenant, principal, now, lifetime)
    return authenticate(db, token)


@pytest.fixture
def world(registry, db, admin_engine):
    registry["clock"].value = datetime.now(UTC)
    now = registry["clock"].now()
    tenant = registry["identity"].tenant_id
    admin = provision_identity(admin_engine, db, tenant, "ADMIN", now)
    human = provision_identity(admin_engine, db, tenant, "HUMAN_APPROVER", now)
    canonical = uuid4()
    with admin_engine.begin() as conn:
        conn.execute(
            text(
                "INSERT INTO execbound.canonical_targets "
                "(tenant_id,canonical_target_id,created_at) VALUES (:t,:c,:n)"
            ),
            {"t": tenant, "c": canonical, "n": now},
        )
        conn.execute(
            text(
                "INSERT INTO execbound.resource_identities "
                "(tenant_id,account_id,provider,resource_type,resource_id,canonical_target_id) "
                "VALUES (:t,:a,'mock_crowdstrike','endpoint',:r,:c)"
            ),
            {"t": tenant, "a": registry["account"], "r": registry["target"], "c": canonical},
        )
        conn.execute(
            text(
                "INSERT INTO execbound.approval_scopes "
                "(tenant_id,approver_id,canonical_target_id,action, space_id) "
                "VALUES (:t,:p,:c,'endpoint.isolate', "
                "(SELECT space_id FROM execbound.spaces WHERE tenant_id = :t))"
            ),
            {"t": tenant, "p": human.principal_id, "c": canonical},
        )
    bundle = endpoint_bundle(tenant, registry["account"], mapping_version="map-v1")
    create_bundle(db, admin, bundle, registry["clock"])
    validate_bundle(db, admin, bundle.bundle_id, registry["clock"])
    activate_bundle(db, admin, bundle.bundle_id, registry["clock"])
    return {**registry, "admin": admin, "human": human, "canonical": canonical, "bundle": bundle}


def test_pending_reuses_frozen_plan_then_commits_once(db, world):
    first = admit(db, world["identity"], request(world), world["clock"])
    assert first.view.state == "PENDING_APPROVAL"
    assert first.ticket is None
    retry = admit(
        db,
        world["identity"],
        request(
            world,
            idempotency_key="second",
            target={"kind": "canonical", "value": str(world["target"])},
        ),
        world["clock"],
    )
    assert retry.view == first.view
    decide_approval(db, world["human"], first.view.approval_id, "APPROVE", world["clock"])
    committed = admit(db, world["identity"], request(world), world["clock"])
    assert committed.view.state == "DISPATCH_COMMITTED"
    assert committed.ticket is not None
    assert admit(db, world["identity"], request(world), world["clock"]).ticket is None
    command = take_dispatch(db, committed.ticket, world["clock"])
    assert command.plan_hash == first.view.plan_hash
    with pytest.raises(ExecutionError):
        take_dispatch(db, committed.ticket, world["clock"])


@pytest.mark.parametrize(
    "before,after",
    [
        ("EXECUTED", "DISPATCH_COMMITTED"),
        ("INDETERMINATE", "RESERVED"),
        ("DENIED", "PENDING_APPROVAL"),
        ("DISPATCH_COMMITTED", "DENIED"),
    ],
)
def test_no_terminal_reopening_or_uncertain_refill(before, after):
    assert not transition_allowed(before, after)


def activate(db, world, **changes):
    bundle = world["bundle"].model_copy(update={"bundle_id": uuid4(), **changes})
    create_bundle(db, world["admin"], bundle, world["clock"])
    validate_bundle(db, world["admin"], bundle.bundle_id, world["clock"])
    activate_bundle(db, world["admin"], bundle.bundle_id, world["clock"])
    world["bundle"] = bundle
    return bundle


def targets(engine, world, count=25, *, production=False):
    tenant = world["identity"].tenant_id
    requests = []
    with engine.begin() as conn:
        for _ in range(count):
            resource, incident, canonical = uuid4(), uuid4(), uuid4()
            p = {
                "t": tenant,
                "a": world["account"],
                "r": resource,
                "i": incident,
                "c": canonical,
                "s": world["inventory"],
                "z": world["incident_source"],
                "p": world["human"].principal_id,
                "n": world["clock"].now(),
                "environment": "production" if production else "development",
            }
            conn.execute(text("INSERT INTO execbound.canonical_targets VALUES (:t,:c,:n)"), p)
            conn.execute(
                text(
                    "INSERT INTO execbound.resources "
                    "(tenant_id,account_id,provider,resource_type,resource_id,provider_id,"
                    "version,source_id,role,environment,criticality,observed_at) "
                    "VALUES (:t,:a,'mock_crowdstrike','endpoint',:r,CAST(:r AS text),"
                    "'v1',:s,'workstation',:environment,2,:n)"
                ),
                p,
            )
            conn.execute(
                text(
                    "INSERT INTO execbound.resource_identities "
                    "VALUES (:t,:a,'mock_crowdstrike','endpoint',:r,:c)"
                ),
                p,
            )
            conn.execute(
                text(
                    "INSERT INTO execbound.incidents "
                    "(tenant_id,account_id,provider,resource_type,incident_id,resource_id,"
                    "source_id,version,status,severity,observed_at) "
                    "VALUES (:t,:a,'mock_crowdstrike','endpoint',:i,:r,:z,'v1',"
                    "'OPEN','CRITICAL',:n)"
                ),
                p,
            )
            conn.execute(
                text(
                    "INSERT INTO execbound.approval_scopes "
                    "(tenant_id,approver_id,canonical_target_id,action, space_id) "
                    "VALUES (:t,:p,:c,'endpoint.isolate', "
                    "(SELECT space_id FROM execbound.spaces WHERE tenant_id = :t))"
                ),
                p,
            )
            requests.append(
                request(
                    world,
                    target={"kind": "canonical", "value": str(resource)},
                    claimed_context={"incident_id": str(incident)},
                    idempotency_key=str(uuid4()),
                )
            )
    return requests


def counts(engine, tenant):
    with engine.connect() as conn:
        return {
            table: conn.execute(
                text(f"SELECT count(*) FROM execbound.{table} WHERE tenant_id=:t"), {"t": tenant}
            ).scalar_one()
            for table in (
                "executions",
                "execution_keys",
                "approvals",
                "execution_impact",
                "resource_claims",
                "execution_events",
                "audit_events",
            )
        }


class FixtureJournal:
    """Trusted test verifier only; it stands in for the authenticated provider proof a real
    connector supplies."""

    def __init__(self, outcome="EXECUTED", **changes):
        self.outcome, self.changes = outcome, changes

    def verify(self, command, evidence):
        assert evidence == b"test-journal-proof"
        return TerminalEvidence(
            operation_id=command.operation_id,
            account_id=command.frozen.intent.account_id,
            intent_hash=command.intent_hash,
            plan_hash=command.plan_hash,
            outcome=self.outcome,
            reason="EXECUTED" if self.outcome == "EXECUTED" else "CANCELLED_NOT_EXECUTED",
            proof_digest="a" * 64,
            authenticated_record="test-verifier-boundary",
        ).model_copy(update=self.changes)


def finish(db, world, admission, outcome="EXECUTED"):
    take_dispatch(db, admission.ticket, world["clock"])
    return record_outcome(
        db, admission.ticket, b"test-journal-proof", FixtureJournal(outcome), world["clock"]
    )


def admitted_plan(conn, world, admission):
    """The frozen plan of an admitted execution, read the way the kernel reads it."""
    tenant = world["identity"].tenant_id
    return store.frozen(store.read(conn, tenant, admission.view.execution_id))


def test_autonomous_ten_then_approval_and_shared_total_twenty(db, world, admin_engine):
    requests = targets(admin_engine, world)
    for req in requests[:10]:
        assert admit(db, world["identity"], req, world["clock"]).ticket is not None
    eleventh = admit(db, world["identity"], requests[10], world["clock"])
    assert eleventh.view.state == "PENDING_APPROVAL"
    decide_approval(db, world["human"], eleventh.view.approval_id, "APPROVE", world["clock"])
    approved = admit(db, world["identity"], requests[10], world["clock"])
    finish(db, world, approved)
    second = provision_identity(
        admin_engine, db, world["identity"].tenant_id, "AGENT", world["clock"].now()
    )
    for req in requests[11:20]:
        assert admit(db, second, req, world["clock"]).ticket is not None
    assert admit(db, second, requests[20], world["clock"]).view.state == "DENIED"
    with db.transaction(second.tenant_id) as conn:
        plan = admitted_plan(conn, world, approved)
        measured = store.usage(
            conn, world["identity"], world["bundle"], world["clock"], frozen=plan
        )
    assert sorted((c.confirmed_targets, c.unresolved_targets) for c in measured.counts) == [
        (0, 10),
        (1, 19),
    ]


@pytest.mark.parametrize("different_keys", [False, True])
def test_racing_first_intent_creates_one_pending_approval(db, world, admin_engine, different_keys):
    barrier = Barrier(6)

    def submit(index):
        barrier.wait(timeout=10)
        return admit(
            db,
            world["identity"],
            request(
                world,
                idempotency_key=str(index) if different_keys else "race",
                target={"kind": "canonical", "value": str(world["target"])}
                if index % 2
                else {"kind": "hostname", "value": "ws01.example"},
            ),
            world["clock"],
        )

    with ThreadPoolExecutor(max_workers=6) as pool:
        results = list(pool.map(submit, range(6)))
    assert len({r.view.execution_id for r in results}) == 1
    assert counts(admin_engine, world["identity"].tenant_id)["approvals"] == 1
    assert counts(admin_engine, world["identity"].tenant_id)["execution_impact"] == 0


def test_racing_approved_retries_issue_one_ticket(db, world, admin_engine):
    first = admit(db, world["identity"], request(world), world["clock"])
    decide_approval(db, world["human"], first.view.approval_id, "APPROVE", world["clock"])
    barrier = Barrier(6)

    def submit(index):
        barrier.wait(timeout=10)
        return admit(
            db, world["identity"], request(world, idempotency_key=f"race-{index}"), world["clock"]
        )

    with ThreadPoolExecutor(max_workers=6) as pool:
        results = list(pool.map(submit, range(6)))
    assert sum(r.ticket is not None for r in results) == 1
    assert counts(admin_engine, world["identity"].tenant_id)["execution_impact"] == 1


def test_same_key_changed_intent_conflicts_under_race(db, world, admin_engine):
    requests = targets(admin_engine, world, 2)
    barrier = Barrier(2)

    def submit(req):
        barrier.wait(timeout=10)
        try:
            return admit(
                db,
                world["identity"],
                req.model_copy(update={"idempotency_key": "shared"}),
                world["clock"],
            )
        except ExecutionError as exc:
            return exc.code

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(submit, requests))
    assert sum(r == "IDEMPOTENCY_CONFLICT" for r in results) == 1
    assert counts(admin_engine, world["identity"].tenant_id)["execution_impact"] == 1


@pytest.mark.parametrize("decision", ["APPROVE", "DENY"])
def test_human_decision_is_single_use_and_agent_cannot_decide(db, world, decision):
    first = admit(db, world["identity"], request(world), world["clock"])
    with pytest.raises(ExecutionError):
        decide_approval(db, world["identity"], first.view.approval_id, decision, world["clock"])
    decide_approval(db, world["human"], first.view.approval_id, decision, world["clock"])
    with pytest.raises(ExecutionError):
        decide_approval(db, world["human"], first.view.approval_id, decision, world["clock"])


@pytest.mark.parametrize("change", ["scope", "role", "revoke", "principal", "tenant"])
def test_approval_requires_persisted_human_scope(db, world, admin_engine, seeded, change):
    first = admit(db, world["identity"], request(world), world["clock"])
    human = world["human"]
    with admin_engine.begin() as conn:
        params = {"t": human.tenant_id, "p": human.principal_id, "c": human.credential_id}
        if change == "scope":
            conn.execute(
                text("UPDATE execbound.approval_scopes SET active=false WHERE tenant_id=:t"), params
            )
        if change == "role":
            conn.execute(
                text(
                    "UPDATE execbound.principals SET kind='AGENT', "
                    "space_id=(SELECT space_id FROM execbound.spaces WHERE tenant_id=:t) "
                    "WHERE tenant_id=:t AND principal_id=:p"
                ),
                params,
            )
        if change == "revoke":
            conn.execute(
                text(
                    "UPDATE execbound.credentials SET revoked_at=now() "
                    "WHERE tenant_id=:t AND credential_id=:c"
                ),
                params,
            )
    if change in {"principal", "tenant"}:
        human = provision_identity(
            admin_engine,
            db,
            seeded["tenants"][1] if change == "tenant" else human.tenant_id,
            "HUMAN_APPROVER",
            world["clock"].now(),
        )
    with pytest.raises(ExecutionError):
        decide_approval(db, human, first.view.approval_id, "APPROVE", world["clock"])
    assert (
        get_execution(db, world["identity"], first.view.execution_id, world["clock"]).approval_state
        == "PENDING"
    )


@pytest.mark.parametrize(
    "change", ["bundle", "context", "alias", "expired", "approver_revoke", "obligations"]
)
def test_pending_authority_changes_invalidate_approval(db, world, admin_engine, change):
    first = admit(db, world["identity"], request(world), world["clock"])
    decide_approval(db, world["human"], first.view.approval_id, "APPROVE", world["clock"])
    if change == "bundle":
        activate(db, world)
    elif change == "expired":
        world["clock"].value += timedelta(seconds=120)
    else:
        with admin_engine.begin() as conn:
            if change == "context":
                conn.execute(text("UPDATE execbound.resources SET version='v2'"))
            elif change == "alias":
                conn.execute(
                    text("UPDATE execbound.resource_aliases SET resource_id=:r"),
                    {"r": world["other"]},
                )
            elif change == "approver_revoke":
                conn.execute(
                    text(
                        "UPDATE execbound.credentials SET revoked_at=now() WHERE credential_id=:c"
                    ),
                    {"c": world["human"].credential_id},
                )
            else:
                conn.execute(
                    text(
                        "UPDATE execbound.approvals SET "
                        "obligation_ids='[\"limit:invented\"]'::jsonb"
                    )
                )
    result = admit(db, world["identity"], request(world), world["clock"])
    assert result.view.state == "STALE_AUTHORIZATION"
    assert result.ticket is None
    assert counts(admin_engine, world["identity"].tenant_id)["execution_impact"] == 0


def test_hard_denial_after_human_approval_never_consumes(db, world, admin_engine):
    first = admit(db, world["identity"], request(world), world["clock"])
    decide_approval(db, world["human"], first.view.approval_id, "APPROVE", world["clock"])
    # Real admissions fill the shared ceiling after the human decision.
    other = provision_identity(
        admin_engine, db, world["identity"].tenant_id, "AGENT", world["clock"].now()
    )
    requests = targets(admin_engine, world, 20)
    for index, req in enumerate(requests):
        identity = world["identity"] if index < 10 else other
        assert admit(db, identity, req, world["clock"]).ticket is not None
    result = admit(db, world["identity"], request(world), world["clock"])
    assert result.view.state == "DENIED" and result.view.approval_state == "INVALIDATED"


@pytest.mark.parametrize(
    "boundary", ["consume", "impact", "guard", "reserved", "owner", "committed", "final"]
)
def test_precommit_failures_roll_back_every_claim(db, world, admin_engine, monkeypatch, boundary):
    first = admit(db, world["identity"], request(world), world["clock"])
    decide_approval(db, world["human"], first.view.approval_id, "APPROVE", world["clock"])
    before = counts(admin_engine, world["identity"].tenant_id)
    patterns = {
        "consume": "UPDATE execbound.approvals SET state",
        "impact": "INSERT INTO execbound.execution_impact",
        "guard": "INSERT INTO execbound.resource_claims",
        "reserved": "UPDATE execbound.executions SET state",
        "owner": "UPDATE execbound.executions SET owner_hash",
        "committed": "UPDATE execbound.executions SET state",
    }
    hits = 0

    def fail(conn, cursor, statement, parameters, context, executemany):
        nonlocal hits
        if patterns.get(boundary, "__never__") in statement:
            hits += 1
            if boundary != "committed" or hits == 2:
                raise ValueError("synthetic failure")

    if boundary == "final":
        original = store.identity_check

        def invalid(conn, identity, clock, kind):
            if conn.execute(text("SELECT count(*) FROM execbound.execution_impact")).scalar_one():
                raise ValueError("synthetic final failure")
            original(conn, identity, clock, kind)

        monkeypatch.setattr(store, "identity_check", invalid)
    event.listen(db.engine, "after_cursor_execute", fail)
    try:
        with pytest.raises(ExecutionError):
            admit(db, world["identity"], request(world), world["clock"])
    finally:
        event.remove(db.engine, "after_cursor_execute", fail)
    after = counts(admin_engine, world["identity"].tenant_id)
    # Failed dispatch-intent events roll back; a separate rejection is retained.
    assert after == {**before, "audit_events": before["audit_events"] + 1}
    assert (
        get_execution(db, world["identity"], first.view.execution_id, world["clock"]).approval_state
        == "APPROVED"
    )


def test_approval_audit_failure_rolls_back_decision(db, world, monkeypatch):
    first = admit(db, world["identity"], request(world), world["clock"])

    def unavailable(*args, **kwargs):
        raise ValueError("synthetic audit outage")

    monkeypatch.setattr(store, "append_event", unavailable)
    with pytest.raises(ExecutionError):
        decide_approval(db, world["human"], first.view.approval_id, "APPROVE", world["clock"])
    assert (
        get_execution(db, world["identity"], first.view.execution_id, world["clock"]).approval_state
        == "PENDING"
    )


def test_confirmed_retries_retain_status_and_new_key_charges_again(db, world, admin_engine):
    req = targets(admin_engine, world, 1)[0]
    first = admit(db, world["identity"], req, world["clock"])
    finish(db, world, first)
    assert admit(db, world["identity"], req, world["clock"]).view.state == "EXECUTED"
    second = admit(
        db, world["identity"], req.model_copy(update={"idempotency_key": "repeat"}), world["clock"]
    )
    assert second.ticket is not None
    assert second.view.execution_id != first.view.execution_id
    assert counts(admin_engine, world["identity"].tenant_id)["execution_impact"] == 2
    world["clock"].value += timedelta(seconds=400)
    assert admit(db, world["identity"], req, world["clock"]).view.state == "EXECUTED"


def test_uncertainty_keeps_capacity_and_target_guard_without_resend(db, world, admin_engine):
    req = targets(admin_engine, world, 1)[0]
    first = admit(db, world["identity"], req, world["clock"])
    take_dispatch(db, first.ticket, world["clock"])
    mark_indeterminate(db, first.ticket, world["clock"])
    with pytest.raises(ExecutionError):
        take_dispatch(db, first.ticket, world["clock"])
    assert admit(db, world["identity"], req, world["clock"]).ticket is None
    other = provision_identity(
        admin_engine, db, world["identity"].tenant_id, "AGENT", world["clock"].now()
    )
    assert admit(db, other, req, world["clock"]).view.state == "DENIED"
    world["clock"].value += timedelta(days=10)
    with db.transaction(other.tenant_id) as conn:
        plan = admitted_plan(conn, world, first)
        measured = store.usage(
            conn, world["identity"], world["bundle"], world["clock"], frozen=plan
        )
    assert all(c.unresolved_targets == 1 and c.confirmed_targets == 0 for c in measured.counts)


@pytest.mark.parametrize(
    "mismatch", ["operation_id", "account_id", "plan_hash", "intent_hash", "missing"]
)
def test_uncorrelated_or_missing_evidence_never_refunds(db, world, admin_engine, mismatch):
    first = admit(db, world["identity"], targets(admin_engine, world, 1)[0], world["clock"])
    take_dispatch(db, first.ticket, world["clock"])
    verifier = FixtureJournal(
        "FAILED_NOT_EXECUTED", **{mismatch: uuid4() if mismatch.endswith("_id") else "f" * 64}
    )
    if mismatch == "missing":
        verifier.verify = lambda *args: None
    with pytest.raises(ExecutionError):
        record_outcome(db, first.ticket, b"test-journal-proof", verifier, world["clock"])
    assert (
        get_execution(db, world["identity"], first.view.execution_id, world["clock"]).state
        == "DISPATCH_COMMITTED"
    )
    with db.transaction(world["identity"].tenant_id) as conn:
        assert all(
            c.unresolved_targets == 1
            for c in store.usage(
                conn,
                world["identity"],
                world["bundle"],
                world["clock"],
                frozen=admitted_plan(conn, world, first),
            ).counts
        )


def test_terminal_nonexecution_releases_once_and_cannot_be_overwritten(db, world, admin_engine):
    req = targets(admin_engine, world, 1)[0]
    first = admit(db, world["identity"], req, world["clock"])
    finish(db, world, first, "FAILED_NOT_EXECUTED")
    repeat = record_outcome(
        db,
        first.ticket,
        b"test-journal-proof",
        FixtureJournal("FAILED_NOT_EXECUTED"),
        world["clock"],
    )
    assert repeat.state == "FAILED_NOT_EXECUTED"
    with pytest.raises(ExecutionError):
        record_outcome(
            db, first.ticket, b"test-journal-proof", FixtureJournal("EXECUTED"), world["clock"]
        )
    assert (
        admit(
            db, world["identity"], req.model_copy(update={"idempotency_key": "new"}), world["clock"]
        ).ticket
        is not None
    )


def test_crash_before_send_has_no_ticket_takeover_and_admin_requires_proof(db, world, admin_engine):
    first = admit(db, world["identity"], targets(admin_engine, world, 1)[0], world["clock"])
    forged = DispatchTicket(world["identity"].tenant_id, first.view.execution_id, "guessed")
    with pytest.raises(ExecutionError):
        take_dispatch(db, forged, world["clock"])
    with pytest.raises(ExecutionError):
        reconcile(
            db,
            world["identity"],
            first.view.execution_id,
            reason="cancel",
            evidence=b"test-journal-proof",
            verifier=FixtureJournal("FAILED_NOT_EXECUTED"),
            clock=world["clock"],
        )
    result = reconcile(
        db,
        world["admin"],
        first.view.execution_id,
        reason="verified cancellation tombstone",
        evidence=b"test-journal-proof",
        verifier=FixtureJournal("FAILED_NOT_EXECUTED"),
        clock=world["clock"],
    )
    assert result.state == "FAILED_NOT_EXECUTED"
    with pytest.raises(ExecutionError):
        take_dispatch(db, first.ticket, world["clock"])


@pytest.mark.parametrize("fill_before_decision", [False, True])
def test_approved_autonomous_contribution_is_zero_at_hard_threshold(
    db, world, admin_engine, fill_before_decision
):
    activate(
        db,
        world,
        limits=tuple(
            r.model_copy(update={"max_targets": 1, "on_exceed": "DENY"})
            if r.budget == "autonomous"
            else r
            for r in world["bundle"].limits
        ),
    )
    pending = admit(db, world["identity"], request(world), world["clock"])
    if fill_before_decision:
        assert admit(
            db, world["identity"], targets(admin_engine, world, 1)[0], world["clock"]
        ).ticket
    decide_approval(db, world["human"], pending.view.approval_id, "APPROVE", world["clock"])
    if not fill_before_decision:
        assert admit(
            db, world["identity"], targets(admin_engine, world, 1)[0], world["clock"]
        ).ticket
    assert admit(db, world["identity"], request(world), world["clock"]).ticket is not None


def test_ambiguous_alias_rejected_before_incident_filter(db, world, admin_engine):
    with admin_engine.begin() as conn:
        conn.execute(
            text(
                "INSERT INTO execbound.resource_aliases "
                "SELECT tenant_id,:alias,account_id,provider,resource_type,kind,"
                "normalized_value,:other,valid_from,expires_at "
                "FROM execbound.resource_aliases WHERE tenant_id=:t AND alias_id=:original"
            ),
            {
                "alias": uuid4(),
                "other": world["other"],
                "t": world["identity"].tenant_id,
                "original": world["alias"],
            },
        )
    with pytest.raises(ExecutionError):
        admit(db, world["identity"], request(world), world["clock"])


@pytest.mark.parametrize("lock", ["control", "audit"])
@pytest.mark.parametrize("change", ["revoke", "expire"])
def test_authority_is_rechecked_after_lock_wait(db, world, admin_engine, lock, change):
    pending = admit(db, world["identity"], request(world), world["clock"])
    decide_approval(db, world["human"], pending.view.approval_id, "APPROVE", world["clock"])
    waiting = Event()
    marker = "SELECT tenant_id FROM execbound." + (
        "tenant_policy_control" if lock == "control" else "audit_heads"
    )

    def at_wait(conn, cursor, statement, parameters, context, executemany):
        if marker in statement and "FOR UPDATE" in statement:
            waiting.set()

    event.listen(db.engine, "before_cursor_execute", at_wait)
    try:
        with ThreadPoolExecutor(max_workers=1) as pool:
            with admin_engine.begin() as owner:
                table = "tenant_policy_control" if lock == "control" else "audit_heads"
                owner.execute(
                    text(f"SELECT tenant_id FROM execbound.{table} WHERE tenant_id=:t FOR UPDATE"),
                    {"t": world["identity"].tenant_id},
                )
                future = pool.submit(admit, db, world["identity"], request(world), world["clock"])
                assert waiting.wait(5)
                if change == "revoke":
                    owner.execute(
                        text(
                            "UPDATE execbound.credentials SET revoked_at=now() "
                            "WHERE credential_id=:c"
                        ),
                        {"c": world["identity"].credential_id},
                    )
                else:
                    world["clock"].value = world["identity"].expires_at
            with pytest.raises(ExecutionError):
                future.result(timeout=10)
    finally:
        event.remove(db.engine, "before_cursor_execute", at_wait)
    assert counts(admin_engine, world["identity"].tenant_id)["execution_impact"] == 0


def test_concurrent_principals_cannot_exceed_shared_first_capacity(db, world, admin_engine):
    activate(
        db,
        world,
        limits=(
            LimitRule(
                rule_id="total",
                action="endpoint.isolate",
                scope="tenant",
                window_seconds=60,
                max_targets=1,
                budget="total",
                on_exceed="DENY",
            ),
        ),
    )
    requests = targets(admin_engine, world, 6)
    identities = [
        provision_identity(
            admin_engine, db, world["identity"].tenant_id, "AGENT", world["clock"].now()
        )
        for _ in range(6)
    ]
    barrier = Barrier(6)

    def submit(index):
        barrier.wait(timeout=10)
        return admit(db, identities[index], requests[index], world["clock"])

    with ThreadPoolExecutor(max_workers=6) as pool:
        results = list(pool.map(submit, range(6)))
    assert sum(r.ticket is not None for r in results) == 1
    assert sum(r.view.state == "DENIED" for r in results) == 5


def test_confirmed_window_is_open_at_start_and_never_double_charges(db, world, admin_engine):
    activate(
        db,
        world,
        limits=(
            LimitRule(
                rule_id="total",
                action="endpoint.isolate",
                scope="tenant",
                window_seconds=60,
                max_targets=1,
                budget="total",
                on_exceed="DENY",
            ),
        ),
    )
    requests = targets(admin_engine, world, 3)
    first = admit(db, world["identity"], requests[0], world["clock"])
    take_dispatch(db, first.ticket, world["clock"])
    for _ in range(2):
        record_outcome(db, first.ticket, b"test-journal-proof", FixtureJournal(), world["clock"])
    world["clock"].value += timedelta(seconds=59, microseconds=999999)
    assert admit(db, world["identity"], requests[1], world["clock"]).view.state == "DENIED"
    world["clock"].value += timedelta(microseconds=1)
    assert admit(db, world["identity"], requests[2], world["clock"]).ticket is not None
    with db.transaction(world["identity"].tenant_id) as conn:
        plan = admitted_plan(conn, world, first)
        measured = store.usage(
            conn, world["identity"], world["bundle"], world["clock"], frozen=plan
        )
    assert measured.counts[0].confirmed_targets == 0 and measured.counts[0].unresolved_targets == 1


def test_new_rule_and_larger_window_recompute_retained_history(db, world, admin_engine):
    requests = targets(admin_engine, world, 2)
    first = admit(db, world["identity"], requests[0], world["clock"])
    finish(db, world, first)
    world["clock"].value += timedelta(seconds=61)
    activate(
        db,
        world,
        limits=(
            LimitRule(
                rule_id="new-total",
                action="endpoint.isolate",
                scope="tenant",
                window_seconds=120,
                max_targets=1,
                budget="total",
                on_exceed="DENY",
            ),
        ),
    )
    assert admit(db, world["identity"], requests[1], world["clock"]).view.state == "DENIED"


def test_pending_new_run_and_reattestation_keep_original_expiry(db, world, admin_engine):
    first = admit(db, world["identity"], request(world), world["clock"])
    world["clock"].value += timedelta(seconds=30)
    with admin_engine.begin() as conn:
        conn.execute(
            text("UPDATE execbound.resources SET observed_at=:n WHERE tenant_id=:t"),
            {"n": world["clock"].now(), "t": world["identity"].tenant_id},
        )
        conn.execute(
            text("UPDATE execbound.incidents SET observed_at=:n WHERE tenant_id=:t"),
            {"n": world["clock"].now(), "t": world["identity"].tenant_id},
        )
    run = issue_run(db, world["identity"], world["clock"])
    retry = admit(
        db,
        world["identity"],
        request(world, idempotency_key="new-run", run_id=str(run)),
        world["clock"],
    )
    assert retry.view == first.view
    world["clock"].value += timedelta(seconds=90)
    assert (
        admit(db, world["identity"], request(world), world["clock"]).view.state
        == "STALE_AUTHORIZATION"
    )


def test_canonical_target_guard_covers_distinct_account_representations(db, world, admin_engine):
    first = admit(db, world["identity"], request(world), world["clock"])
    decide_approval(db, world["human"], first.view.approval_id, "APPROVE", world["clock"])
    assert admit(db, world["identity"], request(world), world["clock"]).ticket
    account, resource, incident = uuid4(), uuid4(), uuid4()
    p = {
        "t": world["identity"].tenant_id,
        "old": world["account"],
        "a": account,
        "r": resource,
        "i": incident,
        "canonical": world["canonical"],
    }
    with admin_engine.begin() as conn:
        conn.execute(
            text(
                "INSERT INTO execbound.connector_accounts "
                "(tenant_id, account_id, provider, active, space_id) "
                "SELECT tenant_id,:a,provider,active,space_id "
                "FROM execbound.connector_accounts "
                "WHERE tenant_id=:t AND account_id=:old"
            ),
            p,
        )
        conn.execute(
            text(
                "INSERT INTO execbound.context_sources "
                "SELECT tenant_id,:a,source_id,kind,allowed_writers,active "
                "FROM execbound.context_sources "
                "WHERE tenant_id=:t AND account_id=:old"
            ),
            p,
        )
        conn.execute(
            text(
                "INSERT INTO execbound.operation_mappings "
                "SELECT tenant_id,'alternate.isolate',:a,provider,resource_type,action,"
                "provider_operation,mapping_version,schema_version,context_contract_version,active "
                "FROM execbound.operation_mappings "
                "WHERE tenant_id=:t AND operation_ref='endpoint.isolate'"
            ),
            p,
        )
        conn.execute(
            text(
                "INSERT INTO execbound.resources "
                "SELECT tenant_id,:a,provider,resource_type,:r,'alternate-device',"
                "version,source_id,"
                "role,'development',criticality,observed_at,active FROM execbound.resources "
                "WHERE tenant_id=:t AND account_id=:old AND resource_id=:target"
            ),
            {**p, "target": world["target"]},
        )
        conn.execute(
            text(
                "INSERT INTO execbound.resource_identities "
                "VALUES (:t,:a,'mock_crowdstrike','endpoint',:r,:canonical)"
            ),
            p,
        )
        conn.execute(
            text(
                "INSERT INTO execbound.incidents "
                "SELECT tenant_id,:a,provider,resource_type,:i,:r,source_id,version,status,"
                "severity,observed_at "
                "FROM execbound.incidents WHERE tenant_id=:t AND incident_id=:incident"
            ),
            {**p, "incident": world["incident"]},
        )
    reference = (
        world["bundle"]
        .mappings[0]
        .model_copy(update={"account_id": account, "operation_ref": "alternate.isolate"})
    )
    activate(db, world, mappings=(*world["bundle"].mappings, reference))
    other = request(
        world,
        operation_ref="alternate.isolate",
        target={"kind": "canonical", "value": str(resource)},
        claimed_context={"incident_id": str(incident)},
        idempotency_key="alternate",
    )
    assert admit(db, world["identity"], other, world["clock"]).view.state == "DENIED"


def test_rules_decide_a_request_on_a_ref_that_is_not_its_actions_name(db, world, admin_engine):
    """`mapping-create --ref` names an operation; a bundle compiled from rules can serve it.

    The mapping row serves endpoint.isolate under the ref `alternate.isolate`, as the
    alternate-account test above maps it by hand. Here the bundle is the compiler's: its rules
    name the catalog action, its mapping names the ref and the action, and the kernel decides
    a request on the ref by those rules, from denial through approval to dispatch.
    """
    tenant = world["identity"].tenant_id
    with admin_engine.begin() as conn:
        conn.execute(
            text(
                "INSERT INTO execbound.operation_mappings "
                "SELECT tenant_id,'alternate.isolate',account_id,provider,resource_type,action,"
                "provider_operation,mapping_version,schema_version,context_contract_version,active "
                "FROM execbound.operation_mappings "
                "WHERE tenant_id=:t AND operation_ref='endpoint.isolate'"
            ),
            {"t": tenant},
        )
    reference = MappingRef(
        **world["bundle"].mappings[0].model_dump(exclude={"operation_ref"}),
        operation_ref="alternate.isolate",
        action="endpoint.isolate",
    )

    def select(ruleset):
        content = ruleset_bundle(
            ruleset, tenant_id=tenant, bundle_id=uuid4(), mappings=(reference,)
        )
        assert '"endpoint.isolate"' in content.cedar_schema
        assert "alternate.isolate" not in content.cedar_schema + content.authorization_policies
        create_bundle(db, world["admin"], content, world["clock"])
        validate_bundle(db, world["admin"], content.bundle_id, world["clock"])
        activate_bundle(db, world["admin"], content.bundle_id, world["clock"])

    production = Rule(
        id="isolate-never-production",
        action="endpoint.isolate",
        effect="DENY",
        when=(fact("is_production", "is", True),),
    )
    select(ENDPOINT_RULESET.model_copy(update={"rules": (*ENDPOINT_RULESET.rules, production)}))
    alternate = {"operation_ref": "alternate.isolate"}
    denied = admit(db, world["identity"], request(world, **alternate), world["clock"])
    assert denied.view.state == "DENIED"
    # The ref is what this bundle offers; the action's own name is not.
    with pytest.raises(ExecutionError):
        admit(db, world["identity"], request(world, idempotency_key="own-name"), world["clock"])
    select(ENDPOINT_RULESET)
    again = request(world, **alternate, idempotency_key="reviewed")
    pending = admit(db, world["identity"], again, world["clock"])
    assert pending.view.state == "PENDING_APPROVAL"
    with admin_engine.connect() as conn:
        plan = admitted_plan(conn, world, pending)
    assert (plan.request.operation_ref, plan.intent.action) == (
        "alternate.isolate",
        "endpoint.isolate",
    )
    decide_approval(db, world["human"], pending.view.approval_id, "APPROVE", world["clock"])
    committed = admit(db, world["identity"], again, world["clock"])
    assert committed.view.state == "DISPATCH_COMMITTED" and committed.ticket is not None


def test_scoped_rejection_audit_contains_no_caller_strings(db, world, admin_engine):
    with pytest.raises(ExecutionError):
        admit(
            db, world["identity"], request(world, operation_ref="sensitive-input"), world["clock"]
        )
    with admin_engine.connect() as conn:
        payload = conn.execute(
            text(
                "SELECT payload FROM execbound.audit_events WHERE tenant_id=:t "
                "AND kind='execution.rejected'"
            ),
            {"t": world["identity"].tenant_id},
        ).scalar_one()
    # The refusal's own code from the closed list (#545), never the caller's string.
    assert payload == {"operation": "admit", "reason": "INVALID_OPERATION"}


def test_approval_audit_retains_scope_expiry_and_deciding_credential(db, world, admin_engine):
    first = admit(db, world["identity"], request(world), world["clock"])
    decide_approval(db, world["human"], first.view.approval_id, "APPROVE", world["clock"])
    with admin_engine.connect() as conn:
        approval = conn.execute(
            text(
                "SELECT payload FROM execbound.audit_events WHERE tenant_id=:t "
                "AND kind='approval.transition' ORDER BY sequence DESC LIMIT 1"
            ),
            {"t": world["identity"].tenant_id},
        ).scalar_one()["binding"]
    assert approval["principal_id"] == str(world["identity"].principal_id)
    assert approval["decided_credential_id"] == str(world["human"].credential_id)
    assert approval["obligation_ids"] == ["policy:policy0"]
    assert datetime.fromisoformat(approval["expires_at"]) == world["clock"].now() + timedelta(
        seconds=120
    )


def latest_audit_payload(engine, tenant):
    with engine.connect() as conn:
        latest = conn.execute(
            text(
                "SELECT payload::text FROM execbound.audit_events WHERE tenant_id=:t "
                "ORDER BY sequence DESC LIMIT 1"
            ),
            {"t": tenant},
        ).scalar_one()
    return json.loads(latest)


@pytest.mark.parametrize("target", ["existing", "absent"])
def test_invalid_arguments_reject_before_the_coordinator_reads_evidence(
    db, world, admin_engine, target
):
    """An argument outside the action spec fails the same way for any target."""
    selector = (
        {"kind": "hostname", "value": "WS01.EXAMPLE."}
        if target == "existing"
        else {"kind": "canonical", "value": str(uuid4())}
    )
    with pytest.raises(ExecutionError) as failure:
        admit(
            db,
            world["identity"],
            request(world, target=selector, arguments={"reason": "other"}),
            world["clock"],
        )
    assert failure.value.code == "INVALID_REQUEST"
    assert latest_audit_payload(admin_engine, world["identity"].tenant_id) == {
        "operation": "admit",
        "reason": "INVALID_ARGUMENTS",
    }
    assert counts(admin_engine, world["identity"].tenant_id)["executions"] == 0


def retained_attributes(engine, tenant, execution_id):
    """The scope attributes one impact row retains, as stored."""
    with engine.connect() as conn:
        return (
            conn.execute(
                text(
                    "SELECT account_id, group_ids, facts FROM execbound.execution_impact "
                    "WHERE tenant_id=:t AND execution_id=:e"
                ),
                {"t": tenant, "e": execution_id},
            )
            .mappings()
            .one()
        )


def typed(facts):
    """Pair each value with its type so a JSON boolean can never pass as a number."""
    return {name: (type(value).__name__, value) for name, value in facts.items()}


def limit(**changes):
    """A total ceiling of ten on isolation, wide enough that nothing here is capped."""
    return LimitRule(
        **{
            "rule_id": "scoped",
            "action": "endpoint.isolate",
            "scope": "tenant",
            "window_seconds": 3600,
            "max_targets": 10,
            "budget": "total",
            "on_exceed": "DENY",
            **changes,
        }
    )


def test_impact_rows_retain_account_groups_and_facts(db, world, admin_engine):
    tenant = world["identity"].tenant_id
    member = provision_identity(admin_engine, db, tenant, "AGENT", world["clock"].now())
    group = uuid4()
    with admin_engine.begin() as conn:
        conn.execute(
            text(
                "INSERT INTO execbound.principal_groups (tenant_id,group_id,name,created_at) "
                "VALUES (:t,:g,'triage',:n)"
            ),
            {"t": tenant, "g": group, "n": world["clock"].now()},
        )
        conn.execute(
            text(
                "INSERT INTO execbound.principal_group_members "
                "(tenant_id,group_id,principal_id,assigned_at) VALUES (:t,:g,:p,:n)"
            ),
            {"t": tenant, "g": group, "p": member.principal_id, "n": world["clock"].now()},
        )
    first, second = targets(admin_engine, world, 2)
    outsider = admit(db, world["identity"], first, world["clock"])
    joined = admit(db, member, second, world["clock"])
    assert outsider.ticket is not None and joined.ticket is not None
    with db.transaction(tenant) as conn:
        plans = [admitted_plan(conn, world, admission) for admission in (outsider, joined)]
    expected_groups = ([], [str(group)])
    for admission, plan, groups in zip((outsider, joined), plans, expected_groups, strict=True):
        row = retained_attributes(admin_engine, tenant, admission.view.execution_id)
        assert row["account_id"] == plan.intent.account_id == world["account"]
        assert row["group_ids"] == groups
        assert typed(row["facts"]) == typed(scalar_facts(plan))
        assert set(row["facts"]) == {
            "role",
            "environment",
            "criticality",
            "is_production",
            "incident_status",
            "incident_severity",
        }
    # A group scope counts the member's row for whoever asks; the snapshot records the
    # memberships read inside the fence for the asking principal, never a caller's claim.
    grouped = world["bundle"].model_copy(update={"limits": (limit(scope="group", group_id=group),)})
    with db.transaction(tenant) as conn:
        for identity, plan, groups in zip(
            (world["identity"], member), plans, ((), (group,)), strict=True
        ):
            measured = store.usage(conn, identity, grouped, world["clock"], frozen=plan)
            assert measured.groups == groups
            assert [(c.confirmed_targets, c.unresolved_targets) for c in measured.counts] == [
                (0, 1)
            ]


def test_account_and_selector_scopes_count_retained_rows(db, world, admin_engine):
    tenant = world["identity"].tenant_id
    activate(
        db,
        world,
        limits=(
            limit(rule_id="account", scope="account", account_id=world["account"]),
            limit(
                rule_id="production",
                scope="selector",
                selector=LimitSelector(fact="environment", equals="production"),
            ),
            limit(
                rule_id="criticality",
                scope="selector",
                selector=LimitSelector(fact="criticality", equals=2),
            ),
            limit(
                rule_id="flagged",
                scope="selector",
                selector=LimitSelector(fact="is_production", equals=True),
            ),
        ),
    )
    [development] = targets(admin_engine, world, 1)
    [production] = targets(admin_engine, world, 1, production=True)
    reserved = admit(db, world["identity"], development, world["clock"])
    assert reserved.ticket is not None
    # The demo pack escalates production targets; the approved retry reserves and settles.
    escalated = admit(db, world["identity"], production, world["clock"])
    assert escalated.view.state == "PENDING_APPROVAL"
    decide_approval(db, world["human"], escalated.view.approval_id, "APPROVE", world["clock"])
    approved = admit(db, world["identity"], production, world["clock"])
    assert approved.ticket is not None
    assert finish(db, world, approved).state == "EXECUTED"
    with db.transaction(tenant) as conn:
        plan = admitted_plan(conn, world, reserved)
        measured = store.usage(
            conn, world["identity"], world["bundle"], world["clock"], frozen=plan
        )
    assert measured.account_id == world["account"] and measured.groups == ()
    # The account rule sees both rows. A selector sees only rows whose retained fact equals
    # its value with the same JSON type: the development reservation is absent from the
    # string and boolean production counts and present in the integer criticality count.
    assert {c.rule_id: (c.confirmed_targets, c.unresolved_targets) for c in measured.counts} == {
        "account": (1, 1),
        "production": (1, 0),
        "criticality": (1, 1),
        "flagged": (1, 0),
    }


def test_multi_action_budget_counts_both_actions(db, world, admin_engine):
    tenant = world["identity"].tenant_id
    activate(
        db,
        world,
        limits=(
            limit(rule_id="pair", actions=("endpoint.isolate", "endpoint.lift_isolation")),
            limit(rule_id="single"),
        ),
    )
    isolated = admit(db, world["identity"], targets(admin_engine, world, 1)[0], world["clock"])
    assert isolated.ticket is not None
    # A settled lift retained beside the reservation, copied from it with the owner engine;
    # the SOC world runs the lift itself in the acceptance scenario (SL4).
    lift, now = uuid4(), world["clock"].now()
    with admin_engine.begin() as conn:
        conn.execute(
            text("""
            INSERT INTO execbound.executions
                (tenant_id,execution_id,principal_id,credential_id,intent_hash,wire_hash,
                 plan_hash,canonical_target_id,bundle_id,frozen,state,created_at,changed_at,
                 operation_id,space_id,request_number)
            SELECT tenant_id,:lift,principal_id,credential_id,repeat('f',64),wire_hash,
                   plan_hash,canonical_target_id,bundle_id,frozen,'EXECUTED',created_at,
                   changed_at,:operation,space_id,request_number+1
            FROM execbound.executions WHERE tenant_id=:t AND execution_id=:e
            """),
            {"lift": lift, "operation": uuid4(), "t": tenant, "e": isolated.view.execution_id},
        )
        conn.execute(
            text("""
            INSERT INTO execbound.execution_impact
                (tenant_id,execution_id,principal_id,action,approved,state,confirmed_at,
                 created_at,account_id,group_ids,facts,space_id)
            SELECT tenant_id,:lift,principal_id,'endpoint.lift_isolation',approved,'CONFIRMED',
                   :now,created_at,account_id,group_ids,facts,space_id
            FROM execbound.execution_impact WHERE tenant_id=:t AND execution_id=:e
            """),
            {"lift": lift, "now": now, "t": tenant, "e": isolated.view.execution_id},
        )
    with db.transaction(tenant) as conn:
        plan = admitted_plan(conn, world, isolated)
        measured = store.usage(
            conn, world["identity"], world["bundle"], world["clock"], frozen=plan
        )
    assert {c.rule_id: (c.confirmed_targets, c.unresolved_targets) for c in measured.counts} == {
        "pair": (1, 1),
        "single": (0, 1),
    }


# The binding the world fixture's action resolves to, as checkpoint_fixtures names it.
CONTAIN = ("mock_crowdstrike", "contain")


def _recorded_class(db, tenant, execution):
    with db.transaction(tenant) as conn:
        return conn.execute(
            text(
                "SELECT precondition_class FROM execbound.executions "
                "WHERE tenant_id = :t AND execution_id = :e"
            ),
            {"t": tenant, "e": execution},
        ).scalar_one()


def test_dispatch_records_the_class_this_deployment_declared(db, world, admin_engine):
    """The class on the row is this deployment's declaration for the binding, nothing else.

    It is keyed by the frozen plan's own provider and provider operation, never by anything
    the caller sent, so no caller can dispatch under a stronger promise than the vendor
    supports by asking for one.
    """
    committed = admit(db, world["identity"], targets(admin_engine, world)[0], world["clock"])
    assert committed.ticket is not None
    take_dispatch(
        db,
        committed.ticket,
        world["clock"],
        preconditions=PreconditionConfig({CONTAIN: "CHECKED_BY_CONNECTOR"}),
    )
    assert (
        _recorded_class(db, world["identity"].tenant_id, committed.view.execution_id)
        == "CHECKED_BY_CONNECTOR"
    )


def test_an_undeclared_binding_records_the_class_that_promises_nothing(db, world, admin_engine):
    """A deployment that declared nothing has told ExecBound nothing about the vendor.

    UNAVAILABLE rather than NULL: NULL means a row written before the column existed, and
    conflating "never declared" with "predates the question" would let a reader assume the
    mock's atomic enforcement for a binding nobody ever described.
    """
    committed = admit(db, world["identity"], targets(admin_engine, world)[0], world["clock"])
    assert committed.ticket is not None
    take_dispatch(db, committed.ticket, world["clock"])
    assert (
        _recorded_class(db, world["identity"].tenant_id, committed.view.execution_id)
        == "UNAVAILABLE"
    )


def test_a_declaration_for_another_binding_does_not_reach_this_dispatch(db, world, admin_engine):
    """Keyed by binding, so a declaration about a different vendor operation is not borrowed."""
    committed = admit(db, world["identity"], targets(admin_engine, world)[0], world["clock"])
    assert committed.ticket is not None
    take_dispatch(
        db,
        committed.ticket,
        world["clock"],
        preconditions=PreconditionConfig({("mock_entra", "disable"): "ENFORCED_BY_PROVIDER"}),
    )
    assert (
        _recorded_class(db, world["identity"].tenant_id, committed.view.execution_id)
        == "UNAVAILABLE"
    )


def test_the_dispatch_attempt_event_retains_the_class_the_dispatch_carried(db, world, admin_engine):
    """The column is a mutable projection; the audit chain is what cannot be edited.

    `take_dispatch` writes the class to `executions.precondition_class`, which the runtime
    holds UPDATE on. A reader asking later what a dispatch was actually worth needs an
    answer nothing can quietly revise, and needs it to survive an export into replay, where
    the row is not available at all. So the class is retained beside the attempt it
    describes, in the event the attempt already appends.
    """
    committed = admit(db, world["identity"], targets(admin_engine, world)[0], world["clock"])
    assert committed.ticket is not None
    take_dispatch(
        db,
        committed.ticket,
        world["clock"],
        preconditions=PreconditionConfig({CONTAIN: "CHECKED_BY_CONNECTOR"}),
    )
    with admin_engine.connect() as conn:
        payload = conn.execute(
            text(
                "SELECT payload FROM execbound.audit_events WHERE tenant_id=:t "
                "AND kind='execution.dispatch_attempt' AND payload->>'execution_id'=:e"
            ),
            {"t": world["identity"].tenant_id, "e": str(committed.view.execution_id)},
        ).scalar_one()
    assert payload["precondition_class"] == "CHECKED_BY_CONNECTOR"
    # The fields the event already carried are unchanged; this adds one beside them.
    assert payload["plan_hash"] and payload["operation_id"]


def test_an_undeclared_binding_retains_the_class_that_promises_nothing(db, world, admin_engine):
    committed = admit(db, world["identity"], targets(admin_engine, world)[0], world["clock"])
    assert committed.ticket is not None
    take_dispatch(db, committed.ticket, world["clock"])
    with admin_engine.connect() as conn:
        payload = conn.execute(
            text(
                "SELECT payload FROM execbound.audit_events WHERE tenant_id=:t "
                "AND kind='execution.dispatch_attempt' AND payload->>'execution_id'=:e"
            ),
            {"t": world["identity"].tenant_id, "e": str(committed.view.execution_id)},
        ).scalar_one()
    assert payload["precondition_class"] == "UNAVAILABLE"


def test_an_operation_execbound_dispatched_settles_with_no_tier(db, world, admin_engine):
    """A tier is a statement about an external executor's word, and there is none here.

    `recovery_run` selects on settlement_tier = 'ASSERTED' to sweep grants whose report
    window closed. A native dispatch carrying a tier would enter a recovery path built for
    executors that never reported, which is why the column stays null for every dispatch
    ExecBound makes, Graph included, and the precondition class carries the distinction
    instead.
    """
    committed = admit(db, world["identity"], targets(admin_engine, world)[0], world["clock"])
    assert committed.ticket is not None
    finish(db, world, committed)
    with db.transaction(world["identity"].tenant_id) as conn:
        tier, klass = conn.execute(
            text(
                "SELECT settlement_tier, precondition_class FROM execbound.executions "
                "WHERE execution_id = :e"
            ),
            {"e": committed.view.execution_id},
        ).one()
    assert tier is None
    assert klass == "UNAVAILABLE"
