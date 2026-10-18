# SPDX-License-Identifier: AGPL-3.0-only
"""The external execution checkpoint on real PostgreSQL: a grant instead of a dispatch.

The file follows the checkpoint in order. Admission: an eligible operation whose bundle
mapping declares an external executor reserves exactly as a dispatch does and then stops
before the connector, answering with a grant the caller may act on once. The runtime's
checkpoint branch, the presenter's signed act grant, and the deployment configuration that
says what the frozen expected version is worth at the vendor the executor calls. The
authenticated outcome route and the asymmetric settlement it feeds: an attested outcome
settles exactly as a dispatch does, an asserted one never releases a canonical claim and
never refunds a reservation, and an executor's uncertainty is retained as uncertainty. The
sweep of an unreported grant, the connector-free administrator exit and the refusals that
keep a grant off the connector paths. Replay, which reads a settlement at the tier its
evidence supports rather than as a provider journal. Then the human pages, and the
acceptance scenarios.
"""

import dataclasses
import json
import re
import secrets
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta
from threading import Barrier
from types import SimpleNamespace
from uuid import UUID, uuid4

import pytest
from checkpoint_fixtures import (
    CONTAIN,
    GATE_KEY_ID,
    TINES_KEY_ID,
    again,
    attestation_claims,
    audit_kinds,
    checkpoint,
    claim_rows,
    clear_attempt,
    connected_account,
    execution_states,
    force_state,
    frozen_command,
    frozen_plan,
    gate_bundle,
    gate_journal,
    gate_runtime,
    grant_row,
    impact_rows,
    journal_provider,
    jws,
    long_lived_admin,
    long_lived_agent,
    move_resource_version,
    register_es256,
    register_key,
    register_keypair,
    report,
    report_body,
    retained,
    second_credential,
    secret_digest,
    set_report_window,
    set_settlement_tier,
    settled_gate_world,
    signed_record,
)
from checkpoint_fixtures import gate_world as gate_world
from checkpoint_fixtures import owner as owner
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi.testclient import TestClient
from markupsafe import escape
from pydantic import ValidationError
from scope_fixtures import (
    agent,
    audit_payloads,
    counted,
    group,
    impact_groups,
    rule,
    scoped_bundle,
    transition_payload,
    usage,
)
from soc_fixtures import SECOND_PROVIDER, TEST_CATALOG
from sqlalchemy import text
from test_approval_quorum import production_obligation, second_approver
from test_execution import FixtureJournal, finish, targets
from test_execution import registry as registry
from test_execution import world as world
from test_human_surface import credential, form_values
from test_resolution import request

from execbound import administration
from execbound import runtime as runtime_module
from execbound.app import create_app
from execbound.contracts import MAX_CEILING_SECONDS
from execbound.execution import (
    activate_stop,
    admit,
    decide_approval,
    mark_indeterminate,
    reconcile,
    record_outcome,
    release_stop,
    report_outcome,
    set_enforcement_mode,
    store,
    take_dispatch,
)
from execbound.execution import admission as admission
from execbound.execution import outcomes as outcomes
from execbound.execution import reconciliation as reconciliation
from execbound.execution.models import (
    ACT_WINDOW,
    MAX_GRANTS,
    NO_PRECONDITIONS,
    REPORT_WINDOW,
    AssertedOutcome,
    CheckpointBinding,
    CheckpointGrant,
    DispatchTicket,
    ExecutionError,
    PreconditionConfig,
    TerminalEvidence,
)
from execbound.execution.outcomes import ReportedOutcome
from execbound.policy.models import MappingRef, QuorumRule
from execbound.provider.gateway import reconcile_operation
from execbound.provider.models import MAX_PROVIDER_BYTES
from execbound.recovery_run import recover
from execbound.requests import Arguments
from execbound.resolution.registry import ResolutionError
from execbound.runtime import Runtime, executor_verifier
from execbound.surfaces.configuration import load_runtime
from execbound.surfaces.http import error_status
from execbound.surfaces.human import EXTERNALLY_EXECUTED, HumanConfig
from execbound.surfaces.tokens import MAX_TOKEN_TTL, TokenKeys, verify
from execbound_harness.demo import APPROVAL


def test_the_act_window_is_exactly_what_a_continuation_can_carry():
    # The act grant of the next task is a continuation token, so a longer act window
    # would be a deadline no token could express and a shorter one wastes the ceiling.
    assert ACT_WINDOW == MAX_TOKEN_TTL
    assert REPORT_WINDOW == timedelta(hours=24)


def test_a_regrant_cannot_outlive_the_report_window():
    # A retry is bounded by the frozen plan's validity alone, which is only sound while a
    # plan cannot outlive the report window: the plan's ceiling is at most
    # MAX_CEILING_SECONDS from resolution and the window is REPORT_WINDOW from the attempt
    # an instant earlier, so the plan always expires first and the window guard would be a
    # refusal no test could reach. Shorten either constant and a retry would answer with a
    # grant whose report window had already closed, so the relationship is pinned here
    # rather than left as an unstated coincidence of two equal numbers.
    assert REPORT_WINDOW >= timedelta(seconds=MAX_CEILING_SECONDS)


# A grant is validated against its own two deadlines and never against a clock, so the
# model cases are built from one fixed instant: reading datetime.now in a parametrize
# decorator evaluates it at collection time and compares it against a later one inside
# grant_fields, which is correct only while the gap stays under the act window.
GRANTED_AT = datetime(2026, 9, 16, 12, 0, tzinfo=UTC)


def grant_fields(**changes):
    operation_id = changes.get("operation_id", uuid4())
    return {
        "operation_id": operation_id,
        "provider": "mock_crowdstrike",
        "provider_operation": "contain",
        "resource_provider_id": "device-01",
        "action": "endpoint.isolate",
        "arguments": Arguments(),
        "precondition_class": "UNAVAILABLE",
        "act_expires_at": GRANTED_AT + ACT_WINDOW,
        "report_expires_at": GRANTED_AT + REPORT_WINDOW,
        "report_secret": "s" * 43,
        "binding": CheckpointBinding(
            operation_id=operation_id,
            account_id=uuid4(),
            intent_hash="a" * 64,
            plan_hash="b" * 64,
        ),
        **changes,
    }


@pytest.mark.parametrize(
    "changes",
    [
        # A class that promises nothing must not carry a version the executor could read
        # as something to check, and a class that promises something must carry one.
        {"expected_version": "resource-v1"},
        {"precondition_class": "ENFORCED_BY_PROVIDER"},
        {"precondition_class": "ASSERTED_BY_EXECUTOR"},
        # CHECKED_BY_CONNECTOR describes a read and a comparison ExecBound's own connector
        # made on the native path. A grant hands the act to somebody else's executor, so a
        # grant carrying it would have ExecBound vouching for a check it never made. The
        # class is illegal here whether or not a version accompanies it.
        {"precondition_class": "CHECKED_BY_CONNECTOR", "expected_version": "resource-v1"},
        {"precondition_class": "CHECKED_BY_CONNECTOR"},
        # An act window outliving the report window would grant an act nothing can settle.
        {"act_expires_at": GRANTED_AT + REPORT_WINDOW + ACT_WINDOW},
        # One mint per execution: a first grant carries its secret and a re-grant, which
        # describes an act already granted, carries none. Neither half may be forged.
        {"regranted": True},
        {"report_secret": None},
    ],
    ids=[
        "version-without-class",
        "enforced-without-version",
        "asserted-without-version",
        "connector-class-on-a-grant-with-a-version",
        "connector-class-on-a-grant",
        "late-act",
        "regrant-carrying-a-secret",
        "first-grant-without-a-secret",
    ],
)
def test_a_grant_states_what_its_class_supports(changes):
    with pytest.raises(ValidationError):
        CheckpointGrant(**grant_fields(**changes))


def test_a_grant_carries_a_version_for_a_checkable_class_and_a_secret_once():
    assert CheckpointGrant(**grant_fields()).expected_version is None
    assert (
        CheckpointGrant(
            **grant_fields(
                precondition_class="ENFORCED_BY_PROVIDER", expected_version="resource-v1"
            )
        ).expected_version
        == "resource-v1"
    )
    described = CheckpointGrant(**grant_fields(regranted=True, report_secret=None))
    # The absence is the type, not a sentinel a caller could mistake for a usable secret.
    assert described.report_secret is None
    assert "report_secret" not in repr(described)


def test_an_eligible_checkpoint_grants_and_reserves_without_a_ticket(db, gate_world, admin_engine):
    world = gate_world
    tenant = world["identity"].tenant_id
    now = world["clock"].now()
    granted = checkpoint(db, world)
    view = granted.view
    assert view.state == "DISPATCH_COMMITTED"
    # The runtime dispatches whenever admission answers with a ticket, so a Gate
    # admission must answer with none at all.
    assert granted.ticket is None
    grant = view.checkpoint
    assert grant is not None
    row = grant_row(admin_engine, tenant, view.execution_id)
    assert grant.operation_id == row["operation_id"]
    assert (grant.action, grant.provider, grant.provider_operation) == (
        "endpoint.isolate",
        "mock_crowdstrike",
        "contain",
    )
    assert grant.resource_provider_id == "device-01"
    assert grant.arguments.root == {}
    # This deployment declared no class for the binding, so the grant carries the class
    # that promises nothing and no version the executor could read as something to check.
    assert grant.precondition_class == "UNAVAILABLE"
    assert grant.expected_version is None
    with db.transaction(tenant) as conn:
        frozen = store.frozen(store.read(conn, tenant, view.execution_id))
    # The act window is the continuation ceiling, the frozen plan's validity and the
    # credential's expiry, whichever comes first; here the plan is the binding one.
    assert grant.act_expires_at == min(
        now + ACT_WINDOW, frozen.valid_until, world["identity"].expires_at
    )
    assert grant.act_expires_at == frozen.valid_until
    assert grant.report_expires_at == row["report_expires_at"]
    assert row["report_expires_at"] == min(now + REPORT_WINDOW, world["identity"].expires_at)
    assert row["owner_hash"] == secret_digest(grant.report_secret)
    assert row["dispatch_attempted_at"] == now
    assert row["settlement_tier"] is None
    impacts = impact_rows(admin_engine, tenant)
    assert [(item["execution_id"], item["state"], item["approved"]) for item in impacts] == [
        (view.execution_id, "UNRESOLVED", False)
    ]
    claims = claim_rows(admin_engine, tenant)
    assert [(item["execution_id"], item["released_at"]) for item in claims] == [
        (view.execution_id, None)
    ]


def test_the_report_window_is_a_day_bounded_by_the_credential(db, gate_world, admin_engine):
    world = gate_world
    tenant = world["identity"].tenant_id
    now = world["clock"].now()
    first, second = targets(admin_engine, world, count=2)
    short = checkpoint(db, world, action=first)
    assert short.view.checkpoint is not None
    assert short.view.checkpoint.report_expires_at == world["identity"].expires_at
    patient = long_lived_agent(admin_engine, db, world)
    assert patient.expires_at > now + REPORT_WINDOW
    long = checkpoint(db, world, patient, action=second)
    assert long.view.checkpoint is not None
    assert long.view.checkpoint.report_expires_at == now + REPORT_WINDOW
    assert grant_row(admin_engine, tenant, long.view.execution_id)["report_expires_at"] == (
        now + REPORT_WINDOW
    )


def test_the_dispatch_path_refuses_a_gate_execution(db, gate_world, admin_engine):
    world = gate_world
    tenant = world["identity"].tenant_id
    granted = checkpoint(db, world)
    grant = granted.view.checkpoint
    assert grant is not None
    # The report secret is the same secret a dispatch ticket carries, so the one thing it
    # must never do is open the send attempt for an operation ExecBound never dispatches.
    ticket = DispatchTicket(tenant, granted.view.execution_id, grant.report_secret)
    with pytest.raises(ExecutionError) as failure:
        take_dispatch(db, ticket, world["clock"])
    assert failure.value.code == "INVALID_STATE"
    row = grant_row(admin_engine, tenant, granted.view.execution_id)
    assert row["state"] == "DISPATCH_COMMITTED"
    assert row["owner_hash"] == secret_digest(grant.report_secret)
    # Defence in depth: even with the attempt stamp gone, which no runtime statement can
    # do, the execution carries a report window and still opens no send attempt.
    clear_attempt(admin_engine, tenant, granted.view.execution_id)
    with pytest.raises(ExecutionError) as unstamped:
        take_dispatch(db, ticket, world["clock"])
    assert unstamped.value.code == "INVALID_STATE"


def test_the_runtime_answers_a_checkpoint_without_reaching_a_connector(db, gate_world):
    world = gate_world
    # A deployment with no connector at all: indexing the connector table for this
    # execution would raise rather than dispatch, so a grant must not reach that branch.
    runtime = Runtime(db, [], clock=world["clock"])
    view = runtime.execute(world["identity"], request(world).model_dump_json().encode())
    assert view.state == "DISPATCH_COMMITTED"
    assert view.checkpoint is not None


def test_a_checkpoint_is_exempt_from_the_connector_refusal(db, world, owner, admin_engine):
    tenant = world["identity"].tenant_id
    register_key(owner, world)
    gate_bundle(db, world, external_executor=False)
    connected, external = targets(admin_engine, world, count=2)
    with pytest.raises(ExecutionError) as failure:
        checkpoint(db, world, action=external)
    assert failure.value.code == "CONNECTOR_UNAVAILABLE"
    # The ordinary path is untouched: with its connector it dispatches, holds the ticket
    # and carries no report window.
    accounts = connected_account(world)
    ordinary = checkpoint(db, world, accounts=accounts, action=connected)
    assert ordinary.ticket is not None and ordinary.view.checkpoint is None
    row = grant_row(admin_engine, tenant, ordinary.view.execution_id)
    assert row["report_expires_at"] is None and row["dispatch_attempted_at"] is None
    gate_bundle(db, world, external_executor=True)
    granted = checkpoint(db, world, action=external)
    assert granted.view.state == "DISPATCH_COMMITTED" and granted.ticket is None
    assert granted.view.checkpoint is not None


def test_the_ninth_outstanding_grant_is_refused(db, gate_world, admin_engine):
    world = gate_world
    tenant = world["identity"].tenant_id
    requests = targets(admin_engine, world, count=9)
    for action in requests[:8]:
        assert checkpoint(db, world, action=action).view.state == "DISPATCH_COMMITTED"
    with pytest.raises(ExecutionError) as failure:
        checkpoint(db, world, action=requests[8])
    assert failure.value.code == "TOO_MANY_GRANTS"
    # The ninth reserved nothing: the refusal is taken before any row is committed.
    assert len(impact_rows(admin_engine, tenant)) == 8
    assert len(claim_rows(admin_engine, tenant)) == 8
    reasons = [
        payload["reason"] for payload in audit_payloads(admin_engine, tenant, "execution.rejected")
    ]
    assert reasons == ["TOO_MANY_GRANTS"]
    # The cap bounds one principal's outstanding grants, not the tenant's.
    other = agent(admin_engine, db, world)
    assert checkpoint(db, world, other, action=requests[8]).view.state == "DISPATCH_COMMITTED"


def test_the_cap_counts_every_unsettled_grant(db, gate_world, admin_engine):
    world = gate_world
    tenant, principal = world["identity"].tenant_id, world["identity"].principal_id
    requests = targets(admin_engine, world, count=MAX_GRANTS + 2)
    granted = [
        checkpoint(db, world, action=action).view.execution_id for action in requests[:MAX_GRANTS]
    ]
    # An asserted non-execution and an unreported sweep both leave a grant INDETERMINATE
    # with its impact still UNRESOLVED and its claim still held, so it is still charging
    # every scope the cap exists to bound. Counting DISPATCH_COMMITTED alone would free a
    # slot for it and the cap would stop binding in exactly the case it was written for.
    force_state(db, world, granted[0], "INDETERMINATE")
    with db.transaction(tenant) as conn:
        assert store.outstanding_grants(conn, tenant, principal) == MAX_GRANTS
    with pytest.raises(ExecutionError) as failure:
        checkpoint(db, world, action=requests[MAX_GRANTS])
    assert failure.value.code == "TOO_MANY_GRANTS"
    charging = [item for item in impact_rows(admin_engine, tenant) if item["state"] == "UNRESOLVED"]
    assert len(charging) == MAX_GRANTS
    assert [item["released_at"] for item in claim_rows(admin_engine, tenant)] == [None] * MAX_GRANTS
    # Settling one, which is the only thing that ends a grant, frees exactly one slot.
    force_state(db, world, granted[1], "EXECUTED")
    with db.transaction(tenant) as conn:
        assert store.outstanding_grants(conn, tenant, principal) == MAX_GRANTS - 1
    freed = checkpoint(db, world, action=requests[MAX_GRANTS])
    assert freed.view.state == "DISPATCH_COMMITTED"
    with pytest.raises(ExecutionError) as full:
        checkpoint(db, world, action=requests[MAX_GRANTS + 1])
    assert full.value.code == "TOO_MANY_GRANTS"


def test_a_gate_mapping_on_a_connected_account_is_refused(db, gate_world, admin_engine):
    world = gate_world
    tenant = world["identity"].tenant_id
    first, second = targets(admin_engine, world, count=2)
    # A checkpoint account has no connection configuration: that is what makes it a
    # checkpoint, and it is the premise the precondition class and the whole settlement
    # path rest on. A Gate mapping on a connected account is a deployment contradicting
    # its own bundle, and admitting it would leave a row the connector paths treat as a
    # lost dispatch: reconciliation would release its claim on cancellation evidence with
    # no executor report, and the recovery run would sweep it inside its report window.
    accounts = connected_account(world)
    with pytest.raises(ExecutionError) as failure:
        checkpoint(db, world, accounts=accounts, action=first)
    assert failure.value.code == "INVALID_BUNDLE"
    # A deployment contradicting its own bundle stays contradicted until an administrator
    # changes one of them, and every retry appends another rejection below, so this is not
    # the transient dependency failure the default 503 asks a caller to retry.
    assert error_status(failure.value) == 409
    # Fails closed before anything is written: no execution, no reservation, no claim.
    assert execution_states(admin_engine, tenant) == []
    assert impact_rows(admin_engine, tenant) == []
    assert claim_rows(admin_engine, tenant) == []
    reasons = [
        payload["reason"] for payload in audit_payloads(admin_engine, tenant, "execution.rejected")
    ]
    assert reasons == ["INVALID_BUNDLE"]
    # The same mapping on an account with no connector is the Gate placement, and it
    # grants.
    assert checkpoint(db, world, action=second).view.checkpoint is not None


def test_a_grant_is_minted_only_after_the_closing_rechecks(
    db, gate_world, admin_engine, monkeypatch
):
    world = gate_world
    first, second = targets(admin_engine, world, count=2)
    minted = []
    issue = admission._grant

    # Named rather than positional, so a change to _grant's signature fails here loudly
    # instead of watching whichever argument happens to sit third.
    def watched(conn, identity, row, resolved, secret, clock, preconditions):
        minted.append(row["execution_id"])
        return issue(conn, identity, row, resolved, secret, clock, preconditions)

    monkeypatch.setattr(admission, "_grant", watched)
    granted = checkpoint(db, world, action=first)
    assert minted == [granted.view.execution_id]

    def drifted(*args, **changes):
        raise ResolutionError("STALE_AUTHORIZATION")

    # The reattestation after the reservation is an authority recheck: any delay in the
    # writes, the audit chain or a foreign-key lock must not extend authority. A secret
    # minted before it would be a caller told it may act on authority the recheck was
    # about to find gone, so the mint is last and this holds it there.
    monkeypatch.setattr(admission, "attest_snapshot", drifted)
    with pytest.raises(ExecutionError):
        checkpoint(db, world, action=second)
    assert minted == [granted.view.execution_id]


def test_an_idempotent_retry_returns_the_same_grant_and_reserves_nothing_new(
    db, gate_world, admin_engine
):
    world = gate_world
    tenant = world["identity"].tenant_id
    first = checkpoint(db, world)
    granted = first.view.checkpoint
    retry = checkpoint(db, world)
    assert retry.view.execution_id == first.view.execution_id
    assert retry.ticket is None
    again = retry.view.checkpoint
    assert again is not None
    assert (again.operation_id, again.act_expires_at, again.report_expires_at) == (
        granted.operation_id,
        granted.act_expires_at,
        granted.report_expires_at,
    )
    assert again.precondition_class == granted.precondition_class
    # The secret is minted exactly once per execution. A retry describes the same act and
    # carries no secret, and says so, so the holder of the one secret this execution ever
    # had keeps the only thing that can settle it. Nothing is reserved a second time.
    assert again.regranted and again.report_secret is None
    row = grant_row(admin_engine, tenant, first.view.execution_id)
    assert row["owner_hash"] == secret_digest(granted.report_secret)
    assert len(impact_rows(admin_engine, tenant)) == 1
    assert len(claim_rows(admin_engine, tenant)) == 1
    # A fresh idempotency key carrying the same intent is the same retry.
    third = checkpoint(db, world, idempotency_key="retry-2")
    assert third.view.execution_id == first.view.execution_id
    assert third.view.checkpoint is not None and third.view.checkpoint.report_secret is None
    assert len(claim_rows(admin_engine, tenant)) == 1
    assert (
        grant_row(admin_engine, tenant, first.view.execution_id)["owner_hash"] == row["owner_hash"]
    )
    grants = audit_payloads(admin_engine, tenant, "execution.checkpoint_granted")
    assert [payload["regranted"] for payload in grants] == [False, True, True]
    assert not any("secret" in str(payload) for payload in grants)


def test_a_second_credential_of_the_principal_never_takes_over_the_secret(
    db, gate_world, admin_engine
):
    world = gate_world
    tenant = world["identity"].tenant_id
    first = checkpoint(db, world)
    granted = first.view.checkpoint
    assert granted is not None
    held = granted.report_secret
    # A story redeployed with a fresh credential, or anything that replays the first
    # request, is the same principal: the execution key, the pending intent and the grant
    # are all scoped to the principal, so it reaches the retry route of a live grant. If a
    # retry re-minted, this second caller would take settlement authority away from the
    # holder of the first secret, and a duplicate arriving while a report is in flight
    # would guarantee that report is refused.
    other = second_credential(admin_engine, db, world)
    retry = checkpoint(db, world, other)
    assert retry.view.execution_id == first.view.execution_id
    again = retry.view.checkpoint
    assert again is not None and again.regranted and again.report_secret is None
    assert again.operation_id == granted.operation_id
    row = grant_row(admin_engine, tenant, first.view.execution_id)
    assert row["owner_hash"] == secret_digest(held)
    assert len(impact_rows(admin_engine, tenant)) == 1
    assert len(claim_rows(admin_engine, tenant)) == 1


def test_a_retry_after_the_owner_stops_externally_executing_describes_the_same_grant(
    db, gate_world, admin_engine
):
    world = gate_world
    tenant = world["identity"].tenant_id
    first = checkpoint(db, world)
    granted = first.view.checkpoint
    assert granted is not None
    digest = grant_row(admin_engine, tenant, first.view.execution_id)["owner_hash"]
    # The owner stops externally executing the operation. An issued grant is not recalled
    # by that: its reservation, its claim, its report window and the secret its holder
    # already has were committed under the bundle the row names, and the re-answer confers
    # nothing new, so the caller is still told what it was told the first time. The change
    # governs the next decision, which resolves under the new bundle.
    gate_bundle(db, world, external_executor=False)
    retry = checkpoint(db, world)
    again = retry.view.checkpoint
    assert retry.view.execution_id == first.view.execution_id
    assert again is not None and again.regranted and again.report_secret is None
    assert again.operation_id == granted.operation_id
    assert grant_row(admin_engine, tenant, first.view.execution_id)["owner_hash"] == digest
    assert len(claim_rows(admin_engine, tenant)) == 1


def test_a_retried_dispatch_keeps_its_owner_secret_and_answers_with_a_bare_view(
    db, world, owner, admin_engine
):
    tenant = world["identity"].tenant_id
    register_key(owner, world)
    gate_bundle(db, world, external_executor=False)
    action = targets(admin_engine, world, count=1)[0]
    accounts = connected_account(world)
    first = checkpoint(db, world, accounts=accounts, action=action)
    assert first.ticket is not None
    digest = grant_row(admin_engine, tenant, first.view.execution_id)["owner_hash"]
    retry = checkpoint(db, world, accounts=accounts, action=action)
    # Re-minting the secret of an execution ExecBound dispatches would revoke the one
    # send attempt its holder already owns, so an ordinary retry answers and writes nothing.
    assert retry.view.execution_id == first.view.execution_id
    assert retry.view.checkpoint is None and retry.ticket is None
    assert grant_row(admin_engine, tenant, first.view.execution_id)["owner_hash"] == digest
    assert take_dispatch(db, first.ticket, world["clock"]).execution_id == first.view.execution_id


def test_a_retry_after_the_plan_expires_grants_nothing_new(db, gate_world, admin_engine):
    world = gate_world
    tenant = world["identity"].tenant_id
    first = checkpoint(db, world)
    digest = grant_row(admin_engine, tenant, first.view.execution_id)["owner_hash"]
    world["clock"].value = world["clock"].now() + timedelta(seconds=300)
    retry = checkpoint(db, world)
    assert retry.view.execution_id == first.view.execution_id
    assert retry.view.state == "DISPATCH_COMMITTED"
    assert retry.view.checkpoint is None and retry.ticket is None
    # The reservation stands and the first secret still settles it; a caller that needs a
    # decision on fresh context makes a new request.
    assert grant_row(admin_engine, tenant, first.view.execution_id)["owner_hash"] == digest
    assert len(claim_rows(admin_engine, tenant)) == 1


def test_an_observing_tenant_grants_nothing(db, gate_world, admin_engine):
    world = gate_world
    tenant = world["identity"].tenant_id
    set_enforcement_mode(db, world["admin"], "OBSERVE", "Onboarding", world["clock"])
    granted = checkpoint(db, world)
    assert granted.view.state == "OBSERVED"
    assert granted.view.checkpoint is None and granted.ticket is None
    row = grant_row(admin_engine, tenant, granted.view.execution_id)
    assert row["owner_hash"] is None and row["dispatch_attempted_at"] is None
    assert row["report_expires_at"] is None
    assert [item["state"] for item in impact_rows(admin_engine, tenant)] == ["OBSERVED"]
    assert claim_rows(admin_engine, tenant) == []


def test_an_observing_tenant_answers_a_retry_without_a_grant(db, gate_world, admin_engine):
    world = gate_world
    tenant = world["identity"].tenant_id
    first = checkpoint(db, world)
    assert first.view.checkpoint is not None
    # The mode is a tenant property and it wins over bundle content, on the retry route as
    # much as on the first request: an observing tenant reserves nothing and grants
    # nothing, and re-describing an act for a caller it is no longer enforcing for would
    # be a grant issued under OBSERVE.
    set_enforcement_mode(db, world["admin"], "OBSERVE", "Onboarding", world["clock"])
    retry = checkpoint(db, world)
    assert retry.view.execution_id == first.view.execution_id
    assert retry.view.state == "DISPATCH_COMMITTED"
    assert retry.view.checkpoint is None and retry.ticket is None
    grants = audit_payloads(admin_engine, tenant, "execution.checkpoint_granted")
    assert [payload["regranted"] for payload in grants] == [False]
    assert len(claim_rows(admin_engine, tenant)) == 1


def test_a_denied_checkpoint_answers_a_retry_without_a_grant(db, gate_world, admin_engine):
    world = gate_world
    tenant = world["identity"].tenant_id
    holder = checkpoint(db, world)
    other = agent(admin_engine, db, world)
    denied = checkpoint(db, world, other)
    assert denied.view.state == "DENIED" and denied.view.execution_id != holder.view.execution_id
    row = grant_row(admin_engine, tenant, denied.view.execution_id)
    # The report window is written before the decision, so a refused row carries one and
    # the marker alone never means "a grant is live". Every reader pairs it with a state,
    # and a retry route that tested anything weaker than DISPATCH_COMMITTED would answer a
    # denied, settled or swept execution with a grant.
    assert row["report_expires_at"] is not None and row["owner_hash"] is None
    retry = checkpoint(db, world, other)
    assert retry.view.execution_id == denied.view.execution_id
    assert retry.view.state == "DENIED"
    assert retry.view.checkpoint is None and retry.ticket is None
    assert grant_row(admin_engine, tenant, denied.view.execution_id)["owner_hash"] is None
    granted = audit_payloads(admin_engine, tenant, "execution.checkpoint_granted")
    assert [payload["execution_id"] for payload in granted] == [str(holder.view.execution_id)]


def test_a_settled_checkpoint_answers_a_retry_without_a_grant(db, gate_world, admin_engine):
    world = gate_world
    tenant = world["identity"].tenant_id
    first = checkpoint(db, world)
    grant = first.view.checkpoint
    assert grant is not None
    record = signed_record(db, world, first.view.execution_id)
    assert report(db, world, first.view.execution_id, grant.report_secret, record=record).state == (
        "EXECUTED"
    )
    settled = retained(admin_engine, tenant, first.view.execution_id)
    assert (settled.state, settled.tier, settled.impact) == ("EXECUTED", "ATTESTED", "CONFIRMED")
    assert settled.released_at is not None
    # The other half of the reason the state test is exactly DISPATCH_COMMITTED, and the
    # half a denied row cannot show: a settled row keeps its report window too, so the
    # marker is as present here as it was while the grant was live. A re-answer would hand
    # a caller a freshly signed act token and a live report deadline for an execution whose
    # impact is already confirmed and whose canonical claim is already released.
    assert grant_row(admin_engine, tenant, first.view.execution_id)["report_expires_at"] is not None
    retry = checkpoint(db, world)
    assert retry.view.execution_id == first.view.execution_id
    assert retry.view.state == "EXECUTED"
    assert retry.view.checkpoint is None and retry.ticket is None
    assert retained(admin_engine, tenant, first.view.execution_id) == settled
    regrants = audit_payloads(admin_engine, tenant, "execution.checkpoint_granted")
    assert [payload["regranted"] for payload in regrants] == [False]


def test_an_uncertain_checkpoint_answers_a_retry_without_a_grant(db, gate_world, admin_engine):
    world = gate_world
    tenant = world["identity"].tenant_id
    first = checkpoint(db, world)
    grant = first.view.checkpoint
    assert grant is not None
    # The executor's bare word that it did not act settles nothing and moves the row to
    # INDETERMINATE with the plan it was frozen under still valid, which is the one
    # non-committed state a retry can reach while a re-grant is still possible. A swept
    # grant is the same row an hour later and cannot be retried at all; see below.
    uncertain = report(
        db, world, first.view.execution_id, grant.report_secret, **UNCERTAIN["non-execution"]
    )
    assert uncertain.state == "INDETERMINATE"
    held = retained(admin_engine, tenant, first.view.execution_id)
    assert (held.state, held.tier, held.impact) == ("INDETERMINATE", None, "UNRESOLVED")
    assert held.released_at is None
    # Nothing but the state test stands between this retry and a fresh act grant: the plan
    # is still valid, the marker is still on the row, and the tenant is still enforcing.
    # A grant here would tell a caller it may act on a target whose uncertainty this
    # tenant has already retained and whose reservation nothing has resolved.
    assert world["clock"].now() < frozen_plan(db, world, first.view.execution_id).valid_until
    retry = checkpoint(db, world)
    assert retry.view.execution_id == first.view.execution_id
    assert retry.view.state == "INDETERMINATE"
    assert retry.view.checkpoint is None and retry.ticket is None
    assert retained(admin_engine, tenant, first.view.execution_id) == held
    regrants = audit_payloads(admin_engine, tenant, "execution.checkpoint_granted")
    assert [payload["regranted"] for payload in regrants] == [False]


def test_a_swept_grant_answers_a_retry_without_a_grant(db, gate_world, admin_engine):
    world = gate_world
    tenant = world["identity"].tenant_id
    world["admin"] = long_lived_admin(admin_engine, db, world)
    patient = long_lived_agent(admin_engine, db, world)
    first = checkpoint(db, world, patient)
    assert first.view.checkpoint is not None
    window = grant_row(admin_engine, tenant, first.view.execution_id)["report_expires_at"]
    world["clock"].value = window + timedelta(seconds=1)
    assert recover(db, world["admin"], {}, clock=world["clock"]).swept == 1
    swept = retained(admin_engine, tenant, first.view.execution_id)
    assert (swept.state, swept.impact, swept.released_at) == ("INDETERMINATE", "UNRESOLVED", None)
    retry = checkpoint(db, world, patient)
    assert retry.view.execution_id == first.view.execution_id
    assert retry.view.state == "INDETERMINATE"
    assert retry.view.checkpoint is None and retry.ticket is None
    assert retained(admin_engine, tenant, first.view.execution_id) == swept
    regrants = audit_payloads(admin_engine, tenant, "execution.checkpoint_granted")
    assert [payload["regranted"] for payload in regrants] == [False]
    # Which guard answered is worth being exact about, because only one of the two could
    # have. A plan's validity is bounded by the requesting credential's expiry and the
    # report window is `min(a day, that same expiry)`, so the window never closes first and
    # a grant the sweep is allowed to touch is always one whose plan has already expired:
    # `_regrant` refuses on the plan before the state is consulted. The state test is what
    # holds the settled and uncertain rows above, where the plan is still live.
    assert world["clock"].now() >= frozen_plan(db, world, first.view.execution_id).valid_until


def test_outstanding_grants_counts_only_this_principal_s_unsettled_grants(
    db, gate_world, admin_engine
):
    world = gate_world
    tenant, principal = world["identity"].tenant_id, world["identity"].principal_id
    first, second = targets(admin_engine, world, count=2)
    checkpoint(db, world, action=first)
    other = agent(admin_engine, db, world)
    checkpoint(db, world, other, action=second)
    with db.transaction(tenant) as conn:
        assert store.outstanding_grants(conn, tenant, principal) == 1
        assert store.outstanding_grants(conn, tenant, other.principal_id) == 1
    # An ordinary dispatch commits the same state and is not a grant.
    connected = targets(admin_engine, world, count=1)[0]
    gate_bundle(db, world, external_executor=False)
    admit(
        db,
        world["identity"],
        connected,
        world["clock"],
        available_accounts=connected_account(world),
    )
    with db.transaction(tenant) as conn:
        assert store.outstanding_grants(conn, tenant, principal) == 1


# The runtime branch, the presenter's act grant, and the deployment configuration
# that says what the frozen expected version is worth at the vendor the executor calls.


@pytest.fixture
def token_keys():
    return TokenKeys("checkpoint-v1", {"checkpoint-v1": secrets.token_bytes(32)})


def granted(runtime, world):
    """The view this runtime answers a Gate request with, asserted to carry its grant."""
    view = runtime.execute(world["identity"], request(world).model_dump_json().encode())
    assert view.checkpoint is not None
    return view


def act_claim(token, keys, identity, clock):
    """Authenticate an act grant exactly as its own audience's verifier would."""
    return verify(
        token,
        keys,
        tenant_id=identity.tenant_id,
        principal_id=identity.principal_id,
        credential_id=identity.credential_id,
        audience="execution.checkpoint_outcome",
        now=clock.now(),
    )


def test_the_response_carries_the_checkpoint_and_a_signed_act_grant(db, gate_world, token_keys):
    world = gate_world
    identity = world["identity"]
    runtime = gate_runtime(db, world, keys=token_keys)
    view = granted(runtime, world)
    grant = view.checkpoint
    payload = runtime.present(identity, view)
    described = payload["checkpoint"]
    # Every field of the grant reaches the caller, including the one secret that will
    # settle it, and the act token is the only thing the presenter adds, in its own member
    # so no later field of the grant can be overwritten by it.
    assert set(described) == {"grant", "act"}
    assert described["grant"] == grant.model_dump(mode="json")
    assert described["grant"]["report_secret"] == grant.report_secret
    claim = act_claim(described["act"], token_keys, identity, world["clock"])
    assert claim.operation_id == grant.operation_id
    assert claim.execution_id == view.execution_id
    assert claim.plan_hash == view.plan_hash
    assert claim.expires_at == grant.act_expires_at
    assert claim.approval_id is None
    # The view's own body is unchanged: the grant is presenter-added, never serialized.
    assert "checkpoint" not in view.model_dump(mode="json")
    assert set(payload) == {
        "request_ref",
        "execution_id",
        "state",
        "plan_hash",
        "approval_id",
        "approval_state",
        "checkpoint",
    }


def test_an_act_grant_is_worthless_at_every_existing_call_site(db, gate_world, token_keys):
    world = gate_world
    identity = world["identity"]
    runtime = gate_runtime(db, world, keys=token_keys)
    view = granted(runtime, world)
    act = runtime.present(identity, view)["checkpoint"]["act"]
    # A grant confers no authority to read status through the continuation it carries:
    # the audience is its own, and the status verifier is one of the three that refuse it.
    with pytest.raises(ExecutionError) as refused:
        runtime.status(identity, view.execution_id, act)
    assert refused.value.code == "INVALID_CONTINUATION"


def test_a_deployment_without_continuation_keys_still_describes_the_grant(
    db, gate_world, admin_engine
):
    world = gate_world
    tenant = world["identity"].tenant_id
    runtime = gate_runtime(db, world)
    assert runtime.keys is None
    view = granted(runtime, world)
    described = runtime.present(world["identity"], view)["checkpoint"]
    # The reservation and the claim are committed whether or not an act can be signed, so
    # the answer says there is no act rather than hiding a grant the caller is holding.
    assert described["act"] is None
    assert described["grant"]["report_secret"] == view.checkpoint.report_secret
    assert described["grant"]["operation_id"] == str(view.checkpoint.operation_id)
    assert len(impact_rows(admin_engine, tenant)) == 1
    assert len(claim_rows(admin_engine, tenant)) == 1


def test_a_closed_act_window_is_signed_no_token(db, gate_world, token_keys):
    world = gate_world
    identity = world["identity"]
    runtime = gate_runtime(db, world, keys=token_keys)
    view = granted(runtime, world)
    assert runtime.present(identity, view)["checkpoint"]["act"] is not None
    # A token past its own expiry is one no verifier would accept; the presenter answers
    # with the grant and no act, as it does for an approval window that has closed.
    world["clock"].value = view.checkpoint.act_expires_at
    assert runtime.present(identity, view)["checkpoint"]["act"] is None


def test_a_ticket_beside_a_grant_never_reaches_a_connector(
    db, gate_world, admin_engine, monkeypatch
):
    world = gate_world
    tenant = world["identity"].tenant_id
    runtime = gate_runtime(db, world)
    admitted = runtime_module.admit

    def also_ticketed(*arguments, **changes):
        answer = admitted(*arguments, **changes)
        if answer.view.checkpoint is None:
            return answer
        return dataclasses.replace(
            answer, ticket=DispatchTicket(tenant, answer.view.execution_id, "s" * 43)
        )

    monkeypatch.setattr(runtime_module, "admit", also_ticketed)
    # A ticket beside a grant would dispatch an operation the caller has just been told to
    # perform itself. The refusal comes before the connector lookup, which for a
    # checkpoint account holds nothing and would raise a KeyError rather than an
    # ExecutionError, so this fails loudly if the branch is ever removed.
    with pytest.raises(ExecutionError) as refused:
        runtime.execute(world["identity"], request(world).model_dump_json().encode())
    assert refused.value.code == "EXECUTION_UNAVAILABLE"
    states = execution_states(admin_engine, tenant)
    assert states == ["DISPATCH_COMMITTED"]
    # The reservation, the claim and the one secret are committed and the caller is told
    # none of it, so the refusal is audited. The rejection carries the reason and no
    # execution; the charged row is findable by the execution.checkpoint_granted event
    # admission committed before the runtime saw the contradiction.
    assert [
        payload["reason"] for payload in audit_payloads(admin_engine, tenant, "execution.rejected")
    ] == ["EXECUTION_UNAVAILABLE"]


@pytest.mark.parametrize(
    "declared", ["ENFORCED_BY_PROVIDER", "ASSERTED_BY_EXECUTOR", "UNAVAILABLE"]
)
def test_a_configured_binding_says_what_the_frozen_version_is_worth(db, gate_world, declared):
    world = gate_world
    granted = checkpoint(db, world, preconditions=PreconditionConfig({CONTAIN: declared}))
    grant = granted.view.checkpoint
    assert grant is not None
    assert (grant.provider, grant.provider_operation) == CONTAIN
    assert grant.precondition_class == declared
    frozen = frozen_plan(db, world, granted.view.execution_id)
    # A checkable class hands the executor the version the plan froze; the class that
    # promises nothing hands it none, so nothing reads as something to check. That the
    # frozen version is never the live one is held by
    # test_a_grant_carries_the_version_its_plan_froze_and_never_the_live_one.
    assert grant.expected_version == (
        None if declared == "UNAVAILABLE" else frozen.resource_version
    )


def test_a_grant_carries_the_version_its_plan_froze_and_never_the_live_one(
    db, gate_world, admin_engine
):
    world = gate_world
    tenant = world["identity"].tenant_id
    configured = PreconditionConfig({CONTAIN: "ENFORCED_BY_PROVIDER"})
    # Whatever the target carried when the plan froze is what the executor is told to
    # check, so the fixture's own version is never the answer: move it and the grant moves.
    move_resource_version(admin_engine, tenant, "resource-v2")
    granted = checkpoint(db, world, preconditions=configured)
    grant = granted.view.checkpoint
    assert grant is not None and grant.expected_version == "resource-v2"
    # And a version that moves under a live grant is exactly the race the precondition
    # class exists to describe. The re-answer describes the same act under the same frozen
    # decision, so it hands the executor the same version to check and never a newer one,
    # which would quietly excuse a change the executor was supposed to detect.
    move_resource_version(admin_engine, tenant, "resource-v3")
    retry = checkpoint(db, world, preconditions=configured)
    again = retry.view.checkpoint
    assert retry.view.execution_id == granted.view.execution_id
    assert again is not None and again.regranted
    assert again.expected_version == "resource-v2"
    assert frozen_plan(db, world, retry.view.execution_id).resource_version == "resource-v2"


def test_an_undeclared_binding_promises_nothing(db, gate_world):
    world = gate_world
    # A declaration for another vendor's binding never speaks for this one, and a
    # deployment that has declared nothing claims nothing.
    elsewhere = PreconditionConfig({("mock_entra", "disable"): "ENFORCED_BY_PROVIDER"})
    for configured in (elsewhere, PreconditionConfig()):
        granted = checkpoint(db, world, preconditions=configured, idempotency_key=str(uuid4()))
        grant = granted.view.checkpoint
        assert grant is not None
        assert grant.precondition_class == "UNAVAILABLE"
        assert grant.expected_version is None


def test_the_runtime_carries_its_declared_class_into_the_grant_and_the_response(
    db, gate_world, token_keys
):
    world = gate_world
    identity = world["identity"]
    runtime = gate_runtime(
        db,
        world,
        keys=token_keys,
        preconditions=PreconditionConfig({CONTAIN: "ENFORCED_BY_PROVIDER"}),
    )
    view = granted(runtime, world)
    frozen = frozen_plan(db, world, view.execution_id)
    described = runtime.present(identity, view)["checkpoint"]["grant"]
    assert described["precondition_class"] == "ENFORCED_BY_PROVIDER"
    assert described["expected_version"] == frozen.resource_version


def test_a_retry_describes_the_same_class(db, gate_world):
    world = gate_world
    configured = PreconditionConfig({CONTAIN: "ASSERTED_BY_EXECUTOR"})
    first = checkpoint(db, world, preconditions=configured)
    retry = checkpoint(db, world, preconditions=configured)
    assert retry.view.execution_id == first.view.execution_id
    again = retry.view.checkpoint
    assert again is not None and again.regranted
    assert again.precondition_class == "ASSERTED_BY_EXECUTOR"
    assert again.expected_version == first.view.checkpoint.expected_version


def test_a_retry_is_presented_as_a_regrant_with_no_secret_and_a_fresh_act(
    db, gate_world, token_keys
):
    world = gate_world
    identity = world["identity"]
    runtime = gate_runtime(db, world, keys=token_keys)
    body = request(world).model_dump_json().encode()
    first = runtime.present(identity, runtime.execute(identity, body))["checkpoint"]
    view = runtime.execute(identity, body)
    described = runtime.present(identity, view)["checkpoint"]
    # What a caller whose first response was lost actually receives: the same act,
    # described again, and no secret at all, so nothing in the body reads as a second way
    # to settle. A caller that reads only the act would otherwise believe it still holds
    # everything the first answer gave it.
    assert described["grant"]["regranted"] is True
    assert described["grant"]["report_secret"] is None
    assert first["grant"]["report_secret"] is not None
    same = (
        "operation_id",
        "provider",
        "provider_operation",
        "resource_provider_id",
        "action",
        "arguments",
        "precondition_class",
        "expected_version",
        "act_expires_at",
        "report_expires_at",
    )
    assert {key: described["grant"][key] for key in same} == {
        key: first["grant"][key] for key in same
    }
    # The act is the presenter's own, minted for this answer: a re-answer inside the act
    # window carries a fresh token that verifies, rather than the first one repeated.
    assert described["act"] != first["act"]
    claim = act_claim(described["act"], token_keys, identity, world["clock"])
    assert claim.execution_id == view.execution_id
    assert view.checkpoint is not None and claim.operation_id == view.checkpoint.operation_id
    assert claim.expires_at == view.checkpoint.act_expires_at


@pytest.mark.parametrize(
    "classes",
    [
        {CONTAIN: "ENFORCED"},
        {CONTAIN: "unavailable"},
        {CONTAIN: None},
        {CONTAIN: True},
        {("mock_crowdstrike",): "UNAVAILABLE"},
        {("mock_crowdstrike", "contain", "extra"): "UNAVAILABLE"},
        {("mock_crowdstrike", "Contain"): "UNAVAILABLE"},
        {("mock_crowdstrike", ""): "UNAVAILABLE"},
        {("mock_crowdstrike", None): "UNAVAILABLE"},
        {"mock_crowdstrike.contain": "UNAVAILABLE"},
        [(CONTAIN, "UNAVAILABLE")],
    ],
)
def test_a_declaration_must_name_a_provider_binding_and_a_known_class(classes):
    # Nothing but the three classes may be declared: a typo that became a class name
    # would claim a guarantee for a vendor nobody checked.
    with pytest.raises(ValueError, match="precondition configuration"):
        PreconditionConfig(classes)


def test_declared_configuration_is_copied_against_later_mutation():
    original = {CONTAIN: "ENFORCED_BY_PROVIDER"}
    configured = PreconditionConfig(original)
    original[CONTAIN] = "UNAVAILABLE"
    original[("mock_entra", "disable")] = "ENFORCED_BY_PROVIDER"
    assert configured.declared(*CONTAIN) == "ENFORCED_BY_PROVIDER"
    assert configured.declared("mock_entra", "disable") == "UNAVAILABLE"
    with pytest.raises(TypeError):
        configured.classes[CONTAIN] = "UNAVAILABLE"


def test_a_runtime_refuses_a_class_for_a_binding_its_catalog_does_not_bind(db, world):
    # A class for an operation no plan can name describes nothing and would sit unread; a
    # deployment that means to declare one has mistyped the binding.
    with pytest.raises(ValueError, match="bound provider operation"):
        gate_runtime(
            db,
            world,
            preconditions=PreconditionConfig(
                {("mock_crowdstrike", "quarantine"): "ENFORCED_BY_PROVIDER"}
            ),
        )
    with pytest.raises(ValueError, match="bound provider operation"):
        gate_runtime(
            db, world, preconditions=PreconditionConfig({("mock_entra", "contain"): "UNAVAILABLE"})
        )
    assert (
        gate_runtime(
            db, world, preconditions=PreconditionConfig({CONTAIN: "ENFORCED_BY_PROVIDER"})
        ).preconditions.declared(*CONTAIN)
        == "ENFORCED_BY_PROVIDER"
    )


@pytest.mark.parametrize(
    "configured", [{CONTAIN: "ENFORCED_BY_PROVIDER"}, [], "", 0, NO_PRECONDITIONS.classes]
)
def test_a_runtime_holds_a_precondition_configuration_or_nothing(db, world, configured):
    # Deployment configuration is validated where it is constructed, so a raw mapping is
    # refused here rather than reaching admission: a falsy one would silently read as "this
    # deployment declared nothing", and a truthy one would fail at the first grant.
    with pytest.raises(ValueError, match="precondition configuration"):
        gate_runtime(db, world, preconditions=configured)
    # A deployment that declares nothing is the one thing that may be absent.
    assert Runtime(db, [], clock=world["clock"]).preconditions is NO_PRECONDITIONS


def test_a_status_read_carries_no_grant(db, gate_world, token_keys):
    world = gate_world
    identity = world["identity"]
    runtime = gate_runtime(db, world, keys=token_keys)
    view = granted(runtime, world)
    # The grant is set by the admission that issued it and by nothing else. A status read
    # answers with the same body it always did, so no later request re-serves the act or
    # the secret, which is retained only as a digest and cannot be re-served at all.
    status = runtime.status(identity, view.execution_id)
    assert status.checkpoint is None
    assert "checkpoint" not in runtime.present(identity, status)


@pytest.mark.parametrize(
    "field,value",
    [
        ("precondition_class", "ENFORCED_BY_PROVIDER"),
        ("expected_version", "resource-v2"),
        ("external_executor", True),
    ],
)
def test_no_request_field_declares_a_class_or_selects_a_checkpoint(db, gate_world, field, value):
    # The class is deployment configuration and the placement is bundle content: neither
    # is anything a caller may state, so a request naming either is an unknown field.
    world = gate_world
    body = json.loads(request(world).model_dump_json())
    body[field] = value
    runtime = gate_runtime(db, world)
    with pytest.raises(ExecutionError) as refused:
        runtime.execute(world["identity"], json.dumps(body).encode())
    assert refused.value.code == "INVALID_REQUEST"


# ---------------------------------------------------------------------------
# The outcome route: who may report, and what a report may never settle.
#
# The route authenticates a report, decides its tier and verifies its evidence, and the
# settlement it feeds decides the state, the impact and the claim at that tier.
# ---------------------------------------------------------------------------


def dispatched(db, world, admin_engine, action=None):
    """One execution ExecBound dispatched, with the owner secret only this process holds."""
    ordinary = checkpoint(db, world, accounts=connected_account(world), action=action)
    assert ordinary.ticket is not None
    take_dispatch(db, ordinary.ticket, world["clock"])
    row = grant_row(admin_engine, world["identity"].tenant_id, ordinary.view.execution_id)
    assert (row["state"], row["report_expires_at"]) == ("DISPATCH_COMMITTED", None)
    assert row["dispatch_attempted_at"] is not None
    return ordinary


def test_an_outcome_report_never_settles_an_operation_execbound_dispatched(
    db, world, owner, admin_engine
):
    # The refusal that keeps a report off a dispatch. An ordinary dispatch's owner secret is
    # the same kind of value a report secret is, held in the same column, and its execution
    # sits in the same state a grant does with the same attempt stamp; only the frozen
    # mapping tells the two apart, and settling a dispatched operation from a caller's
    # report is exactly the fabricated evidence a settlement must never rest on.
    register_key(owner, world)
    gate_bundle(db, world, external_executor=False)
    tenant = world["identity"].tenant_id
    ordinary = dispatched(db, world, admin_engine)
    with pytest.raises(ExecutionError) as refused:
        report(db, world, ordinary.view.execution_id, ordinary.ticket.secret)
    assert refused.value.code == "INVALID_STATE"
    row = grant_row(admin_engine, tenant, ordinary.view.execution_id)
    assert row["state"] == "DISPATCH_COMMITTED"
    assert row["settlement_tier"] is None
    assert [item["state"] for item in impact_rows(admin_engine, tenant)] == ["UNRESOLVED"]
    assert [item["released_at"] for item in claim_rows(admin_engine, tenant)] == [None]
    reasons = [
        payload["reason"] for payload in audit_payloads(admin_engine, tenant, "execution.rejected")
    ]
    assert reasons == ["INVALID_STATE"]


def test_a_dispatched_execution_marked_as_a_checkpoint_is_refused_by_its_mapping(
    db, world, owner, admin_engine
):
    # Two facts say "checkpoint" and they agree by construction: the frozen mapping, and
    # the report window admission writes under that same mapping. Only the owner
    # connection can make them disagree, because the runtime holds no UPDATE on the
    # column, and doing so leaves the mapping as the one thing between a dispatched
    # operation and a settlement from a caller's report.
    register_key(owner, world)
    gate_bundle(db, world, external_executor=False)
    tenant = world["identity"].tenant_id
    ordinary = dispatched(db, world, admin_engine)
    set_report_window(
        admin_engine, tenant, ordinary.view.execution_id, world["clock"].now() + REPORT_WINDOW
    )
    with pytest.raises(ExecutionError) as refused:
        report(db, world, ordinary.view.execution_id, ordinary.ticket.secret)
    assert refused.value.code == "INVALID_STATE"
    assert grant_row(admin_engine, tenant, ordinary.view.execution_id)["state"] == (
        "DISPATCH_COMMITTED"
    )
    assert [item["state"] for item in impact_rows(admin_engine, tenant)] == ["UNRESOLVED"]


def test_a_grant_whose_report_window_is_gone_is_no_live_grant(db, gate_world, admin_engine):
    # The mirror of the test above: the mapping still declares an external executor and
    # the marker is gone, which no runtime statement can do. A row carrying no window is
    # no live grant, so the window guard refuses it on its own.
    world = gate_world
    tenant = world["identity"].tenant_id
    granted = checkpoint(db, world)
    grant = granted.view.checkpoint
    assert grant is not None
    set_report_window(admin_engine, tenant, granted.view.execution_id, None)
    with pytest.raises(ExecutionError) as refused:
        report(db, world, granted.view.execution_id, grant.report_secret)
    assert refused.value.code == "REPORT_WINDOW_CLOSED"
    assert grant_row(admin_engine, tenant, granted.view.execution_id)["state"] == (
        "DISPATCH_COMMITTED"
    )


def test_a_report_reads_the_bundle_its_grant_was_frozen_under(db, gate_world, admin_engine):
    # The re-read is of the immutable bundle the execution names and never of the tenant's
    # active one, and the two tell apart the only case where they differ: the owner edits
    # the mapping after the grant was issued. An issued grant is not recalled by a bundle
    # edit, just as the emergency stop cannot recall one, so reading the active bundle here
    # would refuse the one report that can settle a reservation and a claim already
    # committed, leaving the budget charged and the target held with no way for the
    # executor to say what it did. The retry route answers the same way:
    # `test_a_retry_after_the_owner_stops_externally_executing_describes_the_same_grant`.
    world = gate_world
    tenant = world["identity"].tenant_id
    granted = checkpoint(db, world)
    grant = granted.view.checkpoint
    assert grant is not None
    replacement = gate_bundle(db, world, external_executor=False)
    with db.transaction(tenant) as conn:
        row = store.read(conn, tenant, granted.view.execution_id)
        active = store.active_bundle(conn, tenant)
    # The two bundles really are different bundles, and only one of them declares the
    # mapping externally executed, so the report below can only be answered by the frozen
    # one. Without this the assertion below would hold whichever bundle the route read.
    assert active.bundle_id == replacement.bundle_id != row["bundle_id"]
    assert [m.external_executor for m in active.mappings] == [False]
    assert report(db, world, granted.view.execution_id, grant.report_secret).state == "EXECUTED"
    assert [payload["tier"] for payload in reported(admin_engine, tenant)] == ["ASSERTED"]


def test_another_principals_grant_is_not_found(db, gate_world, admin_engine):
    # The secret is the grant holder's, and it is presented by a principal the grant was
    # not issued to. The answer says nothing about whether the execution exists.
    world = gate_world
    tenant = world["identity"].tenant_id
    (target,) = targets(admin_engine, world, count=1)
    granted = checkpoint(db, world, action=target)
    grant = granted.view.checkpoint
    assert grant is not None
    other = agent(admin_engine, db, world)
    with pytest.raises(ExecutionError) as refused:
        report(db, world, granted.view.execution_id, grant.report_secret, other)
    assert refused.value.code == "NOT_FOUND"
    assert grant_row(admin_engine, tenant, granted.view.execution_id)["state"] == (
        "DISPATCH_COMMITTED"
    )
    # The grant holder still settles its own, so the refusal was about the principal.
    assert report(db, world, granted.view.execution_id, grant.report_secret).state == "EXECUTED"
    assert len(audit_payloads(admin_engine, tenant, "execution.outcome_reported")) == 1


def test_a_settled_execution_is_closed_to_everything_but_its_own_restatement(
    db, gate_world, admin_engine
):
    # What a settled row does to the route, against a settlement the route itself made:
    # the one secret an execution ever had settles it once, anything saying something
    # else is refused rather than quietly discarded, and a restatement is answered so a
    # caller whose acceptance was lost in transit is not left holding a secret its own
    # execution calls invalid.
    world = gate_world
    tenant = world["identity"].tenant_id
    granted = checkpoint(db, world)
    grant = granted.view.checkpoint
    assert grant is not None
    assert report(db, world, granted.view.execution_id, grant.report_secret).state == "EXECUTED"
    settled = retained(admin_engine, tenant, granted.view.execution_id)
    assert (settled.state, settled.tier) == ("EXECUTED", "ASSERTED")
    # The contradiction is attested evidence for a row settled on the executor's own word,
    # because that is the one `_restates` alone refuses: it settles the same EXECUTED, so
    # the state machine would let it through and `_settle_report` would answer it as a
    # no-op, dropping the record silently and leaving the tier where it was. Promoting
    # ASSERTED to ATTESTED would release the claim before the act window on evidence that
    # says nothing new, so the record is refused rather than discarded.
    record = signed_record(db, world, granted.view.execution_id)
    with pytest.raises(ExecutionError) as refused:
        report(db, world, granted.view.execution_id, grant.report_secret, record=record)
    assert refused.value.code == "INVALID_STATE"
    assert retained(admin_engine, tenant, granted.view.execution_id) == settled
    assert report(db, world, granted.view.execution_id, grant.report_secret).state == "EXECUTED"
    # One capture for the settlement and none for either report that followed it.
    assert [payload["tier"] for payload in reported(admin_engine, tenant)] == ["ASSERTED"]


def test_a_settled_row_carrying_no_tier_restates_nothing_and_accepts_nothing(
    db, gate_world, admin_engine
):
    # A shape settlement does not produce, pinned because `_reportable` must survive it:
    # `force_state` leaves a terminal state with no result and no settlement_tier. There
    # is nothing for a report to restate, so this refusal is for that and not for
    # contradicting a settled outcome — and the restatement check reads the NULL result
    # without raising on it, which is the only coverage that guard has.
    world = gate_world
    tenant = world["identity"].tenant_id
    granted = checkpoint(db, world)
    grant = granted.view.checkpoint
    assert grant is not None
    force_state(db, world, granted.view.execution_id, "EXECUTED")
    row = grant_row(admin_engine, tenant, granted.view.execution_id)
    assert (row["state"], row["settlement_tier"], row["result"]) == ("EXECUTED", None, None)
    with pytest.raises(ExecutionError) as refused:
        report(db, world, granted.view.execution_id, grant.report_secret)
    assert refused.value.code == "INVALID_STATE"
    assert grant_row(admin_engine, tenant, granted.view.execution_id)["state"] == "EXECUTED"
    assert audit_payloads(admin_engine, tenant, "execution.outcome_reported") == []


def test_a_closed_report_window_refuses_the_report(db, gate_world, admin_engine):
    world = gate_world
    tenant = world["identity"].tenant_id
    (target,) = targets(admin_engine, world, count=1)
    patient = long_lived_agent(admin_engine, db, world)
    granted = checkpoint(db, world, patient, action=target)
    grant = granted.view.checkpoint
    assert grant is not None
    # The report window is what an executor whose vendor call was queued relies on, so it
    # is open long after the act window and the frozen plan have closed. The report it
    # carries is the unknown result, which settles nothing and leaves the execution
    # reportable, so what refuses at the deadline is the window and not a settled state.
    world["clock"].value = grant.report_expires_at - timedelta(seconds=1)
    assert report(
        db,
        world,
        granted.view.execution_id,
        grant.report_secret,
        patient,
        outcome="UNKNOWN",
        reason=None,
    ).state == ("INDETERMINATE")
    world["clock"].value = grant.report_expires_at
    with pytest.raises(ExecutionError) as refused:
        report(
            db,
            world,
            granted.view.execution_id,
            grant.report_secret,
            patient,
            outcome="UNKNOWN",
            reason=None,
        )
    assert refused.value.code == "REPORT_WINDOW_CLOSED"
    assert grant_row(admin_engine, tenant, granted.view.execution_id)["state"] == "INDETERMINATE"
    assert [item["state"] for item in impact_rows(admin_engine, tenant)] == ["UNRESOLVED"]
    assert [item["released_at"] for item in claim_rows(admin_engine, tenant)] == [None]


def test_a_forged_secret_settles_nothing(db, gate_world, admin_engine, monkeypatch):
    world = gate_world
    tenant = world["identity"].tenant_id
    granted = checkpoint(db, world)
    grant = granted.view.checkpoint
    assert grant is not None

    def never(command, report, verifier):
        # A report that does not authenticate is refused before its evidence is weighed,
        # so an executor cannot spend the deployment's signature checks on refusals.
        raise AssertionError("An unauthenticated report reached evidence verification")

    monkeypatch.setattr(outcomes, "_reported", never)
    with pytest.raises(ExecutionError) as refused:
        report(db, world, granted.view.execution_id, secrets.token_urlsafe(32))
    assert refused.value.code == "INVALID_REPORT"
    assert grant_row(admin_engine, tenant, granted.view.execution_id)["owner_hash"] == (
        secret_digest(grant.report_secret)
    )
    assert audit_payloads(admin_engine, tenant, "execution.outcome_reported") == []


def test_the_report_secret_is_compared_in_constant_time(db, gate_world, monkeypatch):
    # `docs/CHECKPOINT.md` promises it by name. The comparison is over a SHA-256 digest
    # rather than over the secret, so a `!=` would leak only digest bytes and every other
    # test in this file would stay green: the guarantee has no behaviour of its own, and
    # nothing but this pins it. The module's own `secrets` name is what is watched, so no
    # other module's comparison is disturbed while it runs.
    world = gate_world
    granted = checkpoint(db, world)
    grant = granted.view.checkpoint
    assert grant is not None
    compared: list[tuple[str, str]] = []

    def watched(stored, presented):
        compared.append((stored, presented))
        return secrets.compare_digest(stored, presented)

    # The stub is the module with one name swapped, so the day the route reaches for
    # another of `secrets` it keeps working rather than dying on an absent attribute.
    replaced = SimpleNamespace(**vars(secrets) | {"compare_digest": watched})
    monkeypatch.setattr(outcomes, "secrets", replaced)
    forged = secrets.token_urlsafe(32)
    with pytest.raises(ExecutionError) as refused:
        report(db, world, granted.view.execution_id, forged)
    assert refused.value.code == "INVALID_REPORT"
    # Both the stored digest and the presented one, and never the secret itself.
    assert compared == [(secret_digest(grant.report_secret), secret_digest(forged))]
    assert report(db, world, granted.view.execution_id, grant.report_secret).state == "EXECUTED"
    # Once in the first transaction and once under the fence, as every other refusal is.
    assert compared[1:] == [(secret_digest(grant.report_secret),) * 2] * 2


def test_a_secret_from_another_grant_settles_nothing(db, gate_world, admin_engine):
    # A replayed secret: the executor holds this one legitimately, for another execution.
    # The digest is per execution, so a secret settles the one grant that minted it.
    world = gate_world
    tenant = world["identity"].tenant_id
    first, second = targets(admin_engine, world, count=2)
    one = checkpoint(db, world, action=first).view
    two = checkpoint(db, world, action=second).view
    assert one.checkpoint is not None and two.checkpoint is not None
    with pytest.raises(ExecutionError) as refused:
        report(db, world, two.execution_id, one.checkpoint.report_secret)
    assert refused.value.code == "INVALID_REPORT"
    assert [item["state"] for item in impact_rows(admin_engine, tenant)] == ["UNRESOLVED"] * 2
    assert audit_payloads(admin_engine, tenant, "execution.outcome_reported") == []


def test_no_audit_payload_echoes_the_report_secret(db, gate_world, admin_engine):
    world = gate_world
    tenant = world["identity"].tenant_id
    granted = checkpoint(db, world)
    grant = granted.view.checkpoint
    assert grant is not None
    for secret in (secrets.token_urlsafe(32), grant.report_secret):
        try:
            report(db, world, granted.view.execution_id, secret)
        except ExecutionError:
            pass
    # Every refusal is captured, and neither a refusal nor the acceptance beside it
    # carries the one value that settles this execution. The rejection payload is the
    # operation and the reason and names no execution, which is what it has always been.
    reasons = [
        payload["reason"] for payload in audit_payloads(admin_engine, tenant, "execution.rejected")
    ]
    assert reasons == ["INVALID_REPORT"]
    payloads = audit_kinds(admin_engine, tenant)
    assert any(kind == "execution.outcome_reported" for kind, _ in payloads)
    assert not any(grant.report_secret in json.dumps(payload) for _, payload in payloads)
    assert not any(secret_digest(grant.report_secret) in json.dumps(p) for _, p in payloads)


def reported(admin_engine, tenant):
    """Every accepted report the tenant retains, which is what an acceptance amounts to."""
    return audit_payloads(admin_engine, tenant, "execution.outcome_reported")


def unchanged(admin_engine, tenant, execution_id):
    """The grant as the admission left it: state, tier, impact and claim all untouched.

    Filtered to the one execution, as `retained` is, so what it asserts is a property of
    that grant rather than of a tenant that happens to hold only one.
    """
    row = grant_row(admin_engine, tenant, execution_id)
    assert (row["state"], row["settlement_tier"]) == ("DISPATCH_COMMITTED", None)
    assert [
        item["state"]
        for item in impact_rows(admin_engine, tenant)
        if item["execution_id"] == execution_id
    ] == ["UNRESOLVED"]
    assert [
        item["released_at"]
        for item in claim_rows(admin_engine, tenant)
        if item["execution_id"] == execution_id
    ] == [None]


def test_an_attested_execution_settles_exactly_as_a_dispatch_does(db, gate_world, admin_engine):
    world = gate_world
    tenant = world["identity"].tenant_id
    granted = checkpoint(db, world)
    grant = granted.view.checkpoint
    assert grant is not None
    record = signed_record(db, world, granted.view.execution_id)
    view = report(db, world, granted.view.execution_id, grant.report_secret, record=record)
    assert view.state == "EXECUTED"
    row = retained(admin_engine, tenant, granted.view.execution_id)
    assert (row.state, row.tier) == ("EXECUTED", "ATTESTED")
    # Verified evidence confirms the impact and releases the canonical claim, which is
    # what a provider journal does on the path ExecBound dispatches.
    assert (row.impact, row.confirmed_at) == ("CONFIRMED", world["clock"].now())
    assert row.released_at == world["clock"].now()
    # The tier is inside the retained evidence as well as in the column, so an export says
    # what a settlement was worth without joining the execution row.
    assert row.result["tier"] == "ATTESTED"
    assert (row.result["outcome"], row.result["reason"]) == ("EXECUTED", "EXECUTED")
    assert row.result["operation_id"] == str(grant.operation_id)
    (payload,) = reported(admin_engine, tenant)
    assert payload["tier"] == "ATTESTED"
    assert (payload["outcome"], payload["reason"]) == ("EXECUTED", "EXECUTED")
    assert payload["execution_id"] == str(granted.view.execution_id)
    assert payload["operation_id"] == str(grant.operation_id)
    assert payload["plan_hash"] == granted.view.plan_hash
    # An attested report's reported time is inside the record its executor signed, so the
    # capture carries none of its own rather than an unsigned second answer.
    assert payload["reported_at"] is None


@pytest.mark.parametrize(
    "reason,state",
    [
        ("CANCELLED_NOT_EXECUTED", "FAILED_NOT_EXECUTED"),
        ("VERSION_MISMATCH", "STALE_AUTHORIZATION"),
    ],
)
def test_an_attested_non_execution_releases_the_reservation_and_the_claim(
    db, gate_world, admin_engine, reason, state
):
    # The refund an assertion may never have: it is safe here because the executor's
    # statement is authenticated and non-repudiable, which is what the tenant chose when
    # it registered the key. A version mismatch is the stale authorization it is on the
    # dispatch path too.
    world = gate_world
    tenant = world["identity"].tenant_id
    granted = checkpoint(db, world)
    grant = granted.view.checkpoint
    assert grant is not None
    record = signed_record(
        db, world, granted.view.execution_id, outcome="FAILED_NOT_EXECUTED", reason=reason
    )
    view = report(
        db,
        world,
        granted.view.execution_id,
        grant.report_secret,
        record=record,
        outcome="FAILED_NOT_EXECUTED",
        reason=reason,
    )
    assert view.state == state
    row = retained(admin_engine, tenant, granted.view.execution_id)
    assert (row.state, row.tier) == (state, "ATTESTED")
    assert (row.impact, row.confirmed_at) == ("NONEXECUTION", None)
    assert row.released_at == world["clock"].now()
    assert (row.result["tier"], row.result["reason"]) == ("ATTESTED", reason)


def test_an_asserted_execution_confirms_the_impact_and_holds_the_claim(
    db, gate_world, admin_engine
):
    # Charging for an action that may have happened is the safe direction, so an assertion
    # settles the execution and confirms its impact. Releasing the claim is the unsafe one
    # and is not taken: the target stays held, and the scheduled recovery run frees it once
    # the act window has passed
    # (`test_gc7_an_asserted_execution_confirms_the_impact_and_holds_its_target`).
    world = gate_world
    tenant = world["identity"].tenant_id
    granted = checkpoint(db, world)
    grant = granted.view.checkpoint
    assert grant is not None
    # Nothing signed: the executor's authenticated word and nothing ExecBound can check.
    view = report(db, world, granted.view.execution_id, grant.report_secret)
    assert view.state == "EXECUTED"
    row = retained(admin_engine, tenant, granted.view.execution_id)
    assert (row.state, row.tier) == ("EXECUTED", "ASSERTED")
    assert (row.impact, row.confirmed_at) == ("CONFIRMED", world["clock"].now())
    assert row.released_at is None
    assert (row.result["tier"], row.result["outcome"]) == ("ASSERTED", "EXECUTED")
    # The executor's own clock, retained as its word and never as a confirmation time.
    assert datetime.fromisoformat(row.result["reported_at"]) == world["clock"].now()
    assert "proof_digest" not in row.result and "authenticated_record" not in row.result
    (payload,) = reported(admin_engine, tenant)
    assert payload["tier"] == "ASSERTED"
    assert (payload["outcome"], payload["reason"]) == ("EXECUTED", "EXECUTED")
    assert payload["reported_at"] == world["clock"].now().isoformat()


def test_an_asserted_non_execution_is_retained_uncertainty(db, gate_world, admin_engine):
    # A caller that can free its own budget by reporting failure can exceed every limit,
    # so the executor's bare word that nothing happened settles nothing at all.
    world = gate_world
    tenant = world["identity"].tenant_id
    granted = checkpoint(db, world)
    grant = granted.view.checkpoint
    assert grant is not None
    view = report(
        db,
        world,
        granted.view.execution_id,
        grant.report_secret,
        outcome="FAILED_NOT_EXECUTED",
        reason="CANCELLED_NOT_EXECUTED",
    )
    assert view.state == "INDETERMINATE"
    row = retained(admin_engine, tenant, granted.view.execution_id)
    # Nothing is settled, so neither place the tier lives names one.
    assert (row.state, row.tier, row.result) == ("INDETERMINATE", None, None)
    assert (row.impact, row.released_at) == ("UNRESOLVED", None)
    (payload,) = reported(admin_engine, tenant)
    assert (payload["tier"], payload["outcome"]) == ("ASSERTED", "FAILED_NOT_EXECUTED")


def test_an_unknown_result_names_no_tier_and_settles_nothing(db, gate_world, admin_engine):
    # An executor whose vendor call timed out can attest none of the terminal reasons, so
    # its only honest move would otherwise be silence and its profitable one a
    # non-execution. The report says so, at no tier, and is retained as uncertainty with
    # the budget charged and the target held, which is what a lost provider response gets.
    world = gate_world
    tenant = world["identity"].tenant_id
    granted = checkpoint(db, world)
    grant = granted.view.checkpoint
    assert grant is not None
    view = report(
        db, world, granted.view.execution_id, grant.report_secret, outcome="UNKNOWN", reason=None
    )
    assert view.state == "INDETERMINATE"
    row = retained(admin_engine, tenant, granted.view.execution_id)
    assert (row.state, row.tier, row.result) == ("INDETERMINATE", None, None)
    assert (row.impact, row.released_at) == ("UNRESOLVED", None)
    (payload,) = reported(admin_engine, tenant)
    assert (payload["tier"], payload["outcome"], payload["reason"]) == (None, "UNKNOWN", None)


UNCERTAIN = {
    "unknown": {"outcome": "UNKNOWN", "reason": None},
    "non-execution": {"outcome": "FAILED_NOT_EXECUTED", "reason": "CANCELLED_NOT_EXECUTED"},
    "version-mismatch": {"outcome": "FAILED_NOT_EXECUTED", "reason": "VERSION_MISMATCH"},
}
"""Every report body an executor's bare word leaves as uncertainty, named once."""


@pytest.mark.parametrize(
    "changes,impact",
    [({}, "CONFIRMED"), *((body, "UNRESOLVED") for body in UNCERTAIN.values())],
    ids=["execution", *UNCERTAIN],
)
def test_no_asserted_path_releases_a_claim_or_refunds(
    db, gate_world, admin_engine, changes, impact
):
    # The whole asymmetry in one assertion. A refund is the NONEXECUTION impact state,
    # which no limit rule in `store.usage` counts; a released claim is a freed target. An
    # executor that could reach either by speaking would be able to exceed every ceiling
    # and to re-take the target it just claimed to have acted on.
    world = gate_world
    tenant = world["identity"].tenant_id
    granted = checkpoint(db, world)
    grant = granted.view.checkpoint
    assert grant is not None
    report(db, world, granted.view.execution_id, grant.report_secret, **changes)
    row = retained(admin_engine, tenant, granted.view.execution_id)
    assert row.impact == impact
    assert row.released_at is None


@pytest.mark.parametrize(
    "route",
    [
        ("unknown",),
        ("non-execution",),
        ("version-mismatch",),
        ("unknown", "non-execution"),
        ("swept",),
    ],
    ids=[
        "after-an-unknown-result",
        "after-an-asserted-non-execution",
        "after-an-asserted-version-mismatch",
        "after-an-unknown-result-then-a-non-execution",
        "on-a-row-uncertainty-reached-without-a-report",
    ],
)
def test_no_route_to_an_asserted_execution_releases_the_claim(db, gate_world, admin_engine, route):
    # The claim's release is the evidence type and never the row a report arrives at. The
    # test above reports once against a fresh DISPATCH_COMMITTED row, and so does every
    # other assertion in this file, so a release that also fired on INDETERMINATE would
    # pass all of them while handing the executor the release for two sentences instead of
    # one: report an unknown result, then assert success, and the target is free on the
    # executor's bare word. That is the attack of freeing a target on one assertion, reached
    # by a longer road. Every route below ends in the same asserted EXECUTED, and the row it
    # settles is one the executor's own earlier words — or, last, the shape the report-window
    # sweep leaves — put into uncertainty first.
    world = gate_world
    tenant = world["identity"].tenant_id
    action = request(world)
    granted = checkpoint(db, world, action=action)
    grant = granted.view.checkpoint
    assert grant is not None
    for step in route:
        if step == "swept":
            force_state(db, world, granted.view.execution_id, "INDETERMINATE")
        else:
            assert report(
                db, world, granted.view.execution_id, grant.report_secret, **UNCERTAIN[step]
            ).state == ("INDETERMINATE")
    uncertain = retained(admin_engine, tenant, granted.view.execution_id)
    assert (uncertain.state, uncertain.impact, uncertain.released_at) == (
        "INDETERMINATE",
        "UNRESOLVED",
        None,
    )
    view = report(db, world, granted.view.execution_id, grant.report_secret)
    assert view.state == "EXECUTED"
    row = retained(admin_engine, tenant, granted.view.execution_id)
    assert (row.state, row.tier) == ("EXECUTED", "ASSERTED")
    # Charging for an action that may have happened is the safe direction, so the impact
    # confirms; freeing the target on the same word is the unsafe one, so the claim does
    # not move, whatever the row it moved through.
    assert (row.impact, row.confirmed_at) == ("CONFIRMED", world["clock"].now())
    assert row.released_at is None
    # What the held claim is for: the target is still nobody else's to take.
    assert checkpoint(db, world, action=again(action)).view.state == "DENIED"


def test_an_asserted_execution_cannot_free_its_own_target(db, gate_world, admin_engine):
    # The attack this guards against: an executor takes a grant, reports success without
    # acting, and re-requests the same target at once. The claim outlives the report, so the
    # second request is refused while an attested settlement of an identical grant on
    # another target does free it.
    world = gate_world
    tenant = world["identity"].tenant_id
    spoken, attested = targets(admin_engine, world, count=2)
    asserted = checkpoint(db, world, action=spoken).view
    verified = checkpoint(db, world, action=attested).view
    assert asserted.checkpoint is not None and verified.checkpoint is not None
    report(db, world, asserted.execution_id, asserted.checkpoint.report_secret)
    record = signed_record(db, world, verified.execution_id)
    report(db, world, verified.execution_id, verified.checkpoint.report_secret, record=record)
    denied = checkpoint(db, world, action=again(spoken)).view
    assert denied.state == "DENIED"
    regranted = checkpoint(db, world, action=again(attested)).view
    assert (regranted.state, regranted.checkpoint is not None) == ("DISPATCH_COMMITTED", True)
    assert retained(admin_engine, tenant, asserted.execution_id).released_at is None
    assert retained(admin_engine, tenant, verified.execution_id).released_at == (
        world["clock"].now()
    )


def transitions(admin_engine, tenant, state):
    return [
        payload
        for kind, payload in audit_kinds(admin_engine, tenant)
        if kind == "execution.transition" and payload["to_state"] == state
    ]


def test_only_verified_evidence_is_retained_as_terminal_evidence(db, gate_world, admin_engine):
    # Replay treats the presence of terminal evidence as verification, so an assertion is
    # retained under a key of its own: reusing `evidence` would make the executor's word
    # structurally indistinguishable from a provider's proof. The tier is named on the
    # transition exactly where the settlement_tier column is written, so a settlement says
    # what it is worth and an uncertain row claims nothing.
    world = gate_world
    tenant = world["identity"].tenant_id
    proved, spoken, unacted = targets(admin_engine, world, count=3)
    one = checkpoint(db, world, action=proved).view
    two = checkpoint(db, world, action=spoken).view
    three = checkpoint(db, world, action=unacted).view
    assert one.checkpoint is not None and two.checkpoint is not None
    assert three.checkpoint is not None
    record = signed_record(db, world, one.execution_id)
    report(db, world, one.execution_id, one.checkpoint.report_secret, record=record)
    report(db, world, two.execution_id, two.checkpoint.report_secret)
    report(
        db,
        world,
        three.execution_id,
        three.checkpoint.report_secret,
        outcome="FAILED_NOT_EXECUTED",
        reason="CANCELLED_NOT_EXECUTED",
    )
    attested, asserted = transitions(admin_engine, tenant, "EXECUTED")
    assert attested["tier"] == "ATTESTED"
    assert attested["evidence"]["proof_digest"] and "tier" not in attested["evidence"]
    assert "asserted" not in attested
    assert asserted["tier"] == "ASSERTED"
    assert "evidence" not in asserted and asserted["asserted"]["outcome"] == "EXECUTED"
    (uncertain,) = transitions(admin_engine, tenant, "INDETERMINATE")
    assert "evidence" not in uncertain and "tier" not in uncertain
    assert uncertain["asserted"]["reason"] == "CANCELLED_NOT_EXECUTED"


def alternating(world):
    """Five distinct report bodies that each leave an execution exactly where they found it.

    Distinct in outcome, in reason and in the executor's own reported time, because the
    bound this holds is a property of the state machine and not of a body repeated: a
    no-op that compared a report against the one before it would append for every one of
    these while appending nothing for twenty-five identical copies.
    """
    earlier = world["clock"].now() - timedelta(minutes=1)
    return [
        {**UNCERTAIN["unknown"]},
        {**UNCERTAIN["non-execution"]},
        {**UNCERTAIN["unknown"], "reported_at": earlier.isoformat()},
        {**UNCERTAIN["version-mismatch"]},
        {**UNCERTAIN["non-execution"], "reported_at": earlier.isoformat()},
    ]


def test_a_repeated_report_changes_nothing_and_appends_nothing(db, gate_world, admin_engine):
    # What bounds the outcome route's appends. Unbounded, twenty-five valid-secret reports
    # on one grant append twenty-five captures and three UNKNOWN reports on an INDETERMINATE
    # row are all accepted; at the agent rate limit over a day's report window that is
    # hundreds of thousands of chained appends from one leaked secret. A report is recorded
    # exactly when it moves the execution, so one grant can append at most twice: once into
    # uncertainty and once out of it. The reports below alternate rather than repeat,
    # because what must not append is a report that changes nothing and not a report that
    # says the same words.
    world = gate_world
    tenant = world["identity"].tenant_id
    granted = checkpoint(db, world)
    grant = granted.view.checkpoint
    assert grant is not None
    bodies = alternating(world)
    for round_ in range(5):
        for changes in bodies:
            assert report(
                db, world, granted.view.execution_id, grant.report_secret, **changes
            ).state == ("INDETERMINATE")
        assert len(reported(admin_engine, tenant)) == 1, round_
    uncertain = audit_kinds(admin_engine, tenant)
    # The route stays open on an uncertain row, which is the point of leaving it open: the
    # executor that honestly said it did not know can say what happened once it does.
    record = signed_record(db, world, granted.view.execution_id)
    assert report(
        db, world, granted.view.execution_id, grant.report_secret, record=record
    ).state == ("EXECUTED")
    chain = audit_kinds(admin_engine, tenant)
    assert len(chain) > len(uncertain)
    refusals = 0
    for _ in range(5):
        before = audit_kinds(admin_engine, tenant)
        assert report(
            db, world, granted.view.execution_id, grant.report_secret, record=record
        ).state == ("EXECUTED")
        # A no-op appends nothing at all: not a capture, not a transition, not a rejection.
        assert audit_kinds(admin_engine, tenant) == before
        # A settled row is closed to anything that would change it, and each of those is
        # refused rather than discarded, audited as the kernel audits every refused
        # request and bounded by the surfaces' rate limits rather than by this route.
        for changes in bodies:
            with pytest.raises(ExecutionError) as refused:
                report(db, world, granted.view.execution_id, grant.report_secret, **changes)
            assert refused.value.code == "INVALID_STATE"
            refusals += 1
    settled = audit_kinds(admin_engine, tenant)
    assert [kind for kind, _ in settled[len(chain) :]] == ["execution.rejected"] * refusals
    # Two captures for one grant, whatever a leaked secret alternates through its route.
    assert [payload["tier"] for payload in reported(admin_engine, tenant)] == [None, "ATTESTED"]


SETTLED = {
    "an-attested-execution": ({"signed": True}, "EXECUTED", "ATTESTED"),
    "an-asserted-execution": ({}, "EXECUTED", "ASSERTED"),
    "an-attested-non-execution": (
        {"signed": True, **UNCERTAIN["non-execution"]},
        "FAILED_NOT_EXECUTED",
        "ATTESTED",
    ),
    "an-attested-version-mismatch": (
        {"signed": True, **UNCERTAIN["version-mismatch"]},
        "STALE_AUTHORIZATION",
        "ATTESTED",
    ),
}
"""Every settled shape a checkpoint can reach: the report that gets there, its state, its tier."""


@pytest.mark.parametrize("changes,state,tier", list(SETTLED.values()), ids=list(SETTLED))
def test_a_restatement_of_any_settled_outcome_is_answered_and_appends_nothing(
    db, gate_world, admin_engine, changes, state, tier
):
    # The no-op over every settled shape and not only the attested execution. What a
    # restatement must not do is append: the state a report would leave and the state the
    # row carries are one rule, `_terminal_state`, and a second spelling of it that
    # disagreed on any one of these shapes would append a capture for every restatement
    # and then return the row untouched — the two-capture bound gone, silently, for a
    # leaked secret to exploit. The version mismatch is the shape that catches it, since
    # it is the only one whose settled state is not its reported outcome.
    world = gate_world
    tenant = world["identity"].tenant_id
    granted = checkpoint(db, world)
    grant = granted.view.checkpoint
    assert grant is not None
    changes = dict(changes)
    signed = changes.pop("signed", False)
    record = signed_record(db, world, granted.view.execution_id, **changes) if signed else None
    assert report(
        db, world, granted.view.execution_id, grant.report_secret, record=record, **changes
    ).state == (state)
    settled = retained(admin_engine, tenant, granted.view.execution_id)
    assert (settled.state, settled.tier) == (state, tier)
    chain = audit_kinds(admin_engine, tenant)
    for _ in range(3):
        assert report(
            db, world, granted.view.execution_id, grant.report_secret, record=record, **changes
        ).state == (state)
    # Not a capture, not a transition, not a rejection, and nothing moved underneath.
    assert audit_kinds(admin_engine, tenant) == chain
    assert retained(admin_engine, tenant, granted.view.execution_id) == settled
    assert [payload["tier"] for payload in reported(admin_engine, tenant)] == [tier]


@pytest.mark.parametrize(
    "first,second",
    [
        ({}, {"outcome": "FAILED_NOT_EXECUTED", "reason": "CANCELLED_NOT_EXECUTED"}),
        ({}, {"outcome": "UNKNOWN", "reason": None}),
        ({"signed": True}, {}),
        ({}, {"signed": True}),
    ],
    ids=[
        "a-non-execution-after-an-execution",
        "an-unknown-result-after-an-execution",
        "an-assertion-after-attested-evidence",
        "attested-evidence-after-an-assertion",
    ],
)
def test_a_report_that_does_not_restate_a_settled_outcome_is_refused(
    db, gate_world, admin_engine, first, second
):
    # A settled execution has no edge back, so the one secret it ever had settles it once.
    # A repeat is answered because a lost response must not strand a caller, and anything
    # that says something else is refused rather than silently discarded — including
    # attested evidence for an execution already settled on the executor's word, which is
    # a promotion the settlement refuses rather than one to no-op away here.
    world = gate_world
    tenant = world["identity"].tenant_id
    granted = checkpoint(db, world)
    grant = granted.view.checkpoint
    assert grant is not None

    def sent(changes):
        signed = changes.pop("signed", False)
        record = signed_record(db, world, granted.view.execution_id) if signed else None
        return report(
            db, world, granted.view.execution_id, grant.report_secret, record=record, **changes
        )

    opening = sent(dict(first))
    assert opening.state == "EXECUTED"
    before = retained(admin_engine, tenant, granted.view.execution_id)
    chain = audit_kinds(admin_engine, tenant)
    with pytest.raises(ExecutionError) as refused:
        sent(dict(second))
    assert refused.value.code == "INVALID_STATE"
    assert retained(admin_engine, tenant, granted.view.execution_id) == before
    assert [kind for kind, _ in audit_kinds(admin_engine, tenant)[len(chain) :]] == [
        "execution.rejected"
    ]


def test_an_uncertain_checkpoint_stays_reportable_until_it_is_settled(db, gate_world, admin_engine):
    # The route-closing decision, stated as behaviour. Closing an INDETERMINATE row would
    # punish the honest answer of an executor whose vendor call was queued and make
    # silence the better move, since silence keeps the ability to report the truth later.
    world = gate_world
    tenant = world["identity"].tenant_id
    granted = checkpoint(db, world)
    grant = granted.view.checkpoint
    assert grant is not None
    for changes in (UNCERTAIN["unknown"], UNCERTAIN["non-execution"]):
        assert report(
            db, world, granted.view.execution_id, grant.report_secret, **changes
        ).state == ("INDETERMINATE")
    uncertain = retained(admin_engine, tenant, granted.view.execution_id)
    assert (uncertain.impact, uncertain.released_at) == ("UNRESOLVED", None)
    record = signed_record(db, world, granted.view.execution_id)
    view = report(db, world, granted.view.execution_id, grant.report_secret, record=record)
    assert view.state == "EXECUTED"
    row = retained(admin_engine, tenant, granted.view.execution_id)
    assert (row.state, row.tier, row.impact) == ("EXECUTED", "ATTESTED", "CONFIRMED")
    assert row.released_at == world["clock"].now()


def test_an_assertion_never_settles_a_non_execution(db, gate_world, admin_engine):
    # Defence in depth at the one statement that could refund on the executor's word.
    # The route sends an asserted non-execution to INDETERMINATE and never here, so this
    # is the guard that keeps a later caller from reaching the refund by handing `_settle`
    # an assertion it will not settle.
    world = gate_world
    tenant = world["identity"].tenant_id
    granted = checkpoint(db, world)
    assert granted.view.checkpoint is not None
    command = frozen_command(db, world, granted.view.execution_id)
    asserted = AssertedOutcome(
        operation_id=command.operation_id,
        account_id=command.frozen.intent.account_id,
        intent_hash=command.intent_hash,
        plan_hash=command.plan_hash,
        outcome="FAILED_NOT_EXECUTED",
        reason="CANCELLED_NOT_EXECUTED",
        reported_at=world["clock"].now(),
    )
    with db.transaction(tenant) as conn:
        row = store.read(conn, tenant, granted.view.execution_id)
        with pytest.raises(ExecutionError) as refused:
            outcomes._settle(
                conn, row, world["identity"].principal_id, asserted, world["clock"], "TEST"
            )
        assert refused.value.code == "INVALID_STATE"
    unchanged(admin_engine, tenant, granted.view.execution_id)


def test_a_dispatched_execution_settles_at_no_tier(db, world, owner, admin_engine):
    # The column is null for everything ExecBound dispatched: a tier is a statement about
    # an external executor's word, and a provider journal is not one.
    register_key(owner, world)
    gate_bundle(db, world, external_executor=False)
    tenant = world["identity"].tenant_id
    ordinary = dispatched(db, world, admin_engine)
    assert ordinary.ticket is not None
    view = record_outcome(
        db, ordinary.ticket, b"test-journal-proof", FixtureJournal(), world["clock"]
    )
    assert view.state == "EXECUTED"
    row = retained(admin_engine, tenant, ordinary.view.execution_id)
    assert (row.tier, row.impact) == (None, "CONFIRMED")
    assert row.released_at == world["clock"].now()
    assert "tier" not in row.result
    (transition,) = transitions(admin_engine, tenant, "EXECUTED")
    assert "tier" not in transition and "asserted" not in transition


def test_an_unknown_result_carries_no_reason_and_nothing_signed(db, gate_world):
    # No terminal reason names an unknown result, and the executor's record binds a
    # terminal outcome, so nothing it could sign says this either.
    world = gate_world
    granted = checkpoint(db, world)
    grant = granted.view.checkpoint
    assert grant is not None
    signed = report_body(
        world,
        grant.report_secret,
        record=signed_record(db, world, granted.view.execution_id),
        outcome="UNKNOWN",
        reason=None,
    )
    excused = report_body(
        world, grant.report_secret, outcome="UNKNOWN", reason="CANCELLED_NOT_EXECUTED"
    )
    for body in (signed, excused):
        with pytest.raises(ExecutionError) as refused:
            report(db, world, granted.view.execution_id, body=body)
        assert refused.value.code == "INVALID_REQUEST"


def test_a_record_the_kernel_cannot_verify_settles_nothing(db, gate_world, admin_engine, owner):
    world = gate_world
    tenant = world["identity"].tenant_id
    first, second = targets(admin_engine, world, count=2)
    granted = checkpoint(db, world, action=first)
    grant = granted.view.checkpoint
    assert grant is not None
    other = checkpoint(db, world, action=second)
    assert other.view.checkpoint is not None
    stranger = Ed25519PrivateKey.generate()
    genuine = signed_record(db, world, granted.view.execution_id)
    tampered = {**genuine, "signature": "0" * 128}
    relabelled = {**genuine, "key_id": "executor-v2"}
    elsewhere = signed_record(db, world, other.view.execution_id)
    forged = signed_record(db, world, granted.view.execution_id, private_key=stranger)
    for record in (tampered, relabelled, elsewhere, forged):
        with pytest.raises(ExecutionError) as refused:
            report(db, world, granted.view.execution_id, grant.report_secret, record=record)
        assert refused.value.code == "INVALID_RECORD"
    assert reported(admin_engine, tenant) == []
    # The genuine record for this grant still attests, so each refusal was about the
    # record and never about the route.
    assert report(
        db, world, granted.view.execution_id, grant.report_secret, record=genuine
    ).state == ("EXECUTED")
    assert [payload["tier"] for payload in reported(admin_engine, tenant)] == ["ATTESTED"]


def test_a_record_contradicting_the_report_is_refused(db, gate_world, admin_engine):
    # The signed record is the statement. A body saying one thing beside a record saying
    # another would be audited as the first and settled as the second.
    world = gate_world
    tenant = world["identity"].tenant_id
    granted = checkpoint(db, world)
    grant = granted.view.checkpoint
    assert grant is not None
    record = signed_record(
        db,
        world,
        granted.view.execution_id,
        outcome="FAILED_NOT_EXECUTED",
        reason="CANCELLED_NOT_EXECUTED",
    )
    with pytest.raises(ExecutionError) as refused:
        report(db, world, granted.view.execution_id, grant.report_secret, record=record)
    assert refused.value.code == "INVALID_RECORD"
    assert reported(admin_engine, tenant) == []
    agreed = report_body(
        world,
        grant.report_secret,
        record=record,
        outcome="FAILED_NOT_EXECUTED",
        reason="CANCELLED_NOT_EXECUTED",
    )
    assert report(db, world, granted.view.execution_id, body=agreed).state == "FAILED_NOT_EXECUTED"
    (payload,) = reported(admin_engine, tenant)
    assert (payload["tier"], payload["outcome"]) == ("ATTESTED", "FAILED_NOT_EXECUTED")


def malformed(db, world, admin_engine, changes):
    """One change to an otherwise valid report, refused as a request and settling nothing."""
    granted = checkpoint(db, world)
    grant = granted.view.checkpoint
    assert grant is not None
    body = {**report_body(world, grant.report_secret), **changes}
    with pytest.raises(ExecutionError) as refused:
        report(db, world, granted.view.execution_id, body=body)
    assert refused.value.code == "INVALID_REQUEST"
    unchanged(admin_engine, world["identity"].tenant_id, granted.view.execution_id)


@pytest.mark.parametrize(
    "changes",
    [
        {"reason": None},
        {"outcome": "FAILED_NOT_EXECUTED", "reason": "EXECUTED"},
        {"reason": "CANCELLED_NOT_EXECUTED"},
    ],
    ids=[
        "terminal-without-a-reason",
        "disagreeing-outcome-and-reason",
        "execution-with-a-nonexecution-reason",
    ],
)
def test_a_report_states_a_terminal_outcome_with_its_reason_or_neither(
    db, gate_world, admin_engine, changes
):
    malformed(db, gate_world, admin_engine, changes)


@pytest.mark.parametrize(
    "changes",
    [{"tier": "ATTESTED"}, {"operation_id": str(uuid4())}, {"act": "eb1.act"}],
    ids=["caller-named-tier", "caller-named-operation", "caller-presented-act-grant"],
)
def test_a_report_names_no_tier_no_operation_and_presents_no_act_grant(
    db, gate_world, admin_engine, changes
):
    # The tier is what ExecBound could check and the operation is the frozen command's, so
    # a caller names neither. The act grant is not a second authenticator either: the
    # report window outlives the act window, so the secret is the whole of a report's
    # authority and an act token beside it is an unknown field rather than an alternative.
    malformed(db, gate_world, admin_engine, changes)


@pytest.mark.parametrize(
    "changes",
    [{"report_secret": "short"}, {"report_secret": None}],
    ids=["malformed-secret", "absent-secret"],
)
def test_a_report_presents_a_secret_of_the_shape_its_grant_minted(
    db, gate_world, admin_engine, changes
):
    # The secret is the whole of a report's authority and its shape is the grant's, so a
    # body carrying a short one or none is not a report at all.
    malformed(db, gate_world, admin_engine, changes)


@pytest.mark.parametrize(
    "body",
    [b"", b"{", b'{"report_secret": "' + b"s" * 43 + b'"}', b"[]", b"null"],
    ids=["empty", "truncated", "missing-outcome", "array", "null"],
)
def test_a_malformed_report_is_refused_without_reaching_the_execution(
    db, gate_world, body, monkeypatch
):
    world = gate_world
    granted = checkpoint(db, world)

    def never(conn, tenant_id, execution_id):
        # `store.read` is the route's only way to the execution, so watching it is what
        # makes the name's claim true rather than incidental: moving the parse after the
        # read and before the principal check leaves the refusal code exactly as it is,
        # and only this fails. The module is replaced with one name swapped, so every
        # other call `report_outcome` makes into the store still goes through.
        raise AssertionError("A malformed report reached the execution row")

    monkeypatch.setattr(outcomes, "store", SimpleNamespace(**vars(store) | {"read": never}))
    with pytest.raises(ExecutionError) as refused:
        report_outcome(
            db,
            world["identity"],
            granted.view.execution_id,
            body,
            verifier_for=executor_verifier,
            clock=world["clock"],
        )
    assert refused.value.code == "INVALID_REQUEST"


def test_a_reported_time_accompanies_exactly_a_report_with_no_record(db, gate_world):
    world = gate_world
    granted = checkpoint(db, world)
    grant = granted.view.checkpoint
    assert grant is not None
    record = signed_record(db, world, granted.view.execution_id)
    beside = report_body(world, grant.report_secret, record=record)
    beside["reported_at"] = world["clock"].now().isoformat()
    without = report_body(world, grant.report_secret)
    without.pop("reported_at")
    for body in (beside, without):
        with pytest.raises(ExecutionError) as refused:
            report(db, world, granted.view.execution_id, body=body)
        assert refused.value.code == "INVALID_REQUEST"


def test_the_outcome_route_shares_the_runtimes_capacity_bound(db, gate_world):
    # An executor spamming reports must not serialize a tenant's writers or take more of
    # the deployment than the agent path it already holds a credential for.
    world = gate_world
    runtime = Runtime(db, [], clock=world["clock"], concurrency=1)
    view = runtime.execute(world["identity"], request(world).model_dump_json().encode())
    assert view.checkpoint is not None
    body = json.dumps(report_body(world, view.checkpoint.report_secret)).encode()
    assert runtime._capacity.acquire(blocking=False)
    with pytest.raises(ExecutionError) as refused:
        runtime.report(world["identity"], view.execution_id, body)
    assert refused.value.code == "BUSY"
    runtime._capacity.release()
    # Released on the way out, so an accepted report does not cost the deployment a slot.
    assert runtime.report(world["identity"], view.execution_id, body).state == "EXECUTED"
    assert runtime._capacity.acquire(blocking=False)


def test_the_ticket_paths_refuse_a_checkpoint(db, gate_world, admin_engine, monkeypatch):
    # Defence in depth, and the reason it is owed: a grant stamps the attempt and stays
    # DISPATCH_COMMITTED, which is what both paths require, and its report secret's digest
    # sits in the column their owner check compares against, so a ticket built from a
    # secret the executor legitimately holds satisfies every test each one made.
    world = gate_world
    tenant = world["identity"].tenant_id
    granted = checkpoint(db, world)
    grant = granted.view.checkpoint
    assert grant is not None
    ticket = DispatchTicket(tenant, granted.view.execution_id, grant.report_secret)
    record = signed_record(db, world, granted.view.execution_id)

    def never(command, raw, verifier):
        # Evidence verification is an adapter boundary that may contact a provider about
        # the operation it names, and a grant names one ExecBound never dispatched.
        raise AssertionError("A checkpoint reached the journal verifier")

    monkeypatch.setattr(outcomes, "_proof", never)
    with pytest.raises(ExecutionError) as recorded:
        record_outcome(
            db,
            ticket,
            json.dumps(record).encode(),
            _verifier(db, world, granted.view.execution_id),
            world["clock"],
        )
    assert recorded.value.code == "INVALID_STATE"
    with pytest.raises(ExecutionError) as marked:
        mark_indeterminate(db, ticket, world["clock"])
    assert marked.value.code == "INVALID_STATE"
    unchanged(admin_engine, tenant, granted.view.execution_id)


def test_a_grant_is_never_settled_from_a_providers_journal(
    db, gate_world, admin_engine, monkeypatch
):
    # `reconcile` is the one connector-free path that reaches `_settle`, and the operator
    # controls that lately arrived at it counts as absent executor evidence: the activity
    # console renders its reconcile control for every DISPATCH_COMMITTED row, which is
    # every live grant, and `human.py` and `cli.py` both look the account up in the live
    # connector inventory, so an operator who adds a connector for a Gate account after
    # the grant was issued reaches `reconcile_operation` with `cancel_if_missing` and
    # settles the grant FAILED_NOT_EXECUTED from `connector.cancel` evidence — a refund
    # and a released claim on a report the executor never made, which is never allowed.
    # Admission refuses a Gate mapping on a connected account, but that is a fact about
    # the runtime's inventory at admission and configuration can change it afterwards, so
    # the refusal is here rather than resting on the inventory.
    world = gate_world
    tenant = world["identity"].tenant_id
    granted = checkpoint(db, world)
    assert granted.view.checkpoint is not None

    def never(command, evidence, verifier):
        # The refusal is made in the first transaction as well as under the fence, for the
        # reason the route's own refusals are: evidence verification is an adapter
        # boundary whose comment says a future adapter may contact a journal, and a grant
        # must never send a provider a question about an operation ExecBound never
        # dispatched. Removing only the fenced guard still refuses the settlement, so
        # nothing but this says why the first one is there.
        raise AssertionError("A checkpoint reached the provider's evidence verifier")

    monkeypatch.setattr(reconciliation, "_proof", never)
    with pytest.raises(ExecutionError) as refused:
        reconcile(
            db,
            world["admin"],
            granted.view.execution_id,
            reason="operator cancelled the vendor job",
            evidence=b"test-journal-proof",
            verifier=FixtureJournal("FAILED_NOT_EXECUTED"),
            clock=world["clock"],
        )
    assert refused.value.code == "INVALID_STATE"
    unchanged(admin_engine, tenant, granted.view.execution_id)
    # The administrator exit is not foreclosed by the refusal: the same call
    # with the executor's own signed record and the verifier that checks it settles.
    monkeypatch.undo()
    record = json.dumps(signed_record(db, world, granted.view.execution_id)).encode()
    exited = reconcile(
        db,
        world["admin"],
        granted.view.execution_id,
        reason="settled from the executor's signed record",
        evidence=record,
        verifier=_verifier(db, world, granted.view.execution_id),
        clock=world["clock"],
    )
    assert exited.state == "EXECUTED"
    # The administrator exit settles at the tier its evidence supports, exactly as the
    # route does: the row it reached is a checkpoint and the verifier that checked the
    # record is the one that attests an external executor, so it can be nothing else.
    row = retained(admin_engine, tenant, granted.view.execution_id)
    assert (row.tier, row.result["tier"]) == ("ATTESTED", "ATTESTED")
    assert (row.impact, row.released_at) == ("CONFIRMED", world["clock"].now())


@pytest.mark.parametrize(
    "module,settle",
    [
        pytest.param(
            reconciliation,
            lambda db, world, ordinary: reconcile(
                db,
                world["admin"],
                ordinary.view.execution_id,
                reason="verified cancellation tombstone",
                evidence=b"test-journal-proof",
                verifier=FixtureJournal("FAILED_NOT_EXECUTED"),
                clock=world["clock"],
            ),
            id="reconcile",
        ),
        pytest.param(
            outcomes,
            lambda db, world, ordinary: record_outcome(
                db, ordinary.ticket, b"test-journal-proof", FixtureJournal(), world["clock"]
            ),
            id="record_outcome",
        ),
    ],
)
def test_a_row_marked_a_checkpoint_while_its_evidence_verified_is_refused_under_the_fence(
    db, world, owner, admin_engine, monkeypatch, module, settle
):
    # Why every settlement path reads the marker twice, the outcome route's own refusals
    # included: evidence is verified between the two transactions, so what decides is the
    # fenced read and not the state the first one saw. Only the owner connection can move
    # the column, which is what makes the second read observable at all.
    register_key(owner, world)
    gate_bundle(db, world, external_executor=False)
    tenant = world["identity"].tenant_id
    ordinary = dispatched(db, world, admin_engine)
    verified = module._proof

    def mark_first(command, raw, verifier):
        set_report_window(
            admin_engine, tenant, ordinary.view.execution_id, world["clock"].now() + REPORT_WINDOW
        )
        return verified(command, raw, verifier)

    monkeypatch.setattr(module, "_proof", mark_first)
    with pytest.raises(ExecutionError) as refused:
        settle(db, world, ordinary)
    assert refused.value.code == "INVALID_STATE"
    unchanged(admin_engine, tenant, ordinary.view.execution_id)


def _verifier(db, world, execution_id):
    """The verifier the outcome route would build, handed to the ticket path instead."""
    tenant = world["identity"].tenant_id
    with db.transaction(tenant) as conn:
        return executor_verifier(conn, store.read(conn, tenant, execution_id))


@pytest.fixture
def gate_api(db, gate_world, seeded):
    """A deployment serving Gate alone: the agent surfaces with no connector at all."""
    with TestClient(create_app(db, runtime=gate_runtime(db, gate_world))) as client:
        client.headers["Authorization"] = "Bearer " + seeded["tokens"][0]
        yield client


def test_the_route_accepts_a_report_and_refuses_one_that_does_not_authenticate(
    gate_api, db, gate_world, admin_engine
):
    world = gate_world
    tenant = world["identity"].tenant_id
    body = request(world).model_dump(mode="json")
    answered = gate_api.post("/v1/execute", json=body)
    assert answered.status_code == 202
    described = answered.json()["checkpoint"]["grant"]
    path = "/v1/executions/" + answered.json()["execution_id"] + "/outcome"
    forged = report_body(world, secrets.token_urlsafe(32))
    assert gate_api.post(path, json=forged).status_code == 403
    assert gate_api.post(path, json={"report_secret": described["report_secret"]}).status_code == (
        400
    )
    # An execution id that is not one, and a record the tenant's keys do not attest:
    # neither is a dependency failure the caller should be invited to retry.
    unsigned = report_body(
        world,
        described["report_secret"],
        record={
            **signed_record(db, world, UUID(answered.json()["execution_id"])),
            "signature": "0" * 128,
        },
    )
    assert gate_api.post("/v1/executions/not-a-uuid/outcome", json=forged).status_code == 400
    assert gate_api.post(path, json=unsigned).status_code == 400
    # The status follows the state the report left, as every execution answer does: 202
    # while the execution is still in flight, 200 once it is settled.
    uncertain = report_body(world, described["report_secret"], outcome="UNKNOWN", reason=None)
    answered = gate_api.post(path, json=uncertain)
    assert (answered.status_code, answered.json()["state"]) == (202, "INDETERMINATE")
    accepted = gate_api.post(path, json=report_body(world, described["report_secret"]))
    assert accepted.status_code == 200
    assert accepted.json()["state"] == "EXECUTED"
    # The report is not a grant: the answer is the ordinary view, with no second act and
    # no secret re-served to whoever asked last.
    assert "checkpoint" not in accepted.json()
    assert [payload["tier"] for payload in reported(admin_engine, tenant)] == [None, "ASSERTED"]


def test_the_route_answers_another_tenants_execution_as_missing(gate_api, db, gate_world, seeded):
    world = gate_world
    answered = gate_api.post("/v1/execute", json=request(world).model_dump(mode="json"))
    described = answered.json()["checkpoint"]["grant"]
    path = "/v1/executions/" + answered.json()["execution_id"] + "/outcome"
    # Another tenant's credential entirely: the row is not readable and the secret it
    # presents is the right one.
    gate_api.headers["Authorization"] = "Bearer " + seeded["tokens"][1]
    refused = gate_api.post(path, json=report_body(world, described["report_secret"]))
    assert refused.status_code == 404
    assert refused.json()["code"] == "NOT_FOUND"


def test_a_row_settled_while_a_record_was_verified_is_refused_under_the_fence(
    db, gate_world, admin_engine, monkeypatch
):
    # The unfenced verification runs between the two transactions, so the row can move
    # under a report while its signature is being checked. What decides is the fenced
    # read, ordered against every other writer, and not the one that gathered the command.
    #
    # A record is what opens that window in this process at all: an unsigned report checks
    # nothing between the transactions, so the state it finds and the state it settles are
    # read under the same fence. The row can still move between the two transactions
    # either way, and this fenced read is what refuses it either way.
    world = gate_world
    tenant = world["identity"].tenant_id
    granted = checkpoint(db, world)
    grant = granted.view.checkpoint
    assert grant is not None
    verified = outcomes._reported

    def settle_first(command, report, verifier):
        force_state(db, world, granted.view.execution_id, "EXECUTED")
        return verified(command, report, verifier)

    record = signed_record(db, world, granted.view.execution_id)
    monkeypatch.setattr(outcomes, "_reported", settle_first)
    with pytest.raises(ExecutionError) as refused:
        report(db, world, granted.view.execution_id, grant.report_secret, record=record)
    assert refused.value.code == "INVALID_STATE"
    assert reported(admin_engine, tenant) == []


@pytest.mark.parametrize(
    "code,status",
    [("INVALID_REPORT", 403), ("INVALID_RECORD", 400), ("REPORT_WINDOW_CLOSED", 409)],
)
def test_a_refused_report_is_the_callers_own_and_never_a_dependency_failure(code, status):
    # The default is 503, which asks the caller to retry: a report that did not
    # authenticate, a record that did not verify and a window that has closed are all
    # permanent and the caller's own, and a closed window's remedy is the administrator.
    assert error_status(ExecutionError(code)) == status


def test_the_tier_and_its_evidence_cannot_disagree():
    # A tier is what ExecBound could check, so one carrying the other tier's evidence, or
    # none at all, would name a guarantee nothing behind it supports.
    proof = TerminalEvidence(
        operation_id=uuid4(),
        account_id=uuid4(),
        intent_hash="a" * 64,
        plan_hash="b" * 64,
        outcome="EXECUTED",
        reason="EXECUTED",
        proof_digest="c" * 64,
        authenticated_record="{}",
    )
    asserted = AssertedOutcome(
        operation_id=proof.operation_id,
        account_id=proof.account_id,
        intent_hash=proof.intent_hash,
        plan_hash=proof.plan_hash,
        outcome="EXECUTED",
        reason="EXECUTED",
        reported_at=GRANTED_AT,
    )
    for fields in (
        {"tier": "ATTESTED"},
        {"tier": "ASSERTED"},
        {"tier": None, "proof": proof},
        {"tier": None, "asserted": asserted},
        {"tier": "ATTESTED", "asserted": asserted},
        {"tier": "ASSERTED", "proof": proof},
        {"tier": "ATTESTED", "proof": proof, "asserted": asserted},
    ):
        with pytest.raises(ValueError, match="tier carries exactly its own evidence"):
            ReportedOutcome(**fields)
    # An unknown result names no tier and answers for neither model.
    unknown = ReportedOutcome(None)
    assert (unknown.outcome, unknown.reason) == ("UNKNOWN", None)
    assert ReportedOutcome("ATTESTED", proof=proof).reason == "EXECUTED"
    assert ReportedOutcome("ASSERTED", asserted=asserted).outcome == "EXECUTED"


def test_a_key_revoked_after_the_grant_attests_it_and_one_revoked_before_does_not(
    db, gate_world, owner, admin_engine
):
    # The revocation window is judged against the instant ExecBound issued the grant,
    # which the route reads from the execution row and never from the executor's own
    # record, so rotating or revoking a key never invalidates a proof for a grant issued
    # while it was current and a retired key never speaks for a later one.
    world = gate_world
    tenant, admin = world["identity"].tenant_id, world["admin"].principal_id
    opened = world["clock"].now()
    retired = register_keypair(owner, world, key_id="executor-retired")
    administration.revoke_executor_key(owner, tenant, "executor-retired", admin, now=opened)
    world["clock"].value = opened + timedelta(minutes=1)
    granted = checkpoint(db, world)
    grant = granted.view.checkpoint
    assert grant is not None
    assert grant_row(admin_engine, tenant, granted.view.execution_id)["dispatch_attempted_at"] == (
        world["clock"].now()
    )
    stale = signed_record(
        db, world, granted.view.execution_id, private_key=retired, key_id="executor-retired"
    )
    with pytest.raises(ExecutionError) as refused:
        report(db, world, granted.view.execution_id, grant.report_secret, record=stale)
    assert refused.value.code == "INVALID_RECORD"
    # The grant's own key is retired after it was issued, and a retirement must never
    # invalidate what the key already attests.
    register_key(owner, world, key_id="executor-next")
    world["clock"].value = opened + timedelta(minutes=2)
    administration.revoke_executor_key(owner, tenant, GATE_KEY_ID, admin, now=world["clock"].now())
    record = signed_record(db, world, granted.view.execution_id)
    assert report(
        db, world, granted.view.execution_id, grant.report_secret, record=record
    ).state == ("EXECUTED")
    assert [payload["tier"] for payload in reported(admin_engine, tenant)] == ["ATTESTED"]


def test_a_key_revoked_while_an_approval_was_pending_never_attests_the_grant(
    db, world, owner, admin_engine
):
    # The grant instant is the attempt, and on the approval path that is not the insert.
    # `created_at` is stamped when the request is first admitted and answered
    # PENDING_APPROVAL; `dispatch_attempted_at` is stamped in the reserve tail, which runs
    # only on the retry after a human decides, so the two are as far apart as the human
    # took. A key the tenant rotated away from in between never covered the grant that
    # followed it, and a verifier reading the insert would accept it.
    tenant, admin = world["identity"].tenant_id, world["admin"].principal_id
    opened = world["clock"].now()
    compromised = register_keypair(owner, world)
    gate_bundle(db, world, approval_policies=APPROVAL)
    pending = checkpoint(db, world)
    assert (pending.view.state, pending.view.checkpoint) == ("PENDING_APPROVAL", None)
    # The tenant rotates after a compromise while the human is still deciding. The new key
    # keeps the bundle loadable, which is what the mapping's own validation requires.
    world["clock"].value = opened + timedelta(seconds=30)
    register_key(owner, world, key_id="executor-next")
    administration.revoke_executor_key(owner, tenant, GATE_KEY_ID, admin, now=world["clock"].now())
    world["clock"].value = opened + timedelta(seconds=60)
    decide_approval(db, world["human"], pending.view.approval_id, "APPROVE", world["clock"])
    granted = checkpoint(db, world)
    grant = granted.view.checkpoint
    assert grant is not None and granted.view.execution_id == pending.view.execution_id
    row = grant_row(admin_engine, tenant, granted.view.execution_id)
    # The two instants a verifier could read, a revocation apart, on one real row.
    assert (row["created_at"], row["dispatch_attempted_at"]) == (
        opened,
        opened + timedelta(seconds=60),
    )
    stale = signed_record(
        db, world, granted.view.execution_id, private_key=compromised, key_id=GATE_KEY_ID
    )
    with pytest.raises(ExecutionError) as refused:
        report(db, world, granted.view.execution_id, grant.report_secret, record=stale)
    assert refused.value.code == "INVALID_RECORD"
    assert grant_row(admin_engine, tenant, granted.view.execution_id)["settlement_tier"] is None
    assert [payload["tier"] for payload in reported(admin_engine, tenant)] == []


def test_a_key_registered_after_the_grant_attests_nothing(db, gate_world, owner, admin_engine):
    # The key-window rule (`docs/CHECKPOINT.md`, "Executor keys") is symmetric: a revoked
    # key speaks for a grant issued while it was current, which means a key must have
    # existed to speak for one at all. Rotating after a compromise otherwise hands the
    # replacement retroactive authority over every grant it never covered, and the ATTESTED
    # tier's whole worth is that the executor cannot repudiate the statement — which it
    # could, of a key it was not yet holding.
    world = gate_world
    tenant = world["identity"].tenant_id
    opened = world["clock"].now()
    (target,) = targets(admin_engine, world, count=1)
    patient = long_lived_agent(admin_engine, db, world)
    granted = checkpoint(db, world, patient, action=target)
    grant = granted.view.checkpoint
    assert grant is not None
    world["clock"].value = opened + timedelta(hours=1)
    later = register_keypair(owner, world, key_id="executor-later")
    record = signed_record(
        db, world, granted.view.execution_id, private_key=later, key_id="executor-later"
    )
    with pytest.raises(ExecutionError) as refused:
        report(db, world, granted.view.execution_id, grant.report_secret, patient, record=record)
    assert refused.value.code == "INVALID_RECORD"
    assert grant_row(admin_engine, tenant, granted.view.execution_id)["settlement_tier"] is None
    # The key the tenant held when the grant was issued still attests it, so the refusal
    # is about registration order and not about having rotated at all.
    current = signed_record(db, world, granted.view.execution_id)
    assert report(
        db, world, granted.view.execution_id, grant.report_secret, patient, record=current
    ).state == ("EXECUTED")
    assert [payload["tier"] for payload in reported(admin_engine, tenant)] == ["ATTESTED"]


def test_a_tenant_whose_last_key_is_cut_off_grants_nothing_new(db, gate_world, owner, admin_engine):
    """Cutting off the last key is allowed, so admission is what keeps the result safe.

    `administration._keep_attestable` refuses to retire a tenant's last live key while its
    active bundle declares an external executor, and reporting a compromise deliberately
    bypasses that: an operator who cannot cut off a stolen key because it is the last one
    is worse off than before. Admission reads the active bundle through
    `store.active_bundle`, which does not re-run the component validation that requires a
    registered key, so without the check this test pins the tenant would go on issuing
    grants nothing could attest. It fails closed instead, and registering a replacement is
    what restores it — which under the key-window rule gives that replacement no authority
    over the grants the cut-off key covered.
    """
    world = gate_world
    tenant, admin = world["identity"].tenant_id, world["admin"].principal_id
    first, second, third = targets(admin_engine, world, count=3)
    granted = checkpoint(db, world, action=first)
    assert granted.view.checkpoint is not None
    administration.report_executor_key_compromise(
        owner, tenant, GATE_KEY_ID, admin, now=world["clock"].now()
    )
    with pytest.raises(ExecutionError) as refused:
        checkpoint(db, world, action=second)
    assert refused.value.code == "INVALID_BUNDLE"
    assert execution_states(admin_engine, tenant) == ["DISPATCH_COMMITTED"]
    assert len(impact_rows(admin_engine, tenant)) == len(claim_rows(admin_engine, tenant)) == 1
    # The grant already issued is not recalled, so its holder is still described its act:
    # the emergency stop cannot recall an issued grant, and a key ring change is no
    # stronger.
    retry = checkpoint(db, world, action=first)
    assert retry.view.execution_id == granted.view.execution_id
    assert retry.view.checkpoint is not None and retry.view.checkpoint.regranted is True
    # An observing tenant reserves nothing and grants nothing, so it keeps its own answer.
    set_enforcement_mode(db, world["admin"], "OBSERVE", "Onboarding", world["clock"])
    assert checkpoint(db, world, action=second).view.state == "OBSERVED"
    set_enforcement_mode(db, world["admin"], "ENFORCE", "Onboarding done", world["clock"])
    register_key(owner, world, key_id="executor-next")
    assert checkpoint(db, world, action=third).view.checkpoint is not None


def test_a_compromised_key_attests_nothing_it_was_holding(db, gate_world, owner, admin_engine):
    """The one revocation that is not backward-permissive, over the route that settles.

    An ordinary retirement has to keep attesting the grants it covered, or every rotation
    would invalidate every outstanding proof — the key-window rule, and the test two above.
    That is exactly what left a stolen key attesting every grant it was holding for the rest
    of each twenty-four-hour report window, and the worst of it is not a false execution but
    a signed non-execution: it settles FAILED_NOT_EXECUTED, refunds the reservation and
    releases the canonical claim, on the word of whoever holds the key. Recording the
    revocation as a compromise refuses the key here, at the verifier every attested
    settlement reads, rather than moving the execution to a state that route already
    accepts.

    The two keys in this ring covered the same grant and are revoked at one instant. The
    compromised one attests nothing; the retired one still settles it, so what the refusal
    is about is the key and never the grant.
    """
    world = gate_world
    tenant, admin = world["identity"].tenant_id, world["admin"].principal_id
    opened = world["clock"].now()
    retired = register_keypair(owner, world, key_id="executor-retired")
    (target,) = targets(admin_engine, world, count=1)
    granted = checkpoint(db, world, action=target)
    grant = granted.view.checkpoint
    assert grant is not None
    execution_id = granted.view.execution_id
    world["clock"].value = opened + timedelta(minutes=1)
    administration.revoke_executor_key(
        owner, tenant, "executor-retired", admin, now=world["clock"].now()
    )
    administration.report_executor_key_compromise(
        owner, tenant, GATE_KEY_ID, admin, now=world["clock"].now()
    )
    # The refund: a signed non-execution is what would release the claim and hand the
    # reservation back, so it is the report the stolen key would actually send.
    for changes in (
        {"outcome": "FAILED_NOT_EXECUTED", "reason": "CANCELLED_NOT_EXECUTED"},
        {},
    ):
        stolen = signed_record(db, world, execution_id, **changes)
        with pytest.raises(ExecutionError) as refused:
            report(db, world, execution_id, grant.report_secret, record=stolen, **changes)
        assert refused.value.code == "INVALID_RECORD"
        unchanged(admin_engine, tenant, execution_id)
    assert reported(admin_engine, tenant) == []
    # The key retired in the ordinary way, in the same minute, still speaks for this grant.
    record = signed_record(db, world, execution_id, private_key=retired, key_id="executor-retired")
    assert report(db, world, execution_id, grant.report_secret, record=record).state == "EXECUTED"
    row = retained(admin_engine, tenant, execution_id)
    assert (row.state, row.tier) == ("EXECUTED", "ATTESTED")
    assert [payload["tier"] for payload in reported(admin_engine, tenant)] == ["ATTESTED"]


def test_a_key_rotated_away_before_the_theft_was_confirmed_attests_nothing_after(
    db, gate_world, owner, admin_engine
):
    """Rotate-first, then confirm: the order incident response actually runs in.

    An operator who suspects a key does not wait to be sure — the key is rotated or
    revoked at once and the theft confirmed afterwards. Recording the compromise only over
    a live key refused that operator at exactly the moment the remedy was needed, and what
    the refusal left standing is what this test now denies: the retired key attesting
    every grant it was holding, for the rest of each grant's report window.
    """
    world = gate_world
    tenant, admin = world["identity"].tenant_id, world["admin"].principal_id
    opened = world["clock"].now()
    (target,) = targets(admin_engine, world, count=1)
    granted = checkpoint(db, world, action=target)
    grant = granted.view.checkpoint
    assert grant is not None
    execution_id = granted.view.execution_id
    # The rotation an operator performs on suspicion: the stolen key is retired a minute
    # after the grant, and the replacement covers none of it (the key-window rule).
    world["clock"].value = opened + timedelta(minutes=1)
    # The private half of the replacement is kept, so the last report below fails for the
    # reason the key-window rule gives and not for an unverifiable signature.
    replacement_key = Ed25519PrivateKey.generate()
    administration.rotate_executor_key(
        owner,
        tenant,
        GATE_KEY_ID,
        "executor-next",
        replacement_key.public_key().public_bytes_raw().hex(),
        admin,
        now=world["clock"].now(),
    )
    # The confirmation, after the rotation: what matters is the order and not the gap,
    # which is minutes here only because the agent credential the report is made on has
    # its own lifetime.
    world["clock"].value = opened + timedelta(minutes=2)
    administration.report_executor_key_compromise(
        owner, tenant, GATE_KEY_ID, admin, now=world["clock"].now()
    )
    # The refund is what the thief would actually send: a signed non-execution settles
    # FAILED_NOT_EXECUTED, hands the reservation back and releases the canonical claim.
    for changes in ({"outcome": "FAILED_NOT_EXECUTED", "reason": "CANCELLED_NOT_EXECUTED"}, {}):
        stolen = signed_record(db, world, execution_id, **changes)
        with pytest.raises(ExecutionError) as refused:
            report(db, world, execution_id, grant.report_secret, record=stolen, **changes)
        assert refused.value.code == "INVALID_RECORD"
        unchanged(admin_engine, tenant, execution_id)
    assert reported(admin_engine, tenant) == []
    # What the tenant is left with is retained uncertainty and not a release: the grant
    # the cut-off key alone could have attested has no settlement, which is the direction
    # the contract requires. The replacement is genuinely signed and attests none of it,
    # because it was registered after the grant and never covered it (the key-window rule).
    replacement = signed_record(
        db, world, execution_id, private_key=replacement_key, key_id="executor-next"
    )
    with pytest.raises(ExecutionError) as after:
        report(db, world, execution_id, grant.report_secret, record=replacement)
    assert after.value.code == "INVALID_RECORD"
    unchanged(admin_engine, tenant, execution_id)


class RingChangeDuringVerification:
    """The tenant's own verifier, with a key ring change landing in the window it opens.

    Verification runs between the route's two transactions, so a change recorded from
    inside ``verify`` commits in exactly the window a settlement resting on the first,
    unfenced ring read could not see. Which change it is, is the caller's: a compromise is
    retroactive and must be seen, an ordinary retirement is not and must not be.
    """

    attests_external_execution = True

    def __init__(self, verifier, change):
        self._verifier, self._change = verifier, change

    def verify(self, command, evidence):
        self._change()
        return self._verifier.verify(command, evidence)

    def verified_tier(self, proof):
        # The wrapped verifier's own answer, so what decides the outcome is the ring change
        # and never a verifier that states no tier.
        return self._verifier.verified_tier(proof)


def test_a_compromise_committing_while_a_report_verifies_settles_nothing(
    db, gate_world, owner, admin_engine
):
    """The cut-off is asked under the fence, so a report in flight cannot outrun it.

    The key ring used to be read in the first, unfenced transaction and the verifier built
    from it carried into the fenced one, which re-read the row and settled with a ring
    read before the fence was taken. An attacker holding a stolen key can keep reports in
    flight across every grant it is holding, so landing inside that window is retrying
    rather than luck, and what landed there settled ATTESTED with the claim released.

    The direction stays one-way, and the test below holds that half: a retirement landing
    in the same window still attests the grant it covered, because both of a key's own
    instants are weighed against ``dispatch_attempted_at`` and that is stamped once.
    """
    world = gate_world
    tenant, admin = world["identity"].tenant_id, world["admin"].principal_id
    (target,) = targets(admin_engine, world, count=1)
    granted = checkpoint(db, world, action=target)
    grant = granted.view.checkpoint
    assert grant is not None
    execution_id = granted.view.execution_id
    cut_off = []

    def compromise():
        if cut_off:
            return
        cut_off.append(world["clock"].now())
        administration.report_executor_key_compromise(
            owner, tenant, GATE_KEY_ID, admin, now=world["clock"].now()
        )

    def verifier_for(conn, row):
        return RingChangeDuringVerification(executor_verifier(conn, row), compromise)

    payload = report_body(
        world,
        grant.report_secret,
        record=signed_record(
            db,
            world,
            execution_id,
            outcome="FAILED_NOT_EXECUTED",
            reason="CANCELLED_NOT_EXECUTED",
        ),
        outcome="FAILED_NOT_EXECUTED",
        reason="CANCELLED_NOT_EXECUTED",
    )
    with pytest.raises(ExecutionError) as refused:
        report_outcome(
            db,
            world["identity"],
            execution_id,
            json.dumps(payload).encode(),
            verifier_for=verifier_for,
            clock=world["clock"],
        )
    assert refused.value.code == "INVALID_RECORD"
    # The compromise really did commit in the window, and the settlement did not rest on
    # the ring as it stood before it.
    assert len(cut_off) == 1
    [key] = administration.list_executor_keys(owner, tenant)
    assert key.revocation_reason == "COMPROMISED"
    unchanged(admin_engine, tenant, execution_id)
    assert reported(admin_engine, tenant) == []


def test_a_retirement_committing_while_a_report_verifies_still_attests_the_grant(
    db, gate_world, owner, admin_engine
):
    """The half of the window that must not change, checked in the same window as the half
    that must.

    Reading the ring under the fence would be a regression if it made an ordinary
    retirement retroactive: every scheduled rotation would then invalidate every
    outstanding proof of a grant in flight, which is the key-window rule and the reason a
    compromise had to be a different kind of revocation in the first place. It does not,
    and this is why: the ring decides nothing on its own, and what it is weighed against is
    ``dispatch_attempted_at``, stamped once when the grant was issued and immutable after.
    """
    world = gate_world
    tenant, admin = world["identity"].tenant_id, world["admin"].principal_id
    opened = world["clock"].now()
    # A second key, so retiring the first is an ordinary retirement and not a refusal:
    # `_keep_attestable` keeps a tenant's last live key while a bundle declares an executor.
    register_key(owner, world, key_id="executor-next")
    (target,) = targets(admin_engine, world, count=1)
    granted = checkpoint(db, world, action=target)
    grant = granted.view.checkpoint
    assert grant is not None
    execution_id = granted.view.execution_id
    world["clock"].value = opened + timedelta(minutes=1)
    retired = []

    def retire():
        if retired:
            return
        retired.append(world["clock"].now())
        administration.revoke_executor_key(
            owner, tenant, GATE_KEY_ID, admin, now=world["clock"].now()
        )

    def verifier_for(conn, row):
        return RingChangeDuringVerification(executor_verifier(conn, row), retire)

    payload = report_body(world, grant.report_secret, record=signed_record(db, world, execution_id))
    view = report_outcome(
        db,
        world["identity"],
        execution_id,
        json.dumps(payload).encode(),
        verifier_for=verifier_for,
        clock=world["clock"],
    )
    assert view.state == "EXECUTED"
    assert len(retired) == 1
    listed = {item.key_id: item for item in administration.list_executor_keys(owner, tenant)}
    assert listed[GATE_KEY_ID].revocation_reason == "RETIRED"
    assert listed["executor-next"].revoked_at is None
    row = retained(admin_engine, tenant, execution_id)
    assert (row.state, row.tier) == ("EXECUTED", "ATTESTED")


def test_a_compromise_committing_while_an_administrator_settles_is_seen_under_the_fence(
    db, gate_world, owner, admin_engine
):
    """The other path that settles on attested evidence has the same window, so it is closed.

    ``reconcile`` verifies outside the fence for the same reason the outcome route does,
    and the ring it verified against is not what it settles on: the fenced transaction
    builds the verifier again. The administrator here is not the attacker — the operator
    recording the cut-off and the operator settling are on the same side — but the window
    is the same window and a settlement on a stolen key's record is the same settlement.
    """
    world = gate_world
    tenant, admin = world["identity"].tenant_id, world["admin"].principal_id
    (target,) = targets(admin_engine, world, count=1)
    granted = checkpoint(db, world, action=target)
    execution_id = granted.view.execution_id
    cut_off = []

    def compromise():
        if cut_off:
            return
        cut_off.append(world["clock"].now())
        administration.report_executor_key_compromise(
            owner, tenant, GATE_KEY_ID, admin, now=world["clock"].now()
        )

    record = json.dumps(signed_record(db, world, execution_id)).encode()
    # The unfenced verifier is the one the console builds before `reconcile` opens
    # anything, so the cut-off lands between the two reads rather than under the fence.
    stale = RingChangeDuringVerification(_verifier(db, world, execution_id), compromise)
    with pytest.raises(ExecutionError) as refused:
        reconcile(
            db,
            world["admin"],
            execution_id,
            reason="settled from the executor's signed record",
            evidence=record,
            verifier=stale,
            verifier_for=executor_verifier,
            clock=world["clock"],
        )
    assert refused.value.code == "INVALID_EVIDENCE"
    assert len(cut_off) == 1
    unchanged(admin_engine, tenant, execution_id)


def test_admission_refuses_a_grant_the_key_ring_could_not_attest(
    db, gate_world, owner, admin_engine
):
    """Admission asks the question settlement will ask, not a weaker one SQL can express.

    A row with no revocation is not the same thing as a key: a small-order public key is
    thirty-two bytes of lowercase hex like any other and is one nobody holds the private
    half of, so the ring loader refuses it and refuses the ring with it. Asking "is there
    an unrevoked row" therefore granted normally for a tenant holding one, and the outcome
    route then answered a dependency failure with nothing able to settle the grant —
    which is verbatim the state this refusal exists to prevent.
    """
    world = gate_world
    tenant, admin = world["identity"].tenant_id, world["admin"].principal_id
    first, second = targets(admin_engine, world, count=2)
    granted = checkpoint(db, world, action=first)
    grant = granted.view.checkpoint
    assert grant is not None
    execution_id = granted.view.execution_id
    administration.report_executor_key_compromise(
        owner, tenant, GATE_KEY_ID, admin, now=world["clock"].now()
    )
    # Seeded over the owner connection, which is the only way such a row exists: the
    # registration path has refused this encoding since the key ring was built.
    with admin_engine.begin() as conn:
        conn.execute(
            text(
                "INSERT INTO execbound.executor_keys "
                "(tenant_id, key_id, algorithm, public_key, created_at) "
                "VALUES (:t, :k, 'ED25519', :key, :now)"
            ),
            {
                "t": tenant,
                "k": "executor-unusable",
                "key": "01" + "00" * 31,
                "now": world["clock"].now(),
            },
        )
    with pytest.raises(ExecutionError) as refused:
        checkpoint(db, world, action=second)
    assert refused.value.code == "INVALID_BUNDLE"
    # Permanent until an administrator repairs the ring, so not the 503 that asks for a
    # retry every one of which appends another rejection to the tenant's chain.
    assert error_status(refused.value) == 409
    assert execution_states(admin_engine, tenant) == ["DISPATCH_COMMITTED"]
    # The grant already outstanding is named for what it is rather than answered as an
    # unavailable dependency: nothing about it changes until the ring is repaired.
    stolen = signed_record(db, world, execution_id)
    with pytest.raises(ExecutionError) as unusable:
        report(db, world, execution_id, grant.report_secret, record=stolen)
    assert unusable.value.code == "INVALID_KEY_RING"
    assert error_status(unusable.value) == 409
    unchanged(admin_engine, tenant, execution_id)

    # Repaired: the ring loads again, so the report is answered by what it says rather
    # than by the ring, and the refusal above was about the ring and not about the record.
    with admin_engine.begin() as conn:
        conn.execute(
            text("DELETE FROM execbound.executor_keys WHERE tenant_id=:t AND key_id=:k"),
            {"t": tenant, "k": "executor-unusable"},
        )
    with pytest.raises(ExecutionError) as cut_off:
        report(db, world, execution_id, grant.report_secret, record=stolen)
    assert cut_off.value.code == "INVALID_RECORD"
    register_key(owner, world, key_id="executor-next")
    assert checkpoint(db, world, action=second).view.checkpoint is not None


def test_admission_given_no_way_to_check_a_ring_issues_no_grant(db, gate_world, admin_engine):
    # `admit` is the kernel's and the ring is the composition boundary's, so a deployment
    # that supplied no way to ask gets no grant rather than a grant nothing in it was
    # asked to be able to attest. The tenant here holds a perfectly good key: what is
    # missing is the question, not the answer.
    world = gate_world
    (target,) = targets(admin_engine, world, count=1)
    with pytest.raises(ExecutionError) as refused:
        admit(db, world["identity"], target, world["clock"], available_accounts=frozenset())
    assert refused.value.code == "INVALID_BUNDLE"
    assert execution_states(admin_engine, world["identity"].tenant_id) == []


def test_a_denial_under_a_ring_that_cannot_attest_is_still_recorded_as_a_denial(
    db, gate_world, owner, admin_engine
):
    """A hard denial wins, and the record of it survives the deployment fault beside it.

    The ring refusal runs where the cap on outstanding grants runs — after the decision
    and before anything is reserved — so a request the policy denies is answered and
    recorded as DENIED rather than answered with a deployment fault. Neither order grants
    anything or reserves anything; what the earlier one lost was the row the tenant's
    history is read from, and a denial is the row an operator most wants to find there.
    """
    world = gate_world
    tenant, admin = world["identity"].tenant_id, world["admin"].principal_id
    (target,) = targets(admin_engine, world, count=1)
    gate_bundle(
        db,
        world,
        authorization_policies=(
            world["bundle"].authorization_policies + "\nforbid(principal, action, resource);"
        ),
    )
    administration.report_executor_key_compromise(
        owner, tenant, GATE_KEY_ID, admin, now=world["clock"].now()
    )
    denied = checkpoint(db, world, action=target).view
    assert denied.state == "DENIED"
    assert execution_states(admin_engine, tenant) == ["DENIED"]
    assert impact_rows(admin_engine, tenant) == []
    assert claim_rows(admin_engine, tenant) == []


# Expiry, the sweep and the administrator exit. The sweep itself and the claim it
# releases are exercised in tests/test_recovery_run.py, beside the scheduled run that
# performs them; what is here is what an administrator may and may not do with a grant.


class FixtureConnector:
    """A connector that records every question asked of it and answers nothing useful.

    `reconcile_operation` refuses a checkpoint before it reaches any of these, so a
    recorded question is the refusal having failed to happen. It has no configuration, so
    each call hands `reconcile_operation` its verifier, as the runtime does with its own.
    """

    def __init__(self):
        self.asked = []

    def lookup(self, command):
        self.asked.append("lookup")
        return None

    def cancel(self, command):
        self.asked.append("cancel")
        return b"test-journal-proof"


@contextmanager
def console(
    db,
    world,
    admin_engine,
    *,
    identity=None,
    preconditions=NO_PRECONDITIONS,
    checkpoint_providers=(),
):
    """A human session on the pages of a Gate deployment; an ADMIN unless one is named.

    The runtime holds no connector for any account, which is the placement a checkpoint
    runs in, so the control this task routes is the only settlement the console can offer
    for one of these rows. It is a context manager rather than a fixture because a swept
    grant is produced by moving the clock past its report window, and a session issued
    before that move would have expired by the time the page was asked for.

    ``preconditions`` is the deployment configuration the pages read the precondition
    class from, which is the source admission reads; a deployment that has declared
    nothing answers UNAVAILABLE for every binding, which is what most scenarios want.

    ``checkpoint_providers`` is the deployment's journal keys for its Gate accounts; the
    default configures none, so a pasted provider journal verifies against nothing.
    """
    config = HumanConfig(
        "http://127.0.0.1", TokenKeys("state-v1", {"state-v1": secrets.token_bytes(32)})
    )
    runtime = gate_runtime(
        db, world, preconditions=preconditions, checkpoint_providers=checkpoint_providers
    )
    app = create_app(db, runtime=runtime, human=config)
    with TestClient(app, base_url=config.origin, follow_redirects=False) as client:
        _, login = form_values(client.get("/login").text, "/session")
        login["credential"] = credential(admin_engine, identity or world["admin"])
        assert (
            client.post("/session", data=login, headers={"Origin": config.origin}).status_code
            == 303
        )
        client.headers["Origin"] = config.origin
        opened = client.get("/api/console/v1/session")
        assert opened.status_code == 200, opened.text
        client.headers["X-CSRF-Token"] = opened.json()["csrf_token"]
        yield client


def sweep(db, world, admin_engine, execution_id):
    """Move the clock past this grant's own report window and run the scheduled recovery.

    The window is read from the row rather than assumed, because it is the shorter of a
    day and the requesting credential's expiry, so a scenario that jumped a fixed day
    would outlive identities it still needs.
    """
    tenant = world["identity"].tenant_id
    row = grant_row(admin_engine, tenant, execution_id)
    world["clock"].value = row["report_expires_at"] + timedelta(seconds=1)
    return recover(db, world["admin"], {}, clock=world["clock"])


def test_a_grant_is_refused_by_the_connector_reconciliation_in_every_mode(
    db, gate_world, admin_engine
):
    # Admission refuses a Gate mapping whose account is in the runtime's connector
    # inventory, but that is the inventory as it stood at admission: the console and the
    # CLI both look the account up in the live one, so an operator who configures a
    # connector for a Gate account afterwards reaches this function for every grant
    # already outstanding. With `cancel_if_missing` it would settle the grant
    # FAILED_NOT_EXECUTED from `connector.cancel` evidence and release its claim, which is
    # the refund on absent executor evidence that is never allowed; without it,
    # it would ask a provider about an operation ExecBound never dispatched and then
    # record an inconclusive journal for it.
    world = gate_world
    tenant = world["identity"].tenant_id
    granted = checkpoint(db, world)
    grant = granted.view.checkpoint
    assert grant is not None
    connector = FixtureConnector()

    def refuse(cancel):
        with pytest.raises(ExecutionError) as refused:
            reconcile_operation(
                db,
                world["admin"],
                granted.view.execution_id,
                connector,
                reason="operator reconciling this account's operations",
                cancel_if_missing=cancel,
                clock=world["clock"],
                verifier=FixtureJournal("FAILED_NOT_EXECUTED"),
            )
        assert refused.value.code == "INVALID_STATE"

    for cancel in (False, True):
        refuse(cancel)
    assert connector.asked == []
    unchanged(admin_engine, tenant, granted.view.execution_id)
    kinds = [kind for kind, _ in audit_kinds(admin_engine, tenant)]
    assert "execution.reconciliation_requested" not in kinds
    assert "execution.cancellation_requested" not in kinds
    assert kinds.count("execution.rejected") == 2
    # Refused whatever the state, which is why the refusal is read before the state is:
    # a settled grant would otherwise be answered with its own view, which is the silent
    # success this task exists to remove from the administrator's side of the kernel.
    assert report(db, world, granted.view.execution_id, grant.report_secret).state == "EXECUTED"
    for cancel in (False, True):
        refuse(cancel)
    assert connector.asked == []


def test_an_administrator_settles_a_swept_grant_from_the_executors_record(
    db, gate_world, admin_engine
):
    world = gate_world
    tenant = world["identity"].tenant_id
    world["admin"] = long_lived_admin(admin_engine, db, world)
    granted = checkpoint(db, world)
    assert sweep(db, world, admin_engine, granted.view.execution_id).swept == 1
    assert retained(admin_engine, tenant, granted.view.execution_id).state == "INDETERMINATE"
    record = json.dumps(signed_record(db, world, granted.view.execution_id)).encode()
    view = reconcile(
        db,
        world["admin"],
        granted.view.execution_id,
        reason="settled from the executor's signed record",
        evidence=record,
        verifier=_verifier(db, world, granted.view.execution_id),
        clock=world["clock"],
    )
    assert view.state == "EXECUTED"
    row = retained(admin_engine, tenant, granted.view.execution_id)
    assert (row.tier, row.impact) == ("ATTESTED", "CONFIRMED")
    assert row.released_at == world["clock"].now()


def test_a_settled_grant_answers_an_administrator_rather_than_reporting_success(
    db, gate_world, admin_engine, monkeypatch
):
    # A third exit for the claim an assertion settled — an administrator releasing it
    # early — is not built (`docs/CHECKPOINT.md`, "The claim an assertion left held"), and
    # what a settled grant answers instead must not be a success that moved
    # nothing. Answering EXECUTED from `_settle`'s same-terminal-state branch would leave
    # the tier, the claim and the impact where they were and append no event at all,
    # telling an administrator the exit had worked.
    world = gate_world
    tenant = world["identity"].tenant_id
    granted = checkpoint(db, world)
    grant = granted.view.checkpoint
    assert grant is not None
    assert report(db, world, granted.view.execution_id, grant.report_secret).state == "EXECUTED"
    before = retained(admin_engine, tenant, granted.view.execution_id)
    assert (before.tier, before.released_at) == ("ASSERTED", None)
    events = len(audit_kinds(admin_engine, tenant))
    record = json.dumps(signed_record(db, world, granted.view.execution_id)).encode()

    def never(command, evidence, verifier):
        # Refused in the first transaction as well as under the fence, so a settled row
        # spends no verification on a request that cannot change it.
        raise AssertionError("A settled grant reached the evidence verifier")

    monkeypatch.setattr(reconciliation, "_proof", never)
    with pytest.raises(ExecutionError) as refused:
        reconcile(
            db,
            world["admin"],
            granted.view.execution_id,
            reason="promote the executor's word to its signed record",
            evidence=record,
            verifier=_verifier(db, world, granted.view.execution_id),
            clock=world["clock"],
        )
    assert refused.value.code == "INVALID_STATE"
    after = retained(admin_engine, tenant, granted.view.execution_id)
    assert (after.tier, after.impact, after.released_at) == ("ASSERTED", "CONFIRMED", None)
    # The attempt is answered and a refusal is recorded. `_rejection`'s payload names no
    # execution, so what this asserts is that the attempt left a trace at all, which is
    # the whole of what the silent success did not.
    kinds = audit_kinds(admin_engine, tenant)
    assert len(kinds) == events + 1
    assert (kinds[-1][0], kinds[-1][1]["reason"]) == ("execution.rejected", "INVALID_STATE")


def test_a_grant_settled_while_its_record_verified_is_refused_under_the_fence(
    db, gate_world, admin_engine, monkeypatch
):
    # Why the settled-grant refusal is read twice: the administrator's record is verified
    # between the two transactions, so the executor's own report can land in between, and
    # what decides is the fenced read. Without it `_settle` finds the state it would have
    # written already there and answers the view, which is the silent success again — this
    # time reached by a race rather than by asking twice.
    world = gate_world
    tenant = world["identity"].tenant_id
    granted = checkpoint(db, world)
    grant = granted.view.checkpoint
    assert grant is not None
    record = json.dumps(signed_record(db, world, granted.view.execution_id)).encode()
    verified = reconciliation._proof

    def report_first(command, raw, verifier):
        assert report(db, world, granted.view.execution_id, grant.report_secret).state == (
            "EXECUTED"
        )
        return verified(command, raw, verifier)

    monkeypatch.setattr(reconciliation, "_proof", report_first)
    with pytest.raises(ExecutionError) as refused:
        reconcile(
            db,
            world["admin"],
            granted.view.execution_id,
            reason="settle it from the record the executor sent me",
            evidence=record,
            verifier=_verifier(db, world, granted.view.execution_id),
            clock=world["clock"],
        )
    assert refused.value.code == "INVALID_STATE"
    row = retained(admin_engine, tenant, granted.view.execution_id)
    assert (row.state, row.tier, row.released_at) == ("EXECUTED", "ASSERTED", None)


def test_the_console_settles_a_swept_grant_with_no_connector_configured(
    db, gate_world, admin_engine
):
    world = gate_world
    tenant = world["identity"].tenant_id
    world["admin"] = long_lived_admin(admin_engine, db, world)
    granted = checkpoint(db, world)
    assert sweep(db, world, admin_engine, granted.view.execution_id).swept == 1
    with console(db, world, admin_engine) as admin:
        # The control the console offers a grant is the executor's record, not the
        # connector's cancellation: there is no connector for this account to ask.
        assert settlement(admin, granted.view.execution_id) == "record"
        settled = settle_from_console(
            admin,
            granted.view.execution_id,
            reason="the executor reported out of band",
            record=json.dumps(signed_record(db, world, granted.view.execution_id)),
        )
        assert settled.status_code == 200, settled.text
    row = retained(admin_engine, tenant, granted.view.execution_id)
    assert (row.state, row.tier, row.impact) == ("EXECUTED", "ATTESTED", "CONFIRMED")
    assert row.released_at == world["clock"].now()


def test_the_console_offers_each_row_the_control_its_placement_allows(db, gate_world, admin_engine):
    # Both rows are uncertain and both render the administrator's control, so what tells
    # them apart is the row's own checkpoint marker: a grant has no connector to ask and
    # settles from the executor's signed record, and an operation ExecBound dispatched has
    # a connector and the cancellation that goes with it.
    world = gate_world
    granted = checkpoint(db, world)
    gate_bundle(db, world, external_executor=False)
    (target,) = targets(admin_engine, world, count=1)
    ordinary = dispatched(db, world, admin_engine, action=target)
    with console(db, world, admin_engine) as admin:
        assert settlement(admin, granted.view.execution_id) == "record"
        assert settlement(admin, ordinary.view.execution_id) == "provider"
        # A record means nothing where ExecBound dispatched: the provider's journal is
        # what settles that execution, and an executor record beside it would be evidence
        # about an operation no executor was granted.
        refused = settle_from_console(
            admin,
            ordinary.view.execution_id,
            reason="the executor sent me a record for this one",
            record="{}",
        )
        assert refused.status_code == 400, refused.text


def test_the_console_releases_nothing_without_the_executors_record(db, gate_world, admin_engine):
    world = gate_world
    tenant = world["identity"].tenant_id
    world["admin"] = long_lived_admin(admin_engine, db, world)
    granted = checkpoint(db, world)
    assert sweep(db, world, admin_engine, granted.view.execution_id).swept == 1
    forged = json.dumps(
        signed_record(
            db, world, granted.view.execution_id, private_key=Ed25519PrivateKey.generate()
        )
    )
    genuine = json.dumps(signed_record(db, world, granted.view.execution_id))
    execution_id = granted.view.execution_id
    with console(db, world, admin_engine) as admin:
        why = "settle it because the window closed"
        # No record at all; a record that is not one; a record nobody the tenant
        # registered signed; and the cancellation the connector path offers beside a
        # genuine record, which for a grant is the refund on absent evidence.
        assert settle_from_console(admin, execution_id, reason=why).status_code == 400
        assert settle_from_console(admin, execution_id, reason=why, record="{}").status_code == 400
        bad = settle_from_console(admin, execution_id, reason=why, record=forged)
        assert bad.status_code == 400
        both = settle_from_console(
            admin, execution_id, reason=why, record=genuine, cancel_if_missing=True
        )
        assert both.status_code == 400
    row = retained(admin_engine, tenant, granted.view.execution_id)
    assert (row.state, row.tier, row.impact) == ("INDETERMINATE", None, "UNRESOLVED")
    assert row.released_at is None


def test_the_console_names_the_key_ring_it_cannot_build_rather_than_asking_for_a_retry(
    db, gate_world, admin_engine
):
    """A tenant's key ring is read whole and built whole, so one row that will not load
    fails that tenant's attested settlement entirely. It fails closed, which is right, but
    a generic 503 invites the retry that can never succeed; the code now says which thing
    an operator has to repair, and `execbound executor-key-list` is what shows it. Only a
    row written over the owner connection, or one predating the guards, can reach this:
    registration and the key model both refuse a forgeable encoding."""
    world = gate_world
    tenant = world["identity"].tenant_id
    world["admin"] = long_lived_admin(admin_engine, db, world)
    granted = checkpoint(db, world)
    record = json.dumps(signed_record(db, world, granted.view.execution_id))
    assert sweep(db, world, admin_engine, granted.view.execution_id).swept == 1
    with admin_engine.begin() as conn:
        # The identity point: thirty-two bytes of lowercase hex, so the column's CHECK
        # constraint holds it, and a public key nobody holds the private half of.
        conn.execute(
            text(
                "INSERT INTO execbound.executor_keys "
                "(tenant_id, key_id, algorithm, public_key, created_at) "
                "VALUES (:t, 'forgeable', 'ED25519', :k, :n)"
            ),
            {"t": tenant, "k": "01" + "00" * 31, "n": world["clock"].now()},
        )
    execution_id = granted.view.execution_id
    with console(db, world, admin_engine) as admin:
        why = "the executor reported out of band"
        stale = settle_from_console(admin, execution_id, reason=why, record=record)
        assert stale.status_code == 409
        # An oversized record is refused before any of that, by the 16 KiB body bound
        # `guards.mutation` hands `guards.form` on the way to these values, rather than by
        # anything on this route or in `settle_grant`. The reason is bounded at 500 by
        # `reconcile` because
        # it is retained in an audit payload; the record needs no bound of its own because
        # the body's is smaller than the protocol's own MAX_PROVIDER_BYTES, so a per-field
        # check here could never fire. This assertion holds that relationship: widen the
        # body bound past the protocol's and an oversized record reaches the verifier.
        #
        # It holds it only here, and because this tenant's ring is deliberately broken:
        # every request that gets past the body bound answers the 409 above, before the
        # record is looked at at all, so a 400 can be nothing but the bound. In a world
        # whose ring loads, an oversized record reaching the verifier is refused as a
        # record and answers 400 too, and the same assertion would pass having pinned
        # nothing.
        oversized = settle_from_console(
            admin, execution_id, reason=why, record="x" * (MAX_PROVIDER_BYTES + 1)
        )
        assert oversized.status_code == 413
    row = retained(admin_engine, tenant, granted.view.execution_id)
    assert (row.state, row.tier, row.impact) == ("INDETERMINATE", None, "UNRESOLVED")
    assert row.released_at is None
    # Which 409 it is: the generic execution failure this used to raise answers 503, the
    # status a caller retries, and nothing about a ring that will not load changes on one.
    assert error_status(ExecutionError("INVALID_KEY_RING")) == 409
    assert error_status(ExecutionError()) == 503


def test_a_swept_grant_still_counts_against_the_per_principal_cap(db, gate_world, admin_engine):
    # The sweep is what closes this, so it is asserted against the sweep and not against a
    # forced state: an unreported grant charges every scope and holds its target after it
    # is swept, exactly as it did before, so it still occupies its slot.
    world = gate_world
    tenant = world["identity"].tenant_id
    world["admin"] = long_lived_admin(admin_engine, db, world)
    patient = long_lived_agent(admin_engine, db, world)
    granted = [
        checkpoint(db, world, patient, action=action).view.execution_id
        for action in targets(admin_engine, world, count=MAX_GRANTS)
    ]
    assert sweep(db, world, admin_engine, granted[0]).swept == MAX_GRANTS
    with db.transaction(tenant) as conn:
        assert store.outstanding_grants(conn, tenant, patient.principal_id) == MAX_GRANTS
    # The ninth target is seeded after the sweep, because a day's worth of clock leaves the
    # context the earlier requests froze too stale to resolve and the cap is checked after
    # resolution; what is under test is the cap and not context freshness.
    (ninth,) = targets(admin_engine, world, count=1)
    with pytest.raises(ExecutionError) as full:
        checkpoint(db, world, patient, action=ninth)
    assert full.value.code == "TOO_MANY_GRANTS"
    charging = [item for item in impact_rows(admin_engine, tenant) if item["state"] == "UNRESOLVED"]
    assert len(charging) == MAX_GRANTS
    assert [item["released_at"] for item in claim_rows(admin_engine, tenant)] == [None] * MAX_GRANTS


# The tier in replay. First that a settled checkpoint does not end the tenant's whole
# history export, and the operator's bundle preview with it, then what each tier replays
# as.


def test_gc14_a_tenant_that_settled_a_checkpoint_still_exports_publishes_and_previews(
    db, gate_world, admin_engine, tmp_path
):
    """A settled checkpoint must not stop the tenant's export: the offline export and the
    live preview.

    Were `replay/verify.py:_terminal` to parse every retained record as a `SignedJournal`,
    an executor's `SignedOutcome` envelope would make the parse raise and `export_history` —
    which verifies its own output before returning — answer `ExportError`. Audit events
    are append-only and the export covers the tenant's whole chain, so one attested
    settlement would end that tenant's exports permanently, including for later executions
    that have nothing to do with a checkpoint. `policy.preview_bundle` composes the same
    export and would answer `PREVIEW_UNAVAILABLE`, which is a live operator feature on the
    policy path; `publish_export` verifies before it writes; and `runner.run_replay` parses
    a published file offline through the same code.
    """
    from execbound.policy.preview import preview_bundle
    from execbound.policy.store import create_bundle
    from execbound.replay.export import export_history, publish_export
    from execbound.replay.runner import run_replay

    world = gate_world
    settled = settled_gate_world(db, world, admin_engine)
    history = export_history(db, world["admin"], world["clock"])
    assert {settled.attested, settled.asserted, settled.unreported} <= {
        UUID(event.payload["execution_id"])
        for event in history.events
        if "execution_id" in event.payload
    }
    published, checkpoint_file = tmp_path / "history.json", tmp_path / "head.json"
    publish_export(
        db,
        world["admin"],
        history,
        output=published,
        checkpoint=checkpoint_file,
        clock=world["clock"],
    )
    offline = run_replay(published, checkpoint_file, tmp_path / "report")
    assert offline.complete, offline.issues
    candidate = world["bundle"].model_copy(
        update={
            "bundle_id": uuid4(),
            "authorization_policies": "forbid(principal, action, resource);",
        }
    )
    create_bundle(db, world["admin"], candidate, world["clock"])
    preview = preview_bundle(
        db, world["admin"], candidate.bundle_id, window=timedelta(hours=1), clock=world["clock"]
    )
    assert preview.complete, preview.issues
    assert preview.considered == 3
    assert preview.candidate_effects == {"DENY": 3}


def test_gc14_each_tier_replays_as_what_its_evidence_supports(db, gate_world, admin_engine):
    """A history of both tiers and an unreported grant replays completely and keeps them apart.

    The attested settlement replays from the executor's own envelope, the asserted one as a
    recorded transition that is never presented as gateway evidence, and the unreported
    grant as retained uncertainty. The report names the tier of each settlement.

    An unreported grant has two shapes and the row is about both: one still inside its
    report window, whose uncertainty in replay is the absence of any settlement, and the
    one the sweep leaves behind once the window closes, which carries the transition that
    says so. Both are asserted here, because only the second is the swept row of retained
    uncertainty and only the first is what a history exported at any earlier instant
    contains.

    It also holds the states the Arcade extension adds, because the three rows above are
    all from the checkpoint's own vocabulary: a history holding no row in the extension's
    state exercises neither the settlement gate that reads it, nor the replay ledger's
    refusal of a second settlement, nor the terminal gate's `before` set. A corrected row of
    the `CANCELLED_NOT_EXECUTED` direction alone would exercise the third of those no
    better, because that correction settles at FAILED_NOT_EXECUTED, which the same gate's
    `after` set catches, so a gate missing its `before` side would still pass. Both
    directions are here.
    """
    from arcade_fixtures import CORRECTIONS, correct, stated_failure

    from execbound.replay.export import export_history
    from execbound.replay.history import index_history
    from execbound.replay.report import report_json
    from execbound.replay.simulate import simulate
    from execbound.replay.verify import verify_export

    world = gate_world
    tenant = world["identity"].tenant_id
    # The sweep below moves the clock past the grant's report window, a day out or the
    # requesting credential's expiry, so the administrator exporting afterwards outlives it.
    world["admin"] = long_lived_admin(admin_engine, db, world)
    settled = settled_gate_world(db, world, admin_engine)
    fourth, fifth, sixth = targets(admin_engine, world, count=3)
    stated, _ = stated_failure(db, world, admin_engine, action=fourth)
    corrections = {}
    for action, (changes, state) in zip((fifth, sixth), CORRECTIONS, strict=True):
        execution_id, _ = stated_failure(db, world, admin_engine, action=action)
        assert correct(db, world, execution_id, changes).state == state
        corrections[execution_id] = state
    history = export_history(db, world["admin"], world["clock"])
    verified = verify_export(history, history.head)
    assert verified.complete, verified.issues
    replayed = simulate(verified)
    assert replayed.complete, replayed.issues
    rows = {row.execution_id: row for row in replayed.decisions}
    assert (
        rows[settled.attested].baseline.outcome,
        rows[settled.attested].baseline.provenance,
        rows[settled.attested].settlement_tier,
    ) == ("EXECUTED", "RECORDED_EXECUTOR_EVIDENCE", "ATTESTED")
    assert (
        rows[settled.asserted].baseline.outcome,
        rows[settled.asserted].baseline.provenance,
        rows[settled.asserted].settlement_tier,
    ) == ("EXECUTED", "RECORDED_TRANSITION", "ASSERTED")
    assert (
        rows[settled.unreported].baseline.outcome,
        rows[settled.unreported].baseline.provenance,
        rows[settled.unreported].settlement_tier,
    ) == ("INDETERMINATE", "RECORDED_TRANSITION", None)
    # The statement is read as the state it is, at the tier that says what it is worth, and
    # neither of the corrections is read as the statement it replaced.
    assert (
        rows[stated].baseline.outcome,
        rows[stated].baseline.provenance,
        rows[stated].settlement_tier,
    ) == ("FAILED_EFFECT_UNKNOWN", "RECORDED_TRANSITION", "ASSERTED")
    indexed = index_history(verified).executions
    for execution_id, state in corrections.items():
        assert (
            rows[execution_id].baseline.outcome,
            rows[execution_id].baseline.provenance,
            rows[execution_id].settlement_tier,
        ) == ("FAILED_NOT_EXECUTED", "RECORDED_EXECUTOR_EVIDENCE", "ATTESTED")
        assert (indexed[execution_id].state, indexed[execution_id].terminal_verified) == (
            state,
            True,
        )
    # Byte-deterministic: the same history replayed twice is the same report.
    assert report_json(simulate(verify_export(history, history.head))) == report_json(replayed)
    # And the same grant once the sweep has reached it: the transition the sweep writes is
    # in the chain, and replay reads the row as the same retained uncertainty, at no tier
    # and with nothing terminal behind it.
    assert sweep(db, world, admin_engine, settled.unreported).swept == 1
    (uncertain,) = [
        payload
        for payload in transitions(admin_engine, tenant, "INDETERMINATE")
        if payload["execution_id"] == str(settled.unreported)
    ]
    assert uncertain["reason"] == "UNREPORTED_GRANT"
    closed = export_history(db, world["admin"], world["clock"])
    afterwards = simulate(verify_export(closed, closed.head))
    assert afterwards.complete, afterwards.issues
    swept = {row.execution_id: row for row in afterwards.decisions}[settled.unreported]
    assert (swept.baseline.outcome, swept.baseline.provenance, swept.settlement_tier) == (
        "INDETERMINATE",
        "RECORDED_TRANSITION",
        None,
    )


# ---------------------------------------------------------------------------
# The settlement-side mirror. An operation ExecBound dispatched settles from its
# provider's journal, and the kernel refuses an external executor's evidence against it at
# both of the settlement functions that take a verifier from their caller.
# ---------------------------------------------------------------------------


def dispatched_world(db, world, owner, admin_engine):
    """One operation ExecBound dispatched, in a tenant that has a registered executor key.

    The key is what makes the attack expressible at all: an `ExecutorVerifier` for this
    tenant verifies a record the executor signed, and the record binds this execution's own
    frozen command, so nothing about the evidence is forged. What is wrong with it is which
    row it is offered against.
    """
    world["executor_key"] = register_keypair(owner, world)
    gate_bundle(db, world, external_executor=False)
    return dispatched(db, world, admin_engine)


@pytest.mark.parametrize(
    "module,settle",
    [
        pytest.param(
            reconciliation,
            lambda db, world, ordinary, verifier: reconcile(
                db,
                world["admin"],
                ordinary.view.execution_id,
                reason="an executor record for an operation ExecBound dispatched",
                evidence=json.dumps(signed_record(db, world, ordinary.view.execution_id)).encode(),
                verifier=verifier,
                clock=world["clock"],
            ),
            id="reconcile",
        ),
        pytest.param(
            outcomes,
            lambda db, world, ordinary, verifier: record_outcome(
                db,
                ordinary.ticket,
                json.dumps(signed_record(db, world, ordinary.view.execution_id)).encode(),
                verifier,
                world["clock"],
            ),
            id="record_outcome",
        ),
    ],
)
def test_an_operation_execbound_dispatched_is_never_settled_from_an_executors_record(
    db, world, owner, admin_engine, monkeypatch, module, settle
):
    """The mirror of the grant's refusal, and the export failure it exists to keep out.

    `_settle` derives the tier from the report window alone, so before this refusal a
    dispatched row settled from an executor's record read EXECUTED at no tier with a
    `SignedOutcome` retained under `evidence`. `replay/verify.py:_terminal` reads the tier
    to choose an envelope and would parse that record as a `SignedJournal`, which raises;
    `export_history` verifies its own output, so the tenant's whole chain stopped
    exporting, permanently and for every later execution. Measured before the refusal
    existed: both functions returned `state=EXECUTED` with `settlement_tier` null, and the
    next `export_history` answered `ExportError`.

    Both are reachable as kernel functions rather than only in process: `reconcile` is the
    administrator settlement the activity console drives, and `record_outcome` is the
    ticket path. What stopped them today was a check in the human surface, which pairs the
    record field with the row's report-window marker, and the surface is not the kernel.
    """
    from execbound.replay.export import export_history

    ordinary = dispatched_world(db, world, owner, admin_engine)
    tenant = world["identity"].tenant_id
    verifier = _verifier(db, world, ordinary.view.execution_id)

    def never(command, evidence, verifier):
        # The refusal is made before the evidence is verified, so an operation ExecBound
        # dispatched never has an external executor's record checked against its frozen
        # command. Removing only the fenced guard of `reconcile` still refuses the
        # settlement, so nothing but this says why the unfenced one is there.
        raise AssertionError("A dispatched operation reached the executor's evidence verifier")

    monkeypatch.setattr(module, "_proof", never)
    with pytest.raises(ExecutionError) as refused:
        settle(db, world, ordinary, verifier)
    assert refused.value.code == "INVALID_STATE"
    unchanged(admin_engine, tenant, ordinary.view.execution_id)
    # The consequence, held where it was measured: the tenant still exports. `export_history`
    # verifies what it returns, so a settlement carrying the wrong envelope would raise here
    # rather than be found later by an operator whose bundle preview stopped working.
    monkeypatch.undo()
    history = export_history(db, world["admin"], world["clock"])
    assert str(ordinary.view.execution_id) in {
        event.payload.get("execution_id") for event in history.events
    }


def test_a_row_that_stops_being_a_checkpoint_while_its_record_verified_is_refused(
    db, gate_world, admin_engine, monkeypatch
):
    """Why `reconcile` asks twice: the marker it settles on is the one read under the fence.

    The mirror of the fenced test above it. Evidence is verified between the two
    transactions, so the row the first read saw is not what a settlement rests on; only the
    owner connection can move the column, which is what makes the second read observable at
    all. `record_outcome` needs no second ask: `_never_a_checkpoint` under its fence
    refuses the one change that could matter to it, a window appearing.
    """
    world = gate_world
    tenant = world["identity"].tenant_id
    granted = checkpoint(db, world)
    assert granted.view.checkpoint is not None
    execution_id = granted.view.execution_id
    record = json.dumps(signed_record(db, world, execution_id)).encode()
    verifier = _verifier(db, world, execution_id)
    verified = reconciliation._proof

    def clear_first(command, raw, checker):
        set_report_window(admin_engine, tenant, execution_id, None)
        return verified(command, raw, checker)

    monkeypatch.setattr(reconciliation, "_proof", clear_first)
    with pytest.raises(ExecutionError) as refused:
        reconcile(
            db,
            world["admin"],
            execution_id,
            reason="settled from the executor's signed record",
            evidence=record,
            verifier=verifier,
            clock=world["clock"],
        )
    assert refused.value.code == "INVALID_STATE"
    unchanged(admin_engine, tenant, execution_id)


# The human pages. A checkpoint is labelled externally executed on the record and
# the approval pages, with the precondition class and, once settled, the evidence tier, as
# inert text. The report window is what marks one and it is written before the decision, so
# every label built from it is paired with the row's own state; the canonical claim is read
# rather than inferred. No control on either page dispatches.

# A deployment that has declared something about the binding every grant in this world
# names, so the pages have a class to show that is not the honest default.
DECLARED = PreconditionConfig({CONTAIN: "ASSERTED_BY_EXECUTOR"})
# The audit event a grant is recorded in, which is where the class it carries is kept.
GRANTED = "execution.checkpoint_granted"
# The same binding declared the strongest class, for the scenarios that render a grant
# admitted under a different declaration from the one the page is holding.
ENFORCED = PreconditionConfig({CONTAIN: "ENFORCED_BY_PROVIDER"})
# Every class sentence's opening words. A record that was issued a grant carries none of
# them, because the page cannot read which one that grant was issued under.
CLASS_OPENINGS = ("Enforced by the provider", "Asserted by the executor", "Unavailable")


def escaped(text):
    """One label as the classic approval page renders it; the escaping keeps it inert."""
    return str(escape(text))


def shown(text):
    """One sentence as the console carries it: a JSON string value, escaped as JSON.

    The console reads a record over its API and React renders every string as text, so this
    is where the sentence leaves the server. Asserting on the bytes of that answer is the
    same assertion the page-scraping version made before the console took over (#333): the
    sentence is present, and nothing built an element around it.
    """
    return json.dumps(text)[1:-1]


def article(admin, execution_id):
    """One record as the console reads it, so a test can say what it says."""
    answer = admin.get(f"/api/console/v1/executions/{execution_id}")
    assert answer.status_code == 200, (execution_id, answer.status_code, answer.text[:200])
    assert answer.headers["content-type"].startswith("application/json")
    return answer.text


def settlement(admin, execution_id):
    """Which settlement the record offers an administrator, or None when it offers none."""
    view = json.loads(article(admin, execution_id))["reconcile"]
    return None if view is None or not view["available"] else view["kind"]


def uncertain(admin):
    """The uncertain queue as the console asks for it."""
    answer = admin.get("/api/console/v1/executions?state=UNCERTAIN")
    assert answer.status_code == 200, answer.text
    return [item["execution_id"] for item in answer.json()["items"]]


def settle_from_console(admin, execution_id, **changes):
    """Settle one record the way the console does: JSON, the token, the exact origin."""
    detail = json.loads(article(admin, execution_id))["reconcile"]
    body = {"reason": "settled from the console", "continuation": detail["continuation"]}
    return admin.post(
        f"/api/console/v1/executions/{execution_id}/reconcile", json={**body, **changes}
    )


def test_the_record_page_labels_an_externally_executed_grant(db, gate_world, admin_engine):
    world = gate_world
    granted = checkpoint(db, world)
    grant = granted.view.checkpoint
    assert grant is not None
    with console(db, world, admin_engine, preconditions=DECLARED) as admin:
        block = article(admin, granted.view.execution_id)
    assert shown(EXTERNALLY_EXECUTED) in block
    # This grant was admitted under a deployment that had declared nothing, so it carries
    # UNAVAILABLE and the console's own declaration is not what its executor was given.
    # The row is described by neither: the class a grant carries is retained where the
    # grant was recorded, and the page says so rather than reading its configuration.
    assert grant.precondition_class == "UNAVAILABLE"
    for opening in CLASS_OPENINGS:
        assert shown(opening) not in block
    assert shown("Not shown for this record.") in block
    assert shown("None yet: nothing has settled this record.") in block
    # The window is a deadline for this row, because a grant was issued and nothing has
    # settled it, and it is named as the one thing it bounds.
    assert shown("Open until " + grant.report_expires_at.isoformat() + ".") in block
    assert shown("A report presented after that is refused.") in block
    # Paired with the stamp admission writes when it commits the grant, and the claim is
    # read from what the tenant retains rather than assumed from the state.
    assert shown("Issued. Nothing has recorded an outcome for it.") in block
    assert shown("Held: no other ExecBound request in this tenant") in block
    # ExecBound sent nothing for this row, so the evidence line does not say it tried.
    # ExecBound sent nothing for this row, so the record's checkpoint section is the
    # grant's and says nothing about an attempt.
    labels = [note["label"] for note in json.loads(block)["checkpoint"]]
    assert "Grant" in labels and "Notice" in labels


def test_a_grant_is_never_described_by_a_class_it_was_not_issued_under(
    db, gate_world, admin_engine
):
    # The class belongs to the grant: admission reads the declaration in force when it
    # issues one, and nothing declared afterwards changes the grant already in its hands.
    # Admitted under a deployment that had declared nothing, so this grant carries
    # UNAVAILABLE and no version at all, and rendered through a console whose deployment
    # now declares the strongest class. The row describes neither as this grant's.
    world = gate_world
    granted = checkpoint(db, world)
    grant = granted.view.checkpoint
    assert grant is not None
    assert (grant.precondition_class, grant.expected_version) == ("UNAVAILABLE", None)
    with console(db, world, admin_engine, preconditions=ENFORCED) as admin:
        block = article(admin, granted.view.execution_id)
    assert shown("Issued. Nothing has recorded an outcome for it.") in block
    for opening in CLASS_OPENINGS:
        assert shown(opening) not in block
    assert shown("Not shown for this record.") in block
    assert shown("retained beside it, in this record's execution.checkpoint_granted") in block
    # The sentence points at the audit chain, so what it points at carries the class this
    # grant was issued under and not the one the page's deployment declares.
    granted_events = audit_payloads(admin_engine, world["identity"].tenant_id, GRANTED)
    assert [payload["precondition_class"] for payload in granted_events] == ["UNAVAILABLE"]


def test_a_refused_checkpoint_says_no_grant_was_issued_and_offers_no_control(
    db, gate_world, admin_engine
):
    # The marker is written before the decision, so a denied row carries a report window
    # with no owner secret, no reservation and no claim. Every label on it is paired with
    # the state or the grant stamp, and so is the control.
    world = gate_world
    holder = checkpoint(db, world)
    assert holder.view.checkpoint is not None
    denied = checkpoint(db, world, agent(admin_engine, db, world))
    assert denied.view.state == "DENIED"
    row = grant_row(admin_engine, world["identity"].tenant_id, denied.view.execution_id)
    assert row["report_expires_at"] is not None and row["owner_hash"] is None
    assert row["dispatch_attempted_at"] is None
    with console(db, world, admin_engine, preconditions=DECLARED) as admin:
        block = article(admin, denied.view.execution_id)
    assert shown(EXTERNALLY_EXECUTED) in block
    assert shown("None. The decision refused this request.") in block
    assert shown("None was taken for this record.") in block
    assert shown("None recorded.") in block
    assert shown("Held: no other ExecBound request in this tenant") not in block
    assert settlement(admin, denied.view.execution_id) is None
    # The window this row carries is not a deadline for anything: no grant was issued for
    # it, so the instant is never printed. An unqualified future report deadline beside a
    # refusal is the marker read as a live grant, in the one place a human reads it.
    assert row["report_expires_at"].isoformat() not in block
    assert shown("None. The window is stamped before the decision") in block
    # No grant was issued and none can be, so the class this deployment declares for the
    # binding is a statement about the vendor and not about a guarantee this row enjoys.
    assert shown("Asserted by the executor, as this deployment declares this binding") in block


def test_an_operation_execbound_dispatched_carries_no_external_label(db, gate_world, admin_engine):
    world = gate_world
    gate_bundle(db, world, external_executor=False)
    ordinary = dispatched(db, world, admin_engine)
    with console(db, world, admin_engine, preconditions=DECLARED) as admin:
        block = article(admin, ordinary.view.execution_id)
    assert shown(EXTERNALLY_EXECUTED) not in block
    # No gate label at all: the record carries the sentence its own dispatch did instead.
    assert json.loads(block)["checkpoint"] == []
    assert shown("Tier") not in block
    # This once asserted the word "Precondition" was absent, which was a proxy for the gate
    # block being absent: the word appeared nowhere else. A record ExecBound dispatched now
    # carries its own precondition sentence, so the proxy is replaced by the distinction it
    # stood for. The gate wording describes a declaration in force and must stay absent.
    assert shown("as this deployment declares this binding") not in block
    # And the sentence shown is what this dispatch carried, not what the deployment declares
    # for the binding now: `dispatched` takes the send attempt with no configuration, so the
    # row recorded UNAVAILABLE while DECLARED says ASSERTED_BY_EXECUTOR. A page reading the
    # live declaration would show the executor class for an operation ExecBound dispatched
    # itself, which is the confusion the recorded class exists to end.
    assert shown("None: this deployment declared nothing for the binding") in block
    assert "Asserted by the executor" not in block


def test_a_settled_assertion_says_the_claim_is_held_and_what_releases_it(
    db, gate_world, admin_engine
):
    # What an administrator was told nothing about before this task: the row is settled,
    # so `can_reconcile` is false and no control renders, and the claim it is still
    # holding was invisible.
    world = gate_world
    tenant = world["identity"].tenant_id
    granted = checkpoint(db, world)
    grant = granted.view.checkpoint
    assert grant is not None
    assert report(db, world, granted.view.execution_id, grant.report_secret).state == "EXECUTED"
    row = retained(admin_engine, tenant, granted.view.execution_id)
    assert (row.state, row.tier, row.released_at) == ("EXECUTED", "ASSERTED", None)
    stamped = grant_row(admin_engine, tenant, granted.view.execution_id)["dispatch_attempted_at"]
    with console(db, world, admin_engine) as admin:
        block = article(admin, granted.view.execution_id)
    assert shown("Asserted: the executor's authenticated word") in block
    assert shown("Issued and settled.") in block
    assert shown("Held: no other ExecBound request in this tenant") in block
    assert shown("An assertion never releases a canonical claim") in block
    # An administrator is the reader who is offered settlement controls, so the sentence
    # about the one this row does not get is said here. This row is settled on the
    # executor's word that its call ran, which is not the statement the correction
    # answers, so `_correctable` is false of it and `reconcile` refuses a settlement
    # against it.
    assert shown("No settlement control is offered for this record") in block
    assert shown("The control below corrects this settlement") not in block
    # The run's own earliest boundary, said as a boundary: it also selects on the record
    # having been unchanged for its grace period, so this instant does not promise a time.
    assert shown("it selects no record before " + (stamped + ACT_WINDOW).isoformat()) in block
    assert shown("none that changed more recently than its grace period") in block
    # Settled, so the window is not a deadline for a report that could still do anything.
    assert shown("Closed: this record is already settled") in block
    assert settlement(admin, granted.view.execution_id) is None


def test_a_released_claim_is_never_shown_as_held(db, gate_world, admin_engine):
    world = gate_world
    tenant = world["identity"].tenant_id
    world["admin"] = long_lived_admin(admin_engine, db, world)
    granted = checkpoint(db, world)
    grant = granted.view.checkpoint
    assert grant is not None
    assert report(db, world, granted.view.execution_id, grant.report_secret).state == "EXECUTED"
    world["clock"].value = world["clock"].now() + ACT_WINDOW + timedelta(hours=1)
    assert recover(db, world["admin"], {}, clock=world["clock"]).released == 1
    released = retained(admin_engine, tenant, granted.view.execution_id).released_at
    assert released is not None
    with console(db, world, admin_engine) as admin:
        block = article(admin, granted.view.execution_id)
    assert shown("Released " + released.isoformat() + ".") in block
    assert shown("Held: no other ExecBound request in this tenant") not in block
    assert shown("An assertion never releases a canonical claim") not in block


def test_a_settled_record_with_no_tier_never_names_an_assertion(db, gate_world, admin_engine):
    # The sentence above is about an assertion, so it is paired with the tier as well as
    # with the state. A row moved to a settled state with nothing behind it has no tier,
    # and the claim it still holds is not an assertion holding it.
    world = gate_world
    granted = checkpoint(db, world)
    assert granted.view.checkpoint is not None
    force_state(db, world, granted.view.execution_id, "EXECUTED")
    row = retained(admin_engine, world["identity"].tenant_id, granted.view.execution_id)
    assert (row.state, row.tier, row.released_at) == ("EXECUTED", None, None)
    with console(db, world, admin_engine) as admin:
        block = article(admin, granted.view.execution_id)
    assert shown("None recorded.") in block
    assert shown("Held: no other ExecBound request in this tenant") in block
    assert shown("An assertion never releases a canonical claim") not in block


def test_the_page_names_no_release_time_it_cannot_compute(db, gate_world, admin_engine):
    # The recovery run measures the act window from the attempt stamp and releases nothing
    # without one, so a row whose stamp is gone gets the sentence without a time rather
    # than a page that fails to render.
    world = gate_world
    tenant = world["identity"].tenant_id
    granted = checkpoint(db, world)
    grant = granted.view.checkpoint
    assert grant is not None
    assert report(db, world, granted.view.execution_id, grant.report_secret).state == "EXECUTED"
    clear_attempt(admin_engine, tenant, granted.view.execution_id)
    with console(db, world, admin_engine) as admin:
        block = article(admin, granted.view.execution_id)
    assert shown("An assertion never releases a canonical claim") in block
    assert (
        shown("the attempt time this record no longer carries, so it releases nothing here")
        in block
    )
    assert shown("it selects no record before ") not in block
    # The stamp is what the page reads for whether a grant was issued, and this shape —
    # written over the owner connection, as no runtime path produces it — has none, so the
    # row claims none rather than inventing one from the settled state beside it.
    assert shown("None outstanding for this record.") in block
    assert shown("Issued and settled.") not in block
    # Something settled this record, so a grant was issued for it whatever the stamp says
    # now, and the class it carried is not this deployment's to state.
    for opening in CLASS_OPENINGS:
        assert shown(opening) not in block


def test_the_uncertain_queue_lists_unreported_grants_and_offers_no_dispatch(
    db, gate_world, admin_engine
):
    world = gate_world
    tenant = world["identity"].tenant_id
    world["admin"] = long_lived_admin(admin_engine, db, world)
    first, second = targets(admin_engine, world, count=2)
    swept = checkpoint(db, world, action=first)
    # A minute apart, because the run selects oldest first and a fixed test clock would
    # otherwise stamp both with one `created_at` and leave the order to the row ids.
    world["clock"].value = world["clock"].now() + timedelta(seconds=60)
    outstanding = checkpoint(db, world, action=second)
    assert outstanding.view.checkpoint is not None
    row = grant_row(admin_engine, tenant, swept.view.execution_id)
    world["clock"].value = row["report_expires_at"] + timedelta(seconds=1)
    # One grant per run, oldest first, so the newer one is left exactly where an
    # unreported grant sits before a run reaches it.
    assert recover(db, world["admin"], {}, limit=1, clock=world["clock"]).swept == 1
    with console(db, world, admin_engine, preconditions=DECLARED) as admin:
        queued = uncertain(admin)
        assert sorted(queued) == sorted(
            str(view.execution_id) for view in (swept.view, outstanding.view)
        )
        records = {
            view.execution_id: article(admin, view.execution_id)
            for view in (swept.view, outstanding.view)
        }
        for view in (swept.view, outstanding.view):
            block = records[view.execution_id]
            assert shown(EXTERNALLY_EXECUTED) in block
            # The connector-free settlement, and never the cancellation beside it.
            assert settlement(admin, view.execution_id) == "record"
        assert shown("Issued. Nothing has settled it.") in records[swept.view.execution_id]
        assert (
            shown("Issued. Nothing has recorded an outcome for it.")
            in records[outstanding.view.execution_id]
        )
        # Both windows closed at the requesting credential's expiry, which is the shorter
        # bound, so the queue shows two grants whose report deadlines have passed and one of
        # them not yet swept. The record says the deadline has passed rather than printing it
        # bare: an unreported grant inside its window is not the same record as this one.
        closed = shown("Closed " + row["report_expires_at"].isoformat() + ".")
        for view in (swept.view, outstanding.view):
            assert closed in records[view.execution_id]
            assert shown("Open until ") not in records[view.execution_id]


def test_a_settled_stale_checkpoint_says_a_grant_was_issued(db, gate_world, admin_engine):
    # STALE_AUTHORIZATION is the one settled state reachable from a committed grant and
    # from a pending approval alike, so the state cannot say whether a grant was issued and
    # the stamp admission writes with the grant can. A row that reached an evidence tier
    # obviously held one, and saying "None outstanding" beside that tier reads as a record
    # nothing was ever granted for.
    world = gate_world
    tenant = world["identity"].tenant_id
    granted = checkpoint(db, world)
    assert granted.view.checkpoint is not None
    force_state(db, world, granted.view.execution_id, "STALE_AUTHORIZATION")
    set_settlement_tier(admin_engine, tenant, granted.view.execution_id, "ATTESTED")
    row = retained(admin_engine, tenant, granted.view.execution_id)
    assert (row.state, row.tier) == ("STALE_AUTHORIZATION", "ATTESTED")
    assert grant_row(admin_engine, tenant, granted.view.execution_id)["dispatch_attempted_at"]
    with console(db, world, admin_engine, preconditions=DECLARED) as admin:
        block = article(admin, granted.view.execution_id)
    assert shown("Issued and settled.") in block
    assert shown("None outstanding for this record.") not in block
    assert shown("Attested: ExecBound verified the executor's signature") in block
    # A grant was issued, so the class is the grant's and the page does not read its own.
    for opening in CLASS_OPENINGS:
        assert shown(opening) not in block


def test_an_approver_is_never_told_about_a_control_it_is_never_offered(
    db, gate_world, admin_engine
):
    # The held-claim sentence belongs to any reader; the sentence beside it about the
    # settlement control belongs to the reader who is offered one. `can_reconcile` is ADMIN
    # and an unsettled state, so an approver is offered no settlement control on any row in
    # any state, and telling one the control is withheld here describes a page it has none
    # of. The same row, read by both, is what shows the difference.
    world = gate_world
    tenant = world["identity"].tenant_id
    gate_bundle(db, world, approval_policies=APPROVAL)
    waiting = checkpoint(db, world)
    assert (waiting.view.state, waiting.view.checkpoint) == ("PENDING_APPROVAL", None)
    decide_approval(db, world["human"], waiting.view.approval_id, "APPROVE", world["clock"])
    granted = checkpoint(db, world)
    grant = granted.view.checkpoint
    assert grant is not None and granted.view.execution_id == waiting.view.execution_id
    assert report(db, world, granted.view.execution_id, grant.report_secret).state == "EXECUTED"
    row = retained(admin_engine, tenant, granted.view.execution_id)
    assert (row.state, row.tier, row.released_at) == ("EXECUTED", "ASSERTED", None)
    with console(
        db, world, admin_engine, identity=world["human"], preconditions=DECLARED
    ) as approver:
        page = approver.get(f"/approvals/{waiting.view.approval_id}/classic").text
        block = article(approver, granted.view.execution_id)
    assert escaped("An assertion never releases a canonical claim") in page
    assert escaped("The scheduled recovery run is what releases the claim") in page
    assert shown("An assertion never releases a canonical claim") in block
    assert shown("No settlement control is offered for this record") not in block
    assert shown("The control below corrects this settlement") not in block
    with console(db, world, admin_engine, preconditions=DECLARED) as admin:
        block = article(admin, granted.view.execution_id)
    assert shown("No settlement control is offered for this record") in block


def test_gc18_the_approval_page_labels_an_externally_executed_operation(
    db, gate_world, admin_engine
):
    # GC18's approval-page clause, which is the half of that row no Chromium test holds:
    # `tests/test_browser_surfaces.py` drives the record page and the uncertain queue, and
    # this is the other page the row names. Its name carries the row's prefix so the
    # acceptance inventory, which matches node names, counts it.
    #
    # What the approval page owes an approver: it shows what the tenant will and will not
    # be able to prove before it authorizes the act.
    world = gate_world
    gate_bundle(db, world, approval_policies=APPROVAL)
    waiting = checkpoint(db, world)
    assert (waiting.view.state, waiting.view.checkpoint) == ("PENDING_APPROVAL", None)
    with console(
        db, world, admin_engine, identity=world["human"], preconditions=DECLARED
    ) as approver:
        page = approver.get(f"/approvals/{waiting.view.approval_id}/classic").text
    assert escaped(EXTERNALLY_EXECUTED) in page
    # The one page where the class is a decision input, and the page with no grant to
    # describe: what this deployment declares is both the only source and the right one.
    assert escaped("Asserted by the executor, as this deployment declares this binding") in page
    assert escaped("None yet. One is issued only if a human approves") in page
    assert escaped("None was taken for this record.") in page
    # No report has been sent, because no grant exists for one to be about.
    assert escaped("None recorded.") in page
    # The report window this row already carries is no deadline for it; the approver is
    # not shown one for a grant that does not exist.
    row = grant_row(admin_engine, world["identity"].tenant_id, waiting.view.execution_id)
    assert row["report_expires_at"] is not None and row["dispatch_attempted_at"] is None
    assert row["report_expires_at"].isoformat() not in page
    # The decision is the only thing this page submits; nothing here settles or dispatches.
    assert sorted(set(re.findall(r'<form[^>]*action="([^"]+)"', page))) == sorted(
        {"/session/logout", f"/approvals/{waiting.view.approval_id}/decide"}
    )


def test_provider_markup_on_a_checkpoint_row_stays_inert_text(db, gate_world, admin_engine):
    world = gate_world
    injected = "<img src=x onerror=alert(1)>"
    with admin_engine.begin() as conn:
        conn.execute(
            text(
                "UPDATE execbound.resources SET provider_id=:v "
                "WHERE tenant_id=:t AND resource_id=:r"
            ),
            {"v": injected, "t": world["identity"].tenant_id, "r": world["target"]},
        )
    granted = checkpoint(db, world)
    assert granted.view.checkpoint is not None
    with console(db, world, admin_engine, preconditions=DECLARED) as admin:
        block = article(admin, granted.view.execution_id)
    assert shown(EXTERNALLY_EXECUTED) in block
    # It arrives as a JSON string and nothing else: the console renders it as text and
    # `tests/test_browser_surfaces.py` holds that in a browser, but what leaves the server
    # here is `application/json` with `nosniff`, so the characters are never an element.
    assert shown(injected) in block


def test_an_unsettled_record_is_never_told_it_is_settled_by_its_tier_alone(
    db, gate_world, admin_engine
):
    # The guidance says the record is already settled and that the console offers no
    # control for it, so it is paired with the state as well as with the tier. Only
    # `_settle` writes a tier today and it writes a settled state in the same
    # transaction, so this shape is written over the owner connection; the pairing is
    # what keeps the sentence true if a settlement ever writes one without the other.
    world = gate_world
    tenant = world["identity"].tenant_id
    granted = checkpoint(db, world)
    assert granted.view.checkpoint is not None
    force_state(db, world, granted.view.execution_id, "INDETERMINATE")
    set_settlement_tier(admin_engine, tenant, granted.view.execution_id, "ASSERTED")
    row = retained(admin_engine, tenant, granted.view.execution_id)
    assert (row.state, row.tier, row.released_at) == ("INDETERMINATE", "ASSERTED", None)
    with console(db, world, admin_engine) as admin:
        block = article(admin, granted.view.execution_id)
    assert shown("An assertion never releases a canonical claim") not in block
    # Uncertain, so the console does offer the settlement, which is exactly what the
    # guidance would have told an administrator was not there.
    assert settlement(admin, granted.view.execution_id) == "record"


# ---------------------------------------------------------------------------
# The correction's operator control.
#
# `reconcile` admits one settled grant — a `_correctable` row, met by a verified
# non-execution — and without this control the Activity page would offer that row nothing,
# so the correction would be a kernel capability an operator had no route to. The control is
# the same evidence-submission affordance an unsettled grant already gets, gated on the
# kernel's own `_correctable` rather than on a second opinion about it, so what is
# admissible is still `reconcile`'s to decide. The rows below drive the correction through
# the page, and which guard each one falsifies was measured by breaking that guard and
# watching exactly this row fail. Four are covered here: the widened gate in
# `can_reconcile`, its ADMIN check, the continuation naming the record the POST acts on, and
# the session revocation check. Two are covered by rows that already existed — the refusal
# of a settled row that is not correctable by
# `test_a_settled_assertion_says_the_claim_is_held_and_what_releases_it`, and the
# continuation's binding to one session by `test_continuation_cannot_move_between_sessions`
# — and the approver scope narrowing in `records` by
# `test_scope_revocation_hides_pending_and_rejects_old_form`, which the approver row here
# does not falsify, because the ADMIN check hides the control first. Two guards on this path
# are measured as redundant rather than covered: the route's own ADMIN check and
# `settle_grant`'s, since removing either alone fails nothing with `reconcile`'s three ADMIN
# checks behind them, and
# `test_gc8_an_asserted_non_execution_is_settled_only_by_an_administrator` is what fails
# when all three go together.


def stated_failure(db, world, execution_id, secret):
    """One grant settled by nothing but the executor's word that its call failed.

    The three facts `_correctable` reads are written by `_settle` in this one transaction,
    so a row produced here is the row the correction admits rather than one assembled to
    look like it.
    """
    view = report(
        db, world, execution_id, secret, outcome="FAILED_EFFECT_UNKNOWN", reason="REPORTED_FAILURE"
    )
    assert view.state == "FAILED_EFFECT_UNKNOWN"
    return view


def non_execution(db, world, execution_id):
    """The executor-signed record a correction presents: the call was not executed."""
    return json.dumps(
        signed_record(
            db, world, execution_id, outcome="FAILED_NOT_EXECUTED", reason="CANCELLED_NOT_EXECUTED"
        )
    )


def correct_from_console(admin, execution_id, **changes):
    """The correction an operator submits, with the reason they type."""
    return settle_from_console(
        admin, execution_id, reason="the platform's report was false", **changes
    )


def test_the_console_corrects_a_reported_failure_from_the_executors_signed_record(
    db, gate_world, admin_engine
):
    """The correction end to end through the page: what an administrator sees and clicks.

    The row arrives settled and charged on a statement ExecBound could check nothing
    about. What the page offers it is the evidence field an unsettled grant gets, and what
    submitting a verified non-execution into it does is refund the impact and release the
    claim — the same `reconcile` call the kernel rows drive directly, reached here by a
    person rather than by a test.
    """
    world = gate_world
    tenant = world["identity"].tenant_id
    granted = checkpoint(db, world)
    grant = granted.view.checkpoint
    assert grant is not None
    stated_failure(db, world, granted.view.execution_id, grant.report_secret)
    charged = retained(admin_engine, tenant, granted.view.execution_id)
    assert (charged.state, charged.tier, charged.impact) == (
        "FAILED_EFFECT_UNKNOWN",
        "ASSERTED",
        "CONFIRMED",
    )
    assert charged.released_at is None
    record = non_execution(db, world, granted.view.execution_id)
    with console(db, world, admin_engine) as admin:
        block = article(admin, granted.view.execution_id)
        # The settled row is offered the executor's record and not the connector's
        # cancellation, which for a grant would be a refund on absent executor evidence.
        assert settlement(admin, granted.view.execution_id) == "correction"
        # What the console says the control does to this record, rather than what it would
        # say about a row it offered none for.
        assert shown("The control below corrects this settlement") in block
        assert shown("No settlement control is offered for this record") not in block
        answered = correct_from_console(admin, granted.view.execution_id, record=record)
        assert answered.status_code == 200, answered.text
        after = article(admin, granted.view.execution_id)
    row = retained(admin_engine, tenant, granted.view.execution_id)
    assert (row.state, row.tier, row.impact) == ("FAILED_NOT_EXECUTED", "ATTESTED", "NONEXECUTION")
    assert row.confirmed_at is None and row.released_at == world["clock"].now()
    assert row.result["reason"] == "CANCELLED_NOT_EXECUTED"
    # A corrected record holds none of the three facts `_correctable` reads, so the page
    # stops offering it a control and says what it corrected instead.
    assert json.loads(after)["reconcile"]["available"] is False
    assert shown("Corrected: this record was settled once on the executor") in after


def test_the_console_refuses_a_correction_that_states_the_executor_acted(
    db, gate_world, admin_engine
):
    """The one direction the control does not carry, refused where an operator meets it.

    Releasing the canonical claim on a statement that the call ran is the promotion
    `docs/CHECKPOINT.md` refuses under "The claim an assertion left held", and the page
    rendering a control for this row does not widen what `reconcile` takes: the record is
    verified, its outcome is not a non-execution, and the fenced call refuses it with the
    row untouched.
    """
    world = gate_world
    tenant = world["identity"].tenant_id
    granted = checkpoint(db, world)
    grant = granted.view.checkpoint
    assert grant is not None
    stated_failure(db, world, granted.view.execution_id, grant.report_secret)
    executed = json.dumps(signed_record(db, world, granted.view.execution_id))
    with console(db, world, admin_engine) as admin:
        refused = correct_from_console(admin, granted.view.execution_id, record=executed)
        assert refused.status_code == 409, refused.text
    row = retained(admin_engine, tenant, granted.view.execution_id)
    assert (row.state, row.tier, row.impact) == (
        "FAILED_EFFECT_UNKNOWN",
        "ASSERTED",
        "CONFIRMED",
    )
    assert row.released_at is None


@pytest.mark.parametrize(
    "settlement,status,after",
    [
        (
            {"outcome": "FAILED_EFFECT_UNKNOWN", "reason": "REPORTED_FAILURE"},
            200,
            ("FAILED_NOT_EXECUTED", "ATTESTED", "NONEXECUTION"),
        ),
        (
            {"outcome": "EXECUTED", "reason": "EXECUTED"},
            409,
            ("EXECUTED", "ASSERTED", "CONFIRMED"),
        ),
    ],
    ids=["reported-failure", "reported-success"],
)
def test_a_report_settling_a_grant_between_the_render_and_the_submission(
    db, gate_world, admin_engine, settlement, status, after
):
    """The continuation binds the record, not the state the page read it in.

    `settle_grant`'s `Continuation` carries the tenant, the principal, the credential, the
    audience, the execution, the approval, the plan hash, a nonce and an expiry, and no row
    state at all, and `bound_record` re-reads the row at the POST. So a control rendered
    for an unsettled grant is submitted against whatever the row is by then: a report that
    settles it as a reported failure leaves a row the correction admits, and one that
    settles it as executed leaves a row a settlement is refused against. This is the case
    where the page and the row disagree, and the row is what decides.
    """
    world = gate_world
    tenant = world["identity"].tenant_id
    granted = checkpoint(db, world)
    grant = granted.view.checkpoint
    assert grant is not None
    record = non_execution(db, world, granted.view.execution_id)
    with console(db, world, admin_engine) as admin:
        rendered = article(admin, granted.view.execution_id)
        # Read for an unsettled grant, which is the exit from retained uncertainty and not
        # the correction, so the record says neither of the settled row's sentences.
        assert json.loads(rendered)["reconcile"]["kind"] == "record"
        assert shown("The control below corrects this settlement") not in rendered
        continuation = json.loads(rendered)["reconcile"]["continuation"]
        assert report(db, world, granted.view.execution_id, grant.report_secret, **settlement)
        answered = admin.post(
            f"/api/console/v1/executions/{granted.view.execution_id}/reconcile",
            json={
                "reason": "the platform's report was false",
                "continuation": continuation,
                "record": record,
            },
        )
        assert answered.status_code == status, answered.text
    row = retained(admin_engine, tenant, granted.view.execution_id)
    assert (row.state, row.tier, row.impact) == after


@pytest.mark.parametrize(
    ("evidence", "tier"),
    [("provider journal", "PROVIDER_VERIFIED"), ("compact JWS", "ATTESTED")],
)
def test_the_console_settles_a_grant_from_a_pasted_journal_or_attestation(
    db, gate_world, owner, admin_engine, evidence, tier
):
    """The administrator exit through the real surface, with the Gate's two new kinds.

    `settle_grant` builds its verifier from `runtime.verifier_for`, which composes the
    tenant's executor keys with the journal key the deployment configured for the grant's
    account, and the route hands it the pasted `record` text as it arrived. So a provider
    journal pasted into the console settles an unsettled grant at PROVIDER_VERIFIED and a
    compact ES256 JWS settles one at ATTESTED, each releasing the claim. The token is
    pasted with the trailing newline a copied token usually carries, which the console
    does not strip.
    """
    world = gate_world
    tenant = world["identity"].tenant_id
    tines = register_es256(owner, world)
    granted = checkpoint(db, world)
    execution_id = granted.view.execution_id
    if evidence == "provider journal":
        pasted = json.dumps(gate_journal(db, world, execution_id))
    else:
        claims = attestation_claims(db, world, execution_id)
        pasted = jws(tines, {"alg": "ES256", "kid": TINES_KEY_ID}, claims) + "\n"
    with console(db, world, admin_engine, checkpoint_providers=[journal_provider(world)]) as admin:
        assert settlement(admin, execution_id) == "record"
        answered = settle_from_console(admin, execution_id, record=pasted)
        assert answered.status_code == 200, answered.text
        assert answered.json()["state"] == "EXECUTED"
        after = article(admin, execution_id)
    assert shown(f"Executed. Evidence tier {tier}.") in after
    row = retained(admin_engine, tenant, execution_id)
    assert (row.state, row.tier, row.impact) == ("EXECUTED", tier, "CONFIRMED")
    assert row.released_at == world["clock"].now()


def test_a_tampered_form_state_corrects_nothing(db, gate_world, admin_engine):
    """The correction reuses the form state token the settlement control already carries.

    The token is what binds this form to this record, this session and this credential, so
    a correction submitted with one byte changed is refused before any record is read and
    the row it named keeps its statement, its charge and its claim.
    """
    world = gate_world
    tenant = world["identity"].tenant_id
    granted = checkpoint(db, world)
    grant = granted.view.checkpoint
    assert grant is not None
    stated_failure(db, world, granted.view.execution_id, grant.report_secret)
    record = non_execution(db, world, granted.view.execution_id)
    with console(db, world, admin_engine) as admin:
        continuation = json.loads(article(admin, granted.view.execution_id))["reconcile"][
            "continuation"
        ]
        assert continuation is not None
        forged = admin.post(
            f"/api/console/v1/executions/{granted.view.execution_id}/reconcile",
            json={
                "reason": "the platform's report was false",
                "continuation": continuation + "0",
                "record": record,
            },
        )
        assert forged.status_code == 400, forged.text
        empty = admin.post(
            f"/api/console/v1/executions/{granted.view.execution_id}/reconcile",
            json={
                "reason": "the platform's report was false",
                "continuation": "",
                "record": record,
            },
        )
        assert empty.status_code == 400, empty.text
    row = retained(admin_engine, tenant, granted.view.execution_id)
    assert (row.state, row.tier, row.impact) == (
        "FAILED_EFFECT_UNKNOWN",
        "ASSERTED",
        "CONFIRMED",
    )
    assert row.released_at is None


def test_a_revoked_session_corrects_nothing(db, gate_world, admin_engine):
    """The session is checked again when the form comes back, so a revoked one corrects nothing.

    What refuses this submission is the request-time load, which reads the session row and
    raises on a revoked one before the route body runs; `settle_grant`'s own recheck and the
    authority check it hands `reconcile` stand behind that and are measured as redundant
    rather than as what this row falsifies. The record and the reason are valid, so the
    only thing between them and a correction is the session.
    """
    world = gate_world
    tenant = world["identity"].tenant_id
    granted = checkpoint(db, world)
    grant = granted.view.checkpoint
    assert grant is not None
    stated_failure(db, world, granted.view.execution_id, grant.report_secret)
    record = non_execution(db, world, granted.view.execution_id)
    with console(db, world, admin_engine) as admin:
        continuation = json.loads(article(admin, granted.view.execution_id))["reconcile"][
            "continuation"
        ]
        with admin_engine.begin() as conn:
            conn.execute(
                text("UPDATE execbound.human_sessions SET revoked_at=:n"),
                {"n": world["clock"].now()},
            )
        refused = admin.post(
            f"/api/console/v1/executions/{granted.view.execution_id}/reconcile",
            json={
                "reason": "the platform's report was false",
                "continuation": continuation,
                "record": record,
            },
        )
        assert refused.status_code in {400, 401, 403}, refused.status_code
    row = retained(admin_engine, tenant, granted.view.execution_id)
    assert (row.state, row.tier, row.impact) == (
        "FAILED_EFFECT_UNKNOWN",
        "ASSERTED",
        "CONFIRMED",
    )
    assert row.released_at is None


def test_an_approver_is_offered_no_correction_on_a_row_it_can_read(db, gate_world, admin_engine):
    """`can_reconcile` is ADMIN and a row `reconcile` would take, and the kind comes first.

    The same correctable record, read by the approver whose scope reaches it: the row is on
    the page, the statement and the charge are on it, and the control is not — so widening
    which rows are offered one did not widen who is offered it.
    """
    world = gate_world
    granted = checkpoint(db, world)
    grant = granted.view.checkpoint
    assert grant is not None
    stated_failure(db, world, granted.view.execution_id, grant.report_secret)
    with console(db, world, admin_engine, identity=world["human"]) as approver:
        block = article(approver, granted.view.execution_id)
        assert settlement(approver, granted.view.execution_id) is None
        refused = approver.post(
            f"/api/console/v1/executions/{granted.view.execution_id}/reconcile",
            json={"reason": "not mine to settle", "continuation": "x"},
        )
        assert refused.status_code == 403, refused.status_code
    assert shown("The effect was never established.") in block
    # The sentences about a control belong to the reader who is offered controls at all.
    assert shown("The control below corrects this settlement") not in block
    assert shown("No settlement control is offered for this record") not in block


# ---------------------------------------------------------------------------
# The acceptance scenarios GC1 to GC16 (`docs/ACCEPTANCE_TESTS.md`).
#
# Each test below holds one row of that inventory end to end rather than one clause of
# it, so a regression fails the scenario that names the promise. GC14 sits above, with
# the replay tests, beside the export it guards. GC17 is in
# `tests/test_checkpoint_schema.py`, where the migration round trip runs, and GC18's two
# halves are the scripted caller in `tests/test_checkpoint_workflow.py` and the Chromium
# page test in `tests/test_browser_surfaces.py`.
# ---------------------------------------------------------------------------

# The continuation key the deployed configuration below signs its act grants with, held
# here so a scenario can verify one without re-reading the file it wrote.
ACT_KEY = bytes.fromhex("21" * 32)


def private_file(tmp_path, declared="ENFORCED_BY_PROVIDER"):
    """The private configuration file a shipped deployment runs from.

    ``load_runtime`` is what a deployment builds its runtime from: `app.py`, which serves
    the HTTP and MCP surfaces from one ``Runtime``, and the CLI's runtime commands both go
    through it, so a precondition class reachable only through the Python constructor is a
    class no deployment holds. The one connector entry names another tenant's account,
    because the file requires at least one and the account a checkpoint runs on has none.
    """
    config = {
        "origin": "http://127.0.0.1:8000",
        "active_key_id": "state-v1",
        "continuation_keys": {"state-v1": ACT_KEY.hex()},
        "connectors": [
            {
                "tenant_id": str(uuid4()),
                "account_id": str(uuid4()),
                "origin": "http://127.0.0.1:8001",
                "dispatch_token": "dispatch-test" * 3,
                "control_token": "control-test" * 3,
                "evidence_keys": {"proof": "31" * 32},
            }
        ],
        "preconditions": [
            {
                "provider": CONTAIN[0],
                "provider_operation": CONTAIN[1],
                "precondition_class": declared,
            }
        ],
    }
    path = tmp_path / "private.json"
    path.write_text(json.dumps(config), encoding="utf-8")
    return path


def test_gc1_a_deployed_checkpoint_answers_with_a_grant_and_dispatches_nothing(
    db, gate_world, admin_engine, tmp_path
):
    """GC1: an eligible checkpoint in a tenant whose account has no connector.

    Driven through `load_runtime` rather than a constructed `Runtime`, because GC1 is a
    claim about a shipped deployment: the expected version this grant carries depends on a
    class an operator declared in the private file, and a deployment with no way to hold
    one answers UNAVAILABLE for every binding however well the constructor works.
    """
    world = gate_world
    identity = world["identity"]
    tenant = identity.tenant_id
    runtime, _ = load_runtime(private_file(tmp_path), db)
    try:
        assert runtime.preconditions.declared(*CONTAIN) == "ENFORCED_BY_PROVIDER"
        # No connector is configured for this tenant at all, so the dispatch branch would
        # raise rather than send: answering at all is that branch never being taken.
        assert not [key for key in runtime.connectors if key[0] == tenant]
        view = runtime.execute(identity, request(world).model_dump_json().encode())
        described = runtime.present(identity, view)["checkpoint"]
    finally:
        for connector in runtime.connectors.values():
            connector.close()
    assert view.state == "DISPATCH_COMMITTED"
    grant = view.checkpoint
    assert grant is not None
    # The checkpoint object is the pair `docs/CHECKPOINT.md` documents: what admission
    # committed, and the act token minted per answer. The signed act grant is the second
    # key, not a field of the first. The grant carries the two fields that spell the
    # provider binding the class is declared against, the re-answer flag, the executor
    # binding, and, because this deployment declares ENFORCED_BY_PROVIDER, the provider
    # command a vendor that speaks the provider protocol accepts.
    assert set(described) == {"grant", "act"}
    assert set(described["grant"]) == {
        "operation_id",
        "provider",
        "provider_operation",
        "resource_provider_id",
        "action",
        "arguments",
        "precondition_class",
        "expected_version",
        "act_expires_at",
        "report_expires_at",
        "regranted",
        "report_secret",
        "binding",
        "provider_command",
    }
    row = grant_row(admin_engine, tenant, view.execution_id)
    assert grant.operation_id == row["operation_id"]
    assert (grant.provider, grant.provider_operation) == CONTAIN
    assert grant.action == "endpoint.isolate"
    # The class the operator declared, and with it the version the plan froze, which is
    # the pair the configuration file exists for.
    assert grant.precondition_class == "ENFORCED_BY_PROVIDER"
    assert grant.expected_version == frozen_plan(db, world, view.execution_id).resource_version
    assert grant.act_expires_at <= grant.report_expires_at
    assert grant.report_expires_at == row["report_expires_at"]
    assert row["owner_hash"] == secret_digest(grant.report_secret)
    # The act window's token, at an audience of its own, naming this one operation.
    keys = TokenKeys("state-v1", {"state-v1": ACT_KEY})
    claim = act_claim(described["act"], keys, identity, world["clock"])
    assert (claim.execution_id, claim.operation_id) == (view.execution_id, grant.operation_id)
    assert claim.expires_at == grant.act_expires_at
    # Reserved before it was issued: the impact row and the canonical claim are committed.
    impacts = impact_rows(admin_engine, tenant)
    assert [(item["execution_id"], item["state"]) for item in impacts] == [
        (view.execution_id, "UNRESOLVED")
    ]
    claims = claim_rows(admin_engine, tenant)
    assert [(item["execution_id"], item["released_at"]) for item in claims] == [
        (view.execution_id, None)
    ]
    # Admission answers a second Gate request with no dispatch ticket at all, under the
    # same declaration supplied to `admit` directly, and the dispatch path refuses the
    # execution the first grant names even when it is handed that grant's report secret.
    (second,) = targets(admin_engine, world, count=1)
    other = checkpoint(db, world, action=second, preconditions=ENFORCED)
    assert other.ticket is None and other.view.checkpoint is not None
    assert other.view.checkpoint.precondition_class == "ENFORCED_BY_PROVIDER"
    ticket = DispatchTicket(tenant, view.execution_id, grant.report_secret)
    with pytest.raises(ExecutionError) as refused:
        take_dispatch(db, ticket, world["clock"])
    assert refused.value.code == "INVALID_STATE"


def raced(submit, count=6):
    """Run ``submit`` on ``count`` connections, released together by one barrier."""
    barrier = Barrier(count)

    def run(index):
        barrier.wait(timeout=10)
        return index, submit(index)

    with ThreadPoolExecutor(max_workers=count) as pool:
        return sorted(pool.map(run, range(count)))


def test_gc2_six_principals_racing_one_target_leave_exactly_one_grant(db, gate_world, admin_engine):
    """GC2, the target half: a grant takes the same canonical claim a dispatch does.

    Six principals on six connections, released together, so the guard that admits one
    unresolved mutation per target is exercised under real contention and not in sequence.
    """
    world = gate_world
    tenant = world["identity"].tenant_id
    members = [agent(admin_engine, db, world) for _ in range(6)]
    (contested,) = targets(admin_engine, world, count=1)
    results = [
        item
        for _, item in raced(lambda i: checkpoint(db, world, members[i], action=again(contested)))
    ]
    granted = [item for item in results if item.view.checkpoint is not None]
    denied = [item for item in results if item.view.state == "DENIED"]
    assert len(granted) == 1 and len(denied) == 5
    assert all(item.ticket is None for item in results)
    for item in denied:
        payload = transition_payload(admin_engine, tenant, item.view.execution_id, "DENIED")
        assert payload["reason"] == "RESOURCE_BUSY"
    # One grant, one reservation, one claim: the five refused rows charge nothing and hold
    # nothing, so a contested target costs the tenant exactly one unit.
    impacts = impact_rows(admin_engine, tenant)
    assert [(item["execution_id"], item["state"]) for item in impacts] == [
        (granted[0].view.execution_id, "UNRESOLVED")
    ]
    claims = claim_rows(admin_engine, tenant)
    assert [(item["execution_id"], item["released_at"]) for item in claims] == [
        (granted[0].view.execution_id, None)
    ]


def test_gc2_six_principals_at_a_shared_group_ceiling_grant_exactly_the_ceiling(
    db, gate_world, admin_engine, owner
):
    """GC2, the ceiling half: a grant draws on a shared budget exactly as a dispatch does.

    Six members of one group on six connections against a group ceiling of three, then
    each grant settled by the principal it was issued to, so what the counter holds
    afterwards is read from settlements rather than from reservations.
    """
    world = gate_world
    tenant = world["identity"].tenant_id
    members = [agent(admin_engine, db, world) for _ in range(6)]
    squad = group(owner, world, *members, name="squad")
    scoped_bundle(db, world, rule(scope="group", group_id=squad, on_exceed="DENY"))
    requests = targets(admin_engine, world, count=6)
    results = raced(lambda i: checkpoint(db, world, members[i], action=requests[i]))
    granted = [(index, item) for index, item in results if item.view.checkpoint is not None]
    denied = [item for _, item in results if item.view.state == "DENIED"]
    assert len(granted) == 3 and len(denied) == 3
    for item in denied:
        payload = transition_payload(admin_engine, tenant, item.view.execution_id, "DENIED")
        assert payload["reasons"] == ["HARD_LIMIT:scoped"]
    assert len(impact_rows(admin_engine, tenant)) == 3
    assert [item["released_at"] for item in claim_rows(admin_engine, tenant)] == [None] * 3
    first = granted[0][1].view.execution_id
    assert counted(usage(db, world, members[0], first)) == {"scoped": (0, 3)}
    # Each executor settles its own grant with a record ExecBound verifies. What the group
    # counter holds afterwards is three confirmed and none unresolved: every reservation
    # the race took was confirmed exactly once and released exactly once, and none of them
    # was counted out twice, which would show as an unresolved count below the three the
    # race left.
    for index, item in granted:
        settled = report(
            db,
            world,
            item.view.execution_id,
            item.view.checkpoint.report_secret,
            members[index],
            record=signed_record(db, world, item.view.execution_id),
        )
        assert settled.state == "EXECUTED"
    assert [item["state"] for item in impact_rows(admin_engine, tenant)] == ["CONFIRMED"] * 3
    assert all(item["released_at"] is not None for item in claim_rows(admin_engine, tenant))
    assert counted(usage(db, world, members[0], first)) == {"scoped": (3, 0)}
    # Settling does not refill a ceiling: the group's fourth isolation is still refused.
    (seventh,) = targets(admin_engine, world, count=1)
    assert checkpoint(db, world, members[0], action=seventh).view.state == "DENIED"
    assert len(impact_rows(admin_engine, tenant)) == 3


def test_gc3_a_checkpoint_and_a_dispatch_draw_on_one_ceiling_in_every_scope(
    db, gate_world, admin_engine, owner
):
    """GC3: the budget a checkpoint charges is the budget an agent spends.

    The two paths cannot run under one mapping, because a Gate mapping on an account that
    has a connector is refused as a deployment contradicting its own bundle, so the owner
    moves the flag between them here. The limit rules are unchanged across the move, and so
    are the retained rows they count: what the two paths share is the ledger and not the
    mapping.
    """
    world = gate_world
    identity, tenant = world["identity"], world["identity"].tenant_id
    squad = group(owner, world, identity, name="squad")
    scoped_bundle(
        db,
        world,
        rule(rule_id="autonomous", budget="autonomous", max_targets=1),
        rule(rule_id="total", scope="tenant", budget="total", max_targets=3, on_exceed="DENY"),
        # Ten, not three: the group rule is here to show that both paths charge the same
        # shared counter and retain the same membership, and a second ceiling reached in
        # the same request would make the denial below say two things at once.
        rule(rule_id="squad", scope="group", group_id=squad, max_targets=10, on_exceed="DENY"),
    )
    first, second, third, fourth = targets(admin_engine, world, count=4)
    checkpointed = checkpoint(db, world, action=first)
    assert checkpointed.view.checkpoint is not None
    assert counted(usage(db, world, identity, checkpointed.view.execution_id)) == {
        "autonomous": (0, 1),
        "total": (0, 1),
        "squad": (0, 1),
    }
    # At the autonomous ceiling the next checkpoint escalates exactly as an agent request
    # does, and the approved retry adds one total unit and no autonomous one.
    pending = checkpoint(db, world, action=second)
    assert pending.view.state == "PENDING_APPROVAL"
    payload = transition_payload(
        admin_engine, tenant, pending.view.execution_id, "PENDING_APPROVAL"
    )
    assert payload["obligations"] == ["limit:autonomous"]
    decide_approval(db, world["human"], pending.view.approval_id, "APPROVE", world["clock"])
    approved = checkpoint(db, world, action=second)
    assert approved.view.checkpoint is not None
    assert counted(usage(db, world, identity, approved.view.execution_id)) == {
        "autonomous": (0, 1),
        "total": (0, 2),
        "squad": (0, 2),
    }
    # The owner stops externally executing the operation; the agent path now dispatches
    # and meets the same counters, still one short of the tenant's total ceiling.
    gate_bundle(db, world, external_executor=False)
    accounts = connected_account(world)
    escalated = checkpoint(db, world, accounts=accounts, action=third)
    assert escalated.view.state == "PENDING_APPROVAL" and escalated.ticket is None
    decide_approval(db, world["human"], escalated.view.approval_id, "APPROVE", world["clock"])
    dispatched_third = checkpoint(db, world, accounts=accounts, action=third)
    assert dispatched_third.ticket is not None
    assert finish(db, world, dispatched_third).state == "EXECUTED"
    assert counted(usage(db, world, identity, dispatched_third.view.execution_id)) == {
        "autonomous": (0, 1),
        "total": (1, 2),
        "squad": (1, 2),
    }
    # The total ceiling is reached once across the two paths: the fourth request is denied
    # on the dispatch path, and denied again on the checkpoint path when the owner moves
    # the flag back, with nothing reserved either time.
    denied = checkpoint(db, world, accounts=accounts, action=fourth)
    assert denied.view.state == "DENIED" and denied.ticket is None
    gate_bundle(db, world, external_executor=True)
    refused = checkpoint(db, world, action=again(fourth))
    assert refused.view.state == "DENIED" and refused.view.checkpoint is None
    for item in (denied, refused):
        payload = transition_payload(admin_engine, tenant, item.view.execution_id, "DENIED")
        assert payload["reasons"] == ["HARD_LIMIT:total"]
    assert len(impact_rows(admin_engine, tenant)) == 3
    # Both paths retain the same scope attributes, which is what makes the counters shared.
    charged = impact_groups(admin_engine, tenant)
    assert charged == {
        item.view.execution_id: [str(squad)] for item in (checkpointed, approved, dispatched_third)
    }


def approval_row(engine, approval_id):
    with engine.connect() as conn:
        return conn.execute(
            text(
                "SELECT state, required_approvers, expires_at FROM execbound.approvals "
                "WHERE approval_id=:a"
            ),
            {"a": approval_id},
        ).one()


def approval_decisions(engine, approval_id):
    with engine.connect() as conn:
        return conn.execute(
            text(
                "SELECT principal_id, decision FROM execbound.approval_decisions "
                "WHERE approval_id=:a ORDER BY decided_at"
            ),
            {"a": approval_id},
        ).all()


def test_gc4_a_checkpoint_that_requires_approval_grants_once_after_a_human_decides(
    db, gate_world, admin_engine
):
    """GC4: the approval lifecycle is the agent path's, and one decision buys one grant."""
    world = gate_world
    tenant = world["identity"].tenant_id
    gate_bundle(db, world, approval_policies=APPROVAL)
    pending = checkpoint(db, world)
    assert pending.view.state == "PENDING_APPROVAL"
    # No grant and no reservation: a pending approval charges no scope and holds no target,
    # so nothing has been told it may act and nothing is being charged for waiting.
    assert pending.view.checkpoint is None and pending.ticket is None
    assert impact_rows(admin_engine, tenant) == [] and claim_rows(admin_engine, tenant) == []
    row = grant_row(admin_engine, tenant, pending.view.execution_id)
    assert row["owner_hash"] is None and row["dispatch_attempted_at"] is None
    state, required, expires_at = approval_row(admin_engine, pending.view.approval_id)
    # One approver because this bundle declares no quorum rule, which is the default
    # `required_approvers` answers; the quorum the row asks about is the next scenario.
    assert world["bundle"].quorum is None
    assert (state, required) == ("PENDING", 1)
    assert expires_at > world["clock"].now()
    # A retry while the human is still deciding grants nothing either.
    assert checkpoint(db, world).view.checkpoint is None
    decide_approval(db, world["human"], pending.view.approval_id, "APPROVE", world["clock"])
    granted = checkpoint(db, world)
    grant = granted.view.checkpoint
    assert granted.view.execution_id == pending.view.execution_id
    assert grant is not None and not grant.regranted and grant.report_secret is not None
    assert granted.ticket is None
    assert approval_row(admin_engine, pending.view.approval_id).state == "CONSUMED"
    assert [
        decision for _, decision in approval_decisions(admin_engine, pending.view.approval_id)
    ] == ["APPROVE"]
    # Consumed exactly once and reserved exactly once: the grant that followed the decision
    # is the only one, and a later retry re-describes it without a second secret.
    assert [item["approved"] for item in impact_rows(admin_engine, tenant)] == [True]
    assert [item["released_at"] for item in claim_rows(admin_engine, tenant)] == [None]
    retry = checkpoint(db, world)
    assert retry.view.checkpoint is not None and retry.view.checkpoint.regranted
    assert retry.view.checkpoint.report_secret is None
    assert approval_row(admin_engine, pending.view.approval_id).state == "CONSUMED"
    assert len(approval_decisions(admin_engine, pending.view.approval_id)) == 1
    assert len(impact_rows(admin_engine, tenant)) == 1


def test_gc4_a_checkpoint_at_a_two_person_quorum_grants_once_after_both_decide(
    db, gate_world, admin_engine
):
    """GC4's quorum clause: the approval a checkpoint creates is the bundle's, quorum included.

    Gate adds no approval code, so what this holds is that the checkpoint path reaches the
    quorum the active bundle declares rather than a one that a Gate branch could have
    assumed. The machinery itself, including a rejection inside a quorum and the preview of
    a quorum change, belongs to `tests/test_approval_quorum.py`.
    """
    world = gate_world
    tenant = world["identity"].tenant_id
    approving = gate_bundle(db, world, approval_policies=APPROVAL)
    rule = QuorumRule(
        rule_id="two-person-production",
        obligation=production_obligation(approving),
        required=2,
    )
    gate_bundle(db, world, approval_policies=APPROVAL, quorum=(rule,))
    pending = checkpoint(db, world)
    assert pending.view.state == "PENDING_APPROVAL" and pending.view.checkpoint is None
    waiting = approval_row(admin_engine, pending.view.approval_id)
    assert (waiting.state, waiting.required_approvers) == ("PENDING", 2)
    decide_approval(db, world["human"], pending.view.approval_id, "APPROVE", world["clock"])
    # One of the two: the approval is unsatisfied, so the retry is answered exactly as the
    # retry before any decision was, with nothing granted and nothing reserved.
    assert approval_row(admin_engine, pending.view.approval_id).state == "PENDING"
    half = checkpoint(db, world)
    assert half.view.state == "PENDING_APPROVAL" and half.view.checkpoint is None
    assert impact_rows(admin_engine, tenant) == [] and claim_rows(admin_engine, tenant) == []
    other = second_approver(admin_engine, db, world)
    decide_approval(db, other, pending.view.approval_id, "APPROVE", world["clock"])
    granted = checkpoint(db, world)
    assert granted.view.execution_id == pending.view.execution_id
    assert granted.view.checkpoint is not None and not granted.view.checkpoint.regranted
    assert granted.ticket is None
    # Two decisions, one consumption, one grant and one reservation.
    assert approval_row(admin_engine, pending.view.approval_id).state == "CONSUMED"
    assert [
        decision for _, decision in approval_decisions(admin_engine, pending.view.approval_id)
    ] == ["APPROVE", "APPROVE"]
    assert [item["approved"] for item in impact_rows(admin_engine, tenant)] == [True]
    assert [item["released_at"] for item in claim_rows(admin_engine, tenant)] == [None]


def test_gc5_a_denied_checkpoint_grants_nothing_and_replays_to_the_same_decision(
    db, gate_world, admin_engine
):
    """GC5: a denial is a decision the tenant retains, not a grant with nothing in it."""
    from execbound.replay.export import export_history
    from execbound.replay.simulate import simulate
    from execbound.replay.verify import verify_export

    world = gate_world
    tenant = world["identity"].tenant_id
    scoped_bundle(db, world, rule(max_targets=1, on_exceed="DENY"))
    first, second = targets(admin_engine, world, count=2)
    holder = checkpoint(db, world, action=first)
    assert holder.view.checkpoint is not None
    denied = checkpoint(db, world, action=second)
    assert denied.view.state == "DENIED"
    assert denied.view.checkpoint is None and denied.ticket is None
    row = grant_row(admin_engine, tenant, denied.view.execution_id)
    # No secret was minted and no attempt stamped, so nothing about this row says an act
    # was ever authorized; the report window it carries is the marker admission writes at
    # the insert for a Gate mapping in a tenant that is enforcing. An observing tenant is
    # the other half and gets none, which GC15 asserts.
    assert row["owner_hash"] is None and row["dispatch_attempted_at"] is None
    assert row["report_expires_at"] is not None
    assert [item["execution_id"] for item in impact_rows(admin_engine, tenant)] == [
        holder.view.execution_id
    ]
    assert [item["execution_id"] for item in claim_rows(admin_engine, tenant)] == [
        holder.view.execution_id
    ]
    payload = transition_payload(admin_engine, tenant, denied.view.execution_id, "DENIED")
    assert payload["reasons"] == ["HARD_LIMIT:scoped"]
    # The denial is an ordinary capture in the tenant's chain and recomputes to itself.
    history = export_history(db, world["admin"], world["clock"])
    replayed = simulate(verify_export(history, history.head))
    assert replayed.complete, replayed.issues
    rows = {item.execution_id: item for item in replayed.decisions}
    decision = rows[denied.view.execution_id]
    assert decision.recorded_effect == "DENY"
    assert decision.baseline.effect == "DENY"
    assert decision.baseline.reasons == ("HARD_LIMIT:scoped",)
    assert decision.differences == ()
    assert rows[holder.view.execution_id].recorded_effect == "ELIGIBLE"


def test_gc6_a_settled_checkpoint_is_closed_to_change_and_answers_its_own_restatement(
    db, gate_world, admin_engine, owner
):
    """GC6, with the row narrowed to what the code does and is meant to do.

    The acceptance row said "different evidence on the settled row is refused"; what
    `_restates` compares is the tier, the outcome and the reason, so a second record that
    is genuinely different — a later reported time, or a signature by a second registered
    key — but says exactly what the row already settled is verified, found to move
    nothing, and answered as the no-op it is: nothing retained, nothing appended, the
    first record's proof digest still the one this settlement rests on. Only a
    contradiction is refused.

    The row is narrowed rather than the code changed, because refusing such a record
    protects nothing and costs the property the restatement branch exists for. Nothing is
    retained either way, so the refusal would prevent no change to the execution; Ed25519
    signing is deterministic, so a record that differs at all is one some holder of a key
    this tenant registered signed — the executor, or an administrator whose settlement key
    sits in the same ring — and the obvious case is an executor that lost its response and
    re-signs with a current clock, which is what a client that does not cache its own bytes
    does. It would be told its own settled outcome is invalid. What a settled row must be
    closed to is a *change*, and it is.

    What retaining nothing costs is asserted below rather than left implied: the chain is
    byte-identical across all three restatements, so a tenant cannot afterwards see that a
    second of its keys attested this settlement. Nothing about the execution, the budget or
    the claim moved, which is why that is accepted, and it stands as a limit of what the
    history can answer.
    """
    world = gate_world
    tenant = world["identity"].tenant_id
    # Registered before the chain below is captured, because an administration event is an
    # append like any other and this scenario counts appends.
    second_key = register_keypair(owner, world, key_id="executor-second")
    granted = checkpoint(db, world)
    grant = granted.view.checkpoint
    assert grant is not None
    record = signed_record(db, world, granted.view.execution_id)
    assert report(
        db, world, granted.view.execution_id, grant.report_secret, record=record
    ).state == ("EXECUTED")
    settled = retained(admin_engine, tenant, granted.view.execution_id)
    assert (settled.state, settled.tier, settled.impact) == ("EXECUTED", "ATTESTED", "CONFIRMED")
    assert settled.released_at == world["clock"].now()
    assert settled.result["tier"] == "ATTESTED"
    chain = audit_kinds(admin_engine, tenant)
    assert [payload["tier"] for payload in reported(admin_engine, tenant)] == ["ATTESTED"]
    later = signed_record(
        db,
        world,
        granted.view.execution_id,
        reported_at=world["clock"].now() + timedelta(minutes=1),
    )
    by_another_key = signed_record(
        db,
        world,
        granted.view.execution_id,
        private_key=second_key,
        key_id="executor-second",
    )
    # The identical repeat, a later reported time and a second registered key: three
    # records, each verifying, none of them saying anything the row has not settled.
    for restating in (record, later, by_another_key):
        assert report(
            db, world, granted.view.execution_id, grant.report_secret, record=restating
        ).state == ("EXECUTED")
    assert {record["signature"], later["signature"], by_another_key["signature"]} != {
        record["signature"]
    }
    assert audit_kinds(admin_engine, tenant) == chain
    assert retained(admin_engine, tenant, granted.view.execution_id) == settled
    # A contradiction is refused rather than discarded, in either direction: a different
    # outcome, and the executor's bare word where its own signed record settled it.
    contradictions = (
        {
            "record": signed_record(
                db, world, granted.view.execution_id, **UNCERTAIN["non-execution"]
            ),
            **UNCERTAIN["non-execution"],
        },
        {},
    )
    for changes in contradictions:
        with pytest.raises(ExecutionError) as refused:
            report(db, world, granted.view.execution_id, grant.report_secret, **changes)
        assert refused.value.code == "INVALID_STATE"
    assert retained(admin_engine, tenant, granted.view.execution_id) == settled
    assert [kind for kind, _ in audit_kinds(admin_engine, tenant)[len(chain) :]] == [
        "execution.rejected"
    ] * 2
    # The neighbouring case, refused for a different reason and by a different guard: a
    # record stamped before the grant existed is nonsense, and the verifier says so before
    # the settled row is ever consulted about what it restates.
    stamped = grant_row(admin_engine, tenant, granted.view.execution_id)["dispatch_attempted_at"]
    impossible = signed_record(
        db, world, granted.view.execution_id, reported_at=stamped - timedelta(seconds=1)
    )
    with pytest.raises(ExecutionError) as unverifiable:
        report(db, world, granted.view.execution_id, grant.report_secret, record=impossible)
    assert unverifiable.value.code == "INVALID_RECORD"
    assert retained(admin_engine, tenant, granted.view.execution_id) == settled


def test_gc7_an_asserted_execution_confirms_the_impact_and_holds_its_target(
    db, gate_world, admin_engine
):
    """GC7: the safe direction is automatic, and the unsafe one waits for the act window.

    An assertion confirms the impact because charging for an action that may have happened
    is the safe direction, and it does not release the canonical claim, because an executor
    that could free the target by claiming success would take a grant, report without
    acting and re-request the same target at once.
    """
    world = gate_world
    tenant = world["identity"].tenant_id
    action = request(world)
    granted = checkpoint(db, world, action=action)
    grant = granted.view.checkpoint
    assert grant is not None
    assert report(db, world, granted.view.execution_id, grant.report_secret).state == "EXECUTED"
    settled = retained(admin_engine, tenant, granted.view.execution_id)
    assert (settled.state, settled.tier, settled.impact) == ("EXECUTED", "ASSERTED", "CONFIRMED")
    assert settled.confirmed_at == world["clock"].now() and settled.released_at is None
    # Retained under its own key and at its own tier: an assertion is never terminal
    # evidence, so it carries no proof digest and no authenticated record.
    assert settled.result["tier"] == "ASSERTED"
    assert "proof_digest" not in settled.result and "authenticated_record" not in settled.result
    # The observable behind the held claim: the target is unavailable to the tenant.
    other = agent(admin_engine, db, world)
    busy = checkpoint(db, world, other, action=again(action))
    assert busy.view.state == "DENIED" and busy.view.checkpoint is None
    payload = transition_payload(admin_engine, tenant, busy.view.execution_id, "DENIED")
    assert payload["reason"] == "RESOURCE_BUSY"
    # The record says which tier settled it and that the claim is still held.
    with console(db, world, admin_engine) as admin:
        block = article(admin, granted.view.execution_id)
    assert shown("Asserted: the executor's authenticated word") in block
    assert shown("Held: no other ExecBound request in this tenant") in block
    # The one exit: the scheduled run, once the act window measured from the grant's own
    # attempt stamp has passed and the row has been unchanged for the run's grace period.
    # "Only after" is the half worth running, so the same run is made first at an instant
    # past its grace period and one second short of the act window: the executor may still
    # be acting, and a run that freed the target here would free it while it may.
    stamped = grant_row(admin_engine, tenant, granted.view.execution_id)["dispatch_attempted_at"]
    world["clock"].value = stamped + ACT_WINDOW - timedelta(seconds=1)
    early = recover(db, world["admin"], {}, clock=world["clock"])
    assert (early.released, early.swept) == (0, 0)
    assert retained(admin_engine, tenant, granted.view.execution_id) == settled
    world["clock"].value = stamped + ACT_WINDOW + timedelta(seconds=301)
    counts = recover(db, world["admin"], {}, clock=world["clock"])
    assert (counts.released, counts.swept) == (1, 0)
    released = retained(admin_engine, tenant, granted.view.execution_id)
    assert (released.state, released.tier, released.impact) == ("EXECUTED", "ASSERTED", "CONFIRMED")
    assert released.released_at == world["clock"].now()
    assert released.confirmed_at == settled.confirmed_at


def test_gc8_an_asserted_non_execution_is_settled_only_by_an_administrator(
    db, gate_world, admin_engine
):
    """GC8: nothing an executor says refunds a reservation, and the exit is not its to take."""
    world = gate_world
    tenant = world["identity"].tenant_id
    granted = checkpoint(db, world)
    grant = granted.view.checkpoint
    assert grant is not None
    view = report(
        db, world, granted.view.execution_id, grant.report_secret, **UNCERTAIN["non-execution"]
    )
    assert view.state == "INDETERMINATE"
    uncertain = retained(admin_engine, tenant, granted.view.execution_id)
    # Nothing settled: the impact is still charged, the claim is still held, and the row
    # carries no tier, because a tier is what a settlement was worth and nothing settled.
    assert (uncertain.state, uncertain.tier, uncertain.result) == ("INDETERMINATE", None, None)
    assert (uncertain.impact, uncertain.released_at) == ("UNRESOLVED", None)
    (transition,) = transitions(admin_engine, tenant, "INDETERMINATE")
    assert transition["asserted"]["reason"] == "CANCELLED_NOT_EXECUTED"
    assert "evidence" not in transition and "tier" not in transition
    record = json.dumps(signed_record(db, world, granted.view.execution_id)).encode()
    verifier = _verifier(db, world, granted.view.execution_id)
    # The executor cannot reach the administrator's path with the same record: the
    # connector-free reconciliation is an ADMIN route and the grant holder is an AGENT.
    with pytest.raises(ExecutionError) as refused:
        reconcile(
            db,
            world["identity"],
            granted.view.execution_id,
            reason="the executor settling its own uncertainty",
            evidence=record,
            verifier=verifier,
            clock=world["clock"],
        )
    assert refused.value.code == "INVALID_IDENTITY"
    assert retained(admin_engine, tenant, granted.view.execution_id) == uncertain
    # The administrator settles it from the executor's signed record, through a path that
    # asks no connector at all — this tenant has none for the account.
    settled = reconcile(
        db,
        world["admin"],
        granted.view.execution_id,
        reason="settled from the executor's signed record",
        evidence=record,
        verifier=verifier,
        verifier_for=executor_verifier,
        clock=world["clock"],
    )
    assert settled.state == "EXECUTED"
    row = retained(admin_engine, tenant, granted.view.execution_id)
    assert (row.state, row.tier, row.impact) == ("EXECUTED", "ATTESTED", "CONFIRMED")
    assert row.released_at == world["clock"].now()


def test_gc9_every_report_the_route_refuses_leaves_the_row_and_the_secret_where_they_were(
    db, world, owner, admin_engine
):
    """GC9: five refusals, and the one execution none of them may reach.

    The dispatched execution is the point of the row: its owner secret is the same kind of
    value in the same column, and what settles it is its provider's journal — through the
    ticket this process never released, or through an administrator's reconciliation —
    never a report an executor sends.
    """
    tenant = world["identity"].tenant_id
    # The window below closes a day after the grant, so the administrator whose refusals
    # this scenario ends with has to still be a current one when the clock gets there.
    world["admin"] = long_lived_admin(admin_engine, db, world)
    # The private half is kept, because the last clause of this row is about a record the
    # tenant's own executor really signed being offered against the wrong execution.
    world["executor_key"] = register_keypair(owner, world)
    gate_bundle(db, world, external_executor=False)
    (dispatched_target,) = targets(admin_engine, world, count=1)
    ordinary = dispatched(db, world, admin_engine, action=dispatched_target)
    gate_bundle(db, world, external_executor=True)
    patient = long_lived_agent(admin_engine, db, world)
    first, second, third = targets(admin_engine, world, count=3)
    mine = checkpoint(db, world, action=first).view
    settled = checkpoint(db, world, action=second).view
    closing = checkpoint(db, world, patient, action=third).view
    grants = {view.execution_id: view.checkpoint.report_secret for view in (mine, settled, closing)}
    assert all(grants.values())
    assert report(db, world, settled.execution_id, grants[settled.execution_id]).state == "EXECUTED"
    stranger = agent(admin_engine, db, world)
    forged = secrets.token_urlsafe(32)
    refusals = [
        # An operation ExecBound dispatched, presenting the owner secret that does settle
        # it: refused on the frozen mapping before the secret is even compared.
        (ordinary.view.execution_id, ordinary.ticket.secret, world["identity"], "INVALID_STATE"),
        # Another principal's checkpoint, presenting that grant's own secret.
        (mine.execution_id, grants[mine.execution_id], stranger, "NOT_FOUND"),
        # An execution already settled, contradicted rather than restated.
        (settled.execution_id, grants[settled.execution_id], world["identity"], "INVALID_STATE"),
        # A secret that was never minted, and one minted for another grant of the same
        # principal, which is the replay a leaked response makes possible.
        (mine.execution_id, forged, world["identity"], "INVALID_REPORT"),
        (mine.execution_id, grants[settled.execution_id], world["identity"], "INVALID_REPORT"),
    ]
    # The execution row alone would not say it: a refusal that released a claim or moved an
    # impact without touching the state would read as no change at all, so what is captured
    # is the whole of what a settlement writes for each of these rows.
    before = {
        execution_id: (
            grant_row(admin_engine, tenant, execution_id),
            retained(admin_engine, tenant, execution_id),
        )
        for execution_id in (ordinary.view.execution_id, *grants)
    }
    for index, (execution_id, secret, identity, code) in enumerate(refusals):
        changes = UNCERTAIN["non-execution"] if code == "INVALID_STATE" else {}
        with pytest.raises(ExecutionError) as refused:
            report(db, world, execution_id, secret, identity, **changes)
        assert refused.value.code == code, index
    # The window closes last, because closing it means moving the clock past a deadline
    # every other grant here shares.
    world["clock"].value = closing.checkpoint.report_expires_at
    with pytest.raises(ExecutionError) as expired:
        report(
            db,
            world,
            closing.execution_id,
            grants[closing.execution_id],
            patient,
            **UNCERTAIN["unknown"],
        )
    assert expired.value.code == "REPORT_WINDOW_CLOSED"
    # No state changed anywhere — not the execution row, not the impact it charged, not the
    # claim it holds — and no audit payload carries a secret or its digest.
    for execution_id, unchanged in before.items():
        assert (
            grant_row(admin_engine, tenant, execution_id),
            retained(admin_engine, tenant, execution_id),
        ) == unchanged
    payloads = str(audit_kinds(admin_engine, tenant))
    for secret in (*grants.values(), ordinary.ticket.secret, forged):
        assert secret not in payloads and secret_digest(secret) not in payloads
    reasons = [
        payload["reason"] for payload in audit_payloads(admin_engine, tenant, "execution.rejected")
    ]
    assert reasons == [code for *_, code in refusals] + ["REPORT_WINDOW_CLOSED"]
    # The dispatched execution keeps its own owner secret as the only way to settle it:
    # the kernel refuses an executor's record for it at both settlement functions that take
    # a verifier, and the provider's own journal, carried by the ticket, settles it.
    executor = _verifier(db, world, ordinary.view.execution_id)
    signed = json.dumps(signed_record(db, world, ordinary.view.execution_id)).encode()
    with pytest.raises(ExecutionError) as administrator:
        reconcile(
            db,
            world["admin"],
            ordinary.view.execution_id,
            reason="an executor record for an operation ExecBound dispatched",
            evidence=signed,
            verifier=executor,
            clock=world["clock"],
        )
    assert administrator.value.code == "INVALID_STATE"
    with pytest.raises(ExecutionError) as ticketed:
        record_outcome(db, ordinary.ticket, signed, executor, world["clock"])
    assert ticketed.value.code == "INVALID_STATE"
    assert record_outcome(
        db, ordinary.ticket, b"test-journal-proof", FixtureJournal(), world["clock"]
    ).state == ("EXECUTED")
    provider_settled = retained(admin_engine, tenant, ordinary.view.execution_id)
    assert (provider_settled.state, provider_settled.tier) == ("EXECUTED", None)


def test_gc10_an_unreported_grant_is_swept_into_uncertainty_and_never_cancelled(
    db, gate_world, admin_engine
):
    """GC10: an unreported grant becomes retained uncertainty with an exit, never a refund."""
    world = gate_world
    tenant = world["identity"].tenant_id
    world["admin"] = long_lived_admin(admin_engine, db, world)
    granted = checkpoint(db, world)
    assert granted.view.checkpoint is not None
    counts = sweep(db, world, admin_engine, granted.view.execution_id)
    assert (counts.swept, counts.unresolved, counts.uncertain_grants) == (1, 0, 0)
    swept = retained(admin_engine, tenant, granted.view.execution_id)
    # Nothing settled, nothing refunded, nothing released: the reservation goes on charging
    # every scope it took and the target goes on being unavailable to the tenant.
    assert (swept.state, swept.tier, swept.result) == ("INDETERMINATE", None, None)
    assert (swept.impact, swept.released_at) == ("UNRESOLVED", None)
    (transition,) = transitions(admin_engine, tenant, "INDETERMINATE")
    assert transition["reason"] == "UNREPORTED_GRANT"
    with console(db, world, admin_engine) as admin:
        assert uncertain(admin) == [str(granted.view.execution_id)]
        block = article(admin, granted.view.execution_id)
        # The connector-free settlement, and never the cancellation beside it.
        assert settlement(admin, granted.view.execution_id) == "record"
    assert shown(EXTERNALLY_EXECUTED) in block
    # A cancellation run settles a never-attempted dispatch as a non-execution; for a grant
    # that would be the refund on absent evidence that is never allowed, so the run's
    # checkpoint branch is taken before any connector is looked up and nothing moves.
    # Past the run's grace period again, because the sweep is itself a change to the row
    # and a run leaves a row it has just moved for the next one to look at.
    world["clock"].value = world["clock"].now() + timedelta(seconds=301)
    cancelling = recover(db, world["admin"], {}, cancel_unattempted=True, clock=world["clock"])
    assert (cancelling.cancelled, cancelling.not_executed, cancelling.swept) == (0, 0, 0)
    assert (cancelling.uncertain_grants, cancelling.unresolved) == (1, 0)
    assert retained(admin_engine, tenant, granted.view.execution_id) == swept
    # And the connector reconciliation the run would have used refuses a grant outright, in
    # both modes, without asking the provider anything about an operation it never sent.
    connector = FixtureConnector()
    for cancel in (False, True):
        with pytest.raises(ExecutionError) as refused:
            reconcile_operation(
                db,
                world["admin"],
                granted.view.execution_id,
                connector,
                reason="operator reconciling this account's operations",
                cancel_if_missing=cancel,
                clock=world["clock"],
                verifier=FixtureJournal("FAILED_NOT_EXECUTED"),
            )
        assert refused.value.code == "INVALID_STATE"
    assert connector.asked == []
    assert retained(admin_engine, tenant, granted.view.execution_id) == swept


def answer(call):
    """One report's answer as a racing thread sees it: the state, or the refusal's code."""
    try:
        return call().state
    except ExecutionError as exc:
        return exc.code


def test_gc11_two_simultaneous_reports_on_one_grant_settle_it_once(db, gate_world, admin_engine):
    """GC11: two connections, one settlement, one confirmation, one release, one capture.

    The double submit first, which is the shape a retrying caller produces: both are the
    same attested record, so whichever loses the fence finds the row already settled with
    exactly what it was going to say and is answered rather than refused.
    """
    world = gate_world
    tenant = world["identity"].tenant_id
    granted = checkpoint(db, world)
    grant = granted.view.checkpoint
    assert grant is not None
    record = signed_record(db, world, granted.view.execution_id)
    results = raced(
        lambda _: answer(
            lambda: report(db, world, granted.view.execution_id, grant.report_secret, record=record)
        ),
        count=2,
    )
    assert [state for _, state in results] == ["EXECUTED", "EXECUTED"]
    settled = retained(admin_engine, tenant, granted.view.execution_id)
    assert (settled.state, settled.tier, settled.impact) == ("EXECUTED", "ATTESTED", "CONFIRMED")
    assert settled.released_at is not None
    assert len(reported(admin_engine, tenant)) == 1
    assert len(transitions(admin_engine, tenant, "EXECUTED")) == 1
    assert [item["confirmed_at"] for item in impact_rows(admin_engine, tenant)] == [
        settled.confirmed_at
    ]
    assert [item["released_at"] for item in claim_rows(admin_engine, tenant)] == [
        settled.released_at
    ]
    # And when the two disagree, exactly one settles and the other is refused against the
    # row it now finds settled. Which one wins is the fence's to decide, so the assertion
    # is about the pair: the same two reports sent in either order give the same answer.
    (second,) = targets(admin_engine, world, count=1)
    other = checkpoint(db, world, action=second)
    secret = other.view.checkpoint.report_secret
    signed = signed_record(db, world, other.view.execution_id)
    bodies = [{"record": signed}, {}]
    disagreeing = raced(
        lambda index: answer(
            lambda: report(db, world, other.view.execution_id, secret, **bodies[index])
        ),
        count=2,
    )
    answers = sorted(state for _, state in disagreeing)
    assert answers == ["EXECUTED", "INVALID_STATE"]
    row = retained(admin_engine, tenant, other.view.execution_id)
    assert row.state == "EXECUTED" and row.tier in {"ATTESTED", "ASSERTED"}
    assert [payload["tier"] for payload in reported(admin_engine, tenant)][1:] == [row.tier]


# What each precondition class is worth when the target changes between the grant and the
# action: the report the executor can honestly make, and what that report settles.
GC12 = {
    "ENFORCED_BY_PROVIDER": (
        {"signed": True, **UNCERTAIN["version-mismatch"]},
        ("STALE_AUTHORIZATION", "ATTESTED", "NONEXECUTION", True),
    ),
    "ASSERTED_BY_EXECUTOR": (
        dict(UNCERTAIN["version-mismatch"]),
        ("INDETERMINATE", None, "UNRESOLVED", False),
    ),
    "UNAVAILABLE": ({"signed": True}, ("EXECUTED", "ATTESTED", "CONFIRMED", True)),
}


@pytest.mark.parametrize(
    "declared,body,expected", [(k, *v) for k, v in GC12.items()], ids=list(GC12)
)
def test_gc12_the_target_changed_between_grant_and_report(
    db, gate_world, admin_engine, declared, body, expected
):
    """GC12: the frozen precondition is only as strong as the vendor's conditional write.

    The class is deployment configuration keyed by the provider binding, so each case
    declares one and asserts what the grant carried and what the report it made possible
    settled. Under the strongest class the executor's conditional write refuses and the
    reservation is released on evidence ExecBound verified; under the middle one the
    executor can only compare, so its refusal is an assertion and releases nothing; under
    the weakest the grant carries no version and the change is undetectable.
    """
    world = gate_world
    tenant = world["identity"].tenant_id
    granted = checkpoint(db, world, preconditions=PreconditionConfig({CONTAIN: declared}))
    grant = granted.view.checkpoint
    assert grant is not None and grant.precondition_class == declared
    frozen = frozen_plan(db, world, granted.view.execution_id)
    if declared == "UNAVAILABLE":
        assert grant.expected_version is None
    else:
        assert grant.expected_version == frozen.resource_version
    # The vendor's own console changes the target between the grant and the action, which
    # is the window the class is a statement about. A grant hands the executor the version
    # its own plan froze and never a live read, so the change is made where it can say so:
    # the re-answer below is minted after it, and still carries what the plan froze.
    assert frozen.resource_version != "resource-v9"
    move_resource_version(admin_engine, tenant, "resource-v9")
    regranted = checkpoint(db, world, preconditions=PreconditionConfig({CONTAIN: declared}))
    assert regranted.view.checkpoint is not None and regranted.view.checkpoint.regranted
    assert regranted.view.checkpoint.expected_version == grant.expected_version
    changes = dict(body)
    signed = changes.pop("signed", False)
    record = signed_record(db, world, granted.view.execution_id, **changes) if signed else None
    view = report(
        db, world, granted.view.execution_id, grant.report_secret, record=record, **changes
    )
    state, tier, impact, released = expected
    assert view.state == state
    row = retained(admin_engine, tenant, granted.view.execution_id)
    assert (row.state, row.tier, row.impact) == (state, tier, impact)
    assert (row.released_at is not None) == released
    if declared == "ASSERTED_BY_EXECUTOR":
        # Recorded as the executor's word about a race it says it saw, under its own key
        # and at no tier: nothing here is evidence ExecBound checked.
        (transition,) = transitions(admin_engine, tenant, "INDETERMINATE")
        assert transition["asserted"]["reason"] == "VERSION_MISMATCH"
        assert "evidence" not in transition and "tier" not in transition
    if declared == "UNAVAILABLE":
        # The executor was given nothing to compare, so its record names no version and
        # the settled history cannot say whether the target changed. What it does say is
        # the class the grant was issued under, retained where each grant was recorded —
        # the first answer and the re-answer above.
        issued = audit_payloads(admin_engine, tenant, GRANTED)
        assert [payload["precondition_class"] for payload in issued] == ["UNAVAILABLE"] * 2
        assert not [key for key in row.result if "version" in key]


def test_gc13_a_report_outlives_the_plan_and_the_act_window_and_a_retry_grants_nothing_new(
    db, gate_world, admin_engine, token_keys
):
    """GC13: two windows with different authenticators, and one secret per execution.

    The act window is a continuation token bounded by the frozen plan; the report window is
    carried by the row and authenticated by the report secret, because an executor whose
    vendor call was queued or retried must still be able to report after the act window
    has closed.
    """
    world = gate_world
    identity, tenant = world["identity"], world["identity"].tenant_id
    runtime = gate_runtime(db, world, keys=token_keys)
    view = granted(runtime, world)
    first = runtime.present(identity, view)["checkpoint"]
    grant = view.checkpoint
    assert grant is not None and grant.report_secret is not None
    digest = grant_row(admin_engine, tenant, view.execution_id)["owner_hash"]
    # The idempotent retry: the same act, described again, with a freshly signed token and
    # no second secret. The one secret this execution ever had is still what settles it.
    retried = runtime.execute(identity, request(world).model_dump_json().encode())
    second = runtime.present(identity, retried)["checkpoint"]
    assert retried.execution_id == view.execution_id
    assert second["grant"] == {**first["grant"], "regranted": True, "report_secret": None}
    assert second["act"] != first["act"]
    before = act_claim(first["act"], token_keys, identity, world["clock"])
    after = act_claim(second["act"], token_keys, identity, world["clock"])
    assert (after.execution_id, after.operation_id, after.plan_hash, after.expires_at) == (
        before.execution_id,
        before.operation_id,
        before.plan_hash,
        before.expires_at,
    )
    assert grant_row(admin_engine, tenant, view.execution_id)["owner_hash"] == digest
    assert len(impact_rows(admin_engine, tenant)) == 1
    assert len(claim_rows(admin_engine, tenant)) == 1
    # The executor's vendor call is queued and answers long after the plan it was frozen
    # under has expired and the act window has closed.
    record = signed_record(db, world, view.execution_id)
    frozen = frozen_plan(db, world, view.execution_id)
    world["clock"].value = grant.act_expires_at + timedelta(minutes=5)
    now = world["clock"].now()
    assert now > frozen.valid_until and now > grant.act_expires_at
    assert now < grant.report_expires_at
    assert report(db, world, view.execution_id, grant.report_secret, record=record).state == (
        "EXECUTED"
    )
    settled = retained(admin_engine, tenant, view.execution_id)
    assert (settled.state, settled.tier, settled.impact) == ("EXECUTED", "ATTESTED", "CONFIRMED")
    assert settled.released_at == now


def test_gc15_nothing_a_caller_sends_selects_a_checkpoint_and_an_observing_tenant_grants_none(
    db, world, owner, admin_engine
):
    """GC15: Gate is owner-provisioned bundle content, and a tenant property still wins."""
    from execbound.policy.store import (
        PolicyStoreError,
        activate_bundle,
        create_bundle,
        load_active_bundle,
        validate_bundle,
    )

    tenant = world["identity"].tenant_id
    # A bundle carrying both placements cannot be built at all: an observed request
    # reserves nothing and a grant must reserve, so the pair is refused where content is
    # constructed rather than only where it is stored.
    with pytest.raises(ValidationError):
        MappingRef(
            operation_ref="endpoint.isolate",
            account_id=world["account"],
            mapping_version="map-v1",
            schema_version="action.v1",
            context_contract_version="endpoint-isolation.v1",
            observe_only=True,
            external_executor=True,
        )
    # A tenant with no registered executor key can attest no outcome and has no exit for a
    # grant nobody reports, so its bundle cannot declare one.
    with pytest.raises(PolicyStoreError) as unattestable:
        gate_bundle(db, world)
    assert unattestable.value.code == "INVALID_COMPONENT"
    assert unattestable.value.location == "mappings.0.external_executor"
    # A mapping onto a provider operation the released catalog does not bind, validated
    # under a catalog that does: the released catalog decides what may be executed outside
    # ExecBound, because the executor acts against that exact vendor operation.
    register_key(owner, world)
    account = uuid4()
    with admin_engine.begin() as conn:
        conn.execute(
            text(
                "INSERT INTO execbound.connector_accounts(tenant_id, account_id, provider, "
                "space_id) "
                "VALUES (:t, :a, :p, (SELECT space_id FROM execbound.spaces WHERE tenant_id = :t))"
            ),
            {"t": tenant, "a": account, "p": SECOND_PROVIDER},
        )
        conn.execute(
            text(
                "INSERT INTO execbound.operation_mappings "
                "(tenant_id, operation_ref, account_id, provider, resource_type, action, "
                "provider_operation, mapping_version, schema_version, context_contract_version) "
                "VALUES (:t, :ref, :a, :p, 'endpoint', 'endpoint.isolate', 'isolate', "
                "'map-v1', 'action.v1', 'endpoint-isolation.v1')"
            ),
            {"t": tenant, "ref": "endpoint.isolate.unreleased", "a": account, "p": SECOND_PROVIDER},
        )
    unbound = world["bundle"].model_copy(
        update={
            "bundle_id": uuid4(),
            "mappings": (
                MappingRef(
                    operation_ref="endpoint.isolate.unreleased",
                    account_id=account,
                    mapping_version="map-v1",
                    schema_version="action.v1",
                    context_contract_version="endpoint-isolation.v1",
                    external_executor=True,
                ),
            ),
        }
    )
    create_bundle(db, world["admin"], unbound, world["clock"])
    with pytest.raises(PolicyStoreError) as unreleased:
        validate_bundle(db, world["admin"], unbound.bundle_id, world["clock"], catalog=TEST_CATALOG)
    assert unreleased.value.code == "INVALID_COMPONENT"
    assert unreleased.value.location == "mappings.0.external_executor"
    # An existing bundle validates and activates with its bytes unchanged: the flag is
    # serialized only when set, so a mapping without it is the document it always was.
    plain = world["bundle"].model_copy(update={"bundle_id": uuid4()})
    assert "external_executor" not in plain.model_dump_json()
    round_tripped = plain.model_validate_json(plain.model_dump_json())
    assert round_tripped.content_hash == plain.content_hash
    assert round_tripped.security_versions == plain.security_versions
    create_bundle(db, world["admin"], plain, world["clock"])
    validate_bundle(db, world["admin"], plain.bundle_id, world["clock"])
    activate_bundle(db, world["admin"], plain.bundle_id, world["clock"])
    active = load_active_bundle(db, world["admin"], world["clock"])
    assert (active.bundle_id, active.content_hash) == (plain.bundle_id, plain.content_hash)
    assert active.security_versions == plain.security_versions
    # And the flagged bundle this tenant can now support activates and grants.
    gate_bundle(db, world)
    granted = checkpoint(db, world)
    assert granted.view.checkpoint is not None
    # No request field selects Gate, names an executor or declares a class: all three are
    # owner-provisioned content or owner-registered configuration, so each is unknown.
    (unrelated,) = targets(admin_engine, world, count=1)
    runtime = gate_runtime(db, world)
    for field, value in (
        ("external_executor", True),
        ("executor", "story-42"),
        ("precondition_class", "ENFORCED_BY_PROVIDER"),
    ):
        raw = json.loads(unrelated.model_dump_json()) | {field: value}
        with pytest.raises(ExecutionError) as unknown:
            runtime.execute(world["identity"], json.dumps(raw).encode())
        assert unknown.value.code == "INVALID_REQUEST"
    # A tenant-wide OBSERVE mode is not bundle content and wins over it: the request takes
    # the observe branch and is granted nothing, reserves nothing and claims nothing.
    set_enforcement_mode(db, world["admin"], "OBSERVE", "Onboarding", world["clock"])
    (observed_target,) = targets(admin_engine, world, count=1)
    observed = checkpoint(db, world, action=observed_target)
    assert observed.view.state == "OBSERVED" and observed.ticket is None
    assert observed.view.checkpoint is None
    assert observed.view.observed is not None and observed.view.observed.effect == "ELIGIBLE"
    row = grant_row(admin_engine, tenant, observed.view.execution_id)
    assert row["owner_hash"] is None and row["report_expires_at"] is None
    states = [
        item["state"]
        for item in impact_rows(admin_engine, tenant)
        if item["execution_id"] == observed.view.execution_id
    ]
    assert states == ["OBSERVED"]
    assert [item["execution_id"] for item in claim_rows(admin_engine, tenant)] == [
        granted.view.execution_id
    ]


def test_gc16_a_stop_refuses_new_grants_recalls_none_and_starves_no_writer(
    db, gate_world, admin_engine
):
    """GC16: the stop is a gate on new grants, and an issued one is nobody's to recall."""
    from execbound.replay.export import export_history
    from execbound.replay.simulate import simulate
    from execbound.replay.verify import verify_export

    world = gate_world
    tenant = world["identity"].tenant_id
    runtime = gate_runtime(db, world)
    outstanding = checkpoint(db, world)
    grant = outstanding.view.checkpoint
    assert grant is not None
    activate_stop(db, world["admin"], "Suspected credential compromise", world["clock"])
    # A new checkpoint under the stop is refused before anything is decided or reserved.
    (blocked,) = targets(admin_engine, world, count=1)
    with pytest.raises(ExecutionError) as stopped:
        checkpoint(db, world, action=blocked)
    assert stopped.value.code == "TENANT_STOPPED"
    assert len(impact_rows(admin_engine, tenant)) == 1
    # The outstanding grant is not recalled: its act window is the bound on the exposure,
    # and its report still settles, because refusing the report would leave a charged
    # reservation with no way to resolve it.
    assert report(db, world, outstanding.view.execution_id, grant.report_secret).state == "EXECUTED"
    settled = retained(admin_engine, tenant, outstanding.view.execution_id)
    assert (settled.state, settled.tier, settled.impact) == ("EXECUTED", "ASSERTED", "CONFIRMED")
    # An executor spamming reports the route refuses: each is answered and each is audited
    # once, and the capacity the runtime shares between admission and reporting is handed
    # back, so the refusals do not starve the tenant's own writers. Twenty-five is more
    # than the bound this runtime holds, so a request answered after them is slots having
    # been released and not slots there were enough of.
    assert runtime.concurrency < 25
    before = len(audit_payloads(admin_engine, tenant, "execution.rejected"))
    forged = json.dumps(report_body(world, secrets.token_urlsafe(32))).encode()
    for _ in range(25):
        with pytest.raises(ExecutionError) as refused:
            runtime.report(world["identity"], outstanding.view.execution_id, forged)
        assert refused.value.code == "INVALID_REPORT"
    rejections = audit_payloads(admin_engine, tenant, "execution.rejected")
    assert [payload["reason"] for payload in rejections[before:]] == ["INVALID_REPORT"] * 25
    assert retained(admin_engine, tenant, outstanding.view.execution_id) == settled
    release_stop(db, world["admin"], "Incident closed", world["clock"])
    # That every refusal released the slot it took is what the loop above established, not
    # this line: twenty-five refusals on a runtime holding fewer than twenty-five slots
    # could not all have been answered otherwise. This is a writer using one of them.
    answered = runtime.execute(world["identity"], request(world).model_dump_json().encode())
    assert answered.execution_id == outstanding.view.execution_id
    # The stop period is a fact the tenant's history carries.
    history = export_history(db, world["admin"], world["clock"])
    replayed = simulate(verify_export(history, history.head))
    assert replayed.complete, replayed.issues
    assert [period.released_at is not None for period in replayed.stop_periods] == [True]
