# SPDX-License-Identifier: AGPL-3.0-only
"""A platform's bare word that a call failed, and the one correction of a false report.

The post hook table in `docs/ARCADE.md`: a reported failure settles at
`FAILED_EFFECT_UNKNOWN`, tier `ASSERTED`, reason `REPORTED_FAILURE`, confirming the charge
and holding the canonical claim, and one thing moves a row in that state — the one state no
verifier can produce — which is an ADMIN-signed non-execution through `reconcile`. These are
the AL29, AL30, AL31 and AL33 walks against real PostgreSQL. They do not go through the
Arcade carrier: the statement reaches `_settle` over the existing outcome route, which
is the same route the extension constructs a body for, and the rows' hook-carried spellings
are asserted with the hooks further down.

Some of the refusals here are asserted on the guard that makes them rather than through
`reconcile`, and the docstring of each says why. A mutation sweep removed fifteen guards one
at a time and six of the removals failed nothing at all; four of those six are refusals on
the correction's own path — `_correctable`'s state fact and its tier fact,
`_unsettled_grant_only`'s fenced direction clause and `_settle`'s own `correcting` test —
and for each of them either another refusal answers the same way behind it or the row that
would tell the difference is one no kernel path writes. An end-to-end assertion passes over
the removal of such a guard, which is why each is asserted where it is written.
"""

import asyncio
import io
import json
import logging
import os
import statistics
import time
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from concurrent.futures import wait as futures_wait
from contextlib import contextmanager
from copy import deepcopy
from datetime import UTC, datetime, timedelta
from threading import Barrier, Event
from urllib.parse import urlsplit
from uuid import UUID, uuid4

import pytest
from arcade_fixtures import (
    APPROVALS_PAGE,
    APPROVE_RISKY,
    ARCADE_TOOL,
    CORRECTIONS,
    DIRECT_OPERATION,
    FAILURE,
    GOVERNED_TOOL,
    WORLD_DEVICE,
    _alias,
    approving_runtime,
    arcade_boundary,
    arcade_client,
    audit_head,
    claim_releases,
    correct,
    correlation_rows,
    direct_operation,
    governed_bundle,
    governed_target,
    hook_block,
    post,
    post_hook,
    pre,
    pre_hook,
    rewrite_reason,
    signed,
    stated_failure,
    transitions,
    verifier,
)
from arcade_fixtures import arcade_world as arcade_world
from checkpoint_fixtures import (
    GATE_KEY_ID,
    audit_kinds,
    checkpoint,
    claim_rows,
    execution_states,
    frozen_plan,
    grant_row,
    impact_rows,
    long_lived_admin,
    register_keypair,
    report,
    retained,
    scoped,
    second_credential,
    set_settlement_tier,
)
from checkpoint_fixtures import gate_world as gate_world
from checkpoint_fixtures import owner as owner
from context_fixtures import CATALOG, SYNTHETIC_OPERATION
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi.testclient import TestClient
from pydantic import ValidationError
from scope_fixtures import (
    agent,
    counted,
    group,
    impact_groups,
    rule,
    transition_payload,
    usage,
)
from sqlalchemy import event, text
from starlette.websockets import WebSocketDisconnect
from test_execution import finish, provision_credential, provision_identity, targets
from test_execution import registry as registry
from test_execution import world as world
from test_surface_configuration import ARCADE, load
from test_surface_configuration import config as config

from execbound import administration
from execbound import app as app_module
from execbound.app import create_app
from execbound.arcade import (
    ArcadeBlock,
    GovernedCall,
    HookResult,
    ToolMap,
    ToolMapError,
    UngovernedToolkit,
    parse_pre_hook,
)
from execbound.arcade import boundary as boundary
from execbound.arcade import routes as routes
from execbound.arcade import store as arcade_store
from execbound.arcade.boundary import create_arcade
from execbound.arcade.models import MAX_ERROR_MESSAGE, parse_post_hook
from execbound.arcade.routes import _decided
from execbound.contracts import PRODUCTION_CATALOG
from execbound.db import SCHEMA_REVISION, Database, UnsafeDatabaseRole
from execbound.execution import (
    activate_stop,
    admit,
    decide_approval,
    reconcile,
    set_enforcement_mode,
    store,
)
from execbound.execution.models import (
    ACT_WINDOW,
    MAX_GRANTS,
    TERMINAL_PAIRS,
    AssertedOutcome,
    ExecutionError,
    TerminalEvidence,
    transition_allowed,
)
from execbound.execution.outcomes import _correctable, _proof, _settle, parse_report
from execbound.execution.reconciliation import _unsettled_grant_only
from execbound.logging_schema import SchemaFormatter
from execbound.operations import PRODUCTION_ACTIONS, CatalogError
from execbound.policy.models import LimitSelector
from execbound.provider.executor import ExecutorRecord
from execbound.recovery_run import recover, release_claim, select_held_claims
from execbound.replay.ledger import Ledger
from execbound.requests import ClaimedContext, parse_request
from execbound.runtime import Runtime, attestable_ring
from execbound.surfaces import human as human_surface
from execbound.surfaces import sessions
from execbound.surfaces.configuration import load_runtime, read_configuration, reload_keys
from execbound.surfaces.limits import RequestLimits
from execbound.surfaces.tokens import TokenKeys
from execbound_harness.fake_arcade import HOOK_CONTRACT, FakeArcade, tool_info

# An envelope of the shape the outcome route carries a signed record in. `OutcomeReport`
# never parses it — the field is `dict[str, Any]`, opaque until a verifier reads it — so
# what this stands for is its presence and nothing about its contents.
ENVELOPE = {"key_id": "executor-v1", "record": {}, "signature": "00"}


def test_al29_the_pairing_table_is_the_guard_on_the_widened_vocabulary():
    """AL29's core: five pairings validate and every other spelling is a parser refusal.

    The parity rule this replaced admitted every non-executed reason beside every
    non-executed outcome, which for the widened literals is nine pairings for five
    statements. The four it admitted that this refuses are asserted here by name, the
    fatal one first: FAILED_EFFECT_UNKNOWN beside VERSION_MISMATCH settles at
    STALE_AUTHORIZATION at tier ASSERTED, which `replay/verify.py:_asserted` refuses on
    export — permanently, since audit events are append-only.
    """
    assert dict(TERMINAL_PAIRS) == {
        "EXECUTED": "EXECUTED",
        "VERSION_MISMATCH": "FAILED_NOT_EXECUTED",
        "CANCELLED_NOT_EXECUTED": "FAILED_NOT_EXECUTED",
        "TARGET_NOT_FOUND": "FAILED_NOT_EXECUTED",
        "REPORTED_FAILURE": "FAILED_EFFECT_UNKNOWN",
    }
    secret = "s" * 43
    for outcome, reason in (
        ("FAILED_EFFECT_UNKNOWN", "VERSION_MISMATCH"),
        ("FAILED_EFFECT_UNKNOWN", "CANCELLED_NOT_EXECUTED"),
        ("FAILED_EFFECT_UNKNOWN", "TARGET_NOT_FOUND"),
        ("FAILED_NOT_EXECUTED", "REPORTED_FAILURE"),
        ("EXECUTED", "REPORTED_FAILURE"),
    ):
        body = {"report_secret": secret, "outcome": outcome, "reason": reason}
        with pytest.raises(ExecutionError) as refused:
            parse_report(json.dumps({**body, "reported_at": "2026-09-17T12:00:00+00:00"}).encode())
        assert refused.value.code == "INVALID_REQUEST"
    # The one new spelling the parser admits, and the tier it can only ever be.
    admitted = parse_report(
        json.dumps(
            {"report_secret": secret, **FAILURE, "reported_at": "2026-09-17T12:00:00+00:00"}
        ).encode()
    )
    assert (admitted.outcome, admitted.reason, admitted.record) == (
        "FAILED_EFFECT_UNKNOWN",
        "REPORTED_FAILURE",
        None,
    )


def test_al29_no_verified_evidence_model_admits_either_new_member():
    """The vocabulary split: the new pairing is unconstructable by any verifier.

    `TerminalEvidence` is what `EvidenceVerifier.verify` is declared to return and what
    `_proof` revalidates, so a member it does not admit is one no verifier can return —
    not a shipped connector, not a future one, not a duck-typed double.
    """
    bound = {
        "operation_id": uuid4(),
        "account_id": uuid4(),
        "intent_hash": "a" * 64,
        "plan_hash": "b" * 64,
    }
    spoken_at = datetime(2026, 9, 17, 12, 0, tzinfo=UTC)
    for outcome, reason in (
        ("FAILED_EFFECT_UNKNOWN", "REPORTED_FAILURE"),
        ("FAILED_NOT_EXECUTED", "REPORTED_FAILURE"),
        ("FAILED_EFFECT_UNKNOWN", "CANCELLED_NOT_EXECUTED"),
    ):
        with pytest.raises(ValidationError):
            TerminalEvidence(
                **bound,
                outcome=outcome,
                reason=reason,
                proof_digest="c" * 64,
                authenticated_record="{}",
            )
        with pytest.raises(ValidationError):
            ExecutorRecord(**bound, outcome=outcome, reason=reason, reported_at=spoken_at)
    # The same pairing an assertion carries, which is the one thing that may state it.
    assert (
        AssertedOutcome(**bound, **FAILURE, reported_at=spoken_at).outcome
        == "FAILED_EFFECT_UNKNOWN"
    )


def test_al29_a_record_beside_a_control_point_reason_is_the_parser_s_own_refusal():
    """AL29's parser clause, asserted where it is made rather than behind it.

    `OutcomeReport` refuses a signed record presented beside a reason only the asserted
    vocabulary admits. `ExecutorRecord`'s literals refuse the same statement one layer
    further in, so such a report is refused either way and the mutation sweep saw nothing
    fail when the clause was removed. What the clause buys is where the refusal is made:
    INVALID_REQUEST at the parser, with no execution row read and no key ring loaded for it,
    rather than a refusal behind a signature check. So this asserts `parse_report` itself,
    with no database anywhere near it, and triangulates the clause by varying one thing at a
    time — the same body without the record parses, and the same record beside a reason a
    verifier could return parses.
    """
    secret = "s" * 43
    with pytest.raises(ExecutionError) as refused:
        parse_report(json.dumps({"report_secret": secret, **FAILURE, "record": ENVELOPE}).encode())
    assert refused.value.code == "INVALID_REQUEST"
    stated = parse_report(
        json.dumps(
            {"report_secret": secret, **FAILURE, "reported_at": "2026-09-17T12:00:00+00:00"}
        ).encode()
    )
    assert (stated.reason, stated.record) == ("REPORTED_FAILURE", None)
    attested = parse_report(
        json.dumps(
            {
                "report_secret": secret,
                "outcome": "FAILED_NOT_EXECUTED",
                "reason": "CANCELLED_NOT_EXECUTED",
                "record": ENVELOPE,
            }
        ).encode()
    )
    assert (attested.reason, attested.record) == ("CANCELLED_NOT_EXECUTED", ENVELOPE)


def test_a_reported_failure_confirms_the_charge_and_holds_the_claim(db, gate_world, admin_engine):
    """The post hook table's second row: it costs a caller exactly what a success costs."""
    world = gate_world
    tenant = world["identity"].tenant_id
    execution_id, _ = stated_failure(db, world, admin_engine)
    row = retained(admin_engine, tenant, execution_id)
    assert (row.state, row.tier, row.impact) == ("FAILED_EFFECT_UNKNOWN", "ASSERTED", "CONFIRMED")
    assert row.confirmed_at == world["clock"].now()
    # Nothing is freed: the canonical claim stands until the act window has passed, as it
    # does for a reported success, and the target is busy to the tenant in the meantime.
    assert row.released_at is None
    assert (row.result["outcome"], row.result["reason"], row.result["tier"]) == (
        "FAILED_EFFECT_UNKNOWN",
        "REPORTED_FAILURE",
        "ASSERTED",
    )
    # Retained as somebody's word and never as evidence: replay treats the presence of
    # terminal evidence as verification.
    assert "proof_digest" not in row.result and "authenticated_record" not in row.result
    assert transitions(admin_engine, tenant, execution_id) == [
        (None, "ATTEMPTED", None),
        ("ATTEMPTED", "RESERVED", None),
        ("RESERVED", "DISPATCH_COMMITTED", None),
        ("DISPATCH_COMMITTED", "FAILED_EFFECT_UNKNOWN", "ASSERTED"),
    ]


@pytest.mark.parametrize("changes,state", CORRECTIONS, ids=["cancelled", "version-mismatch"])
def test_al30_an_administrator_corrects_a_false_report(
    db, gate_world, admin_engine, changes, state
):
    """AL30: the correction settles at the verified evidence's own state and refunds.

    The charge the platform's word produced is rewritten to a non-execution with a null
    confirmation time, so the next decision's counts drop it; the claim is released
    because the evidence was verified; and the chain holds both statements in order.
    """
    world = gate_world
    tenant = world["identity"].tenant_id
    execution_id, secret = stated_failure(db, world, admin_engine)
    view = correct(db, world, execution_id, changes)
    assert view.state == state
    row = retained(admin_engine, tenant, execution_id)
    assert (row.state, row.tier, row.impact) == (state, "ATTESTED", "NONEXECUTION")
    assert row.confirmed_at is None
    assert row.released_at == world["clock"].now()
    # The row's `result` holds the correcting evidence alone, because `_settle` replaces
    # it; the statement it corrected is in the transition history and nowhere else.
    assert row.result["reason"] == changes["reason"]
    assert "proof_digest" in row.result and row.result["tier"] == "ATTESTED"
    assert transitions(admin_engine, tenant, execution_id)[-2:] == [
        ("DISPATCH_COMMITTED", "FAILED_EFFECT_UNKNOWN", "ASSERTED"),
        ("FAILED_EFFECT_UNKNOWN", state, "ATTESTED"),
    ]
    stated = [
        payload
        for kind, payload in audit_kinds(admin_engine, tenant)
        if kind == "execution.transition" and payload["to_state"] == "FAILED_EFFECT_UNKNOWN"
    ]
    assert stated[0]["asserted"]["reason"] == "REPORTED_FAILURE"
    corrected = [
        payload
        for kind, payload in audit_kinds(admin_engine, tenant)
        if kind == "execution.transition" and payload.get("from_state") == "FAILED_EFFECT_UNKNOWN"
    ]
    assert corrected[0]["reason"] == "the platform's report was false"
    assert corrected[0]["evidence"]["reason"] == changes["reason"]
    # A redelivery of the report that produced the corrected row is no longer a
    # restatement: `_restates` compares the row's tier, now ATTESTED, against the tier the
    # report claims, ASSERTED. The kernel refuses and nothing is settled twice.
    with pytest.raises(ExecutionError) as refused:
        report(db, world, execution_id, secret, **FAILURE)
    assert refused.value.code == "INVALID_STATE"
    assert retained(admin_engine, tenant, execution_id) == row


@pytest.mark.parametrize("changes,state", CORRECTIONS, ids=["cancelled", "version-mismatch"])
def test_al30_the_export_replays_the_ledger_through_the_correction(
    db, gate_world, admin_engine, changes, state
):
    """AL30's export clause, over each correction direction rather than one of them.

    `Ledger.settle` refuses a second settlement in both directions, so without
    `Ledger.correct` and the branch that chooses it, a tenant that corrected one row would
    get a degraded replay of its whole window.

    The direction is the parameter for a reason: a walk of `CANCELLED_NOT_EXECUTED` alone,
    which settles at FAILED_NOT_EXECUTED and is caught by the terminal gate's `after` set,
    passes over a `VERSION_MISMATCH` correction, which settles at STALE_AUTHORIZATION and
    reaches the same gate's `before` set. With that side left as it was the exported row
    keeps the tier and terminal time the *asserted* settlement wrote while the live row
    holds the correction's, which is why both of those are asserted here from the history
    index rather than the tier alone.
    """
    from execbound.replay.export import export_history
    from execbound.replay.history import index_history
    from execbound.replay.report import report_json
    from execbound.replay.simulate import simulate
    from execbound.replay.verify import verify_export

    world = gate_world
    world["admin"] = long_lived_admin(admin_engine, db, world)
    first, second = targets(admin_engine, world, count=2)
    stated, _ = stated_failure(db, world, admin_engine, action=first)
    corrected, _ = stated_failure(db, world, admin_engine, action=second)
    spoken_at = world["clock"].now()
    # Exported once with the statement standing, so the settled row is read as settled.
    history = export_history(db, world["admin"], world["clock"])
    replayed = simulate(verify_export(history, history.head))
    assert replayed.complete, replayed.issues
    rows = {row.execution_id: row for row in replayed.decisions}
    assert (rows[stated].baseline.outcome, rows[stated].settlement_tier) == (
        "FAILED_EFFECT_UNKNOWN",
        "ASSERTED",
    )
    assert rows[stated].baseline.provenance == "RECORDED_TRANSITION"
    # The clock moves so that the correction's terminal time is distinguishable from the
    # statement's; a gate that did not fire would leave the statement's standing.
    world["clock"].value = spoken_at + timedelta(minutes=5)
    assert correct(db, world, corrected, changes).state == state
    after = export_history(db, world["admin"], world["clock"])
    verified = verify_export(after, after.head)
    assert verified.complete, verified.issues
    final = simulate(verified)
    assert final.complete, final.issues
    assert "INVALID_IMPACT_HISTORY" not in final.issues
    assert "INCOMPLETE_HISTORY" not in final.issues
    row = {item.execution_id: item for item in final.decisions}[corrected]
    assert (row.baseline.outcome, row.settlement_tier) == ("FAILED_NOT_EXECUTED", "ATTESTED")
    assert row.baseline.provenance == "RECORDED_EXECUTOR_EVIDENCE"
    indexed = index_history(verified).executions[corrected]
    assert (indexed.state, indexed.settlement_tier, indexed.terminal_verified) == (
        state,
        "ATTESTED",
        True,
    )
    assert indexed.terminal_time == world["clock"].now() != spoken_at
    assert index_history(verified).executions[stated].terminal_time == spoken_at
    assert report_json(simulate(verify_export(after, after.head))) == report_json(final)


def test_al30_a_correction_after_the_run_released_the_claim_rewrites_nothing(
    db, gate_world, admin_engine
):
    """AL30's third walk: the recovery run freed the target before the correction.

    A settled assertion's claim is released by the scheduled run once the act window has
    passed, and `execution.claim_released` names that instant. The correction must not
    rewrite when a target was freed, which is the whole of the `AND released_at IS NULL`
    narrowing.
    """
    world = gate_world
    tenant = world["identity"].tenant_id
    world["admin"] = long_lived_admin(admin_engine, db, world)
    execution_id, _ = stated_failure(db, world, admin_engine)
    stamped = grant_row(admin_engine, tenant, execution_id)["dispatch_attempted_at"]
    world["clock"].value = stamped + ACT_WINDOW + timedelta(seconds=301)
    assert recover(db, world["admin"], {}, clock=world["clock"]).released == 1
    freed = retained(admin_engine, tenant, execution_id)
    assert freed.released_at == world["clock"].now()
    (release,) = claim_releases(admin_engine, tenant)
    assert release["settlement_tier"] == "ASSERTED"
    world["clock"].value = world["clock"].now() + timedelta(minutes=5)
    view = correct(db, world, execution_id, CORRECTIONS[0][0])
    assert view.state == "FAILED_NOT_EXECUTED"
    row = retained(admin_engine, tenant, execution_id)
    assert (row.state, row.tier, row.impact) == ("FAILED_NOT_EXECUTED", "ATTESTED", "NONEXECUTION")
    # The instant the target was freed, and the event that named it, are both unchanged.
    assert row.released_at == freed.released_at
    assert claim_releases(admin_engine, tenant) == [release]


def refusal(db, world, admin_engine, execution_id, changes, **extra):
    """One refused correction, with the row, impact, claim and tier read either side."""
    tenant = world["identity"].tenant_id
    before = retained(admin_engine, tenant, execution_id)
    events = len(audit_kinds(admin_engine, tenant))
    with pytest.raises(ExecutionError) as refused:
        correct(db, world, execution_id, changes, **extra)
    assert retained(admin_engine, tenant, execution_id) == before
    kinds = audit_kinds(admin_engine, tenant)
    assert len(kinds) == events + 1
    assert (kinds[-1][0], kinds[-1][1]["reason"]) == ("execution.rejected", refused.value.code)
    return refused.value.code


def test_al31_the_correction_refuses_everything_but_its_one_row_and_direction(
    db, gate_world, admin_engine
):
    """AL31: every bound is a refusal in code, and each leaves the row untouched.

    An attested EXECUTED against a correctable row is the promotion `docs/CHECKPOINT.md`
    refuses under "The claim an assertion left held", under another name: it would release
    the claim before the act window, which is the one thing the settlement asymmetry exists
    to deny.
    """
    world = gate_world
    tenant = world["identity"].tenant_id
    first, second, third, fourth = targets(admin_engine, world, count=4)
    stated, secret = stated_failure(db, world, admin_engine, action=first)
    # An ADMIN-signed EXECUTED against a correctable row: refused, and the promotion with it.
    assert (
        refusal(
            db,
            world,
            admin_engine,
            stated,
            {"outcome": "EXECUTED", "reason": "EXECUTED"},
        )
        == "INVALID_STATE"
    )
    # An ADMIN-signed non-execution against a row settled EXECUTED at tier ASSERTED.
    executed = checkpoint(db, world, action=second)
    grant = executed.view.checkpoint
    assert grant is not None
    assert report(db, world, executed.view.execution_id, grant.report_secret).state == "EXECUTED"
    assert (
        refusal(db, world, admin_engine, executed.view.execution_id, CORRECTIONS[0][0])
        == "INVALID_STATE"
    )
    # And against one settled EXECUTED at tier ATTESTED.
    attested = checkpoint(db, world, action=third)
    signed_grant = attested.view.checkpoint
    assert signed_grant is not None
    from checkpoint_fixtures import signed_record

    assert (
        report(
            db,
            world,
            attested.view.execution_id,
            signed_grant.report_secret,
            record=signed_record(db, world, attested.view.execution_id),
        ).state
        == "EXECUTED"
    )
    assert (
        refusal(db, world, admin_engine, attested.view.execution_id, CORRECTIONS[0][0])
        == "INVALID_STATE"
    )
    # A row whose retained reason is not REPORTED_FAILURE, forged over the owner
    # connection: the three facts are each required, and this one is the fact whose
    # removal `reconcile` itself would answer differently for. The other two are varied in
    # `test_al31_each_fact_of_the_correctable_trio_is_required`, which says why they cannot
    # be varied here.
    forged, _ = stated_failure(db, world, admin_engine, action=fourth)
    rewrite_reason(admin_engine, tenant, forged, "TARGET_NOT_FOUND")
    assert refusal(db, world, admin_engine, forged, CORRECTIONS[0][0]) == "INVALID_STATE"
    # The correcting evidence presented on the report route instead, while the row is still
    # the one a correction admits: the platform cannot correct itself, and a stolen report
    # secret reaches none of this. `_restates` compares the row's tier, ASSERTED, against
    # the tier this report claims, ATTESTED.
    settled_before = retained(admin_engine, tenant, stated)
    with pytest.raises(ExecutionError) as refused:
        report(
            db,
            world,
            stated,
            secret,
            record=signed_record(db, world, stated, **CORRECTIONS[0][0]),
            **CORRECTIONS[0][0],
        )
    assert refused.value.code == "INVALID_STATE"
    assert retained(admin_engine, tenant, stated) == settled_before
    # The correction itself, and then a second one against the corrected row.
    assert correct(db, world, stated, CORRECTIONS[0][0]).state == "FAILED_NOT_EXECUTED"
    assert refusal(db, world, admin_engine, stated, CORRECTIONS[1][0]) == "INVALID_STATE"
    assert refusal(db, world, admin_engine, stated, CORRECTIONS[0][0]) == "INVALID_STATE"
    # And what the report route does with the same evidence afterwards, which is NOT a
    # refusal: the corrected row's tier, outcome and reason are now exactly what this
    # report claims, so `_restates` admits it and `_settle_report` answers the view it
    # found. Nothing is settled twice — no event is appended and no column moves — but the
    # kernel's answer is a 200 and not INVALID_STATE.
    corrected_before = retained(admin_engine, tenant, stated)
    events = len(audit_kinds(admin_engine, tenant))
    assert (
        report(
            db,
            world,
            stated,
            secret,
            record=signed_record(db, world, stated, **CORRECTIONS[0][0]),
            **CORRECTIONS[0][0],
        ).state
        == "FAILED_NOT_EXECUTED"
    )
    assert retained(admin_engine, tenant, stated) == corrected_before
    assert len(audit_kinds(admin_engine, tenant)) == events
    # No onward edge, from either target of the one correction edge.
    for settled in ("FAILED_NOT_EXECUTED", "STALE_AUTHORIZATION"):
        assert not any(
            transition_allowed(settled, target)
            for target in (
                "EXECUTED",
                "FAILED_NOT_EXECUTED",
                "STALE_AUTHORIZATION",
                "FAILED_EFFECT_UNKNOWN",
                "INDETERMINATE",
                "DISPATCH_COMMITTED",
                "RESERVED",
            )
        )


def test_al31_each_fact_of_the_correctable_trio_is_required(db, gate_world, admin_engine):
    """AL31's three row facts, each varied on its own while the other two hold.

    `_settle` writes the state, the tier and the retained statement in one transaction, so
    a row holding two of the three and not the third is one no kernel path leaves: the
    state fact and the tier fact went uncovered because nothing in the suite built such a
    row, and the sweep that removed each of them saw no test fail. They are varied here on
    the predicate, over a real settled statement read from PostgreSQL with one field
    replaced. What makes the redundancy load-bearing rather than decorative is what makes
    the forgery expressible at all: `store.transition` takes a plain `str`, so an
    in-process caller can write that state with no tier beside it and no statement
    retained.

    The tier fact is then forged into a second row and taken through `reconcile`, because
    that is the one of the two whose removal a caller could reach: admit a tierless row and
    the settlement body runs, where the state fact's forgery would still meet
    `store.transition`, which holds no edge out of the state such a row claims.
    """
    world = gate_world
    tenant = world["identity"].tenant_id
    first, second = targets(admin_engine, world, count=2)
    execution_id, _ = stated_failure(db, world, admin_engine, action=first)
    with db.transaction(tenant) as conn:
        row = store.read(conn, tenant, execution_id)
    assert (row["state"], row["settlement_tier"], row["result"]["reason"]) == (
        "FAILED_EFFECT_UNKNOWN",
        "ASSERTED",
        "REPORTED_FAILURE",
    )
    assert _correctable(row)
    # The state fact: another settled state, at the tier and with the reason a statement
    # leaves behind.
    assert not _correctable({**row, "state": "EXECUTED"})
    # The tier fact: the state and the retained reason with no tier beside them, which is
    # the row a caller writing the state directly would leave.
    assert not _correctable({**row, "settlement_tier": None})
    # The reason fact, varied here beside the other two as well as through `reconcile` in
    # the walk above, where it is the one of the three that changes an answer.
    assert not _correctable({**row, "result": {**row["result"], "reason": "TARGET_NOT_FOUND"}})
    assert not _correctable({**row, "result": None})
    # And the tierless row through `reconcile`, which refuses it with the row, its impact,
    # its claim and its tier where they were.
    forged, _ = stated_failure(db, world, admin_engine, action=second)
    set_settlement_tier(admin_engine, tenant, forged, None)
    assert retained(admin_engine, tenant, forged).tier is None
    assert refusal(db, world, admin_engine, forged, CORRECTIONS[0][0]) == "INVALID_STATE"


def test_al31_each_direction_guard_refuses_the_promotion_on_its_own(db, gate_world, admin_engine):
    """AL31's two direction guards, each asserted by name for the same reason.

    They are mutually redundant behind `transition_allowed`, which holds no edge from
    FAILED_EFFECT_UNKNOWN to EXECUTED, so removing either one alone leaves `reconcile`
    answering INVALID_STATE and auditing the same rejection. Asserting them end to end
    would let a change delete either without a test saying so, so each is exercised where
    it is written: `_unsettled_grant_only` on the row and the proof it is handed, and
    `_settle` on where it answers — above the impact write and the claim release, with
    neither of them made.
    """
    world = gate_world
    tenant = world["identity"].tenant_id
    execution_id, _ = stated_failure(db, world, admin_engine)
    promotion = {"outcome": "EXECUTED", "reason": "EXECUTED"}
    checked = verifier(db, world, execution_id)
    with db.transaction(tenant) as conn:
        row = store.read(conn, tenant, execution_id)
        command = store.command(row)
    executed = _proof(command, signed(db, world, execution_id, promotion), checked)
    non_execution = _proof(command, signed(db, world, execution_id, CORRECTIONS[0][0]), checked)
    # `_unsettled_grant_only`'s fenced clause. The unfenced call narrows on the row alone,
    # because the proof does not exist yet, and admits this row; the fenced one is handed
    # the verified evidence and is where the direction is decided.
    _unsettled_grant_only(row)
    _unsettled_grant_only(row, non_execution)
    with pytest.raises(ExecutionError) as refused:
        _unsettled_grant_only(row, executed)
    assert refused.value.code == "INVALID_STATE"
    # `_settle`'s own `correcting` test, behind it. The clock moves first so that a
    # settlement body reached by mistake would stamp times distinguishable from the ones
    # the statement wrote.
    world["clock"].value = world["clock"].now() + timedelta(minutes=5)
    with db.transaction(tenant) as conn:
        row = store.read(conn, tenant, execution_id)
        state, confirmed_at, released_at = before = settlement_marks(conn, row)
        assert (state, released_at) == ("CONFIRMED", None)
        assert confirmed_at < world["clock"].now()
        with pytest.raises(ExecutionError) as answered:
            _settle(conn, row, world["admin"].principal_id, executed, world["clock"], "promotion")
        assert answered.value.code == "INVALID_STATE"
        # Read in the same transaction, so this is what the refused call left behind rather
        # than what its rollback did: the impact keeps the statement's own confirmation
        # instant and the claim is still held.
        assert settlement_marks(conn, row) == before
    assert retained(admin_engine, tenant, execution_id).released_at is None


def settlement_marks(conn, row):
    """What the settlement body writes before it appends a transition, in this transaction.

    The impact's state and confirmation instant, and the claim's release instant: the two
    statements `_settle` makes above `store.transition`. A call answered above them leaves
    this triple where it found it.
    """
    bound = {"t": row["tenant_id"], "e": row["execution_id"]}
    impact = conn.execute(
        text(
            "SELECT state, confirmed_at FROM execbound.execution_impact "
            "WHERE tenant_id=:t AND execution_id=:e"
        ),
        bound,
    ).one()
    released = conn.execute(
        text(
            "SELECT released_at FROM execbound.resource_claims "
            "WHERE tenant_id=:t AND execution_id=:e"
        ),
        bound,
    ).scalar_one()
    return impact.state, impact.confirmed_at, released


def test_the_replay_ledger_corrects_a_confirmed_impact_and_refuses_the_rest():
    """`Ledger.correct` is the narrow method the export's refund rests on.

    A widened `Ledger.settle` would let any history claim CONFIRMED to NONEXECUTION, which
    is the refund an export must not be able to invent, so the correction is a method of
    its own admitting one starting state. Asserted here because `simulate` calls it for a
    transition out of FAILED_EFFECT_UNKNOWN and the kernel writes the settlement that
    confirms the impact before it writes that transition, so a history the kernel wrote
    reaches this method on a CONFIRMED impact and its refusals went unexercised. AL26
    carries the admitted direction through a replayed history in the schema walk.
    """
    tenant, principal, account = uuid4(), uuid4(), uuid4()
    target, at = uuid4(), datetime(2026, 9, 17, 12, tzinfo=UTC)
    unit = (principal, "endpoint.isolate", target)
    scope = {"account_id": account, "facts": {}, "groups": ()}

    def reserved(number):
        ledger = Ledger(tenant)
        ledger.reserve(UUID(int=number), *unit, False, at, **scope)
        return ledger

    refused = pytest.raises(ValueError, match="Invalid replay correction")
    # The four states `Impact.state` admits beside CONFIRMED, each reached by the method
    # the simulation reaches it with, and each refused.
    with refused:
        reserved(1).correct(UUID(int=1), at)
    non_execution = reserved(2)
    non_execution.settle(UUID(int=2), False, at)
    with refused:
        non_execution.correct(UUID(int=2), at)
    hypothetical = Ledger(tenant)
    hypothetical.uncertain(UUID(int=3), *unit, at, **scope)
    with refused:
        hypothetical.correct(UUID(int=3), at)
    observed = Ledger(tenant)
    observed.observe(UUID(int=4), *unit, False, at, **scope)
    with refused:
        observed.correct(UUID(int=4), at)
    # An execution this ledger never saw, and a correction dated before the reservation.
    with refused:
        reserved(5).correct(uuid4(), at)
    confirmed = reserved(6)
    confirmed.settle(UUID(int=6), True, at)
    with refused:
        confirmed.correct(UUID(int=6), at - timedelta(seconds=1))
    # The one it admits, and then a second call, which the same clause refuses because the
    # row it wrote is no longer CONFIRMED.
    assert confirmed.impacts[UUID(int=6)].state == "CONFIRMED"
    confirmed.correct(UUID(int=6), at)
    written = confirmed.impacts[UUID(int=6)]
    assert (written.state, written.confirmed_at) == ("NONEXECUTION", None)
    with refused:
        confirmed.correct(UUID(int=6), at)
    assert confirmed.impacts[UUID(int=6)] == written


def test_al31_a_row_execbound_dispatched_is_no_correctable_row(db, world, owner, admin_engine):
    """AL31's dispatched row: a settled operation of the other path is refused too.

    It is refused by `_never_executor_evidence` before the settled-row guard is reached —
    an operation ExecBound dispatched never settles from an external executor's record —
    so the refusal does not depend on the correction's own predicate at all. Reaching the
    correction's own guard is impossible here for a second reason: `FAILED_EFFECT_UNKNOWN`
    is written only from an `AssertedOutcome`, which only the report route builds, and a
    dispatched row is unreportable.
    """
    from checkpoint_fixtures import connected_account, gate_bundle

    world["executor_key"] = register_keypair(owner, world)
    gate_bundle(db, world, external_executor=False)
    tenant = world["identity"].tenant_id
    admission = checkpoint(db, world, accounts=connected_account(world))
    assert admission.ticket is not None
    assert finish(db, world, admission).state == "EXECUTED"
    before = retained(admin_engine, tenant, admission.view.execution_id)
    assert before.tier is None
    with pytest.raises(ExecutionError) as refused:
        correct(db, world, admission.view.execution_id, CORRECTIONS[0][0])
    assert refused.value.code == "INVALID_STATE"
    assert retained(admin_engine, tenant, admission.view.execution_id) == before


def test_al33_a_tenant_whose_only_key_was_compromised_cannot_correct(
    db, gate_world, owner, admin_engine
):
    """AL33: the bare word still settles, and no key can ever correct that row.

    Stated as the bound limitation 14 in `docs/ARCADE.md` records rather than as a refusal:
    `ExecutorVerifier._current` refuses a key revoked as COMPROMISED whatever the grant
    instant and refuses any key registered after the grant, so the tenant ends with a
    charged, closed, uncorrectable row where it previously had an open one.
    """
    world = gate_world
    tenant, admin = world["identity"].tenant_id, world["admin"].principal_id
    world["admin"] = long_lived_admin(admin_engine, db, world)
    opened = world["clock"].now()
    (target,) = targets(admin_engine, world, count=1)
    granted = checkpoint(db, world, action=target)
    grant = granted.view.checkpoint
    assert grant is not None
    execution_id = granted.view.execution_id
    world["clock"].value = opened + timedelta(minutes=1)
    administration.report_executor_key_compromise(
        owner, tenant, GATE_KEY_ID, admin, now=world["clock"].now()
    )
    # The attested report the honest executor would have sent settles nothing.
    from checkpoint_fixtures import signed_record

    with pytest.raises(ExecutionError) as refused:
        report(
            db,
            world,
            execution_id,
            grant.report_secret,
            record=signed_record(db, world, execution_id, **CORRECTIONS[0][0]),
            **CORRECTIONS[0][0],
        )
    assert refused.value.code == "INVALID_RECORD"
    # The bare word still settles, charged and closed.
    assert report(db, world, execution_id, grant.report_secret, **FAILURE).state == (
        "FAILED_EFFECT_UNKNOWN"
    )
    settled = retained(admin_engine, tenant, execution_id)
    assert (settled.tier, settled.impact) == ("ASSERTED", "CONFIRMED")
    # The run past the act window releases the claim, as it does for any settled assertion.
    stamped = grant_row(admin_engine, tenant, execution_id)["dispatch_attempted_at"]
    world["clock"].value = stamped + ACT_WINDOW + timedelta(seconds=301)
    assert recover(db, world["admin"], {}, clock=world["clock"]).released == 1
    # No correction is possible: not on the compromised key, and not on one registered
    # after the grant it never covered.
    replacement = Ed25519PrivateKey.generate()
    administration.register_executor_key(
        owner,
        tenant,
        "executor-next",
        replacement.public_key().public_bytes_raw().hex(),
        admin,
        now=world["clock"].now(),
    )
    before = retained(admin_engine, tenant, execution_id)
    for private_key, key_id in ((None, GATE_KEY_ID), (replacement, "executor-next")):
        with pytest.raises(ExecutionError) as refused:
            reconcile(
                db,
                world["admin"],
                execution_id,
                reason="correcting the control point's false report",
                evidence=signed(
                    db,
                    world,
                    execution_id,
                    CORRECTIONS[0][0],
                    private_key=private_key,
                    key_id=key_id,
                ),
                verifier=verifier(db, world, execution_id),
                clock=world["clock"],
            )
        assert refused.value.code == "INVALID_EVIDENCE"
        assert retained(admin_engine, tenant, execution_id) == before


def test_a_settled_statement_makes_the_target_busy_rather_than_free(db, gate_world, admin_engine):
    """What the liar gets for its lie: a charge, a busy target and a record of saying so."""
    from checkpoint_fixtures import again

    world = gate_world
    (target,) = targets(admin_engine, world, count=1)
    execution_id, _ = stated_failure(db, world, admin_engine, action=target)
    other = agent(admin_engine, db, world)
    busy = checkpoint(db, world, other, action=again(target))
    assert busy.view.state == "DENIED" and busy.view.checkpoint is None
    assert retained(admin_engine, world["identity"].tenant_id, execution_id).released_at is None


@pytest.mark.integration
def test_the_downgrade_refuses_on_all_three_constrained_columns(db, gate_world, admin_engine):
    """The corrected row is the case a check of `executions` alone would pass.

    A corrected row's own state is FAILED_NOT_EXECUTED; what still names the new state is
    the `execution_events` pair, in `to_state` and then in `from_state`. A downgrade
    keyed on `executions.state` would drop a constraint those rows violate.
    """
    import os

    from alembic import command
    from alembic.config import Config

    world = gate_world
    tenant = world["identity"].tenant_id
    execution_id, _ = stated_failure(db, world, admin_engine)
    assert correct(db, world, execution_id, CORRECTIONS[0][0]).state == "FAILED_NOT_EXECUTED"
    with admin_engine.begin() as conn:
        scoped(conn, tenant)
        assert (
            conn.execute(
                text("SELECT count(*) FROM execbound.executions WHERE state=:s"),
                {"s": "FAILED_EFFECT_UNKNOWN"},
            ).scalar_one()
            == 0
        )
        assert (
            conn.execute(
                text(
                    "SELECT count(*) FROM execbound.execution_events "
                    "WHERE to_state=:s OR from_state=:s"
                ),
                {"s": "FAILED_EFFECT_UNKNOWN"},
            ).scalar_one()
            == 2
        )
    config = Config("alembic.ini")
    config.attributes["database_url"] = os.environ["TEST_MIGRATION_DATABASE_URL"]
    with pytest.raises(RuntimeError, match="reported failure is retained"):
        command.downgrade(config, "0026_key_compromise")
    with admin_engine.connect() as conn:
        assert (
            conn.execute(text("SELECT version_num FROM execbound.alembic_version")).scalar_one()
            == SCHEMA_REVISION
        )
    assert retained(admin_engine, tenant, execution_id).state == "FAILED_NOT_EXECUTED"


def test_the_second_key_of_the_ring_is_not_what_admits_a_correction(db, gate_world, owner):
    """A key registered before the grant corrects it; the ring is not the exception."""
    world = gate_world
    register_keypair(owner, world, key_id="executor-second")
    assert transition_allowed("FAILED_EFFECT_UNKNOWN", "FAILED_NOT_EXECUTED")
    assert transition_allowed("FAILED_EFFECT_UNKNOWN", "STALE_AUTHORIZATION")
    assert not transition_allowed("FAILED_EFFECT_UNKNOWN", "EXECUTED")
    assert not transition_allowed("FAILED_EFFECT_UNKNOWN", "INDETERMINATE")


def test_a_settled_dispatched_row_reaches_settle_with_its_claim_already_released(
    db, world, owner, admin_engine
):
    """The premise of the `AND released_at IS NULL` narrowing, measured.

    The premise is that no row reaches `_settle` with a released claim, since
    `release_claim` refuses a row not settled at tier ASSERTED and a settled checkpoint
    reaches `_settle` from nowhere. The first clause is true and the second is about
    checkpoints only: a settled row ExecBound *dispatched* carries no report window, so
    `_unsettled_grant_only` does not apply to it, and `reconcile` hands it to `_settle`
    with its claim released by its own earlier settlement. What keeps the narrowing
    harmless is the early return in `_settle`'s terminal branch, which answers before the
    claim is written — not that the row never arrives.
    """
    from checkpoint_fixtures import connected_account, gate_bundle
    from test_execution import FixtureJournal

    register_keypair(owner, world)
    gate_bundle(db, world, external_executor=False)
    tenant = world["identity"].tenant_id
    admission = checkpoint(db, world, accounts=connected_account(world))
    assert admission.ticket is not None
    assert finish(db, world, admission).state == "EXECUTED"
    before = retained(admin_engine, tenant, admission.view.execution_id)
    assert before.released_at is not None
    events = len(audit_kinds(admin_engine, tenant))
    repeated = reconcile(
        db,
        world["admin"],
        admission.view.execution_id,
        reason="the provider's response was lost",
        evidence=b"test-journal-proof",
        verifier=FixtureJournal(),
        clock=world["clock"],
    )
    # The idempotent repeat a lost provider response wants: the same view, nothing moved
    # and nothing appended, with the claim release instant untouched.
    assert repeated.state == "EXECUTED"
    assert retained(admin_engine, tenant, admission.view.execution_id) == before
    assert len(audit_kinds(admin_engine, tenant)) == events


def test_the_connector_reconciliation_cannot_correct_a_stated_failure(db, gate_world, admin_engine):
    """The fourth bound, measured, because the obvious reason for it is wrong.

    The obvious reason is that `reconcile` has one caller, ADMIN-only and connector-free.
    `provider.gateway.reconcile_operation` is a connector path and one of `reconcile`'s
    two callers, handing it the server's verifier for the connection and `connector.cancel`
    evidence. What
    keeps a connector out of the correction is `_executor_evidence_only`, which refuses a
    row carrying a report window settled from a verifier that does not declare it attests
    an external execution — not the absence of a connector caller.
    """
    from test_checkpoint import FixtureConnector
    from test_execution import FixtureJournal

    from execbound.provider.gateway import reconcile_operation

    world = gate_world
    tenant = world["identity"].tenant_id
    execution_id, _ = stated_failure(db, world, admin_engine)
    connector = FixtureConnector()
    before = retained(admin_engine, tenant, execution_id)
    for cancel in (False, True):
        with pytest.raises(ExecutionError) as refused:
            reconcile_operation(
                db,
                world["admin"],
                execution_id,
                connector,
                reason="operator reconciling this account's operations",
                cancel_if_missing=cancel,
                clock=world["clock"],
                verifier=FixtureJournal("FAILED_NOT_EXECUTED"),
            )
        assert refused.value.code == "INVALID_STATE"
    assert connector.asked == []
    assert retained(admin_engine, tenant, execution_id) == before


# The tool map `docs/ARCADE.md` describes, and the file it is declared in. The declarations
# below are the guide's own example varied one field at a time, so what a test changes is
# what it is about. A tool is named by its toolkit, its name and its exact version.
GOVERNED = {"toolkit": "endpoint_mock", "name": "ContainDevice", "version": "1.0"}
# A second governed tool, for the one production action that takes a typed argument.
LIFT = {
    "toolkit": "endpoint_mock",
    "name": "ReleaseDevice",
    "versions": ["1.0"],
    "operation_ref": "endpoint.lift_isolation",
    "target": {"kind": "provider_id", "input": "device_id"},
    "inputs": ["device_id", "reason"],
    "arguments": {"reason": "reason"},
}
RELEASED = {"toolkit": "endpoint_mock", "name": "ReleaseDevice", "version": "1.0"}


def declared(block):
    """One block as the private file carries it, validated the way that file is read."""
    return ArcadeBlock.model_validate_json(json.dumps(block))


def tool_map(**changes):
    """The example block's map, with its one governed declaration varied."""
    block = deepcopy(ARCADE)
    block["tools"][0].update(changes)
    return ToolMap(declared(block))


def test_a_tool_is_governed_at_the_versions_its_declaration_names():
    """Exact versions, no wildcard, and no declaration carried forward to another version.

    A vendor can change what a tool does across versions, so a version nobody declared is
    refused rather than governed by the decision an operator made about a different one.
    An ungoverned toolkit passes at any version, which is the standing decision it is.
    """
    tools = tool_map()
    call = tools.decide(**GOVERNED, inputs={"device_id": "device-9"})
    assert isinstance(call, GovernedCall)
    assert (call.operation_ref, call.target.kind, call.target.value) == (
        "endpoint.isolate",
        "provider_id",
        "device-9",
    )
    for version in ("1.1", "1.0.0", "1", "*"):
        with pytest.raises(ToolMapError, match="^UNMAPPED_TOOL$"):
            tools.decide(**{**GOVERNED, "version": version}, inputs={"device_id": "device-9"})
    # A wildcard is not a version a declaration can hold either.
    with pytest.raises(ValidationError):
        declared(
            {**deepcopy(ARCADE), "tools": [{**deepcopy(ARCADE["tools"][0]), "versions": ["*"]}]}
        )
    assert tools.decide(
        toolkit="gmail", name="SendEmail", version="2.7", inputs={"to": "someone"}
    ) == UngovernedToolkit("gmail")
    # An ungoverned entry names one toolkit exactly: it is not a prefix and not a pattern.
    with pytest.raises(ToolMapError, match="^UNMAPPED_TOOL$"):
        tools.decide(toolkit="gmail_labels", name="AddLabel", version="1.0", inputs={})
    with pytest.raises(ValidationError):
        declared({**deepcopy(ARCADE), "ungoverned_toolkits": ["gmail*"]})
    # Neither a governed declaration nor an ungoverned toolkit: refused, because passing
    # requires an operator to have written it down.
    with pytest.raises(ToolMapError, match="^UNMAPPED_TOOL$"):
        tools.decide(toolkit="slack", name="PostMessage", version="1.0", inputs={})


def test_an_undeclared_input_key_is_refused_before_any_kernel_call():
    """ExecBound decides on the fields the map declares and Arcade executes them all.

    A key the map does not model could change what the vendor does behind a decision made
    without it, so the whole call is refused rather than the key dropped, and the refusal
    carries a code and nothing the caller sent.
    """
    tools = tool_map()
    for inputs in (
        {"device_id": "device-9", "force": True},
        {"device_id": "device-9", "Device_Id": "device-1"},
        {"reason": "false_positive", "device_id": "device-9"},
    ):
        with pytest.raises(ToolMapError) as refused:
            tools.decide(**GOVERNED, inputs=inputs)
        assert str(refused.value) == "UNDECLARED_INPUT"
    # Declaring the key is what admits it; the value is then ignored for selection.
    admitted = tool_map(inputs=["device_id", "force"]).decide(
        **GOVERNED, inputs={"device_id": "device-9", "force": True}
    )
    assert isinstance(admitted, GovernedCall) and admitted.target.value == "device-9"


def test_the_target_is_the_one_declared_key_taken_by_name():
    """One top-level key, extracted by name: no path syntax, no fallback, no second source.

    A second place that can choose a target is a second place that can decide authority, so
    a key that is absent or is not a string is a refusal rather than a search, and a second
    target-shaped input is ignored for selection.
    """
    tools = tool_map()
    for inputs in (
        {},
        {"device_id": 5},
        {"device_id": True},
        {"device_id": None},
        {"device_id": {"id": "device-9"}},
        {"device_id": ["device-9"]},
    ):
        with pytest.raises(ToolMapError, match="^INVALID_TARGET$"):
            tools.decide(**GOVERNED, inputs=inputs)
    # The declared kind is the operator's, and the selector model refuses a value that is
    # not one: a provider id here, and nothing that would pass for a canonical id.
    canonical = tool_map(target={"kind": "canonical", "input": "device_id"})
    with pytest.raises(ToolMapError, match="^INVALID_TARGET$"):
        canonical.decide(**GOVERNED, inputs={"device_id": "device-9"})
    resolved = canonical.decide(
        **GOVERNED, inputs={"device_id": "6f1d0a36-0f4b-4a1a-9a1a-2b7c8d9e0f11"}
    )
    assert isinstance(resolved, GovernedCall) and resolved.target.kind == "canonical"
    # A second target-shaped key is declared and ignored; the declaration picks the key.
    two = tool_map(inputs=["device_id", "hostname"])
    call = two.decide(**GOVERNED, inputs={"device_id": "device-9", "hostname": "host.example.test"})
    assert isinstance(call, GovernedCall) and call.target.value == "device-9"


# What the released example adds to the declaration above: `endpoint.isolate` runs under
# `endpoint-isolation.v1`, which requires an incident, so the operator names the input that
# carries the claim and admits that key.
INCIDENT = {"incident": {"input": "incident_id"}, "inputs": ["device_id", "incident_id"]}
# The one this section's fixture UUID is written as, and the spellings that are the same id.
CLAIMED = "6f1d0a36-0f4b-4a1a-9a1a-2b7c8d9e0f11"


def test_al34_the_declared_incident_is_extracted_by_name_and_no_report_supplies_one():
    """One declared input, taken by name, validated as the wire body's own field is.

    An absent key and an explicit null are refused rather than sent on as an empty claim:
    a declaration naming the key is the operator's statement that this tool carries an
    incident, and a request with none reaches the kernel only to be refused there and
    charged an audited rejection for it. A value `ClaimedContext` would refuse is refused
    here, which makes what the map admits what an `ActionRequest` admits — the alternate
    UUID spellings pydantic's JSON path accepts included, each the same id afterwards.

    Reported metadata supplies no incident. `_consistent` is what reads a report and it
    reads `behavior` alone, so a report naming an id neither fills an absent claim nor
    replaces a declared one.
    """
    tools = tool_map(**INCIDENT)
    call = tools.decide(**GOVERNED, inputs={"device_id": "device-9", "incident_id": CLAIMED})
    assert isinstance(call, GovernedCall)
    assert call.claimed_context == ClaimedContext(incident_id=UUID(CLAIMED))
    for spelling in (
        CLAIMED.upper(),
        CLAIMED.replace("-", ""),
        f"{{{CLAIMED}}}",
        f"urn:uuid:{CLAIMED}",
    ):
        same = tools.decide(**GOVERNED, inputs={"device_id": "device-9", "incident_id": spelling})
        assert isinstance(same, GovernedCall) and same.claimed_context == call.claimed_context
    for claimed in (
        {},
        {"incident_id": None},
        {"incident_id": ""},
        {"incident_id": "not-an-id"},
        {"incident_id": 5},
        {"incident_id": True},
        {"incident_id": {"id": CLAIMED}},
        {"incident_id": [CLAIMED]},
    ):
        with pytest.raises(ToolMapError, match="^INVALID_INCIDENT$"):
            tools.decide(**GOVERNED, inputs={"device_id": "device-9", **claimed})
    # A report cannot fill the absent claim, and cannot displace the declared one.
    with pytest.raises(ToolMapError, match="^INVALID_INCIDENT$"):
        tools.decide(
            **GOVERNED,
            inputs={"device_id": "device-9"},
            metadata={"incident_id": CLAIMED, "behavior": {"destructive": True}},
        )
    reported = tools.decide(
        **GOVERNED,
        inputs={"device_id": "device-9", "incident_id": CLAIMED},
        metadata={"incident_id": str(uuid4()), "extras": {"incident": str(uuid4())}},
    )
    assert reported == call
    # A declaration naming no incident claims none, which is the shape a contract setting
    # `incident="none"` needs and the shape the rest of this section's map has.
    empty = tool_map().decide(**GOVERNED, inputs={"device_id": "device-9"})
    assert isinstance(empty, GovernedCall) and empty.claimed_context == ClaimedContext()


def test_arguments_are_declared_inputs_and_the_catalog_is_what_bounds_them():
    """The wire admits a bounded scalar; the resolved action's catalog spec admits its own.

    `Arguments` refuses anything that is not a bounded scalar, which is the only bound the
    map itself applies. What refuses free text, an argument the action does not declare or
    a value outside its domain is the catalog, one layer further in, so this asserts the
    catalog's answer to what the map produced rather than claiming the map made it.
    """
    tools = ToolMap(declared({"deadline_seconds": 4.0, "tools": [LIFT]}))
    call = tools.decide(**RELEASED, inputs={"device_id": "device-9", "reason": "false_positive"})
    assert isinstance(call, GovernedCall) and call.arguments.root == {"reason": "false_positive"}
    assert PRODUCTION_ACTIONS.normalize_arguments("endpoint.lift_isolation", call.arguments.root)
    free = tools.decide(**RELEASED, inputs={"device_id": "device-9", "reason": "<b>anything</b>"})
    assert isinstance(free, GovernedCall) and free.arguments.root == {"reason": "<b>anything</b>"}
    with pytest.raises(CatalogError):
        PRODUCTION_ACTIONS.normalize_arguments("endpoint.lift_isolation", free.arguments.root)
    for value in ({"nested": 1}, ["false_positive"], 1.5, "x" * 255, ""):
        with pytest.raises(ToolMapError, match="^INVALID_ARGUMENTS$"):
            tools.decide(**RELEASED, inputs={"device_id": "device-9", "reason": value})
    # An input mapped to an argument the action does not declare is refused at resolution:
    # `endpoint.isolate` declares none, and the map has no view of that.
    mismapped = ToolMap(
        declared(
            {"deadline_seconds": 4.0, "tools": [{**LIFT, "operation_ref": "endpoint.isolate"}]}
        )
    )
    produced = mismapped.decide(
        **RELEASED, inputs={"device_id": "device-9", "reason": "false_positive"}
    )
    assert isinstance(produced, GovernedCall) and produced.operation_ref == "endpoint.isolate"
    with pytest.raises(CatalogError):
        PRODUCTION_ACTIONS.normalize_arguments("endpoint.isolate", produced.arguments.root)


def test_reported_metadata_may_refuse_and_decides_nothing_else():
    """Metadata is caller-supplied input: it denies where it contradicts the map, or nothing.

    A tool mapped to a destructive action that reports itself read-only is a disagreement
    between the operator's declaration and the platform's self-description about what the
    action does, and a caller that lies in that direction denies its own call. A report that
    says nothing contradicts nothing, and no report selects a mapping, an action, a target
    or which side of the map a toolkit is on.
    """
    tools = tool_map()
    inputs = {"device_id": "device-9"}
    decided = tools.decide(**GOVERNED, inputs=inputs)
    for behavior in (
        {"read_only": True},
        {"destructive": False},
        {"read_only": "false"},
        {"destructive": 1},
        {"destructive": True, "read_only": True},
    ):
        with pytest.raises(ToolMapError, match="^BEHAVIOR_MISMATCH$"):
            tools.decide(**GOVERNED, inputs=inputs, metadata={"behavior": behavior})
    for metadata in (
        None,
        {},
        {"behavior": {}},
        {"behavior": {"idempotent": True, "open_world": True}},
        {"behavior": {"destructive": True, "read_only": False}},
        {"classification": {"service_domains": ["endpoint"]}},
        {"behavior": "not an object"},
        # Naming another operation, another target and another toolkit changes none of them.
        {
            "extras": {
                "operation_ref": "identity.disable",
                "target": "device-1",
                "toolkit": "gmail",
            }
        },
    ):
        assert tools.decide(**GOVERNED, inputs=inputs, metadata=metadata) == decided
    # A declaration with no expectation weighs no reported behavior at all.
    assert isinstance(
        tool_map(expect={}).decide(
            **GOVERNED, inputs=inputs, metadata={"behavior": {"read_only": True}}
        ),
        GovernedCall,
    )
    # And metadata moves nothing across the map in either direction.
    assert tools.decide(
        toolkit="gmail",
        name="SendEmail",
        version="2.7",
        inputs={},
        metadata={"behavior": {"destructive": True, "read_only": True}},
    ) == UngovernedToolkit("gmail")
    with pytest.raises(ToolMapError, match="^UNMAPPED_TOOL$"):
        tools.decide(
            toolkit="slack",
            name="PostMessage",
            version="1.0",
            inputs={},
            metadata={"extras": {"toolkit": "gmail"}},
        )


def test_al24_the_tool_map_is_validated_at_load_and_pinned_until_a_restart(tmp_path, config):
    """AL24: what the private file refuses, what it now admits, and what a reload may not do.

    Each invalid block is refused as the same opaque answer every invalid file gets, with no
    diagnostic quoting the file. A deployment that dispatches nothing declares no connector,
    which is the one relaxation of that minimum. And the block joins the reload shape, for
    the reason the precondition declarations are already in it: a file whose map differs
    from the running one is a restart, not a key rotation, because the map is bound into the
    surface at startup and a rotation would either change it underneath a live deployment or
    report a change that nothing read.
    """
    for failure in (
        "unservable_operation_ref",
        "governed_and_ungoverned",
        "target_outside_inputs",
        "incident_outside_inputs",
        "duplicate_declaration",
    ):
        block = deepcopy(ARCADE)
        tool = block["tools"][0]
        if failure == "unservable_operation_ref":
            # No ActionRequest this deployment parses could carry it, so no hook for this
            # tool could ever reach the kernel.
            tool["operation_ref"] = "Endpoint.Isolate"
        if failure == "governed_and_ungoverned":
            block["ungoverned_toolkits"] = ["gmail", "endpoint_mock"]
        if failure == "target_outside_inputs":
            tool["target"] = {"kind": "hostname", "input": "hostname"}
        if failure == "incident_outside_inputs":
            # The incident key is an extraction from `inputs` like the target's, so a
            # declaration naming a key outside the allowlist could never be filled.
            tool["incident"] = {"input": "incident_id"}
        if failure == "duplicate_declaration":
            block["tools"] = [tool, deepcopy(tool)]
        config["arcade"] = block
        with pytest.raises(ValueError, match="^Invalid runtime configuration$") as exc:
            load(tmp_path, config)
        assert exc.value.__context__ is None
        assert "endpoint_mock" not in str(exc.value)
    config["arcade"] = deepcopy(ARCADE)
    config["connectors"] = []
    assert not load(tmp_path, config)[0].connectors
    path = tmp_path / "private.json"
    path.write_text(json.dumps(config), encoding="utf-8")
    db = Database("postgresql+psycopg://invalid:invalid@127.0.0.1:1/execbound")
    try:
        runtime, human = load_runtime(path, db)
        baseline = read_configuration(path)
        assert baseline.arcade is not None
        # The deadline is the file's own, and the post-hook bound the documented default.
        assert (baseline.arcade.deadline_seconds, baseline.arcade.post_bytes) == (4.0, 1048576)
        rotated = deepcopy(config)
        rotated["continuation_keys"]["state-v2"] = "41" * 32
        rotated["active_key_id"] = "state-v2"
        rotated["arcade"]["tools"][0]["operation_ref"] = "identity.disable"
        path.write_text(json.dumps(rotated), encoding="utf-8")
        reload = reload_keys(path, runtime, human, baseline)
        assert (reload.state, reload.code, reload.rotated) == (
            "refused",
            "CONFIGURATION_CHANGED",
            False,
        )
        assert runtime.keys is not None and runtime.keys.active_key_id == "state-v1"
        # The running map is the one this refusal kept: a deployment builds it from the
        # configuration the reload returns, which is still the baseline.
        assert reload.configuration is baseline
        held = ToolMap(baseline.arcade).decide(**GOVERNED, inputs={"device_id": "device-9"})
        assert isinstance(held, GovernedCall) and held.operation_ref == "endpoint.isolate"
    finally:
        db.close()


# ---------------------------------------------------------------------------------------
# The pre hook. The decision table in `docs/ARCADE.md`, driven over the real HTTP surface
# against real PostgreSQL, with no connector configured for any account and the operator's
# tool map bound into the application at startup.


def _only_execution(engine, tenant):
    with engine.begin() as conn:
        scoped(conn, tenant)
        return conn.execute(
            text("SELECT execution_id FROM execbound.executions WHERE tenant_id=:t"), {"t": tenant}
        ).scalar_one()


def _execution_in_state(engine, tenant, state):
    """The one execution the tenant holds in this state; a scenario naming two would fail."""
    with engine.begin() as conn:
        scoped(conn, tenant)
        return conn.execute(
            text("SELECT execution_id FROM execbound.executions WHERE tenant_id=:t AND state=:s"),
            {"t": tenant, "s": state},
        ).scalar_one()


def _reserved(engine, tenant):
    """What a refusal must not add to: the reservation rows and the canonical claims."""
    return (impact_rows(engine, tenant), claim_rows(engine, tenant))


@contextmanager
def _captured_log():
    """The schema records this deployment emits, on a handler of this test's own.

    `install` keeps its standard-error handler bound to whatever `sys.stderr` was when the
    process first installed it, so reading the captured stream tells a test nothing it can
    rely on. An extra handler is what the installer's docstring says is left alone.
    """
    stream = io.StringIO()
    handler = logging.StreamHandler(stream)
    handler.setFormatter(SchemaFormatter())
    logger = logging.getLogger("execbound")
    logger.addHandler(handler)
    try:
        yield stream
    finally:
        logger.removeHandler(handler)


# The guide's example block, completed. `endpoint.isolate` is a released action under
# `endpoint-isolation.v1`, whose contract requires an incident, and the tool map's
# `incident` declaration names the input that carries the claim. `registry` seeds one OPEN, CRITICAL
# incident against the world's endpoint, which is the incident these hooks name.
RELEASED_TOOL = {
    **ARCADE_TOOL,
    "operation_ref": "endpoint.isolate",
    **INCIDENT,
}


def _released_block():
    """The deployment's block holding the released declaration and governing nothing else."""
    return hook_block(tools=[deepcopy(RELEASED_TOOL)], ungoverned_toolkits=[])


def _reachable(admin_engine, world):
    """The `provider_id` alias a governed hook needs to name the world's own endpoint."""
    with admin_engine.begin() as conn:
        _alias(
            conn,
            {
                "t": world["identity"].tenant_id,
                "alias": uuid4(),
                "a": world["account"],
                "p": WORLD_DEVICE,
                "r": world["target"],
                "start": world["clock"].now() - timedelta(days=1),
                "expires": world["clock"].now() + timedelta(days=1),
            },
        )


def _incident(admin_engine, world, resource, *, tenant=None):
    """One more OPEN, CRITICAL incident of this account, standing against one resource."""
    incident = uuid4()
    with admin_engine.begin() as conn:
        conn.execute(
            text(
                "INSERT INTO execbound.incidents "
                "(tenant_id, account_id, provider, resource_type, incident_id, resource_id, "
                "source_id, version, status, severity, observed_at) "
                "VALUES (:t, :a, 'mock_crowdstrike', 'endpoint', :i, :r, :s, 'incident-v1', "
                "'OPEN', 'CRITICAL', :observed)"
            ),
            {
                "t": tenant if tenant is not None else world["identity"].tenant_id,
                "a": world["account"],
                "i": incident,
                "r": resource,
                "s": world["incident_source"],
                "observed": world["clock"].now() - timedelta(seconds=60),
            },
        )
    return incident


def _released_hook(world, *, incident=None, execution_id="arcade-execution-1"):
    """One pre hook for the released tool: the world's endpoint and an incident id."""
    return {
        "execution_id": execution_id,
        "inputs": {
            "device_id": WORLD_DEVICE,
            "incident_id": str(world["incident"] if incident is None else incident),
        },
    }


def test_al34_a_released_contract_is_governed_when_the_map_declares_its_incident(
    db, gate_world, seeded, admin_engine
):
    """The guide's own example, end to end: `endpoint.isolate` under its released contract.

    Each context contract the production catalog releases sets `incident="required"`, and
    `resolution.registry.incident` reads the id from `ActionRequest.claimed_context` alone,
    before policy and before anything is reserved. Without the `incident` declaration the
    map would have nothing that could fill that field, and a governed hook against any
    released action would refuse; this is the row that says it does not.

    What the tenant retains says the claim arrived and was checked rather than believed: the
    frozen plan carries the claimed id, and the incident facts the contract froze carry the
    same id as their source object, which is the row `registry.incident` found under the
    mapping's own tenant, account, provider and resource type.
    """
    assert all(
        contract.incident == "required" for contract in PRODUCTION_CATALOG._contracts.values()
    )
    tenant = gate_world["identity"].tenant_id
    _reachable(admin_engine, gate_world)
    runtime = Runtime(db, [], clock=gate_world["clock"])
    with arcade_client(db, gate_world, seeded, block=_released_block(), runtime=runtime) as driver:
        answer = pre(driver, **_released_hook(gate_world))
    assert (answer.status_code, answer.json()) == (200, {"code": "OK"})
    assert execution_states(admin_engine, tenant) == ["DISPATCH_COMMITTED"]
    [impact] = impact_rows(admin_engine, tenant)
    assert impact["state"] == "UNRESOLVED"
    execution_id = UUID(str(_only_execution(admin_engine, tenant)))
    with db.transaction(tenant) as conn:
        frozen = store.frozen(store.read(conn, tenant, execution_id))
    assert frozen.intent.action == "endpoint.isolate"
    assert frozen.intent.target_id == gate_world["target"]
    assert frozen.context_contract_version == "endpoint-isolation.v1"
    assert frozen.request.claimed_context == ClaimedContext(incident_id=gate_world["incident"])
    assert frozen.fact("incident_status").source_object_id == str(gate_world["incident"])
    assert frozen.fact("incident_severity").value == "CRITICAL"


def test_al34_the_claimed_incident_is_checked_against_the_target_and_not_believed(
    db, gate_world, seeded, admin_engine
):
    """What the declaration buys is the ability to claim; the binding is the kernel's.

    `registry.incident` selects on the mapping's tenant, account, provider and resource type
    and on `i.resource_id = :target`, so an id naming nothing, an incident standing against
    another resource of this same account, and an incident another tenant owns each resolve
    no row. The request is refused before policy, opaquely, as every context refusal is, and
    nothing is reserved or claimed.

    The bound is asserted rather than implied: the query binds an incident to **the target**
    and not to this action, this agent or this tool, so a second incident of this tenant
    standing against the same endpoint is a claim it accepts. What a closed or low-severity
    one buys is then the tenant's policy pack's business — this world's pack requires
    `incident_status == "OPEN"` and `incident_severity == "CRITICAL"` among its conditions
    — and not the kernel's.
    """
    tenant = gate_world["identity"].tenant_id
    _reachable(admin_engine, gate_world)
    elsewhere = _incident(admin_engine, gate_world, gate_world["other"])
    foreign = _incident(admin_engine, gate_world, gate_world["target"], tenant=seeded["tenants"][1])
    runtime = Runtime(db, [], clock=gate_world["clock"])
    with arcade_client(db, gate_world, seeded, block=_released_block(), runtime=runtime) as driver:
        for index, claimed in enumerate((uuid4(), elsewhere, foreign)):
            answer = pre(
                driver,
                **_released_hook(gate_world, incident=claimed, execution_id=f"arcade-{index}"),
            )
            assert answer.json() == {
                "code": "CHECK_FAILED",
                "error_message": "EXECUTION_UNAVAILABLE",
            }
        assert execution_states(admin_engine, tenant) == []
        assert impact_rows(admin_engine, tenant) == []
        assert claim_rows(admin_engine, tenant) == []
        beside = _incident(admin_engine, gate_world, gate_world["target"])
        granted = pre(
            driver, **_released_hook(gate_world, incident=beside, execution_id="arcade-beside")
        )
    assert granted.json() == {"code": "OK"}
    assert execution_states(admin_engine, tenant) == ["DISPATCH_COMMITTED"]
    execution_id = UUID(str(_only_execution(admin_engine, tenant)))
    with db.transaction(tenant) as conn:
        frozen = store.frozen(store.read(conn, tenant, execution_id))
    assert frozen.request.claimed_context == ClaimedContext(incident_id=beside)


def test_al34_the_map_refuses_a_missing_or_malformed_incident_before_any_kernel_call(
    db, gate_world, seeded, admin_engine
):
    """An absent or unreadable claim is the map's refusal, not a null claim the kernel meets.

    The distinction is what this row is for. A request carrying no incident is refused by
    `registry.incident` too, so the hook would answer `CHECK_FAILED` either way — but the
    kernel's refusal costs a resolution, an audited rejection on the tenant's chain and the
    surface's own counted work, and it answers the opaque `EXECUTION_UNAVAILABLE` where the
    map answers the code that says which declared input was wrong. Nothing is resolved and
    the tenant's chain does not move.
    """
    tenant = gate_world["identity"].tenant_id
    _reachable(admin_engine, gate_world)
    runtime = Runtime(db, [], clock=gate_world["clock"])
    with arcade_client(db, gate_world, seeded, block=_released_block(), runtime=runtime) as driver:
        head = audit_head(admin_engine, tenant)
        for inputs in (
            {"device_id": WORLD_DEVICE},
            {"device_id": WORLD_DEVICE, "incident_id": None},
            {"device_id": WORLD_DEVICE, "incident_id": "incident-42"},
            {"device_id": WORLD_DEVICE, "incident_id": 42},
        ):
            answer = pre(driver, inputs=inputs)
            assert answer.json() == {"code": "CHECK_FAILED", "error_message": "INVALID_INCIDENT"}
        # A report naming an incident fills neither the absent claim nor the chain.
        named = pre(
            driver,
            inputs={"device_id": WORLD_DEVICE},
            tool={
                **GOVERNED_TOOL,
                "metadata": {
                    "behavior": {"destructive": True},
                    "incident_id": str(gate_world["incident"]),
                },
            },
        )
        assert named.json() == {"code": "CHECK_FAILED", "error_message": "INVALID_INCIDENT"}
        assert audit_head(admin_engine, tenant) == head
    assert execution_states(admin_engine, tenant) == []


def test_al1_a_governed_hook_is_granted_and_nothing_is_dispatched(
    db, arcade_world, seeded, admin_engine
):
    """AL1: the permit is one key, and what it leaves behind is a grant and no dispatch.

    The answer body carries `code` alone: no execution id, no grant and no secret reach the
    platform on a permit, because a permit is the whole of what it needs. What the tenant
    retains is the checkpoint admission's own work — one `DISPATCH_COMMITTED` row, one
    `UNRESOLVED` impact row and one held canonical claim — and the chain holds the grant
    with no dispatch attempt beside it, which is what says the extension asked the kernel to
    decide rather than to act.

    The correlation clause is the last of the row: one row naming this Arcade execution,
    the key admission was given and the execution it opened, holding the one secret that
    settles the grant — which is checkable rather than descriptive, because the execution
    retains that secret's digest in `owner_hash` and nothing else does.
    """
    tenant = arcade_world["identity"].tenant_id
    with _captured_log() as log, arcade_client(db, arcade_world, seeded) as driver:
        assert not driver.runtime.connectors
        answer = pre(driver)
    assert (answer.status_code, answer.json()) == (200, {"code": "OK"})
    # The request log names the surface the hook arrived on rather than folding it into the
    # human one, so an operator reading volume by surface sees the control point's traffic.
    assert '"surface":"arcade"' in log.getvalue()
    assert execution_states(admin_engine, tenant) == ["DISPATCH_COMMITTED"]
    [impact] = impact_rows(admin_engine, tenant)
    assert impact["state"] == "UNRESOLVED"
    [claim] = claim_rows(admin_engine, tenant)
    assert claim["released_at"] is None
    kinds = [kind for kind, _ in audit_kinds(admin_engine, tenant)]
    assert "execution.checkpoint_granted" in kinds
    assert "execution.dispatch_attempt" not in kinds
    # The frozen intent is the operator's declaration and the hook's one declared input,
    # and the idempotency key is Arcade's own execution id carried verbatim.
    execution_id = UUID(str(_only_execution(admin_engine, tenant)))
    with db.transaction(tenant) as conn:
        frozen = store.frozen(store.read(conn, tenant, execution_id))
    assert frozen.intent.target_id == arcade_world["target"]
    assert frozen.intent.action == "endpoint.isolate"
    with admin_engine.begin() as conn:
        scoped(conn, tenant)
        key = conn.execute(
            text("SELECT idempotency_key FROM execbound.execution_keys WHERE tenant_id=:t"),
            {"t": tenant},
        ).scalar_one()
    assert key == "arcade-execution-1"
    rows = correlation_rows(admin_engine, tenant)
    assert list(rows) == ["arcade-execution-1"]
    [row] = rows.values()
    assert (row["decision"], row["execution_id"], row["idempotency_key"]) == (
        "OK",
        execution_id,
        "arcade-execution-1",
    )
    retained_grant = grant_row(admin_engine, tenant, execution_id)
    assert row["operation_id"] == retained_grant["operation_id"]
    assert row["settled_at"] is None
    assert store.ticket_digest(row["report_secret"]) == retained_grant["owner_hash"]
    # The platform's own strings, retained inert: what it said the tool does and who it
    # attributed the call to. The declared input's value is not among them — what the
    # decision was taken on is the frozen plan above.
    assert (row["toolkit"], row["tool_name"], row["tool_version"]) == (
        GOVERNED_TOOL["toolkit"],
        GOVERNED_TOOL["name"],
        GOVERNED_TOOL["version"],
    )
    assert row["reported_metadata"] == {"behavior": {"destructive": True}}
    assert row["reported_user_id"] == "analyst@example.test"


def _al5_case(case, db, world, owner, admin_engine):
    """Set one of AL5's five refusals up and return the hook changes that reach it."""
    tenant = world["identity"].tenant_id
    if case == "denial":
        # The pack permits an isolation on a managed endpoint whose risk is at least 50.
        with admin_engine.begin() as conn:
            scoped(conn, tenant)
            conn.execute(
                text(
                    "UPDATE execbound.resource_facts SET value='10'::jsonb "
                    "WHERE tenant_id=:t AND fact_name='risk_score'"
                ),
                {"t": tenant},
            )
        return {}
    if case == "emergency_stop":
        activate_stop(db, world["admin"], "Incident 42", world["clock"])
        return {}
    if case == "ninth_grant":
        for index in range(8):
            device = f"device-9{index}"
            governed_target(admin_engine, world, device)
            granted = admit(
                db,
                world["identity"],
                _governed_request(device, f"filler-{index}"),
                world["clock"],
                available_accounts=frozenset(),
                catalog=CATALOG,
                attestable=attestable_ring,
            )
            assert granted.view.state == "DISPATCH_COMMITTED"
        return {}
    if case == "claimed_target":
        other = agent(admin_engine, db, world)
        held = admit(
            db,
            other,
            _governed_request(WORLD_DEVICE, "held-by-another"),
            world["clock"],
            available_accounts=frozenset(),
            catalog=CATALOG,
            attestable=attestable_ring,
        )
        assert held.view.state == "DISPATCH_COMMITTED"
        return {}
    administration.report_executor_key_compromise(
        owner, tenant, GATE_KEY_ID, world["admin"].principal_id, now=world["clock"].now()
    )
    return {}


def _governed_request(device, key):
    """The wire body the extension builds, built here for a scenario's own setup."""
    return parse_request(
        json.dumps(
            {
                "operation_ref": SYNTHETIC_OPERATION,
                "target": {"kind": "provider_id", "value": device},
                "arguments": {},
                "idempotency_key": key,
            }
        ).encode()
    )


@pytest.mark.parametrize(
    "case,code,answered_a_view",
    [
        # A denial and a claimed target are decisions the kernel answered with a view, so
        # the message names the execution the tenant now holds. `RESOURCE_BUSY` is the
        # retained reason of the second, and reasons do not reach a caller.
        ("denial", "DENIED", True),
        ("claimed_target", "DENIED", True),
        ("emergency_stop", "TENANT_STOPPED", False),
        ("ninth_grant", "TOO_MANY_GRANTS", False),
        ("unattestable_ring", "INVALID_BUNDLE", False),
    ],
)
def test_al5_a_refusal_carries_a_stable_code_and_an_execution_id_at_most(
    db, arcade_world, seeded, owner, admin_engine, case, code, answered_a_view
):
    """AL5: what a blocked tool call is told, and what the refusal left behind.

    `error_message` lands in the agent's context, so each of these is ExecBound's own
    vocabulary and, where the kernel answered with a view, that view's execution id. The
    denial is the case that matters most: a denial's reasons are retained on the transition
    and the audit record, and `ExecutionView` has no reasons field, so what reaches the
    caller is the state and nothing about why.

    Nothing the hook sent comes back either — not the input value, not the tool identity,
    not the Arcade user and not the access token — because the message is built from the
    kernel's answer rather than from the request.
    """
    tenant = arcade_world["identity"].tenant_id
    changes = _al5_case(case, db, arcade_world, owner, admin_engine)
    before = _reserved(admin_engine, tenant)
    with arcade_client(db, arcade_world, seeded) as driver:
        answer = pre(driver, **changes)
    assert answer.status_code == 200
    body = answer.json()
    assert set(body) == {"code", "error_message"}
    assert body["code"] == "CHECK_FAILED"
    if answered_a_view:
        refused = _execution_in_state(admin_engine, tenant, "DENIED")
        assert body["error_message"] == f"{code} execution={refused}"
    else:
        assert body["error_message"] == code
    for leaked in (
        "RESOURCE_BUSY",
        "device-0",
        "endpoint_mock",
        "ContainDevice",
        "analyst@example.test",
        "CROWDSTRIKE_TOKEN",
        "header.payload.signature",
    ):
        assert leaked not in answer.text
    assert _reserved(admin_engine, tenant) == before


def test_al6_capacity_is_the_retryable_refusal_and_a_ceiling_is_not(
    db, arcade_world, seeded, admin_engine
):
    """AL6: the two refusals ExecBound answers with 429, and the one it does not.

    `BUSY` is the runtime's own capacity bound and `RATE_LIMITED` is the surface rate
    limiter; both mean what Arcade's rate-limit code means and both arrive fast, because
    the capacity bound is acquired without blocking and refuses rather than queues.
    """
    world, tenant = arcade_world, arcade_world["identity"].tenant_id
    with arcade_client(db, world, seeded) as driver:
        # The kernel's own bound, taken the way the kernel takes it: the semaphore
        # `Runtime.execute` acquires without blocking before it admits anything.
        held = [
            driver.runtime._capacity.acquire(blocking=False)
            for _ in range(driver.runtime.concurrency)
        ]
        try:
            assert all(held)
            busy = pre(driver)
        finally:
            for slot in held:
                if slot:
                    driver.runtime._capacity.release()
    assert busy.json() == {"code": "RATE_LIMIT_EXCEEDED", "error_message": "BUSY"}
    assert execution_states(admin_engine, tenant) == []
    limited = Runtime(
        db, [], clock=world["clock"], catalog=CATALOG, limits=RequestLimits(agent_requests=1)
    )
    with arcade_client(db, world, seeded, runtime=limited) as driver:
        assert pre(driver).json() == {"code": "OK"}
        refused = pre(driver, execution_id="arcade-execution-2")
    assert refused.json() == {"code": "RATE_LIMIT_EXCEEDED", "error_message": "RATE_LIMITED"}
    assert execution_states(admin_engine, tenant) == ["DISPATCH_COMMITTED"]


def test_al6_a_shared_hard_ceiling_is_a_denial_and_names_no_rule(
    db, arcade_world, seeded, admin_engine
):
    """AL6's third clause: the ceiling denies, and the caller is told the state alone.

    Answering the retryable code for a budget ceiling would need a channel telling a caller
    which rule stopped it that no other caller of this kernel gets, so the rule id stays on
    the transition and the audit record where an operator reads it.
    """
    world, tenant = arcade_world, arcade_world["identity"].tenant_id
    ceiling = rule(rule_id="ceiling", max_targets=1, on_exceed="DENY")
    governed_bundle(db, world, limits=(ceiling,))
    governed_target(admin_engine, world, "device-77")
    with arcade_client(db, world, seeded) as driver:
        assert pre(driver).json() == {"code": "OK"}
        answer = pre(driver, execution_id="arcade-execution-2", inputs={"device_id": "device-77"})
    body = answer.json()
    assert body["code"] == "CHECK_FAILED"
    assert body["error_message"].startswith("DENIED execution=")
    assert "HARD_LIMIT" not in answer.text and "ceiling" not in answer.text
    reasons = [
        payload["reasons"]
        for kind, payload in audit_kinds(admin_engine, tenant)
        if kind == "execution.transition" and payload["to_state"] == "DENIED"
    ]
    assert reasons == [["HARD_LIMIT:ceiling"]]


def test_al8_the_map_decides_what_passes_and_an_ungoverned_pass_appends_nothing(
    db, arcade_world, seeded, admin_engine
):
    """AL8: a tool nobody declared is refused, and the toolkit an operator declared passes.

    The ungoverned pass is asserted against the tenant's chain specifically: the head's
    sequence and hash are read before and after and are unchanged, and no execution row
    exists for it. Appending one event per ungoverned call would put the project's whole
    tool traffic behind the tenant's audit head inside a five-second hook, to record calls
    the operator explicitly decided not to govern; limitation 7 states what that costs.
    """
    tenant = arcade_world["identity"].tenant_id
    with arcade_client(db, arcade_world, seeded) as driver:
        unmapped = pre(driver, tool={"toolkit": "slack", "name": "PostMessage", "version": "1.0"})
        version = pre(driver, tool={**GOVERNED_TOOL, "version": "1.1"})
        head = audit_head(admin_engine, tenant)
        ungoverned = pre(driver, tool={"toolkit": "gmail", "name": "SendEmail", "version": "2.7"})
        after = audit_head(admin_engine, tenant)
        contradiction = pre(
            driver, tool={**GOVERNED_TOOL, "metadata": {"behavior": {"read_only": True}}}
        )
    assert unmapped.json() == {"code": "CHECK_FAILED", "error_message": "UNMAPPED_TOOL"}
    assert version.json() == {"code": "CHECK_FAILED", "error_message": "UNMAPPED_TOOL"}
    assert ungoverned.json() == {"code": "OK"}
    assert after == head
    assert contradiction.json() == {"code": "CHECK_FAILED", "error_message": "BEHAVIOR_MISMATCH"}
    assert execution_states(admin_engine, tenant) == []
    assert _reserved(admin_engine, tenant) == ([], [])


def test_al9_an_input_the_map_does_not_admit_is_refused_before_any_kernel_call(
    db, arcade_world, seeded, admin_engine
):
    """AL9: the declared key is absent, is not a string, or is joined by one nobody declared.

    Each is refused where the map is read, which is before the kernel is called at all: the
    tenant's chain does not move, nothing resolves, nothing reserves and nothing is claimed.
    The refusal names the rule it broke and never the key or the value, because the message
    is read by the agent that wrote them.
    """
    tenant = arcade_world["identity"].tenant_id
    head = audit_head(admin_engine, tenant)
    with arcade_client(db, arcade_world, seeded) as driver:
        answers = {
            "absent": pre(driver, inputs={}),
            "not_a_string": pre(driver, inputs={"device_id": 5}),
            "undeclared": pre(driver, inputs={"device_id": WORLD_DEVICE, "force": True}),
        }
    assert answers["absent"].json() == {"code": "CHECK_FAILED", "error_message": "INVALID_TARGET"}
    assert answers["not_a_string"].json() == answers["absent"].json()
    assert answers["undeclared"].json() == {
        "code": "CHECK_FAILED",
        "error_message": "UNDECLARED_INPUT",
    }
    for answer in answers.values():
        assert "force" not in answer.text and "device_id" not in answer.text
    assert audit_head(admin_engine, tenant) == head
    assert execution_states(admin_engine, tenant) == []
    assert _reserved(admin_engine, tenant) == ([], [])


def test_al35_a_governed_call_the_map_refuses_leaves_a_countable_row(
    db, arcade_world, seeded, admin_engine
):
    """AL35: a refusal above the kernel is countable, and the chain still does not move.

    A governed call the map refused used to leave nothing anywhere — no correlation row, no
    audit event, no execution — so a tenant counting its own refused governed calls out of
    `arcade_hooks` undercounted by exactly the class of refusal vendor schema drift produces
    (#339). The row now written carries what tells drift from a bad call: the toolkit, the
    tool and the version that was refused.

    It is a plain insert under the tenant fence and not an audit event, which is the whole
    reason it is affordable: an event per refused call would put the project's tool traffic
    behind the tenant's audit head, which is what AL8's comment refuses and what this must
    not start doing. So the chain is asserted unmoved here as it is there.

    The third property is the one that makes the row safe rather than merely useful. A
    refusal row must not wedge a later, legitimate delivery of the same Arcade id: `_OPEN`
    ends `ON CONFLICT DO NOTHING`, so the retry's open is a no-op and the kernel path
    updates the row it finds. That is asserted by granting on an id a refusal already
    opened.
    """
    tenant = arcade_world["identity"].tenant_id
    principal = arcade_world["identity"].principal_id
    head = audit_head(admin_engine, tenant)
    with arcade_client(db, arcade_world, seeded) as driver:
        unmapped = pre(
            driver,
            execution_id="arcade-refused-1",
            tool={"toolkit": "slack", "name": "PostMessage", "version": "1.0"},
        )
        undeclared = pre(
            driver,
            execution_id="arcade-refused-2",
            inputs={"device_id": WORLD_DEVICE, "force": True},
        )
        # An id outside the kernel's class cannot key a row, so this one is answered and
        # not recorded: the correlation key's third part is the unusable thing, and a
        # refusal is not worth inventing a second key for.
        unkeyable = pre(
            driver,
            execution_id="not a usable key",
            tool={"toolkit": "slack", "name": "PostMessage", "version": "1.0"},
        )
        # Read inside the client, after the refusals and before the grant: the grant
        # appends to the chain legitimately, so only the refusals are measured here.
        after_refusals = audit_head(admin_engine, tenant)
        granted = pre(driver, execution_id="arcade-refused-1")
    assert unmapped.json() == {"code": "CHECK_FAILED", "error_message": "UNMAPPED_TOOL"}
    assert undeclared.json() == {"code": "CHECK_FAILED", "error_message": "UNDECLARED_INPUT"}
    assert unkeyable.json() == {"code": "CHECK_FAILED", "error_message": "UNMAPPED_TOOL"}
    assert granted.json() == {"code": "OK"}

    rows = correlation_rows(admin_engine, tenant, principal)
    assert set(rows) == {"arcade-refused-1", "arcade-refused-2"}, (
        "an unkeyable id must record nothing, and every keyable refusal must record"
    )
    refused_row = rows["arcade-refused-2"]
    assert refused_row["decision"] == "CHECK_FAILED"
    assert refused_row["execution_id"] is None and refused_row["report_secret"] is None
    assert (
        refused_row["toolkit"],
        refused_row["tool_name"],
        refused_row["tool_version"],
    ) == (GOVERNED_TOOL["toolkit"], GOVERNED_TOOL["name"], GOVERNED_TOOL["version"])
    # The refused row is not a tombstone: the same Arcade id granted afterwards, and the
    # row it left was completed rather than blocking the delivery.
    adopted = rows["arcade-refused-1"]
    assert adopted["decision"] == "OK" and adopted["execution_id"] is not None
    assert adopted["report_secret"] is not None

    assert after_refusals == head, "recording a refusal must not append to the tenant's chain"


# One identity operation this tenant maps, so a hostname selector reaches the kernel. The
# resource itself is not provisioned: `resource()` refuses an identity resource named by
# hostname before it reads a resource at all, which is the refusal AL10 is about.
IDENTITY_TOOL = {
    "toolkit": "entra_mock",
    "name": "DisableUser",
    "versions": ["1.0"],
    "operation_ref": "identity.disable",
    "target": {"kind": "hostname", "input": "hostname"},
    "inputs": ["hostname"],
    "arguments": {},
}


def _identity_mapping(engine, world):
    tenant, account = world["identity"].tenant_id, uuid4()
    with engine.begin() as conn:
        conn.execute(
            text(
                "INSERT INTO execbound.connector_accounts(tenant_id,account_id,provider, space_id) "
                "VALUES (:t,:a,'mock_entra', "
                "(SELECT space_id FROM execbound.spaces WHERE tenant_id = :t))"
            ),
            {"t": tenant, "a": account},
        )
        conn.execute(
            text(
                "INSERT INTO execbound.operation_mappings "
                "(tenant_id,operation_ref,account_id,provider,resource_type,action,"
                "provider_operation,mapping_version,schema_version,context_contract_version) "
                "VALUES (:t,'identity.disable',:a,'mock_entra','identity','identity.disable',"
                "'disable','map-v1','action.v1','identity-control.v1')"
            ),
            {"t": tenant, "a": account},
        )


def test_al10_the_declared_key_selects_the_target_and_the_kernel_keeps_its_own_refusal(
    db, arcade_world, seeded, admin_engine
):
    """AL10: a second target-shaped input, and a selector kind only the kernel can refuse.

    Declaring a second key admits it and changes nothing about selection, because
    `target.input` names the one key the operator chose and there is no search behind it.
    Leaving it undeclared refuses the whole call rather than dropping the key.

    The identity tool is the other half: the map builds the selector the operator declared
    and hands it over, and what refuses an identity resource named by hostname is the
    kernel, which is where that refusal belongs — asserted by the code that comes back
    being the kernel's and not one of the map's four.
    """
    world, tenant = arcade_world, arcade_world["identity"].tenant_id
    _identity_mapping(admin_engine, world)
    tools = [{**deepcopy(ARCADE_TOOL), "inputs": ["device_id", "hostname"]}, IDENTITY_TOOL]
    with arcade_client(db, world, seeded, block=hook_block(tools=tools)) as driver:
        both = pre(driver, inputs={"device_id": WORLD_DEVICE, "hostname": "ws01.example"})
        identity_hook = pre(
            driver,
            execution_id="arcade-execution-2",
            tool={"toolkit": "entra_mock", "name": "DisableUser", "version": "1.0"},
            inputs={"hostname": "ws01.example"},
        )
    assert both.json() == {"code": "OK"}
    # The declared key alone selected the target: the grant names the endpoint `device_id`
    # pointed at, and the hostname input reached nothing.
    execution_id = UUID(str(_only_execution(admin_engine, tenant)))
    with db.transaction(tenant) as conn:
        frozen = store.frozen(store.read(conn, tenant, execution_id))
    assert frozen.intent.target_id == world["target"]
    assert identity_hook.json() == {
        "code": "CHECK_FAILED",
        "error_message": "EXECUTION_UNAVAILABLE",
    }
    # Undeclared, the same second key refuses the whole call before any kernel work.
    with arcade_client(db, world, seeded) as driver:
        undeclared = pre(
            driver,
            execution_id="arcade-execution-3",
            inputs={"device_id": WORLD_DEVICE, "hostname": "ws01.example"},
        )
    assert undeclared.json() == {"code": "CHECK_FAILED", "error_message": "UNDECLARED_INPUT"}


@contextmanager
def _hold_the_fence(admin_engine, tenant):
    """Take the lock `_admit` takes first, so an admission blocks where the kernel blocks."""
    with admin_engine.begin() as conn:
        scoped(conn, tenant)
        conn.execute(
            text(
                "INSERT INTO execbound.tenant_policy_control(tenant_id,changed_at) "
                "VALUES (:t,now()) ON CONFLICT (tenant_id) DO NOTHING"
            ),
            {"t": tenant},
        )
        conn.execute(
            text(
                "SELECT tenant_id FROM execbound.tenant_policy_control "
                "WHERE tenant_id=:t FOR UPDATE"
            ),
            {"t": tenant},
        ).one()
        yield conn


def _wait_for_commit(admin_engine, tenant, seconds=10):
    limit = time.monotonic() + seconds
    while not execution_states(admin_engine, tenant) and time.monotonic() < limit:
        time.sleep(0.05)


def test_al21_the_deadline_answers_and_leaves_the_abandoned_decision_to_commit(
    db, arcade_world, seeded, admin_engine
):
    """AL21: the hook answers inside its own budget while admission is still in flight.

    Admission is held at the tenant fence by an owner connection holding
    `tenant_policy_control` for update, which is where `_admit` takes its first lock, so the
    decision is genuinely in flight rather than simulated. The extension answers
    `CHECK_FAILED` at its configured budget and below Arcade's documented five-second
    default, and deliberately not the retryable code: the abandoned decision may still
    commit, so inviting an immediate retry would invite a refusal.

    What it commits is then retained and never refunded — one grant, one `UNRESOLVED` impact
    row, one held claim and one slot of the cap of eight — which is a residual
    `docs/ARCADE.md` states rather than one this test discovered. The queue page an operator
    reads it on is tested with the pages; the count admission itself keeps is what is
    asserted here.
    """
    world, tenant = arcade_world, arcade_world["identity"].tenant_id
    waiting = Event()

    def at_fence(conn, cursor, statement, parameters, context, executemany):
        if "tenant_policy_control" in statement and "FOR UPDATE" in statement:
            waiting.set()

    event.listen(db.engine, "before_cursor_execute", at_fence)
    try:
        with arcade_client(db, world, seeded, block=hook_block(deadline_seconds=0.5)) as driver:
            with ThreadPoolExecutor(max_workers=1) as pool:
                with _hold_the_fence(admin_engine, tenant):
                    started = time.monotonic()
                    future = pool.submit(pre, driver)
                    assert waiting.wait(5)
                    answer = future.result(timeout=10)
                    elapsed = time.monotonic() - started
                _wait_for_commit(admin_engine, tenant)
    finally:
        event.remove(db.engine, "before_cursor_execute", at_fence)
    assert answer.json() == {"code": "CHECK_FAILED", "error_message": "DEADLINE_EXCEEDED"}
    assert 0.5 <= elapsed < 5.0
    assert execution_states(admin_engine, tenant) == ["DISPATCH_COMMITTED"]
    [impact] = impact_rows(admin_engine, tenant)
    assert impact["state"] == "UNRESOLVED"
    [claim] = claim_rows(admin_engine, tenant)
    assert claim["released_at"] is None
    with db.transaction(tenant) as conn:
        assert store.outstanding_grants(conn, tenant, world["identity"].principal_id) == 1
    # One decision, not two: the extension gave up on the answer and sent nothing again.
    granted = [
        payload
        for kind, payload in audit_kinds(admin_engine, tenant)
        if kind == "execution.checkpoint_granted"
    ]
    assert len(granted) == 1


def test_the_decision_table_rests_on_two_facts_and_refuses_everything_else(db, gate_world):
    """The decision table's rows against `_decided`, including the ones the kernel cannot pose.

    Two conjuncts behind `OK` are redundant through the kernel: a checkpoint object is set
    only on an admission that granted, and the stop branch answers a known key with a row
    view that carries no grant. An end-to-end walk therefore passes over the removal of
    either. They are varied here one at a time, against views a real admission produced,
    which is what makes each a covered refusal rather than defence nothing exercises.

    The third is no longer redundant and is asserted in both directions here as well as end
    to end: `held` is the correlation row's fact, and a `regranted` answer beside a row that
    does hold the secret is exactly the repeat delivery of one Arcade id that AL2 drives.
    """
    granted = checkpoint(db, gate_world).view
    regranted = checkpoint(db, gate_world).view
    assert granted.checkpoint is not None and granted.checkpoint.report_secret is not None
    assert regranted.checkpoint is not None and regranted.checkpoint.regranted
    page = "https://execbound.example/approvals"
    assert _decided(granted, page, True) == HookResult("OK")
    # A re-grant is answered on the row rather than on the answer: the same view passes
    # where an earlier delivery of this Arcade id retained the secret and is refused where
    # no delivery of it did.
    assert _decided(regranted, page, True) == HookResult("OK")
    assert _decided(regranted, page, False).code == "CHECK_FAILED"
    # The grant's own state, its grant object and the absence of a stop, each on its own.
    assert (
        _decided(granted.model_copy(update={"state": "RESERVED"}), page, True).code
        == "CHECK_FAILED"
    )
    assert _decided(granted.model_copy(update={"checkpoint": None}), page, True).code == (
        "CHECK_FAILED"
    )
    assert _decided(granted.model_copy(update={"tenant_stopped": True}), page, True) == HookResult(
        "CHECK_FAILED", f"TENANT_STOPPED execution={granted.execution_id}"
    )
    # An observing tenant mints no secret, so its own `OK` cannot rest on one.
    observed = granted.model_copy(update={"state": "OBSERVED", "checkpoint": None})
    assert _decided(observed, page, False) == HookResult("OK")
    assert _decided(observed.model_copy(update={"tenant_stopped": True}), page, False).code == (
        "CHECK_FAILED"
    )
    pending = granted.model_copy(update={"state": "PENDING_APPROVAL", "checkpoint": None})
    assert _decided(pending, page, False) == HookResult(
        "CHECK_FAILED", f"PENDING_APPROVAL execution={granted.execution_id} approvals={page}"
    )
    # A deployment naming no approvals page says the state and the execution and stops.
    assert _decided(pending, None, False) == HookResult(
        "CHECK_FAILED", f"PENDING_APPROVAL execution={granted.execution_id}"
    )
    for state in (
        "ATTEMPTED",
        "DENIED",
        "RESERVED",
        "INDETERMINATE",
        "STALE_AUTHORIZATION",
        "EXECUTED",
        "FAILED_NOT_EXECUTED",
        "FAILED_EFFECT_UNKNOWN",
    ):
        answer = _decided(
            granted.model_copy(update={"state": state, "checkpoint": None}), page, True
        )
        assert answer == HookResult("CHECK_FAILED", f"{state} execution={granted.execution_id}")


def _granted(admin_engine, tenant):
    """Every grant this tenant's chain holds, in order, by whether it minted a secret."""
    return [
        payload["regranted"]
        for kind, payload in audit_kinds(admin_engine, tenant)
        if kind == "execution.checkpoint_granted"
    ]


def _held_secret(admin_engine, tenant, arcade_id):
    """The secret this Arcade execution's own row holds, or None where it holds none."""
    return correlation_rows(admin_engine, tenant)[arcade_id]["report_secret"]


def test_al2_a_redelivered_arcade_id_is_answered_from_its_own_row_and_charges_nothing(
    db, arcade_world, seeded, admin_engine
):
    """AL2: three deliveries of one Arcade execution id, then one after the plan expires.

    Arcade documents no idempotency guarantee and retries 5xx, timeouts and connection
    errors, so one tool call arriving three times is ordinary rather than anomalous. Nothing
    in the extension makes that safe: the idempotency key is Arcade's own execution id, the
    kernel answers a known key from its existing row, and the second and third answers are
    re-grants that describe the same act, mint no secret and reserve, charge and claim
    nothing. What the extension adds is the reason those answers are still `OK` — the row
    this Arcade id opened on its first delivery retained the secret the first answer minted.

    The fourth delivery is the same key again once the frozen plan has expired. A re-grant
    is bounded by that plan and this one carries no grant at all, so the row's secret is not
    enough: `OK` needs a live grant beside it, and the answer is the state and the execution
    id. What the first delivery reserved and claimed is untouched by the refusal, which is
    a residual `docs/ARCADE.md` states rather than a failure this walk found.
    """
    world, tenant = arcade_world, arcade_world["identity"].tenant_id
    with arcade_client(db, world, seeded) as driver:
        delivered = [pre(driver) for _ in range(3)]
        execution_id = UUID(str(_only_execution(admin_engine, tenant)))
        secret = _held_secret(admin_engine, tenant, "arcade-execution-1")
        granted = correlation_rows(admin_engine, tenant)["arcade-execution-1"]["operation_id"]
        world["clock"].value = world["clock"].now() + timedelta(seconds=300)
        assert world["clock"].now() >= frozen_plan(db, world, execution_id).valid_until
        expired = pre(driver)
    assert [answer.json() for answer in delivered] == [{"code": "OK"}] * 3
    assert expired.json() == {
        "code": "CHECK_FAILED",
        "error_message": f"DISPATCH_COMMITTED execution={execution_id}",
    }
    assert execution_states(admin_engine, tenant) == ["DISPATCH_COMMITTED"]
    [impact] = impact_rows(admin_engine, tenant)
    assert impact["state"] == "UNRESOLVED"
    [claim] = claim_rows(admin_engine, tenant)
    assert claim["released_at"] is None
    # One secret, minted once and retained on the one row: the two re-grants that were
    # answered `OK` wrote none, and the expired delivery neither wrote nor cleared one.
    assert _granted(admin_engine, tenant) == [False, True, True]
    rows = correlation_rows(admin_engine, tenant)
    assert list(rows) == ["arcade-execution-1"]
    [row] = rows.values()
    assert row["report_secret"] == secret
    # The operation the grant named is retained for the same reason and by the same
    # `COALESCE`: the expired delivery carries no grant, so it names no operation, and a
    # completion that wrote what it carried would leave the row naming none.
    assert granted is not None and row["operation_id"] == granted
    assert (
        store.ticket_digest(secret) == grant_row(admin_engine, tenant, execution_id)["owner_hash"]
    )
    # The column says what the last delivery was answered; the row it says it about is the
    # one the first delivery opened, which its creation time and its key both show.
    assert (row["decision"], row["execution_id"]) == ("CHECK_FAILED", execution_id)
    assert row["idempotency_key"] == "arcade-execution-1"


def test_two_deliveries_of_one_arcade_id_open_one_row_and_mint_one_secret(
    db, arcade_world, seeded, admin_engine
):
    """AL2's deliveries again, released together rather than in turn.

    Arcade retries on a connection error, so a redelivery overlapping the delivery it is
    retrying is the shape a lost response actually has. Two things are settled by the
    database rather than by ordering, and both are asserted: the primary key on
    `(tenant_id, arcade_execution_id)` with `ON CONFLICT DO NOTHING` means one insert opens
    the row and the other is a no-op, and the tenant fence means one admission creates the
    execution and mints the one secret while the other is answered a re-grant carrying none.
    So there is one row, one execution, one reservation, one claim and one secret whichever
    delivery arrives first.

    What the order does decide is the code each delivery is answered. The completions
    serialize on the row and `COALESCE` keeps the secret either way, but a delivery whose
    completion commits before the minting delivery's sees no secret yet and is refused. That
    is the fail-closed side of the `OK` rule and it costs the tenant nothing — the grant,
    the reservation and the claim stand, and the row that retains the secret can still
    settle them — so what is asserted is that at least one delivery is answered `OK` and
    that a delivery that is not gets the ordinary `DISPATCH_COMMITTED` refusal rather than a
    second charge.
    """
    world, tenant = arcade_world, arcade_world["identity"].tenant_id
    barrier = Barrier(2)
    with arcade_client(db, world, seeded) as driver:

        def deliver(_index):
            barrier.wait(timeout=10)
            return pre(driver)

        with ThreadPoolExecutor(max_workers=2) as pool:
            answers = [answer.json() for answer in pool.map(deliver, range(2))]
    execution_id = UUID(str(_only_execution(admin_engine, tenant)))
    refusal = {
        "code": "CHECK_FAILED",
        "error_message": f"DISPATCH_COMMITTED execution={execution_id}",
    }
    assert answers.count({"code": "OK"}) >= 1
    assert [answer for answer in answers if answer != {"code": "OK"}] in ([], [refusal])
    rows = correlation_rows(admin_engine, tenant)
    assert list(rows) == ["arcade-execution-1"]
    [row] = rows.values()
    assert (
        store.ticket_digest(row["report_secret"])
        == grant_row(admin_engine, tenant, execution_id)["owner_hash"]
    )
    assert _granted(admin_engine, tenant) == [False, True]
    assert execution_states(admin_engine, tenant) == ["DISPATCH_COMMITTED"]
    assert [impact["state"] for impact in impact_rows(admin_engine, tenant)] == ["UNRESOLVED"]
    assert [claim["released_at"] for claim in claim_rows(admin_engine, tenant)] == [None]


def test_al3_a_second_arcade_id_for_one_intent_is_refused_and_the_first_stands(
    db, arcade_world, seeded, admin_engine
):
    """AL3: two Arcade ids for one intent, concurrently and then sequentially, then a repeat.

    The concurrent pair is the case intent adoption opens and this design has to close: two
    different Arcade executions of one intent would otherwise both be answered from one
    ExecBound execution, and Arcade would run the tool twice against one reservation and one
    claim. They are released together on a barrier and serialize at the tenant fence, which
    is where the kernel serializes every admission; the winner creates the execution and is
    handed the one secret that execution ever mints, and the loser is adopted onto it and
    answered `regranted` with no secret at all. Its own row holds none, so it is refused —
    and which of the two wins is not asserted, because the fence decides that and either
    order leaves one grant, one reservation and one claim.

    A third Arcade id delivered afterwards, while the grant is live and unsettled, is the
    same refusal arrived at the same way. Once the first settles, the intent is no longer
    adopted: a fourth is resolved and evaluated again, and what refuses it is the canonical
    claim the settlement still holds, which is a denial and not a re-grant.
    """
    world, tenant = arcade_world, arcade_world["identity"].tenant_id
    barrier = Barrier(2)
    with arcade_client(db, world, seeded) as driver:

        def deliver(arcade_id):
            barrier.wait(timeout=10)
            return pre(driver, execution_id=arcade_id)

        with ThreadPoolExecutor(max_workers=2) as pool:
            raced = dict(
                zip(
                    ("arcade-execution-1", "arcade-execution-2"),
                    pool.map(deliver, ("arcade-execution-1", "arcade-execution-2")),
                    strict=True,
                )
            )
        third = pre(driver, execution_id="arcade-execution-3")
        execution_id = UUID(str(_only_execution(admin_engine, tenant)))
        rows = correlation_rows(admin_engine, tenant)
        holders = [name for name, row in rows.items() if row["report_secret"] is not None]
        assert len(holders) == 1
        [holder] = holders
        assert raced[holder].json() == {"code": "OK"}
        refused = f"DISPATCH_COMMITTED execution={execution_id}"
        assert [answer.json() for name, answer in raced.items() if name != holder] == [
            {"code": "CHECK_FAILED", "error_message": refused}
        ]
        assert third.json() == {"code": "CHECK_FAILED", "error_message": refused}
        # One execution, one reservation and one claim under the three of them.
        assert execution_states(admin_engine, tenant) == ["DISPATCH_COMMITTED"]
        assert len(impact_rows(admin_engine, tenant)) == 1
        assert len(claim_rows(admin_engine, tenant)) == 1
        assert sorted(rows) == [f"arcade-execution-{n}" for n in (1, 2, 3)]
        assert {row["execution_id"] for row in rows.values()} == {execution_id}
        assert _granted(admin_engine, tenant) == [False, True, True]
        # The settlement uses the secret the extension retained, which is what says the
        # refused rows were refused for holding nothing rather than for holding the wrong
        # thing: one Arcade execution can settle this grant and it is the one that won.
        assert report(db, world, execution_id, rows[holder]["report_secret"]).state == "EXECUTED"
        fourth = pre(driver, execution_id="arcade-execution-4")
    settled, denied = (
        UUID(str(_execution_in_state(admin_engine, tenant, state)))
        for state in ("EXECUTED", "DENIED")
    )
    assert settled == execution_id
    assert fourth.json() == {
        "code": "CHECK_FAILED",
        "error_message": f"DENIED execution={denied}",
    }
    denials = [
        payload
        for kind, payload in audit_kinds(admin_engine, tenant)
        if kind == "execution.transition" and payload["to_state"] == "DENIED"
    ]
    assert [payload["reason"] for payload in denials] == ["RESOURCE_BUSY"]
    # The repeat was evaluated rather than adopted, and it reserved nothing: the settled
    # row's confirmed charge is still the tenant's only impact row and the claim is held.
    [impact] = impact_rows(admin_engine, tenant)
    assert (impact["execution_id"], impact["state"]) == (execution_id, "CONFIRMED")
    assert [claim["released_at"] for claim in claim_rows(admin_engine, tenant)] == [None]


def test_al4_an_abandoned_decision_leaves_a_grant_no_arcade_id_can_settle(
    db, arcade_world, seeded, admin_engine
):
    """AL4: the extension gives up at its own deadline and admission commits anyway.

    AL21 establishes the first half — the answer arrives inside the budget and the decision
    goes on to commit — and what this adds is the state it leaves and what the next hook
    does with it. The correlation row stays exactly as it was opened: no decision, no
    execution and no secret, because nothing was answered to complete it with. A second
    Arcade id for the same intent is then adopted by admission, answered a re-grant carrying
    no secret, and refused by the one condition that refuses the concurrent second id — no
    secret in this row, no `OK`.

    Arcade's own retry of the abandoned call is refused the same way and for the same
    reason, which is the difference between this row and AL2's: a redelivery passes on the
    secret the first delivery retained, and this Arcade id's first delivery retained none.

    The residual is limitation 9 and is asserted rather than described: the grant stands
    unreported against the principal's cap of eight, the reservation and the claim stand
    with it, and what the extension no longer does is tell the platform to act on it.
    """
    world, tenant = arcade_world, arcade_world["identity"].tenant_id
    waiting = Event()

    def at_fence(conn, cursor, statement, parameters, context, executemany):
        if "tenant_policy_control" in statement and "FOR UPDATE" in statement:
            waiting.set()

    event.listen(db.engine, "before_cursor_execute", at_fence)
    try:
        with arcade_client(db, world, seeded, block=hook_block(deadline_seconds=0.5)) as driver:
            with ThreadPoolExecutor(max_workers=1) as pool:
                with _hold_the_fence(admin_engine, tenant):
                    abandoned = pool.submit(pre, driver)
                    assert waiting.wait(5)
                    assert abandoned.result(timeout=10).json() == {
                        "code": "CHECK_FAILED",
                        "error_message": "DEADLINE_EXCEEDED",
                    }
                _wait_for_commit(admin_engine, tenant)
            second = pre(driver, execution_id="arcade-execution-2")
            # Read before the redelivery below completes it, because what the deadline left
            # is exactly what this asserts.
            opened = correlation_rows(admin_engine, tenant)["arcade-execution-1"]
            redelivered = pre(driver)
    finally:
        event.remove(db.engine, "before_cursor_execute", at_fence)
    execution_id = UUID(str(_only_execution(admin_engine, tenant)))
    refusal = {
        "code": "CHECK_FAILED",
        "error_message": f"DISPATCH_COMMITTED execution={execution_id}",
    }
    assert second.json() == refusal
    assert redelivered.json() == refusal
    assert (opened["decision"], opened["execution_id"], opened["report_secret"]) == (
        None,
        None,
        None,
    )
    assert opened["idempotency_key"] == "arcade-execution-1"
    rows = correlation_rows(admin_engine, tenant)
    assert sorted(rows) == ["arcade-execution-1", "arcade-execution-2"]
    # The redelivery completed the row it had opened, and completed it with a refusal: the
    # secret that would have made it an `OK` was in a response nobody kept.
    assert [
        (row["decision"], row["execution_id"], row["report_secret"]) for row in rows.values()
    ] == [("CHECK_FAILED", execution_id, None)] * 2
    assert execution_states(admin_engine, tenant) == ["DISPATCH_COMMITTED"]
    assert [row["state"] for row in impact_rows(admin_engine, tenant)] == ["UNRESOLVED"]
    assert [claim["released_at"] for claim in claim_rows(admin_engine, tenant)] == [None]
    assert _granted(admin_engine, tenant) == [False, True, True]
    with db.transaction(tenant) as conn:
        assert store.outstanding_grants(conn, tenant, world["identity"].principal_id) == 1


def test_al4_a_crash_between_the_kernel_and_the_row_refuses_the_next_arcade_id(
    db, arcade_world, seeded, admin_engine, monkeypatch
):
    """AL4: the second shape the rule refuses, produced rather than written by hand.

    The completion is made to fail after the kernel has committed, which is the crash
    limitation 9 in `docs/ARCADE.md` names: the grant exists, the response carrying its one
    secret is lost, and the row the extension opened before the call is all that remains.
    The caller is told nothing it could act on — the deployment boundary's job, and here the
    application's own 503 with no hook code in it.

    Under a rule keyed on whether another row's own hook was granted, the next Arcade id
    would pass and be answered `OK` on a grant nothing could ever settle. It is refused here
    for the reason every other secretless row is.
    """
    world, tenant = arcade_world, arcade_world["identity"].tenant_id

    def crash(*args, **kwargs):
        raise RuntimeError("the correlation write never happened")

    with arcade_client(db, world, seeded) as driver:
        monkeypatch.setattr(routes.store, "complete", crash)
        lost = pre(driver)
        monkeypatch.undo()
        second = pre(driver, execution_id="arcade-execution-2")
    execution_id = UUID(str(_only_execution(admin_engine, tenant)))
    assert lost.status_code == 503 and "code" not in lost.json()
    assert second.json() == {
        "code": "CHECK_FAILED",
        "error_message": f"DISPATCH_COMMITTED execution={execution_id}",
    }
    rows = correlation_rows(admin_engine, tenant)
    crashed = rows["arcade-execution-1"]
    assert (crashed["decision"], crashed["execution_id"], crashed["report_secret"]) == (
        None,
        None,
        None,
    )
    assert rows["arcade-execution-2"]["report_secret"] is None
    assert execution_states(admin_engine, tenant) == ["DISPATCH_COMMITTED"]
    assert [claim["released_at"] for claim in claim_rows(admin_engine, tenant)] == [None]
    assert _granted(admin_engine, tenant) == [False, True]


def _undocumented(message, body):
    """One message against `HOOK_CONTRACT`: the fields it lacks, and the ones it invents."""
    fields = HOOK_CONTRACT["messages"][message]
    return (
        sorted(set(fields["required"]) - set(body)),
        sorted(set(body) - set(fields["required"]) - set(fields["optional"])),
    )


def test_the_units_own_hook_fixtures_build_the_published_message_shapes():
    """`pre_hook` and `post_hook` send what the published contract describes, and no more.

    Nearly every row in this file drives one of those two bodies, so a field added to
    either — a key some vendor version carries, or one invented to reach a branch — would
    put this file's evidence behind a message the contract does not describe. The shapes
    are `execbound_harness.fake_arcade.HOOK_CONTRACT` because AL27's walk, the integration
    guide and a demo driver read that one object; this is what holds these fixtures to it.
    """
    for message, body in (("pre", pre_hook()), ("post", post_hook())):
        assert _undocumented(message, body) == ([], []), message
        assert _undocumented("tool", body["tool"]) == ([], []), message
        assert _undocumented("context", body["context"]) == ([], []), message


def test_the_hook_body_rule_is_the_monitoring_intakes_and_the_agent_discipline_holds(
    db, arcade_world, seeded, admin_engine
):
    """What frames a hook, and what the same `checked_request` the agent routes use refuses.

    A platform ExecBound does not control sends the charset parameter, which
    `surfaces/http.read_body` refuses and Arcade never retries, so the hook routes take the
    monitoring intake's rule instead: `application/json` and
    `application/json; charset=utf-8`, case-insensitively, and nothing else. Everything
    above the body is the agent contract's own — no query parameters, none of the four
    identity headers, no content encoding and no duplicated framing header — and each of
    those is a 400 the deployment boundary turns into a hook answer.
    """
    world, tenant = arcade_world, arcade_world["identity"].tenant_id
    for device in ("device-11", "device-12"):
        governed_target(admin_engine, world, device)
    bearer = {"Authorization": "Bearer " + seeded["tokens"][0]}
    with arcade_client(db, world, seeded) as driver:
        charset = pre(
            driver,
            headers={"Content-Type": "application/json; charset=utf-8"},
            inputs={"device_id": "device-11"},
        )
        cased = pre(
            driver,
            headers={"Content-Type": "Application/JSON"},
            execution_id="arcade-execution-2",
            inputs={"device_id": "device-12"},
        )
        refused = {
            "content_type": pre(driver, headers={"Content-Type": "text/plain"}),
            "content_encoding": pre(driver, headers={"Content-Encoding": "gzip"}),
            "identity_header": pre(driver, headers={"X-Tenant-Id": str(uuid4())}),
            "oversized": pre(driver, body=json.dumps(pre_hook(inputs={"device_id": "x" * 20000}))),
            "query": driver.client.post(
                "/pre?tenant=other",
                content=json.dumps(pre_hook()),
                headers={**bearer, "Content-Type": "application/json"},
            ),
            "duplicate_type": driver.client.post(
                "/pre",
                content=json.dumps(pre_hook()),
                headers=[
                    ("Authorization", "Bearer " + seeded["tokens"][0]),
                    ("Content-Type", "application/json"),
                    ("Content-Type", "application/json"),
                ],
            ),
        }
    assert charset.json() == {"code": "OK"}
    assert cased.json() == {"code": "OK"}
    for name, answer in refused.items():
        assert answer.status_code == 400, name
        assert "code" not in answer.json(), name
    assert execution_states(admin_engine, tenant) == ["DISPATCH_COMMITTED"] * 2
    # Each of them is audited, as the agent route audits a request it refuses on the frame.
    kinds = [kind for kind, _ in audit_kinds(admin_engine, tenant)]
    assert kinds.count("execution.rejected") == len(refused)


def test_a_non_agent_bearer_is_refused_and_audited_and_an_unknown_one_reaches_no_hook(
    db, arcade_world, seeded, admin_engine
):
    """The credential boundary is the agent routes', unchanged: this route adds nothing."""
    world, tenant = arcade_world, arcade_world["identity"].tenant_id
    with admin_engine.begin() as conn:
        admin_token = provision_credential(
            conn, tenant, world["admin"].principal_id, world["clock"].now(), timedelta(hours=2)
        )
    before = [kind for kind, _ in audit_kinds(admin_engine, tenant)]
    with arcade_client(db, world, seeded) as driver:
        forbidden = pre(driver, token=admin_token)
        unknown = pre(driver, token=f"eb1.{uuid4()}.{uuid4()}.nonsense")
        missing = driver.client.post(
            "/pre", content=json.dumps(pre_hook()), headers={"Content-Type": "application/json"}
        )
    assert (forbidden.status_code, unknown.status_code, missing.status_code) == (403, 401, 401)
    assert [kind for kind, _ in audit_kinds(admin_engine, tenant)] == [
        *before,
        "execution.rejected",
    ]
    assert execution_states(admin_engine, tenant) == []


def test_a_body_that_is_not_a_hook_and_an_id_the_kernel_cannot_key_on_are_refusals(
    db, arcade_world, seeded, admin_engine
):
    """The decision table's refusals: a malformed hook and anything unrecognized fail closed.

    Arcade's execution id becomes the idempotency key verbatim or not at all. A digest would
    make a correlation row unreadable beside Arcade's own logs at the moment an operator is
    comparing the two; folding it into the kernel's character class could make two Arcade ids
    one key. So a value outside that class is this row's refusal, and the answer names the
    rule rather than the value.
    """
    tenant = arcade_world["identity"].tenant_id
    # The last two are bodies that are otherwise complete and would decide something if the
    # parser let them through, so each fails on the rule it breaks rather than on a second
    # field it is also missing: a duplicate key would pick a target the operator never named,
    # and a nonfinite number would reach the map as an input value.
    valid = json.dumps(pre_hook(inputs={"device_id": WORLD_DEVICE, "score": 1}))
    duplicated = valid.replace(
        f'"device_id": "{WORLD_DEVICE}"', f'"device_id": "{WORLD_DEVICE}", "device_id": "device-99"'
    )
    nonfinite = valid.replace('"score": 1', '"score": NaN')
    assert duplicated != valid and nonfinite != valid
    with arcade_client(db, arcade_world, seeded) as driver:
        answers = {
            "not_json": pre(driver, body=b"{not json"),
            "not_an_object": pre(driver, body=b"[]"),
            "wrong_shape": pre(driver, body=json.dumps({"execution_id": "one"})),
            "duplicate_key": pre(driver, body=duplicated),
            "unmodelled_field": pre(driver, body=json.dumps(pre_hook(trace_id="t-1"))),
            "nonfinite": pre(driver, body=nonfinite),
        }
        unsupported = pre(driver, execution_id="arcade execution/1")
    for name, answer in answers.items():
        assert answer.json() == {"code": "CHECK_FAILED", "error_message": "INVALID_HOOK"}, name
    assert unsupported.json() == {
        "code": "CHECK_FAILED",
        "error_message": "UNSUPPORTED_EXECUTION_ID",
    }
    assert "arcade execution/1" not in unsupported.text
    assert execution_states(admin_engine, tenant) == []
    # A body the surface could not read is audited exactly as the agent route audits one.
    kinds = [kind for kind, _ in audit_kinds(admin_engine, tenant)]
    assert kinds.count("execution.rejected") == len(answers)


def test_the_access_token_is_dropped_before_anything_binds_it(
    db, arcade_world, seeded, admin_engine
):
    """`authorization[].oauth2.at` reaches no field, no answer and no retained payload.

    ExecBound holds no key that could verify an access token's claims, so they could never
    be authority, and this deployment has no reason to hold a third party's identity
    material. The key is removed from the body before the model binds anything, so the token
    is in no object this returns rather than in one nothing happens to read.
    """
    tenant = arcade_world["identity"].tenant_id
    hook = parse_pre_hook(json.dumps(pre_hook()).encode())
    assert "header.payload.signature" not in hook.model_dump_json() + repr(hook)
    assert hook.context.user_id == "analyst@example.test"
    with arcade_client(db, arcade_world, seeded) as driver:
        assert pre(driver).json() == {"code": "OK"}
    retained_payloads = json.dumps(
        [payload for _, payload in audit_kinds(admin_engine, tenant)], default=str
    )
    assert "header.payload.signature" not in retained_payloads


def test_the_error_message_is_bounded_by_the_extension_and_not_by_the_deployment(
    db, arcade_world, seeded, admin_engine
):
    """The approvals page is configuration of no declared length; the message is bounded.

    An agent's context is not the place to discover how long an operator's origin is, so the
    answer is cut to the extension's own bound and still leads with the code and the
    execution id a person needs. The continuation the runtime mints for a pending approval
    is discarded rather than passed on: what progresses an approved execution here is the
    agent's next tool call, arriving as another pre hook.
    """
    world, tenant = arcade_world, arcade_world["identity"].tenant_id
    governed_bundle(db, world, approval_policies=APPROVE_RISKY)
    page = "https://" + "a" * 400 + ".example/approvals"
    keys = TokenKeys("state-v1", {"state-v1": bytes.fromhex("21" * 32)})
    pending = Runtime(db, [], clock=world["clock"], catalog=CATALOG, approval_url=page, keys=keys)
    with arcade_client(db, world, seeded, runtime=pending) as driver:
        answer = pre(driver)
    body = answer.json()
    assert body["code"] == "CHECK_FAILED"
    assert len(body["error_message"]) == MAX_ERROR_MESSAGE
    assert body["error_message"].startswith(
        f"PENDING_APPROVAL execution={_only_execution(admin_engine, tenant)} approvals=https://aaa"
    )
    assert execution_states(admin_engine, tenant) == ["PENDING_APPROVAL"]


def _approvals(engine, tenant):
    """Every approval this tenant holds, oldest first: its id, its state and its window."""
    with engine.begin() as conn:
        scoped(conn, tenant)
        return [
            dict(row)
            for row in conn.execute(
                text(
                    "SELECT approval_id, state, expires_at FROM execbound.approvals "
                    "WHERE tenant_id=:t ORDER BY created_at, approval_id"
                ),
                {"t": tenant},
            ).mappings()
        ]


def test_al11_an_approval_retry_under_a_new_arcade_id_is_answered_the_first_grant(
    db, arcade_world, seeded, admin_engine
):
    """AL11: the pending answer, a human decision, and the retry that consumes it once.

    The sequence `docs/ARCADE.md` describes under "Approvals against a synchronous hook",
    driven as an agent would reach it: the hook is `CHECK_FAILED`
    carrying the state, the execution id and the page a human decides on, and the agent's
    retry is a *new* Arcade execution id because Arcade mints one per tool call. Admission
    adopts the pending execution by intent hash and binds the new key to it, so one
    execution holds one approval and consumes it once.

    The `OK` rule's guard never touches this path and the assertions say why rather than
    assuming it: a pending execution carries no grant, so the first hook's row holds no
    secret and has none to be refused for, and the retry is answered that execution's first
    grant — `regranted` false, a secret minted — handed to the Arcade id that asked for it.
    The first hook's row still holds none afterwards, which is what says the secret went to
    the caller that can settle the act rather than to the one that was told to wait.
    """
    world, tenant = arcade_world, arcade_world["identity"].tenant_id
    governed_bundle(db, world, approval_policies=APPROVE_RISKY)
    with arcade_client(db, world, seeded, runtime=approving_runtime(db, world)) as driver:
        pending = pre(driver)
        execution_id = UUID(str(_only_execution(admin_engine, tenant)))
        assert pending.json() == {
            "code": "CHECK_FAILED",
            "error_message": (
                f"PENDING_APPROVAL execution={execution_id} approvals={APPROVALS_PAGE}"
            ),
        }
        waiting = correlation_rows(admin_engine, tenant)["arcade-execution-1"]
        assert (waiting["decision"], waiting["execution_id"], waiting["report_secret"]) == (
            "CHECK_FAILED",
            execution_id,
            None,
        )
        [approval] = _approvals(admin_engine, tenant)
        # The synthetic contract is in this deployment's catalog and not in the
        # production one, and the review re-attests the frozen snapshot against
        # whichever it is given: a human deciding against the wrong catalog invalidates
        # the approval instead of granting it.
        decide_approval(
            db,
            world["human"],
            approval["approval_id"],
            "APPROVE",
            world["clock"],
            catalog=CATALOG,
        )
        granted = pre(driver, execution_id="arcade-execution-2")
    assert granted.json() == {"code": "OK"}
    assert execution_states(admin_engine, tenant) == ["DISPATCH_COMMITTED"]
    assert _granted(admin_engine, tenant) == [False]
    rows = correlation_rows(admin_engine, tenant)
    assert sorted(rows) == ["arcade-execution-1", "arcade-execution-2"]
    assert rows["arcade-execution-1"]["report_secret"] is None
    retry = rows["arcade-execution-2"]
    assert (retry["decision"], retry["execution_id"]) == ("OK", execution_id)
    assert (
        store.ticket_digest(retry["report_secret"])
        == grant_row(admin_engine, tenant, execution_id)["owner_hash"]
    )
    # One approval, consumed once: both Arcade ids are bound to the one execution it
    # belongs to, and the retry is what spent it.
    assert [row["state"] for row in _approvals(admin_engine, tenant)] == ["CONSUMED"]
    with db.transaction(tenant) as conn:
        assert len(store.approval_decisions(conn, tenant, approval["approval_id"])) == 1
        keys = conn.execute(
            text(
                "SELECT idempotency_key, execution_id FROM execbound.execution_keys "
                "WHERE tenant_id=:t"
            ),
            {"t": tenant},
        ).mappings()
        assert {row["idempotency_key"]: row["execution_id"] for row in keys} == {
            "arcade-execution-1": execution_id,
            "arcade-execution-2": execution_id,
        }
    [impact] = impact_rows(admin_engine, tenant)
    assert impact["state"] == "UNRESOLVED"


def test_al11_an_approval_that_expires_leaves_the_next_attempt_a_new_decision(
    db, arcade_world, seeded, admin_engine
):
    """AL11's second walk: the deadline passes first, which is what `docs/ARCADE.md` expects.

    The default approval deadline gives a human 120 seconds, and the only thing telling the
    agent to try again is a string in its context, so `docs/ARCADE.md` records that most
    approvals on this path will expire rather than describing a flow that works on paper.
    This walk is that one. The retry inside a window nobody decided in reaches
    `STALE_AUTHORIZATION`, and because intent adoption covers only the unresolved states,
    the attempt after it is a new execution, a new decision and a new approval rather than a
    second answer about the first.

    Nothing along it is charged or claimed: a pending approval reserves nothing, and neither
    does a stale one.
    """
    world, tenant = arcade_world, arcade_world["identity"].tenant_id
    governed_bundle(db, world, approval_policies=APPROVE_RISKY)
    with arcade_client(db, world, seeded, runtime=approving_runtime(db, world)) as driver:
        assert pre(driver).json()["code"] == "CHECK_FAILED"
        [approval] = _approvals(admin_engine, tenant)
        first = UUID(str(_only_execution(admin_engine, tenant)))
        world["clock"].value = approval["expires_at"]
        stale = pre(driver, execution_id="arcade-execution-2")
        again = pre(driver, execution_id="arcade-execution-3")
    assert stale.json() == {
        "code": "CHECK_FAILED",
        "error_message": f"STALE_AUTHORIZATION execution={first}",
    }
    second = UUID(str(_execution_in_state(admin_engine, tenant, "PENDING_APPROVAL")))
    assert second != first
    assert again.json() == {
        "code": "CHECK_FAILED",
        "error_message": f"PENDING_APPROVAL execution={second} approvals={APPROVALS_PAGE}",
    }
    assert sorted(execution_states(admin_engine, tenant)) == [
        "PENDING_APPROVAL",
        "STALE_AUTHORIZATION",
    ]
    states = [row["state"] for row in _approvals(admin_engine, tenant)]
    assert states == ["EXPIRED", "PENDING"]
    assert (impact_rows(admin_engine, tenant), claim_rows(admin_engine, tenant)) == ([], [])
    assert _granted(admin_engine, tenant) == []
    rows = correlation_rows(admin_engine, tenant)
    assert sorted(rows) == [f"arcade-execution-{n}" for n in (1, 2, 3)]
    assert [row["report_secret"] for row in rows.values()] == [None] * 3


def test_the_hook_surface_refuses_rather_than_queues_when_its_own_bound_is_full(
    db, arcade_world, seeded, admin_engine
):
    """The route's own capacity bound, filled by a hook the kernel is genuinely holding.

    One slot, one hook held at the tenant fence by an owner connection, and a second hook
    arriving while it is there. The refusal is the retryable code, for the reason the
    kernel's own capacity bound gets it: the deployment is full now and says so at once
    rather than queueing inside a five-second hook.

    The one slot is the deployment's own arithmetic rather than a patched constant: this
    runtime is built with a concurrency of two, and `hook_slots_for` derives one slot from
    it. Nothing here touches the application's in-flight bound, which stays at its shipped
    thirty-two, so what refused the second hook is this surface and not the application.
    """
    world, tenant = arcade_world, arcade_world["identity"].tenant_id
    narrow = Runtime(db, [], clock=world["clock"], catalog=CATALOG, concurrency=2)
    waiting = Event()

    def at_fence(conn, cursor, statement, parameters, context, executemany):
        if "tenant_policy_control" in statement and "FOR UPDATE" in statement:
            waiting.set()

    event.listen(db.engine, "before_cursor_execute", at_fence)
    try:
        with arcade_client(
            db, world, seeded, block=hook_block(deadline_seconds=1.0), runtime=narrow
        ) as driver:
            with ThreadPoolExecutor(max_workers=1) as pool:
                with _hold_the_fence(admin_engine, tenant):
                    held = pool.submit(pre, driver)
                    assert waiting.wait(5)
                    refused = pre(driver, execution_id="arcade-execution-2")
                    assert held.result(timeout=10).json()["code"] == "CHECK_FAILED"
                _wait_for_commit(admin_engine, tenant)
    finally:
        event.remove(db.engine, "before_cursor_execute", at_fence)
    assert refused.json() == {"code": "RATE_LIMIT_EXCEEDED", "error_message": "HOOK_CAPACITY"}


def test_the_hook_surface_is_absent_unless_a_deployment_configured_it(db, arcade_world, seeded):
    """No block, no routes; a block with no runtime is a deployment the surface refuses.

    The deployment boundary's tests pin both answers exactly; what is asserted here is
    that the block is what adds the surface, and that a file declaring hooks for a process
    holding no runtime is refused when the application is built rather than at the first
    hook.
    """
    app = create_app(db, runtime=Runtime(db, [], clock=arcade_world["clock"], catalog=CATALOG))
    with TestClient(app) as client:
        answer = client.post(
            "/pre",
            content=json.dumps(pre_hook()),
            headers={
                "Authorization": "Bearer " + seeded["tokens"][0],
                "Content-Type": "application/json",
            },
        )
    assert answer.status_code == 404
    with pytest.raises(ValueError, match="^Arcade hooks require a runtime$"):
        create_app(db, arcade=hook_block())


def test_a_body_that_does_not_arrive_in_time_is_refused_like_one_that_is_too_large(
    db, arcade_world, seeded, admin_engine, monkeypatch
):
    """The read is bounded in time as well as in bytes; a hook slot is held while it runs.

    Driven by shortening the bound rather than by stalling a sender: the test client feeds
    the body through the same event loop the route runs in, so a sender that slept would
    stop the loop instead of exercising the deadline.
    """
    tenant = arcade_world["identity"].tenant_id
    monkeypatch.setattr(routes, "READ_SECONDS", 0)
    with arcade_client(db, arcade_world, seeded) as driver:
        answer = pre(driver)
    assert answer.status_code == 400
    assert "code" not in answer.json()
    assert execution_states(admin_engine, tenant) == []


# ---------------------------------------------------------------------------------------
# The post hook. The five-row settlement table in `docs/ARCADE.md`, the body bound, the
# silence rules and the two contradictions, over the same HTTP surface the pre hook is
# driven on and against real PostgreSQL. What the fifth row of the table needs is no post
# hook at all, which this route cannot produce and AL20 asserts through the sweep.

CONTRADICTION = "execution.control_point_contradiction"


def _correlated_execution(admin_engine, tenant, arcade_id):
    """The ExecBound execution this Arcade execution id's own correlation row names."""
    return correlation_rows(admin_engine, tenant)[arcade_id]["execution_id"]


def _granted_hook(driver, admin_engine, tenant, arcade_id, device=WORLD_DEVICE):
    """One governed pre hook answered `OK`, and the execution its correlation row names."""
    answer = pre(driver, execution_id=arcade_id, inputs={"device_id": device})
    assert answer.json() == {"code": "OK"}, answer.text
    return _correlated_execution(admin_engine, tenant, arcade_id)


def _plan_hash(admin_engine, tenant, execution_id):
    """The plan hash this execution froze, which a contradiction names and nothing else."""
    with admin_engine.begin() as conn:
        scoped(conn, tenant)
        return conn.execute(
            text(
                "SELECT plan_hash FROM execbound.executions WHERE tenant_id=:t AND execution_id=:e"
            ),
            {"t": tenant, "e": execution_id},
        ).scalar_one()


def _contradictions(admin_engine, tenant):
    """Every contradiction this tenant's chain holds, oldest first."""
    return [payload for kind, payload in audit_kinds(admin_engine, tenant) if kind == CONTRADICTION]


def _outstanding(db, world):
    with db.transaction(world["identity"].tenant_id) as conn:
        return store.outstanding_grants(
            conn, world["identity"].tenant_id, world["identity"].principal_id
        )


def test_al12_a_reported_success_settles_at_the_asserted_tier_and_frees_nothing(
    db, arcade_world, seeded, admin_engine
):
    """AL12: `success: true` closes the row, confirms the charge and releases no target.

    Every settlement a post hook can produce is at tier `ASSERTED`, because the body is the
    platform's, on a channel ExecBound did not shape, with no signature anywhere in it. So
    the claim is untouched here and is released by the scheduled run once the act window
    has passed, exactly as a reported failure's is.

    The second walk is `success: true` beside an `execution_error`, which is a platform
    message inconsistent with itself rather than a signal about the deployment: it decides
    its row as the table says, appends no audit event of its own, changes no settlement
    and, under this design, changes nothing about what the tenant is charged either,
    because both readings of that body confirm the same impact.
    """
    world, tenant = arcade_world, arcade_world["identity"].tenant_id
    governed_target(admin_engine, world, "device-21")
    with arcade_client(db, world, seeded) as driver:
        plain = _granted_hook(driver, admin_engine, tenant, "arcade-execution-1")
        odd = _granted_hook(driver, admin_engine, tenant, "arcade-execution-2", "device-21")
        answers = [
            post(driver, success=True),
            post(
                driver,
                execution_id="arcade-execution-2",
                success=True,
                execution_code="TOOL_ERROR",
                execution_error="the vendor answered 500",
            ),
        ]
    assert [(a.status_code, a.json()) for a in answers] == [(200, {"code": "OK"})] * 2
    for execution_id in (plain, odd):
        row = retained(admin_engine, tenant, execution_id)
        assert (row.state, row.tier, row.impact) == ("EXECUTED", "ASSERTED", "CONFIRMED")
        assert row.confirmed_at == world["clock"].now()
        assert row.released_at is None
        assert (row.result["outcome"], row.result["reason"], row.result["tier"]) == (
            "EXECUTED",
            "EXECUTED",
            "ASSERTED",
        )
    rows = correlation_rows(admin_engine, tenant)
    # The settled rows hold no secret: nothing can present either of them again, and the
    # one credential this extension keeps at rest is gone the moment it stops being usable.
    assert [row["report_secret"] for row in rows.values()] == [None, None]
    assert [row["settled_at"] for row in rows.values()] == [world["clock"].now()] * 2
    assert rows["arcade-execution-1"]["reported_success"] is True
    assert rows["arcade-execution-1"]["reported_code"] is None
    assert (
        rows["arcade-execution-2"]["reported_code"],
        rows["arcade-execution-2"]["reported_error"],
    ) == (
        "TOOL_ERROR",
        "the vendor answered 500",
    )
    assert _contradictions(admin_engine, tenant) == []


def test_al13_a_reported_failure_settles_terminally_and_drains_the_cap(
    db, arcade_world, seeded, admin_engine
):
    """AL13: `success: false` costs a caller exactly what `success: true` costs.

    The same confirmed impact with its confirmation time stamped, the same claim held to
    the act window, and a row closed to everything but a restatement — so there is nothing
    to be gained by choosing one over the other and nothing to lie about. What it buys the
    tenant is the thing the earlier mapping to `UNKNOWN` denied: the row settles, so the
    cap of eight drains and the intent stops being adopted.

    The second walk is the same statement against a row that is already `INDETERMINATE`,
    which is where an absent `success` and the sweep both put a grant. A settlement out of
    retained uncertainty is the exit that state otherwise has only through an
    administrator's signed record.
    """
    world, tenant = arcade_world, arcade_world["identity"].tenant_id
    governed_target(admin_engine, world, "device-22")
    with arcade_client(db, world, seeded) as driver:
        committed = _granted_hook(driver, admin_engine, tenant, "arcade-execution-1")
        uncertain = _granted_hook(driver, admin_engine, tenant, "arcade-execution-2", "device-22")
        assert _outstanding(db, world) == 2
        silent = post(driver, execution_id="arcade-execution-2")
        assert retained(admin_engine, tenant, uncertain).state == "INDETERMINATE"
        answers = [
            post(driver, success=False, execution_code="VENDOR_TIMEOUT"),
            post(driver, execution_id="arcade-execution-2", success=False),
        ]
        assert _outstanding(db, world) == 0
        # The adoption query covers the unresolved states alone, so the same intent under a
        # new Arcade id is a fresh decision rather than the settled execution again.
        again = pre(driver, execution_id="arcade-execution-3")
    assert silent.json() == {"code": "OK"}
    assert [(a.status_code, a.json()) for a in answers] == [(200, {"code": "OK"})] * 2
    for execution_id in (committed, uncertain):
        row = retained(admin_engine, tenant, execution_id)
        assert (row.state, row.tier, row.impact) == (
            "FAILED_EFFECT_UNKNOWN",
            "ASSERTED",
            "CONFIRMED",
        )
        assert row.confirmed_at == world["clock"].now()
        assert row.released_at is None
        assert (row.result["outcome"], row.result["reason"]) == (
            "FAILED_EFFECT_UNKNOWN",
            "REPORTED_FAILURE",
        )
    assert transitions(admin_engine, tenant, committed)[-1] == (
        "DISPATCH_COMMITTED",
        "FAILED_EFFECT_UNKNOWN",
        "ASSERTED",
    )
    assert transitions(admin_engine, tenant, uncertain)[-2:] == [
        ("DISPATCH_COMMITTED", "INDETERMINATE", None),
        ("INDETERMINATE", "FAILED_EFFECT_UNKNOWN", "ASSERTED"),
    ]
    stated = [
        payload
        for kind, payload in audit_kinds(admin_engine, tenant)
        if kind == "execution.transition" and payload["to_state"] == "FAILED_EFFECT_UNKNOWN"
    ]
    assert [payload["asserted"]["reason"] for payload in stated] == ["REPORTED_FAILURE"] * 2
    assert [payload["tier"] for payload in stated] == ["ASSERTED"] * 2
    assert [payload["asserted"]["outcome"] for payload in stated] == ["FAILED_EFFECT_UNKNOWN"] * 2
    rows = correlation_rows(admin_engine, tenant)
    assert rows["arcade-execution-1"]["reported_code"] == "VENDOR_TIMEOUT"
    assert [
        rows[key]["reported_success"] for key in ("arcade-execution-1", "arcade-execution-2")
    ] == [
        False,
        False,
    ]
    assert [rows[key]["report_secret"] for key in ("arcade-execution-1", "arcade-execution-2")] == [
        None,
        None,
    ]
    # A fresh decision rather than an adoption: a second execution row for the same intent,
    # refused because the settled row's canonical claim still stands.
    assert again.json()["code"] == "CHECK_FAILED"
    assert rows["arcade-execution-3"]["execution_id"] not in (committed, uncertain)


def test_al14_silence_settles_nothing_and_is_never_a_refusal(
    db, arcade_world, seeded, admin_engine
):
    """AL14: a post hook that states no result leaves what no post hook leaves.

    Three bodies, one rule. An absent `success` is **silence**: the field is optional in the
    published schema, so its absence is not a quiet failure and not a quiet success, and
    settling on it would write "the control point reported failure" into a tamper-evident
    history when the control point reported nothing. It is reported `UNKNOWN`, which is the
    post hook table's own third row: the row reaches retained uncertainty, which is exactly
    where the sweep puts a grant nobody reports on at all, with the impact charged, the
    claim held and the administrator exit as the way out.

    The other two are bodies ExecBound could not read, and they leave the row untouched
    because nothing was read. Neither is a 4xx: a refusal is never retried, it settles
    nothing, and it tells the agent its tool call failed when it did not.

    `output` is validated for nothing and dropped before anything else happens. The marker
    the oversized body carries is in no audit payload, no correlation row and no log line,
    and the row it was sent against still holds the secret that could settle it.
    """
    world, tenant = arcade_world, arcade_world["identity"].tenant_id
    for device in ("device-23", "device-24"):
        governed_target(admin_engine, world, device)
    block = hook_block(post_bytes=1024)
    with _captured_log() as log, arcade_client(db, world, seeded, block=block) as driver:
        quiet = _granted_hook(driver, admin_engine, tenant, "arcade-execution-1")
        large = _granted_hook(driver, admin_engine, tenant, "arcade-execution-2", "device-23")
        broken = _granted_hook(driver, admin_engine, tenant, "arcade-execution-3", "device-24")
        oversized = json.dumps(
            post_hook(
                execution_id="arcade-execution-2",
                success=True,
                output={"value": "vendor-output-marker" * 200},
            )
        )
        assert len(oversized) > block.post_bytes
        answers = {
            "absent_success": post(driver),
            "oversized": post(driver, body=oversized),
            "unparseable": post(driver, body=b"{not json"),
        }
    for name, answer in answers.items():
        assert (answer.status_code, answer.json()) == (200, {"code": "OK"}), name
    rows = correlation_rows(admin_engine, tenant)
    for arcade_id, execution_id in (
        ("arcade-execution-1", quiet),
        ("arcade-execution-2", large),
        ("arcade-execution-3", broken),
    ):
        row = retained(admin_engine, tenant, execution_id)
        assert (row.tier, row.impact, row.result) == (None, "UNRESOLVED", None)
        assert row.released_at is None
        assert rows[arcade_id]["settled_at"] is None
        # The secret is still there: none of the three settled, so each row is still
        # settleable by the delivery that finally states a result.
        assert rows[arcade_id]["report_secret"] is not None
    # The two unreadable bodies left their rows exactly where they found them; the absent
    # `success` moved its row to the retained uncertainty the table's third row names.
    assert retained(admin_engine, tenant, quiet).state == "INDETERMINATE"
    assert retained(admin_engine, tenant, large).state == "DISPATCH_COMMITTED"
    assert retained(admin_engine, tenant, broken).state == "DISPATCH_COMMITTED"
    payloads = json.dumps(
        [payload for _, payload in audit_kinds(admin_engine, tenant)], default=str
    )
    assert "vendor-output-marker" not in payloads
    assert "vendor-output-marker" not in json.dumps(rows, default=str)
    assert "vendor-output-marker" not in log.getvalue()
    # Each unreadable body is recorded as bounded as every refused request in the kernel is.
    kinds = [kind for kind, _ in audit_kinds(admin_engine, tenant)]
    assert kinds.count("execution.rejected") == 2


def test_the_post_hook_reads_under_its_own_bound_and_not_the_agent_routes(
    db, arcade_world, seeded, admin_engine
):
    """`post_bytes`, not `MAX_REQUEST_BYTES`: a large post hook must still settle.

    `read_body` refuses past 16 KiB and a 4xx is never retried, so under that bound an
    ordinary post hook carrying a tool's output would be refused and its execution would
    never settle — a second, quieter wedge behind the first. The same body decides its row
    under the deployment's own bound and is silence under a bound it exceeds, which is what
    says the configured number is the one that governs rather than a constant.
    """
    world, tenant = arcade_world, arcade_world["identity"].tenant_id
    governed_target(admin_engine, world, "device-25")
    body = json.dumps(post_hook(success=True, output={"value": "x" * 64 * 1024}))
    assert len(body) > 16 * 1024
    with arcade_client(db, world, seeded) as driver:
        generous = _granted_hook(driver, admin_engine, tenant, "arcade-execution-1")
        assert post(driver, body=body).json() == {"code": "OK"}
    assert retained(admin_engine, tenant, generous).state == "EXECUTED"
    with arcade_client(db, world, seeded, block=hook_block(post_bytes=1024)) as driver:
        tight = _granted_hook(driver, admin_engine, tenant, "arcade-execution-2", "device-25")
        assert post(
            driver, body=json.dumps(post_hook(execution_id="arcade-execution-2", success=True))
        ).json() == {"code": "OK"}
        assert retained(admin_engine, tenant, tight).state == "EXECUTED"
        refused = post(driver, body=body.replace("arcade-execution-1", "arcade-execution-9"))
    assert refused.json() == {"code": "OK"}
    assert execution_states(admin_engine, tenant).count("EXECUTED") == 2


def test_al15_the_post_hooks_frame_is_the_monitoring_intakes(
    db, arcade_world, seeded, admin_engine
):
    """AL15: the charset parameter is accepted and the agent contract's framing holds.

    A platform ExecBound does not control sends `application/json; charset=utf-8`, which
    `read_body` refuses and Arcade never retries, so a settlement would never arrive. The
    three accepted spellings settle identically; a duplicated `content-type` and a
    `content-encoding` are refused exactly as the monitoring intake refuses them, which is
    `checked_request`'s own rule and not a second one.
    """
    world, tenant = arcade_world, arcade_world["identity"].tenant_id
    for device in ("device-26", "device-27", "device-28"):
        governed_target(admin_engine, world, device)
    settled = {}
    with arcade_client(db, world, seeded) as driver:
        for index, (header, device) in enumerate(
            (
                ("application/json; charset=utf-8", "device-26"),
                ("application/json", "device-27"),
                ("Application/JSON", "device-28"),
            ),
            start=1,
        ):
            arcade_id = f"arcade-execution-{index}"
            execution_id = _granted_hook(driver, admin_engine, tenant, arcade_id, device)
            settled[header] = (
                post(
                    driver,
                    execution_id=arcade_id,
                    success=True,
                    headers={"Content-Type": header},
                ),
                execution_id,
            )
        refused = {
            "content_encoding": post(driver, success=True, headers={"Content-Encoding": "gzip"}),
            "duplicate_type": driver.client.post(
                "/post",
                content=json.dumps(post_hook(success=True)),
                headers=[
                    ("Authorization", "Bearer " + driver.token),
                    ("Content-Type", "application/json"),
                    ("Content-Type", "application/json"),
                ],
            ),
        }
    for header, (answer, execution_id) in settled.items():
        assert (answer.status_code, answer.json()) == (200, {"code": "OK"}), header
        row = retained(admin_engine, tenant, execution_id)
        assert (row.state, row.tier, row.impact) == ("EXECUTED", "ASSERTED", "CONFIRMED"), header
    for name, answer in refused.items():
        assert answer.status_code == 400, name
        assert "code" not in answer.json(), name


def test_al16_a_report_moves_a_row_once_and_an_orphan_is_recorded_bounded(
    db, arcade_world, seeded, admin_engine
):
    """AL16's first three arrivals: two that move nothing, and one that names no row.

    A report is captured and applied exactly when it changes the execution, so a redelivery
    of one that settled is answered with the settled view having appended and retained
    nothing, and a second `UNKNOWN` against an `INDETERMINATE` row is the same no-op. That
    is what bounds a leaked report secret to a repeat of an answer rather than to volume.

    The orphan is the post hook that overtook its own pre hook, which nothing in the
    published contract forbids. It names no correlation row, so it settles nothing, is
    recorded as bounded as every refused request in the kernel is, and the pre hook that
    follows it decides normally — because nothing here opened a row for that pre hook to
    adopt, tool identity and all.
    """
    world, tenant = arcade_world, arcade_world["identity"].tenant_id
    governed_target(admin_engine, world, "device-29")
    with arcade_client(db, world, seeded) as driver:
        settled = _granted_hook(driver, admin_engine, tenant, "arcade-execution-1")
        uncertain = _granted_hook(driver, admin_engine, tenant, "arcade-execution-2", "device-29")
        assert post(driver, success=True).json() == {"code": "OK"}
        assert post(driver, execution_id="arcade-execution-2").json() == {"code": "OK"}
        head = audit_head(admin_engine, tenant)
        repeats = [
            post(driver, success=True),
            post(driver, execution_id="arcade-execution-2"),
        ]
        assert audit_head(admin_engine, tenant) == head
        # A later delivery contradicting the one that settled. It reaches no kernel at
        # all — the settled row's secret is gone — and the correlation row keeps the
        # statement the chain holds rather than the last one sent, so what an operator
        # reads beside the settled row is what settled it.
        contradicting = post(driver, success=False, execution_code="LATE")
        orphan = post(driver, execution_id="arcade-execution-3", success=True)
        after = pre(driver, execution_id="arcade-execution-3", inputs={"device_id": "device-29"})
    assert [answer.json() for answer in repeats] == [{"code": "OK"}] * 2
    assert contradicting.json() == {"code": "OK"}
    assert (orphan.status_code, orphan.json()) == (200, {"code": "OK"})
    assert retained(admin_engine, tenant, settled).state == "EXECUTED"
    assert retained(admin_engine, tenant, uncertain).state == "INDETERMINATE"
    # The orphan wrote no correlation row of its own, so the pre hook that followed opened
    # the row and was answered on the kernel's decision: the target is claimed by the
    # execution above, so this one is refused, and what refuses it is the kernel.
    rows = correlation_rows(admin_engine, tenant)
    assert rows["arcade-execution-1"]["reported_success"] is True
    assert rows["arcade-execution-1"]["reported_code"] is None
    assert rows["arcade-execution-3"]["decision"] == "CHECK_FAILED"
    assert rows["arcade-execution-3"]["reported_success"] is None
    assert after.json()["code"] == "CHECK_FAILED"
    kinds = [kind for kind, _ in audit_kinds(admin_engine, tenant)]
    # One, for the orphan: the two repeats and the contradicting delivery each cost the
    # tenant nothing in its chain.
    assert kinds.count("execution.rejected") == 1
    assert _contradictions(admin_engine, tenant) == []


def test_al16_a_denied_call_that_ran_anyway_appends_one_contradiction(
    db, arcade_world, seeded, admin_engine
):
    """AL16's fourth arrival: the pre hook said `CHECK_FAILED` and the tool ran anyway.

    That is either a fail-open configuration or a bypass, and it is the one row of the
    checkpoint guide's "cannot be prevented" table this placement gets to see without
    monitoring the vendor's own side. It is evidence of a configuration problem and never a
    proven bypass, and the rule that turns it into a finding belongs to the monitoring
    track.

    It reaches the tenant's hash chain rather than the correlation row alone, because the
    correlation row is not an audit event: it is not hash-chained, it does not export and it
    does not replay, so leaving the only instrument for noticing a bypass there would have
    made it the weakest thing in the design. The volume is bounded the way settlement is:
    the event is appended exactly when it moves the row from no contradiction recorded to
    one recorded, so the second delivery of the same hook appends nothing.
    """
    world, tenant = arcade_world, arcade_world["identity"].tenant_id
    _al5_case("denial", db, world, None, admin_engine)
    with arcade_client(db, world, seeded) as driver:
        denied = pre(driver)
        assert denied.json()["code"] == "CHECK_FAILED"
        first = post(driver, success=True)
        second = post(driver, success=True)
    assert [answer.json() for answer in (first, second)] == [{"code": "OK"}] * 2
    execution_id = _execution_in_state(admin_engine, tenant, "DENIED")
    [recorded] = _contradictions(admin_engine, tenant)
    assert recorded["contradiction"] == "DENIED_CALL"
    assert recorded["execution_id"] == str(execution_id)
    assert (recorded["toolkit"], recorded["tool_name"], recorded["tool_version"]) == (
        GOVERNED_TOOL["toolkit"],
        GOVERNED_TOOL["name"],
        GOVERNED_TOOL["version"],
    )
    assert "inputs" not in json.dumps(recorded)
    [row] = correlation_rows(admin_engine, tenant).values()
    assert row["denial_contradiction_at"] == world["clock"].now()
    assert row["inputs_contradiction_at"] is None
    # Nothing was settled: a denial holds no grant, so the row carries no secret and the
    # platform's word reaches no execution.
    assert (row["report_secret"], row["settled_at"]) == (None, None)
    assert execution_states(admin_engine, tenant) == ["DENIED"]
    assert row["reported_success"] is True


def test_al17_inputs_that_differ_from_the_frozen_request_append_one_contradiction(
    db, arcade_world, seeded, admin_engine
):
    """AL17: `inputs` is optional, so its absence establishes nothing and claims nothing.

    Its presence and difference establishes that what executed is not what was decided. The
    pre hook's own `inputs` are deliberately not retained — what the decision was taken on
    is the frozen plan — so the comparison re-derives the selection through the same
    declaration and holds it against the frozen `ActionRequest`. Neither the difference nor
    the absence changes what the report settles: the statement is the platform's and the
    contradiction is a record beside it.

    The export clause is why the kind joins `_INFORMATIONAL` in the same change. An event
    kind that set does not name makes the tenant's export `UNSUPPORTED` with
    `UNKNOWN_EVENT_SEMANTICS`, permanently, because audit events are append-only — so a
    tenant holding both kinds would have had a bypass record turn into a broken history.
    """
    from execbound.replay.export import export_history
    from execbound.replay.simulate import simulate
    from execbound.replay.verify import verify_export

    world, tenant = arcade_world, arcade_world["identity"].tenant_id
    world["admin"] = long_lived_admin(admin_engine, db, world)
    governed_target(admin_engine, world, "device-31")
    with arcade_client(db, world, seeded) as driver:
        differing = _granted_hook(driver, admin_engine, tenant, "arcade-execution-1")
        # A second Arcade id for the same intent is adopted and answered `CHECK_FAILED`,
        # because its own row holds no secret; its post hook is therefore the denial case.
        assert pre(driver, execution_id="arcade-execution-2").json()["code"] == "CHECK_FAILED"
        same = post(driver, inputs={"device_id": WORLD_DEVICE}, success=True)
        assert same.json() == {"code": "OK"}
        assert _contradictions(admin_engine, tenant) == []
        matching = _granted_hook(driver, admin_engine, tenant, "arcade-execution-3", "device-31")
        answers = {
            "differs": post(
                driver,
                execution_id="arcade-execution-3",
                inputs={"device_id": "device-31-elsewhere"},
                success=True,
            ),
            "denied": post(driver, execution_id="arcade-execution-2", success=True),
        }
    assert [answer.json() for answer in answers.values()] == [{"code": "OK"}] * 2
    # The difference changed no settlement: the row settled on the statement, at the tier
    # and with the impact any reported success leaves.
    for execution_id in (differing, matching):
        row = retained(admin_engine, tenant, execution_id)
        assert (row.state, row.tier, row.impact) == ("EXECUTED", "ASSERTED", "CONFIRMED")
    recorded = _contradictions(admin_engine, tenant)
    assert [item["contradiction"] for item in recorded] == ["INPUTS_DIFFER", "DENIED_CALL"]
    assert recorded[0]["execution_id"] == str(matching)
    assert recorded[0]["plan_hash"] == _plan_hash(admin_engine, tenant, matching)
    assert "device-31-elsewhere" not in json.dumps(recorded)
    rows = correlation_rows(admin_engine, tenant)
    assert rows["arcade-execution-3"]["inputs_contradiction_at"] == world["clock"].now()
    assert rows["arcade-execution-1"]["inputs_contradiction_at"] is None
    history = export_history(db, world["admin"], world["clock"])
    verified = verify_export(history, history.head)
    assert "UNKNOWN_EVENT_SEMANTICS" not in verified.issues
    assert verified.complete, verified.issues
    # Replayed against the catalog this world's contract is released in, which is what
    # the recomputation needs; what the kind had to earn is the line above it.
    replayed = simulate(verified, catalog=CATALOG)
    assert replayed.complete, replayed.issues
    assert {CONTRADICTION} <= {event.event.kind for event in verified.events}


def test_al22_an_observing_tenants_post_hook_is_recorded_and_settles_nothing(
    db, arcade_world, seeded, admin_engine
):
    """AL22: observe-only records what ExecBound would decide while the action proceeds.

    The pre hook is `OK` because permitting is what that mode means, and the row it leaves
    is `OBSERVED`, which is terminal and carries no grant: nothing was reserved, nothing was
    claimed and no secret was minted. So there is nothing for the post hook to settle, and
    what it does instead is what every arrival with no grant behind it does — it is recorded
    on the correlation row and answered `OK`.
    """
    world, tenant = arcade_world, arcade_world["identity"].tenant_id
    set_enforcement_mode(db, world["admin"], "OBSERVE", "Onboarding", world["clock"])
    with arcade_client(db, world, seeded) as driver:
        assert pre(driver).json() == {"code": "OK"}
        answer = post(driver, success=True, execution_code="TOOL_OK")
    assert (answer.status_code, answer.json()) == (200, {"code": "OK"})
    assert execution_states(admin_engine, tenant) == ["OBSERVED"]
    assert claim_rows(admin_engine, tenant) == []
    assert [row["state"] for row in impact_rows(admin_engine, tenant)] == ["OBSERVED"]
    [row] = correlation_rows(admin_engine, tenant).values()
    assert (row["decision"], row["report_secret"], row["settled_at"]) == ("OK", None, None)
    assert (row["reported_success"], row["reported_code"]) == (True, "TOOL_OK")
    assert _contradictions(admin_engine, tenant) == []
    assert "execution.outcome_reported" not in [
        kind for kind, _ in audit_kinds(admin_engine, tenant)
    ]


def test_al23_the_credential_boundary_on_the_post_hook_is_the_agent_routes(
    db, arcade_world, seeded, admin_engine
):
    """AL23: who may report, and what a credential that outlives nothing can reach.

    The post route adds nothing to `checked_request`: a non-AGENT principal is refused and
    audited, an unknown, expired or revoked bearer is refused as unauthenticated and counted
    by the authentication-failure record, and none of them reaches a hook decision — no
    correlation row is read and nothing is settled.

    The last clause is the report window's. `report_expires_at` is `min(now + REPORT_WINDOW,
    the credential's own expiry)`, so a credential that expires first shortens the window it
    could report in, and the post hook that arrives afterwards is refused on identity before
    the deadline is ever consulted.
    """
    world, tenant = arcade_world, arcade_world["identity"].tenant_id
    now = world["clock"].now()
    governed_target(admin_engine, world, "device-32")
    with admin_engine.begin() as conn:
        admin_token = provision_credential(
            conn, tenant, world["admin"].principal_id, now, timedelta(hours=2)
        )
        approver_token = provision_credential(
            conn, tenant, world["human"].principal_id, now, timedelta(hours=2)
        )
        expired_token = provision_credential(
            conn,
            tenant,
            world["identity"].principal_id,
            now - timedelta(hours=3),
            timedelta(hours=1),
        )
        short_token = provision_credential(
            conn, tenant, world["identity"].principal_id, now, timedelta(minutes=5)
        )
        revoked_token = provision_credential(
            conn, tenant, world["identity"].principal_id, now, timedelta(hours=2)
        )
        conn.execute(
            text("UPDATE execbound.credentials SET revoked_at=:n WHERE credential_id=:c"),
            {"n": now, "c": UUID(revoked_token.split(".")[2])},
        )
    with arcade_client(db, world, seeded) as driver:
        granted = _granted_hook(driver, admin_engine, tenant, "arcade-execution-1")
        short_grant = pre(
            driver,
            token=short_token,
            execution_id="arcade-execution-2",
            inputs={"device_id": "device-32"},
        )
        refused = {
            "admin": post(driver, token=admin_token, success=True),
            "approver": post(driver, token=approver_token, success=True),
            "unknown": post(driver, token=f"eb1.{uuid4()}.{uuid4()}.nonsense", success=True),
            "expired": post(driver, token=expired_token, success=True),
            "revoked": post(driver, token=revoked_token, success=True),
            "foreign": post(driver, token=seeded["tokens"][1], success=True),
        }
        # Authentication reads the database's own clock rather than this world's, so the
        # credential is expired by moving its expiry rather than the fixture clock. What is
        # exercised is the same condition a passing minute would reach.
        with admin_engine.begin() as conn:
            conn.execute(
                text("UPDATE execbound.credentials SET expires_at=:e WHERE credential_id=:c"),
                {"e": now - timedelta(minutes=1), "c": UUID(short_token.split(".")[2])},
            )
        late = post(driver, token=short_token, execution_id="arcade-execution-2", success=True)
    assert short_grant.json() == {"code": "OK"}
    # The window this grant could be reported in is the credential's own expiry rather than
    # the full report window, because admission takes the earlier of the two.
    shortened = _correlated_execution(admin_engine, tenant, "arcade-execution-2")
    assert grant_row(admin_engine, tenant, shortened)["report_expires_at"] == now + timedelta(
        minutes=5
    )
    assert [refused[name].status_code for name in ("admin", "approver")] == [403, 403]
    assert [refused[name].status_code for name in ("unknown", "expired", "revoked")] == [401] * 3
    # The foreign bearer authenticates as its own tenant's agent and reaches only that
    # tenant's objects, so this tenant's Arcade execution id names nothing for it.
    assert (refused["foreign"].status_code, refused["foreign"].json()) == (200, {"code": "OK"})
    assert late.status_code == 401
    assert retained(admin_engine, tenant, granted).state == "DISPATCH_COMMITTED"
    rows = correlation_rows(admin_engine, tenant)
    assert rows["arcade-execution-1"]["reported_success"] is None
    assert rows["arcade-execution-1"]["settled_at"] is None
    assert _contradictions(admin_engine, tenant) == []


def test_a_post_hook_settles_only_an_execution_its_own_row_holds_the_secret_for(
    db, arcade_world, seeded, admin_engine
):
    """Correlation names the execution; the row's own secret is what may settle it.

    A second Arcade execution id for a granted intent is adopted by admission and answered
    `CHECK_FAILED`, because its row holds no secret — and that row still names the
    execution the first one opened. Its post hook therefore reaches an execution it may not
    settle, and what refuses it is the one condition the pre hook's rule already turns on
    rather than a second rule written for this route. The first Arcade id's own post hook
    settles the same execution immediately afterwards, which is what says the refusal was
    about the row and not about the execution.
    """
    world, tenant = arcade_world, arcade_world["identity"].tenant_id
    with arcade_client(db, world, seeded) as driver:
        execution_id = _granted_hook(driver, admin_engine, tenant, "arcade-execution-1")
        adopted = pre(driver, execution_id="arcade-execution-2")
        assert adopted.json()["code"] == "CHECK_FAILED"
        borrowed = post(driver, execution_id="arcade-execution-2", success=True)
        assert retained(admin_engine, tenant, execution_id).state == "DISPATCH_COMMITTED"
        settles = post(driver, success=True)
    assert [answer.json() for answer in (borrowed, settles)] == [{"code": "OK"}] * 2
    rows = correlation_rows(admin_engine, tenant)
    # Both rows name the one execution; only the one holding the secret settled it.
    assert rows["arcade-execution-2"]["execution_id"] == execution_id
    assert (
        rows["arcade-execution-2"]["report_secret"],
        rows["arcade-execution-2"]["settled_at"],
    ) == (
        None,
        None,
    )
    assert retained(admin_engine, tenant, execution_id).state == "EXECUTED"
    assert rows["arcade-execution-1"]["settled_at"] == world["clock"].now()
    kinds = [kind for kind, _ in audit_kinds(admin_engine, tenant)]
    reported = [
        payload
        for kind, payload in audit_kinds(admin_engine, tenant)
        if kind == "execution.outcome_reported"
    ]
    assert [payload["outcome"] for payload in reported] == ["EXECUTED"]
    # The kernel was never asked about the row holding no secret. A report it could only
    # refuse would cost the tenant an audited rejection for a delivery the extension can
    # see is unsettleable from the row alone.
    assert "execution.rejected" not in kinds


def test_the_post_hook_answers_ok_for_a_refusal_it_owns_and_lets_a_retryable_one_travel(
    db, arcade_world, seeded, admin_engine
):
    """The asymmetry `docs/ARCADE.md` states: an answer on the way in, an error on the way out.

    A refusal the kernel makes about this row is permanent and the platform can do nothing
    with it — the row settled already, its window closed, its secret does not authenticate —
    so withholding a result the agent is entitled to would be a guess with a cost, and the
    hook answers `OK`. A capacity refusal is neither permanent nor this row's: it means this
    deployment has not settled anything yet, and it travels as the transport-level 429 that
    exists precisely so a settlement Arcade could redeliver is redelivered.

    The refusal here is reached through the row rather than simulated: the execution is
    settled out of band by the same secret, so the correlation row still holds one and the
    post hook that follows is a report against a settled row that is not restating it.
    """
    world, tenant = arcade_world, arcade_world["identity"].tenant_id
    with arcade_client(db, world, seeded) as driver:
        execution_id = _granted_hook(driver, admin_engine, tenant, "arcade-execution-1")
        secret = correlation_rows(admin_engine, tenant)["arcade-execution-1"]["report_secret"]
        assert report(
            db, world, execution_id, secret, outcome="EXECUTED", reason="EXECUTED"
        ).state == ("EXECUTED")
        head = audit_head(admin_engine, tenant)
        refused = post(driver, success=False)
        assert audit_head(admin_engine, tenant) != head
        held = [
            driver.runtime._capacity.acquire(blocking=False)
            for _ in range(driver.runtime.concurrency)
        ]
        try:
            assert all(held)
            busy = post(driver, success=True)
        finally:
            for slot in held:
                if slot:
                    driver.runtime._capacity.release()
    assert (refused.status_code, refused.json()) == (200, {"code": "OK"})
    row = retained(admin_engine, tenant, execution_id)
    assert (row.state, row.tier, row.result["reason"]) == ("EXECUTED", "ASSERTED", "EXECUTED")
    # The kernel recorded its own refusal, as it records every refused request.
    assert [kind for kind, _ in audit_kinds(admin_engine, tenant)][-1] == "execution.rejected"
    # The application's own answer, not a hook one: a 429 carrying `detail`, which the
    # deployment boundary passes through unchanged on this route.
    assert (busy.status_code, busy.json()["detail"]) == (429, "Execution unavailable")
    limited = Runtime(
        db, [], clock=world["clock"], catalog=CATALOG, limits=RequestLimits(agent_requests=1)
    )
    with arcade_client(db, world, seeded, runtime=limited) as driver:
        assert post(driver, execution_id="arcade-execution-9", success=True).status_code == 200
        rated = post(driver, execution_id="arcade-execution-9", success=True)
    assert (rated.status_code, rated.json()["detail"]) == (429, "Execution unavailable")


def test_the_report_secret_is_cleared_once_the_window_it_could_be_used_in_has_closed(
    db, arcade_world, seeded, admin_engine
):
    """The post hook's opportunistic clearing, and the residual it deliberately leaves.

    `_reportable` refuses a report past `report_expires_at`, so a secret a correlation row
    still holds after that instant settles nothing and is only a credential at rest. The
    extension clears it from any such row it reads, which is this post hook. What that does
    not reach is a row nobody reads again, which is limitation 8 and is documented rather
    than swept.

    The window is shortened by taking the grant on a credential that expires before the
    full one would, and the fixture clock is then moved past it. Authentication reads the
    database's own clock, so the credential still authenticates while the window the
    extension measures has closed, which is the ordering this rule needs to be visible in.
    """
    world, tenant = arcade_world, arcade_world["identity"].tenant_id
    now = world["clock"].now()
    with admin_engine.begin() as conn:
        token = provision_credential(
            conn, tenant, world["identity"].principal_id, now, timedelta(minutes=5)
        )
    with arcade_client(db, world, seeded) as driver:
        assert pre(driver, token=token).json() == {"code": "OK"}
        execution_id = _correlated_execution(admin_engine, tenant, "arcade-execution-1")
        assert correlation_rows(admin_engine, tenant)["arcade-execution-1"]["report_secret"]
        world["clock"].value = now + timedelta(minutes=6)
        late = post(driver, token=token, success=True)
    assert (late.status_code, late.json()) == (200, {"code": "OK"})
    [row] = correlation_rows(admin_engine, tenant).values()
    assert (row["report_secret"], row["settled_at"]) == (None, None)
    # Nothing was settled and the kernel was never asked: the row is where the sweep and the
    # administrator exit will find it.
    assert retained(admin_engine, tenant, execution_id).state == "DISPATCH_COMMITTED"
    assert "execution.outcome_reported" not in [
        kind for kind, _ in audit_kinds(admin_engine, tenant)
    ]
    assert row["reported_success"] is True


def test_the_post_hook_refuses_rather_than_queues_when_its_own_bound_is_full(
    db, arcade_world, seeded, admin_engine
):
    """The route's own capacity bound on the settling path, and why it is not a hook answer.

    One slot, one post hook held at the tenant fence by an owner connection, and a second
    arriving while it is there. On the pre path that refusal is the retryable hook code,
    because an answer is what blocks a tool call. Here it is the transport-level 429: this
    deployment has settled nothing yet, and telling the platform `OK` would say a report
    was accepted when it was not, where a 429 is what makes Arcade redeliver it.

    The slot is derived from a runtime built with a concurrency of two, as on the pre path,
    rather than patched into the module.
    """
    world, tenant = arcade_world, arcade_world["identity"].tenant_id
    governed_target(admin_engine, world, "device-33")
    narrow = Runtime(db, [], clock=world["clock"], catalog=CATALOG, concurrency=2)
    waiting = Event()

    def at_fence(conn, cursor, statement, parameters, context, executemany):
        if "tenant_policy_control" in statement and "FOR UPDATE" in statement:
            waiting.set()

    with arcade_client(db, world, seeded, runtime=narrow) as driver:
        first = _granted_hook(driver, admin_engine, tenant, "arcade-execution-1")
        second = _granted_hook(driver, admin_engine, tenant, "arcade-execution-2", "device-33")
        event.listen(db.engine, "before_cursor_execute", at_fence)
        try:
            with ThreadPoolExecutor(max_workers=1) as pool:
                with _hold_the_fence(admin_engine, tenant):
                    held = pool.submit(post, driver, success=True)
                    assert waiting.wait(5)
                    refused = post(driver, execution_id="arcade-execution-2", success=True)
                # Released, so the held delivery takes the fence and settles: the refusal
                # above was the slot and not the kernel.
                assert held.result(timeout=10).json() == {"code": "OK"}
                _wait_for_commit(admin_engine, tenant)
        finally:
            event.remove(db.engine, "before_cursor_execute", at_fence)
    assert (refused.status_code, refused.json()["detail"]) == (429, "Execution unavailable")
    assert retained(admin_engine, tenant, first).state == "EXECUTED"
    # The refused delivery settled nothing and is Arcade's to redeliver.
    assert retained(admin_engine, tenant, second).state == "DISPATCH_COMMITTED"


def test_a_contradiction_is_bounded_by_two_guards_and_each_is_asserted_on_its_own(
    db, arcade_world, seeded, admin_engine, monkeypatch
):
    """One contradiction per row per kind, held by two refusals that are not spare.

    They are redundant by construction, and either alone would keep the count at one — so a
    walk that only delivered twice would pass over the removal of either, which is the
    coverage failure this project's mutation standard exists to catch. Each is exercised
    here while the other holds.

    The route's filter is a bound on **work**: a redelivery whose contradiction is already
    recorded takes no tenant fence at all, and the fence is the per-tenant serializing
    structure every admission and settlement queues behind. The store's own re-check is the
    bound on **appends**, decided under that fence beside the mark it writes, so two
    deliveries racing are ordered rather than both admitted. Neither can do the other's job:
    the filter reads a row it does not hold a lock on, and the re-check has already paid for
    the fence by the time it answers.
    """
    world, tenant = arcade_world, arcade_world["identity"].tenant_id
    calls = []
    marked = arcade_store.contradiction

    def counted(*args, **kwargs):
        calls.append(args[3])
        return marked(*args, **kwargs)

    monkeypatch.setattr(arcade_store, "contradiction", counted)
    _al5_case("denial", db, world, None, admin_engine)
    with arcade_client(db, world, seeded) as driver:
        assert pre(driver).json()["code"] == "CHECK_FAILED"
        assert post(driver, success=True).json() == {"code": "OK"}
        assert post(driver, success=True).json() == {"code": "OK"}
    # The filter: the second delivery never asked the store, so it took no fence.
    assert calls == ["DENIED_CALL"]
    assert [item["contradiction"] for item in _contradictions(admin_engine, tenant)] == [
        "DENIED_CALL"
    ]
    head = audit_head(admin_engine, tenant)
    # The re-check: asked again past the filter, the store refuses and appends nothing.
    again = marked(
        db,
        world["identity"],
        "arcade-execution-1",
        "DENIED_CALL",
        {"contradiction": "DENIED_CALL"},
        world["clock"],
    )
    assert again is False
    assert audit_head(admin_engine, tenant) == head
    assert [item["contradiction"] for item in _contradictions(admin_engine, tenant)] == [
        "DENIED_CALL"
    ]
    # The other kind is still open on the same row, which is what "one of each" means.
    assert (
        marked(
            db,
            world["identity"],
            "arcade-execution-1",
            "INPUTS_DIFFER",
            {"contradiction": "INPUTS_DIFFER"},
            world["clock"],
        )
        is True
    )
    assert [item["contradiction"] for item in _contradictions(admin_engine, tenant)] == [
        "DENIED_CALL",
        "INPUTS_DIFFER",
    ]


def test_another_principals_post_hook_names_no_row_of_this_one(
    db, arcade_world, seeded, admin_engine
):
    """One Arcade project is one ExecBound principal, and correlation is scoped to it.

    An Arcade execution id is the platform's own string, so nothing stops a second project
    of the same tenant from sending one that collides with this project's. The correlation
    lookup is scoped to the principal that opened the row as well as to the tenant, so such
    a hook names no row: it settles nothing, writes nothing to the other project's row and
    is recorded as the orphan it is.

    The kernel would refuse it too — `_reportable` answers `NOT_FOUND` for another
    principal's execution — so what this scoping adds is that the refusal never touches the
    row on the way past, and the other project's retained statement stays its own.
    """
    world, tenant = arcade_world, arcade_world["identity"].tenant_id
    other = provision_identity(admin_engine, db, tenant, "AGENT", world["clock"].now())
    with admin_engine.begin() as conn:
        token = provision_credential(
            conn, tenant, other.principal_id, world["clock"].now(), timedelta(hours=2)
        )
    with arcade_client(db, world, seeded) as driver:
        execution_id = _granted_hook(driver, admin_engine, tenant, "arcade-execution-1")
        collided = post(driver, token=token, success=True)
    assert (collided.status_code, collided.json()) == (200, {"code": "OK"})
    [row] = correlation_rows(admin_engine, tenant).values()
    assert row["principal_id"] == world["identity"].principal_id
    assert (row["reported_success"], row["settled_at"]) == (None, None)
    assert row["report_secret"] is not None
    assert retained(admin_engine, tenant, execution_id).state == "DISPATCH_COMMITTED"


# ---------------------------------------------------------------------------------------
# Two Arcade projects of one tenant, colliding on an Arcade execution id. One project is
# one ExecBound principal and the id is the platform's own string, so the collision needs
# no misbehaviour from either project: two independently configured Arcade deployments can
# mint the same id. The correlation row is keyed `(tenant, principal, arcade_execution_id)`
# to match `execution_keys`, and these three walks are what that key refuses.


def _second_project(db, world, admin_engine):
    """A second Arcade project of the same tenant: its own principal and its own credential."""
    tenant, now = world["identity"].tenant_id, world["clock"].now()
    other = provision_identity(admin_engine, db, tenant, "AGENT", now)
    with admin_engine.begin() as conn:
        token = provision_credential(conn, tenant, other.principal_id, now, timedelta(hours=2))
    return other, token


def _project_row(admin_engine, tenant, identity, arcade_id):
    """One project's correlation row for an Arcade execution id the other may also hold."""
    return correlation_rows(admin_engine, tenant, identity.principal_id)[arcade_id]


def test_a_second_project_cannot_complete_this_ones_correlation_row(
    db, arcade_world, seeded, admin_engine
):
    """Walk 1: the second project's pre hook opens its own row rather than completing this one.

    While the key carried no principal the insert was a no-op — the first project's row
    already held `(tenant, arcade_execution_id)` — and the completion that followed matched
    that row: it wrote the second project's execution and operation onto it and, because
    `report_secret` is written through `COALESCE(:secret, report_secret)`, replaced the
    first project's secret with the second's. Both grants then stranded. The first project's
    post hook reached the second project's execution and was answered `NOT_FOUND`, which
    this route answers `OK`; the second project's post hook named no row of its own and was
    recorded as an orphan. Two `UNRESOLVED` impacts, two claims held, two cap slots spent
    and nothing either project could settle.

    Keyed on the principal, the two hooks are two rows, and each project settles its own.
    """
    world, tenant = arcade_world, arcade_world["identity"].tenant_id
    other, token = _second_project(db, world, admin_engine)
    governed_target(admin_engine, world, "device-p2")
    with arcade_client(db, world, seeded) as driver:
        first = pre(driver)
        collided = pre(driver, token=token, inputs={"device_id": "device-p2"})
        mine = _project_row(admin_engine, tenant, world["identity"], "arcade-execution-1")
        theirs = _project_row(admin_engine, tenant, other, "arcade-execution-1")
        settled = post(driver, success=True)
        settled_theirs = post(driver, token=token, success=True, execution_code="second-project")
        stated = _project_row(admin_engine, tenant, world["identity"], "arcade-execution-1")
        stated_theirs = _project_row(admin_engine, tenant, other, "arcade-execution-1")
    assert (first.json(), collided.json()) == ({"code": "OK"}, {"code": "OK"})
    # Two rows under the one Arcade execution id, each naming its own project's execution
    # and holding the secret that execution minted.
    assert mine["execution_id"] != theirs["execution_id"]
    assert mine["report_secret"] != theirs["report_secret"]
    for row in (mine, theirs):
        assert row["decision"] == "OK"
        assert (
            store.ticket_digest(row["report_secret"])
            == grant_row(admin_engine, tenant, row["execution_id"])["owner_hash"]
        )
    assert (settled.json(), settled_theirs.json()) == ({"code": "OK"}, {"code": "OK"})
    # What each platform stated is retained on the row of the project that stated it, and
    # the vendor string one of them sent did not land on the other's.
    assert (stated["reported_success"], stated["reported_code"]) == (True, None)
    assert (stated_theirs["reported_success"], stated_theirs["reported_code"]) == (
        True,
        "second-project",
    )
    assert stated["settled_at"] is not None and stated_theirs["settled_at"] is not None
    # Each project's own post hook settled the grant its own pre hook opened, which is what
    # the hijack took away from both of them.
    assert retained(admin_engine, tenant, mine["execution_id"]).state == "EXECUTED"
    assert retained(admin_engine, tenant, theirs["execution_id"]).state == "EXECUTED"
    assert sorted(impact["state"] for impact in impact_rows(admin_engine, tenant)) == [
        "CONFIRMED",
        "CONFIRMED",
    ]
    with db.transaction(tenant) as conn:
        assert store.outstanding_grants(conn, tenant, world["identity"].principal_id) == 0
        assert store.outstanding_grants(conn, tenant, other.principal_id) == 0


def test_a_second_projects_adopted_retry_is_not_held_by_this_ones_secret(
    db, arcade_world, seeded, admin_engine
):
    """Walk 2: `held` read off a secret that belongs to another principal's grant.

    The second project asks twice for one intent under two Arcade execution ids. The second
    ask is adopted by admission onto its own in-flight execution and answered `regranted`,
    which carries no secret at all — so its completion wrote `COALESCE(NULL, report_secret)`
    and, on the unkeyed row, kept the **first project's** secret. `held` came back true and
    the `OK` rule answered `OK` on a secret that could never settle the execution the
    answer was about.

    Keyed on the principal, the completion reaches the second project's own empty row, the
    secret stays null and the rule refuses exactly as it refuses a second Arcade id within
    one project.
    """
    world, tenant = arcade_world, arcade_world["identity"].tenant_id
    other, token = _second_project(db, world, admin_engine)
    governed_target(admin_engine, world, "device-p2")
    with arcade_client(db, world, seeded) as driver:
        first = pre(driver)
        opened = pre(
            driver,
            token=token,
            execution_id="arcade-execution-b",
            inputs={"device_id": "device-p2"},
        )
        adopted = pre(driver, token=token, inputs={"device_id": "device-p2"})
        mine = _project_row(admin_engine, tenant, world["identity"], "arcade-execution-1")
        theirs = correlation_rows(admin_engine, tenant, other.principal_id)
        settled = post(driver, success=True)
    adopted_onto = theirs["arcade-execution-b"]["execution_id"]
    assert (first.json(), opened.json()) == ({"code": "OK"}, {"code": "OK"})
    assert adopted.json() == {
        "code": "CHECK_FAILED",
        "error_message": f"DISPATCH_COMMITTED execution={adopted_onto}",
    }
    # The adopted row is the second project's own, holds no secret and was answered a
    # refusal; the first project's row is untouched by any of it.
    assert theirs["arcade-execution-1"]["report_secret"] is None
    assert theirs["arcade-execution-1"]["decision"] == "CHECK_FAILED"
    assert (
        theirs["arcade-execution-1"]["execution_id"] == theirs["arcade-execution-b"]["execution_id"]
    )
    assert mine["decision"] == "OK"
    assert (
        store.ticket_digest(mine["report_secret"])
        == grant_row(admin_engine, tenant, mine["execution_id"])["owner_hash"]
    )
    assert settled.json() == {"code": "OK"}
    assert retained(admin_engine, tenant, mine["execution_id"]).state == "EXECUTED"


def test_a_second_projects_refusal_cannot_rewrite_this_ones_recorded_answer(
    db, arcade_world, seeded, admin_engine
):
    """Walk 3: a refusal of the second project's own, written onto the first project's row.

    `store.refused` records the code a kernel refusal was answered with, and while the key
    carried no principal it recorded it on whichever row held the Arcade execution id. The
    second project here is at its own cap of eight grants, which is a refusal about it and
    not about the first project at all: `TOO_MANY_GRANTS` overwrote the first project's
    `decision` of `OK` with `CHECK_FAILED`, and the first project's own post hook then read
    that column, found an answer that was not `OK`, and appended a `DENIED_CALL`
    contradiction — a tool that ran after ExecBound refused it — into the tenant's
    append-only chain. `docs/ARCADE.md` reads that as evidence of a fail-open configuration
    or a bypass, so the hijack wrote false evidence of the extension's own failure.

    Keyed on the principal, the refusal is recorded on the second project's row and the
    first project's retained answer stays `OK`.
    """
    world, tenant = arcade_world, arcade_world["identity"].tenant_id
    other, token = _second_project(db, world, admin_engine)
    with arcade_client(db, world, seeded) as driver:
        first = pre(driver)
        for index in range(MAX_GRANTS):
            device = f"device-c{index}"
            governed_target(admin_engine, world, device)
            filler = admit(
                db,
                other,
                _governed_request(device, f"other-{index}"),
                world["clock"],
                available_accounts=frozenset(),
                catalog=CATALOG,
                attestable=attestable_ring,
            )
            assert filler.view.state == "DISPATCH_COMMITTED"
        # A ninth target, so the refusal is the cap and not the claim the eighth holds.
        governed_target(admin_engine, world, "device-c8")
        capped = pre(driver, token=token, inputs={"device_id": "device-c8"})
        mine = _project_row(admin_engine, tenant, world["identity"], "arcade-execution-1")
        reported = post(driver, success=True)
    assert first.json() == {"code": "OK"}
    assert capped.json() == {"code": "CHECK_FAILED", "error_message": "TOO_MANY_GRANTS"}
    # The refused hook recorded its code on its own project's row.
    assert _project_row(admin_engine, tenant, other, "arcade-execution-1")["decision"] == (
        "CHECK_FAILED"
    )
    assert mine["decision"] == "OK"
    # No contradiction: the first project's answer was `OK`, and the chain says so.
    assert reported.json() == {"code": "OK"}
    assert _contradictions(admin_engine, tenant) == []
    assert retained(admin_engine, tenant, mine["execution_id"]).state == "EXECUTED"


# ---------------------------------------------------------------------------------------
# Guards a mutation sweep removed with nothing failing.
# Each is asserted here on the smallest thing that can tell the difference, which for four
# of them is the store function rather than the route, for the reason each docstring gives.


def test_a_post_hook_against_a_row_nothing_answered_records_no_denial(
    db, arcade_world, seeded, admin_engine, monkeypatch
):
    """A row an abandoned deadline or a crash left open records no answer to contradict.

    AL4 builds both shapes and posts to neither, so the conjunct that reads the recorded
    answer before comparing it went uncovered. The crash is the cheaper of the two to
    produce: the completion is made to fail after the kernel has committed, so the row keeps
    the null `decision` its insert gave it while the grant exists. A post hook then arrives
    for a tool that ran, which is ordinary — the platform was answered a 503 carrying no
    hook code, so nothing told it to stop — and `DENIED_CALL` would record that ExecBound
    refused the call and was bypassed anyway. It refused nothing here; it answered nothing.
    """
    world, tenant = arcade_world, arcade_world["identity"].tenant_id

    def crash(*args, **kwargs):
        raise RuntimeError("the correlation write never happened")

    with arcade_client(db, world, seeded) as driver:
        monkeypatch.setattr(routes.store, "complete", crash)
        lost = pre(driver)
        monkeypatch.undo()
        reported = post(driver, success=True)
    row = correlation_rows(admin_engine, tenant)["arcade-execution-1"]
    assert lost.status_code == 503 and "code" not in lost.json()
    assert (row["decision"], row["execution_id"]) == (None, None)
    assert reported.json() == {"code": "OK"}
    assert _contradictions(admin_engine, tenant) == []
    assert row["denial_contradiction_at"] is None
    # What the arrival did do: the statement is retained, and nothing settled, because the
    # row names no execution and holds no secret.
    assert (row["reported_success"], row["settled_at"]) == (True, None)
    assert execution_states(admin_engine, tenant) == ["DISPATCH_COMMITTED"]


def test_a_contradiction_cannot_be_appended_while_the_tenant_fence_is_held(
    db, arcade_world, seeded, admin_engine
):
    """The fence is what orders two deliveries racing to append one contradiction.

    The route's filter reads a row it holds no lock on, and the store's own re-check reads
    one under this fence. Without the fence both deliveries read an unmarked column and both
    append; the only thing the second then fails to do is write the column, which happens
    after its event has already landed in the tenant's append-only chain. The two-guard test
    cannot see that, because it delivers in turn.

    Held rather than raced, so the assertion is deterministic: an owner connection takes the
    fence first and two deliveries are released at it. While they wait, neither has passed
    `executions.fence` and so neither can have appended. Released, one appends and the other
    re-reads a column the first has set and appends nothing.
    """
    world, tenant = arcade_world, arcade_world["identity"].tenant_id
    _al5_case("denial", db, world, None, admin_engine)
    with arcade_client(db, world, seeded) as driver:
        assert pre(driver).json()["code"] == "CHECK_FAILED"
    queued, at_fence = [], Event()

    def counting(conn, cursor, statement, parameters, context, executemany):
        if "tenant_policy_control" in statement and "FOR UPDATE" in statement:
            queued.append(statement)
            if len(queued) >= 2:
                at_fence.set()

    def deliver(_index):
        return arcade_store.contradiction(
            db,
            world["identity"],
            "arcade-execution-1",
            "DENIED_CALL",
            {"contradiction": "DENIED_CALL"},
            world["clock"],
        )

    event.listen(db.engine, "before_cursor_execute", counting)
    try:
        with ThreadPoolExecutor(max_workers=2) as pool:
            with _hold_the_fence(admin_engine, tenant):
                racing = [pool.submit(deliver, index) for index in range(2)]
                assert at_fence.wait(10)
                # Both are inside `contradiction` and both are waiting on the fence, so
                # neither can have reached the append below it.
                done, _ = futures_wait(racing, timeout=1)
                assert done == set()
            answers = sorted(future.result(timeout=10) for future in racing)
    finally:
        event.remove(db.engine, "before_cursor_execute", counting)
    assert answers == [False, True]
    assert [item["contradiction"] for item in _contradictions(admin_engine, tenant)] == [
        "DENIED_CALL"
    ]


def test_a_second_settlement_of_one_row_keeps_the_instant_the_first_wrote(
    db, arcade_world, seeded, admin_engine
):
    """`settled_at` says when the row closed, and a later settlement does not move it.

    Asserted on the store rather than through the route, for two reasons the route makes
    unavoidable. A delivery arriving after the first settlement finds the secret nulled and
    returns from `_post` before the kernel call, so it never reaches here; what does reach
    here twice is two deliveries that both read the secret before either settled. And those
    two run against one fixed clock in every deployment this suite builds, which writes the
    same instant twice and hides whichever of the two the column ends up holding.
    """
    world, tenant = arcade_world, arcade_world["identity"].tenant_id
    with arcade_client(db, world, seeded) as driver:
        _granted_hook(driver, admin_engine, tenant, "arcade-execution-1")
        assert post(driver, success=True).json() == {"code": "OK"}
    closed = correlation_rows(admin_engine, tenant)["arcade-execution-1"]["settled_at"]
    assert closed is not None
    world["clock"].value = world["clock"].now() + timedelta(seconds=90)
    arcade_store.settled(db, world["identity"], "arcade-execution-1", world["clock"])
    again = correlation_rows(admin_engine, tenant)["arcade-execution-1"]
    assert again["settled_at"] == closed
    assert again["report_secret"] is None


def test_a_hook_framing_no_content_type_is_refused_where_a_doubled_one_never_arrives(
    db, arcade_world, seeded, admin_engine, monkeypatch
):
    """The two halves of `_framed`'s count, and which of them a request can actually reach.

    A hook sending no `content-type` at all reaches `_framed` and is refused there: this
    deployment accepts two spellings and absence is neither of them. A hook sending the
    header twice is refused by `checked_request`, which every route of this application
    shares, before `_framed` is called at all — so the `> 1` half of the count is
    unreachable through either hook, and this asserts that rather than describing it.
    """
    world, tenant = arcade_world, arcade_world["identity"].tenant_id
    framed = []
    original = routes._framed

    async def counted(request, runtime, identity):
        framed.append(request.url.path)
        return await original(request, runtime, identity)

    monkeypatch.setattr(routes, "_framed", counted)
    with arcade_client(db, world, seeded) as driver:
        bearer = "Bearer " + driver.token
        absent = driver.client.post(
            "/pre", content=json.dumps(pre_hook()), headers={"Authorization": bearer}
        )
        reached = list(framed)
        doubled = driver.client.post(
            "/pre",
            content=json.dumps(pre_hook()),
            headers=[
                ("Authorization", bearer),
                ("Content-Type", "application/json"),
                ("Content-Type", "application/json"),
            ],
        )
    assert (absent.status_code, "code" in absent.json()) == (400, False)
    assert (doubled.status_code, "code" in doubled.json()) == (400, False)
    # The absent header reached the frame check; the doubled one was refused above it.
    assert reached == ["/pre"] and framed == ["/pre"]
    assert execution_states(admin_engine, tenant) == []
    kinds = [kind for kind, _ in audit_kinds(admin_engine, tenant)]
    assert kinds.count("execution.rejected") == 2


@pytest.mark.parametrize("first_write", ["open_hook", "correlate"])
def test_each_hook_paths_first_write_asks_the_runtime_catalog(
    db, arcade_world, seeded, admin_engine, first_write
):
    """The catalog check each path makes before it writes anything of its own request.

    Asserted on the two store functions and not over the surface, because `authenticate`
    asks the same question of the same pool on the way in: over HTTP a role that has gained
    a privilege is refused at the credential and neither of these is reached, so a walk
    through a route cannot tell whether they ask at all. What they are here for is the role
    that changes after that check, on a pooled connection taken afterwards.
    """
    world, tenant = arcade_world, arcade_world["identity"].tenant_id
    grant = "UPDATE(toolkit) ON execbound.arcade_hooks"
    writes = {
        "open_hook": lambda: arcade_store.open_hook(
            db, world["identity"], parse_pre_hook(json.dumps(pre_hook()).encode()), world["clock"]
        ),
        "correlate": lambda: arcade_store.correlate(
            db, world["identity"], parse_post_hook(json.dumps(post_hook()).encode()), world["clock"]
        ),
    }
    with admin_engine.begin() as conn:
        conn.execute(text(f"GRANT {grant} TO execbound_app"))
    try:
        with pytest.raises(UnsafeDatabaseRole):
            writes[first_write]()
    finally:
        with admin_engine.begin() as conn:
            conn.execute(text(f"REVOKE {grant} FROM execbound_app"))
    # Refused before the write rather than after it: no row was opened and none was read.
    assert correlation_rows(admin_engine, tenant) == {}


@pytest.mark.parametrize("write", ["refused", "settled"])
def test_a_correlation_write_scoped_to_another_project_fails_closed(
    db, arcade_world, seeded, admin_engine, write
):
    """A write that matches no row raises rather than passing as a success.

    The Arcade execution id here is one this project holds a completed row for, presented
    under a second project's identity. That is the shape the unkeyed table could not tell
    from a hit and did not: a second project's completion and decision write matched the
    first project's row, and both went on as though they had written their own. Scoped, they
    match nothing — and a correlation write that matches nothing is a row that was never
    opened or a scope this module got wrong, not an outcome to carry on from.
    """
    world, tenant = arcade_world, arcade_world["identity"].tenant_id
    other, _token = _second_project(db, world, admin_engine)
    with arcade_client(db, world, seeded) as driver:
        assert pre(driver).json() == {"code": "OK"}
    writes = {
        "refused": lambda identity: arcade_store.refused(
            db, identity, "arcade-execution-1", HookResult("CHECK_FAILED", "TOO_MANY_GRANTS")
        ),
        "settled": lambda identity: arcade_store.settled(
            db, identity, "arcade-execution-1", world["clock"]
        ),
    }
    with pytest.raises(arcade_store.CorrelationMissing):
        writes[write](other)
    # The row the write would have reached is exactly as its own project left it.
    mine = _project_row(admin_engine, tenant, world["identity"], "arcade-execution-1")
    assert (mine["decision"], mine["settled_at"]) == ("OK", None)
    assert mine["report_secret"] is not None
    assert correlation_rows(admin_engine, tenant, other.principal_id) == {}


# ---------------------------------------------------------------------------------------
# The deployment boundary, as `docs/ARCADE.md` describes it: the three routes a hook
# process serves, the readiness answer under a shorter path, the per-route rewriting of the
# application's own non-hook answers, and the capacity bound that makes this surface's own
# refusal something a deployment can actually reach. AL7 and AL25.


def _wait_for_rows(admin_engine, tenant, count, seconds=10):
    """Wait until this many correlation rows exist.

    Each row is committed before its own hook asks the kernel anything, and the hook slot
    is taken before that, so a row is evidence that its hook holds a slot and will hold it
    until whatever it is waiting on releases.
    """
    limit = time.monotonic() + seconds
    while len(correlation_rows(admin_engine, tenant)) < count and time.monotonic() < limit:
        time.sleep(0.05)
    return correlation_rows(admin_engine, tenant)


def _dead_database(db):
    """The same configuration against a database server that is not listening.

    A dependency failure rather than a simulated one: every statement this deployment tries
    raises `OperationalError`, which the application answers 503 for through the handler it
    already registers for `SQLAlchemyError`.
    """
    return Database(db.engine.url.set(port=1).render_as_string(hide_password=False))


def test_the_hook_bound_is_derived_from_the_two_bounds_above_it_and_from_its_floor():
    """The arithmetic the surface's own refusal rests on, at the shipped application bound.

    Written as a property of `hook_slots_for` rather than of one deployment's numbers,
    because what went wrong before was a constant that happened to equal the application's
    bound: the application refuses first and its 429 carries no hook code, so this surface
    could not refuse anything. Below both bounds, a hook flood is answered here.

    The floor is asserted with the rest: a runtime whose concurrency is one gets one hook
    slot, which is the one value at which this surface can fill the runtime.
    """
    in_flight = app_module.REQUESTS_IN_FLIGHT
    derived = {c: routes.hook_slots_for(in_flight, c) for c in (1, 2, 3, 9, 16, 32, 64)}
    assert derived == {1: 1, 2: 1, 3: 2, 9: 8, 16: 15, 32: 31, 64: 31}
    assert all(slots < in_flight for slots in derived.values())
    assert all(slots <= concurrency for concurrency, slots in derived.items())
    assert [c for c, slots in derived.items() if slots == c] == [1]


def test_a_hook_flood_is_refused_by_this_surface_while_the_application_still_has_slots(
    db, arcade_world, seeded, admin_engine
):
    """The finding, made live: the hook bound fires at its derived value and not by patching.

    This runtime's concurrency is three, so `hook_slots_for` gives the surface two slots
    against an application that still admits thirty-two requests. Two pre hooks are parked
    at the tenant fence by an owner connection — each holding a slot it will not give back
    while the fence is held — and the third is refused by this surface, with the retryable
    code and `HOOK_CAPACITY`, which is a 200 and a hook answer. The application's own
    refusal is a 429 whose body is `{"detail": "Service busy"}`, so the two are told apart
    by what came back rather than by which limiter a test believes fired; `/health/live` is
    answered in the same window, which is the application saying it had slots left.
    """
    world, tenant = arcade_world, arcade_world["identity"].tenant_id
    narrow = Runtime(db, [], clock=world["clock"], catalog=CATALOG, concurrency=3)
    slots = routes.hook_slots_for(app_module.REQUESTS_IN_FLIGHT, narrow.concurrency)
    assert slots == 2
    with arcade_client(
        db, world, seeded, block=hook_block(deadline_seconds=30.0), runtime=narrow
    ) as driver:
        with ThreadPoolExecutor(max_workers=slots) as pool:
            with _hold_the_fence(admin_engine, tenant):
                held = [
                    pool.submit(pre, driver, execution_id=f"arcade-execution-{n}")
                    for n in range(slots)
                ]
                assert len(_wait_for_rows(admin_engine, tenant, slots)) == slots
                refused = pre(driver, execution_id="arcade-execution-over")
                live = driver.client.get("/health/live")
            for future in held:
                future.result(timeout=20)
    assert refused.status_code == 200
    assert refused.json() == {"code": "RATE_LIMIT_EXCEEDED", "error_message": "HOOK_CAPACITY"}
    assert (live.status_code, live.json()) == (200, {"status": "ok"})
    # The refused hook opened no correlation row: it was refused before it read a body.
    assert "arcade-execution-over" not in correlation_rows(admin_engine, tenant)


@pytest.mark.parametrize(
    "method,path",
    [
        ("GET", "/pre"),
        ("PUT", "/pre"),
        ("DELETE", "/pre"),
        ("GET", "/post"),
        ("PATCH", "/post"),
        ("POST", "/pre/"),
        ("POST", "//pre"),
        ("POST", "/PRE"),
        ("POST", "/%70re"),
        ("POST", "/health"),
        ("GET", "/health/ready"),
        ("GET", "/health/live"),
        ("GET", "/v1/me"),
        ("POST", "/v1/execute"),
        ("POST", "/v1/executions/00000000-0000-0000-0000-000000000000/outcome"),
        ("POST", "/v1/monitor/events"),
        ("POST", "/mcp"),
        ("GET", "/"),
        ("GET", "/login"),
        ("POST", "/session"),
        ("GET", "/activity"),
        ("GET", "/assets/app.css"),
    ],
)
def test_al25_the_boundary_refuses_the_other_routes_and_respellings_of_its_own(
    db, arcade_world, seeded, method, path
):
    """What a hook process exposes, asserted as a refusal of everything else it holds.

    The process holds a whole application — the agent surface, the human pages, the
    monitoring intake and the readiness route under its own path — and serves three things.
    The comparison is on the raw path, so a trailing slash, a doubled separator, another
    case and a percent-encoding are each a different string and each refused.
    """
    with arcade_boundary(db, arcade_world, seeded) as driver:
        answer = driver.client.request(method, path, follow_redirects=False)
    assert answer.status_code == 404
    assert answer.json() == {"detail": "Not found"}
    assert "location" not in answer.headers
    assert answer.headers["cache-control"] == "no-store"


def test_al25_the_boundary_closes_a_websocket_rather_than_passing_it_on(db, arcade_world, seeded):
    """A websocket is closed here rather than left to whatever the process holds.

    The close code is what says which layer closed it. The application's own router closes
    an unmatched websocket with the default 1000; 1008 is the boundary's, and it is the
    boundary that has to answer, because the process mounts an application whose `/mcp`
    mount is not this module's to reason about.
    """
    with arcade_boundary(db, arcade_world, seeded) as driver:
        with pytest.raises(WebSocketDisconnect) as refusal:
            with driver.client.websocket_connect("/pre"):
                pass
    assert refusal.value.code == 1008


def test_al25_a_short_health_path_is_served_by_the_applications_own_readiness_route(
    db, arcade_world, seeded
):
    """There is no third health route: `GET /health` is `/health/ready` under another name.

    One readiness answer and one implementation, unauthenticated, naming no tenant, 200
    with the database up and 503 with it down. The 503 is the application's own handler
    answering a real dependency failure, and it is not rewritten: `/health` is not a hook
    route, and a health check that answered 200 while the database was unreachable would be
    worse than useless to the platform that reads it.
    """
    with arcade_boundary(db, arcade_world, seeded) as driver:
        healthy = driver.client.get("/health")
        # Against the route it is renamed from, rather than against a literal body: the
        # claim is that these are one implementation, so a body the application adds to
        # its readiness answer has to appear here without this test being edited. The
        # comparison is against the application itself because `/health/ready` is not a
        # path this boundary serves — it answers 404 to every path but its own three.
        plain = create_app(db, runtime=driver.runtime, arcade=hook_block())
        with TestClient(plain) as application:
            readiness = application.get("/health/ready")
    dead = _dead_database(db)
    try:
        with arcade_boundary(dead, arcade_world, seeded) as driver:
            down = driver.client.get("/health")
    finally:
        dead.close()
    assert healthy.status_code == 200 and healthy.json()["status"] == "ready"
    assert (healthy.status_code, healthy.json()) == (readiness.status_code, readiness.json())
    assert "authorization" not in healthy.request.headers
    assert (down.status_code, down.json()) == (503, {"detail": "Service unavailable"})


def test_al7_a_dependency_failure_is_an_answer_on_the_way_in_and_an_error_on_the_way_out(
    db, arcade_world, seeded
):
    """AL7's handler-level 503, on each route, from a database that is not there.

    On the way in it becomes `CHECK_FAILED`, which blocks the tool call under either of
    Arcade's failure modes and carries no `detail`. On the way out it travels as the 503 it
    was, because nothing was settled and a 5xx is what makes Arcade deliver the report
    again.
    """
    dead = _dead_database(db)
    try:
        with arcade_boundary(dead, arcade_world, seeded) as driver:
            inbound = pre(driver)
            outbound = post(driver)
    finally:
        dead.close()
    assert (inbound.status_code, inbound.json()) == (200, {"code": "CHECK_FAILED"})
    assert (outbound.status_code, outbound.json()) == (503, {"detail": "Service unavailable"})
    # The rewritten answer carries its own framing and the application's other headers.
    assert inbound.headers["content-type"] == "application/json"
    assert inbound.headers["cache-control"] == "no-store"
    assert inbound.headers["x-content-type-options"] == "nosniff"
    assert inbound.headers["x-frame-options"] == "DENY"
    # One of each of the framing headers, not the application's beside the boundary's.
    for name in ("content-length", "content-type", "cache-control", "x-content-type-options"):
        assert len(inbound.headers.get_list(name)) == 1, name
    assert inbound.headers["content-length"] == str(len(inbound.content))


def test_al7_the_applications_capacity_refusal_is_rewritten_on_the_way_in_only(
    db, arcade_world, seeded, admin_engine, monkeypatch
):
    """AL7's 429, from the application's own in-flight limiter rather than the hook slot.

    The application's bound is narrowed to one request, which is the deployment knob the
    hook bound derives from; one pre hook is then parked at the tenant fence, so the next
    request is refused by the outermost middleware before any route runs. That refusal is
    the bare `{"detail": "Service busy"}` the boundary exists to rewrite. On `POST /pre`
    the boundary turns it into the retryable hook code with no `detail` left; on
    `POST /post` it passes through with its own status and body.
    """
    world, tenant = arcade_world, arcade_world["identity"].tenant_id
    monkeypatch.setattr(app_module, "REQUESTS_IN_FLIGHT", 1)
    with arcade_boundary(db, world, seeded, block=hook_block(deadline_seconds=30.0)) as driver:
        with ThreadPoolExecutor(max_workers=1) as pool:
            with _hold_the_fence(admin_engine, tenant):
                held = pool.submit(pre, driver)
                assert len(_wait_for_rows(admin_engine, tenant, 1)) == 1
                inbound = pre(driver, execution_id="arcade-execution-2")
                outbound = post(driver, execution_id="arcade-execution-2")
            held.result(timeout=20)
    assert (inbound.status_code, inbound.json()) == (200, {"code": "RATE_LIMIT_EXCEEDED"})
    assert (outbound.status_code, outbound.json()) == (429, {"detail": "Service busy"})


def test_al7_an_unauthenticated_hook_is_the_refusal_both_routes_pass_through(
    db, arcade_world, seeded
):
    """The 401 both sides already spell the same way, kept as it is on either route."""
    unknown = f"eb1.{uuid4()}.{uuid4()}.{'a' * 43}"
    with arcade_boundary(db, arcade_world, seeded) as driver:
        answers = [pre(driver, token=unknown), post(driver, token=unknown)]
    for answer in answers:
        assert (answer.status_code, answer.json()) == (401, {"detail": "Invalid credentials"})
        assert answer.headers["www-authenticate"] == "Bearer"


def test_al7_a_request_the_pre_route_refused_still_answers_where_the_post_route_does_not(
    db, arcade_world, seeded
):
    """The three refusals the routes make with a status rather than a code, per route.

    A frame the hooks do not accept, a body past the pre hook's own bound, and a query
    string `checked_request` refuses: each is a 400 with a `detail`, and each becomes a
    `CHECK_FAILED` answer with no `detail` on the way in. The same frame on the way out
    keeps its 400, because a post hook that is told `OK` is a settlement that never happens.
    """
    sent = {"Authorization": "Bearer " + seeded["tokens"][0], "Content-Type": "application/json"}
    with arcade_boundary(db, arcade_world, seeded) as driver:
        framed = pre(driver, headers={"Content-Type": "text/plain"})
        oversized = pre(driver, body="{" + "a" * routes.PRE_HOOK_BYTES)
        queried = driver.client.post(
            "/pre?tool=other", content=json.dumps(pre_hook()), headers=sent
        )
        passed = post(driver, headers={"Content-Type": "text/plain"})
    for answer in (framed, oversized, queried):
        assert (answer.status_code, answer.json()) == (200, {"code": "CHECK_FAILED"})
    assert (passed.status_code, passed.json()) == (400, {"detail": "Invalid hook request"})


def test_the_boundary_passes_an_evaluated_hook_through_and_the_grant_settles_behind_it(
    db, arcade_world, seeded, admin_engine
):
    """A grant and its settlement over the surface a hook process actually serves.

    What the boundary rewrites is the application's answers, not the extension's: a hook
    the route evaluated is a 200 already, and it arrives unchanged.
    """
    tenant = arcade_world["identity"].tenant_id
    with arcade_boundary(db, arcade_world, seeded) as driver:
        granted = pre(driver)
        settled = post(driver, success=True)
    assert (granted.status_code, granted.json()) == (200, {"code": "OK"})
    assert (settled.status_code, settled.json()) == (200, {"code": "OK"})
    assert execution_states(admin_engine, tenant) == ["EXECUTED"]


def test_al25_a_factory_hook_process_answers_at_its_own_hostname(
    db, arcade_world, seeded, config, tmp_path, monkeypatch
):
    """A factory hook process as a deployment runs it: `--factory`, and the gateway's own file.

    A private configuration file always names an `origin`, and `load_runtime` always builds a human
    surface from it. Before `human_surface` existed, the hook process took the gateway's origin as
    its own and `response_headers` refused every request whose `Host` header was not that netloc —
    `GET /health` answered 400, so the service would never have become healthy, and every `POST
    /pre` answered 400, which this boundary rewrites to `CHECK_FAILED`. A deployment that blocks
    every governed tool call while answering in the extension's own vocabulary is the worst shape
    this surface has, so the hostname here is deliberately not the file's origin.

    The hook is answered rather than granted: this configuration's tenant is not the seeded
    world's, so what the answer shows is that the request reached the route at all.
    """
    config["arcade"] = deepcopy(ARCADE)
    private = tmp_path / "gateway.json"
    private.write_text(json.dumps(config), encoding="utf-8")
    monkeypatch.setenv("EXECBOUND_RUNTIME_CONFIG", str(private))
    monkeypatch.setenv("DATABASE_URL", db.engine.url.render_as_string(hide_password=False))
    assert urlsplit(config["origin"]).netloc == "127.0.0.1:8000"
    with TestClient(create_arcade(), base_url="http://arcade-hooks.example.test") as client:
        health = client.get("/health")
        hook = client.post(
            "/pre",
            content=json.dumps(pre_hook()),
            headers={
                "Authorization": "Bearer " + seeded["tokens"][0],
                "Content-Type": "application/json",
            },
        )
        page = client.get("/login")
    assert (health.status_code, health.json()["status"]) == (200, "ready")
    assert hook.status_code == 200 and set(hook.json()) <= {"code", "error_message"}
    # The human routes are not registered in this process at all, and the boundary would
    # answer 404 for them either way; both facts are asserted where each is made.
    assert page.status_code == 404


def _answer_of(application):
    """`_answered` driven directly, for two shapes no hook reaches it in over HTTP."""
    sent = []

    async def send(message):
        sent.append(message)

    async def receive():
        return {"type": "http.request", "body": b"", "more_body": False}

    scope = {"type": "http", "method": "POST", "path": "/pre", "raw_path": b"/pre", "headers": []}
    asyncio.run(boundary._answered(application, scope, receive, send))
    start = next(message for message in sent if message["type"] == "http.response.start")
    body = b"".join(
        message.get("body", b"") for message in sent if message["type"] == "http.response.body"
    )
    return start["status"], json.loads(body)


def test_an_application_that_raises_instead_of_answering_still_answers_the_pre_hook():
    """The pre route's last resort, asserted on `_answered` rather than over HTTP.

    The application as layered does not reach it: `response_headers` is the outermost
    middleware and catches an unexpected exception around `call_next`, answering its own
    503, and the registered handlers answer `SQLAlchemyError` and `UnsafeDatabaseRole`
    before that. So the two shapes below are made here — one that answers nothing at all,
    and one that answers and then raises, which is what `ServerErrorMiddleware` would do if
    an exception ever got past that middleware. Both are `CHECK_FAILED`, because a pre hook
    that does not answer leaves the tool call to Arcade's failure-mode setting.
    """

    async def silent(scope, receive, send):
        raise RuntimeError("answered nothing")

    async def late(scope, receive, send):
        await send(
            {
                "type": "http.response.start",
                "status": 503,
                "headers": [(b"content-type", b"application/json")],
            }
        )
        await send({"type": "http.response.body", "body": b'{"detail": "Service unavailable"}'})
        raise RuntimeError("answered, then raised")

    assert _answer_of(silent) == (200, {"code": "CHECK_FAILED"})
    assert _answer_of(late) == (200, {"code": "CHECK_FAILED"})


def test_the_boundary_refuses_a_process_that_would_serve_no_hooks(db, arcade_world):
    """A hook process with no tool map answers 404 to every tool call, which is no answer.

    Refused where `create_app` refuses a block with no runtime: at construction, so the
    deployment fails to start rather than handing Arcade's failure-mode setting every
    decision.
    """
    runtime = Runtime(db, [], clock=arcade_world["clock"], catalog=CATALOG)
    with pytest.raises(ValueError, match="^Arcade hooks are not configured$"):
        create_arcade(db, runtime=runtime)


# ---------------------------------------------------------------------------------------
# What this carrier inherits from the kernel rather than adds to it: the shared limit
# scopes, the grant cap, the act window and the report secret this extension keeps at rest.
# Nothing in `src/` belongs to these rows. Each drives a property the kernel already has
# through the hooks, so what they establish is that a tool call reaches the same counters,
# the same ceilings and the same exits an ordinary agent request reaches. AL18, AL19, AL20.


# `recover`'s own default grace, written out here because the two halves of the act-window
# rule are asserted against the selection directly as well as through a run.
RUN_GRACE = timedelta(seconds=300)


def _direct_request(device, key):
    """The ordinary agent's wire body: the same action and target, dispatched by ExecBound.

    `DIRECT_OPERATION` is the second mapping of the same contract `governed_bundle(direct=
    True)` declares, and the bundle does not declare it externally executed, so admission
    reserves and hands back a dispatch ticket where the governed reference hands back a
    grant. Each writes an impact row against the same action, which is what the shared
    scopes count.
    """
    return parse_request(
        json.dumps(
            {
                "operation_ref": DIRECT_OPERATION,
                "target": {"kind": "provider_id", "value": device},
                "arguments": {},
                "idempotency_key": key,
            }
        ).encode()
    )


def _dispatch(db, world, identity, device, key):
    """One ordinary agent dispatch through the kernel's own admission, as the SL rows drive one.

    `available_accounts` is left unset, which is the kernel's own default and the shape
    the shared-limit scenarios' own admissions take: what these rows are about is the
    reservation the decision writes, and a connector is what a later dispatch would need.
    """
    return admit(db, identity, _direct_request(device, key), world["clock"], catalog=CATALOG)


def _counts(db, world, identity, execution_id):
    """Every limit rule's counted pair for this identity, in the kernel's own projection."""
    return counted(usage(db, world, identity, execution_id))


def _uncertain_queue(db, world, admin):
    """The executions the operations console's uncertain filter selects, read without a page.

    `records` is the listing the console renders and `UNCERTAIN` is its own pseudo-state for
    the two unsettled ones, so this asks the queue's question through the queue's own query.
    The page that renders it is AL28's, in `tests/test_browser_surfaces.py`.
    """
    runtime = Runtime(db, [], clock=world["clock"], catalog=CATALOG)
    grant = sessions.issue_session(db, admin, clock=world["clock"])
    session = sessions.load_session(db, grant.token, clock=world["clock"])
    return [
        row["execution_id"] for row in human_surface.records(runtime, session, state="UNCERTAIN")
    ]


def test_al18_a_stolen_report_secret_settles_the_row_and_the_run_frees_the_target(
    db, arcade_world, seeded, admin_engine
):
    """AL18: what a reader of the correlation table can do with the secret it finds there.

    Limitation 8 is a property this carrier introduces rather than inherits: a Gate caller
    is handed its secret and what ExecBound retains of it is a digest, while here the
    extension holds the secret of a live grant at rest so that the post hook can settle the
    execution its own pre hook opened. The row is read here over the owner connection, with
    no ExecBound credential in the read at all, which is the reader the limitation names.

    What the stolen secret is worth is asserted as the bound limitation 8 states rather than as
    a refusal, because the kernel makes no refusal here: the report secret is what
    authenticates a report, so presenting it settles the row, and once the act window has
    passed the scheduled run releases the canonical claim of a settled assertion — so the
    theft does free the target. What the theft does not do is reduce what the tenant is
    charged: the impact is `CONFIRMED` rather than released, and both rules count the same
    one target afterwards as before, which a refund would show as a scope falling to zero.

    The bound the kernel does put on it is the principal. A live credential of the project
    whose grant it is remains necessary — the report route answers another principal of the
    same tenant `NOT_FOUND` — so what the secret at rest adds to a credential holder is the
    authority to close a row it was never handed, and what it does not add is a way into
    another project's row.
    """
    world, tenant = arcade_world, arcade_world["identity"].tenant_id
    governed_bundle(
        db,
        world,
        limits=(
            rule(rule_id="principal", scope="principal", max_targets=50, on_exceed="DENY"),
            rule(rule_id="tenant", scope="tenant", max_targets=50, on_exceed="DENY"),
        ),
    )
    other, _token = _second_project(db, world, admin_engine)
    with arcade_client(db, world, seeded) as driver:
        execution_id = _granted_hook(driver, admin_engine, tenant, "arcade-execution-1")
        # The theft: the secret is read out of the table, not out of any answer ExecBound
        # gave. The pre hook's own answer is `{"code": "OK"}` and carries no grant at all.
        stolen = correlation_rows(admin_engine, tenant)["arcade-execution-1"]["report_secret"]
        assert stolen is not None
        charged = _counts(db, world, world["identity"], execution_id)
        assert charged == {"principal": (0, 1), "tenant": (0, 1)}
        with pytest.raises(ExecutionError) as refused:
            report(db, world, execution_id, stolen, other)
        assert refused.value.code == "NOT_FOUND"
        settled = report(db, world, execution_id, stolen)
        assert settled.state == "EXECUTED"
        row = retained(admin_engine, tenant, execution_id)
        assert (row.state, row.tier, row.impact) == ("EXECUTED", "ASSERTED", "CONFIRMED")
        # The claim is held to the act window exactly as a genuine assertion's is, so
        # inside it the scheduled run releases nothing and the target stays unavailable.
        # Measured a second before the window closes, which is well past the run's own
        # grace period, so it is the act window answering and not the grace; and on each
        # half of the rule by name, because either of them alone answers a run the same way.
        assert row.released_at is None
        world["clock"].value += ACT_WINDOW - timedelta(seconds=1)
        assert recover(db, world["admin"], {}, clock=world["clock"]).released == 0
        assert (
            select_held_claims(db, world["admin"], grace=RUN_GRACE, limit=50, clock=world["clock"])
            == []
        )
        assert release_claim(db, world["admin"], execution_id, world["clock"]) is False
        world["clock"].value += timedelta(seconds=2)
        assert recover(db, world["admin"], {}, clock=world["clock"]).released == 1
        freed = retained(admin_engine, tenant, execution_id)
        assert freed.released_at == world["clock"].now()
        # Nothing was refunded: the impact moved from unresolved to confirmed rather than
        # away, and both rules count the one target they counted before the theft.
        assert (freed.state, freed.tier, freed.impact) == ("EXECUTED", "ASSERTED", "CONFIRMED")
        assert _counts(db, world, world["identity"], execution_id) == {
            "principal": (1, 0),
            "tenant": (1, 0),
        }
        # The genuine post hook arrives afterwards and is answered with the settled view:
        # it restates what the theft settled, so the kernel moves nothing and appends
        # nothing, and the extension marks its row settled and drops the secret it held.
        head = audit_head(admin_engine, tenant)
        answer = post(driver, success=True)
    assert answer.json() == {"code": "OK"}
    assert audit_head(admin_engine, tenant) == head
    assert retained(admin_engine, tenant, execution_id).state == "EXECUTED"
    stated = correlation_rows(admin_engine, tenant)["arcade-execution-1"]
    assert (stated["report_secret"], stated["reported_success"]) == (None, True)
    assert stated["settled_at"] == world["clock"].now()
    assert [payload["reason"] for payload in claim_releases(admin_engine, tenant)] == [
        "ACT_WINDOW_CLOSED"
    ]


def test_al20_an_unreported_grant_is_swept_and_the_signed_settlement_is_its_exit(
    db, arcade_world, seeded, admin_engine
):
    """AL20's first half: a tool call nobody reports on, and the exit it takes.

    Silence is the residual wedge of the post hook table and limitation 2, and this is what it costs
    a tenant. The sweep settles nothing: it moves the grant into retained uncertainty, where
    the impact goes on charging the scopes it was reserved in — `usage` counts an unresolved
    row with no time filter at all — and the canonical claim goes on holding the target, and
    where the uncertain queue lists it. A report presented after the window is refused on
    the outcome route, and the post hook that would carry one never reaches that refusal:
    the extension clears a secret whose window has closed on its next read of the row, so
    the post path finds none to present. Either way the control point's late word settles
    nothing and the route still answers `OK`.

    The exit taken here is the administrator's, signed by the key the first operator
    obligation in `docs/ARCADE.md` tells the tenant to hold somewhere no control point can
    reach: it settles the row at `ATTESTED`, confirms the impact and releases the claim, and
    the cap slot drains with it. Limitation 14 is the tenant that reported that key
    compromised, where this settlement is frozen along with every other one for a grant
    issued before it.
    """
    world, tenant = arcade_world, arcade_world["identity"].tenant_id
    admin = long_lived_admin(admin_engine, db, world)
    with admin_engine.begin() as conn:
        # A credential of the hook's own principal that outlives the report window, so the
        # late post hook below is refused for being late rather than for being expired.
        late_token = provision_credential(
            conn, tenant, world["identity"].principal_id, world["clock"].now(), timedelta(days=3)
        )
    with arcade_client(db, world, seeded) as driver:
        execution_id = _granted_hook(driver, admin_engine, tenant, "arcade-execution-1")
        held_secret = correlation_rows(admin_engine, tenant)["arcade-execution-1"]["report_secret"]
        window = grant_row(admin_engine, tenant, execution_id)["report_expires_at"]
        # Due for examination and not due to be swept: inside its window the platform may
        # still report, so the run says the grant is open and leaves it as admission
        # committed it.
        world["clock"].value = window - timedelta(seconds=1)
        early = recover(db, admin, {}, clock=world["clock"])
        assert (early.examined, early.open_grants, early.swept) == (1, 1, 0)
        assert retained(admin_engine, tenant, execution_id).state == "DISPATCH_COMMITTED"
        world["clock"].value = window
        swept = recover(db, admin, {}, clock=world["clock"])
        assert (swept.examined, swept.swept, swept.unresolved) == (1, 1, 0)
        uncertain = retained(admin_engine, tenant, execution_id)
        assert (uncertain.state, uncertain.impact, uncertain.tier) == (
            "INDETERMINATE",
            "UNRESOLVED",
            None,
        )
        assert uncertain.released_at is None
        assert _outstanding(db, world) == 1
        assert _uncertain_queue(db, world, admin) == [execution_id]
        # What closes this route is the window, asserted on the outcome route itself with
        # the secret the row held before the extension cleared it, and on a credential of
        # the same principal that outlives the window.
        with pytest.raises(ExecutionError) as expired:
            report(
                db,
                world,
                execution_id,
                held_secret,
                second_credential(admin_engine, db, world, lifetime=timedelta(days=3)),
            )
        assert expired.value.code == "REPORT_WINDOW_CLOSED"
        # The control point's own late word settles nothing either, and the route still
        # answers `OK`. It does not reach that refusal: the extension clears a secret whose
        # window has closed on the next read it makes of the row, so the post path finds
        # none to present.
        head = audit_head(admin_engine, tenant)
        late = post(driver, token=late_token, success=True)
        assert late.json() == {"code": "OK"}
        assert audit_head(admin_engine, tenant) == head
        assert retained(admin_engine, tenant, execution_id).state == "INDETERMINATE"
        assert correlation_rows(admin_engine, tenant)["arcade-execution-1"]["report_secret"] is None
        # A second run has no exit to take either, and says so rather than calling a row
        # nobody can move unresolved.
        world["clock"].value += timedelta(seconds=301)
        again = recover(db, admin, {}, clock=world["clock"])
        assert (again.examined, again.swept, again.uncertain_grants, again.unresolved) == (
            1,
            0,
            1,
            0,
        )
        assert retained(admin_engine, tenant, execution_id).state == "INDETERMINATE"
    view = reconcile(
        db,
        admin,
        execution_id,
        reason="settled from the executor's own record",
        evidence=signed(db, world, execution_id, {}),
        verifier=verifier(db, world, execution_id),
        clock=world["clock"],
    )
    assert view.state == "EXECUTED"
    exited = retained(admin_engine, tenant, execution_id)
    assert (exited.state, exited.tier, exited.impact) == ("EXECUTED", "ATTESTED", "CONFIRMED")
    assert exited.released_at == world["clock"].now()
    assert _outstanding(db, world) == 0
    assert _uncertain_queue(db, world, admin) == []


def test_al20_eight_silent_grants_cap_the_project_until_one_is_settled(
    db, arcade_world, seeded, admin_engine
):
    """AL20's second half: the cap of eight, reached through the carrier and drained by it.

    Eight tool calls whose post hooks state no result leave eight rows in retained
    uncertainty, each still charging and still holding its target, and the cap counts the
    unsettled set rather than one state — so the ninth tool call of the project is refused
    `TOO_MANY_GRANTS` with nothing left behind. That is limitation 3's wedge: eight silent
    rows anywhere in the project stop the whole project, because a project is one principal.

    What drains it is a settlement. The sweep of the row above moved a grant into retained
    uncertainty and left it counted; here one reported failure closes its row terminally,
    which is exactly what the earlier mapping of `success: false` to `UNKNOWN` denied a
    tenant, and the next tool call is answered `OK` with a grant of its own.
    """
    world, tenant = arcade_world, arcade_world["identity"].tenant_id
    devices = [f"device-2{index}" for index in range(MAX_GRANTS + 1)]
    for device in devices:
        governed_target(admin_engine, world, device)
    with arcade_client(db, world, seeded) as driver:
        granted = []
        for index, device in enumerate(devices[:MAX_GRANTS]):
            granted.append(_granted_hook(driver, admin_engine, tenant, f"arcade-{index}", device))
            silent = post(driver, execution_id=f"arcade-{index}")
            assert silent.json() == {"code": "OK"}
        uncertain = [retained(admin_engine, tenant, row) for row in granted]
        assert [(row.state, row.impact, row.released_at) for row in uncertain] == [
            ("INDETERMINATE", "UNRESOLVED", None)
        ] * MAX_GRANTS
        assert _outstanding(db, world) == MAX_GRANTS
        before = _reserved(admin_engine, tenant)
        ninth = pre(driver, execution_id="arcade-ninth", inputs={"device_id": devices[-1]})
        assert ninth.json() == {"code": "CHECK_FAILED", "error_message": "TOO_MANY_GRANTS"}
        # Refused inside the fence and before anything was reserved: no execution, no
        # impact row and no claim on the target it named.
        assert _reserved(admin_engine, tenant) == before
        assert len(execution_states(admin_engine, tenant)) == MAX_GRANTS
        refused = correlation_rows(admin_engine, tenant)["arcade-ninth"]
        assert (refused["decision"], refused["execution_id"]) == ("CHECK_FAILED", None)
        failure = post(driver, execution_id="arcade-0", success=False)
        assert failure.json() == {"code": "OK"}
        assert retained(admin_engine, tenant, granted[0]).state == "FAILED_EFFECT_UNKNOWN"
        assert _outstanding(db, world) == MAX_GRANTS - 1
        tenth = pre(driver, execution_id="arcade-tenth", inputs={"device_id": devices[-1]})
    assert tenth.json() == {"code": "OK"}
    admitted = correlation_rows(admin_engine, tenant)["arcade-tenth"]
    assert admitted["execution_id"] not in granted
    assert (
        store.ticket_digest(admitted["report_secret"])
        == grant_row(admin_engine, tenant, admitted["execution_id"])["owner_hash"]
    )
    assert _outstanding(db, world) == MAX_GRANTS


def _pending_approval(admin_engine, tenant):
    """The one approval this tenant is holding open; a step that left two would fail here."""
    [pending] = [row for row in _approvals(admin_engine, tenant) if row["state"] == "PENDING"]
    return pending["approval_id"]


def _approve(db, world, admin_engine):
    """A scoped human decides the open approval, against this deployment's own catalog."""
    decide_approval(
        db,
        world["human"],
        _pending_approval(admin_engine, world["identity"].tenant_id),
        "APPROVE",
        world["clock"],
        catalog=CATALOG,
    )


def test_al19_a_hook_and_an_agent_dispatch_charge_one_ceiling_in_every_scope(
    db, arcade_world, seeded, admin_engine, owner
):
    """AL19: one tenant, two carriers, one set of counters.

    The pre hook writes the same `UNRESOLVED` impact row an ordinary agent request writes,
    with the same retained scope attributes, so each of this bundle's six rules counts both
    and neither path has a budget of its own. The two budgets a rule may carry are both
    here: a total one that denies, which both paths spend from and which either path is
    refused by once it is reached, and an autonomous one that escalates, which an approved
    candidate is exempt from on both paths — a hook retried after a human decision and an
    agent retrying its own request each add a target to the total and none to the
    autonomous count.

    An agent outside the group and outside the principal scope goes first, so those two
    scope predicates are asserted against a tenant that already holds a row neither of them
    counts; without it they would be asserted by a tenant in which every row satisfies
    them. The account and selector predicates are not isolated here — every row of this
    world shares one account and one set of facts — and what isolates each of them is
    `tests/test_limit_scopes.py`'s SL2 and SL3.
    """
    world, tenant = arcade_world, arcade_world["identity"].tenant_id
    triage = group(owner, world, world["identity"], name="triage")
    outsider = agent(admin_engine, db, world)
    direct_operation(admin_engine, world)
    governed_bundle(
        db,
        world,
        direct=True,
        limits=(
            rule(rule_id="principal", scope="principal", max_targets=50, on_exceed="DENY"),
            rule(
                rule_id="group",
                scope="group",
                group_id=triage,
                max_targets=50,
                on_exceed="DENY",
            ),
            rule(
                rule_id="account",
                scope="account",
                account_id=world["account"],
                max_targets=50,
                on_exceed="DENY",
            ),
            rule(
                rule_id="selector",
                scope="selector",
                selector=LimitSelector(fact="exposure", equals="internal"),
                max_targets=50,
                on_exceed="DENY",
            ),
            rule(rule_id="ceiling", scope="tenant", max_targets=5, on_exceed="DENY"),
            rule(
                rule_id="autonomous",
                scope="tenant",
                max_targets=3,
                budget="autonomous",
                on_exceed="REQUIRE_APPROVAL",
            ),
        ),
    )
    devices = [f"device-1{index}" for index in range(7)]
    for device in devices:
        governed_target(admin_engine, world, device, approver=world["human"].principal_id)
    mine = world["identity"]
    with arcade_client(db, world, seeded) as driver:
        outside = _dispatch(db, world, outsider, devices[0], "outsider-1")
        assert outside.ticket is not None and outside.view.state == "DISPATCH_COMMITTED"
        # Counted by the four rules whose scope this row satisfies — the account, the
        # frozen fact and the two tenant ceilings — and by neither narrow one: the outsider
        # is another principal and is in no group.
        assert _counts(db, world, mine, outside.view.execution_id) == {
            "principal": (0, 0),
            "group": (0, 0),
            "account": (0, 1),
            "selector": (0, 1),
            "ceiling": (0, 1),
            "autonomous": (0, 1),
        }
        hooked = _granted_hook(driver, admin_engine, tenant, "arcade-execution-1", devices[1])
        assert _counts(db, world, mine, hooked) == {
            "principal": (0, 1),
            "group": (0, 1),
            "account": (0, 2),
            "selector": (0, 2),
            "ceiling": (0, 2),
            "autonomous": (0, 2),
        }
        dispatched = _dispatch(db, world, mine, devices[2], "agent-1")
        assert dispatched.ticket is not None
        # The agent's own dispatch adds exactly what the hook added, in every scope: one
        # unit to each of the six rules, against one ceiling rather than a budget of its own.
        assert _counts(db, world, mine, dispatched.view.execution_id) == {
            "principal": (0, 2),
            "group": (0, 2),
            "account": (0, 3),
            "selector": (0, 3),
            "ceiling": (0, 3),
            "autonomous": (0, 3),
        }
        # The autonomous ceiling is reached across the two paths together, and what it does
        # is escalate: the hook is told to wait, a human decides, and the retry reserves.
        escalated = pre(driver, execution_id="arcade-execution-2", inputs={"device_id": devices[3]})
        waiting = UUID(str(_execution_in_state(admin_engine, tenant, "PENDING_APPROVAL")))
        assert escalated.json() == {
            "code": "CHECK_FAILED",
            "error_message": f"PENDING_APPROVAL execution={waiting}",
        }
        _approve(db, world, admin_engine)
        approved_hook = pre(
            driver, execution_id="arcade-execution-3", inputs={"device_id": devices[3]}
        )
        assert approved_hook.json() == {"code": "OK"}
        assert _counts(db, world, mine, waiting) == {
            "principal": (0, 3),
            "group": (0, 3),
            "account": (0, 4),
            "selector": (0, 4),
            "ceiling": (0, 4),
            "autonomous": (0, 3),
        }
        # The same exemption on the agent path: its own retry consumes the approval and
        # reserves, and the autonomous count is where it was.
        agent_request = _direct_request(devices[4], "agent-2")
        pending = admit(db, mine, agent_request, world["clock"], catalog=CATALOG)
        assert pending.ticket is None and pending.view.state == "PENDING_APPROVAL"
        _approve(db, world, admin_engine)
        committed = admit(db, mine, agent_request, world["clock"], catalog=CATALOG)
        assert committed.ticket is not None and committed.view.state == "DISPATCH_COMMITTED"
        assert _counts(db, world, mine, committed.view.execution_id) == {
            "principal": (0, 4),
            "group": (0, 4),
            "account": (0, 5),
            "selector": (0, 5),
            "ceiling": (0, 5),
            "autonomous": (0, 3),
        }
        # The total ceiling is now spent, and it is spent for both carriers at once.
        denied_hook = pre(
            driver, execution_id="arcade-execution-4", inputs={"device_id": devices[5]}
        )
        refused = UUID(str(_execution_in_state(admin_engine, tenant, "DENIED")))
        assert denied_hook.json() == {
            "code": "CHECK_FAILED",
            "error_message": f"DENIED execution={refused}",
        }
        denied_agent = _dispatch(db, world, mine, devices[6], "agent-3")
    assert denied_agent.ticket is None and denied_agent.view.state == "DENIED"
    # Five reservations between the two paths and two denials that reserved nothing, which
    # is the ceiling reached once across them rather than once each.
    # Sorted rather than in order: this world's clock is fixed, so every reservation
    # carries the same instant and the retained order is the execution id's.
    assert sorted(row["approved"] for row in impact_rows(admin_engine, tenant)) == [
        False,
        False,
        False,
        True,
        True,
    ]
    assert (
        sorted(execution_states(admin_engine, tenant))
        == ["DENIED"] * 2 + ["DISPATCH_COMMITTED"] * 5
    )


def test_al19_a_group_ceiling_is_reached_across_two_arcade_projects_of_one_tenant(
    db, arcade_world, seeded, admin_engine, owner
):
    """AL19's second half: a scope wider than a project, spent by whichever project gets there.

    One Arcade project is one ExecBound principal, so a rule scoped to a group of them is
    how an operator bounds what a tenant's control points do between them. The ceiling is
    the group's: the two projects reach it together, and each of them is refused afterwards
    — including the one that spent a single unit of the two — which for the tool call is
    `CHECK_FAILED` and for the agent behind it a blocked call. A third project outside the
    group is in no part of that, which is what says the rule's own scope is what decided.
    """
    world, tenant = arcade_world, arcade_world["identity"].tenant_id
    mine = world["identity"]
    second, second_token = _second_project(db, world, admin_engine)
    outside, outside_token = _second_project(db, world, admin_engine)
    projects = group(owner, world, mine, second, name="arcade-projects")
    governed_bundle(
        db,
        world,
        limits=(
            rule(
                rule_id="projects",
                scope="group",
                group_id=projects,
                max_targets=2,
                on_exceed="DENY",
            ),
        ),
    )
    devices = [f"device-4{index}" for index in range(4)]
    for device in devices:
        governed_target(admin_engine, world, device)
    with arcade_client(db, world, seeded) as driver:
        first = pre(driver, execution_id="project-one", inputs={"device_id": devices[0]})
        together = pre(
            driver, token=second_token, execution_id="project-two", inputs={"device_id": devices[1]}
        )
        assert (first.json(), together.json()) == ({"code": "OK"}, {"code": "OK"})
        # The ceiling is the group's, so it is reached across the two projects and denies
        # each of them next — including the project that spent only one of the two units.
        refused_second = pre(
            driver,
            token=second_token,
            execution_id="project-two-again",
            inputs={"device_id": devices[2]},
        )
        refused_first = pre(
            driver, execution_id="project-one-again", inputs={"device_id": devices[2]}
        )
        unaffected = pre(
            driver,
            token=outside_token,
            execution_id="project-three",
            inputs={"device_id": devices[3]},
        )
    for answer, identity, arcade_id in (
        (refused_second, second, "project-two-again"),
        (refused_first, mine, "project-one-again"),
    ):
        denied = _project_row(admin_engine, tenant, identity, arcade_id)["execution_id"]
        assert answer.json() == {
            "code": "CHECK_FAILED",
            "error_message": f"DENIED execution={denied}",
        }
        assert transition_payload(admin_engine, tenant, denied, "DENIED")["reasons"] == [
            "HARD_LIMIT:projects"
        ]
    # The third project is in no group the rule names, so the rule counts none of its rows
    # and bounds none of its calls.
    assert unaffected.json() == {"code": "OK"}
    granted = _project_row(admin_engine, tenant, outside, "project-three")["execution_id"]
    assert impact_groups(admin_engine, tenant)[granted] == []
    assert sorted(impact_groups(admin_engine, tenant).values()) == [
        [],
        [str(projects)],
        [str(projects)],
    ]
    with db.transaction(tenant) as conn:
        assert [
            store.outstanding_grants(conn, tenant, identity.principal_id)
            for identity in (mine, second, outside)
        ] == [1, 1, 1]


def test_two_projects_of_one_tenant_share_the_target_claim_and_not_the_grant_cap(
    db, arcade_world, seeded, admin_engine
):
    """Limitation 15's residue, read off the code rather than taken from the list.

    The list says two projects of one tenant still share the canonical target claim and the
    shared limit scopes, and that the grant cap is not among them because
    `outstanding_grants` counts by principal. Both halves are asserted here: admission's
    busy check selects `resource_claims` on the tenant and the canonical target with no
    principal in it, so one project's unsettled grant denies the other's call for that
    endpoint; and the cap's own count carries `principal_id`, so a project wedged at eight
    unsettled grants counts none of them against the other project's cap.

    The shared-scope half is the group ceiling above, whose rule spans the two projects.
    """
    world, tenant = arcade_world, arcade_world["identity"].tenant_id
    mine = world["identity"]
    second, second_token = _second_project(db, world, admin_engine)
    with arcade_client(db, world, seeded) as driver:
        held = _granted_hook(driver, admin_engine, tenant, "project-one")
        contested = pre(driver, token=second_token, execution_id="project-two")
        denied = _project_row(admin_engine, tenant, second, "project-two")["execution_id"]
        assert contested.json() == {
            "code": "CHECK_FAILED",
            "error_message": f"DENIED execution={denied}",
        }
        assert transition_payload(admin_engine, tenant, denied, "DENIED")["reason"] == (
            "RESOURCE_BUSY"
        )
        assert retained(admin_engine, tenant, held).released_at is None
        # The cap is the half they do not share. Eight unsettled grants of this project,
        # admitted through the kernel the way AL5's own setup admits them.
        for index in range(MAX_GRANTS - 1):
            device = f"device-5{index}"
            governed_target(admin_engine, world, device)
            filler = admit(
                db,
                mine,
                _governed_request(device, f"filler-{index}"),
                world["clock"],
                available_accounts=frozenset(),
                catalog=CATALOG,
                attestable=attestable_ring,
            )
            assert filler.view.state == "DISPATCH_COMMITTED"
        governed_target(admin_engine, world, "device-59")
        wedged = pre(driver, execution_id="project-one-ninth", inputs={"device_id": "device-59"})
        theirs = pre(
            driver,
            token=second_token,
            execution_id="project-two-first",
            inputs={"device_id": "device-59"},
        )
    assert wedged.json() == {"code": "CHECK_FAILED", "error_message": "TOO_MANY_GRANTS"}
    # The other project's own call for the same endpoint is decided on its own cap and is
    # answered `OK`, because the first project never reserved anything for that target.
    assert theirs.json() == {"code": "OK"}
    with db.transaction(tenant) as conn:
        assert store.outstanding_grants(conn, tenant, mine.principal_id) == MAX_GRANTS
        assert store.outstanding_grants(conn, tenant, second.principal_id) == 1


# ---------------------------------------------------------------------------------------
# AL32: the granting path, timed. Every node above asserts what a hook decides; this one
# measures what deciding costs, because `deadline_seconds` is required of the deployment
# and a number nobody measured this path for is a number nobody can defend.

# The concurrencies the granting-path measurement in `docs/ARCADE.md` names. Sixteen is
# above this fixture deployment's own hook bound — `hook_slots_for` derives that bound from
# the pool the test database hands the runtime — so what the surface answered above it is
# reported here rather than dropped, and the level is not lowered to the bound.
AL32_LEVELS = (1, 4, 16)
# One caller is one Arcade project, which is one ExecBound principal. Sixteen projects
# rather than sixteen tool calls of one: `outstanding_grants` counts by principal against
# `MAX_GRANTS`, so from the ninth call of a single project the measurement would be timing
# `TOO_MANY_GRANTS` instead of a grant.
AL32_CALLERS = max(AL32_LEVELS)


def _al32_devices(admin_engine, world, level, first):
    """One endpoint per caller, each carrying the risk that sends it to a human first.

    A grant holds its target's canonical claim until it settles, so two callers naming one
    endpoint would be measuring `RESOURCE_BUSY` on the second rather than a second grant.
    The default facts carry a risk of 70 and `APPROVE_RISKY` sends anything from 60 to an
    approval, which is what puts an approval in front of each timed hook.
    """
    devices = [f"device-al32-{first + index}" for index in range(level)]
    for device in devices:
        governed_target(admin_engine, world, device, approver=world["human"].principal_id)
    return devices


def _al32_approved(db, world, admin_engine, callers, devices, tag):
    """Leave each caller one hook away from a grant: pending, then decided by a human.

    The waiting hook is refused, and what it leaves behind is an execution and an approval
    and nothing else — admission's approval branch runs before the cap and before anything
    is reserved, so it takes no canonical claim, writes no impact row, loads no key ring
    and mints no secret. Every one of those belongs to the hook that follows it, which is
    the hook this measurement times.
    """
    tenant = world["identity"].tenant_id
    for index, (caller, device) in enumerate(zip(callers, devices, strict=True)):
        waiting = caller.pre(
            f"{tag}-wait-{index}",
            execution_id=f"{tag}-wait-{index}",
            tool=tool_info(**GOVERNED_TOOL),
            inputs={"device_id": device},
        )
        assert waiting.code == "CHECK_FAILED"
        assert waiting.error_message is not None
        assert waiting.error_message.startswith("PENDING_APPROVAL execution=")
    for approval in _approvals(admin_engine, tenant):
        if approval["state"] == "PENDING":
            decide_approval(
                db,
                world["human"],
                approval["approval_id"],
                "APPROVE",
                world["clock"],
                catalog=CATALOG,
            )


def _al32_timed(callers, devices, tag):
    """The timed region: every caller released together, each timing its own pre hook.

    What the clock covers is the whole hook as the platform meets it — the request on the
    wire, the boundary, authentication, the tool map, the fenced admission that consumes
    the approval, reserves the impact, claims the target, asks the key ring whether a grant
    could be attested and mints the report secret, the correlation row's completion, and
    the answer back. The barrier is the limit-scopes pattern: what is being measured is
    what these callers cost each other, so they have to arrive together.
    """
    barrier = Barrier(len(callers))

    def granted(index):
        barrier.wait(timeout=60)
        started = time.perf_counter()
        answer = callers[index].pre(
            f"{tag}-grant-{index}",
            execution_id=f"{tag}-grant-{index}",
            tool=tool_info(**GOVERNED_TOOL),
            inputs={"device_id": devices[index]},
        )
        return time.perf_counter() - started, answer

    with ThreadPoolExecutor(max_workers=len(callers)) as pool:
        return list(pool.map(granted, range(len(callers))))


def _al32_render(measured, runtime, slots, deadline):
    """The figures, with what has to be read with them or they mean something they are not.

    Printed rather than asserted: the assertion is the relation `tests/test_arcade_deadline.py`
    holds, and these are the
    numbers to record beside `scripts/admission_benchmark.py`'s denied-path figures for the
    same concurrencies. `pytest -s` shows them.
    """
    lines = [
        "",
        f"AL32 granting path: deadline_seconds={deadline}, hook slots={slots}, "
        f"runtime concurrency={runtime.concurrency}, pool capacity={runtime.db.capacity}, "
        f"cpus={os.cpu_count()}, load average={tuple(round(x, 2) for x in os.getloadavg())}",
        "| Concurrency | Granted | Refused HOOK_CAPACITY | Median ms | Max ms |",
        "| --- | --- | --- | --- | --- |",
    ]
    for row in measured:
        lines.append(
            f"| {row['concurrency']} | {row['granted']} | {row['refused']} "
            f"| {row['median_ms']} | {row['max_ms']} |"
        )
    return "\n".join(lines)


def al32_measure(db, arcade_world, seeded, admin_engine, alone=None):
    """Grant at each of `AL32_LEVELS` behind one tenant's fence and return what was measured.

    Each level's timed region runs inside `alone(level)` when given (the machine's timing
    lock, for the deadline relation) and bare otherwise. The answers are held here, so the
    figures are a granting path's: `OK` or, above the hook bound, `HOOK_CAPACITY`, and a
    level at or below the bound is granted whole.
    """
    world = arcade_world
    governed_bundle(db, world, approval_policies=APPROVE_RISKY)
    block, runtime = hook_block(), approving_runtime(db, world)
    slots = routes.hook_slots_for(app_module.REQUESTS_IN_FLIGHT, runtime.concurrency)
    measured, granted_total, first, notes = [], 0, 0, []
    with arcade_boundary(db, world, seeded, block=block, runtime=runtime) as driver:
        callers = [
            FakeArcade(driver.client, _second_project(db, world, admin_engine)[1])
            for _ in range(AL32_CALLERS)
        ]
        for level in AL32_LEVELS:
            tag = f"al32-{level}"
            devices = _al32_devices(admin_engine, world, level, first)
            _al32_approved(db, world, admin_engine, callers[:level], devices, tag)
            if alone is None:
                results = _al32_timed(callers[:level], devices, tag)
            else:
                with alone(level) as machine:
                    results = _al32_timed(callers[:level], devices, tag)
                notes.append(f"{level}: {machine.note}")
            first += level
            answers = [(answer.code, answer.error_message) for _, answer in results]
            assert set(answers) <= {("OK", None), ("RATE_LIMIT_EXCEEDED", "HOOK_CAPACITY")}
            # Every caller that finds a free slot takes one, so a level at or below the
            # bound is granted whole and a level above it is granted at least the bound.
            latencies = sorted(elapsed for elapsed, answer in results if answer.code == "OK")
            assert len(latencies) >= min(level, slots)
            assert len(latencies) == level or level > slots
            granted_total += len(latencies)
            measured.append(
                {
                    "concurrency": level,
                    "granted": len(latencies),
                    "refused": len(results) - len(latencies),
                    "median_ms": round(statistics.median(latencies) * 1000, 1),
                    "max_ms": round(latencies[-1] * 1000, 1),
                }
            )
    print(_al32_render(measured, runtime, slots, block.deadline_seconds))
    return measured, granted_total, block, notes


def al32_assert_granted(admin_engine, tenant, granted_total):
    """What the timed regions did, so the figures are a granting path's and not a refusal's.

    One committed grant per timed `OK`, each holding its reservation and its claim, each
    having consumed the approval its waiting hook opened, and each retaining the digest of a
    secret minted inside that region. The key ring was loaded and asked in there too:
    `_attestable` runs on every row that reaches a grant, after the decision and before
    anything is reserved, so a ring it refused would have raised `INVALID_BUNDLE` instead of
    leaving these rows behind.
    """
    states = Counter(execution_states(admin_engine, tenant))
    assert states["DISPATCH_COMMITTED"] == granted_total
    # One execution per waiting hook and none opened by a timed one: the retry was adopted
    # onto the execution its own approval belongs to, which is what makes the consumption
    # below a consumption rather than a second decision.
    assert states.total() == sum(AL32_LEVELS)
    assert states["PENDING_APPROVAL"] == sum(AL32_LEVELS) - granted_total
    assert [impact["state"] for impact in impact_rows(admin_engine, tenant)] == [
        "UNRESOLVED"
    ] * granted_total
    assert [claim["released_at"] for claim in claim_rows(admin_engine, tenant)] == [
        None
    ] * granted_total
    assert Counter(row["state"] for row in _approvals(admin_engine, tenant))["CONSUMED"] == (
        granted_total
    )
    minted = [
        row
        for key, row in correlation_rows(admin_engine, tenant).items()
        if "-grant-" in key and row["decision"] == "OK"
    ]
    assert len(minted) == granted_total
    for row in minted:
        grant = grant_row(admin_engine, tenant, row["execution_id"])
        assert store.ticket_digest(row["report_secret"]) == grant["owner_hash"]
        assert grant["report_expires_at"] is not None


def test_al32_the_granting_path_grants_at_one_four_and_sixteen_callers(
    db, arcade_world, seeded, admin_engine
):
    """AL32: what an eligible pre hook grants, and costs, at one, four and sixteen callers.

    There is no default deadline, because a default would be a number
    chosen against a measurement of a path other than the one it has to survive. The
    denied-path benchmark is that other path: `scripts/admission_benchmark.py` drives
    **denied** admissions, which reserve nothing, take no canonical claim, consume no
    approval, load no executor key ring and issue no grant. Every hook timed here does all
    five in one fenced transaction, behind the deployment boundary a hook process serves:
    it consumes an approval a human decided, writes the impact row, takes the canonical
    claim, asks `attestable_ring` whether a grant could be attested afterwards, and mints
    the report secret whose digest the execution retains, with the grant appended to the
    tenant's hash chain. The two figures are a floor and a measurement of the same fence
    and belong together wherever they are recorded, because either alone reads as the
    other.

    **The deadline relation is a test of its own.** That the deadline this deployment's own
    file carries exceeds the slowest grant measured is asserted by
    `tests/test_arcade_deadline.py`, which measures the same path under the machine's timing
    lock and so is `timed`. This test, which takes no lock and is not `timed`, holds what the
    grants are: the answers, the committed grants with their claims, consumptions and minted
    secrets, and the figures printed beside them.

    **This is not a hosted figure**, which is limitation 11's own words: it is a fixture
    deployment against the test machine's PostgreSQL, with no gateway service sharing the
    connection pool and no hosted network in it. It is also not a quiet-machine figure —
    another suite may be running on the same machine, and the load average is printed with
    the numbers so a reader can see what they were measured under.

    **At four and sixteen callers the maximum is a queueing figure, not a latency figure.**
    `store.fence` takes the tenant's `tenant_policy_control` row `FOR UPDATE`, so one
    tenant's admissions serialize by design: of the callers a level admits, the last waits
    behind all the others, and the maximum grows with how many were admitted together. What
    it measures is the cost of the deadline having to cover a queue, which is exactly the
    number the deployment is setting the deadline against.

    **Sixteen callers exceed this deployment's own hook bound and the excess is reported.**
    `hook_slots_for` derives the bound from the application's in-flight bound and the
    runtime's concurrency, and the runtime's concurrency is `min(16, db.capacity)`, so the
    pool is what decides it: against the test fixture's pool this surface has fewer than
    sixteen slots, and a caller arriving to find none is answered `RATE_LIMIT_EXCEEDED`
    with `HOOK_CAPACITY`. The derived bound and the count of callers answered that way are
    printed with the figures rather than pinned here, because both move with the pool. Such
    an answer is not folded into the latency figures — a refusal is fast and is not a grant,
    so averaging it in would flatter the number — and the level stays at sixteen rather than
    being lowered to whatever the bound turns out to be.
    """
    tenant = arcade_world["identity"].tenant_id
    _measured, granted_total, _block, _notes = al32_measure(db, arcade_world, seeded, admin_engine)
    al32_assert_granted(admin_engine, tenant, granted_total)


def test_al32_a_deployment_file_that_names_no_deadline_is_refused_at_load(tmp_path, config):
    """AL32's other half: the number the measurement defends is one the file had to carry.

    The measurement above is worth nothing if a deployment can run without writing a
    deadline down, because then the number defended is a default nobody chose against any
    path. Both levels refuse: `ArcadeBlock`, the model the private file's `arcade` object is
    parsed into, and `load_runtime` over the whole file, which is what a deployment actually
    starts through and where the refusal is the same opaque answer every invalid file gets,
    quoting nothing of it. The configuration suite asserts the file half as well, in
    `test_the_arcade_deadline_is_required_with_no_default`; this node is AL32's own, in the
    file `docs/ACCEPTANCE_TESTS.md` places the row in, so the validation manifest's `AL`
    prefix counts the row rather than matching nothing.
    """
    naked = {key: value for key, value in deepcopy(ARCADE).items() if key != "deadline_seconds"}
    with pytest.raises(ValidationError):
        ArcadeBlock.model_validate_json(json.dumps(naked))
    config["arcade"] = deepcopy(ARCADE)
    assert load(tmp_path, config)[0] is not None
    config["arcade"] = naked
    with pytest.raises(ValueError, match="^Invalid runtime configuration$") as exc:
        load(tmp_path, config)
    assert exc.value.__context__ is None
