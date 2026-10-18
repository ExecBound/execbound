# SPDX-License-Identifier: AGPL-3.0-only
"""Shared decision, stale-authorization and rejection helpers for every writer."""

from typing import Any, Literal

from sqlalchemy.engine import Connection
from sqlalchemy.exc import SQLAlchemyError

from execbound.audit import acted_with, append_event
from execbound.contracts import PRODUCTION_CATALOG, Catalog
from execbound.db import Database
from execbound.execution import store
from execbound.execution.models import (
    Admission,
    ExecutionError,
)
from execbound.execution.scheduled import RecoveryActor, ScheduledActor, scheduled_check
from execbound.identity import Identity
from execbound.policy.approval import VerifiedApproval
from execbound.policy.evaluate import evaluate
from execbound.policy.models import BundleContent, PolicyEvaluation, UsageSnapshot
from execbound.resolution.models import Clock, ResolvedRequest
from execbound.resolution.registry import RESOLUTION_CODES, ResolutionError


def _rejection(
    db: Database,
    identity: RecoveryActor,
    operation: str,
    code: str,
    clock: Clock,
    *,
    actor_credential: bool = False,
    route: str | None = None,
    method: str | None = None,
) -> None:
    """Retain a scoped rejection after rollback, if identity and audit remain available.

    Invalid credentials establish no attributable principal. Surface authentication
    logging remains separate. Audit failure never permits the rejected operation.
    ``actor_credential`` adds the credential that acted, as administration events carry it:
    a personal access token's refusals name its backing credential, which is the token.
    ``route`` and ``method`` add what was refused, when the caller knows it; a refusal that
    names neither is written exactly as before. A scheduled pass's refusal (#503) names its
    scheduler principal, and one refused before it had anything to attribute names nobody
    and is not retained.
    """
    actor = identity.principal_id
    if actor is None:
        return
    credential = (
        identity.credential_id if actor_credential and isinstance(identity, Identity) else None
    )
    payload: dict[str, str | None] = {
        "operation": operation,
        "reason": code,
        **acted_with(credential),
    }
    if route is not None or method is not None:
        payload["route"] = route
        payload["method"] = method
    try:
        with db.transaction(identity.tenant_id) as conn:
            _still(conn, identity, clock)
            # Lock order (docs/EXECUTION.md): tenant control, then audit head, then row writes.
            store.fence(conn, identity.tenant_id, clock)
            _still(conn, identity, clock)
            append_event(conn, identity.tenant_id, actor, "execution.rejected", payload)
            _still(conn, identity, clock)
    except (SQLAlchemyError, ValueError):
        return


def resolution_reason(error: ResolutionError, fallback: str) -> str:
    """The reason a resolution refusal is audited with: its own code, from the closed list.

    Before #545 admission audited every one but bad arguments as
    `DEPENDENCY_OR_CONTEXT_UNAVAILABLE`, so a person could not tell an unknown action from an
    unknown target or an expired fact. A code outside the list, which the kernel never raises,
    is recorded as the caller's own generic reason, `fallback`, the one that caller already
    records for an unexpected failure, so no path's generic reason changes; existing audit
    rows are history and keep what they say.
    """
    return error.code if error.code in RESOLUTION_CODES else fallback


def _still(conn: Connection, identity: RecoveryActor, clock: Clock) -> None:
    """A rejection's own recheck: the identity's own kind, or the scheduled check (#503)."""
    if isinstance(identity, ScheduledActor):
        scheduled_check(conn, identity)
    else:
        store.identity_check(conn, identity, clock, identity.kind)


def _stale(
    conn: Connection,
    row: dict[str, Any],
    identity: RecoveryActor,
    clock: Clock,
    approval: dict[str, Any] | None,
    reason: str = "STALE_AUTHORIZATION",
) -> Admission:
    actor = identity.principal_id
    if actor is None:
        # The scheduled pass enlists before it ends anything (#503); an actor with nothing to
        # attribute never reaches a transition.
        raise ExecutionError("INVALID_IDENTITY")
    if approval and approval["state"] in {"PENDING", "APPROVED"}:
        state = "EXPIRED" if store.now(clock) >= approval["expires_at"] else "INVALIDATED"
        store.approval_state(conn, row, approval, actor, state, clock)
    store.transition(conn, row, actor, "STALE_AUTHORIZATION", clock, reason=reason)
    return Admission(store.view(conn, row))


def _decision(
    conn: Connection,
    identity: Identity,
    bundle: BundleContent,
    frozen: ResolvedRequest,
    clock: Clock,
    approval: VerifiedApproval | None = None,
    *,
    row: dict[str, Any],
    stage: Literal["ADMISSION", "APPROVAL_REVIEW"] = "ADMISSION",
    reviewer: Identity | None = None,
    human_decision: Literal["APPROVE", "DENY"] | None = None,
    catalog: Catalog = PRODUCTION_CATALOG,
    mode: Literal["ENFORCE", "OBSERVE"] = "ENFORCE",
) -> tuple[PolicyEvaluation, UsageSnapshot]:
    """Evaluate and capture; the snapshot comes back so a reservation writes what was counted."""
    # Replay contracts also import execution models; defer capture until use.
    from execbound.replay.capture import ObservedClock, record_decision

    usage_clock, decision_clock = ObservedClock(clock), ObservedClock(clock)
    usage = store.usage(
        conn, identity, bundle, usage_clock, frozen=frozen, observed=mode == "OBSERVE"
    )
    decision = evaluate(
        bundle=bundle,
        identity=identity,
        resolved=frozen,
        usage=usage,
        clock=decision_clock,
        approval=approval,
        catalog=catalog,
    )
    if not decision_clock.samples:
        raise ExecutionError("INVALID_CLOCK")
    record_decision(
        conn,
        row,
        identity,
        bundle,
        frozen,
        decision,
        clock,
        usage_time=usage_clock.samples[0],
        semantic_time=decision_clock.samples[0],
        finished_time=decision_clock.samples[-1],
        approval=approval,
        stage=stage,
        reviewer=reviewer,
        human_decision=human_decision,
        mode=mode,
        groups=usage.groups,
        space=usage.space_id,
    )
    return decision, usage
