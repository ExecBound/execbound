# SPDX-License-Identifier: AGPL-3.0-only
"""The scoped human decision on one pending approval."""

from typing import Literal
from uuid import UUID

from sqlalchemy import text
from sqlalchemy.exc import SQLAlchemyError

from execbound.audit import append_event
from execbound.contracts import PRODUCTION_CATALOG, Catalog
from execbound.db import Database
from execbound.execution import store
from execbound.execution.authority import _decision, _rejection, _stale, resolution_reason
from execbound.execution.models import (
    AuthorityCheck,
    ExecutionError,
    ExecutionView,
)
from execbound.execution.snapshot import attest_snapshot
from execbound.identity import Identity
from execbound.policy.approval import VerifiedApproval
from execbound.resolution.models import Clock, SystemClock
from execbound.resolution.registry import ResolutionError
from execbound.signals.resolve import SignalScope
from execbound.spaces import is_archived, principal_allows


def _comment(comment: object) -> str | None:
    """A reviewer's note for the audit event: bounded, printable and free of secrets."""
    if comment is None:
        return None
    # Replay contracts also import execution models; defer the import until use.
    from execbound.replay.verify import ReplayValidationError, reject_secrets

    if not isinstance(comment, str):
        raise ExecutionError("INVALID_COMMENT")
    value = comment.strip()
    if not 1 <= len(value) <= 500 or any(not (c.isprintable() or c == "\n") for c in value):
        raise ExecutionError("INVALID_COMMENT")
    try:
        reject_secrets(value)
    except ReplayValidationError:
        raise ExecutionError("INVALID_COMMENT") from None
    return value


def decide_approval(
    db: Database,
    human: Identity,
    approval_id: UUID | None,
    decision: Literal["APPROVE", "DENY"],
    clock: Clock | None = None,
    *,
    authority_check: AuthorityCheck | None = None,
    catalog: Catalog = PRODUCTION_CATALOG,
    comment: str | None = None,
) -> ExecutionView:
    clock = clock or SystemClock()
    try:
        if decision not in {"APPROVE", "DENY"} or approval_id is None:
            raise ExecutionError("INVALID_DECISION")
        comment = _comment(comment)
        with db.transaction(human.tenant_id) as conn:
            store.review_identity_check(conn, human, clock)
            # Lock order (docs/EXECUTION.md): tenant control, then audit head, then row writes.
            store.fence(conn, human.tenant_id, clock)
            if authority_check is not None:
                authority_check(conn)
            if store.stop(conn, human.tenant_id) is not None:
                raise ExecutionError("TENANT_STOPPED")
            execution = conn.execute(
                text(
                    "SELECT execution_id FROM execbound.approvals "
                    "WHERE tenant_id=:t AND approval_id=:a"
                ),
                {"t": human.tenant_id, "a": approval_id},
            ).scalar_one_or_none()
            if execution is None:
                raise ExecutionError("NOT_FOUND")
            row = store.read(conn, human.tenant_id, execution)
            # The space is rechecked inside the kernel's own transaction, beside the
            # injected authority check and under the same tenant fence the archive takes,
            # so an archive and a decision racing have exactly one winner: whichever takes
            # the fence first commits and the other is refused. Membership is the
            # authority, so a person removed from the space since they read the queue is
            # refused here rather than by the page.
            if not principal_allows(conn, human.tenant_id, human.principal_id, row["space_id"]):
                raise ExecutionError("NOT_FOUND")
            if is_archived(conn, human.tenant_id, row["space_id"]):
                raise ExecutionError("SPACE_ARCHIVED")
            store.scope_check(conn, human, row, clock)
            approval = store.approval_row(conn, row)
            if not approval or approval["state"] != "PENDING" or row["state"] != "PENDING_APPROVAL":
                raise ExecutionError("INVALID_STATE")
            if any(
                decided["principal_id"] == human.principal_id
                for decided in store.approval_decisions(
                    conn, human.tenant_id, approval["approval_id"]
                )
            ):
                # One decision per person: a second credential is still the same principal.
                raise ExecutionError("INVALID_STATE")
            frozen = store.frozen(row)
            valid = True
            try:
                agent = store.persisted_identity(
                    conn, human.tenant_id, row["principal_id"], row["credential_id"], "AGENT", clock
                )
                # The **execution's** space selects the bundle a decision is weighed
                # under, not the deciding person's view of the tenant.
                bundle = store.active_bundle(conn, human.tenant_id, row["space_id"])
                frozen_bundle = (
                    bundle
                    if bundle.bundle_id == row["bundle_id"]
                    else store.bundle(conn, human.tenant_id, row["bundle_id"])
                )
                attest_snapshot(
                    conn,
                    agent,
                    frozen,
                    row["canonical_target_id"],
                    clock,
                    settings=frozen_bundle.context_settings,
                    catalog=catalog,
                    signals=SignalScope(frozen_bundle.signal_mappings, row["space_id"]),
                )
                # The scoped, currently authenticated human is deciding this
                # exact pending approval. Evaluate the proposed approved charge
                # before persisting the decision; total hard limits still apply.
                candidate = (
                    VerifiedApproval(
                        approval["approval_id"],
                        human.tenant_id,
                        row["principal_id"],
                        approval["bundle_id"],
                        approval["plan_hash"],
                        tuple(approval["obligation_ids"]),
                        approval["expires_at"],
                    )
                    if decision == "APPROVE"
                    else None
                )
                current, _ = _decision(
                    conn,
                    agent,
                    bundle,
                    frozen,
                    clock,
                    candidate,
                    row=row,
                    stage="APPROVAL_REVIEW",
                    reviewer=human,
                    human_decision=decision,
                    catalog=catalog,
                )
                valid = (
                    bundle.bundle_id == row["bundle_id"]
                    and current.effect != "DENY"
                    and current.obligation_ids == tuple(approval["obligation_ids"])
                    and store.now(clock) < approval["expires_at"]
                )
            except ExecutionError as error:
                # Membership beyond the configured bound is an owner-data defect, not a
                # stale decision: fail the review closed without touching the approval.
                if error.code == "INVALID_CONFIGURATION":
                    raise
                valid = False
            except ValueError:
                valid = False
            if not valid:
                _stale(conn, row, human, clock, approval)
            else:
                decided_at = store.now(clock)
                decisions = store.record_decision(
                    conn, human.tenant_id, approval, human, decision, decided_at
                )
                required = int(approval.get("required_approvers", 1) or 1)
                approvals_so_far = sum(1 for d in decisions if d["decision"] == "APPROVE")
                if decision == "APPROVE" and approvals_so_far < required:
                    # A partial quorum: the decision is on record and the approval waits.
                    append_event(
                        conn,
                        human.tenant_id,
                        human.principal_id,
                        "approval.decision_recorded",
                        {
                            "execution_id": str(row["execution_id"]),
                            "approval_id": str(approval["approval_id"]),
                            "plan_hash": row["plan_hash"],
                            "binding": store.approval_binding(approval, decisions),
                            "replay": {"version": 1, "semantic_time": decided_at.isoformat()},
                            **({"comment": comment} if comment is not None else {}),
                        },
                    )
                    store.identity_check(conn, agent, clock, "AGENT")
                    store.scope_check(conn, human, row, clock)
                    result = store.view(conn, row)
                    if authority_check is not None:
                        authority_check(conn)
                    return result
                conn.execute(
                    text(
                        "UPDATE execbound.approvals SET decided_by=:p,"
                        "decided_credential_id=:c,decided_at=:n "
                        "WHERE tenant_id=:t AND approval_id=:a"
                    ),
                    {
                        "p": human.principal_id,
                        "c": human.credential_id,
                        "n": decided_at,
                        "t": human.tenant_id,
                        "a": approval_id,
                    },
                )
                approval.update(
                    decided_by=human.principal_id,
                    decided_credential_id=human.credential_id,
                    decided_at=decided_at,
                )
                store.approval_state(
                    conn,
                    row,
                    approval,
                    human.principal_id,
                    "APPROVED" if decision == "APPROVE" else "DENIED",
                    clock,
                    comment=comment,
                )
                if decision == "DENY":
                    store.transition(
                        conn, row, human.principal_id, "DENIED", clock, reason="HUMAN_DENIED"
                    )
                store.identity_check(conn, agent, clock, "AGENT")
                attest_snapshot(
                    conn,
                    agent,
                    frozen,
                    row["canonical_target_id"],
                    clock,
                    settings=frozen_bundle.context_settings,
                    catalog=catalog,
                    signals=SignalScope(frozen_bundle.signal_mappings, row["space_id"]),
                )
                if store.now(clock) >= approval["expires_at"]:
                    raise ExecutionError("INVALID_APPROVAL")
            store.scope_check(conn, human, row, clock)
            result = store.view(conn, row)
            if authority_check is not None:
                authority_check(conn)
        return result
    except ExecutionError as exc:
        _rejection(db, human, "decide_approval", exc.code, clock)
        raise
    except ResolutionError as exc:
        # The reattestation after a decision refused: its own code for the audit, as admission
        # records one (#545), and the same generic answer as before.
        _rejection(
            db, human, "decide_approval", resolution_reason(exc, "DEPENDENCY_UNAVAILABLE"), clock
        )
        raise ExecutionError() from None
    except (SQLAlchemyError, ValueError):
        _rejection(db, human, "decide_approval", "DEPENDENCY_UNAVAILABLE", clock)
        raise ExecutionError() from None
