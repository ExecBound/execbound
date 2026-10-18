# SPDX-License-Identifier: AGPL-3.0-only
"""Capture future offline evidence inside the caller's existing authority transaction."""

from datetime import datetime
from typing import Any, Literal
from uuid import UUID

from sqlalchemy import text
from sqlalchemy.engine import Connection

from execbound.audit import append_event
from execbound.execution import store
from execbound.execution.models import ExecutionError
from execbound.identity import Identity
from execbound.policy.approval import VerifiedApproval
from execbound.policy.models import BundleContent, PolicyEvaluation
from execbound.replay.models import ApprovalCapture, DecisionCapture, HistoricalIdentity
from execbound.requests import ActionRequest, ClaimedContext, ResourceSelector
from execbound.resolution.models import Clock, ResolvedRequest


class ObservedClock:
    """Record actual samples without freezing or extending live authority."""

    def __init__(self, clock: Clock) -> None:
        self.clock = clock
        self.samples: list[datetime] = []

    def now(self) -> datetime:
        value = store.now(self.clock)
        self.samples.append(value)
        return value


def historical_identity(
    conn: Connection,
    identity: Identity,
    *,
    groups: tuple[UUID, ...] | None = None,
    space: UUID | None = None,
) -> HistoricalIdentity:
    """The identity as evidence; ``groups`` and ``space`` only for the agent whose
    memberships and space were read inside the fence for this decision."""
    issued_at = conn.execute(
        text("""SELECT issued_at FROM execbound.credentials
            WHERE tenant_id=:t AND principal_id=:p AND credential_id=:c"""),
        {"t": identity.tenant_id, "p": identity.principal_id, "c": identity.credential_id},
    ).scalar_one()
    return HistoricalIdentity(
        tenant_id=identity.tenant_id,
        principal_id=identity.principal_id,
        credential_id=identity.credential_id,
        kind=identity.kind,
        issued_at=issued_at,
        expires_at=identity.expires_at,
        groups=groups,
        space=space,
    )


def record_decision(
    conn: Connection,
    row: dict[str, Any],
    identity: Identity,
    bundle: BundleContent,
    frozen: ResolvedRequest,
    decision: PolicyEvaluation,
    clock: Clock,
    *,
    usage_time: datetime,
    semantic_time: datetime,
    finished_time: datetime,
    approval: VerifiedApproval | None,
    stage: Literal["ADMISSION", "APPROVAL_REVIEW"],
    reviewer: Identity | None = None,
    human_decision: Literal["APPROVE", "DENY"] | None = None,
    mode: Literal["ENFORCE", "OBSERVE"] = "ENFORCE",
    groups: tuple[UUID, ...],
    space: UUID | None = None,
) -> None:
    bound_approval = None
    if approval is not None:
        counted: list[HistoricalIdentity] = []
        retained = store.approval_row(conn, row)
        required = int((retained or {}).get("required_approvers", 1) or 1)
        if stage == "APPROVAL_REVIEW":
            if reviewer is None or human_decision != "APPROVE":
                raise ExecutionError("INVALID_APPROVAL")
            approver = reviewer
        else:
            if retained is None or retained["state"] != "APPROVED":
                raise ExecutionError("INVALID_APPROVAL")
            approver = store.persisted_reviewer(
                conn,
                identity.tenant_id,
                retained["decided_by"],
                retained["decided_credential_id"],
                clock,
            )
            for decided in store.approval_decisions(
                conn, identity.tenant_id, retained["approval_id"]
            ):
                if decided["decision"] != "APPROVE":
                    raise ExecutionError("INVALID_APPROVAL")
                human = store.persisted_reviewer(
                    conn,
                    identity.tenant_id,
                    decided["principal_id"],
                    decided["credential_id"],
                    clock,
                )
                store.scope_check(conn, human, row, clock)
                counted.append(historical_identity(conn, human))
        store.scope_check(conn, approver, row, clock)
        bound_approval = ApprovalCapture(
            status="PROPOSED" if stage == "APPROVAL_REVIEW" else "VERIFIED",
            approval_id=approval.approval_id,
            tenant_id=approval.tenant_id,
            principal_id=approval.principal_id,
            bundle_id=approval.bundle_id,
            plan_hash=approval.plan_hash,
            obligation_ids=approval.obligation_ids,
            expires_at=approval.expires_at,
            approver=historical_identity(conn, approver),
            canonical_target_id=row["canonical_target_id"],
            action=frozen.intent.action,
            required_approvers=required,
            approvers=tuple(counted),
        )
    # Selectors, retry keys, runs and caller opinions are not authorization facts.
    # Preserve only the independently resolved incident selector needed by policy.
    # Request is excluded from the original frozen plan hash; no hash is regenerated.
    normalized = ActionRequest(
        operation_ref=frozen.request.operation_ref,
        target=ResourceSelector(kind="canonical", value=str(frozen.intent.target_id)),
        arguments=frozen.request.arguments,
        idempotency_key="recorded-" + str(row["execution_id"]),
        claimed_context=ClaimedContext(incident_id=frozen.request.claimed_context.incident_id),
    )
    capture = DecisionCapture(
        version=1,
        stage=stage,
        execution_id=row["execution_id"],
        operation_id=row["operation_id"],
        canonical_target_id=row["canonical_target_id"],
        usage_time=usage_time,
        semantic_time=semantic_time,
        finished_time=finished_time,
        identity=historical_identity(conn, identity, groups=groups, space=space),
        frozen=frozen.model_copy(update={"request": normalized}),
        bundle_id=bundle.bundle_id,
        decision=decision,
        approval=bound_approval,
        reviewer=historical_identity(conn, reviewer) if reviewer else None,
        human_decision=human_decision,
        mode=mode,
    )
    append_event(
        conn,
        identity.tenant_id,
        reviewer.principal_id if reviewer else identity.principal_id,
        "execution.evaluated",
        capture.model_dump(mode="json"),
    )
