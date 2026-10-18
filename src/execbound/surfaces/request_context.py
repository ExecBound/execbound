# SPDX-License-Identifier: AGPL-3.0-only
"""Display-only request relationships, read inside the human reader's tenant fence."""

from datetime import datetime
from typing import Any, Literal
from uuid import UUID

from pydantic import BaseModel
from sqlalchemy import text
from sqlalchemy.engine import Connection


class RelatedRequest(BaseModel):
    execution_id: UUID
    request_ref: str
    action: str
    state: str


class DeliveryView(BaseModel):
    delivery_id: UUID
    # Which message the row is (#678): the announcement, a reminder or a close-out.
    kind: Literal["approval.pending", "approval.reminder", "approval.closed"]
    state: str
    attempts: int
    created_at: datetime
    delivered_at: datetime | None


def attach_context(
    conn: Connection,
    row: dict[str, Any],
    *,
    principal: UUID,
    scoped: bool,
    read_spaces: set[UUID],
    space_sql: str,
    space_params: dict[str, Any],
) -> None:
    """Called only after the parent row passed membership and review-scope checks."""
    row["deliveries"] = list(
        conn.execute(
            text(
                "SELECT n.notification_id AS delivery_id, n.kind, n.state, n.attempts, "
                "n.created_at, n.delivered_at FROM execbound.approval_notifications n "
                "JOIN execbound.approvals a ON a.tenant_id=n.tenant_id "
                "AND a.approval_id=n.approval_id "
                "WHERE a.tenant_id=:t AND a.execution_id=:e "
                "ORDER BY n.created_at, n.notification_id LIMIT 100"
            ),
            {"t": row["tenant_id"], "e": row["execution_id"]},
        ).mappings()
    )
    case = row["frozen_model"].request.external_case
    row["related_requests"] = []
    if case is None:
        return
    row["related_requests"] = list(
        conn.execute(
            text(
                "SELECT e.execution_id, 'EB-' || e.request_number AS request_ref, e.state, "
                "e.frozen->'intent'->>'action' AS action FROM execbound.executions e "
                "WHERE e.tenant_id=:t AND e.execution_id<>:e "
                "AND e.frozen->'request'->'external_case'->>'source'=:source "
                "AND e.frozen->'request'->'external_case'->>'case_id'=:case "
                "AND (NOT :scoped OR e.space_id=ANY(CAST(:read_spaces AS uuid[])) "
                "OR EXISTS (SELECT 1 FROM execbound.effective_approval_scopes s "
                "WHERE s.tenant_id=e.tenant_id AND s.approver_id=:p AND s.active "
                "AND s.space_id=e.space_id AND s.canonical_target_id=e.canonical_target_id "
                "AND s.action=e.frozen->'intent'->>'action'))"
                + space_sql  # nosec B608 - the shared helper's literal predicate, bound values
                + " ORDER BY e.created_at DESC, e.execution_id DESC LIMIT 20"
            ),
            {
                **space_params,
                "t": row["tenant_id"],
                "e": row["execution_id"],
                "p": principal,
                "scoped": scoped,
                "read_spaces": list(read_spaces),
                "source": case.source,
                "case": case.case_id,
            },
        ).mappings()
    )
