# SPDX-License-Identifier: AGPL-3.0-only
"""The single send attempt owned by a dispatch ticket, and the indeterminate marker."""

import secrets
from typing import Any

from sqlalchemy import text
from sqlalchemy.engine import Connection
from sqlalchemy.exc import SQLAlchemyError

from execbound.audit import append_event
from execbound.db import Database
from execbound.execution import store
from execbound.execution.models import (
    NO_PRECONDITIONS,
    DispatchCommand,
    DispatchTicket,
    ExecutionError,
    ExecutionView,
    PreconditionConfig,
)
from execbound.resolution.models import Clock, SystemClock


def _owner(conn: Connection, ticket: DispatchTicket) -> dict[str, Any]:
    if type(ticket) is not DispatchTicket:
        raise ExecutionError("INVALID_OWNER")
    row = store.read(conn, ticket.tenant_id, ticket.execution_id)
    if not row["owner_hash"] or not secrets.compare_digest(
        row["owner_hash"], store.ticket_digest(ticket.secret)
    ):
        raise ExecutionError("INVALID_OWNER")
    return row


def _never_a_checkpoint(row: dict[str, Any]) -> None:
    """Refuse a connector path for an execution admission granted rather than dispatched.

    The ticket paths need it because a grant stamps ``dispatch_attempted_at`` and leaves
    the state DISPATCH_COMMITTED, which is exactly what they require, and it stores its
    report secret's digest in the column their owner check compares against, so a ticket
    built from a report secret would satisfy both. Nothing on a surface constructs one
    today, because admission answers a checkpoint with no ticket and the runtime refuses
    one beside a grant; this is what keeps the outcome route the only way a grant settles
    even if that changes.

    ``gateway.reconcile_operation`` needs it for a different reason: a connector knows
    nothing about an operation ExecBound never dispatched, so its cancellation mode would
    settle a grant FAILED_NOT_EXECUTED and release its claim on ``connector.cancel``
    evidence — the refund on absent evidence the execution contract forbids — and its
    ordinary mode would ask a provider about that operation and then record an
    inconclusive journal for it.

    Its three callers are ``mark_indeterminate`` below, ``outcomes.record_outcome`` in
    each of its two transactions, and ``gateway.reconcile_operation`` in its first.
    ``take_dispatch`` reads the same column inline instead, because there the window is
    one disjunct of a single guard and is paired with the state check for a reason of its
    own.
    """
    if row["report_expires_at"] is not None:
        raise ExecutionError("INVALID_STATE")


def take_dispatch(
    db: Database,
    ticket: DispatchTicket,
    clock: Clock | None = None,
    preconditions: PreconditionConfig | None = None,
) -> DispatchCommand:
    """Consume the one send attempt. A lost return never grants a replacement attempt.

    The declared precondition class is recorded on the row in the same statement that
    records the attempt, so what a dispatch was worth is retained beside the attempt rather
    than inferred later from configuration that may since have changed. It is read from
    deployment configuration keyed by the frozen plan's own provider and provider
    operation, never from anything the caller sent, exactly as ``admission`` reads it for a
    grant: a caller cannot ask to dispatch under a stronger promise than the vendor gives.

    A binding this deployment has not declared records UNAVAILABLE rather than NULL. NULL
    is reserved for a row written before the column existed, and conflating "never
    declared" with "predates the question" would invite a reader to assume the mock's
    atomic enforcement for a binding nobody ever described.
    """
    clock = clock or SystemClock()
    preconditions = preconditions or NO_PRECONDITIONS
    try:
        with db.transaction(ticket.tenant_id) as conn:
            # Lock order (docs/EXECUTION.md): tenant control, then audit head, then row writes.
            store.fence(conn, ticket.tenant_id, clock)
            row = _owner(conn, ticket)
            if store.stop(conn, ticket.tenant_id) is not None:
                # The claim stays committed and unattempted; reconciliation settles it.
                raise ExecutionError("TENANT_STOPPED")
            if (
                row["state"] != "DISPATCH_COMMITTED"
                or row["dispatch_attempted_at"] is not None
                # A checkpoint is the one execution whose secret the caller holds, and the
                # one thing that secret must never do is open a send attempt. The report
                # window marks every execution admission would have granted, a DENIED or
                # stale one included, so it is paired with DISPATCH_COMMITTED above; no
                # ordinary dispatch carries it and nothing can update the column.
                or row["report_expires_at"] is not None
            ):
                raise ExecutionError("INVALID_STATE")
            frozen = store.frozen(row)
            store.demo_check(conn, ticket.tenant_id, frozen.request.synthetic_demo)
            intent = frozen.intent
            declared = preconditions.declared(intent.provider, intent.provider_operation)
            conn.execute(
                text(
                    "UPDATE execbound.executions SET dispatch_attempted_at=:n, "
                    "precondition_class=:c WHERE tenant_id=:t AND execution_id=:e"
                ),
                {
                    "n": store.now(clock),
                    "c": declared,
                    "t": ticket.tenant_id,
                    "e": ticket.execution_id,
                },
            )
            append_event(
                conn,
                ticket.tenant_id,
                row["principal_id"],
                "execution.dispatch_attempt",
                {
                    "execution_id": str(row["execution_id"]),
                    "plan_hash": row["plan_hash"],
                    "operation_id": str(row["operation_id"]),
                    # Retained beside the attempt, not only in the column above. The column
                    # is a projection the runtime holds UPDATE on; this chain is what cannot
                    # be quietly revised, and it is the only copy that survives an export
                    # into replay, where the row is not available at all.
                    "precondition_class": declared,
                    # No window is written here, and none could be. This statement commits
                    # the one send attempt, and the connector's exchange — the only thing
                    # that measures a gap — happens after it returns. A dispatch is
                    # one-shot, so the column is NULL at this read by construction rather
                    # than merely not yet written. The measured window is retained where it
                    # is established, in the signed record the settlement keeps.
                },
            )
            result = store.command(row)
        return result
    except ExecutionError:
        raise
    except (SQLAlchemyError, ValueError):
        raise ExecutionError() from None


def mark_indeterminate(
    db: Database, ticket: DispatchTicket, clock: Clock | None = None
) -> ExecutionView:
    clock = clock or SystemClock()
    try:
        with db.transaction(ticket.tenant_id) as conn:
            # Lock order (docs/EXECUTION.md): tenant control, then audit head, then row writes.
            store.fence(conn, ticket.tenant_id, clock)
            row = _owner(conn, ticket)
            # A grant is not a lost dispatch: it becomes uncertain when its report window
            # closes, which is the recovery sweep's to decide and never a ticket holder's.
            _never_a_checkpoint(row)
            if row["state"] == "DISPATCH_COMMITTED":
                store.transition(conn, row, row["principal_id"], "INDETERMINATE", clock)
            elif row["state"] != "INDETERMINATE":
                raise ExecutionError("INVALID_STATE")
            result = store.view(conn, row)
        return result
    except ExecutionError:
        raise
    except (SQLAlchemyError, ValueError):
        raise ExecutionError() from None
