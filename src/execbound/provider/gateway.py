# SPDX-License-Identifier: AGPL-3.0-only
"""Compose durable ownership with network I/O outside every database transaction."""

from uuid import UUID

from sqlalchemy.exc import SQLAlchemyError

from execbound.audit import append_event
from execbound.db import Database
from execbound.execution import (
    _never_a_checkpoint,
    _rejection,
    mark_indeterminate,
    reconcile,
    record_outcome,
    store,
    take_dispatch,
)
from execbound.execution.models import (
    AuthorityCheck,
    DispatchTicket,
    EvidenceVerifier,
    ExecutionError,
    ExecutionView,
    PreconditionConfig,
)
from execbound.execution.scheduled import RecoveryActor, actor_check
from execbound.identity import Identity
from execbound.logging_schema import log_event
from execbound.provider.connector import Connector
from execbound.provider.models import ProviderError, provider_command
from execbound.provider.verifiers import verifier_for
from execbound.resolution.models import Clock, SystemClock
from execbound.secrets import secret_shaped


def dispatch_owned(
    db: Database,
    ticket: DispatchTicket,
    connector: Connector,
    clock: Clock | None = None,
    preconditions: PreconditionConfig | None = None,
    *,
    verifier: EvidenceVerifier | None = None,
) -> ExecutionView:
    """Dispatch an owned ticket through `connector` and settle what it returns.

    `verifier` is the one the runtime holds for this account, built from the configuration
    it validated; every caller in the server passes it. Without one, the evidence settles
    through a verifier built from the connector's configuration: once here, so a connection
    nothing can verify fails before anything is dispatched, and again after the network
    call, so a key rotated while it was in flight applies to its evidence. The connector's
    own word is never the check (#496).
    """
    clock = clock or SystemClock()
    if verifier is None:
        verifier_for(connector.config)
    command = take_dispatch(db, ticket, clock, preconditions)
    log_event(
        "dispatch.attempted",
        tenant_id=ticket.tenant_id,
        execution_id=command.execution_id,
        operation_id=command.operation_id,
    )
    try:
        # The connector receives the frozen provider command and nothing else of the dispatch.
        evidence = connector.dispatch(provider_command(command))
    except ProviderError:
        return mark_indeterminate(db, ticket, clock)
    try:
        settle = verifier or verifier_for(connector.config)
        view = record_outcome(db, ticket, evidence, settle, clock)
        log_event(
            "outcome.recorded",
            tenant_id=ticket.tenant_id,
            execution_id=view.execution_id,
            state=view.state,
        )
        return view
    except ExecutionError:
        # Even a valid provider response cannot release impact without the
        # atomic settlement/audit commit. Retained journal evidence can recover it.
        return mark_indeterminate(db, ticket, clock)


def reconcile_operation(
    db: Database,
    admin: RecoveryActor,
    execution_id: UUID,
    connector: Connector,
    *,
    reason: str,
    cancel_if_missing: bool = False,
    clock: Clock | None = None,
    authority_check: AuthorityCheck | None = None,
    verifier: EvidenceVerifier | None = None,
) -> ExecutionView:
    clock = clock or SystemClock()
    try:
        if (
            not isinstance(reason, str)
            or not 1 <= len(reason.strip()) <= 500
            or type(cancel_if_missing) is not bool
            or secret_shaped(reason)
        ):
            raise ExecutionError("INVALID_REASON")
        if cancel_if_missing and not isinstance(admin, Identity):
            # Cancellation is the one provider write recovery can make; it stays behind an
            # administrator (#503).
            raise ExecutionError("INVALID_IDENTITY")
        actor = admin.principal_id
        if actor is None:
            raise ExecutionError("INVALID_IDENTITY")
        if verifier is None:
            # A connection nothing can verify is refused before any request is captured.
            verifier_for(connector.config)
        with db.transaction(admin.tenant_id) as conn:
            actor_check(conn, admin, clock)
            store.fence(conn, admin.tenant_id, clock)
            actor_check(conn, admin, clock)
            if authority_check is not None:
                authority_check(conn)
            row = store.read(conn, admin.tenant_id, execution_id)
            # Refused whatever its state and whichever mode was asked for, before any
            # connector call and before the request is captured, so an operator who
            # configured a connector for a Gate account is answered rather than having a
            # cancellation silently reduced to an inconclusive journal. Once is enough
            # here: this read is already under the fence, the column is written at the row
            # insert and no runtime statement can change it, and if the marker did appear
            # later the settlement end refuses it too: ``_executor_evidence_only`` refuses
            # a marked row unless the verifier attests an external execution.
            _never_a_checkpoint(row)
            if row["state"] not in {"DISPATCH_COMMITTED", "INDETERMINATE"}:
                return store.view(conn, row)
            command = store.command(row)
            append_event(
                conn,
                admin.tenant_id,
                actor,
                "execution.reconciliation_requested",
                {
                    "execution_id": str(execution_id),
                    "operation_id": str(command.operation_id),
                    "plan_hash": command.plan_hash,
                    "reason": reason.strip(),
                    "cancel_if_missing": cancel_if_missing,
                },
            )
            actor_check(conn, admin, clock)
            if authority_check is not None:
                authority_check(conn)
        log_event(
            "reconciliation.requested",
            tenant_id=admin.tenant_id,
            principal_id=actor,
            execution_id=execution_id,
        )
        try:
            provider = provider_command(command)
            evidence = connector.lookup(provider)
            if evidence is None and cancel_if_missing:
                # A journal lookup can block through revocation or expiry.
                # Commit fresh control authority immediately before cancellation.
                with db.transaction(admin.tenant_id) as conn:
                    store.fence(conn, admin.tenant_id, clock)
                    actor_check(conn, admin, clock)
                    if authority_check is not None:
                        authority_check(conn)
                    current = store.read(conn, admin.tenant_id, execution_id)
                    if current["state"] not in {"DISPATCH_COMMITTED", "INDETERMINATE"}:
                        return store.view(conn, current)
                    append_event(
                        conn,
                        admin.tenant_id,
                        actor,
                        "execution.cancellation_requested",
                        {
                            "execution_id": str(execution_id),
                            "operation_id": str(command.operation_id),
                            "plan_hash": command.plan_hash,
                            "reason": reason.strip(),
                        },
                    )
                    actor_check(conn, admin, clock)
                    if authority_check is not None:
                        authority_check(conn)
                evidence = connector.cancel(provider)
        except ProviderError:
            evidence = None
        if evidence is not None:
            return reconcile(
                db,
                admin,
                execution_id,
                reason=reason,
                evidence=evidence,
                verifier=verifier or verifier_for(connector.config),
                clock=clock,
                authority_check=authority_check,
            )
        with db.transaction(admin.tenant_id) as conn:
            store.fence(conn, admin.tenant_id, clock)
            actor_check(conn, admin, clock)
            if authority_check is not None:
                authority_check(conn)
            row = store.read(conn, admin.tenant_id, execution_id)
            if row["state"] == "DISPATCH_COMMITTED":
                store.transition(
                    conn,
                    row,
                    actor,
                    "INDETERMINATE",
                    clock,
                    reason="INCONCLUSIVE_JOURNAL",
                )
            result = store.view(conn, row)
            actor_check(conn, admin, clock)
            if authority_check is not None:
                authority_check(conn)
        return result
    except ExecutionError as exc:
        _rejection(db, admin, "provider.reconcile", exc.code, clock)
        raise
    except (SQLAlchemyError, ValueError):
        _rejection(db, admin, "provider.reconcile", "DEPENDENCY_UNAVAILABLE", clock)
        raise ExecutionError() from None
