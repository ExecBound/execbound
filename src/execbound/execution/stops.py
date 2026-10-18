# SPDX-License-Identifier: AGPL-3.0-only
"""ADMIN-controlled per-tenant emergency stop: it can only refuse, never grant or erase.

A stop halts every space of the tenant, so since 8 October 2026 only a workspace
administrator activates or releases one (`store.workspace_admin_check`); an administrator
narrowed to spaces is refused both, and reads the stop as before.
"""

from uuid import uuid4

from sqlalchemy import text
from sqlalchemy.exc import SQLAlchemyError

from execbound.audit import acted_with, append_event
from execbound.db import Database
from execbound.execution import store
from execbound.execution.authority import _rejection
from execbound.execution.models import ExecutionError, StopState
from execbound.identity import Identity
from execbound.logging_schema import log_event
from execbound.resolution.models import Clock, SystemClock
from execbound.secrets import secret_shaped


def _reason(reason: object) -> str:
    if not isinstance(reason, str) or not 1 <= len(reason.strip()) <= 500:
        raise ExecutionError("INVALID_REASON")
    if secret_shaped(reason):
        raise ExecutionError("INVALID_REASON")
    return reason.strip()


def _payload(admin: Identity, stop: StopState, reason: str, clock: Clock) -> dict[str, object]:
    """`credential_id` is the key these events have always carried and existing readers use;
    `acted_with` names the same credential under the key every administration event uses for
    the one that acted. Replay reads only the stop id, the reason and the semantic time."""
    return {
        "stop_id": str(stop.stop_id),
        "reason": reason,
        "principal_id": str(admin.principal_id),
        "credential_id": str(admin.credential_id),
        **acted_with(admin.credential_id),
        "replay": {"version": 1, "semantic_time": store.now(clock).isoformat()},
    }


def activate_stop(
    db: Database, admin: Identity, reason: str, clock: Clock | None = None
) -> StopState:
    """Halt new admission, approval decisions and dispatch attempts for the tenant."""
    clock = clock or SystemClock()
    try:
        reason = _reason(reason)
        with db.transaction(admin.tenant_id) as conn:
            store.workspace_admin_check(conn, admin, clock)
            # Lock order (docs/EXECUTION.md): tenant control, then audit head, then row writes.
            store.fence(conn, admin.tenant_id, clock)
            # Waiting for the fence must not preserve stale administrator validity.
            store.workspace_admin_check(conn, admin, clock)
            if store.stop(conn, admin.tenant_id) is not None:
                raise ExecutionError("INVALID_STATE")
            stop = StopState(uuid4(), store.now(clock), admin.principal_id, reason)
            conn.execute(
                text(
                    "UPDATE execbound.tenant_policy_control SET stop_id=:s, stopped_at=:n, "
                    "stopped_by=:p, stop_reason=:r WHERE tenant_id=:t"
                ),
                {
                    "s": stop.stop_id,
                    "n": stop.stopped_at,
                    "p": stop.stopped_by,
                    "r": reason,
                    "t": admin.tenant_id,
                },
            )
            # Operations admitted before the stop stay committed and uncertain until
            # reconciled; the activation records how many the administrator inherits.
            committed = conn.execute(
                text(
                    "SELECT count(*) FROM execbound.executions "
                    "WHERE tenant_id=:t AND state='DISPATCH_COMMITTED'"
                ),
                {"t": admin.tenant_id},
            ).scalar_one()
            append_event(
                conn,
                admin.tenant_id,
                admin.principal_id,
                "tenant.stop_activated",
                {**_payload(admin, stop, reason, clock), "dispatch_committed": int(committed)},
            )
            store.workspace_admin_check(conn, admin, clock)
        log_event("stop.activated", tenant_id=admin.tenant_id, principal_id=admin.principal_id)
        return stop
    except ExecutionError as exc:
        _rejection(db, admin, "activate_stop", exc.code, clock, actor_credential=True)
        raise
    except (SQLAlchemyError, ValueError):
        _rejection(
            db, admin, "activate_stop", "DEPENDENCY_UNAVAILABLE", clock, actor_credential=True
        )
        raise ExecutionError() from None


def release_stop(
    db: Database, admin: Identity, reason: str, clock: Clock | None = None
) -> StopState:
    """Clear the active stop; nothing halted by it is retried or resumed automatically."""
    clock = clock or SystemClock()
    try:
        reason = _reason(reason)
        with db.transaction(admin.tenant_id) as conn:
            store.workspace_admin_check(conn, admin, clock)
            # Lock order (docs/EXECUTION.md): tenant control, then audit head, then row writes.
            store.fence(conn, admin.tenant_id, clock)
            store.workspace_admin_check(conn, admin, clock)
            stop = store.stop(conn, admin.tenant_id)
            if stop is None:
                raise ExecutionError("INVALID_STATE")
            conn.execute(
                text(
                    "UPDATE execbound.tenant_policy_control SET stop_id=NULL, stopped_at=NULL, "
                    "stopped_by=NULL, stop_reason=NULL WHERE tenant_id=:t"
                ),
                {"t": admin.tenant_id},
            )
            append_event(
                conn,
                admin.tenant_id,
                admin.principal_id,
                "tenant.stop_released",
                _payload(admin, stop, reason, clock),
            )
            store.workspace_admin_check(conn, admin, clock)
        log_event("stop.released", tenant_id=admin.tenant_id, principal_id=admin.principal_id)
        return stop
    except ExecutionError as exc:
        _rejection(db, admin, "release_stop", exc.code, clock, actor_credential=True)
        raise
    except (SQLAlchemyError, ValueError):
        _rejection(
            db, admin, "release_stop", "DEPENDENCY_UNAVAILABLE", clock, actor_credential=True
        )
        raise ExecutionError() from None


def stop_status(db: Database, admin: Identity, clock: Clock | None = None) -> StopState | None:
    """The tenant's active stop, or None, for a current ADMIN; a read without the fence."""
    clock = clock or SystemClock()
    try:
        with db.transaction(admin.tenant_id) as conn:
            store.identity_check(conn, admin, clock, "ADMIN")
            return store.stop(conn, admin.tenant_id)
    except ExecutionError:
        raise
    except (SQLAlchemyError, ValueError):
        raise ExecutionError() from None
