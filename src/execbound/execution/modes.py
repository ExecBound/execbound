# SPDX-License-Identifier: AGPL-3.0-only
"""ADMIN-controlled per-tenant enforcement mode: observe records decisions, enforce acts on them.

Switching to OBSERVE is a weakening action; it needs a current ADMIN, the tenant fence and
a reason, and it is audited. Switching back changes nothing retroactively. The mode and the
approval deadline are each one value for every space, so since 8 October 2026 only a
workspace administrator changes them (`store.workspace_admin_check`); any administrator reads
them.

Attribution: each change names the acting administrator's credential twice, as
`credential_id`, the key these events have always carried and existing readers use, and
through `audit.acted_with`, the key every administration event uses for the credential that
acted. A refusal names it the same way.
"""

from collections import Counter
from typing import Any

from sqlalchemy import text
from sqlalchemy.exc import SQLAlchemyError

from execbound.audit import acted_with, append_event
from execbound.db import Database
from execbound.execution import store
from execbound.execution.authority import _rejection
from execbound.execution.models import (
    APPROVAL_DEADLINE_BOUNDS,
    MODES,
    DeadlineChange,
    ExecutionError,
    ModeChange,
)
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


def set_enforcement_mode(
    db: Database, admin: Identity, mode: str, reason: str, clock: Clock | None = None
) -> ModeChange:
    """Change the tenant's mode inside the fence; a no-op is refused, every change audited."""
    clock = clock or SystemClock()
    try:
        if mode not in MODES:
            raise ExecutionError("INVALID_MODE")
        reason = _reason(reason)
        with db.transaction(admin.tenant_id) as conn:
            store.workspace_admin_check(conn, admin, clock)
            # Lock order (docs/EXECUTION.md): tenant control, then audit head, then row writes.
            store.fence(conn, admin.tenant_id, clock)
            # Waiting for the fence must not preserve stale administrator validity.
            store.workspace_admin_check(conn, admin, clock)
            previous = store.enforcement_mode(conn, admin.tenant_id)
            if previous == mode:
                raise ExecutionError("INVALID_STATE")
            changed_at = store.now(clock)
            conn.execute(
                text(
                    "UPDATE execbound.tenant_policy_control SET enforcement_mode=:m "
                    "WHERE tenant_id=:t"
                ),
                {"m": mode, "t": admin.tenant_id},
            )
            append_event(
                conn,
                admin.tenant_id,
                admin.principal_id,
                "tenant.mode_changed",
                {
                    "previous": previous,
                    "mode": mode,
                    "reason": reason,
                    "principal_id": str(admin.principal_id),
                    "credential_id": str(admin.credential_id),
                    **acted_with(admin.credential_id),
                    "replay": {"version": 1, "semantic_time": changed_at.isoformat()},
                },
            )
            store.workspace_admin_check(conn, admin, clock)
        log_event(
            "mode.changed", tenant_id=admin.tenant_id, principal_id=admin.principal_id, state=mode
        )
        return ModeChange(previous, mode, changed_at, admin.principal_id, reason)
    except ExecutionError as exc:
        _rejection(db, admin, "set_enforcement_mode", exc.code, clock, actor_credential=True)
        raise
    except (SQLAlchemyError, ValueError):
        _rejection(
            db,
            admin,
            "set_enforcement_mode",
            "DEPENDENCY_UNAVAILABLE",
            clock,
            actor_credential=True,
        )
        raise ExecutionError() from None


def enforcement_mode(db: Database, admin: Identity, clock: Clock | None = None) -> str:
    """The tenant's current mode for a current ADMIN; a read without the fence."""
    clock = clock or SystemClock()
    try:
        with db.transaction(admin.tenant_id) as conn:
            store.identity_check(conn, admin, clock, "ADMIN")
            return store.enforcement_mode(conn, admin.tenant_id)
    except ExecutionError:
        raise
    except (SQLAlchemyError, ValueError):
        raise ExecutionError() from None


def _deadline(seconds: object) -> int | None:
    """Seconds within the bounds, or None for off; anything else is refused."""
    if seconds is None:
        return None
    low, high = APPROVAL_DEADLINE_BOUNDS
    if type(seconds) is not int or not low <= seconds <= high:
        raise ExecutionError("INVALID_DEADLINE")
    return seconds


def set_approval_deadline(
    db: Database,
    admin: Identity,
    seconds: int | None,
    reason: str,
    clock: Clock | None = None,
) -> DeadlineChange:
    """Change how long a new approval may wait, inside the fence; audited, no-op refused.

    None turns the deadline off: an approval then expires with its frozen plan and nothing
    sooner. Approvals already pending keep the expiry they were created with.
    """
    clock = clock or SystemClock()
    try:
        value = _deadline(seconds)
        reason = _reason(reason)
        with db.transaction(admin.tenant_id) as conn:
            store.workspace_admin_check(conn, admin, clock)
            store.fence(conn, admin.tenant_id, clock)
            store.workspace_admin_check(conn, admin, clock)
            previous = store.approval_deadline(conn, admin.tenant_id)
            if previous == value:
                raise ExecutionError("INVALID_STATE")
            changed_at = store.now(clock)
            conn.execute(
                text(
                    "UPDATE execbound.tenant_policy_control SET approval_deadline_seconds=:s "
                    "WHERE tenant_id=:t"
                ),
                {"s": value, "t": admin.tenant_id},
            )
            append_event(
                conn,
                admin.tenant_id,
                admin.principal_id,
                "tenant.approval_deadline_changed",
                {
                    "previous": previous,
                    "seconds": value,
                    "reason": reason,
                    "principal_id": str(admin.principal_id),
                    "credential_id": str(admin.credential_id),
                    **acted_with(admin.credential_id),
                    "replay": {"version": 1, "semantic_time": changed_at.isoformat()},
                },
            )
            store.workspace_admin_check(conn, admin, clock)
        log_event(
            "approval_deadline.changed",
            tenant_id=admin.tenant_id,
            principal_id=admin.principal_id,
            state="off" if value is None else str(value),
        )
        return DeadlineChange(previous, value, changed_at, admin.principal_id, reason)
    except ExecutionError as exc:
        _rejection(db, admin, "set_approval_deadline", exc.code, clock, actor_credential=True)
        raise
    except (SQLAlchemyError, ValueError):
        _rejection(
            db,
            admin,
            "set_approval_deadline",
            "DEPENDENCY_UNAVAILABLE",
            clock,
            actor_credential=True,
        )
        raise ExecutionError() from None


def approval_deadline(db: Database, admin: Identity, clock: Clock | None = None) -> int | None:
    """The tenant's current deadline in seconds, or None when off, for a current ADMIN."""
    clock = clock or SystemClock()
    try:
        with db.transaction(admin.tenant_id) as conn:
            store.identity_check(conn, admin, clock, "ADMIN")
            return store.approval_deadline(conn, admin.tenant_id)
    except ExecutionError:
        raise
    except (SQLAlchemyError, ValueError):
        raise ExecutionError() from None


def observe_report(
    db: Database, admin: Identity, *, since_hours: int, clock: Clock | None = None
) -> dict[str, Any]:
    """Counts of observed admission decisions from the audit chain, by effect, action and reason.

    Every limit-driven outcome is listed separately because it relied on the assumed-executed
    projection of earlier observed decisions, not on enforced impact. The counts are every
    space's, so only a workspace administrator reads them (decided 8 October 2026).
    """
    clock = clock or SystemClock()
    if not 0 <= since_hours <= 24 * 90:
        raise ExecutionError("INVALID_WINDOW")
    try:
        with db.transaction(admin.tenant_id) as conn:
            store.workspace_admin_check(conn, admin, clock)
            rows = conn.execute(
                text(
                    "SELECT payload FROM execbound.audit_events WHERE tenant_id=:t "
                    "AND kind='execution.evaluated' AND payload->>'mode'='OBSERVE' "
                    "AND payload->>'stage'='ADMISSION' "
                    "AND occurred_at > clock_timestamp() - make_interval(hours => :h) "
                    "ORDER BY sequence"
                ),
                {"t": admin.tenant_id, "h": since_hours},
            ).scalars()
            effects: Counter[str] = Counter()
            actions: dict[str, Counter[str]] = {}
            reasons: Counter[str] = Counter()
            projected: list[dict[str, Any]] = []
            observed = 0
            for payload in rows:
                decision = payload["decision"]
                action = payload["frozen"]["intent"]["action"]
                effect = decision["effect"]
                observed += 1
                effects[effect] += 1
                actions.setdefault(action, Counter())[effect] += 1
                reasons.update(decision.get("reasons", ()))
                limits = [o for o in decision.get("obligation_ids", ()) if o.startswith("limit:")]
                limits += [r for r in decision.get("reasons", ()) if r.startswith("HARD_LIMIT:")]
                if limits:
                    projected.append(
                        {
                            "execution_id": payload["execution_id"],
                            "action": action,
                            "effect": effect,
                            "obligations": limits,
                        }
                    )
            store.workspace_admin_check(conn, admin, clock)
        return {
            "tenant_id": str(admin.tenant_id),
            "since_hours": since_hours,
            "observed": observed,
            "effects": dict(sorted(effects.items())),
            "actions": {
                action: dict(sorted(counts.items())) for action, counts in sorted(actions.items())
            },
            "reasons": dict(sorted(reasons.items())),
            "projected_limits": projected,
        }
    except ExecutionError:
        raise
    except (SQLAlchemyError, ValueError, KeyError, TypeError):
        raise ExecutionError() from None
