# SPDX-License-Identifier: AGPL-3.0-only
"""Explicit bounded worker; notification leases never own protected execution."""

import json
from datetime import timedelta
from typing import Any
from uuid import UUID, uuid4

import httpx
from sqlalchemy import text

from execbound.db import Database, check_runtime
from execbound.execution.scheduled import ScheduledActor
from execbound.identity import Identity
from execbound.logging_schema import log_event
from execbound.monitoring.delivery import LocalReceiver, send_notification
from execbound.monitoring.models import MonitorError
from execbound.monitoring.store import (
    check_admin,
    derive_reach,
    evaluate_actions,
    evaluate_health,
    evaluate_pending,
    purge_audit_observations,
)
from execbound.resolution.models import Clock, SystemClock

SYSTEM_CLOCK = SystemClock()


def deliver_pending(
    db: Database,
    identity: Identity,
    receiver: LocalReceiver,
    *,
    limit: int = 50,
    clock: Clock = SYSTEM_CLOCK,
) -> int:
    if type(limit) is not int or not 1 <= limit <= 50:
        raise MonitorError("INVALID_LIMIT")
    delivered = 0
    with httpx.Client(trust_env=False, follow_redirects=False, timeout=5) as client:
        for _ in range(limit):
            lease = uuid4()
            with db.transaction(identity.tenant_id) as conn:
                check_runtime(conn)
                check_admin(conn, identity, clock=clock)
                now = clock.now()
                row = (
                    conn.execute(
                        text("""
                    SELECT * FROM execbound.monitor_deliveries
                    WHERE tenant_id=:t AND (
                      (state='PENDING' AND next_attempt_at<=:n)
                      OR (state='IN_FLIGHT' AND lease_until<=:n))
                    ORDER BY next_attempt_at, delivery_id LIMIT 1 FOR UPDATE SKIP LOCKED
                    """),
                        {"t": identity.tenant_id, "n": now},
                    )
                    .mappings()
                    .one_or_none()
                )
                if row is None:
                    break
                delivery = dict(row)
                params: dict[str, Any] = {
                    "t": identity.tenant_id,
                    "d": row["delivery_id"],
                    "lease": lease,
                    "until": now + timedelta(seconds=30),
                }
                if row["attempts"] >= 5:
                    conn.execute(
                        text("""UPDATE execbound.monitor_deliveries SET state='FAILED',
                        last_error='DELIVERY_UNCERTAIN',lease_until=NULL,lease_token=NULL
                        WHERE tenant_id=:t AND delivery_id=:d"""),
                        params,
                    )
                    continue
                finding = (
                    conn.execute(
                        text("""SELECT finding_id,source_id,observation_id,rule_version,
                    profile_version
                    FROM execbound.monitor_findings WHERE tenant_id=:t AND finding_id=:f"""),
                        {"t": identity.tenant_id, "f": row["finding_id"]},
                    )
                    .mappings()
                    .one()
                )
                payload = json.dumps(
                    {
                        "version": 1,
                        "kind": "monitor.finding",
                        "delivery_id": str(row["delivery_id"]),
                        **{
                            key: str(value) if value is not None else None
                            for key, value in finding.items()
                        },
                    },
                    sort_keys=True,
                    separators=(",", ":"),
                ).encode()
                conn.execute(
                    text("""UPDATE execbound.monitor_deliveries SET state='IN_FLIGHT',
                    attempts=attempts+1,lease_token=:lease,lease_until=:until
                    WHERE tenant_id=:t AND delivery_id=:d"""),
                    params,
                )
                check_admin(conn, identity, clock=clock)
            # A crash here leaves a recoverable lease. Reuse the stable delivery ID.
            accepted = send_notification(receiver, delivery["delivery_id"], payload, client)
            with db.transaction(identity.tenant_id) as conn:
                check_admin(conn, identity, clock=clock)
                attempts = delivery["attempts"] + 1
                params.update(
                    {
                        "state": "DELIVERED"
                        if accepted
                        else ("FAILED" if attempts >= 5 else "PENDING"),
                        "done": clock.now() if accepted else None,
                        "next": clock.now() + timedelta(seconds=min(300, 2**attempts)),
                        "error": None if accepted else "RECEIVER_UNAVAILABLE",
                    }
                )
                changed = conn.execute(
                    text("""UPDATE execbound.monitor_deliveries SET state=:state,
                    delivered_at=:done,next_attempt_at=:next,last_error=:error,
                    lease_token=NULL,lease_until=NULL
                    WHERE tenant_id=:t AND delivery_id=:d AND state='IN_FLIGHT'
                    AND lease_token=:lease RETURNING delivery_id"""),
                    params,
                ).scalar_one_or_none()
                if changed is not None and accepted:
                    delivered += 1
    return delivered


def process(
    db: Database, identity: Identity, receiver: LocalReceiver | None = None, *, limit: int = 50
) -> dict[str, int]:
    if type(limit) is not int or not 1 <= limit <= 50:
        raise MonitorError("INVALID_LIMIT")
    evaluated = evaluate_pending(db, identity, limit=limit)
    health_changes = evaluate_health(db, identity)
    # Observed and verified reach are read from observations and settled executions here,
    # never written by the execution path, which owns no monitoring row.
    derived = derive_reach(db, identity)
    # An actor's first consequential action is read from the observations just derived (#355).
    actions = evaluate_actions(db, identity)
    delivered = deliver_pending(db, identity, receiver, limit=limit) if receiver else 0
    # Last, once every rule has read them and what they raised is delivered: the audit
    # observations none reads any more, so a purge that fails never holds back a finding.
    purged = purge_audit_observations(db, identity)
    log_event("monitor.processed", tenant_id=identity.tenant_id, count=evaluated + delivered)
    return {
        "evaluated": evaluated,
        "health_changes": health_changes,
        "delivered": delivered,
        "reach": derived["verified"] + derived["observed"],
        "actions": actions["raised"],
        "purged": purged["purged"],
    }


def evaluate_scheduled(
    db: Database, tenant: UUID, *, limit: int = 50, clock: Clock = SYSTEM_CLOCK
) -> dict[str, int]:
    """The scheduled pass's evaluation in one workspace (#503): its pending observations, its
    sources' health, its derived reach, the actions first observed from it and, last, the purge
    of the directory audit observations no rule reads any more (#355), as the workspace's
    scheduled actor with no credential, each step under the workspace's own fence. It delivers
    nothing: a receiver is a deployment's configuration, which only `process --config` names."""
    if type(limit) is not int or not 1 <= limit <= 50:
        raise MonitorError("INVALID_LIMIT")
    actor = ScheduledActor(tenant)
    evaluated = evaluate_pending(db, actor, limit=limit, clock=clock)
    health_changes = evaluate_health(db, actor, clock=clock)
    derived = derive_reach(db, actor, clock=clock)
    actions = evaluate_actions(db, actor, clock=clock)
    purged = purge_audit_observations(db, actor, clock=clock)
    return {
        "evaluated": evaluated,
        "health_changes": health_changes,
        "reach": derived["verified"] + derived["observed"],
        "actions": actions["raised"],
        "purged": purged["purged"],
    }
