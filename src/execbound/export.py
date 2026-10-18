# SPDX-License-Identifier: AGPL-3.0-only
"""Security event export: the sanitized audit chain and authentication failure summaries,
in order and at least once, to operator destinations through a per-destination cursor.

The export reads the chain and never writes it. A cursor advances only on acknowledgement,
one destination's failure never blocks another, and a payload the replay export would refuse
stops the cursor at that event.
"""

import json
from collections.abc import Sequence
from datetime import datetime, timedelta
from typing import Any
from uuid import UUID, uuid4, uuid5

import httpx
from sqlalchemy import text
from sqlalchemy.engine import Connection
from sqlalchemy.exc import SQLAlchemyError

from execbound.audit import GENESIS
from execbound.db import Database, check_runtime
from execbound.execution import store
from execbound.execution.models import ExecutionError
from execbound.identity import Identity
from execbound.logging_schema import log_event
from execbound.monitoring.delivery import EXPORT_ACCEPTED, send_notification
from execbound.notifications import BACKOFF, MAX_ATTEMPTS, Destination
from execbound.replay.models import AuditEvent
from execbound.replay.verify import ReplayValidationError, reject_secrets
from execbound.resolution.models import Clock, SystemClock

MAX_BATCH_BYTES = 1_000_000
BATCH_NAMESPACE = UUID("2f7d6f0a-4c8f-4f2b-9d6e-3a1b5c7e9d01")


def _admin(conn: Connection, admin: Identity, clock: Clock) -> None:
    check_runtime(conn)
    store.identity_check(conn, admin, clock, "ADMIN")


def _cursor(conn: Connection, tenant: UUID, destination_id: str, now: datetime) -> dict[str, Any]:
    conn.execute(
        text(
            "INSERT INTO execbound.export_cursors (tenant_id, destination_id, next_attempt_at) "
            "VALUES (:t, :d, :now) ON CONFLICT (tenant_id, destination_id) DO NOTHING"
        ),
        {"t": tenant, "d": destination_id, "now": now},
    )
    row = (
        conn.execute(
            text(
                "SELECT * FROM execbound.export_cursors WHERE tenant_id=:t AND destination_id=:d "
                "FOR UPDATE SKIP LOCKED"
            ),
            {"t": tenant, "d": destination_id},
        )
        .mappings()
        .one_or_none()
    )
    return dict(row) if row is not None else {}


def _head(conn: Connection, tenant: UUID) -> int:
    value = conn.execute(
        text("SELECT sequence FROM execbound.audit_heads WHERE tenant_id=:t"), {"t": tenant}
    ).scalar_one_or_none()
    return int(value or 0)


def _events(conn: Connection, tenant: UUID, after: int, limit: int) -> list[AuditEvent]:
    rows = conn.execute(
        text(
            "SELECT tenant_id, sequence, event_id, actor_id, kind, occurred_at, payload, "
            "previous_hash, event_hash FROM execbound.audit_events "
            "WHERE tenant_id=:t AND sequence > :after ORDER BY sequence LIMIT :limit"
        ),
        {"t": tenant, "after": after, "limit": limit},
    ).mappings()
    return [AuditEvent.model_validate(dict(row)) for row in rows]


def _failures(conn: Connection, tenant: UUID, since: datetime | None) -> list[dict[str, Any]]:
    rows = conn.execute(
        text(
            "SELECT surface, reason, window_start, subject_kind, subject_id, count "
            "FROM execbound.authentication_failures WHERE tenant_id=:t "
            "AND (CAST(:since AS timestamptz) IS NULL OR window_start > :since) "
            "ORDER BY window_start, surface, reason"
        ),
        {"t": tenant, "since": since},
    ).mappings()
    return [
        {
            "surface": row["surface"],
            "reason": row["reason"],
            "window_start": row["window_start"].isoformat(),
            "subject_kind": row["subject_kind"],
            "subject_id": str(row["subject_id"]) if row["subject_id"] else None,
            "count": int(row["count"]),
        }
        for row in rows
    ]


def _update(conn: Connection, tenant: UUID, destination_id: str, **values: Any) -> None:
    assignments = ", ".join(f"{key}=:{key}" for key in values)
    conn.execute(
        text(
            # The column names are keyword literals at every call site; values are bound.
            f"UPDATE execbound.export_cursors SET {assignments} "  # nosec B608 - literals
            "WHERE tenant_id=:t AND destination_id=:d"
        ),
        {"t": tenant, "d": destination_id, **values},
    )


def export_events(
    db: Database,
    admin: Identity,
    destinations: Sequence[Destination],
    *,
    limit: int = 100,
    clock: Clock | None = None,
) -> dict[str, dict[str, Any]]:
    """One bounded run per destination of the tenant; returns state, exported count and lag."""
    clock = clock or SystemClock()
    if type(limit) is not int or not 1 <= limit <= 1000:
        raise ExecutionError("INVALID_LIMIT")
    selected = [
        d for d in destinations if d.tenant_id == admin.tenant_id and d.kind == "security-events"
    ]
    result: dict[str, dict[str, Any]] = {}
    try:
        with db.transaction(admin.tenant_id) as conn:
            _admin(conn, admin, clock)
        with httpx.Client(trust_env=False, follow_redirects=False, timeout=5) as client:
            for destination in selected:
                outcome, code = _export_one(
                    db, admin, destination, client, limit=limit, clock=clock
                )
                result[destination.destination_id] = outcome
                # After the run's own transactions: what the cursor holds now, and what the
                # run sent. Never the destination's URL or secret, which are not fields.
                log_event(
                    "export.completed",
                    level="INFO" if code is None else "WARNING",
                    tenant_id=admin.tenant_id,
                    destination_id=destination.destination_id,
                    state=outcome["state"],
                    count=outcome["exported"],
                    code=code,
                )
        return result
    except ExecutionError:
        raise
    except (SQLAlchemyError, ValueError):
        raise ExecutionError() from None


def _export_one(
    db: Database,
    admin: Identity,
    destination: Destination,
    client: httpx.Client,
    *,
    limit: int,
    clock: Clock,
) -> tuple[dict[str, Any], str | None]:
    """One destination's run: its outcome, and the error its cursor holds after the run,
    None while the cursor is healthy."""
    tenant, name = admin.tenant_id, destination.destination_id
    lease = uuid4()
    with db.transaction(tenant) as conn:
        _admin(conn, admin, clock)
        now = store.now(clock)
        cursor = _cursor(conn, tenant, name, now)
        head = _head(conn, tenant)
        if not cursor:
            return {"state": "BUSY", "exported": 0, "lag": None}, None
        status = {"state": cursor["state"], "exported": 0, "lag": head - cursor["last_sequence"]}
        if cursor["state"] == "FAILED" or cursor["next_attempt_at"] > now:
            return status, cursor["last_error"]
        if cursor["lease_until"] is not None and cursor["lease_until"] > now:
            return status, cursor["last_error"]
        events = _events(conn, tenant, cursor["last_sequence"], limit)
        failures = _failures(conn, tenant, cursor["last_failure_window"])
        if not events and not failures:
            return status, cursor["last_error"]
        expected = cursor["last_event_hash"] or GENESIS
        for event in events:
            if event.previous_hash != expected:
                _update(conn, tenant, name, state="FAILED", last_error="CHAIN_MISMATCH")
                return {**status, "state": "FAILED"}, "CHAIN_MISMATCH"
            expected = event.event_hash
        try:
            reject_secrets([event.model_dump(mode="json") for event in events])
        except ReplayValidationError:
            _update(conn, tenant, name, state="FAILED", last_error="PAYLOAD_REFUSED")
            return {**status, "state": "FAILED"}, "PAYLOAD_REFUSED"
        batch = {
            "version": 1,
            "kind": "audit.events",
            "tenant_id": str(tenant),
            "destination_id": name,
            "from_sequence": events[0].sequence if events else cursor["last_sequence"],
            "to_sequence": events[-1].sequence if events else cursor["last_sequence"],
            "events": [event.model_dump(mode="json") for event in events],
            "authentication_failures": failures,
        }
        body = json.dumps(batch, sort_keys=True, separators=(",", ":")).encode()
        if len(body) > MAX_BATCH_BYTES:
            _update(conn, tenant, name, state="FAILED", last_error="BATCH_TOO_LARGE")
            return {**status, "state": "FAILED"}, "BATCH_TOO_LARGE"
        last_hash = events[-1].event_hash if events else (cursor["last_event_hash"] or GENESIS)
        last_window = max(f["window_start"] for f in failures) if failures else None
        batch_id = uuid5(BATCH_NAMESPACE, f"{name}:{last_hash}:{last_window}")
        _update(conn, tenant, name, lease_token=lease, lease_until=now + timedelta(seconds=30))
        _admin(conn, admin, clock)
    accepted = send_notification(
        destination, batch_id, body, client, max_bytes=MAX_BATCH_BYTES, accepted=EXPORT_ACCEPTED
    )
    with db.transaction(tenant) as conn:
        _admin(conn, admin, clock)
        now = store.now(clock)
        attempts = int(cursor["attempts"]) + 1
        if accepted:
            _update(
                conn,
                tenant,
                name,
                last_sequence=events[-1].sequence if events else cursor["last_sequence"],
                last_event_hash=last_hash if events else cursor["last_event_hash"],
                last_failure_window=datetime.fromisoformat(last_window)
                if last_window
                else cursor["last_failure_window"],
                attempts=0,
                next_attempt_at=now,
                lease_until=None,
                lease_token=None,
                last_error=None,
            )
            exported = len(events)
            state = "ACTIVE"
        elif attempts >= MAX_ATTEMPTS:
            _update(
                conn,
                tenant,
                name,
                state="FAILED",
                attempts=attempts,
                last_error="RECEIVER_UNAVAILABLE",
                lease_until=None,
                lease_token=None,
            )
            exported, state = 0, "FAILED"
        else:
            _update(
                conn,
                tenant,
                name,
                attempts=attempts,
                next_attempt_at=now + timedelta(seconds=BACKOFF[attempts - 1]),
                last_error="RECEIVER_UNAVAILABLE",
                lease_until=None,
                lease_token=None,
            )
            exported, state = 0, "ACTIVE"
        head = _head(conn, tenant)
        lag = head - (events[-1].sequence if accepted and events else cursor["last_sequence"])
        _admin(conn, admin, clock)
    return {"state": state, "exported": exported, "lag": lag}, (
        None if accepted else "RECEIVER_UNAVAILABLE"
    )


def export_status(
    db: Database,
    admin: Identity,
    destinations: Sequence[Destination],
    *,
    clock: Clock | None = None,
) -> dict[str, dict[str, Any]]:
    clock = clock or SystemClock()
    try:
        with db.transaction(admin.tenant_id) as conn:
            _admin(conn, admin, clock)
            head = _head(conn, admin.tenant_id)
            rows = conn.execute(
                text(
                    "SELECT destination_id, last_sequence, attempts, state, last_error, "
                    "next_attempt_at FROM execbound.export_cursors WHERE tenant_id=:t"
                ),
                {"t": admin.tenant_id},
            ).mappings()
            known = {row["destination_id"]: dict(row) for row in rows}
        result = {}
        for destination in destinations:
            if destination.tenant_id != admin.tenant_id or destination.kind != "security-events":
                continue
            row = known.get(destination.destination_id)
            result[destination.destination_id] = {
                "state": row["state"] if row else "NEW",
                "lag": head - (row["last_sequence"] if row else 0),
                "attempts": row["attempts"] if row else 0,
                "last_error": row["last_error"] if row else None,
                "next_attempt_at": row["next_attempt_at"].isoformat() if row else None,
            }
        return result
    except ExecutionError:
        raise
    except (SQLAlchemyError, ValueError):
        raise ExecutionError() from None


def resume_export(
    db: Database, admin: Identity, destination_id: str, *, clock: Clock | None = None
) -> None:
    clock = clock or SystemClock()
    try:
        with db.transaction(admin.tenant_id) as conn:
            _admin(conn, admin, clock)
            _update(
                conn,
                admin.tenant_id,
                destination_id,
                state="ACTIVE",
                attempts=0,
                next_attempt_at=store.now(clock),
                last_error=None,
                lease_until=None,
                lease_token=None,
            )
            _admin(conn, admin, clock)
    except ExecutionError:
        raise
    except (SQLAlchemyError, ValueError):
        raise ExecutionError() from None
