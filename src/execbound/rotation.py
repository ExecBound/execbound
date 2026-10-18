# SPDX-License-Identifier: AGPL-3.0-only
"""What must settle or expire before a signing or evidence key can be retired."""

from dataclasses import dataclass
from datetime import datetime
from uuid import UUID

from sqlalchemy import text
from sqlalchemy.exc import SQLAlchemyError

from execbound.db import Database
from execbound.execution import store
from execbound.execution.models import ExecutionError
from execbound.identity import Identity
from execbound.resolution.models import Clock, SystemClock


@dataclass(frozen=True)
class RotationReadiness:
    """Per-account unsettled operations still needing their evidence key, and the latest
    expiry of anything signed with the continuation ring (approvals and human sessions)."""

    unsettled: tuple[tuple[UUID, int], ...]
    latest_approval_expiry: datetime | None
    latest_session_expiry: datetime | None


def rotation_readiness(
    db: Database, admin: Identity, clock: Clock | None = None
) -> RotationReadiness:
    """A workspace administrator's read without the fence; it changes nothing and reveals no
    key. It lists every connector account of every space, so an administrator narrowed to
    spaces is refused as an approver is (decided 8 October 2026)."""
    clock = clock or SystemClock()
    try:
        with db.transaction(admin.tenant_id) as conn:
            store.workspace_admin_check(conn, admin, clock)
            unsettled = conn.execute(
                text(
                    "SELECT (frozen -> 'intent' ->> 'account_id')::uuid AS account, count(*) "
                    "FROM execbound.executions WHERE tenant_id=:t "
                    "AND state IN ('DISPATCH_COMMITTED', 'INDETERMINATE') "
                    "GROUP BY 1 ORDER BY 1"
                ),
                {"t": admin.tenant_id},
            ).all()
            approvals = conn.execute(
                text(
                    "SELECT max(expires_at) FROM execbound.approvals "
                    "WHERE tenant_id=:t AND state IN ('PENDING', 'APPROVED')"
                ),
                {"t": admin.tenant_id},
            ).scalar_one()
            sessions = conn.execute(
                text(
                    "SELECT max(expires_at) FROM execbound.human_sessions "
                    "WHERE tenant_id=:t AND revoked_at IS NULL"
                ),
                {"t": admin.tenant_id},
            ).scalar_one()
        return RotationReadiness(
            tuple((row[0], int(row[1])) for row in unsettled), approvals, sessions
        )
    except ExecutionError:
        raise
    except (SQLAlchemyError, ValueError):
        raise ExecutionError() from None
