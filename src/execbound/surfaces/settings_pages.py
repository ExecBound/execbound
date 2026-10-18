# SPDX-License-Identifier: AGPL-3.0-only
"""Settings pages: a person's own sessions and credential; a tenant's mode, deadline and stop.

The personal page reads and writes only the acting principal's own rows: who they are, the
credential they signed in with, and every session signed in as them, which they can end
except for this one. The tenant page calls the store functions the CLI calls, with the
session's identity, so a change made here and a change made with `execbound tenant-mode`,
`tenant-approval-deadline`, `tenant-stop` or `tenant-resume` leave identical audit events.
Nothing here holds a table write privilege the pages did not already have.
"""

import math
from datetime import timedelta
from typing import Any
from urllib.parse import urlsplit

from sqlalchemy import text

from execbound import directory_store
from execbound.approval_routing import approval_windows
from execbound.execution import store
from execbound.execution.models import (
    APPROVAL_DEADLINE_BOUNDS,
    DEFAULT_APPROVAL_DEADLINE,
    ExecutionError,
)
from execbound.monitoring import store as monitor_store
from execbound.notifications import (
    APPROVAL_KINDS,
    CLASS_ORDER,
    MESSAGE_ORDER,
    announces_approvals,
)
from execbound.runtime import Runtime
from execbound.spaces import space_clause, visible_spaces
from execbound.surfaces.names import principal_facts
from execbound.surfaces.sessions import (
    Session,
    check_session,
)

# Codes the store functions raise, mapped to page copy; never a value from the form.
_PROBLEMS: dict[str, tuple[str, int]] = {
    "INVALID_MODE": ("Choose ENFORCE or OBSERVE.", 400),
    "INVALID_DEADLINE": ("The deadline is 120 to 3600 seconds, or off.", 400),
    "INVALID_REASON": ("A reason of 1 to 500 characters is required.", 400),
    "INVALID_STATE": ("That is already the current state; nothing was changed.", 409),
    "INVALID_IDENTITY": ("Administrator session required.", 403),
    "TENANT_STOPPED": ("The emergency stop is active.", 423),
    "SPACE_ARCHIVED": ("This space takes no new work.", 423),
}
_UNAVAILABLE = ("The setting could not be changed; nothing was changed.", 503)

_LATEST_EVENT = (
    "SELECT occurred_at, actor_id, payload FROM execbound.audit_events "
    "WHERE tenant_id=:t AND kind=:k ORDER BY sequence DESC LIMIT 1"
)


def personal_overview(runtime: Runtime, session: Session) -> dict[str, Any]:
    """The acting principal's tenant name, credential, live sessions and own directory link,
    beside the tenant's enabled provider, and nothing else."""
    identity = session.identity
    with runtime.db.transaction(identity.tenant_id) as conn:
        if identity.kind not in {"HUMAN_APPROVER", "ADMIN"}:
            raise ExecutionError("INVALID_IDENTITY")
        store.identity_check(conn, identity, runtime.clock, identity.kind)
        check_session(conn, session, runtime.clock)
        params = {
            "t": identity.tenant_id,
            "p": identity.principal_id,
            "c": identity.credential_id,
            "n": store.now(runtime.clock),
        }
        tenant_name = conn.execute(
            text("SELECT name FROM execbound.tenants WHERE tenant_id=:t"), params
        ).scalar_one()
        credential = (
            conn.execute(
                text(
                    "SELECT issued_at, expires_at FROM execbound.credentials "
                    "WHERE tenant_id=:t AND credential_id=:c"
                ),
                params,
            )
            .mappings()
            .one()
        )
        sessions = [
            {
                "session_id": row["session_id"],
                "created_at": row["created_at"],
                "expires_at": row["expires_at"],
                "label": row["label"] or "Other",
                "current": row["session_id"] == session.session_id,
            }
            for row in conn.execute(
                text(
                    "SELECT session_id, created_at, expires_at, label "
                    "FROM execbound.human_sessions WHERE tenant_id=:t AND principal_id=:p "
                    "AND revoked_at IS NULL AND expires_at > :n ORDER BY created_at DESC"
                ),
                params,
            ).mappings()
        ]
        # Whether this person has a password, so the page offers "change" or says where one
        # comes from. The hash is not read: this statement selects no column carrying it, and
        # the key is `has_password` because `password` is a name the shared secret guard
        # refuses in any rendered output, rightly.
        password = conn.execute(
            text(
                "SELECT 1 FROM execbound.principal_passwords WHERE tenant_id=:t AND principal_id=:p"
            ),
            params,
        ).scalar_one_or_none()
        email = conn.execute(
            text("SELECT email FROM execbound.principals WHERE tenant_id=:t AND principal_id=:p"),
            params,
        ).scalar_one_or_none()
        # The tenant's enabled provider and this person's own link (#253, #241), read for the
        # session's own principal under the same fence; nobody else's link is selected.
        directory = directory_store.own_directory(conn, identity.tenant_id, identity.principal_id)
        # The person's own weekly summary (#678): whether it is on, and the address it goes
        # to, resolved as the drain resolves it. Read before the account block below, which
        # sets the account context again for its own reads.
        from execbound import weekly_summary

        summary = {
            "subscribed": weekly_summary.subscribed(
                conn, identity.tenant_id, identity.principal_id
            ),
            "address": weekly_summary.resolve_address(
                conn, identity.tenant_id, identity.principal_id
            ),
        }
        # The person's own second-factor status, read as the step-up reads it.
        from execbound import mfa

        security = mfa.factor_summary(conn, session)
        if session.account_id is not None:
            from execbound.user_accounts import account_context

            account_context(conn, session.account_id)
            account_params = {"a": session.account_id, "n": runtime.clock.now()}
            email = conn.execute(
                text("SELECT email FROM execbound.user_accounts WHERE account_id=:a"),
                account_params,
            ).scalar_one()
            password = conn.execute(
                text("SELECT 1 FROM execbound.user_passwords WHERE account_id=:a"), account_params
            ).scalar_one_or_none()
            sessions = [
                {
                    "session_id": row["session_id"],
                    "created_at": row["created_at"],
                    "expires_at": row["expires_at"],
                    "label": row["label"],
                    "current": row["session_id"] == session.account_session_id,
                }
                for row in conn.execute(
                    text(
                        "SELECT session_id,created_at,expires_at,label "
                        "FROM execbound.account_sessions "
                        "WHERE account_id=:a AND revoked_at IS NULL "
                        "AND expires_at>:n ORDER BY created_at DESC"
                    ),
                    account_params,
                ).mappings()
            ]
        store.identity_check(conn, identity, runtime.clock, identity.kind)
        check_session(conn, session, runtime.clock)
    return {
        "tenant_name": str(tenant_name),
        "email": email,
        "has_password": password is not None,
        "credential": {
            "issued_at": credential["issued_at"],
            "expires_at": credential["expires_at"],
        },
        "sessions": sessions,
        "others": sum(1 for row in sessions if not row["current"]),
        "directory": directory,
        "weekly_summary": summary,
        "security": security,
    }


def tenant_overview(runtime: Runtime, session: Session) -> dict[str, Any]:
    """What the tenant is and how it decides, read for an administrator; nothing is changed."""
    identity = session.identity
    with runtime.db.transaction(identity.tenant_id) as conn:
        store.identity_check(conn, identity, runtime.clock, "ADMIN")
        check_session(conn, session, runtime.clock)
        # The tenant block keeps the tenant-level facts and its bundle and monitoring
        # counts become the current space's, so the sidebar's Monitoring pill follows the
        # space the person is looking at.
        visibility = visible_spaces(conn, session)
        space = space_clause(visibility, "e")
        params: dict[str, Any] = {
            "t": identity.tenant_id,
            "space": visibility.current,
            **space.params,
        }
        tenant_name = conn.execute(
            text("SELECT name FROM execbound.tenants WHERE tenant_id=:t"), params
        ).scalar_one()
        control = (
            conn.execute(
                text(
                    # The selection is the current space's since migration 0041; the
                    # mode, the deadline and the stop stay tenant-level.
                    "SELECT (SELECT p.bundle_id FROM execbound.space_policy_selection p "
                    "WHERE p.tenant_id=c.tenant_id "
                    "AND (CAST(:space AS uuid) IS NULL OR p.space_id=:space) "
                    "ORDER BY p.changed_at DESC LIMIT 1) AS active_bundle_id, "
                    "c.enforcement_mode, c.approval_deadline_seconds, "
                    "c.stop_id, c.stopped_at, c.stopped_by, c.stop_reason "
                    "FROM execbound.tenant_policy_control c WHERE c.tenant_id=:t"
                ),
                params,
            )
            .mappings()
            .one_or_none()
        )

        deadline = control["approval_deadline_seconds"] if control else DEFAULT_APPROVAL_DEADLINE
        # How long a held request can wait in the Spaces this person is looking at, against
        # the deadline just read (#678): an upper bound per action, never a configuration.
        windows = approval_windows(conn, identity.tenant_id, runtime.catalog, visibility, deadline)

        def latest(kind: str) -> dict[str, Any] | None:
            row = conn.execute(text(_LATEST_EVENT), {**params, "k": kind}).mappings().one_or_none()
            if row is None:
                return None
            payload = row["payload"] if isinstance(row["payload"], dict) else {}
            return {"at": row["occurred_at"], "by": row["actor_id"], "payload": payload}

        mode_change = latest("tenant.mode_changed")
        deadline_change = latest("tenant.approval_deadline_changed")
        activation = latest("tenant.stop_activated")
        stop = None
        if control and control["stop_id"] is not None:
            committed = None
            if activation and activation["payload"].get("stop_id") == str(control["stop_id"]):
                recorded = activation["payload"].get("dispatch_committed")
                committed = int(recorded) if isinstance(recorded, int) else None
            stop = {
                "stop_id": control["stop_id"],
                "stopped_at": control["stopped_at"],
                "stopped_by": control["stopped_by"],
                "reason": str(control["stop_reason"] or ""),
                "committed": committed,
            }
        sources = (
            conn.execute(
                text(
                    "SELECT count(*) FILTER (WHERE active AND revoked_at IS NULL) AS total, "
                    "count(*) FILTER (WHERE active AND revoked_at IS NULL "
                    "AND health_state='REPORTING') AS reporting, "
                    "count(*) FILTER (WHERE active AND revoked_at IS NULL "
                    "AND health_state='STALE') AS stale "
                    "FROM execbound.monitor_sources e WHERE e.tenant_id=:t" + space.sql  # nosec B608 - one helper's predicate; values bound
                ),
                params,
            )
            .mappings()
            .one()
        )
        # Connections whose collection went quiet, by the one freshness rule (#678).
        overdue = conn.execute(
            text(monitor_store.OVERDUE_CONNECTIONS + space.sql),  # nosec B608 - a literal and the one helper's predicate
            {**params, **monitor_store.overdue_bounds(runtime.clock.now())},
        ).scalar_one()
        open_findings = conn.execute(
            text(
                "SELECT count(*) FROM execbound.monitor_findings e "
                "WHERE e.tenant_id=:t AND e.acknowledged_at IS NULL" + space.sql  # nosec B608 - one helper's predicate; values bound
            ),
            params,
        ).scalar_one()
        # How fast this workspace's announcements arrived over seven days (#678): counts
        # and durations only, never a destination, an address or a person. Workspace-wide on
        # purpose, as the deadline it is read against is: an administrator narrowed to one
        # Space sees counts that include other Spaces, which carry no record, target, request
        # or person. `approval_notifications_pending_created` bounds the read to the window.
        delivery = (
            conn.execute(
                text(
                    "SELECT count(*) FILTER (WHERE state='DELIVERED') AS delivered, "
                    "percentile_cont(0.5) WITHIN GROUP (ORDER BY "
                    "extract(epoch FROM delivered_at - created_at)) "
                    "FILTER (WHERE state='DELIVERED') AS median, "
                    "percentile_cont(0.9) WITHIN GROUP (ORDER BY "
                    "extract(epoch FROM delivered_at - created_at)) "
                    "FILTER (WHERE state='DELIVERED') AS p90, "
                    "max(extract(epoch FROM delivered_at - created_at)) "
                    "FILTER (WHERE state='DELIVERED') AS slowest, "
                    "count(*) FILTER (WHERE state='FAILED' "
                    "AND last_error='LAPSED_BEFORE_DELIVERY') AS lapsed, "
                    "count(*) FILTER (WHERE state='FAILED' "
                    "AND last_error NOT IN ('LAPSED_BEFORE_DELIVERY', 'APPROVAL_CLOSED')) "
                    "AS failed "
                    "FROM execbound.approval_notifications WHERE tenant_id=:t "
                    "AND kind='approval.pending' AND created_at > :since"
                ),
                {**params, "since": store.now(runtime.clock) - DELIVERY_WINDOW},
            )
            .mappings()
            .one()
        )
        # Who changed the mode and the deadline and who stopped the workspace, by kind and
        # number, read for the ids these rows name (#678).
        principals = principal_facts(
            conn,
            identity.tenant_id,
            [
                found["by"]
                for found in (mode_change, deadline_change)
                if found is not None and found["by"] is not None
            ]
            + ([stop["stopped_by"]] if stop is not None else []),
        )
        store.identity_check(conn, identity, runtime.clock, "ADMIN")
        check_session(conn, session, runtime.clock)
    # Destinations are configuration, not rows: id, kind, host and how many approvers, never
    # the URL or the secret. A findings-only destination is listed on Alert settings, not here
    # (#31).
    destinations = [
        {
            "destination_id": d.destination_id,
            "kind": d.kind,
            "host": urlsplit(d.url).hostname or "",
            "approvers": None if d.approvers is None else len(d.approvers),
            # In the one canonical order, never sorted; the audit export lists none.
            "messages": (
                [m for m in MESSAGE_ORDER if m in d.messages] if d.kind in APPROVAL_KINDS else []
            ),
            "classes": (
                [c for c in CLASS_ORDER if c in d.classes] if d.kind in APPROVAL_KINDS else []
            ),
        }
        for d in runtime.notifications
        if d.tenant_id == identity.tenant_id
        and (d.kind == "security-events" or announces_approvals(d))
    ]
    delivered = int(delivery["delivered"])
    enough = delivered >= DELIVERY_PERCENTILE_MINIMUM
    return {
        "tenant_name": str(tenant_name),
        "tenant_id": identity.tenant_id,
        "mode": str(control["enforcement_mode"]) if control else "ENFORCE",
        "mode_change": mode_change,
        "deadline": deadline,
        "deadline_change": deadline_change,
        "bounds": APPROVAL_DEADLINE_BOUNDS,
        "stop": stop,
        "bundle_id": control["active_bundle_id"] if control else None,
        "monitoring": {
            "sources": int(sources["total"]),
            "reporting": int(sources["reporting"]),
            "stale": int(sources["stale"]),
            "overdue": int(overdue),
            "open_findings": int(open_findings),
        },
        "destinations": destinations,
        "delivery": {
            "window_days": DELIVERY_WINDOW.days,
            "delivered": delivered,
            "median_seconds": _whole_seconds(delivery["median"]) if enough else None,
            "p90_seconds": _whole_seconds(delivery["p90"]) if enough else None,
            "slowest_seconds": _whole_seconds(delivery["slowest"]) if delivered else None,
            "lapsed": int(delivery["lapsed"]),
            "failed": int(delivery["failed"]),
        },
        "principals": principals,
        "approval_windows": windows,
    }


# The settings read's delivery window, and the fewest deliveries a percentile is given for.
DELIVERY_WINDOW = timedelta(days=7)
DELIVERY_PERCENTILE_MINIMUM = 5


def _whole_seconds(value: object) -> int | None:
    """A duration rounded up, so a figure is never shorter than the time it stands for."""
    if value is None:
        return None
    # Six places first, so a float a hair over a whole second never rounds up a second.
    return math.ceil(round(float(str(value)), 6))


def parse_deadline(raw: str) -> int | None:
    """``off`` or digits, exactly as the CLI reads them; anything else is refused here."""
    value = raw.strip().lower()
    if value == "off":
        return None
    if not value.isdigit():
        raise ExecutionError("INVALID_DEADLINE")
    return int(value)
