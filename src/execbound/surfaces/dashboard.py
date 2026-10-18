# SPDX-License-Identifier: AGPL-3.0-only
"""Tenant home: a bounded, read-only overview that links to the detailed pages.

Nothing here changes state. Reads are tenant-scoped, bounded and rechecked against the
current session and authority before and after the queries, like the listings.
"""

from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import text

from execbound.execution import store
from execbound.execution.models import ExecutionError
from execbound.monitoring import store as monitor_store
from execbound.operations import CatalogError, operation
from execbound.runtime import Runtime
from execbound.spaces import space_clause, visible_spaces
from execbound.surfaces import outcomes
from execbound.surfaces.sessions import Session, check_session

RECENT = timedelta(days=7)
# An approver's view is limited to assigned canonical targets and actions, as the listings
# are; the scope clause is written out in each statement so no query text is assembled.
#
# A request held for a person whose approval is past its deadline reads, on the server's
# clock (`:now`), as `LAPSED` when nobody decided it and `UNUSED` when a person approved it
# and the agent did not use it, until the recovery run moves it to `STALE_AUTHORIZATION`.
# Such a row counts in a window by the moment it lapsed, its approval's `expires_at`, not
# by its last change, so an install that never sweeps does not add every old lapse to this
# week. `FAILED_EFFECT_UNKNOWN` is an open count, like an unsettled dispatch: it stays until
# a person corrects it, whatever its age. Nothing here writes.
_COUNTS = (
    "SELECT d.state, count(*) AS count FROM (SELECT CASE WHEN e.state='PENDING_APPROVAL' "
    "AND a.state IN ('PENDING', 'APPROVED') AND a.expires_at <= :now THEN CASE "
    "WHEN a.decided_at IS NULL THEN 'LAPSED' ELSE 'UNUSED' END ELSE e.state END AS state, "
    "CASE WHEN e.state='PENDING_APPROVAL' AND a.state IN ('PENDING', 'APPROVED') "
    "AND a.expires_at <= :now THEN a.expires_at ELSE e.changed_at END AS at "
    "FROM execbound.executions e LEFT JOIN execbound.approvals a "
    "ON a.tenant_id=e.tenant_id AND a.execution_id=e.execution_id WHERE e.tenant_id=:t "
    "AND (e.state IN ('PENDING_APPROVAL', 'DISPATCH_COMMITTED', 'INDETERMINATE', "
    "'FAILED_EFFECT_UNKNOWN') OR e.changed_at > :since) AND (NOT :scoped "
    "OR e.space_id=ANY(CAST(:read_spaces AS uuid[])) OR EXISTS ("
    "SELECT 1 FROM execbound.effective_approval_scopes s WHERE s.tenant_id=e.tenant_id "
    "AND s.approver_id=:p AND s.active AND s.canonical_target_id=e.canonical_target_id "
    "AND s.space_id=e.space_id "
    "AND s.action=e.frozen -> 'intent' ->> 'action'))/*space*/) d "
    "WHERE d.state IN ('PENDING_APPROVAL', 'DISPATCH_COMMITTED', 'INDETERMINATE', "
    "'FAILED_EFFECT_UNKNOWN') OR d.at > :since GROUP BY d.state"
)
# What a person can still decide: `records(pending=True)`'s predicate, the same scope.
_PENDING = (
    "SELECT count(*) FROM execbound.executions e WHERE e.tenant_id=:t "
    "AND e.state='PENDING_APPROVAL' AND EXISTS (SELECT 1 FROM execbound.approvals a "
    "WHERE a.tenant_id=e.tenant_id AND a.execution_id=e.execution_id AND a.state='PENDING' "
    "AND a.expires_at > :now) AND (NOT :scoped "
    "OR e.space_id=ANY(CAST(:read_spaces AS uuid[])) OR EXISTS ("
    "SELECT 1 FROM execbound.effective_approval_scopes s WHERE s.tenant_id=e.tenant_id "
    "AND s.approver_id=:p AND s.active AND s.canonical_target_id=e.canonical_target_id "
    "AND s.space_id=e.space_id "
    "AND s.action=e.frozen -> 'intent' ->> 'action'))/*space*/"
)
# The lapses still awaiting the sweep, whatever their age: the exact set Home's link opens
# (`outcome=lapsed&state=PENDING_APPROVAL`). This is the one place this module takes a
# predicate from `outcomes.py`, because a count and the list it opens must be one predicate.
_LAPSED = (
    "SELECT count(*) FROM execbound.executions e WHERE e.tenant_id=:t "
    "AND e.state='PENDING_APPROVAL' AND "
    + outcomes.PREDICATES["lapsed"]  # nosec B608 - a module literal
    + " AND (NOT :scoped "
    "OR e.space_id=ANY(CAST(:read_spaces AS uuid[])) OR EXISTS ("
    "SELECT 1 FROM execbound.effective_approval_scopes s WHERE s.tenant_id=e.tenant_id "
    "AND s.approver_id=:p AND s.active AND s.canonical_target_id=e.canonical_target_id "
    "AND s.space_id=e.space_id "
    "AND s.action=e.frozen -> 'intent' ->> 'action'))/*space*/"
)
# The newest request under the same scope, independent of the window: null means no request
# has reached a decision, since a refusal before one leaves no execution row. `board.py`
# holds the same statement, written out there for the same reason as here.
_LAST_REQUEST = (
    "SELECT e.created_at FROM execbound.executions e WHERE e.tenant_id=:t "
    "AND (NOT :scoped OR e.space_id=ANY(CAST(:read_spaces AS uuid[])) "
    "OR EXISTS (SELECT 1 FROM execbound.effective_approval_scopes s "
    "WHERE s.tenant_id=e.tenant_id AND s.approver_id=:p AND s.active "
    "AND s.canonical_target_id=e.canonical_target_id "
    "AND s.space_id=e.space_id "
    "AND s.action=e.frozen -> 'intent' ->> 'action'))/*space*/ "
    "ORDER BY e.created_at DESC, e.execution_id LIMIT 1"
)
_DENIALS = (
    "SELECT e.execution_id, e.changed_at, e.frozen -> 'intent' ->> 'action' AS action, "
    "ev.payload FROM execbound.executions e JOIN execbound.execution_events ev "
    "ON ev.tenant_id=e.tenant_id AND ev.execution_id=e.execution_id AND ev.to_state='DENIED' "
    "WHERE e.tenant_id=:t AND e.state='DENIED' AND e.changed_at > :since "
    "AND (NOT :scoped OR e.space_id=ANY(CAST(:read_spaces AS uuid[])) OR EXISTS ("
    "SELECT 1 FROM execbound.effective_approval_scopes s WHERE s.tenant_id=e.tenant_id "
    "AND s.approver_id=:p AND s.active AND s.canonical_target_id=e.canonical_target_id "
    "AND s.space_id=e.space_id "
    "AND s.action=e.frozen -> 'intent' ->> 'action'))/*space*/ "
    "ORDER BY e.changed_at DESC, e.execution_id LIMIT 10"
)


# The rows of one window bucketed by their last change, aligned to the window's start, and the
# counts of the window before it; the console's chart and its comparison line. The same scope
# clause as the counts, written out for the same reason.
_SERIES = (
    "SELECT date_bin(CAST(:step AS interval), d.at, CAST(:since AS timestamptz)) "
    "AS bucket, d.state, count(*) AS count FROM (SELECT CASE "
    "WHEN e.state='PENDING_APPROVAL' AND a.state IN ('PENDING', 'APPROVED') "
    "AND a.expires_at <= :now THEN CASE WHEN a.decided_at IS NULL THEN 'LAPSED' "
    "ELSE 'UNUSED' END ELSE e.state END AS state, CASE WHEN e.state='PENDING_APPROVAL' "
    "AND a.state IN ('PENDING', 'APPROVED') AND a.expires_at <= :now THEN a.expires_at "
    "ELSE e.changed_at END AS at FROM execbound.executions e "
    "LEFT JOIN execbound.approvals a "
    "ON a.tenant_id=e.tenant_id AND a.execution_id=e.execution_id "
    "WHERE e.tenant_id=:t AND ((e.changed_at > :since AND e.changed_at <= :until) "
    "OR e.state='PENDING_APPROVAL') "
    "AND (NOT :scoped OR e.space_id=ANY(CAST(:read_spaces AS uuid[])) OR EXISTS ("
    "SELECT 1 FROM execbound.effective_approval_scopes s WHERE s.tenant_id=e.tenant_id "
    "AND s.approver_id=:p AND s.active AND s.canonical_target_id=e.canonical_target_id "
    "AND s.space_id=e.space_id "
    "AND s.action=e.frozen -> 'intent' ->> 'action'))/*space*/) d "
    "WHERE d.at > :since AND d.at <= :until GROUP BY 1, 2"
)
_PREVIOUS = (
    "SELECT d.state, count(*) AS count FROM (SELECT CASE "
    "WHEN e.state='PENDING_APPROVAL' AND a.state IN ('PENDING', 'APPROVED') "
    "AND a.expires_at <= :now THEN CASE WHEN a.decided_at IS NULL THEN 'LAPSED' "
    "ELSE 'UNUSED' END ELSE e.state END AS state, CASE WHEN e.state='PENDING_APPROVAL' "
    "AND a.state IN ('PENDING', 'APPROVED') AND a.expires_at <= :now THEN a.expires_at "
    "ELSE e.changed_at END AS at FROM execbound.executions e "
    "LEFT JOIN execbound.approvals a "
    "ON a.tenant_id=e.tenant_id AND a.execution_id=e.execution_id "
    "WHERE e.tenant_id=:t AND ((e.changed_at > :before AND e.changed_at <= :after) "
    "OR e.state='PENDING_APPROVAL') "
    "AND (NOT :scoped OR e.space_id=ANY(CAST(:read_spaces AS uuid[])) OR EXISTS ("
    "SELECT 1 FROM execbound.effective_approval_scopes s WHERE s.tenant_id=e.tenant_id "
    "AND s.approver_id=:p AND s.active AND s.canonical_target_id=e.canonical_target_id "
    "AND s.space_id=e.space_id "
    "AND s.action=e.frozen -> 'intent' ->> 'action'))/*space*/) d "
    "WHERE d.at > :before AND d.at <= :after GROUP BY d.state"
)


def scoped_to(statement: str, filter_sql: str) -> str:
    """One statement with the one helper's predicate in the place it was written for.

    The marker is this module's own literal and the predicate comes from `space_clause`;
    every value in it is a bound parameter, so nothing a caller sends reaches the text.
    """
    return statement.replace("/*space*/", filter_sql)  # nosec B608 - literals only


DAY = timedelta(days=1)
_EPOCH = datetime(2000, 1, 1, tzinfo=UTC)


def calendar_window(
    until: datetime, window: timedelta, step: timedelta, offset: timedelta
) -> tuple[datetime, tuple[datetime, datetime]]:
    """A window on the viewer's calendar, and the stretch of the window before it to compare.

    A window of days starts at the viewer's midnight, so its last day is today; a day's
    window starts on the hour, so its last hour is this one. A window measured back from the
    instant of the read started mid-evening a week ago, and a chart labelled a day per four
    buckets put every label a day behind and none on today. `offset` is the viewer's own
    distance from UTC. The comparison is the window before, cut to the length this one has
    run, so a week read on its first morning is not set against seven whole days.
    """
    unit = step if window <= DAY else DAY
    local = until + offset
    since = local - (local - _EPOCH) % unit - (window - unit) - offset
    return since, (since - window, until - window)


def viewer_midnight(now: datetime, offset: timedelta | None) -> datetime:
    """The UTC instant the viewer's day began: UTC midnight when no offset is given.

    Home, the live board and the decided approvals count "today" from here, so the three
    share one day boundary for the same instant and offset.
    """
    return calendar_window(now, DAY, DAY, offset or timedelta(0))[0]


def action_label(action: str) -> str:
    try:
        return operation(action).label
    except CatalogError:
        return action


def overview(
    runtime: Runtime,
    session: Session,
    *,
    window: timedelta = RECENT,
    step: timedelta | None = None,
    offset: timedelta | None = None,
) -> dict[str, Any]:
    """Counts, the active bundle, recent denials and monitoring health for one tenant.

    `window` is how far back the settled counts reach (the page's seven days). With a
    `step`, the same scoped read also returns `series`, the rows of the window bucketed by
    their last change, and `previous`, the counts of the window before it, which is what
    the console's chart and its "more than the week before" line are drawn from. With the
    viewer's `offset` from UTC as well, the window is `calendar_window`'s; without one it is
    the `window` up to now.
    """
    identity = session.identity
    with runtime.db.transaction(identity.tenant_id) as conn:
        if identity.kind not in {"HUMAN_APPROVER", "ADMIN"}:
            raise ExecutionError("INVALID_IDENTITY")
        store.identity_check(conn, identity, runtime.clock, identity.kind)
        check_session(conn, session, runtime.clock)
        from execbound.access_control import review_read_spaces, review_scoped

        scoped = review_scoped(conn, identity)
        until = store.now(runtime.clock)
        since, previous_window = (
            calendar_window(until, window, step, offset)
            if step is not None and offset is not None
            else (until - window, (until - window * 2, until - window))
        )
        # The visible set, inside the fence, beside the identity and session rechecks.
        visibility = visible_spaces(conn, session)
        space = space_clause(visibility, "e")
        params = {
            "t": identity.tenant_id,
            "p": identity.principal_id,
            "scoped": scoped,
            "read_spaces": list(review_read_spaces(conn, identity)),
            "since": since,
            "now": until,
            **space.params,
        }
        # The selection is the **current space's** since migration 0041, so Home's bundle
        # line and its monitoring block follow the space the person is looking at.
        selected = visibility.current
        control = (
            conn.execute(
                text(
                    "SELECT (SELECT p.bundle_id FROM execbound.space_policy_selection p "
                    "WHERE p.tenant_id=c.tenant_id "
                    "AND (CAST(:space AS uuid) IS NULL OR p.space_id=:space) "
                    "ORDER BY p.changed_at DESC LIMIT 1) AS active_bundle_id, "
                    "c.enforcement_mode, c.approval_deadline_seconds, "
                    "(SELECT l.changed_at FROM execbound.policy_bundle_lifecycle l "
                    "WHERE l.tenant_id=c.tenant_id AND l.bundle_id = "
                    "(SELECT p.bundle_id FROM execbound.space_policy_selection p "
                    "WHERE p.tenant_id=c.tenant_id "
                    "AND (CAST(:space AS uuid) IS NULL OR p.space_id=:space) "
                    "ORDER BY p.changed_at DESC LIMIT 1)) AS changed_at "
                    "FROM execbound.tenant_policy_control c WHERE c.tenant_id=:t"
                ),
                {**params, "space": selected},
            )
            .mappings()
            .one_or_none()
        )
        counts = {
            row["state"]: int(row["count"])
            for row in conn.execute(text(scoped_to(_COUNTS, space.sql)), params).mappings()
        }
        denials = []
        for row in conn.execute(text(scoped_to(_DENIALS, space.sql)), params).mappings():
            payload = row["payload"] if isinstance(row["payload"], dict) else {}
            reasons = payload.get("reasons")
            if not isinstance(reasons, list):
                reasons = [payload["reason"]] if payload.get("reason") else []
            denials.append(
                {
                    "execution_id": row["execution_id"],
                    "changed_at": row["changed_at"],
                    "action_label": action_label(str(row["action"])),
                    "reasons": [str(reason) for reason in reasons],
                }
            )
        monitoring = None
        if identity.kind == "ADMIN":
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
            open_findings = conn.execute(
                text(
                    "SELECT count(*) FROM execbound.monitor_findings e "
                    "WHERE e.tenant_id=:t AND e.acknowledged_at IS NULL" + space.sql  # nosec B608 - one helper's predicate; values bound
                ),
                params,
            ).scalar_one()
            # Connections whose collection went quiet, by the one freshness rule (#678).
            overdue = conn.execute(
                text(monitor_store.OVERDUE_CONNECTIONS + space.sql),  # nosec B608 - a literal and the one helper's predicate
                {**params, **monitor_store.overdue_bounds(runtime.clock.now())},
            ).scalar_one()
            monitoring = {
                "sources": int(sources["total"]),
                "reporting": int(sources["reporting"]),
                "stale": int(sources["stale"]),
                "overdue": int(overdue),
                "open_findings": int(open_findings),
            }
        series: list[dict[str, Any]] = []
        previous: dict[str, int] = {}
        if step is not None:
            buckets = max(1, int(window // step))
            starts = [since + step * index for index in range(buckets)]
            found: dict[Any, dict[str, int]] = {start: {} for start in starts}
            for row in conn.execute(
                text(scoped_to(_SERIES, space.sql)), {**params, "step": step, "until": until}
            ).mappings():
                # A bucket the read aligned to `since` is one of `starts`; a row on the
                # boundary of the window lands in the last one rather than in none.
                start = min(row["bucket"], starts[-1])
                found.setdefault(start, {})[str(row["state"])] = int(row["count"])
            series = [{"start": start, "counts": found[start]} for start in starts]
            previous = {
                str(row["state"]): int(row["count"])
                for row in conn.execute(
                    text(scoped_to(_PREVIOUS, space.sql)),
                    {**params, "before": previous_window[0], "after": previous_window[1]},
                ).mappings()
            }
        pending = conn.execute(text(scoped_to(_PENDING, space.sql)), params).scalar_one()
        lapsed = conn.execute(text(scoped_to(_LAPSED, space.sql)), params).scalar_one()
        last_request = conn.execute(
            text(scoped_to(_LAST_REQUEST, space.sql)), params
        ).scalar_one_or_none()
        store.identity_check(conn, identity, runtime.clock, identity.kind)
        check_session(conn, session, runtime.clock)
    return {
        "since": since,
        "until": until,
        "counts": counts,
        "series": series,
        "previous": previous,
        "bundle_id": control["active_bundle_id"] if control else None,
        "activated_at": control["changed_at"] if control else None,
        "mode": str(control["enforcement_mode"]) if control else "ENFORCE",
        "deadline": (
            "off (context validity)"
            if control and control["approval_deadline_seconds"] is None
            else f"{control['approval_deadline_seconds'] if control else 120} seconds"
        ),
        # What a person can still decide; a request whose approval lapsed is not in it.
        "pending": int(pending),
        # Lapses still awaiting the recovery run's sweep, unwindowed: awaiting cleanup.
        "lapsed": int(lapsed),
        "last_request_at": last_request,
        "unsettled": counts.get("DISPATCH_COMMITTED", 0) + counts.get("INDETERMINATE", 0),
        "denied": counts.get("DENIED", 0),
        "executed": counts.get("EXECUTED", 0),
        "observed": counts.get("OBSERVED", 0),
        "denials": denials,
        "monitoring": monitoring,
    }
