# SPDX-License-Identifier: AGPL-3.0-only
"""What ExecBound did over a window: the value read behind Home's card and the report (#678).

Every count is over **requests made in the window**, `created_at` in `(since, until]`, because
that is what an Activity list filtered from the window's start shows; Home's tiles count by
last change, and the card says which it counts. Each count with an Activity link is computed
from the predicate that list filters on, `outcomes.COUNT_COLUMNS`, so a count and the list it
opens cannot disagree.

The read is the reader's own authority, as `dashboard.overview`'s is: the approver scope
clause is written out in each statement, the space helper's predicate is placed at its
`/*space*/` marker, and the session path rechecks identity and session before and after inside
one transaction. Requests refused before a decision leave an audit event and no execution row,
so they carry no target or space to scope them by: they are counted only for a reader not
narrowed to approval scopes and with no space filter, and are null for everybody else.

Nothing here writes. These are a workspace's own records, read back to its own people; none of
it is analytics and nothing leaves the deployment.
"""

from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any
from uuid import UUID

from sqlalchemy import text
from sqlalchemy.engine import Connection

from execbound.access_control import review_read_spaces, review_scoped
from execbound.execution import store
from execbound.execution.models import ExecutionError
from execbound.monitoring import store as monitor_store
from execbound.runtime import Runtime
from execbound.spaces import NO_SPACE_FILTER, SpaceFilter, space_clause, visible_spaces
from execbound.surfaces import outcomes
from execbound.surfaces.dashboard import action_label, calendar_window
from execbound.surfaces.sessions import Session, check_session

# Every count in one statement: the outcome columns from `outcomes.py`, the requests and the
# held and observed totals beside them, and the median time a person took to decide. The
# approver scope clause is written out, as `dashboard.py` writes it.
_COUNTS = (
    "SELECT count(*) AS requests, count(a.approval_id) AS held_total, "
    "count(*) FILTER (WHERE e.state = 'OBSERVED') AS observed_total, "
    "count(*) FILTER (WHERE e.state = 'EXECUTED') AS executed, "
    + outcomes.COUNT_COLUMNS  # nosec B608 - module literals only
    + ", percentile_cont(0.5) WITHIN GROUP (ORDER BY extract(epoch FROM "
    "a.decided_at - a.created_at)) FILTER (WHERE a.decided_at IS NOT NULL) AS median "
    "FROM execbound.executions e LEFT JOIN execbound.approvals a "
    "ON a.tenant_id=e.tenant_id AND a.execution_id=e.execution_id "
    "WHERE e.tenant_id=:t AND e.created_at > :since AND e.created_at <= :until "
    "AND (NOT :scoped OR e.space_id=ANY(CAST(:read_spaces AS uuid[])) OR EXISTS ("
    "SELECT 1 FROM execbound.effective_approval_scopes s WHERE s.tenant_id=e.tenant_id "
    "AND s.approver_id=:p AND s.active AND s.canonical_target_id=e.canonical_target_id "
    "AND s.space_id=e.space_id "
    "AND s.action=e.frozen -> 'intent' ->> 'action'))/*space*/"
)

# The three actions with the most requests refused by policy, by the catalog's label.
_TOP_ACTIONS = (
    "SELECT e.frozen -> 'intent' ->> 'action' AS action, count(*) AS count "
    "FROM execbound.executions e "
    "WHERE e.tenant_id=:t AND e.created_at > :since AND e.created_at <= :until AND "
    + outcomes.PREDICATES["refused_policy"]  # nosec B608 - a module literal
    + " AND (NOT :scoped OR e.space_id=ANY(CAST(:read_spaces AS uuid[])) OR EXISTS ("
    "SELECT 1 FROM execbound.effective_approval_scopes s WHERE s.tenant_id=e.tenant_id "
    "AND s.approver_id=:p AND s.active AND s.canonical_target_id=e.canonical_target_id "
    "AND s.space_id=e.space_id "
    "AND s.action=e.frozen -> 'intent' ->> 'action'))/*space*/ "
    "GROUP BY 1 ORDER BY 2 DESC, 1 LIMIT 3"
)

# Admission's refusals before a decision, with the board's `_REJECTIONS` conditions, counted.
# Copied rather than imported: statements are written out per module. The partial index
# `audit_events_rejected` is what this reads.
_REJECTIONS = (
    "SELECT count(*) FROM execbound.audit_events a WHERE a.tenant_id=:t "
    "AND a.kind='execution.rejected' AND a.payload ->> 'operation' = 'admit' "
    "AND a.occurred_at > :since AND a.occurred_at <= :until"
)

# An administrator's monitoring health, as `dashboard.overview` reads it: reported by
# sources and collected by connections, not enforced. Quiet is stale sources plus overdue
# connections, so this figure and Home's agree (#678).
_QUIET = (
    "SELECT count(*) FROM execbound.monitor_sources e WHERE e.tenant_id=:t "
    "AND e.active AND e.revoked_at IS NULL AND e.health_state='STALE'/*space*/"
)
# The synthetic directory's findings are not counted: shown labelled on Monitoring alone, they
# would otherwise reach the summary email as open findings of the workspace's own (#355, step 4).
_FINDINGS = (
    "SELECT count(*) FROM execbound.monitor_findings e "
    "WHERE e.tenant_id=:t AND e.acknowledged_at IS NULL "
    "AND NOT EXISTS (SELECT 1 FROM execbound.monitor_connections k "
    "WHERE k.tenant_id = e.tenant_id AND k.kind = 'fixture' "
    "AND k.connection_id = coalesce(e.connection_id, (SELECT ka.connection_id "
    "FROM execbound.monitor_agents ka WHERE ka.tenant_id = e.tenant_id "
    "AND ka.agent_id = e.agent_id)))/*space*/"
)


def scoped_to(statement: str, filter_sql: str) -> str:
    """One statement with the one helper's predicate where it was written for.

    The marker is this module's own literal and the predicate comes from `space_clause`;
    every value in it is a bound parameter.
    """
    return statement.replace("/*space*/", filter_sql)  # nosec B608 - literals only


@dataclass(frozen=True)
class ValueScope:
    """Whose authority a read counts under: one principal of one tenant, and its spaces."""

    tenant: UUID
    principal: UUID
    kind: str
    scoped: bool
    read_spaces: tuple[UUID, ...]
    space: SpaceFilter = NO_SPACE_FILTER


@dataclass(frozen=True)
class TopAction:
    action: str
    action_label: str
    count: int


@dataclass(frozen=True)
class ValueCounts:
    requests: int
    executed: int
    refused_policy: int
    refused_limit: int
    refused_busy: int
    top_actions: tuple[TopAction, ...]
    held_total: int
    approved: int
    approved_unused: int
    refused_by_person: int
    lapsed: int
    closed: int
    waiting: int
    median_seconds_to_decide: int | None
    settled: int
    unsettled_now: int
    effect_unknown: int
    observed_total: int
    would_refuse: int
    would_refuse_by_limit: int
    would_hold: int
    would_run: int
    refused_before_decision: int | None
    quiet_sources: int | None
    open_findings: int | None

    def empty(self) -> bool:
        """Nothing to say: no request, nothing waiting or unsettled, no refusal before one."""
        return (
            self.requests == 0
            and self.waiting == 0
            and self.unsettled_now == 0
            and self.effect_unknown == 0
            and not self.refused_before_decision
        )


def read(
    conn: Connection, scope: ValueScope, since: datetime, until: datetime, now: datetime
) -> ValueCounts:
    """Every count for one window under one authority, on the connection's transaction."""
    params: dict[str, Any] = {
        "t": scope.tenant,
        "p": scope.principal,
        "scoped": scope.scoped,
        "read_spaces": [str(item) for item in scope.read_spaces],
        "since": since,
        "until": until,
        "now": now,
        **scope.space.params,
    }
    row = conn.execute(text(scoped_to(_COUNTS, scope.space.sql)), params).mappings().one()
    top = tuple(
        TopAction(str(found["action"]), action_label(str(found["action"])), int(found["count"]))
        for found in conn.execute(text(scoped_to(_TOP_ACTIONS, scope.space.sql)), params).mappings()
    )
    rejections = None
    if not scope.scoped and not scope.space.sql:
        rejections = int(conn.execute(text(_REJECTIONS), params).scalar_one())
    quiet = findings = None
    if scope.kind == "ADMIN":
        quiet = int(
            conn.execute(text(scoped_to(_QUIET, scope.space.sql)), params).scalar_one()
        ) + int(
            conn.execute(
                text(monitor_store.OVERDUE_CONNECTIONS + scope.space.sql),  # nosec B608 - a literal and the one helper's predicate
                {**params, **monitor_store.overdue_bounds(now)},
            ).scalar_one()
        )
        findings = int(
            conn.execute(text(scoped_to(_FINDINGS, scope.space.sql)), params).scalar_one()
        )
    median = row["median"]
    return ValueCounts(
        requests=int(row["requests"]),
        executed=int(row["executed"]),
        refused_policy=int(row["refused_policy"]),
        refused_limit=int(row["refused_limit"]),
        refused_busy=int(row["refused_busy"]),
        top_actions=top,
        held_total=int(row["held_total"]),
        approved=int(row["approved"]),
        approved_unused=int(row["approved_unused"]),
        refused_by_person=int(row["refused_by_person"]),
        lapsed=int(row["lapsed"]),
        closed=int(row["closed"]),
        waiting=int(row["waiting"]),
        median_seconds_to_decide=None if median is None else round(float(median)),
        settled=int(row["settled"]),
        unsettled_now=int(row["unsettled_now"]),
        effect_unknown=int(row["effect_unknown"]),
        observed_total=int(row["observed_total"]),
        would_refuse=int(row["would_refuse"]),
        would_refuse_by_limit=int(row["would_refuse_by_limit"]),
        would_hold=int(row["would_hold"]),
        would_run=int(row["would_run"]),
        refused_before_decision=rejections,
        quiet_sources=quiet,
        open_findings=findings,
    )


@dataclass(frozen=True)
class Report:
    """One reader's report: its window, what it covers and the counts."""

    since: datetime
    until: datetime
    mode: str
    space: str
    workspace: str
    counts: ValueCounts


ALL_SPACES = "All spaces"


def for_session(
    runtime: Runtime,
    session: Session,
    window: timedelta,
    step: timedelta,
    offset: timedelta | None,
) -> Report:
    """The session's own report, with `dashboard.overview`'s fence, window and rechecks."""
    identity = session.identity
    with runtime.db.transaction(identity.tenant_id) as conn:
        if identity.kind not in {"HUMAN_APPROVER", "ADMIN"}:
            raise ExecutionError("INVALID_IDENTITY")
        store.identity_check(conn, identity, runtime.clock, identity.kind)
        check_session(conn, session, runtime.clock)
        until = store.now(runtime.clock)
        since = (
            calendar_window(until, window, step, offset)[0]
            if offset is not None
            else until - window
        )
        # The visible set, inside the fence beside the identity and session rechecks.
        visibility = visible_spaces(conn, session)
        scope = ValueScope(
            tenant=identity.tenant_id,
            principal=identity.principal_id,
            kind=identity.kind,
            scoped=review_scoped(conn, identity),
            read_spaces=tuple(review_read_spaces(conn, identity)),
            space=space_clause(visibility, "e"),
        )
        counts = read(conn, scope, since, until, until)
        names = (
            conn.execute(
                text(
                    "SELECT t.name AS workspace, c.enforcement_mode AS mode, "
                    "(SELECT s.name FROM execbound.spaces s WHERE s.tenant_id=t.tenant_id "
                    "AND s.space_id=CAST(:space AS uuid)) AS space "
                    "FROM execbound.tenants t LEFT JOIN execbound.tenant_policy_control c "
                    "ON c.tenant_id=t.tenant_id WHERE t.tenant_id=:t"
                ),
                {"t": identity.tenant_id, "space": visibility.current},
            )
            .mappings()
            .one()
        )
        store.identity_check(conn, identity, runtime.clock, identity.kind)
        check_session(conn, session, runtime.clock)
    return Report(
        since=since,
        until=until,
        mode=str(names["mode"] or "ENFORCE"),
        space=str(names["space"]) if names["space"] is not None else ALL_SPACES,
        workspace=str(names["workspace"]),
        counts=counts,
    )


def for_principal(
    conn: Connection,
    tenant: UUID,
    principal: UUID,
    since: datetime,
    until: datetime,
    now: datetime,
) -> tuple[ValueCounts | None, str | None]:
    """One recipient's counts, under their own authority at the moment of reading.

    The weekly summary's path: inside the tenant's own transaction, the recipient must be an
    active `ADMIN` or `HUMAN_APPROVER` of an active tenant, and the counts are read with their
    approval scopes and every space they may read, as "All spaces" reads them. A person whose
    authority narrowed since subscribing gets the narrowed counts; anyone else gets nothing,
    with the reason code: `PRINCIPAL_INACTIVE`.
    """
    from types import SimpleNamespace

    from execbound.access_control import access_visibility
    from execbound.spaces import Visibility

    found = (
        conn.execute(
            text(
                "SELECT p.kind, p.active AND t.active AS active FROM execbound.principals p "
                "JOIN execbound.tenants t ON t.tenant_id=p.tenant_id "
                "WHERE p.tenant_id=:t AND p.principal_id=:p"
            ),
            {"t": tenant, "p": principal},
        )
        .mappings()
        .one_or_none()
    )
    if found is None or not found["active"] or found["kind"] not in {"ADMIN", "HUMAN_APPROVER"}:
        return None, "PRINCIPAL_INACTIVE"
    identity = SimpleNamespace(tenant_id=tenant, principal_id=principal, kind=str(found["kind"]))
    everything, spaces, roles = access_visibility(conn, tenant, principal)
    visibility = Visibility(everything=everything, spaces=spaces, current=None, roles=roles)
    scope = ValueScope(
        tenant=tenant,
        principal=principal,
        kind=identity.kind,
        scoped=review_scoped(conn, identity),
        read_spaces=tuple(review_read_spaces(conn, identity)),
        space=space_clause(visibility, "e"),
    )
    return read(conn, scope, since, until, now), None
