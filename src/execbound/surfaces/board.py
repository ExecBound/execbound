# SPDX-License-Identifier: AGPL-3.0-only
"""A bounded request board: fifteen live minutes or a static historical window.

A board of lanes, not a map. Agents on the left, the checkpoint in the middle, targets on
the right, and every shot is a row this tenant already holds. ExecBound has no location
fact, so a globe would be invented geography; what moves here is the argument, drawn.

Nothing on this page changes anything. It is a second reader of the rows the dashboard and
the listings read, under the same approver scope, and it decides nothing.

The read is one transaction at REPEATABLE READ with a single server-fixed instant, rather
than one statement. The design asked for a single read so the parts could not disagree
about which fifteen minutes they describe; a snapshot buys that outright — every statement
sees the same committed state — and leaves four statements a person can read instead of one
union whose columns are padded to match. `db.transaction(..., snapshot=True)` already
exists for exactly this.
"""

from collections.abc import Mapping
from dataclasses import dataclass, field
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
from execbound.surfaces.dashboard import viewer_midnight
from execbound.surfaces.names import principal_handle, principal_name
from execbound.surfaces.sessions import Session, check_session

# The window every shot is drawn from, and the caps the design fixes. A board is a picture
# of one window, not a listing: past the caps it names the truncation explicitly.
WINDOW = timedelta(minutes=15)
WINDOWS = {"15m": WINDOW, "1h": timedelta(hours=1), "24h": timedelta(hours=24)}
AGENT_LANES = 12
TARGET_LANES = 24
MAX_SHOTS = 200
MAX_REJECTIONS = 50
MAX_OBSERVATIONS = 100
TICKER = 20
# Tenths of a second, as negative `animation-delay`, so a reload lands every shot within a
# tenth of where it was. Fifteen minutes is 9000 tenths; the classes stop at the last
# hundred and fifteen seconds of motion because nothing animates for longer than that.
MAX_AGE_TENTHS = 150

# An approver sees only assigned canonical targets and actions, as the listings and the
# dashboard do. The clause is written out in each statement rather than held in a constant
# and concatenated: `dashboard.py` says why — no query text is ever assembled — and bandit
# agrees, because a statement built by `+` is one refactor away from one built by a format
# string. The repetition is the point.

_SHOTS = (
    "SELECT e.execution_id, e.principal_id, e.canonical_target_id, e.state, "
    "e.created_at, e.changed_at, e.frozen -> 'intent' ->> 'action' AS action, "
    "p.label AS agent_label, p.number AS agent_number, a.expires_at, "
    "a.state AS approval_state, a.decided_at IS NOT NULL AS approval_decided, "
    "r.provider_id, r.resource_type, r.environment "
    "FROM execbound.executions e "
    "LEFT JOIN execbound.principals p "
    "ON p.tenant_id=e.tenant_id AND p.principal_id=e.principal_id "
    "LEFT JOIN execbound.approvals a "
    "ON a.tenant_id=e.tenant_id AND a.execution_id=e.execution_id "
    "LEFT JOIN execbound.resource_identities i "
    "ON i.tenant_id=e.tenant_id AND i.canonical_target_id=e.canonical_target_id "
    "LEFT JOIN execbound.resources r "
    "ON r.tenant_id=i.tenant_id AND r.account_id=i.account_id AND r.provider=i.provider "
    "AND r.resource_type=i.resource_type AND r.resource_id=i.resource_id "
    "WHERE e.tenant_id=:t AND e.created_at > :since "
    "AND (NOT :scoped OR e.space_id=ANY(CAST(:read_spaces AS uuid[])) "
    "OR EXISTS (SELECT 1 FROM execbound.effective_approval_scopes s "
    "WHERE s.tenant_id=e.tenant_id AND s.approver_id=:p AND s.active "
    "AND s.canonical_target_id=e.canonical_target_id "
    "AND s.space_id=e.space_id "
    "AND s.action=e.frozen -> 'intent' ->> 'action'))/*space*/ "
    "ORDER BY e.created_at DESC, e.execution_id LIMIT :shots"
)

# What the transition that denied a shot, or found its authorization stale, recorded. Read
# separately because a shot has at most one such transition and joining it above would fan the
# approvals out. The whole payload rather than one key, because a denial records its codes under
# either of two: admission and a reviewer write one `reason`, the policy writes `reasons`.
_REASONS = (
    "SELECT ev.execution_id, ev.payload "
    "FROM execbound.execution_events ev JOIN execbound.executions e "
    "ON e.tenant_id=ev.tenant_id AND e.execution_id=ev.execution_id "
    "WHERE ev.tenant_id=:t AND ev.to_state IN ('DENIED', 'STALE_AUTHORIZATION') "
    "AND ev.execution_id = ANY(:executions) "
    "AND ev.created_at > :since "
    "AND (NOT :scoped OR e.space_id=ANY(CAST(:read_spaces AS uuid[])) "
    "OR EXISTS (SELECT 1 FROM execbound.effective_approval_scopes s "
    "WHERE s.tenant_id=e.tenant_id AND s.approver_id=:p AND s.active "
    "AND s.canonical_target_id=e.canonical_target_id "
    "AND s.space_id=e.space_id "
    "AND s.action=e.frozen -> 'intent' ->> 'action'))/*space*/"
)

# Requests refused before any decision leave an audit event and no execution row, so they
# are the one shot that never reaches the checkpoint. They carry no canonical target, which
# is why an approver's board cannot show them: there is no scope to check them against.
# `execution.authority._rejection` writes the refusal's code under `reason`; this read named
# `code` until #545, so every refusal on the board arrived with an empty cause. Only
# admission's refusals are requests refused before a decision: the same event kind records a
# reviewer's, an administrator's, a report's and the surfaces' refusals, and an MCP refusal
# writes a `surface` event beside admission's, so reading every one of them drew people's
# refusals as agent requests and counted one agent request twice.
_REJECTIONS = (
    "SELECT a.occurred_at, a.actor_id, a.payload ->> 'reason' AS code "
    "FROM execbound.audit_events a WHERE a.tenant_id=:t AND a.kind='execution.rejected' "
    "AND a.payload ->> 'operation' = 'admit' "
    "AND a.occurred_at > :since AND NOT :scoped AND :unscoped "
    "ORDER BY a.occurred_at DESC, a.sequence LIMIT :rejections"
)

# What monitoring saw, and whether this tenant has anything watching at all. An
# observation carries no canonical target, so it requires broad read permission for its
# own Space. An exact approval assignment alone cannot reveal monitoring activity.
#
# A directory's own audit log (#355) records ExecBound's executions too, and the attempts it
# refused. Neither passed under the checkpoint: the entry an execution ExecBound settled
# accounts for went through it, and a refused attempt changed nothing. So an `entra_audit`
# observation is drawn only when it succeeded and is not one of those `first-consequential-
# action.v1` leaves out, by the store's own definition of the match, `settled`, which is the
# one piece of this statement not written out here: two copies of a security rule drift.
_OBSERVATIONS_SQL = (
    "WITH {settled} "
    "SELECT o.observation_id, o.action, o.target_ref, o.occurred_at, "
    "(f.finding_id IS NOT NULL) AS flagged "
    "FROM execbound.monitor_observations o "
    "LEFT JOIN execbound.monitor_findings f "
    "ON f.tenant_id=o.tenant_id AND f.observation_id=o.observation_id "
    "WHERE o.tenant_id=:t AND o.occurred_at > :since "
    "AND (o.kind <> 'entra_audit' OR (o.outcome = 'success' AND NOT EXISTS "
    "(SELECT 1 FROM settled s WHERE s.observation_id = o.observation_id))) "
    "AND (NOT :scoped OR o.space_id=ANY(CAST(:read_spaces AS uuid[])))/*space*/ "
    "ORDER BY o.occurred_at DESC, o.observation_id LIMIT :observations"
)
_OBSERVATIONS = _OBSERVATIONS_SQL.format(settled=monitor_store.SETTLED_OBSERVATIONS)

_WATCHING = (
    "SELECT EXISTS (SELECT 1 FROM execbound.monitor_sources e "
    "WHERE e.tenant_id=:t AND e.active "
    "AND (NOT :scoped OR e.space_id=ANY(CAST(:read_spaces AS uuid[])))/*space*/) "
    "OR EXISTS (SELECT 1 FROM execbound.monitor_connections e "
    "WHERE e.tenant_id=:t AND e.active "
    "AND (NOT :scoped OR e.space_id=ANY(CAST(:read_spaces AS uuid[])))/*space*/) "
    "AS watching"
)

# A request held for a person whose approval is past its deadline counts as `LAPSED`
# (nobody decided it) or `UNUSED` (approved, not used), on the server's clock, exactly as
# Home's overview reads it; neither is held for a person any more.
_TODAY = (
    "SELECT CASE WHEN e.state='PENDING_APPROVAL' AND a.state IN ('PENDING', 'APPROVED') "
    "AND a.expires_at <= :now THEN CASE WHEN a.decided_at IS NULL THEN 'LAPSED' "
    "ELSE 'UNUSED' END ELSE e.state END AS state, count(*) AS count "
    "FROM execbound.executions e LEFT JOIN execbound.approvals a "
    "ON a.tenant_id=e.tenant_id AND a.execution_id=e.execution_id "
    "WHERE e.tenant_id=:t AND e.created_at >= :midnight "
    "AND (NOT :scoped OR e.space_id=ANY(CAST(:read_spaces AS uuid[])) "
    "OR EXISTS (SELECT 1 FROM execbound.effective_approval_scopes s "
    "WHERE s.tenant_id=e.tenant_id AND s.approver_id=:p AND s.active "
    "AND s.canonical_target_id=e.canonical_target_id "
    "AND s.space_id=e.space_id "
    "AND s.action=e.frozen -> 'intent' ->> 'action'))/*space*/ GROUP BY 1"
)

# Independent of the chart window: quiet periods must not erase the latest known request.
# The tenant, approver and Space predicates are identical to the chart's own read.
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

# What each state is, drawn. The seven the design names, and the three it does not:
# ATTEMPTED is a request in flight with no decision recorded yet, which is exactly "the
# shot leaves the agent lane for the checkpoint"; RESERVED is allowed and not yet
# dispatched, so it is in flight to the target; FAILED_NOT_EXECUTED landed and nothing
# happened, the same picture as a stale authorization with a different reason. All ten are
# mapped because the demonstration asserts every state it produced appears here.
PHASES: dict[str, tuple[str, str]] = {
    "ATTEMPTED": ("shot-in", ""),
    "OBSERVED": ("observe", "would have been decided"),
    "DENIED": ("deny", "denied"),
    "PENDING_APPROVAL": ("hold", "held for a person"),
    "RESERVED": ("shot-out", "allowed"),
    "DISPATCH_COMMITTED": ("unsettled", "unsettled"),
    "INDETERMINATE": ("unsettled", "unsettled"),
    "EXECUTED": ("land", "executed"),
    "FAILED_NOT_EXECUTED": ("hollow", "nothing happened"),
    "STALE_AUTHORIZATION": ("hollow", "nothing happened"),
}


@dataclass(frozen=True)
class Lane:
    """One row of the board. `index` is server-assigned and is the only id the page uses."""

    index: int
    label: str
    group: str = ""
    handle: str | None = None
    """An agent lane whose label is an administrator's carries its handle, "Agent 3", so two
    agents labelled alike stay apart; `None` for a target lane and for an agent lane whose
    label already is its handle."""


@dataclass(frozen=True)
class Shot:
    """One request, at the phase its state puts it in and the age its times give it."""

    agent: int
    target: int | None
    phase: str
    word: str
    detail: str
    age: int
    """Tenths of a second since the moment this phase began, capped at the last class."""
    execution_id: UUID | None = None
    action: str | None = None
    target_label: str | None = None
    requested_at: datetime | None = None
    expires_at: datetime | None = None
    """The approval's deadline for a held shot, or the moment a lapsed or unused one ran out,
    as an instant the console prints in the viewer's zone; `None` for every other shot.
    `detail` keeps its "answer by … UTC" words for the server-rendered page, which says UTC
    and means it."""
    lapsed: bool = False
    """Held for a person, and the approval's deadline passed before anybody decided it."""
    unused: bool = False
    """Held for a person, approved, and not used by the agent before the deadline."""


@dataclass(frozen=True)
class Observation:
    """One thing monitoring saw and the checkpoint did not decide."""

    target: int | None
    label: str
    action: str
    flagged: bool
    age: int


@dataclass(frozen=True)
class Board:
    agents: tuple[Lane, ...] = ()
    targets: tuple[Lane, ...] = ()
    shots: tuple[Shot, ...] = ()
    ticker: tuple[Shot, ...] = ()
    more_agents: int = 0
    more_targets: int = 0
    counts: dict[str, int] = field(default_factory=dict)
    window_counts: dict[str, int] = field(default_factory=dict)
    window_limited: int = 0
    last_request_seconds: int | None = None
    last_request_at: datetime | None = None
    window_seconds: int = 900
    requests_truncated: bool = False
    rejections_truncated: bool = False
    observations_truncated: bool = False
    observations: tuple[Observation, ...] = ()
    watching: bool = False
    """Whether this tenant has an active monitoring source or connection at all.

    The band is rendered only when something is watching. A tenant with no source would
    otherwise get an empty band that reads as "monitoring saw nothing", which is a
    different and much stronger statement than "nothing is watching".
    """


def _age(moment: datetime | None, now: datetime) -> int:
    if moment is None:
        return MAX_AGE_TENTHS
    tenths = int((now - moment).total_seconds() * 10)
    return max(0, min(MAX_AGE_TENTHS, tenths))


def _target_group(resource_type: str | None, environment: str | None) -> str:
    if resource_type is None:
        return "Targets"
    label = {"endpoint": "Endpoints", "identity": "Identities"}.get(
        resource_type, resource_type.title() + "s"
    )
    return f"{label}, {environment}" if environment else label


def _prefix(value: UUID) -> str:
    """Eight characters of an identifier, for a lane with nothing better to be called."""
    return str(value)[:8]


def observed(
    records: list[dict[str, Any]], targets: tuple[Lane, ...], now: datetime
) -> tuple[Observation, ...]:
    """Place what monitoring saw against the lanes the board already drew.

    An observation names its target as the source spelled it, so it lands on a lane when
    that spelling matches one and runs the full width when it does not. Both are true to
    what the band says: monitoring saw this, and it did not pass the checkpoint. Inventing
    a lane for an unmatched target would claim a correspondence nobody established.
    """
    by_label = {lane.label: lane.index for lane in targets}
    return tuple(
        Observation(
            target=by_label.get(record["target_ref"] or ""),
            label=record["target_ref"] or "elsewhere",
            action=record["action"] or "",
            flagged=bool(record["flagged"]),
            age=_age(record["occurred_at"], now),
        )
        for record in records
    )


def _reason(payload: Mapping[str, Any]) -> str:
    """The one recorded reason a shot's detail shows: a reviewer's, a busy target's, a stale
    authorization's. A policy denial records its codes as a list instead and has none."""
    reason = payload.get("reason")
    return str(reason) if reason else ""


def _by_a_limit(row: dict[str, Any], recorded: Mapping[UUID, Mapping[str, Any]]) -> bool:
    """Whether a shot is a denial by a limit, by the rule its agent's category is read by.

    `store.denial_category` is what tells a denied agent `limit`: any `HARD_LIMIT:<rule id>`
    among the recorded codes, whatever sits beside it. `limit:<rule id>` is an approval
    obligation, which holds a request for a person and never denies one.
    """
    if row["state"] != "DENIED":
        return False
    return store.denial_category(recorded.get(row["execution_id"], {})) == "limit"


def lapse(row: Mapping[str, Any], now: datetime) -> str | None:
    """`LAPSED` or `UNUSED` for a held request whose approval ran out, by the server's clock.

    The same two classes `outcomes.PREDICATES` and Home's overview read: an approval still
    `PENDING` or `APPROVED` past its deadline while the request waits for the recovery run.
    Nothing is written; the sweep alone ends it.
    """
    if (
        row["state"] == "PENDING_APPROVAL"
        and row.get("approval_state") in {"PENDING", "APPROVED"}
        and row.get("expires_at") is not None
        and row["expires_at"] <= now
    ):
        return "UNUSED" if row.get("approval_decided") else "LAPSED"
    return None


def lanes(
    rows: list[dict[str, Any]],
    rejections: list[dict[str, Any]],
    recorded: Mapping[UUID, Mapping[str, Any]],
    now: datetime,
) -> Board:
    """Assign lanes and phases. Pure: no database, no clock, no template.

    Everything the picture depends on is decided here, so the caps, the ordering, the
    grouping and the overflow rows are testable without a browser and the template is left
    writing what it is handed. `recorded` is the payload of the transition that denied each
    denied shot, or found its authorization stale, keyed by execution.
    """
    agent_order: dict[UUID, Lane] = {}
    target_order: dict[UUID, Lane] = {}
    for row in rows:
        principal = row["principal_id"]
        if principal not in agent_order:
            label = row["agent_label"] or None
            number = row.get("agent_number")
            agent_order[principal] = Lane(
                len(agent_order),
                principal_name("AGENT", label, number, principal),
                handle=(
                    principal_handle("AGENT", number)
                    if label is not None and number is not None
                    else None
                ),
            )
        target = row["canonical_target_id"]
        if target is not None and target not in target_order:
            target_order[target] = Lane(
                len(target_order),
                row["provider_id"] or _prefix(target),
                _target_group(row["resource_type"], row["environment"]),
            )
    agents = tuple(lane for lane in agent_order.values() if lane.index < AGENT_LANES)
    targets = tuple(
        sorted(
            (lane for lane in target_order.values() if lane.index < TARGET_LANES),
            key=lambda lane: (lane.group, lane.label),
        )
    )

    shots: list[Shot] = []
    for row in rows:
        agent = agent_order[row["principal_id"]]
        if agent.index >= AGENT_LANES:
            continue
        target = target_order.get(row["canonical_target_id"])
        phase, word = PHASES.get(row["state"], ("shot-in", ""))
        detail = _reason(recorded.get(row["execution_id"], {}))
        if _by_a_limit(row, recorded):
            word = "limit"
        expires_at = None
        ran_out = lapse(row, now)
        if ran_out == "LAPSED":
            phase, word = "hollow", "lapsed"
            expires_at = row["expires_at"]
            detail = f"lapsed at {row['expires_at']:%H:%M:%S} UTC"
        elif ran_out == "UNUSED":
            phase, word = "hollow", "unused"
            expires_at = row["expires_at"]
            detail = f"approved, not used by {row['expires_at']:%H:%M:%S} UTC"
        elif row["state"] == "PENDING_APPROVAL" and row["expires_at"] is not None:
            expires_at = row["expires_at"]
            detail = f"answer by {row['expires_at']:%H:%M:%S} UTC"
        # A shot that never reached a target has no second leg to draw, and an observed one
        # is refused a second leg whatever its target: observe mode dispatches nothing. A
        # lapsed or unused approval is drawn hollow at the checkpoint: nothing ran.
        landed = phase in {"land", "hollow", "unsettled", "shot-out"} and ran_out is None
        shots.append(
            Shot(
                agent=agent.index,
                target=target.index if target is not None and landed else None,
                phase=phase,
                word=word,
                detail=detail,
                age=_age(row["changed_at"] or row["created_at"], now),
                execution_id=row["execution_id"],
                action=row["action"],
                target_label=target.label if target is not None else None,
                requested_at=row["created_at"],
                expires_at=expires_at,
                lapsed=ran_out == "LAPSED",
                unused=ran_out == "UNUSED",
            )
        )
    for rejection in rejections:
        shots.append(
            Shot(
                agent=-1,
                target=None,
                phase="short",
                word="refused before a decision",
                detail=rejection["code"] or "",
                age=_age(rejection["occurred_at"], now),
                requested_at=rejection["occurred_at"],
            )
        )
    newest = rows[0]["created_at"] if rows else None
    return Board(
        agents=agents,
        targets=targets,
        shots=tuple(shots),
        ticker=tuple(
            sorted(shots, key=lambda shot: shot.requested_at or now, reverse=True)[:TICKER]
        ),
        more_agents=max(0, len(agent_order) - AGENT_LANES),
        more_targets=max(0, len(target_order) - TARGET_LANES),
        window_counts=_tally(rows, now),
        window_limited=sum(1 for row in rows if _by_a_limit(row, recorded)),
        last_request_seconds=None if newest is None else int((now - newest).total_seconds()),
    )


def _tally(rows: list[dict[str, Any]], now: datetime) -> dict[str, int]:
    """The window's rows by state, a lapsed or unused approval under its own key, so "held for
    a person" counts only what a person can still decide."""
    counts: dict[str, int] = {}
    for row in rows:
        state = lapse(row, now) or row["state"]
        counts[state] = counts.get(state, 0) + 1
    return counts


def scoped_to(statement: str, filter_sql: str) -> str:
    """One statement with the one helper's predicate where it was written for.

    The marker is this module's own literal and the predicate comes from `space_clause`;
    every value in it is a bound parameter.
    """
    return statement.replace("/*space*/", filter_sql)  # nosec B608 - literals only


def read(
    conn: Connection,
    tenant: UUID,
    principal: UUID,
    scoped: bool,
    now: datetime,
    space: SpaceFilter = NO_SPACE_FILTER,
    window: timedelta = WINDOW,
    read_spaces: tuple[UUID, ...] = (),
    offset: timedelta | None = None,
) -> Board:
    """Bounded chart rows and scoped context, under one snapshot and one instant.

    `offset` is the viewer's distance from UTC: today's counters start at the viewer's
    midnight, computed from the same `now` as the snapshot, so a read that straddles midnight
    cannot count from one day and draw another. Without it they start at UTC midnight, which
    is what the server-rendered showcase says it counts.
    """
    params = {
        "t": tenant,
        "p": principal,
        "scoped": scoped,
        "read_spaces": [str(item) for item in read_spaces],
        "unscoped": not space.sql,
        "since": now - window,
        # The settled-execution match, over the executions any observation since then can match.
        "settled_since": now - window,
        "allowance": monitor_store.SETTLED_ALLOWANCE,
        **space.params,
        "shots": MAX_SHOTS + 1,
        "rejections": MAX_REJECTIONS + 1,
        "observations": MAX_OBSERVATIONS + 1,
        "midnight": viewer_midnight(now, offset),
        "now": now,
    }
    shots = conn.execute(text(scoped_to(_SHOTS, space.sql)), params).mappings()
    rows = [dict(row) for row in shots]
    requests_truncated = len(rows) > MAX_SHOTS
    rows = rows[:MAX_SHOTS]
    params["executions"] = [row["execution_id"] for row in rows]
    recorded = {
        row["execution_id"]: row["payload"] if isinstance(row["payload"], dict) else {}
        for row in conn.execute(text(scoped_to(_REASONS, space.sql)), params).mappings()
    }
    rejections = [dict(row) for row in conn.execute(text(_REJECTIONS), params).mappings()]
    rejections_truncated = len(rejections) > MAX_REJECTIONS
    rejections = rejections[:MAX_REJECTIONS]
    counted = conn.execute(text(scoped_to(_TODAY, space.sql)), params).mappings()
    today = {row["state"]: row["count"] for row in counted}
    last_request = conn.execute(
        text(scoped_to(_LAST_REQUEST, space.sql)), params
    ).scalar_one_or_none()
    board = lanes(rows, rejections, recorded, now)
    watching = False
    records: list[dict[str, Any]] = []
    if not scoped or read_spaces:
        watching = bool(conn.execute(text(scoped_to(_WATCHING, space.sql)), params).scalar_one())
        if watching:
            records = [
                dict(row)
                for row in conn.execute(
                    text(scoped_to(_OBSERVATIONS, space.sql.replace("e.", "o."))), params
                ).mappings()
            ]
    return Board(
        agents=board.agents,
        targets=board.targets,
        shots=board.shots,
        ticker=board.ticker,
        more_agents=board.more_agents,
        more_targets=board.more_targets,
        counts=today,
        window_counts=board.window_counts,
        window_limited=board.window_limited,
        last_request_seconds=(
            None if last_request is None else max(0, int((now - last_request).total_seconds()))
        ),
        last_request_at=last_request,
        window_seconds=int(window.total_seconds()),
        requests_truncated=requests_truncated,
        rejections_truncated=rejections_truncated,
        observations_truncated=len(records) > MAX_OBSERVATIONS,
        observations=observed(records[:MAX_OBSERVATIONS], board.targets, now),
        watching=watching,
    )


REFRESH_SECONDS = 5


def for_session(
    runtime: Runtime,
    session: Session,
    window: timedelta = WINDOW,
    offset: timedelta | None = None,
) -> Board:
    """One snapshot, the session's own authority, and the approver scope the listings use."""
    identity = session.identity
    with runtime.db.transaction(identity.tenant_id, snapshot=True) as conn:
        if identity.kind not in {"HUMAN_APPROVER", "ADMIN"}:
            raise ExecutionError("INVALID_IDENTITY")
        store.identity_check(conn, identity, runtime.clock, identity.kind)
        check_session(conn, session, runtime.clock)
        board = read(
            conn,
            identity.tenant_id,
            identity.principal_id,
            review_scoped(conn, identity),
            store.now(runtime.clock),
            # The visible set, inside the same transaction the rows are read in.
            space_clause(visible_spaces(conn, session), "e"),
            window,
            review_read_spaces(conn, identity),
            offset=offset,
        )
        # Rechecked after the read, as the listings are: an authority that ended while the
        # rows were being read must not be answered with them.
        store.identity_check(conn, identity, runtime.clock, identity.kind)
    return board
