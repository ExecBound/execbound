# SPDX-License-Identifier: AGPL-3.0-only
"""`GET /api/console/v1/overview`: the tenant at a glance, for the console's Home.

`dashboard.overview` is the read behind today's home page and this route wraps it with the
same scope: an approver's figures count only the executions their assigned scopes admit, an
administrator's count the tenant's, and monitoring health is an administrator's alone. The
range chooses the window and the bucket the chart is drawn in; the figures, the series and
the counts of the window before are one scoped read. The pending approvals in scope are the
pending listing's first five, for an approver, as the page shows them.

The figures are executed, denied, held, observed, stale and effect unknown. A request whose
approval lapsed is classified on the server's clock and counts as stale on both sides of the
recovery run's sweep (#678): before it, by the moment it lapsed; after it, as the
`STALE_AUTHORIZATION` row the sweep leaves. `pending_approvals` is what a person can still
decide, and `lapsed_approvals` the lapses before a decision still awaiting the sweep, whatever
their age. Unsettled and effect unknown are open counts: a row stays in them until it is
settled or corrected, however old it is.
"""

from collections.abc import Mapping
from datetime import datetime, timedelta
from typing import Literal, cast
from uuid import UUID

from fastapi import APIRouter, Request
from pydantic import BaseModel
from starlette.concurrency import run_in_threadpool

from execbound.runtime import Runtime
from execbound.surfaces.console_api.errors import ApiError
from execbound.surfaces.console_api.executions import (
    AgentView,
    TargetView,
    agent_view,
    target_view,
)
from execbound.surfaces.console_api.guards import ApiGuards
from execbound.surfaces.console_api.viewer_time import utc_offset as parse_offset
from execbound.surfaces.dashboard import overview
from execbound.surfaces.human import HumanConfig, records

Range = Literal["24h", "7d", "30d"]
RANGES: dict[str, tuple[timedelta, timedelta]] = {
    "24h": (timedelta(hours=24), timedelta(hours=1)),
    "7d": (timedelta(days=7), timedelta(hours=6)),
    "30d": (timedelta(days=30), timedelta(days=1)),
}
# Which figure a state counts towards. Open work (unsettled dispatches) is a figure of its
# own and is never a decision; a transient state counts nowhere.
OUTCOMES = {
    "EXECUTED": "executed",
    "DENIED": "denied",
    "PENDING_APPROVAL": "held",
    "OBSERVED": "observed",
    "STALE_AUTHORIZATION": "stale",
    "FAILED_NOT_EXECUTED": "stale",
    # An approval past its deadline, read on the server's clock before the sweep turns the
    # request into `STALE_AUTHORIZATION`: undecided, and approved but not used.
    "LAPSED": "stale",
    "UNUSED": "stale",
    # Its own figure since #678: the state that most needs a person must not read as stale.
    "FAILED_EFFECT_UNKNOWN": "unknown",
}
AWAITING = 5


class Figures(BaseModel):
    decisions: int
    executed: int
    denied: int
    held: int
    observed: int
    stale: int
    unknown: int


class Bucket(Figures):
    start: datetime


class AwaitingView(BaseModel):
    execution_id: UUID
    approval_id: UUID
    action_label: str
    target: TargetView
    agent: AgentView
    expires_at: datetime


class MonitoringView(BaseModel):
    sources: int
    reporting: int
    stale: int
    # Active connections whose collection evidence went stale, by the one freshness rule;
    # monitoring's quiet figure is `stale + overdue` (#678).
    overdue: int
    open_findings: int


class OverviewView(BaseModel):
    range: Range
    since: datetime
    until: datetime
    step_seconds: int
    figures: Figures
    previous: Figures
    series: list[Bucket]
    pending_approvals: int
    lapsed_approvals: int
    """Approvals that lapsed before a decision and still await the recovery run's sweep;
    unwindowed, the exact set `outcome=lapsed&state=PENDING_APPROVAL` lists."""
    last_request_at: datetime | None
    """The newest request in the reader's scope, or null when no request has reached a
    decision; a refusal before a decision leaves no execution row."""
    unsettled: int
    awaiting: list[AwaitingView]
    monitoring: MonitoringView | None
    mode: str


def figures(counts: Mapping[str, int]) -> Figures:
    totals = dict.fromkeys(("executed", "denied", "held", "observed", "stale", "unknown"), 0)
    for state, count in counts.items():
        outcome = OUTCOMES.get(str(state))
        if outcome is not None:
            totals[outcome] += int(count)
    return Figures(decisions=sum(totals.values()), **totals)


def chosen_window(request: Request) -> tuple[Range, timedelta, timedelta, timedelta | None]:
    """The `range` and `utc_offset` keys, validated as Home reads them; shared by the report,
    so the card and Home's tiles cannot read one window two ways."""
    chosen = request.query_params.get("range") or "7d"
    if chosen not in RANGES:
        raise ApiError("INVALID_REQUEST")
    window, step = RANGES[chosen]
    return cast(Range, chosen), window, step, parse_offset(request.query_params.get("utc_offset"))


def overview_routes(
    routes: APIRouter, runtime: Runtime, config: HumanConfig, guards: ApiGuards
) -> None:
    @routes.get("/overview", response_model=OverviewView, operation_id="readOverview")
    async def read_overview(
        request: Request, range: str | None = None, utc_offset: str | None = None
    ) -> OverviewView:
        """`utc_offset` is the viewer's minutes east of UTC; with it the window is theirs."""
        session, _ = await guards.session(request, query=frozenset({"range", "utc_offset"}))
        chosen, window, step, offset = chosen_window(request)
        data = await run_in_threadpool(
            overview, runtime, session, window=window, step=step, offset=offset
        )
        awaiting: list[AwaitingView] = []
        if session.identity.kind in {"HUMAN_APPROVER", "ADMIN"}:
            rows = await run_in_threadpool(
                records, runtime, session, pending=True, enriched=True, reviewing=True
            )
            awaiting = [
                AwaitingView(
                    execution_id=row["execution_id"],
                    approval_id=row["approval"]["approval_id"],
                    action_label=str(row["action_label"]),
                    target=target_view(row),
                    agent=agent_view(row["principal_id"], row.get("principals") or {}),
                    expires_at=row["approval"]["expires_at"],
                )
                for row in rows[:AWAITING]
                if row["approval"]
            ]
        monitoring = data["monitoring"]
        return OverviewView(
            range=chosen,
            since=data["since"],
            until=data["until"],
            step_seconds=int(step.total_seconds()),
            figures=figures(data["counts"]),
            previous=figures(data["previous"]),
            series=[
                Bucket(start=bucket["start"], **figures(bucket["counts"]).model_dump())
                for bucket in data["series"]
            ],
            pending_approvals=int(data["pending"]),
            lapsed_approvals=int(data["lapsed"]),
            last_request_at=data["last_request_at"],
            unsettled=int(data["unsettled"]),
            awaiting=awaiting,
            monitoring=MonitoringView(**monitoring) if monitoring else None,
            mode=str(data["mode"]),
        )
