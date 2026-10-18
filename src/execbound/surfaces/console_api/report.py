# SPDX-License-Identifier: AGPL-3.0-only
"""`GET /api/console/v1/report` and `/report.csv`: what ExecBound did over a range (#678).

Both read `value.for_session`, the reader's own authority under one transaction, for the range
Home reads (`range` and `utc_offset`, validated exactly as `/overview` validates them). The
JSON is Home's "What ExecBound did" card and the printable report page; the CSV is the same
read as fixed rows.

The CSV is a download a plain link starts, so it carries no `x-execbound-workspace` header:
it takes the session generation as a `generation` query key, as the board stream does, and a
stale tab gets 409 `WORKSPACE_CHANGED` rather than another workspace's report. Every cell is
quoted, a cell a spreadsheet would evaluate is prefixed with `'`, the workspace name appears
once in its own row, and the rows are checked for secrets before they are sent.
"""

import csv
import io
from datetime import UTC, datetime

from fastapi import APIRouter, Request
from pydantic import BaseModel
from starlette.concurrency import run_in_threadpool
from starlette.responses import Response

from execbound.logging_schema import log_event
from execbound.personal_tokens import TokenSession
from execbound.replay.verify import ReplayValidationError, reject_secrets
from execbound.runtime import Runtime
from execbound.surfaces.console_api.board import same_generation
from execbound.surfaces.console_api.errors import ApiError
from execbound.surfaces.console_api.guards import ApiGuards
from execbound.surfaces.console_api.overview import Range, chosen_window
from execbound.surfaces.human import HumanConfig
from execbound.surfaces.value import Report, for_session

QUERY = frozenset({"range", "utc_offset"})
CSV_QUERY = QUERY | {"generation"}


class TopActionView(BaseModel):
    action: str
    action_label: str
    count: int


class RefusedView(BaseModel):
    policy: int
    limit: int
    busy: int
    top_actions: list[TopActionView]


class HeldView(BaseModel):
    total: int
    approved: int
    approved_unused: int
    refused: int
    lapsed: int
    closed: int
    waiting: int
    median_seconds_to_decide: int | None


class UncertainView(BaseModel):
    settled: int
    unsettled_now: int
    effect_unknown: int


class ObservedValueView(BaseModel):
    total: int
    would_refuse: int
    would_refuse_by_limit: int
    would_hold: int
    would_run: int


class MonitoringValueView(BaseModel):
    """Reported by sources, not enforced."""

    quiet_sources: int
    open_findings: int


class ReportView(BaseModel):
    """What ExecBound recorded for requests made in the window, in the reader's scope.

    `refused_before_decision` is null where it cannot be scoped to the reader: such a refusal
    names no target or space. `monitoring` is an administrator's alone.
    """

    range: Range
    since: datetime
    until: datetime
    mode: str
    space: str
    requests: int
    refused: RefusedView
    held: HeldView
    uncertain: UncertainView
    observed: ObservedValueView
    refused_before_decision: int | None
    monitoring: MonitoringValueView | None


def report_view(chosen: Range, report: Report) -> ReportView:
    counts = report.counts
    return ReportView(
        range=chosen,
        since=report.since,
        until=report.until,
        mode=report.mode,
        space=report.space,
        requests=counts.requests,
        refused=RefusedView(
            policy=counts.refused_policy,
            limit=counts.refused_limit,
            busy=counts.refused_busy,
            top_actions=[
                TopActionView(action=top.action, action_label=top.action_label, count=top.count)
                for top in counts.top_actions
            ],
        ),
        held=HeldView(
            total=counts.held_total,
            approved=counts.approved,
            approved_unused=counts.approved_unused,
            refused=counts.refused_by_person,
            lapsed=counts.lapsed,
            closed=counts.closed,
            waiting=counts.waiting,
            median_seconds_to_decide=counts.median_seconds_to_decide,
        ),
        uncertain=UncertainView(
            settled=counts.settled,
            unsettled_now=counts.unsettled_now,
            effect_unknown=counts.effect_unknown,
        ),
        observed=ObservedValueView(
            total=counts.observed_total,
            would_refuse=counts.would_refuse,
            would_refuse_by_limit=counts.would_refuse_by_limit,
            would_hold=counts.would_hold,
            would_run=counts.would_run,
        ),
        refused_before_decision=counts.refused_before_decision,
        monitoring=(
            MonitoringValueView(
                quiet_sources=counts.quiet_sources, open_findings=counts.open_findings
            )
            if counts.quiet_sources is not None and counts.open_findings is not None
            else None
        ),
    )


# A cell a spreadsheet would read as a formula starts with one of these; it is prefixed.
FORMULA = ("=", "+", "-", "@", "\t", "\r")


def cell(value: object) -> str:
    """One CSV cell as text a spreadsheet shows rather than evaluates."""
    written = "" if value is None else str(value)
    return "'" + written if written.startswith(FORMULA) else written


def rows(view: ReportView, workspace: str) -> list[tuple[str, str, object]]:
    """The report as `section, measure, value`: fixed copy, the counts, and the workspace and
    the space it covers, each named once."""
    found: list[tuple[str, str, object]] = [
        ("report", "workspace", workspace),
        ("report", "space", view.space),
        ("report", "requests made since", view.since.astimezone(UTC).isoformat()),
        ("report", "requests made until", view.until.astimezone(UTC).isoformat()),
        ("report", "mode", view.mode),
        ("requests", "requests made", view.requests),
        ("refused", "by policy or a failed check", view.refused.policy),
        ("refused", "by an impact limit", view.refused.limit),
        ("refused", "because another request held the target", view.refused.busy),
    ]
    found += [
        ("refused by policy, top actions", top.action_label, top.count)
        for top in view.refused.top_actions
    ]
    found += [
        ("held for a person", "held", view.held.total),
        ("held for a person", "approved", view.held.approved),
        ("held for a person", "approved, not used before the deadline", view.held.approved_unused),
        ("held for a person", "refused", view.held.refused),
        ("held for a person", "lapsed before a decision", view.held.lapsed),
        ("held for a person", "closed without a decision", view.held.closed),
        ("held for a person", "still waiting", view.held.waiting),
        ("held for a person", "median seconds to decide", view.held.median_seconds_to_decide),
        ("uncertain dispatches", "settled", view.uncertain.settled),
        ("uncertain dispatches", "still unsettled", view.uncertain.unsettled_now),
        ("uncertain dispatches", "effect unknown", view.uncertain.effect_unknown),
        ("observe mode, nothing enforced", "observed", view.observed.total),
        ("observe mode, nothing enforced", "would have refused", view.observed.would_refuse),
        (
            "observe mode, nothing enforced",
            "would have refused by a limit",
            view.observed.would_refuse_by_limit,
        ),
        ("observe mode, nothing enforced", "would have held", view.observed.would_hold),
        ("observe mode, nothing enforced", "would have run", view.observed.would_run),
        (
            "refused before a decision",
            "no Activity record; not counted for a narrowed view",
            view.refused_before_decision,
        ),
    ]
    if view.monitoring is not None:
        found += [
            ("monitoring, reported by sources", "quiet sources", view.monitoring.quiet_sources),
            ("monitoring, reported by sources", "open findings", view.monitoring.open_findings),
        ]
    found.append(
        (
            "note",
            "counts",
            "Counts of what ExecBound recorded. A refusal is not proof that harm was prevented.",
        )
    )
    return found


def csv_text(view: ReportView, workspace: str) -> str:
    buffer = io.StringIO()
    writer = csv.writer(buffer, quoting=csv.QUOTE_ALL, lineterminator="\r\n")
    writer.writerow(("section", "measure", "value"))
    for section, measure, value in rows(view, workspace):
        writer.writerow((cell(section), cell(measure), cell(value)))
    return buffer.getvalue()


def report_routes(
    routes: APIRouter, runtime: Runtime, config: HumanConfig, guards: ApiGuards
) -> None:
    @routes.get("/report", response_model=ReportView, operation_id="readReport")
    async def read_report(
        request: Request, range: str | None = None, utc_offset: str | None = None
    ) -> ReportView:
        """Requests made in the range, in the reader's scope; `utc_offset` is the viewer's
        minutes east of UTC, as on `/overview`."""
        session, _ = await guards.session(request, query=QUERY)
        chosen, window, step, offset = chosen_window(request)
        report = await run_in_threadpool(for_session, runtime, session, window, step, offset)
        return report_view(chosen, report)

    @routes.get(
        "/report.csv",
        operation_id="downloadReport",
        response_class=Response,
        responses={
            200: {
                "description": "The same report as `section,measure,value` rows.",
                "content": {"text/csv": {"schema": {"type": "string"}}},
            }
        },
    )
    async def download_report(
        request: Request,
        range: str | None = None,
        utc_offset: str | None = None,
        generation: str | None = None,
    ) -> Response:
        """`generation` is the session generation the console holds, required for an account
        session, since a download link carries no workspace header."""
        session, _ = await guards.session(request, query=CSV_QUERY)
        # A personal access token is bound to one workspace and carries no generation.
        if not isinstance(session, TokenSession):
            same_generation(request, session)
        chosen, window, step, offset = chosen_window(request)
        report = await run_in_threadpool(for_session, runtime, session, window, step, offset)
        view = report_view(chosen, report)
        found = rows(view, report.workspace)
        try:
            reject_secrets([[str(value) for value in row] for row in found])
        except ReplayValidationError:
            log_event("dependency.unavailable", level="ERROR", code="PRIVATE_DATA")
            raise ApiError("UNAVAILABLE") from None
        day = view.until.astimezone(UTC).date().isoformat()
        return Response(
            csv_text(view, report.workspace),
            media_type="text/csv; charset=utf-8",
            headers={
                "Content-Disposition": (
                    f'attachment; filename="execbound-report-{chosen}-{day}.csv"'
                ),
                "Cache-Control": "no-store",
            },
        )
