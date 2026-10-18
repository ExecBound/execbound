# SPDX-License-Identifier: AGPL-3.0-only
"""The live board for the rebuilt console: one snapshot, and a stream of what changes.

The board's model is #280's and is not
restated here. This module is a second carrier of it, not a second reader: `GET /board` hands
back exactly what `surfaces/board.py` reads for the server-rendered page, under the same
snapshot transaction, the same identity and session rechecks and the same approver scope, and
`GET /board/stream` sends that same snapshot again whenever it has actually changed
(#333). No statement, bound or
fence is new here; if the page may not show a row, neither may this.

Two things about the stream are worth stating, because they are what make it cheap and honest.

**It sends the whole snapshot, not a difference.** A shot's age is tenths of a second since its
phase began, so every field of a difference would be a moving number and the client would have
to merge two clocks to draw one picture. Sending the picture whole means a reconnecting client
is correct immediately and a client that misses an event is correct at the next one.

**It compares a digest that leaves the ages out.** The ages change on every read by
construction, so a naive comparison would call every poll a change and the stream would be a
5-second poll with extra steps. What the digest covers is what a viewer would see change: the
lanes, the shots and their phases and words, the counters, the monitoring band. An idle board
therefore costs one heartbeat comment every fifteen seconds on the wire, and the CSS keeps
drawing the motion the last snapshot anchored without being told anything further.
"""

import hashlib
import json
from collections.abc import AsyncIterator
from datetime import datetime, timedelta
from time import monotonic
from typing import Any, Literal
from uuid import UUID

import anyio
from fastapi import APIRouter, Request
from pydantic import BaseModel
from starlette.concurrency import run_in_threadpool
from starlette.responses import StreamingResponse

from execbound.execution.models import ExecutionError
from execbound.runtime import Runtime
from execbound.surfaces.board import (
    MAX_AGE_TENTHS,
    PHASES,
    WINDOW,
    WINDOWS,
    Board,
    Shot,
    for_session,
)
from execbound.surfaces.console_api.guards import ApiGuards
from execbound.surfaces.console_api.viewer_time import utc_offset as parse_offset
from execbound.surfaces.human import HumanConfig
from execbound.surfaces.sessions import Session, SessionError

# How often the stream re-reads the board, how long it may stay silent, and how long one
# connection lives. The poll matches the page's own refresh interval, so an open stream costs
# the server exactly what the reloading page costs it today and no more. The session is
# rechecked by every one of those reads, so the session promise is kept by the poll rather than
# by a second timer: `STREAM_SESSION_SECONDS` is the promise that an open stream rechecks its
# session at least once a minute, and the poll is held under it by a test, so shortening one
# without the other cannot pass unnoticed.
STREAM_POLL_SECONDS = 5.0
STREAM_HEARTBEAT_SECONDS = 15.0
STREAM_SESSION_SECONDS = 60.0
# A stream is not a lease. Fifteen minutes and the connection ends; EventSource reopens it on
# its own, which is also how a wall display recovers from a proxy that dropped it silently.
STREAM_MAX_SECONDS = 900.0
RETRY_MILLISECONDS = 5000

# A shot that crossed the checkpoint is one whose phase has a second leg. Derived from `PHASES`
# rather than written out again, so the counter and the picture cannot come to disagree about
# what "allowed" means: this is the same predicate `board.lanes` uses to draw the second leg.
LANDED = frozenset({"land", "hollow", "unsettled", "shot-out"})
ALLOWED_STATES = frozenset(state for state, (phase, _) in PHASES.items() if phase in LANDED)
DENIED_STATES = frozenset(state for state, (phase, _) in PHASES.items() if phase == "deny")
HELD_STATES = frozenset(state for state, (phase, _) in PHASES.items() if phase == "hold")
OBSERVED_STATES = frozenset(state for state, (phase, _) in PHASES.items() if phase == "observe")
UNSETTLED_STATES = frozenset(state for state, (phase, _) in PHASES.items() if phase == "unsettled")


class BoardLane(BaseModel):
    """One row of the board. `index` is server assigned and is the only id the client draws."""

    index: int
    label: str
    group: str
    handle: str | None
    """An agent lane's handle, "Agent 3", beside an administrator's label; `null` for a target
    lane and for an agent lane whose label already is its handle (#678)."""


class BoardShot(BaseModel):
    """One request, at the phase its state puts it in and the age its event times give it."""

    agent: int
    target: int | None
    phase: str
    word: str
    detail: str
    age: int
    execution_id: UUID | None
    action: str | None = None
    target_label: str | None = None
    requested_at: datetime | None = None
    expires_at: datetime | None
    """A held shot's approval deadline, or when a lapsed or unused one ran out, which the
    console prints in the viewer's zone; `null` for every other shot."""
    lapsed: bool = False
    """The approval's deadline passed before anybody decided it; nothing ran."""
    unused: bool = False
    """The approval was approved and not used before its deadline; nothing ran."""


class BoardObservation(BaseModel):
    """One thing monitoring saw and the checkpoint did not decide."""

    target: int | None
    label: str
    action: str
    flagged: bool
    age: int


class BoardCounters(BaseModel):
    """The figures across the top, counted by the server so no viewer's clock is involved.

    `limited` and `refused` are known for the window and not for the day: a limit refusal is
    read from the codes its denial recorded, by the rule that tells the denied agent `limit`,
    and a request refused before a decision leaves no execution row at all, and both of those
    are bounded reads over the window rather than the day's tally. `null` says "not counted for
    this period", which is a different statement from zero and the only honest one here.
    """

    requests: int
    allowed: int
    denied: int
    held: int
    executed: int
    unsettled: int
    observed: int
    lapsed: int = 0
    """Held requests whose approval lapsed before a decision, by the server's clock. They are
    not in `held`, which counts what a person can still decide. An approved approval the
    agent did not use is in neither."""
    limited: int | None = None
    refused: int | None = None


class BoardView(BaseModel):
    """The whole board, as one value, for one moment the server fixed."""

    observed_at: datetime
    window_seconds: int
    max_age_tenths: int
    agents: list[BoardLane]
    targets: list[BoardLane]
    shots: list[BoardShot]
    ticker: list[BoardShot]
    more_agents: int
    more_targets: int
    today: BoardCounters
    window: BoardCounters
    last_request_seconds: int | None
    last_request_at: datetime | None = None
    requests_truncated: bool = False
    rejections_truncated: bool = False
    observations_truncated: bool = False
    observations: list[BoardObservation]
    watching: bool


def _tallied(tally: dict[str, int], *, limited: int | None, refused: int | None) -> BoardCounters:
    def of(states: frozenset[str]) -> int:
        return sum(count for state, count in tally.items() if state in states)

    return BoardCounters(
        requests=sum(tally.values()),
        allowed=of(ALLOWED_STATES),
        denied=of(DENIED_STATES),
        held=of(HELD_STATES),
        executed=tally.get("EXECUTED", 0),
        unsettled=of(UNSETTLED_STATES),
        observed=of(OBSERVED_STATES),
        lapsed=tally.get("LAPSED", 0),
        limited=limited,
        refused=refused,
    )


def view(board: Board, observed_at: datetime) -> BoardView:
    """The board object as the client's value. Pure: no database, no clock, no request."""
    limited = board.window_limited
    refused = sum(1 for shot in board.shots if shot.phase == "short")
    return BoardView(
        observed_at=observed_at,
        window_seconds=board.window_seconds,
        max_age_tenths=MAX_AGE_TENTHS,
        agents=[
            BoardLane(index=lane.index, label=lane.label, group=lane.group, handle=lane.handle)
            for lane in board.agents
        ],
        targets=[
            BoardLane(index=lane.index, label=lane.label, group=lane.group, handle=None)
            for lane in board.targets
        ],
        shots=[_shot(shot) for shot in board.shots],
        ticker=[_shot(shot) for shot in board.ticker],
        more_agents=board.more_agents,
        more_targets=board.more_targets,
        today=_tallied(board.counts, limited=None, refused=None),
        window=_tallied(board.window_counts, limited=limited, refused=refused),
        last_request_seconds=board.last_request_seconds,
        last_request_at=board.last_request_at,
        requests_truncated=board.requests_truncated,
        rejections_truncated=board.rejections_truncated,
        observations_truncated=board.observations_truncated,
        observations=[
            BoardObservation(
                target=seen.target,
                label=seen.label,
                action=seen.action,
                flagged=seen.flagged,
                age=seen.age,
            )
            for seen in board.observations
        ],
        watching=board.watching,
    )


def _shot(shot: Shot) -> BoardShot:
    return BoardShot(
        agent=shot.agent,
        target=shot.target,
        phase=shot.phase,
        word=shot.word,
        detail=shot.detail,
        age=shot.age,
        execution_id=shot.execution_id,
        action=shot.action,
        target_label=shot.target_label,
        requested_at=shot.requested_at,
        expires_at=shot.expires_at,
        lapsed=shot.lapsed,
        unused=shot.unused,
    )


# Everything that moves on its own. Excluded from the digest so an idle board is recognised as
# idle; included in the payload so a client that has just connected draws it in the right place.
MOVING: dict[str, Any] = {
    "observed_at": True,
    "last_request_seconds": True,
    "shots": {"__all__": {"age"}},
    "ticker": {"__all__": {"age"}},
    "observations": {"__all__": {"age"}},
}


def digest(current: BoardView) -> str:
    """What a viewer would see change, as one string the stream compares against the last."""
    payload = current.model_dump(mode="json", exclude=MOVING)
    return hashlib.sha256(json.dumps(payload, sort_keys=True).encode("utf-8")).hexdigest()


def snapshot(
    runtime: Runtime,
    session: Session,
    window: timedelta = WINDOW,
    offset: timedelta | None = None,
) -> BoardView:
    """The page's own read, as the client's value. Every call rechecks identity and session."""
    board = for_session(runtime, session, window, offset)
    return view(board, runtime.clock.now())


def _frame(name: str, data: str) -> bytes:
    """One server-sent event. The data is JSON on one line, so no line splitting is needed."""
    return f"event: {name}\ndata: {data}\n\n".encode()


async def _stream(
    runtime: Runtime,
    session: Session,
    request: Request,
    first: BoardView,
    offset: timedelta | None = None,
) -> AsyncIterator[bytes]:
    """Poll, send what changed, keep the connection warm, and stop when the session is gone."""
    yield f"retry: {RETRY_MILLISECONDS}\n\n".encode()
    yield _frame("board", first.model_dump_json())
    started = monotonic()
    spoke = started
    last = digest(first)
    while monotonic() - started < STREAM_MAX_SECONDS:
        await anyio.sleep(STREAM_POLL_SECONDS)
        if await request.is_disconnected():
            return
        try:
            current = await run_in_threadpool(snapshot, runtime, session, WINDOW, offset)
        except (ExecutionError, SessionError):
            # The session ended, the credential was revoked or the role changed while the
            # stream was open. The headers went out long ago, so there is no status left to
            # answer with: the honest end is to say so in the stream and stop, and the client
            # closes the connection rather than reconnecting into a refusal.
            yield _frame("closed", json.dumps({"reason": "session"}))
            return
        moment = digest(current)
        if moment != last:
            last = moment
            spoke = monotonic()
            yield _frame("board", current.model_dump_json())
        elif monotonic() - spoke >= STREAM_HEARTBEAT_SECONDS:
            spoke = monotonic()
            yield b": heartbeat\n\n"


def same_generation(request: Request, current: Session) -> None:
    """The workspace generation a URL carries, for a read no header can carry it on.

    `EventSource` and a plain download link send no `x-execbound-workspace` header, so the
    stream and the report's CSV take the session generation the console already holds as a
    `generation` query key, required for an account session: a stale tab on a workspace the
    person has since switched away from is answered 409 `WORKSPACE_CHANGED` rather than with
    the new workspace's data. The generation names a session and grants nothing.
    """
    from execbound.surfaces.console_api.errors import ApiError

    generation = request.query_params.get("generation")
    if (generation is not None and generation != str(current.session_id)) or (
        current.account_id is not None and generation is None
    ):
        raise ApiError("WORKSPACE_CHANGED")


def board_routes(
    routes: APIRouter, runtime: Runtime, config: HumanConfig, guards: ApiGuards
) -> None:
    @routes.get("/board", response_model=BoardView, operation_id="readBoard")
    async def read_board(
        request: Request,
        window: Literal["15m", "1h", "24h"] = "15m",
        utc_offset: str | None = None,
    ) -> BoardView:
        """`utc_offset` is the viewer's minutes east of UTC; with it today's counters start
        at the viewer's midnight instead of UTC midnight."""
        current, _ = await guards.session(request, query=frozenset({"window", "utc_offset"}))
        offset = parse_offset(request.query_params.get("utc_offset"))
        return await run_in_threadpool(snapshot, runtime, current, WINDOWS[window], offset)

    @routes.get(
        "/board/stream",
        operation_id="streamBoard",
        response_class=StreamingResponse,
        responses={
            200: {
                "description": (
                    "The board as server-sent events: a `board` event carrying the same "
                    "snapshot whenever it changes, a comment every fifteen seconds while it "
                    "does not, and a `closed` event when the session ends."
                ),
                "content": {"text/event-stream": {"schema": {"type": "string"}}},
            }
        },
    )
    async def stream_board(request: Request, utc_offset: str | None = None) -> StreamingResponse:
        # The first read happens here, before any byte of the stream, so a refusal is a typed
        # JSON answer with a status like every other route rather than a connection that opens
        # and immediately says something went wrong. The offset is parsed here too, for the
        # same reason, and every later poll counts from the same viewer's midnight.
        current, _ = await guards.session(request, query=frozenset({"generation", "utc_offset"}))
        offset = parse_offset(request.query_params.get("utc_offset"))
        same_generation(request, current)
        first = await run_in_threadpool(snapshot, runtime, current, WINDOW, offset)
        return StreamingResponse(
            _stream(runtime, current, request, first, offset),
            media_type="text/event-stream",
            headers={"Cache-Control": "no-store", "X-Accel-Buffering": "no"},
        )
