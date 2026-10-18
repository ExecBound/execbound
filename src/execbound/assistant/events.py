# SPDX-License-Identifier: AGPL-3.0-only
"""The turn's progress as server-sent events, read from the row and nothing else.

There is no in-process channel between the loop and the stream: the loop writes steps to the
turn row and the stream reads that row on an interval, so a second gateway process, a restart
mid-turn or a person opening the page late all see exactly what the row says. The stream emits
one `step` event per step it has not sent, one `done` event with the finished turn, and then
closes; it also closes at the deadline, by which time a reader has marked an unfinished turn
abandoned, so a stream never outlives the turn it follows.
"""

import json
from collections.abc import AsyncIterator, Awaitable, Callable
from typing import Any

import anyio

from execbound.assistant.turns import Turn

POLL_SECONDS = 0.5
DEADLINE_SECONDS = 90.0
MEDIA_TYPE = "text/event-stream"
# A proxy that buffers would hold every event until the stream closed, which is the one thing
# this must not do; the headers say so to nginx and to a browser's cache alike.
HEADERS = {"Cache-Control": "no-store", "X-Accel-Buffering": "no", "Connection": "keep-alive"}


def event(name: str, data: dict[str, Any]) -> bytes:
    """One event in the wire format: a name, one line of JSON, a blank line."""
    body = json.dumps(data, separators=(",", ":"), sort_keys=True)
    return f"event: {name}\ndata: {body}\n\n".encode()


def done_payload(turn: Turn) -> dict[str, Any]:
    """What the client needs to render the end of a turn without a second request."""
    answer = turn.answer or {}
    return {
        "turn_id": str(turn.turn_id),
        "state": turn.state,
        "reason": turn.reason,
        "paragraphs": answer.get("paragraphs", []),
        "cannot_answer": bool(answer.get("cannot_answer", False)),
        "cited_ids": list(turn.cited_ids),
    }


async def turn_events(
    read: Callable[[], Awaitable[Turn]],
    *,
    poll_seconds: float = POLL_SECONDS,
    deadline_seconds: float = DEADLINE_SECONDS,
) -> AsyncIterator[bytes]:
    """Follow one turn to its end, or to the deadline, emitting what the row gained.

    `read` is the caller's bounded read of that person's own turn; this function never
    touches the database itself, which is what lets a test drive it with a list of rows.
    """
    sent = 0
    elapsed = 0.0
    while True:
        turn = await read()
        for index in range(sent, len(turn.steps)):
            yield event("step", {"index": index, "text": turn.steps[index]})
        sent = len(turn.steps)
        if turn.state != "RUNNING":
            yield event("done", done_payload(turn))
            return
        if elapsed >= deadline_seconds:
            # The reader above marks an unfinished turn abandoned at its own deadline, so
            # this says what the row says rather than inventing an ending for it.
            yield event("done", done_payload(turn))
            return
        await anyio.sleep(poll_seconds)
        elapsed += poll_seconds
