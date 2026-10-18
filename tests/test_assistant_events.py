# SPDX-License-Identifier: AGPL-3.0-only
"""The turn stream: what it emits, and that it reads the row rather than the loop.

The route's end-to-end behaviour is `tests/test_console_api_assistant.py`; this drives the
producer with a list of rows, which is the only way to see a turn that gains steps while it is
being watched, and the only way to reach the deadline without waiting ninety seconds.
"""

import json
from datetime import UTC, datetime
from uuid import uuid4

import pytest

from execbound.assistant.events import turn_events
from execbound.assistant.turns import Turn

NOW = datetime(2026, 9, 19, 12, 0, tzinfo=UTC)


def turn(state="RUNNING", *, steps=(), reason=None, answer=None, cited=()):
    return Turn(
        turn_id=uuid4(),
        principal_id=uuid4(),
        context_kind="question",
        context_id=None,
        question="?",
        state=state,
        reason=reason,
        steps=tuple(steps),
        answer=answer,
        cited_ids=tuple(cited),
        model="scripted",
        tool_names=(),
        input_tokens=0,
        cached_tokens=0,
        output_tokens=0,
        created_at=NOW,
        completed_at=None if state == "RUNNING" else NOW,
        retired_at=None,
    )


def reader(rows):
    remaining = list(rows)

    async def read():
        return remaining.pop(0) if len(remaining) > 1 else remaining[0]

    return read


async def collect(read, **kwargs):
    return [block async for block in turn_events(read, poll_seconds=0, **kwargs)]


def parsed(block):
    head, data = block.decode().split("\n", 1)
    return head.removeprefix("event: "), json.loads(data.removeprefix("data: ").strip())


@pytest.mark.anyio
async def test_each_step_is_emitted_once_as_the_row_gains_it_then_the_ending():
    answer = {"paragraphs": [{"text": "Denied by a rule.", "ids": ["a"]}], "cannot_answer": False}
    rows = [
        turn(),
        turn(steps=("Read the active policy",)),
        turn(steps=("Read the active policy", "Read 3 denials")),
        turn(
            "COMPLETED",
            steps=("Read the active policy", "Read 3 denials"),
            answer=answer,
            cited=("a",),
        ),
    ]
    blocks = [parsed(block) for block in await collect(reader(rows))]
    assert [name for name, _ in blocks] == ["step", "step", "done"]
    assert [data["index"] for name, data in blocks if name == "step"] == [0, 1]
    assert [data["text"] for name, data in blocks if name == "step"] == [
        "Read the active policy",
        "Read 3 denials",
    ]
    ending = blocks[-1][1]
    assert ending["state"] == "COMPLETED" and ending["reason"] is None
    assert ending["paragraphs"] == answer["paragraphs"] and ending["cited_ids"] == ["a"]
    assert ending["cannot_answer"] is False


@pytest.mark.anyio
async def test_a_turn_already_finished_is_one_ending_and_no_wait():
    blocks = [
        parsed(block) for block in await collect(reader([turn("FAILED", reason="TIME_LIMIT")]))
    ]
    assert [name for name, _ in blocks] == ["done"]
    assert blocks[0][1]["reason"] == "TIME_LIMIT" and blocks[0][1]["paragraphs"] == []


@pytest.mark.anyio
async def test_the_stream_closes_at_its_deadline_saying_what_the_row_says():
    """A stream never outlives the turn it follows; the reader marks an unfinished turn
    abandoned at its own deadline, so this reports rather than invents an ending."""
    blocks = [parsed(block) for block in await collect(reader([turn()]), deadline_seconds=0.0)]
    assert [name for name, _ in blocks] == ["done"]
    assert blocks[0][1]["state"] == "RUNNING"
