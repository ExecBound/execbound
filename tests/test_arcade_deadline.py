# SPDX-License-Identifier: AGPL-3.0-only
"""AL32's relation: the deadline a deployment file declares exceeds the slowest grant measured.

`tests/test_arcade.py::test_al32_the_granting_path_grants_at_one_four_and_sixteen_callers`
grants at one, four and sixteen callers on every run and holds what the grants are. This file
holds the number those grants are defended by, measuring the same path under the machine's
timing lock (`timed_alone`), so the slowest grant is this path's cost and not another suite's.
It takes that lock, so it is `timed`.
"""

import pytest
from arcade_fixtures import arcade_world as arcade_world
from checkpoint_fixtures import owner as owner
from test_arcade import al32_assert_granted, al32_measure
from test_execution import registry as registry
from test_execution import world as world


@pytest.mark.timed
def test_al32_the_deadline_the_file_declares_exceeds_the_slowest_grant(
    db, arcade_world, seeded, admin_engine, timed_alone
):
    """**What is asserted is a relation, not a millisecond number.** The relation is that the
    deadline this deployment's own file carries exceeds the slowest grant measured, and it has
    teeth in three ways: a hook that ran past `deadline_seconds` would be answered
    `CHECK_FAILED` with `DEADLINE_EXCEEDED` rather than `OK` and fail the answer assertion
    before the relation was reached; a hook refused for anything other than this surface's
    derived bound — a denial, a busy runtime, an exhausted cap, a 429 the application rather
    than the hook surface answered — fails the same assertion; and a granting path that grew
    slower than the budget the file declares fails the relation itself. A fixed threshold in
    milliseconds is deliberately not used: on a machine running anything else it fails for a
    reason that is not about this code, and what a project does with a number like that is
    widen it until it stops meaning anything.

    The two sides of the relation are not the same span, and the difference is the safe way
    round. `deadline_seconds` bounds the kernel call alone — `asyncio.wait_for` around the
    threadpool — while what is timed here is the whole hook from the caller's side, the body
    read, the correlation row's two writes and the answer included. So the measured number is
    the larger of the two and the relation is the conservative one; a deployment setting its
    budget against these figures is setting it against more than the budget covers rather
    than less. Each level's timed region holds the machine's timing lock, and the load each
    started under is in the failure message.
    """
    measured, granted_total, block, notes = al32_measure(
        db,
        arcade_world,
        seeded,
        admin_engine,
        alone=lambda level: timed_alone(f"AL32's grants at {level} callers"),
    )
    slowest = max(row["max_ms"] for row in measured) / 1000
    assert block.deadline_seconds > slowest, f"{slowest:.3f} s; " + "; ".join(notes)
    al32_assert_granted(admin_engine, arcade_world["identity"].tenant_id, granted_total)
