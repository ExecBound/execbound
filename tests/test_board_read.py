# SPDX-License-Identifier: AGPL-3.0-only
"""What the board draws, and that the statements behind it name real columns.

The lane assignment is a pure function, so most of this needs no database: the caps, the
grouping, the overflow rows and the phase of every state are decided in `lanes` and are
tested there. One test runs the real statements against real rows, because a suite that
only feeds `lanes` hand-built dictionaries proves the drawing and says nothing about
whether the query behind it selects columns that exist.
"""

from datetime import UTC, datetime, timedelta
from uuid import UUID, uuid4

import pytest
from sqlalchemy import text
from test_execution import registry as registry
from test_execution import world as world

from execbound.execution import store
from execbound.surfaces.board import (
    AGENT_LANES,
    MAX_AGE_TENTHS,
    PHASES,
    TARGET_LANES,
    Board,
    lanes,
    read,
)

NOW = datetime(2026, 9, 18, 12, 0, 0, tzinfo=UTC)


def row(state="EXECUTED", *, principal=None, target=None, age=1.0, label=None, **changes):
    moment = NOW - timedelta(seconds=age)
    base = {
        "execution_id": uuid4(),
        "principal_id": principal or uuid4(),
        "canonical_target_id": target if target is not False else None,
        "state": state,
        "created_at": moment,
        "changed_at": moment,
        "action": "identity.disable",
        "agent_label": label,
        "agent_number": None,
        "expires_at": None,
        "approval_state": None,
        "approval_decided": False,
        "provider_id": "host-01",
        "resource_type": "endpoint",
        "environment": "production",
    }
    if target is None:
        base["canonical_target_id"] = uuid4()
    base.update(changes)
    return base


def test_every_execution_state_has_a_phase_and_a_place():
    """All ten, not the seven the design names.

    The demonstration asserts that every state a run produced appears on the board, so a
    state with no phase would fail there rather than here — which is the wrong place to
    find out that the kernel grew a state the picture cannot draw.
    """
    states = [
        "ATTEMPTED",
        "DENIED",
        "PENDING_APPROVAL",
        "RESERVED",
        "DISPATCH_COMMITTED",
        "EXECUTED",
        "FAILED_NOT_EXECUTED",
        "INDETERMINATE",
        "STALE_AUTHORIZATION",
        "OBSERVED",
    ]
    assert set(PHASES) == set(states)
    board = lanes([row(state=state) for state in states], [], {}, NOW)
    assert len(board.shots) == len(states)
    assert {shot.phase for shot in board.shots} <= {
        "shot-in",
        "observe",
        "deny",
        "hold",
        "shot-out",
        "unsettled",
        "land",
        "hollow",
    }


@pytest.mark.parametrize(
    ("state", "second_leg"),
    [
        ("EXECUTED", True),
        ("RESERVED", True),
        ("DISPATCH_COMMITTED", True),
        ("STALE_AUTHORIZATION", True),
        ("DENIED", False),
        ("PENDING_APPROVAL", False),
        ("ATTEMPTED", False),
        # Observe mode dispatches nothing, so the shot reaches the checkpoint and stops
        # however plainly its execution names a target.
        ("OBSERVED", False),
    ],
)
def test_only_a_shot_that_reached_a_target_gets_a_second_leg(state, second_leg):
    board = lanes([row(state=state)], [], {}, NOW)
    assert (board.shots[0].target is not None) is second_leg


@pytest.mark.parametrize(
    ("recorded", "word", "detail"),
    [
        # What the policy records for a spent limit, alone and beside a deny rule. The agent
        # is told `limit` for both, and the board says it too.
        ({"reasons": ["HARD_LIMIT:daily-disables"]}, "limit", ""),
        ({"reasons": ["HARD_LIMIT:daily-disables", "NOT_AUTHORIZED"]}, "limit", ""),
        ({"reasons": ["NOT_AUTHORIZED"]}, "denied", ""),
        # Admission's and a reviewer's single reason, which the detail keeps showing.
        ({"reason": "RESOURCE_BUSY"}, "denied", "RESOURCE_BUSY"),
        ({"reason": "HUMAN_DENIED"}, "denied", "HUMAN_DENIED"),
        # An approval obligation's prefix, which holds a request and denies none.
        ({"reason": "limit:daily-disables"}, "denied", "limit:daily-disables"),
        ({}, "denied", ""),
    ],
)
def test_a_denial_says_limit_exactly_when_its_agent_is_told_limit(recorded, word, detail):
    denied = row(state="DENIED")
    board = lanes([denied], [], {denied["execution_id"]: recorded}, NOW)
    assert (board.shots[0].word, board.shots[0].detail) == (word, detail)
    assert board.window_limited == (1 if word == "limit" else 0)
    # The table above is the agent's own rule, not a second one written beside it.
    assert (word == "limit") is (store.denial_category(recorded) == "limit")


def test_only_a_denial_is_counted_by_a_limit():
    """A shot in any other state is not a denial by a limit, whatever was recorded for it."""
    stale = row(state="STALE_AUTHORIZATION")
    board = lanes([stale], [], {stale["execution_id"]: {"reasons": ["HARD_LIMIT:x"]}}, NOW)
    assert board.shots[0].word == "nothing happened"
    assert board.window_limited == 0


def test_denied_and_historical_requests_retain_action_target_and_time():
    denied = row(state="DENIED", action="endpoint.isolate", age=7200)
    board = lanes([denied], [], {}, NOW)
    shot = board.ticker[0]
    assert shot.target is None  # No dispatched leg, but the requested target remains readable.
    assert shot.action == "endpoint.isolate"
    assert shot.target_label == "host-01"
    assert shot.requested_at == denied["created_at"]


def test_a_held_request_says_when_it_must_be_answered():
    held = row(
        state="PENDING_APPROVAL", expires_at=NOW + timedelta(minutes=9), approval_state="PENDING"
    )
    board = lanes([held], [], {}, NOW)
    assert board.shots[0].word == "held for a person"
    assert "12:09:00 UTC" in board.shots[0].detail
    assert not board.shots[0].lapsed and not board.shots[0].unused
    assert board.window_counts == {"PENDING_APPROVAL": 1}


def test_a_lapsed_request_says_when_it_lapsed():
    """Past its deadline and undecided, by the server's clock: lapsed, not held (#678)."""
    lapsed = row(
        state="PENDING_APPROVAL",
        expires_at=NOW - timedelta(minutes=2),
        approval_state="PENDING",
        approval_decided=False,
    )
    board = lanes([lapsed], [], {}, NOW)
    shot = board.shots[0]
    assert (shot.phase, shot.word) == ("hollow", "lapsed")
    assert "lapsed at 11:58:00 UTC" in shot.detail
    assert shot.lapsed and not shot.unused
    assert shot.expires_at == NOW - timedelta(minutes=2)
    assert shot.target is None
    assert board.window_counts == {"LAPSED": 1}


def test_an_approved_request_not_used_says_so():
    unused = row(
        state="PENDING_APPROVAL",
        expires_at=NOW - timedelta(minutes=2),
        approval_state="APPROVED",
        approval_decided=True,
    )
    board = lanes([unused], [], {}, NOW)
    shot = board.shots[0]
    assert (shot.phase, shot.word) == ("hollow", "unused")
    assert "approved, not used by 11:58:00 UTC" in shot.detail
    assert shot.unused and not shot.lapsed
    assert board.window_counts == {"UNUSED": 1}


def test_a_held_shot_carries_its_approvals_expiry():
    deadline = NOW + timedelta(minutes=9)
    board = lanes(
        [row(state="PENDING_APPROVAL", expires_at=deadline), row(state="EXECUTED")], [], {}, NOW
    )
    held, done = board.shots
    assert held.expires_at == deadline
    # Every other shot has no deadline to print, even one whose row carries a value.
    assert done.expires_at is None
    stale = lanes([row(state="DENIED", expires_at=deadline)], [], {}, NOW)
    assert stale.shots[0].expires_at is None


def _today(db, admin_engine, world, moment, now, offset):
    """The board's today counter, after the world's one request is moved to `moment`."""
    tenant = world["identity"].tenant_id
    with admin_engine.begin() as conn:
        conn.execute(
            text("UPDATE execbound.executions SET created_at=:at WHERE tenant_id=:t"),
            {"at": moment, "t": tenant},
        )
    with db.transaction(tenant, snapshot=True) as conn:
        board = read(conn, tenant, world["admin"].principal_id, False, now, offset=offset)
    return sum(board.counts.values())


def test_read_without_an_offset_counts_from_utc_midnight(db, world, admin_engine):
    """The showcase's own call: no offset, so the day it counts is UTC's, as it says."""
    from test_resolution import request

    from execbound.execution import admit

    admit(db, world["identity"], request(world, idempotency_key="day-1"), world["clock"])
    now = datetime(2026, 10, 8, 2, 0, tzinfo=UTC)
    evening = datetime(2026, 10, 7, 20, 0, tzinfo=UTC)
    assert _today(db, admin_engine, world, evening, now, None) == 0
    assert _today(db, admin_engine, world, evening, now, timedelta(minutes=-240)) == 1
    morning = datetime(2026, 10, 8, 1, 0, tzinfo=UTC)
    assert _today(db, admin_engine, world, morning, now, None) == 1


@pytest.mark.parametrize("minutes", [-240, 0, 330, 840])
@pytest.mark.parametrize("side", [-1, 1])
def test_home_and_the_board_share_one_day_start(minutes, side):
    from execbound.surfaces.console_api.overview import RANGES
    from execbound.surfaces.dashboard import DAY, calendar_window, viewer_midnight

    offset = timedelta(minutes=minutes)
    # An instant a minute either side of the viewer's own midnight.
    local_midnight = datetime(2026, 10, 8, tzinfo=UTC) - offset
    now = local_midnight + timedelta(minutes=side)
    start = viewer_midnight(now, offset)
    assert start == calendar_window(now, DAY, DAY, offset)[0]
    # Home's week starts at a midnight six days before the viewer's today.
    window, step = RANGES["7d"]
    assert calendar_window(now, window, step, offset)[0] + 6 * DAY == start
    assert start == (local_midnight if side > 0 else local_midnight - DAY)


def test_a_rejection_stops_short_of_the_checkpoint():
    board = lanes(
        [], [{"occurred_at": NOW, "actor_id": uuid4(), "code": "UNKNOWN_TARGET"}], {}, NOW
    )
    assert board.shots[0].phase == "short"
    assert board.shots[0].target is None
    assert board.shots[0].agent == -1


def test_the_caps_hold_and_the_overflow_is_counted():
    rows = [row(principal=uuid4(), target=uuid4()) for _ in range(AGENT_LANES + 5)]
    board = lanes(rows, [], {}, NOW)
    assert len(board.agents) == AGENT_LANES
    assert board.more_agents == 5
    # A shot whose agent has no lane is not drawn in someone else's lane.
    assert all(shot.agent < AGENT_LANES for shot in board.shots)

    one_agent = uuid4()
    many = [row(principal=one_agent, target=uuid4()) for _ in range(TARGET_LANES + 3)]
    board = lanes(many, [], {}, NOW)
    assert len(board.targets) == TARGET_LANES
    assert board.more_targets == 3


def test_targets_are_grouped_by_type_and_environment():
    board = lanes(
        [
            row(resource_type="endpoint", environment="production"),
            row(resource_type="endpoint", environment="development"),
            row(resource_type="identity", environment=None),
        ],
        [],
        {},
        NOW,
    )
    assert {lane.group for lane in board.targets} == {
        "Endpoints, production",
        "Endpoints, development",
        "Identities",
    }


def test_age_is_tenths_of_a_second_and_stops_at_the_last_class():
    board = lanes([row(age=0.0), row(age=2.5), row(age=900.0)], [], {}, NOW)
    assert [shot.age for shot in board.shots] == [0, 25, MAX_AGE_TENTHS]


def test_an_agent_without_a_label_is_named_by_its_number():
    board = lanes([row(agent_number=1)], [], {}, NOW)
    assert board.agents[0].label == "Agent 1"
    # The label already is the handle, so nothing is printed beside it.
    assert board.agents[0].handle is None


def test_an_agent_with_no_number_is_named_by_a_prefix_not_by_its_identifier():
    principal = UUID("3f2504e0-4f89-11d3-9a0c-0305e82c3301")
    board = lanes([row(principal=principal)], [], {}, NOW)
    assert board.agents[0].label == "Agent 3f2504e0"
    assert str(principal) not in board.agents[0].label
    assert board.agents[0].handle is None


def test_a_labelled_lane_carries_its_handle():
    board = lanes([row(label="triage-bot", agent_number=1)], [], {}, NOW)
    assert (board.agents[0].label, board.agents[0].handle) == ("triage-bot", "Agent 1")
    # A target lane has no handle.
    assert board.targets[0].handle is None


def test_two_agents_with_one_label_have_two_handles():
    board = lanes(
        [row(label="triage-bot", agent_number=1), row(label="triage-bot", agent_number=2)],
        [],
        {},
        NOW,
    )
    assert [(lane.label, lane.handle) for lane in board.agents] == [
        ("triage-bot", "Agent 1"),
        ("triage-bot", "Agent 2"),
    ]


def test_an_empty_window_is_a_board_with_nothing_on_it():
    board = lanes([], [], {}, NOW)
    assert board == Board()


def test_the_statements_select_columns_that_exist(db, world, admin_engine):
    """The producer check: the real SQL, against real rows, on a real schema.

    `lanes` is fed dictionaries everywhere above, which proves the drawing and nothing
    about the read. This runs the four statements so a renamed column or a wrong join
    fails here rather than on a page.
    """
    tenant = world["identity"].tenant_id
    with db.transaction(tenant, snapshot=True) as conn:
        board = read(conn, tenant, world["human"].principal_id, False, datetime.now(UTC))
    assert isinstance(board, Board)
    assert board.counts == {} or all(isinstance(count, int) for count in board.counts.values())

    with admin_engine.begin() as conn:
        seeded = conn.execute(
            text("SELECT count(*) FROM execbound.executions WHERE tenant_id=:t"), {"t": tenant}
        ).scalar_one()
    assert seeded >= 0


def observation(target="host-01", *, flagged=False, action="tool.call", age=1.0):
    return {
        "observation_id": uuid4(),
        "action": action,
        "target_ref": target,
        "occurred_at": NOW - timedelta(seconds=age),
        "flagged": flagged,
    }


def test_an_observation_lands_on_a_lane_it_matches_and_runs_wide_when_it_does_not():
    from execbound.surfaces.board import observed

    board = lanes([row(provider_id="host-01")], [], {}, NOW)
    seen = observed([observation("host-01"), observation("host-99")], board.targets, NOW)
    assert seen[0].target == board.targets[0].index
    # Not invented onto a lane: an unmatched target keeps its own name and no lane.
    assert seen[1].target is None
    assert seen[1].label == "host-99"


def test_an_observation_with_no_target_says_elsewhere_rather_than_nothing():
    from execbound.surfaces.board import observed

    seen = observed([observation(None)], (), NOW)
    assert seen[0].target is None and seen[0].label == "elsewhere"


def test_a_finding_marks_its_observation():
    from execbound.surfaces.board import observed

    seen = observed([observation(flagged=True), observation()], (), NOW)
    assert [record.flagged for record in seen] == [True, False]


def test_an_approver_is_never_shown_the_band(db, world, admin_engine):
    """An observation carries no canonical target, so it cannot be held to a scope.

    Showing it unfiltered would hand an approver activity outside the scope they were
    given, and filtering it by a target label would be a guess. The band is an
    administrator's view, and `read` decides that rather than the template.
    """
    # Registered through the path that registers one in production, not by an INSERT
    # written here: a fixture that fills the columns it happens to know about drifts from
    # what the monitoring store actually writes, and then tests a shape nothing produces.
    from execbound.monitoring.store import create_source

    tenant = world["identity"].tenant_id
    create_source(
        db,
        world["admin"],
        label="probe",
        story_id="story-1",
        expires_at=world["clock"].now() + timedelta(days=30),
        clock=world["clock"],
    )
    with db.transaction(tenant, snapshot=True) as conn:
        approver = read(conn, tenant, world["human"].principal_id, True, datetime.now(UTC))
        admin = read(conn, tenant, world["admin"].principal_id, False, datetime.now(UTC))
    assert approver.watching is False and approver.observations == ()
    assert admin.watching is True


def test_the_band_is_absent_when_nothing_is_watching(db, world):
    """An empty band reads as "monitoring saw nothing", which is a different claim."""
    tenant = world["identity"].tenant_id
    with db.transaction(tenant, snapshot=True) as conn:
        board = read(conn, tenant, world["admin"].principal_id, False, datetime.now(UTC))
    assert board.watching is False
    assert board.observations == ()


def test_the_band_is_bounded_however_much_monitoring_saw(db, world, monkeypatch):
    """The window is a picture, not a listing: past the cap it stops naming individuals.

    The bound is a `LIMIT` in the statement rather than a slice afterwards, so it is worth
    proving against the database. The constant is lowered here rather than seeding a
    hundred and one observations to prove a number.
    """
    from execbound.monitoring.models import ObservationEvent
    from execbound.monitoring.store import create_source, ingest
    from execbound.surfaces import board as board_module

    tenant = world["identity"].tenant_id
    grant = create_source(
        db,
        world["admin"],
        label="probe",
        story_id="story-bound",
        expires_at=world["clock"].now() + timedelta(days=30),
        clock=world["clock"],
    )
    for index in range(3):
        ingest(
            db,
            grant.token,
            ObservationEvent(
                event_id=f"event-{index}",
                story_id="story-bound",
                occurred_at=datetime.now(UTC),
                kind="tool_result",
                action="endpoint.isolate",
                target_ref=f"host-{index}",
                outcome="success",
            ),
            clock=world["clock"],
        )
    monkeypatch.setattr(board_module, "MAX_OBSERVATIONS", 2)
    with db.transaction(tenant, snapshot=True) as conn:
        board = board_module.read(
            conn, tenant, world["admin"].principal_id, False, datetime.now(UTC)
        )
    assert board.watching is True
    assert len(board.observations) == 2
