# SPDX-License-Identifier: AGPL-3.0-only
"""The console API's live board: the snapshot, its bounds, and the stream that carries it.

What the board draws is already held by `tests/test_board_read.py`, which is where the lanes,
the caps and the phases belong. This file holds what the API adds: that the snapshot carries
the page's own read unchanged, that an approver gets their own scoped board and an agent
credential gets nothing at all, and that the stream sends the board when it changes, a comment
when it does not, and a `closed` event when the session ends.

Requests are made through `admit`, the kernel's own path, rather than by inserting execution
rows here. A fixture that fills the columns it happens to know about drifts from what the
kernel actually writes, and then the board is tested against a shape nothing produces.

The stream's intervals are module constants rather than arguments so a test can shorten them;
shortening them is the only way to watch a fifteen-second heartbeat inside a suite that has to
stay fast. What is under test is the ordering and the conditions, which the numbers do not
change.
"""

import json
import secrets
import socket
import threading
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta

import httpx
import pytest
import uvicorn
from console_api_fixtures import (
    API,
    assert_no_secrets,
    console_client,
    refusals,
)
from space_fixtures import make_space
from sqlalchemy import text
from test_board_read import row
from test_execution import registry as registry
from test_execution import world as world
from test_human_surface import credential, form_values
from test_human_surface import human_config as human_config
from test_protected_path import connector as connector
from test_protected_path import live_provider as live_provider
from test_resolution import request as wire_request
from test_runtime import runtime as runtime

from execbound.app import create_app
from execbound.execution import admit, decide_approval
from execbound.execution.models import ExecutionError
from execbound.surfaces.board import AGENT_LANES, Board, Lane, Observation, Shot, lanes
from execbound.surfaces.console_api import board as board_api
from execbound.surfaces.console_api.board import (
    ALLOWED_STATES,
    STREAM_POLL_SECONDS,
    STREAM_SESSION_SECONDS,
    BoardView,
    digest,
    view,
)
from execbound.surfaces.human import HumanConfig
from execbound.surfaces.tokens import TokenKeys

NOW = datetime(2026, 9, 19, 12, 0, 0, tzinfo=UTC)
BOARD = API + "/board"
STREAM = API + "/board/stream"


def held(db, world, key="board-1"):
    """One request the checkpoint held for a person, through the kernel's own path."""
    return admit(db, world["identity"], wire_request(world, idempotency_key=key), world["clock"])


def executed(db, world, key="board-2"):
    """One request a person approved and the agent's retry committed for dispatch."""
    first = held(db, world, key)
    decide_approval(db, world["human"], first.view.approval_id, "APPROVE", world["clock"])
    return admit(db, world["identity"], wire_request(world, idempotency_key=key), world["clock"])


def unscope(admin_engine, world):
    """Take the approver's assignment away, so the same rows are no longer theirs to see."""
    with admin_engine.begin() as conn:
        conn.execute(
            text("UPDATE execbound.approval_scopes SET active=false WHERE tenant_id=:t"),
            {"t": world["identity"].tenant_id},
        )


def test_the_snapshot_is_the_board_the_page_reads(db, runtime, admin_engine, world):
    executed(db, world)
    with console_client(db, runtime, admin_engine, world["admin"]) as admin:
        response = admin.get(BOARD)
        assert response.status_code == 200, response.text
        body = response.json()
        assert response.headers["Cache-Control"] == "no-store"
        assert response.headers["X-ExecBound-Release"] == ""
        assert body["window_seconds"] == 900
        assert body["max_age_tenths"] == 150
        assert [lane["index"] for lane in body["agents"]] == [0]
        assert body["window"]["requests"] == 1
        assert body["window"]["allowed"] == 1
        assert body["window"]["denied"] == 0
        assert body["today"]["requests"] == 1
        # Known for the window, not counted for the day: `null` rather than a wrong zero.
        assert body["today"]["limited"] is None and body["today"]["refused"] is None
        assert body["window"]["limited"] == 0 and body["window"]["refused"] == 0
        assert body["last_request_seconds"] is not None
        assert body["shots"][0]["phase"] in {"unsettled", "shot-out", "land"}
        assert body["ticker"][0]["action"] == "endpoint.isolate"
        assert body["ticker"][0]["target_label"]
        assert body["ticker"][0]["requested_at"]
        assert_no_secrets(response)


def test_a_held_request_is_drawn_held_with_the_moment_it_must_be_answered(
    db, runtime, admin_engine, world
):
    held(db, world)
    with console_client(db, runtime, admin_engine, world["admin"]) as admin:
        body = admin.get(BOARD).json()
        assert body["window"]["held"] == 1
        assert body["shots"][0]["phase"] == "hold"
        assert body["shots"][0]["word"] == "held for a person"
        assert body["shots"][0]["detail"].startswith("answer by ")
        # A held request never reached a target, so it has no second leg to draw.
        assert body["shots"][0]["target"] is None


def test_cf5_a_held_shot_carries_expires_at(db, runtime, admin_engine, world):
    """The deadline as an instant, which the console prints in the viewer's zone. Every
    other shot carries `null` (`test_board_read.test_a_held_shot_carries_its_approvals_expiry`)."""
    first = held(db, world)
    with admin_engine.begin() as conn:
        expiry = conn.execute(
            text("SELECT expires_at FROM execbound.approvals WHERE approval_id=:a"),
            {"a": first.view.approval_id},
        ).scalar_one()
    with console_client(db, runtime, admin_engine, world["admin"]) as admin:
        body = admin.get(BOARD).json()
    [hold] = body["shots"]
    assert hold["phase"] == "hold"
    assert datetime.fromisoformat(hold["expires_at"]) == expiry
    assert body["ticker"][0]["expires_at"] == hold["expires_at"]


def test_an_empty_window_is_an_empty_board_and_not_an_error(db, runtime, admin_engine, world):
    with console_client(db, runtime, admin_engine, world["admin"]) as admin:
        body = admin.get(BOARD).json()
        assert body["shots"] == [] and body["ticker"] == [] and body["agents"] == []
        assert body["window"]["requests"] == 0
        assert body["last_request_seconds"] is None
        assert body["watching"] is False


def test_an_idle_board_remembers_the_last_visible_request(db, runtime, admin_engine, world):
    result = held(db, world)
    moment = world["clock"].now() - timedelta(hours=2)
    with admin_engine.begin() as conn:
        conn.execute(
            text("UPDATE execbound.executions SET created_at=:at WHERE execution_id=:id"),
            {"at": moment, "id": result.view.execution_id},
        )
    with console_client(db, runtime, admin_engine, world["admin"]) as admin:
        body = admin.get(BOARD).json()
        assert body["window"]["requests"] == 0
        assert body["last_request_seconds"] == 7200
        assert datetime.fromisoformat(body["last_request_at"]) == moment
    unscope(admin_engine, world)
    with console_client(db, runtime, admin_engine, world["human"]) as approver:
        body = approver.get(BOARD).json()
        assert body["last_request_at"] is None
        assert body["last_request_seconds"] is None


def test_historical_windows_are_bounded_and_keep_the_same_scope(
    db, runtime, admin_engine, world, monkeypatch
):
    from execbound.surfaces import board as board_reader

    result = held(db, world)
    with admin_engine.begin() as conn:
        conn.execute(
            text("UPDATE execbound.executions SET created_at=:at WHERE execution_id=:id"),
            {"at": world["clock"].now() - timedelta(minutes=30), "id": result.view.execution_id},
        )
    with console_client(db, runtime, admin_engine, world["admin"]) as admin:
        assert admin.get(BOARD).json()["shots"] == []
        for window, seconds in (("1h", 3600), ("24h", 86400)):
            body = admin.get(BOARD + "?window=" + window).json()
            assert body["window_seconds"] == seconds
            assert body["window"]["requests"] == 1
            assert str(result.view.execution_id) == body["shots"][0]["execution_id"]
        assert admin.get(BOARD + "?window=7d").status_code == 422
        assert admin.get(BOARD + "?window=1h&window=24h").status_code == 400
        assert admin.get(STREAM + "?window=1h").status_code == 400
        cap = board_reader.MAX_SHOTS
        monkeypatch.setattr(board_reader, "MAX_SHOTS", 0)
        body = admin.get(BOARD + "?window=24h").json()
        assert body["shots"] == []
        assert body["requests_truncated"] is True
        monkeypatch.setattr(board_reader, "MAX_SHOTS", cap)
    unscope(admin_engine, world)
    with console_client(db, runtime, admin_engine, world["human"]) as approver:
        body = approver.get(BOARD + "?window=24h").json()
        assert body["shots"] == []
        assert body["last_request_at"] is None


def test_last_known_request_and_history_follow_the_selected_space(db, runtime, admin_engine, world):
    from execbound.monitoring.store import create_source

    held(db, world)
    # A request admission refuses before any decision: the board reads admission's refusals
    # alone, never a surface's, a reviewer's or an administrator's (#545).
    with pytest.raises(ExecutionError):
        admit(db, world["identity"], wire_request(world, operation_ref="nothing.mapped"))
    create_source(
        db,
        world["admin"],
        label="Other Space monitor",
        story_id="board-spaces",
        expires_at=world["clock"].now() + timedelta(days=1),
        clock=world["clock"],
    )
    tenant = world["identity"].tenant_id
    with admin_engine.begin() as conn:
        conn.execute(text("SELECT set_config('execbound.tenant_id', :t, true)"), {"t": str(tenant)})
        empty_space = make_space(conn, tenant, "Empty board space")
    with console_client(db, runtime, admin_engine, world["admin"]) as admin:
        initial = admin.get(BOARD).json()
        assert initial["last_request_at"] is not None
        assert initial["watching"] is True
        assert initial["window"]["refused"] == 1
        changed = admin.post(API + "/session/space", {"space_id": str(empty_space)})
        assert changed.status_code == 200, changed.text
        for window in ("15m", "1h", "24h"):
            body = admin.get(BOARD + "?window=" + window).json()
            assert body["shots"] == []
            assert body["today"]["requests"] == 0
            assert body["last_request_at"] is None
            assert body["last_request_seconds"] is None
            assert body["watching"] is False
            assert body["window"]["refused"] == 0


def test_an_approver_sees_their_scope_and_nothing_outside_it(db, runtime, admin_engine, world):
    """The board's own approver rule, reached through the API rather than the page."""
    held(db, world)
    with console_client(db, runtime, admin_engine, world["human"]) as approver:
        response = approver.get(BOARD)
        body = response.json()
        assert body["window"]["requests"] == 1, "an assigned target is the approver's to see"
        # An observation carries no canonical target, so the band is an administrator's view.
        assert body["watching"] is False and body["observations"] == []
        assert_no_secrets(response)
    unscope(admin_engine, world)
    with console_client(db, runtime, admin_engine, world["human"]) as approver:
        assert approver.get(BOARD).json()["window"]["requests"] == 0
    with console_client(db, runtime, admin_engine, world["admin"]) as admin:
        assert admin.get(BOARD).json()["window"]["requests"] == 1, "the rows are still there"


def test_the_board_refuses_a_bearer_credential_and_a_missing_session(
    db, runtime, seeded, admin_engine, world
):
    for path in (BOARD, STREAM):
        results = refusals(db, runtime, seeded, admin_engine, world, path)
        assert results["bearer"].status_code == 403, path
        assert results["bearer"].json()["code"] == "FORBIDDEN"
        assert results["audited"] == 1, path
        assert results["no_session"].status_code == 401
        assert results["no_session"].json()["code"] == "SESSION_REQUIRED"


def test_the_board_takes_no_query_key_and_no_method_but_get(db, runtime, admin_engine, world):
    """`?live=0` is the page's key; on the API pausing is the client's own business."""
    with console_client(db, runtime, admin_engine, world["admin"]) as admin:
        assert admin.get(BOARD + "?live=0").status_code == 400
        assert admin.get(STREAM + "?live=0").status_code == 400
        assert admin.post(BOARD, {}).status_code == 405
        assert admin.post(STREAM, {}).status_code == 405


def test_an_agent_label_that_is_markup_travels_as_data(db, runtime, admin_engine, world):
    hostile = '<script>alert("x")</script>'
    with admin_engine.begin() as conn:
        conn.execute(
            text("UPDATE execbound.principals SET label=:l WHERE tenant_id=:t AND principal_id=:p"),
            {
                "l": hostile,
                "t": world["identity"].tenant_id,
                "p": world["identity"].principal_id,
            },
        )
    held(db, world)
    with console_client(db, runtime, admin_engine, world["admin"]) as admin:
        response = admin.get(BOARD)
        assert response.json()["agents"][0]["label"] == hostile
        assert response.headers["content-type"].startswith("application/json")


# --- the pure parts: the counters and the digest ---------------------------------------------


def board(**changes) -> Board:
    base: dict = {
        "agents": (Lane(0, "agent"),),
        "targets": (Lane(0, "host-01", "Endpoints, production"),),
        "shots": (Shot(agent=0, target=0, phase="land", word="executed", detail="", age=3),),
        "ticker": (),
        "counts": {"EXECUTED": 4, "DENIED": 1},
        "window_counts": {"EXECUTED": 1},
        "last_request_seconds": 3,
    }
    base.update(changes)
    return Board(**base)


def test_allowed_is_exactly_the_states_that_get_a_second_leg():
    """Derived from `PHASES`, so the counter and the drawing cannot come to disagree."""
    assert ALLOWED_STATES == {
        "RESERVED",
        "DISPATCH_COMMITTED",
        "INDETERMINATE",
        "EXECUTED",
        "FAILED_NOT_EXECUTED",
        "STALE_AUTHORIZATION",
    }


def test_the_window_counters_break_out_limits_and_requests_refused_before_a_decision():
    shots = (
        Shot(agent=0, target=None, phase="deny", word="limit", detail="", age=1),
        Shot(agent=0, target=None, phase="deny", word="denied", detail="", age=1),
        Shot(agent=-1, target=None, phase="short", word="refused first", detail="", age=1),
    )
    current = view(board(shots=shots, window_counts={"DENIED": 2}, window_limited=1), NOW)
    assert current.window.denied == 2
    assert current.window.limited == 1
    assert current.window.refused == 1
    assert current.today.limited is None and current.today.refused is None


def test_limit_counts_include_requests_whose_agent_lane_overflows():
    rows = [row(state="DENIED") for _ in range(AGENT_LANES + 1)]
    recorded = {request["execution_id"]: {"reasons": ["HARD_LIMIT:soc-1"]} for request in rows}
    current = view(lanes(rows, [], recorded, NOW), NOW)
    assert current.more_agents == 1
    assert len(current.shots) == AGENT_LANES
    assert current.window.limited == AGENT_LANES + 1


def test_the_digest_ignores_the_ages_and_notices_everything_else():
    first = view(board(), NOW)
    older = view(
        board(shots=(Shot(agent=0, target=0, phase="land", word="executed", detail="", age=99),)),
        NOW + timedelta(seconds=9),
    )
    assert digest(first) == digest(older), "an ageing board is not a changed board"
    assert digest(first) != digest(view(board(counts={"EXECUTED": 5}), NOW))
    assert digest(first) != digest(view(board(more_agents=1), NOW))
    assert digest(first) != digest(
        view(board(watching=True, observations=(Observation(0, "host-01", "read", False, 2),)), NOW)
    )


def test_the_poll_keeps_the_promise_the_session_interval_makes():
    """The stream rechecks the session on every read, so the read must be the shorter one."""
    assert STREAM_POLL_SECONDS < STREAM_SESSION_SECONDS


# --- the stream ------------------------------------------------------------------------------
#
# Over a real server, not the test client: Starlette's `TestClient` collects a whole response
# before handing it back, so a stream read through it arrives in one piece after it has ended,
# and every assertion about what reached the viewer *while* it was open would be vacuous. One
# uvicorn on a reserved port is what makes "the new request arrived on the open connection" a
# statement about the product rather than about the harness.


@contextmanager
def live_console(db, runtime, admin_engine, identity):
    """A signed-in browser talking to a real gateway: the origin, the cookies, the stream."""
    ready = threading.Event()

    class ReadyServer(uvicorn.Server):
        async def startup(self, sockets=None):
            await super().startup(sockets=sockets)
            ready.set()

    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        origin = f"http://127.0.0.1:{sock.getsockname()[1]}"
        keys = TokenKeys("stream-v1", {"stream-v1": secrets.token_bytes(32)})
        config = HumanConfig(origin, keys)
        app = create_app(db, runtime=runtime, human=config)
        server = ReadyServer(uvicorn.Config(app, log_level="critical", access_log=False))
        thread = threading.Thread(target=server.run, kwargs={"sockets": [sock]}, daemon=True)
        thread.start()
        try:
            assert ready.wait(10) and server.started, "the gateway did not become ready"
            with httpx.Client(base_url=origin, follow_redirects=False, timeout=30) as client:
                _, values = form_values(client.get("/login").text, "/session")
                values["credential"] = credential(admin_engine, identity)
                signed_in = client.post("/session", data=values, headers={"Origin": origin})
                assert signed_in.status_code == 303, signed_in.text
                yield client
        finally:
            server.should_exit = True
            thread.join(timeout=10)
            assert not thread.is_alive(), "the gateway did not stop"


def frames(lines) -> list[tuple[str, str]]:
    """Server-sent events as (name, data); a comment arrives as ("comment", its text)."""
    out: list[tuple[str, str]] = []
    name = ""
    for line in lines:
        if line.startswith(":"):
            out.append(("comment", line[1:].strip()))
        elif line.startswith("event:"):
            name = line.split(":", 1)[1].strip()
        elif line.startswith("data:"):
            out.append((name, line.split(":", 1)[1].strip()))
    return out


@pytest.fixture
def quick(monkeypatch):
    """The same stream with its intervals in tenths of a second instead of seconds."""
    monkeypatch.setattr(board_api, "STREAM_POLL_SECONDS", 0.05)
    monkeypatch.setattr(board_api, "STREAM_HEARTBEAT_SECONDS", 0.15)
    monkeypatch.setattr(board_api, "STREAM_MAX_SECONDS", 20.0)


def listen(client, stop, limit: int = 600) -> list[tuple[str, str]]:
    """Read the stream until `stop` says enough has arrived, then close the connection.

    `stop` is handed every frame so far and may act on what it sees, which is how a test makes
    a request while its own stream is open.
    """
    lines: list[str] = []
    out: list[tuple[str, str]] = []
    with client.stream("GET", STREAM) as response:
        assert response.status_code == 200, response.read()
        assert response.headers["content-type"].startswith("text/event-stream")
        assert response.headers["Cache-Control"] == "no-store"
        for index, line in enumerate(response.iter_lines()):
            lines.append(line)
            # Parsed from the start each time: an event's name is on the line before its data.
            out = frames(lines)
            if stop(out) or index > limit:
                break
    return out


def test_the_stream_opens_with_the_board_and_says_how_soon_to_come_back(
    db, runtime, admin_engine, world, quick
):
    executed(db, world)
    lines: list[str] = []
    with live_console(db, runtime, admin_engine, world["admin"]) as client:
        with client.stream("GET", STREAM) as response:
            for line in response.iter_lines():
                lines.append(line)
                if line.startswith("data:"):
                    break
    assert lines[0].startswith("retry:"), lines[:3]
    sent = frames(lines)
    assert sent[0][0] == "board"
    opening = BoardView.model_validate_json(sent[0][1])
    assert opening.window.requests == 1
    assert opening.agents


def test_the_stream_stays_quiet_while_nothing_changes_and_sends_a_comment(
    db, runtime, admin_engine, world, quick
):
    executed(db, world)
    with live_console(db, runtime, admin_engine, world["admin"]) as client:
        sent = listen(client, lambda out: len(out) >= 3)
    assert sent[0][0] == "board"
    # Nothing changed after the opening snapshot, so every later frame is a heartbeat comment.
    assert [name for name, _ in sent[1:]] == ["comment"] * len(sent[1:])
    assert len(sent) >= 3, sent


def test_a_new_request_reaches_an_open_stream(db, runtime, admin_engine, world, quick):
    boards: list[BoardView] = []
    made: list[bool] = []

    def stop(out):
        boards[:] = [BoardView.model_validate_json(data) for name, data in out if name == "board"]
        if boards and not made:
            made.append(True)
            held(db, world)
        return len(boards) >= 2

    with live_console(db, runtime, admin_engine, world["admin"]) as client:
        listen(client, stop)
    assert len(boards) == 2, "the stream did not carry the new request"
    assert boards[0].window.requests == 0
    assert boards[1].window.requests == 1
    assert boards[1].window.held == 1


def test_the_stream_ends_when_the_session_does(db, runtime, admin_engine, world, quick):
    revoked: list[bool] = []

    def stop(out):
        if any(name == "board" for name, _ in out) and not revoked:
            revoked.append(True)
            with admin_engine.begin() as conn:
                conn.execute(
                    text("UPDATE execbound.human_sessions SET revoked_at=now() WHERE tenant_id=:t"),
                    {"t": world["identity"].tenant_id},
                )
        return any(name == "closed" for name, _ in out)

    with live_console(db, runtime, admin_engine, world["admin"]) as client:
        sent = listen(client, stop)
    assert sent[-1][0] == "closed", sent
    assert json.loads(sent[-1][1]) == {"reason": "session"}
