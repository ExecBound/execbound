# SPDX-License-Identifier: AGPL-3.0-only
"""The live board in the console, in real Chromium (#280 in the shell, #333).

The board is the one page here whose correctness is partly about motion, so what is worth
asserting is what a reader of the source cannot check: that the shots actually animate, that
reduced motion and Pause draw the board still with every word still said, that a request made
while the page is open reaches it over the stream with no reload, and that a hidden tab holds no
connection and asks for nothing.

The shared console audit in `tests/test_browser_console.py` already visits `/board` in both
schemes and at 390 pixels with axe and the policy collector; this file gives it rows to draw and
then looks at what it drew.
"""

import re
import threading
from datetime import timedelta
from time import monotonic

import pytest
from playwright.sync_api import expect
from sqlalchemy import text
from test_browser_console import audit, settled, sign_in_as
from test_browser_console import console_gateway as console_gateway
from test_browser_console import console_page as console_page
from test_browser_surfaces import chromium as chromium
from test_execution import registry as registry
from test_execution import targets
from test_execution import world as world
from test_protected_path import connector as connector
from test_protected_path import live_provider as live_provider
from test_runtime import runtime as runtime

from execbound.execution import admit, decide_approval
from execbound.surfaces.console_api import board as board_api

BOARD = "/board"

# A surface of the kit rises from opacity 0 over 160 ms, and axe reads that moment as a contrast
# failure although the palette is sound. So the question is asked of the settled page: every
# surface that rises fully opaque, and nothing still arriving. Waiting on `getAnimations` alone is
# not enough, because the animation of a surface React has only just mounted may not have started
# yet.
#
# The board is where the second half of that rule has to be said more carefully, and the shared
# helper says it: its shots animate for as long as it is live, by design and as the whole argument
# of the page, so "no running animation" is never true here and waiting for it would hang rather
# than settle. What the rule is actually after is that nothing is still *arriving*; the board's own
# marks are the content, not an arrival, so `settled` excludes animations inside `.board`.


# Fast enough that a three-minute run still renders hundreds of frames, slow enough that the
# server's bounded read is not the thing under test.
POLL = 0.5
# How long the page may take to close the stream once it is hidden. Generous, because a busy
# machine delays an effect, and short beside the twenty seconds the hidden tab is then watched.
CLOSE_SECONDS = 5

# Counts the frames the page was actually handed, by wrapping the listener the application
# registers, and the connections it holds open, by wrapping `close`. It changes nothing the
# application does; it only keeps a tally, so "the heap held" cannot be true because nothing
# arrived, and "nothing arrives while hidden" is measured from the moment the page let go.
COUNT = """
(() => {
  window.__frames = 0;
  window.__open = 0;
  const Native = window.EventSource;
  window.EventSource = function (url, options) {
    const source = new Native(url, options);
    window.__open += 1;
    const close = source.close.bind(source);
    let closed = false;
    source.close = () => {
      if (!closed) { closed = true; window.__open -= 1; }
      close();
    };
    const add = source.addEventListener.bind(source);
    source.addEventListener = (name, handler, rest) =>
      add(name, name === 'board'
        ? (event) => { window.__frames += 1; handler(event); }
        : handler, rest);
    return source;
  };
})();
"""


def let_go(page, seconds: float) -> bool:
    """Whether the page holds no stream within `seconds`. Polled from here, because
    `wait_for_function` polls by evaluating a string inside the page, which the console's
    Content Security Policy refuses."""
    deadline = monotonic() + seconds
    while int(page.evaluate("window.__open")) != 0:
        if monotonic() > deadline:
            return False
        page.wait_for_timeout(100)
    return True


class Renamer(threading.Thread):
    """Renames the agent on an interval, so the board changes and the stream keeps sending."""

    def __init__(self, engine, tenant, principal):
        super().__init__(daemon=True)
        self.engine = engine
        self.tenant = tenant
        self.principal = principal
        self.stop = threading.Event()
        self.writes = 0

    def run(self) -> None:
        while not self.stop.wait(POLL):
            with self.engine.begin() as conn:
                conn.execute(
                    text(
                        "UPDATE execbound.principals SET label=:l "
                        "WHERE tenant_id=:t AND principal_id=:p"
                    ),
                    {"l": f"isolation-bot {self.writes}", "t": self.tenant, "p": self.principal},
                )
            self.writes += 1


@pytest.fixture
def renamer(admin_engine, world):
    thread = Renamer(admin_engine, world["identity"].tenant_id, world["identity"].principal_id)
    yield thread
    thread.stop.set()
    # A test that failed before starting it leaves a thread that cannot be joined.
    if thread.is_alive():
        thread.join(timeout=10)


def quiet(page, seconds: float = 1.5, timeout: float = 25.0) -> None:
    """Wait until the console API has been silent for `seconds`.

    The shell has queries of its own and they are not the board's: the session, the count the
    sidebar reads from the tenant, and the Getting started card's progress. The count cannot even
    start until the session has answered and said the person is an administrator, so the shell's
    asking trails the board's, which needs none of them. On an idle machine the last of them lands
    a twentieth of a second before the board says it is live; under load on a busy machine the
    order flips, a listener attached at that moment sees a request the board did not make, and
    this file fails on a branch that touches nothing of the board (a `GET /api/console/v1/tenant`,
    #410).

    Silence is the honest signal rather than any one pill, because it covers all three of today's
    queries and whichever query is later added to the shell.
    """
    last = monotonic()

    def note(request) -> None:
        nonlocal last
        if "/api/console/" in request.url:
            last = monotonic()

    page.on("request", note)
    try:
        started = monotonic()
        while monotonic() - started < timeout:
            if monotonic() - last >= seconds:
                return
            page.wait_for_timeout(100)
        raise AssertionError(f"the console API never went quiet for {seconds}s")
    finally:
        page.remove_listener("request", note)


HOSTILE = "<script>alert(1)</script>"
PHONE = {"width": 390, "height": 844}


@pytest.fixture
def drawn(db, world, admin_engine):
    """A window with something in it, and an agent whose label is markup.

    One development workstation, which the pack allows outright and which therefore lands on its
    target lane, and one production workstation, which it holds for a person. Two lanes in two
    groups, so the picture exercises the sorted target column as well as both phases.
    """
    with admin_engine.begin() as conn:
        conn.execute(
            text("UPDATE execbound.principals SET label=:l WHERE tenant_id=:t AND principal_id=:p"),
            {
                "l": HOSTILE,
                "t": world["identity"].tenant_id,
                "p": world["identity"].principal_id,
            },
        )
    admit(db, world["identity"], targets(admin_engine, world, 1)[0], world["clock"])
    production = targets(admin_engine, world, 1, production=True)[0]
    world["held"] = admit(db, world["identity"], production, world["clock"])
    world["retry"] = production
    return world


def open_board(page, admin_engine, world, query=""):
    sign_in_as(page, admin_engine, world["admin"])
    page.goto(BOARD + query)
    expect(page.get_by_role("heading", level=1)).to_have_text("Live board")
    # The first snapshot arrives over the API; wait for the picture rather than for a timeout.
    expect(page.locator(".checkpoint-rule")).to_have_count(1)
    settled(page)
    return page


def test_the_board_draws_its_lanes_the_checkpoint_and_a_shot_that_moves(
    console_page, console_gateway, admin_engine, drawn
):
    page = open_board(console_page, admin_engine, drawn)
    expect(page.locator(".lane-label").first).to_be_visible()
    assert page.locator(".shot").count() >= 2
    # It moves: the phases are running animations, which is the whole argument of the page.
    assert page.evaluate("document.getAnimations().length") > 0
    # Every state is said in a word beside the ticker's tone, not only drawn.
    expect(page.get_by_text("held for a person").last).to_be_visible()
    expect(page.get_by_text("unsettled").last).to_be_visible()
    # The held request never reached a target, so it has one leg; the committed one has two.
    expect(page.locator(".shot.hold")).to_have_count(1)
    expect(page.locator(".shot.unsettled")).to_have_count(2)
    assert page.evaluate("window.__violations") == []


def test_an_agent_label_that_is_markup_is_text_and_reaches_no_attribute(
    console_page, console_gateway, admin_engine, drawn
):
    page = open_board(console_page, admin_engine, drawn)
    assert page.evaluate("document.querySelectorAll('script:not([src])').length") == 0
    markup = page.content()
    assert HOSTILE not in markup
    label = page.locator(".lane-label").first
    expect(label).to_have_text(HOSTILE)
    assert page.evaluate("window.__violations") == []


def test_pausing_stills_the_board_closes_the_stream_and_stays_in_the_url(
    console_page, console_gateway, admin_engine, drawn
):
    page = open_board(console_page, admin_engine, drawn)
    # The same race the hidden-tab test above has: the shell's session, count and progress
    # queries are not the board's and necessarily trail it, so a listener attached the moment
    # the board is drawn sees a request the board did not make and the assertion below reads
    # the machine's load rather than the pause. Wait for the mode pill, which is the session
    # answered and is what lets the count query start at all, then for silence.
    expect(page.get_by_text(re.compile(r"Enforcing|Observe only"))).to_be_visible()
    quiet(page)
    opened: list[str] = []
    page.on("request", lambda request: opened.append(request.url))
    page.get_by_role("link", name="Pause").click()
    expect(page).to_have_url(re.compile(r"live=false$"))
    expect(page.locator(".board-still")).to_have_count(1)
    assert page.evaluate("document.getAnimations().length") == 0
    expect(page.get_by_text("Paused; nothing moves")).to_be_visible()
    # A paused board holds no connection: nothing is asked for after the link was followed.
    page.wait_for_timeout(1500)
    assert [url for url in opened if "/api/console/" in url] == []
    # Resume comes back to a live board, and the still picture is what a reload of the paused
    # address gives, which is what "a link restores it" means.
    page.reload()
    expect(page.locator(".board-still")).to_have_count(1)
    page.get_by_role("link", name="Resume").click()
    expect(page.locator(".board-still")).to_have_count(0)


def test_with_reduced_motion_nothing_moves_and_every_word_is_still_said(
    console_page, console_gateway, admin_engine, drawn
):
    console_page.emulate_media(reduced_motion="reduce")
    page = open_board(console_page, admin_engine, drawn)
    assert page.evaluate("document.getAnimations().length") == 0
    expect(page.get_by_text("checkpoint").first).to_be_visible()
    expect(page.get_by_text("held for a person").last).to_be_visible()
    expect(page.get_by_text("unsettled").last).to_be_visible()
    assert page.locator(".shot").count() >= 3
    console_page.emulate_media(reduced_motion="no-preference")


def test_a_request_made_while_the_board_is_open_arrives_over_the_stream(
    console_page, console_gateway, admin_engine, db, drawn
):
    page = open_board(console_page, admin_engine, drawn)
    expect(page.get_by_text("Live. The board updates itself")).to_be_visible()
    reloads: list[str] = []
    page.on("framenavigated", lambda frame: reloads.append(frame.url))
    assert page.locator(".shot.deny").count() == 0
    # What changes on the board is a decision: the held shot is refused by a person, and the
    # agent's own retry is what moves the execution on, exactly as the board's model says.
    decide_approval(db, drawn["human"], drawn["held"].view.approval_id, "DENY", drawn["clock"])
    admit(db, drawn["identity"], drawn["retry"], drawn["clock"])
    # No reload, no polling interval: the change arrives on the connection already open.
    expect(page.locator(".shot.deny")).to_have_count(1, timeout=15000)
    expect(page.locator(".badge-deny")).to_have_count(1)
    assert reloads == [], reloads
    assert page.evaluate("window.__violations") == []


def test_a_hidden_tab_holds_no_connection_and_asks_for_nothing(
    monkeypatch, console_page, console_gateway, admin_engine, drawn, renamer
):
    # A board that keeps changing, so the server has a frame to send on every poll and "nothing
    # arrives while hidden" is a statement about the page rather than about a quiet board. The
    # soak checks the same after minutes open; this checks it on every run, including one that
    # deselects the `timed` soak.
    monkeypatch.setattr(board_api, "STREAM_POLL_SECONDS", POLL)
    console_page.add_init_script(COUNT)
    page = open_board(console_page, admin_engine, drawn)
    expect(page.get_by_text("Live. The board updates itself")).to_be_visible()
    renamer.start()
    # The mode pill is the session answered, which is what lets the sidebar's count query start
    # at all; `quiet` then waits for that one and anything else the shell asks. Only after both
    # is two seconds of silence a statement about the board rather than about the machine's load.
    expect(page.get_by_text(re.compile(r"Enforcing|Observe only"))).to_be_visible()
    quiet(page)
    deadline = monotonic() + 15
    while int(page.evaluate("window.__frames")) == 0:
        assert monotonic() < deadline, "no frame reached the visible board in 15 s"
        page.wait_for_timeout(100)
    asked: list[str] = []
    page.on("request", lambda request: asked.append(request.url))
    page.evaluate(
        "Object.defineProperty(document, 'hidden', {value: true, configurable: true});"
        "Object.defineProperty(document, 'visibilityState', "
        "{value: 'hidden', configurable: true});"
        "document.dispatchEvent(new Event('visibilitychange'));"
    )
    expect(page.get_by_text("Not in view")).to_be_visible()
    # The stream is closed in an effect's cleanup, a moment after the event, so frames are
    # counted from the close; a page that only stopped asking would still be handed frames.
    assert let_go(page, CLOSE_SECONDS), (
        f"the hidden tab still held its stream {CLOSE_SECONDS}s after it was hidden"
    )
    before = int(page.evaluate("window.__frames"))
    page.wait_for_timeout(2000)
    assert [url for url in asked if "/api/console/" in url] == []
    assert int(page.evaluate("window.__frames")) == before
    assert page.evaluate("window.__violations") == []


def test_the_drawn_board_passes_the_audit_at_phone_width(
    console_page, console_gateway, admin_engine, drawn
):
    """The shared audit visits an empty board; this one has lanes, shots, a ticker and figures."""
    console_page.set_viewport_size(PHONE)
    sign_in_as(console_page, admin_engine, drawn["admin"])
    console_page.goto(BOARD)
    settled(console_page)
    audit(console_page, BOARD, "Live board")
    expect(console_page.locator(".checkpoint-rule")).to_have_count(1)
    for scheme in ("dark", "light"):
        console_page.emulate_media(color_scheme=scheme)
        console_page.goto(BOARD)
        settled(console_page)
        audit(console_page, BOARD, "Live board")
    console_page.emulate_media(color_scheme="light")


def test_historical_windows_are_static_bounded_and_link_to_request_evidence(
    console_page, console_gateway, admin_engine, drawn
):
    page = open_board(console_page, admin_engine, drawn)
    opened: list[str] = []
    page.on("request", lambda request: opened.append(request.url))
    page.get_by_role("button", name="1 hour · Historical", exact=True).click()
    expect(page.get_by_role("heading", name="Historical board", exact=True)).to_be_visible()
    expect(
        page.get_by_text("Historical snapshot. Motion and live updates are off.")
    ).to_be_visible()
    expect(page.get_by_role("button", name="Refresh snapshot")).to_be_visible()
    expect(page.get_by_text("Last hour", exact=True)).to_be_visible()
    quiet(page)
    assert page.evaluate("document.getAnimations().length") == 0
    assert not any("/board/stream" in url for url in opened)
    links = page.get_by_role("link", name=re.compile("^Open request "))
    assert links.count() > 0
    assert "open=" in links.first.get_attribute("href")
    page.get_by_role("button", name="24 hours · Historical", exact=True).click()
    expect(page.get_by_text("Last 24 hours", exact=True)).to_be_visible()
    page.reload()
    settled(page)
    expect(page.get_by_role("heading", name="Historical board", exact=True)).to_be_visible()
    assert not any("/board/stream" in url for url in opened)
    page.set_viewport_size(PHONE)
    audit(page, page.url, "Historical board")
    assert page.evaluate("window.__violations") == []


def test_an_idle_board_shows_history_and_next_steps_instead_of_a_blank_diagram(
    console_page, console_gateway, admin_engine, drawn
):
    with admin_engine.begin() as conn:
        conn.execute(
            text("UPDATE execbound.executions SET created_at=:at WHERE tenant_id=:t"),
            {"at": drawn["clock"].now() - timedelta(hours=2), "t": drawn["admin"].tenant_id},
        )
    sign_in_as(console_page, admin_engine, drawn["admin"])
    console_page.goto(BOARD)
    settled(console_page)
    expect(console_page.get_by_text("No requests in the last fifteen minutes.")).to_be_visible()
    expect(console_page.get_by_text(re.compile("Last request 2 hours ago"))).to_be_visible()
    expect(console_page.get_by_role("link", name="Browse requests")).to_be_visible()
    expect(console_page.locator(".board svg")).to_have_count(0)
    assert console_page.evaluate("window.__violations") == []
