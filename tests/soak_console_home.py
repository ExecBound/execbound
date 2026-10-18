# SPDX-License-Identifier: AGPL-3.0-only
"""Ten minutes on Home: the heap holds, and a hidden tab asks for nothing.

The console's performance criterion for a page left open
(#333): after ten minutes on the Live
board and Home with polling, the JavaScript heap has grown by less than twenty per cent since
minute two, and no request fires while the tab is hidden. `tests/test_browser_console_soak.py`
holds the board to it; this file holds Home, which is kept current by the console's shared
ten-second timer (`console/src/lib/poll.ts`) rather than a stream.

**This file is run deliberately, never by CI.** A soak takes minutes, and the ten-minute figure
is a measurement taken on purpose, on an otherwise idle machine, beside the board's. pytest
collects only `test_*.py` by itself, so this file runs only when it is named, and nothing in it
is skipped:

    EXECBOUND_BOARD_SOAK_MINUTES=10 uv run pytest -s tests/soak_console_home.py

`EXECBOUND_BOARD_SOAK_MINUTES` sets the length, as it does the board's, three minutes by default;
the baseline is taken a fifth of the way in, which is minute two of ten.

**The page actually changes.** The board's renamer renames the agent every half second, so every
poll's recent decisions name it differently, and a second thread here admits a request every few
seconds, so the overview's figures and charts change too. What is soaked is the render path, which
is where a leak would live. The heap is read as the board's soak reads it, after two forced
collections over the DevTools protocol.

**What it can and cannot catch.** Ten minutes is about forty-eight polls, so with a heap of about
eight megabytes it fails on a leak of roughly thirty kilobytes a poll or more; a smaller leak
passes. The criterion is the twenty per cent, and that is what is held.
"""

import threading

import pytest
from playwright.sync_api import expect
from test_browser_console import console_gateway as console_gateway
from test_browser_console import console_page as console_page
from test_browser_console import sign_in_as
from test_browser_console_board import drawn as drawn
from test_browser_console_board import renamer as renamer
from test_browser_console_soak import BASELINE_FRACTION, SOAK_SECONDS, heap
from test_browser_surfaces import chromium as chromium
from test_execution import registry as registry
from test_execution import targets
from test_execution import world as world
from test_protected_path import connector as connector
from test_protected_path import live_provider as live_provider
from test_runtime import runtime as runtime

from execbound.execution import admit

# Home asks on the console's shared timer, `POLL_MS` in `console/src/lib/poll.ts`.
HOME_POLL_SECONDS = 10
# A request admitted this often changes the overview's figures between most polls.
ADMIT_SECONDS = 4
OVERVIEW = "/api/console/v1/overview"
# Longer than the slowest timer Home holds, the session's sixty-second refresh, so a timer of any
# of Home's cadences left running while hidden ticks at least once.
HIDDEN_SECONDS = 65


class Admitter(threading.Thread):
    """Admits one governed request on an interval, each on a target of its own, so Home's
    figures and charts change between polls as its recent decisions do."""

    def __init__(self, db, world, waiting):
        super().__init__(daemon=True)
        self.db = db
        self.world = world
        self.waiting = waiting
        self.stop = threading.Event()
        self.admitted = 0
        self.failed: list[str] = []

    def run(self) -> None:
        while self.waiting and not self.stop.wait(ADMIT_SECONDS):
            try:
                admit(self.db, self.world["identity"], self.waiting.pop(), self.world["clock"])
                self.admitted += 1
            except Exception as exc:  # reported by the soak rather than dying silently
                self.failed.append(repr(exc))


@pytest.fixture
def admitter(db, admin_engine, drawn):
    # One target for every admission the soak can make, made before it starts.
    waiting = targets(admin_engine, drawn, int(SOAK_SECONDS / ADMIT_SECONDS) + 10)
    thread = Admitter(db, drawn, waiting)
    yield thread
    thread.stop.set()
    if thread.is_alive():
        thread.join(timeout=10)


def hide(page) -> None:
    """Hide the tab: the two properties a page reads, then the event a browser fires, which
    bubbles, so a listener on `window` hears it as one on `document` does."""
    page.evaluate(
        "Object.defineProperty(document, 'hidden', {value: true, configurable: true});"
        "Object.defineProperty(document, 'visibilityState', "
        "{value: 'hidden', configurable: true});"
        "document.dispatchEvent(new Event('visibilitychange', {bubbles: true}));"
    )


def figure(page, label: str) -> str:
    """The value a Home figure shows, by its label."""
    tile = page.locator(".home-figure", has=page.locator(".home-figure-label", has_text=label))
    return tile.locator(".home-figure-value").first.inner_text()


@pytest.mark.timed
def test_home_left_open_neither_grows_nor_asks_while_it_is_hidden(
    console_page, console_gateway, admin_engine, db, drawn, renamer, admitter, timed_alone
):
    answered: list[str] = []
    console_page.on(
        "response",
        lambda response: (
            answered.append(response.url) if OVERVIEW in response.url and response.ok else None
        ),
    )

    # The same lock as the board's soak: polls that arrive and a heap that holds are this page's
    # behaviour, not contention from other work on the machine. The session is made once the lock
    # is held, because the browser counts its cookie's fifteen minutes in real time while the
    # server counts the session against the test's frozen clock, and the waits for a quiet machine
    # and for the lock can outlast the cookie. The threads start then too, so those waits spend
    # none of the admitter's targets.
    with timed_alone("the Home soak") as machine:
        sign_in_as(console_page, admin_engine, drawn["admin"])
        console_page.goto("/")
        expect(console_page.get_by_role("heading", level=1)).to_have_text("Home")
        recent = console_page.get_by_role("table", name="Recent decisions", exact=False)
        expect(recent).to_be_visible()
        cdp = console_page.context.new_cdp_session(console_page)
        cdp.send("Performance.enable")
        cdp.send("HeapProfiler.enable")
        renamer.start()
        admitter.start()

        console_page.wait_for_timeout(int(SOAK_SECONDS * BASELINE_FRACTION * 1000))
        settled = heap(cdp)
        seen = len(answered)
        rows, decisions = recent.inner_text(), figure(console_page, "Decisions")

        console_page.wait_for_timeout(int(SOAK_SECONDS * (1 - BASELINE_FRACTION) * 1000))
        grown = heap(cdp)
        polls = len(answered) - seen
        rows_after, decisions_after = recent.inner_text(), figure(console_page, "Decisions")

    assert admitter.failed == [], admitter.failed
    # One overview answer a poll; well under half of that means the timer stalled, and a heap that
    # held while nothing was answered proves nothing.
    expected = SOAK_SECONDS * (1 - BASELINE_FRACTION) / HOME_POLL_SECONDS
    assert polls > expected * 0.4, (
        f"only {polls} of about {expected:.0f} overview polls were answered; {machine.note}"
    )
    # And what the polls brought was drawn: the recent decisions name the agent as renamed since,
    # and the overview counts the requests admitted since.
    assert rows_after != rows, "Home's recent decisions were not drawn again over the soak"
    assert decisions_after != decisions, "Home's Decisions figure did not change over the soak"
    growth = (grown - settled) / settled
    # Printed so a deliberate run records its own figures rather than only its verdict.
    print(
        f"home soak {SOAK_SECONDS / 60:.0f}min: {polls} polls, {admitter.admitted} admitted, "
        f"heap {settled} -> {grown} ({growth:+.1%})"
    )
    assert growth < 0.20, (
        f"the heap grew {growth:.1%} over {SOAK_SECONDS - SOAK_SECONDS * BASELINE_FRACTION:.0f}s "
        f"and {polls} polls: {settled} to {grown} bytes; {machine.note}"
    )
    assert console_page.evaluate("window.__violations") == []

    # Hidden, in the same long-lived page. A request the visible page sent a moment before is not
    # the hidden page's, so the watch starts once the hide has settled; every timer Home holds
    # would then tick at least once in what is left.
    admitter.stop.set()
    hide(console_page)
    console_page.wait_for_timeout(500)
    hidden: list[str] = []
    console_page.on("request", lambda request: hidden.append(request.url))
    console_page.wait_for_timeout(HIDDEN_SECONDS * 1000)
    assert [url for url in hidden if "/api/console/" in url] == []
