# SPDX-License-Identifier: AGPL-3.0-only
"""Ten minutes on the live board: the heap holds, and a hidden tab asks for nothing.

The console's performance criterion for a page left open
(#333): after ten minutes on the Live
board the JavaScript heap has grown by less than twenty per cent since minute two, and no request
fires while the tab is hidden. A display on a wall is
the case that matters, because nobody reloads it.

Two things make this a soak rather than a wait.

**The board actually changes.** An idle board sends a comment every fifteen seconds and renders
nothing, so ten minutes of it would prove that a page which does nothing leaks nothing. A thread
here renames the agent every half second, which changes the board's digest, so the server sends a
frame every poll and the page re-renders the whole picture each time. What is soaked is the
render path, which is where a leak would live.

**The heap is read after a collection, not before.** `HeapProfiler.collectGarbage` over the
DevTools protocol, twice with a pause between, and `JSHeapUsedSize` from `Performance.getMetrics`;
reading `performance.memory` from the page would measure uncollected garbage and call it growth.

`EXECBOUND_BOARD_SOAK_MINUTES` sets the length. The default is three minutes, which is a real soak
and is what a full run of the suite takes; the ten-minute figure the criterion names is a
measurement taken on purpose, on an otherwise idle machine, with `EXECBOUND_BOARD_SOAK_MINUTES=10`
and `-s` so the run prints its own figures. The baseline is always taken a fifth of the way in,
which is minute two of ten.
"""

import os

import pytest
from playwright.sync_api import expect
from test_browser_console import console_gateway as console_gateway
from test_browser_console import console_page as console_page
from test_browser_console import sign_in_as
from test_browser_console_board import BOARD, CLOSE_SECONDS, COUNT, POLL, let_go
from test_browser_console_board import drawn as drawn
from test_browser_console_board import renamer as renamer
from test_browser_surfaces import chromium as chromium
from test_execution import registry as registry
from test_execution import world as world
from test_protected_path import connector as connector
from test_protected_path import live_provider as live_provider
from test_runtime import runtime as runtime

from execbound.surfaces.console_api import board as board_api

SOAK_SECONDS = float(os.environ.get("EXECBOUND_BOARD_SOAK_MINUTES", "3")) * 60
# Minute two of ten: far enough in that the route chunk, the fonts and the first renders have
# settled, so what is measured afterwards is the steady state and not the arrival.
BASELINE_FRACTION = 0.2
HIDDEN_SECONDS = 20


def heap(cdp) -> int:
    """Used heap after a collection, in bytes. Twice, because one pass leaves stragglers."""
    for _ in range(2):
        cdp.send("HeapProfiler.collectGarbage")
    metrics = cdp.send("Performance.getMetrics")["metrics"]
    return int(next(metric["value"] for metric in metrics if metric["name"] == "JSHeapUsedSize"))


@pytest.mark.timed
def test_the_board_left_open_neither_grows_nor_asks_while_it_is_hidden(
    monkeypatch, console_page, console_gateway, admin_engine, db, drawn, renamer, timed_alone
):
    monkeypatch.setattr(board_api, "STREAM_POLL_SECONDS", POLL)
    console_page.add_init_script(COUNT)
    sign_in_as(console_page, admin_engine, drawn["admin"])
    console_page.goto(BOARD)
    expect(console_page.get_by_role("heading", level=1)).to_have_text("Live board")
    expect(console_page.get_by_text("Live. The board updates itself")).to_be_visible()

    cdp = console_page.context.new_cdp_session(console_page)
    cdp.send("Performance.enable")
    cdp.send("HeapProfiler.enable")
    renamer.start()

    # The soak window is a measurement, so it holds the machine's timing lock: frames that
    # arrive and a heap that holds are this page's behaviour, not contention from other work on
    # the machine. Nothing outside this block waits on it, and the hidden half below asks for
    # none.
    with timed_alone("the live board soak") as machine:
        console_page.wait_for_timeout(int(SOAK_SECONDS * BASELINE_FRACTION * 1000))
        settled = heap(cdp)
        seen = int(console_page.evaluate("window.__frames"))

        console_page.wait_for_timeout(int(SOAK_SECONDS * (1 - BASELINE_FRACTION) * 1000))
        grown = heap(cdp)
        frames = int(console_page.evaluate("window.__frames")) - seen

    # Two frames a second is what the renamer and the poll ask for; well under half of that
    # means the stream stalled, and a heap that held while nothing arrived proves nothing.
    expected = SOAK_SECONDS * (1 - BASELINE_FRACTION) / POLL
    assert frames > expected * 0.4, (
        f"only {frames} of about {expected:.0f} frames arrived; {machine.note}"
    )
    growth = (grown - settled) / settled
    # Printed so a deliberate run records its own figures rather than only its verdict; pytest
    # captures it unless the run asks for it with -s, which is how the ten-minute run is taken.
    print(
        f"soak {SOAK_SECONDS / 60:.0f}min: {frames} frames, heap {settled} -> {grown} "
        f"({growth:+.1%})"
    )
    assert growth < 0.20, (
        f"the heap grew {growth:.1%} over {SOAK_SECONDS - SOAK_SECONDS * BASELINE_FRACTION:.0f}s "
        f"and {frames} frames: {settled} to {grown} bytes; {machine.note}"
    )
    assert console_page.evaluate("window.__violations") == []

    # Hidden, in the same long-lived page: the connection goes and nothing is asked for at all.
    asked: list[str] = []
    console_page.on("request", lambda request: asked.append(request.url))
    console_page.evaluate(
        "Object.defineProperty(document, 'hidden', {value: true, configurable: true});"
        "Object.defineProperty(document, 'visibilityState', "
        "{value: 'hidden', configurable: true});"
        "document.dispatchEvent(new Event('visibilitychange'));"
    )
    expect(console_page.get_by_text("Not in view")).to_be_visible()
    # The page lets go of the stream in an effect's cleanup, a moment after the event, and the
    # renamer keeps the server sending all the while: a frame already on its way can land in
    # that moment, while the page is still entitled to it. So the frames are counted from the
    # close, and the close itself has to come promptly, or the tab is still holding a connection.
    assert let_go(console_page, CLOSE_SECONDS), (
        f"the hidden tab still held its stream {CLOSE_SECONDS}s after it was hidden"
    )
    before = int(console_page.evaluate("window.__frames"))
    console_page.wait_for_timeout(HIDDEN_SECONDS * 1000)
    assert [url for url in asked if "/api/console/" in url] == []
    assert int(console_page.evaluate("window.__frames")) == before
