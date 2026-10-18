# SPDX-License-Identifier: AGPL-3.0-only
"""The browser hears of no host network change (#746), held to what `browser_network` promises.

A plain Chromium binds a `NETLINK_ROUTE` socket that joins the address and link groups; that is
what makes a container started elsewhere on the machine fail its requests. Launched through
`browser_network.launched`, the same browser's route sockets join no group and pages still
load. Where the library cannot be built, the browser starts as before and says why; where it
was built but did not take, the fixture says that too.
"""

import os
import threading
import warnings
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import browser_network
import pytest
from playwright.sync_api import sync_playwright


@pytest.fixture
def host_server():
    """A server on loopback that answers with the path it was asked for."""

    class Echo(BaseHTTPRequestHandler):
        def do_GET(self):
            body = f"<p id=path>{self.path}</p>".encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *args):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Echo)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server.server_address[1]
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=10)


def isolation_warnings(caught):
    warning = browser_network.BrowserIsolationWarning
    return [str(w.message) for w in caught if issubclass(w.category, warning)]


def test_a_plain_browser_joins_the_route_groups_the_library_takes_away():
    # What the library exists to undo, and what makes the check below mean something: if
    # Chromium stops subscribing this way, this fails and the library should be revisited.
    with sync_playwright() as playwright:
        browser = playwright.chromium.launch()
        try:
            joined = [group for group in browser_network.route_groups(os.getpid()) if group]
        finally:
            browser.close()
    assert joined, "a plain browser held no route socket in any group"


def test_the_launched_browser_joins_no_route_group_and_still_loads_pages(host_server):
    reason = browser_network._library()[1]
    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        with (
            sync_playwright() as playwright,
            browser_network.launched(playwright.chromium) as browser,
        ):
            groups = browser_network.route_groups(os.getpid())
            page = browser.new_page()
            page.goto(f"http://127.0.0.1:{host_server}/by-address")
            assert page.locator("#path").inner_text() == "/by-address"
            page.goto(f"http://localhost:{host_server}/by-name")
            assert page.locator("#path").inner_text() == "/by-name"
    if reason is None:
        assert groups and not any(groups), groups
        assert isolation_warnings(caught) == []
    else:
        assert isolation_warnings(caught) == [f"browser isolation: {reason}"]


def test_without_the_library_the_browser_runs_as_before_and_says_why(host_server, monkeypatch):
    monkeypatch.setattr(browser_network, "_library", lambda: (None, "no C compiler here"))
    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        with (
            sync_playwright() as playwright,
            browser_network.launched(playwright.chromium) as browser,
        ):
            page = browser.new_page()
            page.goto(f"http://127.0.0.1:{host_server}/plain")
            assert page.locator("#path").inner_text() == "/plain"
    assert isolation_warnings(caught) == ["browser isolation: no C compiler here"]


def test_a_library_that_does_not_take_is_reported(monkeypatch):
    # The C library itself, preloaded: it changes nothing, so the route socket keeps its groups.
    monkeypatch.setattr(browser_network, "_library", lambda: ("libc.so.6", None))
    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        with sync_playwright() as playwright, browser_network.launched(playwright.chromium):
            pass
    reported = isolation_warnings(caught)
    assert len(reported) == 1 and "a route socket still joins groups" in reported[0], reported
