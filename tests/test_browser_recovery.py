# SPDX-License-Identifier: AGPL-3.0-only
"""The browser suite's recovery, held to what it does and to what it must never do.

`tests/browser_recovery.py` watches every context the `chromium` fixture opens: it logs each
failed request by method, path and error, tries a `page.goto` once more when it fails with
`net::ERR_NETWORK_CHANGED`, and reloads a page once when its module script did not load
because a script request's connection broke. It must never recover an HTTP error status, a
JavaScript exception or a refusal a test made on purpose.

`route.abort("connectionreset")` stands in for the broken connection. Chromium has no
`networkchanged` abort, so the goto retry is driven with a stand-in `goto`; its predicate is
what is under test there.
"""

import re
import time
from types import SimpleNamespace
from urllib.parse import urlsplit

import pytest
from browser_recovery import (
    BrowserRecoveryWarning,
    described,
    retries_goto,
    retrying,
    transient,
)
from playwright.sync_api import Error as PlaywrightError
from playwright.sync_api import TimeoutError as PlaywrightTimeoutError
from playwright.sync_api import expect
from test_browser_surfaces import browser_gateway as browser_gateway
from test_browser_surfaces import chromium as chromium
from test_browser_surfaces import human_page as human_page
from test_browser_surfaces import sign_in
from test_execution import registry as registry
from test_execution import world as world
from test_protected_path import connector as connector
from test_protected_path import live_provider as live_provider
from test_runtime import runtime as runtime

CHANGED = "Page.goto: net::ERR_NETWORK_CHANGED at http://127.0.0.1:49589/people/5b36b1ff"
STATE = "window.__execboundRecovery === undefined ? null : window.__execboundRecovery"


def entry_module(page, origin):
    """The path of the module script the console's document loads, read from that document."""
    served = page.request.get(origin + "/activity").text()
    found = re.search(r'<script type="module"[^>]*\ssrc="([^"]+)"', served)
    assert found is not None, served[:400]
    return urlsplit(found.group(1)).path


def intercept(page, origin, answer):
    """Route the entry module through `answer(route, attempt)`; return the attempts seen."""
    entry = entry_module(page, origin)
    attempts: list[str] = []

    def handle(route):
        attempts.append(route.request.url)
        answer(route, len(attempts))

    page.route(lambda url: urlsplit(url).path == entry, handle)
    return entry, attempts


def settled_on(page, verdict):
    """Wait until the watcher in the page has said `verdict`; the console's CSP refuses
    `wait_for_function`, so this asks with `evaluate` until it hears it."""
    deadline = time.monotonic() + 10
    seen = None
    while time.monotonic() < deadline:
        try:
            seen = page.evaluate(STATE)
        except PlaywrightError:
            seen = "between documents"  # a reload replaced the document mid-question
        if seen == verdict:
            return
        page.wait_for_timeout(50)
    raise AssertionError(f"the page's recovery said {seen!r}, not {verdict!r}")


def recoveries(recwarn):
    return [str(w.message) for w in recwarn.list if issubclass(w.category, BrowserRecoveryWarning)]


def test_an_entry_module_reset_on_the_wire_is_loaded_again(
    human_page, browser_gateway, admin_engine, world, capsys, recwarn
):
    """The flake this answers: the page stays at the plain frame's "Loading" because its entry
    module never arrived. One reload, printed, and the page reaches its heading."""
    page = human_page
    sign_in(page, admin_engine, world)

    def reset_once(route, attempt):
        if attempt == 1:
            route.abort("connectionreset")
        else:
            route.continue_()

    entry, attempts = intercept(page, browser_gateway, reset_once)
    page.goto("/activity")
    expect(page.get_by_role("heading", level=1)).to_have_text("Activity")
    assert len(attempts) == 2
    assert recoveries(recwarn) == [
        f"browser recovery: reloaded /activity after GET {entry} net::ERR_CONNECTION_RESET"
    ]
    printed = capsys.readouterr().out
    assert f"browser request failed: GET {entry} net::ERR_CONNECTION_RESET" in printed
    assert "browser recovery: reloaded /activity" in printed


def test_a_page_is_reloaded_once_and_never_twice(
    human_page, browser_gateway, admin_engine, world, recwarn
):
    page = human_page
    sign_in(page, admin_engine, world)
    _, attempts = intercept(
        page, browser_gateway, lambda route, attempt: route.abort("connectionreset")
    )
    page.goto("/activity")
    settled_on(page, "declined")
    expect(page.locator("#frame")).to_be_visible()
    assert len(attempts) == 2
    assert len(recoveries(recwarn)) == 1


@pytest.mark.parametrize("refusal", ["status", "refused"])
def test_an_entry_module_refused_rather_than_cut_off_is_not_reloaded(
    human_page, browser_gateway, admin_engine, world, recwarn, refusal
):
    """An HTTP error status is the server's answer, and `route.abort()` with no code
    (`net::ERR_FAILED`) is how a test refuses the bundle on purpose (the plain frame's own
    test does): neither is a connection that broke, so the page is left as it is."""
    page = human_page
    sign_in(page, admin_engine, world)

    def refuse(route, attempt):
        if refusal == "status":
            route.fulfill(status=503, content_type="text/plain", body="unavailable")
        else:
            route.abort()

    _, attempts = intercept(page, browser_gateway, refuse)
    page.goto("/activity")
    settled_on(page, "declined")
    expect(page.locator("#frame")).to_be_visible()
    assert len(attempts) == 1
    assert recoveries(recwarn) == []


def test_an_entry_module_that_throws_is_not_reloaded(
    human_page, browser_gateway, admin_engine, world, recwarn
):
    """A script that arrived and threw is a defect to see, not a network to wait out: no
    load error fires, so the watcher never asks."""
    page = human_page
    sign_in(page, admin_engine, world)

    def throws(route, attempt):
        route.fulfill(
            status=200,
            content_type="text/javascript",
            body="throw new Error('the entry module threw');",
        )

    _, attempts = intercept(page, browser_gateway, throws)
    with page.expect_event("pageerror") as thrown:
        page.goto("/activity")
    assert "the entry module threw" in str(thrown.value)
    assert page.evaluate(STATE) is None
    expect(page.locator("#frame")).to_be_visible()
    assert len(attempts) == 1
    assert recoveries(recwarn) == []


@pytest.mark.parametrize(
    ("error", "retried"),
    [
        (PlaywrightError(CHANGED), True),
        (PlaywrightError(CHANGED + "\nCall log:\n  - navigating to /people"), True),
        (PlaywrightError("Page.goto: net::ERR_CONNECTION_REFUSED at http://127.0.0.1:1/"), False),
        (PlaywrightError("Page.goto: net::ERR_ABORTED at http://127.0.0.1:1/"), False),
        (PlaywrightError("Page.goto: net::ERR_CONNECTION_RESET at http://127.0.0.1:1/"), False),
        (
            PlaywrightError(
                "Page.goto: Timeout 15000ms exceeded.\nCall log:\n  - net::ERR_NETWORK_CHANGED"
            ),
            False,
        ),
        (PlaywrightTimeoutError(CHANGED), False),
        (RuntimeError("net::ERR_NETWORK_CHANGED"), False),
    ],
)
def test_goto_is_retried_only_when_the_network_changed(error, retried):
    assert retries_goto(error) is retried


def stand_in(*outcomes):
    """A `goto` that answers with each outcome in turn, raising the exceptions among them."""
    calls: list[str] = []
    remaining = list(outcomes)

    def goto(url, **options):
        calls.append(url)
        outcome = remaining.pop(0)
        if isinstance(outcome, BaseException):
            raise outcome
        return outcome

    return goto, calls


def test_a_changed_network_costs_a_goto_one_more_try_and_says_so():
    goto, calls = stand_in(PlaywrightError(CHANGED), "the response")
    with pytest.warns(BrowserRecoveryWarning, match=r"^browser recovery: retried goto /people/x"):
        assert retrying(goto)("/people/x?open=1", wait_until="load") == "the response"
    assert calls == ["/people/x?open=1", "/people/x?open=1"]


def test_a_second_changed_network_fails_the_goto():
    second = PlaywrightError(CHANGED)
    goto, calls = stand_in(PlaywrightError(CHANGED), second)
    with pytest.warns(BrowserRecoveryWarning), pytest.raises(PlaywrightError) as raised:
        retrying(goto)("/people/x")
    assert raised.value is second
    assert len(calls) == 2


def test_any_other_goto_failure_or_an_error_status_is_not_retried(recwarn):
    refused = PlaywrightError("Page.goto: net::ERR_CONNECTION_REFUSED at http://127.0.0.1:1/")
    goto, calls = stand_in(refused)
    with pytest.raises(PlaywrightError) as raised:
        retrying(goto)("/activity")
    assert raised.value is refused and len(calls) == 1
    # An HTTP error status is a response, not an exception: it comes back as it was.
    unavailable = SimpleNamespace(status=503)
    goto, calls = stand_in(unavailable)
    assert retrying(goto)("/activity") is unavailable and len(calls) == 1
    assert recoveries(recwarn) == []


@pytest.mark.parametrize(
    ("failure", "broke"),
    [
        ("net::ERR_NETWORK_CHANGED", True),
        ("net::ERR_CONNECTION_RESET", True),
        ("net::ERR_CONNECTION_CLOSED", True),
        ("net::ERR_CONNECTION_ABORTED", True),
        ("net::ERR_FAILED", False),
        ("net::ERR_ABORTED", False),
        ("net::ERR_CONNECTION_REFUSED", False),
        ("net::ERR_BLOCKED_BY_CLIENT", False),
        ("", False),
        (None, False),
    ],
)
def test_only_a_connection_that_broke_counts_as_transient(failure, broke):
    assert transient(failure) is broke


def test_a_failed_request_is_described_by_method_path_and_error_only():
    request = SimpleNamespace(
        method="POST",
        url="http://127.0.0.1:5/api/console/v1/session?token=not-for-the-log#and-not-this",
        failure="net::ERR_NETWORK_CHANGED",
    )
    assert described(request) == "POST /api/console/v1/session net::ERR_NETWORK_CHANGED"
    data = SimpleNamespace(method="GET", url="data:text/html,<h1>x</h1>", failure=None)
    assert described(data) == "GET data: (no error text)"
