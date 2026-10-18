# SPDX-License-Identifier: AGPL-3.0-only
"""The browser suite's recovery from a connection that breaks under it.

On a host that runs more than one job at a time, the suite's commonest rerun was not a product
failure: a page left at the console's plain frame ("Loading") because its entry module never
ran, or `page.goto` failing with `net::ERR_NETWORK_CHANGED`, while every request the server saw
answered 200. The cause was confirmed in October 2026 (#746): Chromium treats any address added
to or removed from any interface on the host as a change of network and fails the requests it
has in flight, even to 127.0.0.1, and Docker adds and removes such addresses whenever another
job starts or stops a container. `tests/browser_network.py` now launches the browser so that it
never hears of those changes; this module stays as the second line, for a host where that
library cannot be built and for any connection that breaks for another reason.

`watched(browser)` wraps the `chromium` fixture's browser so that every context it opens:

- prints each failed request as its method, path and error text, never its query string, and
  saves no trace, HAR, video or screenshot;
- tries a `page.goto` that failed with `net::ERR_NETWORK_CHANGED` once more;
- reloads a page once when its module script failed to load and a script request of that
  document failed because its connection broke (`TRANSIENT`).

Nothing else is recovered: not an HTTP error status, not a JavaScript exception, not a request
the browser cancelled (`net::ERR_ABORTED`) and not one a test refused with `route.abort()`
(`net::ERR_FAILED`). Each recovery is printed and raised as a `BrowserRecoveryWarning`, which
pytest lists in the run's warnings summary even when the test passes, so the rate stays
visible. The recovery keys off the script's load error, never off the frame still showing,
because the frame's lifetime belongs to the console.
"""

import functools
import warnings
from urllib.parse import urlsplit

from playwright.sync_api import Error as PlaywrightError
from playwright.sync_api import TimeoutError as PlaywrightTimeoutError

# The errors that mean the connection itself broke: the network changed under it, or the
# other end reset, closed or aborted it. A refused connection is a server that is not there.
TRANSIENT = frozenset(
    {
        "net::ERR_NETWORK_CHANGED",
        "net::ERR_CONNECTION_RESET",
        "net::ERR_CONNECTION_CLOSED",
        "net::ERR_CONNECTION_ABORTED",
    }
)
GOTO_RETRIED = "net::ERR_NETWORK_CHANGED"
BINDING = "__execboundBrowserRecovery"

# Runs in every document before its own scripts; an init script is not subject to the page's
# CSP. A module script's `error` event fires only when its module graph failed to load (a
# network error or an error status), never for an exception it throws, and it does not
# bubble, so it is caught in the capture phase. The page asks the harness whether a script
# request's connection broke; the answer may lag the event by a moment, so "wait" is asked
# again a few times before the page gives up. The reload waits for `load`, so the navigation
# that opened the page has completed before the document is replaced.
WATCH_ENTRY = """
(() => {
  let asked = false;
  window.addEventListener('error', (event) => {
    const script = event.target;
    if (asked || !(script instanceof HTMLScriptElement) || script.type !== 'module') return;
    asked = true;
    window.__execboundRecovery = 'asking';
    const reload = () => {
      window.__execboundRecovery = 'reloading';
      location.reload();
    };
    (async () => {
      for (let attempt = 0; attempt < 10; attempt += 1) {
        const verdict = await window.BINDING(script.src);
        if (verdict === 'reload') {
          if (document.readyState === 'complete') reload();
          else window.addEventListener('load', reload, { once: true });
          return;
        }
        if (verdict !== 'wait') break;
        await new Promise((resolve) => setTimeout(resolve, 50));
      }
      window.__execboundRecovery = 'declined';
    })();
  }, true);
})();
""".replace("BINDING", BINDING)


class BrowserRecoveryWarning(UserWarning):
    """A browser test went on only because the harness retried or reloaded for it."""


def announce(what: str) -> None:
    message = f"browser recovery: {what}"
    print(message, flush=True)
    warnings.warn(message, BrowserRecoveryWarning, stacklevel=2)


def path_of(url: str) -> str:
    """A URL's path, never its query or fragment; a non-HTTP URL is only its scheme."""
    parts = urlsplit(url)
    if parts.scheme and parts.scheme not in ("http", "https"):
        return parts.scheme + ":"
    return parts.path or "/"


def described(request) -> str:
    return f"{request.method} {path_of(request.url)} {request.failure or '(no error text)'}"


def transient(failure: str | None) -> bool:
    return failure in TRANSIENT


def retries_goto(error: BaseException) -> bool:
    """Only a navigation that failed because the network changed, judged by the error's own
    first line, never by a call log under a timeout."""
    if not isinstance(error, PlaywrightError) or isinstance(error, PlaywrightTimeoutError):
        return False
    return GOTO_RETRIED in error.message.split("\n", 1)[0]


def retrying(goto):
    @functools.wraps(goto)
    def go(url, *args, **options):
        try:
            return goto(url, *args, **options)
        except PlaywrightError as error:
            if not retries_goto(error):
                raise
            announce(f"retried goto {path_of(url)} after {GOTO_RETRIED}")
            return goto(url, *args, **options)

    return go


class _Page:
    """What one page has seen: its document's broken script requests, and its one reload."""

    def __init__(self) -> None:
        self.broken: list[str] = []
        self.reloaded = False


def _watch_context(context) -> None:
    pages: dict[object, _Page] = {}

    def verdict(source, src):
        # A binding callback runs on Playwright's event loop: it may read state, never call
        # the sync API.
        page = source["page"]
        seen = pages.get(page)
        if seen is None or seen.reloaded:
            return "spent"
        if not seen.broken:
            return "wait"
        seen.reloaded = True
        announce(f"reloaded {path_of(page.url)} after {seen.broken[0]}")
        return "reload"

    def page_opened(page) -> None:
        seen = pages[page] = _Page()

        def failed(request) -> None:
            print(f"browser request failed: {described(request)}", flush=True)
            if request.resource_type == "script" and transient(request.failure):
                seen.broken.append(described(request))

        def navigated(frame) -> None:
            if frame.parent_frame is None:
                seen.broken.clear()

        page.on("requestfailed", failed)
        page.on("framenavigated", navigated)
        page.goto = retrying(page.goto)

    context.add_init_script(WATCH_ENTRY)
    context.expose_binding(BINDING, verdict)
    context.on("page", page_opened)


def watched(browser):
    """`browser`, opening only watched contexts.

    A context's `page` event fires before `new_page` returns, so every page is watched before
    its first navigation. `browser.new_page()` would open a context this wrapper never sees,
    so it is refused rather than left unwatched.
    """
    opened = browser.new_context

    def new_context(*args, **options):
        context = opened(*args, **options)
        _watch_context(context)
        return context

    def new_page(*args, **options):
        raise AssertionError(
            "Open a page with chromium.new_context().new_page(), so the page is watched"
        )

    browser.new_context = new_context
    browser.new_page = new_page
    return browser
