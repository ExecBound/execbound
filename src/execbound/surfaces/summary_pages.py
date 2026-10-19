# SPDX-License-Identifier: AGPL-3.0-only
"""The weekly summary's unsubscribe pages (#678): one click, without signing in.

Each summary carries `<origin>/weekly-summary/unsubscribe/ebw1.<tenant>.<message>.<secret>`
in its `List-Unsubscribe` header and once in its body. RFC 8058 has the mail client `POST` to
that address, which a fragment cannot carry, so unlike the invitation link the secret is in
the path; the request log records no path, both pages send `Referrer-Policy: no-referrer`
and `Cache-Control: no-store`, their refusals `no-referrer` too, and `ebw1` is one of the
secret shapes the log and export guards refuse.

`GET` reads nothing and changes nothing, so a mail scanner's prefetch does nothing: it shows a
page with one form that posts to the same address. `POST` ends the subscription only when the
secret is that message's own, its subscription is active and started no later than the message
was queued, and answers every request the same way, a forged, unknown, used or malformed link
and a workspace that does not exist included, so nothing tells anyone whether a subscription
exists. There is no CSRF token, by RFC 8058's design: the only power of a valid link is to end
its own recipient's summary. Both routes are limited per peer, which behind a proxy bounds the
deployment, and per message, which bounds guessing against one link; a 256-bit secret is what
makes guessing pointless.
"""

from fastapi import APIRouter, HTTPException, Request
from starlette.concurrency import run_in_threadpool
from starlette.responses import HTMLResponse

from execbound.runtime import Runtime
from execbound.surfaces.http import IDENTITY_HEADERS, client_key
from execbound.surfaces.human import HumanConfig, _page
from execbound.surfaces.limits import RateLimited
from execbound.weekly_summary import parse_link, unsubscribe

# A one-click body is one short field; anything larger is not one.
MAX_BODY = 2048
FORMS = frozenset({"application/x-www-form-urlencoded", "multipart/form-data"})
# A refusal's page is answered at the same address, which holds the link's secret, and it
# loads the stylesheet and links to sign in: it keeps the stricter policy too.
REFUSED = {"Referrer-Policy": "no-referrer"}


def summary_router(runtime: Runtime, config: HumanConfig) -> APIRouter:
    routes = APIRouter()

    def page(*, done: bool) -> HTMLResponse:
        response = _page(
            "summary_unsubscribe.html",
            service=config.service,
            title="Weekly summary",
            session=None,
            csrf="",
            done=done,
        )
        response.headers["Cache-Control"] = "no-store"
        response.headers["Referrer-Policy"] = "no-referrer"
        return response

    def checked(request: Request, link: str) -> None:
        """The request's shape, then both limits; a link names its message only if well formed.

        No session, cookie or credential is read or required, and none is refused for being
        there: a person signed in to the console may click the link in the same browser.
        """
        if (
            request.query_params
            or any(name in request.headers for name in IDENTITY_HEADERS)
            or "authorization" in request.headers
            or "content-encoding" in request.headers
        ):
            raise HTTPException(400, "Invalid request", headers=REFUSED)
        if request.method == "GET" and (
            request.headers.get("content-length", "0") != "0"
            or "transfer-encoding" in request.headers
        ):
            raise HTTPException(400, "Invalid request", headers=REFUSED)
        if request.method == "POST":
            kind = request.headers.get("content-type", "").split(";", 1)[0].strip().lower()
            length = request.headers.get("content-length", "")
            if (
                kind not in FORMS
                or "transfer-encoding" in request.headers
                or not length.isdigit()
                or int(length) > MAX_BODY
            ):
                raise HTTPException(400, "Invalid request", headers=REFUSED)
        parsed = parse_link(link)
        try:
            runtime.limiter.refuse("client", client_key(request))
            if parsed is not None:
                runtime.limiter.refuse("login", f"ebw1:{parsed[1]}")
        except RateLimited as exc:
            raise HTTPException(
                429, "Too many attempts", headers={**REFUSED, "Retry-After": str(exc.retry_after)}
            ) from None

    @routes.get("/weekly-summary/unsubscribe/{link}")
    async def show(request: Request, link: str) -> HTMLResponse:
        checked(request, link)
        return page(done=False)

    @routes.post("/weekly-summary/unsubscribe/{link}")
    async def stop(request: Request, link: str) -> HTMLResponse:
        checked(request, link)
        # The outcome is never shown: every request gets the same page.
        await run_in_threadpool(unsubscribe, runtime.db, link, runtime.clock)
        return page(done=True)

    return routes
