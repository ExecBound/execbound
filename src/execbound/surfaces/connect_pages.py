# SPDX-License-Identifier: AGPL-3.0-only
"""Microsoft Entra admin consent's two browser routes (#228, #678).

`POST /connect/entra/signed-in` takes Microsoft's `form_post` of the administrator's id_token and,
once `monitoring.consent.signed_in` has verified it, the attempt, the browser and the directory,
sends the browser on to that directory's admin consent page. `GET /connect/entra/consented` takes
Microsoft's redirect back and completes the consent. Both run with no session: Microsoft's
callbacks are cross-site, and the console's SameSite=Strict session cookie does not travel on
them. What admits a request is the binding cookie the starting browser holds, set by the console
API's start route with SameSite=None so that it does travel, and a live attempt its `state`
names.

The sign-in callback is the one post this application takes from another origin, and it takes
it from Microsoft's alone. Every refusal, and the success of a consent, lands on a page of this
site's own (`onward`) that moves the browser to the Connections view: a 303 in a chain a
cross-site navigation began reaches the console without its session. The page says nothing
about what happened; the console reads that from the server. Both routes are served only where
the runtime configuration names the platform app (`scout.entra`), and answer 404 everywhere else.
Both are limited per peer, like the sign-in callbacks, and neither page carries a referrer.
"""

from typing import Any
from urllib.parse import parse_qsl

import anyio
from fastapi import APIRouter, HTTPException, Request
from starlette.concurrency import run_in_threadpool
from starlette.responses import RedirectResponse, Response

from execbound.directory import DirectoryKeys
from execbound.monitoring import consent
from execbound.runtime import Runtime
from execbound.surfaces.http import client_key
from execbound.surfaces.human import HumanConfig, onward, request_guards
from execbound.surfaces.limits import RateLimited

MAX_FORM = 16384
FORM_FIELDS = 16
# The binding cookie's life: an attempt's.
BINDING_SECONDS = 600
# One set of attributes for setting the binding cookie and for ending it, so the two always
# agree. HttpOnly, so no script reads it; SameSite=None, so it travels on Microsoft's
# cross-site callbacks, which a browser accepts only with Secure (a loopback origin included).
BINDING_ATTRIBUTES: dict[str, Any] = {
    "path": "/",
    "secure": True,
    "httponly": True,
    "samesite": "none",
}


def set_binding(response: Response, config: HumanConfig, value: str) -> None:
    """Give the browser that starts an attempt the value only it can finish it with."""
    response.set_cookie(
        config.cookie("connect"), value, max_age=BINDING_SECONDS, **BINDING_ATTRIBUTES
    )


def end_binding(response: Response, config: HumanConfig) -> None:
    response.delete_cookie(config.cookie("connect"), **BINDING_ATTRIBUTES)


def connect_router(runtime: Runtime, config: HumanConfig) -> APIRouter:
    """The consent's browser routes, for a configuration that names the platform app."""
    entra = config.scout.entra if config.scout is not None else None
    if entra is None:
        raise ValueError("The consent routes need the platform app")
    routes = APIRouter()
    guards = request_guards(runtime, config)
    # Microsoft's signing keys, fetched once and cached for an hour (`directory.JWKS_TTL`).
    keys = DirectoryKeys(consent.KEYS_URI, entra.http)

    def limited(request: Request) -> None:
        try:
            runtime.limiter.refuse("client", client_key(request))
        except RateLimited as exc:
            raise HTTPException(
                429, "Too many attempts", headers={"Retry-After": str(exc.retry_after)}
            ) from None

    def binding(request: Request) -> str | None:
        return guards.cookies(request).get(config.cookie("connect")) or None

    def landing(location: str) -> Response:
        """The onward page to the Connections view, with the binding cookie ended."""
        response = onward(location, "Returning to Monitoring.", config.service)
        response.headers["Cache-Control"] = "no-store"
        response.headers["Referrer-Policy"] = "no-referrer"
        end_binding(response, config)
        return response

    async def form(request: Request) -> list[tuple[str, str]]:
        """Microsoft's form_post, as pairs: a repeated key is the handler's to refuse."""
        if request.headers.getlist("content-type") != ["application/x-www-form-urlencoded"]:
            raise HTTPException(400, "Invalid request")
        raw = bytearray()
        try:
            with anyio.fail_after(5):
                async for part in request.stream():
                    raw.extend(part)
                    if len(raw) > MAX_FORM:
                        raise ValueError
            return parse_qsl(
                raw.decode("utf-8"),
                keep_blank_values=True,
                strict_parsing=bool(raw),
                encoding="utf-8",
                errors="strict",
                max_num_fields=FORM_FIELDS,
            )
        except (ValueError, TimeoutError):
            raise HTTPException(400, "Invalid request") from None

    @routes.post(consent.SIGNED_IN, include_in_schema=False)
    async def signed_in(request: Request) -> Response:
        limited(request)
        # Microsoft's page posts this form; nothing else may. The shared boundary holds the post
        # to that one origin, and a post from any other is refused against its attempt.
        from_microsoft = request.headers.getlist("origin") == [consent.LOGIN_ORIGIN]
        if from_microsoft:
            await guards.boundary(request, frozenset(), origin=consent.LOGIN_ORIGIN)
        pairs = await form(request)
        try:
            location = await run_in_threadpool(
                consent.signed_in,
                runtime.db,
                keys,
                client_id=entra.client_id,
                authority=entra.authority,
                origin=config.origin,
                request_origin=consent.LOGIN_ORIGIN if from_microsoft else None,
                pairs=pairs,
                binding=binding(request),
                now=runtime.clock.now().timestamp(),
            )
        except consent.ConnectRefused:
            return landing(consent.REFUSED)
        response = RedirectResponse(location, status_code=303)
        response.headers["Cache-Control"] = "no-store"
        response.headers["Referrer-Policy"] = "no-referrer"
        return response

    @routes.get(consent.CONSENTED, include_in_schema=False)
    async def consented(request: Request) -> Response:
        limited(request)
        # The query is Microsoft's, read in the handler by the keys its reference documents.
        await guards.boundary(request, None)
        try:
            await run_in_threadpool(
                consent.consented,
                runtime.db,
                client_id=entra.client_id,
                pairs=request.query_params.multi_items(),
                binding=binding(request),
            )
        except consent.ConnectRefused:
            return landing(consent.REFUSED)
        return landing(consent.DONE)

    return routes
