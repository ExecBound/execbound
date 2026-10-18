# SPDX-License-Identifier: AGPL-3.0-only
"""The deployment boundary: the three routes a hook process serves, and what it rewrites.

See docs/ARCADE.md, Deployment and "The boundary rewrites the application's own refusals".
`create_arcade` takes `create_app`'s parameters but for the human surface, so
`uvicorn --factory` with no arguments builds the database and the runtime from the same
`EXECBOUND_RUNTIME_CONFIG` file the gateway reads, and a test passes both in; what it does
not take, and why a hook process must not have one, is in its own docstring. What is
borrowed from `monitoring/ingress.create_ingress` is one idea and its five lines: an ASGI
wrapper that answers 404 to every method and raw path but its own and closes websockets.
Everything else here is this surface's own.

**There is no third health route.** A `GET /health` arriving here is served by the
application's existing `/health/ready` — one readiness answer, one implementation,
unauthenticated, naming no tenant, 200 with the database up and 503 with it down. The path
the hook process publishes is short because that is what Arcade's own configuration and a
hosting platform's health check ask for; what answers it is unchanged.

**The boundary rewrites the application's own non-hook answers, per route, and the two
routes get opposite rules.** `create_app`'s outermost middleware answers a bare 429 whose
body is `{"detail": "Service busy"}` when its in-flight bound is full, and its handlers
answer a bare 503 `{"detail": "Service unavailable"}` for a dependency failure. Neither is
a hook result, neither carries a `code`, and the route never runs — so without this wrapper
the extension's whole decision table is bypassed exactly when the deployment is under load,
and what happens to the tool call then is the customer's failure-mode setting, which is the
dependency this boundary exists to remove.

On `POST /pre` a 429 becomes `200 {"code": "RATE_LIMIT_EXCEEDED"}` and every other answer
that is neither a 200 nor a 401 becomes `200 {"code": "CHECK_FAILED"}`, with no `detail`
key surviving — a malformed body included, because the contract's 400 is a permission to be
unhelpful and nothing here needs it. On `POST /post` nothing is rewritten: a 400, 429, 500
or 503 passes through with its own status and body, because converting one to `OK` would
tell the platform its report was accepted when nothing was settled, and Arcade retries 5xx,
timeouts and connection errors. A 401 passes through on both, because authentication is the
one answer the hook contract and ExecBound already spell the same way.

The asymmetry is the rule: on the way in an answer is better than an error, because an
answer blocks; on the way out an error is better than an answer, because an error is
retried.
"""

import json
from collections.abc import Iterable
from typing import Any

from starlette.responses import JSONResponse
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from execbound.app import create_app
from execbound.arcade.map import ArcadeBlock
from execbound.arcade.models import HookResult
from execbound.db import Database
from execbound.runtime import Runtime

# Method and raw path, so a trailing slash, a doubled separator, a percent-encoding and
# another case are each a different string and each a 404. Everything else this process
# holds is refused the same way, the readiness route under its own path included; the query
# string is not part of the comparison, because a server puts it in `query_string` and
# `checked_request` is what refuses a hook that sends one.
SERVED = frozenset({("POST", b"/pre"), ("POST", b"/post"), ("GET", b"/health")})
# The one path the boundary renames, onto the application's existing readiness answer, and
# the one whose non-hook answers it rewrites.
HEALTH = b"/health"
READINESS = "/health/ready"
REWRITTEN = b"/pre"
# What a pre hook's answer is allowed to keep: an evaluated hook, and the one refusal the
# hook contract spells the same way ExecBound does.
PASSED = frozenset({200, 401})
# Headers the rewritten answer supplies itself, so each is present exactly once whatever
# the application sent. Anything else it set — the request id, the content security policy,
# the frame and referrer rules — is kept as it was.
REPLACED = frozenset(
    {b"content-length", b"content-type", b"cache-control", b"x-content-type-options"}
)
ANSWER_HEADERS = (
    (b"content-type", b"application/json"),
    (b"cache-control", b"no-store"),
    (b"x-content-type-options", b"nosniff"),
)


def create_arcade(
    database: Database | None = None,
    *,
    runtime: Runtime | None = None,
    arcade: ArcadeBlock | None = None,
) -> ASGIApp:
    """The application a hook process serves, behind the boundary that bounds what it is.

    The parameters are `create_app`'s but for the human surface: **a hook process is not a
    human origin**, so this takes no `human` and asks `create_app` to attach none. Without
    the parameter, a factory process reading the gateway's file would take that file's `origin`
    as its own, and `response_headers` would then refuse every request whose `Host` header
    was not the gateway's netloc. At the hook service's own hostname that is a 400 for
    `GET /health`, so the deployment never becomes healthy, and a 400 for every `POST /pre`,
    which this boundary then rewrites to `CHECK_FAILED` — a deployment that blocks every
    governed tool call while answering in the extension's own vocabulary.

    A process built with no hook routes is refused here rather than at the first hook. The
    ways that happens are a configuration file with no `arcade` block and a factory given a
    runtime and no block, and both end the same way: Arcade receives a 404 for every tool
    call, which is not a hook answer either, and what the tool call does then is the
    failure-mode setting again. Refusing at startup is the same fail-closed rule
    `create_app` already applies to a block with no runtime.
    """
    application = create_app(database, runtime=runtime, arcade=arcade, human_surface=False)
    if not {"/pre", "/post"} <= _paths(application.routes):
        raise ValueError("Arcade hooks are not configured")

    async def boundary(scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] == "websocket":
            await send({"type": "websocket.close", "code": 1008})
            return
        if scope["type"] == "http":
            if (scope["method"], scope.get("raw_path")) not in SERVED:
                response = JSONResponse(
                    {"detail": "Not found"},
                    status_code=404,
                    headers={"Cache-Control": "no-store", "X-Content-Type-Options": "nosniff"},
                )
                await response(scope, receive, send)
                return
            if scope["raw_path"] == REWRITTEN:
                await _answered(application, scope, receive, send)
                return
            if scope["raw_path"] == HEALTH:
                scope = {**scope, "path": READINESS, "raw_path": READINESS.encode()}
        await application(scope, receive, send)

    return boundary


def _paths(routes: Iterable[Any]) -> set[str]:
    """Every path this application serves, following the routers it includes.

    `include_router` records one entry holding the router it was given rather than that
    router's own routes, so a set comprehension over `app.routes` misses every path that
    arrived through a router, the two this asks about included.
    `tests/test_route_authority.py` walks the same shape for the same reason.
    """
    found: set[str] = set()
    for route in routes:
        included = getattr(route, "original_router", None)
        found |= _paths(included.routes) if included is not None else {getattr(route, "path", "")}
    return found


async def _answered(application: ASGIApp, scope: Scope, receive: Receive, send: Send) -> None:
    """One pre hook, with whatever the application answered turned into a hook answer.

    The answer is collected rather than streamed because it has to be read before it can be
    classified, and because the two things this route sends — a hook result and one of the
    application's own short refusals — are both small.

    An exception that escapes the application is answered rather than re-raised, and so is
    a request it answered nothing at all for. Neither is reachable through the application
    as it is layered — `response_headers` is the outermost middleware and catches around
    `call_next`, answering its own 503, and the registered handlers answer the rest — so
    this is a last resort rather than a covered path, and the test that pins it drives this
    function directly and says so. What it decides is what the platform is told, and an
    error told to the platform is the one thing this route exists to avoid.
    """
    status = 0
    headers: list[tuple[bytes, bytes]] = []
    body = bytearray()

    async def collect(message: Message) -> None:
        nonlocal status, headers
        if message["type"] == "http.response.start":
            status = int(message["status"])
            headers = [(bytes(name), bytes(value)) for name, value in message["headers"]]
        elif message["type"] == "http.response.body":
            body.extend(bytes(message.get("body", b"")))

    try:
        await application(scope, receive, collect)
    except Exception:  # nosec B110 - the swallow is the point, and the docstring above says why
        # An exception answered rather than re-raised: what reaches here has already escaped
        # `response_headers`, which is outermost and answers its own 503, so the application
        # has had its chance to log it. Re-raising would send the platform an error, which is
        # the one thing this route exists to avoid.
        pass
    if status in PASSED:
        await send({"type": "http.response.start", "status": status, "headers": headers})
        await send({"type": "http.response.body", "body": bytes(body)})
        return
    refusal = HookResult("RATE_LIMIT_EXCEEDED") if status == 429 else HookResult("CHECK_FAILED")
    answer = json.dumps(refusal.body()).encode()
    kept = [(name, value) for name, value in headers if name.lower() not in REPLACED]
    kept.extend(ANSWER_HEADERS)
    kept.append((b"content-length", str(len(answer)).encode()))
    await send({"type": "http.response.start", "status": 200, "headers": kept})
    await send({"type": "http.response.body", "body": answer})
