# SPDX-License-Identifier: AGPL-3.0-only
"""The request guards of the console API, built on the ones every page shares.

A console API route has exactly the authority a page has
(#333): the session cookie says who is
asking. `session()` is the pages' own `session_for`: the query allowlist, the bearer refusal
that is audited as `INVALID_IDENTITY`, the Host pin, the identity-header refusal, the exact
Origin check on a POST, the cookie session with its renewal, and the CSRF cookie.
`mutation()` adds what a JSON body needs instead of a form: the `X-CSRF-Token` header equal
to the session's token, `application/json` and nothing else, a bounded body read once, no
duplicate keys, and a strict model that refuses an unknown field. Every mutation is a POST,
so the Origin rule stays the one line the pages have. A route that is one role's names it
(`kind="ADMIN"`), and anyone else is refused before the body is read.

The one other way in is an administrator's personal access token, `Authorization: Bearer
ebp1.…`. It keeps the query allowlist, the Host pin, the identity-header refusal and every body
rule, is refused beside a session cookie, is rate-limited per token, and reaches only a route
`token_rules` allows; a refusal there is `TOKEN_NOT_ALLOWED`, audited. The Origin check, CSRF,
the workspace generation and the step-up do not apply: they defend a cookie a browser sends on
its own and a session that can switch workspace, and a token is neither. Any other bearer
credential still meets the pages' refusal above. A token keeps no current space, so a request
may name one in `X-ExecBound-Space`; `visible_spaces` holds it to the owner's membership, and a
cookie request never reads the header.
"""

import hmac
import json
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, replace
from typing import Any, TypeVar
from uuid import UUID

import anyio
from fastapi import HTTPException, Request
from pydantic import BaseModel, ValidationError
from sqlalchemy.exc import SQLAlchemyError
from starlette.concurrency import run_in_threadpool

from execbound.db import UnsafeDatabaseRole
from execbound.identity import record_failure
from execbound.personal_tokens import TOKEN_PREFIX, TokenRefused, TokenSession, load_token_session
from execbound.runtime import Runtime
from execbound.spaces import SpaceError, visible_spaces
from execbound.surfaces.console_api.errors import ApiError
from execbound.surfaces.console_api.token_rules import token_allowed
from execbound.surfaces.http import client_key
from execbound.surfaces.human import HumanConfig, request_guards
from execbound.surfaces.sessions import Session

Model = TypeVar("Model", bound=BaseModel)
BODY_BYTES = 65536
# The session mutations that change who can act, who approves, or how they sign in, which ask
# for a factor verified within `mfa.STEP_UP_WINDOW` (THREAT_MODEL.md T4.48). Each prefix has
# to match a route: one that matches none steps nothing up and fails no request, which is how
# the directory's routes, `/tenant/sign-in`, went unguarded under a `/sign-in/` prefix.
# `tests/test_console_api_step_up.py` holds every prefix to a route core serves, except
# `/invitations`, the hosted plugin's sandbox pool, which that plugin's own tests hold.
# Activating a policy, the samples routes that install and activate the starter, and changing
# the enforcement mode ask too (#678, 8 October 2026). The mode route asks in both
# directions, because the sets are path-based and checked before the body is read; the
# emergency stop (`/tenant/stop`) stays outside them as the immediate tightening control.
STEP_UP_PREFIXES = (
    "/api/console/v1/access/",
    "/api/console/v1/people/",
    "/api/console/v1/credentials",
    "/api/console/v1/invitations",
    "/api/console/v1/teammate-invitations",
    "/api/console/v1/tenant/sign-in",
    "/api/console/v1/tenant/mode",
    "/api/console/v1/settings/password",
    "/api/console/v1/settings/tokens",
    "/api/console/v1/account/requests",
    "/api/console/v1/approval-rules",
    "/api/console/v1/approvers/",
    # Connecting Tines creates a connection holding a credential, and a Microsoft Entra
    # consent one reading a whole directory (#678).
    "/api/console/v1/monitor/connections/tines",
    "/api/console/v1/monitor/connections/entra/",
    # Minting and rotating a reporting source issue an intake credential, and revoking one
    # silences what its story reports (#678). Reading one is not a change.
    "/api/console/v1/monitor/sources",
)
# The same for a change nested under a resource whose other changes do not ask: an agent's
# credentials, a space's membership (renaming or archiving a space does not ask), a policy's
# activation (creating, validating, previewing, retiring or editing one does not), and a
# monitoring connection's key and its revocation, which silences what it watches (asking for
# a collection or changing its schedule does not ask).
STEP_UP_NESTED = (
    ("/api/console/v1/agents/", "/credentials/"),
    ("/api/console/v1/spaces/", "/members/"),
    ("/api/console/v1/policy/", "/activate"),
    ("/api/console/v1/monitor/connections/", "/key"),
    ("/api/console/v1/monitor/connections/", "/revoke"),
)
# Exact paths, where a prefix would catch too much: installing and refreshing the samples
# activate the starter policy, but a `/samples` prefix would also catch `/samples/remove`,
# which only tightens.
STEP_UP_EXACT = ("/api/console/v1/samples", "/api/console/v1/samples/refresh")


def steps_up(path: str) -> bool:
    """Whether a session mutation at `path` asks for a recently verified factor."""
    return (
        path in STEP_UP_EXACT
        or path.startswith(STEP_UP_PREFIXES)
        or any(path.startswith(prefix) and part in path for prefix, part in STEP_UP_NESTED)
    )


@dataclass(frozen=True)
class ApiGuards:
    session: Callable[..., Awaitable[tuple[Session, str]]]
    mutation: Callable[..., Awaitable[tuple[Session, Any]]]


def _pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate key")
        result[key] = value
    return result


def _media_type(request: Request) -> str:
    values = request.headers.getlist("content-type")
    if len(values) != 1:
        return ""
    return values[0].split(";", 1)[0].strip().lower()


def _of_kind(session: Session, kind: str | None) -> None:
    """The role check a page makes first in its handler (`admin(session)`), as a refusal."""
    if kind is not None and session.identity.kind != kind:
        raise ApiError("FORBIDDEN")


def _bearer_token(request: Request) -> str | None:
    """A personal access token, if the one Authorization header carries one."""
    values = request.headers.getlist("authorization")
    if len(values) != 1:
        return None
    scheme, _, value = values[0].partition(" ")
    if scheme.lower() == "bearer" and value.startswith(TOKEN_PREFIX + "."):
        return value
    return None


def _space_header(request: Request) -> UUID | None:
    """The space a bearer request names in `X-ExecBound-Space`, once, in its canonical
    spelling, as every identifier in a console API path is; anything else is refused."""
    values = request.headers.getlist("x-execbound-space")
    if not values:
        return None
    try:
        if len(values) != 1:
            raise ValueError
        space = UUID(values[0])
        if str(space) != values[0]:
            raise ValueError
    except ValueError:
        raise HTTPException(400, "Invalid request") from None
    return space


def api_guards(runtime: Runtime, config: HumanConfig) -> ApiGuards:
    pages = request_guards(runtime, config)

    def generation(request: Request, current: Session, *, mutation: bool = False) -> None:
        selected = str(current.session_id)
        request.state.workspace_generation = selected
        header = request.headers.getlist("x-execbound-workspace")
        if (
            header
            and header != [selected]
            or (mutation and current.account_id is not None and not header)
        ):
            raise ApiError("WORKSPACE_CHANGED")

    def space_visible(current: TokenSession) -> None:
        with runtime.db.transaction(current.identity.tenant_id) as conn:
            visible_spaces(conn, current)

    async def token_session(
        request: Request, token: str, query: frozenset[str], kind: str | None
    ) -> TokenSession:
        await pages.token_boundary(request, query)
        space = _space_header(request)
        runtime.limiter.refuse("client", client_key(request))
        try:
            current = await run_in_threadpool(
                load_token_session, runtime.db, token, clock=runtime.clock
            )
        except TokenRefused as refused:
            # Every failure class records through this one path before the unchanged answer,
            # as `identity_for` records an `eb1` credential's; the answer is the same 401 for
            # every class, so it says nothing about whether a token exists.
            await run_in_threadpool(
                record_failure, runtime.db, "token", refused.failure, runtime.clock.now()
            )
            raise ApiError("SESSION_REQUIRED", headers={"WWW-Authenticate": "Bearer"}) from None
        runtime.limiter.refuse("token", str(current.token_id))
        # The route's full template, `/api/console/v1/agents/{row_id}`: the router carries the
        # prefix, so this is the key `token_rules` is written in, and a loaded plugin's own
        # classification of its routes (#496). No route, no authority.
        route = request.scope.get("route")
        if route is None or not token_allowed(route.path, request.method, runtime.plugins):
            await run_in_threadpool(
                lambda: runtime.reject(
                    current.identity,
                    "TOKEN_NOT_ALLOWED",
                    actor_credential=True,
                    route=getattr(route, "path", None),
                    method=request.method,
                )
            )
            raise ApiError("TOKEN_NOT_ALLOWED")
        if space is not None:
            current = replace(current, space_id=space)
            # Checked here too, so a read and a write answer one typed refusal for a space
            # that is not the owner's; `visible_spaces` rechecks it inside every transaction.
            try:
                await run_in_threadpool(space_visible, current)
            except SpaceError:
                raise ApiError("SPACE_REQUIRED") from None
            except (SQLAlchemyError, UnsafeDatabaseRole):
                raise ApiError("UNAVAILABLE") from None
        _of_kind(current, kind)
        return current

    async def session(
        request: Request, query: frozenset[str] = frozenset(), kind: str | None = None
    ) -> tuple[Session, str]:
        token = _bearer_token(request)
        if token is not None:
            return await token_session(request, token, query, kind), ""
        current, csrf = await pages.session_for(request, query)
        generation(request, current)
        _of_kind(current, kind)
        return current, csrf

    async def mutation(
        request: Request, model: type[Model], max_bytes: int = BODY_BYTES, kind: str | None = None
    ) -> tuple[Session, Model]:
        token = _bearer_token(request)
        current: Session
        if token is not None:
            # No CSRF, no workspace generation and no step-up: a token is bound to one
            # workspace, carries no cookie, and was created behind a verified factor.
            current = await token_session(request, token, frozenset(), kind)
        else:
            current, csrf = await pages.session_for(request)
            generation(request, current, mutation=True)
            _of_kind(current, kind)
            header = request.headers.getlist("x-csrf-token")
            if len(header) != 1 or not hmac.compare_digest(header[0].encode(), csrf.encode()):
                await run_in_threadpool(runtime.reject, current.identity, "INVALID_CSRF")
                raise ApiError("INVALID_CSRF")
            if steps_up(request.url.path):
                from execbound.mfa import MfaError, require_recent_factor

                try:
                    await run_in_threadpool(
                        require_recent_factor, runtime.db, current, clock=runtime.clock
                    )
                except MfaError as exc:
                    raise ApiError(
                        "MFA_REQUIRED" if exc.code == "RECENT_AUTH_REQUIRED" else "UNAVAILABLE"
                    ) from None
        if _media_type(request) != "application/json":
            raise ApiError("UNSUPPORTED_MEDIA_TYPE")
        raw = bytearray()
        try:
            with anyio.fail_after(5):
                async for part in request.stream():
                    raw.extend(part)
                    if len(raw) > max_bytes:
                        raise ApiError("TOO_LARGE")
        except TimeoutError:
            raise ApiError("INVALID_REQUEST") from None
        try:
            data = json.loads(raw.decode("utf-8"), object_pairs_hook=_pairs)
        except ValueError:
            raise ApiError("INVALID_BODY") from None
        if not isinstance(data, dict):
            raise ApiError("INVALID_BODY")
        try:
            parsed = model.model_validate(data, strict=True)
        except ValidationError as error:
            locations = sorted(
                {".".join(str(part) for part in item["loc"]) for item in error.errors()}
            )
            raise ApiError("INVALID_BODY", fields=locations[:8]) from None
        return current, parsed

    return ApiGuards(session=session, mutation=mutation)


def json_body(model: type[BaseModel]) -> dict[str, Any]:
    """The OpenAPI request body of a mutation, for the route decorator's `openapi_extra`.

    `mutation()` reads and validates the JSON itself, so FastAPI sees no body parameter and
    the document would say nothing; this declares the model's schema so the generated client
    types the body. The guard, not this declaration, is what validates a request.
    """
    return {
        "requestBody": {
            "required": True,
            "content": {"application/json": {"schema": model.model_json_schema()}},
        }
    }
