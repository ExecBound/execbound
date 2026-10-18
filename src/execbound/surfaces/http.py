# SPDX-License-Identifier: AGPL-3.0-only
"""Strict wire handling shared by authenticated HTTP and MCP adapters."""

from collections.abc import Mapping
from types import MappingProxyType
from uuid import UUID

import anyio
from fastapi import APIRouter, HTTPException, Request
from starlette.concurrency import run_in_threadpool
from starlette.responses import JSONResponse

from execbound.execution.models import ExecutionError, ExecutionView
from execbound.identity import AuthenticationFailed, Identity, Surface, authenticate, record_failure
from execbound.requests import MAX_REQUEST_BYTES
from execbound.runtime import Runtime

IDENTITY_HEADERS = ("x-tenant-id", "x-account-id", "x-principal-id", "x-role")


# The status each execution error code is answered with; a code not listed is 503, the
# transient failure a caller may retry. Named, so the published agent API document and
# its error reference are built from the table the gateway answers with.
ERROR_STATUS: Mapping[str, int] = MappingProxyType(
    {
        "INVALID_REQUEST": 400,
        "INVALID_IDENTITY": 403,
        "DEMO_UNAVAILABLE": 409,
        "NOT_FOUND": 404,
        "IDEMPOTENCY_CONFLICT": 409,
        # RESOURCE_BUSY is deliberately absent. A target another execution still holds is
        # recorded as a DENIED transition with that reason and answered with the view, 200,
        # never raised as an error; listing it here published a retryable 409 that no path
        # answers, beside a guide telling the agent never to retry a denial.
        "INVALID_STATE": 409,
        "TENANT_STOPPED": 423,
        # An agent whose space is archived: "this space takes no new work", refused
        # before any dispatch at the emergency stop's own check point and answered in
        # the stop's shape, because it is the same kind of fact about the deployment.
        "SPACE_ARCHIVED": 423,
        "INVALID_CONTINUATION": 400,
        # An outcome report that did not authenticate against the grant's stored digest,
        # one whose evidence did not verify or is not accepted for the grant, and one that
        # arrived after its report window closed. All three are permanent and the caller's
        # own, so none invites the retry a 503 asks for; INVALID_EVIDENCE keeps its meaning
        # for the connector paths, where the same failure is a provider fault.
        "INVALID_REPORT": 403,
        "INVALID_RECORD": 400,
        "REPORT_WINDOW_CLOSED": 409,
        # The tenant's executor key ring cannot be built, so no record can be attested
        # against it. Retrying changes nothing; listing and repairing the ring does.
        "INVALID_KEY_RING": 409,
        # The active bundle cannot authorize this request in the deployment it is running
        # in — a Gate mapping on a connected account, a key ring that could not attest the
        # grant it asks for, an active selection pointing at content that is not ACTIVE.
        # Every such condition holds until an administrator changes the deployment, and
        # every retry appends another rejection to the tenant's chain, so none of them is
        # the transient dependency failure a 503 tells a caller to retry.
        "INVALID_BUNDLE": 409,
        "BUSY": 429,
        "RATE_LIMITED": 429,
    }
)


def error_status(exc: ExecutionError) -> int:
    return ERROR_STATUS.get(exc.code, 503)


def view_response(view: ExecutionView, payload: dict[str, object]) -> JSONResponse:
    status = (
        202 if view.state in {"PENDING_APPROVAL", "DISPATCH_COMMITTED", "INDETERMINATE"} else 200
    )
    return JSONResponse(payload, status_code=status)


def client_key(request: Request) -> str:
    """The direct peer address; behind a reverse proxy every caller shares this key."""
    return request.client.host if request.client else "unknown"


async def identity_for(request: Request, runtime: Runtime, surface: Surface = "http") -> Identity:
    # Limits run before any lookup or parsing, so a refusal consumes nothing.
    runtime.limiter.refuse("client", client_key(request))
    values = request.headers.getlist("authorization")
    if len(values) != 1:
        raise HTTPException(401, "Invalid credentials", headers={"WWW-Authenticate": "Bearer"})
    parts = values[0].split(" ")
    try:
        if len(parts) != 2 or parts[0].lower() != "bearer":
            raise AuthenticationFailed("Invalid credentials")
        identity = await run_in_threadpool(authenticate, runtime.db, parts[1])
    except AuthenticationFailed as failure:
        # Every failure class records through this one path before the unchanged answer.
        await run_in_threadpool(record_failure, runtime.db, surface, failure, runtime.clock.now())
        raise HTTPException(
            401, "Invalid credentials", headers={"WWW-Authenticate": "Bearer"}
        ) from None
    runtime.limiter.refuse("agent", f"{identity.tenant_id}:{identity.credential_id}")
    return identity


async def checked_request(
    request: Request, runtime: Runtime, surface: Surface = "http"
) -> Identity:
    identity = await identity_for(request, runtime, surface)
    if (
        request.query_params
        or any(name in request.headers for name in IDENTITY_HEADERS)
        or "content-encoding" in request.headers
        or len(request.headers.getlist("content-type")) > 1
        or len(request.headers.getlist("content-length")) > 1
    ):
        await run_in_threadpool(runtime.reject, identity)
        raise HTTPException(400, "Invalid request")
    if identity.kind != "AGENT":
        await run_in_threadpool(runtime.reject, identity, "INVALID_IDENTITY")
        raise HTTPException(403, "Forbidden")
    return identity


async def read_body(request: Request, limit: int = MAX_REQUEST_BYTES) -> bytes:
    if request.headers.get("content-type", "").lower() != "application/json":
        raise ExecutionError("INVALID_REQUEST")
    raw = bytearray()
    try:
        with anyio.fail_after(5):
            async for chunk in request.stream():
                raw.extend(chunk)
                if len(raw) > limit:
                    raise ExecutionError("INVALID_REQUEST")
    except (TimeoutError, ValueError):
        raise ExecutionError("INVALID_REQUEST") from None
    return bytes(raw)


def _identifier(execution_id: str) -> UUID:
    """The one canonical spelling of an execution id; every other spelling is refused."""
    identifier = UUID(execution_id)
    if str(identifier) != execution_id:
        raise ValueError
    return identifier


def router(runtime: Runtime) -> APIRouter:
    routes = APIRouter()

    @routes.post("/v1/execute")
    async def execute(request: Request) -> JSONResponse:
        identity = await checked_request(request, runtime)
        try:
            raw = await read_body(request)
        except ExecutionError:
            await run_in_threadpool(runtime.reject, identity)
            raise
        view = await run_in_threadpool(runtime.execute, identity, raw)
        return view_response(view, await run_in_threadpool(runtime.present, identity, view))

    @routes.post("/v1/executions/{execution_id}/outcome")
    async def outcome(request: Request, execution_id: str) -> JSONResponse:
        """An external executor's report on the grant it holds for this execution.

        The same authentication as every other agent route: the report secret in the body
        names which grant is being settled and is no substitute for the credential. The
        act grant the checkpoint carried is not presented here, because the report window
        deliberately outlives the act window; a report is authenticated by the secret the
        execution row retains the digest of, and by nothing else.
        """
        identity = await checked_request(request, runtime)
        try:
            identifier = _identifier(execution_id)
        except ValueError:
            await run_in_threadpool(runtime.reject, identity)
            raise ExecutionError("INVALID_REQUEST") from None
        try:
            raw = await read_body(request)
        except ExecutionError:
            await run_in_threadpool(runtime.reject, identity)
            raise
        view = await run_in_threadpool(runtime.report, identity, identifier, raw)
        return view_response(view, await run_in_threadpool(runtime.present, identity, view))

    @routes.get("/v1/executions/{execution_id}")
    async def status(request: Request, execution_id: str) -> JSONResponse:
        identity = await checked_request(request, runtime)
        try:
            if (
                request.headers.get("content-length", "0") != "0"
                or "transfer-encoding" in request.headers
            ):
                raise ValueError
            identifier = _identifier(execution_id)
        except ValueError:
            await run_in_threadpool(runtime.reject, identity)
            raise ExecutionError("INVALID_REQUEST") from None
        values = request.headers.getlist("x-execution-continuation")
        if len(values) > 1:
            raise ExecutionError("INVALID_REQUEST")
        view = await run_in_threadpool(
            runtime.status, identity, identifier, values[0] if values else None
        )
        return view_response(view, await run_in_threadpool(runtime.present, identity, view))

    @routes.get("/v1/actions")
    async def actions(request: Request) -> JSONResponse:
        """The operations the agent's own space offers; a listed action is not permission."""
        identity = await checked_request(request, runtime)
        if (
            request.headers.get("content-length", "0") != "0"
            or "transfer-encoding" in request.headers
        ):
            await run_in_threadpool(runtime.reject, identity)
            raise ExecutionError("INVALID_REQUEST")
        listed = await run_in_threadpool(runtime.list_actions, identity)
        return JSONResponse(listed.model_dump(mode="json", exclude_none=True))

    return routes
