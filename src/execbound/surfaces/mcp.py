# SPDX-License-Identifier: AGPL-3.0-only
"""Stateless official MCP transport; caller metadata never establishes identity."""

import json
from typing import Any
from urllib.parse import urlsplit
from uuid import UUID

from fastapi import HTTPException
from mcp import types
from mcp.server import Server, ServerRequestContext
from mcp.server.transport_security import TransportSecuritySettings
from starlette.concurrency import run_in_threadpool
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from execbound.audit import canonical_json
from execbound.execution.models import ExecutionError
from execbound.identity import Identity
from execbound.logging_schema import log_event
from execbound.requests import ActionRequest, StrictModel, _reject_number, _unique_object
from execbound.runtime import Runtime
from execbound.surfaces.http import checked_request, read_body
from execbound.surfaces.limits import RateLimited

MAX_MCP_BYTES = 24576


class _ExecuteArguments(StrictModel):
    request: ActionRequest


# Generate the whole wrapper so all local JSON Schema references resolve at
# the tool schema root, including in clients that validate before calling.
EXECUTE_SCHEMA = _ExecuteArguments.model_json_schema()

# The advertised tools, built once here rather than inside the handler so that what a
# client is told and what a test reads are the same objects. The `execute` description
# names both things an answer to it can be mistaken for: a pending approval is a decision
# nobody has made yet, and a checkpoint grant is an answer for an externally executed
# operation, where ExecBound reserved the budget and took the target claim and then
# dispatched nothing at all (docs/CHECKPOINT.md). It also says where action names come from,
# since the schema lists none, and that a denial's reason is kept for a person: the agent is
# told the state and the request's reference and never the cause (THREAT_MODEL.md T1.16), so
# it is told to relay the reference rather than guess. `list_actions` lists what the agent's
# own space offers, never a target (T1.17).
TOOLS = (
    types.Tool(
        name="execute",
        description=(
            "Submit one protected action. Pass reference: the ticket, case or run id this "
            "action responds to; the gateway derives the idempotency key from it. To "
            "progress the same action after a human decision, re-send the identical "
            "request; never change the reference or the key for the same intent. A "
            "pending approval is not execution, and a checkpoint grant is neither an "
            "execution nor an approval: ExecBound dispatched nothing and the executor "
            "must report the outcome. Call list_actions for the operation_ref values your "
            "space offers and their arguments. A denial's reason is kept for a person: on "
            "DENIED, stop and give the person the request_ref, such as EB-12, rather than "
            "guessing why."
        ),
        input_schema=EXECUTE_SCHEMA,
    ),
    types.Tool(
        name="execution_status",
        description="Read your own execution status.",
        input_schema={
            "type": "object",
            "properties": {
                "execution_id": {"type": "string", "format": "uuid"},
                "continuation": {"type": "string", "maxLength": 4096},
            },
            "required": ["execution_id"],
            "additionalProperties": False,
        },
    ),
    types.Tool(
        name="list_actions",
        description=(
            "List the actions your space offers: each operation_ref, its arguments and the "
            "target kinds it accepts. A listed action is not permission: every request is "
            "still decided. Targets are never listed."
        ),
        input_schema={"type": "object", "properties": {}, "additionalProperties": False},
    ),
)


def validate_envelope(raw: bytes) -> dict[str, Any]:
    """Run on original bytes: the SDK may discard unknown/duplicate fields."""
    try:
        if not 0 < len(raw) <= MAX_MCP_BYTES:
            raise ValueError
        body = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=_unique_object,
            parse_float=_reject_number,
            parse_constant=_reject_number,
        )
        if (
            not isinstance(body, dict)
            or set(body) - {"jsonrpc", "id", "method", "params"}
            or body.get("jsonrpc") != "2.0"
            or not isinstance(body.get("method"), str)
            or ("id" in body and (type(body["id"]) not in {int, str} or len(str(body["id"])) > 128))
        ):
            raise ValueError
        params = body.get("params", {})
        if not isinstance(params, dict):
            raise ValueError
        # This service does not implement protocol-driven human decisions.
        if set(params) & {"inputResponses", "requestState", "task"}:
            raise ValueError
        if body["method"] == "tools/call":
            if set(params) - {"name", "arguments", "_meta"}:
                raise ValueError
            # `arguments` is optional (a tool that takes none may be called without it, as
            # the SDK's own client does), and an object whenever it is sent.
            if not isinstance(params.get("name"), str) or (
                "arguments" in params and not isinstance(params["arguments"], dict)
            ):
                raise ValueError
        if body["method"] == "tools/list" and set(params) - {"cursor", "_meta"}:
            raise ValueError
        return body
    except (ValueError, RecursionError):
        pass
    raise ExecutionError("INVALID_REQUEST")


class RawAuthenticatedGate:
    def __init__(self, app: ASGIApp, runtime: Runtime) -> None:
        self.app, self.runtime = app, runtime

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        request = Request(scope, receive)
        identity = None
        try:
            identity = await checked_request(request, self.runtime, "mcp")
            scope["execbound.identity"] = identity
            if request.method == "POST":
                raw = await read_body(request, MAX_MCP_BYTES)
                validate_envelope(raw)
                sent = False

                async def replay() -> Message:
                    nonlocal sent
                    if not sent:
                        sent = True
                        return {"type": "http.request", "body": raw, "more_body": False}
                    return await receive()

                await self.app(scope, replay, send)
            else:
                if (
                    request.headers.get("content-length", "0") != "0"
                    or "transfer-encoding" in request.headers
                ):
                    raise ExecutionError("INVALID_REQUEST")
                await self.app(scope, receive, send)
        except HTTPException as exc:
            await JSONResponse(
                {"detail": exc.detail}, status_code=exc.status_code, headers=exc.headers
            )(scope, receive, send)
        except ExecutionError as exc:
            if isinstance(exc, RateLimited):
                await JSONResponse(
                    {"detail": "Execution unavailable", "code": exc.code},
                    status_code=429,
                    headers={"Retry-After": str(exc.retry_after)},
                )(scope, receive, send)
                return
            if identity is not None:
                await run_in_threadpool(self.runtime.reject, identity)
            await JSONResponse({"detail": "Invalid request"}, status_code=400)(scope, receive, send)


def _short(value: object) -> str | None:
    """A caller-chosen identifier for the log: a string, cut to 80 characters, or nothing."""
    return value[:80] if isinstance(value, str) and value else None


def _client_identity(ctx: ServerRequestContext) -> tuple[str | None, str | None]:
    """The client's self-reported name and version, where the SDK exposes them: the
    initialize parameters on the older revision, the per-request client metadata on the
    newer one. Identifiers only; they establish nothing."""
    params = getattr(ctx.session, "client_params", None)
    info = getattr(params, "client_info", None)
    return _short(getattr(info, "name", None)), _short(getattr(info, "version", None))


def create_mcp(runtime: Runtime, origin: str | None = None) -> tuple[Server, ASGIApp]:
    def current(ctx: ServerRequestContext) -> Identity:
        if not isinstance(ctx.request, Request):
            raise ExecutionError("INVALID_IDENTITY")
        identity = ctx.request.scope.get("execbound.identity")
        if not isinstance(identity, Identity) or identity.kind != "AGENT":
            raise ExecutionError("INVALID_IDENTITY")
        return identity

    def record_call(ctx: ServerRequestContext, tool: str) -> None:
        """One identifier-only record per tool call, so a trial can cite what the server
        talked to: the tool, the protocol revision the request carried, and the client's
        name and version. Never arguments, never results."""
        name, version = _client_identity(ctx)
        log_event(
            "mcp.call",
            tool=_short(tool),
            protocol_version=_short(getattr(ctx, "protocol_version", None)),
            client_name=name,
            client_version=version,
        )

    async def list_tools(
        ctx: ServerRequestContext, params: types.PaginatedRequestParams | None
    ) -> types.ListToolsResult:
        current(ctx)
        return types.ListToolsResult(tools=list(TOOLS))

    async def call_tool(
        ctx: ServerRequestContext, params: types.CallToolRequestParams
    ) -> types.CallToolResult:
        identity = current(ctx)
        record_call(ctx, params.name)
        failed = False
        try:
            # Absent arguments are none at all; `execute` and `execution_status` still refuse
            # an empty set by their exact key checks.
            args = {} if params.arguments is None else params.arguments
            if not isinstance(args, dict):
                raise ExecutionError("INVALID_REQUEST")
            payload: dict[str, Any]
            if params.name == "execute" and set(args) == {"request"}:
                view = await run_in_threadpool(
                    runtime.execute, identity, canonical_json(args["request"]).encode()
                )
                payload = await run_in_threadpool(runtime.present, identity, view)
            elif (
                params.name == "execution_status"
                and "execution_id" in args
                and not set(args) - {"execution_id", "continuation"}
            ):
                value = args["execution_id"]
                if not isinstance(value, str) or str(UUID(value)) != value:
                    raise ExecutionError("INVALID_REQUEST")
                continuation = args.get("continuation")
                if continuation is not None and not isinstance(continuation, str):
                    raise ExecutionError("INVALID_REQUEST")
                view = await run_in_threadpool(runtime.status, identity, UUID(value), continuation)
                payload = await run_in_threadpool(runtime.present, identity, view)
            elif params.name == "list_actions" and args == {}:
                listed = await run_in_threadpool(runtime.list_actions, identity)
                payload = listed.model_dump(mode="json", exclude_none=True)
            else:
                raise ExecutionError("INVALID_REQUEST")
        except (ExecutionError, ValueError) as exc:
            code = exc.code if isinstance(exc, ExecutionError) else "INVALID_REQUEST"
            await run_in_threadpool(runtime.reject, identity, code)
            payload, failed = {"detail": "Execution unavailable", "code": code}, True
        except Exception:
            # Older SDK dispatchers serialize unexpected exception messages.
            # Keep diagnostics private and leave committed uncertainty intact.
            payload = {"detail": "Execution unavailable", "code": "EXECUTION_UNAVAILABLE"}
            failed = True
        return types.CallToolResult(
            content=[types.TextContent(type="text", text=canonical_json(payload))],
            structured_content=payload,
            is_error=failed,
        )

    server = Server("ExecBound", on_list_tools=list_tools, on_call_tool=call_tool)
    mounted = server.streamable_http_app(
        streamable_http_path="/",
        stateless_http=True,
        json_response=True,
        max_request_body_size=MAX_MCP_BYTES,
        transport_security=TransportSecuritySettings(
            enable_dns_rebinding_protection=True,
            allowed_hosts=[urlsplit(origin).netloc],
            allowed_origins=[origin],
        )
        if origin
        else None,
    )
    return server, RawAuthenticatedGate(mounted, runtime)
