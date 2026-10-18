# SPDX-License-Identifier: AGPL-3.0-only
"""`POST /v1/signals`: bounded exactly as `/v1/monitor/events`, with its own 8 KiB body limit."""

import anyio
from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import JSONResponse
from starlette.concurrency import run_in_threadpool

from execbound.db import Database
from execbound.identity import AuthenticationFailed, record_failure
from execbound.logging_schema import log_event
from execbound.signals.envelope import MAX_ENVELOPE_BYTES, EnvelopeError, parse_signal
from execbound.signals.intake import SignalError, admit_signal

JSON_TYPES = {"application/json", "application/json; charset=utf-8"}
# Envelopes read at once, beyond which a request is refused immediately rather than queued.
INTAKE_SLOTS = 8
# How long a body may take to arrive in full.
BODY_DEADLINE_SECONDS = 5


def signal_router(db: Database) -> APIRouter:
    routes = APIRouter()
    intake_slots = anyio.CapacityLimiter(INTAKE_SLOTS)

    @routes.post("/v1/signals")
    async def intake(request: Request) -> JSONResponse:
        auth = request.headers.getlist("authorization")
        content_types = request.headers.getlist("content-type")
        if (
            request.query_params
            or any(name in request.headers for name in ("x-tenant-id", "x-principal-id", "x-role"))
            or "content-encoding" in request.headers
            or len(content_types) != 1
            or content_types[0].lower() not in JSON_TYPES
        ):
            raise HTTPException(400, "Invalid signal request")
        if len(auth) != 1 or not auth[0].startswith("Bearer ") or len(auth[0]) > 170:
            if auth:
                await run_in_threadpool(record_failure, db, "signal", AuthenticationFailed())
            raise HTTPException(401, "Producer credential required")
        try:
            intake_slots.acquire_nowait()
        except anyio.WouldBlock:
            raise HTTPException(429, "Signal intake busy") from None
        try:
            raw = bytearray()
            try:
                with anyio.fail_after(BODY_DEADLINE_SECONDS):
                    async for part in request.stream():
                        if len(raw) + len(part) > MAX_ENVELOPE_BYTES:
                            raise ValueError
                        raw.extend(part)
            except (ValueError, TimeoutError):
                raise HTTPException(400, "Invalid signal request") from None
            try:
                # A body that is not an envelope and one the secret screen refuses are both
                # `INVALID_ENVELOPE`, and both are logged here alike, naming no source.
                try:
                    signal = parse_signal(bytes(raw))
                except EnvelopeError:
                    raise SignalError("INVALID_ENVELOPE") from None
                result = await run_in_threadpool(admit_signal, db, auth[0][7:], signal)
            except SignalError as error:
                if error.failure is not None:
                    await run_in_threadpool(record_failure, db, "signal", error.failure)
                log_event(
                    "signal.refused", level="WARNING", code=error.code, source_id=error.source_id
                )
                raise
            status = 200 if result["duplicate"] else 202
            log_event("signal.intake", status=status, source_id=result["source_id"])
            return JSONResponse(result, status_code=status)
        finally:
            intake_slots.release()

    return routes
