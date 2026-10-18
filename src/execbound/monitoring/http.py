# SPDX-License-Identifier: AGPL-3.0-only
"""Bounded, source-authenticated intake for explicitly instrumented story events."""

import json
from typing import Any
from uuid import UUID

import anyio
from fastapi import APIRouter, HTTPException, Request
from pydantic import ValidationError
from starlette.concurrency import run_in_threadpool
from starlette.responses import JSONResponse

from execbound.db import Database
from execbound.identity import AuthenticationFailed, record_failure
from execbound.logging_schema import log_event
from execbound.monitoring import store
from execbound.monitoring.models import MonitorError, ObservationEvent

MAX_EVENT_BYTES = 16384


def _object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    if len({key for key, _ in pairs}) != len(pairs):
        raise ValueError
    return dict(pairs)


def _constant(value: str) -> Any:
    raise ValueError


def parse_event(raw: bytes) -> ObservationEvent:
    try:
        if len(raw) > MAX_EVENT_BYTES:
            raise ValueError
        value = json.loads(raw, object_pairs_hook=_object, parse_constant=_constant)
        if not isinstance(value, dict):
            raise ValueError
        return ObservationEvent.model_validate_json(raw)
    except (ValueError, ValidationError, RecursionError):
        raise MonitorError("INVALID_EVENT") from None


def monitor_router(db: Database) -> APIRouter:
    routes = APIRouter()
    intake_slots = anyio.CapacityLimiter(8)

    @routes.post("/v1/monitor/events")
    async def intake(request: Request) -> JSONResponse:
        auth = request.headers.getlist("authorization")
        content_types = request.headers.getlist("content-type")
        if (
            request.query_params
            or any(name in request.headers for name in ("x-tenant-id", "x-principal-id", "x-role"))
            or "content-encoding" in request.headers
            or len(content_types) != 1
            or content_types[0].lower()
            not in {"application/json", "application/json; charset=utf-8"}
        ):
            raise HTTPException(400, "Invalid monitoring request")
        if len(auth) != 1 or not auth[0].startswith("Bearer ") or len(auth[0]) > 170:
            if auth:
                await run_in_threadpool(record_failure, db, "monitor", AuthenticationFailed())
            raise HTTPException(401, "Source credential required")
        try:
            intake_slots.acquire_nowait()
        except anyio.WouldBlock:
            raise HTTPException(429, "Monitoring intake busy") from None
        try:
            raw = bytearray()
            try:
                with anyio.fail_after(5):
                    async for part in request.stream():
                        if len(raw) + len(part) > MAX_EVENT_BYTES:
                            raise ValueError
                        raw.extend(part)
            except (ValueError, TimeoutError):
                raise HTTPException(400, "Invalid monitoring request") from None
            event = parse_event(bytes(raw))
            try:
                result = await run_in_threadpool(store.ingest, db, auth[0][7:], event)
            except MonitorError as error:
                if isinstance(error.failure, AuthenticationFailed):
                    await run_in_threadpool(record_failure, db, "monitor", error.failure)
                raise
            status = 200 if result["duplicate"] else 202
            try:
                source_id: UUID | None = store._selectors(auth[0][7:])[1]
            except MonitorError:
                source_id = None
            log_event("monitor.intake", status=status, source_id=source_id)
            return JSONResponse(result, status_code=status)
        finally:
            intake_slots.release()

    return routes
