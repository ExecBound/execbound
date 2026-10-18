# SPDX-License-Identifier: AGPL-3.0-only
"""`/api/console/v1/monitor/sources`: reporting sources from the console (#678).

A reporting source lets one Tines story send events about itself to the intake
(`/v1/monitor/events`). `POST /monitor/sources` registers the story in the session's space and
answers its token once; `GET /monitor/sources/{source_id}` reads a source as the Connections
view shows it, never its token; `/rotate` mints a replacement token and keeps the previous one
for a grace of up to an hour; `/revoke` stops every token the source ever had at once.

A token authorizes intake for its one story and nothing else: it cannot run an action, decide
an approval or read anything back. It lives 1, 7 or 30 days. The two answers that carry one are
`Cache-Control: no-store`, set here on the route's own response so the header holds whatever the
console's default becomes, and the token is in no other answer. Minting and rotation are served
only where the deployment has configured console connect (`scout.collector`): console minting is
not live on a deployment until console connect is. Reading and revoking a source are served
everywhere, because they issue nothing and a source minted earlier must always be revocable.

Every route is an administrator's, behind the session, the exact Origin and CSRF. Minting,
rotating and revoking ask for a recently verified factor and refuse a personal access token
(`guards.STEP_UP_PREFIXES`, `token_rules`): minting and rotating issue an intake credential, and
revoking silences what a story reports. A label or story ID that reads as a secret is refused by
field and never repeated. Source lifecycle stays on the source's own row (`created_by`,
`rotated_by`, `revoked_by`) and off the execution audit chain.
"""

from datetime import datetime, timedelta
from typing import Any, Literal
from uuid import UUID

from fastapi import APIRouter, Request, Response
from pydantic import BaseModel, ConfigDict, Field, field_validator
from starlette.concurrency import run_in_threadpool

from execbound.monitoring import store as monitor_store
from execbound.monitoring.models import MonitorError
from execbound.runtime import Runtime
from execbound.secrets import secret_shaped
from execbound.surfaces.console_api.bodies import body
from execbound.surfaces.console_api.errors import ApiError
from execbound.surfaces.console_api.guards import ApiGuards
from execbound.surfaces.console_api.monitoring import MonitorSource, coverage_word
from execbound.surfaces.console_api.monitoring import _identifier as identifier
from execbound.surfaces.human import HumanConfig
from execbound.surfaces.sessions import Session

# The path a Tines story posts its events to, under the deployment's configured origin.
INTAKE_PATH = "/v1/monitor/events"
STORY = r"^[A-Za-z0-9._:-]{1,96}$"


def _number(value: Any) -> Any:
    """JSON's `true` is not the number 1, though a literal 1 would take it."""
    if isinstance(value, bool):
        raise ValueError("a number is required")
    return value


class CreateSource(BaseModel):
    """One Tines story to report: a name for it, the story's ID, how long its token lives and
    how often it sends a heartbeat."""

    model_config = ConfigDict(extra="forbid")

    label: str = Field(min_length=1, max_length=96)
    story_id: str = Field(min_length=1, max_length=96, pattern=STORY)
    lifetime_days: Literal[1, 7, 30]
    # Every 5, 15 or 60 minutes (#678). The health pass calls a source that never reported
    # silent twice its interval after registration, so a minute would raise that finding before
    # most stories are built. A source registered every minute before keeps its interval.
    heartbeat_seconds: Literal[300, 900, 3600]

    _numbers = field_validator("lifetime_days", "heartbeat_seconds", mode="before")(_number)


class RotateSource(BaseModel):
    """How long the replacement token lives, and how many minutes the previous one keeps
    reporting (none, 10, 30 or 60, and never past its own expiry)."""

    model_config = ConfigDict(extra="forbid")

    lifetime_days: Literal[1, 7, 30]
    grace_minutes: Literal[0, 10, 30, 60]

    _numbers = field_validator("lifetime_days", "grace_minutes", mode="before")(_number)


class SourceChange(BaseModel):
    """No fields: the address names the source and the change."""

    model_config = ConfigDict(extra="forbid")


class MintedSource(BaseModel):
    """A source's token, shown once: the console holds it in one dialog and nowhere else. The
    intake address is the deployment's configured origin, never the request's."""

    source_id: UUID
    story_id: str
    label: str
    token: str
    expires_at: datetime
    heartbeat_seconds: int
    # After a rotation, when the previous token stops reporting; null without a grace.
    previous_valid_until: datetime | None
    intake_url: str


_CODES = {
    "SOURCE_CAPACITY": "SOURCE_CAPACITY",
    "SOURCE_EXISTS": "SOURCE_EXISTS",
    "SPACE_REQUIRED": "SPACE_REQUIRED",
    "INVALID_SPACE": "SPACE_REQUIRED",
    "SPACE_ARCHIVED": "SPACE_ARCHIVED",
    "INVALID_ADMIN": "FORBIDDEN",
    "SOURCE_UNAVAILABLE": "NOT_FOUND",
    "INVALID_STATE": "CONFLICT",
}


def _refused(exc: MonitorError) -> ApiError:
    if exc.code == "INVALID_INPUT":
        return ApiError("INVALID_BODY", fields=[])
    return ApiError(_CODES.get(exc.code, "UNAVAILABLE"))


def intake_url(config: HumanConfig) -> str:
    """Where a story sends its events: the configured origin, never a `Host` header."""
    return config.origin + INTAKE_PATH


def _person_text(label: str, story_id: str) -> None:
    """A label is printable text with something in it, and neither it nor the story ID reads
    as a secret; each fault is named by its field and its value is never repeated."""
    faults = []
    if not label.strip() or not label.isprintable() or secret_shaped(label):
        faults.append("label")
    if secret_shaped(story_id):
        faults.append("story_id")
    if faults:
        raise ApiError("INVALID_BODY", fields=faults)


def _available(config: HumanConfig) -> None:
    """Minting is served only where console connect is configured."""
    if config.scout is None or config.scout.collector is None:
        raise ApiError("CONNECT_UNAVAILABLE")


def _source(row: dict[str, Any], now: datetime) -> MonitorSource:
    return MonitorSource(
        **{key: row[key] for key in MonitorSource.model_fields if key != "coverage"},
        coverage=coverage_word(row, now),
    )


def _read(runtime: Runtime, session: Session, source_id: UUID) -> MonitorSource:
    row = monitor_store.source(runtime.db, session, source_id, clock=runtime.clock)
    return _source(row, runtime.clock.now())


def monitoring_sources_routes(
    routes: APIRouter, runtime: Runtime, config: HumanConfig, guards: ApiGuards
) -> None:
    @routes.post(
        "/monitor/sources",
        response_model=MintedSource,
        status_code=201,
        operation_id="createMonitorSource",
        openapi_extra=body(CreateSource),
    )
    async def create_source(request: Request, response: Response) -> MintedSource:
        current, values = await guards.mutation(request, CreateSource, kind="ADMIN")
        _available(config)
        _person_text(values.label, values.story_id)

        def mint() -> MintedSource:
            expires_at = runtime.clock.now() + timedelta(days=values.lifetime_days)
            grant = monitor_store.create_source(
                runtime.db,
                current.identity,
                label=values.label,
                story_id=values.story_id,
                expires_at=expires_at,
                heartbeat_seconds=values.heartbeat_seconds,
                clock=runtime.clock,
                session=current,
            )
            return MintedSource(
                source_id=grant.source_id,
                story_id=values.story_id,
                label=values.label,
                token=grant.token,
                expires_at=expires_at,
                heartbeat_seconds=values.heartbeat_seconds,
                previous_valid_until=None,
                intake_url=intake_url(config),
            )

        try:
            minted = await run_in_threadpool(mint)
        except MonitorError as exc:
            raise _refused(exc) from None
        response.headers["Cache-Control"] = "no-store"
        return minted

    @routes.get(
        "/monitor/sources/{source_id}",
        response_model=MonitorSource,
        operation_id="readMonitorSource",
    )
    async def read_source(request: Request, source_id: str) -> MonitorSource:
        current, _ = await guards.session(request, kind="ADMIN")
        target = identifier(source_id)
        try:
            return await run_in_threadpool(_read, runtime, current, target)
        except MonitorError as exc:
            raise _refused(exc) from None

    @routes.post(
        "/monitor/sources/{source_id}/rotate",
        response_model=MintedSource,
        operation_id="rotateMonitorSource",
        openapi_extra=body(RotateSource),
    )
    async def rotate_source(request: Request, response: Response, source_id: str) -> MintedSource:
        current, values = await guards.mutation(request, RotateSource, kind="ADMIN")
        _available(config)
        target = identifier(source_id)

        def rotate() -> MintedSource:
            # What the answer names besides the token cannot change (the runtime updates none
            # of it), so it is read first: nothing after the rotation commits can lose the
            # token it minted.
            row = monitor_store.source(runtime.db, current, target, clock=runtime.clock)
            expires_at = runtime.clock.now() + timedelta(days=values.lifetime_days)
            grant = monitor_store.rotate_source(
                runtime.db,
                current.identity,
                target,
                expires_at=expires_at,
                grace_seconds=values.grace_minutes * 60,
                clock=runtime.clock,
                session=current,
            )
            return MintedSource(
                source_id=target,
                story_id=row["story_id"],
                label=row["label"],
                token=grant.token,
                expires_at=expires_at,
                heartbeat_seconds=row["heartbeat_seconds"],
                previous_valid_until=grant.previous_valid_until,
                intake_url=intake_url(config),
            )

        try:
            minted = await run_in_threadpool(rotate)
        except MonitorError as exc:
            raise _refused(exc) from None
        response.headers["Cache-Control"] = "no-store"
        return minted

    @routes.post(
        "/monitor/sources/{source_id}/revoke",
        response_model=MonitorSource,
        operation_id="revokeMonitorSource",
        openapi_extra=body(SourceChange),
    )
    async def revoke_source(request: Request, source_id: str) -> MonitorSource:
        current, _ = await guards.mutation(request, SourceChange, kind="ADMIN")
        target = identifier(source_id)

        def revoke() -> MonitorSource:
            # Answered from the revoking transaction itself: a read after the commit that
            # failed would say a revocation that took effect had not.
            row = monitor_store.revoke_source(
                runtime.db, current.identity, target, clock=runtime.clock, session=current
            )
            return _source(row, runtime.clock.now())

        try:
            return await run_in_threadpool(revoke)
        except MonitorError as exc:
            raise _refused(exc) from None
