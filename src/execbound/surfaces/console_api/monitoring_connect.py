# SPDX-License-Identifier: AGPL-3.0-only
"""`/api/console/v1/monitor/connect` and a monitoring connection's actions (#228, #678).

`GET /monitor/connect` says which providers this deployment can connect from the console: Tines
where the runtime configuration's `scout.collector` gives the collector's public key, and
Microsoft Entra where `scout.entra` names the platform app. `POST /monitor/connections/tines`
takes a pasted Tines key once and seals it to that key before it reaches the database
(`monitoring.connect`); the web service can write a key and never read one back.
`POST /monitor/connections/entra/start` begins an admin consent (`monitoring.consent`): it
records the attempt, sets the binding cookie the consent's callbacks require in this browser,
and answers Microsoft's sign-in address, the one answer here that carries a secret, its
`state`. `{connection_id}/key` replaces a sealed connection's key,
`{connection_id}/collect` asks for a collection the next scheduled pass answers,
`{connection_id}/schedule` sets the intervals and `{connection_id}/revoke` stops collection.

Every route is an administrator's, behind the session, the exact Origin and CSRF, and answers
the connection as the Connections view reads it, from the server: nothing is optimistic.
Connecting, replacing a key and revoking ask for a recently verified factor and refuse a
personal access token (`guards.STEP_UP_PREFIXES`, `token_rules`), because they create a
credentialed connection or silence one; asking and scheduling do neither. A malformed body is
refused by field location only, so no value, a key least of all, is ever echoed. Nothing here
calls Tines: collection runs only in the collector.
"""

from collections.abc import Callable, Mapping
from typing import Any, Literal
from uuid import UUID

from fastapi import APIRouter, Request, Response
from pydantic import BaseModel, ConfigDict, Field
from starlette.concurrency import run_in_threadpool

from execbound.monitoring import connect, consent
from execbound.monitoring import store as monitor_store
from execbound.monitoring.models import MonitorError
from execbound.monitoring.sealing import CollectorPublicKey
from execbound.runtime import Runtime
from execbound.surfaces.connect_pages import set_binding
from execbound.surfaces.console_api.bodies import body
from execbound.surfaces.console_api.errors import ApiError
from execbound.surfaces.console_api.guards import ApiGuards
from execbound.surfaces.console_api.monitoring import MonitorConnection, _connection, _facts
from execbound.surfaces.console_api.monitoring import _identifier as identifier
from execbound.surfaces.console_api.monitoring_sources import intake_url
from execbound.surfaces.human import HumanConfig
from execbound.surfaces.sessions import Session

Availability = Literal["available", "unconfigured"]
# A Tines tenant's own origin, as `monitoring.store._connection_shape` admits it.
TINES_ORIGIN = r"^https://[A-Za-z0-9.-]{1,240}\.tines\.(com|io)$"
TEAM = r"^[A-Za-z0-9._:-]{1,64}$"
# Printable ASCII with no whitespace, as an API key is.
API_KEY = r"^[\x21-\x7e]{1,4096}$"
UUID_TEXT = r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"


class MonitorConnectAttempt(BaseModel):
    """How the session's own latest Microsoft Entra consent attempt ended, if it ended within
    the last ten minutes: what the page says on the return from Microsoft. Never a code, and
    never another person's attempt."""

    outcome: Literal["consented", "refused"]
    # Refused at the consent callback, when Microsoft may already hold the consent.
    refused_after_consent: bool
    connection_id: UUID | None


class MonitorPlacement(BaseModel):
    """Where a connection or a reporting source made now lands: the session's Space by id and
    name, whether it is archived, and whether this administrator administers it. An administrator
    narrowed to Spaces sees Spaces they only review, and adds nothing there. The id lets the
    console tell a placement read before the session moved to another Space, which it reads
    again."""

    space_id: UUID
    name: str
    archived: bool
    administered: bool


class MonitorConnectOptions(BaseModel):
    """Which providers this deployment connects from the console. `unconfigured` means the
    console shows who connects one instead of a form that cannot work. Where Microsoft Entra is
    available, the platform app's name as a directory administrator sees it and its client id,
    which the console names when it says how to withdraw consent. `sources` says whether the
    console mints reporting sources, which it does exactly where Tines connects, and
    `intake_url` is where a reporting story sends its events, from the configured origin.
    `placement` is where something made now lands, or null where the session sees several
    Spaces and has chosen none."""

    tines: Availability
    entra: Availability
    sources: Availability
    intake_url: str
    entra_display_name: str | None
    entra_client_id: str | None
    last_attempt: MonitorConnectAttempt | None
    placement: MonitorPlacement | None


class ConnectTines(BaseModel):
    """A Tines connection: its name, the tenant's address, an optional team and the API key,
    which is sealed for the collector and never stored, shown or logged."""

    model_config = ConfigDict(extra="forbid")

    label: str = Field(min_length=1, max_length=96)
    base_url: str = Field(min_length=1, max_length=260, pattern=TINES_ORIGIN)
    team_id: str | None = Field(default=None, pattern=TEAM)
    api_key: str = Field(min_length=1, max_length=4096, pattern=API_KEY)


class ReplaceConnectionKey(BaseModel):
    """A new API key for a sealed Tines connection."""

    model_config = ConfigDict(extra="forbid")

    api_key: str = Field(min_length=1, max_length=4096, pattern=API_KEY)


class ConnectionSchedule(BaseModel):
    """A connection's intervals in seconds; left out or null, the kind's default. Entra
    collects every 3,600 to 86,400 seconds; Tines reads its audit records every 300 to 3,600
    and its inventory daily, which is not adjustable."""

    model_config = ConfigDict(extra="forbid")

    collect_interval_seconds: int | None = Field(default=None, ge=3600, le=86400)
    activity_interval_seconds: int | None = Field(default=None, ge=300, le=3600)


class ConnectionChange(BaseModel):
    """No fields: the address names the connection and the change."""

    model_config = ConfigDict(extra="forbid")


class StartEntraConnect(BaseModel):
    """A new Microsoft Entra connection's name, or the consented connection whose consent to
    update; never both."""

    model_config = ConfigDict(extra="forbid")

    label: str | None = Field(default=None, min_length=1, max_length=96)
    connection_id: str | None = Field(default=None, pattern=UUID_TEXT)


class EntraConnectStart(BaseModel):
    """Microsoft's sign-in address for this attempt. Its `state` is a secret for ten minutes:
    the console navigates to it and keeps it nowhere."""

    authorize_url: str


# The store's refusals, each to the console's code and, for a body's fault, its field.
_FIELDS = {
    "INVALID_LABEL": ["label"],
    "INVALID_TEAM": ["team_id"],
    "INVALID_BASE_URL": ["base_url"],
    "INVALID_KEY": ["api_key"],
    "INVALID_SCHEDULE": ["activity_interval_seconds", "collect_interval_seconds"],
    "INVALID_INPUT": [],
}
_CODES = {
    "SPACE_REQUIRED": "SPACE_REQUIRED",
    "SPACE_ARCHIVED": "SPACE_ARCHIVED",
    "CONNECTION_EXISTS": "CONNECTION_EXISTS",
    "CONNECTION_CAPACITY": "CONNECTION_CAPACITY",
    "INVALID_ADMIN": "FORBIDDEN",
    "CONNECTION_UNAVAILABLE": "NOT_FOUND",
    "CONNECTION_REVOKED": "CONFLICT",
    "CONNECTION_NOT_SEALED": "CONFLICT",
    "CONNECTION_NOT_CONSENTED": "CONFLICT",
    "ATTEMPT_CAPACITY": "ATTEMPT_CAPACITY",
}


def _refused(exc: MonitorError) -> ApiError:
    if exc.code in _FIELDS:
        return ApiError("INVALID_BODY", fields=_FIELDS[exc.code])
    return ApiError(_CODES.get(exc.code, "UNAVAILABLE"))


def options(
    config: HumanConfig,
    last: Mapping[str, Any] | None = None,
    placement: Mapping[str, Any] | None = None,
) -> MonitorConnectOptions:
    collector = config.scout.collector if config.scout is not None else None
    entra = config.scout.entra if config.scout is not None else None
    return MonitorConnectOptions(
        tines="available" if collector is not None else "unconfigured",
        entra="available" if entra is not None else "unconfigured",
        # Console minting is live exactly where console connect is (#678).
        sources="available" if collector is not None else "unconfigured",
        intake_url=intake_url(config),
        entra_display_name=entra.display_name if entra is not None else None,
        entra_client_id=entra.client_id if entra is not None else None,
        last_attempt=MonitorConnectAttempt(**last) if last is not None else None,
        placement=MonitorPlacement(**placement) if placement is not None else None,
    )


def _collector(config: HumanConfig) -> CollectorPublicKey:
    """The collector's public key, or `CONNECT_UNAVAILABLE` where the deployment gave none."""
    collector = config.scout.collector if config.scout is not None else None
    if collector is None:
        raise ApiError("CONNECT_UNAVAILABLE")
    return collector


def _applied(runtime: Runtime, session: Session, change: Callable[[], UUID]) -> MonitorConnection:
    """Make the change, then answer the connection as the server now holds it."""
    try:
        connection_id = change()
        row, requesters = connect.connection(
            runtime.db, session, connection_id, clock=runtime.clock
        )
    except MonitorError as exc:
        raise _refused(exc) from None
    return _connection(row, _facts(requesters), runtime.clock.now())


def monitoring_connect_routes(
    routes: APIRouter, runtime: Runtime, config: HumanConfig, guards: ApiGuards
) -> None:
    @routes.get(
        "/monitor/connect",
        response_model=MonitorConnectOptions,
        operation_id="readMonitorConnect",
    )
    async def read_monitor_connect(request: Request) -> MonitorConnectOptions:
        current, _ = await guards.session(request, kind="ADMIN")
        entra = config.scout is not None and config.scout.entra is not None

        def read() -> tuple[Mapping[str, Any] | None, Mapping[str, Any] | None]:
            last = consent.last_attempt(runtime.db, current, clock=runtime.clock) if entra else None
            return last, monitor_store.placement(runtime.db, current, clock=runtime.clock)

        try:
            last, placed = await run_in_threadpool(read)
        except MonitorError as exc:
            raise _refused(exc) from None
        return options(config, last, placed)

    @routes.post(
        "/monitor/connections/tines",
        response_model=MonitorConnection,
        status_code=201,
        operation_id="connectTines",
        openapi_extra=body(ConnectTines),
    )
    async def connect_tines(request: Request) -> MonitorConnection:
        current, values = await guards.mutation(request, ConnectTines, kind="ADMIN")
        public = _collector(config)

        def create() -> UUID:
            return connect.create_sealed_connection(
                runtime.db,
                current,
                label=values.label,
                base_url=values.base_url,
                team_id=values.team_id,
                api_key=values.api_key,
                public=public,
                clock=runtime.clock,
            )

        return await run_in_threadpool(_applied, runtime, current, create)

    @routes.post(
        "/monitor/connections/entra/start",
        response_model=EntraConnectStart,
        operation_id="startEntraConnect",
        openapi_extra=body(StartEntraConnect),
    )
    async def start_entra_connect(request: Request, response: Response) -> EntraConnectStart:
        current, values = await guards.mutation(request, StartEntraConnect, kind="ADMIN")
        entra = config.scout.entra if config.scout is not None else None
        if entra is None:
            raise ApiError("CONNECT_UNAVAILABLE")
        if (values.label is None) == (values.connection_id is None):
            raise ApiError("INVALID_BODY", fields=["label", "connection_id"])
        target = identifier(values.connection_id) if values.connection_id is not None else None

        def begin() -> consent.Started:
            return consent.start(
                runtime.db,
                current,
                client_id=entra.client_id,
                authority=entra.authority,
                origin=config.origin,
                label=values.label,
                connection_id=target,
                clock=runtime.clock,
            )

        try:
            started = await run_in_threadpool(begin)
        except MonitorError as exc:
            raise _refused(exc) from None
        # The browser that started the attempt, and only it, can finish it.
        set_binding(response, config, started.binding)
        response.headers["Cache-Control"] = "no-store"
        return EntraConnectStart(authorize_url=started.authorize_url)

    @routes.post(
        "/monitor/connections/{connection_id}/key",
        response_model=MonitorConnection,
        operation_id="replaceMonitorConnectionKey",
        openapi_extra=body(ReplaceConnectionKey),
    )
    async def replace_connection_key(request: Request, connection_id: str) -> MonitorConnection:
        current, values = await guards.mutation(request, ReplaceConnectionKey, kind="ADMIN")
        public = _collector(config)
        target = identifier(connection_id)

        def replace() -> UUID:
            connect.replace_sealed_key(
                runtime.db,
                current,
                target,
                api_key=values.api_key,
                public=public,
                clock=runtime.clock,
            )
            return target

        return await run_in_threadpool(_applied, runtime, current, replace)

    @routes.post(
        "/monitor/connections/{connection_id}/collect",
        response_model=MonitorConnection,
        operation_id="requestMonitorCollection",
        openapi_extra=body(ConnectionChange),
    )
    async def request_collection(request: Request, connection_id: str) -> MonitorConnection:
        current, _ = await guards.mutation(request, ConnectionChange, kind="ADMIN")
        target = identifier(connection_id)

        def ask() -> UUID:
            connect.request_collection(runtime.db, current, target, clock=runtime.clock)
            return target

        return await run_in_threadpool(_applied, runtime, current, ask)

    @routes.post(
        "/monitor/connections/{connection_id}/schedule",
        response_model=MonitorConnection,
        operation_id="scheduleMonitorConnection",
        openapi_extra=body(ConnectionSchedule),
    )
    async def schedule_connection(request: Request, connection_id: str) -> MonitorConnection:
        current, values = await guards.mutation(request, ConnectionSchedule, kind="ADMIN")
        target = identifier(connection_id)

        def schedule() -> UUID:
            connect.set_schedule(
                runtime.db,
                current,
                target,
                collect=values.collect_interval_seconds,
                activity=values.activity_interval_seconds,
                clock=runtime.clock,
            )
            return target

        return await run_in_threadpool(_applied, runtime, current, schedule)

    @routes.post(
        "/monitor/connections/{connection_id}/revoke",
        response_model=MonitorConnection,
        operation_id="revokeMonitorConnection",
        openapi_extra=body(ConnectionChange),
    )
    async def revoke_connection(request: Request, connection_id: str) -> MonitorConnection:
        current, _ = await guards.mutation(request, ConnectionChange, kind="ADMIN")
        target = identifier(connection_id)

        def revoke() -> UUID:
            connect.revoke_connection(runtime.db, current, target, clock=runtime.clock)
            return target

        return await run_in_threadpool(_applied, runtime, current, revoke)
