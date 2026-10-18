# SPDX-License-Identifier: AGPL-3.0-only
"""Verify customer-operated collectors from persisted, scoped evidence only.

The browser never submits a provider secret or destination. Provisioning and collection
remain the existing explicit operator commands; this route does not contact a provider.
"""

from datetime import datetime
from typing import Literal
from uuid import UUID

from fastapi import APIRouter, Request
from pydantic import BaseModel, ConfigDict, Field
from starlette.concurrency import run_in_threadpool

from execbound.monitoring import store
from execbound.runtime import Runtime
from execbound.surfaces.console_api.bodies import body
from execbound.surfaces.console_api.errors import ApiError
from execbound.surfaces.console_api.guards import ApiGuards
from execbound.surfaces.console_api.monitoring import MonitorCapability, _identifier, _read
from execbound.surfaces.human import HumanConfig
from execbound.surfaces.sessions import Session

Provider = Literal["tines", "entra_agent_id"]


class VerifyMonitorSetup(BaseModel):
    model_config = ConfigDict(extra="forbid")

    provider: Provider
    connection_id: str = Field(min_length=36, max_length=36)


class MonitorSetupVerification(BaseModel):
    connection_id: UUID
    label: str
    provider: Provider
    state: Literal["awaiting_sync", "reporting", "attention", "inactive"]
    last_run_at: datetime | None
    last_sync_at: datetime | None
    last_outcome: str | None
    last_error_code: str | None
    health_state: str
    capabilities: dict[str, MonitorCapability]
    recent_observations: int
    latest_observation_at: datetime | None
    checked_at: datetime


def verify_setup(
    runtime: Runtime, session: Session, provider: Provider, connection_id: UUID
) -> MonitorSetupVerification:
    # snapshot checks the current session and ADMIN authority inside its transaction and
    # filters connections and observations with the common visible_spaces predicate.
    rows = store.snapshot(runtime.db, session, clock=runtime.clock)
    connection = next(
        (row for row in rows["connections"] if row["connection_id"] == connection_id), None
    )
    if connection is None or connection["kind"] != provider:
        raise ApiError("NOT_FOUND")
    now = runtime.clock.now()
    capabilities = {
        str(name): MonitorCapability(**value)
        for name, value in (connection["capabilities"] or {}).items()
        if isinstance(value, dict)
    }
    # One freshness rule, shared with the Connections view and the counts: reporting exactly
    # when the evidence shows collection running and complete, recently. A historical
    # successful sync proves collection happened, not that an unattended collector is still
    # running.
    state: Literal["awaiting_sync", "reporting", "attention", "inactive"]
    if not connection["active"] or connection["revoked_at"] is not None:
        state = "inactive"
    elif store.collection_reporting(connection, now):
        state = "reporting"
    elif (
        connection["last_sync_at"] is None
        and store.collection_overdue_since(connection, now) is None
        and connection["last_error_code"] is None
        and connection["last_outcome"] in {None, "COMPLETE"}
        and not any(value.state == "forbidden" for value in capabilities.values())
    ):
        state = "awaiting_sync"
    else:
        state = "attention"
    observations = [row for row in rows["observations"] if row["connection_id"] == connection_id]
    return MonitorSetupVerification(
        connection_id=connection_id,
        label=connection["label"],
        provider=provider,
        state=state,
        last_run_at=connection["last_run_at"],
        last_sync_at=connection["last_sync_at"],
        last_outcome=connection["last_outcome"],
        last_error_code=connection["last_error_code"],
        health_state=connection["health_state"],
        capabilities=capabilities,
        recent_observations=len(observations),
        latest_observation_at=max((row["received_at"] for row in observations), default=None),
        checked_at=now,
    )


def monitoring_setup_routes(
    routes: APIRouter, runtime: Runtime, config: HumanConfig, guards: ApiGuards
) -> None:
    @routes.post(
        "/monitor/setup/verify",
        response_model=MonitorSetupVerification,
        operation_id="verifyMonitorSetup",
        openapi_extra=body(VerifyMonitorSetup),
    )
    async def verify_monitor_setup(request: Request) -> MonitorSetupVerification:
        current, values = await guards.mutation(request, VerifyMonitorSetup, kind="ADMIN")
        identifier = _identifier(values.connection_id)
        return await run_in_threadpool(
            _read, lambda: verify_setup(runtime, current, values.provider, identifier)
        )
