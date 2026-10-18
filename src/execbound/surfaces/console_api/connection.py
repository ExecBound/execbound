# SPDX-License-Identifier: AGPL-3.0-only
"""`GET /api/console/v1/connection`: the "Connect this agent" card's own data, core-served.

Connecting an agent is core: every self-hosted install needs the gateway origin, the client
recipes rendered from it, and (once a workspace has installed sample targets) the sample
development workstation's hint for the example request, with the `operation_ref` the samples'
starter bundle names for their active mapping, so a person relays the whole request and the
agent guesses nothing (#545). It names one target, to a person; no agent is given a target
listing. A hosted sandbox's own fixture workstation is a plugin's
onboarding, not core's, and stays on the plugin's own welcome view; the console falls back to
that only when this route's ``workstation`` is None.

The read is an administrator's, guarded exactly as any other console API route
(``guards.session(request, kind="ADMIN")``), and rechecks the identity and the session inside
the same fenced transaction the read is taken in, as any console API read that touches the
database does. That transaction is `GET /samples`'s own (`samples.checked_status`).
"""

from fastapi import APIRouter, Request
from pydantic import BaseModel
from starlette.concurrency import run_in_threadpool

from execbound import samples as sample_targets
from execbound.runtime import Runtime
from execbound.surfaces.console_api.guards import ApiGuards
from execbound.surfaces.console_api.samples import checked_status
from execbound.surfaces.human import HumanConfig
from execbound.surfaces.recipes import render_recipes
from execbound.surfaces.sessions import Session


class Target(BaseModel):
    kind: str
    value: str
    incident_id: str


class ConnectionView(BaseModel):
    origin: str
    recipes: dict[str, str]
    # The sample development workstation's hint only; a hosted sandbox's own fixture stays a
    # plugin's. None when the workspace has no samples installed or no open incident.
    workstation: Target | None
    # The operation_ref the starter bundle names for the installed samples' active mapping,
    # which the example request and guided setup name; None while no samples are installed,
    # or where the starter names no such mapping.
    operation_ref: str | None
    samples_state: sample_targets.SampleState


def _sample_workstation(status: sample_targets.SampleStatus) -> Target | None:
    """The development workstation's hint, from the one selection `sample_workstation` makes."""
    host = sample_targets.sample_workstation(status)
    return (
        None
        if host is None
        else Target(kind="hostname", value=host.hostname, incident_id=str(host.incident_id))
    )


def connection_view(runtime: Runtime, session: Session, origin: str) -> ConnectionView:
    status = checked_status(runtime, session)
    return ConnectionView(
        origin=origin,
        recipes={str(name): str(recipe) for name, recipe in render_recipes(origin).items()},
        workstation=_sample_workstation(status),
        operation_ref=status.operation_ref,
        samples_state=status.state,
    )


def connection_routes(
    routes: APIRouter, runtime: Runtime, config: HumanConfig, guards: ApiGuards
) -> None:
    @routes.get("/connection", response_model=ConnectionView, operation_id="readConnection")
    async def read_connection(request: Request) -> ConnectionView:
        current, _ = await guards.session(request, kind="ADMIN")
        return await run_in_threadpool(connection_view, runtime, current, config.origin)
