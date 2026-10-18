# SPDX-License-Identifier: AGPL-3.0-only
"""`/api/console/v1/samples`: read, add, refresh and remove a workspace's sample targets (#420).

All five routes are an administrator's. `GET` is the status Home's guided setup and Getting
started show, read in one fenced transaction with the identity and session rechecked, as
`GET /connection` reads. The three changes sit behind the session, CSRF and Origin checks every
mutation has (`guards.mutation`), and each answers with that same status afterwards. Refreshing
(#545) removes the samples and adds them again in one transaction, so their facts are
recorded afresh; like adding, it activates the starter bundle, so a personal access token is
refused both (`token_rules.TOKEN_REFUSED`). `GET /samples/demo-configuration` (#247) is the same
status in the shape `execbound-demo` reads, an attachment named `sandbox.json` with no
credential in it, read as `GET /samples` reads and allowed to a token as that read is.
A refusal is one of three typed codes beside the shared ones: `SAMPLES_NOT_OFFERED` when the
workspace already has a policy or a connection, or, for a refresh, while a policy a person
made depends on the samples: a policy of their own that names the samples, or the starter
selected in a space other than the default one, which the refresh would leave with no policy;
`SAMPLES_BUSY` while a sample request is pending or unsettled; and
`SAMPLES_UNAVAILABLE` when this deployment holds no sample key or holds a configured connector
for the workspace (`Runtime.samples_available`). An approver sees the samples, their requests
and their marks elsewhere in the console, and can read, download, add, refresh or remove
nothing through these five routes.
"""

from datetime import datetime
from typing import Any, Literal
from uuid import UUID

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict
from starlette.concurrency import run_in_threadpool

from execbound import samples
from execbound.execution import store
from execbound.execution.models import ExecutionError
from execbound.logging_schema import log_event
from execbound.personal_tokens import TokenSession
from execbound.provider.sample_accounts import SAMPLE_PROVIDER
from execbound.replay.verify import ReplayValidationError, reject_secrets
from execbound.runtime import Runtime
from execbound.surfaces.console_api.board import same_generation
from execbound.surfaces.console_api.bodies import body as body_of
from execbound.surfaces.console_api.errors import ApiError
from execbound.surfaces.console_api.executions import STATE_WORDS
from execbound.surfaces.console_api.guards import ApiGuards
from execbound.surfaces.human import HumanConfig, authority_guard
from execbound.surfaces.sessions import Session, SessionError, check_session


class SampleChange(BaseModel):
    """Every change takes an empty object; the session says whose workspace it is."""

    model_config = ConfigDict(extra="forbid")


class SampleHostView(BaseModel):
    provider_id: str
    hostname: str
    role: str
    environment: str
    criticality: int
    incident_id: UUID | None
    # What the starter rules read on this target's facts, "allow", "require approval" or
    # "deny": as the rules read, never the kernel's decision.
    effect: str
    rules: list[str]


class SampleRequestView(BaseModel):
    execution_id: UUID
    state: str
    state_label: str
    provider_id: str
    created_at: datetime


class SampleStatusView(BaseModel):
    state: Literal["absent", "present", "removable"]
    offered: bool
    available: bool
    # Whether `GET /samples/demo-configuration` hands out `execbound-demo`'s configuration for
    # these samples now (#247), so the console links it only then (`samples.demo_targets`), and
    # only until `stale_at`, from which the facts it rests on are refused.
    demo_available: bool
    # Whether a refresh of the sample facts is all that stands between these samples and that
    # configuration: the facts have gone stale, or a request since they were recorded, such as
    # guided setup's, changed a target the demo names (`samples.demo_needs_refresh`). Never
    # true beside `demo_available`.
    demo_needs_refresh: bool
    bundle_id: UUID | None
    hosts: list[SampleHostView]
    observed_at: datetime | None
    stale_at: datetime | None
    first_request: SampleRequestView | None


_REFUSALS = {
    "FORBIDDEN": "FORBIDDEN",
    "POLICY_PRESENT": "SAMPLES_NOT_OFFERED",
    "ACCOUNT_PRESENT": "SAMPLES_NOT_OFFERED",
    "MAPPING_PRESENT": "SAMPLES_NOT_OFFERED",
    "SAMPLES_BUSY": "SAMPLES_BUSY",
    "SAMPLES_UNAVAILABLE": "SAMPLES_UNAVAILABLE",
}


def sample_view(status: samples.SampleStatus, *, now: datetime) -> SampleStatusView:
    """The status as the console reads it; whether the demo can run on the samples is judged
    at `now`, the runtime's clock, which the facts' staleness is judged by too."""
    first = status.first_request
    return SampleStatusView(
        state=status.state,
        offered=status.offered,
        available=status.available,
        demo_available=samples.demo_targets(status, now=now) is not None,
        demo_needs_refresh=samples.demo_needs_refresh(status, now=now),
        bundle_id=status.bundle_id,
        hosts=[
            SampleHostView(
                provider_id=host.provider_id,
                hostname=host.hostname,
                role=host.role,
                environment=host.environment,
                criticality=host.criticality,
                incident_id=host.incident_id,
                effect=host.effect,
                rules=list(host.rules),
            )
            for host in status.hosts
        ],
        observed_at=status.observed_at,
        stale_at=status.stale_at,
        first_request=None
        if first is None
        else SampleRequestView(
            execution_id=first.execution_id,
            state=first.state,
            state_label=STATE_WORDS.get(first.state, first.state),
            provider_id=first.provider_id,
            created_at=first.created_at,
        ),
    )


def _act(
    runtime: Runtime, session: Session, action: Literal["install", "remove", "refresh"]
) -> SampleStatusView:
    run = {"install": samples.install, "remove": samples.remove, "refresh": samples.refresh}[action]
    try:
        found = run(
            runtime.db,
            session.identity,
            available=runtime.samples_available(session.identity.tenant_id),
            clock=runtime.clock,
            authority_check=authority_guard(runtime, session),
        )
    except samples.SampleError as exc:
        raise ApiError(_REFUSALS.get(exc.code, "UNAVAILABLE")) from None
    return sample_view(found, now=store.now(runtime.clock))


def checked_status(runtime: Runtime, session: Session) -> samples.SampleStatus:
    """The workspace's sample status, as an administrator's read.

    One fenced transaction checks the identity as an administrator's, then the session, reads
    the status, and checks the identity again. Both `GET /samples` and `GET /connection` read
    it here. A lapsed session is `SESSION_REQUIRED`, someone other than a live administrator is
    `FORBIDDEN`, and any other refusal of the checks is `UNAVAILABLE`.
    """
    identity = session.identity
    try:
        with runtime.db.transaction(identity.tenant_id) as conn:
            store.identity_check(conn, identity, runtime.clock, "ADMIN")
            check_session(conn, session, runtime.clock)
            status = samples.status(
                conn, identity.tenant_id, available=runtime.samples_available(identity.tenant_id)
            )
            store.identity_check(conn, identity, runtime.clock, "ADMIN")
    except SessionError:
        raise ApiError("SESSION_REQUIRED") from None
    except ExecutionError as exc:
        raise ApiError("FORBIDDEN" if exc.code == "INVALID_IDENTITY" else "UNAVAILABLE") from None
    return status


# A download link carries no workspace header, so it names the session generation as the
# report's CSV does (`board.same_generation`).
DEMO_QUERY = frozenset({"generation"})


def demo_configuration(runtime: Runtime, session: Session, origin: str) -> dict[str, Any]:
    """The samples as `execbound-demo`'s `sandbox.json`, read as `GET /samples` reads them.

    `NOT_FOUND` while the workspace has no samples the demo can run on, including samples
    this deployment does not serve and samples whose facts have gone stale by the runtime's
    clock (`samples.demo_targets`). The document passes the export's secret check before it
    leaves, as every download does; one that failed it would be a fault, answered
    `UNAVAILABLE` and logged with no detail.
    """
    status = checked_status(runtime, session)
    # Without the sample key nothing serves the samples, and `status.available` says so too.
    provider = runtime.sample_providers.get(SAMPLE_PROVIDER)
    document = (
        None
        if provider is None
        else samples.demo_configuration(
            status,
            now=store.now(runtime.clock),
            origin=origin,
            tenant_id=session.identity.tenant_id,
            provider_origin=provider.origin,
        )
    )
    if document is None:
        raise ApiError("NOT_FOUND")
    try:
        reject_secrets(document)
    except ReplayValidationError:
        log_event("dependency.unavailable", level="ERROR", code="PRIVATE_DATA")
        raise ApiError("UNAVAILABLE") from None
    return document


def samples_routes(
    routes: APIRouter, runtime: Runtime, config: HumanConfig, guards: ApiGuards
) -> None:
    @routes.get("/samples", response_model=SampleStatusView, operation_id="readSamples")
    async def read_samples(request: Request) -> SampleStatusView:
        session, _ = await guards.session(request, kind="ADMIN")
        status = await run_in_threadpool(checked_status, runtime, session)
        return sample_view(status, now=store.now(runtime.clock))

    @routes.post(
        "/samples",
        response_model=SampleStatusView,
        operation_id="installSamples",
        openapi_extra=body_of(SampleChange),
    )
    async def install_samples(request: Request) -> SampleStatusView:
        session, _ = await guards.mutation(request, SampleChange, kind="ADMIN")
        return await run_in_threadpool(_act, runtime, session, "install")

    @routes.post(
        "/samples/refresh",
        response_model=SampleStatusView,
        operation_id="refreshSamples",
        openapi_extra=body_of(SampleChange),
    )
    async def refresh_samples(request: Request) -> SampleStatusView:
        session, _ = await guards.mutation(request, SampleChange, kind="ADMIN")
        return await run_in_threadpool(_act, runtime, session, "refresh")

    @routes.post(
        "/samples/remove",
        response_model=SampleStatusView,
        operation_id="removeSamples",
        openapi_extra=body_of(SampleChange),
    )
    async def remove_samples(request: Request) -> SampleStatusView:
        session, _ = await guards.mutation(request, SampleChange, kind="ADMIN")
        return await run_in_threadpool(_act, runtime, session, "remove")

    @routes.get(
        "/samples/demo-configuration",
        response_class=JSONResponse,
        operation_id="downloadSampleDemoConfiguration",
        summary=(
            "The samples as execbound-demo's sandbox.json, an attachment with no credential in it."
        ),
    )
    async def download_demo_configuration(
        request: Request, generation: str | None = None
    ) -> JSONResponse:
        """`generation` is the session generation the console holds, required for an account
        session, since a download link carries no workspace header."""
        session, _ = await guards.session(request, query=DEMO_QUERY, kind="ADMIN")
        # A personal access token is bound to one workspace and carries no generation.
        if not isinstance(session, TokenSession):
            same_generation(request, session)
        document = await run_in_threadpool(demo_configuration, runtime, session, config.origin)
        return JSONResponse(
            document,
            headers={
                "Content-Disposition": 'attachment; filename="sandbox.json"',
                "Cache-Control": "no-store",
            },
        )
