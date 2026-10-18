# SPDX-License-Identifier: AGPL-3.0-only
"""Account, support and aggregate-report endpoints use existing session/CSRF guards."""

from datetime import datetime
from typing import Literal
from uuid import UUID

from fastapi import APIRouter, Request
from pydantic import BaseModel, ConfigDict, Field
from starlette.concurrency import run_in_threadpool

from execbound import accounts
from execbound.runtime import Runtime
from execbound.surfaces.console_api.bodies import body
from execbound.surfaces.console_api.directory import UUID_PATTERN
from execbound.surfaces.console_api.errors import ApiError
from execbound.surfaces.console_api.guards import ApiGuards
from execbound.surfaces.console_api.principals import PrincipalKind
from execbound.surfaces.human import HumanConfig
from execbound.surfaces.sessions import Session

RequestKind = Literal["data_access", "close_account", "close_workspace"]
RequestState = Literal["pending", "completed", "declined"]


class AccountRequest(BaseModel):
    request_id: UUID
    kind: RequestKind
    state: RequestState
    requested_at: datetime
    closed_at: datetime | None
    response: str | None


class QueuedRequest(AccountRequest):
    name: str | None
    principal_id: UUID
    # The requester's counting number and kind, so an unlabelled person reads "User 3" (#678).
    # `kind` already names the request's own kind, so the principal's is `principal_kind`.
    number: int
    principal_kind: PrincipalKind


class SecurityNotice(BaseModel):
    sequence: int | UUID
    at: datetime
    message: str


class AccountView(BaseModel):
    name: str | None
    requests: list[AccountRequest]
    notifications: list[SecurityNotice]


class ProfileChange(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: str = Field(min_length=1, max_length=80)


class PrivacyRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    kind: RequestKind


class PrivacyResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")
    request_id: str = Field(pattern=UUID_PATTERN)
    state: Literal["completed", "declined"]
    response: str = Field(min_length=1, max_length=1000)


def account_routes(
    routes: APIRouter, runtime: Runtime, config: HumanConfig, guards: ApiGuards
) -> None:
    async def view(session: Session) -> AccountView:
        return AccountView.model_validate(
            await run_in_threadpool(accounts.overview, runtime.db, session, clock=runtime.clock)
        )

    async def mutate(
        request: Request, model: type[BaseModel], operation: str, *, admin: bool = False
    ) -> AccountView:
        session, data = await guards.mutation(request, model, kind="ADMIN" if admin else None)
        try:
            await run_in_threadpool(
                accounts.change,
                runtime.db,
                session,
                operation,
                data.model_dump(mode="json"),
                clock=runtime.clock,
            )
            return await view(session)
        except accounts.AccountError as error:
            raise ApiError(error.code) from None

    @routes.get("/account", response_model=AccountView, operation_id="readAccount")
    async def read_account(request: Request) -> AccountView:
        session, _ = await guards.session(request)
        return await view(session)

    @routes.post(
        "/account/profile",
        response_model=AccountView,
        operation_id="changeProfile",
        openapi_extra=body(ProfileChange),
    )
    async def profile(request: Request) -> AccountView:
        return await mutate(request, ProfileChange, "profile")

    @routes.post(
        "/account/requests",
        response_model=AccountView,
        operation_id="requestAccountData",
        openapi_extra=body(PrivacyRequest),
    )
    async def privacy_request(request: Request) -> AccountView:
        return await mutate(request, PrivacyRequest, "request")

    @routes.get(
        "/account/requests", response_model=list[QueuedRequest], operation_id="readAccountRequests"
    )
    async def queue(request: Request) -> list[QueuedRequest]:
        session, _ = await guards.session(request, kind="ADMIN")
        try:
            rows = await run_in_threadpool(
                accounts.request_queue, runtime.db, session, clock=runtime.clock
            )
        except accounts.AccountError as error:
            # An administrator narrowed to spaces is refused 403, as a response is.
            raise ApiError(error.code) from None
        return [QueuedRequest.model_validate(row) for row in rows]

    @routes.post(
        "/account/requests/resolve",
        response_model=AccountView,
        operation_id="resolveAccountRequest",
        openapi_extra=body(PrivacyResponse),
    )
    async def resolve(request: Request) -> AccountView:
        return await mutate(request, PrivacyResponse, "resolve", admin=True)
