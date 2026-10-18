# SPDX-License-Identifier: AGPL-3.0-only
"""`/api/console/v1/tenant/sign-in`: the tenant's own identity provider, as data.

An administrator registers one OpenID Connect provider here, proves it works by signing in
through it, enables it and disables it. Every route wraps the store function the design names,
under an administrator's session and the same fence, and none of them reads or returns a client
secret: what a page shows about a provider is its name, its issuer, its client id, its state and
how many people are linked (#177,
#241).

Registration is the one route here that reaches out of the process: the discovery document is
fetched and validated before anything is written, so a registration that could not work is a
refusal rather than a row somebody has to notice later. It runs on a worker thread, bounded by
the same in-flight cap every request has.

A provider signs people in to the whole tenant, so since 0073 only a workspace administrator
configures it. An administrator narrowed to spaces still reads this view, because the
invitations and links they make for their own people stand on the provider it describes, and
is answered 403 on registration and on every state change before anything is written or any
directory is asked, as the access page answers a setting only a workspace administrator holds.
"""

from datetime import datetime
from typing import Literal
from uuid import UUID

from fastapi import APIRouter, Request
from pydantic import BaseModel, ConfigDict, Field
from starlette.concurrency import run_in_threadpool

from execbound import directory_store as store
from execbound.directory import DirectoryRefused, discover, normalize_issuer
from execbound.runtime import Runtime
from execbound.surfaces.console_api.directory import admin, body_of, parse_uuid
from execbound.surfaces.console_api.errors import ApiError
from execbound.surfaces.console_api.guards import ApiGuards
from execbound.surfaces.human import HumanConfig
from execbound.surfaces.sessions import Session

State = Literal["draft", "verified", "enabled", "disabled"]
Requestable = Literal["enabled", "disabled"]

# What the store and the relying party refuse, as the code the client maps to copy. A value
# from the body is never echoed, and a directory's own words never reach a response.
_REFUSALS: dict[str, tuple[str, list[str]]] = {
    "INVALID_ISSUER": ("INVALID_BODY", ["issuer"]),
    "SHARED_ENTRA_ISSUER": ("INVALID_BODY", ["issuer"]),
    "DISCOVERY_UNAVAILABLE": ("INVALID_BODY", ["issuer"]),
    "DISCOVERY_ISSUER_MISMATCH": ("INVALID_BODY", ["issuer"]),
    "DISCOVERY_INCOMPLETE": ("INVALID_BODY", ["issuer"]),
    "DISCOVERY_INSECURE": ("INVALID_BODY", ["issuer"]),
    "DISCOVERY_FOREIGN_HOST": ("INVALID_BODY", ["issuer"]),
    "DISCOVERY_UNSUPPORTED": ("INVALID_BODY", ["issuer"]),
    "INVALID_SECRET": ("INVALID_BODY", ["client_secret"]),
    "INVALID_PROVIDER": ("INVALID_BODY", ["issuer"]),
    "PROVIDER_EXISTS": ("CONFLICT", []),
    "INVALID_STATE": ("CONFLICT", []),
    "ALREADY_LINKED": ("CONFLICT", []),
    "INVALID_ACTOR": ("FORBIDDEN", []),
    "INVALID_PRINCIPAL": ("FORBIDDEN", []),
}


def refused(code: str) -> ApiError:
    mapped, fields = _REFUSALS.get(code, ("UNAVAILABLE", []))
    return ApiError(mapped, fields=fields)


class Provider(BaseModel):
    """One registered provider. No secret and no ciphertext: neither is read for this view."""

    provider_id: UUID
    name: str
    issuer: str
    client_id: str
    subject_claim: str
    state: State
    created_at: datetime
    verified_at: datetime | None
    enabled_at: datetime | None
    linked: int
    last_sign_in_at: datetime | None
    self_linked: bool


class SignInView(BaseModel):
    """What the tenant settings page shows about signing in with the customer's directory.

    `configured` is false when the deployment holds no key ring, in which case there is nowhere
    to keep a client secret and the page says so rather than offering a form that cannot work.
    """

    configured: bool
    redirect_uri: str | None
    sign_in_url: str | None
    invite_url: str | None
    subject_claims: list[str]
    provider: Provider | None


class RegisterBody(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str = Field(min_length=1, max_length=80)
    issuer: str = Field(min_length=1, max_length=512)
    client_id: str = Field(min_length=1, max_length=256)
    client_secret: str = Field(min_length=1, max_length=2048)
    subject_claim: Literal["sub", "oid"]


class StateBody(BaseModel):
    model_config = ConfigDict(extra="forbid")

    state: Requestable


def configuring(runtime: Runtime, session: Session) -> None:
    """403 unless this administrator administers the whole workspace rather than some spaces.

    Asked before the write, and before registration fetches a discovery document, so a
    narrowed administrator's request reaches neither the definer function nor the directory;
    the definer function refuses the same again (`INVALID_ACTOR`).
    """
    try:
        allowed = store.configures(
            runtime.db, session.identity.tenant_id, session.identity.principal_id
        )
    except store.DirectoryError as exc:
        raise refused(exc.code) from None
    if not allowed:
        raise ApiError("FORBIDDEN")


def read_view(runtime: Runtime, config: HumanConfig, session: Session) -> SignInView:
    data = store.provider_overview(runtime, config.directory, session)
    provider = data.pop("provider")
    return SignInView(
        **data, provider=Provider.model_validate(provider) if provider is not None else None
    )


def sign_in_routes(
    routes: APIRouter, runtime: Runtime, config: HumanConfig, guards: ApiGuards
) -> None:
    @routes.get("/tenant/sign-in", response_model=SignInView, operation_id="readSignIn")
    async def read_sign_in(request: Request) -> SignInView:
        session, _ = await guards.session(request)
        admin(session)
        return await run_in_threadpool(read_view, runtime, config, session)

    @routes.post(
        "/tenant/sign-in",
        response_model=SignInView,
        operation_id="registerProvider",
        openapi_extra=body_of(RegisterBody),
    )
    async def register(request: Request) -> SignInView:
        """Validate a registration against the directory itself, then write it as a draft.

        Discovery is fetched here rather than at the first sign-in, so an issuer that is wrong,
        unreachable or multi-tenant is a refusal the administrator sees while they are looking
        at the form, and nothing is saved.
        """
        session, body = await guards.mutation(request, RegisterBody)
        admin(session)
        await run_in_threadpool(configuring, runtime, session)
        if config.directory is None:
            raise ApiError("UNAVAILABLE")
        settings = config.directory
        try:
            issuer = normalize_issuer(body.issuer)
            discovery = await run_in_threadpool(discover, issuer, http=settings.http)
        except DirectoryRefused as exc:
            raise refused(exc.code) from None
        try:
            await run_in_threadpool(
                lambda: store.register(
                    runtime.db,
                    settings,
                    session.identity.tenant_id,
                    session.identity.principal_id,
                    name=body.name,
                    client_id=body.client_id,
                    client_secret=body.client_secret,
                    subject_claim=body.subject_claim,
                    discovery=discovery,
                    clock=runtime.clock,
                )
            )
        except store.DirectoryError as exc:
            raise refused(exc.code) from None
        return await run_in_threadpool(read_view, runtime, config, session)

    @routes.post(
        "/tenant/sign-in/{provider_id}/state",
        response_model=SignInView,
        operation_id="setProviderState",
        openapi_extra=body_of(StateBody),
    )
    async def set_state(request: Request, provider_id: str) -> SignInView:
        """Enable or disable. `verified` is never requestable: only a sign-in writes it."""
        session, body = await guards.mutation(request, StateBody)
        admin(session)
        await run_in_threadpool(configuring, runtime, session)
        provider = parse_uuid(provider_id)
        try:
            await run_in_threadpool(
                store.set_state,
                runtime.db,
                session.identity.tenant_id,
                session.identity.principal_id,
                provider,
                body.state,
                clock=runtime.clock,
            )
        except store.DirectoryError as exc:
            raise refused(exc.code) from None
        return await run_in_threadpool(read_view, runtime, config, session)
