# SPDX-License-Identifier: AGPL-3.0-only
"""`/api/console/v1/credentials`: the cross-cutting credential list, issue and revoke, as JSON.

Every route wraps the function the credentials page calls today (`surfaces/admin_pages.py`),
under an administrator's session, the same fence and the same bounds: every credential of the
tenant grouped by principal kind and principal, a credential issued to an existing agent or
approver or to a new one created for it, and a credential revoked. The functions themselves
bound the rest: an ADMIN principal is given no console credential and theirs is never revoked
here (#333).
"""

from datetime import datetime
from typing import Any, Literal
from uuid import UUID

from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel, ConfigDict, Field
from starlette.concurrency import run_in_threadpool

from execbound.administration import AdministrationError
from execbound.personal_tokens import TokenSession
from execbound.runtime import Runtime
from execbound.surfaces.admin_pages import (
    NEW_PRINCIPALS,
    credentials_overview,
    delete,
    expiring_keys,
    issue,
    revoke,
)
from execbound.surfaces.agents_pages import require_agent
from execbound.surfaces.console_api.directory import (
    LABEL_LIMIT,
    UUID_PATTERN,
    CredentialState,
    Empty,
    IssuedCredential,
    KeyLifetime,
    admin,
    body_of,
    issued_view,
    key_lifetime_of,
    parse_uuid,
    refused,
)
from execbound.surfaces.console_api.errors import ApiError
from execbound.surfaces.console_api.guards import ApiGuards
from execbound.surfaces.human import HumanConfig
from execbound.surfaces.sessions import Session

PrincipalKind = Literal["AGENT", "HUMAN_APPROVER", "ADMIN"]
NEW_PATTERN = "^(new:AGENT|new:HUMAN_APPROVER|" + UUID_PATTERN[1:-1] + ")$"


class PrincipalOption(BaseModel):
    principal_id: UUID
    kind: PrincipalKind
    active: bool
    label: str | None
    # The principal's counting number in its workspace: an agent's (0058) or a person's
    # (0062), each class counting on its own.
    number: int | None
    live: int


class CredentialListRow(BaseModel):
    credential_id: UUID
    principal_id: UUID
    kind: PrincipalKind
    label: str | None
    # The holder's email, which names a person with no label; `None` for an agent.
    email: str | None
    # The key's number (0058), `None` for a person's credential, and its holder's number:
    # an agent's (0058) or a person's (0062).
    number: int | None
    principal_number: int | None
    issued_at: datetime
    expires_at: datetime
    revoked_at: datetime | None
    state: CredentialState
    failures_24h: int
    # When the key last authenticated, at most once a minute (0079); display only.
    last_used_at: datetime | None = None
    # A live key names this one as the key it replaces, through Rotate (0079).
    replaced: bool = False


class ExpiringKey(BaseModel):
    """A used agent key that expires within seven days and that no live key replaces."""

    credential_id: UUID
    number: int | None
    principal_id: UUID
    principal_number: int | None
    # Agent text, rendered as text.
    principal_label: str | None
    expires_at: datetime
    last_used_at: datetime


class ExpiringKeys(BaseModel):
    """At most five agents, each by its soonest key, and how many more there are."""

    keys: list[ExpiringKey]
    more: int


class CredentialsPage(BaseModel):
    principals: list[PrincipalOption]
    credentials: list[CredentialListRow]
    live: int


class IssueBody(BaseModel):
    """An existing principal's id, or `new:AGENT` or `new:HUMAN_APPROVER` to create one."""

    model_config = ConfigDict(extra="forbid")

    principal: str = Field(pattern=NEW_PATTERN)
    lifetime: KeyLifetime
    # The name of an agent created for this key, "Coding agent on my laptop"; only with
    # `new:AGENT`.
    label: str | None = Field(default=None, max_length=LABEL_LIMIT)


def _page(data: dict[str, Any]) -> CredentialsPage:
    return CredentialsPage(
        principals=[PrincipalOption.model_validate(row) for row in data["principals"]],
        credentials=[CredentialListRow.model_validate(row) for row in data["credentials"]],
        live=int(data["live"]),
    )


def read_page(runtime: Runtime, session: Session) -> CredentialsPage:
    return _page(credentials_overview(runtime, session))


def _is_agent(runtime: Runtime, session: Session, principal: UUID | None, kind: str | None) -> bool:
    """Whether a key issued here is an agent's: a new agent, or an existing principal whose kind
    is AGENT. A principal's kind never changes, so reading it before the issue cannot race.
    Whether the administrator may administer that agent is the issue's own question, answered
    by the function with the code an unknown principal gets."""
    if principal is None:
        return kind == "AGENT"
    try:
        require_agent(runtime, session, principal, administered=False)
    except HTTPException:
        return False
    return True


def credentials_routes(
    routes: APIRouter, runtime: Runtime, config: HumanConfig, guards: ApiGuards
) -> None:
    @routes.get("/credentials", response_model=CredentialsPage, operation_id="listCredentials")
    async def list_credentials(request: Request) -> CredentialsPage:
        session, _ = await guards.session(request)
        admin(session)
        return await run_in_threadpool(read_page, runtime, session)

    @routes.get(
        "/credentials/expiring", response_model=ExpiringKeys, operation_id="listExpiringKeys"
    )
    async def list_expiring_keys(request: Request) -> ExpiringKeys:
        session, _ = await guards.session(request)
        admin(session)
        data = await run_in_threadpool(expiring_keys, runtime, session)
        return ExpiringKeys.model_validate(data)

    @routes.post(
        "/credentials/issue",
        response_model=IssuedCredential,
        operation_id="issueCredential",
        openapi_extra=body_of(IssueBody),
    )
    async def issue_credential(request: Request) -> IssuedCredential:
        session, body = await guards.mutation(request, IssueBody)
        admin(session)
        if body.principal in NEW_PRINCIPALS:
            principal, kind = None, NEW_PRINCIPALS[body.principal]
        else:
            principal, kind = parse_uuid(body.principal, 400), None
        if isinstance(session, TokenSession) and not await run_in_threadpool(
            _is_agent, runtime, session, principal, kind
        ):
            # A person's credential can be exchanged for a session, so a token that could issue
            # one could sign in as someone it made and approve by proxy.
            await run_in_threadpool(
                lambda: runtime.reject(
                    session.identity,
                    "TOKEN_NOT_ALLOWED",
                    actor_credential=True,
                    route=request.scope["route"].path,
                    method=request.method,
                )
            )
            raise ApiError("TOKEN_NOT_ALLOWED")
        label = None if body.label is None else " ".join(body.label.split())
        if label is not None and (kind != "AGENT" or not label):
            raise ApiError("INVALID_BODY", fields=["label"])
        try:
            issued = await run_in_threadpool(
                issue,
                runtime,
                session,
                principal=principal,
                kind=kind,
                lifetime=key_lifetime_of(body.lifetime),
                label=label,
            )
        except AdministrationError as exc:
            raise refused(exc) from None
        return issued_view(issued)

    @routes.post(
        "/credentials/{credential_id}/revoke",
        response_model=CredentialsPage,
        operation_id="revokeCredential",
        openapi_extra=body_of(Empty),
    )
    async def revoke_credential(request: Request, credential_id: str) -> CredentialsPage:
        session, _ = await guards.mutation(request, Empty)
        admin(session)
        credential = parse_uuid(credential_id)
        try:
            await run_in_threadpool(revoke, runtime, session, credential)
        except AdministrationError as exc:
            raise refused(exc) from None
        return await run_in_threadpool(read_page, runtime, session)

    @routes.post(
        "/credentials/{credential_id}/delete",
        response_model=CredentialsPage,
        operation_id="deleteCredential",
        openapi_extra=body_of(Empty),
    )
    async def delete_credential(request: Request, credential_id: str) -> CredentialsPage:
        """Take a revoked or expired API key out of every list; its history stays."""
        session, _ = await guards.mutation(request, Empty)
        admin(session)
        credential = parse_uuid(credential_id)
        try:
            await run_in_threadpool(delete, runtime, session, credential)
        except AdministrationError as exc:
            raise refused(exc) from None
        return await run_in_threadpool(read_page, runtime, session)
