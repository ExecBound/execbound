# SPDX-License-Identifier: AGPL-3.0-only
"""`/api/console/v1/teammate-invitations`: invite, list, resend and revoke a workspace member.

Named `teammate_invitations` rather than `invitations` because `/api/console/v1/invitations`
is a different area, one a plugin may add to invite someone to claim a whole workspace (#204).
Every operation id below carries `TeammateInvitation`, so that nothing here collides with that
area's names in a generated client that holds both.

Every route wraps `execbound.invitations`, exactly as `access.py` wraps `access_control`: the
service already re-checks `access.manage` inside its own fenced transaction on every call, so a
route here adds no role gate of its own before calling it; `FORBIDDEN` is the service's own
answer, mapped like any other refusal. `create` and `resend` each schedule one best-effort
delivery attempt as a background task after their transaction commits, using the same lease the
scheduled drain would use next; neither ever blocks the response on mail, and neither runs at
all where this deployment has no relay configured. The origin a link is built from is this
deployment's own configured one (`config.origin`), never a request header.
"""

from datetime import datetime
from functools import partial
from typing import Literal
from uuid import UUID

from fastapi import APIRouter, BackgroundTasks, Request
from pydantic import BaseModel, ConfigDict, Field
from starlette.concurrency import run_in_threadpool

from execbound import invitations as invitations_module
from execbound.invitations import MAX_GRANTS, InvitationError
from execbound.runtime import Runtime
from execbound.surfaces.console_api.access import AccessGrant, AccessGrantInput
from execbound.surfaces.console_api.directory import (
    EMAIL_LIMIT,
    UUID_PATTERN,
    Empty,
    body_of,
    parse_uuid,
)
from execbound.surfaces.console_api.errors import ApiError
from execbound.surfaces.console_api.guards import ApiGuards
from execbound.surfaces.human import HumanConfig

State = Literal["PENDING", "ACCEPTED", "REVOKED"]

# A definer function's or the service's own refusal, as the API's typed code and, for a body
# fault, its field. `INVALID_STATE` covers a resend or revoke racing an acceptance, a revoke or
# another resend; the page's own refresh is what shows the person what is there now, so it
# reuses the generic `CONFLICT` rather than a code of its own.
REFUSALS: dict[str, tuple[str, list[str] | None]] = {
    "FORBIDDEN": ("FORBIDDEN", None),
    "INVALID_EMAIL": ("INVALID_BODY", ["email"]),
    "INVALID_ROLES": ("INVALID_BODY", ["grants"]),
    "INVALID_ROLE": ("INVALID_BODY", ["grants"]),
    "INVALID_ROLE_SCOPE": ("INVALID_BODY", ["grants"]),
    "INVALID_SPACE": ("INVALID_BODY", ["grants"]),
    "INVALID_GROUP": ("INVALID_BODY", ["reviewer_group_id"]),
    "ALREADY_MEMBER": ("ALREADY_MEMBER", None),
    "INVITATION_PENDING": ("INVITATION_PENDING", None),
    "NOT_FOUND": ("NOT_FOUND", None),
    "INVALID_STATE": ("CONFLICT", None),
    "RESEND_LIMIT": ("RESEND_LIMIT", None),
    "INVALID_REQUEST": ("INVALID_BODY", None),
    "INVALID_CLOCK": ("UNAVAILABLE", None),
}


def refused(exc: InvitationError) -> ApiError:
    """The typed refusal for a service code; anything unlisted is unavailability."""
    code, fields = REFUSALS.get(exc.code, ("UNAVAILABLE", None))
    return ApiError(code, fields=fields)


class CreateTeammateInvitation(BaseModel):
    model_config = ConfigDict(extra="forbid")

    email: str = Field(min_length=3, max_length=EMAIL_LIMIT)
    # Absent, the service's own default: one Viewer grant at workspace scope.
    grants: list[AccessGrantInput] | None = Field(default=None, max_length=MAX_GRANTS)
    # The reviewer group the invited Approver joins on acceptance. The invitation must grant
    # Approver, and the group may grant nothing the invitation does not.
    reviewer_group_id: str | None = Field(default=None, pattern=UUID_PATTERN)


class CreatedTeammateInvitation(BaseModel):
    invitation_id: UUID
    expires_at: datetime


class TeammateInvitationRow(BaseModel):
    invitation_id: UUID
    email: str
    grants: list[AccessGrant]
    state: State
    created_at: datetime
    expires_at: datetime
    # How many sends this invitation has had, and the delivery outcome of the latest one: a
    # failure the drain will retry has `last_error` set and `delivered_at` still null.
    sends: int
    last_error: str | None
    delivered_at: datetime | None
    # The reviewer group the invitation names, and its name now: `null` when it names none,
    # and a name of `null` when the group was deleted since.
    reviewer_group_id: UUID | None
    reviewer_group_name: str | None


class TeammateInvitationsPage(BaseModel):
    invitations: list[TeammateInvitationRow]


class TeammateInvitationChanged(BaseModel):
    changed: bool = True


def teammate_invitations_routes(
    routes: APIRouter, runtime: Runtime, config: HumanConfig, guards: ApiGuards
) -> None:
    def deliver(tenant: UUID, message_id: UUID) -> None:
        """The fast first send (#487), off the request. `deliver_one` never raises."""
        mail = runtime.mail
        assert mail is not None
        invitations_module.deliver_one(
            runtime.db, tenant, message_id, mail=mail, origin=config.origin, clock=runtime.clock
        )

    @routes.get(
        "/teammate-invitations",
        response_model=TeammateInvitationsPage,
        operation_id="listTeammateInvitations",
    )
    async def list_invitations(request: Request) -> TeammateInvitationsPage:
        session, _ = await guards.session(request)
        try:
            rows = await run_in_threadpool(invitations_module.list_invitations, runtime, session)
        except InvitationError as exc:
            raise refused(exc) from None
        return TeammateInvitationsPage(
            invitations=[TeammateInvitationRow.model_validate(row) for row in rows]
        )

    @routes.post(
        "/teammate-invitations",
        response_model=CreatedTeammateInvitation,
        operation_id="createTeammateInvitation",
        openapi_extra=body_of(CreateTeammateInvitation),
    )
    async def create(request: Request, background: BackgroundTasks) -> CreatedTeammateInvitation:
        session, body = await guards.mutation(request, CreateTeammateInvitation)
        grants = None if body.grants is None else [grant.model_dump() for grant in body.grants]
        group = None if body.reviewer_group_id is None else parse_uuid(body.reviewer_group_id, 400)
        try:
            created = await run_in_threadpool(
                partial(invitations_module.create_invitation, reviewer_group=group),
                runtime,
                session,
                body.email,
                grants,
            )
        except InvitationError as exc:
            raise refused(exc) from None
        if runtime.mail is not None:
            background.add_task(deliver, session.identity.tenant_id, created["message_id"])
        return CreatedTeammateInvitation(
            invitation_id=created["invitation_id"], expires_at=created["expires_at"]
        )

    @routes.post(
        "/teammate-invitations/{id}/resend",
        response_model=TeammateInvitationChanged,
        operation_id="resendTeammateInvitation",
        openapi_extra=body_of(Empty),
    )
    async def resend(
        request: Request, id: str, background: BackgroundTasks
    ) -> TeammateInvitationChanged:
        session, _ = await guards.mutation(request, Empty)
        invitation = parse_uuid(id)
        try:
            message_id = await run_in_threadpool(
                invitations_module.resend_invitation, runtime, session, invitation
            )
        except InvitationError as exc:
            raise refused(exc) from None
        if runtime.mail is not None:
            background.add_task(deliver, session.identity.tenant_id, message_id)
        return TeammateInvitationChanged()

    @routes.post(
        "/teammate-invitations/{id}/revoke",
        response_model=TeammateInvitationChanged,
        operation_id="revokeTeammateInvitation",
        openapi_extra=body_of(Empty),
    )
    async def revoke(request: Request, id: str) -> TeammateInvitationChanged:
        session, _ = await guards.mutation(request, Empty)
        invitation = parse_uuid(id)
        try:
            await run_in_threadpool(
                invitations_module.revoke_invitation, runtime, session, invitation
            )
        except InvitationError as exc:
            raise refused(exc) from None
        return TeammateInvitationChanged()
