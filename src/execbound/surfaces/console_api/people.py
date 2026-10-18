# SPDX-License-Identifier: AGPL-3.0-only
"""`/api/console/v1/people`: the People page's functions, answered as JSON.

People are humans, approvers and administrators; agents are the Agents area's. Every route
wraps the function the People page calls today (`surfaces/people_pages.py`, and the credential
and scope helpers of `admin_pages.py` it shares), under an administrator's session, the same
fence and the same bounds: the list with its two filters, a labelled `New approver`, the detail
with identity, credentials, scopes, sessions and history, and the changes, each of which the
functions themselves bound (an ADMIN target is refused a console credential and a deactivation,
and the acting administrator cannot end their own sessions or deactivate themselves here)
(#333).
"""

from datetime import datetime
from typing import Any, Literal
from uuid import UUID

from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import text
from starlette.concurrency import run_in_threadpool
from starlette.responses import Response

from execbound import directory_store
from execbound.administration import AdministrationError
from execbound.passwords import MAX_RESET_LIFETIME, MIN_RESET_LIFETIME
from execbound.runtime import Runtime
from execbound.spaces import NO_SPACE_FILTER, administered_clause
from execbound.surfaces import people_pages as pages
from execbound.surfaces.admin_pages import _admin, assign, issue, revoke
from execbound.surfaces.console_api.directory import (
    UUID_PATTERN,
    Created,
    CredentialRow,
    EmailBody,
    Empty,
    IssuedCode,
    IssuedCredential,
    LabelBody,
    Lifetime,
    LifetimeBody,
    ReasonBody,
    admin,
    body_of,
    credential_rows,
    filters_from,
    issued_view,
    lifetime_of,
    parse_uuid,
    query_parameters,
    refused,
)
from execbound.surfaces.console_api.errors import ApiError
from execbound.surfaces.console_api.guards import ApiGuards
from execbound.surfaces.console_api.sign_in import refused as sign_in_refused
from execbound.surfaces.human import HumanConfig
from execbound.surfaces.sessions import Session, revoke_sessions_of

KINDS: tuple[str, ...] = ("any", *pages.HUMAN_KINDS)
FILTERS: dict[str, tuple[str, ...]] = {"state": pages.STATES, "kind": KINDS}
Kind = Literal["HUMAN_APPROVER", "ADMIN"]


class PersonRow(BaseModel):
    principal_id: UUID
    kind: Kind
    active: bool
    label: str | None
    # The address the person signs in with, which names them when they have no label, and
    # their counting number among the workspace's people, "User 3" (0062). The number is a
    # display handle only; every reference keeps `principal_id`.
    email: str | None
    number: int
    created_at: datetime | None
    deactivated_at: datetime | None
    # The principal that took this one's place when the person rejoined through an
    # invitation (0061). Such a principal is retired for good and cannot be reactivated.
    replaced_by: UUID | None
    live: int
    sessions: int
    last_sign_in: datetime | None
    scopes: int
    # Whether the person has an enabled second factor, read as step-up enforcement reads it
    # (0079); on hosted, the account's factor, which it shares across its workspaces.
    second_factor: bool = False


class PeoplePage(BaseModel):
    people: list[PersonRow]


class Person(BaseModel):
    principal_id: UUID
    kind: Kind
    active: bool
    label: str | None
    # As on `PersonRow`; the address is `sign_in.email`.
    number: int
    created_at: datetime | None
    deactivated_at: datetime | None
    # As on `PersonRow`: the entry that replaced this one, which the page links to instead
    # of offering Reactivate.
    replaced_by: UUID | None
    # As on `PersonRow`.
    second_factor: bool = False


class ScopeRow(BaseModel):
    canonical_target_id: UUID
    action: str
    labels: str | None


class TargetOption(BaseModel):
    canonical_target_id: UUID
    labels: str | None


class SessionRow(BaseModel):
    session_id: UUID
    created_at: datetime
    expires_at: datetime
    label: str | None


class DecisionRow(BaseModel):
    decided_at: datetime
    approval: str
    action: str
    target: str
    decision: Literal["approved", "denied"]
    approval_id: UUID
    # Null outside the reader's visible spaces, where the Activity record would not open.
    execution_id: UUID | None = None


class SignInRow(BaseModel):
    occurred_at: datetime
    session: str
    credential: str
    device: str
    state: str


class EventRow(BaseModel):
    occurred_at: datetime
    words: str
    subject: str
    label: str | None
    # The subject's full identifier and what it names, for a link the router builds.
    subject_id: UUID | None = None
    subject_kind: Literal["bundle", "space", "credential", "principal"] | None = None
    subject_principal_kind: Literal["AGENT", "HUMAN_APPROVER", "ADMIN", "SYSTEM"] | None = None
    subject_number: int | None = None


class History(BaseModel):
    decisions: list[DecisionRow]
    sign_ins: list[SignInRow]
    events: list[EventRow]


class IdentityRow(BaseModel):
    provider: str
    subject: str
    display_name: str | None
    last_sign_in_at: datetime | None


class DirectoryLink(BaseModel):
    """The account a person signs in with at the tenant's own directory.

    `subject` is the identifier; the two display values are hints the directory reported and
    are shown as text, never used to find anybody. `via` says who bound it.
    """

    provider_id: UUID
    provider_name: str
    subject: str
    via: Literal["invitation", "self", "admin"]
    display_name: str | None
    display_username: str | None
    last_sign_in_at: datetime | None


class DirectoryInvitation(BaseModel):
    """A pending invitation: when it stops working, and nothing about the code itself."""

    invitation_id: UUID
    provider_id: UUID
    expires_at: datetime


class SignIn(BaseModel):
    """How this person signs in, beside the credentials they hold.

    `has_password` says whether one is set and never anything about it; `pending_until` is
    when an unredeemed set-password code stops working. Neither the hash nor the code's
    digest is read for this view, so neither can reach a response by accident. The name is
    `has_password` rather than `password` because the shared secret guard refuses a key
    called `password` in any rendered output, and a boolean should not be the exception.
    """

    account_owned: bool = False
    email: str | None
    has_password: bool
    pending_until: datetime | None
    identities: list[IdentityRow]
    link: DirectoryLink | None
    invitation: DirectoryInvitation | None


class PersonDetail(BaseModel):
    person: Person
    sign_in: SignIn
    credentials: list[CredentialRow]
    scopes: list[ScopeRow]
    targets: list[TargetOption]
    actions: list[str]
    sessions: list[SessionRow]
    history: History
    history_limit: int
    is_self: bool


class ScopeBody(BaseModel):
    model_config = ConfigDict(extra="forbid")

    target: str = Field(pattern=UUID_PATTERN)
    action: str = Field(min_length=1, max_length=200)


class InviteBody(BaseModel):
    model_config = ConfigDict(extra="forbid")

    provider_id: str = Field(pattern=UUID_PATTERN)
    # The lifetimes the page offers, in hours, and the same four a set-password code offers.
    # The store bounds an invitation to between an hour and fourteen days, so a longer one is
    # simply not offered rather than refused after a click.
    lifetime: Lifetime = "168"


class InvitationBody(BaseModel):
    model_config = ConfigDict(extra="forbid")

    invitation_id: str = Field(pattern=UUID_PATTERN)


class LinkBody(BaseModel):
    model_config = ConfigDict(extra="forbid")

    provider_id: str = Field(pattern=UUID_PATTERN)
    subject: str = Field(min_length=1, max_length=255)


def _directory(call: Any, *args: Any, **kwargs: Any) -> None:
    """One directory write, with its refusal mapped to a code the client has copy for."""
    try:
        call(*args, **kwargs)
    except directory_store.DirectoryError as exc:
        raise sign_in_refused(exc.code) from None


def _detail(data: dict[str, Any]) -> PersonDetail:
    history = data["history"]
    return PersonDetail(
        person=Person.model_validate(data["person"]),
        sign_in=SignIn.model_validate(data["sign_in"]),
        credentials=credential_rows(data["credentials"]),
        scopes=[ScopeRow.model_validate(row) for row in data["scopes"]],
        targets=[TargetOption.model_validate(row) for row in data["targets"]],
        actions=list(data["actions"]),
        sessions=[SessionRow.model_validate(row) for row in data["sessions"]],
        history=History(
            decisions=[DecisionRow.model_validate(row) for row in history["decisions"]],
            sign_ins=[SignInRow.model_validate(row) for row in history["sign_ins"]],
            events=[EventRow.model_validate(row) for row in history["events"]],
        ),
        history_limit=int(data["history_limit"]),
        is_self=bool(data["is_self"]),
    )


def read_detail(runtime: Runtime, session: Session, principal: UUID) -> PersonDetail:
    return _detail(pages.person_overview(runtime, session, principal))


def require_person(
    runtime: Runtime,
    session: Session,
    principal: UUID,
    credential: UUID | None = None,
    *,
    administered: bool = True,
) -> None:
    """404 unless ``principal`` is a human of this tenant (holding ``credential``, if given)
    whom this administrator may administer.

    A principal's kind and a credential's holder never change, so reading them before the
    write's own transaction cannot race. Without this, a change under ``/people`` could
    label or revoke an agent the People page never shows. Since 0072 an administrator
    narrowed to spaces administers only the people whose every seat is in one of their
    `ADMIN` spaces, and a person outside that is answered as one who does not exist; the
    definer function behind each change refuses them again in its own statement.
    ``administered=False`` asks only whether it is a human of this tenant, for a change
    authorised by the space it is written in rather than by the person.
    """
    identity = session.identity
    with runtime.db.transaction(identity.tenant_id) as conn:
        _admin(conn, runtime, session)
        people = administered_clause(conn, session, "p") if administered else NO_SPACE_FILTER
        found = conn.execute(
            text(
                "SELECT EXISTS (SELECT 1 FROM execbound.principals p "
                "WHERE p.tenant_id = :t AND p.principal_id = :p "
                "AND p.kind IN ('HUMAN_APPROVER', 'ADMIN') "
                "AND (CAST(:c AS uuid) IS NULL OR EXISTS (SELECT 1 FROM execbound.credentials c "
                "WHERE c.tenant_id = p.tenant_id AND c.principal_id = p.principal_id "
                "AND c.credential_id = CAST(:c AS uuid)))"
                + people.sql  # nosec B608 - one helper's predicate; values are bound
                + ")"
            ),
            {"t": identity.tenant_id, "p": principal, "c": credential, **people.params},
        ).scalar_one()
    if not found:
        raise HTTPException(404, "Not found")


def people_routes(
    routes: APIRouter, runtime: Runtime, config: HumanConfig, guards: ApiGuards
) -> None:
    @routes.get(
        "/people",
        response_model=PeoplePage,
        operation_id="listPeople",
        openapi_extra=query_parameters(FILTERS),
    )
    async def list_people(request: Request) -> PeoplePage:
        session, _ = await guards.session(request, query=frozenset(FILTERS))
        admin(session)
        filters = filters_from(request.query_params, FILTERS)
        kind = None if filters["kind"] == "any" else filters["kind"]
        data = await run_in_threadpool(
            lambda: pages.people_overview(runtime, session, state=filters["state"], kind=kind)
        )
        return PeoplePage(people=[PersonRow.model_validate(row) for row in data["people"]])

    @routes.post(
        "/people",
        response_model=Created,
        operation_id="createApprover",
        openapi_extra=body_of(LabelBody),
    )
    async def create_approver(request: Request) -> Created:
        session, body = await guards.mutation(request, LabelBody)
        admin(session)
        try:
            principal = await run_in_threadpool(pages.create_approver, runtime, session, body.label)
        except AdministrationError as exc:
            raise refused(exc) from None
        return Created(principal_id=principal)

    @routes.get("/people/{principal_id}", response_model=PersonDetail, operation_id="readPerson")
    async def read_person(request: Request, principal_id: str) -> PersonDetail:
        session, _ = await guards.session(request)
        admin(session)
        return await run_in_threadpool(read_detail, runtime, session, parse_uuid(principal_id))

    async def change(
        request: Request,
        principal_id: str,
        model: type[Any],
        apply: Any,
        *,
        credential: UUID | None = None,
    ) -> PersonDetail:
        """One change to a person: the body, a human of this tenant, the write, and the
        person as they are afterwards."""
        session, body = await guards.mutation(request, model)
        admin(session)
        principal = parse_uuid(principal_id)
        await run_in_threadpool(require_person, runtime, session, principal, credential)
        try:
            await run_in_threadpool(apply, session, principal, body)
        except AdministrationError as exc:
            raise refused(exc) from None
        return await run_in_threadpool(read_detail, runtime, session, principal)

    @routes.post(
        "/people/{principal_id}/label",
        response_model=PersonDetail,
        operation_id="labelPerson",
        openapi_extra=body_of(LabelBody),
    )
    async def label_person(request: Request, principal_id: str) -> PersonDetail:
        def apply(session: Session, principal: UUID, body: LabelBody) -> None:
            pages.label_person(runtime, session, principal, body.label)

        return await change(request, principal_id, LabelBody, apply)

    @routes.post(
        "/people/{principal_id}/email",
        response_model=PersonDetail,
        operation_id="setPersonEmail",
        openapi_extra=body_of(EmailBody),
    )
    async def set_person_email(request: Request, principal_id: str) -> PersonDetail:
        def apply(session: Session, principal: UUID, body: EmailBody) -> None:
            pages.set_email(runtime, session, principal, body.email)

        return await change(request, principal_id, EmailBody, apply)

    @routes.post(
        "/people/{principal_id}/password-link",
        response_model=IssuedCode,
        operation_id="issuePasswordCode",
        openapi_extra=body_of(LifetimeBody),
    )
    async def issue_password_code(request: Request, principal_id: str) -> IssuedCode:
        """One set-password code for a person, shown once beside the page to open.

        The lifetime shares the credential page's choices and is bounded again by the
        function, which also revokes whatever code was pending, so exactly one works.
        """
        session, body = await guards.mutation(request, LifetimeBody)
        admin(session)
        principal = parse_uuid(principal_id)
        await run_in_threadpool(require_person, runtime, session, principal)
        lifetime = lifetime_of(body.lifetime)
        if not MIN_RESET_LIFETIME <= lifetime <= MAX_RESET_LIFETIME:
            raise ApiError("INVALID_BODY", fields=["lifetime"])
        try:
            minted = await run_in_threadpool(
                pages.password_link, runtime, session, principal, lifetime
            )
        except AdministrationError as exc:
            raise refused(exc) from None
        return IssuedCode(
            code=minted["code"],
            address=config.origin + "/set-password",
            reset_id=minted["reset_id"],
            principal_id=minted["principal_id"],
            expires_at=minted["expires_at"],
        )

    @routes.post(
        "/people/{principal_id}/directory-invite",
        response_model=IssuedCode,
        operation_id="inviteToDirectory",
        openapi_extra=body_of(InviteBody),
    )
    async def invite_to_directory(request: Request, principal_id: str) -> IssuedCode:
        """One invitation code for a person, shown once beside the page to open.

        The code is not part of the address: a link carrying one is a code in somebody's
        history, a proxy log and a chat preview.
        """
        session, body = await guards.mutation(request, InviteBody)
        admin(session)
        principal = parse_uuid(principal_id)
        await run_in_threadpool(require_person, runtime, session, principal)
        lifetime = lifetime_of(body.lifetime)
        # The shared choices run to ninety days and an invitation runs to fourteen, so the two
        # that are too long are refused here with the field named rather than at the function.
        if not (
            directory_store.MIN_INVITATION_LIFETIME
            <= lifetime
            <= directory_store.MAX_INVITATION_LIFETIME
        ):
            raise ApiError("INVALID_BODY", fields=["lifetime"])
        try:
            minted = await run_in_threadpool(
                directory_store.invite,
                runtime.db,
                session.identity.tenant_id,
                session.identity.principal_id,
                principal,
                parse_uuid(body.provider_id, 400),
                lifetime=lifetime,
                clock=runtime.clock,
            )
        except directory_store.DirectoryError as exc:
            raise sign_in_refused(exc.code) from None
        return IssuedCode(
            code=minted.code,
            address=config.origin + "/invite",
            reset_id=minted.invitation_id,
            principal_id=minted.principal_id,
            expires_at=minted.expires_at,
        )

    @routes.post(
        "/people/{principal_id}/directory-invite/revoke",
        response_model=PersonDetail,
        operation_id="revokeDirectoryInvitation",
        openapi_extra=body_of(InvitationBody),
    )
    async def revoke_directory_invitation(request: Request, principal_id: str) -> PersonDetail:
        def apply(session: Session, principal: UUID, body: InvitationBody) -> None:
            _directory(
                directory_store.revoke_invitation,
                runtime.db,
                session.identity.tenant_id,
                session.identity.principal_id,
                parse_uuid(body.invitation_id, 400),
                clock=runtime.clock,
            )

        return await change(request, principal_id, InvitationBody, apply)

    @routes.post(
        "/people/{principal_id}/directory-link",
        response_model=PersonDetail,
        operation_id="linkPersonToDirectory",
        openapi_extra=body_of(LinkBody),
    )
    async def link_person_to_directory(request: Request, principal_id: str) -> PersonDetail:
        """Bind a person to an account an administrator already knows the identifier of."""

        def apply(session: Session, principal: UUID, body: LinkBody) -> None:
            _directory(
                directory_store.link_person,
                runtime.db,
                session.identity.tenant_id,
                session.identity.principal_id,
                principal,
                parse_uuid(body.provider_id, 400),
                body.subject,
                clock=runtime.clock,
            )

        return await change(request, principal_id, LinkBody, apply)

    @routes.post(
        "/people/{principal_id}/directory-unlink",
        response_model=PersonDetail,
        operation_id="unlinkPersonFromDirectory",
        openapi_extra=body_of(Empty),
    )
    async def unlink_person_from_directory(request: Request, principal_id: str) -> PersonDetail:
        def apply(session: Session, principal: UUID, body: Empty) -> None:
            _directory(
                directory_store.unlink_person,
                runtime.db,
                session.identity.tenant_id,
                session.identity.principal_id,
                principal,
                clock=runtime.clock,
            )

        return await change(request, principal_id, Empty, apply)

    @routes.post(
        "/people/{principal_id}/credentials/issue",
        response_model=IssuedCredential,
        operation_id="issuePersonCredential",
        openapi_extra=body_of(LifetimeBody),
    )
    async def issue_person_credential(request: Request, principal_id: str) -> IssuedCredential:
        session, body = await guards.mutation(request, LifetimeBody)
        admin(session)
        principal = parse_uuid(principal_id)
        await run_in_threadpool(require_person, runtime, session, principal)
        try:
            issued = await run_in_threadpool(
                issue,
                runtime,
                session,
                principal=principal,
                kind=None,
                lifetime=lifetime_of(body.lifetime),
            )
        except AdministrationError as exc:
            raise refused(exc) from None
        return issued_view(issued)

    @routes.post(
        "/people/{principal_id}/credentials/{credential_id}/revoke",
        response_model=PersonDetail,
        operation_id="revokePersonCredential",
        openapi_extra=body_of(Empty),
    )
    async def revoke_person_credential(
        request: Request, principal_id: str, credential_id: str
    ) -> PersonDetail:
        credential = parse_uuid(credential_id)

        def apply(session: Session, principal: UUID, body: Empty) -> None:
            revoke(runtime, session, credential)

        return await change(request, principal_id, Empty, apply, credential=credential)

    async def scope(request: Request, principal_id: str, *, active: bool) -> Any:
        """A scope is a write on the space it lands in, not on the person (#678): it is
        authorised exactly as `/approvers/assign` authorises it, by the definer function's
        check of the space, so the person need only be a human of this tenant. The answer is
        the person as the reader may see them, or no content where the reader may not
        administer them, as an administrator assigning themselves from an approval may not."""
        session, body = await guards.mutation(request, ScopeBody)
        admin(session)
        principal = parse_uuid(principal_id)
        await run_in_threadpool(
            require_person, runtime, session, principal, None, administered=False
        )
        try:
            await run_in_threadpool(
                lambda: assign(
                    runtime,
                    session,
                    principal,
                    parse_uuid(body.target, 400),
                    body.action,
                    active=active,
                )
            )
        except AdministrationError as exc:
            raise refused(exc) from None
        try:
            return await run_in_threadpool(read_detail, runtime, session, principal)
        except HTTPException as exc:
            if exc.status_code != 404:
                raise
            return Response(status_code=204)

    @routes.post(
        "/people/{principal_id}/scopes/assign",
        response_model=PersonDetail,
        operation_id="assignPersonScope",
        openapi_extra=body_of(ScopeBody),
        responses={204: {"description": "Assigned; the reader may not administer this person."}},
    )
    async def assign_scope(request: Request, principal_id: str) -> Any:
        return await scope(request, principal_id, active=True)

    @routes.post(
        "/people/{principal_id}/scopes/unassign",
        response_model=PersonDetail,
        operation_id="unassignPersonScope",
        openapi_extra=body_of(ScopeBody),
        responses={204: {"description": "Unassigned; the reader may not administer this person."}},
    )
    async def unassign_scope(request: Request, principal_id: str) -> Any:
        return await scope(request, principal_id, active=False)

    @routes.post(
        "/people/{principal_id}/sessions/end",
        response_model=PersonDetail,
        operation_id="endPersonSessions",
        openapi_extra=body_of(Empty),
    )
    async def end_sessions(request: Request, principal_id: str) -> PersonDetail:
        def apply(session: Session, principal: UUID, body: Empty) -> None:
            # The acting administrator's own sessions belong on Settings, as on the page.
            if principal == session.identity.principal_id:
                raise ApiError("INVALID_PRINCIPAL")
            revoke_sessions_of(runtime.db, session, principal, reason="ADMIN", clock=runtime.clock)

        return await change(request, principal_id, Empty, apply)

    @routes.post(
        "/people/{principal_id}/deactivate",
        response_model=PersonDetail,
        operation_id="deactivatePerson",
        openapi_extra=body_of(ReasonBody),
    )
    async def deactivate_person(request: Request, principal_id: str) -> PersonDetail:
        def apply(session: Session, principal: UUID, body: ReasonBody) -> None:
            pages.deactivate(runtime, session, principal, body.reason)

        return await change(request, principal_id, ReasonBody, apply)

    @routes.post(
        "/people/{principal_id}/reactivate",
        response_model=PersonDetail,
        operation_id="reactivatePerson",
        openapi_extra=body_of(Empty),
    )
    async def reactivate_person(request: Request, principal_id: str) -> PersonDetail:
        def apply(session: Session, principal: UUID, body: Empty) -> None:
            pages.reactivate(runtime, session, principal)

        return await change(request, principal_id, Empty, apply)
