# SPDX-License-Identifier: AGPL-3.0-only
"""`/api/console/v1/spaces`: the spaces of one tenant, as JSON.

Every route wraps the function `surfaces/space_pages.py` opens a fenced transaction for,
under the console API's own guards: the session cookie and nothing else, a bearer
credential refused 403 and audited, the exact `Origin`, `X-CSRF-Token` and
`application/json` on every mutation, a bounded body with no duplicate or undeclared key,
and a typed JSON refusal.

The authority is membership, not the session's current space: a space that is unknown,
another tenant's or outside the person's visible set answers `NOT_FOUND` alike, so the
answer says nothing about what exists. Administration is a **tenant** administrator's,
which is an active `ADMIN` principal with no membership at all; the definer functions decide
that, not this module.

`POST /session/space` lives in the session area beside `GET /session`, because it changes
the session and answers the fresh session view.
"""

import base64
from datetime import datetime
from typing import Any, Literal
from uuid import UUID

from fastapi import APIRouter, Request
from pydantic import BaseModel, ConfigDict, Field
from starlette.concurrency import run_in_threadpool

from execbound.runtime import Runtime
from execbound.spaces import (
    MAX_DETAIL_LENGTH,
    MAX_NAME_LENGTH,
    MAX_REASON_LENGTH,
    SpaceError,
)
from execbound.surfaces import space_pages as pages
from execbound.surfaces.console_api.directory import (
    UUID_PATTERN,
    body_of,
    parse_uuid,
    query_parameters,
)
from execbound.surfaces.console_api.errors import ApiError
from execbound.surfaces.console_api.guards import ApiGuards
from execbound.surfaces.human import HumanConfig
from execbound.surfaces.sessions import Session

SPACE_QUERY = frozenset({"state", "q", "cursor"})
FILTERS: dict[str, tuple[str, ...]] = {"state": pages.STATES}
CURSOR_MAX = 256

# A definer function's refusal as the API's typed code, and, for a body fault, its field.
# The codes come from the existing closed list; `SPACE_ARCHIVED` is the one addition,
# because "this space takes no new work" is not "this change was already made" and the
# console's copy has to say which.
REFUSALS: dict[str, tuple[str, list[str] | None]] = {
    "INVALID_NAME": ("INVALID_BODY", ["name"]),
    "NAME_TAKEN": ("CONFLICT", None),
    "INVALID_ROLE": ("INVALID_BODY", ["role"]),
    "INVALID_PRINCIPAL": ("INVALID_PRINCIPAL", None),
    "LAST_TENANT_ADMIN": ("CONFLICT", None),
    "SPACE_ARCHIVED": ("SPACE_ARCHIVED", None),
    "CONFLICT": ("CONFLICT", None),
    "INVALID_SPACE": ("NOT_FOUND", None),
    "INVALID_SESSION": ("SESSION_REQUIRED", None),
    "INVALID_ACTOR": ("FORBIDDEN", None),
    "INVALID_TENANT": ("FORBIDDEN", None),
}


def refused(exc: SpaceError) -> ApiError:
    """The typed refusal for a function's code; anything unlisted is unavailability."""
    code, fields = REFUSALS.get(exc.code, ("UNAVAILABLE", None))
    return ApiError(code, fields=fields)


class SpaceRow(BaseModel):
    space_id: UUID
    name: str
    detail: str | None
    created_at: datetime
    archived_at: datetime | None
    members: int
    agents: int
    pending: int
    findings: int


class SpacePage(BaseModel):
    items: list[SpaceRow]
    next_cursor: str | None
    # Whether this person may administer spaces at all, and whether "All spaces" is worth
    # offering them: a visible set of one space has nothing to switch between.
    administrator: bool
    all_spaces: bool
    current_space_id: UUID | None


class MemberRow(BaseModel):
    principal_id: UUID
    label: str | None
    # What names a member without a label: their email, else their counting number in the
    # workspace, "User 3" (0062), a display handle only.
    email: str | None
    number: int
    kind: Literal["ADMIN", "HUMAN_APPROVER", "AGENT"]
    role: Literal["ADMIN", "HUMAN_APPROVER"]
    assigned_at: datetime


class SelectionRow(BaseModel):
    bundle_id: UUID
    changed_at: datetime


class OfferedRow(BaseModel):
    kind: Literal["connector_account", "policy_bundle"]
    object_id: UUID
    label: str | None


class SpaceDetail(BaseModel):
    space: SpaceRow
    members: list[MemberRow]
    selection: SelectionRow | None
    offered: list[OfferedRow]
    administrator: bool


class Created(BaseModel):
    space_id: UUID


class NameBody(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str = Field(min_length=1, max_length=MAX_NAME_LENGTH)
    detail: str | None = Field(default=None, max_length=MAX_DETAIL_LENGTH)


class ReasonBody(BaseModel):
    model_config = ConfigDict(extra="forbid")

    reason: str = Field(min_length=1, max_length=MAX_REASON_LENGTH)


class AssignBody(BaseModel):
    model_config = ConfigDict(extra="forbid")

    principal_id: str = Field(pattern=UUID_PATTERN)
    role: Literal["ADMIN", "HUMAN_APPROVER"]


class UnassignBody(BaseModel):
    model_config = ConfigDict(extra="forbid")

    principal_id: str = Field(pattern=UUID_PATTERN)


def encode_space_cursor(name: str, space_id: UUID) -> str:
    """An opaque page position over `(lower(name), space_id)`, the list's own order.

    It bounds a read inside the reader's own visible set and nowhere else, exactly as the
    activity cursor bounds one inside the reader's own tenant.
    """
    return (
        base64.urlsafe_b64encode(f"{name.lower()}|{space_id}".encode()).decode("ascii").rstrip("=")
    )


def decode_space_cursor(value: str) -> tuple[str, UUID]:
    if len(value) > CURSOR_MAX:
        raise ValueError("Cursor too long")
    padded = value + "=" * (-len(value) % 4)
    raw = base64.urlsafe_b64decode(padded.encode("ascii")).decode("utf-8")
    name, separator, identifier = raw.rpartition("|")
    if not separator:
        raise ValueError("Malformed cursor")
    return name, UUID(identifier)


def _row(row: dict[str, Any]) -> SpaceRow:
    return SpaceRow.model_validate(row)


def read_page(
    runtime: Runtime, session: Session, *, query: str | None, state: str, cursor: str | None
) -> SpacePage:
    position = None
    if cursor:
        try:
            position = decode_space_cursor(cursor)
        except ValueError:
            raise ApiError("INVALID_REQUEST") from None
    data = pages.spaces_overview(
        runtime,
        session,
        query=query,
        state=state,
        cursor=position,
        limit=pages.PAGE_SIZE + 1,
    )
    rows = data["spaces"]
    next_cursor = None
    if len(rows) > pages.PAGE_SIZE:
        rows = rows[: pages.PAGE_SIZE]
        last = rows[-1]
        next_cursor = encode_space_cursor(last["name"], last["space_id"])
    visibility = data["visibility"]
    return SpacePage(
        items=[_row(row) for row in rows],
        next_cursor=next_cursor,
        administrator=bool(data["administrator"]),
        all_spaces=visibility.allows_many(int(data["visible"])),
        current_space_id=visibility.current,
    )


def read_detail(runtime: Runtime, session: Session, space: UUID) -> SpaceDetail:
    data = pages.space_overview(runtime, session, space)
    return SpaceDetail(
        space=_row(data["space"]),
        members=[MemberRow.model_validate(row) for row in data["members"]],
        selection=(
            SelectionRow.model_validate(data["selection"])
            if data["selection"] is not None
            else None
        ),
        offered=[OfferedRow.model_validate(row) for row in data["offered"]],
        administrator=bool(data["administrator"]),
    )


def spaces_routes(
    routes: APIRouter, runtime: Runtime, config: HumanConfig, guards: ApiGuards
) -> None:
    @routes.get(
        "/spaces",
        response_model=SpacePage,
        operation_id="listSpaces",
        openapi_extra=query_parameters(FILTERS, cursor=True),
    )
    async def list_spaces(request: Request) -> SpacePage:
        session, _ = await guards.session(request, query=SPACE_QUERY)
        values = dict(request.query_params.multi_items())
        state = values.get("state", pages.STATES[0])
        if state not in pages.STATES:
            raise ApiError("INVALID_REQUEST")
        query = values.get("q")
        if query is not None and not 1 <= len(query) <= pages.MAX_QUERY_LENGTH:
            raise ApiError("INVALID_REQUEST")
        try:
            return await run_in_threadpool(
                read_page,
                runtime,
                session,
                query=query,
                state=state,
                cursor=values.get("cursor"),
            )
        except SpaceError as exc:
            raise refused(exc) from None

    @routes.post(
        "/spaces",
        response_model=Created,
        operation_id="createSpace",
        openapi_extra=body_of(NameBody),
    )
    async def create_space(request: Request) -> Created:
        session, body = await guards.mutation(request, NameBody, kind="ADMIN")
        try:
            space = await run_in_threadpool(pages.create, runtime, session, body.name, body.detail)
        except SpaceError as exc:
            raise refused(exc) from None
        return Created(space_id=space)

    @routes.get("/spaces/{space_id}", response_model=SpaceDetail, operation_id="readSpace")
    async def read_space(request: Request, space_id: str) -> SpaceDetail:
        session, _ = await guards.session(request)
        space = parse_uuid(space_id)
        try:
            return await run_in_threadpool(read_detail, runtime, session, space)
        except SpaceError as exc:
            raise refused(exc) from None

    @routes.post(
        "/spaces/{space_id}/rename",
        response_model=SpaceDetail,
        operation_id="renameSpace",
        openapi_extra=body_of(NameBody),
    )
    async def rename_space(request: Request, space_id: str) -> SpaceDetail:
        session, body = await guards.mutation(request, NameBody, kind="ADMIN")
        space = parse_uuid(space_id)
        try:
            await run_in_threadpool(pages.rename, runtime, session, space, body.name, body.detail)
            return await run_in_threadpool(read_detail, runtime, session, space)
        except SpaceError as exc:
            raise refused(exc) from None

    async def _state(request: Request, space_id: str, *, archived: bool) -> SpaceDetail:
        session, body = await guards.mutation(request, ReasonBody, kind="ADMIN")
        space = parse_uuid(space_id)
        change = pages.archive if archived else pages.unarchive
        try:
            await run_in_threadpool(change, runtime, session, space, body.reason)
            return await run_in_threadpool(read_detail, runtime, session, space)
        except SpaceError as exc:
            if exc.code == "INVALID_NAME":
                # `_reason` kept the existing `INVALID_NAME` code rather than invent one,
                # but `ReasonBody` carries only a reason: the shared `refused()` mapping
                # names "name", which is wrong here and fits nothing on this form.
                raise ApiError("INVALID_BODY", fields=["reason"]) from None
            raise refused(exc) from None

    @routes.post(
        "/spaces/{space_id}/archive",
        response_model=SpaceDetail,
        operation_id="archiveSpace",
        openapi_extra=body_of(ReasonBody),
    )
    async def archive_space(request: Request, space_id: str) -> SpaceDetail:
        return await _state(request, space_id, archived=True)

    @routes.post(
        "/spaces/{space_id}/unarchive",
        response_model=SpaceDetail,
        operation_id="unarchiveSpace",
        openapi_extra=body_of(ReasonBody),
    )
    async def unarchive_space(request: Request, space_id: str) -> SpaceDetail:
        return await _state(request, space_id, archived=False)

    @routes.post(
        "/spaces/{space_id}/members/assign",
        response_model=SpaceDetail,
        operation_id="assignSpaceMember",
        openapi_extra=body_of(AssignBody),
    )
    async def assign_member(request: Request, space_id: str) -> SpaceDetail:
        session, body = await guards.mutation(request, AssignBody, kind="ADMIN")
        space = parse_uuid(space_id)
        principal = parse_uuid(body.principal_id, 400)
        try:
            await run_in_threadpool(pages.assign, runtime, session, space, principal, body.role)
            return await run_in_threadpool(read_detail, runtime, session, space)
        except SpaceError as exc:
            raise refused(exc) from None

    @routes.post(
        "/spaces/{space_id}/members/unassign",
        response_model=SpaceDetail,
        operation_id="unassignSpaceMember",
        openapi_extra=body_of(UnassignBody),
    )
    async def unassign_member(request: Request, space_id: str) -> SpaceDetail:
        session, body = await guards.mutation(request, UnassignBody, kind="ADMIN")
        space = parse_uuid(space_id)
        principal = parse_uuid(body.principal_id, 400)
        try:
            await run_in_threadpool(pages.unassign, runtime, session, space, principal)
            return await run_in_threadpool(read_detail, runtime, session, space)
        except SpaceError as exc:
            raise refused(exc) from None
