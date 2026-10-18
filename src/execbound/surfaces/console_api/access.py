# SPDX-License-Identifier: AGPL-3.0-only
"""Session-only management of human roles and groups; stores recheck every permission."""

from typing import Any, Literal
from uuid import UUID

from fastapi import APIRouter, Request
from pydantic import BaseModel, ConfigDict, Field
from starlette.concurrency import run_in_threadpool

from execbound import access_control as access
from execbound.runtime import Runtime
from execbound.surfaces.console_api.directory import UUID_PATTERN, body_of, parse_uuid
from execbound.surfaces.console_api.errors import ApiError
from execbound.surfaces.console_api.guards import ApiGuards
from execbound.surfaces.human import HumanConfig

RoleId = Literal["administrator", "policy_manager", "approver", "viewer"]


class AccessGrant(BaseModel):
    model_config = ConfigDict(extra="forbid")
    role: RoleId
    space_id: UUID | None = None


class InheritedAccessGrant(BaseModel):
    role: RoleId
    space_id: UUID | None
    group_id: UUID
    group_name: str


class AccessRole(BaseModel):
    id: RoleId
    name: str
    description: str
    permissions: list[str]
    scopes: list[str]


class AccessUser(BaseModel):
    principal_id: UUID
    label: str | None
    email: str | None
    # The person's counting number in the workspace, "User 3" (0062); a display handle only.
    number: int
    kind: str
    active: bool
    managed: bool
    direct_roles: list[AccessGrant]
    inherited_roles: list[InheritedAccessGrant]


class AccessGroup(BaseModel):
    group_id: UUID
    name: str
    description: str | None
    members: list[UUID]
    roles: list[AccessGrant]


class AccessSpace(BaseModel):
    space_id: UUID
    name: str


class AccessPage(BaseModel):
    roles: list[AccessRole]
    users: list[AccessUser]
    groups: list[AccessGroup]
    spaces: list[AccessSpace]


class AccessReason(BaseModel):
    model_config = ConfigDict(extra="forbid")
    reason: str = Field(min_length=1, max_length=500)


class AccessGrantInput(BaseModel):
    model_config = ConfigDict(extra="forbid")
    role: RoleId
    space_id: str | None = Field(default=None, pattern=UUID_PATTERN)


class RoleAssignments(AccessReason):
    grants: list[AccessGrantInput] = Field(max_length=100)


class GroupDetails(AccessReason):
    name: str = Field(min_length=1, max_length=80)
    description: str | None = Field(default=None, max_length=240)


class GroupMembers(AccessReason):
    members: list[str] = Field(max_length=100)


class CreatedGroup(BaseModel):
    group_id: UUID


class AccessChanged(BaseModel):
    changed: bool = True


# A definer function's refusal, as the API's typed code and, for a body fault, its field.
REFUSALS: dict[str, tuple[str, list[str] | None]] = {
    "FORBIDDEN": ("FORBIDDEN", None),
    "INVALID_ACTOR": ("FORBIDDEN", None),
    "NOT_FOUND": ("NOT_FOUND", None),
    "INVALID_PRINCIPAL": ("INVALID_PRINCIPAL", None),
    "INVALID_SPACE": ("NOT_FOUND", None),
    "LAST_ADMIN": ("LAST_ADMIN", None),
    "LAST_TENANT_ADMIN": ("LAST_ADMIN", None),
    "LAST_ADMINISTRATOR": ("LAST_ADMIN", None),
    "CONFLICT": ("CONFLICT", None),
    "GROUP_IN_USE": ("GROUP_IN_USE", None),
    "NAME_TAKEN": ("CONFLICT", None),
    "INVALID_ROLE": ("INVALID_BODY", None),
    # `_change` screens name and description together (`secret_shaped(name, description)`)
    # and cannot say which one was shaped like a secret, so both are named; a person
    # checks the one they meant to change.
    "INVALID_NAME": ("INVALID_BODY", ["name", "description"]),
    "INVALID_REASON": ("INVALID_BODY", ["reason"]),
    "INVALID_MEMBERS": ("INVALID_BODY", None),
    "INVALID_GRANTS": ("INVALID_BODY", None),
    "INVALID_BODY": ("INVALID_BODY", None),
    "INVALID_ROLES": ("INVALID_BODY", None),
    "INVALID_ROLE_SCOPE": ("INVALID_BODY", None),
}


def refused(exc: access.AccessError) -> ApiError:
    code, fields = REFUSALS.get(exc.code, ("UNAVAILABLE", None))
    return ApiError(code, fields=fields)


def _page(runtime: Runtime, session: Any) -> AccessPage:
    try:
        return AccessPage.model_validate(access.read_access(runtime, session))
    except access.AccessError as exc:
        raise refused(exc) from None


def access_routes(
    routes: APIRouter, runtime: Runtime, config: HumanConfig, guards: ApiGuards
) -> None:
    @routes.get("/access", response_model=AccessPage, operation_id="readAccess")
    async def read(request: Request) -> AccessPage:
        session, _ = await guards.session(request)
        return await run_in_threadpool(_page, runtime, session)

    @routes.post(
        "/access/users/{principal_id}/roles",
        response_model=AccessChanged,
        operation_id="setUserRoles",
        openapi_extra=body_of(RoleAssignments),
    )
    async def user_roles(request: Request, principal_id: str) -> AccessChanged:
        session, body = await guards.mutation(request, RoleAssignments)
        principal = parse_uuid(principal_id)
        try:
            await run_in_threadpool(
                access.set_user_roles,
                runtime,
                session,
                principal,
                [row.model_dump() for row in body.grants],
                body.reason,
            )
        except access.AccessError as exc:
            raise refused(exc) from None
        return AccessChanged()

    @routes.post(
        "/access/groups",
        response_model=CreatedGroup,
        operation_id="createAccessGroup",
        openapi_extra=body_of(GroupDetails),
    )
    async def create(request: Request) -> CreatedGroup:
        session, body = await guards.mutation(request, GroupDetails)
        try:
            identifier = await run_in_threadpool(
                access.create_group, runtime, session, body.name, body.description, body.reason
            )
        except access.AccessError as exc:
            raise refused(exc) from None
        return CreatedGroup(group_id=identifier)

    @routes.post(
        "/access/groups/{group_id}",
        response_model=AccessChanged,
        operation_id="updateAccessGroup",
        openapi_extra=body_of(GroupDetails),
    )
    async def update(request: Request, group_id: str) -> AccessChanged:
        session, body = await guards.mutation(request, GroupDetails)
        group = parse_uuid(group_id)
        try:
            await run_in_threadpool(
                access.update_group,
                runtime,
                session,
                group,
                body.name,
                body.description,
                body.reason,
            )
        except access.AccessError as exc:
            raise refused(exc) from None
        return AccessChanged()

    @routes.post(
        "/access/groups/{group_id}/members",
        response_model=AccessChanged,
        operation_id="setGroupMembers",
        openapi_extra=body_of(GroupMembers),
    )
    async def members(request: Request, group_id: str) -> AccessChanged:
        session, body = await guards.mutation(request, GroupMembers)
        group = parse_uuid(group_id)
        # Canonical spellings only; a bad member never produces a database diagnostic.
        people = [parse_uuid(member, 400) for member in body.members]
        try:
            await run_in_threadpool(
                access.set_group_members, runtime, session, group, people, body.reason
            )
        except access.AccessError as exc:
            raise refused(exc) from None
        return AccessChanged()

    @routes.post(
        "/access/groups/{group_id}/delete",
        response_model=AccessChanged,
        operation_id="deleteAccessGroup",
        openapi_extra=body_of(AccessReason),
    )
    async def delete(request: Request, group_id: str) -> AccessChanged:
        session, body = await guards.mutation(request, AccessReason)
        group = parse_uuid(group_id)
        try:
            await run_in_threadpool(access.delete_group, runtime, session, group, body.reason)
        except access.AccessError as exc:
            raise refused(exc) from None
        return AccessChanged()

    @routes.post(
        "/access/groups/{group_id}/roles",
        response_model=AccessChanged,
        operation_id="setGroupRoles",
        openapi_extra=body_of(RoleAssignments),
    )
    async def group_roles(request: Request, group_id: str) -> AccessChanged:
        session, body = await guards.mutation(request, RoleAssignments)
        group = parse_uuid(group_id)
        try:
            await run_in_threadpool(
                access.set_group_roles,
                runtime,
                session,
                group,
                [row.model_dump() for row in body.grants],
                body.reason,
            )
        except access.AccessError as exc:
            raise refused(exc) from None
        return AccessChanged()
