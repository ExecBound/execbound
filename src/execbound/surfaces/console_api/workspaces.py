# SPDX-License-Identifier: AGPL-3.0-only
"""`/api/console/v1/session/workspaces`, `/session/workspace`: switching between an account's
own workspaces (#238).
"""

from datetime import datetime
from typing import Literal
from uuid import UUID

from fastapi import APIRouter, Request
from pydantic import BaseModel, ConfigDict, Field
from starlette.concurrency import run_in_threadpool
from starlette.responses import JSONResponse, Response

from execbound.runtime import Runtime
from execbound.surfaces.console_api.directory import UUID_PATTERN, body_of
from execbound.surfaces.console_api.guards import ApiGuards
from execbound.surfaces.human import HumanConfig, _session_cookies
from execbound.surfaces.login_return import remember_section
from execbound.surfaces.sections import Section
from execbound.workspaces import list_workspaces, switch_workspace


class WorkspaceBody(BaseModel):
    model_config = ConfigDict(extra="forbid")
    tenant_id: str = Field(pattern=UUID_PATTERN)
    # The section the person is on, so the switch lands on the same page of the other
    # workspace. A closed set of page roots: never a record, a query or another address.
    section: Section | None = None


RoleId = Literal["administrator", "policy_manager", "approver", "viewer"]
Entry = Literal["open", "factor", "enrol", "directory"]
Waiting = Literal["current", "counted", "withheld", "not_counted"]


class WorkspaceItem(BaseModel):
    tenant_id: UUID
    name: str
    current: bool
    # The kind a session there would carry, and the roles held across that whole workspace.
    kind: Literal["ADMIN", "HUMAN_APPROVER"]
    roles: list[RoleId]
    # What entering it asks beyond this sign-in.
    entry: Entry
    # A count of this account's own waiting approvals crosses the boundary, never a record,
    # and only where entering asks nothing more: `counted` carries it, `withheld` is a
    # workspace that would ask for more proof, `not_counted` one past the cap.
    waiting_state: Waiting
    waiting: int | None
    next_lapse: datetime | None
    # When this account last entered it, by signing in there or switching to it; null for one
    # it has never entered. The account's own record, which orders the menu.
    last_entered_at: datetime | None


class WorkspaceList(BaseModel):
    workspaces: list[WorkspaceItem]


class WorkspaceSelection(BaseModel):
    # The section asked for when the new session may open it, else where that session starts;
    # or the second factor, after which the person lands on that section. Always a member of
    # a closed set, so the answer can never become an open redirect.
    location: Literal["/mfa"] | Section


def workspace_routes(
    routes: APIRouter, runtime: Runtime, config: HumanConfig, guards: ApiGuards
) -> None:
    @routes.get("/session/workspaces", response_model=WorkspaceList, operation_id="readWorkspaces")
    async def workspaces(request: Request) -> WorkspaceList:
        current, _ = await guards.session(request)
        available = await run_in_threadpool(
            list_workspaces,
            runtime.db,
            current,
            request.cookies.get(config.cookie("account"), ""),
            clock=runtime.clock,
            waiting=True,
        )
        return WorkspaceList(workspaces=[WorkspaceItem.model_validate(item) for item in available])

    @routes.post(
        "/session/workspace",
        response_model=WorkspaceSelection,
        operation_id="selectWorkspace",
        openapi_extra=body_of(WorkspaceBody),
    )
    async def select_workspace(request: Request) -> Response:
        current, body = await guards.mutation(request, WorkspaceBody)
        grant = await run_in_threadpool(
            switch_workspace,
            runtime.db,
            current,
            request.cookies.get(config.cookie("account"), ""),
            UUID(body.tenant_id),
            section=body.section,
            clock=runtime.clock,
        )
        # Renewal of the source session must never overwrite the destination cookies.
        request.state.session_renewal = None
        assert grant.place is not None
        response = _session_cookies(
            JSONResponse({"location": "/mfa" if grant.mfa_required else grant.place}),
            config,
            runtime,
            grant,
        )
        if grant.mfa_required:
            # The verification page lands the person on the section once the code is right.
            remember_section(response, config, runtime, grant.place)
        return response
