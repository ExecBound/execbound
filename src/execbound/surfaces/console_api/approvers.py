# SPDX-License-Identifier: AGPL-3.0-only
"""`/api/console/v1/approvers`: the scope matrix by approver, target and action, as JSON.

Every route wraps the function the approvers page calls today (`surfaces/admin_pages.py`),
under an administrator's session, the same fence and the same bounds: the active assignments
with the approvers, canonical targets and catalog actions the assign form offers, an
assignment made, an assignment withdrawn. The definer functions decide what may be assigned:
an active approver of this tenant, a canonical target of this tenant, an action of the catalog
(#333).
"""

from typing import Any
from uuid import UUID

from fastapi import APIRouter, Request
from pydantic import BaseModel, ConfigDict, Field
from starlette.concurrency import run_in_threadpool

from execbound.administration import AdministrationError
from execbound.operations import PRODUCTION_ACTIONS
from execbound.runtime import Runtime
from execbound.surfaces.admin_pages import approvers_overview, assign
from execbound.surfaces.console_api.directory import (
    UUID_PATTERN,
    admin,
    body_of,
    parse_uuid,
    refused,
)
from execbound.surfaces.console_api.guards import ApiGuards
from execbound.surfaces.human import HumanConfig
from execbound.surfaces.sessions import Session


class Assignment(BaseModel):
    approver_id: UUID
    # What names the approver: the label, else the email, else "User 3" by their counting
    # number among the workspace's people (0062), a display handle only.
    label: str | None
    email: str | None
    number: int
    canonical_target_id: UUID
    labels: str | None
    action: str


class ApproverOption(BaseModel):
    principal_id: UUID
    label: str | None
    email: str | None
    number: int


class TargetOption(BaseModel):
    canonical_target_id: UUID
    labels: str | None


class ApproversPage(BaseModel):
    assignments: list[Assignment]
    approvers: list[ApproverOption]
    targets: list[TargetOption]
    actions: list[str]


class AssignmentBody(BaseModel):
    model_config = ConfigDict(extra="forbid")

    approver: str = Field(pattern=UUID_PATTERN)
    target: str = Field(pattern=UUID_PATTERN)
    action: str = Field(min_length=1, max_length=200)


def _page(data: dict[str, Any]) -> ApproversPage:
    names: dict[UUID, dict[str, Any]] = data["names"]
    targets = {row["canonical_target_id"]: row["labels"] for row in data["targets"]}

    def named(principal: UUID) -> dict[str, Any]:
        row = names[principal]
        return {"label": row["label"], "email": row["email"], "number": row["number"]}

    return ApproversPage(
        assignments=[
            Assignment(
                approver_id=row["approver_id"],
                **named(row["approver_id"]),
                canonical_target_id=row["canonical_target_id"],
                labels=targets.get(row["canonical_target_id"]),
                action=row["action"],
            )
            for row in data["assignments"]
        ],
        approvers=[
            ApproverOption(principal_id=principal, **named(principal))
            for principal in data["approvers"]
        ],
        targets=[TargetOption.model_validate(row) for row in data["targets"]],
        actions=sorted(PRODUCTION_ACTIONS.names),
    )


def read_page(runtime: Runtime, session: Session) -> ApproversPage:
    return _page(approvers_overview(runtime, session))


def approvers_routes(
    routes: APIRouter, runtime: Runtime, config: HumanConfig, guards: ApiGuards
) -> None:
    @routes.get("/approvers", response_model=ApproversPage, operation_id="listApproverScopes")
    async def list_scopes(request: Request) -> ApproversPage:
        session, _ = await guards.session(request)
        admin(session)
        return await run_in_threadpool(read_page, runtime, session)

    async def assignment(request: Request, *, active: bool) -> ApproversPage:
        session, body = await guards.mutation(request, AssignmentBody)
        admin(session)
        approver = parse_uuid(body.approver, 400)
        target = parse_uuid(body.target, 400)
        try:
            await run_in_threadpool(
                lambda: assign(runtime, session, approver, target, body.action, active=active)
            )
        except AdministrationError as exc:
            raise refused(exc) from None
        return await run_in_threadpool(read_page, runtime, session)

    @routes.post(
        "/approvers/assign",
        response_model=ApproversPage,
        operation_id="assignApproverScope",
        openapi_extra=body_of(AssignmentBody),
    )
    async def assign_scope(request: Request) -> ApproversPage:
        return await assignment(request, active=True)

    @routes.post(
        "/approvers/unassign",
        response_model=ApproversPage,
        operation_id="unassignApproverScope",
        openapi_extra=body_of(AssignmentBody),
    )
    async def unassign_scope(request: Request) -> ApproversPage:
        return await assignment(request, active=False)
