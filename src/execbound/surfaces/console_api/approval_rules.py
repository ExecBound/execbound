# SPDX-License-Identifier: AGPL-3.0-only
"""Bounded, session-only approval group rule management."""

from uuid import UUID

from fastapi import APIRouter, Request
from pydantic import BaseModel, Field
from starlette.concurrency import run_in_threadpool

from execbound import approval_rules as rules
from execbound.runtime import Runtime
from execbound.surfaces.console_api.access import AccessReason
from execbound.surfaces.console_api.directory import UUID_PATTERN, body_of, parse_uuid
from execbound.surfaces.console_api.errors import ApiError
from execbound.surfaces.console_api.guards import ApiGuards
from execbound.surfaces.human import HumanConfig


class ApprovalRule(BaseModel):
    rule_id: UUID
    name: str
    space_id: UUID
    space_name: str
    group_id: UUID
    group_name: str
    actions: list[str]
    targets: list[UUID]
    active: bool
    eligible_reviewers: int


class ApprovalAction(BaseModel):
    id: str
    name: str


class ApprovalRulesPage(BaseModel):
    rules: list[ApprovalRule]
    actions: list[ApprovalAction]


class ApprovalRuleBody(AccessReason):
    name: str = Field(min_length=1, max_length=80)
    space_id: str = Field(pattern=UUID_PATTERN)
    group_id: str = Field(pattern=UUID_PATTERN)
    actions: list[str] = Field(min_length=1, max_length=20)
    targets: list[str] = Field(min_length=1, max_length=100)


class SavedApprovalRule(BaseModel):
    rule_id: UUID


def refused(exc: rules.ApprovalRuleError) -> ApiError:
    codes = {
        "INVALID_ACTOR": "FORBIDDEN",
        "INVALID_TENANT": "FORBIDDEN",
        "NOT_FOUND": "NOT_FOUND",
        "INVALID_SPACE": "SPACE_REQUIRED",
        "INVALID_ACTION": "INVALID_BODY",
        "INVALID_TARGET": "INVALID_BODY",
        "INVALID_BODY": "INVALID_BODY",
        "LIMIT_REACHED": "CONFLICT",
    }
    code = codes.get(exc.code, "UNAVAILABLE")
    # `change_rule` answers the reason, the name and the choice counts alike with
    # `INVALID_BODY`; `exc.field` is the one `ApprovalRuleError` itself set for the reason
    # and name screens, and unset for everything else this maps.
    return ApiError(code, fields=[exc.field] if exc.field else None)


def approval_rule_routes(
    routes: APIRouter, runtime: Runtime, config: HumanConfig, guards: ApiGuards
) -> None:
    @routes.get(
        "/approval-rules", response_model=ApprovalRulesPage, operation_id="listApprovalRules"
    )
    async def read(request: Request) -> ApprovalRulesPage:
        session, _ = await guards.session(request)
        try:
            return ApprovalRulesPage.model_validate(
                await run_in_threadpool(rules.read_rules, runtime, session)
            )
        except rules.ApprovalRuleError as exc:
            raise refused(exc) from None

    async def save(request: Request, identifier: UUID | None) -> SavedApprovalRule:
        session, body = await guards.mutation(request, ApprovalRuleBody)
        for target in body.targets:
            parse_uuid(target, 400)
        payload = body.model_dump(exclude={"reason"}) | {"operation": "save"}
        try:
            rule = await run_in_threadpool(
                rules.change_rule, runtime, session, identifier, payload, body.reason
            )
        except rules.ApprovalRuleError as exc:
            raise refused(exc) from None
        return SavedApprovalRule(rule_id=rule)

    @routes.post(
        "/approval-rules",
        response_model=SavedApprovalRule,
        operation_id="createApprovalRule",
        openapi_extra=body_of(ApprovalRuleBody),
    )
    async def create(request: Request) -> SavedApprovalRule:
        return await save(request, None)

    @routes.post(
        "/approval-rules/{rule_id}",
        response_model=SavedApprovalRule,
        operation_id="updateApprovalRule",
        openapi_extra=body_of(ApprovalRuleBody),
    )
    async def update(request: Request, rule_id: str) -> SavedApprovalRule:
        return await save(request, parse_uuid(rule_id))

    @routes.post(
        "/approval-rules/{rule_id}/disable",
        response_model=SavedApprovalRule,
        operation_id="disableApprovalRule",
        openapi_extra=body_of(AccessReason),
    )
    async def disable(request: Request, rule_id: str) -> SavedApprovalRule:
        session, body = await guards.mutation(request, AccessReason)
        identifier = parse_uuid(rule_id)
        try:
            rule = await run_in_threadpool(
                rules.change_rule,
                runtime,
                session,
                identifier,
                {"operation": "disable"},
                body.reason,
            )
        except rules.ApprovalRuleError as exc:
            raise refused(exc) from None
        return SavedApprovalRule(rule_id=rule)
