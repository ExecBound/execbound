# SPDX-License-Identifier: AGPL-3.0-only
"""Decision coverage and unrouted approvals: a workspace administrator's two reads (#678).

`GET /approval-coverage` answers, for each Space and each action its active policy can hold,
how many people can decide it now, and which targets held, requested or thinly covered in the
last 30 days fewer people can decide than the action needs. `GET /approval-coverage/unrouted`
answers how many open approvals fewer people can decide now than they need, and how many held
in the last seven days were recorded that way when they were held.

Both require workspace-wide `access.manage`, the authority `/approval-rules` and `/approvers`
already need; an administrator narrowed to Spaces, an approver and an agent credential are
refused. Both carry counts and never a reviewer's identity, and both are previews read in their
own snapshot without the tenant fence: eligibility is checked again when a person decides and
before execution.
"""

from collections.abc import Callable
from datetime import datetime
from typing import Any, Literal
from uuid import UUID

from fastapi import APIRouter, Request
from pydantic import BaseModel
from sqlalchemy.exc import SQLAlchemyError
from starlette.concurrency import run_in_threadpool

from execbound import approval_routing
from execbound.execution.models import ExecutionError
from execbound.runtime import Runtime
from execbound.surfaces.console_api.errors import ApiError
from execbound.surfaces.console_api.guards import ApiGuards
from execbound.surfaces.human import HumanConfig
from execbound.surfaces.sessions import Session, SessionError


class CoverageTarget(BaseModel):
    canonical_target_id: UUID
    # Provider identifiers, operator data: rendered as text.
    labels: str | None
    requests: int
    last_requested_at: datetime
    reviewers: int


class CoverageList(BaseModel):
    total: int
    rows: list[CoverageTarget]


class CoverageAction(BaseModel):
    action: str
    action_label: str
    # What holds it: `rule:<id>`, `limit:<id>`, or `policy` for a custom bundle's own policies.
    held_by: list[str]
    # False where a custom policy may hold the action and which requests it holds cannot be
    # read from the policy.
    known: bool
    # How many people a held request needs: the largest quorum of the rules that hold it, and 1
    # where the policy is custom. `upto` is the most a custom policy can ask, when above 1.
    required: int
    upto: int | None
    reviewers: int
    held_uncovered: CoverageList
    requested_uncovered: CoverageList
    thin: CoverageList


class CoverageSpace(BaseModel):
    space_id: UUID
    name: str
    bundle_id: UUID | None
    policy: Literal["none", "rules", "custom"]
    actions: list[CoverageAction]


class ApprovalCoverage(BaseModel):
    server_time: datetime
    since: datetime
    mode: Literal["ENFORCE", "OBSERVE"]
    truncated: bool
    spaces: list[CoverageSpace]


class UnroutedRecord(BaseModel):
    approval_id: UUID
    execution_id: UUID
    request_ref: str
    space_id: UUID
    # The expiry of an open approval; when a recent one was held.
    at: datetime
    state: str


class UnroutedApprovals(BaseModel):
    server_time: datetime
    pending: int
    pending_nobody: int
    pending_truncated: bool
    pending_latest: UnroutedRecord | None
    recent: int
    recent_latest: UnroutedRecord | None


def _answer(
    read: Callable[[Runtime, Session], dict[str, Any]], runtime: Runtime, session: Session
) -> dict[str, Any]:
    try:
        return read(runtime, session)
    except approval_routing.ApprovalRoutingError:
        raise ApiError("FORBIDDEN") from None
    except SessionError:
        raise ApiError("SESSION_REQUIRED") from None
    except ExecutionError as exc:
        raise ApiError("FORBIDDEN" if exc.code == "INVALID_IDENTITY" else "UNAVAILABLE") from None
    except SQLAlchemyError:
        raise ApiError("UNAVAILABLE") from None


def approval_coverage_routes(
    routes: APIRouter, runtime: Runtime, config: HumanConfig, guards: ApiGuards
) -> None:
    @routes.get(
        "/approval-coverage", response_model=ApprovalCoverage, operation_id="readApprovalCoverage"
    )
    async def coverage(request: Request) -> ApprovalCoverage:
        session, _ = await guards.session(request)
        return ApprovalCoverage.model_validate(
            await run_in_threadpool(_answer, approval_routing.read_coverage, runtime, session)
        )

    @routes.get(
        "/approval-coverage/unrouted",
        response_model=UnroutedApprovals,
        operation_id="readUnroutedApprovals",
    )
    async def unrouted(request: Request) -> UnroutedApprovals:
        session, _ = await guards.session(request)
        return UnroutedApprovals.model_validate(
            await run_in_threadpool(_answer, approval_routing.read_unrouted, runtime, session)
        )
