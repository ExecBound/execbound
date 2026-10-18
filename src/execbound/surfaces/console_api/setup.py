# SPDX-License-Identifier: AGPL-3.0-only
"""`GET /api/console/v1/setup`: what is already set up in the selected Space, from records (#678).

Getting started, the sidebar's card and Home's next step read this one view. It answers five
steps for the session's Space, each from the record that satisfies it at request time
(`getting_started.setup_state`): a selected policy, an agent holding a live API key, the first
request, someone able to review an action the policy maps, and the first decided approval.
Beside them it says whether the Space has a registered connection, which decides what the next
step says and is never counted, and, while the workspace observes, this Space's observed
decisions of the last seven days.

The read is an administrator's: the guard's ADMIN kind, then one fenced transaction that checks
the identity as an administrator's, the session, the Space and the identity again. The Space
is the session's write Space, held to the reader's visibility and to the `ADMIN` role in it,
so a person seated in it as a reviewer is refused. A personal access token reads the Space it
names, held to its owner's visibility. A workspace-wide reader on "All spaces" in a workspace
with several answers `choose_space` and no steps. The answer carries identifiers and
references, never a hostname, a target or a label, and the read writes nothing.
"""

from datetime import datetime
from typing import Literal
from uuid import UUID

from fastapi import APIRouter, Request
from pydantic import BaseModel
from starlette.concurrency import run_in_threadpool

from execbound.execution import store
from execbound.execution.models import ExecutionError
from execbound.getting_started import SetupState, setup_state
from execbound.runtime import Runtime
from execbound.spaces import SpaceError, default_space, visible_spaces, write_space
from execbound.surfaces.console_api.errors import ApiError
from execbound.surfaces.console_api.guards import ApiGuards
from execbound.surfaces.human import HumanConfig
from execbound.surfaces.sessions import Session, SessionError, check_session

SetupKey = Literal["policy", "agent_key", "first_request", "reviewer", "first_decision"]


class SetupRecord(BaseModel):
    kind: Literal["bundle", "agent", "execution", "approver"]
    id: UUID
    # "EB-<n>" for an execution; None otherwise.
    request_ref: str | None


class SetupMilestone(BaseModel):
    key: SetupKey
    # "needs_enforcing" only for first_decision while the workspace observes: no approval can
    # exist in Observe only, so the step is still owed but cannot be done now.
    state: Literal["done", "todo", "not_applicable", "needs_enforcing"]
    # When the satisfying record came to hold; None where the record carries no time.
    at: datetime | None
    record: SetupRecord | None


class ObservedCounts(BaseModel):
    since: datetime
    eligible: int
    held: int
    denied: int


class SetupView(BaseModel):
    state: Literal["ready", "choose_space"]
    space_id: UUID | None
    # An active connector account usable in this Space with an active mapping.
    connected: bool
    # True only when this Space is the workspace's default Space and the reader is
    # workspace-wide: the only place and the only reader for which installing the sample
    # targets can tick anything here, since they always install into the default Space.
    samples_here: bool
    # The default Space's id, for a workspace-wide reader only; None for anyone else.
    default_space_id: UUID | None
    milestones: list[SetupMilestone]
    done: int
    required: int
    # The first step still to do, or None when none is; a step that needs Enforcing is never
    # next.
    next: SetupKey | None
    # Only while the workspace is in Observe only: this Space's observed decisions, 7 days.
    observed: ObservedCounts | None


def _view(space: UUID | None, state: SetupState | None, *, default: UUID | None) -> SetupView:
    if space is None or state is None:
        return SetupView(
            state="choose_space",
            space_id=None,
            connected=False,
            samples_here=False,
            default_space_id=default,
            milestones=[],
            done=0,
            required=0,
            next=None,
            observed=None,
        )
    milestones = [
        SetupMilestone.model_validate(
            {
                "key": item.key,
                "state": item.state,
                "at": item.at,
                "record": None
                if item.record_id is None
                else {
                    "kind": item.record_kind,
                    "id": item.record_id,
                    "request_ref": item.request_ref,
                },
            }
        )
        for item in state.milestones
    ]
    observed = (
        None
        if state.observed is None or state.observed_since is None
        else ObservedCounts(since=state.observed_since, **state.observed)
    )
    return SetupView(
        state="ready",
        space_id=space,
        connected=state.connected,
        samples_here=default is not None and space == default,
        default_space_id=default,
        milestones=milestones,
        done=sum(1 for item in milestones if item.state == "done"),
        required=sum(1 for item in milestones if item.state != "not_applicable"),
        next=next((item.key for item in milestones if item.state == "todo"), None),
        observed=observed,
    )


def setup_view(runtime: Runtime, session: Session) -> SetupView:
    identity = session.identity
    try:
        with runtime.db.transaction(identity.tenant_id) as conn:
            store.identity_check(conn, identity, runtime.clock, "ADMIN")
            check_session(conn, session, runtime.clock)
            try:
                visibility = visible_spaces(conn, session)
            except SpaceError:
                raise ApiError("SPACE_REQUIRED") from None
            try:
                space: UUID | None = write_space(conn, identity.tenant_id, visibility)
            except SpaceError:
                space = None
            if space is not None and not (
                visibility.everything or visibility.roles.get(space) == "ADMIN"
            ):
                raise ApiError("FORBIDDEN")
            # The sample targets always install into the default Space, and only a
            # workspace-wide administrator may install them.
            default = default_space(conn, identity.tenant_id) if visibility.everything else None
            state = (
                None
                if space is None
                else setup_state(
                    conn,
                    identity.tenant_id,
                    space,
                    now=store.now(runtime.clock),
                    observing=store.enforcement_mode(conn, identity.tenant_id) == "OBSERVE",
                )
            )
            store.identity_check(conn, identity, runtime.clock, "ADMIN")
    except SessionError:
        raise ApiError("SESSION_REQUIRED") from None
    except ExecutionError as exc:
        raise ApiError("FORBIDDEN" if exc.code == "INVALID_IDENTITY" else "UNAVAILABLE") from None
    return _view(space, state, default=default)


def setup_routes(
    routes: APIRouter, runtime: Runtime, config: HumanConfig, guards: ApiGuards
) -> None:
    @routes.get("/setup", response_model=SetupView, operation_id="readSetup")
    async def read_setup(request: Request) -> SetupView:
        session, _ = await guards.session(request, kind="ADMIN")
        return await run_in_threadpool(setup_view, runtime, session)
