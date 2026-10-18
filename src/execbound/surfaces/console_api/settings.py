# SPDX-License-Identifier: AGPL-3.0-only
"""`/api/console/v1/settings` and `/api/console/v1/tenant`: the two settings pages, as data.

The personal page reads and writes only the acting principal's own rows, beside the one fact
about the tenant a person needs to link their own directory account, which provider is
enabled; the tenant page is an administrator's and calls the store functions the command line
calls, with the session's identity, so a change made here and one made with `execbound tenant-mode`,
`tenant-approval-deadline`, `tenant-stop` or `tenant-resume` leave identical audit events
(#253,
#333). Every route wraps the function
its page calls today: `personal_overview`, `revoke_other_sessions`, `tenant_overview`,
`set_enforcement_mode`, `set_approval_deadline`, `activate_stop` and `release_stop`. The
deadline travels as the text the person typed, `off` or seconds, and is read by the page's own
parser, so `119`, `3601` and a word are refused before any store function sees them.
Destinations are id, kind, host and how many approvers, never the URL or the secret.
"""

from collections.abc import Callable, Mapping
from datetime import datetime
from typing import Any, Literal
from uuid import UUID

from fastapi import APIRouter, Request
from pydantic import BaseModel, ConfigDict, Field
from starlette.concurrency import run_in_threadpool

from execbound.execution.models import ExecutionError
from execbound.execution.modes import set_approval_deadline, set_enforcement_mode
from execbound.execution.stops import activate_stop, release_stop
from execbound.operations import CatalogError
from execbound.passwords import (
    MAX_PASSWORD,
    MIN_PASSWORD,
    PasswordError,
    change_password,
)
from execbound.personal_tokens import TokenSession
from execbound.runtime import Runtime
from execbound.surfaces.console_api.bodies import body
from execbound.surfaces.console_api.errors import ApiError
from execbound.surfaces.console_api.guards import ApiGuards
from execbound.surfaces.console_api.principals import PrincipalRef, principal_ref
from execbound.surfaces.human import HumanConfig
from execbound.surfaces.names import PrincipalFacts
from execbound.surfaces.sessions import Session, SessionError, revoke_other_sessions
from execbound.surfaces.settings_pages import parse_deadline, personal_overview, tenant_overview
from execbound.weekly_summary import SummaryError, offered, subscribe

Kind = Literal["ADMIN", "HUMAN_APPROVER"]
Mode = Literal["ENFORCE", "OBSERVE"]

# What the store functions refuse, as the code the client maps to copy; a value from the body
# is never echoed. Anything else is the tenant being unavailable.
_REFUSALS: dict[str, tuple[str, list[str]]] = {
    "INVALID_MODE": ("INVALID_BODY", ["mode"]),
    "INVALID_DEADLINE": ("INVALID_BODY", ["deadline"]),
    "INVALID_REASON": ("INVALID_BODY", ["reason"]),
    "INVALID_STATE": ("CONFLICT", []),
    "INVALID_IDENTITY": ("FORBIDDEN", []),
    "TENANT_STOPPED": ("STOPPED", []),
}
# What a password change refuses, as the code the client maps to copy. A wrong current
# password and a new one the store will not take are different faults for the person who
# typed them, and neither says anything about anybody else's account.
_PASSWORD_REFUSALS: dict[str, tuple[str, list[str]]] = {
    "INVALID_CURRENT": ("INVALID_BODY", ["current"]),
    "INVALID_PASSWORD": ("INVALID_BODY", ["new"]),
    "PASSWORD_UNCHANGED": ("INVALID_BODY", ["new"]),
    "INVALID_STATE": ("CONFLICT", []),
    "INVALID_PRINCIPAL": ("FORBIDDEN", []),
}


class SettingsIdentity(BaseModel):
    principal_id: UUID
    kind: Kind
    credential_id: UUID


class SettingsCredential(BaseModel):
    issued_at: datetime
    expires_at: datetime


class SettingsSession(BaseModel):
    session_id: UUID
    created_at: datetime
    expires_at: datetime
    label: str
    current: bool


class SettingsDirectoryProvider(BaseModel):
    """The tenant's enabled provider, the one a person links their own account through.

    Its id, its name and its state only: the issuer, the client id and the secret are an
    administrator's (`/tenant/sign-in`) and are not read for this view.
    """

    provider_id: UUID
    name: str
    state: Literal["enabled"]


class SettingsDirectoryLink(BaseModel):
    """The acting person's own account at the tenant's directory.

    `subject` is the identifier; the two display values are hints the directory reported, its
    text and not a person's, shown as text and never used to find anybody. `via` says who
    bound it: the person themselves, an administrator, or an invitation they redeemed.
    """

    provider_id: UUID
    provider_name: str
    subject: str
    via: Literal["invitation", "self", "admin"]
    display_name: str | None
    display_username: str | None
    created_at: datetime
    last_sign_in_at: datetime | None


class SettingsDirectory(BaseModel):
    """`provider` is null when nothing is offered: no provider is enabled, or this deployment
    holds no key ring, so the link route would answer 404. `link` is null when this person has
    no active link. An approver's link is removed by an administrator on the approver's page; an
    administrator's link is not removed from the console."""

    provider: SettingsDirectoryProvider | None
    link: SettingsDirectoryLink | None


class WeeklySummarySettings(BaseModel):
    """The person's own weekly summary (#678): whether the deployment sends it, whether it is
    on, and the address it goes to, which is the person's own and null where none resolves."""

    available: bool
    subscribed: bool
    address: str | None


class WeeklySummaryChange(BaseModel):
    """Turn one's own summary on or off. No principal travels: the session is the person."""

    model_config = ConfigDict(extra="forbid")

    subscribed: bool


class SettingsSecurity(BaseModel):
    """The person's own second factor (#678): counts and flags only, never a secret."""

    # An enabled authenticator app.
    authenticator: bool
    passkeys: int
    # Recovery codes left; zero without an authenticator.
    recovery_remaining: int
    requirement: Literal["optional", "admins", "all"]
    # Whether this deployment has account security at all.
    available: bool


class PersonalSettingsView(BaseModel):
    identity: SettingsIdentity
    tenant_name: str
    # The address this person signs in with, and whether they hold a password at all. The
    # hash is never read for this view, so it cannot reach a response by accident.
    email: str | None
    has_password: bool
    credential: SettingsCredential
    sessions: list[SettingsSession]
    others: int
    directory: SettingsDirectory
    # Always set by this server; a default, so a client written before it reads as "not
    # offered" rather than failing (#678).
    weekly_summary: WeeklySummarySettings = Field(
        default_factory=lambda: WeeklySummarySettings(
            available=False, subscribed=False, address=None
        )
    )
    # Always set by this server; a default for the same reason as `weekly_summary`.
    security: SettingsSecurity = Field(
        default_factory=lambda: SettingsSecurity(
            authenticator=False,
            passkeys=0,
            recovery_remaining=0,
            requirement="optional",
            available=False,
        )
    )


class PasswordChange(BaseModel):
    """A person changing their own password, presenting the current one.

    Both bounds are the store's, restated here so a body outside them is refused as
    `INVALID_BODY` naming the field rather than reaching the hash at all.
    """

    model_config = ConfigDict(extra="forbid")

    current: str = Field(min_length=1, max_length=MAX_PASSWORD)
    new: str = Field(min_length=MIN_PASSWORD, max_length=MAX_PASSWORD)


class RevokeOtherSessions(BaseModel):
    """The confirmation carries nothing but the session's token, as the form does."""

    model_config = ConfigDict(extra="forbid")


class Change(BaseModel):
    """When a setting last changed and who changed it."""

    at: datetime
    by: UUID
    # The person who changed it, by kind and number (#678); `null` where the principal could
    # not be read.
    by_ref: PrincipalRef | None


class TenantMode(BaseModel):
    value: Mode
    changed: Change | None


class DeadlineBounds(BaseModel):
    min: int
    max: int


class TenantDeadline(BaseModel):
    seconds: int | None
    bounds: DeadlineBounds
    changed: Change | None


class TenantStop(BaseModel):
    stop_id: UUID
    stopped_at: datetime
    stopped_by: UUID
    reason: str
    committed: int | None
    stopped_by_ref: PrincipalRef | None


class MonitoringHealth(BaseModel):
    sources: int
    reporting: int
    stale: int
    # Active connections whose collection evidence went stale, by the one freshness rule;
    # monitoring's quiet figure is `stale + overdue` (#678).
    overdue: int
    open_findings: int


class NotificationDestination(BaseModel):
    destination_id: str
    kind: str
    host: str
    approvers: int | None
    # Which approval messages it receives, in the order `pending`, `reminder`, `closed`; empty
    # for the audit export, which announces no approval (#678).
    messages: list[Literal["pending", "reminder", "closed"]]


class NotificationDelivery(BaseModel):
    """How fast this workspace's announcements arrived over the last week (#678).

    Counts and durations only, over `approval.pending` rows, workspace-wide as the deadline is.
    Durations are whole seconds rounded up; the percentiles are null below five deliveries.
    """

    window_days: int
    delivered: int
    median_seconds: int | None
    p90_seconds: int | None
    slowest_seconds: int | None
    # Not sent because the approval would have lapsed before the message arrived.
    lapsed: int
    # Failed with any other code but `APPROVAL_CLOSED`.
    failed: int


class ApprovalWindow(BaseModel):
    """How long a held request for one action can wait at most (#678).

    An upper bound: the smallest validity over the kinds of fact the action's contract resolves,
    through the bundle's own context settings, capped by the deadline. A request waits less,
    because its time starts when its facts were recorded. `known` is false where a custom policy
    may hold the action; `limited_by` is `unknown`, with no figure, where a contract is unknown.
    """

    action: str
    action_label: str
    context_seconds: int | None
    bound_seconds: int | None
    limited_by: Literal["deadline", "context", "unknown"]
    # The kinds of fact whose validity sets `context_seconds`.
    source_kinds: list[Literal["inventory", "incident", "signal"]]
    known: bool


class ApprovalWindowSpace(BaseModel):
    """One Space's held actions; none, with no bundle, where no policy is active."""

    space_id: UUID
    name: str
    bundle_id: UUID | None
    actions: list[ApprovalWindow]


class TenantSettingsView(BaseModel):
    tenant_id: UUID
    tenant_name: str
    mode: TenantMode
    deadline: TenantDeadline
    stop: TenantStop | None
    bundle_id: UUID | None
    monitoring: MonitoringHealth
    destinations: list[NotificationDestination]
    delivery: NotificationDelivery
    # The current Space's held actions, or each visible Space's under "All spaces" (#678).
    approval_windows: list[ApprovalWindowSpace]


class ModeChange(BaseModel):
    model_config = ConfigDict(extra="forbid")

    mode: Mode
    reason: str = Field(min_length=1, max_length=500)


class DeadlineChange(BaseModel):
    model_config = ConfigDict(extra="forbid")

    deadline: str = Field(min_length=1, max_length=8, description="Seconds, or off.")
    reason: str = Field(min_length=1, max_length=500)


class StopChange(BaseModel):
    model_config = ConfigDict(extra="forbid")

    reason: str = Field(min_length=1, max_length=500)


def _change(row: dict[str, Any] | None, principals: Mapping[UUID, PrincipalFacts]) -> Change | None:
    if row is None:
        return None
    return Change(at=row["at"], by=row["by"], by_ref=principal_ref(row["by"], principals))


def personal_view(
    runtime: Runtime, session: Session, *, linkable: bool, secured: bool = False
) -> PersonalSettingsView:
    """`linkable` is whether this deployment serves the directory routes at all, and
    `secured` whether it has account security (`HumanConfig.mfa`)."""
    identity = session.identity
    data = personal_overview(runtime, session)
    directory = data["directory"]
    return PersonalSettingsView(
        identity=SettingsIdentity(
            principal_id=identity.principal_id,
            kind=identity.kind,  # type: ignore[arg-type]
            credential_id=identity.credential_id,
        ),
        tenant_name=data["tenant_name"],
        email=data["email"],
        has_password=bool(data["has_password"]),
        credential=SettingsCredential(**data["credential"]),
        sessions=[SettingsSession(**row) for row in data["sessions"]],
        others=data["others"],
        directory=SettingsDirectory(
            provider=(
                SettingsDirectoryProvider(**directory["provider"])
                if linkable and directory["provider"] is not None
                else None
            ),
            link=(
                SettingsDirectoryLink(**directory["link"])
                if directory["link"] is not None
                else None
            ),
        ),
        weekly_summary=WeeklySummarySettings(
            available=offered(runtime.mail),
            subscribed=bool(data["weekly_summary"]["subscribed"]),
            address=data["weekly_summary"]["address"],
        ),
        security=SettingsSecurity(**data["security"], available=secured),
    )


def tenant_view(runtime: Runtime, session: Session) -> TenantSettingsView:
    data = tenant_overview(runtime, session)
    stop = data["stop"]
    principals = data["principals"]
    return TenantSettingsView(
        tenant_id=data["tenant_id"],
        tenant_name=data["tenant_name"],
        mode=TenantMode(
            value="OBSERVE" if data["mode"] == "OBSERVE" else "ENFORCE",
            changed=_change(data["mode_change"], principals),
        ),
        deadline=TenantDeadline(
            seconds=data["deadline"],
            bounds=DeadlineBounds(min=data["bounds"][0], max=data["bounds"][1]),
            changed=_change(data["deadline_change"], principals),
        ),
        stop=(
            None
            if stop is None
            else TenantStop(**stop, stopped_by_ref=principal_ref(stop["stopped_by"], principals))
        ),
        bundle_id=data["bundle_id"],
        monitoring=MonitoringHealth(**data["monitoring"]),
        destinations=[NotificationDestination(**item) for item in data["destinations"]],
        delivery=NotificationDelivery(**data["delivery"]),
        approval_windows=[
            ApprovalWindowSpace(
                space_id=space.space_id,
                name=space.name,
                bundle_id=space.bundle_id,
                actions=[
                    ApprovalWindow(
                        action=window.action,
                        action_label=_action_label(runtime, window.action),
                        context_seconds=window.context_seconds,
                        bound_seconds=window.bound_seconds,
                        limited_by=window.limited_by,
                        source_kinds=list(window.source_kinds),
                        known=window.known,
                    )
                    for window in space.windows
                ],
            )
            for space in data["approval_windows"]
        ],
    )


def _action_label(runtime: Runtime, action: str) -> str:
    """The catalog's label for an action, or its name where this catalog does not know it."""
    try:
        return runtime.catalog.actions.action(action).label
    except CatalogError:
        return action


def _read(read: Callable[[], Any]) -> Any:
    try:
        return read()
    except SessionError:
        raise ApiError("SESSION_REQUIRED") from None
    except ExecutionError as exc:
        code, fields = _REFUSALS.get(exc.code, ("UNAVAILABLE", []))
        raise ApiError(code, fields=fields) from None


def settings_routes(
    routes: APIRouter, runtime: Runtime, config: HumanConfig, guards: ApiGuards
) -> None:
    linkable = config.directory is not None
    secured = config.mfa is not None

    @routes.get("/settings", response_model=PersonalSettingsView, operation_id="readSettings")
    async def read_settings(request: Request) -> PersonalSettingsView:
        current, _ = await guards.session(request)
        return await run_in_threadpool(
            _read, lambda: personal_view(runtime, current, linkable=linkable, secured=secured)
        )

    @routes.post(
        "/settings/sessions/revoke-others",
        response_model=PersonalSettingsView,
        operation_id="revokeOtherSessions",
        openapi_extra=body(RevokeOtherSessions),
    )
    async def revoke_others(request: Request) -> PersonalSettingsView:
        current, _ = await guards.mutation(request, RevokeOtherSessions)

        def apply() -> PersonalSettingsView:
            revoke_other_sessions(runtime.db, current, clock=runtime.clock)
            return personal_view(runtime, current, linkable=linkable, secured=secured)

        return await run_in_threadpool(_read, apply)

    @routes.post(
        "/settings/weekly-summary",
        response_model=PersonalSettingsView,
        operation_id="changeWeeklySummary",
        openapi_extra=body(WeeklySummaryChange),
    )
    async def change_weekly_summary(request: Request) -> PersonalSettingsView:
        """Turn the person's own weekly summary on or off (#678).

        503 `UNAVAILABLE` where this deployment does not send it; 409 `CONFLICT` for a change
        that changes nothing, and for turning it on with no address to send it to. The
        change is the server's: the page shows the new state from this answer.
        """
        current, body_values = await guards.mutation(request, WeeklySummaryChange)
        if not offered(runtime.mail):
            raise ApiError("UNAVAILABLE")

        def apply() -> PersonalSettingsView:
            try:
                subscribe(runtime, current, body_values.subscribed)
            except SummaryError:
                raise ApiError("CONFLICT") from None
            return personal_view(runtime, current, linkable=linkable, secured=secured)

        return await run_in_threadpool(_read, apply)

    @routes.post(
        "/settings/password",
        response_model=PersonalSettingsView,
        operation_id="changePassword",
        openapi_extra=body(PasswordChange),
    )
    async def change_password_route(request: Request) -> PersonalSettingsView:
        """A person changes their own password and nobody else's.

        The identity comes from the session, so the body names no principal and there is
        nothing here for an administrator to aim at somebody. The current password is
        verified against the stored record before the write, and the write itself refuses a
        person who holds none, so this can never become a way to set one.
        """
        current, body_values = await guards.mutation(request, PasswordChange)

        def apply() -> PersonalSettingsView:
            try:
                change_password(
                    runtime.db,
                    current.identity,
                    body_values.current,
                    body_values.new,
                    clock=runtime.clock,
                    session=current,
                )
            except PasswordError as exc:
                code, fields = _PASSWORD_REFUSALS.get(exc.code, ("UNAVAILABLE", []))
                raise ApiError(code, fields=fields) from None
            return personal_view(runtime, current, linkable=linkable, secured=secured)

        return await run_in_threadpool(_read, apply)

    @routes.get("/tenant", response_model=TenantSettingsView, operation_id="readTenant")
    async def read_tenant(request: Request) -> TenantSettingsView:
        current, _ = await guards.session(request, kind="ADMIN")
        return await run_in_threadpool(_read, lambda: tenant_view(runtime, current))

    async def change(
        request: Request, model: type[BaseModel], apply: Callable[[Session, Any], None]
    ) -> TenantSettingsView:
        """One tenant change: the store function with the session's identity, then the view."""
        current, body = await guards.mutation(request, model, kind="ADMIN")

        def run() -> TenantSettingsView:
            apply(current, body)
            return tenant_view(runtime, current)

        return await run_in_threadpool(_read, run)

    @routes.post(
        "/tenant/mode",
        response_model=TenantSettingsView,
        operation_id="changeMode",
        openapi_extra=body(ModeChange),
    )
    async def change_mode(request: Request) -> TenantSettingsView:
        def apply(session: Session, body: ModeChange) -> None:
            # A token may tighten and never loosen: enforcing, never observe-only.
            if isinstance(session, TokenSession) and body.mode != "ENFORCE":
                runtime.reject(
                    session.identity,
                    "TOKEN_NOT_ALLOWED",
                    actor_credential=True,
                    route=request.scope["route"].path,
                    method=request.method,
                )
                raise ApiError("TOKEN_NOT_ALLOWED")
            set_enforcement_mode(
                runtime.db, session.identity, body.mode, body.reason, runtime.clock
            )

        return await change(request, ModeChange, apply)

    @routes.post(
        "/tenant/deadline",
        response_model=TenantSettingsView,
        operation_id="changeDeadline",
        openapi_extra=body(DeadlineChange),
    )
    async def change_deadline(request: Request) -> TenantSettingsView:
        def apply(session: Session, body: DeadlineChange) -> None:
            set_approval_deadline(
                runtime.db,
                session.identity,
                parse_deadline(body.deadline),
                body.reason,
                runtime.clock,
            )

        return await change(request, DeadlineChange, apply)

    @routes.post(
        "/tenant/stop",
        response_model=TenantSettingsView,
        operation_id="activateStop",
        openapi_extra=body(StopChange),
    )
    async def stop(request: Request) -> TenantSettingsView:
        def apply(session: Session, body: StopChange) -> None:
            activate_stop(runtime.db, session.identity, body.reason, runtime.clock)

        return await change(request, StopChange, apply)

    @routes.post(
        "/tenant/resume",
        response_model=TenantSettingsView,
        operation_id="releaseStop",
        openapi_extra=body(StopChange),
    )
    async def resume(request: Request) -> TenantSettingsView:
        def apply(session: Session, body: StopChange) -> None:
            release_stop(runtime.db, session.identity, body.reason, runtime.clock)

        return await change(request, StopChange, apply)
