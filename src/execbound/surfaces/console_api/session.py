# SPDX-License-Identifier: AGPL-3.0-only
"""`GET /api/console/v1/session`: who is signed in, for which tenant, and the CSRF token, once.

The one place the CSRF token leaves the server as data: the cookie that holds it is httponly,
so the application reads it here and keeps it in memory, never in storage or a URL. The
identity and the tenant come from the session and its tenant's rows, read inside the tenant
fence with the same identity and session rechecks every page makes, and the release is the
running commit so the client can tell a build it is not. The tenant's active emergency stop
travels here too, read as `active_stop` reads it for the banner every page shows, so the
shell shows the same banner on every route and an approver sees the state without a route
of their own. So do the deployment's service links (`HumanConfig.service`), which the
console's Help page, footer, My account and requests card link to.
"""

from dataclasses import asdict
from datetime import datetime
from typing import Literal
from uuid import UUID

from fastapi import APIRouter, Request
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import text
from starlette.concurrency import run_in_threadpool

from execbound.access_control import capabilities
from execbound.build import running_commit
from execbound.execution import store
from execbound.execution.models import DEFAULT_APPROVAL_DEADLINE, ExecutionError
from execbound.runtime import Runtime
from execbound.spaces import SpaceError, set_current_space, visible_spaces
from execbound.surfaces.console_api.directory import UUID_PATTERN, body_of
from execbound.surfaces.console_api.guards import ApiGuards
from execbound.surfaces.console_api.principals import PrincipalRef, principal_ref
from execbound.surfaces.console_api.spaces import refused
from execbound.surfaces.human import HumanConfig
from execbound.surfaces.names import principal_facts
from execbound.surfaces.sessions import Session, check_session

KIND_WORDS = {"ADMIN": "Administrator", "HUMAN_APPROVER": "Approver"}


class SessionIdentity(BaseModel):
    principal_id: UUID
    kind: Literal["ADMIN", "HUMAN_APPROVER"]
    label: str


class SessionTenant(BaseModel):
    tenant_id: UUID
    name: str
    mode: Literal["ENFORCE", "OBSERVE"]
    approval_deadline_seconds: int


class SessionStop(BaseModel):
    stop_id: UUID
    stopped_at: datetime
    stopped_by: UUID
    reason: str
    # The administrator who activated the stop, by kind and number, for an administrator's
    # session or token alone; an approver's is `null` and its banner says "an administrator"
    # (#678). `stopped_by` is unchanged for everyone.
    stopped_by_ref: PrincipalRef | None


class SessionSpace(BaseModel):
    """The space this session is looking at; `null` is "All spaces"."""

    space_id: UUID
    name: str
    archived: bool


class ServiceLinksView(BaseModel):
    """The deployment's support address and public pages, each null where it names none, and
    a link with no address is not shown (`execbound.service_links`)."""

    support_email: str | None
    help_url: str | None
    status_url: str | None
    privacy_url: str | None
    terms_url: str | None
    plans_url: str | None
    security_url: str | None
    privacy_requests_url: str | None
    source_url: str | None
    # Who runs the deployment, the footer's copyright holder; null reads "Powered by ExecBound".
    operator: str | None


class SpaceBody(BaseModel):
    """`{space_id}` or `{space_id: null}`; nothing else names a space anywhere."""

    model_config = ConfigDict(extra="forbid")

    space_id: str | None = Field(default=None, pattern=UUID_PATTERN)


class SessionView(BaseModel):
    generation: UUID
    # Whether this session can hold and switch between several workspaces: any session signed
    # in through an account can.
    can_switch_workspaces: bool
    identity: SessionIdentity
    tenant: SessionTenant
    stop: SessionStop | None
    # The space the person is looking at, how many they can see, and whether
    # "All spaces" is worth offering. The space id is the first identifier the client is
    # given; `tenant_id` still never reaches it as anything but the tenant's own row.
    space: SessionSpace | None
    spaces: int
    all_spaces: bool
    csrf_token: str
    release: str | None
    expires_at: datetime
    # The hard end no renewal passes, and why it falls then: two days after sign-in
    # (`sign_in`), or the expiry of the setup credential the session was opened with
    # (`setup_credential`). The console warns before it (#678).
    ends_at: datetime
    end_reason: Literal["sign_in", "setup_credential"]
    # Whether this deployment has an assistant at all (#330, #333). It travels with
    # the session the shell already reads, so the sidebar, the top bar and the palette ask
    # nothing of their own and a console built for a deployment without one shows no door
    # to it, not even for a frame. Whether a tenant turned it on is the assistant area's
    # own answer, read by the pages that act on it.
    assistant: bool
    # Whether this session administers a plugin's invitation codes (#178, #204). False with
    # no plugin loaded; a plugin's own session feature answers it otherwise, so the console of
    # every tenant that is not the operator's shows no door to a page that would answer 404.
    invitations: bool
    # Whether this deployment has a mail relay, so a teammate invitation can reach anyone. The
    # people page offers to invite only where it does; without one an invitation would wait
    # for a relay that never comes, and the console points at `person-invite` instead.
    mail: bool
    # The session features the loaded plugins report as holding for this session, by name and
    # sorted (#496). Core reads none of them itself (`invitations` above is the one it
    # names); a plugin's console edition reads its own, such as the hosted service's
    # `create_workspace`.
    features: list[str]
    # The deployment's support address and public pages, the same for every session: the
    # runtime configuration's `service` block or a loaded plugin's, and with neither all null
    # but `source_url`, the public repository.
    service: ServiceLinksView
    access: "SessionAccess"


class SessionAccess(BaseModel):
    managed: bool
    roles: list[str]
    permissions: list[str]
    workspace_permissions: list[str]
    space_permissions: dict[str, list[str]]


def read_session(
    runtime: Runtime, session: Session
) -> tuple[
    SessionIdentity,
    SessionTenant,
    SessionStop | None,
    SessionSpace | None,
    int,
    bool,
    SessionAccess,
]:
    identity = session.identity
    if identity.kind not in KIND_WORDS:
        raise ExecutionError("INVALID_IDENTITY")
    with runtime.db.transaction(identity.tenant_id) as conn:
        store.identity_check(conn, identity, runtime.clock, identity.kind)
        check_session(conn, session, runtime.clock)
        params = {"t": identity.tenant_id, "p": identity.principal_id}
        name = conn.execute(
            text("SELECT name FROM execbound.tenants WHERE tenant_id=:t"), params
        ).scalar_one()
        # Nobody who joins by invitation or signup is given a label, so a person is named as
        # the Users page names them: by label, then by the address they sign in with. The
        # role word is the last resort, since the sidebar already says the role beneath it.
        label = conn.execute(
            text(
                "SELECT coalesce(label, email) FROM execbound.principals "
                "WHERE tenant_id=:t AND principal_id=:p"
            ),
            params,
        ).scalar_one_or_none()
        control = (
            conn.execute(
                text(
                    "SELECT enforcement_mode, approval_deadline_seconds "
                    "FROM execbound.tenant_policy_control WHERE tenant_id=:t"
                ),
                params,
            )
            .mappings()
            .one_or_none()
        )
        stop = store.stop(conn, identity.tenant_id)
        stopped_by_ref = None
        if stop is not None and identity.kind == "ADMIN":
            stopped_by_ref = principal_ref(
                stop.stopped_by, principal_facts(conn, identity.tenant_id, [stop.stopped_by])
            )
        # The visible set is recomputed inside the fence on every read, so a person
        # removed from the space their session holds loses it at the next poll
        # rather than keeping it because a column says so.
        visibility = visible_spaces(conn, session)
        access = SessionAccess.model_validate(
            capabilities(conn, identity.tenant_id, identity.principal_id)
        )
        space = None
        if visibility.current is not None:
            found = (
                conn.execute(
                    text(
                        "SELECT space_id, name, archived_at IS NOT NULL AS archived "
                        "FROM execbound.spaces WHERE tenant_id=:t AND space_id=:s"
                    ),
                    {"t": identity.tenant_id, "s": visibility.current},
                )
                .mappings()
                .one_or_none()
            )
            if found is not None:
                space = SessionSpace(
                    space_id=found["space_id"], name=str(found["name"]), archived=found["archived"]
                )
        visible = (
            conn.execute(
                text("SELECT count(*) FROM execbound.spaces WHERE tenant_id=:t"),
                {"t": identity.tenant_id},
            ).scalar_one()
            if visibility.everything
            else len(visibility.spaces)
        )
    mode = str(control["enforcement_mode"]) if control else "ENFORCE"
    deadline = control["approval_deadline_seconds"] if control else None
    return (
        SessionIdentity(
            principal_id=identity.principal_id,
            kind=identity.kind,  # type: ignore[arg-type]
            label=str(label) if label else KIND_WORDS[identity.kind],
        ),
        SessionTenant(
            tenant_id=identity.tenant_id,
            name=str(name),
            mode="OBSERVE" if mode == "OBSERVE" else "ENFORCE",
            approval_deadline_seconds=(
                int(deadline) if deadline is not None else DEFAULT_APPROVAL_DEADLINE
            ),
        ),
        None
        if stop is None
        else SessionStop(
            stop_id=stop.stop_id,
            stopped_at=stop.stopped_at,
            stopped_by=stop.stopped_by,
            reason=stop.reason,
            stopped_by_ref=stopped_by_ref,
        ),
        space,
        int(visible),
        visibility.allows_many(int(visible)),
        access,
    )


def session_routes(
    routes: APIRouter, runtime: Runtime, config: HumanConfig, guards: ApiGuards
) -> None:
    def _view(current: Session, csrf: str) -> SessionView:
        identity, tenant, stop, space, spaces, all_spaces, access = read_session(runtime, current)
        features = runtime.plugins.features(runtime, current)
        return SessionView(
            generation=current.session_id,
            can_switch_workspaces=current.account_id is not None,
            identity=identity,
            tenant=tenant,
            stop=stop,
            space=space,
            spaces=spaces,
            all_spaces=all_spaces,
            csrf_token=csrf,
            release=running_commit(),
            expires_at=current.expires_at,
            # A token session has no row to name its end, and a token cannot reach this route.
            ends_at=current.ends_at or current.expires_at,
            end_reason="setup_credential"
            if current.end_reason == "setup_credential"
            else "sign_in",
            assistant=config.assistant_enabled,
            invitations="invitations" in features,
            mail=runtime.mail is not None,
            features=sorted(features),
            service=ServiceLinksView(**asdict(config.service)),
            access=access,
        )

    @routes.get("/session", response_model=SessionView, operation_id="readSession")
    async def read(request: Request) -> SessionView:
        current, csrf = await guards.session(request)
        return await run_in_threadpool(_view, current, csrf)

    @routes.post(
        "/session/space",
        response_model=SessionView,
        operation_id="setSessionSpace",
        openapi_extra=body_of(SpaceBody),
    )
    async def set_space(request: Request) -> SessionView:
        """Change the space this session is looking at, and answer the fresh view.

        The one mutation that names a space, and its argument is verified against
        membership **in the database** by `session_set_space`. A view change grants
        nothing and is deliberately not audited: every read it enables is already bounded by
        membership and already covered by its own surface's events.
        """
        current, body = await guards.mutation(request, SpaceBody)
        space = UUID(body.space_id) if body.space_id else None
        # The guard has already compared this header to the session's own token, so it
        # is the token, and the answer carries it back rather than loading the session
        # a second time.
        csrf = request.headers["x-csrf-token"]

        def change() -> SessionView:
            with runtime.db.transaction(current.identity.tenant_id) as conn:
                store.identity_check(conn, current.identity, runtime.clock, current.identity.kind)
                check_session(conn, current, runtime.clock)
                set_current_space(conn, current, space)
            return _view(current, csrf)

        try:
            return await run_in_threadpool(change)
        except SpaceError as exc:
            raise refused(exc) from None
