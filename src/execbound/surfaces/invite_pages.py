# SPDX-License-Identifier: AGPL-3.0-only
"""Teammate invitation acceptance pages (#487): opening an invitation link, and accepting it
either as a new address or as a signed-in account.

`GET /join` is static: a scanner, a prefetch or a person all get the same page and nothing
changes. The page's own script moves the secret from the fragment into the form, and
`POST /join` (the exchange) only reads what the link is for, through `inspect_invitation`,
which changes nothing but the failure count. Only `POST /join/accept` (a new address) or
`POST /join/confirm` (a signed-in account) joins anything, through `accept_invitation`.

The link `invitations.invite_link` mints is `<origin>/join#ebt1.<tenant>.<invitation>.<secret>`.
The page is `/join`, not `/invite`: `directory_pages.py` already serves `GET/POST /invite` for
the customer-directory one-time invitation code (#241), registered ahead of this router, and
Starlette hands a request to the first route that matches path and method, so a second
`/invite` route here would never be reached. See `invitations.py`'s module docstring.
"""

import hmac
import re
import secrets
from importlib.resources import files
from typing import Any

from fastapi import APIRouter, HTTPException, Request
from sqlalchemy.exc import SQLAlchemyError
from starlette.concurrency import run_in_threadpool
from starlette.responses import HTMLResponse, Response

from execbound.access_control import ROLES
from execbound.invitations import (
    InvitationError,
    accept_invitation,
    inspect_invitation,
    invitation_selectors,
    sign_in_invited_account,
)
from execbound.runtime import Runtime
from execbound.surfaces.http import client_key
from execbound.surfaces.human import HumanConfig, _page, landing, request_guards, session_response
from execbound.surfaces.limits import RateLimited
from execbound.surfaces.sessions import SessionError, device_label, issue_session
from execbound.user_accounts import locate_account

_CSRF = re.compile(r"[A-Za-z0-9_-]{43}")
PASSWORDS = "Passwords must match and be at least 12 characters."
# One status per result page, whichever route shows it: a page that only says what happens
# next is 200; an account or session this person may not use here is 403; a fault on our own
# side, with the link still good, is 503.
RESULT_STATUS = {
    "joined": 200,
    "ready": 200,
    "sign_in_first": 200,
    "mismatch": 403,
    "revoked": 403,
    "invalid": 403,
    "retry": 503,
}

_ROLE_NAMES = {str(role["id"]): str(role["name"]) for role in ROLES}


def _grant_labels(grants: list[dict[str, Any]], space_names: dict[str, str]) -> list[str]:
    """Plain words for a role grant: "Viewer in all Spaces", "Approver in Payments"."""
    labels = []
    for grant in grants:
        name = _ROLE_NAMES.get(str(grant.get("role")), str(grant.get("role")))
        space_id = grant.get("space_id")
        where = "all Spaces" if space_id is None else space_names.get(space_id, "a Space")
        labels.append(f"{name} in {where}")
    return labels


def _private(page: HTMLResponse) -> HTMLResponse:
    page.headers["Cache-Control"] = "no-store"
    return page


def invite_router(runtime: Runtime, config: HumanConfig) -> APIRouter:
    routes = APIRouter()
    guards = request_guards(runtime, config)
    cookie = config.cookie("invite_open")

    def with_cookie(page: HTMLResponse, csrf: str) -> HTMLResponse:
        page.set_cookie(
            cookie,
            csrf,
            max_age=1800,
            httponly=True,
            secure=config.secure,
            samesite="strict",
            path="/",
        )
        return _private(page)

    def open_page(csrf: str, problem: str | None = None, status: int = 200) -> HTMLResponse:
        page = _page(
            "invite_open.html",
            service=config.service,
            title="Open your invitation",
            session=None,
            csrf=csrf,
            problem=problem,
        )
        page.status_code = status
        return with_cookie(page, csrf)

    def result(kind: str, *, workspace: str = "") -> HTMLResponse:
        page = _page(
            "invite_result.html",
            service=config.service,
            title="Teammate invitation",
            session=None,
            csrf="",
            kind=kind,
            workspace=workspace,
        )
        page.status_code = RESULT_STATUS[kind]
        return _private(page)

    def accept_page(
        csrf: str,
        token: str,
        *,
        existing: bool,
        workspace: str = "",
        inviter: str | None = None,
        grant_labels: list[str] | None = None,
        problem: str | None = None,
    ) -> HTMLResponse:
        return _page(
            "invite_accept.html",
            service=config.service,
            title="Join the workspace",
            session=None,
            csrf=csrf,
            token=token,
            existing=existing,
            workspace=workspace,
            inviter=inviter,
            grant_labels=grant_labels or [],
            problem=problem,
        )

    def checked(request: Request, values: dict[str, str]) -> str:
        csrf = guards.cookies(request).get(cookie, "")
        if not _CSRF.fullmatch(csrf) or not hmac.compare_digest(
            csrf.encode(), values.get("csrf", "").encode()
        ):
            raise HTTPException(403, "Invalid request")
        return csrf

    def limited(request: Request, token: str) -> None:
        try:
            runtime.limiter.refuse("client", client_key(request))
            _, invitation = invitation_selectors(token)
            runtime.limiter.refuse("login", f"ebt1:{invitation}")
        except RateLimited as exc:
            raise HTTPException(
                429, "Too many attempts", headers={"Retry-After": str(exc.retry_after)}
            ) from None

    def token_of(values: dict[str, str]) -> str:
        token, pasted = values.get("token", ""), values.get("pasted", "").strip()
        if token and pasted:
            raise HTTPException(403, "Invalid request")
        if pasted:
            # A pasted whole link: keep only what follows the fragment mark.
            token = pasted.split("#", 1)[1] if "#" in pasted else pasted
        return token

    @routes.get("/assets/invite.js")
    async def script(request: Request) -> Response:
        await guards.boundary(request)
        return Response(
            files("execbound.surfaces").joinpath("assets/invite.js").read_text(),
            media_type="text/javascript",
        )

    @routes.get("/join")
    async def open_join(request: Request) -> HTMLResponse:
        await guards.boundary(request)
        # A second tab opening the same link must not break the first: reuse a well-formed
        # cookie the request already carries instead of minting a fresh one, which would
        # leave the first tab's own embedded csrf no longer matching the cookie.
        carried = guards.cookies(request).get(cookie, "")
        csrf = carried if _CSRF.fullmatch(carried) else secrets.token_urlsafe(32)
        return open_page(csrf)

    async def _signed_in_as(request: Request, email: str) -> bool | None:
        """True for this address's account, False for another account, None for nobody.

        A browser with no session cookie at all, or a session still waiting on its MFA, fails
        inside `load_session`/`check_session` with `SessionError`, not an `HTTPException`; the
        CSRF and header checks in `guards.boundary` can also refuse a malformed request the
        same way an ordinary anonymous GET would look. Every one of those reads as "not signed
        in" here, so a pending-MFA session is sent to sign in again rather than ever shown the
        invalid or mismatch page.
        """
        try:
            session, _ = await guards.session_for(request)
        except (SessionError, HTTPException):
            return None
        if session.account_id is None:
            return None
        found = await run_in_threadpool(locate_account, runtime.db, email)
        return found is not None and found["account_id"] == session.account_id

    @routes.post("/join")
    async def exchange(request: Request) -> HTMLResponse:
        values = await guards.form(request)
        if not set(values) <= {"csrf", "token", "pasted"} or "csrf" not in values:
            raise HTTPException(403, "Invalid request")
        csrf = checked(request, values)
        token = token_of(values)
        try:
            limited(request, token)
            seen = await run_in_threadpool(
                inspect_invitation, runtime.db, token, clock=runtime.clock
            )
        except InvitationError as exc:
            if exc.code == "INVITATION_UNAVAILABLE":
                return result("retry")
            return result("invalid")
        if seen.state == "EXPIRED":
            return result("invalid")
        if seen.state == "REVOKED":
            return result("revoked")
        if seen.state == "ACCEPTED":
            return result("ready")
        labels = _grant_labels(seen.grants, seen.space_names)
        if seen.account == "new":
            page = accept_page(
                csrf,
                token,
                existing=False,
                workspace=seen.workspace,
                inviter=seen.inviter,
                grant_labels=labels,
            )
            return with_cookie(page, csrf)
        signed_in = await _signed_in_as(request, seen.email)
        if signed_in is None:
            return result("sign_in_first")
        if signed_in is False:
            return result("mismatch")
        session_csrf = guards.cookies(request).get(config.cookie("csrf"), "")
        page = accept_page(
            session_csrf,
            token,
            existing=True,
            workspace=seen.workspace,
            inviter=seen.inviter,
            grant_labels=labels,
        )
        return _private(page)

    @routes.post("/join/accept")
    async def accept(request: Request) -> Response:
        values = await guards.form(request)
        if set(values) != {"csrf", "token", "password", "confirm"}:
            raise HTTPException(403, "Invalid request")
        csrf = checked(request, values)
        token = values["token"]

        def again(problem: str, status: int = 400) -> HTMLResponse:
            page = accept_page(csrf, token, existing=False, problem=problem)
            page.status_code = status
            return with_cookie(page, csrf)

        # `limited` and `accept_invitation` share this block: a malformed token fails inside
        # `invitation_selectors`, which `limited` calls too, and that is `InvitationError`
        # like everything else here, not an exception this route lets escape uncaught.
        try:
            limited(request, token)
            if values["password"] != values["confirm"]:
                return again(PASSWORDS)
            accepted = await run_in_threadpool(
                accept_invitation,
                runtime.db,
                token,
                password=values["password"],
                clock=runtime.clock,
            )
        except InvitationError as exc:
            # `inspect_invitation` and `accept_invitation` already log every refusal by its
            # code through `invitations._refuse`; a second log line here would only repeat it.
            if exc.code == "INVALID_PASSWORD":
                return again(PASSWORDS)
            if exc.code == "ACCOUNT_EXISTS":
                return result("sign_in_first")
            if exc.code == "INVITATION_REVOKED":
                return result("revoked")
            if exc.code == "INVITATION_UNAVAILABLE":
                return result("retry")
            return result("invalid")
        if accepted.outcome == "ALREADY":
            return result("ready")
        try:
            identity = await run_in_threadpool(
                sign_in_invited_account, runtime.db, accepted, clock=runtime.clock
            )
            granted = await run_in_threadpool(
                issue_session,
                runtime.db,
                identity,
                clock=runtime.clock,
                label=device_label(request.headers.get("user-agent")),
            )
        except (SessionError, InvitationError, SQLAlchemyError):
            # The membership exists; a normal sign-in reaches it.
            return result("ready")
        answer = session_response(config, runtime, granted, landing(identity.kind))
        answer.delete_cookie(cookie, secure=config.secure, httponly=True, samesite="strict")
        return answer

    @routes.post("/join/confirm")
    async def confirm(request: Request) -> HTMLResponse:
        session, csrf, values = await guards.mutation(request)
        if set(values) != {"csrf", "token"}:
            raise HTTPException(403, "Invalid request")
        token = values["token"]
        account_token = guards.cookies(request).get(config.cookie("account"), "")
        try:
            limited(request, token)
            await run_in_threadpool(
                accept_invitation,
                runtime.db,
                token,
                session=session,
                account_token=account_token,
                clock=runtime.clock,
            )
        except InvitationError as exc:
            if exc.code == "ACCOUNT_MISMATCH":
                return result("mismatch")
            if exc.code == "INVITATION_REVOKED":
                return result("revoked")
            if exc.code == "INVITATION_UNAVAILABLE":
                return result("retry")
            # `ALREADY_MEMBER`: this account already holds an active membership in this
            # tenant, however it got there. That is "joined" too, so it falls through to the
            # same re-read below rather than a refusal.
            if exc.code != "ALREADY_MEMBER":
                return result("invalid")
        # Success and the retry of an already-committed acceptance (`Accepted("ALREADY", ...)`)
        # both land here alongside `ALREADY_MEMBER`, all with the one true fact: the account is
        # a member. The workspace name is not carried on `Accepted`, so it is read back once,
        # fenced, exactly as `inspect_invitation` reads it for the exchange page above.
        seen = await run_in_threadpool(inspect_invitation, runtime.db, token, clock=runtime.clock)
        return result("joined", workspace=seen.workspace)

    return routes
