# SPDX-License-Identifier: AGPL-3.0-only
"""The routes a customer's own identity provider adds: the flow, the self-link and `/invite`.

Three of these run before a session exists, so they are server-rendered pages on the guards
`/login`, `/onboard` and `/set-password` already use: the exact `Origin` on every post, a CSRF
cookie compared with the field, the peer limit, and one sentence for every refusal with the
reason in the structured log alone.

One redirect URI serves every tenant, `<origin>/login/directory/callback`, so the callback
holds a provider id and no tenant at all and the transient cookie is what says which flow this
is. It carries #429's state, nonce and verifier and, beyond them, the provider and either the
invitation being redeemed or the person linking their own account. That cookie is the one
SameSite=Lax cookie this module sets, for the same reason #429's is: the directory's redirect
back is a cross-site top-level navigation and a Strict cookie would not be sent with it.

`/login/directory/callback` is declared before `/login/{provider}/callback`, which would
otherwise match it with `provider = "directory"`. The order is what decides, so it is stated
here and pinned by a test rather than left to whoever edits `app.py` next.
"""

import hmac
import re
import secrets
from uuid import UUID

from fastapi import APIRouter, HTTPException, Request
from starlette.concurrency import run_in_threadpool
from starlette.responses import HTMLResponse, RedirectResponse, Response

from execbound import directory_store as store
from execbound.directory import (
    DirectoryAccount,
    DirectoryConfig,
    DirectoryFlow,
    DirectoryProvider,
    DirectoryRefused,
    ProviderRow,
    new_flow,
)
from execbound.identity import Identity
from execbound.logging_schema import log_event
from execbound.runtime import Runtime
from execbound.surfaces.http import client_key
from execbound.surfaces.human import (
    HumanConfig,
    _page,
    landing,
    login_page,
    onward,
    request_guards,
    session_landing,
)
from execbound.surfaces.limits import RateLimited
from execbound.surfaces.login_return import destination
from execbound.surfaces.sessions import device_label, issue_session
from execbound.surfaces.sign_in_pages import MAX_CODE_BYTES

# One sentence for a code that never existed, one that expired, one that was already used, one
# that was revoked and one whose secret is wrong. A different sentence for any of them would say
# which, and a person holding a wrong code learns nothing from knowing which kind of wrong.
INVALID_CODE = "This invitation is not valid."
REFUSED = "That account cannot sign in here."
FLOW_COOKIE_SECONDS = 300
# The hint cookie's life. It authenticates nobody and carries no secret: it names the provider a
# previous successful sign-in used, so `/login` can offer that tenant's button to a browser that
# has already been through it. A browser that has not is told nothing, which is what keeps the
# sign-in form from becoming an oracle about which addresses exist and where they work.
HINT_COOKIE_SECONDS = 180 * 24 * 3600
_CSRF = re.compile(r"[A-Za-z0-9_-]{43}")
_UUID = re.compile(r"[0-9a-fA-F-]{36}")


def directory_router(runtime: Runtime, config: HumanConfig) -> APIRouter:
    routes = APIRouter()
    guards = request_guards(runtime, config)

    def directory() -> DirectoryConfig:
        """The deployment's key ring, or 404: with none, no tenant can hold a secret at all."""
        if config.directory is None:
            raise HTTPException(404, "Not found")
        return config.directory

    def refuse(peer: str) -> None:
        try:
            runtime.limiter.refuse("client", peer)
        except RateLimited as exc:
            raise HTTPException(
                429, "Too many attempts", headers={"Retry-After": str(exc.retry_after)}
            ) from None

    def checked_csrf(request: Request, values: dict[str, str], cookie: str) -> str:
        csrf = guards.cookies(request).get(config.cookie(cookie), "")
        if _CSRF.fullmatch(csrf) is None or not hmac.compare_digest(
            csrf.encode(), values.get("csrf", "").encode()
        ):
            raise HTTPException(403, "Invalid request")
        return csrf

    def started(
        settings: DirectoryConfig,
        location: str,
        flow: DirectoryFlow,
        response: Response | None = None,
    ) -> Response:
        answer = response if response is not None else RedirectResponse(location, status_code=303)
        answer.set_cookie(
            config.cookie("dirflow"),
            settings.seal_flow(flow),
            max_age=FLOW_COOKIE_SECONDS,
            httponly=True,
            secure=config.secure,
            samesite="lax",
            path="/",
        )
        return answer

    def cleared(response: Response) -> Response:
        response.delete_cookie(
            config.cookie("dirflow"), secure=config.secure, httponly=True, samesite="lax"
        )
        return response

    def refusal(csrf: str, code: str, status: int = 403) -> Response:
        log_event("directory.refused", level="WARNING", code=code)
        page = login_page(config, csrf, runtime=runtime, problem=REFUSED, status=status)
        return cleared(page)

    def invite_page(
        csrf: str,
        *,
        problem: str | None = None,
        status: int = 200,
        provider: str | None = None,
        authorize: str | None = None,
    ) -> HTMLResponse:
        page = _page(
            "invite.html",
            service=config.service,
            title="Redeem an invitation",
            session=None,
            csrf=csrf,
            problem=problem,
            provider=provider,
            authorize=authorize,
        )
        page.status_code = status
        if authorize is None:
            page.set_cookie(
                config.cookie("invite"),
                csrf,
                max_age=FLOW_COOKIE_SECONDS,
                httponly=True,
                secure=config.secure,
                samesite="strict",
                path="/",
            )
        return page

    @routes.get("/login/directory/callback")
    async def callback(request: Request) -> Response:
        # The query here is the directory's, not this application's, so the keys are read in
        # the handler rather than matched at the boundary: a client must ignore what it does
        # not recognise (RFC 6749, section 4.1.2), and refusing an unexpected parameter would
        # refuse the directory's own success before a line of sign-in code ran.
        await guards.boundary(request, None)
        settings = directory()
        refuse(client_key(request))
        csrf = secrets.token_urlsafe(32)
        supplied = dict(request.query_params.multi_items())
        names = [key for key, _ in request.query_params.multi_items()]
        if len(set(names)) != len(names):
            return refusal(csrf, "REPEATED_PARAMETER")
        if "error" in supplied:
            return refusal(csrf, "PROVIDER_ERROR")
        cookie = guards.cookies(request).get(config.cookie("dirflow"), "")
        try:
            flow = settings.open_flow(cookie)
            code = supplied.get("code", "")
            if not 0 < len(code) <= MAX_CODE_BYTES:
                raise DirectoryRefused("INVALID_CODE")
            # As bytes: the state is the directory's query parameter, as untrusted as the
            # rest of it, and `hmac.compare_digest` refuses a `str` outside ASCII.
            if not hmac.compare_digest(supplied.get("state", "").encode(), flow.state.encode()):
                raise DirectoryRefused("INVALID_STATE")
            row = await run_in_threadpool(store.locate_provider, runtime.db, UUID(flow.provider_id))
            if row is None:
                raise DirectoryRefused("INVALID_PROVIDER")
            if supplied.get("iss") is not None and supplied["iss"] != row.issuer:
                # RFC 9207: a directory that names itself must name the one this flow began at.
                raise DirectoryRefused("INVALID_ISSUER")
            provider = settings.provider(row)
            account = await run_in_threadpool(_complete, provider, code, flow, runtime)
        except DirectoryRefused as refused:
            return refusal(csrf, refused.code)
        except store.DirectoryError as exc:
            log_event("directory.refused", level="ERROR", code=exc.code)
            raise HTTPException(503, "Sign-in unavailable") from None
        if flow.link_principal is not None:
            return await _linked(request, settings, row, account, flow)
        return await _entered(request, settings, row, account, flow, csrf)

    async def _linked(
        request: Request,
        settings: DirectoryConfig,
        row: ProviderRow,
        account: DirectoryAccount,
        flow: DirectoryFlow,
    ) -> Response:
        """A person already signed in binds their own account, and nothing else changes.

        No credential is minted and no session is issued: the person has one already. Who is
        linking comes from the flow cookie rather than from that session, because this request
        is the directory's cross-site redirect back and a SameSite=Strict session cookie is not
        sent with it. The cookie carries a MAC, so the principal in it is the one this server
        wrote on a request it had already checked, and `directory_link_self` refuses a
        principal that is not an active administrator or approver of this provider's tenant.

        What this proves for a draft provider is that the issuer, the client id, the secret,
        the redirect URI and the subject claim are all right together, which is the only
        evidence worth enabling a provider on.
        """
        try:
            linked = await run_in_threadpool(
                store.link_self,
                runtime.db,
                row.tenant_id,
                UUID(str(flow.link_principal)),
                row.provider_id,
                account,
                clock=runtime.clock,
            )
        except store.DirectoryError as exc:
            return refusal(secrets.token_urlsafe(32), exc.code)
        target = "/tenant" if linked["kind"] == "ADMIN" else "/settings"
        # The same cross-site chain as a sign-in, and the person's session is Strict too, so
        # the next page is reached from a page of this site's own rather than by a 303.
        return cleared(_remembered(onward(target, "Linked.", config.service), row))

    async def _entered(
        request: Request,
        settings: DirectoryConfig,
        row: ProviderRow,
        account: DirectoryAccount,
        flow: DirectoryFlow,
        csrf: str,
    ) -> Response:
        invitation = UUID(flow.invitation_id) if flow.invitation_id is not None else None
        if invitation is None:
            # A subject with no link is refused and never created. The lookup is here rather
            # than in the store function so an account nobody linked costs one indexed read.
            found = await run_in_threadpool(
                store.locate_link, runtime.db, row.provider_id, account.subject
            )
            if found is None:
                return refusal(csrf, "NO_LINK")
        try:
            identity = await run_in_threadpool(
                _sign_in, runtime, settings, row, account, invitation
            )
        except store.DirectoryError as exc:
            if exc.code == "DIRECTORY_UNAVAILABLE":
                log_event("directory.refused", level="ERROR", code=exc.code)
                raise HTTPException(503, "Sign-in unavailable") from None
            return refusal(csrf, exc.code)
        granted = await run_in_threadpool(
            issue_session,
            runtime.db,
            identity,
            clock=runtime.clock,
            label=device_label(request.headers.get("user-agent")),
        )
        # The directory's redirect back is cross-site, so this lands on a page of this site's
        # own rather than redirecting on (`session_landing`), and the session stays Strict.
        answer = session_landing(
            config, runtime, granted, destination(request, config, runtime, landing(identity.kind))
        )
        return cleared(_remembered(answer, row))

    def _remembered(response: Response, row: ProviderRow) -> Response:
        """Name this tenant's provider to this browser, so `/login` can offer its button.

        It is set only after a sign-in through that provider succeeded, so it tells a stranger
        nothing: a browser that has never been through the flow carries none.
        """
        response.set_cookie(
            config.cookie("directory"),
            str(row.provider_id),
            max_age=HINT_COOKIE_SECONDS,
            httponly=True,
            secure=config.secure,
            samesite="lax",
            path="/",
        )
        return response

    @routes.post("/login/directory/{provider_id}")
    async def start(request: Request, provider_id: str) -> Response:
        # The key ring first: a deployment that was given none serves no directory route at
        # all, and saying 403 before 404 would say the route exists.
        settings = directory()
        values = await guards.form(request)
        checked_csrf(request, values, "login")
        if set(values) != {"csrf"}:
            raise HTTPException(403, "Invalid request")
        refuse(client_key(request))
        row = await _enabled(provider_id)
        flow = new_flow(str(row.provider_id))
        return started(settings, settings.provider(row).begin(flow), flow)

    @routes.get("/login/directory/{provider_id}/link")
    async def link(request: Request, provider_id: str) -> Response:
        """A signed-in person starts a sign-in that binds their own account.

        No CSRF field, because this is a navigation rather than a form post: the session cookie
        is SameSite=Strict and is simply not sent on a cross-site navigation, so a forged one
        answers 401 and starts nothing.

        A workspace administrator may start it through a draft, which is the test sign-in that
        verifies a registration; anybody else only through an enabled provider (My account's
        `Link my identity`). A draft or verified provider answers an approver, and since 0073
        an administrator narrowed to spaces, the 404 the public start answers, so the route
        says nothing about a registration they cannot use, and `directory_store.link_self` and
        `directory_link_self` refuse the same again on the way back.
        """
        # The session first here, unlike the two public routes: this one has a caller to
        # identify, and answering "not found" to an unauthenticated request before refusing it
        # would make the deployment's configuration the first thing a stranger learns.
        session, _ = await guards.session_for(request)
        settings = directory()
        identity = session.identity
        row = await _readable(identity.tenant_id, provider_id)
        if row.state != "enabled":
            # The session's kind refuses an approver without a database read; `configures`
            # asks the rest, whether this administrator is narrowed to spaces.
            if identity.kind != "ADMIN":
                raise HTTPException(404, "Not found")
            try:
                configures = await run_in_threadpool(
                    store.configures, runtime.db, identity.tenant_id, identity.principal_id
                )
            except store.DirectoryError:
                raise HTTPException(503, "Sign-in unavailable") from None
            if not configures:
                raise HTTPException(404, "Not found")
        flow = new_flow(str(row.provider_id), link_principal=str(session.identity.principal_id))
        return started(settings, settings.provider(row).begin(flow), flow)

    async def _enabled(provider_id: str) -> ProviderRow:
        row = await _located(provider_id)
        if row.state != "enabled":
            raise HTTPException(404, "Not found")
        return row

    async def _located(provider_id: str) -> ProviderRow:
        if _UUID.fullmatch(provider_id) is None:
            raise HTTPException(404, "Not found")
        try:
            row = await run_in_threadpool(store.locate_provider, runtime.db, UUID(provider_id))
        except (store.DirectoryError, ValueError):
            raise HTTPException(503, "Sign-in unavailable") from None
        if row is None:
            raise HTTPException(404, "Not found")
        return row

    async def _readable(tenant_id: UUID, provider_id: str) -> ProviderRow:
        row = await _located(provider_id)
        if row.tenant_id != tenant_id:
            raise HTTPException(404, "Not found")
        return row

    @routes.get("/invite")
    async def invite(request: Request) -> HTMLResponse:
        await guards.boundary(request)
        directory()
        return invite_page(secrets.token_urlsafe(32))

    @routes.post("/invite")
    async def redeem(request: Request) -> Response:
        settings = directory()
        values = await guards.form(request)
        csrf = checked_csrf(request, values, "invite")
        if set(values) != {"code", "csrf"}:
            raise HTTPException(403, "Invalid request")
        refuse(client_key(request))
        try:
            invitation, provider_id = await run_in_threadpool(
                store.check_invitation, runtime.db, values["code"]
            )
        except store.DirectoryError as exc:
            log_event("directory.refused", level="WARNING", code=exc.code)
            if exc.code == "DIRECTORY_UNAVAILABLE":
                raise HTTPException(503, "Sign-in unavailable") from None
            return invite_page(csrf, problem=INVALID_CODE, status=403)
        row = await _located(str(provider_id))
        flow = new_flow(str(row.provider_id), invitation_id=str(invitation))
        # The next step is an ordinary link rather than a redirect this response follows: the
        # page's `form-action` cannot name a host it could not know before the code was typed,
        # and a page that says which directory it is sending somebody to is the right thing on
        # a page reached with a one-time code anyway.
        page = invite_page("", provider=row.name, authorize=settings.provider(row).begin(flow))
        page.delete_cookie(
            config.cookie("invite"), secure=config.secure, httponly=True, samesite="strict"
        )
        return started(settings, "", flow, page)

    return routes


def _complete(
    provider: DirectoryProvider, code: str, flow: DirectoryFlow, runtime: Runtime
) -> DirectoryAccount:
    return provider.complete(code, flow, now=runtime.clock.now().timestamp())


def _sign_in(
    runtime: Runtime,
    settings: DirectoryConfig,
    row: ProviderRow,
    account: DirectoryAccount,
    invitation: UUID | None,
) -> Identity:
    return store.sign_in(
        runtime.db, settings, row, account, invitation_id=invitation, clock=runtime.clock
    )
