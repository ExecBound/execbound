# SPDX-License-Identifier: AGPL-3.0-only
"""Factor enrollment and challenge. A pending session has access only to these forms."""

import functools
import hmac
import json
from importlib.resources import files
from typing import Any
from urllib.parse import quote

import anyio
import qrcode  # type: ignore[import-untyped]
import qrcode.image.svg  # type: ignore[import-untyped]
from fastapi import APIRouter, HTTPException, Request
from markupsafe import Markup
from starlette.concurrency import run_in_threadpool
from starlette.responses import RedirectResponse, Response

from execbound import mfa, passkeys
from execbound.envelope import EnvelopeError, KeyRing
from execbound.passwords import MAX_PASSWORD, MIN_PASSWORD, PasswordError, set_first_password
from execbound.runtime import Runtime
from execbound.surfaces.human import (
    HumanConfig,
    _page,
    _session_cookies,
    landing,
    request_guards,
)
from execbound.surfaces.login_return import destination
from execbound.surfaces.sessions import Session, load_session, verify_csrf
from execbound.user_accounts import password_record

# What a person reads when a first password is refused, by the refusal's code.
_FIRST_PASSWORD_PROBLEMS = {
    "INVALID_PASSWORD": f"Choose a password of at least {MIN_PASSWORD} characters.",
    "RECENT_AUTH_REQUIRED": (
        "Sign in again first, then add your password within five minutes. If two-step "
        "verification is on, verify with a new code below before you add it."
    ),
    "PASSWORD_EXISTS": (  # nosec B105 - A sentence for a person, not a credential.
        "Your account already has a password. Change it from your settings."
    ),
}


def mfa_router(runtime: Runtime, config: HumanConfig) -> APIRouter:
    routes = APIRouter()
    guards = request_guards(runtime, config)
    # Hashing a password is deliberately expensive; a few at a time, as the sign-in pages do.
    hashing = anyio.CapacityLimiter(4)

    def ring() -> KeyRing:
        if config.mfa is None:
            raise HTTPException(
                503, "Account security is not configured. Contact your administrator."
            )
        return config.mfa

    async def current(request: Request) -> tuple[Session, str]:
        await guards.boundary(request)
        cookies = guards.cookies(request)
        session = await run_in_threadpool(
            load_session,
            runtime.db,
            cookies.get(config.cookie("session"), ""),
            clock=runtime.clock,
            allow_pending_mfa=True,
        )
        csrf = cookies.get(config.cookie("csrf"), "")
        if not verify_csrf(session, csrf):
            raise HTTPException(403, "Invalid request")
        # Federated sessions must still pass the directory lifecycle recheck before MFA.
        if config.directory is not None:
            from execbound.directory_store import recheck_session

            await run_in_threadpool(recheck_session, runtime, config.directory, session)
        return session, csrf

    async def page(session: Session, csrf: str, **values: Any) -> Response:
        view = await run_in_threadpool(
            mfa.security_overview, runtime.db, session, clock=runtime.clock
        )
        # An account with no password may add one here (#593); a workspace-only session has
        # no account to add it to, and a password is changed from settings, never here.
        first_password = session.account_id is not None and (
            await run_in_threadpool(password_record, runtime.db, session.account_id) is None
        )
        defaults: dict[str, Any] = {
            "secret": None,  # nosec B105 - Empty template default, not a credential.
            "recovery": None,
            "problem": None,
            "notice": None,
            "options": None,
            "ceremony": None,
            "qr": None,
            "continue_to": "/settings",
        }
        defaults.update(values)
        # The second step of signing in gets a page of its own: one code, then on to the
        # console. Enrolling because an organization requires it, and every deliberate visit,
        # stay on Account security, where the factors are managed.
        challenge = view["required"] and view["enabled"] and not defaults["recovery"]
        # After a workspace switch the code opens that workspace, and the page says which.
        heading = (
            f"Verify to open {view['entering']}" if view["entering"] else "Two-step verification"
        )
        return _page(
            "mfa_challenge.html" if challenge else "mfa.html",
            service=config.service,
            title=heading if challenge else "Account security",
            session=None,
            csrf=csrf,
            view=view,
            admin=session.identity.kind == "ADMIN",
            available=config.mfa is not None,
            link_providers=config.providers if session.account_id is not None else (),
            first_password=first_password,
            minimum=MIN_PASSWORD,
            maximum=MAX_PASSWORD,
            **defaults,
        )

    @routes.get("/assets/account-security.js")
    async def script() -> Response:
        return Response(
            files("execbound.surfaces").joinpath("assets/account-security.js").read_text(),
            media_type="text/javascript",
            headers={"Cache-Control": "public, max-age=3600"},
        )

    def onward(request: Request, session: Session, signing_in: bool) -> str:
        """Where the person goes next: the review a sign-in began from, else where a sign-in
        lands for their role, or back to their settings from a deliberate visit."""
        fallback = landing(session.identity.kind) if signing_in else "/settings"
        return destination(request, config, runtime, fallback)

    async def verified_page(
        request: Request, session: Session, signing_in: bool, **values: Any
    ) -> Response:
        grant = await run_in_threadpool(
            mfa.rotate_verified_session, runtime.db, session, clock=runtime.clock
        )
        current_session = await run_in_threadpool(
            load_session, runtime.db, grant.token, clock=runtime.clock
        )
        response = await page(
            current_session,
            grant.csrf_token,
            continue_to=onward(request, session, signing_in),
            **values,
        )
        return _session_cookies(response, config, runtime, grant)

    async def signed_in(request: Request, session: Session) -> Response:
        """The second step of signing in succeeded: on to the console, not to a page about it."""
        grant = await run_in_threadpool(
            mfa.rotate_verified_session, runtime.db, session, clock=runtime.clock
        )
        return _session_cookies(
            RedirectResponse(onward(request, session, True), status_code=303),
            config,
            runtime,
            grant,
        )

    @routes.get("/mfa")
    @routes.get("/account/security")
    async def security_page(request: Request) -> Response:
        session, csrf = await current(request)
        return await page(session, csrf)

    # Declared before `/account/security/{operation}`, which would otherwise take this path.
    @routes.post("/account/security/password")
    async def first_password_change(request: Request) -> Response:
        session, csrf = await current(request)
        values = await guards.form(request)
        if set(values) != {"csrf", "password", "confirm"} or not hmac.compare_digest(
            values["csrf"].encode(), csrf.encode()
        ):
            raise HTTPException(403, "Invalid request")
        shown: dict[str, Any] = {}
        # As bytes: `hmac.compare_digest` refuses a `str` holding a character outside ASCII.
        if not hmac.compare_digest(values["password"].encode(), values["confirm"].encode()):
            shown["problem"] = "The two passwords are not the same."
        else:
            try:
                await anyio.to_thread.run_sync(
                    functools.partial(
                        set_first_password,
                        runtime.db,
                        session,
                        values["password"],
                        clock=runtime.clock,
                    ),
                    limiter=hashing,
                )
                shown["notice"] = (
                    "Your password is set. You can sign in with your address and this "
                    "password as well as with your provider. Your other sessions were signed out."
                )
            except PasswordError as exc:
                shown["problem"] = _FIRST_PASSWORD_PROBLEMS.get(
                    exc.code, "Your password could not be set. Try again."
                )
        # The change moved the account's version; reload the session it kept.
        session, csrf = await current(request)
        return await page(session, csrf, **shown)

    @routes.post("/account/security/{operation}")
    async def security_change(request: Request, operation: str) -> Response:
        if operation not in {"enroll", "confirm", "verify", "disable", "recovery", "policy"}:
            raise HTTPException(404, "Not found")
        session, csrf = await current(request)
        signing_in = session.mfa_required
        values = await guards.form(request)
        expected = {"csrf"} | (
            {"code"}
            if operation in {"confirm", "verify"}
            else {"requirement"}
            if operation == "policy"
            else set()
        )
        if set(values) != expected or not hmac.compare_digest(
            values.get("csrf", "").encode(), csrf.encode()
        ):
            raise HTTPException(403, "Invalid request")
        configured = ring()
        shown: dict[str, Any] = {}
        try:
            # Inside the `try`, so a read that fails here is the page's problem, as a change that
            # fails is, rather than a server error.
            if operation == "policy" and not await run_in_threadpool(
                mfa.sets_requirement, runtime.db, session, clock=runtime.clock
            ):
                # The requirement is the whole workspace's: refused before anything is written
                # to anybody who is not a workspace administrator, as the definer function
                # refuses it.
                raise HTTPException(
                    403, "Only a workspace administrator sets the organization's requirement."
                )
            if operation == "enroll":
                shown["secret"] = await run_in_threadpool(
                    mfa.begin_enrollment, runtime.db, session, configured, clock=runtime.clock
                )
                uri = (
                    f"otpauth://totp/{quote('ExecBound:' + str(session.identity.principal_id))}"
                    f"?secret={shown['secret']}&issuer=ExecBound&algorithm=SHA1&digits=6&period=30"
                )
                qr = qrcode.make(uri, image_factory=qrcode.image.svg.SvgPathImage)
                # The library emits SVG geometry for a server-generated seed and UUID.
                # No URI text or caller-supplied markup is embedded in the SVG.
                shown["qr"] = Markup(  # nosec B704 - library SVG has no caller markup
                    qr.to_string(encoding="unicode")
                )
            elif operation == "confirm":
                shown["recovery"] = await run_in_threadpool(
                    mfa.confirm_enrollment,
                    runtime.db,
                    session,
                    configured,
                    values["code"],
                    clock=runtime.clock,
                )
                shown["notice"] = (
                    "Multi-factor authentication is on. Save your recovery codes before continuing."
                )
            elif operation == "verify":
                checked = await run_in_threadpool(
                    mfa.check_factor,
                    runtime.db,
                    session,
                    configured,
                    values["code"],
                    clock=runtime.clock,
                )
                if checked is mfa.FactorCheck.VERIFIED:
                    shown["notice"] = (
                        "Identity verified. You can continue to your account or make a security "
                        "change below."
                    )
                elif checked is mfa.FactorCheck.REUSED:
                    shown["problem"] = (
                        "That code was just used. Wait for the next code from your "
                        "authenticator app, then enter it."
                    )
                else:
                    shown["problem"] = (
                        "That code could not be used. Enter a current authenticator code or an "
                        "unused recovery code. After five failed attempts, wait 15 minutes."
                    )
            else:
                codes = await run_in_threadpool(
                    mfa.manage_security,
                    runtime.db,
                    session,
                    operation,
                    values.get("requirement", "optional"),
                    clock=runtime.clock,
                )
                shown["recovery"] = codes or None
                shown["notice"] = "Your security settings were updated."
        except mfa.MfaError as exc:
            shown["problem"] = (
                (
                    "Verify your identity below first. For first-time setup, sign in again "
                    "and start within five minutes."
                )
                if exc.code == "RECENT_AUTH_REQUIRED"
                else (
                    "The security change could not be completed. Check your code, "
                    "enrollment expiry and organization requirements, then try again."
                )
            )
        except EnvelopeError:
            raise HTTPException(
                503, "Account security is temporarily unavailable. Contact your administrator."
            ) from None
        # Reload the same opaque session to reflect its newly established assurance.
        session, csrf = await current(request)
        if operation == "verify" and signing_in and shown.get("notice"):
            return await signed_in(request, session)
        if operation in {"verify", "confirm"} and shown.get("notice"):
            return await verified_page(request, session, signing_in, **shown)
        return await page(session, csrf, **shown)

    @routes.post("/account/security/passkey/{kind}/{stage}")
    async def passkey_change(request: Request, kind: str, stage: str) -> Response:
        if kind not in {"register", "authenticate", "remove"} or stage not in {"start", "finish"}:
            raise HTTPException(404, "Not found")
        session, csrf = await current(request)
        signing_in = session.mfa_required
        ring()
        values = await guards.form(request)
        expected = {"csrf"} | ({"credential"} if stage == "finish" or kind == "remove" else set())
        if set(values) != expected or not hmac.compare_digest(
            values["csrf"].encode(), csrf.encode()
        ):
            raise HTTPException(403, "Invalid request")
        try:
            if kind == "remove":
                await run_in_threadpool(
                    passkeys.remove, runtime.db, session, values["credential"], clock=runtime.clock
                )
                return await page(session, csrf, notice="Passkey removed.")
            if stage == "start":
                options = await run_in_threadpool(
                    passkeys.begin, runtime.db, session, config.origin, kind, clock=runtime.clock
                )
                return await page(session, csrf, options=json.dumps(options), ceremony=kind)
            credential = json.loads(values["credential"])
            if not isinstance(credential, dict):
                raise ValueError
            accepted = await run_in_threadpool(
                passkeys.complete,
                runtime.db,
                session,
                config.origin,
                kind,
                credential,
                clock=runtime.clock,
            )
            session, csrf = await current(request)
            if accepted and kind == "authenticate" and signing_in:
                return await signed_in(request, session)
            if accepted and kind == "authenticate":
                return await verified_page(request, session, False, notice="Identity verified.")
            return await page(
                session,
                csrf,
                notice="Passkey added."
                if kind == "register" and accepted
                else "Identity verified."
                if accepted
                else None,
                problem=None
                if accepted
                else (
                    "The passkey could not be verified. Start again and use a passkey "
                    "registered to this account."
                ),
            )
        except (mfa.MfaError, ValueError):
            return await page(
                session,
                csrf,
                problem=(
                    "Verify your identity first, then try again. You can save up to five passkeys."
                ),
            )

    return routes
