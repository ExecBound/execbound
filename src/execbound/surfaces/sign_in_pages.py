# SPDX-License-Identifier: AGPL-3.0-only
"""The sign-in routes that are not the credential exchange: a password, a configured
provider, and the public page a one-time code sets a password on.

They run before a session exists, so they are server-rendered pages on the same guards
`/login` and `/onboard` already use: the exact `Origin` on every post, a CSRF cookie
compared with the field, the peer and per-subject rate limits, and one sentence for every
refusal with the reason in the structured log alone. What proves who the person is differs;
what happens afterwards does not, because `session_response` issues the same cookies for
every method and `issue_session` is unchanged.

The two provider routes are written once over `HumanConfig.providers` rather than once per
provider, so Google and GitHub differ only in the module behind the name and a third
provider (#177) adds no route. A name
that is not a configured provider answers 404, so nothing a caller sends chooses a flow.

`/login/{provider}/callback` is the one address that has to accept a cross-site top-level
navigation, so the transient cookies it reads are the SameSite=Lax cookies this server sets
for that reason: `signin`, which carries the flow's state, nonce and PKCE verifier, and
`provider_signup`, which a plugin's own page sets beside it to mark a flow as one it started
as a signup (`start_provider_flow`, `ProviderSignup`). Each is `__Host-` prefixed and
HttpOnly: deleted by every answer that renders a page (`_clear`), while an answer that is a
bare 503 instead leaves it to expire in five minutes or be overwritten by the next flow's
own start.
"""

import functools
import hashlib
import hmac
import re
import secrets
from uuid import UUID

import anyio
from fastapi import APIRouter, HTTPException, Request
from starlette.concurrency import run_in_threadpool
from starlette.responses import HTMLResponse, RedirectResponse, Response

from execbound.db import UnsafeDatabaseRole
from execbound.identity import AuthenticationFailed, Identity, record_failure
from execbound.logging_schema import log_event
from execbound.passwords import (
    MAX_PASSWORD,
    MIN_PASSWORD,
    PasswordError,
    normalize_email,
    redeem_reset,
    sign_in_with_password,
)
from execbound.runtime import Runtime
from execbound.signin import (
    ExternalAccount,
    FlowState,
    SignInProvider,
    SignInRefused,
    new_flow,
    read_flow,
)
from execbound.surfaces.http import client_key
from execbound.surfaces.human import (
    HumanConfig,
    _page,
    landing,
    onward,
    request_guards,
    session_landing,
    session_response,
)
from execbound.surfaces.human import login_page as page_for
from execbound.surfaces.limits import RateLimited
from execbound.surfaces.login_return import destination, hinted_workspace
from execbound.surfaces.sessions import device_label, issue_session

# One sentence for a wrong address, a wrong password, a person who is not active and a tenant
# that is not: the private reason reaches `record_failure` and the structured log, never the
# browser. A different sentence for any of them would be an account oracle.
WRONG = "Those sign-in details are not right."
PROVIDER_REFUSED = "That account cannot sign in here."
INVALID_CODE = "This code is not valid."
WEAK = f"Choose a password of at least {MIN_PASSWORD} characters."
MISMATCHED = "The two passwords are not the same."
FLOW_COOKIE_SECONDS = 300
# An authorization code is the provider's to size (RFC 6749, section 4.1.2), so the bound is
# generous: Entra ID issued 2,208 characters on 21 September 2026, over the 2,048 this was,
# and Microsoft's have run past 4,000. It is still a bound, because this server sends the
# code on to the token endpoint. The directory callback uses this one too.
MAX_CODE_BYTES = 8192
MAX_PARAMETERS = 12
_CSRF = re.compile(r"[A-Za-z0-9_-]{43}")
_PARAMETER = re.compile(r"[A-Za-z0-9_.-]{1,32}")
_ERROR = re.compile(r"[a-z_]{1,64}")
# A signup intent cookie's own shape: a SHA-256 hex digest, lowercase, nothing else. Checked
# before any comparison, so a cookie of some other shape is refused on sight rather than
# measured against the flow's own digest, which `hmac.compare_digest` cannot do for a
# string carrying a non-ASCII character.
_SIGNUP_INTENT = re.compile(r"[0-9a-f]{64}")
# A plugin's own refusal code, the only shape this file will put a plugin's own text into
# the log as: upper-case words and underscores, the grammar every core code already uses.
# Anything else is a plugin's mistake, not a code, and is logged as `PLUGIN_FAILED` instead,
# so an address or some other value a careless plugin raises never reaches a log line.
_PLUGIN_CODE = re.compile(r"[A-Z_]{1,64}")


def email_selector(email: str) -> str:
    """The rate limiter's key for an address: its digest, so no address is held in memory."""
    return "pw:" + hashlib.sha256(email.encode("utf-8")).hexdigest()[:32]


def parameter_names(names: list[str]) -> str:
    """The query keys a callback arrived with, for the log: names only, never values.

    A provider writes this query, so the names are as untrusted as anything else it sends:
    each is kept only if it looks like a parameter name, the rest count as `unnamed`, and
    the list is bounded so a caller cannot write a long line into the log.
    """
    kept = sorted({name if _PARAMETER.fullmatch(name) else "unnamed" for name in names})
    return " ".join(kept[:MAX_PARAMETERS]) + (" ..." if len(kept) > MAX_PARAMETERS else "")


def provider_code(error: str) -> str:
    """The provider's own refusal word, bounded, for the log and nowhere else.

    `access_denied` and `redirect_uri_mismatch` are the two a deployment meets most, and
    they are the difference between a person pressing cancel and a misconfigured client.
    Anything that is not a plain OAuth error name is recorded as the fact that one came.
    """
    return f"PROVIDER_{error.upper()}" if _ERROR.fullmatch(error) else "PROVIDER_ERROR"


def _plugin_refusal(code: object) -> tuple[str, str]:
    """A plugin's own `SignInRefused(code)` turned into the code and level to log it at.

    A well-formed code is logged exactly as the plugin raised it, at the same `WARNING`
    every other refusal in this file logs at. Anything else, a value this is not a plugin's
    mistake to word as a code, becomes `PLUGIN_FAILED` at `ERROR`, the level the other ways a
    plugin can fail are logged at (`plugins.feature_failed`, `plugins.sign_in_link_failed`).
    """
    if type(code) is str and _PLUGIN_CODE.fullmatch(code):
        return code, "WARNING"
    return "PLUGIN_FAILED", "ERROR"


def start_provider_flow(
    config: HumanConfig, provider: SignInProvider, *, signup: bool
) -> RedirectResponse:
    """Begin a provider flow: the one transient Lax cookie every flow sets, plus the intent
    cookie that tells the callback which page started it.

    A flow is exactly one of an ordinary sign-in, a link or a signup, so starting one clears
    the other two flows' own leftover cookie: `provider_link` here, and `provider_signup`
    when ``signup`` is false. `provider_start` calls this with ``signup=False``; a plugin's
    own signup page (`/signup/google`) calls it with ``signup=True``, after which the
    callback dispatches to `LoadedPlugins.provider_signup` only if its own intent cookie's
    digest matches the flow that comes back (`provider_callback`).
    """
    flow = new_flow()
    response = RedirectResponse(provider.begin(flow), status_code=303)
    # The transient `signin` cookie every flow sets. The provider's redirect back is a
    # cross-site top-level navigation, and a Strict cookie would not be sent with it.
    # `__Host-` requires `Path=/`, which is why the path is not narrowed to the callback;
    # what bounds it instead is five minutes and deletion on first use. `provider_signup`,
    # set below only for a signup, is the same shape for the same reason.
    response.set_cookie(
        config.cookie("signin"),
        flow.encode(),
        max_age=FLOW_COOKIE_SECONDS,
        httponly=True,
        secure=config.secure,
        samesite="lax",
        path="/",
    )
    response.delete_cookie(
        config.cookie("provider_link"), secure=config.secure, httponly=True, samesite="lax"
    )
    if signup:
        response.set_cookie(
            config.cookie("provider_signup"),
            hashlib.sha256(flow.state.encode()).hexdigest(),
            max_age=FLOW_COOKIE_SECONDS,
            httponly=True,
            secure=config.secure,
            samesite="lax",
            path="/",
        )
    else:
        response.delete_cookie(
            config.cookie("provider_signup"), secure=config.secure, httponly=True, samesite="lax"
        )
    return response


def sign_in_router(runtime: Runtime, config: HumanConfig) -> APIRouter:
    routes = APIRouter()
    guards = request_guards(runtime, config)
    # A verification costs about sixty milliseconds and 32 MiB, so a flood queues here
    # rather than taking the process. The application's own in-flight cap bounds the queue.
    hashing = anyio.CapacityLimiter(4)

    def login_page(csrf: str, problem: str, status: int) -> HTMLResponse:
        # One definition of this page, shared with `/login` itself and with the directory
        # routes, so a refusal that lands back here shows the same buttons the page showed.
        return page_for(config, csrf, runtime=runtime, problem=problem, status=status)

    def checked_csrf(request: Request, values: dict[str, str], cookie: str) -> str:
        csrf = guards.cookies(request).get(config.cookie(cookie), "")
        if _CSRF.fullmatch(csrf) is None or not hmac.compare_digest(
            csrf.encode(), values.get("csrf", "").encode()
        ):
            raise HTTPException(403, "Invalid request")
        return csrf

    def refuse(peer: str, selector: str | None = None) -> None:
        try:
            runtime.limiter.refuse("client", peer)
            if selector is not None:
                runtime.limiter.refuse("login", selector)
        except RateLimited as exc:
            raise HTTPException(
                429, "Too many attempts", headers={"Retry-After": str(exc.retry_after)}
            ) from None

    def configured(name: str) -> SignInProvider:
        """The provider a path segment names, or 404. Nothing a caller sends adds one."""
        found = config.provider(name)
        if found is None:
            raise HTTPException(404, "Not found")
        return found

    @routes.post("/session/password")
    async def password_sign_in(request: Request) -> Response:
        values = await guards.form(request)
        csrf = checked_csrf(request, values, "login")
        if set(values) != {"email", "password", "csrf"}:
            raise HTTPException(403, "Invalid request")
        normalized = normalize_email(values["email"])
        refuse(client_key(request), email_selector(normalized or values["email"][:254]))
        # A signed hint naming a workspace-scoped approval opens that workspace when the account
        # may open it; only this completing sign-in chooses, never a page's GET.
        prefer = hinted_workspace(request, config, runtime)
        try:
            identity = await anyio.to_thread.run_sync(
                functools.partial(
                    sign_in_with_password,
                    runtime.db,
                    values["email"],
                    values["password"],
                    clock=runtime.clock,
                    prefer=prefer,
                ),
                limiter=hashing,
            )
        except AuthenticationFailed as failure:
            await run_in_threadpool(
                record_failure, runtime.db, "human", failure, runtime.clock.now()
            )
            return login_page(csrf, WRONG, 401)
        except PasswordError as exc:
            log_event("sign_in.refused", level="ERROR", method="password", code=exc.code)
            raise HTTPException(503, "Sign-in unavailable") from None
        return await _signed_in(request, identity)

    async def _signed_in(
        request: Request, identity: Identity, *, from_provider: bool = False
    ) -> Response:
        granted = await run_in_threadpool(
            issue_session,
            runtime.db,
            identity,
            clock=runtime.clock,
            label=device_label(request.headers.get("user-agent")),
        )
        # A provider's callback arrived cross-site, so it lands on a page of this site's own
        # rather than redirecting on; the password form posted from here and keeps the 303.
        answer = session_landing if from_provider else session_response
        return answer(
            config, runtime, granted, destination(request, config, runtime, landing(identity.kind))
        )

    @routes.post("/login/{provider}")
    async def provider_start(request: Request, provider: str) -> Response:
        values = await guards.form(request)
        checked_csrf(request, values, "login")
        if set(values) != {"csrf"}:
            raise HTTPException(403, "Invalid request")
        chosen = configured(provider)
        refuse(client_key(request))
        return start_provider_flow(config, chosen, signup=False)

    @routes.post("/account/link/{provider}")
    async def link_start(request: Request, provider: str) -> Response:
        from execbound.account_links import begin_link

        current, _, values = await guards.mutation(request)
        if set(values) != {"csrf"}:
            raise HTTPException(403, "Invalid request")
        chosen = configured(provider)
        refuse(client_key(request))
        flow = new_flow()
        try:
            token = await run_in_threadpool(
                begin_link, runtime.db, current, provider, flow, clock=runtime.clock
            )
        except SignInRefused:
            raise HTTPException(
                403, "Sign in again and verify your account before linking."
            ) from None
        request.state.form_action = (chosen.authorization_origin,)
        response = RedirectResponse(chosen.begin(flow), status_code=303)
        for name, value in (("signin", flow.encode()), ("provider_link", token)):
            response.set_cookie(
                config.cookie(name),
                value,
                max_age=FLOW_COOKIE_SECONDS,
                httponly=True,
                secure=config.secure,
                samesite="lax",
                path="/",
            )
        # A link flow is never a signup: a leftover intent cookie from an earlier `/signup`
        # would otherwise point the callback at a plugin's completion instead of `finish_link`.
        response.delete_cookie(
            config.cookie("provider_signup"), secure=config.secure, httponly=True, samesite="lax"
        )
        return response

    def _clear(response: Response) -> Response:
        response.delete_cookie(
            config.cookie("signin"), secure=config.secure, httponly=True, samesite="lax"
        )
        response.delete_cookie(
            config.cookie("provider_link"), secure=config.secure, httponly=True, samesite="lax"
        )
        response.delete_cookie(
            config.cookie("provider_signup"), secure=config.secure, httponly=True, samesite="lax"
        )
        return response

    def provider_refusal(
        request: Request,
        intent: str | None,
        csrf: str,
        provider: str,
        code: str,
        status: int = 403,
        parameters: str = "",
        level: str = "WARNING",
    ) -> Response:
        named = {"parameters": parameters} if parameters else {}
        log_event("sign_in.refused", level=level, method=provider, code=code, **named)
        signup = runtime.plugins.provider_signup
        if intent is not None and signup is not None:
            # A refusal mid-signup is the plugin's own page to show, never core's bare
            # login page, so a flow that began at `/signup` never quietly lands on `/login`.
            try:
                return _clear(signup.refused(runtime, config, request))
            except (HTTPException, UnsafeDatabaseRole):
                raise
            except Exception:
                # The plugin's own refused page failed too; its text is never logged, for
                # the same reason `finish`'s own failure below never is.
                log_event("sign_in.refused", level="ERROR", method=provider, code="PLUGIN_FAILED")
        return _clear(login_page(csrf, PROVIDER_REFUSED, status))

    @routes.get("/login/{provider}/callback")
    async def provider_callback(request: Request, provider: str) -> Response:
        # The query here is the provider's, not this application's: Google sends `scope`
        # with every success and usually `authuser` and `prompt` beside it, and both
        # providers answer a failure with `error`, `error_description` and `error_uri`. A
        # client must ignore what it does not recognise (RFC 6749, section 4.1.2), so the
        # keys are read below rather than matched exactly at the boundary, where refusing
        # them answered 400 before a line of sign-in code ran and told nobody why.
        await guards.boundary(request, None)
        chosen = configured(provider)
        # Before the exchange, not after: completing a flow makes this server call the
        # provider, so the peer limit has to bound that outbound call rather than only the
        # lookup behind it. The per-address limit comes once an address is known.
        refuse(client_key(request))
        csrf = secrets.token_urlsafe(32)
        names = [key for key, _ in request.query_params.multi_items()]
        supplied = dict(request.query_params.multi_items())
        cookies = guards.cookies(request)
        cookie = cookies.get(config.cookie("signin"), "")
        # Read once, here, rather than wherever a refusal is answered from: every refusal in
        # this function, early or late, shows the plugin's own page when this names a flow a
        # signup point is registered for (`provider_refusal`).
        intent = cookies.get(config.cookie("provider_signup"))
        arrived = parameter_names(names)
        if len(set(names)) != len(names):
            # One key twice is nothing either provider sends, and the last value would
            # silently win. It is refused rather than resolved.
            return provider_refusal(
                request, intent, csrf, provider, "REPEATED_PARAMETER", parameters=arrived
            )
        if "error" in supplied:
            # The provider refused before this server was ever going to call it: a person
            # pressed cancel, an organization's policy said no, the app is suspended. The
            # page says what every refusal says; the log carries the provider's own word.
            code = provider_code(supplied["error"])
            return provider_refusal(request, intent, csrf, provider, code, parameters=arrived)
        try:
            flow = read_flow(cookie)
            code = supplied.get("code", "")
            if not 0 < len(code) <= MAX_CODE_BYTES:
                # Its own name, not INVALID_STATE: a code past the bound looked exactly like
                # a forged state in the log, which is how a long code went unexplained.
                raise SignInRefused("INVALID_CODE")
            # Compared as bytes, never as `str`: `hmac.compare_digest` refuses a `str`
            # argument carrying a non-ASCII character, and the state is the provider's own
            # query parameter to size and fill, as untrusted as the rest of it.
            if not hmac.compare_digest(supplied.get("state", "").encode(), flow.state.encode()):
                raise SignInRefused("INVALID_STATE")
            account = await run_in_threadpool(_complete, chosen, code, flow, runtime)
        except SignInRefused as refused:
            return provider_refusal(
                request, intent, csrf, provider, refused.code, parameters=arrived
            )
        refuse(client_key(request), email_selector(account.email))
        link_token = cookies.get(config.cookie("provider_link"))
        if link_token is not None:
            from execbound.account_links import finish_link

            try:
                await run_in_threadpool(
                    finish_link, runtime.db, link_token, flow, account, clock=runtime.clock
                )
            except SignInRefused as refused:
                return provider_refusal(request, intent, csrf, provider, refused.code)
            return _clear(onward("/account/security", "Sign-in method linked", config.service))
        signup = runtime.plugins.provider_signup
        if intent is not None:
            if (
                signup is None
                or _SIGNUP_INTENT.fullmatch(intent) is None
                or not hmac.compare_digest(
                    intent.encode(), hashlib.sha256(flow.state.encode()).hexdigest().encode()
                )
            ):
                # No plugin registered a signup point, this cookie is not the one shape a
                # digest ever takes, or it names a flow that is not the one that just
                # completed: either way, nothing of the plugin's runs.
                return provider_refusal(request, intent, csrf, provider, "SIGNUP_REFUSED")
            try:
                answer = await signup.finish(runtime, config, request, account)
            except SignInRefused as refused:
                code, level = _plugin_refusal(refused.code)
                return provider_refusal(request, intent, csrf, provider, code, level=level)
            except (HTTPException, UnsafeDatabaseRole):
                raise
            except PasswordError as exc:
                # A person the store refuses is a refusal like any other; only an
                # unavailable store is a 503, exactly as the ordinary binding lookup below
                # answers the same fault, because retrying is the right answer to it alone.
                if exc.code == "PASSWORD_UNAVAILABLE":
                    log_event("sign_in.refused", level="ERROR", method=provider, code=exc.code)
                    raise HTTPException(503, "Sign-in unavailable") from None
                # Not necessarily a plugin's own code: a store can raise `PasswordError`
                # with whatever it likes, so this goes through the same shape check every
                # other plugin code does, the one `SignInRefused` already gets above.
                code, level = _plugin_refusal(exc.code)
                return provider_refusal(request, intent, csrf, provider, code, level=level)
            except Exception:
                # The plugin's own failure, never its text: that could carry its
                # configuration or a value from its database.
                return provider_refusal(
                    request, intent, csrf, provider, "PLUGIN_FAILED", level="ERROR"
                )
            if answer is None:
                # The subject already signs in: fall through to the ordinary binding
                # lookup below, exactly as a flow with no signup intent does.
                pass
            elif isinstance(answer, Response):
                return _clear(answer)
            else:
                # A plugin that answers something that is not a page at all is the same
                # mistake as any other unexpected failure: never let an `AttributeError`
                # from treating it as one crash into a bare 503 instead of this refusal.
                return provider_refusal(
                    request, intent, csrf, provider, "PLUGIN_FAILED", level="ERROR"
                )
        try:
            identity = await anyio.to_thread.run_sync(
                functools.partial(
                    _link, runtime, account, prefer=hinted_workspace(request, config, runtime)
                ),
                limiter=hashing,
            )
        except SignInRefused as refused:
            return provider_refusal(request, intent, csrf, provider, refused.code)
        except PasswordError as exc:
            # A person the store refuses is a refusal like any other; only an unavailable
            # store is a 503, because retrying is the right answer to exactly one of them.
            if exc.code == "PASSWORD_UNAVAILABLE":
                log_event("sign_in.refused", level="ERROR", method=provider, code=exc.code)
                raise HTTPException(503, "Sign-in unavailable") from None
            return provider_refusal(request, intent, csrf, provider, exc.code)
        return _clear(await _signed_in(request, identity, from_provider=True))

    def set_page(
        csrf: str, *, problem: str | None = None, status: int = 200, done: bool = False
    ) -> HTMLResponse:
        page = _page(
            "set_password.html",
            service=config.service,
            title="Set a password",
            session=None,
            csrf=csrf,
            problem=problem,
            done=done,
            minimum=MIN_PASSWORD,
            maximum=MAX_PASSWORD,
        )
        page.status_code = status
        if not done:
            page.set_cookie(
                config.cookie("reset"),
                csrf,
                max_age=FLOW_COOKIE_SECONDS,
                httponly=True,
                secure=config.secure,
                samesite="strict",
                path="/",
            )
        return page

    @routes.get("/set-password")
    async def set_password(request: Request) -> HTMLResponse:
        await guards.boundary(request)
        return set_page(secrets.token_urlsafe(32))

    @routes.post("/set-password")
    async def redeem(request: Request) -> HTMLResponse:
        values = await guards.form(request)
        csrf = checked_csrf(request, values, "reset")
        if set(values) != {"code", "password", "confirm", "csrf"}:
            raise HTTPException(403, "Invalid request")
        refuse(client_key(request))
        # As bytes: `hmac.compare_digest` refuses a `str` holding a character outside ASCII,
        # and a person's password may hold any character.
        if not hmac.compare_digest(values["password"].encode(), values["confirm"].encode()):
            return set_page(csrf, problem=MISMATCHED, status=400)
        try:
            await anyio.to_thread.run_sync(
                functools.partial(
                    redeem_reset,
                    runtime.db,
                    values["code"],
                    values["password"],
                    clock=runtime.clock,
                ),
                limiter=hashing,
            )
        except PasswordError as exc:
            log_event("password.refused", level="WARNING", code=exc.code)
            if exc.code == "INVALID_PASSWORD":
                return set_page(csrf, problem=WEAK, status=400)
            if exc.code == "PASSWORD_UNAVAILABLE":
                raise HTTPException(503, "Sign-in unavailable") from None
            return set_page(csrf, problem=INVALID_CODE, status=403)
        page = set_page("", done=True)
        page.delete_cookie(
            config.cookie("reset"), secure=config.secure, httponly=True, samesite="strict"
        )
        return page

    return routes


def _complete(
    provider: SignInProvider, code: str, flow: FlowState, runtime: Runtime
) -> ExternalAccount:
    return provider.complete(code, flow, now=runtime.clock.now().timestamp())


def _link(runtime: Runtime, account: ExternalAccount, *, prefer: UUID | None = None) -> Identity:
    """Sign in an already-bound subject; matching email never creates a binding. `prefer` is
    the workspace a signed hint names, opened only when the account may open it."""
    from execbound.user_accounts import provider_sign_in

    return provider_sign_in(runtime.db, account, clock=runtime.clock, prefer=prefer)
