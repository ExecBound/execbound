# SPDX-License-Identifier: AGPL-3.0-only
import os
import threading
import time
from collections.abc import AsyncIterator, Awaitable, Callable
from contextlib import AsyncExitStack, asynccontextmanager
from importlib.resources import files
from pathlib import Path
from typing import Annotated
from uuid import UUID, uuid4

import anyio
from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.exception_handlers import http_exception_handler
from fastapi.responses import JSONResponse, Response
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy.exc import SQLAlchemyError
from starlette.exceptions import HTTPException as StarletteHTTPException

from execbound.arcade.map import ArcadeBlock, ToolMap
from execbound.arcade.routes import arcade_router
from execbound.build import package_version, running_commit
from execbound.config import Settings
from execbound.db import Database, UnsafeDatabaseRole, check_runtime
from execbound.execution.models import ExecutionError
from execbound.identity import AuthenticationFailed, Identity, authenticate
from execbound.logging_schema import install as install_logging
from execbound.logging_schema import log_event, reset_request_id, set_request_id
from execbound.monitoring.http import monitor_router
from execbound.monitoring.models import MONITOR_STATUS, MonitorError
from execbound.plugins import NO_PLUGINS, PLUGIN_API_VERSION, check_paths, plugin_pages
from execbound.runtime import Runtime
from execbound.service_links import ServiceLinks
from execbound.signals.http import signal_router
from execbound.signals.intake import SIGNAL_STATUS, SignalError
from execbound.surfaces.configuration import (
    KeyReload,
    load_runtime,
    read_configuration,
    reload_keys,
)
from execbound.surfaces.console import (
    CONSOLE_POLICY,
    build_edition,
    console_matcher,
    console_router,
    is_console_api,
    is_console_path,
    load_build,
    page_policy,
)
from execbound.surfaces.console_api import console_api_router
from execbound.surfaces.console_api.errors import ApiError, api_error_response
from execbound.surfaces.directory_pages import directory_router
from execbound.surfaces.http import error_status, router
from execbound.surfaces.human import HumanConfig, error_page, human_router, wants_html
from execbound.surfaces.limits import RateLimited
from execbound.surfaces.mcp import create_mcp
from execbound.surfaces.sessions import SessionError
from execbound.surfaces.sign_in_pages import sign_in_router

bearer = HTTPBearer(auto_error=False)
# Requests this process serves at once, held by the outermost middleware below and named
# here because the hook surface derives its own, smaller bound from it: a control point's
# refusal has to be a hook answer, and this middleware's 429 is not one.
REQUESTS_IN_FLIGHT = 32


def _default_no_store(response: Response) -> None:
    """Every console response is `no-store`: it is somebody's tenant, read under their
    session, and a shared cache must never hold it. The public showcase is the one response
    that is nobody's in particular (one configured tenant, no session, no cookie) and it sets
    its own directive, which this must not overwrite. An answer that carries a secret, such as
    a minted reporting token, sets `no-store` itself rather than relying on this default."""
    if "Cache-Control" not in response.headers:
        response.headers["Cache-Control"] = "no-store"


def create_app(
    database: Database | None = None,
    *,
    runtime: Runtime | None = None,
    human: HumanConfig | None = None,
    arcade: ArcadeBlock | None = None,
    human_surface: bool = True,
) -> FastAPI:
    """The application, and with `human_surface` false the same one serving no human routes.

    A private configuration file always names an `origin`, so the factory path below always
    builds a `HumanConfig` from it. A process that serves only the hooks must not take that
    origin as its own: the `response_headers` middleware refuses every request whose `Host`
    header is not the configured origin's netloc, and that process answers at a hostname of
    its own. `human_surface` is what separates holding the configuration — the key rings
    reload against it — from serving the pages and applying the rule that belongs to them.
    """
    db = database or Database(Settings().database_url.get_secret_value())  # type: ignore[call-arg]
    owns_runtime = False
    key_reload: KeyReload | None = None
    reload: Callable[[], KeyReload] | None = None
    if database is None and runtime is None and os.environ.get("EXECBOUND_RUNTIME_CONFIG"):
        private = Path(os.environ["EXECBOUND_RUNTIME_CONFIG"])
        runtime, configured = load_runtime(private, db)
        human = configured if human_surface else None
        owns_runtime = True
        baseline = read_configuration(private)
        key_reload = KeyReload("current" if baseline.key_reload_seconds else "disabled")
        reload_lock = threading.Lock()

        def reload() -> KeyReload:
            # Serialized so a poll and an operator-triggered check cannot interleave. The
            # key rings rotate against the configuration's own human surface whether or not
            # this process serves it, because that is where the continuation ring lives.
            nonlocal key_reload
            assert runtime is not None
            with reload_lock:
                current = key_reload.configuration if key_reload is not None else None
                result = reload_keys(private, runtime, configured, current or baseline)
                key_reload = result
                return result

        key_reload = KeyReload(key_reload.state, configuration=baseline)
        # The tool map is the same declaration the gateway reads, from the same file: two
        # processes given different files would disagree about what is governed. A block
        # passed in wins, so a test and the boundary can each construct one explicitly.
        arcade = arcade or baseline.arcade
    # The pages' policy, fixed once: `form-action` names the hosts this deployment's own
    # sign-in buttons redirect to, and nothing a request sends can add one.
    configured_origins = (
        tuple(provider.authorization_origin for provider in human.providers) if human else ()
    )
    pages_policy = page_policy(configured_origins)
    # What an error page's footer links to: the deployment's own, or none without a human
    # surface, which serves no page that could have linked to one.
    service = human.service if human is not None else ServiceLinks()
    # The console's paths and any a loaded plugin added, fixed once like the policy above.
    console_pages = console_matcher(runtime.plugins if runtime is not None else NO_PLUGINS)
    # The packaged console build, read once for a human surface: the console router serves it,
    # and readiness reports the edition its document names (#496), so a deployment can
    # see which console it serves. None without a human surface or a build.
    console_build = load_build() if human is not None else None
    console_edition = build_edition(console_build)
    mcp_server, mcp_app = (
        create_mcp(runtime, human.origin if human else None)
        if runtime is not None
        else (None, None)
    )

    async def watch_keys(seconds: int) -> None:
        assert reload is not None
        while True:
            await anyio.sleep(seconds)
            await anyio.to_thread.run_sync(reload)

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        try:
            async with AsyncExitStack() as stack:
                if mcp_server is not None:
                    await stack.enter_async_context(mcp_server.session_manager.run())
                seconds = (
                    key_reload.configuration.key_reload_seconds
                    if key_reload is not None and key_reload.configuration is not None
                    else 0
                )
                if reload is not None and seconds > 0:
                    group = await stack.enter_async_context(anyio.create_task_group())
                    group.start_soon(watch_keys, seconds)
                    stack.callback(group.cancel_scope.cancel)
                yield
        finally:
            if owns_runtime and runtime is not None:
                for connector in runtime.connectors.values():
                    connector.close()
            if database is None:
                db.close()

    app = FastAPI(
        title="ExecBound",
        version=package_version(),
        lifespan=lifespan,
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
    )
    requests_in_flight = anyio.CapacityLimiter(REQUESTS_IN_FLIGHT)
    install_logging()

    def surface_of(path: str) -> str:
        if path.startswith("/mcp"):
            return "mcp"
        if path.startswith("/v1/monitor"):
            return "monitor"
        if path.startswith("/v1/signals"):
            return "signal"
        if path.startswith("/v1/") or path.startswith("/health/"):
            return "http"
        if path in ("/pre", "/post"):
            # Both hook paths are labelled arcade; without this the control point's traffic
            # would be logged as the human one.
            return "arcade"
        return "human"

    @app.middleware("http")
    async def request_identity(
        request: Request, call_next: Callable[[Request], Awaitable[Response]]
    ) -> Response:
        supplied = request.headers.get("x-request-id", "")
        try:
            request_id = str(UUID(supplied)) if len(supplied) == 36 else str(uuid4())
        except ValueError:
            request_id = str(uuid4())
        token = set_request_id(request_id)
        started = time.monotonic()
        try:
            response = await call_next(request)
        finally:
            reset_request_id(token)
        response.headers["X-Request-Id"] = request_id
        log_event(
            "request.completed",
            request_id=request_id,
            surface=surface_of(request.url.path),
            status=response.status_code,
            duration_ms=int((time.monotonic() - started) * 1000),
        )
        return response

    @app.middleware("http")
    async def response_headers(
        request: Request, call_next: Callable[[Request], Awaitable[Response]]
    ) -> Response:
        ambiguous_identity = len(request.headers.getlist("authorization")) > 1
        if human is not None:
            from urllib.parse import urlsplit

            ambiguous_identity |= request.headers.getlist("host") != [urlsplit(human.origin).netloc]
        if request.url.path == "/v1/me":
            ambiguous_identity |= bool(request.query_params) or any(
                name in request.headers for name in ("x-tenant-id", "x-principal-id", "x-role")
            )
            # This endpoint has no body contract. Reject framed bodies before reading them.
            ambiguous_identity |= (
                request.headers.get("content-length", "0") != "0"
                or "transfer-encoding" in request.headers
            )
        if ambiguous_identity:
            response: Response = JSONResponse(
                status_code=400, content={"detail": "Unsupported or ambiguous identity fields"}
            )
        else:
            try:
                requests_in_flight.acquire_nowait()
            except anyio.WouldBlock:
                response = JSONResponse({"detail": "Service busy"}, status_code=429)
            else:
                try:
                    response = await call_next(request)
                    renewal = getattr(request.state, "session_renewal", None)
                    if renewal is not None and human is not None and runtime is not None:
                        # The session row was just extended; the browser must keep the
                        # same cookies as long. Values are the request's own, unchanged.
                        ttl = max(0, int((renewal - runtime.clock.now()).total_seconds()))
                        for name in ("session", "csrf"):
                            value = request.cookies.get(human.cookie(name))
                            if value is not None:
                                response.set_cookie(
                                    human.cookie(name),
                                    value,
                                    max_age=ttl,
                                    httponly=True,
                                    secure=human.secure,
                                    samesite="strict",
                                    path="/",
                                )
                except Exception:
                    # Do not let server middleware log unexpected diagnostics
                    # after sending an otherwise safe error response.
                    response = JSONResponse({"detail": "Service unavailable"}, status_code=503)
                finally:
                    requests_in_flight.release()
        _default_no_store(response)
        response.headers["X-Content-Type-Options"] = "nosniff"
        # The console takes its own policy by path prefix alone, never by anything a client
        # sends; every other response keeps the pages' policy unchanged.
        # A tenant's own identity provider is a row, so its authorization host cannot be in
        # the policy fixed above: the page that offers its button names it on that response
        # alone, through `request.state.form_action`. The value is read from the provider's row,
        # which a discovery fetch validated as an https origin at registration, and a handler
        # can only ever add a host to `form-action` this way, never remove one or change any
        # other directive.
        extra = getattr(request.state, "form_action", ())
        response.headers["Content-Security-Policy"] = (
            CONSOLE_POLICY
            if is_console_path(request.url.path, console_pages)
            else (page_policy(configured_origins + tuple(extra)) if extra else pages_policy)
        )
        if is_console_path(request.url.path, console_pages):
            # The release the client compares with its built one (#333).
            response.headers["X-ExecBound-Release"] = running_commit() or ""
        generation = getattr(request.state, "workspace_generation", None)
        if generation is not None:
            response.headers["X-ExecBound-Workspace"] = generation
        # A page whose address carries a secret says so itself (the weekly summary's one-click
        # unsubscribe, #678) and keeps the stricter policy; every other page is same-origin.
        if response.headers.get("Referrer-Policy") != "no-referrer":
            response.headers["Referrer-Policy"] = "same-origin"
        response.headers["X-Frame-Options"] = "DENY"
        if human is not None and human.secure:
            response.headers["Strict-Transport-Security"] = "max-age=31536000"
        return response

    async def unavailable(request: Request, exc: Exception) -> JSONResponse:
        log_event("dependency.unavailable", level="ERROR", surface=surface_of(request.url.path))
        return JSONResponse(status_code=503, content={"detail": "Service unavailable"})

    app.add_exception_handler(SQLAlchemyError, unavailable)
    app.add_exception_handler(UnsafeDatabaseRole, unavailable)
    app.add_exception_handler(Exception, unavailable)

    @app.exception_handler(HTTPException)
    async def http_error(request: Request, exc: HTTPException) -> Response:
        # Browsers get a page with the same status and generic copy; clients get JSON. The
        # console API answers JSON with a typed code to everyone, a browser included.
        if is_console_api(request.url.path):
            code = exc.code if isinstance(exc, ApiError) else None
            fields = exc.fields if isinstance(exc, ApiError) else None
            return api_error_response(exc.status_code, code, fields=fields, headers=exc.headers)
        if wants_html(request):
            return error_page(exc.status_code, exc.headers, service=service)
        return await http_exception_handler(request, exc)

    @app.exception_handler(StarletteHTTPException)
    async def routing_error(request: Request, exc: StarletteHTTPException) -> Response:
        # The router's own refusals (a method the path does not take, a path that does not
        # exist) are Starlette's exception, not FastAPI's; the console API still answers them
        # with a typed code, and everything else keeps the default answer.
        if is_console_api(request.url.path):
            return api_error_response(exc.status_code, headers=exc.headers)
        return await http_exception_handler(request, exc)

    @app.exception_handler(SessionError)
    async def session_error(request: Request, exc: SessionError) -> Response:
        if exc.code == "DIRECTORY_REQUIRED":
            if is_console_api(request.url.path):
                return api_error_response(403, "DIRECTORY_REQUIRED")
            return JSONResponse(
                {"detail": "Use this workspace's organization sign-in to continue."},
                status_code=403,
            )
        if exc.code == "MFA_REQUIRED":
            if is_console_api(request.url.path):
                return api_error_response(401, "MFA_REQUIRED")
            from starlette.responses import RedirectResponse

            return RedirectResponse("/mfa", status_code=303)
        code = 429 if exc.code == "SESSION_CAPACITY" else 401
        if exc.code == "SESSION_UNAVAILABLE":
            code = 503
        if is_console_api(request.url.path):
            return api_error_response(code)
        if wants_html(request):
            return error_page(code, service=service)
        return JSONResponse({"detail": "Session unavailable"}, status_code=code)

    @app.exception_handler(ExecutionError)
    async def execution_error(request: Request, exc: ExecutionError) -> Response:
        headers = {"Retry-After": str(exc.retry_after)} if isinstance(exc, RateLimited) else None
        if is_console_api(request.url.path):
            return api_error_response(error_status(exc), headers=headers)
        if wants_html(request):
            return error_page(error_status(exc), headers, service=service)
        return JSONResponse(
            {"detail": "Execution unavailable", "code": exc.code},
            status_code=error_status(exc),
            headers=headers,
        )

    @app.exception_handler(MonitorError)
    async def monitoring_error(request: Request, exc: MonitorError) -> JSONResponse:
        return JSONResponse(
            {"detail": "Monitoring unavailable", "code": exc.code},
            status_code=MONITOR_STATUS.get(exc.code, 400),
        )

    app.include_router(monitor_router(db))

    @app.exception_handler(SignalError)
    async def signal_error(request: Request, exc: SignalError) -> JSONResponse:
        return JSONResponse(
            {"detail": "Signal refused", "code": exc.code},
            status_code=SIGNAL_STATUS.get(exc.code, 400),
        )

    app.include_router(signal_router(db))

    if runtime is not None:
        if runtime.db is not db:
            raise ValueError("Runtime database mismatch")
        app.include_router(router(runtime))
        assert mcp_app is not None
        app.mount("/mcp", mcp_app)
    if arcade is not None:
        if runtime is None:
            raise ValueError("Arcade hooks require a runtime")
        app.include_router(arcade_router(runtime, ToolMap(arcade), REQUESTS_IN_FLIGHT))
    if human is not None:
        if runtime is None:
            raise ValueError("Human surfaces require a runtime")
        # The pages that run before a session exists, and the classic approval page behind
        # every notification. Everything else a person opens is the console below (#333), or
        # a loaded plugin's own pages, mounted after every core route below.
        app.include_router(human_router(runtime, human))
        # Before `sign_in_router`: `/login/directory/callback` would otherwise be matched by
        # `/login/{provider}/callback` with `provider = "directory"`, which no configured
        # provider is ever called, and answer 404 instead of completing the flow. The order is
        # what decides, so it is stated here and pinned by a test.
        app.include_router(directory_router(runtime, human))
        app.include_router(sign_in_router(runtime, human))
        from execbound.surfaces.mfa_pages import mfa_router

        app.include_router(mfa_router(runtime, human))
        from execbound.surfaces.invite_pages import invite_router

        app.include_router(invite_router(runtime, human))
        from execbound.surfaces.summary_pages import summary_router

        # The weekly summary's one-click unsubscribe (#678): no session, the same answer to
        # every request.
        app.include_router(summary_router(runtime, human))
        if human.scout is not None and human.scout.entra is not None:
            from execbound.surfaces.connect_pages import connect_router

            # Microsoft Entra admin consent's two callbacks (#678), only where the private
            # configuration names the platform app: absent, not disabled, everywhere else.
            app.include_router(connect_router(runtime, human))
        # A plugin's console page may not be a path a core page mounted above already takes.
        check_paths(runtime.plugins.console_paths, app.routes)
        app.include_router(console_router(runtime, human, console_build))
        app.include_router(console_api_router(runtime, human))

        @app.get("/assets/app.css")
        def stylesheet() -> Response:
            content = files("execbound.surfaces").joinpath("assets/app.css").read_text()
            return Response(content, media_type="text/css")

    def authenticated_identity(
        credentials: Annotated[HTTPAuthorizationCredentials | None, Depends(bearer)],
    ) -> Identity:
        try:
            if credentials is None or credentials.scheme.lower() != "bearer":
                raise AuthenticationFailed("Invalid credentials")
            return authenticate(db, credentials.credentials)
        except AuthenticationFailed as exc:
            raise HTTPException(
                status_code=401,
                detail="Invalid credentials",
                headers={"WWW-Authenticate": "Bearer"},
            ) from exc

    @app.get("/health/live")
    def live() -> dict[str, str]:
        return {"status": "ok"}

    @app.get("/health/ready")
    def ready() -> dict[str, object]:
        with db.engine.connect() as conn:
            check_runtime(conn)
        # What is running, so a trial record can cite it: the package version and the
        # source commit; the last key reload outcome, never a key id, path or diagnostic;
        # and any loaded plugin's name with the plugin API, never its configuration.
        body: dict[str, object] = {
            "status": "ready",
            "version": package_version(),
            "commit": running_commit(),
        }
        if key_reload is not None:
            body["keys"] = key_reload.state
        if runtime is not None and runtime.plugins.loaded:
            body["plugin_api"] = PLUGIN_API_VERSION
            body["plugins"] = list(runtime.plugins.names)
        if console_edition is not None:
            body["console"] = console_edition
        return body

    if reload is not None:
        app.state.reload_keys = reload

    @app.get("/v1/me")
    def me(identity: Annotated[Identity, Depends(authenticated_identity)]) -> Identity:
        return identity

    if runtime is not None and human is not None:
        # A loaded plugin's pages, after every core route, so a path core answers stays
        # core's. One core already answers, or one a core pattern would take first, refuses
        # start rather than being silently unreachable (#238, #496). A plugin that refuses
        # while its pages are built refuses start too, logged like the loader's refusals.
        for factory in runtime.plugins.human_routers:
            app.include_router(plugin_pages(factory, runtime, human, app.routes))

    return app
