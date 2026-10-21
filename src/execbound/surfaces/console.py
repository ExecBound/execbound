# SPDX-License-Identifier: AGPL-3.0-only
"""The console: one application, served at the console's own paths (#333).

The application answers `/`, `/approvals`, `/activity` and the rest directly, and the paths an
earlier layout used (`/admin/people`, `/monitor/{view}`, `/next/...`) redirect, so a bookmark
and a notification link still arrive somewhere.

What this module serves is a directory of files the Vite build wrote into the package
(`console_dist`, admitted to the wheel by hatch's `artifacts` line). It is read once, when the
application is built, into memory: the build is small, a lookup by exact key cannot traverse
anything, and every byte a browser receives was in the package at start. The application's own
files keep one address of their own, `/console/`, because the routes it answers are now the
product's paths and `/assets/` belongs to the pages that stay server-rendered. The hashed files
under `/console/assets/` are immutable; `index.html` is `no-store` and carries the running commit
in a `meta` tag so the client can notice a release it was not built for; everything else the
build ships unhashed (the token stylesheet, the plain frame, the fonts) revalidates by `ETag`.

A console page needs a session, exactly as a Jinja page did. A visit with no session, or an
ended one, is sent to `/login`; a bearer credential is refused and audited through the same
boundary the pages use, because an agent never opens a console route.

Two things the document carries are decided here rather than in the browser. The appearance a
person chose for this browser — System, Light or Dark — arrives as a cookie and leaves as an
attribute on the root element, because the console may carry no inline script and its first
paint happens before the bundle runs; `APPEARANCE` below says why that makes the server the
only place the choice can be applied without a flash. And the mark is served at `/favicon.ico`
and `/favicon.svg`, which is where a browser asks for it whatever a document says.

The route list here is core's application's own, checked against `console/src/routeTree.gen.ts`
by `tests/test_console_serving.py`, and a plugin's console edition adds its own through
`console_routes`: an address the application does not have answers 404 rather than a shell that
would render "not found" with a 200, and a page added to the application without a line here
fails that test before it can be reached.
"""

import hashlib
import re
from collections.abc import Awaitable, Callable, Iterator
from dataclasses import dataclass
from importlib.resources import files
from importlib.resources.abc import Traversable
from urllib.parse import quote, urlencode
from uuid import UUID

from fastapi import APIRouter, HTTPException, Request, Response
from fastapi.responses import RedirectResponse
from starlette.concurrency import run_in_threadpool
from starlette.routing import Route

from execbound.build import running_commit
from execbound.plugins import NO_PLUGINS, LoadedPlugins, check_added_routes
from execbound.runtime import Runtime
from execbound.surfaces.human import HumanConfig, request_guards
from execbound.surfaces.login_return import canonical, login_location, remember_path
from execbound.surfaces.sessions import SessionError, verify_csrf

# What every response outside the console carries: no script or style but the package's own,
# no frames, no base. `font-src 'self'` is there because the pages take the console's own IBM
# Plex from the packaged build. `img-src 'self'` is there because every page links
# `/favicon.svg` and `/favicon.ico`, a favicon is an image, and with no `img-src` the page's
# own `default-src 'none'` refuses it, so the sign-in tab would show the browser's blank globe.
PAGE_POLICY = (
    "default-src 'none'; style-src 'self'; script-src 'self'; img-src 'self'; "
    "font-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'"
)


def page_policy(origins: tuple[str, ...] = ()) -> str:
    """The pages' policy, with the sign-in providers this deployment configured named in
    `form-action` and nothing else added.

    `form-action` governs the **redirect** a form submission follows, not only where it
    posts, so starting a provider's flow with a form — which is how it keeps the exact
    `Origin` check and the CSRF token every other mutation has — needs that provider's
    authorization host written into the policy. Each host is pinned in the provider's own
    module and reaches this list only because a block in the private configuration named
    that provider, so a deployment permits exactly the redirects it offers buttons for and a
    deployment with no provider has the policy it has always had.
    """
    if not origins:
        return PAGE_POLICY
    permitted = " ".join(sorted(set(origins)))
    return PAGE_POLICY.replace("form-action 'self'", f"form-action 'self' {permitted}")


# The console's policy (#333). `connect-src 'self'` is what lets the application
# call its own API and nothing else; `font-src 'self'` serves the packaged fonts;
# `img-src data:` admits the SVG the charts draw inline; Trusted Types makes every DOM sink
# refuse a raw string in every current browser, with no policy registered to bless one.
CONSOLE_POLICY = (
    "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; "
    "font-src 'self'; connect-src 'self'; form-action 'self'; frame-ancestors 'none'; "
    "base-uri 'none'; require-trusted-types-for 'script'; trusted-types 'none'"
)
IMMUTABLE = "public, max-age=31536000, immutable"
REVALIDATE = "no-cache"

# Where the build's own files live, so the application's addresses stay the product's paths.
ASSETS = "/console"

# Every address core's application answers, in the order FastAPI matches them: a literal before
# the parameterised path it would otherwise be read as. The names are the application's route
# files; `tests/test_console_serving.py` holds this list equal to core's generated route tree.
# A plugin's addresses are added by `console_routes` below, never here (#496).
CONSOLE_ROUTES = (
    "/",
    "/activity",
    "/agents",
    "/agents/{agent_id}",
    "/approvals",
    "/approvals/{approval_id}",
    "/approvers",
    "/access",
    "/ask",
    "/ask/{turn_id}",
    "/board",
    "/credentials",
    "/monitor",
    "/monitor/agents/{agent_id}",
    "/people",
    "/people/{person_id}",
    "/policy",
    "/policy/{bundle_id}",
    "/policy/{bundle_id}/rules",
    "/report",
    "/settings",
    "/help",
    "/spaces",
    "/tenant",
    "/welcome",
)

# The address a pending-approval notification opens where a loaded plugin's approval links name
# the approval's workspace (`plugins.ApprovalLinks`). Core owns its shape, as it owns the classic
# page's beside it in `human.py`, and serves it only where such a plugin is loaded; the page
# handler below runs the plugin's review step first.
SCOPED_APPROVAL_ROUTE = "/workspaces/{tenant_id}/approvals/{approval_id}"

# What the pages the application replaced used to answer, and where each of them is now. A
# bookmark, a browser's history and a link in an old message all still arrive; the answer is a
# permanent redirect, so a client that caches one stops asking. `/next` and its children are
# here too: the console ran there while it was being built, and a deployment that served it has
# people with those addresses open. The sandbox welcome page's two downloads are not: their
# console API routes are a plugin's, so their old addresses are that plugin's too (#496).
LEGACY_REDIRECTS = (
    ("/admin/approvers", "/approvers"),
    ("/admin/credentials", "/credentials"),
    ("/admin/people", "/people"),
    ("/admin/people/{principal_id}", "/people/{principal_id}"),
    ("/admin/settings", "/tenant"),
    # The active draft's rules were edited on one page; the application edits a named bundle's,
    # so the list is where the person chooses which. It must be registered before
    # `/policy/{bundle_id}`, which would otherwise read `rules` as a bundle id.
    ("/policy/rules", "/policy"),
)
# The monitoring views were a path segment and are a search parameter now.
MONITOR_VIEWS = ("connections", "sources", "findings", "inventory", "agents", "health")

# Media types by suffix. A file of any other kind is not served at all, so nothing in the build
# can reach a browser under a type it would sniff.
MEDIA_TYPES = {
    ".css": "text/css; charset=utf-8",
    ".html": "text/html; charset=utf-8",
    ".ico": "image/x-icon",
    ".js": "text/javascript; charset=utf-8",
    ".json": "application/json",
    ".png": "image/png",
    ".svg": "image/svg+xml",
    ".txt": "text/plain; charset=utf-8",
    ".webp": "image/webp",
    ".woff2": "font/woff2",
}
_RELEASE_META = re.compile(r'<meta name="execbound-release" content=""\s*/?>')
_HTML_TAG = re.compile(r"<html\b[^>]*>")
# The edition the build names in its document (console's `scripts/editions.ts`), a plugin-style
# name; anything else names none.
_EDITION_META = re.compile(r'<meta name="execbound-edition" content="([a-z][a-z0-9_]{0,31})"\s*/?>')

# The appearance a person chose for this browser: System, Light or Dark (#333). System is the
# absence of the cookie and is what everybody has until they choose otherwise.
#
# It has to be a cookie rather than the browser storage the sidebar rail and the table density
# use, and the server has to be the one that applies it, because of two rules that meet here:
# the console document carries no inline script, and it paints a plain frame from the tokens
# before any script runs. A choice the bundle applied would therefore always arrive after
# the first paint, as a flash of the other scheme. So the browser writes the word, the
# server reads it here and renders `data-eb-scheme` on the root element, and the stylesheet
# takes the attribute over `prefers-color-scheme`.
#
# The cookie is a preference and not a credential: it holds one of three words, it is read
# nowhere but this function, it decides nothing but which palette paints, and it is never
# stored against the person on the server. Anything other than the two forced words — a value
# from another version, a value somebody typed into their own browser, a missing cookie — is
# System, which is why this needs no validation beyond membership of a two-element set.
APPEARANCE = "appearance"
SCHEMES = ("light", "dark")


def _matcher(routes: tuple[str, ...]) -> re.Pattern[str]:
    """One expression over a list of FastAPI paths, with each parameter one path segment."""
    parts = []
    for route in routes:
        pattern = "".join(
            "[^/]+" if piece.startswith("{") else re.escape(piece)
            for piece in re.split(r"(\{[^}]+\})", route)
        )
        parts.append(pattern)
    return re.compile("^(?:" + "|".join(parts) + ")$")


_CONSOLE_PATHS = _matcher(CONSOLE_ROUTES)


def core_console_routes(plugins: LoadedPlugins = NO_PLUGINS) -> tuple[str, ...]:
    """The console addresses core mounts as its own in a process: its pages, and the scoped
    approval address where a loaded plugin's approval links exist (#496). The console
    router mounts exactly these, before any plugin's console page."""
    scoped = (SCOPED_APPROVAL_ROUTE,) if plugins.approval_links is not None else ()
    return CONSOLE_ROUTES + scoped


def console_routes(plugins: LoadedPlugins = NO_PLUGINS) -> tuple[str, ...]:
    """Every address the console answers in a process: core's own, then the plugins' console
    pages (#496). The policy's matcher and both route-tree tests read this."""
    return core_console_routes(plugins) + plugins.console_paths


def console_matcher(plugins: LoadedPlugins = NO_PLUGINS) -> re.Pattern[str]:
    """The console's addresses in a process, as one expression."""
    return _matcher(console_routes(plugins))


def is_console_path(path: str, pages: re.Pattern[str] = _CONSOLE_PATHS) -> bool:
    """Whether a request path belongs to the console and takes its policy.

    Matched against the application's own route list rather than a prefix, because the console
    and the pages that stay now share the address space: `/approvals/{id}` is the application
    and `/approvals/{id}/classic` is the page behind it.
    """
    if path.startswith((ASSETS + "/", "/api/console/")) or path == ASSETS:
        return True
    return bool(pages.match(path))


def is_console_api(path: str) -> bool:
    """Whether a request path is the console API, whose refusals are JSON with a code."""
    return path.startswith("/api/console/")


@dataclass(frozen=True)
class BuildFile:
    body: bytes
    media_type: str
    etag: str


def build_root() -> Traversable:
    """Where the packaged build lives; tests point this at a directory of their own."""
    return files("execbound.surfaces").joinpath("console_dist")


def _walk(node: Traversable, prefix: str) -> Iterator[tuple[str, Traversable]]:
    for child in node.iterdir():
        name = child.name
        if name.startswith("."):
            # `.vite/manifest.json` is build metadata, never a page's business.
            continue
        key = f"{prefix}{name}"
        if child.is_dir():
            yield from _walk(child, key + "/")
        else:
            yield key, child


def load_build(root: Traversable | None = None) -> dict[str, BuildFile] | None:
    """Every servable file of the build keyed by its path under `/console/`, or None if none."""
    node = build_root() if root is None else root
    if not node.is_dir():
        return None
    found: dict[str, BuildFile] = {}
    for key, child in _walk(node, ""):
        suffix = "." + key.rsplit(".", 1)[-1] if "." in key.rsplit("/", 1)[-1] else ""
        media_type = MEDIA_TYPES.get(suffix)
        if media_type is None:
            continue
        body = child.read_bytes()
        found[key] = BuildFile(body, media_type, '"' + hashlib.sha256(body).hexdigest()[:32] + '"')
    if "index.html" not in found:
        return None
    return found


def build_edition(build: dict[str, BuildFile] | None) -> str | None:
    """The edition a loaded console build names in its document (#496), or None where
    there is no build or it names none. The application reads it from the build it serves, so
    the document served and the edition readiness reports come from one read."""
    if build is None:
        return None
    found = _EDITION_META.search(build["index.html"].body.decode("utf-8"))
    return None if found is None else found.group(1)


def packaged_edition(root: Traversable | None = None) -> str | None:
    """The edition the packaged console build names, read from the package on its own: CI's
    image check calls it to see which console an image carries, and tests compare readiness
    with it. Readiness itself reads the build the application loaded (`build_edition`)."""
    return build_edition(load_build(root))


def _document(index: BuildFile, scheme: str | None = None) -> bytes:
    """`index.html` with the running commit in its release meta tag (an empty value if none),
    and `data-eb-scheme` on the root element when this browser asked for a forced scheme.

    The attribute is written into the opening tag rather than set by the bundle, so the very
    first paint — the plain frame drawn before any script runs — is already the scheme the
    person chose.
    `scheme` is one of `SCHEMES` or None; nothing a request carries reaches this string.
    """
    commit = running_commit() or ""
    text = index.body.decode("utf-8")
    text = _RELEASE_META.sub(f'<meta name="execbound-release" content="{commit}">', text, 1)
    if scheme is not None:
        text = _HTML_TAG.sub(
            lambda tag: tag.group(0)[:-1].rstrip() + f' data-eb-scheme="{scheme}">', text, 1
        )
    return text.encode("utf-8")


def console_router(
    runtime: Runtime, config: HumanConfig, build: dict[str, BuildFile] | None
) -> APIRouter:
    """The console at its own paths, the build's files under `/console/`, and the redirects.
    `build` is what `load_build()` read when the application was built, or None without one."""
    routes = APIRouter()
    # One document per appearance, built once at construction rather than per request: there
    # are three of them and the only difference is an attribute on the root element.
    documents = (
        {scheme: _document(build["index.html"], scheme) for scheme in (None, *SCHEMES)}
        if build is not None
        else None
    )
    guards = request_guards(runtime, config)

    def missing() -> Response:
        # The package carries no console: say so plainly rather than answering 404, which
        # would read as a path that does not exist.
        return Response(
            "The console build is not packaged.",
            status_code=503,
            media_type="text/plain; charset=utf-8",
        )

    def serve(file: BuildFile, request: Request, cache: str) -> Response:
        if request.headers.get("if-none-match") == file.etag:
            return Response(status_code=304, headers={"ETag": file.etag, "Cache-Control": cache})
        return Response(
            file.body,
            media_type=file.media_type,
            headers={"ETag": file.etag, "Cache-Control": cache},
        )

    @routes.get(ASSETS + "/{file:path}", include_in_schema=False)
    async def asset(request: Request, file: str) -> Response:
        if build is None:
            return missing()
        # The document is only ever served as a page below, with its session check and its
        # release; nothing reaches it through the file route.
        held = None if file == "index.html" else build.get(file)
        if held is None:
            raise HTTPException(404, "Not found")
        return serve(held, request, IMMUTABLE if file.startswith("assets/") else REVALIDATE)

    @routes.get("/favicon.ico", include_in_schema=False)
    @routes.get("/favicon.svg", include_in_schema=False)
    async def favicon(request: Request) -> Response:
        """The mark at the root, where a browser asks for it without being told to.

        Every document links both explicitly, the pages that stay as well as the console, but
        a browser requests `/favicon.ico` of its own accord whatever a page says, and until
        now the gateway answered that with the API's not-found handler. The bytes are the
        console build's own, so there is one copy of the mark in the package and the pages and
        the application cannot end up with different icons.
        """
        if build is None:
            return missing()
        held = build.get(request.url.path.lstrip("/"))
        if held is None:
            raise HTTPException(404, "Not found")
        return serve(held, request, REVALIDATE)

    async def page(request: Request) -> Response:
        if build is None or documents is None:
            return missing()
        # The application keeps its own state in the query string (which drawer is open, which
        # filter applies) and the server reads none of it, so every key is tolerated here where
        # a page would name the ones it accepts; duplicates are still refused, and the bearer,
        # body, host and header checks are the boundary's as on every page.
        keys = frozenset(key for key, _ in request.query_params.multi_items())
        await guards.boundary(request, keys)
        cookies = guards.cookies(request)
        try:
            from execbound.directory_store import load_rechecked

            session = await run_in_threadpool(
                load_rechecked, runtime, config.directory, cookies.get(config.cookie("session"), "")
            )
            if session.renewal_due and config.directory is not None:
                # The shell's load uses up the renewal that is due, so it rechecks a directory
                # session exactly as `session_for` does: a person disabled at the directory who
                # only reloads the page is refused here, not on a later API read.
                from execbound.directory_store import recheck_session

                await run_in_threadpool(recheck_session, runtime, config.directory, session)
        except SessionError as exc:
            # The whole place, the page and the query that says what it shows, rides the
            # signed hint through sign-in or the second factor; `canonical` keeps only what a
            # page may be returned to (#678).
            query = request.url.query
            target = request.url.path + (f"?{query}" if query else "")
            response = RedirectResponse(
                "/mfa" if exc.code == "MFA_REQUIRED" else login_location(target, runtime.plugins),
                status_code=303,
            )
            if exc.code == "MFA_REQUIRED" and canonical(target, runtime.plugins) is not None:
                remember_path(response, config, runtime, target)
            return response
        if session.renewed and session.account_id is None:
            request.state.session_renewal = session.expires_at
        if not verify_csrf(session, cookies.get(config.cookie("csrf"), "")):
            raise HTTPException(403, "Invalid session")
        if "tenant_id" in request.path_params:
            links = runtime.plugins.approval_links
            # Unreachable: the scoped address is mounted only with links. Kept to narrow the type.
            if links is None:
                raise HTTPException(404, "Not found")
            try:
                tenant = UUID(request.path_params["tenant_id"])
                approval = UUID(request.path_params["approval_id"])
                if (
                    str(tenant) != request.path_params["tenant_id"]
                    or str(approval) != request.path_params["approval_id"]
                ):
                    raise ValueError
            except ValueError:
                raise HTTPException(404, "Not found") from None
            entry = await links.review(
                request,
                runtime,
                config,
                session,
                cookies[config.cookie("csrf")],
                tenant,
                approval,
                False,
            )
            if entry is not None:
                return entry
        chosen = cookies.get(config.cookie(APPEARANCE))
        return Response(
            documents[chosen if chosen in SCHEMES else None],
            media_type="text/html; charset=utf-8",
            # The document already varies by session and is never stored; saying it varies by
            # the cookie as well is what keeps a cache in front of this from handing one
            # person's scheme to the next.
            headers={"Cache-Control": "no-store", "Vary": "Cookie"},
        )

    def moved(request: Request, target: str, **extra: str) -> RedirectResponse:
        """A permanent redirect that keeps whatever the old address carried after the path."""
        query = dict(request.query_params)
        query.update(extra)
        suffix = "?" + urlencode(query) if query else ""
        return RedirectResponse(target + suffix, status_code=308)

    def to(new: str) -> Callable[[Request], Awaitable[Response]]:
        """A handler that fills the new path from whatever the old path captured."""

        async def redirect(request: Request) -> Response:
            target = new
            for name, value in request.path_params.items():
                target = target.replace("{" + name + "}", quote(str(value), safe=""))
            return moved(request, target)

        return redirect

    async def monitor_view(request: Request) -> Response:
        """The six monitoring views were a path segment; they are the page's `view` now."""
        view = str(request.path_params["view"])
        if view not in MONITOR_VIEWS:
            raise HTTPException(404, "Not found")
        return moved(request, "/monitor", view=view)

    async def from_next(request: Request) -> Response:
        """Where the console was served while it was being built (#333, phases 1 and 2)."""
        return moved(request, "/" + str(request.path_params.get("route", "")))

    # Registered before the pages below, so `/policy/rules` is a redirect and not a bundle
    # whose id happens to be that word. These are Starlette routes rather than declared
    # operations because none of them reads its parameter: the path is rewritten and the
    # answer is a header, so there is nothing to validate, document or generate a client for.
    for old, new_path in LEGACY_REDIRECTS:
        routes.routes.append(Route(old, to(new_path), methods=["GET"]))
    routes.routes.append(Route("/monitor/{view}", monitor_view, methods=["GET"]))
    routes.routes.append(Route("/next", from_next, methods=["GET"]))
    routes.routes.append(Route("/next/{route:path}", from_next, methods=["GET"]))
    # Core's pages, and the workspace-scoped approval address where a loaded plugin's approval
    # links build and open one (#496): its shape is core's, so it is mounted as core's
    # own, before the plugins' console pages are checked against everything already here.
    for path in core_console_routes(runtime.plugins):
        routes.routes.append(Route(path, page, methods=["GET"]))
    # A loaded plugin's console pages, after every core one, so core keeps its own paths
    # (#238). `create_app` has already checked them against the pages mounted before this.
    before = list(routes.routes)
    for path in runtime.plugins.console_paths:
        routes.routes.append(Route(path, page, methods=["GET"]))
    check_added_routes(routes.routes[len(before) :], before)

    return routes
