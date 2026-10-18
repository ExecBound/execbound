# SPDX-License-Identifier: AGPL-3.0-only
"""The console API under `/api/console/v1/`, or nothing at all.

Each area of the console is one module here that registers its routes on the shared router
through the one list below; each area adds its module by one line, so the shared file changes
by one line per page (#333). The
router is mounted with the human surface, as the console's pages are, and every route takes its
authority from the guards in `guards.py`: the session cookie, or an administrator's personal
access token on a route `token_rules.py` allows one.

The OpenAPI document the client is generated from is built from this router alone, never from
the application's, so the agent API and the pages never reach the generated client.
"""

from collections.abc import Callable
from types import SimpleNamespace
from typing import Any, cast

from fastapi import APIRouter
from fastapi.openapi.utils import get_openapi
from starlette.routing import BaseRoute

from execbound.plugins import NO_PLUGINS, LoadedPlugins, check_console_area
from execbound.runtime import Runtime
from execbound.surfaces.console_api.access import access_routes
from execbound.surfaces.console_api.account import account_routes
from execbound.surfaces.console_api.agents import agents_routes
from execbound.surfaces.console_api.approval_coverage import approval_coverage_routes
from execbound.surfaces.console_api.approval_rules import approval_rule_routes
from execbound.surfaces.console_api.approvals import approval_routes
from execbound.surfaces.console_api.approvers import approvers_routes
from execbound.surfaces.console_api.assistant import assistant_routes
from execbound.surfaces.console_api.board import board_routes
from execbound.surfaces.console_api.bodies import body_schemas
from execbound.surfaces.console_api.client_errors import client_error_routes
from execbound.surfaces.console_api.connection import connection_routes
from execbound.surfaces.console_api.credentials import credentials_routes
from execbound.surfaces.console_api.executions import execution_routes
from execbound.surfaces.console_api.guards import ApiGuards, api_guards
from execbound.surfaces.console_api.monitoring import monitoring_routes
from execbound.surfaces.console_api.monitoring_connect import monitoring_connect_routes
from execbound.surfaces.console_api.monitoring_setup import monitoring_setup_routes
from execbound.surfaces.console_api.monitoring_sources import monitoring_sources_routes
from execbound.surfaces.console_api.overview import overview_routes
from execbound.surfaces.console_api.people import people_routes
from execbound.surfaces.console_api.policy import policy_routes
from execbound.surfaces.console_api.report import report_routes
from execbound.surfaces.console_api.samples import samples_routes
from execbound.surfaces.console_api.search import search_routes
from execbound.surfaces.console_api.session import session_routes
from execbound.surfaces.console_api.settings import settings_routes
from execbound.surfaces.console_api.setup import setup_routes
from execbound.surfaces.console_api.sign_in import sign_in_routes
from execbound.surfaces.console_api.spaces import spaces_routes
from execbound.surfaces.console_api.step_up import step_up_routes
from execbound.surfaces.console_api.teammate_invitations import teammate_invitations_routes
from execbound.surfaces.console_api.token_rules import TOKEN_BODY_LIMITS, token_allowed
from execbound.surfaces.console_api.tokens import token_routes
from execbound.surfaces.console_api.welcome import welcome_routes
from execbound.surfaces.console_api.workspaces import workspace_routes
from execbound.surfaces.human import HumanConfig
from execbound.surfaces.limits import RequestLimits

PREFIX = "/api/console/v1"
Area = Callable[[APIRouter, Runtime, HumanConfig, ApiGuards], None]

# The console API reference is generated at build time from the default limits, exactly as
# `agent_api_guide.introduction` reads `RequestLimits()` for the agent API's own rate-limit
# table; `tests/test_console_api_base.py` holds the rendered number to this default.
_LIMITS = RequestLimits()

CONSOLE_INTRODUCTION = f"""\
## Authentication

The console API is the console's own interface, and it accepts two kinds of caller.

- **A signed-in person**, in a browser: the session cookie, with the `X-CSRF-Token` header on \
every `POST`. This is how the console calls it.
- **A personal access token**, from a script or a tool such as a coding agent: \
`Authorization: Bearer <token>`. An administrator creates their own token under **My account → \
Personal access tokens**; if they have enrolled a second factor, it must have been verified in \
the last thirty minutes, and an administrator with none enrolled is not asked for one. The token \
is shown once. It carries the administrator's authority, and every audit event it causes names \
the administrator and the token.

### What a token cannot do

A token acts as its owner, except where an audit log could only report afterwards what these \
refusals exist to prevent. Each answers 403 `TOKEN_NOT_ALLOWED`:

- **Decisions and settlement.** It cannot decide an approval, or settle or correct an \
execution's outcome.
- **Loosening enforcement.** It cannot activate a policy, switch the workspace to \
observe-only, lift an emergency stop, reactivate an agent, unarchive a space, or install the \
sample targets.
- **People, access and sign-in.** It cannot change people, access, approval rules, approvers, \
a space's member roster, invitations or account requests; change a workspace's sign-in; issue \
a person their own credential; or revoke a credential from the Credentials list, which can be \
a person's own sign-in credential.
- **The owner's own account and tokens.** It cannot read or switch the browser session, \
change its owner's password, sessions, profile, preferences or product-usage setting, or \
manage tokens.
- **Monitoring credentials and findings.** It cannot connect, re-key or revoke a monitoring \
connection, mint, rotate or revoke a reporting source, or acknowledge several findings at once.

Each operation below says whether a token may call it; the two whose rule depends on the \
request body say what it may not do. A token has its own rate limit of \
{_LIMITS.token_requests} requests per {_LIMITS.token_window_seconds} seconds, and a request \
carrying a session cookie and a token together is refused.

A token's request may name a space with the `X-ExecBound-Space` header; without it, a token \
sees every space its owner can, and a write that needs one space answers 422 `SPACE_REQUIRED` \
in a workspace with several. A workspace that requires sign-in through an identity provider \
accepts no tokens (`DIRECTORY_REQUIRED`). An unknown, expired or revoked token answers 401 \
`SESSION_REQUIRED` with `WWW-Authenticate: Bearer`.

Agents do not call this API: they call the [agent API](/api/agent) with an API key.
"""

# One line per area. Keep the order: it is the order of the OpenAPI document.
AREAS: tuple[Area, ...] = (
    session_routes,
    workspace_routes,
    step_up_routes,
    access_routes,
    approval_rule_routes,
    approval_coverage_routes,
    client_error_routes,
    board_routes,
    approval_routes,
    settings_routes,
    account_routes,
    agents_routes,
    policy_routes,
    people_routes,
    credentials_routes,
    token_routes,
    approvers_routes,
    assistant_routes,
    monitoring_routes,
    monitoring_setup_routes,
    monitoring_connect_routes,
    monitoring_sources_routes,
    welcome_routes,
    connection_routes,
    samples_routes,
    setup_routes,
    overview_routes,
    report_routes,
    execution_routes,
    search_routes,
    spaces_routes,
    teammate_invitations_routes,
    sign_in_routes,
)


def console_api_router(runtime: Runtime, config: HumanConfig) -> APIRouter:
    routes, _ = _built(runtime, config)
    return routes


def _built(runtime: Runtime, config: HumanConfig) -> tuple[APIRouter, int]:
    """The console API router, and how many of its routes core's own areas added, counted in
    this same build: every route after that many is a loaded plugin's."""
    routes = APIRouter(prefix=PREFIX)
    guards = api_guards(runtime, config)
    for area in AREAS:
        area(routes, runtime, config, guards)
    core = len(routes.routes)
    # A loaded plugin's areas, after every core area and under the same guards (#238). The
    # document below builds against a stand-in that carries only `plugins`, so it can be
    # built with a plugin's areas included without any of the rest of a runtime existing.
    plugins: LoadedPlugins = getattr(runtime, "plugins", NO_PLUGINS)
    for area in plugins.console_areas:
        before = list(routes.routes)
        area(routes, runtime, config, guards)
        # An area may only append, and only under `/api/console/v1/`: that prefix is itself
        # under the reserved `/api`, so the prefix check confines it rather than `reserve`.
        check_console_area(routes, before, PREFIX + "/")
    return routes, core


def _router(plugins: LoadedPlugins) -> tuple[APIRouter, int]:
    """The console API router built for its route metadata only, with its core route count.

    The handlers are never called, so the runtime they would close over is not needed; the
    stand-in carries the one attribute `console_api_router` reads outside a handler closure,
    ``plugins``, so a named plugin's areas are included with no other runtime built at all.
    """
    config = HumanConfig("http://127.0.0.1", _keys(), assistant_enabled=True)
    return _built(cast(Runtime, SimpleNamespace(plugins=plugins)), config)


def console_api_document() -> dict[str, Any]:
    """The published OpenAPI document of the console API: core's areas, from their routes
    alone. A plugin's areas are in `plugin_console_document`'s, never here (#496)."""
    routes, _ = _router(NO_PLUGINS)
    return _document(routes.routes, "ExecBound console API", CONSOLE_INTRODUCTION, NO_PLUGINS)


def plugin_console_document(plugins: LoadedPlugins) -> dict[str, Any]:
    """The routes the loaded plugins' console areas add, and none of core's (#496).

    A plugin's console edition generates its own client from this document, beside core's,
    and the published document (`console_api_document`) carries none of these routes. Every
    area only appends (`check_console_area`), so the plugins' routes are those after the count
    of core's own, taken in the same build rather than assumed from a plugin-free one.
    """
    routes, core = _router(plugins)
    names = ", ".join(plugins.names)
    return _document(
        routes.routes[core:],
        f"ExecBound console API: {names}",
        f"The console API routes {names} adds. Authentication, the rules for personal access "
        "tokens and every other route are the core console API's own document.",
        plugins,
    )


def _document(
    routes: list[BaseRoute], title: str, description: str, plugins: LoadedPlugins
) -> dict[str, Any]:
    document = get_openapi(
        title=title,
        version="1",
        description=description,
        routes=routes,
        servers=[{"url": "/"}],
    )
    # The bodies the guards read are documented here, beside the responses FastAPI found. Only
    # the models this document's own routes reference: `body()` registers into a process-global
    # dict that only grows, so a plugin's document built earlier in this process must not leak
    # its body models into a later, plugin-free one (or the reverse).
    schemas = document.setdefault("components", {}).setdefault("schemas", {})
    schemas.update(body_schemas(_referenced_body_names(document)))
    # FastAPI documents a 422 on every route with a path parameter, which this API never
    # answers: the guards refuse a bad body or path with a typed code, so the client's error
    # type is the refusal's and not a validation report.
    for path in document["paths"].values():
        for operation in path.values():
            operation.get("responses", {}).pop("422", None)
    schemas = document.get("components", {}).get("schemas", {})
    for name in ("HTTPValidationError", "ValidationError"):
        schemas.pop(name, None)
    # Every operation carries whether a personal access token may call it (`token_rules.py`,
    # and a plugin's own classification of its routes), both machine-readable for the generated
    # client and in its own description line; the two routes in `TOKEN_BODY_LIMITS` state the
    # further limit on their body instead of the plain line.
    for path, item in document["paths"].items():
        for method, operation in item.items():
            rule = "allowed" if token_allowed(path, method.upper(), plugins) else "refused"
            operation["x-execbound-token"] = rule
            line = TOKEN_BODY_LIMITS.get((path, method.upper())) or (
                "Personal access tokens: allowed."
                if rule == "allowed"
                else "Personal access tokens: refused; sign in to the console."
            )
            operation["description"] = (operation.get("description", "") + "\n\n" + line).strip()
    return document


def _referenced_body_names(document: dict[str, Any]) -> set[str]:
    """The body model names this document's own routes reference (`bodies.body`'s `$ref`)."""
    prefix = "#/components/schemas/"
    names: set[str] = set()
    for path in document.get("paths", {}).values():
        for operation in path.values():
            if not isinstance(operation, dict):
                continue
            ref = (
                operation.get("requestBody", {})
                .get("content", {})
                .get("application/json", {})
                .get("schema", {})
                .get("$ref")
            )
            if isinstance(ref, str) and ref.startswith(prefix):
                names.add(ref[len(prefix) :])
    return names


def _keys() -> Any:
    from execbound.surfaces.tokens import TokenKeys

    return TokenKeys("schema-v1", {"schema-v1": bytes(32)})
