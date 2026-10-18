# SPDX-License-Identifier: AGPL-3.0-only
"""First-party plugins: explicit enablement, one registry, nothing on the execution path.

A plugin is the module ``execbound.<name>`` exposing ``PLUGIN``. It loads only when the
owner-controlled configuration names it: the private runtime configuration's ``plugins`` map
for a server process, ``EXECBOUND_PLUGINS`` for the command line. Being installed grants
nothing (#238, principle 1). What a plugin can add is exactly the registry's points: human
pages, console API areas, console pages, commands, session features, approval links, a
sign-in link, the deployment's service links, which of its console routes a personal access
token may call, and claims on the database's dormant objects. None of them reaches admission,
resolution, policy evaluation, reservation, approval consumption, dispatch or settlement
(#238, principle 3), apart from the claims: data recorded at load time, which core's database
check compares with the database and which can only refuse, never admit. No plugin code runs
there, and core never imports a plugin by name (#496).

Every addition is mounted after the core routes it could collide with, so a path core answers
stays core's. A plugin route core already answers, or one a core pattern would take first,
refuses start instead of being silently unreachable.
"""

import argparse
import importlib
import importlib.util
import inspect
import json
import os
import re
from collections.abc import Awaitable, Callable, Iterable, Mapping
from dataclasses import dataclass, field
from types import MappingProxyType
from typing import TYPE_CHECKING, Any
from uuid import UUID

from fastapi.routing import RouteContext, iter_route_contexts
from pydantic import BaseModel, ValidationError
from starlette.routing import BaseRoute, Match, Route, WebSocketRoute, compile_path

from execbound.db import (
    EMPTY_CLAIMS,
    ClaimConflict,
    Claims,
    DormantGrantsRefused,
    UnsafeDatabaseRole,
    claim_is_valid,
    honour_claims,
    honoured_claims,
)
from execbound.logging_schema import log_event
from execbound.service_links import SOURCE_URL, ServiceLinks

if TYPE_CHECKING:
    from fastapi import APIRouter
    from starlette.requests import Request
    from starlette.responses import Response

    from execbound.runtime import Runtime
    from execbound.signin import ExternalAccount
    from execbound.surfaces.console_api.guards import ApiGuards
    from execbound.surfaces.human import HumanConfig
    from execbound.surfaces.sessions import Session

PLUGIN_API_VERSION = 1
MAX_PLUGINS = 8
ENVIRONMENT = "EXECBOUND_PLUGINS"
# What an operator reads when `check_runtime` refuses the runtime connection; see
# `database_refusal`, which chooses among them (#496). None names a plugin.
# The database holds grants and this process claims none: most often a command run against a
# plugin's database without that plugin named.
PLUGIN_GRANTS_REFUSAL = (
    "Database refused: it holds grants for a plugin this process has not loaded. Set "
    f"{ENVIRONMENT} in the real environment to the plugins the deployment runs, and run the "
    "command again.\n"
)
# This process claims grants and the database's differ from them: most often a plugin's
# database migrated without that plugin's own upgrade, which grants what the plugin claims.
PLUGIN_GRANTS_MISMATCH = (
    "Database refused: its grants do not match what the plugins this process has loaded "
    "claim. Restore them with the upgrade command of the plugin that claims them, then run "
    "the command again.\n"
)
# Any other refusal: the check failed, and why is not an operator's to read here.
RUNTIME_CHECK_REFUSAL = "Database refused: the runtime connection failed its safety check.\n"
# Paths only core answers: the agent surfaces, the health probes, the console API and the
# console's own files. A plugin page there could be mistaken for one of them.
RESERVED_PREFIXES = ("/v1", "/mcp", "/health", "/api", "/console", "/next", "/pre", "/post")
_NAME = re.compile(r"[a-z][a-z0-9_]{0,31}")
_COMMAND = re.compile(r"[a-z][a-z0-9-]{0,39}")
# The first segment is always literal, so a console path can never be mistaken for the
# parameter of some route mounted after it; a later segment may still be a parameter.
_CONSOLE_PATH = re.compile(r"/[a-z0-9][a-z0-9-]*(/([a-z0-9][a-z0-9-]*|\{[a-z_]+\}))*")
_PARAMETER = re.compile(r"\{[^}]+\}")
# A convertor such as `{rest:path}` can span segments, which no check below compares.
_CONVERTOR = re.compile(r"\{[^}]*:[^}]*\}")
# The console page handler opens an approval's review when a path carries these two.
_CONSOLE_HANDLER_PARAMETERS = ("{tenant_id}", "{approval_id}")
# The longest label the sign-in page shows for a plugin's link: one short line of text.
MAX_SIGN_IN_LABEL = 60
# A console API route a plugin classifies for personal access tokens: its full template under
# the console API's prefix, each segment a literal or a whole-segment parameter, as the guard
# reads `route.path`; and an HTTP method, in upper case.
_TOKEN_ROUTE = re.compile(r"/api/console/v1(/([a-z0-9][a-z0-9._-]*|\{[a-z_]+\}))+")
_TOKEN_METHODS = frozenset({"GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"})
TokenRoutes = frozenset[tuple[str, str]]

HumanRouter = Callable[["Runtime", "HumanConfig"], "APIRouter"]
ConsoleArea = Callable[["APIRouter", "Runtime", "HumanConfig", "ApiGuards"], None]
SessionCheck = Callable[["Runtime", "Session"], bool]
ApprovalReview = Callable[
    ["Request", "Runtime", "HumanConfig", "Session", str, UUID, UUID, bool],
    Awaitable["Response | None"],
]


class PluginError(ValueError):
    """A plugin refused; ``code`` says why and nothing else does."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


class CommandError(Exception):
    """A plugin command's refusal, printed exactly as given with exit status 2.

    It carries only the text the plugin chose, the way core's own commands print a fixed
    sentence and a code; never a value an operator passed or a configuration secret.
    """

    def __init__(self, message: str) -> None:
        super().__init__(message)
        self.message = message


def database_refusal(error: UnsafeDatabaseRole) -> str:
    """The one sentence a command prints when `check_runtime` refuses the runtime connection.

    Every command on the runtime connection an operator may run during an incident (the
    emergency stop and its siblings, a policy rollback, the history export) and every
    scheduled run prints this rather than a traceback. The database check compared what the
    runtime role holds on the dormant objects with what this process's loaded plugins claim,
    so whether it claims anything tells the two causes apart: with no claim, the database
    holds grants for a plugin this process has not loaded; with claims, the grants are
    missing or different, which the plugin's own upgrade restores.
    """
    if not isinstance(error, DormantGrantsRefused):
        return RUNTIME_CHECK_REFUSAL
    return PLUGIN_GRANTS_MISMATCH if honoured_claims() else PLUGIN_GRANTS_REFUSAL


def _refused(code: str, plugin: str | None = None) -> PluginError:
    # The name is logged only once it is known to be a plugin name, never as supplied.
    if plugin is None:
        log_event("plugins.refused", level="ERROR", code=code)
    else:
        log_event("plugins.refused", level="ERROR", code=code, plugin=plugin)
    return PluginError(code)


@dataclass(frozen=True)
class Command:
    """A command-line command: its parser, and a run that returns what to print."""

    name: str
    help: str
    configure: Callable[[argparse.ArgumentParser], None]
    run: Callable[[argparse.Namespace], str]


@dataclass(frozen=True)
class ApprovalLinks:
    """A plugin's own address for an approval, and what opening that address does first.

    ``path(tenant_id, approval_id)`` is the absolute path a notification links to. ``review``
    runs when a person opens a console or classic approval address that names a tenant: it
    answers instead of the approval page (for example, to ask which workspace to open), or
    returns None to let the page render. Without this point core links to
    ``/approvals/{approval_id}`` and an address naming a tenant answers 404.
    """

    path: Callable[[UUID, UUID], str]
    review: ApprovalReview


@dataclass(frozen=True)
class SignInLink:
    """A link the sign-in page shows beneath its sign-in options, such as the way to sign up.

    ``path`` is a literal absolute path on this site, the link's destination. ``label(runtime)``
    is what the link says, or None for no link. A plugin's configuration is fixed for the life
    of the process, so the answer does not change from one render to the next; it is asked on
    every render of the sign-in page all the same, which keeps a label that fails from costing
    anything but its own link. Core renders the answer as text, never as
    markup, and shows no link when the label is not one short line of printable text or when
    asking for it raises. The label runs while a public page renders, so it should read only
    what the plugin already holds in memory. Without this point the sign-in page links only
    to core's own help page.
    """

    path: str
    label: Callable[["Runtime"], str | None]


@dataclass(frozen=True)
class ShownLink:
    """The sign-in page's plugin link for one render: where it goes and what it says."""

    path: str
    label: str


SignupFinish = Callable[
    ["Runtime", "HumanConfig", "Request", "ExternalAccount"], Awaitable["Response | None"]
]
SignupRefused = Callable[["Runtime", "HumanConfig", "Request"], "Response"]


@dataclass(frozen=True)
class ProviderSignup:
    """Completes a provider flow a plugin's own page started as a signup.

    Core's ``/login/{provider}/callback`` sets no signup of its own; a plugin's own page
    (``/signup/google``) starts one with the intent cookie `start_provider_flow` sets, and the
    callback calls `finish` when that cookie's digest matches the completed flow.

    ``finish(runtime, config, request, account)`` answers the page to show for the verified
    account. ``None`` means the subject already signs in: the callback signs it in exactly as
    `/login` would and records nothing. It may raise `SignInRefused(code)` for the same
    refusal every other one in the callback shows. ``refused(runtime, config, request)``
    answers every refusal the callback shows while the intent cookie is present and this
    point is registered: a provider's own error, a state mismatch, `finish`'s own
    `SignInRefused`, `finish`'s own unexpected failure (`PLUGIN_FAILED`), and a sign-in
    refused after `finish` returned `None`. It is synchronous because it only ever renders a
    page from what the plugin already holds, never anything it would need to await, even
    when it is answering for what `finish` already ran.
    """

    finish: SignupFinish
    refused: SignupRefused


@dataclass(frozen=True)
class Plugin:
    """What ``execbound.<name>.PLUGIN`` must be."""

    name: str
    api_version: int
    register: Callable[["Registry"], None]
    config: type[BaseModel] | None = None


def reserved(path: str, prefixes: tuple[str, ...] = RESERVED_PREFIXES) -> bool:
    return any(path == prefix or path.startswith(prefix + "/") for prefix in prefixes)


class Registry:
    """What one plugin adds, collected while its ``register`` runs."""

    def __init__(self, plugin: str) -> None:
        self._plugin = plugin
        self._human_routers: list[HumanRouter] = []
        self._console_areas: list[ConsoleArea] = []
        self._console_paths: list[str] = []
        self._commands: list[Command] = []
        self._session_features: list[tuple[str, SessionCheck]] = []
        self._approval_links: ApprovalLinks | None = None
        self._sign_in_link: SignInLink | None = None
        self._recovery_link: SignInLink | None = None
        self._provider_signup: ProviderSignup | None = None
        self._service_links: ServiceLinks | None = None
        self._token_routes: tuple[TokenRoutes, TokenRoutes] | None = None
        self._claims: dict[str, frozenset[str]] = {}

    def human_router(self, factory: HumanRouter) -> None:
        """Pages, mounted after every core route; see `check_page_router`."""
        self._human_routers.append(factory)

    def console_area(self, area: ConsoleArea) -> None:
        """A console API area, run after every core area under the same guards."""
        self._console_areas.append(area)

    def console_path(self, path: str) -> None:
        """A console page the server answers with the console document."""
        if (
            type(path) is not str
            or not _CONSOLE_PATH.fullmatch(path)
            or _CONVERTOR.search(path)
            or any(name in path for name in _CONSOLE_HANDLER_PARAMETERS)
            or reserved(path, RESERVED_PREFIXES + ("/assets",))
        ):
            raise _refused("INVALID_ROUTE", self._plugin)
        self._console_paths.append(path)

    def command(self, command: Command) -> None:
        if type(command) is not Command or not _COMMAND.fullmatch(command.name):
            raise _refused("INVALID_COMMAND", self._plugin)
        self._commands.append(command)

    def session_feature(self, name: str, check: SessionCheck) -> None:
        """A feature the console's session reports, on for a session where ``check`` holds."""
        if type(name) is not str or not _NAME.fullmatch(name) or not callable(check):
            raise _refused("INVALID_FEATURE", self._plugin)
        self._session_features.append((name, check))

    def approval_links(self, links: ApprovalLinks) -> None:
        """How this plugin's approval addresses are built and opened; at most once."""
        if type(links) is not ApprovalLinks or self._approval_links is not None:
            raise _refused("INVALID_APPROVAL_LINKS", self._plugin)
        self._approval_links = links

    def sign_in_link(self, link: SignInLink) -> None:
        """The link the sign-in page shows beneath its sign-in options; at most once.

        The path is spelled out in full: no parameter a request could fill in, no other origin
        and no query. It may not lie where only core answers, nor under ``/assets``, where
        files are served rather than pages.
        """
        if not _valid_link(link) or self._sign_in_link is not None:
            raise _refused("INVALID_SIGN_IN_LINK", self._plugin)
        self._sign_in_link = link

    def recovery_link(self, link: SignInLink) -> None:
        """The sign-in page's link for a person who forgot their password; at most once.

        Held to exactly the sign-in link's rules: a literal absolute path on this site with no
        parameter, outside the reserved prefixes and ``/assets``, and a callable label that
        answers one short line of text or None. Without one, the sign-in page shows only the
        deployment's help line, as it always has.
        """
        if not _valid_link(link) or self._recovery_link is not None:
            raise _refused("INVALID_RECOVERY_LINK", self._plugin)
        self._recovery_link = link

    def provider_signup(self, signup: ProviderSignup) -> None:
        """Complete a provider flow a plugin's own page started as a signup; at most once.

        Exactly a `ProviderSignup` whose `finish` is a coroutine function, matching its
        `Awaitable` contract, and whose `refused` is a plain callable that is not one itself,
        so a plugin that builds one wrong is refused at load rather than the callback finding
        at the first request that it cannot `await` what `finish` gave it, or finding that
        `refused`, called with no `await` of its own, handed back a coroutine instead of the
        page it is supposed to render.
        """
        if (
            type(signup) is not ProviderSignup
            or self._provider_signup is not None
            or not inspect.iscoroutinefunction(signup.finish)
            or not callable(signup.refused)
            or inspect.iscoroutinefunction(signup.refused)
        ):
            raise _refused("INVALID_PROVIDER_SIGNUP", self._plugin)
        self._provider_signup = signup

    def service_links(self, links: ServiceLinks) -> None:
        """The deployment's support address and public pages; at most once.

        Exactly a `ServiceLinks`, whose values are checked again here, so a value changed
        after it was built is refused rather than rendered. A deployment whose runtime
        configuration also carries a `service` block refuses to start (`LoadedPlugins.service`).
        """
        if type(links) is not ServiceLinks or self._service_links is not None or not links.valid():
            raise _refused("INVALID_SERVICE_LINKS", self._plugin)
        self._service_links = links

    def token_routes(
        self,
        *,
        allowed: Iterable[tuple[str, str]] = (),
        refused: Iterable[tuple[str, str]] = (),
    ) -> None:
        """Which of this plugin's console API routes a personal access token may call, and
        which it may not; at most once.

        Each is a `(path, method)` pair: the route's full template under `/api/console/v1/`,
        as `token_rules` spells core's own, and an HTTP method in upper case. Routes are
        compared by shape, whatever their parameters are called (`token_rules.route_shape`):
        the two sets may not share a route, and neither may name any method of a path whose
        shape core classifies (`token_rules.CORE_SHAPES`), so a plugin can never loosen one of
        core's. Whether a pair names a route the plugin itself serves is its route inventory
        test's to check. A route classified nowhere stays refused to a token.
        """
        # Imported here: the console API package imports this module.
        from execbound.surfaces.console_api.token_rules import CORE_SHAPES, route_shape

        permitted = _token_pairs(allowed)
        denied = _token_pairs(refused)
        if (
            self._token_routes is not None
            or permitted is None
            or denied is None
            or {(route_shape(path), method) for path, method in permitted}
            & {(route_shape(path), method) for path, method in denied}
            or any(route_shape(path) in CORE_SHAPES for path, _ in permitted | denied)
        ):
            raise _refused("INVALID_TOKEN_ROUTES", self._plugin)
        self._token_routes = (permitted, denied)

    def claim(self, name: str, privileges: Iterable[str]) -> None:
        """A dormant object this plugin uses, and exactly what the runtime role holds on it.

        ``name`` is a table or function of the database's dormant catalog (`db.DORMANT`).
        ``privileges`` is what the runtime must hold on it: ``SELECT``, ``INSERT`` or ``UPDATE``
        on a table, whole or one column at a time as ``UPDATE(state)`` but never both for one
        privilege, and ``EXECUTE`` on a function. Core's database check refuses to run unless
        each claimed object holds exactly this and each dormant object no loaded plugin claims
        holds nothing (#496).
        """
        try:
            held = None if isinstance(privileges, (str, bytes)) else frozenset(privileges)
        except TypeError:
            held = None
        if held is None or not claim_is_valid(name, held) or name in self._claims:
            raise _refused("INVALID_CLAIM", self._plugin)
        self._claims[name] = held


def _token_pairs(pairs: Iterable[object]) -> TokenRoutes | None:
    """The `(path, method)` pairs a plugin classified, or None when any is not one."""
    if isinstance(pairs, (str, bytes)):
        return None
    try:
        items = list(pairs)
    except TypeError:
        return None
    found: set[tuple[str, str]] = set()
    for item in items:
        if type(item) is not tuple or len(item) != 2:
            return None
        path, method = item
        if (
            type(path) is not str
            or type(method) is not str
            or not _TOKEN_ROUTE.fullmatch(path)
            or method not in _TOKEN_METHODS
        ):
            return None
        found.add((path, method))
    return frozenset(found)


@dataclass(frozen=True)
class LoadedPlugin:
    name: str
    api_version: int
    # Out of the repr, so no traceback, log line or debug print of a loaded plugin (or of the
    # `LoadedPlugins` holding it) can show its configuration.
    config: BaseModel | None = field(repr=False)


@dataclass(frozen=True)
class LoadedPlugins:
    """Everything the named plugins added, fixed once they have loaded."""

    loaded: tuple[LoadedPlugin, ...] = ()
    human_routers: tuple[HumanRouter, ...] = ()
    console_areas: tuple[ConsoleArea, ...] = ()
    console_paths: tuple[str, ...] = ()
    commands: tuple[Command, ...] = ()
    session_features: tuple[tuple[str, SessionCheck], ...] = ()
    approval_links: ApprovalLinks | None = None
    # The plugin that registered the sign-in link, named when asking its label fails, and the
    # link: one pair, so the two can never disagree.
    sign_in_link: tuple[str, SignInLink] | None = None
    # The plugin that registered the sign-in page's recovery link, and the link (#678).
    recovery_link: tuple[str, SignInLink] | None = None
    # The point that completes a provider flow a plugin's own page started as a signup
    # (#504); at most one plugin may register one, and `provider_callback` dispatches to it
    # only when a signup's own intent cookie matches the completed flow.
    provider_signup: ProviderSignup | None = None
    # The deployment's support address and public pages, where a plugin registered them.
    service_links: ServiceLinks | None = None
    # The plugins' own console API routes a personal access token may call, and those it may
    # not (`Registry.token_routes`); `token_rules.token_allowed` reads the first after core's.
    allowed_token_routes: TokenRoutes = frozenset()
    refused_token_routes: TokenRoutes = frozenset()
    # A mapping proxy has no hash, so the claims stay out of this dataclass's.
    claims: Claims = field(default=EMPTY_CLAIMS, hash=False)

    @property
    def names(self) -> tuple[str, ...]:
        return tuple(plugin.name for plugin in self.loaded)

    def features(self, runtime: "Runtime", session: "Session") -> frozenset[str]:
        """The session features that hold for one session: every registered name whose check
        does. The console session lists them all in its `features`; core itself reads back only
        `invitations`, and a plugin's console edition reads its own.

        A check that raises does not hold (#496): the feature is withheld and the
        session is still answered, because a feature only offers a page or a link whose own
        route checks its caller again. The failure is logged by the feature's name alone.
        A database-safety refusal is not a failing check: `UnsafeDatabaseRole`, and with it
        `DormantGrantsRefused`, propagates, and the application answers it as it answers
        every other one, with a 503 and `dependency.unavailable`."""
        held: set[str] = set()
        for name, check in self.session_features:
            try:
                if check(runtime, session):
                    held.add(name)
            except UnsafeDatabaseRole:
                raise
            except Exception:
                # The exception's text could carry a value from the plugin's own settings or
                # its database, so only the fact of the failure and the feature's name leave.
                log_event("plugins.feature_failed", level="ERROR", feature=name)
        return frozenset(held)

    def shown_sign_in_link(self, runtime: "Runtime") -> ShownLink | None:
        """The sign-in page's plugin link for this render, or None to show none.

        The sign-in page must never depend on the label: one that raises, or that answers
        anything but one short line of printable text, hides the link and is logged by its
        plugin and a code alone, never with the exception's text or the label itself. A
        label of None is the plugin choosing to show no link, and is not logged.
        """
        return _shown(self.sign_in_link, runtime, _sign_in_link_failed, "INVALID_SIGN_IN_LINK")

    def shown_recovery_link(self, runtime: "Runtime") -> ShownLink | None:
        """The sign-in page's recovery link for this render, held to the sign-in link's rules
        and logged as `plugins.recovery_link_failed` when its label fails (#678)."""
        return _shown(self.recovery_link, runtime, _recovery_link_failed, "INVALID_RECOVERY_LINK")

    def service(self, configured: ServiceLinks | None) -> ServiceLinks:
        """The deployment's service links: the runtime configuration's `service` block, a
        loaded plugin's, or with neither only the Source link, to the public repository.

        Both at once refuses start with `PLUGIN_CONFLICT`: the deployment is misconfigured,
        and choosing one silently would hide which addresses its pages show. A plugin's links
        are taken whole, so one that leaves `source_url` unset shows no Source link.
        """
        if configured is not None and self.service_links is not None:
            raise _refused("PLUGIN_CONFLICT")
        if configured is not None:
            return configured
        if self.service_links is not None:
            return self.service_links
        return ServiceLinks(source_url=SOURCE_URL)

    def config(self, name: str) -> BaseModel | None:
        """A loaded plugin's own validated section; None when it has none."""
        for plugin in self.loaded:
            if plugin.name == name:
                return plugin.config
        raise KeyError(name)


NO_PLUGINS = LoadedPlugins()


def _valid_link(link: object) -> bool:
    """A sign-in page link's registration rules: exactly a `SignInLink`, a callable label, and
    a literal absolute path on this site with no parameter, outside the reserved prefixes and
    ``/assets``, so it cannot point at another origin, carry a query or name a core route."""
    return (
        type(link) is SignInLink
        and callable(link.label)
        and type(link.path) is str
        and _CONSOLE_PATH.fullmatch(link.path) is not None
        and not _PARAMETER.search(link.path)
        and not reserved(link.path, RESERVED_PREFIXES + ("/assets",))
    )


def _sign_in_link_failed(plugin: str, code: str) -> None:
    log_event("plugins.sign_in_link_failed", level="ERROR", code=code, plugin=plugin)


def _recovery_link_failed(plugin: str, code: str) -> None:
    log_event("plugins.recovery_link_failed", level="ERROR", code=code, plugin=plugin)


def _shown(
    entry: tuple[str, SignInLink] | None,
    runtime: "Runtime",
    failed: Callable[[str, str], None],
    invalid: str,
) -> ShownLink | None:
    """One sign-in page link for this render: its label asked, checked and never trusted."""
    if entry is None:
        return None
    plugin, link = entry
    try:
        label = link.label(runtime)
    except Exception:
        failed(plugin, "PLUGIN_FAILED")
        return None
    if label is None:
        return None
    if (
        type(label) is not str
        or not label.strip()
        or len(label) > MAX_SIGN_IN_LABEL
        or not label.isprintable()
    ):
        failed(plugin, invalid)
        return None
    return ShownLink(link.path, label)


def _resolve(name: str) -> Plugin:
    module_name = "execbound." + name
    try:
        found = importlib.util.find_spec(module_name) is not None
    except (ImportError, ValueError):
        found = False
    if not found:
        raise _refused("UNKNOWN_PLUGIN", name)
    try:
        module = importlib.import_module(module_name)
    except Exception:
        # The exception's text could carry a value from the plugin's own settings, so only
        # the fact of the failure and the plugin's name leave this function.
        raise _refused("PLUGIN_FAILED", name) from None
    plugin = getattr(module, "PLUGIN", None)
    if type(plugin) is not Plugin or plugin.name != name:
        raise _refused("NOT_A_PLUGIN", name)
    if plugin.api_version != PLUGIN_API_VERSION:
        raise _refused("PLUGIN_API_MISMATCH", name)
    return plugin


def _configure(plugin: Plugin, section: Mapping[str, Any] | None) -> BaseModel | None:
    if section is None:
        return None
    if plugin.config is None:
        if section:
            raise _refused("INVALID_PLUGIN_CONFIG", plugin.name)
        return None
    try:
        # Round-tripped through JSON, exactly like the private configuration file's own top
        # level: a value like a UUID or a tuple is a plain string or a list once it has come
        # through real JSON, and strict validation admits that coercion only in JSON mode, not
        # for an already-Python value. `default=str` covers a value a test builds directly in
        # Python (a `UUID` instance rather than the string a config file would hold); it never
        # runs on a real deployment's section, whose values are already JSON-native.
        raw = json.dumps(dict(section), default=str)
    except (TypeError, ValueError):
        raise _refused("INVALID_PLUGIN_CONFIG", plugin.name) from None
    try:
        return plugin.config.model_validate_json(raw)
    except ValidationError:
        raise _refused("INVALID_PLUGIN_CONFIG", plugin.name) from None
    except Exception:
        raise _refused("PLUGIN_FAILED", plugin.name) from None


def load_plugins(sections: Mapping[str, Mapping[str, Any] | None]) -> LoadedPlugins:
    """Load the named plugins in name order, or refuse them all.

    A section of None loads a plugin without its configuration, which is what the command
    line does: a plugin's commands take their settings from their own arguments.
    """
    if not sections:
        return NO_PLUGINS
    if len(sections) > MAX_PLUGINS:
        raise _refused("TOO_MANY_PLUGINS")
    if any(type(name) is not str or not _NAME.fullmatch(name) for name in sections):
        raise _refused("INVALID_PLUGIN_NAME")
    loaded: list[LoadedPlugin] = []
    routers: list[HumanRouter] = []
    areas: list[ConsoleArea] = []
    paths: list[str] = []
    commands: list[Command] = []
    features: list[tuple[str, SessionCheck]] = []
    links: list[ApprovalLinks] = []
    sign_in_links: list[tuple[str, SignInLink]] = []
    recovery_links: list[tuple[str, SignInLink]] = []
    provider_signups: list[ProviderSignup] = []
    service_links: list[ServiceLinks] = []
    token_classified: list[tuple[str, str]] = []
    allowed_token_routes: set[tuple[str, str]] = set()
    refused_token_routes: set[tuple[str, str]] = set()
    claimed: list[str] = []
    claims: dict[str, frozenset[str]] = {}
    for name in sorted(sections):
        plugin = _resolve(name)
        config = _configure(plugin, sections[name])
        registry = Registry(name)
        try:
            plugin.register(registry)
        except PluginError:
            raise
        except Exception:
            raise _refused("PLUGIN_FAILED", name) from None
        loaded.append(LoadedPlugin(name, plugin.api_version, config))
        routers.extend(registry._human_routers)
        areas.extend(registry._console_areas)
        paths.extend(registry._console_paths)
        commands.extend(registry._commands)
        features.extend(registry._session_features)
        if registry._approval_links is not None:
            links.append(registry._approval_links)
        if registry._sign_in_link is not None:
            sign_in_links.append((name, registry._sign_in_link))
        if registry._recovery_link is not None:
            recovery_links.append((name, registry._recovery_link))
        if registry._provider_signup is not None:
            provider_signups.append(registry._provider_signup)
        if registry._service_links is not None:
            service_links.append(registry._service_links)
        if registry._token_routes is not None:
            permitted, denied = registry._token_routes
            token_classified.extend(permitted | denied)
            allowed_token_routes |= permitted
            refused_token_routes |= denied
        claimed.extend(registry._claims)
        claims.update(registry._claims)
    feature_names = [feature for feature, _ in features]
    if (
        len(set(paths)) != len(paths)
        or len({c.name for c in commands}) != len(commands)
        or len(set(feature_names)) != len(feature_names)
        or len(links) > 1
        or len(sign_in_links) > 1
        or len(recovery_links) > 1
        or len(provider_signups) > 1
        or len(service_links) > 1
        or len(set(token_classified)) != len(token_classified)
        or len(set(claimed)) != len(claimed)
    ):
        raise _refused("PLUGIN_CONFLICT")
    try:
        honour_claims(claims)
    except ClaimConflict:
        # A process honours what every load claimed; a later load may add, never change.
        raise _refused("PLUGIN_CONFLICT") from None
    for plugin_loaded in loaded:
        log_event("plugins.loaded", plugin=plugin_loaded.name)
    return LoadedPlugins(
        loaded=tuple(loaded),
        human_routers=tuple(routers),
        console_areas=tuple(areas),
        console_paths=tuple(paths),
        commands=tuple(commands),
        session_features=tuple(features),
        approval_links=links[0] if links else None,
        sign_in_link=sign_in_links[0] if sign_in_links else None,
        recovery_link=recovery_links[0] if recovery_links else None,
        provider_signup=provider_signups[0] if provider_signups else None,
        service_links=service_links[0] if service_links else None,
        allowed_token_routes=frozenset(allowed_token_routes),
        refused_token_routes=frozenset(refused_token_routes),
        claims=MappingProxyType(claims),
    )


def names_from_environment(environ: Mapping[str, str] | None = None) -> tuple[str, ...]:
    """The plugins the command line loads: ``EXECBOUND_PLUGINS``, comma separated."""
    raw = (os.environ if environ is None else environ).get(ENVIRONMENT, "")
    names = tuple(part.strip() for part in raw.split(",") if part.strip())
    if len(set(names)) != len(names):
        raise _refused("PLUGIN_CONFLICT")
    return names


def load_command_plugins(environ: Mapping[str, str] | None = None) -> LoadedPlugins:
    return load_plugins({name: None for name in names_from_environment(environ)})


def _leading_parameter(path: str) -> bool:
    """Whether ``path``'s first segment could ever answer for more than its literal spelling
    (``path`` already starts with ``/``).

    Starlette compiles a ``{parameter}`` wherever it appears in a segment, not only where it
    is the whole of one, so ``v{a}`` is a real one-letter-then-anything pattern and not the
    literal string it looks like. Any ``{`` at all in the first segment is enough: with one
    ruled out, the first segment is a plain literal, which is what makes comparing it against
    ``RESERVED_PREFIXES`` as a string in ``reserved()`` sound.
    """
    first = path[1:].split("/", 1)[0]
    return "{" in first


def _segment_matches(pattern: str, literal: str) -> bool:
    """Whether Starlette's own pattern for the one segment ``pattern`` matches ``literal``."""
    return compile_path("/" + pattern)[0].fullmatch("/" + literal) is not None


def _segments_overlap(ours: str, theirs: str) -> bool:
    """Whether one path segment could match both ``ours`` and ``theirs``."""
    if ours == theirs or ("{" in ours and "{" in theirs):
        return True
    if "{" in ours:
        return _segment_matches(ours, theirs)
    if "{" in theirs:
        return _segment_matches(theirs, ours)
    return False


def _overlap(path: str, other: str) -> bool:
    """Whether one request path could match both, compared segment by segment."""
    ours, theirs = path.split("/"), other.split("/")
    return len(ours) == len(theirs) and all(map(_segments_overlap, ours, theirs))


def check_paths(
    paths: Iterable[str],
    existing: Iterable[BaseRoute],
    *,
    reserve: bool = True,
    require_prefix: str | None = None,
) -> None:
    """Refuse a plugin path that is malformed, reserved, or that overlaps an existing route.

    ``INVALID_ROUTE`` refuses a path that is not a string, does not start with ``/``, ends
    with ``/``, uses a convertor such as ``{rest:path}``, or lies outside ``require_prefix``.
    With ``reserve``, it also refuses a reserved path and a parameter anywhere in the first
    segment. A path ending in ``/`` would take the path Starlette redirects to a core route,
    and a convertor can span segments, which the comparison below does not model. A nested
    router has no path of its own, so a plugin router that includes one reads as ``""`` and is
    refused here too.

    ``ROUTE_CONFLICT`` refuses a path an existing route would answer for any method, found by
    that route's own ``matches`` on the path with each parameter replaced by one segment, or a
    path that overlaps an existing route's path segment by segment. Two paths overlap when they
    have as many segments and each pair is equal, both hold a parameter, or one holds a
    parameter whose pattern matches the other. The existing paths are read through
    ``iter_route_contexts``, because ``app.routes`` holds included routers with no path.
    """
    todo = list(paths)
    if not todo:
        return
    routes = list(existing)
    contexts: list[RouteContext] = list(iter_route_contexts(routes))
    for path in todo:
        if (
            type(path) is not str
            or not path.startswith("/")
            or path.endswith("/")
            or _CONVERTOR.search(path)
            or (reserve and (reserved(path) or _leading_parameter(path)))
            or (require_prefix is not None and not path.startswith(require_prefix))
        ):
            raise _refused("INVALID_ROUTE")
        sample = _PARAMETER.sub("sample", path)
        for route in routes:
            matches = getattr(route, "matches", None)
            if not callable(matches):
                continue
            match, _ = matches({"type": "http", "method": "GET", "path": sample, "headers": []})
            if match != Match.NONE:
                raise _refused("ROUTE_CONFLICT")
        for context in contexts:
            existing_path = context.path
            if isinstance(existing_path, str) and _overlap(path, existing_path):
                raise _refused("ROUTE_CONFLICT")


def check_added_routes(
    added: Iterable[object],
    existing: Iterable[BaseRoute],
    *,
    reserve: bool = True,
    require_prefix: str | None = None,
) -> None:
    """Refuse a route that is not a plain HTTP or WebSocket route, then check its path.

    A ``Mount`` or a ``Host`` (or any other ``BaseRoute``) is refused with ``INVALID_ROUTE``
    before its path is even read: ``Mount.path`` is one literal segment as far as the checks
    below are concerned, so a mount at ``/account`` would be admitted and would then answer
    every path beneath it, including one core already answers under a different method
    (#238's mount bypass). FastAPI's ``APIRoute`` and ``APIWebSocketRoute`` subclass ``Route``
    and ``WebSocketRoute`` and so are unaffected.
    """
    routes = list(added)
    if any(not isinstance(route, (Route, WebSocketRoute)) for route in routes):
        raise _refused("INVALID_ROUTE")
    check_paths(
        (getattr(route, "path", "") for route in routes),
        existing,
        reserve=reserve,
        require_prefix=require_prefix,
    )


def _low_priority(router: "APIRouter") -> bool:
    # `APIRouter.frontend()` (FastAPI 0.141) keeps its routes in `_low_priority_routes`, not in
    # `routes`, and they answer any path no other route matched, so no path check sees them.
    return bool(getattr(router, "_low_priority_routes", None))


def check_page_router(router: "APIRouter", existing: Iterable[BaseRoute]) -> None:
    """Refuse a plugin's page router with low-priority routes, or with a path `check_paths`
    refuses."""
    if _low_priority(router):
        raise _refused("INVALID_ROUTE")
    check_added_routes(router.routes, existing)


def plugin_pages(
    factory: HumanRouter,
    runtime: "Runtime",
    human: "HumanConfig",
    existing: Iterable[BaseRoute],
) -> "APIRouter":
    """One plugin page router, built by its factory and then held to `check_page_router`.

    A plugin may refuse while its pages are built, where its own section first meets core's
    configuration: a section that needs a core block the configuration lacks can only be
    refused here. That refusal is logged as `plugins.refused` like every other, by its code
    alone, because a factory does not carry the name of the plugin that registered it.
    """
    try:
        pages = factory(runtime, human)
    except PluginError as exc:
        raise _refused(exc.code) from None
    check_page_router(pages, existing)
    return pages


def check_console_area(routes: "APIRouter", before: list[BaseRoute], prefix: str) -> None:
    """Refuse what one plugin console area did to the console API router, unless it only
    appended routes under ``prefix`` that `check_paths` admits. An area that inserted, replaced
    or removed a route, or added low-priority routes, is refused with ``INVALID_ROUTE``."""
    kept = routes.routes[: len(before)]
    if (
        _low_priority(routes)
        or len(kept) != len(before)
        or any(route is not earlier for route, earlier in zip(kept, before, strict=True))
    ):
        raise _refused("INVALID_ROUTE")
    check_added_routes(routes.routes[len(before) :], before, reserve=False, require_prefix=prefix)
