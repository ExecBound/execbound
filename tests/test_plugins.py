# SPDX-License-Identifier: AGPL-3.0-only
"""Loading first-party plugins: named or nothing, the right API, the plugin's own settings.

No database: these are the loader's rules. What a loaded plugin adds to a running gateway is
`test_plugin_surfaces.py`.
"""

import importlib
from dataclasses import replace
from typing import Any
from uuid import UUID

import pytest
from fastapi import APIRouter, FastAPI
from plugin_fixtures import captured as captured
from plugin_fixtures import events, install
from plugin_fixtures import sample as sample
from pydantic import model_validator
from starlette.routing import Host, Mount, Route, WebSocketRoute

from execbound.db import (
    ClaimConflict,
    DormantGrantsRefused,
    UnsafeDatabaseRole,
    honour_claims,
    honoured_claims,
)
from execbound.plugins import (
    NO_PLUGINS,
    PLUGIN_API_VERSION,
    PLUGIN_GRANTS_MISMATCH,
    PLUGIN_GRANTS_REFUSAL,
    RUNTIME_CHECK_REFUSAL,
    ApprovalLinks,
    CommandError,
    PluginError,
    ProviderSignup,
    Registry,
    ShownLink,
    SignInLink,
    check_added_routes,
    check_paths,
    database_refusal,
    load_plugins,
    names_from_environment,
)
from execbound.requests import StrictModel
from execbound.service_links import SOURCE_URL, ServiceLinks
from execbound.surfaces.console_api.token_rules import token_allowed


def refused(sections) -> str:
    with pytest.raises(PluginError) as caught:
        load_plugins(sections)
    return caught.value.code


def test_an_installed_plugin_nobody_named_loads_nothing(sample):
    assert load_plugins({}) is NO_PLUGINS
    assert NO_PLUGINS.names == () and NO_PLUGINS.console_paths == ()


def test_a_named_plugin_loads_with_its_own_configuration(sample, captured):
    loaded = load_plugins({"sample_plugin": {"greeting": "hi"}})
    assert loaded.names == ("sample_plugin",)
    assert loaded.config("sample_plugin") == sample.SampleConfig(greeting="hi")
    assert loaded.console_paths == ("/sample-plugin",)
    assert [command.name for command in loaded.commands] == ["sample-echo"]
    assert len(loaded.human_routers) == 1 and len(loaded.console_areas) == 1
    [record] = events(captured, "plugins.loaded")
    assert record["plugin"] == "sample_plugin" and "greeting" not in record


def test_a_loaded_plugins_repr_never_shows_its_configuration(sample):
    """Structurally, not by care at each call site: a traceback or a debug print of what
    loaded names the plugin and never its section."""
    loaded = load_plugins({"sample_plugin": {"greeting": "private-greeting"}})
    [plugin] = loaded.loaded
    assert "sample_plugin" in repr(plugin) and "sample_plugin" in repr(loaded)
    assert "private-greeting" not in repr(plugin) and "private-greeting" not in repr(loaded)
    assert "config" not in repr(plugin)


@pytest.mark.parametrize("name", ["", "Sample", "../etc", "a.b", "a-b", "1st", "x" * 33])
def test_a_name_that_cannot_be_a_plugin_is_refused_without_echoing_it(name, captured):
    assert refused({name: {}}) == "INVALID_PLUGIN_NAME"
    [record] = events(captured, "plugins.refused")
    assert record["code"] == "INVALID_PLUGIN_NAME" and "plugin" not in record


def test_more_plugins_than_a_deployment_may_name_are_refused():
    assert refused({f"p{number}": {} for number in range(9)}) == "TOO_MANY_PLUGINS"


def test_a_plugin_that_is_not_installed_is_refused(captured):
    assert refused({"no_such_plugin": {}}) == "UNKNOWN_PLUGIN"
    [record] = events(captured, "plugins.refused")
    assert record["plugin"] == "no_such_plugin"


@pytest.mark.parametrize("name", ["db", "plugins", "cli"])
def test_a_core_module_is_not_a_plugin(name):
    assert refused({name: {}}) == "NOT_A_PLUGIN"


def test_a_plugin_claiming_another_name_is_refused(monkeypatch):
    install(monkeypatch, "sample_twin")
    assert refused({"sample_twin": {}}) == "NOT_A_PLUGIN"


def test_a_plugin_built_for_another_api_major_refuses_start(monkeypatch):
    install(monkeypatch, api_version=PLUGIN_API_VERSION + 1)
    assert refused({"sample_plugin": {}}) == "PLUGIN_API_MISMATCH"


@pytest.mark.parametrize("section", [{"greeting": 3}, {"greeting": "hi", "extra": True}])
def test_the_plugin_validates_its_own_section(sample, section):
    assert refused({"sample_plugin": section}) == "INVALID_PLUGIN_CONFIG"


def test_a_plugin_without_a_configuration_model_takes_only_an_empty_section(monkeypatch):
    install(monkeypatch, config=None)
    assert load_plugins({"sample_plugin": {}}).config("sample_plugin") is None
    assert refused({"sample_plugin": {"greeting": "hi"}}) == "INVALID_PLUGIN_CONFIG"


class _TypedConfig(StrictModel):
    """A strict section with the two field types a JSON document cannot hold as themselves."""

    tenant_id: UUID
    origins: tuple[str, ...] = ()


_TENANT = UUID("00000000-0000-4000-8000-000000000001")
_TYPED = _TypedConfig(tenant_id=_TENANT, origins=("https://a.example",))


def test_a_section_is_validated_as_the_json_a_configuration_file_holds(monkeypatch):
    """A UUID arrives as a string and a tuple as a list, as they do from the private file,
    and a strict model admits that coercion only from JSON, so the loader validates the
    section's JSON rather than the Python mapping it was handed."""
    install(monkeypatch, config=_TypedConfig)
    section = {"tenant_id": str(_TENANT), "origins": ["https://a.example"]}
    assert load_plugins({"sample_plugin": section}).config("sample_plugin") == _TYPED


def test_a_section_built_in_python_validates_as_its_json_would(monkeypatch):
    """A caller that builds the section in Python, as a test does, may hand the UUID itself:
    it reaches the plugin as the string a file would hold rather than refusing the load."""
    install(monkeypatch, config=_TypedConfig)
    section = {"tenant_id": _TENANT, "origins": ("https://a.example",)}
    assert load_plugins({"sample_plugin": section}).config("sample_plugin") == _TYPED


def _circular() -> dict[str, Any]:
    section: dict[str, Any] = {"greeting": "private-greeting"}
    section["again"] = section
    return section


@pytest.mark.parametrize(
    "section",
    [{("private-greeting",): "hi"}, _circular()],
    ids=["key-json-cannot-hold", "circular"],
)
def test_a_section_json_cannot_hold_is_refused_by_code_alone(sample, captured, section):
    assert refused({"sample_plugin": section}) == "INVALID_PLUGIN_CONFIG"
    [record] = events(captured, "plugins.refused")
    assert record["code"] == "INVALID_PLUGIN_CONFIG" and record["plugin"] == "sample_plugin"
    assert "private-greeting" not in captured.getvalue()


def test_the_command_line_loads_a_plugin_without_its_section(sample):
    loaded = load_plugins({"sample_plugin": None})
    assert loaded.names == ("sample_plugin",) and loaded.config("sample_plugin") is None


@pytest.mark.parametrize(
    "path",
    [
        "/v1/sample",
        "/api/sample",
        "/console/sample",
        "/health/sample",
        "/mcp",
        "/next/sample",
        "/pre",
        "/post",
        "/assets/sample",
        "sample",
        "/Sample",
        "/sample//x",
        "/sample/{Bad}",
        "/{a}",
        "/{a}/b",
        "/sample/",
        "/sample/{rest:path}",
    ],
)
def test_a_console_page_that_is_reserved_or_malformed_is_refused(path):
    with pytest.raises(PluginError) as caught:
        Registry("sample_plugin").console_path(path)
    assert caught.value.code == "INVALID_ROUTE"


@pytest.mark.parametrize("path", ["/sample/{tenant_id}", "/sample/{approval_id}/review"])
def test_a_console_page_may_not_use_a_parameter_the_page_handler_reads(path):
    """The console page handler opens an approval's review when it sees `tenant_id`, and then
    reads `approval_id` too; a plugin page with either name would break every request to it."""
    with pytest.raises(PluginError) as caught:
        Registry("sample_plugin").console_path(path)
    assert caught.value.code == "INVALID_ROUTE"


def test_one_path_or_command_registered_twice_conflicts(monkeypatch):
    def twice(registry):
        registry.console_path("/sample-plugin")
        registry.console_path("/sample-plugin")

    install(monkeypatch, register=twice)
    assert refused({"sample_plugin": {}}) == "PLUGIN_CONFLICT"


def test_the_command_line_reads_its_plugins_from_the_environment():
    assert names_from_environment({}) == ()
    assert names_from_environment({"EXECBOUND_PLUGINS": " a , b,,"}) == ("a", "b")
    with pytest.raises(PluginError) as caught:
        names_from_environment({"EXECBOUND_PLUGINS": "a,a"})
    assert caught.value.code == "PLUGIN_CONFLICT"


def test_the_registry_offers_no_point_on_the_execution_path():
    public = {name for name in vars(Registry) if not name.startswith("_")}
    assert public == {
        "human_router",
        "console_area",
        "console_path",
        "command",
        "session_feature",
        "approval_links",
        "sign_in_link",
        "recovery_link",
        "provider_signup",
        "service_links",
        "token_routes",
        # Recorded data, never plugin code: the one point the execution path reads, and only
        # to refuse.
        "claim",
    }


@pytest.mark.parametrize(
    "path",
    [
        "/{a}/detail",
        # A parameter embedded in a first segment still lets Starlette match more than the
        # literal spelling, so it must be refused as surely as a segment that is only one.
        "/{a}1/sample",
        "/v{a}/sample",
        "/heal{a}/x",
        "/{a}.json",
    ],
)
def test_a_plugin_page_with_a_parameter_in_its_first_segment_is_refused(path):
    with pytest.raises(PluginError) as caught:
        check_paths([path], [])
    assert caught.value.code == "INVALID_ROUTE"


def _routed_app() -> FastAPI:
    """A small app shaped like the pieces `check_paths` must see behind `app.routes`: a
    router included into a prefixed router (itself included into the app), a parameterized
    path two levels deep, a POST-only route beside it, a literal path for the reverse check,
    and a raw `Mount`.
    """
    app = FastAPI()

    async def noop() -> dict[str, str]:
        return {}

    inner = APIRouter()
    inner.get("/{person_id}")(noop)
    inner.post("/{person_id}/decide")(noop)

    outer = APIRouter(prefix="/people")
    outer.include_router(inner)
    app.include_router(outer)

    @app.get("/people/me/detail")
    def literal() -> dict[str, str]:
        return {}

    async def tool_app(scope: Any, receive: Any, send: Any) -> None:  # pragma: no cover
        pass

    app.router.routes.append(Mount("/tools", app=tool_app))
    return app


def test_check_paths_reaches_a_route_nested_two_includes_deep():
    """The included, prefixed `/people/{person_id}` conflicts with a plugin at that shape,
    even though `app.routes` holds no flattened route of its own to read a `path_regex` off."""
    with pytest.raises(PluginError) as caught:
        check_paths(["/people/{x}"], _routed_app().routes)
    assert caught.value.code == "ROUTE_CONFLICT"


def test_check_paths_counts_a_partial_method_match_as_a_conflict():
    """`/people/{person_id}/decide` is POST-only; a literal plugin path at that same shape
    still conflicts, since methods are never compared."""
    with pytest.raises(PluginError) as caught:
        check_paths(["/people/me/decide"], _routed_app().routes)
    assert caught.value.code == "ROUTE_CONFLICT"


def test_the_forward_check_alone_counts_a_partial_method_match():
    """A POST-only route whose `:path` parameter spans segments: the segment comparison never
    fires (the segment counts differ), so only the route's own `matches` answering PARTIAL for
    a GET can refuse the plugin path."""
    app = FastAPI()

    async def noop() -> dict[str, str]:
        return {}

    app.post("/files/{rest:path}")(noop)
    with pytest.raises(PluginError) as caught:
        check_paths(["/files/a/b"], app.routes)
    assert caught.value.code == "ROUTE_CONFLICT"


def test_check_paths_conflicts_with_a_mount():
    with pytest.raises(PluginError) as caught:
        check_paths(["/tools/{x}"], _routed_app().routes)
    assert caught.value.code == "ROUTE_CONFLICT"


async def _tool_app(scope, receive, send) -> None:  # pragma: no cover
    pass


async def _noop() -> dict[str, str]:
    return {}


async def _ws(websocket) -> None:  # pragma: no cover
    pass


def test_check_added_routes_refuses_a_mount_or_a_host():
    """A plugin router that adds a `Mount` or a `Host` reads as one literal path segment to
    every check below, so it would be admitted and then answer whatever it spans, core routes
    under a different method included. Neither is a route at all, so both are refused before
    their path is ever read."""
    for added in (Mount("/account", app=_tool_app), Host("sample.example", app=_tool_app)):
        with pytest.raises(PluginError) as caught:
            check_added_routes([added], [])
        assert caught.value.code == "INVALID_ROUTE"


def test_check_added_routes_admits_a_route_and_a_websocket_route():
    check_added_routes([Route("/sample", _noop), WebSocketRoute("/sample/ws", _ws)], [])


def test_check_paths_conflicts_the_other_way_too():
    """The plugin's own pattern would answer a core route's literal path, even though no
    core route answers the plugin's own sample: `/people/sample/detail` matches nothing
    existing, but `/people/me/detail` matches the plugin's `[^/]+` in the middle segment."""
    with pytest.raises(PluginError) as caught:
        check_paths(["/people/{x}/detail"], _routed_app().routes)
    assert caught.value.code == "ROUTE_CONFLICT"


def test_check_paths_does_not_false_positive_on_an_unrelated_path():
    check_paths(["/gadgets/{x}"], _routed_app().routes)


def _approval_routes() -> FastAPI:
    """Core's two basic approval routes: a GET and a POST, each with a parameter in the middle."""
    app = FastAPI()
    core = APIRouter()

    async def noop() -> dict[str, str]:
        return {}

    core.get("/approvals/{approval_id}/classic")(noop)
    core.post("/approvals/{approval_id}/decide")(noop)
    app.include_router(core)
    return app


def test_check_paths_conflicts_with_a_route_it_crosses():
    """The plugin's parameter stands against a core literal in the last segment, and a core
    parameter against the plugin's literal in the middle one, so `/approvals/pending/classic`
    would match both. Neither path's sample matches the other; comparing segment by segment
    does."""
    with pytest.raises(PluginError) as caught:
        check_paths(["/approvals/pending/{x}"], _approval_routes().routes)
    assert caught.value.code == "ROUTE_CONFLICT"


@pytest.mark.parametrize(
    "path,conflicts",
    [("/reports/{name}.json", True), ("/reports/weekly.csv", False), ("/reports/{a}/x", False)],
)
def test_a_parameter_inside_a_segment_overlaps_only_what_its_pattern_matches(path, conflicts):
    app = FastAPI()

    async def noop() -> dict[str, str]:
        return {}

    app.get("/reports/weekly.json")(noop)
    app.get("/reports/{name}.xml")(noop)
    if conflicts:
        with pytest.raises(PluginError) as caught:
            check_paths([path], app.routes)
        assert caught.value.code == "ROUTE_CONFLICT"
    else:
        check_paths([path], app.routes)


@pytest.mark.parametrize(
    "path",
    [
        "/account/security/passkey/{rest:path}",
        "/sample/{name:str}",
        "/sample/{number:int}",
    ],
)
def test_a_plugin_path_with_a_convertor_is_refused(path):
    """A `:path` parameter spans segments, so it would answer a GET under a POST-only core
    route; no plugin needs a convertor, so none is admitted."""
    app = FastAPI()

    async def noop() -> dict[str, str]:
        return {}

    app.post("/account/security/passkey/{kind}/{stage}")(noop)
    with pytest.raises(PluginError) as caught:
        check_paths([path], app.routes)
    assert caught.value.code == "INVALID_ROUTE"


@pytest.mark.parametrize("path", ["/login/", "/sample-plugin/", "/"])
def test_a_plugin_path_ending_in_a_slash_is_refused(path):
    """`/login/` would take the path Starlette redirects to core's `/login`."""
    app = FastAPI()

    async def noop() -> dict[str, str]:
        return {}

    app.get("/login")(noop)
    with pytest.raises(PluginError) as caught:
        check_paths([path], app.routes)
    assert caught.value.code == "INVALID_ROUTE"


def test_a_path_beside_a_core_route_is_admitted():
    """A plugin's paths sit beside core's `POST /session` and `GET /assets/app.css`
    and share nothing with them but a first segment."""
    app = FastAPI()

    async def noop() -> dict[str, str]:
        return {}

    app.post("/session")(noop)
    app.get("/assets/app.css")(noop)
    check_paths(["/session/logout", "/assets/account-security.js"], app.routes)


async def _review(request, runtime, config, session, csrf, tenant_id, approval_id, classic):
    return None


def _path(tenant_id, approval_id):
    return f"/workspaces/{tenant_id}/approvals/{approval_id}"


@pytest.mark.parametrize("name", ["Bad", "has space", "", "x" * 33, None])
def test_a_session_feature_needs_a_plugin_style_name(name):
    with pytest.raises(PluginError) as caught:
        Registry("sample_plugin").session_feature(name, lambda runtime, session: True)
    assert caught.value.code == "INVALID_FEATURE"


def test_a_session_feature_needs_a_check_it_can_call():
    with pytest.raises(PluginError) as caught:
        Registry("sample_plugin").session_feature("invitations", "yes")
    assert caught.value.code == "INVALID_FEATURE"


def test_a_plugin_sets_approval_links_once():
    registry = Registry("sample_plugin")
    registry.approval_links(ApprovalLinks(_path, _review))
    with pytest.raises(PluginError) as caught:
        registry.approval_links(ApprovalLinks(_path, _review))
    assert caught.value.code == "INVALID_APPROVAL_LINKS"
    with pytest.raises(PluginError) as caught:
        Registry("sample_plugin").approval_links((_path, _review))
    assert caught.value.code == "INVALID_APPROVAL_LINKS"


def test_the_loaded_plugins_carry_features_and_approval_links(sample):
    loaded = load_plugins({"sample_plugin": {}})
    assert [name for name, _ in loaded.session_features] == ["invitations"]
    assert loaded.approval_links is not None
    assert NO_PLUGINS.session_features == () and NO_PLUGINS.approval_links is None


def test_a_session_feature_whose_check_raises_is_withheld_and_logged_by_name(captured):
    """A failing check does not hold, and the other features are still read (#496).
    The log names the feature and never carries the exception's text."""

    def failing(runtime, session):
        raise RuntimeError("postgresql://owner:hunter2@db/execbound")

    loaded = replace(
        NO_PLUGINS,
        session_features=(
            ("invitations", failing),
            ("other_feature", lambda runtime, session: True),
        ),
    )
    assert loaded.features(None, None) == frozenset({"other_feature"})
    [record] = events(captured, "plugins.feature_failed")
    assert record["level"] == "ERROR" and record["feature"] == "invitations"
    assert "hunter2" not in captured.getvalue()


def test_a_session_feature_check_refused_by_the_database_is_not_swallowed(captured):
    """A database-safety refusal inside a check is the process's to answer, not the
    feature's to withhold (#496): it propagates, and no feature failure is logged."""

    def refused(runtime, session):
        raise DormantGrantsRefused("the dormant grants differ from the claims")

    loaded = replace(
        NO_PLUGINS,
        session_features=(
            ("other_feature", lambda runtime, session: True),
            ("invitations", refused),
        ),
    )
    with pytest.raises(DormantGrantsRefused):
        loaded.features(None, None)
    assert events(captured, "plugins.feature_failed") == []


def _feature_only(registry):
    registry.session_feature("invitations", lambda runtime, session: True)


def _links_only(registry):
    registry.approval_links(ApprovalLinks(_path, _review))


def _sign_in_link_only(registry):
    registry.sign_in_link(SignInLink("/other-plugin", lambda runtime: "Other"))


async def _finish(runtime, config, request, account):
    return None


def _page_refused(runtime, config, request):
    return None


def _sync_finish(runtime, config, request, account):
    """A plain function, not a coroutine function: what a plugin writes when it forgets
    `async def`, which `Registry.provider_signup` must catch rather than let the callback
    discover the first time it tries to `await` this and cannot."""
    return None


async def _async_refused(runtime, config, request):
    """A coroutine function: still callable, so `callable(signup.refused)` alone would miss
    it, but `refused` is called with no `await` of its own (`provider_refusal`), so one of
    these would hand the callback a coroutine instead of the page it is supposed to render."""
    return None


def _provider_signup_only(registry):
    registry.provider_signup(ProviderSignup(_finish, _page_refused))


@pytest.mark.parametrize(
    "register", [_feature_only, _links_only, _sign_in_link_only, _provider_signup_only]
)
def test_a_second_plugin_claiming_a_feature_links_a_sign_in_link_or_a_provider_signup_conflicts(
    monkeypatch, register
):
    install(monkeypatch, "sample_plugin")
    other = install(monkeypatch, "other_plugin")
    other.PLUGIN = replace(other.PLUGIN, name="other_plugin", config=None, register=register)
    assert refused({"sample_plugin": {}, "other_plugin": None}) == "PLUGIN_CONFLICT"


def test_a_plugin_adds_one_provider_signup_point(monkeypatch):
    """Loaded as `sign_in_link` is: at most one across plugins, filled from the registry."""
    install(monkeypatch, register=_provider_signup_only)
    loaded = load_plugins({"sample_plugin": {}})
    assert loaded.provider_signup == ProviderSignup(_finish, _page_refused)
    assert NO_PLUGINS.provider_signup is None


def test_a_plugin_sets_its_provider_signup_point_once(captured):
    registry = Registry("sample_plugin")
    registry.provider_signup(ProviderSignup(_finish, _page_refused))
    with pytest.raises(PluginError) as caught:
        registry.provider_signup(ProviderSignup(_finish, _page_refused))
    assert caught.value.code == "INVALID_PROVIDER_SIGNUP"
    [event] = events(captured, "plugins.refused")
    assert event["code"] == "INVALID_PROVIDER_SIGNUP" and event["plugin"] == "sample_plugin"


@pytest.mark.parametrize(
    "signup",
    [
        (_finish, _page_refused),
        None,
        "a provider signup",
        ProviderSignup(3, _page_refused),
        ProviderSignup(_finish, 3),
        ProviderSignup("not callable", "also not callable"),
        ProviderSignup(_sync_finish, _page_refused),
        ProviderSignup(_finish, _async_refused),
    ],
)
def test_a_provider_signup_point_needs_an_async_finish_and_a_callable_refused(signup):
    with pytest.raises(PluginError) as caught:
        Registry("sample_plugin").provider_signup(signup)
    assert caught.value.code == "INVALID_PROVIDER_SIGNUP"


def _label(runtime):
    return "Join"


def test_a_plugin_adds_one_sign_in_link(sample):
    """The sample links the sign-in page to its own page; nothing loaded links nowhere."""
    loaded = load_plugins({"sample_plugin": {}})
    assert loaded.sign_in_link is not None
    plugin, link = loaded.sign_in_link
    assert plugin == "sample_plugin" and link.path == "/sample-plugin/hello"
    assert NO_PLUGINS.sign_in_link is None
    assert NO_PLUGINS.shown_sign_in_link(object()) is None


def test_a_plugin_sets_its_sign_in_link_once(captured):
    registry = Registry("sample_plugin")
    registry.sign_in_link(SignInLink("/join", _label))
    with pytest.raises(PluginError) as caught:
        registry.sign_in_link(SignInLink("/join", _label))
    assert caught.value.code == "INVALID_SIGN_IN_LINK"
    [event] = events(captured, "plugins.refused")
    assert event["code"] == "INVALID_SIGN_IN_LINK" and event["plugin"] == "sample_plugin"


@pytest.mark.parametrize(
    "link",
    [
        ("/join", _label),
        None,
        "/join",
        SignInLink("/join", "Join"),
        SignInLink("/join", None),
        SignInLink(3, _label),
        SignInLink("join", _label),
        SignInLink("/", _label),
        SignInLink("/Join", _label),
        SignInLink("/join/", _label),
        SignInLink("/join//us", _label),
        SignInLink("/join?next=/", _label),
        SignInLink("https://gateway.example/join", _label),
        SignInLink("//gateway.example/join", _label),
        SignInLink("/join/{person}", _label),
        SignInLink("/{page}", _label),
        SignInLink("/join/{rest:path}", _label),
        SignInLink("/v1/join", _label),
        SignInLink("/api/join", _label),
        SignInLink("/console", _label),
        SignInLink("/health/ready", _label),
        SignInLink("/assets/join.js", _label),
        SignInLink("/assets", _label),
        SignInLink("/assets/join", _label),
    ],
)
def test_a_sign_in_link_is_a_literal_page_path_and_a_callable_label(link):
    """Only a path of this site's own, spelled out: no parameter a request could fill in, no
    other origin, no query, and nowhere only core answers or where files rather than pages
    are served."""
    with pytest.raises(PluginError) as caught:
        Registry("sample_plugin").sign_in_link(link)
    assert caught.value.code == "INVALID_SIGN_IN_LINK"


class _Link(str):
    """A path that is a string and is not one."""


def test_a_sign_in_link_path_must_be_exactly_a_string():
    with pytest.raises(PluginError) as caught:
        Registry("sample_plugin").sign_in_link(SignInLink(_Link("/join"), _label))
    assert caught.value.code == "INVALID_SIGN_IN_LINK"


def _shown(label, monkeypatch):
    """What the sign-in page shows for one label, from a plugin registering only that link."""

    def register(registry):
        registry.sign_in_link(SignInLink("/join-us", label))

    install(monkeypatch, register=register)
    return load_plugins({"sample_plugin": {}}).shown_sign_in_link(object())


def test_the_sign_in_label_is_asked_on_every_render(monkeypatch):
    answers = iter(["First", None, "Second"])
    loaded_label = []

    def label(runtime):
        loaded_label.append(runtime)
        return next(answers)

    def register(registry):
        registry.sign_in_link(SignInLink("/join-us", label))

    install(monkeypatch, register=register)
    loaded = load_plugins({"sample_plugin": {}})
    assert loaded_label == []
    runtime = object()
    assert loaded.shown_sign_in_link(runtime) == ShownLink("/join-us", "First")
    assert loaded.shown_sign_in_link(runtime) is None
    assert loaded.shown_sign_in_link(runtime) == ShownLink("/join-us", "Second")
    assert loaded_label == [runtime] * 3


def test_a_sign_in_label_that_raises_hides_the_link_and_is_logged_without_its_text(
    monkeypatch, captured
):
    def label(runtime):
        raise RuntimeError("secret-from-label")

    assert _shown(label, monkeypatch) is None
    [event] = events(captured, "plugins.sign_in_link_failed")
    assert event["level"] == "ERROR"
    assert event["code"] == "PLUGIN_FAILED" and event["plugin"] == "sample_plugin"
    assert "secret" not in captured.getvalue()


@pytest.mark.parametrize(
    "label",
    [3, b"Join", "", "   ", "x" * 61, "Join\nus", "Join\tus", "Join\x00", "Join\u202eus"],
)
def test_a_sign_in_label_that_is_not_a_short_printable_line_hides_the_link(
    monkeypatch, captured, label
):
    assert _shown(lambda runtime: label, monkeypatch) is None
    [event] = events(captured, "plugins.sign_in_link_failed")
    assert event["code"] == "INVALID_SIGN_IN_LINK" and event["plugin"] == "sample_plugin"
    assert "Join" not in captured.getvalue()


class _Label(str):
    """A label that is a string and is not one."""


def test_a_sign_in_label_must_be_exactly_a_string(monkeypatch, captured):
    assert _shown(lambda runtime: _Label("Join"), monkeypatch) is None
    [event] = events(captured, "plugins.sign_in_link_failed")
    assert event["code"] == "INVALID_SIGN_IN_LINK"


def test_a_sign_in_label_of_none_hides_the_link_quietly(monkeypatch, captured):
    assert _shown(lambda runtime: None, monkeypatch) is None
    assert events(captured, "plugins.sign_in_link_failed") == []


def test_a_sign_in_label_up_to_sixty_characters_is_shown(monkeypatch):
    label = "Sign up for Community, " + "x" * 37
    assert len(label) == 60
    assert _shown(lambda runtime: label, monkeypatch) == ShownLink("/join-us", label)


@pytest.mark.parametrize("stage", ["import", "register", "config"])
def test_a_plugin_that_raises_is_refused_by_name_and_its_text_is_dropped(
    monkeypatch, captured, stage
):
    module = install(monkeypatch)
    if stage == "import":
        real = importlib.import_module

        def failing(name, *args):
            if name == "execbound.sample_plugin":
                raise RuntimeError("secret-from-import")
            return real(name, *args)

        monkeypatch.setattr("execbound.plugins.importlib.import_module", failing)
    elif stage == "register":

        def register(registry):
            raise ValueError("secret-from-register")

        module.PLUGIN = replace(module.PLUGIN, register=register)
    else:

        class Exploding(StrictModel):
            @model_validator(mode="after")
            def explode(self):
                raise RuntimeError("secret-from-config")

        module.PLUGIN = replace(module.PLUGIN, config=Exploding)
    assert refused({"sample_plugin": {}}) == "PLUGIN_FAILED"
    [event] = events(captured, "plugins.refused")
    assert event["code"] == "PLUGIN_FAILED" and event["plugin"] == "sample_plugin"
    assert "secret" not in captured.getvalue()


def test_a_command_refusal_carries_only_its_message():
    error = CommandError("Sample refused: NO.")
    assert error.message == "Sample refused: NO." and str(error) == "Sample refused: NO."


def test_a_database_refusal_says_which_of_two_things_is_wrong():
    """The database check compared the dormant grants with this process's claims (#496), so
    whether it honours any tells the causes apart: with none, the database holds grants for a
    plugin it has not loaded; with some, the grants are missing or different. Any other
    refusal says only that the check failed, whatever it carried."""
    refused = DormantGrantsRefused("Unsafe dormant grants")
    other = UnsafeDatabaseRole("Database revision mismatch")
    assert database_refusal(refused) == PLUGIN_GRANTS_REFUSAL
    assert database_refusal(other) == RUNTIME_CHECK_REFUSAL
    honour_claims({"product_counts": frozenset({"SELECT"})})
    assert database_refusal(refused) == PLUGIN_GRANTS_MISMATCH
    assert database_refusal(other) == RUNTIME_CHECK_REFUSAL
    for sentence in (PLUGIN_GRANTS_REFUSAL, PLUGIN_GRANTS_MISMATCH, RUNTIME_CHECK_REFUSAL):
        assert sentence.startswith("Database refused: ") and sentence.count("\n") == 1
        assert sentence.endswith(".\n")
    assert "EXECBOUND_PLUGINS" in PLUGIN_GRANTS_REFUSAL
    assert "upgrade command" in PLUGIN_GRANTS_MISMATCH


def _claiming(*entries):
    def register(registry):
        for name, privileges in entries:
            registry.claim(name, privileges)

    return register


def _other(monkeypatch, register):
    """The sample file installed a second time, as `other_plugin`, registering ``register``."""
    other = install(monkeypatch, "other_plugin")
    other.PLUGIN = replace(other.PLUGIN, name="other_plugin", config=None, register=register)
    return other


class _EqualToAnything(str):
    """A name that says it equals every name it meets."""

    __hash__ = str.__hash__

    def __eq__(self, other):
        return True


class _RendersAsTenants(str):
    """A name that renders as a core table wherever it is formatted."""

    def __format__(self, spec):
        return "tenants"


def test_dc2_a_plugin_claims_dormant_objects_and_the_process_honours_them(monkeypatch):
    install(
        monkeypatch,
        register=_claiming(
            ("signup_messages", {"SELECT", "UPDATE(state)"}), ("product_count", ["EXECUTE"])
        ),
    )
    claimed = {
        "signup_messages": frozenset({"SELECT", "UPDATE(state)"}),
        "product_count": frozenset({"EXECUTE"}),
    }
    loaded = load_plugins({"sample_plugin": {}})
    assert loaded.claims == claimed
    assert honoured_claims() == claimed
    assert NO_PLUGINS.claims == {}
    # The claims stay out of the hash, so what loaded hashes as it did before they existed.
    assert hash(NO_PLUGINS) == hash(NO_PLUGINS)


@pytest.mark.parametrize(
    ("name", "privileges"),
    [
        pytest.param("principals", {"SELECT"}, id="core-table"),
        pytest.param("admin_create_principal", {"EXECUTE"}, id="core-function"),
        pytest.param("account_switch", {"EXECUTE"}, id="core-switching-function"),
        pytest.param("no_such_object", {"SELECT"}, id="unknown-object"),
        pytest.param(None, {"SELECT"}, id="name-none"),
        pytest.param("product_counts", set(), id="no-privileges"),
        pytest.param("product_counts", "SELECT", id="privileges-str"),
        pytest.param("product_counts", b"SELECT", id="privileges-bytes"),
        pytest.param("product_counts", 5, id="privileges-not-iterable"),
        pytest.param("product_counts", [["SELECT"]], id="privileges-unhashable"),
        pytest.param("product_counts", {"DELETE"}, id="table-delete"),
        pytest.param("product_counts", {"TRUNCATE"}, id="table-truncate"),
        pytest.param("product_counts", {"REFERENCES"}, id="table-references"),
        pytest.param("product_counts", {"MAINTAIN"}, id="table-maintain"),
        pytest.param("product_counts", {"EXECUTE"}, id="table-execute"),
        pytest.param("product_counts", {"select"}, id="table-lowercase"),
        pytest.param("product_counts", {1}, id="privilege-not-str"),
        pytest.param("signup_messages", {"UPDATE(State)"}, id="column-uppercase"),
        pytest.param(
            "signup_messages",
            {"UPDATE(state) ON execbound.tenants TO public; --"},
            id="column-injection",
        ),
        # Never satisfiable: a whole-table privilege never reads as its columns.
        pytest.param("onboarding_invitations", {"SELECT", "SELECT(note)"}, id="whole-and-column"),
        pytest.param("signup_messages", {"UPDATE", "UPDATE(state)"}, id="whole-and-column-update"),
        pytest.param("product_count", {"SELECT"}, id="function-select"),
        pytest.param("product_count", {"EXECUTE", "SELECT"}, id="function-execute-and-select"),
        # Exact types: these names reach the owner's grant statements (#496).
        pytest.param(_EqualToAnything("principals"), {"SELECT"}, id="name-equal-to-anything"),
        pytest.param(
            _RendersAsTenants("product_counts"), {"SELECT"}, id="name-rendering-as-another"
        ),
        pytest.param(
            "product_counts", {_EqualToAnything("SELECT")}, id="privilege-equal-to-anything"
        ),
        pytest.param(
            "product_counts", {_RendersAsTenants("SELECT")}, id="privilege-rendering-as-another"
        ),
        pytest.param(
            "product_count", {_EqualToAnything("EXECUTE")}, id="function-privilege-subclass"
        ),
    ],
)
def test_dc2_a_claim_outside_the_catalog_or_its_grammar_is_refused(name, privileges):
    with pytest.raises(PluginError) as caught:
        Registry("sample_plugin").claim(name, privileges)
    assert caught.value.code == "INVALID_CLAIM"


@pytest.mark.parametrize(
    ("name", "privileges"),
    [
        pytest.param("execbound.tenants", {"SELECT"}, id="name"),
        pytest.param(
            "signup_messages", {"UPDATE(state) ON execbound.tenants TO public; --"}, id="privilege"
        ),
    ],
)
def test_dc2_a_refused_claim_is_logged_by_code_and_plugin_and_never_echoed(
    captured, name, privileges
):
    with pytest.raises(PluginError):
        Registry("sample_plugin").claim(name, privileges)
    [record] = events(captured, "plugins.refused")
    assert record["code"] == "INVALID_CLAIM" and record["plugin"] == "sample_plugin"
    assert "execbound.tenants" not in captured.getvalue()


def test_dc2_a_plugin_claims_an_object_once():
    registry = Registry("sample_plugin")
    registry.claim("product_counts", {"SELECT"})
    with pytest.raises(PluginError) as caught:
        registry.claim("product_counts", {"SELECT"})
    assert caught.value.code == "INVALID_CLAIM"


def test_dc2_two_plugins_claiming_one_object_conflict_and_nothing_is_honoured(monkeypatch):
    install(monkeypatch, "sample_plugin", register=_claiming(("product_counts", {"SELECT"})))
    _other(monkeypatch, _claiming(("product_counts", {"SELECT"})))
    assert refused({"sample_plugin": {}, "other_plugin": None}) == "PLUGIN_CONFLICT"
    assert honoured_claims() == {}


def test_dc2_a_claim_conflict_is_found_after_every_plugin_resolves(monkeypatch):
    """Like every other conflict: a plugin that is not there refuses first."""
    install(monkeypatch, "sample_plugin", register=_claiming(("product_counts", {"SELECT"})))
    _other(monkeypatch, _claiming(("product_counts", {"SELECT"})))
    sections = {"other_plugin": None, "sample_plugin": {}, "unknown_plugin": None}
    assert refused(sections) == "UNKNOWN_PLUGIN"
    assert honoured_claims() == {}


def test_dc2_a_later_load_adds_to_what_is_honoured_and_never_changes_it(monkeypatch):
    install(monkeypatch, register=_claiming(("product_counts", {"SELECT"})))
    load_plugins({"sample_plugin": {}})
    load_plugins({"sample_plugin": {}})
    assert honoured_claims() == {"product_counts": frozenset({"SELECT"})}
    _other(monkeypatch, _claiming(("product_count", {"EXECUTE"})))
    assert load_plugins({"other_plugin": None}).claims == {"product_count": frozenset({"EXECUTE"})}
    both = {"product_counts": frozenset({"SELECT"}), "product_count": frozenset({"EXECUTE"})}
    assert honoured_claims() == both
    # A later load that leaves one out takes nothing away.
    assert load_plugins({"sample_plugin": {}}).claims == {"product_counts": frozenset({"SELECT"})}
    assert honoured_claims() == both
    install(monkeypatch, register=_claiming(("product_counts", {"SELECT", "INSERT"})))
    assert refused({"sample_plugin": {}}) == "PLUGIN_CONFLICT"
    assert honoured_claims() == both


def _claims_then_duplicates_a_path(registry):
    registry.claim("product_counts", {"SELECT"})
    registry.console_path("/sample-plugin")
    registry.console_path("/sample-plugin")


def _claims_then_raises(registry):
    registry.claim("product_counts", {"SELECT"})
    raise RuntimeError("after the claim")


def _claims(registry):
    registry.claim("product_counts", {"SELECT"})


@pytest.mark.parametrize(
    ("register", "sections", "code"),
    [
        pytest.param(
            _claims_then_duplicates_a_path,
            {"sample_plugin": {}},
            "PLUGIN_CONFLICT",
            id="duplicate-console-path",
        ),
        pytest.param(
            _claims,
            {"sample_plugin": {}, "unknown_plugin": None},
            "UNKNOWN_PLUGIN",
            id="unknown-second-plugin",
        ),
        pytest.param(
            _claims_then_raises, {"sample_plugin": {}}, "PLUGIN_FAILED", id="register-raises"
        ),
    ],
)
def test_dc2_a_refused_load_honours_nothing(monkeypatch, register, sections, code):
    install(monkeypatch, register=register)
    assert refused(sections) == code
    assert honoured_claims() == {}


def test_dc2_honouring_an_invalid_or_conflicting_claim_changes_nothing():
    honour_claims({"product_counts": frozenset({"SELECT"})})
    before = {"product_counts": frozenset({"SELECT"})}
    for claims in (
        {"principals": frozenset({"SELECT"})},
        {"product_counts": {"SELECT"}},
        {_EqualToAnything("product_count"): frozenset({"EXECUTE"})},
        # A valid new claim beside an invalid one: neither is recorded.
        {"product_count": frozenset({"EXECUTE"}), "tenants": frozenset({"SELECT"})},
    ):
        with pytest.raises(ValueError) as caught:
            honour_claims(claims)
        assert type(caught.value) is ValueError
        assert honoured_claims() == before
    with pytest.raises(ClaimConflict):
        honour_claims(
            {"product_count": frozenset({"EXECUTE"}), "product_counts": frozenset({"INSERT"})}
        )
    assert honoured_claims() == before


LINKS = ServiceLinks(support_email="support@example.com", help_url="https://example.com/help")


def test_the_sample_registers_its_service_links_and_nothing_loaded_registers_none(sample):
    assert load_plugins({"sample_plugin": {}}).service_links == sample.SERVICE_LINKS
    assert NO_PLUGINS.service_links is None


def test_a_plugin_sets_its_service_links_once(captured):
    registry = Registry("sample_plugin")
    registry.service_links(LINKS)
    with pytest.raises(PluginError) as caught:
        registry.service_links(LINKS)
    assert caught.value.code == "INVALID_SERVICE_LINKS"
    [event] = events(captured, "plugins.refused")
    assert event["code"] == "INVALID_SERVICE_LINKS" and event["plugin"] == "sample_plugin"


class _Links(ServiceLinks):
    """Service links that are a `ServiceLinks` and are not one."""


def _changed_after_it_was_built() -> ServiceLinks:
    links = ServiceLinks(help_url="https://example.com/help")
    object.__setattr__(links, "help_url", "javascript:alert(1)")
    return links


@pytest.mark.parametrize(
    "links",
    [
        None,
        {"help_url": "https://example.com/help"},
        ("support@example.com", "https://example.com/help"),
        _Links(help_url="https://example.com/help"),
        _changed_after_it_was_built(),
    ],
)
def test_service_links_are_exactly_a_service_links_whose_values_hold(links):
    """A link's destination is rendered as it is, so the registry checks every value again
    rather than trusting that an object which looks right was built through the check."""
    with pytest.raises(PluginError) as caught:
        Registry("sample_plugin").service_links(links)
    assert caught.value.code == "INVALID_SERVICE_LINKS"


def _service_links_only(registry):
    registry.service_links(LINKS)


def test_a_second_plugin_registering_service_links_conflicts(monkeypatch):
    install(monkeypatch, "sample_plugin")
    other = install(monkeypatch, "other_plugin")
    other.PLUGIN = replace(
        other.PLUGIN, name="other_plugin", config=None, register=_service_links_only
    )
    assert refused({"sample_plugin": {}, "other_plugin": None}) == "PLUGIN_CONFLICT"


def test_the_service_links_come_from_the_configuration_or_a_plugin_never_both(sample, captured):
    loaded = load_plugins({"sample_plugin": {}})
    assert NO_PLUGINS.service(None) == ServiceLinks(source_url=SOURCE_URL)
    assert NO_PLUGINS.service(LINKS) == LINKS
    assert loaded.service(None) == sample.SERVICE_LINKS
    with pytest.raises(PluginError) as caught:
        loaded.service(LINKS)
    assert caught.value.code == "PLUGIN_CONFLICT"
    [event] = events(captured, "plugins.refused")
    assert event["code"] == "PLUGIN_CONFLICT" and "plugin" not in event


SAMPLE_ROUTE = ("/api/console/v1/sample-plugin", "GET")


def test_a_plugin_classifies_its_own_console_route_for_tokens(sample):
    """Core's table no longer names the sample's route; the sample classifies it, and a token
    may call it only where the sample is loaded."""
    loaded = load_plugins({"sample_plugin": {}})
    assert loaded.allowed_token_routes == {SAMPLE_ROUTE}
    assert loaded.refused_token_routes == frozenset()
    assert token_allowed(*SAMPLE_ROUTE) is False
    assert token_allowed(*SAMPLE_ROUTE, loaded) is True
    assert token_allowed(*SAMPLE_ROUTE, NO_PLUGINS) is False
    assert NO_PLUGINS.allowed_token_routes == NO_PLUGINS.refused_token_routes == frozenset()


def test_a_route_a_plugin_refuses_or_leaves_out_is_refused_to_a_token():
    loaded = replace(
        NO_PLUGINS,
        allowed_token_routes=frozenset({SAMPLE_ROUTE, ("/api/console/v1/session", "GET")}),
        refused_token_routes=frozenset(
            {("/api/console/v1/sample-plugin", "POST"), ("/api/console/v1/agents", "GET")}
        ),
    )
    assert token_allowed("/api/console/v1/sample-plugin", "POST", loaded) is False
    assert token_allowed("/api/console/v1/sample-plugin/other", "GET", loaded) is False
    # Core's own table still answers first, whatever a plugin holds.
    assert token_allowed("/api/console/v1/agents", "GET", loaded) is True
    assert token_allowed("/api/console/v1/session", "GET", loaded) is False


@pytest.mark.parametrize(
    "route",
    [
        # A pair core refuses.
        ("/api/console/v1/settings/tokens", "GET"),
        ("/api/console/v1/session", "GET"),
        # A core path under a method core does not list.
        ("/api/console/v1/settings/tokens", "DELETE"),
        ("/api/console/v1/session", "HEAD"),
        ("/api/console/v1/agents", "DELETE"),
        # Core's `/agents/{row_id}` under another parameter name: the same URL, so the same
        # path to the guard.
        ("/api/console/v1/agents/{agent_id}", "DELETE"),
        ("/api/console/v1/agents/{agent_id}", "GET"),
    ],
)
def test_a_plugin_cannot_allow_any_method_of_a_core_path(route):
    """Registration refuses these, but the guard does not rely on it: core's refusal is
    decided before a plugin's set is read, for any method of a path core classifies."""
    loaded = replace(NO_PLUGINS, allowed_token_routes=frozenset({route}))
    assert token_allowed(*route, loaded) is False


def test_a_plugin_classifies_its_token_routes_once(captured):
    registry = Registry("sample_plugin")
    registry.token_routes(allowed=[SAMPLE_ROUTE])
    with pytest.raises(PluginError) as caught:
        registry.token_routes(refused=[("/api/console/v1/sample-plugin/other", "POST")])
    assert caught.value.code == "INVALID_TOKEN_ROUTES"
    [event] = events(captured, "plugins.refused")
    assert event["code"] == "INVALID_TOKEN_ROUTES" and event["plugin"] == "sample_plugin"


class _Path(str):
    """A path that is a string and is not one."""


@pytest.mark.parametrize(
    ("allowed", "denied"),
    [
        # A route core classifies, either way: a plugin can never loosen, or restate, core's.
        ([("/api/console/v1/session", "GET")], []),
        ([("/api/console/v1/agents", "GET")], []),
        ([], [("/api/console/v1/agents", "GET")]),
        ([], [("/api/console/v1/settings/tokens", "GET")]),
        # A path core classifies, under a method core does not list.
        ([("/api/console/v1/session", "HEAD")], []),
        ([("/api/console/v1/settings/tokens", "DELETE")], []),
        # A core path's shape under other parameter names: the same URLs as core's route.
        ([("/api/console/v1/agents/{agent_id}", "DELETE")], []),
        ([], [("/api/console/v1/policy/{policy_id}/rules", "PUT")]),
        # One route in both sets, spelt alike or with another parameter name.
        ([SAMPLE_ROUTE], [SAMPLE_ROUTE]),
        (
            [("/api/console/v1/sample-plugin/{item_id}", "GET")],
            [("/api/console/v1/sample-plugin/{other_id}", "GET")],
        ),
        # Not a console API route.
        ([("/v1/executions", "POST")], []),
        ([("/sample-plugin", "GET")], []),
        ([("/api/console/v1", "GET")], []),
        ([("/api/console/v1/", "GET")], []),
        ([("/api/console/v1/../session", "GET")], []),
        ([("/api/console/v1/sample-plugin/", "GET")], []),
        ([("/api/console/v1/Sample-Plugin", "GET")], []),
        ([("/api/console/v1/sample-plugin/{rest:path}", "GET")], []),
        ([("/api/console/v1/sample-plugin?x=1", "GET")], []),
        # Not an HTTP method in upper case.
        ([("/api/console/v1/sample-plugin", "get")], []),
        ([("/api/console/v1/sample-plugin", "FETCH")], []),
        # Not a pair of exact strings.
        ([("/api/console/v1/sample-plugin", "GET", "x")], []),
        ([["/api/console/v1/sample-plugin", "GET"]], []),
        (["/api/console/v1/sample-plugin"], []),
        ("/api/console/v1/sample-plugin", []),
        ([(_Path("/api/console/v1/sample-plugin"), "GET")], []),
        ([("/api/console/v1/sample-plugin", 3)], []),
        (None, []),
    ],
)
def test_token_routes_are_the_plugins_own_console_routes_and_methods(allowed, denied):
    with pytest.raises(PluginError) as caught:
        Registry("sample_plugin").token_routes(allowed=allowed, refused=denied)
    assert caught.value.code == "INVALID_TOKEN_ROUTES"


def _classifies_the_sample_route(registry):
    registry.token_routes(refused=[SAMPLE_ROUTE])


def test_two_plugins_classifying_one_route_conflict(monkeypatch):
    install(monkeypatch, "sample_plugin")
    other = install(monkeypatch, "other_plugin")
    other.PLUGIN = replace(
        other.PLUGIN, name="other_plugin", config=None, register=_classifies_the_sample_route
    )
    assert refused({"sample_plugin": {}, "other_plugin": None}) == "PLUGIN_CONFLICT"


# --- The recovery link (#678): held to the sign-in link's rules (RP12) -----------------------

_BAD_LINKS = [
    ("/reset", _label),
    None,
    "/reset",
    SignInLink("/reset", "Forgot"),
    SignInLink("/reset", None),
    SignInLink(3, _label),
    SignInLink("reset", _label),
    SignInLink("/reset?next=/", _label),
    SignInLink("https://gateway.example/reset", _label),
    SignInLink("/reset/{id}", _label),
    SignInLink("/api/x", _label),
    SignInLink("/console", _label),
    SignInLink("/assets/x", _label),
    SignInLink(_Link("/reset"), _label),
]


@pytest.mark.parametrize("link", _BAD_LINKS)
def test_rp12_the_recovery_link_is_held_to_the_sign_in_link_rules(link, captured):
    with pytest.raises(PluginError) as caught:
        Registry("sample_plugin").recovery_link(link)
    assert caught.value.code == "INVALID_RECOVERY_LINK"
    [event] = events(captured, "plugins.refused")
    assert event["code"] == "INVALID_RECOVERY_LINK" and event["plugin"] == "sample_plugin"


def test_rp12_a_plugin_sets_its_recovery_link_once(captured):
    registry = Registry("sample_plugin")
    registry.recovery_link(SignInLink("/reset-password", _label))
    with pytest.raises(PluginError) as caught:
        registry.recovery_link(SignInLink("/reset-password", _label))
    assert caught.value.code == "INVALID_RECOVERY_LINK"


def _recovery_only(registry):
    registry.recovery_link(SignInLink("/reset-password", _label))


def test_rp12_a_second_plugin_registering_a_recovery_link_conflicts(monkeypatch):
    install(monkeypatch, register=_recovery_only)
    other = install(monkeypatch, "other_plugin")
    other.PLUGIN = replace(other.PLUGIN, name="other_plugin", config=None, register=_recovery_only)
    assert refused({"sample_plugin": {}, "other_plugin": None}) == "PLUGIN_CONFLICT"


def _recovery_shown(label, monkeypatch):
    def register(registry):
        registry.recovery_link(SignInLink("/reset-password", label))

    install(monkeypatch, register=register)
    return load_plugins({"sample_plugin": {}}).shown_recovery_link(object())


def test_rp12_a_recovery_link_loads_and_shows_its_label(monkeypatch):
    assert _recovery_shown(lambda runtime: "Forgot your password?", monkeypatch) == ShownLink(
        "/reset-password", "Forgot your password?"
    )
    assert NO_PLUGINS.recovery_link is None
    assert NO_PLUGINS.shown_recovery_link(object()) is None


def test_rp12_a_recovery_label_that_raises_hides_the_link_and_is_logged(monkeypatch, captured):
    def label(runtime):
        raise RuntimeError("secret-from-label")

    assert _recovery_shown(label, monkeypatch) is None
    [event] = events(captured, "plugins.recovery_link_failed")
    assert event["code"] == "PLUGIN_FAILED" and event["plugin"] == "sample_plugin"
    assert "secret" not in captured.getvalue()
    assert events(captured, "plugins.sign_in_link_failed") == []


@pytest.mark.parametrize("label", ["x" * 61, "Forgot\nyour password", 3])
def test_rp12_a_recovery_label_that_is_not_a_short_line_hides_the_link(
    monkeypatch, captured, label
):
    assert _recovery_shown(lambda runtime: label, monkeypatch) is None
    [event] = events(captured, "plugins.recovery_link_failed")
    assert event["code"] == "INVALID_RECOVERY_LINK"


def test_rp12_a_recovery_label_of_none_hides_the_link_quietly(monkeypatch, captured):
    assert _recovery_shown(lambda runtime: None, monkeypatch) is None
    assert events(captured, "plugins.recovery_link_failed") == []
