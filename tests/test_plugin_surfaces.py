# SPDX-License-Identifier: AGPL-3.0-only
"""A loaded plugin in a running gateway: configuration, pages, console, commands, readiness.

Every test here names the sample plugin explicitly, or deliberately does not, because the
contract is that naming it is the only way it does anything.
"""

import copy
import json
import os
import re
import secrets
import sys
from dataclasses import replace
from datetime import timedelta
from uuid import uuid4

import pytest
from console_api_fixtures import rejections
from fastapi import APIRouter
from fastapi.testclient import TestClient
from plugin_fixtures import captured as captured
from plugin_fixtures import events, install
from plugin_fixtures import sample as sample
from starlette.requests import Request
from starlette.responses import Response
from starlette.routing import Route
from test_console_serving import fake_build as fake_build
from test_console_serving import served, sign_in
from test_human_surface import form_values, pending
from test_notification_transports import message as build_message
from test_runtime import connector as connector
from test_runtime import live_provider as live_provider
from test_runtime import registry as registry
from test_runtime import runtime as runtime
from test_runtime import world as world
from test_sign_in_surface import StandIn

from execbound.app import create_app
from execbound.cli import main
from execbound.db import DormantGrantsRefused, UnsafeDatabaseRole
from execbound.directory import DirectoryConfig
from execbound.envelope import KEY_BYTES, KeyRing
from execbound.personal_tokens import issue_token
from execbound.plugins import (
    NO_PLUGINS,
    PLUGIN_API_VERSION,
    PLUGIN_GRANTS_REFUSAL,
    RUNTIME_CHECK_REFUSAL,
    Command,
    PluginError,
    SignInLink,
    load_plugins,
)
from execbound.runtime import Runtime
from execbound.surfaces.configuration import load_runtime, read_configuration, reload_keys
from execbound.surfaces.console import CONSOLE_POLICY, PAGE_POLICY
from execbound.surfaces.human import HumanConfig
from execbound.surfaces.sessions import issue_session, load_session
from execbound.surfaces.tokens import TokenKeys

pytestmark = pytest.mark.integration


def configuration() -> dict:
    """The smallest private configuration a gateway loads: one Gate account, no connector."""
    return {
        "origin": "http://127.0.0.1:8000",
        "active_key_id": "continuation-v1",
        "continuation_keys": {"continuation-v1": secrets.token_bytes(32).hex()},
        "checkpoint_providers": [
            {
                "tenant_id": str(uuid4()),
                "account_id": str(uuid4()),
                "evidence_keys": {"journal-v1": secrets.token_bytes(32).hex()},
            }
        ],
    }


def written(tmp_path, value: dict):
    path = tmp_path / "private.json"
    path.write_text(json.dumps(value), encoding="utf-8")
    return path


def test_the_private_configuration_names_the_plugins_a_gateway_loads(db, sample, tmp_path):
    value = configuration() | {"plugins": {"sample_plugin": {"greeting": "hi"}}}
    runtime, _ = load_runtime(written(tmp_path, value), db)
    assert runtime.plugins.names == ("sample_plugin",)
    assert runtime.plugins.config("sample_plugin") == sample.SampleConfig(greeting="hi")


def test_a_configuration_without_plugins_loads_none(db, sample, tmp_path):
    runtime, _ = load_runtime(written(tmp_path, configuration()), db)
    assert runtime.plugins is NO_PLUGINS


def test_a_plugin_the_gateway_cannot_load_refuses_the_whole_file(db, tmp_path, captured):
    value = configuration() | {"plugins": {"no_such_plugin": {}}}
    with pytest.raises(ValueError, match="Invalid runtime configuration"):
        load_runtime(written(tmp_path, value), db)
    [record] = events(captured, "plugins.refused")
    assert record["code"] == "UNKNOWN_PLUGIN"


def test_a_reload_that_changes_a_plugin_section_is_refused(db, sample, tmp_path):
    value = configuration() | {"plugins": {"sample_plugin": {"greeting": "hi"}}}
    path = written(tmp_path, value)
    runtime, human = load_runtime(path, db)
    baseline = read_configuration(path)
    assert reload_keys(path, runtime, human, baseline).state == "current"
    changed = copy.deepcopy(value)
    changed["plugins"]["sample_plugin"]["greeting"] = "changed"
    written(tmp_path, changed)
    outcome = reload_keys(path, runtime, human, baseline)
    assert (outcome.state, outcome.code) == ("refused", "CONFIGURATION_CHANGED")


def test_a_runtime_takes_only_loaded_plugins(db):
    with pytest.raises(ValueError, match="Invalid plugins"):
        Runtime(db, [], plugins=("sample_plugin",))


API = "/api/console/v1"


@pytest.fixture
def plugin_runtime(db, world, connector, sample):
    keys = TokenKeys("pending-v1", {"pending-v1": secrets.token_bytes(32)})
    loaded = load_plugins({"sample_plugin": {"greeting": "hi"}})
    return Runtime(db, [connector], clock=world["clock"], keys=keys, plugins=loaded)


def gateway(db, runtime):
    return TestClient(
        create_app(db, runtime=runtime, human=served()),
        base_url="http://127.0.0.1",
        follow_redirects=False,
    )


def test_a_named_plugin_adds_its_page_its_area_and_its_console_page(
    db, plugin_runtime, fake_build, admin_engine, world
):
    with gateway(db, plugin_runtime) as client:
        hello = client.get("/sample-plugin/hello")
        assert hello.json() == {"greeting": "hi"}
        assert hello.headers["Content-Security-Policy"] == PAGE_POLICY
        assert client.get(API + "/sample-plugin").status_code == 401
        assert client.get("/sample-plugin").status_code == 303
        sign_in(client, admin_engine, world)
        assert client.get(API + "/sample-plugin").json() == {"greeting": "hi"}
        page = client.get("/sample-plugin")
        assert page.status_code == 200
        assert page.headers["Content-Security-Policy"] == CONSOLE_POLICY


@pytest.mark.parametrize(("greeting", "reported"), [("pool", True), ("hi", False)])
def test_the_session_reports_a_plugins_invitations_feature_as_its_check_answers(
    db, world, connector, sample, admin_engine, greeting, reported
):
    """Core reads a plugin's `invitations` session feature back into `GET /session`, true
    exactly when the plugin's own check holds for the session: the sample's holds when its
    section's greeting is "pool"."""
    keys = TokenKeys("pending-v1", {"pending-v1": secrets.token_bytes(32)})
    loaded = load_plugins({"sample_plugin": {"greeting": greeting}})
    runtime = Runtime(db, [connector], clock=world["clock"], keys=keys, plugins=loaded)
    with gateway(db, runtime) as client:
        sign_in(client, admin_engine, world)
        session = client.get(API + "/session")
    assert session.status_code == 200, session.text
    assert session.json()["invitations"] is reported
    # Every feature a plugin reports is listed by name, `invitations` among them (#496).
    assert session.json()["features"] == (["invitations"] if reported else [])


def test_a_session_feature_check_that_raises_withholds_the_feature_and_the_session_answers(
    db, world, connector, sample, admin_engine, captured
):
    """A plugin's check that fails is read as not holding (#496), so the console's
    session still answers, with the feature in neither `invitations` nor `features`."""

    def failing(runtime, session):
        raise RuntimeError("the plugin's database is unavailable")

    keys = TokenKeys("pending-v1", {"pending-v1": secrets.token_bytes(32)})
    loaded = replace(
        load_plugins({"sample_plugin": {"greeting": "pool"}}),
        session_features=(("invitations", failing),),
    )
    runtime = Runtime(db, [connector], clock=world["clock"], keys=keys, plugins=loaded)
    with gateway(db, runtime) as client:
        sign_in(client, admin_engine, world)
        session = client.get(API + "/session")
    assert session.status_code == 200, session.text
    assert session.json()["invitations"] is False and session.json()["features"] == []
    failures = events(captured, "plugins.feature_failed")
    assert failures and {record["feature"] for record in failures} == {"invitations"}


def test_an_installed_plugin_nobody_named_adds_nothing(db, runtime, sample, fake_build):
    with gateway(db, runtime) as client:
        assert client.get("/sample-plugin/hello").status_code == 404
        assert client.get(API + "/sample-plugin").status_code == 404
        assert client.get("/sample-plugin").status_code == 404
        login = client.get("/login")
    assert login.status_code == 200
    assert "/sample-plugin" not in login.text and "Say " not in login.text
    # Without a plugin's link or a deployment's help page, the sign-in form links nowhere.
    assert sign_in_links(login.text) == []


SAMPLE_LINK = '<p><a href="/sample-plugin/hello">Say hi</a></p>'
DIRECTORY_RING = KeyRing("dir-v1", {"dir-v1": b"\x22" * KEY_BYTES})


def sign_in_links(page: str) -> list[str]:
    """Where the sign-in section's links go, leaving out the page frame's own."""
    [section] = re.findall(r'<section class="login">(.*?)</section>', page, re.S)
    return re.findall(r'<a href="([^"]+)"', section)


def test_a_plugins_sign_in_link_is_on_the_sign_in_page(db, plugin_runtime):
    with gateway(db, plugin_runtime) as client:
        page = client.get("/login")
    assert page.status_code == 200
    assert page.text.count(SAMPLE_LINK) == 1
    assert sign_in_links(page.text) == ["/sample-plugin/hello"]
    # A plain link, so the page's buttons and fields are what they were.
    assert len(re.findall(r"<button\b", page.text)) == 1


def test_a_wrong_password_shows_the_plugins_sign_in_link_again(db, plugin_runtime):
    with gateway(db, plugin_runtime) as client:
        _, values = form_values(client.get("/login").text, "/session/password")
        values.update(email="nobody@example.com", password="not the password at all")
        answer = client.post(
            "/session/password", data=values, headers={"Origin": "http://127.0.0.1"}
        )
    assert answer.status_code == 401
    assert "Those sign-in details are not right." in answer.text
    assert answer.text.count(SAMPLE_LINK) == 1


def test_a_refused_directory_sign_in_shows_the_plugins_sign_in_link_again(db, plugin_runtime):
    human = HumanConfig(
        "http://127.0.0.1",
        TokenKeys("state-v1", {"state-v1": secrets.token_bytes(32)}),
        directory=DirectoryConfig(DIRECTORY_RING, "http://127.0.0.1"),
    )
    app = create_app(db, runtime=plugin_runtime, human=human)
    with TestClient(app, base_url="http://127.0.0.1", follow_redirects=False) as client:
        answer = client.get("/login/directory/callback", params={"error": "access_denied"})
    assert answer.status_code == 403
    assert "That account cannot sign in here." in answer.text
    assert answer.text.count(SAMPLE_LINK) == 1


def test_a_refused_provider_sign_in_shows_the_plugins_sign_in_link_again(db, plugin_runtime):
    human = HumanConfig(
        "http://127.0.0.1",
        TokenKeys("state-v1", {"state-v1": secrets.token_bytes(32)}),
        providers=(StandIn(name="google", label="Google"),),
    )
    app = create_app(db, runtime=plugin_runtime, human=human)
    with TestClient(app, base_url="http://127.0.0.1", follow_redirects=False) as client:
        answer = client.get("/login/google/callback", params={"error": "access_denied"})
    assert answer.status_code == 403
    assert "That account cannot sign in here." in answer.text
    assert answer.text.count(SAMPLE_LINK) == 1


def test_a_sign_in_label_is_text_and_never_markup(db, world, connector, sample):
    loaded = load_plugins({"sample_plugin": {"greeting": '<b onclick="x()">hi</b>'}})
    runtime = Runtime(db, [connector], clock=world["clock"], plugins=loaded)
    with gateway(db, runtime) as client:
        page = client.get("/login")
    assert page.status_code == 200
    assert "<b onclick" not in page.text
    assert (
        '<a href="/sample-plugin/hello">Say &lt;b onclick=&#34;x()&#34;&gt;hi&lt;/b&gt;</a>'
        in page.text
    )


def _classified_area(routes, runtime, config, guards):
    """Three reads: one the plugin allows a token, one it refuses, one it leaves out."""

    @routes.get("/sample-plugin")
    async def allowed(request: Request) -> dict[str, str]:
        await guards.session(request)
        return {"route": "allowed"}

    @routes.get("/sample-plugin/refused")
    async def refused(request: Request) -> dict[str, str]:
        await guards.session(request)
        return {"route": "refused"}

    @routes.get("/sample-plugin/unclassified")
    async def unclassified(request: Request) -> dict[str, str]:
        await guards.session(request)
        return {"route": "unclassified"}


def _classifies_its_routes(registry):
    registry.console_area(_classified_area)
    registry.token_routes(
        allowed=[(API + "/sample-plugin", "GET")], refused=[(API + "/sample-plugin/refused", "GET")]
    )


def test_a_token_calls_the_route_a_plugin_allows_and_no_other(
    db, monkeypatch, world, connector, admin_engine
):
    """The guard reads a plugin's classification after core's (#496): a token passes on the
    route the plugin allows, and the route it refuses and the one it leaves out both answer
    `TOKEN_NOT_ALLOWED`, audited, exactly as a core route in neither of core's sets would."""
    install(monkeypatch, register=_classifies_its_routes)
    keys = TokenKeys("pending-v1", {"pending-v1": secrets.token_bytes(32)})
    loaded = load_plugins({"sample_plugin": {}})
    runtime = Runtime(db, [connector], clock=world["clock"], keys=keys, plugins=loaded)
    grant = issue_session(db, world["admin"], clock=runtime.clock)
    session = load_session(db, grant.token, clock=runtime.clock)
    token, _ = issue_token(db, session, "plugin", timedelta(days=1), clock=runtime.clock)
    headers = {"Authorization": f"Bearer {token}"}
    before = rejections(admin_engine, world["admin"])
    with gateway(db, runtime) as client:
        allowed = client.get(API + "/sample-plugin", headers=headers)
        refused = client.get(API + "/sample-plugin/refused", headers=headers)
        unclassified = client.get(API + "/sample-plugin/unclassified", headers=headers)
    assert allowed.status_code == 200, allowed.text
    assert allowed.json() == {"route": "allowed"}
    for answer in (refused, unclassified):
        assert answer.status_code == 403, answer.text
        assert answer.json()["code"] == "TOKEN_NOT_ALLOWED"
    assert rejections(admin_engine, world["admin"]) == before + 2


def test_a_sign_in_label_that_fails_leaves_sign_in_working(db, monkeypatch, connector, captured):
    def label(runtime):
        raise RuntimeError("secret-from-label")

    install(
        monkeypatch,
        register=lambda registry: registry.sign_in_link(SignInLink("/sample-plugin", label)),
    )
    loaded = Runtime(db, [connector], plugins=load_plugins({"sample_plugin": {}}))
    with gateway(db, loaded) as client:
        page = client.get("/login")
    assert page.status_code == 200
    assert 'action="/session/password"' in page.text
    assert sign_in_links(page.text) == []
    [event] = events(captured, "plugins.sign_in_link_failed")
    assert event["code"] == "PLUGIN_FAILED" and event["plugin"] == "sample_plugin"
    assert "secret" not in captured.getvalue()


@pytest.fixture
def gateway_without_plugin(db, runtime, world, admin_engine, fake_build):
    with gateway(db, runtime) as client:
        sign_in(client, admin_engine, world)
        view = pending(runtime, world)
        yield client, world["identity"].tenant_id, view.approval_id


@pytest.fixture
def gateway_with_sample(db, plugin_runtime, world, admin_engine, fake_build):
    with gateway(db, plugin_runtime) as client:
        sign_in(client, admin_engine, world)
        view = pending(plugin_runtime, world)
        yield client, world["identity"].tenant_id, view.approval_id


def test_without_approval_links_a_tenant_scoped_approval_address_is_not_found(
    gateway_without_plugin,
):
    client, tenant, approval = gateway_without_plugin
    other = uuid4()
    assert client.get(f"/workspaces/{other}/approvals/{approval}").status_code == 404
    assert client.get(f"/workspaces/{other}/approvals/{approval}/classic").status_code == 404


def test_approval_links_review_a_tenant_scoped_address_before_the_page(gateway_with_sample):
    client, tenant, approval = gateway_with_sample
    other = uuid4()
    console = client.get(f"/workspaces/{other}/approvals/{approval}")
    assert console.status_code == 409 and console.text == "sample review console"
    classic = client.get(f"/workspaces/{other}/approvals/{approval}/classic")
    assert classic.status_code == 409 and classic.text == "sample review classic"
    assert client.get(f"/workspaces/{tenant}/approvals/{approval}").status_code == 200


MESSAGE = build_message(approval_url="https://gateway.example/approvals")


def test_a_notification_links_through_the_plugin_path_or_to_the_plain_address():
    tenant, approval = uuid4(), uuid4()
    plain = replace(MESSAGE, tenant_id=tenant, approval_id=approval, path=None)
    assert plain.link == f"https://gateway.example/approvals/{approval}"
    scoped = replace(plain, path=f"/workspaces/{tenant}/approvals/{approval}")
    assert scoped.link == f"https://gateway.example/workspaces/{tenant}/approvals/{approval}"
    assert scoped.classic_link == scoped.link + "/classic"


def page_at(path):
    def factory(runtime, config):
        routes = APIRouter()

        @routes.get(path)
        def page() -> dict[str, str]:
            return {}

        return routes

    return factory


@pytest.mark.parametrize("path", ["/v1/sample", "/health/sample", "/api/sample", "/mcp/sample"])
def test_a_plugin_page_on_a_reserved_path_refuses_start(db, monkeypatch, connector, path):
    install(monkeypatch, register=lambda registry: registry.human_router(page_at(path)))
    loaded = Runtime(db, [connector], plugins=load_plugins({"sample_plugin": {}}))
    with pytest.raises(PluginError) as refused:
        create_app(db, runtime=loaded, human=served())
    assert refused.value.code == "INVALID_ROUTE"


@pytest.mark.parametrize(
    "path", ["/login", "/people/{person}", "/approvals", "/approvals/pending/{x}"]
)
def test_a_plugin_page_core_already_answers_refuses_start(db, monkeypatch, connector, path):
    install(monkeypatch, register=lambda registry: registry.human_router(page_at(path)))
    loaded = Runtime(db, [connector], plugins=load_plugins({"sample_plugin": {}}))
    with pytest.raises(PluginError) as refused:
        create_app(db, runtime=loaded, human=served())
    assert refused.value.code == "ROUTE_CONFLICT"


@pytest.mark.parametrize("path", ["/agents", "/policy/{bundle}", "/login"])
def test_a_plugin_console_page_core_already_answers_refuses_start(db, monkeypatch, connector, path):
    install(monkeypatch, register=lambda registry: registry.console_path(path))
    loaded = Runtime(db, [connector], plugins=load_plugins({"sample_plugin": {}}))
    with pytest.raises(PluginError) as refused:
        create_app(db, runtime=loaded, human=served())
    assert refused.value.code == "ROUTE_CONFLICT"


@pytest.mark.parametrize("path", ["/login/", "/account/security/passkey/{rest:path}"])
def test_a_malformed_plugin_page_refuses_start(db, monkeypatch, connector, path):
    """A trailing slash takes the path Starlette would redirect to core's `/login`, and a
    `:path` parameter would answer a GET under core's POST-only passkey routes."""
    install(monkeypatch, register=lambda registry: registry.human_router(page_at(path)))
    loaded = Runtime(db, [connector], plugins=load_plugins({"sample_plugin": {}}))
    with pytest.raises(PluginError) as refused:
        create_app(db, runtime=loaded, human=served())
    assert refused.value.code == "INVALID_ROUTE"


def frontend_directory(tmp_path):
    (tmp_path / "index.html").write_text("<p>plugin</p>", encoding="utf-8")
    return tmp_path


def test_a_plugin_page_router_with_a_frontend_refuses_start(db, monkeypatch, connector, tmp_path):
    """`APIRouter.frontend()` keeps its routes out of `routes`, where no check would see them,
    and they answer every path nothing else does, `/v1/unknown` and `/health/other` included."""
    directory = frontend_directory(tmp_path)

    def factory(runtime, config):
        routes = page_at("/sample-plugin/hello")(runtime, config)
        routes.frontend("/", directory=directory)
        return routes

    install(monkeypatch, register=lambda registry: registry.human_router(factory))
    loaded = Runtime(db, [connector], plugins=load_plugins({"sample_plugin": {}}))
    with pytest.raises(PluginError) as refused:
        create_app(db, runtime=loaded, human=served())
    assert refused.value.code == "INVALID_ROUTE"


def test_a_plugin_area_with_a_frontend_refuses_start(db, monkeypatch, connector, tmp_path):
    directory = frontend_directory(tmp_path)

    def area(routes, runtime, config, guards):
        routes.frontend("/", directory=directory)

    install(monkeypatch, register=lambda registry: registry.console_area(area))
    loaded = Runtime(db, [connector], plugins=load_plugins({"sample_plugin": {}}))
    with pytest.raises(PluginError) as refused:
        create_app(db, runtime=loaded, human=served())
    assert refused.value.code == "INVALID_ROUTE"


async def tool_app(scope, receive, send) -> None:  # pragma: no cover
    pass


def test_a_plugin_page_router_with_a_mount_refuses_start(db, monkeypatch, connector):
    """A `Mount` reads as one literal path segment to every check below, so `/account` would be
    admitted and then answer every path it spans, including `GET /account/security/passkey/...`
    under core's POST-only route there."""

    def factory(runtime, config):
        routes = APIRouter()
        routes.mount("/account", app=tool_app)
        return routes

    install(monkeypatch, register=lambda registry: registry.human_router(factory))
    loaded = Runtime(db, [connector], plugins=load_plugins({"sample_plugin": {}}))
    with pytest.raises(PluginError) as refused:
        create_app(db, runtime=loaded, human=served())
    assert refused.value.code == "INVALID_ROUTE"


def test_a_plugin_that_refuses_while_its_pages_are_built_refuses_start_and_is_logged(
    db, monkeypatch, connector, captured
):
    """A plugin's section may need a core block the configuration lacks, which it can only see
    once its pages are built. Its refusal there stops start like a route refusal, and is logged
    the same way: `plugins.refused` with the code alone."""

    def factory(runtime, config):
        raise PluginError("INVALID_PLUGIN_CONFIG")

    install(monkeypatch, register=lambda registry: registry.human_router(factory))
    loaded = Runtime(db, [connector], plugins=load_plugins({"sample_plugin": {}}))
    with pytest.raises(PluginError) as refused:
        create_app(db, runtime=loaded, human=served())
    assert refused.value.code == "INVALID_PLUGIN_CONFIG"
    [record] = events(captured, "plugins.refused")
    assert (record["code"], record["level"]) == ("INVALID_PLUGIN_CONFIG", "ERROR")
    assert "plugin" not in record


def test_a_plugin_area_with_a_mount_refuses_start(db, monkeypatch, connector):
    """A console API area can do the same under its own prefix, `/api/console/v1/`."""

    def area(routes, runtime, config, guards):
        routes.mount(API + "/tools", app=tool_app)

    install(monkeypatch, register=lambda registry: registry.console_area(area))
    loaded = Runtime(db, [connector], plugins=load_plugins({"sample_plugin": {}}))
    with pytest.raises(PluginError) as refused:
        create_app(db, runtime=loaded, human=served())
    assert refused.value.code == "INVALID_ROUTE"


@pytest.mark.parametrize("change", ["insert", "replace"])
def test_a_plugin_area_that_changes_a_core_route_refuses_start(db, monkeypatch, connector, change):
    """An area is handed the router core's areas built, and may only append to it."""

    async def shadow(request: Request) -> Response:
        return Response("{}", media_type="application/json")

    def area(routes, runtime, config, guards):
        route = Route(API + "/sample-plugin", shadow, methods=["GET"])
        if change == "insert":
            routes.routes.insert(0, route)
        else:
            routes.routes[0] = route

    install(monkeypatch, register=lambda registry: registry.console_area(area))
    loaded = Runtime(db, [connector], plugins=load_plugins({"sample_plugin": {}}))
    with pytest.raises(PluginError) as refused:
        create_app(db, runtime=loaded, human=served())
    assert refused.value.code == "INVALID_ROUTE"


def test_a_plugin_area_cannot_take_a_core_console_api_route(db, monkeypatch, connector):
    def session_again(routes, runtime, config, guards):
        @routes.get("/session")
        def shadow() -> dict[str, str]:
            return {}

    install(monkeypatch, register=lambda registry: registry.console_area(session_again))
    loaded = Runtime(db, [connector], plugins=load_plugins({"sample_plugin": {}}))
    with pytest.raises(PluginError) as refused:
        create_app(db, runtime=loaded, human=served())
    assert refused.value.code == "ROUTE_CONFLICT"


def test_the_console_api_document_is_unchanged_by_an_installed_plugin(sample):
    from execbound.surfaces.console_api import console_api_document

    assert not any("sample-plugin" in path for path in console_api_document()["paths"])


def test_a_plugins_console_document_holds_only_what_its_areas_add(sample):
    """A plugin's console edition generates its own client from its own document (#496): the
    routes its areas append after core's, and none of core's."""
    from execbound.surfaces.console_api import plugin_console_document

    document = plugin_console_document(load_plugins({"sample_plugin": {}}))
    assert set(document["paths"]) == {"/api/console/v1/sample-plugin"}
    assert document["info"]["title"] == "ExecBound console API: sample_plugin"
    assert document["paths"]["/api/console/v1/sample-plugin"]["get"]["x-execbound-token"] in {
        "allowed",
        "refused",
    }
    assert plugin_console_document(NO_PLUGINS)["paths"] == {}


def test_a_plugins_console_document_splits_where_the_same_builds_core_areas_end(
    sample, monkeypatch
):
    """The plugins' routes are those after core's own, counted in the same build rather than
    in a plugin-free one: a core route that exists only beside a plugin stays core's."""
    from execbound.surfaces import console_api

    def beside_a_plugin(routes, runtime, config, guards):
        if runtime.plugins.names:

            @routes.get("/beside-a-plugin")
            async def beside() -> dict[str, str]:
                return {}

    monkeypatch.setattr(console_api, "AREAS", (*console_api.AREAS, beside_a_plugin))
    plugins = load_plugins({"sample_plugin": {}})
    routes, core = console_api._router(plugins)
    assert "/api/console/v1/beside-a-plugin" in {
        getattr(route, "path", None) for route in routes.routes[:core]
    }
    document = console_api.plugin_console_document(plugins)
    assert set(document["paths"]) == {"/api/console/v1/sample-plugin"}


def test_an_area_route_outside_the_console_api_prefix_refuses_start(db, monkeypatch, connector):
    """An area that appends a raw route rather than using its own ``routes.get(...)`` can
    escape the ``/api/console/v1`` prefix ``routes`` was built with; `require_prefix` is what
    still catches it (#238)."""

    async def shadow(request: Request) -> Response:
        return Response("{}", media_type="application/json")

    def escapes_prefix(routes, runtime, config, guards):
        routes.routes.append(Route("/health/ready", shadow, methods=["GET"]))

    install(monkeypatch, register=lambda registry: registry.console_area(escapes_prefix))
    loaded = Runtime(db, [connector], plugins=load_plugins({"sample_plugin": {}}))
    with pytest.raises(PluginError) as refused:
        create_app(db, runtime=loaded, human=served())
    assert refused.value.code == "INVALID_ROUTE"


def test_a_loaded_plugin_console_page_does_not_change_a_core_page_s_policy(
    db, plugin_runtime, fake_build
):
    with gateway(db, plugin_runtime) as client:
        assert client.get("/login").headers["Content-Security-Policy"] == PAGE_POLICY


def command(monkeypatch, capsys, *argv):
    monkeypatch.setattr(sys, "argv", ["execbound", *argv])
    main()
    return capsys.readouterr().out


def command_refused(monkeypatch, capsys, *argv):
    monkeypatch.setattr(sys, "argv", ["execbound", *argv])
    with pytest.raises(SystemExit) as caught:
        main()
    assert caught.value.code == 2
    return capsys.readouterr().err


def test_the_command_line_adds_a_named_plugins_commands(monkeypatch, capsys, sample):
    monkeypatch.setenv("EXECBOUND_PLUGINS", "sample_plugin")
    assert command(monkeypatch, capsys, "sample-echo", "a", "b").strip() == "sample: a b"
    listed = json.loads(command(monkeypatch, capsys, "plugins"))
    assert listed == {
        "plugin_api": PLUGIN_API_VERSION,
        "plugins": [{"api_version": PLUGIN_API_VERSION, "name": "sample_plugin"}],
    }


def test_without_the_variable_no_plugin_command_exists(monkeypatch, capsys, sample):
    monkeypatch.delenv("EXECBOUND_PLUGINS", raising=False)
    assert "invalid choice" in command_refused(monkeypatch, capsys, "sample-echo", "a")
    assert json.loads(command(monkeypatch, capsys, "plugins")) == {
        "plugin_api": PLUGIN_API_VERSION,
        "plugins": [],
    }


def test_a_plugin_command_named_like_a_core_one_is_refused(monkeypatch, capsys):
    clash = Command("recover", "clash", lambda parser: None, lambda args: "")
    install(monkeypatch, register=lambda registry: registry.command(clash))
    monkeypatch.setenv("EXECBOUND_PLUGINS", "sample_plugin")
    assert "Plugin refused: COMMAND_CONFLICT." in command_refused(monkeypatch, capsys, "plugins")


@pytest.mark.parametrize(
    "raised,message",
    [
        (PluginError("INVALID_PLUGIN_CONFIG"), "Command refused: INVALID_PLUGIN_CONFIG."),
        (ValueError("a detail nobody should see"), "Command unavailable."),
        # A plugin command on the runtime connection refuses the way core's do (#496).
        (DormantGrantsRefused("a detail nobody should see"), PLUGIN_GRANTS_REFUSAL.rstrip()),
        (UnsafeDatabaseRole("a detail nobody should see"), RUNTIME_CHECK_REFUSAL.rstrip()),
    ],
)
def test_a_plugin_command_that_fails_says_only_how(monkeypatch, capsys, raised, message):
    def run(args):
        raise raised

    failing = Command("sample-fail", "Fail", lambda parser: None, run)
    install(monkeypatch, register=lambda registry: registry.command(failing))
    monkeypatch.setenv("EXECBOUND_PLUGINS", "sample_plugin")
    monkeypatch.setattr(sys, "argv", ["execbound", "sample-fail"])
    with pytest.raises(SystemExit) as caught:
        main()
    assert caught.value.code == 2
    printed = capsys.readouterr()
    # Standard error also carries the process's own log lines; the message is one line of it.
    assert printed.out == "" and message in printed.err.splitlines()
    assert "detail" not in printed.err


def test_an_unknown_plugin_in_the_variable_stops_every_command(monkeypatch, capsys):
    monkeypatch.setenv("EXECBOUND_PLUGINS", "no_such_plugin")
    assert "Plugin refused: UNKNOWN_PLUGIN." in command_refused(monkeypatch, capsys, "plugins")


def test_readiness_names_the_loaded_plugins_and_never_their_configuration(
    db, plugin_runtime, monkeypatch
):
    monkeypatch.delenv("EXECBOUND_COMMIT", raising=False)
    monkeypatch.delenv("RENDER_GIT_COMMIT", raising=False)
    with TestClient(create_app(db, runtime=plugin_runtime)) as client:
        body = client.get("/health/ready").json()
    assert body["plugins"] == ["sample_plugin"] and body["plugin_api"] == PLUGIN_API_VERSION
    assert "hi" not in json.dumps(body["plugins"]) and "greeting" not in json.dumps(body)


def test_readiness_without_plugins_is_unchanged(db, runtime):
    with TestClient(create_app(db, runtime=runtime)) as client:
        assert set(client.get("/health/ready").json()) == {"status", "version", "commit"}


def test_a_plugin_command_runs_after_the_environment_file_is_read(
    sample, tmp_path, monkeypatch, capsys
):
    """Commands are registered before `load_dotenv()` runs (`EXECBOUND_PLUGINS` must already
    be in the real process environment), but a command's own `run` executes after it, beside
    core's owner commands, so a plugin command sees what `.env` sets exactly as they do.

    `load_dotenv()` with no path resolves `.env` from the calling frame's own file
    (`cli.py`), never from `os.getcwd()`, so it would otherwise find this checkout's real
    `.env` rather than one this test writes. `cli.load_dotenv` is monkeypatched to a file
    this test controls instead, the way `test_replay_cli.py` and
    `test_monitoring_setup_commands.py` already monkeypatch it.
    """
    from dotenv import load_dotenv

    from execbound import cli

    env_file = tmp_path / ".env"
    env_file.write_text("SAMPLE_FROM_DOTENV=yes\n", encoding="utf-8")
    monkeypatch.setattr(cli, "load_dotenv", lambda: load_dotenv(env_file))
    monkeypatch.setenv("EXECBOUND_PLUGINS", "sample_plugin")
    # Set, then removed, both through monkeypatch: the set records what the variable was before
    # this test (normally absent), so teardown restores that rather than leaking the value `.env`
    # writes below into later tests, and the removal leaves it unset for `load_dotenv`, which
    # never overrides a variable that is already set.
    monkeypatch.setenv("SAMPLE_FROM_DOTENV", "unset")
    monkeypatch.delenv("SAMPLE_FROM_DOTENV")
    out = command(monkeypatch, capsys, "sample-echo", "hi")
    assert out.strip() == "sample: hi"
    assert os.environ.get("SAMPLE_FROM_DOTENV") == "yes"


def test_a_plugin_command_refusal_prints_its_own_sentence(sample, monkeypatch, capsys):
    monkeypatch.setenv("EXECBOUND_PLUGINS", "sample_plugin")
    err = command_refused(monkeypatch, capsys, "sample-echo", "refuse")
    assert "Sample refused: NO." in err.splitlines()


RECOVERY_LINK = '<p><a href="/sample-plugin/reset">Forgot your password?</a></p>'


def test_a_plugins_recovery_link_is_on_every_page_sign_in_lands_on(db, monkeypatch, connector):
    """`/login`, a wrong password and a refused provider sign-in all carry the plugin's
    recovery link once, as a plain link (#678)."""
    install(
        monkeypatch,
        register=lambda registry: registry.recovery_link(
            SignInLink("/sample-plugin/reset", lambda runtime: "Forgot your password?")
        ),
    )
    loaded = Runtime(db, [connector], plugins=load_plugins({"sample_plugin": {}}))
    human = HumanConfig(
        "http://127.0.0.1",
        TokenKeys("state-v1", {"state-v1": secrets.token_bytes(32)}),
        providers=(StandIn(name="google", label="Google"),),
    )
    app = create_app(db, runtime=loaded, human=human)
    with TestClient(app, base_url="http://127.0.0.1", follow_redirects=False) as client:
        page = client.get("/login")
        _, values = form_values(page.text, "/session/password")
        values.update(email="nobody@example.com", password="not the password at all")
        wrong = client.post(
            "/session/password", data=values, headers={"Origin": "http://127.0.0.1"}
        )
        provider = client.get("/login/google/callback", params={"error": "access_denied"})
    for answer in (page, wrong, provider):
        assert answer.text.count(RECOVERY_LINK) == 1
        assert sign_in_links(answer.text) == ["/sample-plugin/reset"]
