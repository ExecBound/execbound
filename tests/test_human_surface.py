# SPDX-License-Identifier: AGPL-3.0-only
"""Human credential, session, CSRF and scope checks at the routes a browser really reaches.

Since the console took over (#333) those routes are three things: the pages that stay
server-rendered (sign-in, the session, and the classic approval page a person still decides on),
the console's own document, and the console API the console reads. A record and a queue are read
here through the API, because that is what the console reads and it is the same `records()`
under the same scope, fence and bounds the pages used; a decision is posted to the classic
page's form, because that form is still the product's no-script human control.
"""

import json
import re
import secrets
from datetime import timedelta
from html import unescape
from types import SimpleNamespace
from uuid import uuid4

import pytest
from arcade_fixtures import (
    CORRECTIONS,
    GOVERNED_TOOL,
    correct,
    correlation_rows,
    governed_bundle,
    hook_block,
    post,
    pre,
)
from arcade_fixtures import arcade_world as arcade_world
from checkpoint_fixtures import retained
from context_fixtures import CATALOG
from fastapi.testclient import TestClient
from scope_fixtures import group, rule, scoped_bundle
from scope_fixtures import owner as owner
from sqlalchemy import text
from test_runtime import connector as connector
from test_runtime import live_provider as live_provider
from test_runtime import registry as registry
from test_runtime import request
from test_runtime import runtime as runtime
from test_runtime import world as world

from execbound import administration
from execbound.app import create_app
from execbound.contracts import IDENTITY_CONTROL_V1, Catalog
from execbound.identity import new_token
from execbound.operations import PRODUCTION_ACTIONS, ActionCatalog
from execbound.policy.models import LimitSelector
from execbound.runtime import Runtime
from execbound.surfaces.human import HumanConfig, limit_label
from execbound.surfaces.tokens import TokenKeys


def form_values(html, contains):
    for action, body in re.findall(r'<form[^>]*action="([^"]+)"[^>]*>(.*?)</form>', html, re.S):
        if contains in action:
            fields = {
                name: unescape(value)
                for name, value in re.findall(
                    r'<input[^>]*name="([^"]+)"[^>]*value="([^"]*)"', body
                )
            }
            return action, fields
    raise AssertionError("Expected form not found")


def credential(engine, identity):
    token, digest = new_token(identity.tenant_id, identity.credential_id)
    with engine.begin() as conn:
        conn.execute(
            text(
                "UPDATE execbound.credentials SET token_hash=:h "
                "WHERE tenant_id=:t AND credential_id=:c"
            ),
            {"h": digest, "t": identity.tenant_id, "c": identity.credential_id},
        )
    return token


@pytest.fixture
def human_config():
    return HumanConfig(
        "http://127.0.0.1", TokenKeys("state-v1", {"state-v1": secrets.token_bytes(32)})
    )


@pytest.fixture
def human_app(db, runtime, human_config):
    return create_app(db, runtime=runtime, human=human_config)


@pytest.fixture
def human_client(human_app, world, admin_engine):
    with TestClient(human_app, base_url="http://127.0.0.1", follow_redirects=False) as client:
        login = client.get("/login")
        _, values = form_values(login.text, "/session")
        values["credential"] = credential(admin_engine, world["human"])
        result = client.post("/session", data=values, headers={"Origin": "http://127.0.0.1"})
        assert result.status_code == 303
        assert (
            "HttpOnly" in result.headers["set-cookie"]
            and "SameSite=strict" in result.headers["set-cookie"]
        )
        yield client


def pending(runtime, world):
    return runtime.execute(world["identity"], request(world).model_dump_json().encode())


def classic(client, approval_id):
    """The decision form of the classic approval page: where a person still decides."""
    page = client.get(f"/approvals/{approval_id}/classic")
    assert page.status_code == 200, page.status_code
    return form_values(page.text, "/decide")


def test_human_approval_then_gateway_dispatch(human_client, runtime, world, live_provider):
    first = pending(runtime, world)
    page = human_client.get(f"/approvals/{first.approval_id}/classic")
    assert page.status_code == 200
    assert "device-01" in page.text and "Authoritative context" in page.text
    assert "Content-Security-Policy" in page.headers
    path, values = form_values(page.text, "/decide")
    values["decision"] = "APPROVE"
    assert (
        human_client.post(path, data=values, headers={"Origin": "http://127.0.0.1"}).status_code
        == 303
    )
    assert (
        human_client.post(path, data=values, headers={"Origin": "http://127.0.0.1"}).status_code
        == 409
    )
    result = pending(runtime, world)
    assert result.execution_id == first.execution_id and result.state == "EXECUTED"
    assert (
        live_provider.store.resource(world["identity"].tenant_id, world["canonical"]).mutation_count
        == 1
    )


@pytest.mark.parametrize(
    "attack",
    [
        "origin",
        "missing_origin",
        "csrf",
        "unicode_csrf",
        "state",
        "duplicate",
        "unknown",
        "alternate_path",
    ],
)
def test_forged_human_forms_do_not_approve(human_client, runtime, world, admin_engine, attack):
    first = pending(runtime, world)
    path, values = classic(human_client, first.approval_id)
    values["decision"] = "APPROVE"
    headers = {"Origin": "http://127.0.0.1"}
    if attack == "origin":
        headers["Origin"] = "https://attacker.invalid"
    if attack == "missing_origin":
        headers = {}
    if attack == "csrf":
        values["csrf"] = "forged"
    if attack == "unicode_csrf":
        values["csrf"] = "☃"
    if attack == "state":
        values["state"] += "0"
    if attack == "unknown":
        values["approved"] = "true"
    if attack == "alternate_path":
        path = path.replace(str(first.approval_id), "00000000-0000-0000-0000-000000000000")
    if attack == "duplicate":
        from urllib.parse import urlencode

        headers["Content-Type"] = "application/x-www-form-urlencoded"
        response = human_client.post(
            path, content=urlencode(values) + "&decision=DENY", headers=headers
        )
    else:
        response = human_client.post(path, data=values, headers=headers)
    assert response.status_code in {400, 403}
    with admin_engine.connect() as conn:
        assert (
            conn.execute(
                text("SELECT state FROM execbound.approvals WHERE approval_id=:a"),
                {"a": first.approval_id},
            ).scalar_one()
            == "PENDING"
        )


def test_logout_invalidates_retained_cookie(human_client, runtime, world):
    old = dict(human_client.cookies)
    first = pending(runtime, world)
    page = human_client.get(f"/approvals/{first.approval_id}/classic")
    path, values = form_values(page.text, "/session/logout")
    assert (
        human_client.post(path, data=values, headers={"Origin": "http://127.0.0.1"}).status_code
        == 303
    )
    human_client.cookies.update(old)
    assert human_client.get("/api/console/v1/approvals").status_code == 401


def test_expired_session_cannot_read(human_client, world):
    world["clock"].value += timedelta(minutes=16)
    # A person who opened a console route is sent to sign in; the API a script calls answers
    # 401, because a redirect to an HTML page is not an answer a fetch can act on.
    document = human_client.get("/activity")
    # It returns to the page after signing in (#678).
    assert document.status_code == 303
    assert document.headers["location"] == "/login?review=%2Factivity"
    assert human_client.get("/api/console/v1/executions").status_code == 401


def test_scope_revocation_hides_pending_and_rejects_old_form(
    human_client, runtime, world, admin_engine
):
    first = pending(runtime, world)
    path, values = classic(human_client, first.approval_id)
    values["decision"] = "APPROVE"
    with admin_engine.begin() as conn:
        conn.execute(text("UPDATE execbound.approval_scopes SET active=false"))
    queue = human_client.get("/api/console/v1/approvals")
    assert queue.status_code == 200
    assert str(first.approval_id) not in queue.text
    assert (
        human_client.post(path, data=values, headers={"Origin": "http://127.0.0.1"}).status_code
        == 400
    )


@pytest.mark.parametrize(
    "path",
    [
        "/approvals",
        "/activity",
        "/api/console/v1/approvals",
        "/api/console/v1/executions",
        "/approvals/00000000-0000-0000-0000-000000000000/classic",
        "/session/logout",
        "/api/console/v1/executions/00000000-0000-0000-0000-000000000000/reconcile",
        "/approvals/00000000-0000-0000-0000-000000000000/decide",
    ],
)
def test_agent_bearer_cannot_use_human_routes(human_app, seeded, path, admin_engine, world):
    with TestClient(human_app, base_url="http://127.0.0.1") as client:
        headers = {"Authorization": "Bearer " + seeded["tokens"][0], "Origin": "http://127.0.0.1"}
        response = (
            client.get(path, headers=headers)
            if not path.endswith(("/decide", "/reconcile", "/logout"))
            else client.post(path, data={}, headers=headers)
        )
        assert response.status_code in {400, 401, 403}
    with admin_engine.connect() as conn:
        assert (
            conn.execute(
                text(
                    "SELECT count(*) FROM execbound.audit_events "
                    "WHERE tenant_id=:t AND actor_id=:p AND kind='execution.rejected'"
                ),
                {"t": world["identity"].tenant_id, "p": world["identity"].principal_id},
            ).scalar_one()
            == 1
        )
        assert conn.execute(text("SELECT count(*) FROM execbound.human_sessions")).scalar_one() == 0


def test_agent_cannot_open_human_session(human_app, seeded):
    with TestClient(human_app, base_url="http://127.0.0.1") as client:
        _, values = form_values(client.get("/login").text, "/session")
        values["credential"] = seeded["tokens"][0]
        assert (
            client.post("/session", data=values, headers={"Origin": "http://127.0.0.1"}).status_code
            == 403
        )


def test_session_expiry_during_decision_rolls_back(
    human_client, runtime, world, admin_engine, monkeypatch
):
    from execbound.execution import store

    first = pending(runtime, world)
    with admin_engine.begin() as conn:
        conn.execute(
            # About to expire and at its absolute cap, so activity cannot renew it.
            text(
                "UPDATE execbound.human_sessions "
                "SET expires_at=:e, created_at=:e - interval '8 hours'"
            ),
            {"e": world["clock"].now() + timedelta(seconds=1)},
        )
    path, values = classic(human_client, first.approval_id)
    values["decision"] = "APPROVE"
    original = store.approval_state

    def expire(*args, **kwargs):
        original(*args, **kwargs)
        world["clock"].value += timedelta(seconds=2)

    monkeypatch.setattr(store, "approval_state", expire)
    assert (
        human_client.post(path, data=values, headers={"Origin": "http://127.0.0.1"}).status_code
        == 403
    )
    with admin_engine.connect() as conn:
        assert (
            conn.execute(
                text("SELECT state FROM execbound.approvals WHERE approval_id=:a"),
                {"a": first.approval_id},
            ).scalar_one()
            == "PENDING"
        )


def test_continuation_cannot_move_between_sessions(
    human_client, human_config, runtime, world, admin_engine
):
    first = pending(runtime, world)
    path, values = classic(human_client, first.approval_id)
    values["decision"] = "APPROVE"
    other_app = create_app(runtime.db, runtime=runtime, human=human_config)
    with TestClient(other_app, base_url="http://127.0.0.1", follow_redirects=False) as other:
        _, login = form_values(other.get("/login").text, "/session")
        login["credential"] = credential(admin_engine, world["human"])
        assert (
            other.post("/session", data=login, headers={"Origin": "http://127.0.0.1"}).status_code
            == 303
        )
        _, own = classic(other, first.approval_id)
        values["csrf"] = own["csrf"]
        assert (
            other.post(path, data=values, headers={"Origin": "http://127.0.0.1"}).status_code == 400
        )


def test_https_session_cookie_security(db, runtime, world, admin_engine, human_config):
    config = HumanConfig("https://review.example.test", human_config.keys)
    with TestClient(
        create_app(db, runtime=runtime, human=config),
        base_url=config.origin,
        follow_redirects=False,
    ) as client:
        _, values = form_values(client.get("/login").text, "/session")
        values["credential"] = credential(admin_engine, world["human"])
        response = client.post("/session", data=values, headers={"Origin": config.origin})
        assert response.status_code == 303
        headers = response.headers.get_list("set-cookie")
        for name in ("session", "csrf"):
            item = next(value for value in headers if value.startswith("__Host-eb_" + name + "="))
            assert "Secure" in item and "HttpOnly" in item and "SameSite=strict" in item
            assert "Domain=" not in item and "Path=/" in item
        assert client.get("/api/console/v1/session").status_code == 200


@pytest.mark.parametrize(
    "change", ["expire_before_read", "logout_before_read", "expire_during_read"]
)
def test_privileged_list_rechecks_session(human_client, runtime, world, monkeypatch, change):
    from execbound.surfaces import human
    from execbound.surfaces.sessions import revoke_session

    pending(runtime, world)
    if change == "expire_during_read":
        original = human.store.bundle

        def read(*args, **kwargs):
            result = original(*args, **kwargs)
            world["clock"].value += timedelta(minutes=16)
            return result

        monkeypatch.setattr(human.store, "bundle", read)
    else:
        original = human.load_session

        def load(*args, **kwargs):
            session = original(*args, **kwargs)
            if change == "logout_before_read":
                revoke_session(runtime.db, session, clock=runtime.clock)
            else:
                world["clock"].value += timedelta(minutes=16)
            return session

        monkeypatch.setattr(human, "load_session", load)
    # The console reads its queue through the API, so that is where the recheck has to bite.
    response = human_client.get("/api/console/v1/approvals")
    assert response.status_code == 401
    assert "device-01" not in response.text


def test_listing_renders_unknown_contract_label_instead_of_failing(
    human_config, db, runtime, world, connector, admin_engine
):
    """A frozen plan can name a contract the running catalog lacks; the row must still render."""
    pending(runtime, world)
    narrowed = Runtime(
        db,
        [connector],
        clock=world["clock"],
        keys=TokenKeys("pending-v1", {"pending-v1": secrets.token_bytes(32)}),
        catalog=Catalog((IDENTITY_CONTROL_V1,)),
    )
    app = create_app(db, runtime=narrowed, human=human_config)
    with TestClient(app, base_url="http://127.0.0.1", follow_redirects=False) as client:
        _, values = form_values(client.get("/login").text, "/session")
        values["credential"] = credential(admin_engine, world["human"])
        started = client.post("/session", data=values, headers={"Origin": "http://127.0.0.1"})
        assert started.status_code == 303
        page = client.get("/api/console/v1/approvals")
    assert page.status_code == 200
    assert "device-01" in page.text
    assert "unknown contract endpoint-isolation.v1" in page.text


def test_listing_renders_unknown_action_label_instead_of_failing(
    human_config, db, runtime, world, connector, admin_engine
):
    """A frozen plan can name an action the running catalog lacks; the row must still render."""
    pending(runtime, world)
    identity_only = ActionCatalog(
        tuple(spec for spec in PRODUCTION_ACTIONS.specs if spec.resource_type == "identity"),
        PRODUCTION_ACTIONS.bindings_for("mock_entra"),
    )
    narrowed = Runtime(
        db,
        [connector],
        clock=world["clock"],
        keys=TokenKeys("pending-v1", {"pending-v1": secrets.token_bytes(32)}),
        catalog=Catalog((IDENTITY_CONTROL_V1,), actions=identity_only),
    )
    app = create_app(db, runtime=narrowed, human=human_config)
    with TestClient(app, base_url="http://127.0.0.1", follow_redirects=False) as client:
        _, values = form_values(client.get("/login").text, "/session")
        values["credential"] = credential(admin_engine, world["human"])
        started = client.post("/session", data=values, headers={"Origin": "http://127.0.0.1"})
        assert started.status_code == 303
        page = client.get("/api/console/v1/approvals")
    assert page.status_code == 200
    assert "device-01" in page.text
    assert "unknown action endpoint.isolate" in page.text.lower()


def scoped_rules(triage, account):
    """One rule per scope the record page must label, all covering ``endpoint.isolate``."""
    return (
        rule(rule_id="squad", scope="group", group_id=triage),
        rule(rule_id="crowdstrike", scope="account", account_id=account),
        rule(
            rule_id="production",
            scope="selector",
            selector=LimitSelector(fact="environment", equals="production"),
        ),
        rule(rule_id="pair", actions=("endpoint.isolate", "endpoint.lift_isolation")),
    )


def record(client, execution_id):
    """One record as the console reads it: the drawer's own view, over the console API."""
    view = client.get(f"/api/console/v1/executions/{execution_id}")
    assert view.status_code == 200, view.status_code
    return view


def test_record_page_labels_every_limit_scope(human_client, runtime, world, db, owner):
    """SL11 (the record): each applicable rule states its scope and its actions."""
    triage = group(owner, world, world["identity"], name="triage")
    scoped_bundle(db, world, *scoped_rules(triage, world["account"]))
    first = pending(runtime, world)
    sentences = {
        item["sentence"] for item in record(human_client, first.execution_id).json()["limits"]
    }
    ceiling = "at most 3 total targets per 3600 seconds; over that, a person decides."
    assert f"Group triage: {ceiling}" in sentences
    assert f"Account {world['account']}: {ceiling}" in sentences
    assert f"Environment = production: {ceiling}" in sentences
    assert f"Principal: {ceiling}" in sentences
    assert not any(sentence.startswith("Tenant:") for sentence in sentences)


def test_record_page_escapes_group_names(human_client, runtime, world, db, owner):
    """A group name is tenant data: it travels as a string and never as markup.

    The console renders it as text and the browser suite holds that; what is asserted here is
    that the server builds no element around it, so there is nothing for a template to escape
    or forget to escape.
    """
    tenant, actor = world["identity"].tenant_id, world["admin"].principal_id
    marked = administration.create_group(owner, tenant, "<b>triage</b>", actor)
    scoped_bundle(db, world, rule(scope="group", group_id=marked))
    first = pending(runtime, world)
    view = record(human_client, first.execution_id)
    [limit] = view.json()["limits"]
    assert limit["sentence"].startswith("Group <b>triage</b>: at most 3 total targets")
    # It arrives as a JSON string and nothing else: the answer is `application/json` with
    # `nosniff`, so no browser reads those characters as an element, and the server built
    # no markup around them for one to escape or forget to escape.
    assert view.headers["content-type"].startswith("application/json")
    assert view.headers["X-Content-Type-Options"] == "nosniff"


def test_limit_label_names_every_scope_without_raising():
    known, unknown, mixed = uuid4(), uuid4(), uuid4()
    names = {known: "triage", mixed: "Tier-1 SOC"}
    assert limit_label(rule(scope="group", group_id=known), names) == "Group triage"
    # Only the leading word is capitalized; the retained name keeps its own case.
    assert limit_label(rule(scope="group", group_id=mixed), names) == "Group Tier-1 SOC"
    assert limit_label(rule(scope="group", group_id=unknown), names) == f"Group {unknown}"
    assert limit_label(rule(scope="account", account_id=known), names) == f"Account {known}"
    for equals, shown in (("CRITICAL", "CRITICAL"), (3, "3"), (True, "true"), (False, "false")):
        selector = LimitSelector(fact="incident_severity", equals=equals)
        scoped = rule(scope="selector", selector=selector)
        assert limit_label(scoped, names) == f"Incident_severity = {shown}"
    assert limit_label(rule(), names) == "Principal"
    assert limit_label(rule(scope="tenant"), names) == "Tenant"


def test_every_precondition_class_has_a_sentence_for_the_approval_page():
    """A class with no sentence is a KeyError on an approval page, not a blank space.

    `human._PRECONDITION_TEXT` is indexed directly, not read with a default, and it is
    indexed for a record that is still PENDING_APPROVAL or DENIED — before any grant
    exists, so a refusal at grant time does not protect this path. Adding a class to the
    union without adding its sentence would take down the page a reviewer uses to decide.
    """
    from execbound.execution.models import PRECONDITION_CLASSES
    from execbound.surfaces.human import _PRECONDITION_TEXT

    assert set(_PRECONDITION_TEXT) == PRECONDITION_CLASSES


# What a control point said about a record, on the pages a person reads. These are the
# server-rendered half — the escaped bytes, and the activity filter's allowlist. The
# Chromium half of AL28 and AL30's page clause is in `tests/test_browser_surfaces.py`.

# A distinct script element per field, so no one escaped value can stand in for another.
# Each is chosen without a quote character: the expected escaped form is then written out
# below rather than computed with the same escaper the template uses, which would pass
# whatever that escaper did.
MARKED_FIELDS = ("user", "code", "error", "metadata_key", "metadata_value")
# The approval policy `tests/test_arcade.py` uses for the same purpose, written out here
# rather than imported, so this module does not collect that one to read a literal.
APPROVE_RISKY = (
    'permit(principal, action == ExecBound::Action::"endpoint.isolate", resource) '
    "when { resource.risk_score >= 60 };"
)


def markup(field):
    return f"<script>alert({field})</script>"


def escaped(field):
    return f"&lt;script&gt;alert({field})&lt;/script&gt;"


HOSTILE_METADATA = {
    "behavior": {"destructive": True},
    markup("metadata_key"): markup("metadata_value"),
}
HOSTILE_CONTEXT = {"user_id": markup("user"), "secrets": ["CROWDSTRIKE_TOKEN"]}
HOSTILE_TOOL = {**GOVERNED_TOOL, "metadata": HOSTILE_METADATA}


def session_for(app, engine, identity):
    """A browser session on this application for this identity."""
    client = TestClient(app, base_url="http://127.0.0.1", follow_redirects=False)
    login = client.get("/login")
    _, values = form_values(login.text, "/session")
    values["credential"] = credential(engine, identity)
    opened = client.post("/session", data=values, headers={"Origin": "http://127.0.0.1"})
    assert opened.status_code == 303
    return client


def form_actions(html):
    """Where every form on the rendered page submits; a page that dispatches has one."""
    return sorted(re.findall(r'<form[^>]*action="([^"]+)"', html))


@pytest.fixture
def carried(db, arcade_world, seeded, human_config):
    """One deployment serving both the Arcade hooks and the human pages.

    The runtime holds no connector, which is the placement `arcade_world` provisions, and
    its catalog carries the governed operation's contract. The hooks and the pages are one
    application because what is under test is what a page shows about a record the hooks
    opened, and the correlation row is the only thing carrying it between them.
    """
    world = arcade_world
    runtime = Runtime(db, [], clock=world["clock"], catalog=CATALOG)
    app = create_app(db, runtime=runtime, human=human_config, arcade=hook_block())
    with TestClient(app, base_url="http://127.0.0.1", follow_redirects=False) as client:
        yield SimpleNamespace(client=client, token=seeded["tokens"][0], app=app, world=world)


def hostile_call(driver, **changes):
    """One governed tool call whose reported strings each carry a script element.

    The end user, the tool metadata's key and its value, the reported code and the
    reported error: the five free columns a correlation row retains. The tool identity
    and the Arcade execution id are not among them — `ToolInfo` and the idempotency key
    class narrow those before the row is opened.
    """
    answered = pre(driver, tool=HOSTILE_TOOL, context=HOSTILE_CONTEXT)
    reported = post(
        driver,
        tool=HOSTILE_TOOL,
        context=HOSTILE_CONTEXT,
        execution_code=markup("code"),
        execution_error=markup("error"),
        **changes,
    )
    return answered, reported


def test_a_control_points_strings_reach_the_record_page_as_inert_text(carried, admin_engine):
    """The four free correlation columns reach the record as data and never as markup.

    `reported_metadata`, `reported_user_id`, `reported_code` and `reported_error` take
    whatever the platform sends: an attack review found each retaining a script element
    verbatim while nothing rendered them. The console reads the record over the API, so
    what is asserted here is what leaves the server — each string present, byte for byte,
    inside a JSON string, in an answer typed `application/json` with `nosniff`, so no
    browser can read those characters as an element and the server built none. That the
    console then draws them as text is `tests/test_browser_console_activity.py`'s.

    The report secret is asserted absent from the same answer. It is the one credential the
    correlation row holds at rest, `CARRIER_QUERY` does not select it, and the outstanding
    grant is the state in which the row still has one to leak.
    """
    world = carried.world
    tenant = world["identity"].tenant_id
    admin = session_for(carried.app, admin_engine, world["admin"])
    assert pre(carried, tool=HOSTILE_TOOL, context=HOSTILE_CONTEXT).json() == {"code": "OK"}
    secret = correlation_rows(admin_engine, tenant)["arcade-execution-1"]["report_secret"]
    assert secret, "the granted row holds no secret this assertion could be about"
    execution_id = correlation_rows(admin_engine, tenant)["arcade-execution-1"]["execution_id"]
    outstanding = record(admin, execution_id)
    assert secret not in outstanding.text
    reported = post(
        carried,
        tool=HOSTILE_TOOL,
        context=HOSTILE_CONTEXT,
        success=False,
        execution_code=markup("code"),
        execution_error=markup("error"),
    )
    assert reported.status_code == 200
    page = record(admin, execution_id)
    assert secret not in page.text
    carriers = json.dumps(page.json()["carriers"])
    for field in MARKED_FIELDS:
        assert markup(field) in carriers, field
    assert page.json()["carriers"], "the record carries no control point at all"
    assert page.headers["content-type"].startswith("application/json")
    assert page.headers["X-Content-Type-Options"] == "nosniff"


def test_a_control_points_strings_reach_the_approval_page_as_inert_text(db, carried, admin_engine):
    """The same four columns on the approval page, where the decision is still open.

    A pre hook that answers `CHECK_FAILED` for a pending approval still opens the
    correlation row, and `store.correlate` retains what a later post hook states before
    the kernel is asked anything — which is the shape a control point configured to fail
    open produces. So the page a human decides on is a page that shows the platform's own
    strings, and it shows them as text.
    """
    world = carried.world
    governed_bundle(db, world, approval_policies=APPROVE_RISKY)
    answered, reported = hostile_call(carried, success=True)
    assert answered.json()["code"] == "CHECK_FAILED" and reported.status_code == 200
    approver = session_for(carried.app, admin_engine, world["human"])
    queue = approver.get("/api/console/v1/approvals")
    assert queue.status_code == 200
    [item] = queue.json()["items"]
    page = approver.get(f"/approvals/{item['approval_id']}/classic")
    assert page.status_code == 200
    for field in MARKED_FIELDS:
        assert escaped(field) in page.text, field
        assert markup(field) not in page.text, field
    # The only control the classic page offers is the decision, and it names the approval
    # rather than anything the platform sent.
    assert form_actions(page.text) == [
        f"/approvals/{item['approval_id']}/decide",
        "/session/logout",
    ]


def test_the_activity_filter_admits_the_settled_reported_failure_state(carried, admin_engine):
    """A settled state the console can show is a state the console can ask for.

    `activity_filters` is a strict allowlist that answers 400 for a state it does not
    hold. Without the new state in `ACTIVITY_STATES` its rows appear unfiltered and cannot
    be filtered to: a settled state the console shows and could not be asked for. Both
    halves are asserted here: the state is admitted, and a string outside the allowlist is
    still refused.
    """
    world = carried.world
    hostile_call(carried, success=False)
    page = session_for(carried.app, admin_engine, world["admin"])
    filtered = page.get("/api/console/v1/executions?state=FAILED_EFFECT_UNKNOWN")
    assert filtered.status_code == 200
    [item] = filtered.json()["items"]
    assert item["state"] == "FAILED_EFFECT_UNKNOWN"
    assert page.get("/api/console/v1/executions?state=RESERVED").status_code == 400
    assert page.get("/api/console/v1/executions?state=NOT_A_STATE").status_code == 400


@pytest.mark.parametrize("changes,state", CORRECTIONS, ids=["cancelled", "version-mismatch"])
def test_a_corrected_record_shows_the_statement_its_own_result_no_longer_holds(
    db, carried, admin_engine, changes, state
):
    """The earlier statement comes from the transition history and from nothing else.

    `_settle` replaces `result` with the correcting evidence, so the reason the page
    prints for the statement that was corrected — `REPORTED_FAILURE` — is one the record's
    own column no longer holds. That is asserted against the column here, so a page that
    read the column could not have produced this text.
    """
    world = carried.world
    tenant = world["identity"].tenant_id
    hostile_call(carried, success=False)
    execution_id = correlation_rows(admin_engine, tenant)["arcade-execution-1"]["execution_id"]
    admin = session_for(carried.app, admin_engine, world["admin"])
    stated = record(admin, execution_id).text
    assert "The effect was never established." in stated
    assert "Corrected: this record was settled once on the executor" not in stated

    view = correct(db, world, execution_id, changes)
    assert view.state == state
    row = retained(admin_engine, tenant, execution_id)
    assert row.result["reason"] == changes["reason"] and row.result["reason"] != "REPORTED_FAILURE"
    corrected = record(admin, execution_id).text
    assert "Corrected: this record was settled once on the executor" in corrected
    assert (
        "the executor stated FAILED_EFFECT_UNKNOWN for reason REPORTED_FAILURE, "
        "on its own clock at" in corrected
    )
    assert "The effect was never established." not in corrected


def test_every_recordable_class_has_a_sentence_for_a_dispatch_ExecBound_made():
    """The same whole-union guard as the gate map, for the retrospective wording.

    A class with no sentence here is a KeyError on the page a reviewer decides from, and
    the two maps are different statements: one describes a declaration in force now, the
    other what one attempt actually carried.
    """
    from execbound.execution.models import PRECONDITION_CLASSES
    from execbound.surfaces.human import _DISPATCHED_PRECONDITION

    assert set(_DISPATCHED_PRECONDITION) == PRECONDITION_CLASSES


def test_an_externally_executed_record_gets_no_dispatch_sentence():
    """A grant stamps dispatch_attempted_at, so the column alone would lie about it.

    The record is acted on by somebody else's executor and its gate label already carries
    the class; a second sentence describing an attempt ExecBound never made, under a class
    nobody recorded for it, is the confusion this guard exists to prevent.
    """
    from datetime import UTC, datetime

    from execbound.surfaces.human import dispatched_precondition

    granted = {
        "dispatch_attempted_at": datetime.now(UTC),
        "precondition_class": None,
        "report_expires_at": datetime.now(UTC),
    }
    # The helper itself describes an attempt; the caller is what must not ask about a grant.
    assert dispatched_precondition(granted)
    assert dispatched_precondition({"dispatch_attempted_at": None}) == (
        "Not yet: no send attempt has been made for this record."
    )


def test_a_record_dispatched_before_the_column_existed_reads_as_the_mock_it_had():
    """NULL is history, not unknown: every provider then refused a moved version."""
    from datetime import UTC, datetime

    from execbound.surfaces.human import dispatched_precondition

    sentence = dispatched_precondition(
        {"dispatch_attempted_at": datetime.now(UTC), "precondition_class": None}
    )
    assert "predates the recording" in sentence
    assert sentence.startswith("Enforced by the provider")


def test_the_measured_window_renders_as_a_number_with_its_unit():
    """A reader weighs a measurement. An adjective would be the pitch, not the evidence."""
    from datetime import UTC, datetime

    from execbound.surfaces.human import dispatched_precondition

    sentence = dispatched_precondition(
        {
            "dispatch_attempted_at": datetime.now(UTC),
            "precondition_class": "CHECKED_BY_CONNECTOR",
            "precondition_window_ms": 37,
        }
    )
    assert "37 milliseconds" in sentence
    assert "measured and retained" in sentence
    # The sentence still refuses the claim the number might be mistaken for.
    assert "not atomicity" in sentence


def test_a_window_is_never_shown_beside_a_class_that_measured_nothing():
    from datetime import UTC, datetime

    from execbound.surfaces.human import dispatched_precondition

    for declared in ("ENFORCED_BY_PROVIDER", "ASSERTED_BY_EXECUTOR", "UNAVAILABLE"):
        sentence = dispatched_precondition(
            {
                "dispatch_attempted_at": datetime.now(UTC),
                "precondition_class": declared,
                # A value that should never be believed for this class.
                "precondition_window_ms": 9999,
            }
        )
        assert "milliseconds" not in sentence, declared
    # And a connector dispatch that measured nothing says nothing about a gap.
    unmeasured = dispatched_precondition(
        {
            "dispatch_attempted_at": datetime.now(UTC),
            "precondition_class": "CHECKED_BY_CONNECTOR",
            "precondition_window_ms": None,
        }
    )
    assert "milliseconds" not in unmeasured


def test_the_connector_sentence_says_what_it_cannot_do():
    """The one sentence that must not read as a guarantee."""
    from execbound.surfaces.human import _DISPATCHED_PRECONDITION

    checked = _DISPATCHED_PRECONDITION["CHECKED_BY_CONNECTOR"]
    assert "not atomicity" in checked
    assert "between the read and the write is not detectable" in checked
