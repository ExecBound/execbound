# SPDX-License-Identifier: AGPL-3.0-only
"""The sign-in routes as a browser reaches them: the password form, a provider, the code page.

The provider here is a stand-in that implements the contract and talks to nothing, because
what these tests are about is the route: the transient cookie, the `state` comparison, the
refusals that all look alike, and the session that comes out the other end being the same
session a credential produces. What each real provider verifies is `tests/test_oidc.py` and
`tests/test_github_sign_in.py`.
"""

import hashlib
import logging
import re
import secrets
from dataclasses import dataclass, field, replace
from datetime import timedelta
from html import escape, unescape
from urllib.parse import urlencode
from uuid import uuid4

import pytest
from conftest import assert_secret_free
from fastapi import HTTPException
from fastapi.testclient import TestClient
from sqlalchemy import text
from starlette.responses import PlainTextResponse
from test_runtime import connector as connector
from test_runtime import live_provider as live_provider
from test_runtime import registry as registry
from test_runtime import runtime as runtime
from test_runtime import world as world

from execbound.app import create_app
from execbound.db import UnsafeDatabaseRole
from execbound.passwords import (
    SIGN_IN_LIFETIME,
    PasswordError,
    bind_identity,
    issue_reset,
    redeem_reset,
    reset_code,
    set_email,
    sign_in_with_password,
)
from execbound.plugins import ProviderSignup
from execbound.signin import ExternalAccount, FlowState, SignInRefused
from execbound.surfaces.human import HumanConfig
from execbound.surfaces.limits import RequestLimits
from execbound.surfaces.sign_in_pages import MAX_CODE_BYTES, start_provider_flow
from execbound.surfaces.tokens import TokenKeys

pytestmark = pytest.mark.integration

ORIGIN = "http://127.0.0.1"
PASSWORD = "a decent passphrase"
NEW_PASSWORD = "an entirely different one"
ADDRESS = "dana@example.com"
SUBJECT = "the-provider-subject"
WRONG = "Those sign-in details are not right."
REFUSED = "That account cannot sign in here."
REFRESH = re.compile(r'<meta http-equiv="refresh" content="0; url=([^"]+)">')


def landed_at(answer, *, session: bool = True) -> str:
    """Where a callback sends the browser next, and that it sends it there from a page of
    this site's own (`onward`): a 200 whose refresh and whose one link name the same page. A
    303 would reach that page in the provider's cross-site chain, and a SameSite=Strict
    session is not sent there. A sign-in carries the new session; a self-link issues none,
    because the person already had one."""
    assert answer.status_code == 200, (answer.status_code, answer.headers.get("location"))
    found = REFRESH.search(answer.text)
    assert found is not None, "the onward page has no refresh"
    location = found.group(1)
    assert f'<a href="{location}">Continue to ExecBound</a>' in answer.text
    issued = [c for c in answer.headers.get_list("set-cookie") if c.startswith("eb_session=")]
    if session:
        assert len(issued) == 1 and "samesite=strict" in issued[0].lower(), issued
    else:
        assert issued == [], issued
    return location


@dataclass(frozen=True)
class StandIn:
    """A provider that implements the contract and reaches no network.

    It records the flow it was given, so a test can assert the `state` the route put in the
    cookie is the one the authorization request carried.
    """

    account: ExternalAccount | None = None
    refusal: str | None = None
    name: str = "google"
    label: str = "Google"
    authorization_origin: str = "https://provider.example"
    seen: list[tuple[str, FlowState]] = field(default_factory=list)

    def begin(self, flow: FlowState) -> str:
        return f"https://provider.example/authorize?state={flow.state}"

    def complete(self, code: str, flow: FlowState, *, now: float) -> ExternalAccount:
        self.seen.append((code, flow))
        if self.refusal is not None or self.account is None:
            raise SignInRefused(self.refusal or "NO_PERSON")
        return self.account


def form_values(html, action):
    """What a browser posts from the form at `action` untouched: every named input with a
    value, except a checkbox nobody ticked, which a browser leaves out."""
    for found, body in re.findall(r'<form[^>]*action="([^"]+)"[^>]*>(.*?)</form>', html, re.S):
        if found == action:
            return {
                name: unescape(value)
                for tag in re.findall(r"<input\b[^>]*>", body)
                if 'type="checkbox"' not in tag or re.search(r"\schecked\b", tag)
                for name, value in re.findall(r'name="([^"]+)"[^>]*value="([^"]*)"', tag)
            }
    raise AssertionError(f"No form posting to {action}")


@pytest.fixture
def providers(request):
    """The deployment's configured providers: none unless a test asks for some."""
    return getattr(request, "param", [])


@pytest.fixture
def config(providers):
    return HumanConfig(
        ORIGIN,
        TokenKeys("state-v1", {"state-v1": secrets.token_bytes(32)}),
        providers=tuple(providers),
    )


@pytest.fixture
def client(db, runtime, config):
    with TestClient(create_app(db, runtime=runtime, human=config), base_url=ORIGIN) as made:
        made.follow_redirects = False
        yield made


@pytest.fixture
def signed_up(db, runtime, world, admin_engine):
    """An approver of the tenant with an address and a password set through a code."""
    tenant = world["human"].tenant_id
    principal = world["human"].principal_id
    with admin_engine.begin() as conn:
        conn.execute(text("SELECT set_config('execbound.tenant_id', :t, true)"), {"t": str(tenant)})
        conn.execute(
            text("UPDATE execbound.principals SET email = :e WHERE principal_id = :p"),
            {"e": ADDRESS, "p": principal},
        )
    reset = issue_reset(db, tenant, world["admin"].principal_id, principal, clock=runtime.clock)
    redeem_reset(db, reset.code, PASSWORD, clock=runtime.clock)
    return {"tenant": tenant, "principal": principal}


def sign_in(client, email=ADDRESS, password=PASSWORD):
    page = client.get("/login")
    values = form_values(page.text, "/session/password")
    return client.post(
        "/session/password",
        data={**values, "email": email, "password": password},
        headers={"Origin": ORIGIN},
    )


@pytest.fixture
def bound_provider(db, runtime, signed_up):
    """A binding retained from before account migration, never an email-based callback."""
    bind_identity(
        db,
        signed_up["tenant"],
        signed_up["principal"],
        provider="google",
        subject=SUBJECT,
        email=ADDRESS,
        display_name="Dana Reyes",
        clock=runtime.clock,
    )
    return signed_up


# The page.


@pytest.mark.parametrize(
    "providers",
    [[StandIn(account=ExternalAccount("google", "explicit-route-subject", ADDRESS, "Dana"))]],
    indirect=True,
)
def test_explicit_provider_link_requires_csrf_and_does_not_issue_anonymous_session(
    client, signed_up, db, runtime, admin_engine
):
    from execbound.surfaces.sessions import load_session

    sign_in(client)
    original_token = client.cookies.get("eb_session")
    session = load_session(db, original_token, clock=runtime.clock)
    with admin_engine.begin() as conn:
        conn.execute(
            text("UPDATE execbound.user_accounts SET email_verified_at=now() WHERE account_id=:a"),
            {"a": session.account_id},
        )
    csrf = client.cookies.get("eb_csrf")
    assert (
        client.post(
            "/account/link/google", data={"csrf": "wrong"}, headers={"Origin": ORIGIN}
        ).status_code
        == 403
    )
    begun = client.post("/account/link/google", data={"csrf": csrf}, headers={"Origin": ORIGIN})
    assert begun.status_code == 303
    from execbound.signin import read_flow

    flow = read_flow(client.cookies.get("eb_signin"))
    result = client.get("/login/google/callback", params={"code": "fresh", "state": flow.state})
    assert landed_at(result, session=False) == "/account/security"
    assert client.cookies.get("eb_session") == original_token
    with admin_engine.connect() as conn:
        assert (
            conn.execute(
                text("SELECT subject FROM execbound.user_identities WHERE account_id=:a"),
                {"a": session.account_id},
            ).scalar_one()
            == "explicit-route-subject"
        )


@pytest.mark.parametrize("classic", [False, True])
def test_password_login_returns_to_the_requested_approval(client, signed_up, classic):
    path = "/approvals/abcdef01-0000-4000-8000-000000000001" + ("/classic" if classic else "")
    redirect = client.get(path, headers={"Accept": "text/html"})
    assert redirect.status_code == 303
    assert redirect.headers["location"].startswith("/login?")
    page = client.get(redirect.headers["location"])
    fields = form_values(page.text, "/session/password")
    result = client.post(
        "/session/password",
        data={**fields, "email": ADDRESS, "password": PASSWORD},
        headers={"Origin": ORIGIN},
    )
    assert result.status_code == 303 and result.headers["location"] == path
    assert any(
        "eb_review_return=" in cookie and "Max-Age=0" in cookie
        for cookie in result.headers.get_list("set-cookie")
    )


@pytest.mark.parametrize(
    "providers",
    [[StandIn(account=ExternalAccount("google", SUBJECT, ADDRESS, "Dana Reyes"))]],
    indirect=True,
)
def test_google_login_returns_to_the_requested_approval(client, providers, bound_provider):
    path = "/approvals/abcdef01-0000-4000-8000-000000000001"
    page = client.get("/login", params={"review": path})
    assert page.status_code == 200
    fields = form_values(page.text, "/login/google")
    start = client.post("/login/google", data=fields, headers={"Origin": ORIGIN})
    state = start.headers["location"].split("state=", 1)[1]
    back = client.get(f"/login/google/callback?code=the-code&state={state}")
    assert landed_at(back) == path


@pytest.fixture
def console_client(db, runtime, config, tmp_path, monkeypatch):
    """A client whose application serves a console build, so a console page answers."""
    from test_console_serving import write_build

    from execbound.surfaces import console as console_module

    root = write_build(tmp_path / "console_dist")
    monkeypatch.setattr(console_module, "build_root", lambda: root)
    with TestClient(create_app(db, runtime=runtime, human=config), base_url=ORIGIN) as made:
        made.follow_redirects = False
        yield made


def _hint_deleted(response) -> bool:
    return any(
        "eb_review_return=" in cookie and "Max-Age=0" in cookie
        for cookie in response.headers.get_list("set-cookie")
    )


def _hints(response) -> list[str]:
    return [
        cookie
        for cookie in response.headers.get_list("set-cookie")
        if cookie.startswith("eb_review_return=") and "Max-Age=0" not in cookie
    ]


@pytest.mark.parametrize(
    "providers",
    [[StandIn(account=ExternalAccount("google", SUBJECT, ADDRESS, "Dana Reyes"))]],
    indirect=True,
)
def test_sn4_password_and_provider_sign_in_return_to_any_console_page(
    console_client, providers, bound_provider
):
    record = str(uuid4())
    place = f"/activity?open={record}&state=DENIED"
    for how in ("password", "google"):
        console_client.cookies.clear()
        redirect = console_client.get(place + "&cursor=x", headers={"Accept": "text/html"})
        assert redirect.status_code == 303
        assert redirect.headers["location"] == "/login?" + urlencode({"review": place})
        page = console_client.get(redirect.headers["location"])
        assert page.status_code == 200
        assert len(_hints(page)) == 1
        if how == "password":
            fields = form_values(page.text, "/session/password")
            result = console_client.post(
                "/session/password",
                data={**fields, "email": ADDRESS, "password": PASSWORD},
                headers={"Origin": ORIGIN},
            )
            assert result.status_code == 303 and result.headers["location"] == place
            assert _hint_deleted(result)
        else:
            fields = form_values(page.text, "/login/google")
            start = console_client.post("/login/google", data=fields, headers={"Origin": ORIGIN})
            state = start.headers["location"].split("state=", 1)[1]
            back = console_client.get(f"/login/google/callback?code=the-code&state={state}")
            assert landed_at(back) == escape(place)
            assert _hint_deleted(back)


# Each refused input of the grammar's own test, as `?review=` would carry it.
UNUSABLE = [
    "https://evil.example/",
    "//evil.example",
    "/approvals/../admin",
    "/%2Fevil",
    "/a\\b",
    "/activity#x",
    "/agents/ABCDEF01-0000-4000-8000-000000000001",
    "/agents/not-a-uuid",
    "/" + "a" * 512,
    "/nowhere",
    "/workspaces/abcdef01-0000-4000-8000-000000000001/approvals/"
    "abcdef01-0000-4000-8000-000000000002",
]


@pytest.mark.parametrize("path", UNUSABLE)
def test_sn5_an_unusable_return_is_ignored_not_refused(client, path):
    page = client.get("/login", params={"review": path})
    assert page.status_code == 200
    assert form_values(page.text, "/session/password") is not None
    assert _hints(page) == []


def test_sn5_an_unusable_return_deletes_an_earlier_one(client, signed_up):
    kept = client.get("/login", params={"review": "/activity"})
    assert len(_hints(kept)) == 1
    ignored = client.get("/login", params={"review": "/nowhere"})
    assert ignored.status_code == 200
    assert _hint_deleted(ignored) and _hints(ignored) == []
    result = sign_in(client)
    assert result.status_code == 303 and result.headers["location"] == "/approvals"


@pytest.mark.parametrize("attack", ["tampered", "expired", "duplicate"])
def test_an_invalid_navigation_cookie_never_controls_the_login_destination(
    client, signed_up, world, attack, monkeypatch
):
    # Expire only the navigation hint, without moving past the database clock-skew fence.
    if attack == "expired":
        monkeypatch.setattr("execbound.surfaces.login_return.TTL", 10)
    path = "/approvals/abcdef01-0000-4000-8000-000000000001"
    client.get("/login", params={"review": path})
    value = client.cookies.get("eb_review_return")
    assert value is not None
    if attack == "expired":
        world["clock"].value += timedelta(seconds=11)
    else:
        client.cookies.clear()
        client.cookies.set("eb_review_return", value + "x" if attack == "tampered" else value)
        if attack == "duplicate":
            client.cookies.set("eb_review_return", value, domain="127.0.0.1", path="/session")
    result = sign_in(client)
    if attack == "duplicate":
        assert result.status_code == 400  # The request boundary rejects duplicate cookies.
        assert "location" not in result.headers
    else:
        assert result.status_code == 303 and result.headers["location"] == "/approvals"


def test_the_page_offers_normal_sign_in_without_a_review_credential(client):
    page = client.get("/login")
    assert page.status_code == 200
    assert 'action="/session/password"' in page.text
    assert 'action="/session"' not in page.text
    assert "Continue with" not in page.text
    # Core names no signup of its own; only a plugin's sign-in link could add one.
    assert "/signup" not in page.text
    assert_secret_free(page)


def test_installation_setup_keeps_its_explicit_credential_exchange(client):
    page = client.get("/login?setup=1")
    assert page.status_code == 200
    assert 'action="/session"' in page.text and "Setup credential" in page.text
    assert "Review credential" not in page.text
    assert client.get("/login?setup=anything").status_code == 400


@pytest.mark.parametrize(
    "providers",
    [
        [StandIn(name="google", label="Google")],
        [StandIn(name="github", label="GitHub")],
        [StandIn(name="google", label="Google"), StandIn(name="github", label="GitHub")],
    ],
    indirect=True,
)
def test_a_configured_provider_gets_a_button_and_nothing_else_does(client, providers):
    page = client.get("/login")
    for provider in providers:
        assert f'action="/login/{provider.name}"' in page.text
        assert f"Continue with {provider.label}" in page.text
    for absent in {"google", "github"} - {provider.name for provider in providers}:
        assert f'action="/login/{absent}"' not in page.text


def test_a_provider_route_answers_404_when_nothing_configured_it(client):
    page = client.get("/login")
    values = form_values(page.text, "/session/password")
    started = client.post(
        "/login/google", data={"csrf": values["csrf"]}, headers={"Origin": ORIGIN}
    )
    assert started.status_code == 404
    assert client.get("/login/github/callback?code=x&state=y").status_code == 404


# The password.


def test_the_address_and_the_password_open_a_session(client, signed_up):
    answer = sign_in(client)
    assert answer.status_code == 303
    assert answer.headers["location"] == "/approvals"
    cookies = answer.headers.get_list("set-cookie")
    assert any("eb_session=" in cookie and "HttpOnly" in cookie for cookie in cookies)
    assert any("eb_csrf=" in cookie and "samesite=strict" in cookie.lower() for cookie in cookies)
    # The session works: the console's own document answers for it.
    assert client.get("/activity", headers={"Accept": "text/html"}).status_code == 200


def test_an_administrator_lands_on_home(client, db, runtime, world, admin_engine):
    """An administrator signs in with a password like anybody else, and lands on Home,
    where the guided setup and the overview are (#243's hosted acceptance, September 24,
    2026, found a new workspace's administrator dropped on an empty Activity page). Their
    address and their code come from owner tooling, because the console refuses an
    administrator as a target, which the store tests hold."""
    tenant, principal = world["admin"].tenant_id, world["admin"].principal_id
    code = owner_code(admin_engine, tenant, principal, "root@example.com")
    redeem_reset(db, code, PASSWORD, clock=runtime.clock)
    answer = sign_in(client, "root@example.com")
    assert answer.status_code == 303
    assert answer.headers["location"] == "/"


def owner_code(admin_engine, tenant, principal, address):
    """What `execbound person-invite` writes over the owner connection, in two statements."""
    reset_id = uuid4()
    code, digest = reset_code(tenant, reset_id)
    with admin_engine.begin() as conn:
        conn.execute(text("SELECT set_config('execbound.tenant_id', :t, true)"), {"t": str(tenant)})
        conn.execute(
            text("UPDATE execbound.principals SET email = :e WHERE principal_id = :p"),
            {"e": address, "p": principal},
        )
        conn.execute(
            text(
                "INSERT INTO execbound.password_resets (tenant_id, reset_id, principal_id, "
                "token_hash, created_by, created_at, expires_at) VALUES "
                "(:t, :r, :p, :h, :p, now(), now() + interval '1 day')"
            ),
            {"t": tenant, "r": reset_id, "p": principal, "h": digest},
        )
    return code


@pytest.mark.parametrize(
    ("email", "password"),
    [
        (ADDRESS, "the wrong one entirely"),
        ("nobody@example.com", PASSWORD),
        ("not-an-address", PASSWORD),
        ("", ""),
    ],
)
def test_a_wrong_address_and_a_wrong_password_are_one_answer(client, signed_up, email, password):
    answer = sign_in(client, email, password)
    assert answer.status_code == 401
    assert WRONG in answer.text
    assert "set-cookie" in answer.headers
    assert "eb_session=" not in answer.headers.get("set-cookie", "")
    assert_secret_free(answer)


def test_the_answer_never_says_which_half_was_wrong(client, signed_up):
    first = sign_in(client, ADDRESS, "the wrong one entirely")
    second = sign_in(client, "nobody@example.com", PASSWORD)
    assert first.status_code == second.status_code
    assert _body(first) == _body(second)


def _body(answer):
    """The page without the CSRF token it mints, which differs by design."""
    return re.sub(r'value="[A-Za-z0-9_-]{43}"', 'value="x"', answer.text)


def test_a_password_post_without_the_cookie_or_with_the_wrong_token_is_refused(client, signed_up):
    page = client.get("/login")
    values = form_values(page.text, "/session/password")
    client.cookies.clear()
    bare = client.post(
        "/session/password",
        data={**values, "email": ADDRESS, "password": PASSWORD},
        headers={"Origin": ORIGIN},
    )
    assert bare.status_code == 403
    page = client.get("/login")
    forged = client.post(
        "/session/password",
        data={"csrf": secrets.token_urlsafe(32), "email": ADDRESS, "password": PASSWORD},
        headers={"Origin": ORIGIN},
    )
    assert forged.status_code == 403


def test_a_password_post_from_another_origin_is_refused(client, signed_up):
    page = client.get("/login")
    values = form_values(page.text, "/session/password")
    answer = client.post(
        "/session/password",
        data={**values, "email": ADDRESS, "password": PASSWORD},
        headers={"Origin": "https://evil.example.net"},
    )
    assert answer.status_code == 403


def test_a_password_post_carrying_an_extra_field_is_refused(client, signed_up):
    page = client.get("/login")
    values = form_values(page.text, "/session/password")
    answer = client.post(
        "/session/password",
        data={**values, "email": ADDRESS, "password": PASSWORD, "principal": str(uuid4())},
        headers={"Origin": ORIGIN},
    )
    assert answer.status_code == 403


def test_attempts_beyond_the_limit_are_refused_even_with_the_right_password(
    db, runtime, config, signed_up
):
    runtime.limiter.limits = RequestLimits(login_attempts=3, client_requests=1000)
    with TestClient(create_app(db, runtime=runtime, human=config), base_url=ORIGIN) as client:
        client.follow_redirects = False
        for _ in range(3):
            assert sign_in(client, ADDRESS, "the wrong one entirely").status_code == 401
        refused = sign_in(client, ADDRESS, PASSWORD)
    assert refused.status_code == 429
    assert refused.headers["Retry-After"]


def test_a_bearer_credential_is_refused_at_the_password_route(client, signed_up, seeded):
    answer = client.post(
        "/session/password",
        data={"csrf": "x", "email": ADDRESS, "password": PASSWORD},
        headers={"Origin": ORIGIN, "Authorization": "Bearer " + seeded["tokens"][0]},
    )
    assert answer.status_code == 403


# The set-password page.


def test_a_code_sets_a_password_and_the_person_then_signs_in(client, db, runtime, world):
    principal = world["human"].principal_id
    minted = _addressed_code(db, runtime, world)
    page = client.get("/set-password")
    values = form_values(page.text, "/set-password")
    answer = client.post(
        "/set-password",
        data={
            **values,
            "code": minted.code,
            "password": NEW_PASSWORD,
            "confirm": NEW_PASSWORD,
        },
        headers={"Origin": ORIGIN},
    )
    assert answer.status_code == 200
    assert "Your password is set" in answer.text
    assert_secret_free(answer, known=(minted.code,))
    assert sign_in_with_password(db, ADDRESS, NEW_PASSWORD, clock=runtime.clock)
    assert principal


def _addressed_code(db, runtime, world):
    """Give the approver an address the way an administrator does, then mint one code."""
    tenant, principal = world["human"].tenant_id, world["human"].principal_id
    set_email(db, tenant, world["admin"].principal_id, principal, ADDRESS)
    return issue_reset(db, tenant, world["admin"].principal_id, principal, clock=runtime.clock)


def test_a_code_that_is_not_valid_says_so_once_and_sets_nothing(client, db, runtime, world):
    page = client.get("/set-password")
    values = form_values(page.text, "/set-password")
    answer = client.post(
        "/set-password",
        data={
            **values,
            "code": f"ebp1.{uuid4()}.{uuid4()}." + "A" * 43,
            "password": NEW_PASSWORD,
            "confirm": NEW_PASSWORD,
        },
        headers={"Origin": ORIGIN},
    )
    assert answer.status_code == 403
    assert "This code is not valid." in answer.text


def test_two_different_passwords_are_refused_before_the_code_is_read(client, db, runtime, world):
    minted = _addressed_code(db, runtime, world)
    page = client.get("/set-password")
    values = form_values(page.text, "/set-password")
    answer = client.post(
        "/set-password",
        data={
            **values,
            "code": minted.code,
            "password": NEW_PASSWORD,
            "confirm": NEW_PASSWORD + "x",
        },
        headers={"Origin": ORIGIN},
    )
    assert answer.status_code == 400
    assert "not the same" in answer.text
    # The code is untouched, so the person can try again.
    assert redeem_reset(db, minted.code, NEW_PASSWORD, clock=runtime.clock)


def test_a_password_outside_ascii_is_compared_like_any_other(client, db, runtime, world):
    """`hmac.compare_digest` refuses a `str` holding a character outside ASCII, so comparing
    the two fields as text answered 503 to a person whose new password had an umlaut in it."""
    minted = _addressed_code(db, runtime, world)
    page = client.get("/set-password")
    values = form_values(page.text, "/set-password")
    chosen = "Grüße aus Köln, 2026"

    def post(confirm: str):
        return client.post(
            "/set-password",
            data={**values, "code": minted.code, "password": chosen, "confirm": confirm},
            headers={"Origin": ORIGIN},
        )

    different = post(chosen + "ß")
    assert different.status_code == 400
    assert "not the same" in different.text
    same = post(chosen)
    assert same.status_code == 200, same.text
    assert "Your password is set" in same.text
    assert sign_in_with_password(db, ADDRESS, chosen, clock=runtime.clock)


def test_a_password_below_the_minimum_is_refused_with_the_length(client, db, runtime, world):
    minted = _addressed_code(db, runtime, world)
    page = client.get("/set-password")
    values = form_values(page.text, "/set-password")
    answer = client.post(
        "/set-password",
        data={**values, "code": minted.code, "password": "short", "confirm": "short"},
        headers={"Origin": ORIGIN},
    )
    assert answer.status_code == 400
    assert "at least 12 characters" in answer.text


# A provider.


def account(provider="google"):
    return ExternalAccount(provider, SUBJECT, ADDRESS, "Dana Reyes")


def started(client):
    page = client.get("/login")
    values = form_values(page.text, "/login/google")
    return client.post("/login/google", data=values, headers={"Origin": ORIGIN})


@pytest.mark.parametrize("providers", [[StandIn(account=account())]], indirect=True)
def test_starting_a_provider_flow_sets_one_lax_cookie_and_redirects(client, providers):
    answer = started(client)
    assert answer.status_code == 303
    assert answer.headers["location"].startswith("https://provider.example/authorize?state=")
    cookie = next(c for c in answer.headers.get_list("set-cookie") if "eb_signin=" in c)
    assert "HttpOnly" in cookie
    assert "samesite=lax" in cookie.lower()
    assert "Path=/" in cookie
    assert "Max-Age=300" in cookie


@pytest.mark.parametrize("providers", [[StandIn(account=account())]], indirect=True)
def test_a_retained_provider_binding_opens_an_account_session(client, providers, bound_provider):
    answer = started(client)
    state = answer.headers["location"].split("state=", 1)[1]
    back = client.get(f"/login/google/callback?code=the-code&state={state}")
    assert landed_at(back) == "/approvals"
    # The transient cookie is deleted on first use, so a replay has nothing to match.
    assert any(
        "eb_signin=" in cookie and "Max-Age=0" in cookie
        for cookie in back.headers.get_list("set-cookie")
    )
    replay = client.get(f"/login/google/callback?code=the-code&state={state}")
    assert replay.status_code == 403
    assert REFUSED in replay.text


@pytest.mark.parametrize("providers", [[StandIn(account=account())]], indirect=True)
def test_a_verified_account_matching_nobody_is_refused_and_creates_nothing(
    client, providers, db, world
):
    answer = started(client)
    state = answer.headers["location"].split("state=", 1)[1]
    back = client.get(f"/login/google/callback?code=the-code&state={state}")
    assert back.status_code == 403
    assert REFUSED in back.text
    with db.transaction(world["human"].tenant_id) as conn:
        assert (
            conn.execute(text("SELECT count(*) FROM execbound.principal_identities")).scalar_one()
            == 0
        )


@pytest.mark.parametrize("providers", [[StandIn(account=account())]], indirect=True)
def test_a_callback_with_a_wrong_state_or_no_cookie_is_refused(client, providers, signed_up):
    answer = started(client)
    state = answer.headers["location"].split("state=", 1)[1]
    wrong = client.get(f"/login/google/callback?code=the-code&state={state}x")
    assert wrong.status_code == 403
    client.cookies.clear()
    bare = client.get(f"/login/google/callback?code=the-code&state={state}")
    assert bare.status_code == 403


@pytest.mark.parametrize("providers", [[StandIn(account=account())]], indirect=True)
def test_a_callback_signs_in_through_the_parameters_the_provider_adds(
    client, providers, bound_provider
):
    """Google's success carries `scope`, and usually `authuser` and `prompt`, beside the code.

    Matching the query exactly refused every one of them with 400 before any sign-in code
    ran, which is how this deployment met Google on 20 September 2026: the provider's own
    success looked like a malformed request. A client ignores what it does not recognise
    (RFC 6749, section 4.1.2); what is still required is a code and the state.
    """
    answer = started(client)
    state = answer.headers["location"].split("state=", 1)[1]
    back = client.get(
        f"/login/google/callback?code=the-code&state={state}"
        "&scope=openid+email&authuser=0&prompt=consent&hd=example.com"
    )
    assert landed_at(back) == "/approvals"


@pytest.mark.parametrize("providers", [[StandIn(account=account())]], indirect=True)
def test_a_code_as_long_as_microsoft_issues_signs_in(client, providers, bound_provider):
    """The same bound as the directory callback's: Entra ID issued a 2,208-character code on
    21 September 2026, over the 2,048 both callbacks allowed, and Microsoft's have run past
    4,000. A provider's code is the provider's to size (RFC 6749, section 4.1.2)."""
    answer = started(client)
    state = answer.headers["location"].split("state=", 1)[1]
    back = client.get("/login/google/callback", params={"code": "c" * 4096, "state": state})
    assert landed_at(back) == "/approvals"


@pytest.mark.parametrize("providers", [[StandIn(account=account())]], indirect=True)
def test_a_missing_or_oversized_code_is_refused_under_its_own_name(
    client, providers, signed_up, caplog
):
    for code in ("", "c" * (MAX_CODE_BYTES + 1)):
        answer = started(client)
        state = answer.headers["location"].split("state=", 1)[1]
        caplog.clear()
        with caplog.at_level(logging.WARNING, logger="execbound"):
            back = client.get("/login/google/callback", params={"code": code, "state": state})
        assert back.status_code == 403 and REFUSED in back.text
        written = [
            getattr(record, "execbound", {}).get("code")
            for record in caplog.records
            if getattr(record, "execbound", {}).get("event") == "sign_in.refused"
        ]
        assert written == ["INVALID_CODE"], (len(code), written)


@pytest.mark.parametrize("providers", [[StandIn(account=account())]], indirect=True)
def test_a_provider_error_is_the_refusal_page_and_never_a_bare_status(
    client, providers, signed_up, caplog
):
    """`error=` is the provider saying no, which is a refusal, not a request nobody could read.

    The person sees the one sentence every refusal shows; the log carries the provider's own
    word, so a cancelled consent and a misconfigured client are told apart afterwards.
    """
    started(client)
    with caplog.at_level(logging.WARNING, logger="execbound"):
        refused = client.get(
            "/login/google/callback?error=access_denied"
            "&error_description=The+user+has+denied+your+application+access"
            "&error_uri=https%3A%2F%2Fdocs.example%2Fapps&state=whatever"
        )
    assert refused.status_code == 403
    assert REFUSED in refused.text
    assert "access_denied" not in refused.text
    written = [
        getattr(record, "execbound", {})
        for record in caplog.records
        if getattr(record, "execbound", {}).get("event") == "sign_in.refused"
    ]
    assert written, [getattr(r, "execbound", None) for r in caplog.records][-5:]
    assert written[-1]["code"] == "PROVIDER_ACCESS_DENIED"
    assert written[-1]["method"] == "google"
    # Names, never values: what the provider said about the person stays out of the log.
    assert written[-1]["parameters"] == "error error_description error_uri state"
    assert "denied your application" not in str(written[-1])


@pytest.mark.parametrize("providers", [[StandIn(account=account())]], indirect=True)
def test_a_callback_repeating_a_key_is_refused(client, providers, signed_up):
    answer = started(client)
    state = answer.headers["location"].split("state=", 1)[1]
    repeated = client.get(f"/login/google/callback?code=a&code=b&state={state}")
    assert repeated.status_code == 403
    assert REFUSED in repeated.text


def test_every_other_route_still_refuses_a_query_key_it_does_not_name(client):
    """The tolerance is the callback's alone, because the query there is the provider's."""
    assert client.get("/login?prompt=none").status_code == 400
    assert client.get("/set-password?code=x").status_code == 400


@pytest.mark.parametrize("providers", [[StandIn(refusal="EMAIL_UNVERIFIED")]], indirect=True)
def test_a_provider_refusal_is_the_same_sentence_as_every_other(client, providers, signed_up):
    answer = started(client)
    state = answer.headers["location"].split("state=", 1)[1]
    back = client.get(f"/login/google/callback?code=the-code&state={state}")
    assert back.status_code == 403
    assert REFUSED in back.text
    assert "EMAIL_UNVERIFIED" not in back.text


@pytest.mark.parametrize("providers", [[StandIn(account=account())]], indirect=True)
def test_the_subject_identifies_the_person_after_the_first_sign_in(
    client, providers, db, runtime, world, bound_provider, admin_engine
):
    """The retained subject identifies the account, so a
    changed address at the provider does not lock anybody out or let anybody in."""
    answer = started(client)
    state = answer.headers["location"].split("state=", 1)[1]
    assert landed_at(client.get(f"/login/google/callback?code=c&state={state}")) == "/approvals"
    moved = StandIn(account=ExternalAccount("google", SUBJECT, "moved@example.net", "Dana"))
    config = HumanConfig(
        ORIGIN,
        TokenKeys("state-v1", {"state-v1": secrets.token_bytes(32)}),
        providers=(moved,),
    )
    with TestClient(create_app(db, runtime=runtime, human=config), base_url=ORIGIN) as second:
        second.follow_redirects = False
        again = started(second)
        state = again.headers["location"].split("state=", 1)[1]
        back = second.get(f"/login/google/callback?code=c&state={state}")
    assert landed_at(back) == "/approvals"


@pytest.mark.parametrize("providers", [[StandIn(account=account())]], indirect=True)
def test_a_provider_session_is_an_ordinary_session_that_logs_out(client, providers, bound_provider):
    answer = started(client)
    state = answer.headers["location"].split("state=", 1)[1]
    assert landed_at(client.get(f"/login/google/callback?code=c&state={state}")) == "/approvals"
    page = client.get("/settings", headers={"Accept": "text/html"})
    assert page.status_code == 200
    csrf = client.cookies.get("eb_csrf")
    out = client.post("/session/logout", data={"csrf": csrf}, headers={"Origin": ORIGIN})
    assert out.status_code == 303
    # The session is gone, so the console's document is no longer served for it.
    assert client.get("/settings", headers={"Accept": "text/html"}).status_code != 200


# A plugin's provider signup point (#504): the callback dispatches to it only when its own
# intent cookie, minted by `start_provider_flow(signup=True)`, matches the flow that just
# completed. Nothing here is the hosted plugin's own page; the fake `finish`/`refused` pair
# stands in for whatever a plugin registers, as the `StandIn` provider stands in for Google.


def _registered(monkeypatch, runtime_, finish, refused):
    """Register a fake `ProviderSignup`, the way loading a plugin would fill it in."""
    monkeypatch.setattr(
        runtime_,
        "plugins",
        replace(runtime_.plugins, provider_signup=ProviderSignup(finish, refused)),
    )


def _signup_intent(answer):
    """The flow's own state, and the digest a signup's own start route sets beside it."""
    state = answer.headers["location"].split("state=", 1)[1]
    return state, hashlib.sha256(state.encode()).hexdigest()


def _never(*args, **kwargs):
    raise AssertionError("not reached")


def _refusals(caplog):
    """Every `sign_in.refused` line this test captured, as `(code, level)` pairs in order."""
    return [
        (getattr(record, "execbound", {})["code"], record.levelname)
        for record in caplog.records
        if getattr(record, "execbound", {}).get("event") == "sign_in.refused"
    ]


def _created_nothing(admin_engine, tenant_id):
    """Counts of the three tables a provider signup can write: a personal account, its
    `user_identities` binding, and a tenant's legacy `principal_identities` binding. The
    first two are not tenant-scoped, so they are read over `admin_engine` (BYPASSRLS)
    rather than `db.transaction(tenant_id)`, which would show zero of them either way and
    prove nothing."""
    with admin_engine.begin() as conn:
        counts = {
            table: conn.execute(text(f"SELECT count(*) FROM execbound.{table}")).scalar_one()
            for table in ("user_accounts", "user_identities")
        }
        counts["principal_identities"] = conn.execute(
            text("SELECT count(*) FROM execbound.principal_identities WHERE tenant_id=:t"),
            {"t": tenant_id},
        ).scalar_one()
    return counts


@pytest.mark.parametrize("providers", [[StandIn(account=account())]], indirect=True)
def test_a_registered_signup_point_completes_the_flow_its_own_page_started(
    client, providers, runtime, monkeypatch
):
    seen = []

    async def finish(rt, cfg, request, acct):
        seen.append(acct)
        return PlainTextResponse("named the workspace")

    _registered(monkeypatch, runtime, finish, _never)
    answer = started(client)
    state, intent = _signup_intent(answer)
    client.cookies.set("eb_provider_signup", intent)
    back = client.get(f"/login/google/callback?code=the-code&state={state}")
    assert back.status_code == 200 and "named the workspace" in back.text
    assert seen == [account()]
    for name in ("eb_signin", "eb_provider_link", "eb_provider_signup"):
        assert any(
            f"{name}=" in cookie and "Max-Age=0" in cookie
            for cookie in back.headers.get_list("set-cookie")
        ), (name, back.headers.get_list("set-cookie"))


@pytest.mark.parametrize("providers", [[StandIn(account=account())]], indirect=True)
def test_a_plugins_own_start_route_sets_the_intent_a_browser_then_carries_back(
    client, providers, config, runtime, monkeypatch
):
    """Nothing in core ever calls `start_provider_flow(signup=True)`; a plugin's own page
    does (`/signup/google`), so this calls it directly rather than through a core route,
    the way `test_starting_a_provider_flow_sets_one_lax_cookie_and_redirects` calls the
    ordinary one through `/login/google`. The intent cookie it sets, fed back through an
    ordinary request, is what lets the callback reach a registered `finish`.
    """
    seen = []

    async def finish(rt, cfg, request, acct):
        seen.append(acct)
        return PlainTextResponse("named the workspace")

    _registered(monkeypatch, runtime, finish, _never)

    minted = start_provider_flow(config, providers[0], signup=True)
    assert minted.status_code == 303
    assert minted.headers["location"].startswith("https://provider.example/authorize?state=")
    state = minted.headers["location"].split("state=", 1)[1]
    # `minted` is the plain `Response` the function returns, not a client's own: its
    # headers are Starlette's `MutableHeaders`, whose list accessor is `getlist`, never
    # `get_list`, the name every other assertion in this file reads from an httpx response.
    cookies = minted.headers.getlist("set-cookie")

    intent_cookie = next(c for c in cookies if c.startswith("eb_provider_signup="))
    intent_value = intent_cookie.split("=", 2)[1].split(";", 1)[0]
    assert intent_value == hashlib.sha256(state.encode()).hexdigest()
    assert "HttpOnly" in intent_cookie
    assert "samesite=lax" in intent_cookie.lower()
    assert "Path=/" in intent_cookie
    assert "Max-Age=300" in intent_cookie
    assert ("Secure" in intent_cookie) == config.secure

    signin_cookie = next(c for c in cookies if c.startswith("eb_signin="))
    signin_value = signin_cookie.split("=", 2)[1].split(";", 1)[0]
    link_cookie = next(c for c in cookies if c.startswith("eb_provider_link="))
    assert "Max-Age=0" in link_cookie

    # Only the two cookies this flow actually set go to the client; the deleted
    # `provider_link` carries no value of its own and would otherwise look present.
    client.cookies.set("eb_signin", signin_value)
    client.cookies.set("eb_provider_signup", intent_value)
    back = client.get(f"/login/google/callback?code=the-code&state={state}")
    assert back.status_code == 200 and "named the workspace" in back.text
    assert seen == [account()]


@pytest.mark.parametrize("providers", [[StandIn(account=account())]], indirect=True)
def test_a_registered_signup_point_returning_none_signs_a_bound_subject_in(
    client, providers, runtime, monkeypatch, bound_provider
):
    async def finish(rt, cfg, request, acct):
        return None

    _registered(monkeypatch, runtime, finish, _never)
    answer = started(client)
    state, intent = _signup_intent(answer)
    client.cookies.set("eb_provider_signup", intent)
    back = client.get(f"/login/google/callback?code=the-code&state={state}")
    assert landed_at(back) == "/approvals"


@pytest.mark.parametrize("providers", [[StandIn(account=account())]], indirect=True)
def test_a_registered_signup_point_returning_none_for_an_unbound_subject_is_refused(
    client, providers, runtime, monkeypatch, db, world, admin_engine, caplog
):
    """`finish` answering `None` defers to `provider_sign_in`'s own question. An unbound
    subject fails that exactly as `/login` would, and because the signup intent is still
    present, the refusal the callback shows is the plugin's own page, not core's bare one.
    """

    async def finish(rt, cfg, request, acct):
        return None

    def refused(rt, cfg, request):
        return PlainTextResponse("refused page", status_code=403)

    _registered(monkeypatch, runtime, finish, refused)
    answer = started(client)
    state, intent = _signup_intent(answer)
    client.cookies.set("eb_provider_signup", intent)
    with caplog.at_level(logging.WARNING, logger="execbound"):
        back = client.get(f"/login/google/callback?code=the-code&state={state}")
    assert back.status_code == 403
    assert "refused page" in back.text
    assert not any(c.startswith("eb_session=") for c in back.headers.get_list("set-cookie"))
    assert _refusals(caplog)[-1] == ("NO_ACCOUNT", "WARNING")
    assert _created_nothing(admin_engine, world["human"].tenant_id) == {
        "user_accounts": 0,
        "user_identities": 0,
        "principal_identities": 0,
    }


@pytest.mark.parametrize("providers", [[StandIn(account=account())]], indirect=True)
def test_a_registered_signup_point_returning_none_for_a_revoked_binding_is_refused(
    client, providers, runtime, monkeypatch, db, world, admin_engine, bound_provider, caplog
):
    """A binding `provider_sign_in` once adopted and then revoked can no longer sign in
    either: the same `NO_ACCOUNT` an unbound subject gets, and the same plugin page."""
    # Adopt the legacy binding with an ordinary sign-in first, then revoke the
    # `user_identities` row it left, the way `test_subject_known_...` revokes one.
    first = started(client)
    state = first.headers["location"].split("state=", 1)[1]
    assert landed_at(client.get(f"/login/google/callback?code=c&state={state}")) == "/approvals"
    with admin_engine.begin() as conn:
        account_id = conn.execute(
            text("SELECT account_id FROM execbound.user_identities WHERE subject=:s"),
            {"s": SUBJECT},
        ).scalar_one()
        conn.execute(
            text("UPDATE execbound.user_identities SET revoked_at=now() WHERE account_id=:a"),
            {"a": account_id},
        )
    client.cookies.clear()
    before = _created_nothing(admin_engine, world["human"].tenant_id)

    async def finish(rt, cfg, request, acct):
        return None

    def refused(rt, cfg, request):
        return PlainTextResponse("refused page", status_code=403)

    _registered(monkeypatch, runtime, finish, refused)
    answer = started(client)
    state, intent = _signup_intent(answer)
    client.cookies.set("eb_provider_signup", intent)
    with caplog.at_level(logging.WARNING, logger="execbound"):
        back = client.get(f"/login/google/callback?code=the-code&state={state}")
    assert back.status_code == 403
    assert "refused page" in back.text
    assert not any(c.startswith("eb_session=") for c in back.headers.get_list("set-cookie"))
    assert _refusals(caplog)[-1] == ("NO_ACCOUNT", "WARNING")
    assert _created_nothing(admin_engine, world["human"].tenant_id) == before


@pytest.mark.parametrize("providers", [[StandIn(account=account())]], indirect=True)
def test_a_mismatched_signup_intent_never_calls_finish_and_creates_nothing(
    client, providers, runtime, monkeypatch, db, world, admin_engine, bound_provider, caplog
):
    """`bound_provider` is the point: this very subject would sign in if the mismatch fell
    through to the ordinary binding lookup below, so a session or a second account is what
    a broken guard would actually produce here, not a bare absence this fixture alone could
    ever tell apart from a guard that never ran.
    """
    called = []

    async def finish(rt, cfg, request, acct):
        called.append(acct)
        return PlainTextResponse("should not run")

    def refused(rt, cfg, request):
        return PlainTextResponse("refused page", status_code=403)

    _registered(monkeypatch, runtime, finish, refused)
    answer = started(client)
    state, _ = _signup_intent(answer)
    client.cookies.set("eb_provider_signup", hashlib.sha256(b"not-the-flows-state").hexdigest())
    with caplog.at_level(logging.WARNING, logger="execbound"):
        back = client.get(f"/login/google/callback?code=the-code&state={state}")
    assert back.status_code == 403
    assert "refused page" in back.text
    assert called == []
    assert not any(c.startswith("eb_session=") for c in back.headers.get_list("set-cookie"))
    for name in ("eb_signin", "eb_provider_signup"):
        assert any(
            f"{name}=" in cookie and "Max-Age=0" in cookie
            for cookie in back.headers.get_list("set-cookie")
        ), name
    assert _refusals(caplog)[-1] == ("SIGNUP_REFUSED", "WARNING")
    # `bound_provider` already left its one legacy row; the mismatch creates no second one.
    assert _created_nothing(admin_engine, world["human"].tenant_id) == {
        "user_accounts": 0,
        "user_identities": 0,
        "principal_identities": 1,
    }


@pytest.mark.parametrize("providers", [[StandIn(account=account())]], indirect=True)
def test_an_intent_with_no_registered_point_falls_back_to_the_login_page(
    client, providers, db, world, admin_engine, bound_provider, caplog
):
    """`bound_provider` is the point here too: with no plugin registered, a fall-through to
    the ordinary binding lookup would sign this very subject in rather than find nobody."""
    answer = started(client)
    state, intent = _signup_intent(answer)
    client.cookies.set("eb_provider_signup", intent)
    with caplog.at_level(logging.WARNING, logger="execbound"):
        back = client.get(f"/login/google/callback?code=the-code&state={state}")
    assert back.status_code == 403
    assert REFUSED in back.text
    assert not any(c.startswith("eb_session=") for c in back.headers.get_list("set-cookie"))
    # The refusal is `SIGNUP_REFUSED`, found with no plugin ever asked: a mutation that let
    # a matching digest fall through to `signup.finish` with `signup` still `None` would
    # crash into the generic `PLUGIN_FAILED` handler instead, showing the same page for the
    # wrong reason, which this line catches and the status and text above alone would not.
    assert _refusals(caplog)[-1] == ("SIGNUP_REFUSED", "WARNING")
    assert _created_nothing(admin_engine, world["human"].tenant_id) == {
        "user_accounts": 0,
        "user_identities": 0,
        "principal_identities": 1,
    }


@pytest.mark.parametrize("providers", [[StandIn(account=account())]], indirect=True)
def test_a_malformed_intent_cookie_refuses_as_signup_refused_never_503(
    client, providers, runtime, monkeypatch, bound_provider, caplog
):
    """The intent cookie's shape is checked before any comparison (`_SIGNUP_INTENT`): a
    SHA-256 hex digest, lowercase, nothing else. A point is registered, so what holds is
    only this: the hex-shape check and the bytes comparison below it are jointly what keep
    a malformed intent from ever reaching a 503, by answering `SIGNUP_REFUSED` instead;
    `bound_provider` also proves the refusal is real, not an accident of there being nobody
    to sign in anyway, and `providers[0].seen` being non-empty proves the exchange ran
    before this guard ever looked at the cookie.
    """
    called = []

    async def finish(rt, cfg, request, acct):
        called.append(acct)
        return PlainTextResponse("should not run")

    def refused(rt, cfg, request):
        return PlainTextResponse("refused page", status_code=403)

    _registered(monkeypatch, runtime, finish, refused)
    for bad_intent in ("g" * 64, "a" * 63, ("a" * 64).upper()):
        answer = started(client)
        state = answer.headers["location"].split("state=", 1)[1]
        client.cookies.set("eb_provider_signup", bad_intent)
        with caplog.at_level(logging.WARNING, logger="execbound"):
            back = client.get(f"/login/google/callback?code=the-code&state={state}")
        assert back.status_code == 403, bad_intent
        assert "refused page" in back.text, bad_intent
        assert not any(c.startswith("eb_session=") for c in back.headers.get_list("set-cookie")), (
            bad_intent
        )
        assert _refusals(caplog)[-1] == ("SIGNUP_REFUSED", "WARNING"), bad_intent
    assert called == []
    assert providers[0].seen


@pytest.mark.parametrize("providers", [[StandIn(account=account())]], indirect=True)
def test_a_non_ascii_intent_cookie_refuses_as_signup_refused_never_503(
    client, providers, runtime, monkeypatch, bound_provider, caplog
):
    """A non-ASCII cookie value cannot be written through `client.cookies.set`: the test
    client itself refuses to encode it as a header, exactly as a real HTTP client would
    never send one raw. What a server can receive instead is a `Cookie` header whose bytes
    are not ASCII-only (an intermediary rewriting one, or a client sending its own encoding
    of a byte string), which Starlette decodes as `latin-1` and hands this file a `str`
    that still is not 64 lowercase hex characters, and is not ASCII either. The raw header
    is built here, in the one request this test sends, with the flow's own `signin` cookie
    carried alongside it by hand, because setting it through the jar first and this header
    second would let the jar overwrite what this builds; a point is registered for the same
    reason the malformed-shape test registers one. What holds is only this, the same as that
    test: the hex-shape check and the bytes comparison are jointly what keep a non-ASCII
    intent from a 503, never a claim that the comparison itself runs — the shape check
    alone already fails a non-ASCII value, by `or` short-circuit, before `hmac.compare_digest`
    would ever see it.
    """
    called = []

    async def finish(rt, cfg, request, acct):
        called.append(acct)
        return PlainTextResponse("should not run")

    def refused(rt, cfg, request):
        return PlainTextResponse("refused page", status_code=403)

    _registered(monkeypatch, runtime, finish, refused)
    answer = started(client)
    state = answer.headers["location"].split("state=", 1)[1]
    signin_value = client.cookies.get("eb_signin")
    client.cookies.clear()
    cookie_header = f"eb_signin={signin_value}; eb_provider_signup=".encode("ascii") + (
        "é" * 64
    ).encode("utf-8")
    with caplog.at_level(logging.WARNING, logger="execbound"):
        back = client.get(
            f"/login/google/callback?code=the-code&state={state}",
            headers=[(b"Cookie", cookie_header)],
        )
    assert back.status_code == 403
    assert "refused page" in back.text
    assert not any(c.startswith("eb_session=") for c in back.headers.get_list("set-cookie"))
    assert called == []
    assert _refusals(caplog)[-1] == ("SIGNUP_REFUSED", "WARNING")
    assert providers[0].seen


@pytest.mark.parametrize("providers", [[StandIn(account=account())]], indirect=True)
def test_a_non_ascii_state_refuses_as_invalid_state_never_503(client, providers, caplog):
    """The state is the provider's own query parameter to size and fill, as untrusted as the
    rest of its query, and is compared as bytes for the same reason the intent cookie is: a
    `str` carrying a non-ASCII character is exactly what `hmac.compare_digest` refuses to
    compare directly, which a comparison outside the `try/except SignInRefused` around it
    would turn into an unhandled exception and a 503 instead of this refusal.
    """
    started(client)
    with caplog.at_level(logging.WARNING, logger="execbound"):
        back = client.get("/login/google/callback", params={"code": "the-code", "state": "é" * 64})
    assert back.status_code == 403
    assert REFUSED in back.text
    assert _refusals(caplog)[-1] == ("INVALID_STATE", "WARNING")


@pytest.mark.parametrize("providers", [[StandIn(refusal="EMAIL_UNVERIFIED")]], indirect=True)
def test_a_providers_own_refusal_during_a_signup_flow_shows_the_plugins_page(
    client, providers, runtime, monkeypatch
):
    def refused(rt, cfg, request):
        return PlainTextResponse("try the email form instead", status_code=403)

    _registered(monkeypatch, runtime, _never, refused)
    answer = started(client)
    state, intent = _signup_intent(answer)
    client.cookies.set("eb_provider_signup", intent)
    back = client.get(f"/login/google/callback?code=the-code&state={state}")
    assert back.status_code == 403
    assert "try the email form instead" in back.text
    assert "EMAIL_UNVERIFIED" not in back.text
    for name in ("eb_signin", "eb_provider_signup"):
        assert any(
            f"{name}=" in cookie and "Max-Age=0" in cookie
            for cookie in back.headers.get_list("set-cookie")
        ), name


@pytest.mark.parametrize("providers", [[StandIn(account=account())]], indirect=True)
def test_a_providers_cancelled_consent_during_a_signup_flow_shows_the_plugins_page(
    client, providers, runtime, monkeypatch
):
    def refused(rt, cfg, request):
        return PlainTextResponse("try the email form instead", status_code=403)

    _registered(monkeypatch, runtime, _never, refused)
    answer = started(client)
    _, intent = _signup_intent(answer)
    client.cookies.set("eb_provider_signup", intent)
    back = client.get("/login/google/callback?error=access_denied&state=whatever")
    assert back.status_code == 403
    assert "try the email form instead" in back.text


@pytest.mark.parametrize("providers", [[StandIn(refusal="EMAIL_UNVERIFIED")]], indirect=True)
def test_a_refused_page_that_fails_falls_back_to_the_login_page(
    client, providers, runtime, monkeypatch, caplog
):
    """`refused` is a plugin's own page too, and can fail the same way `finish` can. Its
    failure is never let through either: the callback falls back to core's own login page,
    at the same generic sentence every other refusal shows, with its text never logged."""

    def refused(rt, cfg, request):
        raise RuntimeError("secret-from-the-plugin")

    _registered(monkeypatch, runtime, _never, refused)
    answer = started(client)
    state, intent = _signup_intent(answer)
    client.cookies.set("eb_provider_signup", intent)
    with caplog.at_level(logging.WARNING, logger="execbound"):
        back = client.get(f"/login/google/callback?code=the-code&state={state}")
    assert back.status_code == 403
    assert REFUSED in back.text
    assert "secret-from-the-plugin" not in back.text
    assert _refusals(caplog)[-1] == ("PLUGIN_FAILED", "ERROR")
    assert "secret-from-the-plugin" not in caplog.text
    for name in ("eb_signin", "eb_provider_link", "eb_provider_signup"):
        assert any(
            f"{name}=" in cookie and "Max-Age=0" in cookie
            for cookie in back.headers.get_list("set-cookie")
        ), name


@pytest.mark.parametrize("providers", [[StandIn(refusal="EMAIL_UNVERIFIED")]], indirect=True)
def test_a_refused_page_raising_an_http_exception_propagates(
    client, providers, runtime, monkeypatch
):
    def refused(rt, cfg, request):
        raise HTTPException(503, "plugin unavailable")

    _registered(monkeypatch, runtime, _never, refused)
    answer = started(client)
    state, intent = _signup_intent(answer)
    client.cookies.set("eb_provider_signup", intent)
    back = client.get(f"/login/google/callback?code=the-code&state={state}")
    assert back.status_code == 503


@pytest.mark.parametrize("providers", [[StandIn(account=account())]], indirect=True)
def test_finish_raising_sign_in_refused_gives_the_ordinary_refusal(
    client, providers, runtime, monkeypatch, caplog
):
    async def finish(rt, cfg, request, acct):
        raise SignInRefused("SOME_PLUGIN_CODE")

    def refused(rt, cfg, request):
        return PlainTextResponse("try the email form instead", status_code=403)

    _registered(monkeypatch, runtime, finish, refused)
    answer = started(client)
    state, intent = _signup_intent(answer)
    client.cookies.set("eb_provider_signup", intent)
    with caplog.at_level(logging.WARNING, logger="execbound"):
        back = client.get(f"/login/google/callback?code=the-code&state={state}")
    assert back.status_code == 403
    assert "try the email form instead" in back.text
    assert "SOME_PLUGIN_CODE" not in back.text
    # A well-formed code is logged exactly as the plugin raised it, never replaced with
    # `PLUGIN_FAILED`: only a malformed one is (below).
    assert _refusals(caplog)[-1] == ("SOME_PLUGIN_CODE", "WARNING")


@pytest.mark.parametrize("providers", [[StandIn(account=account())]], indirect=True)
def test_finish_raising_sign_in_refused_with_a_malformed_code_is_logged_as_plugin_failed(
    client, providers, runtime, monkeypatch, caplog
):
    """A plugin's own `SignInRefused(code)` is logged verbatim only when `code` is a string
    shaped like every other one this file logs, `[A-Z_]{1,64}`; anything else is a plugin's
    mistake to word as a code, not a code, and never reaches the log as written."""

    async def finish(rt, cfg, request, acct):
        raise SignInRefused("not a valid code!")

    def refused(rt, cfg, request):
        return PlainTextResponse("try the email form instead", status_code=403)

    _registered(monkeypatch, runtime, finish, refused)
    answer = started(client)
    state, intent = _signup_intent(answer)
    client.cookies.set("eb_provider_signup", intent)
    with caplog.at_level(logging.WARNING, logger="execbound"):
        back = client.get(f"/login/google/callback?code=the-code&state={state}")
    assert back.status_code == 403
    assert "not a valid code!" not in back.text
    assert _refusals(caplog)[-1] == ("PLUGIN_FAILED", "ERROR")
    assert "not a valid code!" not in caplog.text


@pytest.mark.parametrize("providers", [[StandIn(account=account())]], indirect=True)
def test_finish_raising_password_unavailable_answers_503_exactly_as_the_binding_lookup_does(
    client, providers, runtime, monkeypatch, caplog
):
    """`finish` has its own store to fail in, and an unavailable one is answered exactly as
    the ordinary binding lookup below answers the very same fault (`_link`'s own
    `PasswordError("PASSWORD_UNAVAILABLE")` branch): a 503, because retrying is the right
    answer to it alone, never the plugin's own refused page."""

    async def finish(rt, cfg, request, acct):
        raise PasswordError("PASSWORD_UNAVAILABLE")

    _registered(monkeypatch, runtime, finish, _never)
    answer = started(client)
    state, intent = _signup_intent(answer)
    client.cookies.set("eb_provider_signup", intent)
    with caplog.at_level(logging.WARNING, logger="execbound"):
        back = client.get(f"/login/google/callback?code=the-code&state={state}")
    assert back.status_code == 503
    assert _refusals(caplog)[-1] == ("PASSWORD_UNAVAILABLE", "ERROR")


@pytest.mark.parametrize("providers", [[StandIn(account=account())]], indirect=True)
def test_finish_raising_password_error_with_a_malformed_code_is_logged_as_plugin_failed(
    client, providers, runtime, monkeypatch, caplog
):
    """`finish`'s store can raise `PasswordError` with any code of its own, not only
    `PASSWORD_UNAVAILABLE`, and a careless one could put an address in it rather than a
    code. That value goes through the same shape check every other plugin code does
    (`_plugin_refusal`), the one `SignInRefused` already gets above, so it is logged as
    `PLUGIN_FAILED` and never reaches the page or the log as if it were a code."""

    async def finish(rt, cfg, request, acct):
        raise PasswordError("dana@example.com")

    def refused(rt, cfg, request):
        return PlainTextResponse("try the email form instead", status_code=403)

    _registered(monkeypatch, runtime, finish, refused)
    answer = started(client)
    state, intent = _signup_intent(answer)
    client.cookies.set("eb_provider_signup", intent)
    with caplog.at_level(logging.WARNING, logger="execbound"):
        back = client.get(f"/login/google/callback?code=the-code&state={state}")
    assert back.status_code == 403
    assert "dana@example.com" not in back.text
    assert _refusals(caplog)[-1] == ("PLUGIN_FAILED", "ERROR")
    assert "dana@example.com" not in caplog.text


@pytest.mark.parametrize("providers", [[StandIn(account=account())]], indirect=True)
def test_finish_raising_an_unexpected_error_is_refused_and_logged_as_plugin_failed(
    client, providers, runtime, monkeypatch, caplog
):
    async def finish(rt, cfg, request, acct):
        raise RuntimeError("secret-from-the-plugin")

    def refused(rt, cfg, request):
        return PlainTextResponse("try the email form instead", status_code=403)

    _registered(monkeypatch, runtime, finish, refused)
    answer = started(client)
    state, intent = _signup_intent(answer)
    client.cookies.set("eb_provider_signup", intent)
    with caplog.at_level(logging.WARNING, logger="execbound"):
        back = client.get(f"/login/google/callback?code=the-code&state={state}")
    assert back.status_code == 403
    assert "try the email form instead" in back.text
    assert _refusals(caplog)[-1] == ("PLUGIN_FAILED", "ERROR")
    assert "secret-from-the-plugin" not in caplog.text


@pytest.mark.parametrize("providers", [[StandIn(account=account())]], indirect=True)
def test_finish_raising_an_http_exception_propagates_rather_than_being_swallowed(
    client, providers, runtime, monkeypatch
):
    async def finish(rt, cfg, request, acct):
        raise HTTPException(503, "plugin unavailable")

    _registered(monkeypatch, runtime, finish, _never)
    answer = started(client)
    state, intent = _signup_intent(answer)
    client.cookies.set("eb_provider_signup", intent)
    back = client.get(f"/login/google/callback?code=the-code&state={state}")
    assert back.status_code == 503


@pytest.mark.parametrize("providers", [[StandIn(account=account())]], indirect=True)
def test_finish_raising_unsafe_database_role_propagates_rather_than_being_swallowed(
    client, providers, runtime, monkeypatch
):
    """`UnsafeDatabaseRole` is a database-safety refusal, not a plugin's ordinary failure: it
    propagates to the application's own handler, which answers it the same way everywhere
    else, rather than being swallowed into the generic `PLUGIN_FAILED` page."""

    async def finish(rt, cfg, request, acct):
        raise UnsafeDatabaseRole("a detail nobody should see")

    _registered(monkeypatch, runtime, finish, _never)
    answer = started(client)
    state, intent = _signup_intent(answer)
    client.cookies.set("eb_provider_signup", intent)
    back = client.get(f"/login/google/callback?code=the-code&state={state}")
    assert back.status_code == 503
    assert "a detail nobody should see" not in back.text


@pytest.mark.parametrize("providers", [[StandIn(account=account())]], indirect=True)
def test_finish_answering_something_that_is_not_a_response_is_plugin_failed(
    client, providers, runtime, monkeypatch, caplog
):
    """`finish`'s contract is `Response | None`; a plugin that answers anything else (a
    string, say, from forgetting to wrap it) is the same mistake as any other unexpected
    failure, not an `AttributeError` this file lets crash into a bare 503: it is checked
    with `isinstance(answer, Response)` rather than only `is not None`, so this is caught
    and shown as the plugin's own refused page, logged as `PLUGIN_FAILED`."""

    async def finish(rt, cfg, request, acct):
        return "not a response"

    def refused(rt, cfg, request):
        return PlainTextResponse("try the email form instead", status_code=403)

    _registered(monkeypatch, runtime, finish, refused)
    answer = started(client)
    state, intent = _signup_intent(answer)
    client.cookies.set("eb_provider_signup", intent)
    with caplog.at_level(logging.WARNING, logger="execbound"):
        back = client.get(f"/login/google/callback?code=the-code&state={state}")
    assert back.status_code == 403
    assert "try the email form instead" in back.text
    assert _refusals(caplog)[-1] == ("PLUGIN_FAILED", "ERROR")


@pytest.mark.parametrize("providers", [[StandIn(account=account())]], indirect=True)
def test_an_ordinary_login_flow_never_calls_a_registered_signup_point(
    client, providers, db, world, runtime, monkeypatch, admin_engine
):
    """T4.21 holds for a flow started at `/login`: an unknown subject creates no row, and a
    plugin's registered point is never asked, because no intent cookie names this flow as
    one of its own."""
    called = []

    async def finish(rt, cfg, request, acct):
        called.append(acct)
        return None

    def refused(rt, cfg, request):
        called.append("refused")
        return PlainTextResponse("should not run", status_code=403)

    _registered(monkeypatch, runtime, finish, refused)
    answer = started(client)
    state = answer.headers["location"].split("state=", 1)[1]
    back = client.get(f"/login/google/callback?code=the-code&state={state}")
    assert back.status_code == 403
    assert REFUSED in back.text
    assert called == []
    assert _created_nothing(admin_engine, world["human"].tenant_id) == {
        "user_accounts": 0,
        "user_identities": 0,
        "principal_identities": 0,
    }


@pytest.mark.parametrize("providers", [[StandIn(account=account())]], indirect=True)
def test_starting_sign_in_or_a_link_each_delete_a_leftover_signup_intent(
    client, providers, signed_up, db, runtime, admin_engine
):
    from execbound.surfaces.sessions import load_session

    client.cookies.set("eb_provider_signup", "stale-value")
    login_start = started(client)
    assert any(
        "eb_provider_signup=" in cookie and "Max-Age=0" in cookie
        for cookie in login_start.headers.get_list("set-cookie")
    )

    sign_in(client)
    session = load_session(db, client.cookies.get("eb_session"), clock=runtime.clock)
    with admin_engine.begin() as conn:
        conn.execute(
            text("UPDATE execbound.user_accounts SET email_verified_at=now() WHERE account_id=:a"),
            {"a": session.account_id},
        )
    csrf = client.cookies.get("eb_csrf")
    client.cookies.set("eb_provider_signup", "stale-value")
    link_start = client.post(
        "/account/link/google", data={"csrf": csrf}, headers={"Origin": ORIGIN}
    )
    assert link_start.status_code == 303
    assert any(
        "eb_provider_signup=" in cookie and "Max-Age=0" in cookie
        for cookie in link_start.headers.get_list("set-cookie")
    )


def test_a_session_lasts_no_longer_than_a_credential_one(db, runtime, signed_up):
    identity = sign_in_with_password(db, ADDRESS, PASSWORD, clock=runtime.clock)
    assert identity.expires_at - runtime.clock.now() == SIGN_IN_LIFETIME == timedelta(days=2)


# The pages' policy names exactly the hosts the deployment's own buttons redirect to.


def test_no_provider_leaves_the_pages_policy_as_it_was(client):
    page = client.get("/login")
    policy = page.headers["Content-Security-Policy"]
    assert "form-action 'self';" in policy
    assert "https://" not in policy


@pytest.mark.parametrize(
    "providers",
    [
        [StandIn(account=account(), name="google", label="Google")],
        [
            StandIn(account=account(), name="google", label="Google"),
            StandIn(
                account=account("github"),
                name="github",
                label="GitHub",
                authorization_origin="https://github.example",
            ),
        ],
    ],
    indirect=True,
)
def test_a_configured_provider_is_named_in_form_action_and_nothing_else_is(client, providers):
    """`form-action` governs the redirect a form submission follows, so a provider's
    authorization host has to be in the policy or the browser aborts the navigation. Each
    host is pinned in that provider's module and is here only because a block named it."""
    policy = client.get("/login").headers["Content-Security-Policy"]
    for provider in providers:
        assert provider.authorization_origin in policy
    assert "accounts.google.com" not in policy
    assert policy.count("form-action") == 1


@pytest.mark.parametrize("providers", [[StandIn(account=account())]], indirect=True)
def test_the_callback_is_limited_before_it_calls_the_provider(db, runtime, config, providers):
    """Completing a flow makes this server call the provider, so the peer limit has to bound
    that outbound call rather than only the lookup behind it."""
    runtime.limiter.limits = RequestLimits(client_requests=2, login_attempts=100)
    with TestClient(create_app(db, runtime=runtime, human=config), base_url=ORIGIN) as client:
        client.follow_redirects = False
        started_flow = started(client)
        state = started_flow.headers["location"].split("state=", 1)[1]
        refused = None
        for _ in range(4):
            refused = client.get(f"/login/google/callback?code=the-code&state={state}")
            if refused.status_code == 429:
                break
    assert refused is not None and refused.status_code == 429
    assert refused.headers["Retry-After"]
    # The provider was called at most as often as the limiter allowed, and never after it
    # refused: the stand-in records every completion it was asked for.
    assert len(providers[0].seen) <= 2


@pytest.mark.parametrize(
    "providers",
    [
        [],
        [StandIn(account=account(), name="google", label="Google")],
        [
            StandIn(account=account(), name="google", label="Google"),
            StandIn(account=account("github"), name="github", label="GitHub"),
        ],
    ],
    indirect=True,
)
def test_no_control_on_the_page_is_named_inside_another(client, providers):
    """On each page, every button and field has a name no other one on it contains.

    Playwright matches an accessible name as a case-insensitive substring unless a caller
    asks for an exact one, so a page carrying both "Sign in" and "Sign in securely" makes
    every unanchored locator for either of them ambiguous. That is not a test-only problem:
    it is two controls a person reads as the same instruction. `scripts/monitoring_demo.py`
    drove the credential form by the loose name and stopped working the day the password
    form arrived, which is what this holds against. The check is per page, because a
    locator only ever resolves within one.
    """
    for address, expected in (("/login", 1 + len(providers)), ("/set-password", 1)):
        page = client.get(address).text
        # A provider button carries its mark as inline SVG, which is `aria-hidden` and so is
        # no part of the button's name. Dropping the marks first leaves exactly the text a
        # person reads and a locator matches.
        page = re.sub(r"<svg\b.*?</svg>", "", page, flags=re.DOTALL)
        buttons = [name.strip() for name in re.findall(r"<button[^>]*>([^<]*)</button>", page)]
        labels = [name.strip() for name in re.findall(r"<label[^>]*>([^<]*)<input", page)]
        assert len(buttons) == expected, (address, buttons)
        assert labels, address
        for names in (buttons, labels):
            for one in names:
                assert one, (address, names)
                inside = [other for other in names if other != one and one.lower() in other.lower()]
                assert inside == [], (address, one, inside)


# The workspace a sign-in opens.

MEMBER = "member@example.test"
MEMBER_PASSWORD = "a retained example passphrase"


@pytest.fixture
def linked_client(db, runtime, config, tmp_path, monkeypatch):
    """A console client whose deployment registers workspace-scoped approval links, so the
    scoped approval address is mounted and a hint may name it."""
    from test_console_serving import write_build
    from test_login_return import LINKED

    from execbound.surfaces import console as console_module

    root = write_build(tmp_path / "console_dist")
    monkeypatch.setattr(console_module, "build_root", lambda: root)
    monkeypatch.setattr(runtime, "plugins", LINKED)
    # One account signs in many times over, which is what the test is about, not the limit.
    runtime.limiter.limits = RequestLimits(login_attempts=100)
    with TestClient(create_app(db, runtime=runtime, human=config), base_url=ORIGIN) as made:
        made.follow_redirects = False
        yield made


@pytest.fixture
def two_workspaces(db, admin_engine, seeded):
    """An account that administers A, where it signed in last, and approves in B, with a
    retained Google binding beside its password."""
    from test_workspace_accounts import adopt, enroll, second_membership

    from execbound.surfaces.sessions import issue_session

    first, second = seeded["tenants"]
    principal, _ = enroll(admin_engine, first, kind="ADMIN")
    bind_identity(
        db,
        first,
        principal,
        provider="google",
        subject="two-workspaces",
        email=MEMBER,
        display_name=None,
    )
    account = adopt(db, first, principal)
    other = second_membership(admin_engine, seeded, account)
    with admin_engine.begin() as conn:
        conn.execute(
            text("INSERT INTO execbound.access_principals(tenant_id,principal_id) VALUES(:t,:p)"),
            {"t": second, "p": other},
        )
        conn.execute(
            text(
                "INSERT INTO execbound.access_role_grants(tenant_id,grant_id,principal_id,role) "
                "VALUES(:t,:g,:p,'viewer')"
            ),
            {"t": second, "p": other, "g": uuid4()},
        )
    issue_session(db, sign_in_with_password(db, MEMBER, MEMBER_PASSWORD))
    return {"account": account, "a": first, "b": second}


def _entered_last(admin_engine, account, tenant):
    """Make `tenant` the one workspace this account has entered, a day ago, so any sign-in
    after it, whatever its clock, is later."""
    with admin_engine.begin() as conn:
        conn.execute(
            text(
                "UPDATE execbound.workspace_memberships SET last_entered_at = "
                "CASE WHEN tenant_id=:t THEN now() - interval '1 day' END WHERE account_id=:a"
            ),
            {"a": account, "t": tenant},
        )


def _signed_in_to(db, client, review, how):
    """Sign in from `/login?review=<review>` and answer the workspace the session opened."""
    from execbound.surfaces.sessions import load_session

    client.cookies.clear()
    page = client.get("/login", params={"review": review})
    assert page.status_code == 200
    if how == "password":
        fields = form_values(page.text, "/session/password")
        result = client.post(
            "/session/password",
            data={**fields, "email": MEMBER, "password": MEMBER_PASSWORD},
            headers={"Origin": ORIGIN},
        )
        assert result.status_code == 303, result.text
    else:
        fields = form_values(page.text, "/login/google")
        start = client.post("/login/google", data=fields, headers={"Origin": ORIGIN})
        state = start.headers["location"].split("state=", 1)[1]
        result = client.get(f"/login/google/callback?code=the-code&state={state}")
        landed_at(result)
    issued = [
        cookie.split(";", 1)[0].split("=", 1)[1]
        for cookie in result.headers.get_list("set-cookie")
        if cookie.startswith("eb_session=")
    ]
    assert len(issued) == 1
    return load_session(db, issued[0]).identity.tenant_id


@pytest.mark.parametrize(
    "providers",
    [[StandIn(account=ExternalAccount("google", "two-workspaces", MEMBER, None))]],
    indirect=True,
)
def test_sn11_a_sign_in_opens_the_workspace_its_link_names(
    db, admin_engine, linked_client, providers, two_workspaces
):
    from test_workspace_waiting import new_tenant

    from execbound.surfaces.sessions import load_session

    account, first, second = two_workspaces["account"], two_workspaces["a"], two_workspaces["b"]
    approval = uuid4()
    scoped = f"/workspaces/{second}/approvals/{approval}"
    for how in ("password", "google"):
        _entered_last(admin_engine, account, first)
        assert _signed_in_to(db, linked_client, scoped, how) == second
        # An unhinted sign-in now opens B, the workspace entered last.
        assert _signed_in_to(db, linked_client, "/activity", how) == second

    # A workspace the account does not belong to chooses nothing.
    stranger, _ = new_tenant(admin_engine, "Not a member")
    for how in ("password", "google"):
        _entered_last(admin_engine, account, first)
        assert (
            _signed_in_to(db, linked_client, f"/workspaces/{stranger}/approvals/{approval}", how)
            == first
        )

    # Nor does a membership that is not active.
    with admin_engine.begin() as conn:
        conn.execute(
            text(
                "UPDATE execbound.workspace_memberships SET active=false,version=version+1 "
                "WHERE account_id=:a AND tenant_id=:t"
            ),
            {"a": account, "t": second},
        )
    for how in ("password", "google"):
        _entered_last(admin_engine, account, first)
        assert _signed_in_to(db, linked_client, scoped, how) == first
    with admin_engine.begin() as conn:
        conn.execute(
            text(
                "UPDATE execbound.workspace_memberships SET active=true,version=version+1 "
                "WHERE account_id=:a AND tenant_id=:t"
            ),
            {"a": account, "t": second},
        )

    # Nor a workspace that requires sign-in through its own directory.
    from test_directory_store import RING, FixedClock, enabled, person

    from execbound.directory import DirectoryConfig

    directory = enabled(
        db,
        DirectoryConfig(RING, "https://app.example"),
        {"tenant": second, "admin": person(admin_engine, second, "ADMIN")},
        FixedClock(),
    )
    with admin_engine.begin() as conn:
        conn.execute(
            text(
                "UPDATE execbound.identity_providers SET require_sign_in=true "
                "WHERE tenant_id=:t AND provider_id=:p"
            ),
            {"t": second, "p": directory},
        )
    for how in ("password", "google"):
        _entered_last(admin_engine, account, first)
        assert _signed_in_to(db, linked_client, scoped, how) == first

    # A session already signed in to A that opens B's address is not moved by the GET.
    with admin_engine.begin() as conn:
        conn.execute(
            text(
                "UPDATE execbound.identity_providers SET require_sign_in=false WHERE tenant_id=:t"
            ),
            {"t": second},
        )
    _entered_last(admin_engine, account, first)
    assert _signed_in_to(db, linked_client, "/activity", "password") == first
    token = linked_client.cookies.get("eb_session")
    assert token is not None
    opened = linked_client.get(scoped, headers={"Accept": "text/html"})
    assert opened.status_code == 200
    assert not any(c.startswith("eb_session=") for c in opened.headers.get_list("set-cookie"))
    assert load_session(db, token).identity.tenant_id == first


def _login_section(page: str) -> str:
    [section] = re.findall(r'<section class="login">(.*?)</section>', page, re.S)
    return section


def test_rp12_core_alone_shows_no_reset(db, runtime, connector, monkeypatch):
    """Without a plugin's recovery link the sign-in page is exactly what it was, and there is
    no reset page; with one, the link and the help line for a lost factor (#678)."""
    from plugin_fixtures import install

    from execbound.plugins import SignInLink, load_plugins
    from execbound.runtime import Runtime
    from execbound.service_links import ServiceLinks

    help_url = "https://help.example/account"
    human = HumanConfig(
        ORIGIN,
        TokenKeys("state-v1", {"state-v1": secrets.token_bytes(32)}),
        service=ServiceLinks(help_url=help_url),
    )
    with TestClient(
        create_app(db, runtime=runtime, human=human), base_url=ORIGIN, follow_redirects=False
    ) as client:
        section = _login_section(client.get("/login").text)
        assert client.get("/reset-password").status_code == 404
        assert client.get("/reset-password/verify").status_code == 404
    assert (
        f'<p class="alternative"><a href="{help_url}">Forgot your password or lost access?</a></p>'
    ) in section
    assert "Lost your authenticator app" not in section
    assert re.findall(r'<a href="([^"]+)"', section) == [help_url]

    install(
        monkeypatch,
        register=lambda registry: registry.recovery_link(
            SignInLink("/sample-plugin/reset", lambda runtime: "Forgot your password?")
        ),
    )
    loaded = Runtime(db, [connector], plugins=load_plugins({"sample_plugin": {}}))
    with TestClient(
        create_app(db, runtime=loaded, human=human), base_url=ORIGIN, follow_redirects=False
    ) as client:
        page = client.get("/login")
        values = form_values(page.text, "/session/password")
        values.update(email="nobody@example.com", password="not the password at all")
        wrong = client.post("/session/password", data=values, headers={"Origin": ORIGIN})
    for answer in (page, wrong):
        section = _login_section(answer.text)
        assert (
            section.count(
                '<p class="alternative">'
                '<a href="/sample-plugin/reset">Forgot your password?</a></p>'
            )
            == 1
        )
        assert (
            '<p class="muted">Lost your authenticator app and recovery codes? '
            f'<a href="{help_url}">Get account help</a></p>'
        ) in section
        assert "Forgot your password or lost access?" not in section


# Microsoft, through the same routes: a work account is identified by its tenant and object
# identifiers together, and only a link its signed-in owner makes binds it.

MICROSOFT_TENANT = "72f988bf-86f1-41af-91ab-2d7cd011db47"
OTHER_MICROSOFT_TENANT = "0a1b2c3d-4e5f-4a6b-8c7d-9e0f1a2b3c4d"
MICROSOFT_OBJECT = "00000000-0000-0000-66f3-3332eca7ea81"
MICROSOFT_SUBJECT = f"{MICROSOFT_TENANT}:{MICROSOFT_OBJECT}"


def microsoft(subject: str = MICROSOFT_SUBJECT, email: str = ADDRESS) -> StandIn:
    return StandIn(
        account=ExternalAccount("microsoft", subject, email, None),
        name="microsoft",
        label="Microsoft",
        authorization_origin="https://login.microsoftonline.com",
    )


def through_microsoft(client):
    """Start a Microsoft flow from the sign-in page and come back with the code."""
    page = client.get("/login")
    begun = client.post(
        "/login/microsoft",
        data=form_values(page.text, "/login/microsoft"),
        headers={"Origin": ORIGIN},
    )
    assert begun.status_code == 303
    state = begun.headers["location"].split("state=", 1)[1]
    return client.get(f"/login/microsoft/callback?code=the-code&state={state}")


def microsoft_bindings(admin_engine) -> list[tuple[str, str]]:
    with admin_engine.connect() as conn:
        return [
            tuple(row)
            for row in conn.execute(
                text(
                    "SELECT provider, subject FROM execbound.user_identities "
                    "WHERE provider = 'microsoft'"
                )
            ).all()
        ]


@pytest.mark.parametrize("providers", [[microsoft()]], indirect=True)
def test_mi3_microsoft_signs_in_and_links_by_subject_only(
    client, providers, signed_up, db, runtime, admin_engine
):
    from execbound.surfaces.sessions import load_session

    # Unbound: the address matches an account, and still nothing signs in or is created.
    unbound = through_microsoft(client)
    assert unbound.status_code == 403 and REFUSED in unbound.text
    assert microsoft_bindings(admin_engine) == []
    # The signed-in owner links it from Account security.
    sign_in(client)
    session = load_session(db, client.cookies.get("eb_session"), clock=runtime.clock)
    with admin_engine.begin() as conn:
        conn.execute(
            text("UPDATE execbound.user_accounts SET email_verified_at=now() WHERE account_id=:a"),
            {"a": session.account_id},
        )
    csrf = client.cookies.get("eb_csrf")
    begun = client.post("/account/link/microsoft", data={"csrf": csrf}, headers={"Origin": ORIGIN})
    assert begun.status_code == 303
    from execbound.signin import read_flow

    flow = read_flow(client.cookies.get("eb_signin"))
    back = client.get("/login/microsoft/callback", params={"code": "c", "state": flow.state})
    assert landed_at(back, session=False) == "/account/security"
    assert microsoft_bindings(admin_engine) == [("microsoft", MICROSOFT_SUBJECT)]
    # From a browser with nothing in it, the subject signs in, and it is recorded as Microsoft.
    client.cookies.clear()
    assert landed_at(through_microsoft(client)) == "/approvals"
    with admin_engine.connect() as conn:
        conn.execute(
            text("SELECT set_config('execbound.tenant_id', :t, false)"),
            {"t": str(signed_up["tenant"])},
        )
        kinds = conn.execute(
            text("SELECT kind FROM execbound.audit_events WHERE kind LIKE 'human_sign_in.%'")
        ).scalars()
        assert "human_sign_in.microsoft" in set(kinds)
    # The same object identifier in another Microsoft tenant is another person.
    elsewhere = HumanConfig(
        ORIGIN,
        TokenKeys("state-v1", {"state-v1": secrets.token_bytes(32)}),
        providers=(microsoft(f"{OTHER_MICROSOFT_TENANT}:{MICROSOFT_OBJECT}"),),
    )
    with TestClient(create_app(db, runtime=runtime, human=elsewhere), base_url=ORIGIN) as other:
        other.follow_redirects = False
        refused = through_microsoft(other)
    assert refused.status_code == 403 and REFUSED in refused.text
    assert microsoft_bindings(admin_engine) == [("microsoft", MICROSOFT_SUBJECT)]


def test_mi3_a_microsoft_link_needs_a_recent_sign_in_the_factor_and_the_same_address(
    db, admin_engine, seeded
):
    from test_human_sessions import FixedClock
    from test_workspace_accounts import adopt, enroll

    from execbound import mfa
    from execbound.account_links import begin_link, finish_link
    from execbound.envelope import KeyRing
    from execbound.resolution.models import SystemClock
    from execbound.signin import new_flow
    from execbound.surfaces.sessions import issue_session, load_session

    tenant = seeded["tenants"][0]
    principal, _ = enroll(admin_engine, tenant)
    account_id = adopt(db, tenant, principal)
    with admin_engine.begin() as conn:
        conn.execute(
            text("UPDATE execbound.user_accounts SET email_verified_at=now() WHERE account_id=:a"),
            {"a": account_id},
        )
    clock = FixedClock(SystemClock().now())
    owner = "member@example.test"

    def signed_in():
        identity = sign_in_with_password(db, owner, "a retained example passphrase", clock=clock)
        return issue_session(db, identity, clock=clock).token

    def session_now(token=None):
        return load_session(db, token or signed_in(), clock=clock, allow_pending_mfa=True)

    proof = ExternalAccount("microsoft", MICROSOFT_SUBJECT, owner, None)
    # A sign-in older than five minutes. Every clock stays within the database's own five
    # minutes of its `now()`, so what refuses is the sign-in's age and not the clock.
    start = clock.value
    clock.value = start - timedelta(seconds=290)
    stale = session_now()
    clock.value = start + timedelta(seconds=15)
    with pytest.raises(SignInRefused):
        begin_link(db, stale, "microsoft", new_flow(), clock=clock)
    clock.value = start
    # An address Microsoft verified that is not the account's own.
    fresh = session_now()
    flow = new_flow()
    token = begin_link(db, fresh, "microsoft", flow, clock=clock)
    with pytest.raises(SignInRefused):
        finish_link(
            db,
            token,
            flow,
            ExternalAccount("microsoft", MICROSOFT_SUBJECT, "someone@example.test", None),
            clock=clock,
        )
    assert microsoft_bindings(admin_engine) == []
    # With a factor enabled, a session that has not verified it cannot link.
    ring = KeyRing("test", {"test": b"m" * 32})
    enrolling = session_now()
    seed = mfa.begin_enrollment(db, enrolling, ring, clock=clock)
    mfa.confirm_enrollment(
        db, enrolling, ring, mfa.totp(seed, int(clock.now().timestamp() // 30)), clock=clock
    )
    second = signed_in()
    pending = session_now(second)
    assert pending.mfa_required
    with pytest.raises(SignInRefused):
        begin_link(db, pending, "microsoft", new_flow(), clock=clock)
    clock.value += timedelta(seconds=30)
    assert mfa.verify_factor(
        db, pending, ring, mfa.totp(seed, int(clock.now().timestamp() // 30)), clock=clock
    )
    flow = new_flow()
    token = begin_link(db, session_now(second), "microsoft", flow, clock=clock)
    finish_link(db, token, flow, proof, clock=clock)
    assert microsoft_bindings(admin_engine) == [("microsoft", MICROSOFT_SUBJECT)]


def test_mi3_a_workspace_that_requires_its_directory_is_never_opened_by_microsoft(
    db, admin_engine, seeded
):
    from types import SimpleNamespace

    from test_directory_store import RING, FixedClock, enabled, person
    from test_workspace_accounts import adopt, enroll

    from execbound.account_links import begin_link, finish_link
    from execbound.directory import DirectoryConfig
    from execbound.resolution.models import SystemClock
    from execbound.signin import new_flow
    from execbound.surfaces.sessions import issue_session, load_session
    from execbound.surfaces.sign_in_pages import _link

    tenant = seeded["tenants"][0]
    principal, _ = enroll(admin_engine, tenant)
    account_id = adopt(db, tenant, principal)
    with admin_engine.begin() as conn:
        conn.execute(
            text("UPDATE execbound.user_accounts SET email_verified_at=now() WHERE account_id=:a"),
            {"a": account_id},
        )
    granted = issue_session(
        db, sign_in_with_password(db, "member@example.test", "a retained example passphrase")
    )
    flow = new_flow()
    token = begin_link(db, load_session(db, granted.token), "microsoft", flow)
    proof = ExternalAccount("microsoft", MICROSOFT_SUBJECT, "member@example.test", None)
    finish_link(db, token, flow, proof)
    runtime_ = SimpleNamespace(db=db, clock=SystemClock())
    assert _link(runtime_, proof).tenant_id == tenant
    provider = enabled(
        db,
        DirectoryConfig(RING, "https://app.example"),
        {"tenant": tenant, "admin": person(admin_engine, tenant, "ADMIN")},
        FixedClock(),
    )
    with admin_engine.begin() as conn:
        conn.execute(
            text(
                "UPDATE execbound.identity_providers SET require_sign_in=true "
                "WHERE tenant_id=:t AND provider_id=:p"
            ),
            {"t": tenant, "p": provider},
        )
    with pytest.raises(SignInRefused):
        _link(runtime_, proof)
