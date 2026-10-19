# SPDX-License-Identifier: AGPL-3.0-only
"""Real Chromium against the sign-in pages: a password, a code, and a provider button.

These are the pages a person meets before any session exists, so what is asserted is what a
browser actually does with them: the form posts, the cookies come back, the landing page is
the one the role gets, and a refusal says one sentence without saying which half was wrong.
The provider here is the same stand-in the route tests use, because what a real provider
verifies has its own files and a browser adds nothing to it.
"""

import html
import re
import secrets
import threading
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest
from playwright.sync_api import expect
from sqlalchemy import text
from test_browser_surfaces import ACTION_TIMEOUT_MS, FITS, serve
from test_browser_surfaces import browser_gateway as browser_gateway
from test_browser_surfaces import chromium as chromium
from test_runtime import connector as connector
from test_runtime import live_provider as live_provider
from test_runtime import registry as registry
from test_runtime import runtime as runtime
from test_runtime import world as world
from test_sign_in_surface import ADDRESS, PASSWORD, StandIn, account

from execbound.app import create_app
from execbound.passwords import bind_identity, issue_reset, redeem_reset, set_email
from execbound.surfaces.human import HumanConfig
from execbound.surfaces.tokens import TokenKeys

pytestmark = pytest.mark.integration

NEW_PASSWORD = "chosen on the page itself"


def gateway_app(db, runtime, origin, providers=()):
    return create_app(
        db,
        runtime=runtime,
        human=HumanConfig(
            origin,
            TokenKeys("browser-v1", {"browser-v1": secrets.token_bytes(32)}),
            providers=tuple(providers),
        ),
    )


@pytest.fixture
def sign_in_gateway(db, runtime, request):
    providers = getattr(request, "param", ())
    with serve(lambda origin: gateway_app(db, runtime, origin, providers)) as origin:
        yield origin


@pytest.fixture
def page(chromium, sign_in_gateway):
    # Authentication stays in this fresh context's memory: no trace, no HAR, no video and no
    # storage-state file, so nothing a person typed is written to disk by the test.
    with chromium.new_context(
        base_url=sign_in_gateway, viewport={"width": 1440, "height": 1000}
    ) as context:
        opened = context.new_page()
        opened.set_default_timeout(ACTION_TIMEOUT_MS)
        yield opened


@pytest.fixture
def addressed(db, runtime, world, admin_engine):
    """The approver, holding a sign-in address and one pending set-password code."""
    tenant, principal = world["human"].tenant_id, world["human"].principal_id
    set_email(db, tenant, world["admin"].principal_id, principal, ADDRESS)
    return issue_reset(db, tenant, world["admin"].principal_id, principal, clock=runtime.clock)


def test_a_person_sets_a_password_on_the_page_and_then_signs_in_with_it(page, db, addressed):
    page.goto("/set-password")
    expect(page.get_by_role("heading", level=1)).to_have_text("Choose a password.")
    page.get_by_label("One-time code").fill(addressed.code)
    page.get_by_label("New password", exact=True).fill(NEW_PASSWORD)
    page.get_by_label("Repeat it").fill(NEW_PASSWORD)
    page.get_by_role("button", name="Set the password").click()
    expect(page.get_by_role("heading", level=1)).to_have_text("Your password is set.")

    page.get_by_role("link", name="Go to sign in").click()
    expect(page).to_have_url(re.compile(r"/login$"))
    page.get_by_label("Email").fill(ADDRESS)
    page.get_by_label("Password", exact=True).fill(NEW_PASSWORD)
    page.get_by_role("button", name="Sign in with a password").click()
    expect(page).to_have_url(re.compile(r"/approvals$"))
    expect(page.get_by_role("heading", level=1)).to_have_text("Approvals")


def test_a_code_works_once_and_the_second_person_to_try_it_is_refused(page, db, addressed):
    page.goto("/set-password")
    page.get_by_label("One-time code").fill(addressed.code)
    page.get_by_label("New password", exact=True).fill(NEW_PASSWORD)
    page.get_by_label("Repeat it").fill(NEW_PASSWORD)
    page.get_by_role("button", name="Set the password").click()
    expect(page.get_by_role("heading", level=1)).to_have_text("Your password is set.")

    page.goto("/set-password")
    page.get_by_label("One-time code").fill(addressed.code)
    page.get_by_label("New password", exact=True).fill(NEW_PASSWORD + " again")
    page.get_by_label("Repeat it").fill(NEW_PASSWORD + " again")
    page.get_by_role("button", name="Set the password").click()
    expect(page.get_by_role("alert")).to_have_text("This code is not valid.")


def test_a_wrong_password_and_an_unknown_address_say_the_same_thing(page, db, runtime, addressed):
    redeem_reset(db, addressed.code, PASSWORD, clock=runtime.clock)
    page.goto("/login")
    page.get_by_label("Email").fill(ADDRESS)
    page.get_by_label("Password", exact=True).fill("not the password at all")
    page.get_by_role("button", name="Sign in with a password").click()
    wrong = page.get_by_role("alert").text_content()
    expect(page).to_have_url(re.compile(r"/session/password$"))

    page.goto("/login")
    page.get_by_label("Email").fill("nobody@example.com")
    page.get_by_label("Password", exact=True).fill(PASSWORD)
    page.get_by_role("button", name="Sign in with a password").click()
    assert page.get_by_role("alert").text_content() == wrong
    assert wrong == "Those sign-in details are not right."


def test_the_credential_form_still_signs_an_administrator_in(page, admin_engine, world):
    from test_human_surface import credential

    page.goto("/login")
    page.goto("/login?setup=1")
    page.get_by_label("Setup credential").fill(credential(admin_engine, world["human"]))
    page.get_by_role("button", name="Continue setup").click()
    expect(page).to_have_url(re.compile(r"/approvals$"))


def test_the_sign_in_page_is_allowed_the_mark_it_links(page):
    """The favicon loads under the page's own policy, as an image the browser actually fetches.

    The policy lacked `img-src`, so its `default-src 'none'` refused `/favicon.svg` and
    `/favicon.ico` and the tab showed a blank globe. Loading the mark as an image from the
    page is the same check the browser makes for the tab.
    """
    page.goto("/login")
    loaded = page.evaluate(
        """() => new Promise((done) => {
            const mark = new Image();
            mark.onload = () => done(true);
            mark.onerror = () => done(false);
            mark.src = '/favicon.svg';
        })"""
    )
    assert loaded


def test_no_provider_button_appears_without_a_configured_provider(page):
    page.goto("/login")
    expect(page.get_by_role("button", name=re.compile("Continue with"))).to_have_count(0)
    # Nothing about providers is on the page at all, including the line that divides them
    # from the password form.
    expect(page.get_by_text("or continue with")).to_have_count(0)


@pytest.mark.parametrize(
    "sign_in_gateway",
    [
        (
            StandIn(account=account(), name="google", label="Google"),
            StandIn(account=account(), name="github", label="GitHub"),
        )
    ],
    indirect=True,
)
def test_each_provider_button_is_a_button_with_its_own_mark(page):
    """A way in, not a footnote.

    The first version styled these `quiet`: a transparent border and muted text, which a
    reviewer read straight past on 20 September 2026. Each one is now the width of the
    password button, bordered, and carries the provider's mark. The mark is inline SVG
    because the pages' policy allows no image source at all, and it is `aria-hidden`
    because the button's text is already its name.
    """
    page.goto("/login")
    for label in ("Google", "GitHub"):
        button = page.get_by_role("button", name=f"Continue with {label}")
        expect(button).to_be_visible()
        assert button.locator("svg.provider-mark").count() == 1
        assert "quiet" not in (button.get_attribute("class") or "")
        box = button.bounding_box()
        password = page.get_by_role("button", name="Sign in with a password").bounding_box()
        assert box and password and box["width"] == password["width"] and box["height"] >= 44


@pytest.mark.parametrize(
    "sign_in_gateway",
    [(StandIn(account=account(), name="google", label="Google"),)],
    indirect=True,
)
def test_a_configured_provider_signs_a_matched_person_in(page, db, runtime, world, addressed):
    # A previously linked subject, not a matching-email attachment at anonymous login.
    proof = account()
    bind_identity(
        db,
        world["human"].tenant_id,
        world["human"].principal_id,
        provider=proof.provider,
        subject=proof.subject,
        email=proof.email,
        display_name=proof.display_name,
        clock=runtime.clock,
    )
    redeem_reset(db, addressed.code, PASSWORD, clock=runtime.clock)
    page.goto("/login")
    button = page.get_by_role("button", name="Continue with Google")
    expect(button).to_be_visible()
    # The stand-in's authorization endpoint is nobody's host, so the browser gets as far as
    # trying to reach it and no further. That is enough: what the test is about is that the
    # form submission was not blocked, that the browser was sent to the provider, and that
    # it kept the transient cookie the callback then has to match.
    sent: list[str] = []
    page.on("response", lambda answer: sent.append(answer.headers.get("location", "")))
    button.click()
    page.wait_for_timeout(500)
    assert any(location.startswith("https://provider.example/") for location in sent), sent
    kept = next(c for c in page.context.cookies() if c["name"] == "eb_signin")
    assert kept["httpOnly"] and kept["sameSite"] == "Lax" and kept["path"] == "/"
    state = kept["value"].split(".")[0]
    page.goto(f"/login/google/callback?code=the-code&state={state}")
    expect(page).to_have_url(re.compile(r"/approvals$"))
    expect(page.get_by_role("heading", level=1)).to_have_text("Approvals")


@contextmanager
def another_site(target: str):
    """A page on a different site that sends the browser to `target`, the way a provider's
    consent page does. `localhost` and `127.0.0.1` are two sites to a browser, so a link
    followed from here arrives at the gateway as a cross-site top-level navigation, which is
    the one thing `page.goto` on the callback cannot reproduce: a typed address is same-site.
    """

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            body = f'<!doctype html><a href="{html.escape(target)}">Back</a>'.encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *args: object) -> None:
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://localhost:{server.server_address[1]}/"
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


@pytest.mark.parametrize(
    "sign_in_gateway",
    [(StandIn(account=account(), name="google", label="Google"),)],
    indirect=True,
)
def test_a_provider_sending_the_browser_back_from_its_own_site_leaves_it_signed_in(
    page, db, runtime, world, addressed, sign_in_gateway
):
    """Found on the live deployment on 21 September 2026: Google accepted, the callback
    signed the person in and answered 303 to the landing page, and the landing page sent
    them back to `/login`. The session cookie is SameSite=Strict, and a request that follows
    a redirect in a chain a cross-site navigation began is sent without it. The callback
    therefore lands on a page of this site's own, and the next request starts here.
    """
    # A previously linked subject, not a matching-email attachment at anonymous login.
    proof = account()
    bind_identity(
        db,
        world["human"].tenant_id,
        world["human"].principal_id,
        provider=proof.provider,
        subject=proof.subject,
        email=proof.email,
        display_name=proof.display_name,
        clock=runtime.clock,
    )
    redeem_reset(db, addressed.code, PASSWORD, clock=runtime.clock)
    page.goto("/login")
    page.get_by_role("button", name="Continue with Google").click()
    page.wait_for_timeout(500)
    kept = next(c for c in page.context.cookies() if c["name"] == "eb_signin")
    state = kept["value"].split(".")[0]
    callback = f"{sign_in_gateway}/login/google/callback?code=the-code&state={state}"
    with another_site(callback) as elsewhere:
        page.goto(elsewhere)
        page.get_by_role("link", name="Back").click()
        expect(page).to_have_url(re.compile(r"/approvals$"))
        expect(page.get_by_role("heading", level=1)).to_have_text("Approvals")
    session = next(c for c in page.context.cookies() if c["name"] == "eb_session")
    assert session["sameSite"] == "Strict" and session["httpOnly"]


@pytest.mark.parametrize(
    "sign_in_gateway",
    [(StandIn(account=account(), name="github", label="GitHub"),)],
    indirect=True,
)
def test_a_callback_with_no_transient_cookie_is_refused_on_the_sign_in_page(page, db):
    page.goto(f"/login/github/callback?code=the-code&state={secrets.token_urlsafe(32)}")
    expect(page.get_by_role("alert")).to_have_text("That account cannot sign in here.")
    expect(page.get_by_role("heading", level=1)).to_have_text("Sign in.")


def test_the_pages_are_reachable_and_labelled_at_phone_width(page, db, addressed):
    """Every control has a name a screen reader can read, at the width a phone gives it."""
    page.set_viewport_size({"width": 390, "height": 844})
    for address, heading in (
        ("/login", "Sign in."),
        ("/set-password", "Choose a password."),
    ):
        page.goto(address)
        expect(page.get_by_role("heading", level=1)).to_have_text(heading)
        assert page.evaluate(FITS)
        for control in page.get_by_role("textbox").all():
            assert control.get_attribute("name")
        for button in page.get_by_role("button").all():
            assert (button.text_content() or "").strip()


def test_a_password_session_ends_like_any_other_and_the_cookie_stops_working(
    page, db, runtime, addressed
):
    redeem_reset(db, addressed.code, PASSWORD, clock=runtime.clock)
    page.goto("/login")
    page.get_by_label("Email").fill(ADDRESS)
    page.get_by_label("Password", exact=True).fill(PASSWORD)
    page.get_by_role("button", name="Sign in with a password").click()
    expect(page).to_have_url(re.compile(r"/approvals$"))
    kept = {
        cookie["name"]: cookie["value"]
        for cookie in page.context.cookies()
        if cookie["name"].startswith("eb_")
    }
    assert "eb_session" in kept
    page.get_by_role("button", name=re.compile("Sign out")).first.click()
    expect(page).to_have_url(re.compile(r"/login$"))
    page.context.add_cookies(
        [{"name": name, "value": value, "url": page.url} for name, value in kept.items()]
    )
    page.goto("/approvals")
    expect(page).not_to_have_url(re.compile(r"/approvals$"))


def test_a_sign_in_is_recorded_in_the_audit_chain_without_the_password(
    page, db, runtime, world, addressed
):
    redeem_reset(db, addressed.code, PASSWORD, clock=runtime.clock)
    page.goto("/login")
    page.get_by_label("Email").fill(ADDRESS)
    page.get_by_label("Password", exact=True).fill(PASSWORD)
    page.get_by_role("button", name="Sign in with a password").click()
    expect(page).to_have_url(re.compile(r"/approvals$"))
    with db.transaction(world["human"].tenant_id) as conn:
        rows = [
            dict(row)
            for row in conn.execute(
                text(
                    "SELECT kind, payload FROM execbound.audit_events "
                    "WHERE tenant_id = :t AND kind = 'human_sign_in.password'"
                ),
                {"t": world["human"].tenant_id},
            ).mappings()
        ]
    assert len(rows) == 1
    assert PASSWORD not in str(rows)
    assert ADDRESS not in str(rows)
