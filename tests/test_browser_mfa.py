# SPDX-License-Identifier: AGPL-3.0-only
"""Signing in with a second step, in real Chromium: one focused page, then the console.

The second step of signing in used to be Account security itself: the code field sat among
the authenticator, passkey, organization and sign-in method controls, and once the code was
accepted the page stayed where it was, with a small link as the only way on. Now the step is
a page of its own that asks for one code, as every sign-in a person already knows does, and
an accepted code goes straight to where the sign-in lands.
"""

import re
import secrets
from datetime import timedelta

import pytest
from playwright.sync_api import expect
from test_browser_console import AXE, AXE_RUN, COLLECT
from test_browser_surfaces import ACTION_TIMEOUT_MS, FITS, serve
from test_browser_surfaces import chromium as chromium
from test_runtime import connector as connector
from test_runtime import live_provider as live_provider
from test_runtime import registry as registry
from test_runtime import runtime as runtime
from test_runtime import world as world
from test_sign_in_surface import ADDRESS, PASSWORD

from execbound import mfa
from execbound.app import create_app
from execbound.envelope import KeyRing
from execbound.passwords import issue_reset, redeem_reset, set_email
from execbound.surfaces.human import HumanConfig
from execbound.surfaces.sessions import load_session
from execbound.surfaces.tokens import TokenKeys

pytestmark = pytest.mark.integration

RING = KeyRing("test", {"test": b"m" * 32})


def step(runtime) -> int:
    return int(runtime.clock.now().timestamp() // 30)


@pytest.fixture
def mfa_gateway(db, runtime):
    def app(origin):
        keys = TokenKeys("browser-v1", {"browser-v1": secrets.token_bytes(32)})
        return create_app(db, runtime=runtime, human=HumanConfig(origin, keys, mfa=RING))

    with serve(app) as origin:
        yield origin


@pytest.fixture
def page(chromium, mfa_gateway):
    with chromium.new_context(
        base_url=mfa_gateway, viewport={"width": 1280, "height": 900}
    ) as context:
        opened = context.new_page()
        opened.set_default_timeout(ACTION_TIMEOUT_MS)
        opened.add_init_script(COLLECT)
        opened.add_init_script(path=str(AXE))
        yield opened


def password(page):
    page.goto("/login")
    page.get_by_label("Email").fill(ADDRESS)
    page.get_by_label("Password", exact=True).fill(PASSWORD)
    page.get_by_role("button", name="Sign in with a password").click()


@pytest.fixture
def enrolled(db, runtime, world, page):
    """The approver, holding a password and an authenticator they set up themselves: signed
    in once with the password, the authenticator confirmed on that session, then signed out,
    on a blank page with no console left running."""
    tenant, principal = world["human"].tenant_id, world["human"].principal_id
    set_email(db, tenant, world["admin"].principal_id, principal, ADDRESS)
    reset = issue_reset(db, tenant, world["admin"].principal_id, principal, clock=runtime.clock)
    redeem_reset(db, reset.code, PASSWORD, clock=runtime.clock)
    password(page)
    expect(page).to_have_url(re.compile(r"/approvals$"))
    token = next(c["value"] for c in page.context.cookies() if c["name"] == "eb_session")
    session = load_session(db, token, clock=runtime.clock)
    seed = mfa.begin_enrollment(db, session, RING, clock=runtime.clock)
    codes = mfa.confirm_enrollment(
        db, session, RING, mfa.totp(seed, step(runtime)), clock=runtime.clock
    )
    # Leave the console before its cookies go. Left open, any request it sends after they are
    # cleared is answered 401, and it sends itself to /login, which aborts the sign-in's own
    # `goto` with ERR_ABORTED whenever that answer lands first.
    page.goto("about:blank")
    page.context.clear_cookies()
    # The next time step, so the code the sign-in uses is not a replay of the one above.
    runtime.clock.value += timedelta(seconds=30)
    return seed, codes


def sign_in(page):
    password(page)
    expect(page).to_have_url(re.compile(r"/mfa$"))
    expect(page.get_by_role("heading", level=1)).to_have_text("Two-step verification")


def test_the_second_step_is_one_code_on_its_own_page_and_then_the_console(page, runtime, enrolled):
    seed, _ = enrolled
    sign_in(page)
    # Nothing to manage here: those controls are Account security's.
    for managed in ("Organization requirement", "Replace authenticator", "Add a passkey"):
        expect(page.get_by_text(managed)).to_have_count(0)
    code = page.get_by_label("Authentication code")
    expect(code).to_be_focused()
    for scheme, width, height in (
        ("light", 1280, 900),
        ("dark", 1280, 900),
        ("light", 390, 844),
        ("dark", 390, 844),
    ):
        page.emulate_media(color_scheme=scheme)
        page.set_viewport_size({"width": width, "height": height})
        assert page.evaluate(AXE_RUN) == [], (scheme, width)
        assert page.evaluate(FITS), (scheme, width)
    assert page.evaluate("window.__violations") == []
    page.set_viewport_size({"width": 1280, "height": 900})
    # A wrong code says so and leaves the person on the same step.
    code.fill("000000")
    page.get_by_role("button", name="Verify", exact=True).click()
    expect(page.get_by_role("alert")).to_contain_text("That code could not be used")
    expect(page.get_by_role("heading", level=1)).to_have_text("Two-step verification")
    # The right one goes straight to where an approver's sign-in lands.
    page.get_by_label("Authentication code").fill(mfa.totp(seed, step(runtime)))
    page.get_by_role("button", name="Verify", exact=True).click()
    expect(page).to_have_url(re.compile(r"/approvals$"))
    expect(page.get_by_role("heading", level=1)).to_have_text("Approvals")


def test_a_recovery_code_finishes_signing_in_from_the_same_page(page, enrolled):
    _, codes = enrolled
    sign_in(page)
    page.get_by_text("Lost your authenticator? Use a recovery code").click()
    page.get_by_label("Recovery code").fill(codes[0])
    page.get_by_role("button", name="Verify with a recovery code").click()
    expect(page).to_have_url(re.compile(r"/approvals$"))
    expect(page.get_by_role("heading", level=1)).to_have_text("Approvals")
