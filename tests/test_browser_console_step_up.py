# SPDX-License-Identifier: AGPL-3.0-only
"""The step-up asked in place, in real Chromium: the case that prompted it (28 September 2026).

In the pilot workspace an administrator with an authenticator opened Users, then Invite
teammate, typed an address and clicked Invite. The console left the page for Account security
to ask for a code, and the dialog and the address were lost. Now the code is asked for in a
dialog over the page, the session's cookie and CSRF token rotate as the security page rotates
them, and the invitation is sent again, once, without the page ever navigating.

The administrator signs in with their authenticator on the injected clock, the console stays
open while more than thirty minutes pass on that clock (read every few minutes, so the
fifteen-minute idle limit keeps renewing the session), and only then invites. The clock starts
that far in the past so that it ends at the database's own time: the invitation function
refuses a clock more than five minutes from it. The session is a credential's, not an
account's, for the same reason: the account sign-in functions refuse a clock more than five
minutes from the database's, so an account session cannot begin thirty minutes back. The
console sends the same requests either way, and the account half of the exchange (its
workspace header, its password change checked again by the database) is proven over HTTP in
`test_console_api_step_up.py`.
"""

import re
import secrets
from datetime import UTC, datetime, timedelta

import pytest
from playwright.sync_api import expect
from sqlalchemy import text
from test_browser_console import AXE, AXE_RUN, COLLECT, SETTLED
from test_browser_surfaces import ACTION_TIMEOUT_MS, FITS, serve
from test_browser_surfaces import chromium as chromium
from test_execution import provision_credential
from test_execution import registry as registry
from test_execution import world as world
from test_protected_path import connector as connector
from test_protected_path import live_provider as live_provider
from test_runtime import runtime as runtime

from execbound import mfa
from execbound.app import create_app
from execbound.envelope import KeyRing
from execbound.identity import authenticate
from execbound.surfaces import console as console_module
from execbound.surfaces.human import HumanConfig
from execbound.surfaces.sessions import issue_session, load_session
from execbound.surfaces.tokens import TokenKeys
from execbound.transports import MailConfig

pytestmark = pytest.mark.integration

RING = KeyRing("test", {"test": b"m" * 32})
INVITED = "casey@example.org"


def step(runtime) -> int:
    return int(runtime.clock.now().timestamp() // 30)


@pytest.fixture
def gateway(db, runtime):
    if console_module.load_build() is None:
        pytest.fail("No console build is packaged: run `pnpm build` in console/ first")
    if not AXE.exists():
        pytest.fail("axe-core is not installed: run `pnpm install` in console/ first")

    def app(origin):
        keys = TokenKeys("browser-v1", {"browser-v1": secrets.token_bytes(32)})
        return create_app(db, runtime=runtime, human=HumanConfig(origin, keys, mfa=RING))

    with serve(app) as origin:
        yield origin


@pytest.fixture
def page(chromium, gateway):
    with chromium.new_context(base_url=gateway, viewport={"width": 1280, "height": 900}) as context:
        opened = context.new_page()
        opened.set_default_timeout(ACTION_TIMEOUT_MS)
        opened.add_init_script(COLLECT)
        opened.add_init_script(path=str(AXE))
        yield opened


def session_cookie(page) -> str:
    return next(c["value"] for c in page.context.cookies() if c["name"] == "eb_session")


def test_an_invitation_asks_for_a_code_over_the_users_page_and_is_sent_without_leaving(
    page, gateway, db, runtime, world, admin_engine, monkeypatch
):
    # The Users page offers to invite only where this deployment has a mail relay. Nothing
    # listens on this one, so the first send fails at once and the invitation stays pending,
    # which is all this test reads of it.
    monkeypatch.setattr(
        runtime,
        "mail",
        MailConfig("localhost", 1, "tls", "relay", "relay-password", "execbound@example.test"),
    )
    # The administrator's credential dates from before the session: the injected clock starts
    # thirty-four minutes back, and a session may not begin before its credential was issued.
    started = datetime.now(UTC) - timedelta(minutes=34)
    tenant, admin = world["admin"].tenant_id, world["admin"].principal_id
    with admin_engine.begin() as conn:
        conn.execute(text("SELECT set_config('execbound.tenant_id', :t, true)"), {"t": str(tenant)})
        token = provision_credential(
            conn, tenant, admin, started - timedelta(minutes=2), timedelta(hours=2)
        )
    identity = authenticate(db, token)

    # They set up an authenticator on one session, then signed in again and gave a code.
    runtime.clock.value = started - timedelta(minutes=1)
    setup = load_session(
        db, issue_session(db, identity, clock=runtime.clock).token, clock=runtime.clock
    )
    seed = mfa.begin_enrollment(db, setup, RING, clock=runtime.clock)
    mfa.confirm_enrollment(db, setup, RING, mfa.totp(seed, step(runtime)), clock=runtime.clock)
    runtime.clock.value = started
    grant = issue_session(db, identity, clock=runtime.clock)
    assert grant.mfa_required
    host = gateway.split("//", 1)[1].split(":", 1)[0]
    page.context.add_cookies(
        [
            {
                "name": name,
                "value": value,
                "domain": host,
                "path": "/",
                "httpOnly": True,
                "sameSite": "Strict",
            }
            for name, value in (("eb_session", grant.token), ("eb_csrf", grant.csrf_token))
        ]
    )
    page.goto("/mfa")
    expect(page.get_by_role("heading", level=1)).to_have_text("Two-step verification")
    page.get_by_label("Authentication code").fill(mfa.totp(seed, step(runtime)))
    page.get_by_role("button", name="Verify", exact=True).click()
    expect(page).not_to_have_url(re.compile(r"/mfa$"))

    # The console stays open for more than thirty minutes on the injected clock.
    page.goto("/people")
    expect(page.get_by_role("heading", level=1)).to_have_text("Users")
    for _ in range(11):
        runtime.clock.value += timedelta(minutes=3)
        assert page.evaluate("fetch('/api/console/v1/session').then((r) => r.status)") == 200
    signed_in = session_cookie(page)

    # A marker on the document: a navigation would take it away.
    page.evaluate("window.__stayed = true")
    page.get_by_role("button", name="Invite teammate").click()
    inviting = page.get_by_role("dialog", name="Invite a teammate")
    inviting.get_by_label("Email").fill(INVITED)
    inviting.get_by_role("button", name="Invite", exact=True).click()

    asking = page.get_by_role("dialog", name="Verify your identity")
    expect(asking).to_be_visible()
    code = asking.get_by_label("Authentication code")
    expect(code).to_be_focused()
    expect(page).to_have_url(re.compile(r"/people$"))
    # The invitation's dialog is still there, holding the address, beneath the question; while
    # the question is open it is out of the accessibility tree, as anything under a modal is.
    expect(page.locator(".dialog input[type=email]")).to_have_value(INVITED)

    # The question is clean in both schemes, at desktop and phone widths.
    for scheme, width, height in (
        ("light", 1280, 900),
        ("dark", 1280, 900),
        ("light", 390, 844),
        ("dark", 390, 844),
    ):
        page.emulate_media(color_scheme=scheme)
        page.set_viewport_size({"width": width, "height": height})
        page.wait_for_function(SETTLED)
        assert page.evaluate(AXE_RUN) == [], (scheme, width)
        assert page.evaluate(FITS), (scheme, width)
        expect(asking).to_be_in_viewport()
    page.set_viewport_size({"width": 1280, "height": 900})
    page.emulate_media(color_scheme="light")

    # A wrong code says so in the dialog, and the person tries again.
    code.fill("000000")
    asking.get_by_role("button", name="Verify", exact=True).click()
    expect(asking.get_by_role("alert")).to_contain_text("That code could not be used")
    expect(asking).to_be_visible()

    code.fill(mfa.totp(seed, step(runtime)))
    asking.get_by_role("button", name="Verify", exact=True).click()
    expect(asking).to_be_hidden()
    expect(inviting).to_be_hidden()
    pending = page.get_by_role("table", name=re.compile("Teammate invitations"))
    expect(pending.get_by_role("cell", name=INVITED)).to_be_visible()

    assert page.evaluate("window.__stayed") is True
    expect(page).to_have_url(re.compile(r"/people$"))
    # The session was rotated as the security page rotates it, and the page carries on with it.
    assert session_cookie(page) != signed_in
    assert page.evaluate("fetch('/api/console/v1/session').then((r) => r.status)") == 200
    assert page.evaluate("window.__violations") == []
