# SPDX-License-Identifier: AGPL-3.0-only
"""The "Trust this browser for 30 days" box on the code prompt, in real Chromium (#859).

The box sits in each form that finishes a sign-in, unticked. It is reached from the code field
with Tab and ticked with Space, its label is the target and is 44 px tall at phone width
(#858's bar), and the page still passes the server-rendered pages' audit, axe-core and the
sideways check in both schemes at 1280 and 390. Ticked, the code goes straight on and the
browser keeps an HttpOnly, Lax trust cookie; the next sign-in on it skips the code. My
account's Trusted browsers card, holding trusts with this browser's marked, passes axe-core,
the sideways check and the policy record in both schemes at 1280 and 390.
"""

import re
import secrets
from datetime import timedelta

import pytest
from playwright.sync_api import expect
from test_browser_accessibility import AUDIT
from test_browser_console import AXE, AXE_RUN, COLLECT, settled
from test_browser_mfa import enrolled as enrolled
from test_browser_mfa import mfa_gateway as mfa_gateway
from test_browser_mfa import page as page
from test_browser_mfa import password, sign_in, step
from test_browser_surfaces import ACTION_TIMEOUT_MS, FITS, serve
from test_browser_surfaces import chromium as chromium
from test_runtime import connector as connector
from test_runtime import live_provider as live_provider
from test_runtime import registry as registry
from test_runtime import runtime as runtime
from test_runtime import world as world

from execbound import mfa
from execbound.app import create_app
from execbound.resolution.models import SystemClock
from execbound.surfaces.human import HumanConfig
from execbound.surfaces.tokens import TokenKeys

pytestmark = pytest.mark.integration

BOX = "Trust this browser for 30 days"
VIEWS = (("light", 1280, 900), ("dark", 1280, 900), ("light", 390, 844), ("dark", 390, 844))


def clean(page, where) -> None:
    """axe-core, the sideways check and the audit the pages that stay are held to."""
    assert page.evaluate(AXE_RUN) == [], where
    assert page.evaluate(FITS), where
    assert page.evaluate(AUDIT) == [], where


def tall_enough(locator, width, where) -> None:
    box = locator.bounding_box()
    assert box is not None and box["height"] >= (44 if width <= 767 else 24), (where, box)


def test_tb_the_box_is_keyboard_reachable_and_44px_on_a_phone(page, runtime, enrolled):
    seed, _ = enrolled
    sign_in(page)
    code_form = page.locator('form[action="/account/security/verify"]').first
    recovery_form = page.locator("details.recovery form")
    box = code_form.get_by_label(BOX)
    expect(box).not_to_be_checked()
    expect(recovery_form.get_by_label(BOX)).not_to_be_checked()
    for scheme, width, height in VIEWS:
        page.emulate_media(color_scheme=scheme)
        page.set_viewport_size({"width": width, "height": height})
        clean(page, (scheme, width))
        tall_enough(code_form.locator("label.trust"), width, (scheme, width))
    # The recovery form's box, once the person opens it.
    page.get_by_text("Lost your authenticator? Use a recovery code").click()
    for scheme, width, height in VIEWS:
        page.emulate_media(color_scheme=scheme)
        page.set_viewport_size({"width": width, "height": height})
        clean(page, ("recovery", scheme, width))
        tall_enough(recovery_form.locator("label.trust"), width, ("recovery", scheme, width))
    assert page.evaluate("window.__violations") == []
    page.emulate_media(color_scheme="light")
    page.set_viewport_size({"width": 1280, "height": 900})

    # From the code field, Tab reaches the box and Space ticks it; Tab again, the button.
    code = page.get_by_label("Authentication code")
    code.fill(mfa.totp(seed, step(runtime)))
    expect(code).to_be_focused()
    page.keyboard.press("Tab")
    expect(box).to_be_focused()
    page.keyboard.press("Space")
    expect(box).to_be_checked()
    page.keyboard.press("Tab")
    expect(code_form.get_by_role("button", name="Verify", exact=True)).to_be_focused()
    page.keyboard.press("Enter")
    expect(page).to_have_url(re.compile(r"/approvals$"))
    [trust] = [c for c in page.context.cookies() if c["name"] == "eb_trust"]
    assert trust["httpOnly"] and trust["sameSite"] == "Lax" and trust["path"] == "/"

    # Signed out, with only the trust cookie left, the next sign-in on this browser skips the
    # code and lands where an approver's sign-in lands.
    page.goto("about:blank")
    page.context.clear_cookies()
    page.context.add_cookies([trust])
    runtime.clock.value += timedelta(seconds=30)
    password(page)
    expect(page).to_have_url(re.compile(r"/approvals$"))
    expect(page.get_by_role("heading", level=1)).to_have_text("Approvals")


def test_tb_an_unticked_box_leaves_the_next_sign_in_asking(page, runtime, enrolled):
    seed, _ = enrolled
    sign_in(page)
    page.get_by_label("Authentication code").fill(mfa.totp(seed, step(runtime)))
    page.get_by_role("button", name="Verify", exact=True).click()
    expect(page).to_have_url(re.compile(r"/approvals$"))
    assert [c for c in page.context.cookies() if c["name"] == "eb_trust"] == []
    page.goto("about:blank")
    page.context.clear_cookies()
    runtime.clock.value += timedelta(seconds=30)
    sign_in(page)


def test_tb_the_trusted_browsers_card_passes_the_audit_in_both_schemes(
    chromium, runtime, db, admin_engine, seeded
):
    """My account with two trusted browsers, this one marked: the card, and the page around
    it, are axe-clean, scroll nowhere sideways and record no policy violation in both schemes
    at 1280 and 390 (the spec's bar for the populated card)."""
    from test_trusted_browsers import granted
    from test_workspace_switching import RING, verified_pair

    runtime.clock = SystemClock()
    grant, current, _, _, _ = verified_pair(db, admin_engine, seeded)
    granted(db, admin_engine, current)
    mine, _, _ = granted(db, admin_engine, current)
    keys = TokenKeys("browser-v1", {"browser-v1": secrets.token_bytes(32)})

    def app(origin):
        return create_app(db, runtime=runtime, human=HumanConfig(origin, keys, mfa=RING))

    with serve(app) as gateway, chromium.new_context(base_url=gateway) as context:
        page = context.new_page()
        page.set_default_timeout(ACTION_TIMEOUT_MS)
        page.add_init_script(COLLECT)
        page.add_init_script(path=str(AXE))
        context.add_cookies(
            [
                {
                    "name": name,
                    "value": value,
                    "url": gateway,
                    "httpOnly": True,
                    "sameSite": same_site,
                }
                for name, value, same_site in (
                    ("eb_session", grant.token, "Strict"),
                    ("eb_csrf", grant.csrf_token, "Strict"),
                    ("eb_account", grant.account_token, "Strict"),
                    ("eb_trust", mine, "Lax"),
                )
            ]
        )
        page.goto("/settings")
        card = (
            page.locator("section, article, div.card")
            .filter(has=page.get_by_role("heading", name="Trusted browsers"))
            .last
        )
        expect(card).to_be_visible()
        rows = card.get_by_role("table").get_by_role("row")
        # The header row and the two trusts, newest (this browser's) first.
        expect(rows).to_have_count(3)
        expect(rows.nth(1)).to_contain_text("This browser")
        expect(rows.nth(2)).not_to_contain_text("This browser")
        expect(card.get_by_role("button", name="Remove all")).to_be_visible()
        for scheme, width, height in VIEWS:
            page.emulate_media(color_scheme=scheme)
            page.set_viewport_size({"width": width, "height": height})
            settled(page)
            card.scroll_into_view_if_needed()
            assert page.evaluate(AXE_RUN) == [], (scheme, width)
            assert page.evaluate(FITS), (scheme, width)
        assert page.evaluate("window.__violations") == []
