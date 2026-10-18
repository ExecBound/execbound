# SPDX-License-Identifier: AGPL-3.0-only
"""Returning to your place, in real Chromium (#678).

Signed out on a record's address, a person signs in and the drawer opens on that record. A new
policy document typed before the session ended is back after signing in again, and said so once.
Two minutes before a session's hard end the shell says when and what to do: a setup credential's
holder is told how to keep signing in and offered no sign-in it could not complete, and an
eight-hour session says typing is kept only on a page that keeps it. Copy link puts the router's
address on the clipboard. Each of those states passes axe at WCAG 2.2 AA with no policy or
Trusted Types violation and no sideways scroll, in both schemes, at 1280 and 390 pixels.
"""

import re
from urllib.parse import quote

import pytest
from playwright.sync_api import expect
from sqlalchemy import text
from test_browser_console import AXE_RUN, settled
from test_browser_console import console_gateway as console_gateway
from test_browser_console import console_page as console_page
from test_browser_surfaces import chromium as chromium
from test_console_api_activity import denied
from test_execution import registry as registry
from test_execution import world as world
from test_human_surface import credential
from test_protected_path import connector as connector
from test_protected_path import live_provider as live_provider
from test_runtime import runtime as runtime

DOCUMENT = '{"rules": "kept across a sign-in"}'


def setup_sign_in(page, admin_engine, identity) -> None:
    """Sign in with the setup credential from wherever the page is, keeping any hint."""
    page.goto("/login?setup=1")
    page.get_by_label("Setup credential").fill(credential(admin_engine, identity))
    page.get_by_role("button", name="Continue setup").click()


def clean(page, where: str) -> None:
    settled(page)
    assert page.evaluate(AXE_RUN) == [], where
    assert page.evaluate("window.__violations") == [], where
    assert page.evaluate(
        "document.documentElement.scrollWidth <= document.documentElement.clientWidth"
    ), (where, "horizontal scroll")


def end_in(admin_engine, identity, seconds: int, *, setup: bool) -> None:
    """Move the signed-in session's hard end to `seconds` from now, through the admin engine.

    A setup credential's session ends on the credential; an eight-hour session ends eight hours
    after it was created, so its creation is moved back instead and its credential with it."""
    with admin_engine.begin() as conn:
        if setup:
            conn.execute(
                text(
                    "UPDATE execbound.human_sessions SET credential_expires_at = "
                    "now() + make_interval(secs => :s), expires_at = least(expires_at, "
                    "now() + make_interval(secs => :s)) WHERE tenant_id=:t AND principal_id=:p "
                    "AND revoked_at IS NULL"
                ),
                {"s": seconds, "t": identity.tenant_id, "p": identity.principal_id},
            )
            ends = "now() + make_interval(secs => :s)"
        else:
            conn.execute(
                text(
                    "UPDATE execbound.human_sessions SET created_at = now() - interval '8 hours' "
                    "+ make_interval(secs => :s), credential_expires_at = now() + "
                    "make_interval(secs => :s), expires_at = least(expires_at, now() + "
                    "make_interval(secs => :s)) WHERE tenant_id=:t AND principal_id=:p "
                    "AND revoked_at IS NULL"
                ),
                {"s": seconds, "t": identity.tenant_id, "p": identity.principal_id},
            )
            ends = "now() + make_interval(secs => :s)"
        conn.execute(
            text(
                f"UPDATE execbound.credentials SET expires_at = {ends} "
                "WHERE tenant_id=:t AND credential_id=:c"
            ),
            {"s": seconds, "t": identity.tenant_id, "c": identity.credential_id},
        )


def notice(page):
    return page.locator(".banner-ending")


def type_document(page) -> None:
    page.get_by_text("Advanced: import or copy complete configuration").click()
    page.get_by_label("Bundle JSON").fill(DOCUMENT)


def test_sn19_a_signed_out_record_link_opens_its_drawer_after_signing_in(
    console_page, admin_engine, world, runtime
):
    record = denied(runtime, admin_engine, world).execution_id
    console_page.goto(f"/activity?open={record}&cursor=x")
    place = f"/activity?open={record}"
    expect(console_page).to_have_url(
        re.compile(re.escape("/login?review=" + quote(place, safe="")))
    )
    setup_sign_in(console_page, admin_engine, world["admin"])
    expect(console_page).to_have_url(re.compile(re.escape(place) + "$"))
    drawer = console_page.get_by_role("dialog", name=re.compile("Isolate endpoint"))
    expect(drawer).to_be_visible()
    # Copy link puts the router's address for the record on the clipboard, not the bar's.
    console_page.context.grant_permissions(["clipboard-read", "clipboard-write"])
    drawer.get_by_role("button", name="Copy link").click()
    expect(drawer.get_by_text("Link copied.")).to_be_visible()
    origin = console_page.evaluate("location.origin")
    assert console_page.evaluate("navigator.clipboard.readText()") == origin + place


def test_sn19_a_new_policy_document_survives_the_session_ending(console_page, admin_engine, world):
    setup_sign_in(console_page, admin_engine, world["admin"])
    console_page.goto("/policy")
    expect(console_page.get_by_role("heading", level=1)).to_have_text("Policies")
    type_document(console_page)
    # The session ends underneath the page: its row is revoked, as signing out elsewhere does.
    with admin_engine.begin() as conn:
        conn.execute(
            text(
                "UPDATE execbound.human_sessions SET revoked_at = now() "
                "WHERE tenant_id=:t AND principal_id=:p AND revoked_at IS NULL"
            ),
            {"t": world["admin"].tenant_id, "p": world["admin"].principal_id},
        )
    # The change is refused for the ended session, and the console leaves for sign-in with
    # this page as the place to come back to.
    console_page.get_by_role("button", name="Create from JSON").click()
    expect(console_page).to_have_url(re.compile(re.escape("/login?review=%2Fpolicy") + "$"))
    setup_sign_in(console_page, admin_engine, world["admin"])
    expect(console_page).to_have_url(re.compile(r"/policy$"))
    expect(console_page.get_by_label("Bundle JSON")).to_have_value(DOCUMENT)
    expect(console_page.get_by_text("Your policy document was kept.")).to_have_count(1)


def test_sn19_a_setup_credential_is_told_how_to_keep_signing_in(console_page, admin_engine, world):
    setup_sign_in(console_page, admin_engine, world["admin"])
    end_in(admin_engine, world["admin"], 100, setup=True)
    console_page.goto("/policy")
    expect(notice(console_page)).to_contain_text(
        "The setup credential you signed in with expires at"
    )
    expect(notice(console_page)).to_contain_text(
        "It cannot be used after that: set up your own sign-in before then. "
        "Save what you are doing."
    )
    expect(notice(console_page).get_by_role("button", name="Sign in again")).to_have_count(0)
    notice(console_page).get_by_role("link", name="How to sign in after setup").click()
    expect(console_page).to_have_url(re.compile(r"/help$"))
    expect(console_page.get_by_text("Signed in with a setup credential?")).to_be_visible()


def test_sn19_an_eight_hour_session_says_typing_is_kept_only_where_it_is(
    console_page, admin_engine, world
):
    setup_sign_in(console_page, admin_engine, world["admin"])
    end_in(admin_engine, world["admin"], 100, setup=False)
    console_page.goto("/policy")
    expect(notice(console_page)).to_contain_text("eight hours after you signed in.")
    expect(notice(console_page)).to_contain_text(
        "Sign in again to keep working. What you have typed on this page is kept."
    )
    expect(notice(console_page).get_by_role("button", name="Sign in again")).to_be_visible()
    console_page.goto("/settings")
    expect(notice(console_page)).to_contain_text(
        "Save what you are doing, then sign in again to keep working."
    )


@pytest.mark.parametrize("width", [1280, 390])
@pytest.mark.parametrize("scheme", ["light", "dark"])
def test_sn19_each_state_is_clean(console_page, admin_engine, world, runtime, scheme, width):
    console_page.emulate_media(color_scheme=scheme)
    console_page.set_viewport_size({"width": width, "height": 844 if width == 390 else 900})
    record = denied(runtime, admin_engine, world).execution_id
    setup_sign_in(console_page, admin_engine, world["admin"])
    # The drawer with Copy reference and Copy link.
    console_page.goto(f"/activity?open={record}")
    drawer = console_page.get_by_role("dialog", name=re.compile("Isolate endpoint"))
    expect(drawer.get_by_role("button", name="Copy reference")).to_be_visible()
    clean(console_page, "the drawer")
    # The agent page with its own Copy link.
    console_page.goto(f"/agents/{world['identity'].principal_id}")
    expect(console_page.get_by_role("button", name="Copy link")).to_be_visible()
    clean(console_page, "the agent page")
    # The setup credential's notice.
    end_in(admin_engine, world["admin"], 100, setup=True)
    console_page.goto("/settings")
    expect(notice(console_page)).to_be_visible()
    clean(console_page, "the setup credential's notice")
    if width == 390:
        box = notice(console_page).get_by_role("link").bounding_box()
        assert box is not None and box["height"] >= 44, box
    # The eight-hour notice, over a kept document restored on the policy page.
    end_in(admin_engine, world["admin"], 100, setup=False)
    console_page.goto("/policy")
    type_document(console_page)
    console_page.reload()
    expect(console_page.get_by_text("Your policy document was kept.")).to_be_visible()
    expect(notice(console_page)).to_contain_text("What you have typed on this page is kept.")
    clean(console_page, "the eight-hour notice and the kept document")
    if width == 390:
        box = notice(console_page).get_by_role("button").bounding_box()
        assert box is not None and box["height"] >= 44, box
