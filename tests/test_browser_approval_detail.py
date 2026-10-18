# SPDX-License-Identifier: AGPL-3.0-only
"""The classic approval page in real Chromium: its policy, the keyboard, a phone, no scripts.

`/approvals/{id}/classic` is the page that stays server-rendered after the switch to the
console (#333): the console's approval route links it from its error boundary and every approval
notification links it from its footer, because it is the product's most important human control
and some locked-down phones block scripts. It carries no script of its own now — the
enhancement module went with the pages the console replaced — so what is asserted here is that
it decides with scripts blocked entirely, and that it still says why once it cannot.
"""

import re

from playwright.sync_api import expect
from test_browser_surfaces import agent_http as agent_http
from test_browser_surfaces import assert_responsive, sign_in
from test_browser_surfaces import browser_gateway as browser_gateway
from test_browser_surfaces import chromium as chromium
from test_browser_surfaces import human_page as human_page
from test_browser_surfaces import pending as pending_over_http
from test_execution import registry as registry
from test_execution import targets
from test_execution import world as world
from test_protected_path import connector as connector
from test_protected_path import live_provider as live_provider
from test_runtime import runtime as runtime

COMMENT = "Comment for the audit record (optional, up to 500 characters)"


def test_the_classic_page_decides_by_keyboard_and_with_scripts_blocked(
    human_page, browser_gateway, agent_http, admin_engine, world
):
    sign_in(human_page, admin_engine, world)
    first = pending_over_http(agent_http, world)
    response = human_page.goto(f"/approvals/{first['approval_id']}/classic")
    assert response is not None
    policy = response.headers["content-security-policy"]
    # The pages' own policy, not the console's: this page is server-rendered and has no
    # script to allow, and `font-src 'self'` is what serves it the packaged IBM Plex.
    assert "default-src 'none'" in policy and "script-src 'self'" in policy
    assert "font-src 'self'" in policy and "require-trusted-types-for" not in policy
    expect(human_page.get_by_role("heading", level=1)).to_contain_text("device-01")
    approve = human_page.get_by_role("button", name="Approve this action")
    deny = human_page.get_by_role("button", name="Deny")
    human_page.set_viewport_size({"width": 390, "height": 844})
    assert_responsive(human_page, [human_page.get_by_label(COMMENT), approve, deny])
    # Keyboard only: comment, tab to Approve, Enter.
    human_page.get_by_label(COMMENT).focus()
    human_page.keyboard.type("Approved after review")
    human_page.keyboard.press("Tab")
    expect(human_page.get_by_role("button", name="Approve this action")).to_be_focused()
    human_page.keyboard.press("Enter")
    expect(human_page).to_have_url(re.compile(r"/approvals$"))

    # With every script blocked the page behaves the same, because it has none of its own.
    [production] = targets(admin_engine, world, count=1, production=True)
    second = agent_http.post("/v1/execute", json=production.model_dump(mode="json")).json()
    assert second["state"] == "PENDING_APPROVAL"
    human_page.route("**/*.js", lambda route: route.abort())
    human_page.goto(f"/approvals/{second['approval_id']}/classic")
    expect(human_page.get_by_role("heading", level=1)).to_be_visible()
    assert human_page.locator("script").count() == 0
    human_page.get_by_role("button", name="Deny").click()
    expect(human_page).to_have_url(re.compile(r"/approvals$"))
    human_page.goto(f"/approvals/{second['approval_id']}/classic")
    expect(human_page.locator(".notice")).to_contain_text("denied")
    expect(human_page.locator("form.decision")).to_have_count(0)
