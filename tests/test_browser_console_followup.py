# SPDX-License-Identifier: AGPL-3.0-only
"""The reported empty approvals and self-profile regressions in a real browser."""

import re
from pathlib import Path

from playwright.sync_api import expect
from test_browser_console import AXE_RUN, audit, person_name, settled, sign_in_as
from test_browser_console import console_gateway as console_gateway
from test_browser_console import console_page as console_page
from test_browser_surfaces import chromium as chromium
from test_execution import registry as registry
from test_execution import world as world
from test_protected_path import connector as connector
from test_protected_path import live_provider as live_provider
from test_runtime import runtime as runtime

from execbound.spaces import create_space


def test_empty_queue_and_own_profile_after_space_creation(console_page, admin_engine, world, db):
    page = console_page
    actor = world["admin"]
    with db.transaction(actor.tenant_id) as conn:
        create_space(
            conn, actor.tenant_id, actor.principal_id, "Profile regression", None, credential=None
        )
    sign_in_as(page, admin_engine, actor)
    output = Path("local-data/access-experience/followup")
    output.mkdir(parents=True, exist_ok=True)
    for width in (1280, 390):
        page.set_viewport_size({"width": width, "height": 900})
        audit(page, "/approvals", "Approvals")
        expect(page.get_by_text("Nothing is waiting for you.", exact=True)).to_have_count(1)
        expect(page.get_by_role("region", name="Detail", exact=True)).to_have_count(0)
        page.screenshot(path=output / f"approvals-{width}.png", full_page=True)
        audit(page, "/people", "Users")
        page.locator(f'a[href="/people/{actor.principal_id}"]').click()
        name = person_name(admin_engine, actor.principal_id)
        expect(page.get_by_role("heading", name=name, exact=True)).to_be_visible()
        expect(page.get_by_text("Created space", exact=True)).to_be_visible()
        expect(page.get_by_text("This user could not be loaded.", exact=True)).to_have_count(0)
        page.screenshot(path=output / f"profile-{width}.png", full_page=True)
        # The endpoint seed reads as its rules on the agent's Permissions, with the exact
        # documents kept beneath them (#678).
        page.goto(f"/agents/{world['identity'].principal_id}?section=permissions")
        rules = page.get_by_role("table", name=re.compile("Rules are as they read"))
        expect(rules).to_contain_text("Isolate endpoint")
        conditions = page.locator("details").filter(
            has=page.get_by_text("Exact policy documents", exact=True)
        )
        conditions.get_by_text("Exact policy documents", exact=True).click()
        expect(conditions.locator("pre").first).to_be_visible()
        settled(page)
        assert page.evaluate(AXE_RUN) == []
        assert page.evaluate(
            "document.documentElement.scrollWidth <= document.documentElement.clientWidth"
        )
        conditions.screenshot(path=output / f"policy-conditions-{width}.png")
