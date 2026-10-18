# SPDX-License-Identifier: AGPL-3.0-only
"""Synthetic group access and approval routing through the real console and API."""

import re
from pathlib import Path

from playwright.sync_api import expect
from sqlalchemy import text
from test_browser_console import AXE_RUN, audit, settled, sign_in_as
from test_browser_console import console_gateway as console_gateway
from test_browser_console import console_page as console_page
from test_browser_surfaces import chromium as chromium
from test_execution import registry as registry
from test_execution import world as world
from test_protected_path import connector as connector
from test_protected_path import live_provider as live_provider
from test_runtime import runtime as runtime


def card(page, name):
    return page.locator("section.card").filter(
        has=page.get_by_role("heading", level=2, name=name, exact=True)
    )


def capture(page, name):
    output = Path(__file__).resolve().parents[1] / "local-data" / "access-experience"
    output.mkdir(parents=True, exist_ok=True)
    page.screenshot(path=output / name, full_page=True)


def test_group_members_roles_and_approval_rule_lifecycle(console_page, admin_engine, world):
    """A group grants review access only through explicit role, action and resource choices."""
    page = console_page
    with admin_engine.begin() as conn:
        conn.execute(
            text("UPDATE execbound.principals SET label=:label WHERE principal_id=:p"),
            {"label": "Synthetic responder", "p": world["human"].principal_id},
        )
        conn.execute(
            text("DELETE FROM execbound.approval_scopes WHERE approver_id=:p"),
            {"p": world["human"].principal_id},
        )
    sign_in_as(page, admin_engine, world["admin"])
    audit(page, "/access", "Groups & roles")
    space = page.request.get("/api/console/v1/access").json()["spaces"][0]

    page.get_by_role("button", name="Create group", exact=True).click()
    dialog = page.get_by_role("dialog", name="Create group", exact=True)
    expect(dialog.get_by_role("button", name="Create group", exact=True)).to_be_disabled()
    dialog.get_by_label("Group name").fill("Synthetic response team")
    dialog.get_by_label("Description", exact=True).fill("Review synthetic endpoint actions")
    dialog.get_by_label("Reason for this change").fill("Set up the synthetic response team")
    settled(page)
    assert page.evaluate(AXE_RUN) == []
    dialog.get_by_role("button", name="Create group", exact=True).click()
    expect(dialog).to_have_count(0)
    group_card = card(page, "Synthetic response team")
    expect(group_card).to_contain_text("0 users")
    expect(group_card).to_contain_text("No group roles")

    group_card.get_by_role("button", name="Edit members").click()
    dialog = page.get_by_role("dialog", name="Members of Synthetic response team")
    dialog.get_by_role("checkbox", name="Synthetic responder", exact=True).check()
    dialog.get_by_label("Reason for this change").fill("Assign the synthetic responder")
    dialog.get_by_role("button", name="Save members").click()
    expect(dialog).to_have_count(0)
    expect(group_card).to_contain_text("1 user")

    group_card.get_by_role("button", name="Edit group roles").click()
    dialog = page.get_by_role("dialog", name="Roles for Synthetic response team")
    dialog.get_by_role("button", name="Add role", exact=True).click()
    dialog.get_by_role("combobox", name="Role 1", exact=True).select_option("approver")
    dialog.get_by_role("combobox", name="Scope 1", exact=True).select_option(space["space_id"])
    dialog.get_by_label("Reason for this change").fill("Grant review access in the selected Space")
    dialog.get_by_role("button", name="Save group roles").click()
    expect(dialog).to_have_count(0)
    expect(group_card).to_contain_text(f"Approver · {space['name']}")
    user_row = (
        page.get_by_role("table", name="User roles and their sources")
        .get_by_role("row")
        .filter(has=page.get_by_role("link", name="Synthetic responder", exact=True))
    )
    expect(user_row).to_contain_text(f"Approver · {space['name']} (Synthetic response team)")
    settled(page)
    capture(page, "groups-and-roles.png")

    audit(page, "/approvers", "Approval rules")
    page.get_by_role("button", name="Create approval rule", exact=True).click()
    dialog = page.get_by_role("dialog", name="Create approval rule", exact=True)
    expect(dialog.get_by_label("Rule name")).to_be_focused()
    dialog.get_by_label("Rule name").fill("Synthetic endpoint response")
    dialog.get_by_label("Reviewer group").select_option(label="Synthetic response team")
    dialog.get_by_role("combobox", name="Space", exact=True).select_option(space["space_id"])
    expect(dialog.get_by_role("status")).to_contain_text("1 eligible reviewer")
    actions = page.request.get("/api/console/v1/approval-rules").json()["actions"]
    action_names = {action["id"]: action["name"] for action in actions}
    dialog.get_by_role("checkbox", name=action_names["endpoint.isolate"], exact=True).check()
    dialog.get_by_label("Reason for this rule change").fill("Route only the selected endpoint")
    expect(dialog.get_by_role("button", name="Save rule")).to_be_disabled()
    dialog.get_by_role("checkbox", name=re.compile(str(world["canonical"])[:8])).check()
    settled(page)
    assert page.evaluate(AXE_RUN) == []
    capture(page, "approval-rule-dialog.png")
    for width in (1280, 390):
        page.set_viewport_size({"width": width, "height": 844})
        for scheme in ("dark", "light"):
            page.emulate_media(color_scheme=scheme)
            settled(page)
            save_bounds = dialog.get_by_role("button", name="Save rule").bounding_box()
            assert save_bounds is not None
            assert 0 <= save_bounds["y"] < save_bounds["y"] + save_bounds["height"] <= 844
            assert page.evaluate(AXE_RUN) == []
    page.set_viewport_size({"width": 1280, "height": 900})
    dialog.get_by_role("button", name="Save rule").click()
    expect(dialog).to_have_count(0)
    rule_card = card(page, "Synthetic endpoint response")
    expect(rule_card).to_contain_text("Active")
    expect(rule_card).to_contain_text("1 eligible reviewer")
    expect(rule_card).to_contain_text("1 selected resource")

    rule_card.get_by_role("button", name="Edit rule").click()
    dialog = page.get_by_role("dialog", name="Edit Synthetic endpoint response")
    dialog.get_by_role("checkbox", name=action_names["endpoint.isolate"], exact=True).uncheck()
    dialog.get_by_role("checkbox", name=action_names["endpoint.lift_isolation"], exact=True).check()
    dialog.get_by_label("Reason for this rule change").fill("Route recovery reviews instead")
    dialog.get_by_role("button", name="Save rule").click()
    expect(dialog).to_have_count(0)
    expect(rule_card).to_contain_text(action_names["endpoint.lift_isolation"])
    expect(rule_card).not_to_contain_text(action_names["endpoint.isolate"])
    saved = page.request.get("/api/console/v1/approval-rules").json()["rules"]
    assert len(saved) == 1
    assert saved[0]["actions"] == ["endpoint.lift_isolation"]
    assert saved[0]["targets"] == [str(world["canonical"])]
    assert saved[0]["space_id"] == space["space_id"]

    rule_card.get_by_role("button", name="Disable rule").click()
    dialog = page.get_by_role("dialog", name="Disable Synthetic endpoint response?")
    expect(dialog.get_by_role("button", name="Disable rule")).to_be_disabled()
    dialog.get_by_label("Reason for disabling").fill("Retire the synthetic routing rule")
    dialog.get_by_role("button", name="Disable rule").click()
    expect(dialog).to_have_count(0)
    expect(rule_card).to_contain_text("Disabled")
    expect(rule_card.get_by_role("button", name="Disable rule")).to_have_count(0)
    assert page.request.get("/api/console/v1/approval-rules").json()["rules"][0]["active"] is False
    page.reload()
    expect(card(page, "Synthetic endpoint response")).to_contain_text("Disabled")
    settled(page)
    assert page.evaluate(AXE_RUN) == []
    assert page.evaluate("window.__violations") == []

    audit(page, "/access", "Groups & roles")
    group_card = card(page, "Synthetic response team")
    group_card.get_by_role("button", name="Edit members").click()
    dialog = page.get_by_role("dialog", name="Members of Synthetic response team")
    dialog.get_by_role("checkbox", name="Synthetic responder", exact=True).uncheck()
    dialog.get_by_label("Reason for this change").fill("Complete synthetic test")
    dialog.get_by_role("button", name="Save members").click()
    expect(dialog).to_have_count(0)
    expect(group_card).to_contain_text("0 users")
    group_card.get_by_role("button", name="Edit group roles").click()
    dialog = page.get_by_role("dialog", name="Roles for Synthetic response team")
    dialog.get_by_role("button", name="Remove role 1").click()
    expect(dialog).to_contain_text("This group grants no roles")
    dialog.get_by_label("Reason for this change").fill("Complete synthetic test")
    dialog.get_by_role("button", name="Save group roles").click()
    expect(dialog).to_have_count(0)
    expect(group_card).to_contain_text("No group roles")
    group_card.get_by_role("button", name="Delete group").click()
    dialog = page.get_by_role("dialog", name="Delete Synthetic response team?")
    dialog.get_by_label("Reason for deleting").fill("Remove completed synthetic group")
    dialog.get_by_role("button", name="Delete group").click()
    expect(dialog).to_have_count(0)
    expect(group_card).to_have_count(0)
    assert page.request.get("/api/console/v1/approval-rules").json()["rules"] == []

    page.set_viewport_size({"width": 390, "height": 844})
    for scheme in ("dark", "light"):
        page.emulate_media(color_scheme=scheme)
        audit(page, "/access", "Groups & roles")
        audit(page, "/approvers", "Approval rules")
