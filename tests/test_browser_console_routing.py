# SPDX-License-Identifier: AGPL-3.0-only
"""Decision coverage in real Chromium (AR22, AR23).

A request held with nobody who can decide it shows on Home to a workspace administrator; the
line's Choose reviewers lands on the Decision coverage card, whose Add to a rule opens the
existing rule dialog with the gap's target chosen; once the administrator saves the rule with a
reason, the gap leaves the card and the reviewer can decide the held request. The pages that
carry the line and the card are axe-clean with zero policy or Trusted Types violations in both
schemes at 1280 and 390 pixels.
"""

from uuid import uuid4

import pytest
from playwright.sync_api import expect
from sqlalchemy import text
from test_browser_console import audit, settled, sign_in_as
from test_browser_console import console_gateway as console_gateway
from test_browser_console import console_page as console_page
from test_browser_surfaces import FITS
from test_browser_surfaces import chromium as chromium
from test_execution import registry as registry
from test_execution import request
from test_execution import world as world
from test_protected_path import connector as connector
from test_protected_path import live_provider as live_provider
from test_runtime import runtime as runtime

from execbound import approval_routing
from execbound.execution import admit, decide_approval
from execbound.policy.rulesets import ruleset_bundle
from execbound.policy.store import activate_bundle, create_bundle, validate_bundle
from execbound_harness.demo import ENDPOINT_RULESET

pytestmark = pytest.mark.integration


def held_with_nobody(db, admin_engine, world):
    """The endpoint ruleset active, nobody assigned, one request held, and an empty reviewer
    group with the reviewer in it for a rule to name."""
    tenant = world["identity"].tenant_id
    bundle = ruleset_bundle(
        ENDPOINT_RULESET, tenant_id=tenant, bundle_id=uuid4(), mappings=world["bundle"].mappings
    )
    create_bundle(db, world["admin"], bundle, world["clock"])
    validate_bundle(db, world["admin"], bundle.bundle_id, world["clock"])
    activate_bundle(db, world["admin"], bundle.bundle_id, world["clock"])
    group = uuid4()
    with admin_engine.begin() as conn:
        conn.execute(
            text("DELETE FROM execbound.approval_scopes WHERE tenant_id = :t"), {"t": tenant}
        )
        conn.execute(
            text(
                "INSERT INTO execbound.access_groups(tenant_id, group_id, name) "
                "VALUES (:t, :g, 'Endpoint reviewers')"
            ),
            {"t": tenant, "g": group},
        )
        conn.execute(
            text(
                "INSERT INTO execbound.access_group_members(tenant_id, group_id, principal_id) "
                "VALUES (:t, :g, :p)"
            ),
            {"t": tenant, "g": group, "p": world["human"].principal_id},
        )
    pending = admit(db, world["identity"], request(world), world["clock"])
    assert pending.view.state == "PENDING_APPROVAL"
    with admin_engine.connect() as conn:
        recorded = conn.execute(
            text(
                "SELECT reviewers_at_hold FROM execbound.approvals "
                "WHERE tenant_id = :t AND approval_id = :a"
            ),
            {"t": tenant, "a": pending.view.approval_id},
        ).scalar_one()
    assert recorded == 0
    return pending.view


def test_ar22_an_unrouted_request_is_shown_and_fixed_from_coverage(
    console_page, db, admin_engine, world
):
    view = held_with_nobody(db, admin_engine, world)
    page = console_page
    sign_in_as(page, admin_engine, world["admin"])
    page.goto("/")
    needs = page.locator("section").filter(
        has=page.get_by_role("heading", name="Waiting on a person")
    )
    expect(needs.get_by_text("No one can approve 1 held request.")).to_be_visible()
    expect(needs.get_by_text("cannot be approved as things stand")).to_be_visible()
    needs.get_by_role("link", name="Choose reviewers").click()
    expect(page).to_have_url("/approvers#coverage")
    card = page.locator("#coverage")
    expect(
        card.get_by_text("1 resource requested in the last 30 days cannot be decided.")
    ).to_be_visible()
    card.get_by_text("Add to a rule").first.click()
    card.get_by_role("button", name="New rule").first.click()
    dialog = page.get_by_role("dialog", name="Create approval rule")
    dialog.get_by_label("Rule name").fill("Endpoint response")
    dialog.get_by_label("Reviewer group").select_option(label="Endpoint reviewers")
    expect(dialog.get_by_role("checkbox", name="Isolate endpoint")).to_be_checked()
    dialog.get_by_label("Reason for this rule change").fill("Route the held endpoint")
    dialog.get_by_role("button", name="Save rule").click()
    expect(dialog).to_be_hidden()
    expect(card.get_by_text("cannot be decided")).to_have_count(0)
    settled(page)
    assert page.evaluate("window.__violations") == []
    tenant = world["identity"].tenant_id
    with db.transaction(tenant) as conn:
        space = conn.execute(
            text("SELECT space_id FROM execbound.approvals WHERE tenant_id=:t AND approval_id=:a"),
            {"t": tenant, "a": view.approval_id},
        ).scalar_one()
        assert (
            approval_routing.eligible_reviewers(
                conn, tenant, space, world["canonical"], "endpoint.isolate"
            )
            == 1
        )
    # The reviewer can now decide the request held before the rule existed.
    decide_approval(db, world["human"], view.approval_id, "APPROVE", world["clock"])


@pytest.mark.parametrize("width", [1280, 390])
@pytest.mark.parametrize("scheme", ["dark", "light"])
def test_ar23_routing_pages_are_accessible(console_page, db, admin_engine, world, scheme, width):
    held_with_nobody(db, admin_engine, world)
    page = console_page
    page.emulate_media(color_scheme=scheme)
    page.set_viewport_size({"width": width, "height": 844 if width == 390 else 900})
    sign_in_as(page, admin_engine, world["admin"])
    audit(page, "/approvers", "Approval rules")
    expect(page.locator("#coverage").get_by_text("Nobody can decide this action")).to_be_visible()
    audit(page, "/", "Home")
    expect(page.get_by_text("No one can approve 1 held request.")).to_be_visible()
    audit(page, "/approvals", "Approvals")
    expect(page.get_by_text("No one can approve 1 held request.")).to_be_visible()
    for path in ("/approvers", "/", "/approvals"):
        page.goto(path)
        settled(page)
        assert page.evaluate(FITS), (path, width)
        assert page.evaluate("window.__violations") == []
