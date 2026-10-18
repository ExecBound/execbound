# SPDX-License-Identifier: AGPL-3.0-only
"""The Approvals page of the console in real Chromium (#333).

A cold approval link, decided by the keyboard alone; the phone layout with the tab bar and
the decision buttons pinned at equal widths and 50 px; the ring counting down from the server's
expiry even on a phone whose clock is an hour fast; the toast and the next item after a
decision; a quorum of two needing two different people; a decision posted during a stop
refused with the page saying why; a hostile target rendered as text; and the route axe-clean
with zero policy or Trusted Types violations in both schemes at 1280 and 390 px.
"""

import re
from datetime import timedelta
from uuid import UUID

import httpx
import pytest
from playwright.sync_api import expect
from sqlalchemy import text
from test_approval_quorum import activate, quorum_bundle, second_approver
from test_browser_console import AXE_RUN, settled, sign_in_as
from test_browser_console import console_gateway as console_gateway
from test_browser_console import console_page as console_page
from test_browser_console_step_up import RING, step
from test_browser_console_step_up import gateway as gateway
from test_browser_console_step_up import page as page
from test_browser_surfaces import ACTION_TIMEOUT_MS
from test_browser_surfaces import chromium as chromium
from test_execution import provision_identity, request, targets
from test_execution import registry as registry
from test_execution import world as world
from test_monitoring_worker import receiver as receiver
from test_protected_path import connector as connector
from test_protected_path import live_provider as live_provider
from test_runtime import runtime as runtime

from execbound import mfa, notifications
from execbound.administration import assign_approver, invite_person
from execbound.execution import activate_stop, release_stop
from execbound.notifications import Destination
from execbound.passwords import redeem_reset
from execbound.recovery_run import recover
from execbound.surfaces.sessions import issue_session, load_session, revoke_sessions_of

COLLECT = """
(() => {
  window.__violations = [];
  document.addEventListener('securitypolicyviolation', (event) => {
    window.__violations.push(event.violatedDirective + ' ' + (event.blockedURI || ''));
  });
})();
"""
FAST_CLOCK = "const real = Date.now; Date.now = () => real() + 3600 * 1000;"


@pytest.fixture
def agent(console_gateway, seeded):
    with httpx.Client(
        base_url=console_gateway,
        headers={"Authorization": "Bearer " + seeded["tokens"][0]},
        trust_env=False,
    ) as client:
        yield client


def pending(agent, world, **changes):
    response = agent.post("/v1/execute", json=request(world, **changes).model_dump(mode="json"))
    assert response.status_code == 202, response.text
    result = response.json()
    assert result["state"] == "PENDING_APPROVAL"
    return result


def approval_state(engine, approval_id):
    with engine.begin() as conn:
        return conn.execute(
            text("SELECT state FROM execbound.approvals WHERE approval_id=:a"), {"a": approval_id}
        ).scalar_one()


def open_approval(page, approval_id, target="device-01"):
    response = page.goto(f"/approvals/{approval_id}")
    assert response is not None and response.ok
    expect(page.get_by_role("heading", level=1)).to_have_text("Approvals")
    expect(page.get_by_role("heading", level=2, name=target)).to_be_visible()
    expect(page.get_by_role("button", name="Approve")).to_be_visible()
    expect(page.get_by_role("button", name="Refuse")).to_be_visible()


def test_existing_admin_opens_email_link_signs_in_normally_and_reviews_on_phone_layout(
    console_page, admin_engine, world, agent, db, runtime, console_gateway, tmp_path
):
    admin = world["admin"]
    with admin_engine.begin() as conn:
        conn.execute(
            text("UPDATE execbound.principals SET email=:e WHERE principal_id=:p"),
            {"e": "review-admin@example.com", "p": admin.principal_id},
        )
    code_file = tmp_path / "set-password.txt"
    invited = invite_person(
        admin_engine,
        admin.tenant_id,
        "review-admin@example.com",
        "ADMIN",
        actor=admin.principal_id,
        origin=console_gateway,
        output=code_file,
        now=runtime.clock.now(),
    )
    assert invited.principal_id == admin.principal_id
    redeem_reset(
        db, code_file.read_text().strip(), "An ordinary test password!", clock=runtime.clock
    )
    assign_approver(
        admin_engine,
        admin.tenant_id,
        admin.principal_id,
        world["canonical"],
        "endpoint.isolate",
        admin.principal_id,
    )
    first = pending(agent, world, external_case={"source": "tines", "case_id": "INC-4821"})
    console_page.set_viewport_size({"width": 390, "height": 844})
    path = f"/approvals/{first['approval_id']}"
    console_page.goto(path)
    expect(console_page.get_by_label("Review credential")).to_have_count(0)
    console_page.get_by_label("Email", exact=True).fill("review-admin@example.com")
    console_page.get_by_label("Password", exact=True).fill("An ordinary test password!")
    console_page.get_by_role("button", name="Sign in with a password").click()
    expect(console_page).to_have_url(console_gateway + path)
    settled(console_page)
    # The page itself carries the reference; the breadcrumb names the page by it too (#678).
    expect(
        console_page.locator("main").get_by_text(first["request_ref"], exact=True)
    ).to_be_visible()
    expect(console_page.get_by_text("INC-4821", exact=True)).to_be_visible()
    expect(console_page.get_by_role("button", name=re.compile(r"^Approve\b"))).to_be_visible()
    with console_page.expect_response(
        lambda response: (
            response.request.method == "POST"
            and response.url.endswith(f"/approvals/{first['approval_id']}/decision")
        )
    ) as decision_response:
        console_page.get_by_role("button", name=re.compile(r"^Approve\b")).click()
    assert decision_response.value.request.header_value("x-csrf-token"), "Missing session CSRF"
    assert decision_response.value.status == 200, decision_response.value.json()
    expect(console_page.get_by_text("Nothing is waiting for you.").first).to_be_visible()
    assert approval_state(admin_engine, first["approval_id"]) == "APPROVED"
    result = agent.post("/v1/execute", json=request(world).model_dump(mode="json")).json()
    assert result["state"] == "EXECUTED" and result["execution_id"] == first["execution_id"]
    assert result["request_ref"] == first["request_ref"]
    with admin_engine.connect() as conn:
        assert (
            conn.execute(
                text("SELECT principal_id FROM execbound.approval_decisions WHERE approval_id=:a"),
                {"a": first["approval_id"]},
            ).scalar_one()
            == admin.principal_id
        )


def test_a_cold_link_is_decided_by_the_keyboard_alone_and_the_next_item_follows(
    console_page, admin_engine, world, agent, live_provider
):
    sign_in_as(console_page, admin_engine, world["human"])
    first = pending(agent, world)
    [production] = targets(admin_engine, world, count=1, production=True)
    second = agent.post("/v1/execute", json=production.model_dump(mode="json")).json()
    assert second["state"] == "PENDING_APPROVAL"
    open_approval(console_page, first["approval_id"])
    assert console_page.evaluate("window.__violations") == []
    # The queue lists both, the opened one marked as the current page.
    queue = console_page.get_by_role("list", name="Approvals")
    expect(queue.get_by_role("link")).to_have_count(2)
    expect(queue.locator('a[aria-current="page"]')).to_contain_text("device-01")
    # The approver can decide it, so at any width it is waiting for them (#678).
    expect(console_page.get_by_text("Waiting for you")).to_be_visible()
    expect(console_page.get_by_text("Reversible: yes, by Lift endpoint isolation.")).to_be_visible()
    expect(console_page.get_by_role("rowheader", name="environment")).to_be_visible()
    # Keyboard only: the comment, then Refuse, then Approve; Enter decides.
    console_page.get_by_label("Comment for the audit record (optional)").focus()
    console_page.keyboard.type("Approved after review")
    console_page.keyboard.press("Tab")
    expect(console_page.get_by_role("button", name="Refuse")).to_be_focused()
    console_page.keyboard.press("Tab")
    expect(console_page.get_by_role("button", name="Approve")).to_be_focused()
    console_page.keyboard.press("Enter")
    expect(console_page.get_by_role("status").filter(has_text="Approved device-01")).to_be_visible()
    # The next item is shown, and the decided one has left the queue.
    expect(console_page).to_have_url(re.compile(rf"/approvals/{second['approval_id']}$"))
    expect(queue.get_by_role("link")).to_have_count(1)
    # Never optimistic: the page showed the toast only once the row held the decision.
    assert approval_state(admin_engine, first["approval_id"]) == "APPROVED"
    # Decided today lists it.
    console_page.get_by_role("button", name=re.compile(r"^Decided today")).click()
    expect(
        console_page.get_by_role("list", name="Approvals").get_by_text("Approved")
    ).to_be_visible()
    assert console_page.evaluate("window.__violations") == []


def test_the_phone_layout_pins_the_buttons_and_counts_from_the_servers_clock(
    console_page, admin_engine, world, agent
):
    console_page.set_viewport_size({"width": 390, "height": 844})
    # A phone an hour fast: the ring still counts from the server's expiry.
    console_page.add_init_script(FAST_CLOCK)
    sign_in_as(console_page, admin_engine, world["human"])
    first = pending(agent, world)
    [production] = targets(admin_engine, world, count=1, production=True)
    agent.post("/v1/execute", json=production.model_dump(mode="json"))
    open_approval(console_page, first["approval_id"])
    tabs = console_page.get_by_role("navigation", name="Main, phone")
    expect(tabs).to_be_visible()
    expect(tabs.get_by_role("link", name=re.compile("Approvals"))).to_be_visible()
    approve = console_page.get_by_role("button", name="Approve")
    refuse = console_page.get_by_role("button", name="Refuse")
    approve_box = approve.bounding_box()
    refuse_box = refuse.bounding_box()
    tabs_box = tabs.bounding_box()
    assert approve_box is not None and refuse_box is not None and tabs_box is not None
    assert round(approve_box["height"]) == 50 and round(refuse_box["height"]) == 50
    # Equal widths: neither choice is preselected by its size (#678).
    assert abs(approve_box["width"] / refuse_box["width"] - 1) < 0.1, (approve_box, refuse_box)
    assert approve_box["y"] + approve_box["height"] <= tabs_box["y"] + 1
    assert approve_box["y"] + approve_box["height"] <= 844
    expect(console_page.get_by_text("Waiting for you", exact=True)).to_be_visible()
    left = console_page.locator(".detail-left")
    expect(left).to_have_text(re.compile(r"^[12]:[0-5]\d left$"))
    expect(console_page.get_by_role("heading", level=2, name="Also waiting")).to_be_visible()
    expect(console_page.get_by_role("list", name="Also waiting").get_by_role("link")).to_have_count(
        1
    )
    assert console_page.evaluate(
        "document.documentElement.scrollWidth <= document.documentElement.clientWidth"
    )
    settled(console_page)
    violations = console_page.evaluate(AXE_RUN)
    assert violations == []
    assert console_page.evaluate("window.__violations") == []


def test_a_quorum_of_two_needs_two_different_people(
    chromium, console_gateway, db, admin_engine, world, agent
):
    activate(db, world, quorum_bundle(world))
    other = second_approver(admin_engine, db, world)
    first = pending(agent, world)
    with chromium.new_context(
        base_url=console_gateway, viewport={"width": 1280, "height": 900}
    ) as one:
        page = one.new_page()
        page.set_default_timeout(ACTION_TIMEOUT_MS)
        sign_in_as(page, admin_engine, world["human"])
        open_approval(page, first["approval_id"])
        expect(page.get_by_text("Quorum: 2 approvals needed, none recorded yet.")).to_be_visible()
        page.get_by_role("button", name="Approve").click()
        expect(
            page.get_by_role("status").filter(has_text="recorded, 1 of 2 needed")
        ).to_be_visible()
        # The same person cannot count twice: the page says so and offers no buttons.
        page.goto(f"/approvals/{first['approval_id']}")
        expect(
            page.get_by_role("status").filter(has_text="Your decision (approve) is recorded")
        ).to_be_visible()
        expect(page.get_by_role("button", name="Approve")).to_have_count(0)
    assert approval_state(admin_engine, first["approval_id"]) == "PENDING"
    with chromium.new_context(
        base_url=console_gateway, viewport={"width": 1280, "height": 900}
    ) as two:
        page = two.new_page()
        page.set_default_timeout(ACTION_TIMEOUT_MS)
        sign_in_as(page, admin_engine, other)
        open_approval(page, first["approval_id"])
        expect(
            page.get_by_text(re.compile(r"Quorum: 2 approvals needed, 1 recorded"))
        ).to_be_visible()
        page.get_by_role("button", name="Approve").click()
        expect(page.get_by_role("status").filter(has_text="Approved device-01.")).to_be_visible()
    assert approval_state(admin_engine, first["approval_id"]) == "APPROVED"


def toasted(page, text: str):
    """One toast, not the page's own notice: several refusals say the same sentence twice,
    once as the answer to what was just tried and once as the state the page is in."""
    return page.locator(".toast").filter(has_text=text)


def test_a_decision_during_a_stop_is_refused_and_the_page_says_why(
    console_page, db, admin_engine, world, agent
):
    sign_in_as(console_page, admin_engine, world["human"])
    first = pending(agent, world)
    open_approval(console_page, first["approval_id"])
    activate_stop(db, world["admin"], "Contain agent 7", world["clock"])
    console_page.get_by_role("button", name="Approve").click()
    # Two live regions say it, and both are right: the toast answers the decision this
    # person just tried, the page's own notice is the standing state. Each is asserted
    # where it lives, because "the emergency stop is active" is a substring of both and a
    # locator over every role=status matches whichever has rendered by then.
    expect(toasted(console_page, "The emergency stop is active")).to_be_visible()
    expect(
        console_page.locator("p.notice[role=status]").filter(
            has_text="Decisions are paused while the emergency stop is active"
        )
    ).to_be_visible()
    expect(console_page.get_by_text("Contain agent 7")).to_be_visible()
    expect(console_page.get_by_role("button", name="Approve")).to_have_count(0)
    assert approval_state(admin_engine, first["approval_id"]) == "PENDING"
    release_stop(db, world["admin"], "Reviewed", world["clock"])
    console_page.reload()
    expect(console_page.get_by_role("button", name="Approve")).to_be_visible()
    console_page.get_by_role("button", name="Refuse").click()
    expect(console_page.get_by_role("status").filter(has_text="Refused device-01")).to_be_visible()
    assert approval_state(admin_engine, first["approval_id"]) == "DENIED"


def test_an_expired_approval_says_so_and_a_hostile_target_is_text(
    console_page, admin_engine, world, agent
):
    markup = "<b>device</b><img src=x onerror=alert(1)>"
    with admin_engine.begin() as conn:
        conn.execute(
            text(
                "UPDATE execbound.resources SET provider_id=:m "
                "WHERE tenant_id=:t AND resource_id=:r"
            ),
            {"m": markup, "t": world["identity"].tenant_id, "r": world["target"]},
        )
    sign_in_as(console_page, admin_engine, world["human"])
    first = pending(agent, world)
    open_approval(console_page, first["approval_id"], target=markup)
    title = console_page.get_by_role("heading", level=2, name=markup)
    expect(title).to_have_text(markup)
    assert console_page.locator("main img, main b").count() == 0
    world["clock"].value += timedelta(seconds=121)
    console_page.get_by_role("button", name="Approve").click()
    # An approver may have come from a message: they read what happened and who can act on
    # it, never advice about an execution history they cannot open (#678).
    expired = "This approval lapsed before your decision reached it. Nothing ran."
    expect(toasted(console_page, expired)).to_be_visible()
    expect(
        console_page.locator("p.notice[role=status]").filter(
            has_text="This approval lapsed before anyone decided it. Nothing ran. If the agent "
            "still needs this, it must send the request again."
        )
    ).to_be_visible()
    expect(console_page.get_by_role("button", name="Approve")).to_have_count(0)
    assert approval_state(admin_engine, first["approval_id"]) == "PENDING"
    assert console_page.evaluate("window.__violations") == []
    # #426: it is out of the pending queue and in the lapsed one, with the moment it
    # lapsed, rather than sitting in the queue reading 0:00.
    console_page.goto("/approvals")
    expect(console_page.get_by_role("button", name=re.compile(r"^Pending 0"))).to_be_visible()
    console_page.get_by_role("button", name=re.compile(r"^Lapsed")).click()
    row = console_page.locator("a.queue-row").first
    expect(row).to_contain_text("Lapsed")
    expect(row).to_contain_text("lapsed 20")
    assert console_page.locator(".queue-left").count() == 0
    assert console_page.evaluate("window.__violations") == []


@pytest.mark.parametrize("scheme", ["dark", "light"])
def test_the_approval_route_is_clean_in_both_schemes_and_at_both_widths(
    console_page, admin_engine, world, agent, scheme
):
    console_page.emulate_media(color_scheme=scheme)
    sign_in_as(console_page, admin_engine, world["human"])
    first = pending(agent, world)
    for width in (1280, 390):
        console_page.set_viewport_size({"width": width, "height": 900})
        open_approval(console_page, first["approval_id"])
        assert console_page.locator("#frame").count() == 0
        settled(console_page)
        violations = console_page.evaluate(AXE_RUN)
        assert violations == [], (width, violations)
        assert console_page.evaluate("window.__violations") == []
        assert console_page.evaluate(
            "document.documentElement.scrollWidth <= document.documentElement.clientWidth"
        ), width
    console_page.set_viewport_size({"width": 1280, "height": 900})
    console_page.goto("/approvals")
    expect(console_page.get_by_role("heading", level=1)).to_have_text("Approvals")
    expect(
        console_page.get_by_role("status").filter(has_text="Choose an approval to read it.")
    ).to_be_visible()
    settled(console_page)
    assert console_page.evaluate(AXE_RUN) == []


DECISION_BAR = """
() => {
  const input = document.querySelector('#decision-comment');
  const label = document.querySelector('label[for="decision-comment"]');
  const box = input.getBoundingClientRect();
  const buttons = [...document.querySelectorAll('.decision-bar button[type=submit]')]
    .map((button) => button.getBoundingClientRect());
  const ring = document.querySelector('.detail-ring svg')?.parentElement ?? null;
  return {
    input: box.width,
    label: label.getBoundingClientRect().height,
    buttons: buttons.map((button) => button.width),
    overlap: buttons.some((b) => b.left < box.right && b.right > box.left
      && b.top < box.bottom && b.bottom > box.top),
    ring: ring === null ? null : getComputedStyle(ring).boxShadow,
    scroll: document.documentElement.scrollWidth - document.documentElement.clientWidth,
  };
}
"""


def test_the_decision_bar_keeps_its_comment_usable_from_768_up(
    console_page, admin_engine, world, agent
):
    """The comment field between Refuse and Approve never collapses (#678).

    At 1280 the two 280 px buttons filled the detail pane and left the comment a sliver whose
    label wrapped a word per line; at 768 the queue's fixed column left the detail about 70 px.
    The countdown ring is a circle with no frame around it.
    """
    sign_in_as(console_page, admin_engine, world["human"])
    first = pending(agent, world)
    for width in (768, 1024, 1280, 1600):
        console_page.set_viewport_size({"width": width, "height": 900})
        open_approval(console_page, first["approval_id"])
        settled(console_page)
        geometry = console_page.evaluate(DECISION_BAR)
        assert geometry["input"] >= 240, (width, geometry)
        assert geometry["label"] <= 20, (width, geometry)
        assert min(geometry["buttons"]) >= 140, (width, geometry)
        assert not geometry["overlap"], (width, geometry)
        assert geometry["scroll"] <= 0, (width, geometry)
        assert geometry["ring"] == "none", (width, geometry)
    assert console_page.evaluate("window.__violations") == []


# Approval pages (#678): Waiting on others, the decision bar on a phone, assigning yourself
# behind the step-up, and the comment kept across signing in again.

LONG_WORKSPACE = "Northwind Security Operations"


def name_workspace(engine, world, name=LONG_WORKSPACE):
    with engine.begin() as conn:
        conn.execute(
            text("UPDATE execbound.tenants SET name=:n WHERE tenant_id=:t"),
            {"n": name, "t": world["identity"].tenant_id},
        )


def test_an_administrator_chases_an_approval_waiting_on_someone_else(
    console_page, admin_engine, world, agent
):
    page = console_page
    page.context.grant_permissions(["clipboard-read", "clipboard-write"])
    first = pending(agent, world)
    sign_in_as(page, admin_engine, world["admin"])
    page.goto("/approvals")
    expect(
        page.get_by_text("You are not assigned to review any of the 1 request waiting here.")
    ).to_be_visible()
    page.get_by_role("button", name="Show waiting on others").click()
    expect(page).to_have_url(re.compile(r"/approvals\?view=others$"))
    chip = page.get_by_role("button", name=re.compile(r"^Waiting on others"))
    expect(chip).to_have_attribute("aria-pressed", "true")
    row = page.locator("a.queue-row").first
    expect(row).to_contain_text("0 of 1 approvals")
    expect(row).to_contain_text("1 assigned")
    expect(row.locator(".queue-left")).to_have_text(re.compile(r"^\d+:[0-5]\d left$"))
    row.click()
    expect(page).to_have_url(re.compile(rf"/approvals/{first['approval_id']}\?view=others$"))
    expect(
        page.get_by_role("heading", name="You are not assigned to decide this request.")
    ).to_be_visible()
    expect(page.locator(".detail-eyebrow").get_by_text("Waiting for a person")).to_be_visible()
    expect(page.get_by_role("form", name="Your decision")).to_have_count(0)
    page.get_by_role("button", name="Copy approval link").click()
    expect(page.get_by_text("Link copied.")).to_be_visible()
    copied = page.evaluate("navigator.clipboard.readText()")
    assert copied.endswith(f"/approvals/{first['approval_id']}"), copied
    page.go_back()
    expect(page).to_have_url(re.compile(r"/approvals\?view=others$"))
    expect(chip).to_have_attribute("aria-pressed", "true")
    page.reload()
    expect(page.get_by_role("button", name=re.compile(r"^Waiting on others"))).to_have_attribute(
        "aria-pressed", "true"
    )
    assert approval_state(admin_engine, first["approval_id"]) == "PENDING"
    assert page.evaluate("window.__violations") == []


ACCENT = """
() => {
  const probe = document.createElement('span');
  probe.style.background = 'var(--eb-accent)';
  document.body.append(probe);
  const accent = getComputedStyle(probe).backgroundColor;
  probe.remove();
  return accent;
}
"""

UNDER_THE_BAR = """
() => {
  const last = document.querySelector('.timeline li:last-child');
  last.scrollIntoView({ block: 'end' });
  for (let node = last.parentElement; node; node = node.parentElement) {
    node.scrollTop = node.scrollHeight;
  }
  window.scrollTo(0, document.documentElement.scrollHeight);
  const bar = document.querySelector('form.decision-bar').getBoundingClientRect();
  return last.getBoundingClientRect().bottom - bar.top;
}
"""


@pytest.mark.parametrize("scheme", ["light", "dark"])
def test_the_phone_bar_names_the_effect_the_time_and_the_workspace(
    console_page, admin_engine, world, agent, scheme
):
    page = console_page
    name_workspace(admin_engine, world)
    page.emulate_media(color_scheme=scheme)
    page.set_viewport_size({"width": 390, "height": 844})
    sign_in_as(page, admin_engine, world["human"])
    first = pending(agent, world)
    open_approval(page, first["approval_id"])
    approve = page.get_by_role("button", name=re.compile(r"^Approve\b"))
    refuse = page.get_by_role("button", name=re.compile(r"^Refuse\b"))
    approve_box, refuse_box = approve.bounding_box(), refuse.bounding_box()
    assert approve_box is not None and refuse_box is not None
    assert round(approve_box["height"]) == 50 and round(refuse_box["height"]) == 50
    assert abs(approve_box["width"] / refuse_box["width"] - 1) < 0.1, (approve_box, refuse_box)
    # Equal emphasis: each tinted in its own tone, neither the accent fill.
    accent = page.evaluate(ACCENT)
    style = "(button) => getComputedStyle(button).backgroundColor"
    fills = {approve.evaluate(style), refuse.evaluate(style)}
    assert accent not in fills and len(fills) == 2, (accent, fills)
    weights = {b.evaluate("(node) => getComputedStyle(node).fontWeight") for b in (approve, refuse)}
    assert len(weights) == 1, weights
    # The bar names the effect, the deadline, the quorum and the workspace, in full as text.
    context = page.locator(".decision-context")
    expect(context).to_be_visible()
    expect(context).to_contain_text("Reversible by Lift endpoint isolation")
    expect(context).to_contain_text("0 of 1 approvals recorded")
    scope = page.locator(".decision-scope")
    expect(scope).to_contain_text("Deciding in")
    assert LONG_WORKSPACE in (scope.get_attribute("title") or "")
    for choice in ("Approve", "Refuse"):
        named = re.compile(rf"^{choice}\b.* in {LONG_WORKSPACE}$")
        expect(page.get_by_role("button", name=named)).to_have_count(1)
    workspace = page.locator(".decision-workspace")
    assert workspace.evaluate("(node) => node.scrollWidth <= node.clientWidth")
    # The eyebrow holds the workspace on one line, and says "Waiting for you" to the approver.
    eyebrow = page.locator(".detail-eyebrow")
    expect(eyebrow.locator(".detail-workspace")).to_contain_text(LONG_WORKSPACE)
    assert eyebrow.evaluate(
        "(row) => new Set([...row.children].map((child) => Math.round("
        "child.getBoundingClientRect().top + child.getBoundingClientRect().height / 2))).size === 1"
    )
    expect(eyebrow.get_by_text("Waiting for you", exact=True)).to_be_visible()
    # Nothing on the page sits under the bar.
    assert page.evaluate(UNDER_THE_BAR) <= 1
    assert page.evaluate(
        "document.documentElement.scrollWidth <= document.documentElement.clientWidth"
    )
    settled(page)
    assert page.evaluate(AXE_RUN) == []
    assert page.evaluate("window.__violations") == []


def test_assigning_yourself_asks_for_the_factor_and_then_the_decision_lands(
    page, gateway, db, runtime, admin_engine, world
):
    """The administrator verified their authenticator more than thirty minutes ago, so the
    assignment asks for it in place, over the approval, and the decision then lands."""
    from test_human_surface import pending as held

    tenant, admin = world["admin"].tenant_id, world["admin"].principal_id
    setup = load_session(
        db, issue_session(db, world["admin"], clock=runtime.clock).token, clock=runtime.clock
    )
    seed = mfa.begin_enrollment(db, setup, RING, clock=runtime.clock)
    mfa.confirm_enrollment(db, setup, RING, mfa.totp(seed, step(runtime)), clock=runtime.clock)
    runtime.clock.value += timedelta(seconds=31)
    grant = issue_session(db, world["admin"], clock=runtime.clock)
    assert grant.mfa_required
    host = gateway.split("//", 1)[1].split(":", 1)[0]
    page.context.add_cookies(
        [
            {"name": name, "value": value, "domain": host, "path": "/", "httpOnly": True}
            for name, value in (("eb_session", grant.token), ("eb_csrf", grant.csrf_token))
        ]
    )
    page.goto("/mfa")
    page.get_by_label("Authentication code").fill(mfa.totp(seed, step(runtime)))
    page.get_by_role("button", name="Verify", exact=True).click()
    expect(page).not_to_have_url(re.compile(r"/mfa$"))
    # The factor was verified thirty-four minutes ago, as far as the server can tell.
    with admin_engine.begin() as conn:
        conn.execute(
            text(
                "UPDATE execbound.session_assurance "
                "SET verified_at = verified_at - interval '34 minutes' WHERE tenant_id=:t"
            ),
            {"t": tenant},
        )
    view = held(runtime, world)
    page.goto(f"/approvals/{view.approval_id}")
    expect(
        page.get_by_role("heading", name="You are not assigned to decide this request.")
    ).to_be_visible()
    page.get_by_role("button", name="Assign yourself to review this").click()
    confirming = page.get_by_role("dialog", name="Assign yourself to review")
    expect(confirming).to_contain_text("you will be asked for it")
    confirming.get_by_role("button", name="Assign me").click()
    asking = page.get_by_role("dialog", name="Verify your identity")
    expect(asking).to_be_visible()
    runtime.clock.value += timedelta(seconds=31)
    asking.get_by_label("Authentication code").fill(mfa.totp(seed, step(runtime)))
    asking.get_by_role("button", name="Verify", exact=True).click()
    expect(asking).to_be_hidden()
    expect(
        page.locator(".toast").filter(has_text="You can now decide this request.")
    ).to_be_visible()
    approve = page.get_by_role("button", name=re.compile(r"^Approve\b"))
    expect(approve).to_be_visible()
    approve.click()
    expect(page.get_by_role("status").filter(has_text="Approved device-01")).to_be_visible()
    assert approval_state(admin_engine, view.approval_id) == "APPROVED"
    with admin_engine.connect() as conn:
        assigned = conn.execute(
            text(
                "SELECT count(*) FROM execbound.audit_events WHERE tenant_id=:t "
                "AND actor_id=:p AND kind='approval_scope.assigned'"
            ),
            {"t": tenant, "p": admin},
        ).scalar_one()
    assert assigned == 1
    assert page.evaluate("window.__violations") == []


def drafts_left(page) -> list[str]:
    return page.evaluate("Object.keys(sessionStorage).filter((key) => key.startsWith('eb:draft:'))")


def test_a_typed_comment_survives_signing_in_again(
    console_page, admin_engine, world, agent, db, runtime, console_gateway, tmp_path
):
    page = console_page
    admin = world["admin"]
    with admin_engine.begin() as conn:
        conn.execute(
            text("UPDATE execbound.principals SET email=:e WHERE principal_id=:p"),
            {"e": "draft-admin@example.com", "p": admin.principal_id},
        )
    code_file = tmp_path / "set-password.txt"
    invite_person(
        admin_engine,
        admin.tenant_id,
        "draft-admin@example.com",
        "ADMIN",
        actor=admin.principal_id,
        origin=console_gateway,
        output=code_file,
        now=runtime.clock.now(),
    )
    redeem_reset(
        db, code_file.read_text().strip(), "An ordinary test password!", clock=runtime.clock
    )
    assign_approver(
        admin_engine,
        admin.tenant_id,
        admin.principal_id,
        world["canonical"],
        "endpoint.isolate",
        admin.principal_id,
    )
    [production] = targets(admin_engine, world, count=1, production=True)
    first = pending(agent, world)
    second = agent.post("/v1/execute", json=production.model_dump(mode="json")).json()
    assert second["state"] == "PENDING_APPROVAL"
    with admin_engine.connect() as conn:
        canonical = conn.execute(
            text("SELECT canonical_target_id FROM execbound.executions WHERE execution_id=:e"),
            {"e": second["execution_id"]},
        ).scalar_one()
    assign_approver(
        admin_engine,
        admin.tenant_id,
        admin.principal_id,
        canonical,
        "endpoint.isolate",
        admin.principal_id,
    )

    def sign_in(path):
        page.goto(path)
        page.get_by_label("Email", exact=True).fill("draft-admin@example.com")
        page.get_by_label("Password", exact=True).fill("An ordinary test password!")
        page.get_by_role("button", name="Sign in with a password").click()
        expect(page).to_have_url(re.compile(re.escape(path) + "$"))

    path = f"/approvals/{first['approval_id']}"
    sign_in(path)
    comment = page.get_by_label("Comment for the audit record (optional)")
    comment.fill("Checked with the on-call lead")
    # Someone else ends this person's sessions; the next poll answers 401.
    other = provision_identity(admin_engine, db, admin.tenant_id, "ADMIN", runtime.clock.now())
    acting = load_session(
        db, issue_session(db, other, clock=runtime.clock).token, clock=runtime.clock
    )
    assert revoke_sessions_of(db, acting, admin.principal_id, reason="ADMIN", clock=runtime.clock)
    expect(page).to_have_url(re.compile(r"/login"), timeout=30_000)
    page.get_by_label("Email", exact=True).fill("draft-admin@example.com")
    page.get_by_label("Password", exact=True).fill("An ordinary test password!")
    page.get_by_role("button", name="Sign in with a password").click()
    expect(page).to_have_url(re.compile(re.escape(path) + "$"))
    expect(comment).to_have_value("Checked with the on-call lead")
    expect(page.locator(".toast").filter(has_text="Your comment was kept.")).to_be_visible()
    # A comment typed on one approval stays with it: the other opens with an empty field, and
    # the first still holds its own when the person comes back to it.
    page.locator("a.queue-row").filter(has_text=second["request_ref"]).click()
    expect(page).to_have_url(re.compile(rf"/approvals/{second['approval_id']}$"))
    expect(comment).to_have_value("")
    assert drafts_left(page) == [f"eb:draft:approval:{first['approval_id']}"]
    page.locator("a.queue-row").filter(has_text=first["request_ref"]).click()
    expect(comment).to_have_value("Checked with the on-call lead")
    page.get_by_role("button", name=re.compile(r"^Approve\b")).click()
    expect(page.get_by_role("status").filter(has_text="Approved device-01")).to_be_visible()
    assert drafts_left(page) == []

    # Signing out forgets every draft.
    page.goto(f"/approvals/{second['approval_id']}")
    comment.fill("Unsent words")
    for _ in range(50):
        if drafts_left(page):
            break
        page.wait_for_timeout(100)
    assert drafts_left(page) == [f"eb:draft:approval:{second['approval_id']}"]
    page.goto("/settings")
    page.get_by_role("button", name="Sign out").first.click()
    expect(page).to_have_url(re.compile(r"/login"))
    assert drafts_left(page) == []


@pytest.mark.parametrize("scheme", ["dark", "light"])
def test_waiting_on_others_lapsed_and_the_waiting_panel_are_clean(
    console_page, admin_engine, world, agent, scheme, db, receiver
):
    page = console_page
    page.emulate_media(color_scheme=scheme)
    waiting = pending(agent, world)
    [production] = targets(admin_engine, world, count=1, production=True)
    lapsing = agent.post("/v1/execute", json=production.model_dump(mode="json")).json()
    assert lapsing["state"] == "PENDING_APPROVAL"
    sign_in_as(page, admin_engine, world["admin"])
    for width in (1280, 390):
        page.set_viewport_size({"width": width, "height": 900})
        for path, ready in (
            ("/approvals?view=others", page.locator("a.queue-row").first),
            (
                f"/approvals/{waiting['approval_id']}?view=others",
                page.get_by_role("heading", name="You are not assigned to decide this request."),
            ),
        ):
            page.goto(path)
            expect(ready).to_be_visible()
            settled(page)
            assert page.evaluate(AXE_RUN) == [], (path, width)
            assert page.evaluate("window.__violations") == [], (path, width)
            assert page.evaluate(
                "document.documentElement.scrollWidth <= document.documentElement.clientWidth"
            ), (path, width)
    # One message lapses unsent inside the drain's margin: the Lapsed view flags it and says
    # why, and its detail carries the delivery line (#678).
    hook = [notified_by(world, receiver)]
    queue_for(db, world, lapsing["approval_id"], hook)
    world["clock"].value = expiry(admin_engine, lapsing["approval_id"]) - timedelta(seconds=10)
    assert drain_now(db, world, hook)["closed"] == 1
    world["clock"].value += timedelta(seconds=11)
    for width in (1280, 390):
        page.set_viewport_size({"width": width, "height": 900})
        page.goto("/approvals?view=lapsed")
        expect(page.locator("a.queue-row")).to_have_count(2)
        expect(page.get_by_role("note")).to_contain_text("1 of these lapsed")
        expect(page.locator("a.queue-row").filter(has_text="Message late")).to_have_count(1)
        settled(page)
        assert page.evaluate(AXE_RUN) == [], width
        assert page.evaluate("window.__violations") == [], width
        assert page.evaluate(
            "document.documentElement.scrollWidth <= document.documentElement.clientWidth"
        ), width
        page.goto(f"/approvals/{lapsing['approval_id']}?view=lapsed")
        expect(page.get_by_text("Not sent: the approval lapsed before delivery.")).to_be_visible()
        settled(page)
        assert page.evaluate(AXE_RUN) == [], ("detail", width)
        assert page.evaluate("window.__violations") == [], ("detail", width)
        assert page.evaluate(
            "document.documentElement.scrollWidth <= document.documentElement.clientWidth"
        ), ("detail", width)


# What the page says about the message and the lapse (#678): AQ12 and AQ13.


def notified_by(world, receiver):
    local, _ = receiver
    return Destination(
        destination_id="soc",
        tenant_id=world["identity"].tenant_id,
        url=local.url,
        secret=local.secret,
    )


def queue_for(db, world, approval_id, destinations):
    """Queue the approval's announcement as admission does, under the tenant fence."""
    tenant = world["identity"].tenant_id
    with db.transaction(tenant) as conn:
        queued = notifications.queue_notifications(
            conn,
            tenant,
            UUID(approval_id),
            world["canonical"],
            "endpoint.isolate",
            world["clock"].now(),
            destinations,
        )
    assert queued == len(destinations)


def drain_now(db, world, destinations):
    return notifications.deliver_pending(
        db,
        world["admin"],
        destinations,
        approval_url="http://127.0.0.1/approvals",
        clock=world["clock"],
    )


def expiry(engine, approval_id):
    with engine.begin() as conn:
        return conn.execute(
            text("SELECT expires_at FROM execbound.approvals WHERE approval_id=:a"),
            {"a": approval_id},
        ).scalar_one()


def lapse_notice(page):
    return page.locator("p.notice[role=status]")


def test_an_approver_reads_what_happened_after_a_lapse(
    console_page, admin_engine, world, agent, db, receiver
):
    page = console_page
    first = pending(agent, world)
    hook = [notified_by(world, receiver)]
    queue_for(db, world, first["approval_id"], hook)
    world["clock"].value += timedelta(seconds=5)
    assert drain_now(db, world, hook)["delivered"] == 1
    world["clock"].value += timedelta(seconds=121)
    sign_in_as(page, admin_engine, world["human"])
    page.goto(f"/approvals/{first['approval_id']}?view=lapsed")
    expect(lapse_notice(page)).to_have_text(
        "This approval lapsed before anyone decided it. Nothing ran. If the agent still needs "
        "this, it must send the request again."
    )
    expect(
        page.get_by_text(re.compile(r"^Notification delivered .+, 1 min before the deadline\.$"))
    ).to_be_visible()
    expect(page.get_by_text("execution history")).to_have_count(0)
    # It reads as lapsed, as the queue's row does, and nothing on it says it still waits (#678).
    lapsed_not_waiting(page)
    # The record's drawer agrees with its row in Activity (#678).
    page.goto(f"/activity?open={first['execution_id']}")
    drawer = page.get_by_role("dialog")
    expect(drawer.locator(".badge").first).to_have_text("Lapsed")
    expect(drawer.get_by_text("Approval lapsed")).to_be_visible()
    page.goto(f"/approvals/{first['approval_id']}?view=lapsed")
    # After the recovery run has ended it, the same.
    world["clock"].value += timedelta(seconds=301)
    assert recover(db, world["admin"], {}, clock=world["clock"]).expired == 1
    page.reload()
    expect(lapse_notice(page)).to_contain_text("This approval lapsed before anyone decided it.")
    lapsed_not_waiting(page)
    assert page.evaluate("window.__violations") == []
    sign_in_as(page, admin_engine, world["admin"])
    page.goto(f"/approvals/{first['approval_id']}?view=lapsed")
    expect(lapse_notice(page)).to_have_text(
        "This approval lapsed and cannot be used. Review the execution history before asking "
        "the agent for a fresh plan."
    )
    lapsed_not_waiting(page)


def lapsed_not_waiting(page):
    detail = page.locator("article.detail")
    expect(detail.locator(".detail-eyebrow .badge")).to_have_text("Lapsed")
    expect(detail).not_to_contain_text(re.compile("waiting for", re.IGNORECASE))


def test_an_approver_who_approved_is_not_told_nobody_decided(
    console_page, admin_engine, world, agent, db
):
    page = console_page
    sign_in_as(page, admin_engine, world["human"])
    # Approved in full, and never used by the agent.
    used = pending(agent, world)
    open_approval(page, used["approval_id"])
    page.get_by_role("button", name=re.compile(r"^Approve\b")).click()
    expect(page.get_by_role("status").filter(has_text="Approved device-01")).to_be_visible()
    assert approval_state(admin_engine, used["approval_id"]) == "APPROVED"
    # One of two approvals recorded.
    activate(db, world, quorum_bundle(world))
    second_approver(admin_engine, db, world)
    [wire] = targets(admin_engine, world, count=1, production=True)
    partly = agent.post("/v1/execute", json=wire.model_dump(mode="json")).json()
    assert partly["state"] == "PENDING_APPROVAL"
    page.goto(f"/approvals/{partly['approval_id']}")
    page.get_by_role("button", name=re.compile(r"^Approve\b")).click()
    expect(page.get_by_role("status").filter(has_text="recorded, 1 of 2 needed")).to_be_visible()
    world["clock"].value += timedelta(seconds=121 + 301)
    assert recover(db, world["admin"], {}, clock=world["clock"]).expired == 2
    page.goto(f"/approvals/{partly['approval_id']}?view=lapsed")
    expect(lapse_notice(page)).to_have_text(
        "This approval lapsed before enough people approved it. Nothing ran. If the agent still "
        "needs this, it must send the request again."
    )
    page.goto(f"/approvals/{used['approval_id']}?view=lapsed")
    expect(lapse_notice(page)).to_have_text(
        "This approval was approved but lapsed before the agent used it. Nothing ran. If the "
        "agent still needs this, it must send the request again."
    )
    expect(page.get_by_text("lapsed before anyone decided it")).to_have_count(0)
    assert page.evaluate("window.__violations") == []
