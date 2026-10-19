# SPDX-License-Identifier: AGPL-3.0-only
"""The settings pages of the console in real Chromium (#333, #253).

The personal page shows this device and the other one, and ends the other after a confirmation
and no sooner; the tenant page changes the mode with a reason and the top bar's pill follows,
refuses 119, 3,601 and a word for the deadline with the bound as its answer and no audit event,
and activates and releases the stop with the events the command line writes. Every dialog is
axe-clean open in both schemes, and an approver who types the tenant address gets the route's
error boundary with the shell intact, because the server refused and the page shows only that.
The token card's Try again keeps the focus it was given through the read it asks for, and a
read that fails once the tokens loaded leaves them in place.
"""

import json
import re
from dataclasses import replace
from datetime import timedelta

import pytest
from playwright.sync_api import expect
from sqlalchemy import text
from test_browser_console import AXE, AXE_RUN, COLLECT, person_name, settled, sign_in_as
from test_browser_console import console_gateway as console_gateway
from test_browser_console import console_page as console_page
from test_browser_surfaces import ACTION_TIMEOUT_MS, FITS
from test_browser_surfaces import chromium as chromium
from test_console_api_settings import seed_delivery
from test_emergency_stop import audit
from test_execution import registry as registry
from test_execution import world as world
from test_human_surface import pending
from test_protected_path import connector as connector
from test_protected_path import live_provider as live_provider
from test_runtime import runtime as runtime

from execbound.execution.stops import stop_status
from execbound.notifications import Destination
from execbound.surfaces.sessions import SessionError, issue_session, load_session


# A dialog rises over 160 ms from opacity 0, and axe reads the opacity of that moment as a
# contrast failure, so the question is asked of the settled page: nothing still animating, and
# every surface that rises fully opaque. Waiting on `getAnimations` alone is not enough, because
# the animation of a surface React has only just mounted may not have started yet.
def clean(page, what):
    settled(page)
    violations = page.evaluate(AXE_RUN)
    assert violations == [], (what, violations)
    assert page.evaluate("window.__violations") == [], what


def phone_navigation_fits(page):
    menu = page.get_by_role("button", name="Navigation menu")
    space_box = page.locator(".switcher-compact .tenant").bounding_box()
    menu_box = menu.bounding_box()
    assert space_box is not None and menu_box is not None
    assert space_box["x"] + space_box["width"] <= menu_box["x"]
    for control in (menu, page.get_by_role("button", name=re.compile(r"^Notifications"))):
        box = control.bounding_box()
        assert box is not None and box["width"] >= 34 and box["height"] >= 34
    assert page.evaluate(FITS)


@pytest.mark.parametrize("scheme", ["dark", "light"])
def test_settings_shows_this_device_and_ends_the_other_after_a_confirmation(
    console_page, admin_engine, world, runtime, scheme
):
    console_page.emulate_media(color_scheme=scheme)
    if scheme == "light":
        console_page.set_viewport_size({"width": 390, "height": 844})
    sign_in_as(console_page, admin_engine, world["human"])
    other = issue_session(runtime.db, world["human"], clock=runtime.clock, label="Safari on iPhone")
    stranger = issue_session(
        runtime.db, world["admin"], clock=runtime.clock, label="Edge on Windows"
    )
    console_page.goto("/settings")
    expect(console_page.get_by_role("heading", level=1)).to_have_text("My account")
    expect(console_page.get_by_text("Safari on iPhone")).to_be_visible()
    expect(console_page.get_by_text("This device")).to_be_visible()
    expect(console_page.get_by_text("Edge on Windows")).to_have_count(0)
    console_page.get_by_text("Advanced sign-in details", exact=True).click()
    expect(console_page.get_by_text(str(world["human"].credential_id)[:8])).to_be_visible()
    clean(console_page, "settings")
    button = console_page.get_by_role("button", name="Sign out other devices")
    button.click()
    dialog = console_page.get_by_role("dialog", name="Sign out other devices?")
    expect(dialog).to_be_visible()
    clean(console_page, "settings dialog")
    # Cancelling ends nothing.
    dialog.get_by_role("button", name="Cancel").click()
    expect(dialog).to_have_count(0)
    assert load_session(runtime.db, other.token, clock=runtime.clock).session_id == other.session_id
    button.click()
    console_page.get_by_role("dialog").get_by_role("button", name="Sign out other devices").click()
    expect(console_page.get_by_text("No other device is signed in as you.")).to_be_visible()
    expect(
        console_page.get_by_role("status").filter(has_text="Signed out 1 other device")
    ).to_be_visible()
    with pytest.raises(SessionError):
        load_session(runtime.db, other.token, clock=runtime.clock)
    assert load_session(runtime.db, stranger.token, clock=runtime.clock).session_id == (
        stranger.session_id
    )
    # This device stays signed in.
    console_page.reload()
    expect(console_page.get_by_role("heading", level=1)).to_have_text("My account")
    expect(console_page.get_by_text("This device")).to_be_visible()


def test_tenant_settings_changes_the_mode_refuses_a_bad_deadline_and_stops_with_the_cli_events(
    console_page, admin_engine, world, runtime
):
    tenant = world["identity"].tenant_id
    sign_in_as(console_page, admin_engine, world["admin"])
    console_page.goto("/tenant")
    expect(console_page.get_by_role("heading", level=1)).to_have_text("Workspace settings")
    expect(console_page.get_by_role("navigation", name="Breadcrumb")).to_contain_text(
        "Workspace settings"
    )
    expect(console_page.get_by_text("Enforcing").first).to_be_visible()
    expect(
        console_page.get_by_text(
            "No approval destination is configured, so pending approvals are announced only in "
            "this console.",
            exact=True,
        )
    ).to_be_visible()
    clean(console_page, "tenant")

    # Mode: a reason is required, the server decides, and the pill in the top bar follows.
    console_page.get_by_role("button", name="Change mode").click()
    dialog = console_page.get_by_role("dialog", name="Change the enforcement mode?")
    expect(dialog).to_be_visible()
    clean(console_page, "mode dialog")
    dialog.get_by_role("button", name="Change mode").click()
    expect(dialog.get_by_role("alert")).to_have_text(
        "A reason of 1 to 500 characters is required, with nothing in it that looks like a "
        "password, key or token."
    )
    assert audit(admin_engine, tenant, "tenant.mode_changed") == []
    dialog.get_by_label("Reason for the mode change").fill("Onboarding trial")
    dialog.get_by_role("button", name="Change mode").click()
    expect(dialog).to_have_count(0)
    expect(console_page.get_by_role("banner").get_by_text("Observe only")).to_be_visible()
    # The administrator by their one name, "User 1", never by an id prefix.
    changed = console_page.get_by_text(re.compile(r"^Changed 20")).first
    expect(changed).to_contain_text(person_name(admin_engine, world["admin"].principal_id))
    expect(changed).not_to_contain_text(str(world["admin"].principal_id)[:8])
    assert [e["reason"] for e in audit(admin_engine, tenant, "tenant.mode_changed")] == [
        "Onboarding trial"
    ]

    # Deadline: 119, 3601 and a word are refused by the server with the bound, and nothing
    # reaches the audit chain; off and 600 go through.
    console_page.get_by_role("button", name="Change deadline").click()
    dialog = console_page.get_by_role("dialog", name="Change the approval deadline?")
    field = dialog.get_by_label(re.compile(r"^Seconds"))
    expect(field).to_have_value("120")
    dialog.get_by_label("Reason for the deadline change").fill("Try")
    for bad in ("119", "3601", "soon"):
        field.fill(bad)
        dialog.get_by_role("button", name="Change deadline").click()
        expect(dialog.get_by_role("alert")).to_have_text(
            "The deadline is 120 to 3600 seconds, or off."
        )
        expect(field).to_have_attribute("aria-invalid", "true")
    assert audit(admin_engine, tenant, "tenant.approval_deadline_changed") == []
    clean(console_page, "deadline dialog with a refusal")
    field.fill("off")
    dialog.get_by_role("button", name="Change deadline").click()
    expect(dialog).to_have_count(0)
    expect(console_page.get_by_text("off", exact=True)).to_be_visible()
    console_page.get_by_role("button", name="Change deadline").click()
    dialog = console_page.get_by_role("dialog", name="Change the approval deadline?")
    expect(dialog.get_by_label(re.compile(r"^Seconds"))).to_have_value("off")
    dialog.get_by_label(re.compile(r"^Seconds")).fill(" 600 ")
    dialog.get_by_label("Reason for the deadline change").fill("Ten minutes")
    dialog.get_by_role("button", name="Change deadline").click()
    expect(console_page.get_by_text("600 s", exact=True)).to_be_visible()
    assert [
        e["seconds"] for e in audit(admin_engine, tenant, "tenant.approval_deadline_changed")
    ] == [None, 600]

    # Stop: the same event the command line writes, the page shows the state, resume clears it.
    console_page.get_by_role("button", name="Activate the emergency stop").click()
    dialog = console_page.get_by_role("dialog", name="Activate the emergency stop?")
    expect(dialog).to_be_visible()
    clean(console_page, "stop dialog")
    dialog.get_by_label("Reason for stopping").fill("Contain <b>agent 7</b>")
    dialog.get_by_role("button", name="Activate the emergency stop").click()
    expect(console_page.get_by_text("Stop active", exact=True)).to_be_visible()
    expect(console_page.get_by_text("Reason: Contain <b>agent 7</b>")).to_be_visible()
    assert console_page.locator("b").count() == 0
    expect(
        console_page.get_by_text("0 committed dispatches recorded at activation", exact=False)
    ).to_be_visible()
    active = stop_status(runtime.db, world["admin"], runtime.clock)
    assert active is not None and active.reason == "Contain <b>agent 7</b>"
    activation = audit(admin_engine, tenant, "tenant.stop_activated")[-1]
    assert activation["stop_id"] == str(active.stop_id)
    assert activation["principal_id"] == str(world["admin"].principal_id)
    assert set(activation) == {
        "stop_id",
        "reason",
        "principal_id",
        "credential_id",
        "actor_credential_id",
        "replay",
        "dispatch_committed",
    }
    assert activation["actor_credential_id"] == activation["credential_id"]
    clean(console_page, "tenant stopped")
    console_page.get_by_role("button", name="Resume the tenant").click()
    dialog = console_page.get_by_role("dialog", name="Resume this tenant?")
    dialog.get_by_label("Reason for resuming").fill("Reviewed")
    dialog.get_by_role("button", name="Resume the tenant").click()
    expect(console_page.get_by_text("Not active")).to_be_visible()
    assert stop_status(runtime.db, world["admin"], runtime.clock) is None
    assert [e["reason"] for e in audit(admin_engine, tenant, "tenant.stop_released")] == [
        "Reviewed"
    ]
    # The token never reached the URL or storage on the way.
    assert "csrf" not in console_page.url
    stored = console_page.evaluate("JSON.stringify(localStorage) + JSON.stringify(sessionStorage)")
    assert "csrf" not in stored.lower()


def test_an_approver_at_the_tenant_address_gets_the_boundary_and_the_shell(
    console_page, admin_engine, world
):
    sign_in_as(console_page, admin_engine, world["human"])
    console_page.goto("/tenant")
    expect(console_page.get_by_role("heading", level=1)).to_have_text(
        "You don't have access to this"
    )
    expect(console_page.get_by_role("navigation", name="Main")).to_be_visible()
    sidebar = console_page.get_by_role("navigation", name="Main")
    expect(sidebar.get_by_role("link", name="Workspace settings")).to_have_count(0)
    expect(console_page.get_by_text("Emergency stop")).to_have_count(0)
    assert console_page.evaluate("window.__violations") == []


UNAVAILABLE = json.dumps({"code": "UNAVAILABLE", "detail": "Unavailable."})


def test_try_again_keeps_its_focus_and_a_failed_read_keeps_the_tokens(
    console_page, admin_engine, world
):
    """What jsdom cannot show: in Chromium the Try again a keyboard user pressed is the same
    element, still focused, after the read it asked for fails again, and a read that fails
    once the tokens loaded leaves them in place."""
    sign_in_as(console_page, admin_engine, world["admin"])
    failed: list[str] = []

    def unavailable(route):
        failed.append(route.request.method)
        route.fulfill(status=503, content_type="application/json", body=UNAVAILABLE)

    tokens = "**/api/console/v1/settings/tokens"
    console_page.route(tokens, unavailable)
    console_page.goto("/settings")
    card = console_page.locator("section").filter(
        has=console_page.get_by_role("heading", name="Personal access tokens", exact=True)
    )
    alert = card.get_by_role("alert")
    expect(alert).to_contain_text("Your tokens could not be loaded.")
    button = alert.get_by_role("button", name="Try again")
    button.focus()
    handle = button.element_handle()
    asked = len(failed)
    console_page.keyboard.press("Enter")
    for _ in range(200):
        if len(failed) > asked:
            break
        console_page.wait_for_timeout(25)
    assert len(failed) > asked
    expect(button).not_to_have_attribute("aria-disabled", "true")
    expect(alert).to_contain_text("Your tokens could not be loaded.")
    assert console_page.evaluate("(el) => el.isConnected && document.activeElement === el", handle)

    # The server answers again: the same press reads the list.
    console_page.unroute(tokens)
    console_page.keyboard.press("Enter")
    expect(card.get_by_text("No tokens yet.")).to_be_visible()
    expect(alert).to_have_count(0)

    # A return to the tab reads the stale list again, and that read fails: the list stays.
    console_page.route(tokens, unavailable)
    console_page.evaluate("window.dispatchEvent(new Event('visibilitychange'))")
    expect(alert).to_contain_text("Your tokens could not be loaded.")
    expect(card.get_by_text("No tokens yet.")).to_be_visible()


def test_the_top_bar_stops_and_resumes_and_the_banner_reaches_everyone(
    console_page, console_gateway, chromium, admin_engine, world, runtime
):
    """The button opens the dialog, the banner spans every route, an approver sees the state
    and no button, and Resume from the banner clears it with the command line's event."""
    tenant = world["identity"].tenant_id
    sign_in_as(console_page, admin_engine, world["admin"])
    console_page.goto("/")
    expect(console_page.get_by_role("heading", level=1)).to_have_text("Home")
    expect(console_page.get_by_text("Emergency stop active")).to_have_count(0)
    console_page.get_by_role("button", name="Emergency stop").click()
    dialog = console_page.get_by_role("dialog", name="Activate the emergency stop?")
    expect(dialog).to_be_visible()
    clean(console_page, "stop dialog from the top bar")
    dialog.get_by_label("Reason for stopping").fill("Incident <b>7</b>")
    dialog.get_by_role("button", name="Activate the emergency stop").click()
    banner = console_page.locator(".banner-stop")
    expect(banner).to_be_visible()
    expect(banner).to_have_attribute("role", "status")
    expect(banner).to_contain_text("Incident <b>7</b>")
    expect(banner).to_contain_text(
        "activated by " + person_name(admin_engine, world["admin"].principal_id)
    )
    expect(banner).not_to_contain_text(str(world["admin"].principal_id)[:8])
    assert console_page.locator("b").count() == 0
    clean(console_page, "home with the banner")
    # Across the shell: the banner is on every route, and the button reads active.
    console_page.goto("/activity")
    expect(console_page.get_by_role("heading", level=1)).to_have_text("Activity")
    expect(banner).to_be_visible()
    expect(console_page.get_by_role("button", name="Emergency stop")).to_have_class(
        re.compile(r"btn-danger(?!-outline)")
    )
    clean(console_page, "activity with the banner")
    activation = audit(admin_engine, tenant, "tenant.stop_activated")[-1]
    assert activation["reason"] == "Incident <b>7</b>"
    assert set(activation) == {
        "stop_id",
        "reason",
        "principal_id",
        "credential_id",
        "actor_credential_id",
        "replay",
        "dispatch_committed",
    }
    assert activation["actor_credential_id"] == activation["credential_id"]

    # An approver sees the banner and the state, with no button and no Resume.
    with chromium.new_context(
        base_url=console_gateway, viewport={"width": 390, "height": 844}
    ) as context:
        other = context.new_page()
        other.set_default_timeout(ACTION_TIMEOUT_MS)
        other.add_init_script(COLLECT)
        other.add_init_script(path=str(AXE))
        sign_in_as(other, admin_engine, world["human"])
        other.goto("/")
        expect(other.locator(".banner-stop")).to_contain_text("Emergency stop active")
        # An approver is told that an administrator stopped the workspace, not which one.
        expect(other.locator(".banner-stop")).to_contain_text("activated by an administrator")
        expect(other.get_by_text("Stop active", exact=True)).to_be_visible()
        expect(other.get_by_role("button", name="Emergency stop")).to_have_count(0)
        expect(other.get_by_role("button", name="Resume")).to_have_count(0)
        menu = other.get_by_role("button", name="Navigation menu")
        phone_navigation_fits(other)
        clean(other, "an approver's phone with the banner")
        # A long customer Space label must truncate inside its button, not cover Menu.
        with admin_engine.begin() as conn:
            conn.execute(
                text("UPDATE execbound.spaces SET name=:name WHERE tenant_id=:t"),
                {"name": "Production security operations customer workspace", "t": tenant},
            )
            conn.execute(
                text(
                    "UPDATE execbound.human_sessions SET current_space_id="
                    "(SELECT space_id FROM execbound.spaces WHERE tenant_id=:t) "
                    "WHERE tenant_id=:t AND principal_id=:p"
                ),
                {"t": tenant, "p": world["human"].principal_id},
            )
        other.reload()
        expect(other.locator(".switcher-compact .tenant")).to_have_attribute(
            "aria-label", re.compile("Production security operations customer workspace")
        )
        phone_navigation_fits(other)
        clean(other, "an approver's phone with the banner and a long Space name")
        menu.click()
        expect(other.get_by_role("dialog", name="Menu")).to_be_visible()
        clean(other, "phone navigation remains usable while stopped")
        other.keyboard.press("Escape")

    # Resume from the banner.
    console_page.get_by_role("button", name="Resume").click()
    dialog = console_page.get_by_role("dialog", name="Resume this tenant?")
    dialog.get_by_label("Reason for resuming").fill("Reviewed")
    dialog.get_by_role("button", name="Resume the tenant").click()
    expect(banner).to_have_count(0)
    expect(console_page.get_by_role("button", name="Emergency stop")).to_have_class(
        re.compile(r"btn-danger-outline")
    )
    assert stop_status(runtime.db, world["admin"], runtime.clock) is None
    assert [e["reason"] for e in audit(admin_engine, tenant, "tenant.stop_released")] == [
        "Reviewed"
    ]


# Approval delivery on Workspace settings (#678): AY15 and AY17.

VIEWS = [("light", 1280), ("dark", 1280), ("light", 390), ("dark", 390)]


def announcing(runtime, world, admin_engine):
    """A webhook destination that also asks for outcomes, and five announcements it received."""
    tenant = world["identity"].tenant_id
    runtime.notifications = (
        Destination(
            "soc",
            tenant,
            "https://alerts.example.net/execbound/hook",
            "s3cr3t-" + "x" * 32,
            messages=frozenset({"pending", "closed"}),
        ),
        Destination("jane", tenant, "", "", kind="email", to="jane@example.com"),
    )
    approval = pending(runtime, world).approval_id
    for day, lag in enumerate([10, 20, 30, 40, 90], start=1):
        seed_delivery(admin_engine, world, approval, f"d{lag}", lag=lag, age=timedelta(days=day))
    seed_delivery(admin_engine, world, approval, "lapsed", error="LAPSED_BEFORE_DELIVERY")


def fits(page, what):
    assert page.evaluate(FITS), what


def test_ay15_the_messages_column_and_delivery_line(console_page, admin_engine, world, runtime):
    announcing(runtime, world, admin_engine)
    sign_in_as(console_page, admin_engine, world["admin"])
    for scheme, width in VIEWS:
        console_page.emulate_media(color_scheme=scheme)
        console_page.set_viewport_size({"width": width, "height": 900})
        console_page.goto("/tenant")
        table = console_page.get_by_role("table", name=re.compile("notification destinations"))
        expect(table.get_by_role("columnheader", name="Messages")).to_be_attached()
        expect(table.get_by_text("New requests, Outcomes")).to_be_attached()
        line = console_page.get_by_text(re.compile(r"^Last 7 days: 5 notifications delivered\."))
        expect(line).to_have_text(
            "Last 7 days: 5 notifications delivered. Half arrived within 30 s, nine in ten "
            "within 70 s. 1 not sent because the approval would have lapsed before it arrived."
        )
        clean(console_page, f"tenant delivery {scheme} {width}")
        if width == 390:
            fits(console_page, f"tenant delivery {scheme}")


ANNOUNCED = """
() => {
  const heading = [...document.querySelectorAll('h3')]
    .find((h) => h.textContent === 'Where approvals are announced');
  const card = heading.closest('.card');
  const edge = card.getBoundingClientRect().right;
  const wrap = card.querySelector('.table-wrap');
  const cells = [...card.querySelectorAll('td, p')].filter((cell) => cell.offsetParent !== null);
  return {
    hidden: wrap === null ? 0 : wrap.scrollWidth - wrap.clientWidth,
    past: cells.filter((cell) => cell.getBoundingClientRect().right > edge + 0.5)
      .map((cell) => cell.textContent),
  };
}
"""


def test_where_approvals_are_announced_wraps_inside_its_card(
    console_page, admin_engine, world, runtime
):
    """The destinations sat in a table wider than the narrow Approval readiness card, cut at its
    edge with the empty sentence half hidden (#678): each now wraps inside the card, the sixth
    column, Classes (#31), with its widest value among them."""
    sign_in_as(console_page, admin_engine, world["admin"])
    for announced in (False, True):
        if announced:
            announcing(runtime, world, admin_engine)
            soc, jane = runtime.notifications
            runtime.notifications = (
                replace(soc, classes=frozenset({"approvals", "findings"})),
                jane,
            )
        for scheme, width in VIEWS:
            console_page.emulate_media(color_scheme=scheme)
            console_page.set_viewport_size({"width": width, "height": 900})
            console_page.goto("/tenant")
            heading = console_page.get_by_role("heading", name="Where approvals are announced")
            expect(heading).to_be_visible()
            if announced:
                table = console_page.get_by_role(
                    "table", name=re.compile("notification destinations")
                )
                expect(table.get_by_role("columnheader")).to_have_count(6)
                expect(table.get_by_role("columnheader", name="Classes")).to_be_attached()
                expect(table.get_by_text("Approvals, Findings", exact=True)).to_be_visible()
                expect(table.get_by_text("Approvals", exact=True)).to_be_visible()
            settled(console_page)
            geometry = console_page.evaluate(ANNOUNCED)
            assert geometry["hidden"] <= 0, (announced, scheme, width, geometry)
            assert geometry["past"] == [], (announced, scheme, width, geometry)
            fits(console_page, f"announcements {scheme} {width}")


def test_ay17_the_deadline_dialog_warns_against_measured_delivery(
    console_page, admin_engine, world, runtime
):
    announcing(runtime, world, admin_engine)
    sign_in_as(console_page, admin_engine, world["admin"])
    measured = (
        "Nine in ten notifications here arrived within 70 s over the last 7 days. A deadline "
        "under 4 min can lapse before an approver has read the message."
    )
    for scheme, width in VIEWS:
        console_page.emulate_media(color_scheme=scheme)
        console_page.set_viewport_size({"width": width, "height": 900})
        console_page.goto("/tenant")
        console_page.get_by_role("button", name="Change deadline").click()
        dialog = console_page.get_by_role("dialog", name="Change the approval deadline?")
        field = dialog.get_by_role("textbox", name=re.compile("Seconds"))
        field.fill("180")
        hint = dialog.get_by_text(measured)
        expect(hint).to_be_visible()
        described = field.get_attribute("aria-describedby") or ""
        assert hint.get_attribute("id") in described.split()
        expect(field).not_to_have_attribute("aria-invalid", "true")
        expect(dialog.get_by_role("button", name="Change deadline")).to_be_enabled()
        clean(console_page, f"deadline dialog hint {scheme} {width}")
        if width == 390:
            fits(console_page, f"deadline dialog {scheme}")
        field.fill("600")
        expect(hint).to_have_count(0)
        dialog.get_by_role("button", name="Cancel").click()
        expect(dialog).to_have_count(0)


def test_ar13_readiness_is_accessible(console_page, admin_engine, world, runtime):
    """AR13: Approval readiness with its warning, then the deadline dialog's lapse warning.

    The world's policy holds isolations and its deadline is 120 s, so with nothing announcing
    approvals the card warns; once two destinations announce them, the card does not, and a
    deadline of 300 s typed into the dialog draws the lapse warning with the slowest delivery.
    """
    sign_in_as(console_page, admin_engine, world["admin"])
    for scheme, width in VIEWS:
        console_page.emulate_media(color_scheme=scheme)
        console_page.set_viewport_size({"width": width, "height": 900})
        console_page.goto("/tenant")
        card = console_page.locator("section.card").filter(
            has=console_page.get_by_role("heading", name="Approval readiness")
        )
        expect(
            card.get_by_text("Isolate endpoint: at most 2 minutes, the approval deadline.")
        ).to_be_visible()
        warning = card.locator(".readiness-warning")
        expect(warning).to_contain_text(
            "Held requests here wait at most 2 minutes and are announced only in this console."
        )
        expect(warning.get_by_role("link", name="Approvals")).to_have_attribute(
            "href", "/approvals"
        )
        clean(console_page, f"readiness {scheme} {width}")
        fits(console_page, f"readiness {scheme} {width}")
    announcing(runtime, world, admin_engine)
    lapse = (
        "Messages to reviewers can arrive after a 5 min deadline, and a request that lapses "
        "first cannot be decided. In the last 7 days the slowest message here arrived after 90 s."
    )
    for scheme, width in VIEWS:
        console_page.emulate_media(color_scheme=scheme)
        console_page.set_viewport_size({"width": width, "height": 900})
        console_page.goto("/tenant")
        expect(console_page.locator(".readiness-warning")).to_have_count(0)
        console_page.get_by_role("button", name="Change deadline").click()
        dialog = console_page.get_by_role("dialog", name="Change the approval deadline?")
        field = dialog.get_by_role("textbox", name=re.compile("Seconds"))
        field.fill("300")
        warning = dialog.get_by_text(lapse)
        expect(warning).to_be_visible()
        assert (
            warning.get_attribute("id") in (field.get_attribute("aria-describedby") or "").split()
        )
        clean(console_page, f"deadline lapse warning {scheme} {width}")
        fits(console_page, f"deadline lapse warning {scheme} {width}")
        dialog.get_by_role("button", name="Cancel").click()
        expect(dialog).to_have_count(0)
