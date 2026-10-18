# SPDX-License-Identifier: AGPL-3.0-only
"""Real browser workspace selection, old tabs and phone-width layout.

Workspace switching is part of core, so the switcher is tested with no plugin loaded. The
workspace-scoped approval address a plugin's notification links to belongs to that plugin, and
is tested with it.
"""

import re
from time import monotonic

import pytest
from playwright.sync_api import expect
from sqlalchemy import text
from test_browser_console import AXE, AXE_RUN, COLLECT, console_app, settled
from test_browser_console import console_gateway as console_gateway
from test_browser_console import console_page as console_page
from test_browser_surfaces import ACTION_TIMEOUT_MS, serve
from test_browser_surfaces import chromium as chromium
from test_execution import registry as registry
from test_execution import world as world
from test_protected_path import connector as connector
from test_protected_path import live_provider as live_provider
from test_runtime import runtime as runtime
from test_workspace_switching import member_pair

from execbound.resolution.models import SystemClock


def clean(page, what):
    """axe-core finds nothing, the policy was never violated, and nothing scrolls sideways."""
    settled(page)
    assert page.evaluate(AXE_RUN) == [], what
    assert page.evaluate("window.__violations") == [], what
    assert page.evaluate(
        "document.documentElement.scrollWidth <= document.documentElement.clientWidth"
    ), what


@pytest.mark.parametrize("width", [1280, 390])
def test_workspace_switch_replaces_viewer_context_and_stops_old_tabs(
    console_page, console_gateway, runtime, db, admin_engine, seeded, width
):
    runtime.clock = SystemClock()
    grant, _, _, _ = member_pair(db, admin_engine, seeded)
    with admin_engine.begin() as conn:
        for tenant, name in zip(seeded["tenants"], ("Personal", "Team"), strict=True):
            conn.execute(
                text("UPDATE execbound.tenants SET name=:name WHERE tenant_id=:t"),
                {"name": name, "t": tenant},
            )
    console_page.context.add_cookies(
        [
            {
                "name": name,
                "value": value,
                "url": console_gateway,
                "httpOnly": True,
                "sameSite": "Strict",
            }
            for name, value in (
                ("eb_session", grant.token),
                ("eb_csrf", grant.csrf_token),
                ("eb_account", grant.account_token),
            )
        ]
    )
    console_page.set_viewport_size({"width": width, "height": 900})
    console_page.goto("/activity")
    expect(console_page.get_by_role("heading", level=1)).to_have_text("Activity")
    old = console_page.context.new_page()
    old.goto(console_gateway + "/board")
    expect(old.get_by_role("heading", level=1)).to_have_text("Live board")
    console_page.get_by_role("button", name=re.compile(r"^Workspace.*Personal")).click()
    expect(console_page.get_by_role("heading", name="Your workspaces")).to_be_visible()
    settled(console_page)
    assert console_page.evaluate(AXE_RUN) == []
    assert console_page.evaluate(
        "document.documentElement.scrollWidth <= document.documentElement.clientWidth"
    )
    console_page.get_by_role("option", name=re.compile("^Team")).click()
    expect(console_page.get_by_role("button", name=re.compile(r"^Workspace.*Team"))).to_be_visible()
    expect(old.get_by_role("heading", level=1)).to_have_text("Workspace changed")
    expect(
        old.get_by_text("This tab was showing Personal. This browser is now in Team.")
    ).to_be_visible()
    expect(old.get_by_role("link", name="Open Live board in Team")).to_have_attribute(
        "href", "/board"
    )
    current = console_page.request.get(console_gateway + "/api/console/v1/session").json()
    assert current["tenant"]["tenant_id"] == str(seeded["tenants"][1])
    assert current["access"]["roles"] == ["viewer"]
    stale = old.request.post(
        console_gateway + "/api/console/v1/session/workspace",
        data={"tenant_id": str(seeded["tenants"][0])},
        headers={
            "Origin": console_gateway,
            "X-CSRF-Token": current["csrf_token"],
            "X-ExecBound-Workspace": str(grant.session_id),
        },
    )
    assert stale.status == 409 and stale.json()["code"] == "WORKSPACE_CHANGED"
    assert console_page.evaluate("window.__violations") == []
    old.close()


# Where each line of the switcher sits against the button that holds it and the button against
# the top bar, and whether the name is cut short on one line with an ellipsis rather than cut
# through vertically. The name clips its own overflow, so a name squeezed shorter than its line
# still sits inside the button; only its own height and scroll height show the cut.
CHIP_GEOMETRY = """
(button) => {
  const box = button.getBoundingClientRect();
  const bar = button.closest('header').getBoundingClientRect();
  const label = document.createRange();
  label.selectNodeContents(button.firstChild);
  const first = label.getBoundingClientRect();
  const name = button.querySelector('.workspace-current');
  const second = name.getBoundingClientRect();
  const style = getComputedStyle(name);
  const inside = (line) => line.top >= box.top - 0.5 && line.bottom <= box.bottom + 0.5
    && line.left >= box.left - 0.5 && line.right <= box.right + 0.5;
  return {
    label: button.firstChild.textContent,
    label_inside: inside(first),
    name_inside: inside(second),
    in_bar: box.top >= bar.top - 0.5 && box.bottom <= bar.bottom + 0.5,
    below: second.top >= first.bottom - 0.5,
    overflow: button.scrollHeight > button.clientHeight + 1,
    lines: name.getClientRects().length,
    one_line: Math.abs(second.height - parseFloat(style.lineHeight)) <= 1,
    cut: name.scrollHeight > name.clientHeight + 1,
    truncated: name.scrollWidth > name.clientWidth,
    ellipsis: style.textOverflow === 'ellipsis' && style.whiteSpace === 'nowrap',
  };
}
"""


@pytest.mark.parametrize("width", [1280, 390])
@pytest.mark.parametrize("name", ["contoso", "Northwind security operations, second shift"])
def test_the_switcher_shows_the_whole_workspace_name(
    console_page, console_gateway, runtime, db, admin_engine, seeded, width, name
):
    """The chip at the top left reads "Workspace" over the workspace's name, both lines inside
    the button in either scheme; a name too long for it ends in an ellipsis on its one line."""
    runtime.clock = SystemClock()
    grant, _, _, _ = member_pair(db, admin_engine, seeded)
    with admin_engine.begin() as conn:
        conn.execute(
            text("UPDATE execbound.tenants SET name=:name WHERE tenant_id=:t"),
            {"name": name, "t": seeded["tenants"][0]},
        )
    console_page.context.add_cookies(
        [
            {
                "name": cookie,
                "value": value,
                "url": console_gateway,
                "httpOnly": True,
                "sameSite": "Strict",
            }
            for cookie, value in (
                ("eb_session", grant.token),
                ("eb_csrf", grant.csrf_token),
                ("eb_account", grant.account_token),
            )
        ]
    )
    console_page.set_viewport_size({"width": width, "height": 900})
    console_page.goto("/activity")
    expect(console_page.get_by_role("heading", level=1)).to_have_text("Activity")
    chip = console_page.get_by_role("button", name=re.compile(r"^Workspace"))
    expect(chip).to_have_accessible_name(f"Workspace {name}")
    for scheme in ("light", "dark"):
        console_page.emulate_media(color_scheme=scheme)
        clean(console_page, f"the switcher at {width} in {scheme}")
        seen = chip.evaluate(CHIP_GEOMETRY)
        assert seen["label"] == "Workspace", seen
        assert seen["label_inside"] and seen["name_inside"] and seen["below"], (scheme, seen)
        assert seen["in_bar"] and not seen["overflow"] and not seen["cut"], (scheme, seen)
        assert seen["lines"] == 1 and seen["one_line"] and seen["ellipsis"], (scheme, seen)
        if name == "contoso":
            assert not seen["truncated"], (scheme, seen)
        else:
            assert seen["truncated"], (scheme, seen)
    console_page.emulate_media(color_scheme="light")


# Where each control in the top bar, and the breadcrumb between them, paints: its own box joined
# with every visible descendant's and every line of its text, each cut by any ancestor below the
# bar that clips its overflow. A box squeezed narrower than its content still paints that
# content, which is how the compact Space switcher, held to 19 px, came to paint its chevron over
# the Menu button. Visually hidden text (absolutely positioned and clipped, as `.sr-only` is)
# paints nothing and is left out, though it is still the control's name; so is anything that
# paints nothing at all, such as a breadcrumb squeezed to no width.
TOPBAR_ITEMS = """
(bar) => {
  const clipped = (start, rect) => {
    const box = { left: rect.left, right: rect.right, top: rect.top, bottom: rect.bottom };
    for (let node = start; node !== null && node !== bar; node = node.parentElement) {
      const style = getComputedStyle(node);
      if (style.overflowX === 'visible' && style.overflowY === 'visible') continue;
      const edge = node.getBoundingClientRect();
      box.left = Math.max(box.left, edge.left);
      box.right = Math.min(box.right, edge.right);
      box.top = Math.max(box.top, edge.top);
      box.bottom = Math.min(box.bottom, edge.bottom);
    }
    return box;
  };
  const hidden = (element) => {
    for (let node = element; node !== null && node !== bar; node = node.parentElement) {
      const style = getComputedStyle(node);
      if (style.visibility === 'hidden') return true;
      if (style.position === 'absolute' && style.clip !== 'auto') return true;
    }
    return false;
  };
  const painted = (control) => {
    const boxes = [];
    const add = (start, rect) => {
      if (rect.width <= 0 || rect.height <= 0) return;
      const box = clipped(start, rect);
      if (box.right - box.left > 0.5 && box.bottom - box.top > 0.5) boxes.push(box);
    };
    add(control.parentElement, control.getBoundingClientRect());
    const walker = document.createTreeWalker(
      control, NodeFilter.SHOW_ELEMENT | NodeFilter.SHOW_TEXT
    );
    for (let node = walker.nextNode(); node !== null; node = walker.nextNode()) {
      if (node.nodeType === Node.TEXT_NODE) {
        if (node.textContent.trim() === '' || hidden(node.parentElement)) continue;
        const range = document.createRange();
        range.selectNodeContents(node);
        for (const rect of range.getClientRects()) add(node.parentElement, rect);
      } else if (!hidden(node)) {
        for (const rect of node.getClientRects()) add(node.parentElement, rect);
      }
    }
    if (boxes.length === 0) return null;
    return {
      name: control.getAttribute('aria-label') || control.textContent.trim(),
      left: Math.min(...boxes.map((box) => box.left)),
      right: Math.max(...boxes.map((box) => box.right)),
      top: Math.min(...boxes.map((box) => box.top)),
      bottom: Math.max(...boxes.map((box) => box.bottom)),
    };
  };
  const style = getComputedStyle(bar);
  const edge = bar.getBoundingClientRect();
  const shown = [...bar.querySelectorAll('button, summary, a[href], nav')].filter(
    (item) => item.getClientRects().length > 0 && !hidden(item)
  );
  const outermost = shown.filter(
    (item) => !shown.some((other) => other !== item && other.contains(item))
  );
  return {
    left: edge.left + parseFloat(style.paddingLeft),
    right: edge.right - parseFloat(style.paddingRight),
    items: outermost.map(painted).filter((item) => item !== null),
  };
}
"""


# The workspace name that squeezed the compact Space switcher most.
LONG_NAME = "Northwind security operations, second shift"


def long_named_account(runtime, db, admin_engine, seeded):
    """An administrator's account with a second workspace, so the top bar shows the workspace
    chip, whose first workspace has the long name; the grant of a password sign-in to it."""
    runtime.clock = SystemClock()
    grant, _, _, _ = member_pair(db, admin_engine, seeded)
    with admin_engine.begin() as conn:
        conn.execute(
            text("UPDATE execbound.tenants SET name=:name WHERE tenant_id=:t"),
            {"name": LONG_NAME, "t": seeded["tenants"][0]},
        )
    return grant


def sign_in(page, origin, grant):
    """The session's cookies in the page's browser, as a password sign-in leaves them."""
    page.context.add_cookies(
        [
            {
                "name": cookie,
                "value": value,
                "url": origin,
                "httpOnly": True,
                "sameSite": "Strict",
            }
            for cookie, value in (
                ("eb_session", grant.token),
                ("eb_csrf", grant.csrf_token),
                ("eb_account", grant.account_token),
            )
        ]
    )


def bar_controls(bar, what):
    """The top bar's painted controls, the breadcrumb left out, once nothing in the bar reaches
    into either gutter or paints over anything else."""
    seen = bar.evaluate(TOPBAR_ITEMS)
    items = seen["items"]
    for index, first in enumerate(items):
        assert first["left"] >= seen["left"] - 0.5, (what, "left gutter", first)
        assert first["right"] <= seen["right"] + 0.5, (what, "right gutter", first)
        for second in items[index + 1 :]:
            apart = (
                first["right"] <= second["left"] + 0.5
                or second["right"] <= first["left"] + 0.5
                or first["bottom"] <= second["top"] + 0.5
                or second["bottom"] <= first["top"] + 0.5
            )
            assert apart, (what, first, second)
    return [item for item in items if item["name"] != "Breadcrumb"]


# What a classic scrollbar, as on Windows or with a mouse on Linux, takes from a window's width.
# A window 768 px wide still takes the sidebar's layout, whose rules read the window, and lays it
# out in 753 px. Headless Chromium draws no scrollbar, so an audit leaves the room instead.
CLASSIC_SCROLLBAR_PX = 15


# Whether an element's text is set in the web font it asks for yet. The page's load event waits
# only for the face the plain frame uses. The shell's controls ask for the medium weight once they
# render, and with `font-display: swap` they are laid out in a fallback font until it arrives.
# Where the fallback is wider than IBM Plex Sans, as DejaVu Sans is on Ubuntu, a box measured
# before the swap and one measured after it come from two layouts. On a 2-CPU runner the stop,
# measured in DejaVu Sans, ran 2.25 px past Ask, measured in Plex, though in either layout alone
# Ask sits the actions' 8 px gap after the stop.
IN_ITS_OWN_FONT = """
async (element) => {
  await document.fonts.ready;
  const style = getComputedStyle(element);
  const font = `${style.fontStyle} ${style.fontWeight} ${style.fontSize} ${style.fontFamily}`;
  return document.fonts.check(font, element.textContent);
}
"""


def in_its_own_font(locator, what):
    """Wait until `locator`'s text is set in its own web font. Each pass waits for the fonts
    the page is loading, then checks the element's own face, which a face the page has not yet
    asked for fails."""
    deadline = monotonic() + ACTION_TIMEOUT_MS / 1000
    while not locator.evaluate(IN_ITS_OWN_FONT):
        assert monotonic() < deadline, (what, "its web font never loaded")
        locator.page.wait_for_timeout(50)


def stop_on_screen(bar, width, what):
    """The emergency stop's whole box is on screen at `width`, with room for a classic
    scrollbar beside it; its box, for a test that places something else against it. The box is
    measured once the stop's label is in its own font, so it and a box measured after it come
    from the same layout."""
    stop = bar.get_by_role("button", name="Emergency stop")
    expect(stop).to_be_visible()
    in_its_own_font(stop, what)
    box = stop.bounding_box()
    assert box is not None, what
    assert box["x"] >= 0, (what, box)
    assert box["x"] + box["width"] <= width - CLASSIC_SCROLLBAR_PX, (what, box)
    return box


@pytest.fixture(params=[False, True], ids=["without-ask", "with-ask"])
def topbar_page(request, chromium, db, runtime):
    """A console at phone width, for a deployment with Ask or without it: one that configured
    a model has an Ask button in the top bar at wider widths, 34 px the others would lack. No
    plugin is loaded: the workspace switcher and its own API route are core."""
    with serve(lambda origin: console_app(db, runtime, origin, assistant=request.param)) as origin:
        with chromium.new_context(
            base_url=origin, viewport={"width": 390, "height": 844}
        ) as context:
            page = context.new_page()
            page.set_default_timeout(ACTION_TIMEOUT_MS)
            page.add_init_script(COLLECT)
            page.add_init_script(path=str(AXE))
            yield page, origin, request.param


@pytest.mark.parametrize("width", [360, 390, 430])
def test_no_top_bar_control_overlaps_another_on_a_phone(
    topbar_page, runtime, db, admin_engine, seeded, width
):
    """At 390 px, at 430 px where the switcher painted over the breadcrumb instead, and at
    360 px, with a second workspace (so the chip is there) and a tenant administrator's
    controls, nothing in the top bar paints over anything else in either scheme: the compact
    Space switcher gives up its name for its mark and chevron, and the mode its word for its
    dot, each still carrying its full name for a screen reader, and Ask moves behind Menu.
    Nothing reaches into either 16 px gutter, and nothing scrolls sideways. From 390 px the
    switcher shows its whole mark and chevron; at 360 px, beside this long a name, it clips
    its chevron inside its own box."""
    page, origin, ask = topbar_page
    page.set_viewport_size({"width": width, "height": 844})
    sign_in(page, origin, long_named_account(runtime, db, admin_engine, seeded))
    page.goto("/activity")
    expect(page.get_by_role("heading", level=1)).to_have_text("Activity")
    bar = page.locator("header.topbar")
    expect(bar.get_by_role("button", name=re.compile(r"^Workspace"))).to_be_visible()
    expect(bar.get_by_role("button", name=re.compile(r"^Space .*; change space$"))).to_be_visible()
    expect(bar.get_by_role("button", name="Navigation menu")).to_be_visible()
    expect(bar.get_by_role("button", name="Ask")).to_have_count(0)
    # Chromium puts a space between the two visually hidden runs of text; the word itself is
    # what has to survive.
    expect(bar.locator("summary")).to_have_accessible_name(
        re.compile(r"^(Enforcing|Observe only|Mode) ?: protection coverage$")
    )
    if ask:
        # Ask is not in the bar at this width, and Menu's navigation sheet still offers it.
        bar.get_by_role("button", name="Navigation menu").click()
        sheet = page.get_by_role("dialog", name="Menu")
        expect(sheet.get_by_role("link", name="Ask", exact=True)).to_be_visible()
        page.keyboard.press("Escape")
        expect(sheet).to_have_count(0)
    for scheme in ("light", "dark"):
        page.emulate_media(color_scheme=scheme)
        clean(page, f"the top bar at {width} in {scheme}")
        # The chip, the Space switcher, Menu, the mode, the stop and the bell, and the
        # breadcrumb if it has any room.
        controls = bar_controls(bar, (width, scheme))
        assert len(controls) == 6, (width, scheme, controls)
        if width >= 390:
            switcher = bar.get_by_role("button", name=re.compile(r"^Space "))
            assert switcher.evaluate("(button) => button.scrollWidth <= button.clientWidth"), (
                width,
                scheme,
            )
    page.emulate_media(color_scheme="light")


@pytest.mark.parametrize("width", [900, 1024])
def test_no_top_bar_control_overlaps_another_on_a_tablet_or_small_laptop(
    topbar_page, runtime, db, admin_engine, seeded, width
):
    """Beside the sidebar, with the chip, this long a name and a tenant administrator's
    controls, the breadcrumb gives up its room first and Ask, where a deployment has it, shows
    its icon alone below 1280 px, keeping its name. At 900 px the breadcrumb, which kept its
    whole width, pushed the bell past the right gutter, and Ask's label pushed Ask with it, and
    the page scrolled sideways. Nothing paints over anything else and nothing reaches the
    gutter, in either scheme.

    From 768 px to about 850 px the bar still does not fit this long a name beside the
    emergency stop's label, with Ask or without it: that is left to its own change, and the
    stop itself stays on screen there (below)."""
    page, origin, ask = topbar_page
    page.set_viewport_size({"width": width, "height": 900})
    sign_in(page, origin, long_named_account(runtime, db, admin_engine, seeded))
    page.goto("/activity")
    expect(page.get_by_role("heading", level=1)).to_have_text("Activity")
    bar = page.locator("header.topbar")
    if ask:
        expect(bar.get_by_role("button", name="Ask")).to_be_visible()
        expect(bar.get_by_role("button", name="Ask").locator(".btn-label")).to_be_hidden()
    for scheme in ("light", "dark"):
        page.emulate_media(color_scheme=scheme)
        clean(page, f"the top bar at {width} in {scheme}")
        bar_controls(bar, (width, scheme))
    page.emulate_media(color_scheme="light")


def test_the_emergency_stop_stays_on_screen_at_768_px(
    topbar_page, runtime, db, admin_engine, seeded
):
    """At 768 px, the narrowest width with the sidebar, the bar does not yet fit this long a
    name beside the stop's label (above), and what runs past the right edge is what follows the
    stop, never the stop: its whole box, label and all, is on screen with room for a classic
    scrollbar, with Ask or without it."""
    page, origin, ask = topbar_page
    page.set_viewport_size({"width": 768, "height": 900})
    sign_in(page, origin, long_named_account(runtime, db, admin_engine, seeded))
    page.goto("/activity")
    expect(page.get_by_role("heading", level=1)).to_have_text("Activity")
    expect(page.get_by_role("navigation", name="Main", exact=True)).to_be_visible()
    bar = page.locator("header.topbar")
    expect(bar.get_by_role("button", name="Emergency stop").locator(".btn-label")).to_be_visible()
    stop = stop_on_screen(bar, 768, ("768", ask))
    if ask:
        after = bar.get_by_role("button", name="Ask").bounding_box()
        assert after is not None and stop["x"] + stop["width"] <= after["x"], (stop, after)


def _signed_in(page, gateway, grant):
    page.context.add_cookies(
        [
            {
                "name": name,
                "value": value,
                "url": gateway,
                "httpOnly": True,
                "sameSite": "Strict",
            }
            for name, value in (
                ("eb_session", grant.token),
                ("eb_csrf", grant.csrf_token),
                ("eb_account", grant.account_token),
            )
        ]
    )


def _another(page, width):
    """A second tab in the same browser, carrying the audit and the policy watcher too."""
    other = page.context.new_page()
    other.set_default_timeout(ACTION_TIMEOUT_MS)
    other.add_init_script(COLLECT)
    other.add_init_script(path=str(AXE))
    other.set_viewport_size({"width": width, "height": 900})
    return other


def _name(admin_engine, tenants, names):
    with admin_engine.begin() as conn:
        for tenant, name in zip(tenants, names, strict=True):
            conn.execute(
                text("UPDATE execbound.tenants SET name=:name WHERE tenant_id=:t"),
                {"name": name, "t": tenant},
            )


def _both_schemes(page, what):
    for scheme in ("light", "dark"):
        page.emulate_media(color_scheme=scheme)
        clean(page, f"{what} in {scheme}")
    page.emulate_media(color_scheme="light")


RECORD = "abcdef01-0000-4000-8000-000000000001"


@pytest.mark.parametrize("width", [1280, 390])
def test_xw8_a_tab_left_behind_names_both_workspaces_and_keeps_its_section(
    console_page, console_gateway, runtime, db, admin_engine, seeded, width
):
    from execbound.passwords import sign_in_with_password
    from execbound.surfaces.sessions import issue_session

    runtime.clock = SystemClock()
    grant, _, _, _ = member_pair(db, admin_engine, seeded)
    _name(admin_engine, seeded["tenants"], ("Personal", "Team"))
    _signed_in(console_page, console_gateway, grant)
    console_page.set_viewport_size({"width": width, "height": 900})
    console_page.goto("/board")
    expect(console_page.get_by_role("heading", level=1)).to_have_text("Live board")
    left = _another(console_page, width)
    left.goto(console_gateway + f"/policy/{RECORD}")
    expect(left.get_by_role("button", name=re.compile(r"^Workspace Personal"))).to_be_visible()
    console_page.get_by_role("button", name=re.compile(r"^Workspace Personal")).click()
    console_page.get_by_role("option", name=re.compile("^Team")).click()
    expect(console_page.get_by_role("button", name=re.compile(r"^Workspace Team"))).to_be_visible()
    # The switch kept the section: a viewer in Team opens the Live board there too.
    expect(console_page).to_have_url(re.compile(r"/board$"))
    expect(left.get_by_role("heading", level=1)).to_have_text("Workspace changed")
    expect(
        left.get_by_text("This tab was showing Personal. This browser is now in Team.")
    ).to_be_visible()
    link = left.get_by_role("link", name="Open Policies in Team")
    expect(link).to_have_attribute("href", "/policy")
    _both_schemes(left, f"the stale page at {width}")
    # A sign-in again to Personal, in a third tab: the server confirms it before either tab acts.
    # Team was entered last, so the sign-in names Personal, as a link into it would.
    again = issue_session(
        db,
        sign_in_with_password(
            db, "member@example.test", "a retained example passphrase", prefer=seeded["tenants"][0]
        ),
    )
    third = _another(console_page, width)
    _signed_in(third, console_gateway, again)
    third.goto(console_gateway + "/activity")
    expect(third.get_by_role("heading", level=1)).to_have_text("Activity")
    expect(left.get_by_role("heading", level=1)).to_have_text("You signed in again")
    expect(left.get_by_role("link", name="Reload this page")).to_have_attribute(
        "href", f"/policy/{RECORD}"
    )
    _both_schemes(left, f"the signed-in-again page at {width}")
    expect(console_page.get_by_role("heading", level=1)).to_have_text("Workspace changed")
    expect(
        console_page.get_by_text("This tab was showing Team. This browser is now in Personal.")
    ).to_be_visible()
    stale = left.request.post(
        console_gateway + "/api/console/v1/session/workspace",
        data={"tenant_id": str(seeded["tenants"][1])},
        headers={
            "Origin": console_gateway,
            "X-CSRF-Token": again.csrf_token,
            "X-ExecBound-Workspace": str(grant.session_id),
        },
    )
    assert stale.status == 409 and stale.json()["code"] == "WORKSPACE_CHANGED"
    for page in (left, third):
        assert page.evaluate("window.__violations") == []
        page.close()


def test_xw9_the_menu_by_keyboard_and_pointer(
    console_page, console_gateway, runtime, db, admin_engine, seeded
):
    from test_workspace_accounts import membership_in
    from test_workspace_waiting import new_tenant

    runtime.clock = SystemClock()
    grant, _, account, _ = member_pair(db, admin_engine, seeded)
    _name(admin_engine, seeded["tenants"], ("Personal", "Team"))
    for name in ("Contoso SOC", "Contoso lab", "Fabrikam", "Northwind", "Tailspin"):
        membership_in(admin_engine, account, new_tenant(admin_engine, name)[0])
    _signed_in(console_page, console_gateway, grant)
    console_page.goto("/activity")
    expect(console_page.get_by_role("heading", level=1)).to_have_text("Activity")
    trigger = console_page.get_by_role("button", name=re.compile(r"^Workspace Personal"))
    trigger.focus()
    console_page.keyboard.press("Enter")
    menu = console_page.get_by_role("listbox", name="Workspaces")
    expect(menu.get_by_role("option")).to_have_count(7)
    expect(menu.get_by_role("option").first).to_have_attribute("aria-selected", "true")
    filter_box = console_page.get_by_role("textbox", name="Filter workspaces")
    expect(filter_box).to_be_focused()
    filter_box.type("contoso")
    expect(menu.get_by_role("option")).to_have_count(2)
    console_page.keyboard.press("ArrowDown")
    expect(menu.get_by_role("option").first).to_be_focused()
    console_page.keyboard.press("ArrowDown")
    expect(menu.get_by_role("option").nth(1)).to_be_focused()
    console_page.keyboard.press("Escape")
    expect(menu).to_have_count(0)
    expect(trigger).to_be_focused()
    trigger.click()
    expect(menu).to_be_visible()
    # A press well away from the menu, on the page beneath it.
    console_page.mouse.click(1200, 850)
    expect(menu).to_have_count(0)


@pytest.mark.parametrize("width", [1280, 390])
def test_xw12_the_switcher_shows_what_waits_elsewhere_and_passes_the_audit(
    console_page, console_gateway, runtime, db, admin_engine, seeded, world, width
):
    from test_human_surface import pending
    from test_workspace_accounts import adopt, enroll, membership_in

    from execbound.passwords import sign_in_with_password
    from execbound.surfaces.sessions import issue_session

    runtime.clock = SystemClock()
    first, second = seeded["tenants"]
    assert world["identity"].tenant_id == first
    principal, _ = enroll(admin_engine, second)
    account = adopt(db, second, principal)
    membership_in(admin_engine, account, first, principal=world["human"].principal_id)
    _name(admin_engine, (first, second), ("Customer A", "Team"))
    pending(runtime, world)
    grant = issue_session(
        db, sign_in_with_password(db, "member@example.test", "a retained example passphrase")
    )
    _signed_in(console_page, console_gateway, grant)
    console_page.set_viewport_size({"width": width, "height": 900})
    console_page.goto("/activity")
    expect(console_page.get_by_role("heading", level=1)).to_have_text("Activity")
    trigger = console_page.get_by_role(
        "button", name="Workspace Team, approvals waiting in another workspace"
    )
    expect(trigger).to_be_visible()
    expect(console_page.locator(".workspace-dot")).to_be_visible()
    trigger.click()
    menu = console_page.get_by_role("listbox", name="Workspaces")
    waiting = menu.get_by_role("option", name=re.compile("^Customer A"))
    expect(waiting).to_contain_text("1 waiting for you")
    _both_schemes(console_page, f"the open menu at {width}")
    viewport = console_page.viewport_size
    assert viewport is not None
    for option in menu.get_by_role("option").all():
        box = option.bounding_box()
        assert box is not None
        assert 0 <= box["x"] and box["x"] + box["width"] <= viewport["width"], box
        if width == 390:
            assert box["height"] >= 44, box
