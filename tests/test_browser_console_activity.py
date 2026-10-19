# SPDX-License-Identifier: AGPL-3.0-only
"""Home and the record drawer under `/` in real Chromium (#333).

An administrator's Home shows the figures, the chart with its text alternative, what needs
them and the recent decisions; a row opens the drawer and the URL keeps it, so a reload and
the back button restore it; axe finds nothing and the browser reports no policy violation
with the drawer open, at 1280 and at 390 pixels. An approver's Home is their scope: the held
approval awaits them, an execution outside their scope is in no figure, no row and no drawer.
The command palette finds the records the search endpoint answers and opens each where it
belongs, and an approver's palette answers nothing outside their scope.
"""

import re

from playwright.sync_api import expect
from test_browser_console import AXE_RUN, settled, sign_in_as
from test_browser_console import console_gateway as console_gateway
from test_browser_console import console_page as console_page
from test_browser_surfaces import FITS
from test_browser_surfaces import chromium as chromium
from test_console_api_activity import denied, executed, held, unscope
from test_execution import registry as registry
from test_execution import targets
from test_execution import world as world
from test_protected_path import connector as connector
from test_protected_path import live_provider as live_provider
from test_runtime import runtime as runtime

from execbound.execution import admit


def clean(page, where: str) -> None:
    settled(page)
    assert page.evaluate(AXE_RUN) == [], where
    assert page.evaluate("window.__violations") == [], where


def test_home_shows_the_figures_and_the_url_keeps_the_open_record(
    console_page, admin_engine, world, db, runtime
):
    executed(db, runtime, world)
    refused = denied(runtime, admin_engine, world)
    held(runtime, admin_engine, world)
    sign_in_as(console_page, admin_engine, world["admin"])
    console_page.goto("/")
    expect(console_page.get_by_role("heading", level=1)).to_have_text("Home")
    figures = console_page.locator(".home-figure")
    # Decisions, executed, denied, stale, held for a person, unsettled and effect unknown:
    # every outcome the headline counts has a tile, so the tiles and the legend add to the
    # same number (#426, #678).
    expect(figures).to_have_count(7)
    expect(figures.nth(0)).to_contain_text("Decisions")
    expect(figures.nth(0).locator(".home-figure-value")).to_have_text("3")
    expect(figures.nth(1).locator(".home-figure-value")).to_have_text("1")
    expect(figures.nth(2).locator(".home-figure-value")).to_have_text("1")
    expect(figures.nth(3)).to_contain_text("Stale")
    expect(figures.nth(3).locator(".home-figure-value")).to_have_text("0")
    expect(figures.nth(4).locator(".home-figure-value")).to_have_text("1")
    assert console_page.locator(".legend").inner_text().split("\n") == [
        "Executed 1",
        "Held 1",
        "Denied 1",
        "Observed 0",
        "Stale 0",
        "Effect unknown 0",
    ]
    # The chart's description is a summary, not the 28 buckets read out one by one (#427).
    caption = console_page.locator("figure.chart figcaption").text_content() or ""
    assert "Executed 1, Held 1, Denied 1, Observed 0, Stale 0, Effect unknown 0." in caption
    assert "columns carry something" in caption or "All of it is in one of" in caption
    assert ": Executed 0, Held 0, Denied 0, Observed 0" not in caption
    expect(console_page.get_by_text("1 approval pending with an approver")).to_be_visible()
    table = console_page.get_by_role("table", name=re.compile("Recent decisions"))
    rows = table.get_by_role("row")
    expect(rows).to_have_count(4)
    clean(console_page, "home")
    rows.filter(has_text="Denied").get_by_role("button", name="Isolate endpoint").click()
    expect(console_page).to_have_url(re.compile(rf":\d+/\?open={refused.execution_id}$"))
    drawer = console_page.get_by_role("dialog", name=re.compile("Isolate endpoint"))
    expect(drawer).to_be_visible()
    expect(drawer.get_by_text("Request denied", exact=True)).to_be_visible()
    expect(
        drawer.get_by_text("ExecBound refused this request before dispatch.", exact=False)
    ).to_be_visible()
    expect(drawer.get_by_text("NOT_AUTHORIZED", exact=True)).to_be_hidden()
    expect(drawer).to_contain_text("Facts used")
    expect(drawer).to_contain_text("Request received and the plan frozen.")
    drawer.get_by_text("Decision evidence", exact=True).click()
    expect(drawer.get_by_text("NOT_AUTHORIZED", exact=True)).to_be_visible()
    drawer.get_by_text("Timeline evidence", exact=True).click()
    expect(drawer.get_by_text("Denied: NOT_AUTHORIZED.", exact=False)).to_be_visible()
    clean(console_page, "drawer")
    # A reload restores the drawer from the URL; Escape closes it and clears the URL; the
    # back button brings it back.
    console_page.reload()
    expect(console_page.get_by_role("dialog", name=re.compile("Isolate endpoint"))).to_be_visible()
    console_page.keyboard.press("Escape")
    expect(console_page.get_by_role("dialog")).to_have_count(0)
    expect(console_page).to_have_url(re.compile(r":\d+/$"))
    console_page.go_back()
    expect(console_page.get_by_role("dialog", name=re.compile("Isolate endpoint"))).to_be_visible()
    console_page.set_viewport_size({"width": 390, "height": 844})
    clean(console_page, "drawer at phone width")
    assert console_page.evaluate(FITS)
    console_page.emulate_media(color_scheme="light")
    clean(console_page, "drawer in light")


ROWS = """
(caption) => {
  const table = [...document.querySelectorAll('table')]
    .find((t) => t.querySelector('caption')?.textContent.startsWith(caption));
  const wrap = table.parentElement;
  const edge = wrap.getBoundingClientRect().right;
  const row = table.querySelector('tbody tr');
  const cells = [...row.querySelectorAll('td')].filter((cell) => cell.textContent.trim() !== '');
  return {
    hidden: wrap.scrollWidth - wrap.clientWidth,
    past: cells.filter((cell) => cell.getBoundingClientRect().right > edge + 0.5)
      .map((cell) => cell.textContent),
    badge: row.querySelector('.badge')?.getBoundingClientRect().right <= innerWidth,
  };
}
"""


def test_a_phone_reads_every_column_of_a_record(console_page, admin_engine, world, db, runtime):
    """On a phone, Home's Recent decisions and Activity were six columns cut off at the card's
    right edge, the decision among the columns out of sight (#678): each row now stacks."""
    executed(db, runtime, world)
    held(runtime, admin_engine, world)
    sign_in_as(console_page, admin_engine, world["admin"])
    for scheme in ("light", "dark"):
        console_page.emulate_media(color_scheme=scheme)
        console_page.set_viewport_size({"width": 390, "height": 844})
        for path, caption in (("/", "Recent decisions"), ("/activity", "Activity")):
            console_page.goto(path)
            expect(console_page.locator("table .row-link").first).to_be_attached()
            settled(console_page)
            geometry = console_page.evaluate(ROWS, caption)
            assert geometry["hidden"] <= 0, (path, scheme, geometry)
            assert geometry["past"] == [], (path, scheme, geometry)
            assert geometry["badge"], (path, scheme, geometry)
            clean(console_page, f"{path} {scheme} 390")


def test_an_approvers_home_is_their_scope(console_page, admin_engine, world, db, runtime):
    ran = executed(db, runtime, world)
    held(runtime, admin_engine, world)
    unscope(admin_engine, world["canonical"])
    sign_in_as(console_page, admin_engine, world["human"])
    console_page.goto("/")
    expect(console_page.get_by_role("heading", level=1)).to_have_text("Home")
    expect(console_page.get_by_text("1 approval awaiting you")).to_be_visible()
    needs = console_page.locator(
        "section", has=console_page.get_by_role("heading", name="Needs you")
    )
    expect(needs.get_by_role("button", name=re.compile("Isolate endpoint"))).to_be_visible()
    expect(needs.get_by_role("link", name="All approvals")).to_have_attribute("href", "/approvals")
    figures = console_page.locator(".home-figure")
    expect(figures.nth(1).locator(".home-figure-value")).to_have_text("0")
    expect(figures.nth(3)).to_contain_text("Stale")
    rows = console_page.get_by_role("table", name=re.compile("Recent decisions")).get_by_role("row")
    expect(rows).to_have_count(2)
    expect(console_page.locator(".badge", has_text="Executed")).to_have_count(0)
    clean(console_page, "approver home")
    # The unscoped record is not theirs, by URL either.
    console_page.goto(f"/?open={ran.execution_id}")
    expect(console_page.get_by_role("alert")).to_contain_text("This record could not load.")
    assert console_page.evaluate("window.__violations") == []
    console_page.keyboard.press("Escape")
    expect(console_page.get_by_role("dialog")).to_have_count(0)
    needs.get_by_role("button", name=re.compile("Isolate endpoint")).click()
    expect(console_page.get_by_role("dialog", name=re.compile("Isolate endpoint"))).to_contain_text(
        "Waiting for a person"
    )


def committed(db, admin_engine, world):
    """A dispatch admitted and never sent: DISPATCH_COMMITTED, the queue's first case."""
    [development] = targets(admin_engine, world, count=1)
    admission = admit(db, world["identity"], development, world["clock"])
    assert admission.view.state == "DISPATCH_COMMITTED"
    return admission.view.execution_id


def test_activity_settles_an_unsettled_dispatch_from_the_drawer(
    console_page, admin_engine, world, db, runtime
):
    execution_id = committed(db, admin_engine, world)
    sign_in_as(console_page, admin_engine, world["admin"])
    console_page.goto("/activity?state=UNCERTAIN")
    expect(console_page.get_by_role("heading", level=1)).to_have_text("Activity")
    expect(console_page.get_by_role("button", name="Uncertain")).to_have_attribute(
        "aria-pressed", "true"
    )
    rows = console_page.get_by_role("table", name=re.compile("Activity")).get_by_role("row")
    expect(rows).to_have_count(2)
    expect(rows.nth(1)).to_contain_text("Committed")
    clean(console_page, "the uncertain queue")
    console_page.set_viewport_size({"width": 390, "height": 844})
    clean(console_page, "the uncertain queue at phone width")
    assert console_page.evaluate(FITS)
    console_page.emulate_media(color_scheme="light")
    clean(console_page, "the uncertain queue in light at phone width")
    console_page.emulate_media(color_scheme="dark")
    console_page.set_viewport_size({"width": 1280, "height": 900})
    rows.nth(1).get_by_role("button", name="Reconcile").click()
    expect(console_page).to_have_url(re.compile(f"open={execution_id}"))
    dialog = console_page.get_by_role("dialog", name="Reconcile with provider evidence")
    expect(dialog).to_be_visible()
    clean(console_page, "the reconcile dialog")
    dialog.get_by_label("Reason").fill("Lost the ticket holder")
    dialog.get_by_role("button", name="Reconcile with provider evidence").click()
    expect(
        console_page.get_by_text(
            "Still unsettled: the provider's journal holds no terminal evidence."
        )
    ).to_be_visible()
    drawer = console_page.get_by_role("dialog", name=re.compile("Isolate endpoint"))
    expect(drawer).to_contain_text("Unsettled")
    assert runtime.status(world["identity"], execution_id).state == "INDETERMINATE"
    # Nothing was sent, so cancelling is the settlement the page offers; the button waits
    # for the server and the queue empties once the record has left it.
    drawer.get_by_role("button", name="Reconcile").click()
    dialog = console_page.get_by_role("dialog", name="Reconcile with provider evidence")
    dialog.get_by_label("Reason").fill("Nothing was sent")
    dialog.get_by_label("Cancel if no terminal evidence exists").check()
    dialog.get_by_role("button", name="Reconcile with provider evidence").click()
    expect(console_page.get_by_text("Settled: Not executed.")).to_be_visible()
    expect(drawer).to_contain_text("Not executed")
    assert runtime.status(world["identity"], execution_id).state == "FAILED_NOT_EXECUTED"
    console_page.keyboard.press("Escape")
    expect(console_page.get_by_role("dialog")).to_have_count(0)
    expect(console_page.get_by_text("No actions match these filters.")).to_be_visible()
    console_page.goto(f"/activity?open={execution_id}")
    expect(console_page.get_by_role("dialog", name=re.compile("Isolate endpoint"))).to_contain_text(
        "Failed before any effect"
    )
    assert console_page.evaluate("window.__violations") == []


def test_an_approver_is_offered_no_settlement(console_page, admin_engine, world, db, runtime):
    execution_id = committed(db, admin_engine, world)
    sign_in_as(console_page, admin_engine, world["human"])
    console_page.goto("/activity?state=UNCERTAIN")
    expect(console_page.get_by_role("heading", level=1)).to_have_text("Activity")
    rows = console_page.get_by_role("table", name=re.compile("Activity")).get_by_role("row")
    expect(rows).to_have_count(2)
    expect(console_page.get_by_role("button", name="Reconcile")).to_have_count(0)
    rows.nth(1).get_by_role("button", name="Isolate endpoint").click()
    drawer = console_page.get_by_role("dialog", name=re.compile("Isolate endpoint"))
    expect(drawer).to_contain_text("Dispatch committed.")
    expect(drawer.get_by_role("button", name="Reconcile")).to_have_count(0)
    clean(console_page, "an approver's drawer")
    assert runtime.status(world["identity"], execution_id).state == "DISPATCH_COMMITTED"


def test_the_palette_finds_records_in_scope_and_opens_them(
    console_page, admin_engine, world, db, runtime
):
    ran = executed(db, runtime, world)
    sign_in_as(console_page, admin_engine, world["admin"])
    console_page.goto("/")
    expect(console_page.get_by_role("heading", level=1)).to_have_text("Home")
    console_page.keyboard.press("Control+k")
    palette = console_page.get_by_role("dialog", name=re.compile(r"^Search( or ask)?$"))
    expect(palette).to_be_visible()
    console_page.keyboard.type("ws01")
    # The target's own row, not the "Go to" entry, which names it too.
    expect(palette.get_by_role("option", name=re.compile(r"^ws01\.example"))).to_be_visible()
    expect(
        palette.get_by_role("option", name="Activity where the target is ws01.example")
    ).to_be_visible()
    clean(console_page, "the palette with records")
    console_page.keyboard.press("Enter")
    expect(console_page).to_have_url(re.compile(rf"/activity\?target={world['canonical']}$"))
    expect(console_page.get_by_role("heading", level=1)).to_have_text("Activity")
    rows = console_page.get_by_role("table", name=re.compile("Activity")).get_by_role("row")
    expect(rows).to_have_count(2)
    expect(rows.nth(1)).to_contain_text("Executed")
    expect(console_page.get_by_role("button", name="Remove the target filter")).to_be_visible()
    # A request by the start of its id opens its record in the drawer.
    console_page.keyboard.press("Control+k")
    console_page.keyboard.type(str(ran.execution_id)[:8])
    option = console_page.get_by_role("option", name=re.compile("Isolate endpoint on device-01"))
    expect(option).to_be_visible()
    expect(option).to_contain_text("Executed")
    console_page.keyboard.press("Enter")
    expect(console_page).to_have_url(re.compile(rf"open={ran.execution_id}$"))
    expect(console_page.get_by_role("dialog", name=re.compile("Isolate endpoint"))).to_be_visible()
    assert console_page.evaluate("window.__violations") == []


def test_the_palette_shows_an_approver_nothing_outside_their_scope(
    console_page, admin_engine, world, db, runtime
):
    ran = executed(db, runtime, world)
    unscope(admin_engine, world["canonical"])
    sign_in_as(console_page, admin_engine, world["human"])
    console_page.goto("/")
    expect(console_page.get_by_role("heading", level=1)).to_have_text("Home")
    console_page.keyboard.press("Control+k")
    palette = console_page.get_by_role("dialog", name=re.compile(r"^Search( or ask)?$"))
    expect(palette).to_be_visible()
    console_page.keyboard.type("ws01")
    expect(palette.get_by_text("No record matches in your scope.")).to_be_visible()
    expect(palette.get_by_role("option", name=re.compile("ws01"))).to_have_count(0)
    console_page.keyboard.press("Control+a")
    console_page.keyboard.type(str(ran.execution_id)[:8])
    expect(palette.get_by_text("No record matches in your scope.")).to_be_visible()
    assert console_page.evaluate("window.__violations") == []
