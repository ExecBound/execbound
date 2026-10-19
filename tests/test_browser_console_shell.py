# SPDX-License-Identifier: AGPL-3.0-only
"""The console's shell in real Chromium (#678): titles, the phone's navigation sheet, the crumb
chain, Recent, searching all spaces, focus, a failed page's report and a newer release.

Each test names the acceptance row it proves (NV1 to NV18 in `docs/ACCEPTANCE_TESTS.md`). The
gateway is the real one on real PostgreSQL, with axe-core injected as an init script, so a page
stays under the exact policy a browser enforces.
"""

import json
import re
import time

import pytest
from playwright.sync_api import expect
from space_fixtures import default_space, make_space, seat
from sqlalchemy import text
from test_browser_console import AXE_RUN, ENTRIES, settled, sign_in_as
from test_browser_console import console_gateway as console_gateway
from test_browser_console import console_page as console_page
from test_browser_console_policy import rules_draft as rules_draft
from test_browser_surfaces import FITS
from test_browser_surfaces import chromium as chromium
from test_console_api_activity import held, unscope
from test_execution import registry as registry
from test_execution import world as world
from test_protected_path import connector as connector
from test_protected_path import live_provider as live_provider
from test_runtime import runtime as runtime

CLASSIC_SCROLLBAR_PX = 15
ANNOUNCER = "[data-announcer]"


def clean(page, where) -> None:
    settled(page)
    violations = page.evaluate(AXE_RUN)
    assert violations == [], (where, violations)
    assert page.evaluate("window.__violations") == [], where
    assert page.evaluate(FITS), (where, "scroll")


def after_paint(page) -> None:
    """The shell's after-paint layer, which holds the title, the keys and the live region."""
    expect(page.locator(ANNOUNCER)).to_be_attached()


def test_nv1_titles_name_the_page_and_never_a_server_string(
    console_page, admin_engine, world, runtime
):
    with admin_engine.begin() as conn:
        conn.execute(
            text("UPDATE execbound.principals SET label=:l WHERE principal_id=:p"),
            {"l": "<img src=x onerror=alert(1)>", "p": world["identity"].principal_id},
        )
    view, _ = held(runtime, admin_engine, world)
    sign_in_as(console_page, admin_engine, world["admin"])
    record = console_page.request.get(f"/api/console/v1/executions/{view.execution_id}").json()
    host = record["target"]["provider_id"]
    console_page.goto(f"/approvals/{view.approval_id}")
    expect(console_page).to_have_title(
        re.compile(rf"^(\(\d+\) )?{view.request_ref} · Approvals · ")
    )
    console_page.goto(f"/activity?open={view.execution_id}")
    expect(console_page).to_have_title(re.compile(rf"^(\(\d+\) )?{view.request_ref} · Activity · "))
    assert host not in console_page.title()
    console_page.goto(f"/agents/{world['identity'].principal_id}")
    expect(console_page).to_have_title(re.compile(r"^(\(\d+\) )?Agent \d+ · Agent connections · "))
    for title in (console_page.title(),):
        assert "img" not in title and "onerror" not in title, title
        assert title.endswith(" · ExecBound"), title


def test_nv2_the_title_counts_what_waits_and_asks_nothing_while_hidden(
    console_page, admin_engine, world, runtime
):
    held(runtime, admin_engine, world)
    held(runtime, admin_engine, world)
    sign_in_as(console_page, admin_engine, world["human"])
    console_page.goto("/approvals")
    expect(console_page).to_have_title(re.compile(r"^\(2\) Approvals · "))
    asked: list[str] = []
    console_page.on("request", lambda request: asked.append(request.url))
    console_page.evaluate(
        "Object.defineProperty(document, 'hidden', {value: true, configurable: true});"
        "Object.defineProperty(document, 'visibilityState', "
        "{value: 'hidden', configurable: true});"
        "document.dispatchEvent(new Event('visibilitychange'));"
    )
    held(runtime, admin_engine, world)
    console_page.wait_for_timeout(20_000)
    assert asked == [], asked
    console_page.evaluate(
        "Object.defineProperty(document, 'hidden', {value: false, configurable: true});"
        "Object.defineProperty(document, 'visibilityState', "
        "{value: 'visible', configurable: true});"
        "document.dispatchEvent(new Event('visibilitychange'));"
    )
    expect(console_page).to_have_title(re.compile(r"^\(3\) Approvals · "), timeout=20_000)


def open_sheet(page):
    menu = page.get_by_role("button", name="Navigation menu")
    assert menu.evaluate("(button) => button.scrollWidth <= button.clientWidth")
    menu.click()
    sheet = page.get_by_role("dialog", name="Menu")
    expect(sheet).to_be_visible()
    assert page.evaluate("document.activeElement.tagName") != "INPUT"
    return sheet


@pytest.mark.parametrize("who", ["admin", "human"])
def test_nv8_the_phone_menu_opens_the_navigation_sheet(console_page, admin_engine, world, who):
    console_page.set_viewport_size({"width": 390, "height": 844})
    sign_in_as(console_page, admin_engine, world[who])
    console_page.goto("/")
    expect(console_page.get_by_role("heading", level=1)).to_be_visible()
    after_paint(console_page)
    for scheme in ("light", "dark"):
        console_page.emulate_media(color_scheme=scheme)
        sheet = open_sheet(console_page)
        box = sheet.bounding_box()
        assert box is not None and box["width"] <= 0.85 * 390 + 1, box
        clean(console_page, (who, scheme, "sheet"))
        console_page.keyboard.press("Escape")
        expect(sheet).to_have_count(0)
    console_page.emulate_media(color_scheme="light")
    sheet = open_sheet(console_page)
    labels = [
        name.strip().splitlines()[0]
        for name in sheet.get_by_role("link").all_inner_texts()
        if name.strip() != ""
    ]
    console_page.keyboard.press("Escape")
    known = {heading for _, heading in ENTRIES}
    for label in [label for label in labels if label in known]:
        sheet = open_sheet(console_page)
        sheet.get_by_role("link", name=label, exact=True).first.click()
        expect(console_page.get_by_role("heading", level=1)).to_have_text(label)
        expect(console_page.get_by_role("dialog", name="Menu")).to_have_count(0)


@pytest.mark.parametrize("width", [768, 1024, 1280])
def test_nv9_a_policy_versions_rules_name_their_ancestors(
    console_page, admin_engine, world, rules_draft, width
):
    console_page.set_viewport_size({"width": width, "height": 900})
    sign_in_as(console_page, admin_engine, world["admin"])
    console_page.goto(f"/policy/{rules_draft.bundle_id}/rules")
    expect(console_page.get_by_role("heading", level=1)).to_have_text("Rules")
    crumbs = console_page.get_by_role("navigation", name="Breadcrumb")
    expect(crumbs.locator("[aria-current=page]")).to_have_text("Rules")
    links = crumbs.locator("a.crumb-link")
    expect(links).to_have_count(2)
    expect(links.nth(0)).to_have_attribute("href", "/policy")
    expect(links.nth(1)).to_have_attribute("href", f"/policy/{rules_draft.bundle_id}")
    stop = console_page.locator("header.topbar").get_by_role("button", name="Emergency stop")
    box = stop.bounding_box()
    assert box is not None and 0 <= box["x"], box
    assert box["x"] + box["width"] <= width - CLASSIC_SCROLLBAR_PX, (width, box)
    more = crumbs.get_by_role("button", name="Show 1 more level")
    if width == 1024:
        expect(links.nth(0)).to_be_hidden()
        clean(console_page, "the crumbs closed at 1024")
        more.focus()
        console_page.keyboard.press("Enter")
        expect(more).to_have_attribute("aria-expanded", "true")
        hidden = crumbs.locator(".crumb-more-list").get_by_role("link", name="Policies")
        expect(hidden).to_be_visible()
        hidden.focus()
        expect(hidden).to_be_focused()
        clean(console_page, "the crumbs open at 1024")
        console_page.keyboard.press("Escape")
        expect(more).to_be_focused()
    elif width == 1280:
        expect(more).to_be_hidden()
        expect(links.nth(0)).to_be_visible()


def recent_record(page, execution_id):
    """The palette's Recent row for one execution, by the value it carries, never a label."""
    return page.locator(f'[cmdk-item][data-value="recent:execution:{execution_id}"]')


def test_nv11_recents_are_per_person_and_drop_revoked_records(
    console_page, admin_engine, world, runtime
):
    view, _ = held(runtime, admin_engine, world)
    sign_in_as(console_page, admin_engine, world["human"])
    console_page.goto(f"/approvals/{view.approval_id}")
    expect(console_page.get_by_role("heading", level=1)).to_be_visible()
    after_paint(console_page)
    for _ in range(50):
        stored = console_page.evaluate("JSON.stringify(localStorage)")
        if str(view.execution_id) in stored:
            break
        time.sleep(0.2)
    console_page.keyboard.press("Control+k")
    expect(recent_record(console_page, view.execution_id)).to_be_visible()
    console_page.keyboard.press("Escape")
    stored = console_page.evaluate("JSON.stringify(localStorage)")
    assert view.request_ref not in stored and "Isolate" not in stored, stored
    recents = json.loads(
        console_page.evaluate(
            "JSON.stringify(Object.entries(localStorage)"
            ".filter(([key]) => key.startsWith('eb.recent.v1.')))"
        )
    )
    for _key, value in recents:
        for entry in json.loads(value):
            assert set(entry) in ({"k", "to"}, {"k", "id"}), entry
    # The scope that made it readable is withdrawn: the record leaves Recent.
    with admin_engine.connect() as conn:
        canonical = conn.execute(
            text(
                "SELECT canonical_target_id FROM execbound.executions "
                "WHERE tenant_id=:t AND execution_id=:e"
            ),
            {"t": world["identity"].tenant_id, "e": view.execution_id},
        ).scalar_one()
    unscope(admin_engine, canonical)
    console_page.goto("/")
    expect(console_page.get_by_role("heading", level=1)).to_be_visible()
    after_paint(console_page)
    console_page.keyboard.press("Control+k")
    palette = console_page.get_by_role("dialog", name=re.compile(r"^Search"))
    expect(palette.get_by_role("group", name="Records")).to_be_visible()
    console_page.wait_for_timeout(1000)
    expect(recent_record(console_page, view.execution_id)).to_have_count(0)
    console_page.keyboard.press("Escape")
    # Another person in the same browser sees none of it; their own visit is theirs.
    sign_in_as(console_page, admin_engine, world["admin"])
    console_page.goto("/")
    after_paint(console_page)
    console_page.keyboard.press("Control+k")
    palette = console_page.get_by_role("dialog", name=re.compile(r"^Search"))
    expect(palette.get_by_role("group", name="Records")).to_be_visible()
    console_page.wait_for_timeout(1000)
    expect(recent_record(console_page, view.execution_id)).to_have_count(0)
    console_page.keyboard.press("Escape")
    other, _ = held(runtime, admin_engine, world)
    console_page.goto(f"/approvals/{other.approval_id}")
    expect(console_page.get_by_role("heading", level=1)).to_be_visible()
    after_paint(console_page)
    for _ in range(50):
        if str(other.execution_id) in console_page.evaluate("JSON.stringify(localStorage)"):
            break
        time.sleep(0.2)
    console_page.keyboard.press("Control+k")
    expect(recent_record(console_page, other.execution_id)).to_be_visible()


def test_nv13_a_record_in_another_space_is_found_by_searching_all_spaces(
    console_page, admin_engine, world, runtime
):
    # The record first, in the tenant's one space, then a second space to search from.
    view, _ = held(runtime, admin_engine, world)
    tenant = world["identity"].tenant_id
    with admin_engine.begin() as conn:
        first = default_space(conn, tenant)
        second = make_space(conn, tenant, "Payments", created_by=world["admin"].principal_id)
        seat(conn, tenant, first, world["human"].principal_id)
        seat(conn, tenant, second, world["human"].principal_id)
    asked: list[str] = []
    console_page.on("request", lambda request: asked.append(request.url))
    sign_in_as(console_page, admin_engine, world["human"])
    console_page.goto("/")
    console_page.get_by_role("button", name=re.compile(r"^Space .* change space$")).click()
    console_page.get_by_role("option", name=re.compile("Payments")).click()
    expect(console_page.get_by_role("button", name=re.compile(r"^Space Payments"))).to_be_visible()
    after_paint(console_page)
    console_page.keyboard.press("Control+k")
    palette = console_page.get_by_role("dialog", name=re.compile(r"^Search"))
    palette.get_by_role("combobox").fill(view.request_ref or "")
    expect(palette.get_by_text("No record matches in Payments.")).to_be_visible()
    palette.get_by_role("option", name="Search all your spaces").click()
    expect(
        palette.locator(f'[cmdk-item][data-value="execution:{view.execution_id}"]')
    ).to_be_visible()
    assert not any("space=" in url for url in asked), [url for url in asked if "space=" in url]


def test_nv14_focus_stays_on_a_query_change_and_returns_to_the_row(
    console_page, admin_engine, world, runtime
):
    held(runtime, admin_engine, world)
    sign_in_as(console_page, admin_engine, world["admin"])
    console_page.goto("/activity")
    expect(console_page.get_by_role("heading", level=1)).to_have_text("Activity")
    after_paint(console_page)
    chip = console_page.get_by_role("button", name="Held", exact=True)
    chip.focus()
    console_page.keyboard.press("Enter")
    expect(console_page).to_have_url(re.compile(r"state=PENDING_APPROVAL"))
    console_page.wait_for_timeout(300)
    expect(chip).to_be_focused()
    expect(console_page.locator(ANNOUNCER)).to_have_text(re.compile(r"action"))
    row = console_page.locator(".row-link").first
    row.focus()
    console_page.keyboard.press("Enter")
    drawer = console_page.get_by_role("dialog")
    expect(drawer).to_be_visible()
    console_page.keyboard.press("Escape")
    expect(drawer).to_have_count(0)
    expect(console_page.locator(".row-link").first).to_be_focused()
    console_page.goto("/")
    expect(console_page.get_by_role("heading", level=1)).to_have_text("Home")
    home_row = console_page.locator(".row-link").first
    home_row.focus()
    console_page.keyboard.press("Enter")
    expect(console_page.get_by_role("dialog")).to_be_visible()
    console_page.keyboard.press("Escape")
    expect(console_page.get_by_role("dialog")).to_have_count(0)
    expect(console_page.locator(".row-link").first).to_be_focused()


def test_nv16_a_failed_page_reports_once_by_its_route_and_shows_a_reference(
    console_page, admin_engine, world
):
    reports: list[dict] = []

    def record(request):
        if request.url.endswith("/api/console/v1/client-errors") and request.method == "POST":
            reports.append(request.post_data_json)

    console_page.on("request", record)
    agent = world["identity"].principal_id
    console_page.route(
        f"**/api/console/v1/agents/{agent}",
        lambda route: route.fulfill(status=200, content_type="application/json", body="{}"),
    )
    sign_in_as(console_page, admin_engine, world["admin"])
    console_page.goto(f"/agents/{agent}")
    expect(console_page.get_by_role("heading", level=1)).to_have_text("This page could not load")
    expect(console_page.get_by_text(re.compile(r"^Reference"))).to_be_visible()
    assert len(reports) == 1, reports
    assert set(reports[0]) == {"route", "release", "name", "stack_hash"}, reports[0]
    assert reports[0]["route"] == "/agents_/$agentId"
    assert str(agent) not in json.dumps(reports[0])


@pytest.fixture
def released(monkeypatch):
    """The gateway names the release it runs, so the build it serves names one too."""
    monkeypatch.setenv("EXECBOUND_COMMIT", "a" * 40)


def test_nv18_a_newer_release_loads_on_the_next_change_of_page(
    released, console_page, admin_engine, world
):
    # The API's answers below name a newer release than the build the page was served.
    sign_in_as(console_page, admin_engine, world["admin"])
    console_page.goto("/")
    expect(console_page.get_by_role("heading", level=1)).to_have_text("Home")
    after_paint(console_page)

    def newer(route):
        response = route.fetch()
        headers = {**response.headers, "x-execbound-release": "f" * 40}
        route.fulfill(response=response, headers=headers)

    console_page.route("**/api/console/v1/**", newer)
    console_page.reload()
    expect(
        console_page.get_by_text(re.compile("A new version of ExecBound is available"))
    ).to_be_visible()
    after_paint(console_page)
    documents: list[str] = []
    console_page.on(
        "request",
        lambda request: (
            documents.append(request.url) if request.resource_type == "document" else None
        ),
    )
    navigated: list[str] = []
    console_page.on(
        "framenavigated",
        lambda frame: navigated.append(frame.url) if frame == console_page.main_frame else None,
    )
    console_page.get_by_role("navigation", name="Main").get_by_role("link", name="Activity").click()
    expect(console_page.get_by_role("heading", level=1)).to_have_text("Activity")
    assert any(url.endswith("/activity") for url in documents), documents
    assert any(url.endswith("/activity") for url in navigated), navigated
    # Requests still on their way through the handler end with the test, not in the next one.
    console_page.unroute_all(behavior="ignoreErrors")


@pytest.mark.parametrize("scheme", ["dark", "light"])
@pytest.mark.parametrize("width", [1280, 390])
def test_cr4_the_bell_panel_and_the_keyboard_list_are_clean(
    console_page, admin_engine, world, runtime, scheme, width
):
    held(runtime, admin_engine, world)
    console_page.emulate_media(color_scheme=scheme)
    console_page.set_viewport_size({"width": width, "height": 844 if width == 390 else 900})
    sign_in_as(console_page, admin_engine, world["admin"])
    console_page.goto("/")
    expect(console_page.get_by_role("heading", level=1)).to_have_text("Home")
    after_paint(console_page)
    console_page.get_by_role("button", name=re.compile(r"^Notifications")).click()
    panel = console_page.get_by_role("dialog", name="Notifications")
    expect(panel.get_by_role("heading", name="Waiting on you")).to_be_visible()
    expect(panel.get_by_role("heading", name="Sign-in security")).to_be_visible()
    clean(console_page, (scheme, width, "bell"))
    console_page.keyboard.press("Escape")
    expect(panel).to_have_count(0)
    console_page.locator("main h1").click()
    console_page.keyboard.press("?")
    shortcuts = console_page.get_by_role("dialog", name="Keyboard")
    expect(shortcuts).to_be_visible()
    clean(console_page, (scheme, width, "keyboard list"))
