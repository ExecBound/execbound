# SPDX-License-Identifier: AGPL-3.0-only
"""The console's foundation in real Chromium (#678): times, names and words.

Each `test_cf<N>_` test proves a row of the "Console foundation" acceptance group. Vitest runs
in UTC, where a local time labelled UTC cannot be seen; a browser context with a time zone of
its own is the end-to-end proof that the approval reads in the viewer's zone and says which.
"""

import re
from datetime import timedelta

import pytest
from playwright.sync_api import expect
from test_browser_console import AXE_RUN, settled, sign_in_as
from test_browser_console import console_gateway as console_gateway
from test_browser_console import console_page as console_page
from test_browser_console_approvals import COLLECT, pending
from test_browser_console_approvals import agent as agent
from test_browser_surfaces import ACTION_TIMEOUT_MS
from test_browser_surfaces import chromium as chromium
from test_execution import registry as registry
from test_execution import targets
from test_execution import world as world
from test_protected_path import connector as connector
from test_protected_path import live_provider as live_provider
from test_runtime import runtime as runtime

from execbound.execution import activate_stop

NEW_YORK = "America/New_York"
EASTERN = re.compile(r"\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2} E[DS]T")
IN_UTC = re.compile(r"\d{4}-\d{2}-\d{2} \d{2}:\d{2}(:\d{2})? UTC")
# Storage that refuses every read and write, as a locked-down browser's does.
NO_STORAGE = """
Object.defineProperty(window, 'localStorage', {
  configurable: true,
  get() { throw new DOMException('blocked', 'SecurityError'); },
});
"""


@pytest.fixture
def eastern(chromium, console_gateway):
    """A viewer in New York, at a desktop width."""
    with chromium.new_context(
        base_url=console_gateway, viewport={"width": 1280, "height": 900}, timezone_id=NEW_YORK
    ) as context:
        page = context.new_page()
        page.set_default_timeout(ACTION_TIMEOUT_MS)
        page.add_init_script(COLLECT)
        yield page


def open_detail(page, approval_id):
    response = page.goto(f"/approvals/{approval_id}")
    assert response is not None and response.ok
    expect(page.get_by_role("heading", level=2, name="device-01")).to_be_visible()
    settled(page)


def test_cf1_the_approval_reads_in_the_viewers_zone(eastern, admin_engine, world, agent, db):
    page = eastern
    held = pending(agent, world)
    sign_in_as(page, admin_engine, world["human"])
    open_detail(page, held["approval_id"])
    sentence = page.locator(".detail-sentence")
    expect(sentence).to_contain_text(EASTERN)
    expect(sentence).not_to_contain_text("UTC")
    stamp = sentence.locator("time")
    expect(stamp).to_have_attribute("title", re.compile(r" UTC$"))
    assert EASTERN.search(stamp.inner_text()), stamp.inner_text()

    activate_stop(db, world["admin"], "Contain agent 7", world["clock"])
    open_detail(page, held["approval_id"])
    notice = page.get_by_role("status").filter(has_text="Stopped at")
    expect(notice).to_contain_text(EASTERN)
    expect(notice).not_to_contain_text("UTC")
    expect(notice.locator("time")).to_have_attribute("title", re.compile(r" UTC$"))
    assert page.evaluate("window.__violations") == []


def choose_utc(page):
    page.goto("/settings")
    group = page.get_by_role("group", name="Show times in")
    expect(
        group.get_by_role("button", name=re.compile(r"^My time zone \(E[DS]T\)$"))
    ).to_have_attribute("aria-pressed", "true")
    group.get_by_role("button", name="UTC", exact=True).click()
    expect(group.get_by_role("button", name="UTC", exact=True)).to_have_attribute(
        "aria-pressed", "true"
    )


def today_requests(page) -> str:
    return page.locator(".board-today div").filter(has_text="requests").locator("dd").inner_text()


def test_cf2_a_viewer_who_chooses_utc_reads_utc_everywhere(
    eastern, admin_engine, world, agent, live_provider
):
    page = eastern
    held = pending(agent, world)
    sign_in_as(page, admin_engine, world["human"])
    choose_utc(page)

    for _ in range(2):
        open_detail(page, held["approval_id"])
        sentence = page.locator(".detail-sentence")
        expect(sentence).to_contain_text(IN_UTC)
        expect(sentence.locator("time")).to_have_attribute("title", re.compile(r" E[DS]T$"))

        page.goto("/activity")
        settled(page)
        expect(page.get_by_role("columnheader", name="Time (UTC)")).to_be_visible()

        page.goto("/")
        settled(page)
        expect(page.get_by_text(re.compile(r"left, by \d\d:\d\d UTC$")).first).to_be_visible()

        page.goto("/board")
        expect(page.get_by_text("Today (UTC)", exact=True)).to_be_visible()
        expect(page.locator(".board-counters .board-note")).to_contain_text(IN_UTC)
        # The second pass is after a reload: the choice is this browser's and survives it.
        page.reload()

    # The live board keeps updating after the choice: the stream's frames land in the entry the
    # page reads, so a new request reaches the counter and the ticker without a reload.
    expect(page.get_by_role("status").filter(has_text="Live.")).to_be_visible()
    before = int(today_requests(page))
    ticker = page.get_by_role("table").filter(has_text="Requested").locator("tbody tr")
    rows = ticker.count()
    [other] = targets(admin_engine, world, count=1)
    response = agent.post("/v1/execute", json=other.model_dump(mode="json"))
    assert response.status_code in {200, 202}, response.text
    expect(page.locator(".board-today div").filter(has_text="requests").locator("dd")).to_have_text(
        str(before + 1)
    )
    expect(ticker).to_have_count(rows + 1)
    assert page.evaluate("window.__violations") == []


def test_cf2_storage_that_refuses_leaves_local_times(
    chromium, console_gateway, admin_engine, world, agent
):
    held = pending(agent, world)
    with chromium.new_context(
        base_url=console_gateway, viewport={"width": 1280, "height": 900}, timezone_id=NEW_YORK
    ) as context:
        page = context.new_page()
        page.set_default_timeout(ACTION_TIMEOUT_MS)
        errors: list[str] = []
        page.on("pageerror", lambda error: errors.append(str(error)))
        sign_in_as(page, admin_engine, world["human"])
        page.add_init_script(NO_STORAGE)
        open_detail(page, held["approval_id"])
        expect(page.locator(".detail-sentence")).to_contain_text(EASTERN)
        page.goto("/settings")
        group = page.get_by_role("group", name="Show times in")
        group.get_by_role("button", name="UTC", exact=True).click()
        # Nothing to remember it in: the console stays in the viewer's own zone, and nothing
        # fails.
        expect(
            group.get_by_role("button", name=re.compile(r"^My time zone \(E[DS]T\)$"))
        ).to_have_attribute("aria-pressed", "true")
        open_detail(page, held["approval_id"])
        expect(page.locator(".detail-sentence")).to_contain_text(EASTERN)
        assert errors == [], errors


# Names (CF6, CF7, CF12, CF13): one name per principal on every page the design lists.


def reviewing_admin(admin_engine, world):
    """The world's administrator, assigned to the world's target: the approval pages are theirs."""
    from execbound.administration import assign_approver

    admin = world["admin"]
    assign_approver(
        admin_engine,
        admin.tenant_id,
        admin.principal_id,
        world["canonical"],
        "endpoint.isolate",
        admin.principal_id,
    )


def two_requests(agent, admin_engine, world):
    """One request held for a person and one that ran, both by the world's agent."""
    held = pending(agent, world)
    [other] = targets(admin_engine, world, 1)
    ran = agent.post("/v1/execute", json=other.model_dump(mode="json"))
    assert ran.status_code in {200, 202}, ran.text
    return held


def palette(page, term):
    # "Search or ask" where the deployment has an assistant, "Search" where it has none.
    page.get_by_role("button", name=re.compile("^Search")).click()
    page.get_by_placeholder(re.compile("^Search( or ask)?$")).fill(term)


def label(admin_engine, principal, text_value):
    from sqlalchemy import text

    with admin_engine.begin() as conn:
        conn.execute(
            text("UPDATE execbound.principals SET label=:l WHERE principal_id=:p"),
            {"l": text_value, "p": principal},
        )


def assert_named(page, held, name: str, handle: str | None) -> None:
    """Every surface CF6 lists names the world's agent `name`, with `handle` beside a label."""
    beside = name if handle is None else f"{name} {handle}"
    page.goto("/activity")
    settled(page)
    table = page.get_by_role("table").first
    # Two requests may share an instant, so the row is found by its agent, not its place.
    row = table.locator("tbody tr").filter(has_text=beside).first
    expect(row).to_be_visible()
    row.get_by_role("button", name="Isolate endpoint").click()
    expect(page.locator(".drawer-sub").first).to_contain_text(f"by {beside} at")
    page.keyboard.press("Escape")

    page.goto("/")
    settled(page)
    needs = page.locator(".needs")
    expect(needs).to_contain_text(beside)

    page.goto(f"/approvals/{held['approval_id']}")
    expect(page.get_by_role("heading", level=2, name="device-01")).to_be_visible()
    sentence = "requested by " + (name if handle is None else f"{name} ({handle})") + " at"
    expect(page.locator(".detail-sentence")).to_contain_text(sentence)
    expect(page.locator(".queue-list")).to_contain_text(name)

    page.goto("/board")
    expect(page.locator(".board-today")).to_be_visible()
    expect(page.locator("svg .lanes")).to_contain_text(name)
    ticker = page.get_by_role("table").filter(has_text="Requested")
    agents = ticker.locator("tbody tr td:first-child")
    expect(agents.filter(has_text=re.compile("^" + re.escape(beside) + "$")).first).to_be_visible()

    # Getting started's step is in the address (#678); Connect an agent lists the agents.
    page.goto("/welcome?step=connect")
    expect(page.get_by_role("link", name=name, exact=True).first).to_be_visible()

    palette(page, "agent 1")
    expect(page.get_by_role("option", name=re.compile("^" + re.escape(name)))).to_be_visible()
    page.keyboard.press("Escape")
    for text_node in ("Agent 3f", "agent " + str(held["execution_id"])[:4]):
        assert text_node not in page.locator("body").inner_text()


def test_cf6_an_unlabelled_agent_has_one_name(console_page, admin_engine, world, agent):
    page = console_page
    reviewing_admin(admin_engine, world)
    held = two_requests(agent, admin_engine, world)
    sign_in_as(page, admin_engine, world["admin"])
    assert_named(page, held, "Agent 1", None)
    page.goto(f"/agents/{world['identity'].principal_id}")
    expect(page.get_by_role("heading", level=1, name="Agent 1")).to_be_visible()
    body = page.locator("body").inner_text()
    assert str(world["identity"].principal_id)[:8] not in body.split("Principal")[0]
    assert page.evaluate("window.__violations") == []


def test_cf7_a_labelled_agent_shows_its_handle_beside_it(
    console_page, admin_engine, world, agent, db
):
    from scope_fixtures import agent as another_agent

    from execbound.execution import admit

    page = console_page
    reviewing_admin(admin_engine, world)
    label(admin_engine, world["identity"].principal_id, "triage-bot")
    # The twin asks first, so the world agent's two requests are the newest rows.
    twin = another_agent(admin_engine, db, world)
    label(admin_engine, twin.principal_id, "triage-bot")
    [elsewhere] = targets(admin_engine, world, 1)
    admit(db, twin, elsewhere, world["clock"])
    held = two_requests(agent, admin_engine, world)
    sign_in_as(page, admin_engine, world["admin"])
    assert_named(page, held, "triage-bot", "Agent 1")
    page.goto("/board")
    titles = page.locator("svg .lanes title")
    expect(titles).to_have_count(2)
    assert sorted(titles.all_text_contents()) == ["triage-bot · Agent 1", "triage-bot · Agent 2"]
    ticker = page.get_by_role("table").filter(has_text="Requested")
    cells = ticker.locator("tbody tr").locator("td:first-child").all_inner_texts()
    assert {"triage-bot Agent 1", "triage-bot Agent 2"} <= set(cells), cells


def test_cf12_the_palette_finds_a_person_by_number(console_page, admin_engine, world):
    page = console_page
    sign_in_as(page, admin_engine, world["admin"])
    page.goto("/")
    settled(page)
    palette(page, "user 2")
    option = page.get_by_role("option", name="Open User 2")
    expect(option).to_be_visible()
    option.click()
    expect(page).to_have_url(re.compile(rf"/people/{world['human'].principal_id}$"))
    expect(page.get_by_role("heading", level=1)).to_be_visible()


def test_cf13_naming_an_agent_from_its_heading(console_page, admin_engine, world):
    page = console_page
    sign_in_as(page, admin_engine, world["admin"])
    page.goto(f"/agents/{world['identity'].principal_id}")
    expect(page.get_by_role("heading", level=1, name="Agent 1")).to_be_visible()
    prompt = page.get_by_role("form", name="Name this agent")
    prompt.get_by_label("Agent name").fill("triage-bot")
    prompt.get_by_role("button", name="Save name").click()
    expect(page.get_by_role("heading", level=1, name="triage-bot")).to_be_visible()
    expect(prompt).to_have_count(0)
    # The Identity card is on Overview; a new agent opens on Connection (#678).
    page.get_by_role("navigation", name="Agent sections").get_by_role(
        "link", name="Overview"
    ).click()
    expect(page.get_by_label("Label (1 to 80 characters)")).to_have_value("triage-bot")
    assert page.evaluate("window.__violations") == []


# Fit and words (CF14).

OUTSIDE_GUTTERS = """
() => {
  const width = document.documentElement.clientWidth;
  const outside = [];
  const controls = document.querySelectorAll(
    'main button, main a[href], main input, main select, main textarea, main summary'
  );
  for (const control of controls) {
    const box = control.getBoundingClientRect();
    if (box.width < 2 || box.height < 2) continue;
    // A control inside something that pans sideways on its own (a wide table, the board) is
    // reached by panning, not by the page: it is that container's business, not the gutter's.
    let pans = false;
    for (let node = control.parentElement; node !== null; node = node.parentElement) {
      const style = getComputedStyle(node);
      if (/(auto|scroll)/.test(style.overflowX) && node.scrollWidth > node.clientWidth) {
        pans = true;
        break;
      }
    }
    if (pans) continue;
    if (box.left < 15.5 || box.right > width - 15.5) {
      outside.push(control.outerHTML.slice(0, 120));
    }
  }
  return outside;
}
"""


def fits_and_passes(page, where: str, *, phone: bool) -> None:
    settled(page)
    assert page.evaluate(AXE_RUN) == [], where
    assert page.evaluate("window.__violations") == [], where
    assert page.evaluate(
        "document.documentElement.scrollWidth <= document.documentElement.clientWidth"
    ), (where, "horizontal scroll")
    if phone:
        assert page.evaluate(OUTSIDE_GUTTERS) == [], where


def test_cf14_foundation_pages_fit_and_pass_axe(
    console_page, admin_engine, world, agent, live_provider
):
    page = console_page
    reviewing_admin(admin_engine, world)
    first = two_requests(agent, admin_engine, world)
    sign_in_as(page, admin_engine, world["admin"])
    for width, phone in ((1280, False), (390, True)):
        page.set_viewport_size({"width": width, "height": 900})
        for scheme in ("light", "dark"):
            page.emulate_media(color_scheme=scheme)
            where = f"{width} px, {scheme}"
            page.goto(f"/approvals/{first['approval_id']}")
            expect(page.get_by_role("heading", level=2, name="device-01")).to_be_visible()
            expect(page.get_by_role("button", name=re.compile(r"^Approve\b"))).to_be_visible()
            expect(page.get_by_role("button", name=re.compile(r"^Refuse\b"))).to_be_visible()
            fits_and_passes(page, f"the approval at {where}", phone=phone)

            page.goto("/activity")
            settled(page)
            page.get_by_role("table").first.get_by_role(
                "button", name="Isolate endpoint"
            ).first.click()
            expect(page.locator(".drawer-sub").first).to_be_visible()
            fits_and_passes(page, f"Activity with the drawer at {where}", phone=phone)

            page.goto("/board")
            expect(page.locator(".board-today")).to_be_visible()
            fits_and_passes(page, f"the board at {where}", phone=phone)

            page.goto("/")
            expect(page.get_by_role("heading", level=1)).to_have_text("Home")
            fits_and_passes(page, f"Home at {where}", phone=phone)

            page.goto("/settings")
            expect(page.get_by_role("group", name="Show times in")).to_be_visible()
            fits_and_passes(page, f"My account at {where}", phone=phone)
    page.emulate_media(color_scheme="light")
    page.set_viewport_size({"width": 1280, "height": 900})

    # The words: a person's refusal reads Refused, and an approval left undecided, Lapsed.
    page.goto(f"/approvals/{first['approval_id']}")
    page.get_by_role("button", name=re.compile(r"^Refuse\b")).click()
    expect(page.get_by_role("status").filter(has_text="Refused")).to_be_visible()
    page.goto("/approvals")
    page.get_by_role("button", name=re.compile("^Decided today")).click()
    expect(page.locator(".queue-list").get_by_text("Refused", exact=True)).to_be_visible()
    second = pending(agent, world, idempotency_key="cf14-lapse")
    world["clock"].value += timedelta(seconds=121)
    page.goto("/approvals")
    page.get_by_role("button", name=re.compile("^Lapsed")).click()
    lapsed = page.locator(".queue-list a").filter(has_text=second["request_ref"])
    expect(lapsed).to_contain_text("Lapsed")
    expect(page.get_by_text("Expired", exact=True)).to_have_count(0)
