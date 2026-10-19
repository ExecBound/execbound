# SPDX-License-Identifier: AGPL-3.0-only
"""Connecting monitoring sources from the console, in real Chromium (#678).

Where console connect is not configured, a deployment whose edition offers operator commands
keeps the operator steps, and one whose edition does not names who connects a provider and how
to ask, with no host step (MC18). The hosted build's half is the hosted edition's own browser
test, which reuses `walk` below.

Where the deployment gives the collector's public key, an administrator connects Tines with a
pasted key, a scheduled collection run collects it against the fake Tines API, and the
verification reaches "Reporting"; each connection's Schedule and Revoke dialogs, and the
Connect Tines form, are audited (MC17). Where it also names the platform app, an administrator
connects Microsoft Entra: the console sends the browser to Microsoft's sign-in and nowhere else,
the fake Microsoft completes both callbacks with the browser's own binding cookie, and the page
the browser returns to says what the server recorded. Every surface is checked in light and dark
at 1280 and 390 px with axe-core, no CSP violation and no sideways scroll.

Where console connect is configured, an administrator adds a reporting source, sees its token
once, and watches the waiting card flip when the story's first heartbeat arrives (MC16, MC17);
a discovered story with an open gap is reported from Inventory (MC19). Where it is not, the
console mints nothing and still revokes a source made earlier (MC22).
"""

import re
import secrets
from datetime import UTC, datetime, timedelta
from urllib.parse import urlencode

import httpx
import pytest
from playwright.sync_api import expect
from sqlalchemy import text
from test_browser_console import AXE, AXE_RUN, COLLECT, settled, sign_in_as
from test_browser_console import console_gateway as console_gateway
from test_browser_console import console_page as console_page
from test_browser_surfaces import ACTION_TIMEOUT_MS, FITS, serve
from test_browser_surfaces import chromium as chromium
from test_execution import registry as registry
from test_execution import world as world
from test_protected_path import connector as connector
from test_protected_path import live_provider as live_provider
from test_runtime import runtime as runtime
from test_tines_collection import scenario

from execbound.app import create_app
from execbound.monitoring import due, sealing
from execbound.monitoring import store as monitor_store
from execbound.surfaces import console as console_module
from execbound.surfaces.human import HumanConfig, ScoutConfig, ScoutEntra
from execbound.surfaces.tokens import TokenKeys
from execbound_harness import fake_tines
from execbound_harness.fake_entra_login import CLIENT, FakeEntraLogin
from execbound_harness.fake_tines import BASE_URL

# Words only the host steps use; none may reach a reader whose edition offers no commands.
HOST_STEPS = re.compile(
    r"DATABASE_URL|local-data|create-connection|collect-tines|collect-entra|trusted host"
)
EMPTY = "No collection connection registered"


CONNECT_READ = "/api/console/v1/monitor/connect"


def visit_read(page, url):
    """Open `url` and wait until the console has read whether this deployment connects from the
    console and drawn what it read, so a check that a control is absent cannot pass while the
    read is still in flight, before the control would appear."""
    with page.expect_response(lambda response: response.url.endswith(CONNECT_READ)) as answer:
        page.goto(url)
    assert answer.value.ok
    # The whole body has arrived before the frames that draw it are counted.
    assert answer.value.finished() is None
    page.evaluate(
        "() => new Promise((done) => requestAnimationFrame(() => requestAnimationFrame(done)))"
    )


def clean(page, what):
    settled(page)
    violations = page.evaluate(AXE_RUN)
    assert violations == [], (what, violations)
    assert page.evaluate("window.__violations") == [], what
    assert page.evaluate(FITS), (what, "horizontal scroll")


def walk(page, check) -> None:
    """Open Monitoring with no connection in each scheme at each width, check the empty state
    and the setup dialog with `check(page, where, dialog)`, and audit both."""
    for scheme in ("light", "dark"):
        for width, height in ((1280, 900), (390, 844)):
            what = f"{scheme} at {width}"
            page.emulate_media(color_scheme=scheme)
            page.set_viewport_size({"width": width, "height": height})
            page.goto("/monitor")
            empty = page.get_by_role("status").filter(has_text=EMPTY)
            expect(empty).to_be_visible()
            check(page, empty, None)
            clean(page, f"the empty state in {what}")
            page.get_by_role("button", name="Connect a source").click()
            dialog = page.get_by_role("dialog", name="Connect a source")
            expect(dialog).to_be_visible()
            check(page, empty, dialog)
            clean(page, f"the setup dialog in {what}")
            dialog.get_by_role("button", name="Close").click()
            expect(dialog).to_have_count(0)


def operator_steps(page, empty, dialog) -> None:
    if dialog is None:
        expect(empty).to_contain_text("Register a read-only collection connection")
        expect(empty).not_to_contain_text("connects monitoring providers")
        return
    expect(dialog.get_by_text("Step 1 of 4", exact=False)).to_be_visible()
    expect(dialog.get_by_role("heading", name="Customer-operated collector")).to_be_visible()
    expect(dialog).not_to_contain_text("connects this provider")


def test_mc18_with_operator_commands_the_console_keeps_the_operator_steps(
    console_page, admin_engine, world
):
    sign_in_as(console_page, admin_engine, world["admin"])
    walk(console_page, operator_steps)
    # The steps still lead to the operator's commands, unchanged.
    console_page.get_by_role("button", name="Connect a source").click()
    dialog = console_page.get_by_role("dialog", name="Connect a source")
    dialog.get_by_role("button", name="Continue").click()
    dialog.get_by_role("button", name="Continue").click()
    expect(dialog.get_by_label("Registration command")).to_contain_text("--kind tines")
    assert HOST_STEPS.search(dialog.inner_text())


# A key the page, the answers and the document must never show back.
SENTINEL = "SENTINEL-browser-tines-key-0c55"
SIZES = ((1280, 900), (390, 844))


@pytest.fixture
def collector(tmp_path):
    public = sealing.generate(tmp_path / "collector")
    return public, sealing.read_private_file(tmp_path / "collector" / sealing.PRIVATE_FILE)


@pytest.fixture
def connect_gateway(db, runtime, collector):
    """The console on a deployment that gives the collector's public key."""
    if console_module.load_build() is None:
        pytest.fail("No console build is packaged: run `pnpm build` in console/ first")
    keys = TokenKeys("browser-v1", {"browser-v1": secrets.token_bytes(32)})

    def build(origin):
        human = HumanConfig(origin, keys, scout=ScoutConfig(collector=collector[0]))
        return create_app(db, runtime=runtime, human=human)

    with serve(build) as origin:
        yield origin


@pytest.fixture
def connect_page(chromium, connect_gateway):
    with chromium.new_context(
        base_url=connect_gateway, viewport={"width": 1280, "height": 900}
    ) as context:
        page = context.new_page()
        page.set_default_timeout(ACTION_TIMEOUT_MS)
        page.add_init_script(COLLECT)
        page.add_init_script(path=str(AXE))
        yield page


def each_size(page):
    for scheme in ("light", "dark"):
        for width, height in SIZES:
            page.emulate_media(color_scheme=scheme)
            page.set_viewport_size({"width": width, "height": height})
            yield f"{scheme} at {width}", width


def connect_tines(page) -> None:
    page.goto("/monitor")
    page.get_by_role("button", name="Connect Tines").first.click()
    dialog = page.get_by_role("dialog", name="Connect Tines")
    expect(dialog).to_be_visible()
    dialog.get_by_role("button", name="Continue").click()
    dialog.get_by_label("Connection name").fill("Lab Tines")
    dialog.get_by_label("Tines tenant URL").fill(BASE_URL)
    dialog.get_by_label("API key").fill(SENTINEL)
    dialog.get_by_role("button", name="Connect").click()
    # Success opens verification for the new connection, and the form is gone.
    verify = page.get_by_role("dialog", name="Connect a source")
    expect(verify).to_be_visible()
    expect(dialog).to_have_count(0)
    assert SENTINEL not in page.content()


def test_mc17_connect_tines_collect_and_verify_reporting(
    connect_page, admin_engine, world, db, collector
):
    page = connect_page
    sign_in_as(page, admin_engine, world["admin"])
    # The form itself, unsent, in each scheme and width.
    for what, _ in each_size(page):
        page.goto("/monitor")
        page.get_by_role("button", name="Connect Tines").first.click()
        dialog = page.get_by_role("dialog", name="Connect Tines")
        expect(dialog).to_contain_text("Monitoring is visibility.")
        clean(page, f"Connect Tines, what it reads, in {what}")
        dialog.get_by_role("button", name="Continue").click()
        expect(dialog.get_by_label("API key")).to_have_attribute("type", "password")
        clean(page, f"the Connect Tines form in {what}")
        dialog.get_by_role("button", name="Close").click()
        expect(dialog).to_have_count(0)
    page.emulate_media(color_scheme="light")
    page.set_viewport_size({"width": 1280, "height": 900})
    connect_tines(page)
    verify = page.get_by_role("dialog", name="Connect a source")
    # The scheduled collector's pass, in this process, against the fake Tines API.
    with fake_tines.serving(scenario(datetime.now(UTC))) as server:
        with httpx.Client(transport=fake_tines.transport(server), trust_env=False) as client:
            report = due.collect_due(db, key_files=None, collector=collector[1], client=client)
        assert {headers.get("X-User-Token") for _, _, headers in server.requests} == {SENTINEL}
    assert sum(outcome.get("collected", 0) for outcome in report["tenants"].values()) == 1
    verify.get_by_role("button", name="Check connection").click()
    expect(verify.get_by_role("heading", name="Reporting — first sync verified")).to_be_visible()
    clean(page, "verification reporting")
    verify.get_by_role("button", name="Done").click()
    # Each card names its credential, and its actions wrap rather than widen the page.
    card = page.locator(".card").filter(has_text="Lab Tines")
    expect(card.get_by_text("Key sealed for the collector")).to_be_visible()
    for what, width in each_size(page):
        page.goto("/monitor")
        actions = page.get_by_role("group", name="Actions for Lab Tines")
        expect(actions).to_be_visible()
        clean(page, f"the connection card in {what}")
        if width == 390:
            tops = actions.get_by_role("button").evaluate_all(
                "(buttons) => buttons.map("
                "(button) => Math.round(button.getBoundingClientRect().top))"
            )
            assert len(set(tops)) > 1, (what, "the actions sit on one line at 390 px")
        actions.get_by_role("button", name="Schedule").click()
        schedule = page.get_by_role("dialog", name="Schedule collection")
        expect(schedule).to_be_visible()
        clean(page, f"the Schedule dialog in {what}")
        schedule.get_by_role("button", name="Cancel").click()
        expect(schedule).to_have_count(0)
        actions.get_by_role("button", name="Revoke").click()
        revoke = page.get_by_role("dialog", name="Revoke this connection?")
        expect(revoke).to_be_visible()
        clean(page, f"the Revoke dialog in {what}")
        revoke.get_by_role("button", name="Cancel").click()
        expect(revoke).to_have_count(0)
    # A schedule saved, then the connection revoked, each from the server's answer.
    actions = page.get_by_role("group", name="Actions for Lab Tines")
    actions.get_by_role("button", name="Schedule").click()
    schedule = page.get_by_role("dialog", name="Schedule collection")
    schedule.get_by_label("Read audit records every").select_option(label="30 minutes")
    schedule.get_by_role("button", name="Save schedule").click()
    expect(schedule).to_have_count(0)
    expect(card).to_contain_text("Audit records every 30 minutes, inventory daily")
    actions.get_by_role("button", name="Revoke").click()
    revoke = page.get_by_role("dialog", name="Revoke this connection?")
    revoke.get_by_role("button", name="Revoke connection").click()
    expect(revoke).to_have_count(0)
    expect(card.get_by_text("Revoked")).to_be_visible()
    with admin_engine.connect() as conn:
        assert (
            conn.execute(
                text(
                    "SELECT active FROM execbound.monitor_connections WHERE tenant_id = :t "
                    "AND label = 'Lab Tines'"
                ),
                {"t": world["admin"].tenant_id},
            ).scalar_one()
            is False
        )
    assert SENTINEL not in page.content()


LOGIN = "https://login.microsoftonline.com"
SCOUT = "Synthetic Scout"
# On a plain loopback origin the binding cookie has no `__Host-` prefix (`HumanConfig.cookie`);
# it is still Secure, which Chromium sets for a loopback address.
BINDING = "eb_connect"


@pytest.fixture
def login():
    return FakeEntraLogin()


@pytest.fixture
def entra_gateway(db, runtime, collector, login):
    """The console on a deployment that names the platform app."""
    if console_module.load_build() is None:
        pytest.fail("No console build is packaged: run `pnpm build` in console/ first")
    keys = TokenKeys("browser-v1", {"browser-v1": secrets.token_bytes(32)})

    def build(origin):
        scout = ScoutConfig(
            collector=collector[0],
            entra=ScoutEntra(CLIENT, "organizations", SCOUT, http=login.client()),
        )
        return create_app(db, runtime=runtime, human=HumanConfig(origin, keys, scout=scout))

    with serve(build) as origin:
        yield origin


@pytest.fixture
def entra_page(chromium, entra_gateway):
    with chromium.new_context(
        base_url=entra_gateway, viewport={"width": 1280, "height": 900}
    ) as context:
        page = context.new_page()
        page.set_default_timeout(ACTION_TIMEOUT_MS)
        page.add_init_script(COLLECT)
        page.add_init_script(path=str(AXE))
        yield page


def test_mc17_connect_microsoft_entra_to_microsofts_sign_in_and_back(
    entra_page, entra_gateway, admin_engine, world, login
):
    page = entra_page
    sign_in_as(page, admin_engine, world["admin"])
    # Microsoft's sign-in is never reached: the navigation the console starts is caught here.
    left = []

    def microsoft(route):
        left.append(route.request.url)
        route.fulfill(
            status=200, content_type="text/html", body="<!doctype html><title>Sign in</title>"
        )

    page.route(f"{LOGIN}/**", microsoft)
    # The dialog, unsent, in each scheme and width.
    for what, _ in each_size(page):
        page.goto("/monitor")
        page.get_by_role("button", name="Connect Microsoft Entra").first.click()
        dialog = page.get_by_role("dialog", name="Connect Microsoft Entra")
        expect(dialog).to_contain_text("Nothing is created until you approve.")
        expect(dialog).to_contain_text(f"remove the {SCOUT} enterprise application")
        clean(page, f"Connect Microsoft Entra in {what}")
        dialog.get_by_role("button", name="Close").click()
        expect(dialog).to_have_count(0)
    page.emulate_media(color_scheme="light")
    page.set_viewport_size({"width": 1280, "height": 900})
    page.goto("/monitor")
    page.get_by_role("button", name="Connect Microsoft Entra").first.click()
    dialog = page.get_by_role("dialog", name="Connect Microsoft Entra")
    dialog.get_by_label("Connection name").fill("Lab directory")
    dialog.get_by_role("button", name="Continue to Microsoft").click()
    page.wait_for_url(re.compile(r"^https://login\.microsoftonline\.com/organizations/"))
    [address] = left
    # The browser holds the binding the callbacks require, unreadable to a script.
    [binding] = [cookie for cookie in page.context.cookies() if cookie["name"] == BINDING]
    assert (binding["httpOnly"], binding["secure"], binding["sameSite"]) == (True, True, "None")
    # Microsoft's two callbacks, carrying that browser's own binding cookie.
    _, fields = login.authorize(address)
    with httpx.Client(
        base_url=entra_gateway,
        follow_redirects=False,
        cookies={BINDING: binding["value"]},
    ) as client:
        signed = client.post(
            "/connect/entra/signed-in",
            content=urlencode(fields).encode(),
            headers={"Origin": LOGIN, "Content-Type": "application/x-www-form-urlencoded"},
        )
        assert signed.status_code == 303, signed.text
        _, pairs = login.consent(signed.headers["location"])
        landed = client.get("/connect/entra/consented?" + urlencode(pairs))
        assert "connect=done" in landed.text
    # The return reads the server's record of the attempt, opens verification for the new
    # connection, and takes the return out of the address.
    page.goto("/monitor?view=connections&connect=done")
    expect(
        page.get_by_text(
            "Microsoft Entra is connected. The first collection runs within five minutes."
        )
    ).to_be_visible()
    verify = page.get_by_role("dialog", name="Connect a source")
    expect(verify).to_be_visible()
    expect(page).not_to_have_url(re.compile(r"connect="))
    clean(page, "the return from Microsoft, verifying the new connection")
    verify.get_by_role("button", name="Close").click()
    expect(verify).to_have_count(0)
    # The consented connection's card and its Revoke dialog, in each scheme and width.
    for what, _ in each_size(page):
        page.goto("/monitor")
        card = page.locator(".card").filter(has_text="Lab directory")
        expect(card.get_by_text("Admin consent")).to_be_visible()
        clean(page, f"the consented connection's card in {what}")
        card.get_by_role("group", name="Actions for Lab directory").get_by_role(
            "button", name="Revoke"
        ).click()
        revoke = page.get_by_role("dialog", name="Revoke this connection?")
        expect(revoke).to_contain_text(
            f"remove the {SCOUT} enterprise application (client ID {CLIENT})"
        )
        clean(page, f"the Entra Revoke dialog in {what}")
        revoke.get_by_role("button", name="Cancel").click()
        expect(revoke).to_have_count(0)
    with admin_engine.connect() as conn:
        assert (
            conn.execute(
                text(
                    "SELECT credential_mode FROM execbound.monitor_connections "
                    "WHERE tenant_id = :t AND label = 'Lab directory'"
                ),
                {"t": world["admin"].tenant_id},
            ).scalar_one()
            == "platform_app"
        )
    state = dict(re.findall(r"[?&](state)=([^&]+)", address))["state"]
    assert state not in page.content()


# A discovered story with an open coverage gap, as the last reconciliation leaves one.
GAP_STORY = "4002"


def gap_story(db, admin_engine, world) -> None:
    connection = monitor_store.create_connection(
        db,
        world["admin"],
        label="Operator's Tines",
        base_url=BASE_URL,
        key_fingerprint="ab" * 32,
        clock=world["clock"],
    )
    now = datetime.now(UTC)
    with admin_engine.begin() as conn:
        conn.execute(
            text(
                "INSERT INTO execbound.monitor_inventory (tenant_id, connection_id, item_kind, "
                "external_id, name, first_seen_at, last_seen_at, gap_opened_at, coverage_class) "
                "VALUES (:t, :c, 'story', :e, 'Unreported story', :now, :now, :now, "
                "'discovered_only')"
            ),
            {"t": world["admin"].tenant_id, "c": connection, "e": GAP_STORY, "now": now},
        )


def light(page) -> None:
    page.emulate_media(color_scheme="light")
    page.set_viewport_size({"width": 1280, "height": 900})


def test_mc16_mc17_add_a_reporting_source_and_see_its_first_heartbeat(
    connect_page, connect_gateway, admin_engine, world
):
    page = connect_page
    sign_in_as(page, admin_engine, world["admin"])
    # The form, unsent, in each scheme and width.
    for what, _ in each_size(page):
        page.goto("/monitor")
        page.get_by_role("button", name="Add a reporting source").click()
        dialog = page.get_by_role("dialog", name="Add a reporting source")
        expect(dialog).to_contain_text("This token authorizes intake only.")
        clean(page, f"Add a reporting source in {what}")
        dialog.get_by_role("button", name="Cancel").click()
        expect(dialog).to_have_count(0)
    light(page)
    page.goto("/monitor")
    page.get_by_role("button", name="Add a reporting source").click()
    dialog = page.get_by_role("dialog", name="Add a reporting source")
    dialog.get_by_label("Tines story ID").fill("4001")
    dialog.get_by_role("button", name="Create source").click()
    shown = page.get_by_role("dialog", name="Copy the source token now")
    field = shown.get_by_label("Source token (copy it now)")
    token = field.input_value()
    assert token.startswith(f"mo1.{world['admin'].tenant_id}.")
    # The token dialog in each scheme and width: the field scrolls inside itself at 390 px.
    for what, width in each_size(page):
        expect(shown).to_be_visible()
        clean(page, f"the source token dialog in {what}")
        if width == 390:
            assert field.evaluate("(input) => input.scrollWidth > input.clientWidth"), what
    light(page)
    shown.get_by_role("button", name="I have copied it").click()
    expect(shown).to_have_count(0)
    waiting = page.get_by_text("Waiting for the first heartbeat from story 4001…")
    expect(waiting).to_be_visible()
    assert token not in page.content()
    card = page.locator(".card").filter(has_text="Story 4001")
    for what, _ in each_size(page):
        expect(waiting).to_be_visible()
        clean(page, f"the waiting card in {what}")
        actions = card.get_by_role("group", name="Actions for Story 4001")
        actions.get_by_role("button", name="Rotate token").click()
        rotate = page.get_by_role("dialog", name="Rotate the source token")
        expect(rotate).to_be_visible()
        clean(page, f"the Rotate dialog in {what}")
        rotate.get_by_role("button", name="Cancel").click()
        expect(rotate).to_have_count(0)
        actions.get_by_role("button", name="Revoke").click()
        revoke = page.get_by_role("dialog", name="Revoke this source?")
        expect(revoke).to_be_visible()
        clean(page, f"the source Revoke dialog in {what}")
        revoke.get_by_role("button", name="Cancel").click()
        expect(revoke).to_have_count(0)
    light(page)
    # The story's first heartbeat, sent with the token as a Tines story sends it.
    sent = httpx.post(
        connect_gateway + "/v1/monitor/events",
        json={
            "version": 1,
            "event_id": "heartbeat-1",
            "story_id": "4001",
            "occurred_at": datetime.now(UTC).isoformat(),
            "kind": "heartbeat",
        },
        headers={"Authorization": "Bearer " + token},
        timeout=10,
    )
    assert sent.status_code == 202, sent.text
    reporting = card.get_by_text("Reporting. First heartbeat at", exact=False)
    expect(reporting).to_be_visible(timeout=30_000)
    expect(card.get_by_role("link", name="See its Activity")).to_have_attribute(
        "href", "/monitor?view=activity"
    )
    clean(page, "the waiting card once the story reports")
    assert token not in page.content()


def test_mc19_report_a_story_with_an_open_gap_from_inventory(connect_page, admin_engine, world, db):
    page = connect_page
    gap_story(db, admin_engine, world)
    sign_in_as(page, admin_engine, world["admin"])
    for what, _ in each_size(page):
        page.goto("/monitor?view=inventory")
        row = page.get_by_role("row").filter(has_text="Unreported story")
        expect(row.get_by_role("button", name="Report this story", exact=True)).to_be_visible()
        expect(row).to_contain_text("Reporting does not govern or block it.")
        clean(page, f"Inventory with a reportable story in {what}")
    light(page)
    row = page.get_by_role("row").filter(has_text="Unreported story")
    row.get_by_role("button", name="Report this story", exact=True).click()
    dialog = page.get_by_role("dialog", name="Add a reporting source")
    expect(dialog.get_by_label("Tines story ID")).to_have_value(GAP_STORY)
    clean(page, "Add a reporting source for a story")
    # Once minted, the row names the new source beside a gap only the next inventory pass
    # closes, and never tells the administrator to rotate or revoke it: none of the words an
    # expired source's row carries.
    dialog.get_by_role("button", name="Create source").click()
    shown = page.get_by_role("dialog", name="Copy the source token now")
    shown.get_by_role("button", name="I have copied it").click()
    expect(shown).to_have_count(0)
    expect(row).to_contain_text(
        "This source can report. The gap stays open until the next inventory pass reassesses "
        "the story."
    )
    expect(row).not_to_contain_text(
        re.compile("does not report|rotate|revoke|expired", re.IGNORECASE)
    )
    clean(page, "Inventory just after reporting a story")


def test_mc22_without_console_connect_nothing_is_minted_and_a_source_is_still_revoked(
    console_page, admin_engine, world, db
):
    page = console_page
    gap_story(db, admin_engine, world)
    monitor_store.create_source(
        db,
        world["admin"],
        label="Command line story",
        story_id="story-cli",
        expires_at=world["clock"].now() + timedelta(hours=2),
        clock=world["clock"],
    )
    sign_in_as(page, admin_engine, world["admin"])
    visit_read(page, "/monitor")
    expect(page.get_by_role("button", name="Connect a source")).to_be_visible()
    actions = page.get_by_role("group", name="Actions for Command line story")
    expect(actions.get_by_role("button", name="Revoke")).to_be_visible()
    expect(page.get_by_role("button", name="Add a reporting source")).to_have_count(0)
    expect(actions.get_by_role("button", name="Rotate token")).to_have_count(0)
    clean(page, "Connections where console connect is not configured")
    visit_read(page, "/monitor?view=inventory")
    row = page.get_by_role("row").filter(has_text="Unreported story")
    expect(row.get_by_role("button", name="Show the command to report this story")).to_be_visible()
    expect(row.get_by_role("button", name="Report this story", exact=True)).to_have_count(0)
    page.goto("/monitor")
    actions.get_by_role("button", name="Revoke").click()
    revoke = page.get_by_role("dialog", name="Revoke this source?")
    revoke.get_by_role("button", name="Revoke source").click()
    expect(revoke).to_have_count(0)
    with admin_engine.connect() as conn:
        assert (
            conn.execute(
                text(
                    "SELECT revoked_by FROM execbound.monitor_sources WHERE tenant_id = :t "
                    "AND story_id = 'story-cli'"
                ),
                {"t": world["admin"].tenant_id},
            ).scalar_one()
            == world["admin"].principal_id
        )
