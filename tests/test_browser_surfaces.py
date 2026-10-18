# SPDX-License-Identifier: AGPL-3.0-only
"""Real Chromium, PostgreSQL, and a separate authenticated provider process.

The console (#333) is the surface a person opens, so these are the console's routes now: the
approval the notification links to, the activity a record lands in, the drawer a record opens
into. The pages that stay server-rendered — sign-in, the classic approval page, the public
showcase — have their own files. What is asserted is unchanged: exactly one provider effect for
one approval, a denial that leaves the provider alone, a retained cookie that no longer opens
anything, and every string an agent or a platform sent rendered as text with no element built
from it.
"""

import asyncio
import re
import secrets
import socket
import threading
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from pathlib import Path
from types import SimpleNamespace

import httpx
import httpx2
import pytest
import uvicorn
from arcade_fixtures import (
    CORRECTIONS,
    correlation_rows,
    governed_bundle,
    governed_target,
    hook_block,
    post,
    pre,
    signed,
)
from arcade_fixtures import arcade_world as arcade_world
from browser_network import launched
from browser_recovery import watched
from checkpoint_fixtures import CONTAIN, gate_runtime, retained
from checkpoint_fixtures import gate_world as gate_world
from context_fixtures import CATALOG
from mcp import Client
from mcp.client.streamable_http import streamable_http_client
from playwright.sync_api import expect, sync_playwright
from scope_fixtures import group, scoped_bundle
from scope_fixtures import owner as owner
from sqlalchemy import text
from test_human_surface import (
    APPROVE_RISKY,
    HOSTILE_CONTEXT,
    HOSTILE_TOOL,
    MARKED_FIELDS,
    credential,
    markup,
    scoped_rules,
)
from test_runtime import connector as connector
from test_runtime import live_provider as live_provider
from test_runtime import registry as registry
from test_runtime import request
from test_runtime import runtime as runtime
from test_runtime import world as world

from execbound.app import create_app
from execbound.execution.models import PreconditionConfig
from execbound.runtime import Runtime
from execbound.surfaces import console as console_module
from execbound.surfaces.human import CONTROL_POINT_CARRIED, EXTERNALLY_EXECUTED, HumanConfig
from execbound.surfaces.tokens import TokenKeys


def self_signed(directory: Path) -> tuple[str, str]:
    """A throwaway certificate for `localhost`, valid for one day, and its key, as files."""
    from datetime import UTC, datetime, timedelta

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID

    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])
    now = datetime.now(UTC)
    certificate = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=5))
        .not_valid_after(now + timedelta(days=1))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName("localhost")]), critical=False)
        .sign(key, hashes.SHA256())
    )
    certfile, keyfile = directory / "localhost.pem", directory / "localhost.key"
    certfile.write_bytes(certificate.public_bytes(serialization.Encoding.PEM))
    keyfile.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    return str(certfile), str(keyfile)


@contextmanager
def serve(build, *, date_header=True, tls=None):
    """Reserve the socket before startup; stop the actual ASGI server on teardown.

    ``build`` is handed the origin, because the human surface is bound to one and the port
    is only known once the socket is reserved. ``tls`` serves `https://localhost` with a
    supplied certificate/key file pair, for a test that needs a secure context with a name as
    its WebAuthn relying party (Chromium refuses an IP address as one). The caller can pin
    that certificate in its test browser. Every other test keeps the cleartext loopback default.
    """
    ready = threading.Event()

    class ReadyServer(uvicorn.Server):
        async def startup(self, sockets=None):
            await super().startup(sockets=sockets)
            ready.set()

    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        port = sock.getsockname()[1]
        origin = f"https://localhost:{port}" if tls else f"http://127.0.0.1:{port}"
        certificate = tls if tls else (None, None)
        # Browser contexts are closed before this fixture exits, but a disconnected
        # polling request can remain in Uvicorn's graceful drain on Windows. Bound that
        # cleanup after the test's assertions; never abandon a live server thread.
        server = ReadyServer(
            uvicorn.Config(
                build(origin),
                log_level="critical",
                access_log=False,
                timeout_graceful_shutdown=3,
                date_header=date_header,
                ssl_certfile=certificate[0],
                ssl_keyfile=certificate[1],
            )
        )
        thread = threading.Thread(target=server.run, kwargs={"sockets": [sock]}, daemon=True)
        thread.start()
        try:
            assert ready.wait(10) and server.started, "Browser gateway did not become ready"
            yield origin
        finally:
            server.should_exit = True
            thread.join(timeout=10)
            assert not thread.is_alive(), "Browser gateway did not stop"


def human_app(db, runtime, origin):
    return create_app(
        db,
        runtime=runtime,
        human=HumanConfig(origin, TokenKeys("browser-v1", {"browser-v1": secrets.token_bytes(32)})),
    )


@pytest.fixture
def browser_gateway(db, runtime):
    if console_module.load_build() is None:
        pytest.fail("No console build is packaged: run `pnpm build` in console/ first")
    with serve(lambda origin: human_app(db, runtime, origin)) as origin:
        yield origin


# How long an `expect` assertion holds still for something to arrive. Playwright's default
# is five seconds, which is a wait rather than a budget: a cold route's chunk has to be
# fetched, parsed and rendered before the page says anything but "Loading", and a CI
# machine may be running other work beside it. A first visit has missed five seconds twice
# on trees that changed no product code, on the policy page in
# #431 and on
# #395, each with the aria snapshot
# showing only `main: status Loading`. Fifteen is a harness allowance for a loaded machine
# and is not a claim about how fast the console is: every deliberate budget carries its own
# number and measures it itself, the cold approval link's 2.5 seconds on a throttled phone
# by its own clock in `tests/test_browser_approval_speed.py`, the live board's by frames and
# heap in `tests/test_browser_console_soak.py` and Home's by polls and heap in
# `tests/soak_console_home.py`, and none of them reads this.
EXPECT_TIMEOUT_MS = 15_000
# The same number for an action that waits, because a click that waits for a navigation is
# the same cold-route case: `test_a_configured_provider_signs_a_matched_person_in` has timed
# out at Playwright's five-second action default on a heavily loaded machine. Every page
# fixture in the browser suite takes this; the cold approval link keeps its own longer
# number, deliberately, so a slow load is a figure it reports rather than a timeout that
# says only that something took too long.
ACTION_TIMEOUT_MS = EXPECT_TIMEOUT_MS


@pytest.fixture(scope="module")
def chromium():
    # The browser hears of no change to the host's network (`tests/browser_network.py`), so a
    # container another job starts or stops cannot fail its requests with
    # `net::ERR_NETWORK_CHANGED`. Every context is also watched
    # (`tests/browser_recovery.py`): failed requests are printed by method, path and error, and
    # a connection that breaks under a navigation or the console's entry module costs one retry
    # or one reload, each printed and warned. Nothing is saved.
    expect.set_options(timeout=EXPECT_TIMEOUT_MS)
    with sync_playwright() as playwright, launched(playwright.chromium) as browser:
        yield watched(browser)


@pytest.fixture
def human_page(chromium, browser_gateway):
    # Authentication remains in this fresh context's memory. No trace, HAR,
    # video, storage-state file, or screenshot of the credential form is saved.
    with chromium.new_context(
        base_url=browser_gateway, viewport={"width": 1440, "height": 1000}
    ) as context:
        page = context.new_page()
        page.set_default_timeout(ACTION_TIMEOUT_MS)
        yield page


@pytest.fixture
def agent_http(browser_gateway, seeded):
    with httpx.Client(
        base_url=browser_gateway,
        headers={"Authorization": "Bearer " + seeded["tokens"][0]},
        trust_env=False,
    ) as client:
        yield client


def sign_in(page, admin_engine, world):
    page.goto("/login?setup=1")
    page.get_by_label("Setup credential").fill(credential(admin_engine, world["human"]))
    page.get_by_role("button", name="Continue setup").click()
    expect(page).to_have_url(re.compile(r"/approvals$"))
    expect(page.get_by_role("heading", level=1)).to_have_text("Approvals")


def open_approval(page, approval_id):
    """One approval, at the address a notification links: the queue beside the detail."""
    page.goto(f"/approvals/{approval_id}")
    expect(page.get_by_role("heading", level=1)).to_have_text("Approvals")
    expect(page.get_by_role("button", name=re.compile(r"^Approve\b"))).to_be_visible()


def open_activity(page):
    """Activity, reached the way a person reaches it: the sidebar, or the phone's tab bar."""
    bar = page.get_by_role("navigation", name="Main")
    if not bar.is_visible():
        bar = page.get_by_role("navigation", name="Main, phone")
    bar.get_by_role("link", name="Activity").click()
    expect(page.get_by_role("heading", level=1)).to_have_text("Activity")


def open_record(page, action="Isolate endpoint"):
    """The record drawer, opened from the row whose action this is."""
    table = page.get_by_role("table", name=re.compile("Activity"))
    table.get_by_role("button", name=action).first.click()
    drawer = page.get_by_role("dialog", name=re.compile(action))
    expect(drawer).to_be_visible()
    return drawer


def pending(agent_http, world):
    response = agent_http.post("/v1/execute", json=request(world).model_dump(mode="json"))
    assert response.status_code == 202
    result = response.json()
    assert result["state"] == "PENDING_APPROVAL"
    return result


def assert_responsive(page, controls, *, scroll=True):
    """Every control is visible, reachable and enabled, and the page never scrolls sideways.

    `scroll` is False where the console re-renders as the viewport crosses its phone
    breakpoint: an element handle taken before the layout changed is detached by the time it
    would be scrolled to, and the controls that matter there are pinned anyway. Every
    assertion re-resolves its locator, so nothing else holds a handle across a layout.
    """
    # wait_for_function evaluates its predicate inside the page and can hit
    # strict CSP. Read settled layout directly without relaxing that policy.
    page.wait_for_load_state("load")
    assert page.evaluate(
        "() => document.documentElement.scrollWidth <= document.documentElement.clientWidth"
    )
    for control in controls:
        expect(control).to_be_visible()
        if scroll:
            control.scroll_into_view_if_needed()
        expect(control).to_be_in_viewport(ratio=0.95)
        expect(control).to_be_enabled()


def capture_reviews(page, name, controls, destination: Path):
    destination.mkdir(parents=True, exist_ok=True)
    for label, viewport in (
        ("desktop", {"width": 1440, "height": 1000}),
        ("mobile", {"width": 390, "height": 844}),
    ):
        page.set_viewport_size(viewport)
        assert_responsive(page, controls, scroll=False)
        page.evaluate("window.scrollTo(0, 0)")
        page.screenshot(path=str(destination / f"{name}-{label}.png"), full_page=True)


def test_browser_approval_http_mcp_single_effect_and_activity(
    human_page, browser_gateway, agent_http, admin_engine, world, live_provider, seeded, tmp_path
):
    page = human_page
    first = pending(agent_http, world)
    sign_in(page, admin_engine, world)
    open_approval(page, first["approval_id"])
    expect(page.get_by_role("heading", level=2, name="device-01")).to_be_visible()
    expect(page.get_by_role("rowheader", name="incident severity", exact=True)).to_be_visible()
    expect(page.get_by_role("cell", name="CRITICAL", exact=True)).to_be_visible()
    expect(page.get_by_text("policy0").first).to_be_visible()
    approve = page.get_by_role("button", name=re.compile(r"^Approve\b"))
    deny = page.get_by_role("button", name=re.compile(r"^Refuse\b"))
    capture_reviews(page, "approvals", [approve, deny], tmp_path / "ui-review")
    approve.click()
    # Scoped to the queue: the detail pane beside it renders the same sentence when
    # nothing is selected, so an unscoped match is two elements whenever both panes have
    # settled, which is what a loaded machine makes happen every time.
    expect(page.get_by_label("Queue").get_by_text("Nothing is waiting for you.")).to_be_visible()

    executed = agent_http.post("/v1/execute", json=request(world).model_dump(mode="json"))
    assert executed.status_code == 200
    assert executed.json()["state"] == "EXECUTED"
    assert executed.json()["execution_id"] == first["execution_id"]

    async def mcp_retry():
        async with httpx2.AsyncClient(
            headers={"Authorization": "Bearer " + seeded["tokens"][0]}, trust_env=False
        ) as http:
            async with Client(
                streamable_http_client(browser_gateway + "/mcp/", http_client=http)
            ) as client:
                result = await client.call_tool(
                    "execute", {"request": request(world).model_dump(mode="json")}
                )
                assert not result.is_error
                assert result.structured_content["state"] == "EXECUTED"
                assert result.structured_content["execution_id"] == first["execution_id"]

    # The SDK's event loop is independent of Playwright's synchronous driver.
    with ThreadPoolExecutor(max_workers=1) as pool:
        pool.submit(lambda: asyncio.run(mcp_retry())).result(timeout=15)
    assert (
        live_provider.store.resource(world["identity"].tenant_id, world["canonical"]).mutation_count
        == 1
    )
    open_activity(page)
    expect(page.get_by_text("Executed", exact=True).first).to_be_visible()
    expect(page.get_by_text("device-01", exact=True).first).to_be_visible()
    capture_reviews(
        page, "activity", [page.get_by_role("link", name="Activity").first], tmp_path / "ui-review"
    )


def test_browser_denial_keeps_provider_unchanged(
    human_page, agent_http, admin_engine, world, live_provider
):
    page = human_page
    page.set_viewport_size({"width": 390, "height": 844})
    first = pending(agent_http, world)
    sign_in(page, admin_engine, world)
    open_approval(page, first["approval_id"])
    deny = page.get_by_role("button", name=re.compile(r"^Refuse\b"))
    assert_responsive(page, [deny], scroll=False)
    deny.click()
    # Scoped to the queue: the detail pane beside it renders the same sentence when
    # nothing is selected, so an unscoped match is two elements whenever both panes have
    # settled, which is what a loaded machine makes happen every time.
    expect(page.get_by_label("Queue").get_by_text("Nothing is waiting for you.")).to_be_visible()
    result = agent_http.post("/v1/execute", json=request(world).model_dump(mode="json"))
    assert result.json()["state"] == "DENIED"
    assert result.json()["execution_id"] == first["execution_id"]
    open_activity(page)
    expect(page.get_by_text("Denied", exact=True).first).to_be_visible()
    assert (
        live_provider.store.resource(world["identity"].tenant_id, world["canonical"]).mutation_count
        == 0
    )
    assert not Path(live_provider.environment["TEST_PROVIDER_INVOCATIONS"]).exists()


def test_browser_logout_rejects_retained_session_cookies(
    human_page, admin_engine, world, browser_gateway
):
    page = human_page
    sign_in(page, admin_engine, world)
    retained = page.context.cookies()
    assert {cookie["name"] for cookie in retained} == {"eb_session", "eb_csrf"}
    assert all(cookie["httpOnly"] and cookie["sameSite"] == "Strict" for cookie in retained)
    # Sign out is a form the browser submits, not a call the application makes: the session
    # cookie is the gateway's and ending it is a navigation.
    page.get_by_role("button", name="Sign out").click()
    expect(page).to_have_url(browser_gateway + "/login")
    expect(page.get_by_label("Password", exact=True)).to_be_empty()
    page.context.add_cookies(retained)
    page.goto("/activity")
    # Sign-in, carrying the page to return to (#678).
    expect(page).to_have_url(re.compile(r"/login\?review=%2Factivity$"))
    expect(page.get_by_label("Password", exact=True)).to_be_visible()


def test_browser_provider_markup_is_literal_inert_text(
    human_page, agent_http, admin_engine, world, live_provider
):
    page = human_page
    injected = (
        '<img src=x onerror="document.body.dataset.injected=1">'
        '<svg onload="document.body.dataset.injected=1"></svg>'
    )
    with admin_engine.begin() as conn:
        conn.execute(
            text(
                "UPDATE execbound.resources SET provider_id=:v "
                "WHERE tenant_id=:t AND resource_id=:r"
            ),
            {"v": injected, "t": world["identity"].tenant_id, "r": world["target"]},
        )
    first = pending(agent_http, world)
    sign_in(page, admin_engine, world)
    open_approval(page, first["approval_id"])
    for viewport in ({"width": 1440, "height": 1000}, {"width": 390, "height": 844}):
        page.set_viewport_size(viewport)
        # The provider's own string is the heading, as characters; the console draws its
        # own icons as SVG, so what must be absent is an element built from that string.
        expect(page.get_by_role("heading", level=2, name=injected)).to_be_visible()
        expect(page.locator("main img, main script, main [onerror], main [onload]")).to_have_count(
            0
        )
        assert page.locator("body").get_attribute("data-injected") is None
        assert_responsive(
            page, [page.get_by_role("button", name=re.compile(r"^Approve\b"))], scroll=False
        )
    page.set_viewport_size({"width": 1440, "height": 1000})
    open_activity(page)
    expect(page.get_by_text(injected, exact=True).first).to_be_visible()
    expect(page.locator("main img, main script, main [onerror], main [onload]")).to_have_count(0)
    assert (
        live_provider.store.resource(world["identity"].tenant_id, world["canonical"]).mutation_count
        == 0
    )


def test_browser_activity_renders_autonomous_execution_without_approval(
    human_page, agent_http, admin_engine, world, live_provider
):
    page = human_page
    with admin_engine.begin() as conn:
        conn.execute(
            text("UPDATE execbound.resources SET environment='development' WHERE resource_id=:r"),
            {"r": world["target"]},
        )
    executed = agent_http.post("/v1/execute", json=request(world).model_dump(mode="json"))
    assert executed.status_code == 200 and executed.json()["state"] == "EXECUTED"
    assert executed.json()["approval_id"] is None
    sign_in(page, admin_engine, world)
    # Scoped to the queue: the detail pane beside it renders the same sentence when
    # nothing is selected, so an unscoped match is two elements whenever both panes have
    # settled, which is what a loaded machine makes happen every time.
    expect(page.get_by_label("Queue").get_by_text("Nothing is waiting for you.")).to_be_visible()
    open_activity(page)
    expect(page.get_by_text("device-01", exact=True).first).to_be_visible()
    expect(page.get_by_text("Executed", exact=True).first).to_be_visible()
    drawer = open_record(page)
    expect(drawer).to_contain_text("Facts used")
    # No approval was needed, so the record has no approval section at all.
    expect(drawer.get_by_role("heading", name="Approval")).to_have_count(0)
    expect(drawer.get_by_role("heading", name="A person decides")).to_have_count(0)
    assert (
        live_provider.store.resource(world["identity"].tenant_id, world["canonical"]).mutation_count
        == 1
    )


def test_sl11_record_page_labels_every_scope_as_inert_text(
    human_page, agent_http, admin_engine, world, db, owner, live_provider
):
    page = human_page
    triage = group(owner, world, world["identity"], name="triage")
    scoped_bundle(db, world, *scoped_rules(triage, world["account"]))
    pending(agent_http, world)
    sign_in(page, admin_engine, world)
    open_activity(page)
    expect(page.get_by_text("device-01", exact=True).first).to_be_visible()
    drawer = open_record(page)
    limits = drawer.locator("section").filter(
        has=page.get_by_role("heading", name="Shared limits that apply")
    )
    expect(limits).to_contain_text("Group triage:")
    expect(limits).to_contain_text(f"Account {world['account']}:")
    expect(limits).to_contain_text("Environment = production:")
    expect(limits).to_contain_text("Principal: at most 3 total targets per 1 hour")
    # Every scope label is inert text: the section holds four sentences and no control,
    # so nothing can act on a group name or a fact value.
    expect(limits.locator(".why")).to_have_count(4)
    assert (
        limits.evaluate("node => node.querySelectorAll('a, form, button, script, img').length") == 0
    )
    assert (
        live_provider.store.resource(world["identity"].tenant_id, world["canonical"]).mutation_count
        == 0
    )


# The page half of GC18. The record page and the uncertain queue label a checkpoint
# externally executed, with the precondition class and, once settled, the evidence tier, as
# inert text, and no control on either page dispatches.


@pytest.fixture
def gate_gateway(db, gate_world):
    """A Gate deployment behind a real server: no connector configured for any account.

    The precondition class is deployment configuration, so it is declared here as an
    operator would rather than by anything the caller sends, and the strongest class is
    chosen so the page has something to render that is not the honest default.
    """

    def build(origin):
        runtime = gate_runtime(
            db,
            gate_world,
            keys=TokenKeys("act-v1", {"act-v1": secrets.token_bytes(32)}),
            preconditions=PreconditionConfig({CONTAIN: "ENFORCED_BY_PROVIDER"}),
        )
        return human_app(db, runtime, origin)

    with serve(build) as origin:
        yield origin


@pytest.fixture
def gate_page(chromium, gate_gateway):
    with chromium.new_context(
        base_url=gate_gateway, viewport={"width": 1440, "height": 1000}
    ) as context:
        page = context.new_page()
        page.set_default_timeout(ACTION_TIMEOUT_MS)
        yield page


@pytest.fixture
def gate_http(gate_gateway, seeded):
    with httpx.Client(
        base_url=gate_gateway,
        headers={"Authorization": "Bearer " + seeded["tokens"][0]},
        trust_env=False,
    ) as client:
        yield client


def controls(scope):
    """Every control the scope offers a person, by its accessible name.

    The console dispatches nothing through a form: a change is a call the page makes and
    waits for. So what a page offers is its buttons, and one that offers none offers nothing
    to act on whatever an agent or a platform sent.
    """
    return sorted(
        name.strip() for name in scope.get_by_role("button").all_inner_texts() if name.strip()
    )


def test_gc18_the_pages_label_an_externally_executed_operation_as_inert_text(
    gate_page, gate_http, admin_engine, db, gate_world
):
    page, world = gate_page, gate_world
    injected = "<img src=x onerror=alert(1)>"
    with admin_engine.begin() as conn:
        conn.execute(
            text(
                "UPDATE execbound.resources SET provider_id=:v "
                "WHERE tenant_id=:t AND resource_id=:r"
            ),
            {"v": injected, "t": world["identity"].tenant_id, "r": world["target"]},
        )
    answered = gate_http.post("/v1/execute", json=request(world).model_dump(mode="json"))
    assert answered.status_code == 202 and answered.json()["state"] == "DISPATCH_COMMITTED"
    grant = answered.json()["checkpoint"]["grant"]
    assert grant["precondition_class"] == "ENFORCED_BY_PROVIDER"
    page.goto("/login?setup=1")
    page.get_by_label("Setup credential").fill(credential(admin_engine, world["admin"]))
    page.get_by_role("button", name="Continue setup").click()
    # An administrator lands on Home; the record is on Activity.
    expect(page.get_by_role("heading", level=1)).to_have_text("Home")
    page.goto("/activity")
    execution_id = answered.json()["execution_id"]

    drawer = open_record(page)
    expect(drawer).to_contain_text(EXTERNALLY_EXECUTED)
    # A grant was issued for this row, so the class it carries is the one the deployment
    # declared at that moment and is retained where the grant was recorded. The record
    # reads only the declaration in force now, which a redeployment moves, so it shows
    # none: the class as inert text is the approval page's, where no grant exists and the
    # declaration is both the only source and the right one.
    expect(drawer).to_contain_text("Not shown for this record.")
    expect(drawer.get_by_text("Enforced by the provider", exact=False)).to_have_count(0)
    expect(drawer).to_contain_text("None yet: nothing has settled this record.")
    expect(drawer).to_contain_text("Held: no other ExecBound request")
    # The provider's own string is literal text in the record, and the page holds no
    # element the markup could have become.
    expect(drawer).to_contain_text(injected)
    # The console draws its own icons as SVG, so what must be absent is an element built
    # from one of those strings: a script, an image, or an event handler attribute.
    expect(page.locator("main img, main script, main [onerror], main [onload]")).to_have_count(0)
    assert page.locator("body").get_attribute("data-injected") is None
    page.keyboard.press("Escape")

    page.goto("/activity?state=UNCERTAIN")
    expect(page.get_by_role("heading", level=1)).to_have_text("Activity")
    # The only change the queue offers is the connector-free settlement. Nothing on this
    # page dispatches, and the grant's cancellation, which would be a refund on absent
    # executor evidence, is not offered for a checkpoint.
    settle = page.get_by_role("table", name=re.compile("Activity")).get_by_role(
        "button", name="Reconcile"
    )
    settle.first.click()
    dialog = page.get_by_role("dialog", name="Settle from the executor's signed record")
    expect(dialog).to_be_visible()
    expect(dialog.get_by_label("Cancel if no terminal evidence exists")).to_have_count(0)
    page.keyboard.press("Escape")
    expect(
        page.get_by_role("dialog", name="Settle from the executor's signed record")
    ).to_have_count(0)
    page.keyboard.press("Escape")
    # The row's settlement is reachable at both widths: the table scrolls inside its own
    # region rather than the page scrolling sideways, so the control is scrolled to.
    for viewport in ({"width": 1440, "height": 1000}, {"width": 390, "height": 844}):
        page.set_viewport_size(viewport)
        page.wait_for_load_state("load")
        assert page.evaluate(
            "() => document.documentElement.scrollWidth <= document.documentElement.clientWidth"
        )
        expect(settle.first).to_be_enabled()
    page.set_viewport_size({"width": 1440, "height": 1000})

    settled = gate_http.post(
        f"/v1/executions/{execution_id}/outcome",
        json={
            "report_secret": grant["report_secret"],
            "outcome": "EXECUTED",
            "reason": "EXECUTED",
            "reported_at": world["clock"].now().isoformat(),
        },
    )
    assert settled.status_code == 200 and settled.json()["state"] == "EXECUTED"
    page.goto(f"/activity?open={execution_id}")
    drawer = page.get_by_role("dialog", name=re.compile("Isolate endpoint"))
    expect(drawer).to_contain_text("Asserted: the executor's authenticated word")
    # Settled on the executor's word that its call ran, which is not the statement the
    # correction answers, so the console offers no control and the sentence is what it
    # says instead.
    expect(drawer).to_contain_text("An assertion never releases a canonical claim")
    assert "Settle from record" not in controls(drawer)


# AL28 and AL30's page clause. An Arcade-carried execution on the record and approval pages,
# with real Chromium: what the platform said about itself is shown as text and nothing on
# either page acts on it, and a corrected record shows the statement it corrected from the
# transition history rather than from a column that no longer holds it.


@pytest.fixture
def carrier_gateway(db, arcade_world, seeded):
    """One deployment serving both the Arcade hooks and the human pages.

    A Gate placement: no connector for the account, one registered executor key, and the
    catalog that carries the governed operation's contract. The hooks and the pages are
    one application because what is under test is what a page shows about a record the
    hooks opened.
    """
    world = arcade_world

    def build(origin):
        runtime = Runtime(db, [], clock=world["clock"], catalog=CATALOG)
        return create_app(
            db,
            runtime=runtime,
            human=HumanConfig(
                origin, TokenKeys("carrier-v1", {"carrier-v1": secrets.token_bytes(32)})
            ),
            arcade=hook_block(),
        )

    with serve(build) as origin:
        yield origin


@pytest.fixture
def carrier_hooks(carrier_gateway, seeded):
    """The control point's own client: the agent credential, over real HTTP."""
    with httpx.Client(base_url=carrier_gateway, trust_env=False) as client:
        yield SimpleNamespace(client=client, token=seeded["tokens"][0])


@pytest.fixture
def carrier_page(chromium, carrier_gateway):
    with chromium.new_context(
        base_url=carrier_gateway, viewport={"width": 1440, "height": 1000}
    ) as context:
        page = context.new_page()
        page.set_default_timeout(ACTION_TIMEOUT_MS)
        yield page


# Where an administrator lands after signing in: Home, the origin's own root.
HOME = r"://[^/]+/$"


def as_identity(page, admin_engine, identity, landing):
    page.goto("/login?setup=1")
    page.get_by_label("Setup credential").fill(credential(admin_engine, identity))
    page.get_by_role("button", name="Continue setup").click()
    expect(page).to_have_url(re.compile(landing))
    return page


def hostile_hooks(driver, **changes):
    """One governed tool call whose reported strings each carry a script element.

    The end user, the tool metadata's key and its value, the reported code and the
    reported error: the five free columns a correlation row retains. The tool identity
    and the Arcade execution id are not among them — `ToolInfo` and the idempotency key
    class narrow those before the row is opened.
    """
    sent = {"tool": HOSTILE_TOOL, "context": HOSTILE_CONTEXT}
    answered = pre(driver, **sent, **{k: v for k, v in changes.items() if k != "success"})
    reported = post(
        driver,
        **sent,
        execution_code=markup("code"),
        execution_error=markup("error"),
        **changes,
    )
    return answered, reported


def assert_no_markup_became_an_element(page, scope=None):
    """Every marked string is on the page as text, and the page holds no element from one.

    The console draws its own icons as SVG, so an SVG in `main` is the kit's and not a
    platform's string; what must be absent is a script, an image or an event handler.
    """
    within = page if scope is None else scope
    for field in MARKED_FIELDS:
        expect(within.get_by_text(markup(field), exact=False).first).to_be_visible()
    expect(page.locator("main img, main script, main [onerror], main [onload]")).to_have_count(0)
    assert page.locator("body").get_attribute("data-injected") is None


def test_al28_the_pages_show_an_arcade_carried_execution_as_inert_text(
    carrier_page, carrier_hooks, carrier_gateway, chromium, admin_engine, db, arcade_world
):
    """AL28: the tool identity, the end user and the reported strings, on both pages.

    Two records: one the deployment granted and the platform reported failed, and one held
    for a human decision, whose control point reported success anyway — the shape a
    control point configured to fail open produces, and the reason the page a human
    decides on has to show what the platform said.
    """
    world = arcade_world
    granted, reported = hostile_hooks(carrier_hooks, success=False)
    assert granted.json() == {"code": "OK"} and reported.status_code == 200
    governed_target(admin_engine, world, "device-22", approver=world["human"].principal_id)
    governed_bundle(db, world, approval_policies=APPROVE_RISKY)
    waiting, _ = hostile_hooks(
        carrier_hooks,
        execution_id="arcade-execution-2",
        inputs={"device_id": "device-22"},
        success=True,
    )
    assert waiting.json()["code"] == "CHECK_FAILED"

    page = as_identity(carrier_page, admin_engine, world["admin"], HOME)
    reported = correlation_rows(admin_engine, world["identity"].tenant_id)
    corrigible = reported["arcade-execution-1"]["execution_id"]
    page.goto(f"/activity?open={corrigible}")
    drawer = page.get_by_role("dialog", name=re.compile("Isolate endpoint"))
    expect(drawer).to_contain_text(CONTROL_POINT_CARRIED)
    expect(drawer).to_contain_text("endpoint_mock.ContainDevice 1.0")
    assert_no_markup_became_an_element(page, drawer)
    # The tier is shown with what it rests on, the settled assertion says what still holds
    # its claim and what releases it, and the settled reported failure says what was never
    # established and what it still costs.
    expect(drawer).to_contain_text("Asserted: the executor's authenticated word")
    expect(drawer).to_contain_text("An assertion never releases a canonical claim")
    expect(drawer).to_contain_text("The scheduled recovery run is what releases the claim")
    expect(drawer).to_contain_text("The effect was never established.")
    # Nothing here dispatches. The settled reported failure is the row `reconcile` admits a
    # correction for, so the record is offered one and the pending record is not.
    assert "Correct settlement" in controls(drawer)
    for viewport in ({"width": 1440, "height": 1000}, {"width": 390, "height": 844}):
        page.set_viewport_size(viewport)
        assert_responsive(
            page, [drawer.get_by_role("button", name="Correct settlement")], scroll=False
        )
    page.set_viewport_size({"width": 1440, "height": 1000})
    page.keyboard.press("Escape")

    with chromium.new_context(
        base_url=carrier_gateway, viewport={"width": 1440, "height": 1000}
    ) as context:
        review = context.new_page()
        review.set_default_timeout(ACTION_TIMEOUT_MS)
        as_identity(review, admin_engine, world["human"], r"/approvals$")
        # The queue lists what is waiting; a row opens its approval beside it.
        review.get_by_role("list", name="Approvals").get_by_role("link").first.click()
        expect(review).to_have_url(re.compile(r"/approvals/[0-9a-f-]{36}$"))
        expect(review.get_by_role("heading", level=2, name="device-22")).to_be_visible()
        assert_no_markup_became_an_element(review)
        expect(review.get_by_text(CONTROL_POINT_CARRIED, exact=True).first).to_be_visible()
        expect(
            review.get_by_text("CHECK_FAILED: the extension refused this tool call")
        ).to_be_visible()
        expect(
            review.get_by_text("Success, as the platform states it", exact=False)
        ).to_be_visible()
        # The decision is the only change offered, and it names the approval rather than
        # anything the platform sent.
        # Each button's first line is its word; the second says what it does (#678).
        words = {name.split("\n")[0] for name in controls(review)}
        assert "Approve" in words and "Refuse" in words


@pytest.mark.parametrize("changes,state", CORRECTIONS, ids=["cancelled", "version-mismatch"])
def test_al30_the_record_page_shows_a_corrected_rows_earlier_statement(
    carrier_page, carrier_hooks, admin_engine, db, arcade_world, changes, state
):
    """AL30's page clause: the correction driven through the page, in a real browser.

    The correction is made by an administrator filling the control the record page now
    offers, rather than by this test calling `reconcile`, so what the row asserts is the
    route a person actually has. `_settle` replaces `result` with the correcting evidence,
    so `REPORTED_FAILURE` — the reason the page prints for the statement that was corrected
    — is one the record's own column no longer holds. That is asserted against the column
    here, so a page reading the column could not have produced this text.
    """
    world, tenant = arcade_world, arcade_world["identity"].tenant_id
    hostile_hooks(carrier_hooks, success=False)
    execution_id = correlation_rows(admin_engine, tenant)["arcade-execution-1"]["execution_id"]
    page = as_identity(carrier_page, admin_engine, world["admin"], HOME)
    page.goto(f"/activity?open={execution_id}")
    drawer = page.get_by_role("dialog", name=re.compile("Isolate endpoint"))
    expect(drawer).to_contain_text("The effect was never established.")

    # What an operator is told the control does, beside the control it is told it about.
    drawer.get_by_role("button", name="Correct settlement").click()
    dialog = page.get_by_role("dialog", name="Correct this settlement")
    expect(dialog).to_contain_text("This record was settled on the platform's own word")
    dialog.get_by_label("Reason").fill("the platform's report was false")
    dialog.get_by_label("Executor record").fill(signed(db, world, execution_id, changes).decode())
    dialog.get_by_role("button", name="Correct this settlement with a signed non-execution").click()
    expect(page.get_by_role("dialog", name="Correct this settlement")).to_have_count(0)
    row = retained(admin_engine, tenant, execution_id)
    assert (row.state, row.tier, row.impact) == (state, "ATTESTED", "NONEXECUTION")
    assert row.confirmed_at is None and row.released_at is not None
    assert row.result["reason"] == changes["reason"] and row.result["reason"] != "REPORTED_FAILURE"
    page.goto(f"/activity?open={execution_id}")
    drawer = page.get_by_role("dialog", name=re.compile("Isolate endpoint"))
    expect(drawer).to_contain_text("Corrected: this record was settled once on the executor")
    expect(drawer).to_contain_text(
        "the executor stated FAILED_EFFECT_UNKNOWN for reason REPORTED_FAILURE"
    )
    expect(drawer.get_by_text("The effect was never established.")).to_have_count(0)
    # A correction is a settlement and offers no control of its own.
    assert "Correct settlement" not in controls(drawer)
    assert_no_markup_became_an_element(page, drawer)
