# SPDX-License-Identifier: AGPL-3.0-only
"""Sample targets in real Chromium (#420, #545, SM7).

An administrator of an empty workspace adds the samples from Home's guided setup, refreshes
their facts, their agent's first request executes against the real endpoint mock, the Verify
step shows it and names the other two targets as the request to relay, and Activity shows it
with its Sample mark, and removing the samples offers them again. Every stage is held to the
bar the console holds everywhere: no axe violation, no policy violation, no sideways scroll and
no secret in the page, at desktop and at phone width. Home's guided setup and its Sample
targets step are core's Getting started page, which reads core's own
`GET /api/console/v1/samples` (#496), so the gateway loads no plugin and serves the core build
the package carries.
"""

import re

import httpx
import pytest
from conftest import assert_secret_free, remember_secret
from playwright.sync_api import expect
from sample_fixtures import agent_token, empty_workspace
from sample_fixtures import sample_key as sample_key
from sample_fixtures import sample_mock as sample_mock
from sample_fixtures import sample_runtime as sample_runtime
from test_browser_console import AXE, AXE_RUN, COLLECT, console_app, settled, sign_in_as
from test_browser_surfaces import ACTION_TIMEOUT_MS, serve
from test_browser_surfaces import chromium as chromium

from execbound import samples
from execbound.provider.sample_accounts import sample_material
from execbound.surfaces import console as console_module

TABLE = "Sample targets and what the starter policy does to an isolation request"
EXPECTED = (
    ("dc-01.sample.invalid", "Denied"),
    ("ws-dev-01.sample.invalid", "Allowed"),
    ("ws-prod-01.sample.invalid", "Needs approval"),
)


@pytest.fixture
def samples_gateway(db, sample_runtime):
    if console_module.load_build() is None:
        pytest.fail("No console build is packaged: run `pnpm build` in console/ first")
    if not AXE.exists():
        pytest.fail("axe-core is not installed: run `pnpm install` in console/ first")
    with serve(lambda origin: console_app(db, sample_runtime, origin)) as origin:
        yield origin


@pytest.fixture
def samples_page(chromium, samples_gateway):
    with chromium.new_context(
        base_url=samples_gateway, viewport={"width": 1280, "height": 900}
    ) as context:
        page = context.new_page()
        page.set_default_timeout(ACTION_TIMEOUT_MS)
        page.add_init_script(COLLECT)
        page.add_init_script(path=str(AXE))
        yield page


def clean(page, what):
    settled(page)
    violations = page.evaluate(AXE_RUN)
    assert violations == [], (what, violations)
    assert page.evaluate("window.__violations") == [], what
    assert page.evaluate(
        "document.documentElement.scrollWidth <= document.documentElement.clientWidth"
    ), (what, "horizontal scroll")
    assert_secret_free(page.content())


@pytest.mark.parametrize("width", [1280, 390])
def test_sm7_add_samples_connect_an_agent_see_the_first_request_and_remove(
    samples_page, samples_gateway, db, admin_engine, seeded, sample_key, width
):
    page = samples_page
    page.set_viewport_size({"width": width, "height": 900})
    workspace = empty_workspace(admin_engine, db)
    sign_in_as(page, admin_engine, workspace.admin)

    # Home offers an empty workspace the samples, which Getting started's example step adds
    # (#678): with no connection, they are the one path to a decision in this Space.
    page.goto("/")
    page.get_by_role("link", name="Add sample targets").click()
    expect(page).to_have_url(re.compile(r"/welcome\?step=example$"))
    expect(page.get_by_role("heading", level=1)).to_have_text("Getting started")
    expect(page.get_by_role("heading", name="Sample targets")).to_be_visible()
    clean(page, f"samples offered at {width}")
    page.get_by_role("button", name="Add sample targets").click()
    table = page.get_by_role("table", name=TABLE)
    for hostname, word in EXPECTED:
        row = table.get_by_role("row").filter(has_text=hostname)
        expect(row).to_contain_text("Sample")
        expect(row).to_contain_text(word)
    expect(page.get_by_role("button", name="Remove sample targets")).to_be_enabled()
    clean(page, f"samples added at {width}")

    # Refreshing re-creates the samples in one click: fresh facts and new incidents, so the
    # status read below and the agent's request name the refreshed set (#545).
    page.get_by_role("button", name="Refresh sample facts").click()
    expect(
        page.get_by_text(re.compile(r"^Sample facts refreshed\. Each target has a new incident"))
    ).to_be_visible()
    expect(page.get_by_role("button", name="Refresh sample facts")).to_be_enabled()
    for hostname, word in EXPECTED:
        expect(table.get_by_role("row").filter(has_text=hostname)).to_contain_text(word)
    clean(page, f"samples refreshed at {width}")

    # The derived secrets exist only in memory on either side; no page may show one.
    with db.transaction(workspace.tenant_id) as conn:
        status = samples.status(conn, workspace.tenant_id, available=True)
    assert status.account_id is not None
    material = sample_material(sample_key, workspace.tenant_id, status.account_id)
    for value in (material.dispatch_token, material.control_token, material.journal_key.hex()):
        remember_secret(value)
    allowed = next(host for host in status.hosts if host.effect == "allow")
    prod = next(host for host in status.hosts if host.effect == "require approval")

    # The person's agent asks the gateway itself, and the development workstation executes.
    token = remember_secret(agent_token(admin_engine, workspace))
    answer = httpx.post(
        samples_gateway + "/v1/execute",
        json={
            "operation_ref": "endpoint.isolate",
            "target": {"kind": "hostname", "value": allowed.hostname},
            "arguments": {},
            "idempotency_key": f"sample-dev-{width}",
            "claimed_context": {"incident_id": str(allowed.incident_id)},
        },
        headers={"Authorization": "Bearer " + token},
        timeout=30,
    )
    assert answer.status_code == 200 and answer.json()["state"] == "EXECUTED", answer.text

    steps = page.get_by_role("navigation", name="Setup steps")
    steps.get_by_role("button", name=re.compile("Connect an agent")).click()
    # The agent by its workspace number, "Agent 2", never by an id prefix (#678).
    expect(page.get_by_role("link", name=re.compile(r"^Agent \d+$"))).to_be_visible()
    clean(page, f"connect step at {width}")
    steps.get_by_role("button", name=re.compile("Verify protection")).click()
    first = page.get_by_role("link", name="sample-ws-dev-01")
    expect(first).to_be_visible()
    expect(first.locator("xpath=..")).to_contain_text("First request: sample-ws-dev-01 Executed")
    denied_line = page.get_by_text("dc-01.sample.invalid", exact=True).locator("xpath=ancestor::li")
    expect(denied_line).to_contain_text("searching the console for that reference finds it")
    held_line = page.get_by_text("ws-prod-01.sample.invalid", exact=True).locator(
        "xpath=ancestor::li"
    )
    expect(held_line).to_contain_text(
        "call execute with operation_ref endpoint.isolate, target hostname "
        f"ws-prod-01.sample.invalid and claimed_context.incident_id {prod.incident_id}"
    )
    expect(held_line).to_contain_text("this workspace's approval deadline")
    clean(page, f"verify step at {width}")

    # Activity carries the request with its Sample mark. The click opens the record drawer,
    # which correctly hides the rest of the page from the accessibility tree while it is open
    # (as every other drawer in the console does); close it with Escape before reading the
    # table, the same way test_browser_console_activity.py does.
    first.click()
    expect(page).to_have_url(re.compile(r"/activity\?open=[0-9a-f-]{36}$"))
    expect(page.get_by_role("dialog", name=re.compile("sample-ws-dev-01"))).to_be_visible()
    page.keyboard.press("Escape")
    expect(page.get_by_role("dialog")).to_have_count(0)
    activity = page.get_by_role("table", name=re.compile("^Activity"))
    row = activity.get_by_role("row").filter(has_text="sample-ws-dev-01")
    expect(row).to_contain_text("Sample")
    expect(row).to_contain_text("Executed")
    clean(page, f"activity at {width}")

    # Removing asks first, keeps the history and offers the samples again. Getting started
    # now opens on the first step left, so the samples' own step is named in the address.
    page.goto("/welcome?step=example")
    page.get_by_role("button", name="Remove sample targets").click()
    confirm = page.get_by_role("group", name="Confirm removal")
    confirm.get_by_role("button", name="Remove", exact=True).click()
    expect(page.get_by_role("button", name="Add sample targets")).to_be_visible()
    expect(page.get_by_role("table", name=TABLE)).to_have_count(0)
    clean(page, f"samples removed at {width}")
    with db.transaction(workspace.tenant_id) as conn:
        assert samples.status(conn, workspace.tenant_id, available=True).state == "absent"


def test_ay17_guided_setup_states_delivery_after_the_deadline(
    samples_page, admin_engine, db, seeded
):
    page = samples_page
    workspace = empty_workspace(admin_engine, db)
    sign_in_as(page, admin_engine, workspace.admin)
    page.goto("/welcome")
    page.get_by_role("button", name="Add sample targets").click()
    expect(page.get_by_role("button", name="Remove sample targets")).to_be_enabled()
    steps = page.get_by_role("navigation", name="Setup steps")
    steps.get_by_role("button", name=re.compile("Verify protection")).click()
    held_line = page.get_by_text("ws-prod-01.sample.invalid", exact=True).locator(
        "xpath=ancestor::li"
    )
    deadline = held_line.get_by_text(re.compile("this workspace's approval deadline"))
    expect(deadline).to_be_visible()
    # This deployment announces nothing, so the step says where a held request is announced,
    # right after the deadline (#678).
    following = deadline.locator("xpath=following-sibling::p[1]")
    expect(following).to_have_text(
        "No approval destination is configured, so a held request is announced only in "
        "this console."
    )
    clean(page, "verify step with the delivery sentence")
