# SPDX-License-Identifier: AGPL-3.0-only
"""Getting started's progress, the sidebar's fold and the setup pages in real Chromium (#678).

Every value Getting started and the sidebar card show is read from records by
`GET /api/console/v1/setup`; these cases drive the real console over a real gateway, with the
sample targets installed through their own library, an agent's key issued by the fixtures and a
request admitted by the kernel. The fold is measured here because jsdom cannot lay a page out:
at 1280 by 800 the account block and Sign out stay in view without scrolling, and in a short
window the sidebar scrolls as one column so Sign out is reached and never clipped. Every page is
held to the bar the console holds everywhere: no axe violation, no policy or Trusted Types
violation, no sideways scroll and no secret in the page, at desktop and at phone width, in both
schemes.
"""

import re
from pathlib import Path

import pytest
from conftest import assert_secret_free
from playwright.sync_api import expect
from sample_fixtures import agent_identity, empty_workspace
from sample_fixtures import sample_key as sample_key
from sample_fixtures import sample_mock as sample_mock
from sample_fixtures import sample_runtime as sample_runtime
from test_browser_console import AXE_RUN, settled, sign_in_as
from test_browser_console_samples import samples_gateway as samples_gateway
from test_browser_console_samples import samples_page as samples_page
from test_browser_surfaces import FITS
from test_browser_surfaces import chromium as chromium
from test_console_api_samples import ask, by_effect

from execbound import samples

INTEGRATIONS = Path(__file__).resolve().parents[1] / "integrations"


def clean(page, what):
    settled(page)
    violations = page.evaluate(AXE_RUN)
    assert violations == [], (what, violations)
    assert page.evaluate("window.__violations") == [], what
    assert page.evaluate(FITS), (what, "horizontal scroll")
    assert_secret_free(page.content())


def in_view(page, locator) -> bool:
    box = locator.bounding_box()
    size = page.viewport_size
    assert box is not None and size is not None
    return box["y"] >= 0 and box["y"] + box["height"] <= size["height"]


def test_the_sidebar_footer_stays_in_view_at_1280_by_800(
    samples_page, db, admin_engine, seeded, sample_key
):
    page = samples_page
    page.set_viewport_size({"width": 1280, "height": 800})
    workspace = empty_workspace(admin_engine, db)
    sign_in_as(page, admin_engine, workspace.admin)
    page.goto("/")
    sidebar = page.get_by_role("navigation", name="Main")
    # An empty workspace has every step left, so the card shows with its count and next step.
    expect(sidebar.get_by_text(re.compile(r"^0 of 5 · Next: "))).to_be_visible()
    sign_out = sidebar.get_by_role("button", name="Sign out")
    account = sidebar.get_by_role("link", name="My account")
    expect(sign_out).to_be_visible()
    assert in_view(page, sign_out) and in_view(page, account)
    # The navigation in the middle is the part that scrolls; the sidebar itself has nothing
    # left to scroll, so the footer is where the window ends.
    assert page.evaluate(
        "getComputedStyle(document.querySelector('.sidebar-scroll')).overflowY"
    ) in ("auto", "scroll")
    assert page.evaluate(
        "(() => { const s = document.querySelector('.sidebar');"
        " return s.scrollHeight <= s.clientHeight; })()"
    )
    clean(page, "the sidebar at 1280 by 800")


def test_sign_out_is_reachable_in_a_short_viewport(
    samples_page, db, admin_engine, seeded, sample_key
):
    page = samples_page
    page.set_viewport_size({"width": 1280, "height": 560})
    workspace = empty_workspace(admin_engine, db)
    sign_in_as(page, admin_engine, workspace.admin)
    page.goto("/")
    sidebar = page.get_by_role("navigation", name="Main")
    expect(sidebar.get_by_text(re.compile(r"^0 of 5 · Next: "))).to_be_visible()
    # Too short for the pinned brand and footer: the sidebar scrolls as one column again.
    assert page.evaluate(
        "(() => { const s = document.querySelector('.sidebar');"
        " return s.scrollHeight > s.clientHeight; })()"
    )
    assert (
        page.evaluate("getComputedStyle(document.querySelector('.sidebar-scroll')).overflowY")
        == "visible"
    )
    page.evaluate(
        "() => { const s = document.querySelector('.sidebar'); s.scrollTop = s.scrollHeight; }"
    )
    sign_out = sidebar.get_by_role("button", name="Sign out")
    assert in_view(page, sign_out)
    # Clickable, which a clipped control is not: the point at its centre is the button itself.
    assert page.evaluate(
        """() => {
          const button = [...document.querySelectorAll('.sidebar button')]
            .find((b) => b.textContent.trim() === 'Sign out');
          const r = button.getBoundingClientRect();
          return document.elementFromPoint(r.x + r.width / 2, r.y + r.height / 2) === button;
        }"""
    )


def test_getting_started_ticks_steps_from_records_and_keeps_the_step_on_reload(
    samples_page, db, admin_engine, seeded, sample_key
):
    page = samples_page
    workspace = empty_workspace(admin_engine, db)
    installed = samples.install(db, workspace.admin, available=True)
    agent = agent_identity(admin_engine, db, workspace)
    ask(db, agent, by_effect(installed)["deny"], "setup-dc")
    sign_in_as(page, admin_engine, workspace.admin)
    page.goto("/welcome")
    expect(page.get_by_role("heading", name="Choose your policy")).to_be_visible()
    expect(page).to_have_url(re.compile(r"/welcome\?step=controls$"))
    steps = page.get_by_role("navigation", name="Setup steps")
    expect(
        steps.get_by_role("button", name=re.compile(r"Connect an agent\s*, done"))
    ).to_be_visible()
    expect(
        steps.get_by_role("button", name=re.compile(r"Verify protection\s*, done"))
    ).to_be_visible()
    expect(page.get_by_text(re.compile(r"Policy active since"))).to_be_visible()
    clean(page, "set your controls with progress")
    page.get_by_role("button", name="Back").click()
    expect(page).to_have_url(re.compile(r"/welcome\?step=verify$"))
    expect(page.get_by_role("heading", name="Verify protection")).to_be_visible()
    page.reload()
    expect(page).to_have_url(re.compile(r"/welcome\?step=verify$"))
    expect(page.get_by_role("heading", name="Verify protection")).to_be_visible()
    first = page.get_by_text(re.compile(r"First request EB-\d+"))
    expect(first).to_be_visible()
    # The browser's Back returns to the step before.
    page.go_back()
    expect(page).to_have_url(re.compile(r"/welcome\?step=controls$"))


def test_the_listening_panel_links_the_first_request(
    samples_page, db, admin_engine, seeded, sample_key
):
    page = samples_page
    workspace = empty_workspace(admin_engine, db)
    installed = samples.install(db, workspace.admin, available=True)
    agent = agent_identity(admin_engine, db, workspace)
    sign_in_as(page, admin_engine, workspace.admin)
    page.goto(f"/agents/{agent.principal_id}")
    expect(page.get_by_text(re.compile(r"^Waiting for the first request from "))).to_be_visible()
    asked = ask(db, agent, by_effect(installed)["deny"], "setup-listen")
    # Within one poll of the shared ten-second timer.
    link = page.get_by_role("link", name="Open this decision")
    expect(link).to_be_visible(timeout=20_000)
    expect(link).to_have_attribute("href", f"/activity?open={asked.view.execution_id}")
    clean(page, "the first request arrived")


def test_the_story_downloads_are_the_committed_files(
    samples_page, db, admin_engine, seeded, sample_key
):
    page = samples_page
    workspace = empty_workspace(admin_engine, db)
    sign_in_as(page, admin_engine, workspace.admin)
    for name in ("execbound-gate.json", "execbound-governed-action.json"):
        answer = page.request.get(f"/console/stories/tines/{name}")
        assert answer.ok, (name, answer.status)
        assert answer.body() == (INTEGRATIONS / "tines" / name).read_bytes(), name


@pytest.mark.parametrize("scheme", ["light", "dark"])
def test_setup_pages_are_accessible_in_both_schemes_and_at_390(
    samples_page, db, admin_engine, seeded, sample_key, scheme
):
    page = samples_page
    page.emulate_media(color_scheme=scheme)
    workspace = empty_workspace(admin_engine, db)
    sign_in_as(page, admin_engine, workspace.admin)
    for width in (1280, 390):
        page.set_viewport_size({"width": width, "height": 900})
        for path, heading in (
            ("/welcome?step=connect", "Connect an agent"),
            ("/welcome?step=controls", "Pilot in Observe only (optional)"),
            ("/welcome?step=foo", None),
            ("/agents", "Agent connections"),
            ("/monitor?setup=tines", None),
        ):
            page.goto(path)
            if heading is not None:
                expect(page.get_by_role("heading", name=heading)).to_be_visible()
            elif path.startswith("/welcome"):
                # An unknown step opens on the opening step, written into the address.
                expect(page).to_have_url(re.compile(r"/welcome\?step=(example|connect)$"))
            else:
                expect(page.get_by_role("dialog", name="Connect a source")).to_be_visible()
            if path == "/agents":
                expect(page.get_by_text("No agents in this Space yet.")).to_be_visible()
            clean(page, f"{path} at {width} in {scheme}")
