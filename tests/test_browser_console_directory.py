# SPDX-License-Identifier: AGPL-3.0-only
"""The Agents pages under `/` in real Chromium (#333): the list, the detail and its changes.

The list and the detail pages are axe-clean with zero policy or Trusted Types violations in
both schemes at 1280 and 390 pixels, through the same `audit` the kit's pages pass. Then the
flows a person runs: a credential issued and shown once, nowhere once its dialog closes (not in
the document, the address, or storage), and the dialog closing on its own button only; `Govern
this agent` from a discovered agent, with what to do next carrying no secret and the address
following the new principal; deactivation asking for a reason, reachable by keyboard, felt on
the page; the filters living in the address so the back button restores them.
"""

import re
from uuid import uuid4

import httpx
import pytest
from conftest import assert_secret_free
from playwright.sync_api import expect
from sqlalchemy import text
from test_agents_bindings import found as found
from test_agents_bindings import new_agent_principal
from test_browser_console import AXE_RUN, audit, person_name, settled, sign_in_as
from test_browser_console import console_gateway as console_gateway
from test_browser_console import console_page as console_page
from test_browser_surfaces import ACTION_TIMEOUT_MS
from test_browser_surfaces import chromium as chromium
from test_execution import registry as registry
from test_execution import request
from test_execution import world as world
from test_protected_path import connector as connector
from test_protected_path import live_provider as live_provider
from test_runtime import runtime as runtime

from execbound.policy.rulesets import ruleset_bundle
from execbound.policy.store import activate_bundle, create_bundle, validate_bundle
from execbound_harness.demo import ENDPOINT_RULESET

TOKEN = re.compile(r"eb1\.[0-9a-f-]{36}\.[0-9a-f-]{36}\.[A-Za-z0-9_-]+")


def agent_name(engine, principal) -> str:
    """How the console names an unlabelled agent: by its counting number (0058)."""
    with engine.connect() as conn:
        number = conn.execute(
            text("SELECT number FROM execbound.principals WHERE principal_id = :p"),
            {"p": principal},
        ).scalar_one()
    return f"Agent {number}"


def stored(page) -> str:
    return page.evaluate("JSON.stringify(localStorage) + JSON.stringify(sessionStorage)")


def nowhere(page, token: str) -> None:
    """The secret is in no part of the page a person or a script could read back."""
    assert token not in page.content()
    assert token not in page.url
    assert_secret_free(stored(page), known=[token])
    assert page.evaluate("window.__violations") == []


def audit_agent(page, path, heading):
    audit(page, path, heading)
    geometry = page.evaluate(
        """() => {
            const main = document.querySelector('main');
            const steps = document.querySelector('.connection-steps');
            return {
                mainWidth: main.clientWidth, mainScrollWidth: main.scrollWidth,
                stepsWidth: steps?.clientWidth, stepsScrollWidth: steps?.scrollWidth,
                documentHeight: document.documentElement.scrollHeight,
                viewportHeight: innerHeight, viewportWidth: innerWidth,
            };
        }"""
    )
    assert geometry["mainScrollWidth"] <= geometry["mainWidth"], geometry
    if geometry["stepsWidth"] is not None:
        assert geometry["stepsScrollWidth"] <= geometry["stepsWidth"], geometry
    if geometry["viewportWidth"] == 390:
        assert geometry["documentHeight"] <= geometry["viewportHeight"], geometry


@pytest.mark.parametrize("scheme", ["dark", "light"])
def test_the_agents_pages_are_clean_in_both_schemes_and_at_phone_width(
    console_page, admin_engine, world, found, scheme
):
    console_page.emulate_media(color_scheme=scheme)
    sign_in_as(console_page, admin_engine, world["admin"])
    mine = str(world["identity"].principal_id)
    second = str(found["agents"][1]["agent_id"])
    # HF51 (#439, #496): a tenant at its agent limit (`tenants.max_agents`) shows the line's
    # over-limit sentence -- the refusal toast's own words -- and, with one of its agents
    # asleep, the dormancy sentence and an "Asleep" badge, all proven axe-clean here rather
    # than in a Playwright test of its own. `world["identity"]` is already one AGENT
    # principal; two more (each labelled, so neither reads as the "unlabelled" row below) put
    # the tenant at exactly its limit of three once the limit is set -- the second of the two
    # goes to sleep instead of staying merely active, since a sleeping agent still counts
    # against the limit exactly as a live one does.
    tenant = world["identity"].tenant_id
    extras = [new_agent_principal(admin_engine, tenant) for _ in range(2)]
    with admin_engine.begin() as conn:
        labels = ("Second free-plan agent", "Third free-plan agent")
        for extra, label in zip(extras, labels, strict=True):
            conn.execute(
                text(
                    "UPDATE execbound.principals SET label = :l "
                    "WHERE tenant_id = :t AND principal_id = :p"
                ),
                {"l": label, "t": tenant, "p": extra},
            )
        conn.execute(
            text(
                "UPDATE execbound.principals SET active = false, dormant_at = now() "
                "WHERE tenant_id = :t AND principal_id = :p"
            ),
            {"t": tenant, "p": extras[1]},
        )
        conn.execute(
            text("UPDATE execbound.tenants SET max_agents = 3 WHERE tenant_id = :t"),
            {"t": tenant},
        )
    for width in (1280, 390):
        console_page.set_viewport_size({"width": width, "height": 900})
        audit(console_page, "/agents", "Agent connections")
        audit_agent(console_page, f"/agents/{mine}", agent_name(admin_engine, mine))
        audit_agent(console_page, f"/agents/{second}", "Synthetic agent 2")
    # The list names the three rows the fixture holds and links them by id.
    console_page.goto("/agents?state=all")
    table = console_page.get_by_role("table", name=re.compile("Agents matching"))
    expect(
        table.get_by_role("link", name=agent_name(admin_engine, mine), exact=True)
    ).to_have_attribute("href", f"/agents/{mine}")
    expect(table.get_by_role("link", name="Synthetic agent 2")).to_have_attribute(
        "href", f"/agents/{second}"
    )
    usage = console_page.get_by_text("Discovery coverage and agent capacity", exact=True)
    expect(usage.locator("..")).not_to_have_attribute("open", "")
    usage.click()
    expect(
        console_page.get_by_text(
            "Agents: 3 of 3. "
            "This workspace has reached its agent limit. "
            "Every agent you have keeps running. 1 agent is asleep after ninety days "
            "without a governed request. Open an agent marked Asleep to reactivate it."
        )
    ).to_be_visible()
    expect(table.get_by_text("Asleep")).to_be_visible()
    assert console_page.evaluate("window.__violations") == []


@pytest.fixture
def isolate_rules(db, world):
    """The endpoint pack as rules, active, so the reach rows have rules to name."""
    content = ruleset_bundle(
        ENDPOINT_RULESET,
        tenant_id=world["identity"].tenant_id,
        bundle_id=uuid4(),
        mappings=world["bundle"].mappings,
    )
    create_bundle(db, world["admin"], content, world["clock"])
    validate_bundle(db, world["admin"], content.bundle_id, world["clock"])
    activate_bundle(db, world["admin"], content.bundle_id, world["clock"])
    return content


@pytest.mark.parametrize("scheme", ["dark", "light"])
def test_the_reach_rows_name_the_rules_and_link_them_to_the_rules_page(
    console_page, admin_engine, world, isolate_rules, scheme
):
    """#273: a bundle written as rules gives each governed path its rules by name.

    The name is a link the router builds to the rules page of the bundle the rule is in, not
    an address assembled from a word, and the caption says the reading is not the decision.
    """
    console_page.emulate_media(color_scheme=scheme)
    sign_in_as(console_page, admin_engine, world["admin"])
    mine = str(world["identity"].principal_id)
    # The rules are on the agent's Permissions section (#678), read as sentences.
    for width in (1280, 390):
        console_page.set_viewport_size({"width": width, "height": 900})
        audit_agent(
            console_page, f"/agents/{mine}?section=permissions", agent_name(admin_engine, mine)
        )
    table = console_page.get_by_role("table", name=re.compile("Rules are as they read"))
    expect(table.get_by_role("columnheader", name="Rules")).to_be_visible()
    expect(table).to_contain_text("Allow isolating an endpoint when")
    expect(table).to_contain_text(
        "Deny isolating an endpoint when the target is a domain controller."
    )
    expect(table.get_by_role("link", name="isolate-workstation-open-critical")).to_be_visible()
    link = table.get_by_role("link", name="isolate-production-needs-review")
    expect(link).to_have_attribute("href", f"/policy/{isolate_rules.bundle_id}/rules")
    # The link goes where it says: the rules of that bundle, read and not editable.
    link.click()
    expect(console_page.get_by_role("heading", level=1)).to_have_text("Rules")
    expect(console_page.get_by_text("Only a draft can be changed.", exact=False)).to_be_visible()
    expect(console_page.get_by_text("isolate-production-needs-review").first).to_be_visible()
    assert console_page.evaluate("window.__violations") == []


REACH = """
() => {
  const table = document.querySelector('#agent-permissions table');
  const wrap = table.parentElement;
  const rules = [...table.querySelectorAll('thead th')]
    .find((th) => th.textContent.trim() === 'Rules');
  return {
    rules: rules.getBoundingClientRect().width,
    table: table.getBoundingClientRect().width,
    hidden: wrap.scrollWidth - wrap.clientWidth,
    height: document.documentElement.scrollHeight,
  };
}
"""


def test_the_rules_column_keeps_a_readable_measure(
    console_page, admin_engine, world, isolate_rules, runtime
):
    """The Permissions tab's rules are read as sentences, so they keep a column of their own
    (#678): it was one word wide at 1280, behind identifiers and timestamps that would not wrap,
    and the page ran to about 7,400 px."""
    runtime.execute(world["identity"], request(world).model_dump_json().encode())
    sign_in_as(console_page, admin_engine, world["admin"])
    mine = str(world["identity"].principal_id)
    console_page.set_viewport_size({"width": 1280, "height": 900})
    console_page.goto(f"/agents/{mine}?section=permissions")
    expect(console_page.get_by_role("columnheader", name="Rules")).to_be_visible()
    settled(console_page)
    geometry = console_page.evaluate(REACH)
    assert geometry["hidden"] <= 0, geometry
    assert geometry["rules"] >= 320, geometry
    assert geometry["rules"] >= geometry["table"] * 0.35, geometry


NAME_PROMPT = """
() => {
  const form = document.querySelector('.name-prompt');
  const meta = document.querySelector('.meta');
  if (form === null || meta === null) return null;
  const a = form.getBoundingClientRect();
  const b = meta.getBoundingClientRect();
  return {
    form: [a.top, a.bottom], meta: [b.top, b.bottom],
    overlap: a.top < b.bottom && b.top < a.bottom,
  };
}
"""


def test_the_name_prompt_keeps_clear_of_the_line_under_the_heading(
    console_page, admin_engine, world
):
    """An agent or a person with no name offers a field to name them (#678); its help text sat
    on the "Back to" line under the heading, on both pages and at every width."""
    sign_in_as(console_page, admin_engine, world["admin"])
    agent, person = str(world["identity"].principal_id), str(world["human"].principal_id)
    for width in (1280, 390):
        console_page.set_viewport_size({"width": width, "height": 900})
        for path in (f"/agents/{agent}", f"/people/{person}"):
            console_page.goto(path)
            expect(console_page.get_by_role("button", name="Save name")).to_be_visible()
            settled(console_page)
            geometry = console_page.evaluate(NAME_PROMPT)
            assert geometry is not None and not geometry["overlap"], (path, width, geometry)


def test_a_credential_is_shown_once_and_then_nowhere(console_page, admin_engine, world):
    sign_in_as(console_page, admin_engine, world["admin"])
    mine = str(world["identity"].principal_id)
    console_page.goto(f"/agents/{mine}")
    expect(console_page.get_by_role("heading", level=1)).to_have_text(
        agent_name(admin_engine, mine)
    )
    console_page.get_by_label("API key expires after").select_option("24")
    console_page.get_by_role("button", name="Issue another API key").click()
    dialog = console_page.get_by_role("dialog", name="Copy the API key now")
    expect(dialog).to_be_visible()
    field = dialog.get_by_label("API key (copy it now)")
    token = field.input_value()
    assert TOKEN.fullmatch(token), token
    expect(field).to_have_attribute("readonly", "")
    # A stray click outside, or Escape, does not lose a secret that cannot be shown again.
    console_page.mouse.click(8, 8)
    console_page.keyboard.press("Escape")
    expect(dialog).to_be_visible()
    console_page.get_by_role("button", name="I have copied it").click()
    expect(console_page.get_by_role("dialog")).to_have_count(0)
    nowhere(console_page, token)
    # The API keys sit in the Connection section beside the steps (#678).
    expect(console_page.get_by_role("table", name=re.compile("Every API key"))).to_contain_text(
        "live"
    )
    nowhere(console_page, token)
    console_page.reload()
    expect(console_page.get_by_role("heading", level=1)).to_have_text(
        agent_name(admin_engine, mine)
    )
    nowhere(console_page, token)


def test_phone_menu_reaches_agent_setup_and_check_reads_an_actual_authenticated_request(
    console_page, console_gateway, admin_engine, world
):
    """A saved credential is not connection proof; a persisted governed request is."""
    sign_in_as(console_page, admin_engine, world["admin"])
    console_page.set_viewport_size({"width": 390, "height": 844})
    console_page.goto("/")
    console_page.get_by_role("button", name="Navigation menu").click()
    menu = console_page.get_by_role("dialog", name="Menu")
    expect(menu).to_be_visible()
    settled(console_page)
    assert console_page.evaluate(AXE_RUN) == []
    assert console_page.evaluate("window.__violations") == []
    menu.get_by_role("link", name="Agent connections", exact=True).click()
    expect(menu).not_to_be_visible()
    expect(console_page.get_by_role("heading", level=1)).to_have_text("Agent connections")
    mine = str(world["identity"].principal_id)
    table = console_page.get_by_role("table", name=re.compile("Agents matching"))
    table.get_by_role("link", name=agent_name(admin_engine, mine), exact=True).click()
    expect(console_page.get_by_role("heading", name="Connect this agent")).to_be_visible()
    console_page.get_by_role("button", name="Check connection").click()
    expect(
        console_page.get_by_text("No governed request is recorded yet.", exact=False)
    ).to_be_visible()
    console_page.get_by_role("combobox", name="Agent host", exact=True).select_option("mcp")
    expect(console_page.get_by_text("Server URL:", exact=False)).to_contain_text(console_gateway)
    # No lifetime is chosen for the person: the key waits for one (AK1).
    expect(console_page.get_by_role("button", name="Issue another API key")).to_be_disabled()
    console_page.get_by_label("API key expires after").select_option("720")
    console_page.get_by_role("button", name="Issue another API key").click()
    shown = console_page.get_by_role("dialog", name="Copy the API key now")
    token = shown.get_by_label("API key (copy it now)").input_value()
    assert TOKEN.fullmatch(token)
    shown.get_by_role("button", name="I have copied it").click()
    nowhere(console_page, token)
    # The test agent makes a real request to this gateway with the freshly issued key.
    # The synthetic policy requires approval, so verification must not claim execution.
    with httpx.Client(base_url=console_gateway, trust_env=False) as agent:
        response = agent.post(
            "/v1/execute",
            json=request(world).model_dump(mode="json"),
            headers={"Authorization": "Bearer " + token},
        )
    assert response.status_code == 202, response.text
    assert response.json()["state"] == "PENDING_APPROVAL"
    console_page.get_by_role("button", name="Check connection").click()
    expect(console_page.get_by_text("Requests received", exact=True)).to_be_visible()
    expect(
        console_page.get_by_text("Authenticated requests from this agent appear in Activity.")
    ).to_be_visible()
    expect(console_page.get_by_text("No confirmed execution appears", exact=False)).to_be_visible()
    nowhere(console_page, token)
    activity = console_page.get_by_role("link", name="View this agent’s activity")
    expect(activity).to_have_attribute("href", f"/activity?agent={mine}")
    activity.click()
    expect(console_page).to_have_url(re.compile(r"/activity\?agent=" + re.escape(mine) + "$"))
    expect(console_page.get_by_role("heading", level=1)).to_have_text("Activity")
    nowhere(console_page, token)


def test_govern_this_agent_issues_once_and_lands_on_the_new_principal(
    console_page, admin_engine, world, found
):
    sign_in_as(console_page, admin_engine, world["admin"])
    target = str(found["agents"][2]["agent_id"])
    console_page.goto(f"/agents/{target}")
    expect(console_page.get_by_role("heading", level=1)).to_have_text(re.compile("^Quarterly"))
    console_page.get_by_label(re.compile("^Govern this agent: create its principal")).select_option(
        "720"
    )
    console_page.get_by_role("button", name="Govern this agent").click()
    dialog = console_page.get_by_role("dialog", name="Copy the API key now")
    expect(dialog).to_be_visible()
    token = dialog.get_by_label("API key (copy it now)").input_value()
    assert TOKEN.fullmatch(token), token
    recipes = dialog.locator("pre").all_inner_texts()
    assert len(recipes) == 2 and all(token not in recipe for recipe in recipes)
    native_mcp = dialog.locator("pre").filter(has_text="claude mcp add")
    optional_client = dialog.locator("pre").filter(has_text="pipx install")
    expect(native_mcp).to_be_visible()
    expect(optional_client).not_to_be_visible()
    dialog.get_by_text("Optional Python client (source checkout required)", exact=True).click()
    expect(optional_client).to_be_visible()
    expect(optional_client).to_contain_text("Public installation is not available yet.")
    console_page.get_by_role("button", name="I have copied it").click()
    expect(console_page).to_have_url(
        re.compile(r"/agents/(?!" + re.escape(target) + ")[0-9a-f-]{36}$")
    )
    expect(console_page.get_by_role("heading", level=1)).to_have_text(re.compile("^Quarterly"))
    console_page.get_by_role("navigation", name="Agent sections").get_by_role(
        "link", name="Advanced"
    ).click()
    expect(
        console_page.get_by_role("heading", level=2, name="What the source lists")
    ).to_be_visible()
    expect(console_page.get_by_role("button", name="Unbind")).to_be_visible()
    nowhere(console_page, token)
    # The discovered agent's own address now answers with its principal's page.
    console_page.goto(f"/agents/{target}")
    expect(console_page).to_have_url(
        re.compile(r"/agents/(?!" + re.escape(target) + ")[0-9a-f-]{36}$")
    )
    nowhere(console_page, token)


def test_deactivation_asks_for_a_reason_by_keyboard_and_shows_on_the_page(
    console_page, admin_engine, world
):
    sign_in_as(console_page, admin_engine, world["admin"])
    mine = str(world["identity"].principal_id)
    console_page.goto(f"/agents/{mine}?section=advanced")
    console_page.get_by_role("button", name="Deactivate this agent").focus()
    console_page.keyboard.press("Enter")
    dialog = console_page.get_by_role("dialog", name="Deactivate this agent?")
    expect(dialog).to_be_visible()
    confirm = dialog.get_by_role("button", name="Deactivate")
    expect(confirm).to_be_disabled()
    # The reason field has focus on opening; the confirming button waits for the server.
    console_page.keyboard.type("left the team")
    expect(confirm).to_be_enabled()
    confirm.focus()
    console_page.keyboard.press("Enter")
    expect(console_page.get_by_role("dialog")).to_have_count(0)
    expect(console_page.get_by_role("status").filter(has_text="Agent deactivated.")).to_be_visible()
    expect(console_page.get_by_role("heading", level=2, name="Reactivate")).to_be_visible()
    expect(console_page.get_by_role("button", name="Issue API key")).to_have_count(0)
    expect(console_page.get_by_role("button", name="Issue another API key")).to_have_count(0)
    console_page.get_by_role("button", name="Reactivate this agent").click()
    console_page.get_by_role("dialog").get_by_role("button", name="Reactivate").click()
    expect(console_page.get_by_role("dialog")).to_have_count(0)
    expect(
        console_page.get_by_role("heading", level=2, name="Deactivate", exact=True)
    ).to_be_visible()
    # Active again, the agent has its Connection section, where a key is issued.
    console_page.get_by_role("navigation", name="Agent sections").get_by_role(
        "link", name="Connection"
    ).click()
    keys = console_page.locator("section").filter(
        has=console_page.get_by_role("heading", level=2, name="API keys")
    )
    expect(keys.get_by_role("button", name="Issue API key")).to_be_visible()
    assert console_page.evaluate("window.__violations") == []


def test_the_filters_live_in_the_address(console_page, admin_engine, world):
    sign_in_as(console_page, admin_engine, world["admin"])
    console_page.goto("/agents")
    console_page.get_by_label("State").select_option("deactivated")
    expect(console_page).to_have_url(re.compile(r"/agents\?state=deactivated$"))
    expect(console_page.get_by_text("No agent matches these filters.")).to_be_visible()
    console_page.go_back()
    expect(console_page).to_have_url(re.compile(r"/agents$"))
    expect(console_page.get_by_label("State")).to_have_value("active")
    mine = str(world["identity"].principal_id)
    expect(
        console_page.get_by_role("link", name=agent_name(admin_engine, mine), exact=True)
    ).to_be_visible()
    # A value outside the choices reads as the default rather than reaching the server.
    console_page.goto("/agents?state=nope&population=bound")
    expect(console_page.get_by_label("State")).to_have_value("active")
    expect(console_page.get_by_label("Population")).to_have_value("bound")
    assert console_page.evaluate("window.__violations") == []


# People: the list, a person, End all sessions, deactivation.


@pytest.mark.parametrize("scheme", ["dark", "light"])
def test_the_people_pages_are_clean_in_both_schemes_and_at_phone_width(
    console_page, admin_engine, world, scheme
):
    console_page.emulate_media(color_scheme=scheme)
    sign_in_as(console_page, admin_engine, world["admin"])
    human, admin = str(world["human"].principal_id), str(world["admin"].principal_id)
    # A person with no label or email is titled by their number, never "Unlabelled".
    titles = {who: person_name(admin_engine, world[who].principal_id) for who in ("human", "admin")}
    for width in (1280, 390):
        console_page.set_viewport_size({"width": width, "height": 900})
        audit(console_page, "/people", "Users")
        audit(console_page, f"/people/{human}", titles["human"])
        audit(console_page, f"/people/{admin}", titles["admin"])
    table = console_page.get_by_role("table", name=re.compile("Users matching"))
    console_page.goto("/people")
    expect(table.get_by_role("link")).to_have_count(2)
    expect(console_page.get_by_text("owner tooling", exact=True)).to_have_count(0)
    console_page.goto(f"/people/{admin}")
    expect(console_page.get_by_text("Advanced access details")).to_be_visible()
    expect(
        console_page.get_by_role("button", name=re.compile("^Issue (an? )?(credential|API key)"))
    ).to_have_count(0)
    expect(console_page.get_by_role("button", name="Deactivate this user")).to_have_count(0)
    expect(console_page.get_by_role("button", name="End all sessions")).to_have_count(0)
    assert console_page.evaluate("window.__violations") == []


def test_end_all_sessions_ends_the_person_in_their_own_browser(
    console_page, chromium, console_gateway, admin_engine, world
):
    human = str(world["human"].principal_id)
    with chromium.new_context(base_url=console_gateway) as theirs:
        their_page = theirs.new_page()
        their_page.set_default_timeout(ACTION_TIMEOUT_MS)
        sign_in_as(their_page, admin_engine, world["human"])
        their_page.goto("/approvals")
        expect(their_page.get_by_role("heading", level=1)).to_have_text("Approvals")
        sign_in_as(console_page, admin_engine, world["admin"])
        console_page.goto(f"/people/{human}")
        sessions = console_page.get_by_role("table", name="Active sessions of this user.")
        expect(sessions).not_to_contain_text("No active session.")
        expect(sessions.get_by_role("row")).to_have_count(2)
        console_page.get_by_role("button", name="End all sessions").click()
        console_page.get_by_role("dialog").get_by_role("button", name="End all sessions").click()
        expect(console_page.get_by_role("dialog")).to_have_count(0)
        expect(
            console_page.get_by_role("table", name="Active sessions of this user.")
        ).to_contain_text("No active session.")
        their_page.goto("/approvals")
        # Sign-in, carrying the page to return to (#678).
        expect(their_page).to_have_url(re.compile(r"/login\?review=%2Fapprovals$"))
        # The administrator's own session is intact.
        console_page.goto("/people")
        expect(console_page.get_by_role("heading", level=1)).to_have_text("Users")
    assert console_page.evaluate("window.__violations") == []


def test_a_person_is_deactivated_with_a_reason_and_legacy_access_can_be_inspected(
    console_page, admin_engine, world
):
    sign_in_as(console_page, admin_engine, world["admin"])
    human = str(world["human"].principal_id)
    console_page.goto(f"/people/{human}")
    expect(
        console_page.get_by_role("button", name=re.compile("^Issue (an? )?(credential|API key)"))
    ).to_have_count(0)
    console_page.get_by_role("button", name="Deactivate this user").click()
    asked = console_page.get_by_role("dialog", name="Deactivate this user?")
    asked.get_by_label(re.compile("^Reason")).fill("left the team")
    asked.get_by_role("button", name="Deactivate").click()
    expect(console_page.get_by_role("dialog")).to_have_count(0)
    expect(console_page.get_by_role("heading", level=2, name="Reactivate")).to_be_visible()
    console_page.get_by_text("Advanced access details").click()
    credentials = console_page.get_by_role(
        "table", name="Every credential of this user, newest first."
    )
    expect(credentials).not_to_contain_text("live")
    expect(
        console_page.get_by_role("button", name=re.compile("^Issue (an? )?(credential|API key)"))
    ).to_have_count(0)
    # Scopes are kept through deactivation.
    expect(console_page.get_by_role("table", name=re.compile("Canonical targets"))).to_contain_text(
        "endpoint.isolate"
    )
    assert console_page.evaluate("window.__violations") == []


def test_a_named_reviewer_sets_up_normal_sign_in_and_receives_explicit_permissions(
    console_page, chromium, console_gateway, admin_engine, world
):
    """A synthetic account uses a password setup code, then ordinary sign-in to review."""
    sign_in_as(console_page, admin_engine, world["admin"])
    address = f"reviewer-{uuid4().hex}@example.com"
    console_page.goto("/people")
    console_page.get_by_role("button", name="Add user").click()
    dialog = console_page.get_by_role("dialog", name="Add a user")
    dialog.get_by_label("Name (required)").fill("Synthetic reviewer")
    dialog.get_by_label("Sign-in email (required)").fill(address)
    dialog.get_by_role("button", name="Create account").click()
    expect(console_page).to_have_url(re.compile(r"/people/[0-9a-f-]{36}$"))
    person_url = console_page.url
    expect(console_page.get_by_role("heading", level=1)).to_have_text("Synthetic reviewer")
    expect(console_page.get_by_text("Individual review assignments: none assigned")).to_be_visible()
    expect(
        console_page.get_by_role("button", name=re.compile("^Issue (an? )?(credential|API key)"))
    ).to_have_count(0)
    console_page.get_by_role("button", name="Create password setup code").click()
    shown = console_page.get_by_role("dialog", name="Copy the code now")
    code = shown.get_by_label("One-time code (copy it now)").input_value()
    setup_url = shown.get_by_label("Page to open").input_value()
    assert code not in setup_url
    shown.get_by_role("button", name="I have copied it").click()
    nowhere(console_page, code)

    with chromium.new_context(base_url=console_gateway) as reviewer:
        page = reviewer.new_page()
        page.set_default_timeout(ACTION_TIMEOUT_MS)
        page.goto(setup_url)
        page.get_by_label("One-time code").fill(code)
        page.get_by_label("New password", exact=True).fill("synthetic reviewer password")
        page.get_by_label("Repeat it").fill("synthetic reviewer password")
        page.get_by_role("button", name="Set the password").click()
        expect(page.get_by_role("heading", level=1)).to_have_text("Your password is set.")
        page.get_by_role("link", name="Go to sign in").click()
        expect(page.get_by_label("Setup credential")).to_have_count(0)
        page.get_by_label("Email").fill(address)
        page.get_by_label("Password", exact=True).fill("synthetic reviewer password")
        page.get_by_role("button", name="Sign in with a password").click()
        expect(page).to_have_url(re.compile(r"/approvals$"))
        expect(page.get_by_role("heading", level=1)).to_have_text("Approvals")

        console_page.goto(person_url)
        expect(console_page.get_by_text("Sign-in: configured")).to_be_visible()
        expect(
            console_page.get_by_text("Individual review assignments: none assigned")
        ).to_be_visible()
        console_page.get_by_role("combobox", name="Action", exact=True).select_option(
            "endpoint.isolate"
        )
        console_page.get_by_role("button", name="Assign", exact=True).click()
        expect(
            console_page.get_by_text("Individual review assignments: 1 assigned")
        ).to_be_visible()
    assert console_page.evaluate("window.__violations") == []


# Credentials and Approver scopes.


@pytest.mark.parametrize("scheme", ["dark", "light"])
def test_the_access_pages_are_clean_in_both_schemes_and_at_phone_width(
    console_page, admin_engine, world, scheme
):
    console_page.emulate_media(color_scheme=scheme)
    sign_in_as(console_page, admin_engine, world["admin"])
    for width in (1280, 390):
        console_page.set_viewport_size({"width": width, "height": 900})
        audit(console_page, "/credentials", "API keys")
        audit(console_page, "/approvers", "Approval rules")
    # Each credential links to its principal's own page; an administrator's has no revoke.
    console_page.goto("/credentials")
    table = console_page.get_by_role("table", name=re.compile("API keys in this tenant"))
    expect(table.get_by_role("link", name="agent")).to_have_attribute(
        "href", f"/agents/{world['identity'].principal_id}"
    )
    legacy = console_page.get_by_role("table", name=re.compile("Legacy human"))
    expect(legacy).not_to_be_visible()
    console_page.get_by_text("Advanced: legacy human and administrator credentials").click()
    # The holder is named as the console names any person, by number here, not by kind.
    holder = person_name(admin_engine, world["admin"].principal_id)
    expect(legacy.get_by_role("link", name=holder, exact=True)).to_have_attribute(
        "href", f"/people/{world['admin'].principal_id}"
    )
    expect(legacy.get_by_text("owner tooling")).to_have_count(1)
    assert console_page.evaluate("window.__violations") == []


def test_a_credential_for_an_existing_agent_is_shown_once_and_the_list_follows(
    console_page, admin_engine, world
):
    sign_in_as(console_page, admin_engine, world["admin"])
    console_page.goto("/credentials")
    before = int(
        console_page.get_by_text("Live API keys")
        .locator("xpath=following-sibling::*[1]")
        .inner_text()
    )
    console_page.get_by_role("button", name="Issue an API key").click()
    asked = console_page.get_by_role("dialog", name="Issue an API key")
    asked.get_by_label("Agent").select_option(str(world["identity"].principal_id))
    asked.get_by_label("Lifetime").select_option("24")
    asked.get_by_role("button", name="Issue API key").click()
    shown = console_page.get_by_role("dialog", name="Copy the API key now")
    expect(shown).to_be_visible()
    token = shown.get_by_label("API key (copy it now)").input_value()
    assert TOKEN.fullmatch(token), token
    expect(shown).to_contain_text(re.compile(r"API key \d+ is shown once"))
    console_page.get_by_role("button", name="I have copied it").click()
    expect(console_page.get_by_role("dialog")).to_have_count(0)
    nowhere(console_page, token)
    figure = console_page.get_by_text("Live API keys").locator("xpath=following-sibling::*[1]")
    expect(figure).to_have_text(str(before + 1))
    nowhere(console_page, token)


def test_a_scope_is_assigned_and_unassigned_with_confirmation(console_page, admin_engine, world):
    sign_in_as(console_page, admin_engine, world["admin"])
    console_page.goto("/approvers")
    console_page.get_by_text(re.compile(r"^Advanced: individual review assignments")).click()
    table = console_page.get_by_role("table", name=re.compile("Active assignments"))
    expect(table.get_by_role("row")).to_have_count(2)
    console_page.get_by_role("button", name="Assign an approver").click()
    asked = console_page.get_by_role("dialog", name="Assign an approver")
    asked.get_by_label("Action").select_option("endpoint.lift_isolation")
    asked.get_by_role("button", name="Assign").click()
    expect(console_page.get_by_role("dialog")).to_have_count(0)
    expect(table.get_by_role("row")).to_have_count(3)
    expect(table).to_contain_text("endpoint.lift_isolation")
    console_page.get_by_role(
        "button", name=re.compile("^Unassign .* endpoint.lift_isolation")
    ).click()
    console_page.get_by_role("dialog").get_by_role("button", name="Unassign").click()
    expect(console_page.get_by_role("dialog")).to_have_count(0)
    expect(table.get_by_role("row")).to_have_count(2)
    expect(table).not_to_contain_text("endpoint.lift_isolation")
    assert console_page.evaluate("window.__violations") == []


def test_times_read_in_the_viewers_own_time_zone(chromium, console_gateway, admin_engine, world):
    """A viewer in New York reads the API keys page in Eastern time, with the zone named."""
    with chromium.new_context(
        base_url=console_gateway,
        viewport={"width": 1280, "height": 900},
        timezone_id="America/New_York",
    ) as context:
        page = context.new_page()
        page.set_default_timeout(ACTION_TIMEOUT_MS)
        sign_in_as(page, admin_engine, world["admin"])
        page.goto("/credentials")
        table = page.get_by_role("table", name=re.compile("API keys in this tenant"))
        expect(table).to_contain_text(re.compile(r"\d{4}-\d{2}-\d{2} \d{2}:\d{2} E[DS]T"))
        expect(table).not_to_contain_text(" UTC")
