# SPDX-License-Identifier: AGPL-3.0-only
"""The console under `/` in real Chromium (#333).

Every navigation entry, in both colour schemes, at 1280 and at 390 pixels: axe-core finds no
violation of WCAG 2.2 AA, the browser reports zero policy or Trusted Types violations, the
plain frame is gone once the application mounted, nothing scrolls sideways, the fonts came
from `/fonts` under `font-src 'self'`, and a signed-out visit goes to `/login`. The
keyboard reaches the skip link, the palette, a page and the shortcuts list.

The two schemes here are the system ones. A scheme somebody chose in Settings against the
opposite system setting is held to the same bar, and to one more: that it is already painted
before the bundle has run, measured with the bundle refused at the network.

axe-core is injected as an init script over the automation protocol, which the policy does not
govern, so the page itself stays under the exact policy a browser enforces and a violation is
what it would be for a person.
"""

import json
import re
import secrets
from pathlib import Path

import pytest
from playwright.sync_api import expect
from sqlalchemy import text
from test_browser_surfaces import ACTION_TIMEOUT_MS, serve
from test_browser_surfaces import chromium as chromium
from test_execution import registry as registry
from test_execution import world as world
from test_human_surface import credential
from test_protected_path import connector as connector
from test_protected_path import live_provider as live_provider
from test_runtime import runtime as runtime

from execbound.app import create_app
from execbound.surfaces import console as console_module
from execbound.surfaces.human import HumanConfig
from execbound.surfaces.tokens import TokenKeys

AXE = Path(__file__).resolve().parents[1] / "console" / "node_modules" / "axe-core" / "axe.min.js"
ENTRIES = [
    ("/", "Home"),
    ("/approvals", "Approvals"),
    ("/activity", "Activity"),
    ("/policy", "Policies"),
    ("/agents", "Agent connections"),
    ("/credentials", "API keys"),
    ("/people", "Users"),
    ("/access", "Groups & roles"),
    ("/approvers", "Approval rules"),
    ("/spaces", "Spaces"),
    ("/board", "Live board"),
    ("/monitor", "Monitoring"),
    ("/welcome", "Getting started"),
    ("/tenant", "Workspace settings"),
    ("/help", "Help & support"),
    ("/settings", "My account"),
]
COLLECT = """
(() => {
  window.__violations = [];
  document.addEventListener('securitypolicyviolation', (event) => {
    window.__violations.push(
      event.violatedDirective + ' ' + (event.blockedURI || '')
        + ' ' + event.sourceFile + ':' + event.lineNumber
    );
  });
})();
"""
# The audit is asked of the settled page, not of the frame that mounted it (#333). Three
# things have to have stopped happening. The page's own queries have answered, which shows
# as no route still rendering its "Loading" placeholder: an audit taken before that reads an
# almost empty page and passes for the wrong reason. Nothing is still arriving, which is no
# running animation — except inside `.board`, whose marks animate for as long as it is live
# by design, so waiting for them to stop would hang rather than settle. And every surface
# that rises from opacity 0 over 160 ms is opaque, because axe reads the opacity of that
# moment as a contrast failure; `getAnimations()` alone is not enough, since a surface React
# has only just mounted may not have started animating yet.
SETTLED = """
() => {
  const loading = [...document.querySelectorAll('p, div, span')].some(
    (node) => node.children.length === 0 && node.textContent.trim().startsWith('Loading')
  );
  if (loading) return false;
  const board = document.querySelector('.board');
  const arriving = document.getAnimations().some((animation) => {
    if (animation.playState !== 'running') return false;
    const target = animation.effect && animation.effect.target;
    return !(board !== null && target instanceof Element && board.contains(target));
  });
  if (arriving) return false;
  return [...document.querySelectorAll('.dialog, .drawer, .palette')].every(
    (surface) => getComputedStyle(surface).opacity === '1'
  );
}
"""
AXE_RUN = """
() => axe.run(document, {
  runOnly: {
    type: 'tag',
    values: ['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa', 'wcag22aa', 'best-practice']
  }
}).then((result) => result.violations.map(
  (violation) => violation.id + ': '
    + violation.nodes.map((node) => node.target.join(' ')).join(', ')
))
"""


def console_app(db, runtime, origin, *, assistant=False):
    keys = TokenKeys("browser-v1", {"browser-v1": secrets.token_bytes(32)})
    return create_app(
        db,
        runtime=runtime,
        human=HumanConfig(origin, keys, assistant_enabled=assistant),
    )


@pytest.fixture
def console_gateway(db, runtime):
    if console_module.load_build() is None:
        pytest.fail("No console build is packaged: run `pnpm build` in console/ first")
    if not AXE.exists():
        pytest.fail("axe-core is not installed: run `pnpm install` in console/ first")
    with serve(lambda origin: console_app(db, runtime, origin)) as origin:
        yield origin


@pytest.fixture
def console_page(chromium, console_gateway):
    with chromium.new_context(
        base_url=console_gateway, viewport={"width": 1280, "height": 900}
    ) as context:
        page = context.new_page()
        page.set_default_timeout(ACTION_TIMEOUT_MS)
        page.add_init_script(COLLECT)
        page.add_init_script(path=str(AXE))
        yield page


def sign_in_as(page, admin_engine, identity):
    page.goto("/login?setup=1")
    page.get_by_label("Setup credential").fill(credential(admin_engine, identity))
    page.get_by_role("button", name="Continue setup").click()
    # The pages decide where a signed-in person lands; the console does not care which.
    expect(page).to_have_url(re.compile(r"/(activity|approvals)?$"))


def person_name(engine, principal) -> str:
    """How the console names a fixture person, who has neither a label nor an email: by their
    counting number among the workspace's people, "User 2" (0062)."""
    with engine.connect() as conn:
        label, email, number = conn.execute(
            text("SELECT label, email, number FROM execbound.principals WHERE principal_id = :p"),
            {"p": principal},
        ).one()
    assert label is None and email is None, (label, email)
    return f"User {number}"


def settled(page) -> None:
    """Wait until the page has answered, nothing is arriving and every surface is opaque."""
    page.wait_for_function(SETTLED)


def audit(page, path, heading):
    response = page.goto(path)
    assert response is not None and response.ok, (path, response.status if response else None)
    assert page.url.endswith(path), (path, page.url)
    expect(page.get_by_role("heading", level=1)).to_have_text(heading)
    assert page.locator("#frame").count() == 0, "the plain frame is still in the document"
    settled(page)
    violations = page.evaluate(AXE_RUN)
    assert violations == [], (path, violations)
    policy = page.evaluate("window.__violations")
    assert policy == [], (path, policy)
    assert page.evaluate(
        "document.documentElement.scrollWidth <= document.documentElement.clientWidth"
    ), (path, "horizontal scroll")


def test_a_signed_out_visit_goes_to_login(console_page):
    # The page rides sign-in as the return hint; an `open` that is no record id is dropped.
    console_page.goto("/activity?open=abc")
    expect(console_page).to_have_url(re.compile(r"/login\?review=%2Factivity$"))
    console_page.goto("/")
    expect(console_page).to_have_url(re.compile(r"/login$"))


@pytest.mark.parametrize("scheme", ["dark", "light"])
def test_every_entry_is_clean_in_both_schemes(console_page, admin_engine, world, scheme):
    console_page.emulate_media(color_scheme=scheme)
    sign_in_as(console_page, admin_engine, world["admin"])
    for path, heading in ENTRIES:
        audit(console_page, path, heading)
    names = (
        console_page.get_by_role("navigation", name="Main").get_by_role("link").all_inner_texts()
    )
    # The Getting started card carries a second line; the first line is the entry's name.
    assert [name.strip().splitlines()[0] for name in names] == [heading for _, heading in ENTRIES]
    assert console_page.evaluate("document.fonts.check('13px \"IBM Plex Sans\"')")
    assert console_page.evaluate("document.fonts.check('13px \"IBM Plex Mono\"')")
    policy = console_page.evaluate(
        "document.querySelector('meta[name=execbound-release]') !== null"
    )
    assert policy
    # The mark reaches the tab: the document names both files and the browser can fetch each
    # one under the console's own policy, which `img-src 'self'` permits.
    icons = console_page.eval_on_selector_all("link[rel=icon]", "nodes => nodes.map(n => n.href)")
    assert len(icons) == 2, icons
    for href in icons:
        assert console_page.request.get(href).ok, href


LUMINANCE = """
() => {
  const parts = getComputedStyle(document.documentElement).backgroundColor.match(/\\d+(\\.\\d+)?/g);
  const channel = (c) => {
    const v = Number(c) / 255;
    return v <= 0.03928 ? v / 12.92 : Math.pow((v + 0.055) / 1.055, 2.4);
  };
  return 0.2126 * channel(parts[0]) + 0.7152 * channel(parts[1]) + 0.0722 * channel(parts[2]);
}
"""


@pytest.mark.parametrize("system,chosen", [("light", "dark"), ("dark", "light")])
def test_a_chosen_appearance_paints_before_the_bundle_and_stays_clean(
    console_page, admin_engine, world, system, chosen
):
    """System, Light or Dark, chosen in Settings, against the opposite system setting.

    The point of the choice is the paint before the bundle: the console carries no inline
    script and `index.html` paints a plain frame from the tokens before any script runs, so a
    scheme applied by the application would be one frame of the wrong colours on every visit.
    The last part of this test is what proves it did not happen — the bundle is refused at the
    network, so what is measured is exactly the first paint, the plain frame under the
    stylesheet, with nothing of the application having run at all.
    """
    console_page.emulate_media(color_scheme=system)
    sign_in_as(console_page, admin_engine, world["admin"])
    audit(console_page, "/settings", "My account")
    group = console_page.get_by_role("group", name="Appearance")
    expect(group.get_by_role("button", name="System")).to_have_attribute("aria-pressed", "true")

    group.get_by_role("button", name=chosen.capitalize(), exact=True).click()
    expect(console_page.locator("html")).to_have_attribute("data-eb-scheme", chosen)

    def painted(where: str) -> None:
        """The root's own background, which is the scheme the page is actually in."""
        measured = console_page.evaluate(LUMINANCE)
        dark = measured < 0.05
        assert dark == (chosen == "dark"), f"{where}: luminance {measured:.3f} is not {chosen}"

    painted("after choosing")

    # The server writes it into the next document it serves, from the cookie this browser now
    # carries. `page.request` shares the page's cookie jar, so this is the document a reload
    # would receive, read before a browser has done anything with it.
    served = console_page.request.get(console_page.url).text()
    assert f'data-eb-scheme="{chosen}"' in served.split("<head", 1)[0], served[:400]

    # Every route stays axe-clean with no policy or Trusted Types violation in the forced
    # scheme, as it is in the two system ones.
    for path, heading in (("/", "Home"), ("/activity", "Activity"), ("/settings", "My account")):
        audit(console_page, path, heading)
    expect(console_page.locator("html")).to_have_attribute("data-eb-scheme", chosen)

    # And the first paint: the bundle never arrives, so the plain frame is all there is, and
    # it is already the scheme the person chose.
    console_page.route("**/console/assets/*.js", lambda route: route.abort())
    console_page.goto("/")
    expect(console_page.locator("#frame")).to_be_visible()
    painted("the plain frame, with the bundle refused")
    assert console_page.evaluate("window.__violations") == []
    console_page.unroute("**/console/assets/*.js")

    # Back to System, and the frame follows the device again.
    console_page.goto("/settings")
    expect(console_page.get_by_role("heading", level=1)).to_have_text("My account")
    console_page.get_by_role("group", name="Appearance").get_by_role(
        "button", name="System"
    ).click()
    assert console_page.evaluate("document.documentElement.hasAttribute('data-eb-scheme')") is False
    assert "data-eb-scheme" not in console_page.request.get(console_page.url).text()


@pytest.mark.parametrize("scheme", ["dark", "light"])
def test_every_entry_is_clean_at_phone_width(console_page, admin_engine, world, scheme):
    console_page.emulate_media(color_scheme=scheme)
    console_page.set_viewport_size({"width": 390, "height": 844})
    sign_in_as(console_page, admin_engine, world["admin"])
    for path, heading in ENTRIES:
        audit(console_page, path, heading)
    tabs = console_page.get_by_role("navigation", name="Main, phone").get_by_role("link")
    assert [name.strip() for name in tabs.all_inner_texts()] == [
        "Home",
        "Approvals",
        "Activity",
        "Live",
        "My account",
    ]
    assert not console_page.get_by_role("navigation", name="Main", exact=True).is_visible()
    # Menu opens the navigation sheet, which is as clean as the pages (#678).
    console_page.get_by_role("button", name="Navigation menu").click()
    expect(console_page.get_by_role("dialog", name="Menu")).to_be_visible()
    settled(console_page)
    assert console_page.evaluate(AXE_RUN) == []
    assert console_page.evaluate("window.__violations") == []
    assert console_page.evaluate(
        "document.documentElement.scrollWidth <= document.documentElement.clientWidth"
    )


def test_the_keyboard_reaches_everything(console_page, admin_engine, world):
    sign_in_as(console_page, admin_engine, world["admin"])
    console_page.goto("/")
    expect(console_page.get_by_role("heading", level=1)).to_have_text("Home")
    console_page.keyboard.press("Tab")
    assert console_page.evaluate("document.activeElement.getAttribute('href')") == "#main"
    console_page.keyboard.press("Control+k")
    palette = console_page.get_by_role("dialog", name=re.compile(r"^Search( or ask)?$"))
    expect(palette).to_be_visible()
    console_page.keyboard.type("Activ")
    console_page.keyboard.press("Enter")
    expect(console_page).to_have_url(re.compile(r"/activity$"))
    heading = console_page.get_by_role("heading", level=1)
    expect(heading).to_have_text("Activity")
    # The heading takes focus a frame after the navigation resolves; wait for it, as a person does.
    expect(heading).to_be_focused()
    console_page.keyboard.press("?")
    expect(console_page.get_by_role("dialog", name="Keyboard")).to_be_visible()
    console_page.keyboard.press("Escape")
    expect(console_page.get_by_role("dialog")).to_have_count(0)
    assert console_page.evaluate("window.__violations") == []
    # The rail is remembered per browser.
    console_page.get_by_role("button", name="Collapse the sidebar").click()
    console_page.reload()
    expect(console_page.get_by_role("button", name="Expand the sidebar")).to_be_visible()


def test_a_label_with_markup_renders_as_text(console_page, admin_engine, world):
    """The notification drawer opens safely, and strings remain text rather than markup."""
    sign_in_as(console_page, admin_engine, world["admin"])
    console_page.goto("/")
    # Ask is absent here, because this gateway carries no assistant block (#330).
    assert console_page.get_by_role("button", name="Ask", exact=True).count() == 0
    console_page.get_by_role("button", name=re.compile(r"^Notifications")).click()
    notices = console_page.get_by_role("dialog", name="Notifications")
    expect(notices).to_be_visible()
    security = notices.get_by_role("region", name="Sign-in security")
    expect(security.get_by_text("No security changes in the last 90 days.")).to_be_visible()
    console_page.keyboard.press("Escape")
    expect(notices).not_to_be_visible()
    # An agent labelled with markup: the Agents page shows the label as the characters it
    # is, and no element it describes exists in the document.
    hostile = '<img src=x onerror="window.__fired=1"> "quoted"'
    with admin_engine.begin() as conn:
        conn.execute(
            text("UPDATE execbound.principals SET label=:l WHERE principal_id=:p"),
            {"l": hostile, "p": world["identity"].principal_id},
        )
    console_page.goto("/agents")
    expect(console_page.get_by_role("heading", level=1)).to_have_text("Agent connections")
    expect(console_page.get_by_text(hostile, exact=True).first).to_be_visible()
    assert console_page.locator('img[src="x"]').count() == 0
    assert console_page.evaluate("window.__fired") is None
    assert console_page.evaluate("window.__violations") == []


LABEL_BOXES = """
() => {
  const svg = document.querySelector('figure.chart svg');
  if (svg === null) return null;
  const view = svg.viewBox.baseVal;
  return [...svg.querySelectorAll('text.chart-label')]
    .filter((node) => node.textContent.trim() !== '')
    .map((node) => {
      const box = node.getBBox();
      return { text: node.textContent, left: box.x, right: box.x + box.width,
               plot: [view.x, view.x + view.width] };
    });
}
"""


def test_home_labels_are_whole_and_an_administrator_is_not_told_it_needs_them(
    console_page, admin_engine, world
):
    """#427's third row at a wide viewport, and #426's heading.

    The chart centres each label under its column, which put the first one's left half
    outside the plot and cut its leading character off; the pane was narrow when that was
    retested, so this asks at 1920. Nothing here reads a rendered pixel: every label's own
    bounding box is compared with the viewBox it is drawn into, which is where the crop
    happens.
    """
    console_page.set_viewport_size({"width": 1920, "height": 1080})
    sign_in_as(console_page, admin_engine, world["admin"])
    console_page.goto("/")
    expect(console_page.get_by_role("heading", level=1)).to_have_text("Home")
    settled(console_page)
    boxes = console_page.evaluate(LABEL_BOXES)
    assert boxes, "the decisions chart drew no labels"
    for box in boxes:
        left, right = box["plot"]
        assert box["left"] >= left - 0.01, box
        assert box["right"] <= right + 0.01, box
    # An administrator cannot decide an approval, so the card is not headed as theirs.
    assert console_page.get_by_role("heading", name="Needs you").count() == 0
    expect(console_page.get_by_role("heading", name="Waiting on a person")).to_be_visible()
    assert console_page.evaluate("window.__violations") == []


def test_an_approver_sees_their_entries_and_the_mode_reads_the_tenant(
    console_page, admin_engine, world
):
    """The shell reads the session through the generated client once the API base exists."""
    sign_in_as(console_page, admin_engine, world["human"])
    console_page.goto("/")
    expect(console_page.get_by_role("heading", level=1)).to_have_text("Home")
    sidebar = console_page.get_by_role("navigation", name="Main")
    expect(sidebar.get_by_role("link", name="Policies")).to_have_count(0)
    names = sidebar.get_by_role("link").all_inner_texts()
    assert [name.strip().splitlines()[0] for name in names] == [
        "Home",
        "Approvals",
        "Activity",
        "Live board",
        "Help & support",
        "My account",
    ]
    expect(console_page.get_by_text("Enforcing")).to_be_visible()
    expect(console_page.get_by_role("button", name="Emergency stop")).to_have_count(0)
    expect(console_page.get_by_role("navigation", name="Breadcrumb")).to_contain_text("Synthetic")
    assert console_page.evaluate("window.__violations") == []
    # The token never reaches storage or the URL.
    assert "csrf" not in console_page.url
    stored = console_page.evaluate("JSON.stringify(localStorage) + JSON.stringify(sessionStorage)")
    assert "csrf" not in stored.lower()


# --- The assistant (#330, #333) ------------------------------------------------------------

PARAGRAPHS = (
    "Nine requests today and one was denied.",
    "Nothing is waiting for a person.",
)


@pytest.fixture
def assistant_gateway(db, runtime, world):
    """A gateway whose operator configured a model, whose tenant turned it on, and whose
    provider is a script. CI never calls a model: the runtime carries the scripted transport
    that #330's own routes read, so nothing here patches the assistant's own code."""
    from execbound.assistant.client import (
        ScriptedTransport,
        scripted_message,
        text_message,
        tool_use,
    )
    from execbound.assistant.config import AssistantConfig
    from execbound.assistant.turns import set_tenant_switch

    if console_module.load_build() is None:
        pytest.fail("No console build is packaged: run `pnpm build` in console/ first")
    if not AXE.exists():
        pytest.fail("axe-core is not installed: run `pnpm install` in console/ first")
    runtime.assistant = AssistantConfig(api_key="scripted-key")
    set_tenant_switch(db, world["admin"], True, "The fixtures are synthetic", world["clock"])
    answer = json.dumps(
        {
            "paragraphs": [
                {"text": PARAGRAPHS[0], "ids": [str(world["bundle"].bundle_id)]},
                {"text": PARAGRAPHS[1], "ids": []},
            ],
            "cannot_answer": False,
        }
    )
    # CI never calls a model: the runtime's own transport seam carries a script.
    runtime.assistant_transport = ScriptedTransport(
        [
            scripted_message(tool_use("toolu_1", "get_policy", {}), stop_reason="tool_use"),
            scripted_message(text_message(answer)),
        ]
    )
    with serve(lambda origin: console_app(db, runtime, origin, assistant=True)) as origin:
        yield origin


@pytest.fixture
def assistant_page(chromium, assistant_gateway):
    with chromium.new_context(
        base_url=assistant_gateway, viewport={"width": 1280, "height": 900}
    ) as context:
        page = context.new_page()
        page.set_default_timeout(ACTION_TIMEOUT_MS)
        page.add_init_script(COLLECT)
        page.add_init_script(path=str(AXE))
        yield page


def test_ask_answers_and_the_turn_shows_its_steps_and_citations(
    assistant_page, admin_engine, world
):
    """The path a person walks: the entry exists because the operator configured a model, the
    question becomes a turn of its own, and the turn shows what was read, the answer as text,
    and a chip for the one identifier a tool returned."""
    sign_in_as(assistant_page, admin_engine, world["admin"])
    audit(assistant_page, "/ask", "Ask")
    names = (
        assistant_page.get_by_role("navigation", name="Main").get_by_role("link").all_inner_texts()
    )
    assert "Ask" in [name.strip().splitlines()[0] for name in names]
    assistant_page.get_by_label("What would you like to know?").fill("What happened today?")
    assistant_page.get_by_role("button", name="Ask", exact=True).last.click()
    expect(assistant_page).to_have_url(re.compile(r"/ask/[0-9a-f-]{36}$"))
    expect(assistant_page.get_by_text(PARAGRAPHS[0])).to_be_visible()
    expect(assistant_page.get_by_text("Read the active policy")).to_be_visible()
    # The bundle id the tool returned is cited as text: the server says which ids a tool
    # returned, not what kind of record each names, so nothing here becomes a wrong link.
    expect(
        assistant_page.get_by_text(str(world["bundle"].bundle_id)[:8], exact=False).first
    ).to_be_visible()
    assert assistant_page.evaluate("window.__violations") == []
    violations = assistant_page.evaluate(AXE_RUN)
    assert violations == [], violations


def test_ask_and_a_turn_are_clean_in_dark_and_at_phone_width(assistant_page, admin_engine, world):
    sign_in_as(assistant_page, admin_engine, world["admin"])
    assistant_page.goto("/ask")
    expect(assistant_page.get_by_role("heading", level=1)).to_have_text("Ask")
    assistant_page.get_by_label("What would you like to know?").fill("What happened today?")
    assistant_page.get_by_role("button", name="Ask", exact=True).last.click()
    expect(assistant_page).to_have_url(re.compile(r"/ask/[0-9a-f-]{36}$"))
    expect(assistant_page.get_by_text(PARAGRAPHS[0])).to_be_visible()
    turn = "/ask/" + assistant_page.url.rsplit("/ask/", 1)[1]
    heading = assistant_page.get_by_role("heading", level=1).inner_text()
    for scheme, width, height in (("dark", 1280, 900), ("light", 390, 844), ("dark", 390, 844)):
        assistant_page.emulate_media(color_scheme=scheme)
        assistant_page.set_viewport_size({"width": width, "height": height})
        audit(assistant_page, "/ask", "Ask")
        audit(assistant_page, turn, heading)


def test_the_assistant_is_absent_where_no_model_is_configured(console_page, admin_engine, world):
    """Absent, not disabled: no entry, no top bar button, and the address is the shell's own
    not-found rather than a page that says the feature is turned off."""
    sign_in_as(console_page, admin_engine, world["admin"])
    names = (
        console_page.get_by_role("navigation", name="Main").get_by_role("link").all_inner_texts()
    )
    assert "Ask" not in [name.strip().splitlines()[0] for name in names]
    console_page.goto("/ask")
    expect(console_page.get_by_role("heading", level=1)).to_have_text("There is no page here")


RULE_ANSWER = {
    "id": "isolate-never-tier-zero",
    "action": "endpoint.isolate",
    "effect": "DENY",
    "when": [{"kind": "fact", "name": "role", "operator": "is", "values": ["domain_controller"]}],
}


@pytest.fixture
def described_gateway(db, runtime, world):
    """The assistant gateway again, scripted to answer one rule (#330, version 2)."""
    from execbound.assistant.client import ScriptedTransport, scripted_message, text_message
    from execbound.assistant.config import AssistantConfig
    from execbound.assistant.turns import set_tenant_switch

    if console_module.load_build() is None:
        pytest.fail("No console build is packaged: run `pnpm build` in console/ first")
    runtime.assistant = AssistantConfig(api_key="scripted-key")
    set_tenant_switch(db, world["admin"], True, "The fixtures are synthetic", world["clock"])
    runtime.assistant_transport = ScriptedTransport(
        [scripted_message(text_message(json.dumps(RULE_ANSWER)))]
    )
    with serve(lambda origin: console_app(db, runtime, origin, assistant=True)) as origin:
        yield origin


@pytest.fixture
def described_page(chromium, described_gateway):
    with chromium.new_context(
        base_url=described_gateway, viewport={"width": 1280, "height": 900}
    ) as context:
        page = context.new_page()
        page.set_default_timeout(ACTION_TIMEOUT_MS)
        page.add_init_script(COLLECT)
        page.add_init_script(path=str(AXE))
        yield page


def test_a_described_rule_fills_the_form_and_the_draft_is_unchanged_until_it_is_added(
    described_page, db, admin_engine, world
):
    """Version 2's whole claim in one walk: the words become a rule in the form, and the
    draft is what it was until the ordinary Add the rule submits it."""
    from uuid import uuid4

    from execbound.policy.rulesets import ruleset_bundle
    from execbound.policy.store import create_bundle, read_bundle
    from execbound_harness.demo import ENDPOINT_RULESET

    content = ruleset_bundle(
        ENDPOINT_RULESET,
        tenant_id=world["identity"].tenant_id,
        bundle_id=uuid4(),
        mappings=world["bundle"].mappings,
    )
    create_bundle(db, world["admin"], content, world["clock"])
    sign_in_as(described_page, admin_engine, world["admin"])
    audit(described_page, f"/policy/{content.bundle_id}/rules", "Rules")
    described_page.get_by_label("What should the rule do?").fill(
        "never isolate a domain controller"
    )
    described_page.get_by_role("button", name="Describe a rule").click()
    expect(
        described_page.get_by_text("Deny endpoint.isolate when role is domain_controller")
    ).to_be_visible()
    # The form below is filled, and every field is still the person's to change.
    expect(described_page.get_by_label("Rule identifier")).to_have_value("isolate-never-tier-zero")
    after = read_bundle(db, world["admin"], content.bundle_id, world["clock"]).content
    assert after.ruleset is not None
    assert "isolate-never-tier-zero" not in {rule.id for rule in after.ruleset.rules}
    assert described_page.evaluate("window.__violations") == []
    assert described_page.evaluate(AXE_RUN) == []
