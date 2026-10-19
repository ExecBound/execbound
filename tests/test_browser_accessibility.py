# SPDX-License-Identifier: AGPL-3.0-only
"""Every page that stays server-rendered, in real Chromium: headings, labels, table semantics,
the skip link, phone width and contrast in both schemes.

Since the console took over (#333) those are sign-in, the classic approval page a person still
decides on and the error page. The console has its own pass in `tests/test_browser_console.py`,
which runs axe-core over every route in both schemes at 1280 and 390 px; these are the pages
axe never sees there because they run before a session exists. A plugin's own pages are checked
with that plugin, whose checks read `audit` and `readable` from here (#496).
"""

import secrets
from dataclasses import dataclass

import pytest
from test_browser_surfaces import FITS, sign_in
from test_browser_surfaces import agent_http as agent_http
from test_browser_surfaces import browser_gateway as browser_gateway
from test_browser_surfaces import chromium as chromium
from test_browser_surfaces import human_page as human_page
from test_browser_surfaces import pending as pending_over_http
from test_execution import registry as registry
from test_execution import world as world
from test_protected_path import connector as connector
from test_protected_path import live_provider as live_provider
from test_runtime import runtime as runtime

AUDIT = (
    """
() => {
  const problems = [];
  if (document.documentElement.lang !== 'en') problems.push('lang');
  if (document.querySelectorAll('h1').length !== 1) problems.push('h1 count');
  const first = document.querySelector('a.skip');
  const main = document.getElementById('main');
  if (!first || first.getAttribute('href') !== '#main' || !main) problems.push('skip link');
  const named = (node) => node.getAttribute('aria-label') || node.getAttribute('aria-labelledby');
  for (const control of document.querySelectorAll('input:not([type=hidden]), textarea, select')) {
    const byId = control.id && document.querySelector(`label[for="${control.id}"]`);
    if (!byId && !control.closest('label') && !named(control)) {
      problems.push('unlabelled control ' + (control.name || control.type));
    }
  }
  for (const button of document.querySelectorAll('button')) {
    if (!button.textContent.trim() && !named(button)) problems.push('unnamed button');
  }
  for (const link of document.querySelectorAll('a')) {
    if (!link.textContent.trim() && !named(link)) {
      problems.push('unnamed link ' + link.getAttribute('href'));
    }
  }
  for (const table of document.querySelectorAll('table')) {
    if (!table.querySelector('caption')) problems.push('table without caption');
    for (const th of table.querySelectorAll('th')) {
      if (!th.getAttribute('scope')) problems.push('th without scope');
    }
  }
  // FITS, the browser suite's one sideways check: neither the document nor `main`.
  if (!("""
    + FITS
    + """)()) problems.push('horizontal scroll');
  return problems;
}
"""
)
# AUDIT calls FITS without awaiting it: an async FITS would hand back a promise, which is
# truthy, and the audit would pass every page however wide.
assert not FITS.lstrip().startswith("async")


def audit(page, path):
    response = page.goto(path)
    assert response is not None and response.ok, (
        f"{path}: {response.status if response else 'no response'}"
    )
    page.wait_for_load_state("load")
    problems = page.evaluate(AUDIT)
    assert problems == [], f"{path}: {problems}"
    page.keyboard.press("Tab")
    assert page.evaluate("document.activeElement.getAttribute('href')") == "#main", path


def test_the_pages_that_stay_pass_the_audit_at_phone_width(
    human_page, browser_gateway, agent_http, admin_engine, world
):
    first = pending_over_http(agent_http, world)
    human_page.set_viewport_size({"width": 390, "height": 844})
    audit(human_page, "/login")
    sign_in(human_page, admin_engine, world)
    audit(human_page, f"/approvals/{first['approval_id']}/classic")
    # The error page a replayed decision lands on is one of these pages too.
    replayed = human_page.request.post(
        f"/approvals/{first['approval_id']}/decide",
        form={"csrf": "x", "state": "y", "decision": "APPROVE"},
        headers={"Origin": browser_gateway, "Accept": "text/html"},
    )
    assert replayed.status >= 400 and "<h1>" in replayed.text()
    assert "Error" in replayed.text() and 'href="/login"' in replayed.text()


# Alpha tokens sit over an opaque surface, so every translucent layer is composited over the
# one beneath it before the ratio is taken, which is what the browser draws. The console's own
# pass uses axe-core, which does the same; this is the probe for the pages that stay.
CONTRAST = """
() => {
  const parse = (value) => {
    const match = value.match(/rgba?\\(([^)]+)\\)/);
    if (!match) return null;
    const parts = match[1].split(",").map((part) => parseFloat(part));
    return {r: parts[0], g: parts[1], b: parts[2], a: parts.length > 3 ? parts[3] : 1};
  };
  const luminance = ({r, g, b}) => {
    const channel = (c) => {
      const v = c / 255;
      return v <= 0.03928 ? v / 12.92 : Math.pow((v + 0.055) / 1.055, 2.4);
    };
    return 0.2126 * channel(r) + 0.7152 * channel(g) + 0.0722 * channel(b);
  };
  const body = parse(getComputedStyle(document.body).backgroundColor);
  const background = (node) => {
    const layers = [];
    for (let current = node; current; current = current.parentElement) {
      const colour = parse(getComputedStyle(current).backgroundColor);
      if (colour && colour.a > 0) {
        layers.push(colour);
        if (colour.a >= 1) break;
      }
    }
    let base = layers.length && layers[layers.length - 1].a >= 1 ? layers.pop() : body;
    for (const layer of layers.reverse()) {
      base = {
        r: layer.r * layer.a + base.r * (1 - layer.a),
        g: layer.g * layer.a + base.g * (1 - layer.a),
        b: layer.b * layer.a + base.b * (1 - layer.a),
        a: 1,
      };
    }
    return base;
  };
  const results = [];
  const selector =
    "h1, h2, h3, p, a, button, label, td, th, dt, dd, small, span, li, summary, legend, "
    + "code, time, caption";
  for (const node of document.querySelectorAll(selector)) {
    if (!node.textContent.trim() || node.closest("[hidden]")) continue;
    const box = node.getBoundingClientRect();
    if (box.width === 0 || box.height === 0) continue;
    const style = getComputedStyle(node);
    if (style.visibility === "hidden" || style.display === "none") continue;
    const text = parse(style.color);
    const behind = background(node);
    if (!text || !behind) continue;
    const size = parseFloat(style.fontSize);
    const weight = parseInt(style.fontWeight, 10) || 400;
    const large = size >= 24 || (size >= 18.66 && weight >= 700);
    const hi = Math.max(luminance(text), luminance(behind));
    const lo = Math.min(luminance(text), luminance(behind));
    const ratio = (hi + 0.05) / (lo + 0.05);
    results.push({
      tag:
        node.tagName.toLowerCase() +
        (node.className ? "." + String(node.className).split(" ")[0] : ""),
      text: node.textContent.trim().slice(0, 40),
      ratio: Math.round(ratio * 100) / 100,
      minimum: large ? 3 : 4.5,
    });
  }
  return {samples: results, bodyLuminance: body ? luminance(body) : null};
}
"""


def readable(page, path, scheme, ink=False):
    """Every visible text element on the page meets WCAG 2.2 AA contrast in this scheme.

    `ink` is the one deliberate exception: the live board is a display surface for a wall or
    a screen share and is full ink in both schemes. Its text still has to meet AA against
    that ink, which is what the samples below measure; what it does not do is follow the
    page background, and saying so here is better than letting the board quietly not be
    measured.
    """
    response = page.goto(path)
    assert response is not None and response.ok, (
        f"{path}: {response.status if response else 'no response'}"
    )
    page.wait_for_load_state("load")
    report = page.evaluate(CONTRAST)
    assert report["samples"], f"{path}: nothing to measure"
    if ink:
        # Ink in both schemes, and never lighter than the dark scheme's own page.
        assert report["bodyLuminance"] < 0.05, f"{path}: an ink page is not ink"
    elif scheme == "dark":
        assert report["bodyLuminance"] < 0.05, f"{path}: light body in dark scheme"
    else:
        assert report["bodyLuminance"] > 0.8, f"{path}: dark body in light scheme"
    failing = [s for s in report["samples"] if s["ratio"] < s["minimum"]]
    assert failing == [], f"{path} ({scheme}): {failing}"


@pytest.mark.parametrize("scheme", ["light", "dark"])
def test_every_page_that_stays_reads_in_both_colour_schemes(
    human_page, browser_gateway, agent_http, admin_engine, world, scheme
):
    first = pending_over_http(agent_http, world)
    human_page.emulate_media(color_scheme=scheme)
    human_page.set_viewport_size({"width": 1280, "height": 900})
    readable(human_page, "/login", scheme)
    sign_in(human_page, admin_engine, world)
    classic = f"/approvals/{first['approval_id']}/classic"
    readable(human_page, classic, scheme)
    human_page.set_viewport_size({"width": 390, "height": 844})
    readable(human_page, classic, scheme)


def test_the_challenge_after_a_switch_passes_the_audit_in_both_schemes(
    human_page, browser_gateway, runtime, db, admin_engine, seeded
):
    """The code a workspace switch asks for names the workspace it opens (#678): the page is
    audited at phone width and read in both schemes, as every page that stays is."""
    from sqlalchemy import text
    from test_console_api_step_up import stale
    from test_workspace_switching import member_pair

    from execbound import mfa, workspaces
    from execbound.envelope import KeyRing
    from execbound.resolution.models import SystemClock
    from execbound.surfaces.sessions import load_session

    runtime.clock = SystemClock()
    ring = KeyRing("test", {"test": b"m" * 32})
    grant, current, _, _ = member_pair(db, admin_engine, seeded)
    destination = seeded["tenants"][1]
    seed = mfa.begin_enrollment(db, current, ring)
    mfa.confirm_enrollment(
        db, current, ring, mfa.totp(seed, int(SystemClock().now().timestamp() // 30))
    )
    with admin_engine.begin() as conn:
        conn.execute(
            text("UPDATE execbound.tenants SET name='Team' WHERE tenant_id=:t"), {"t": destination}
        )
    # A code entered within the step-up window would be carried through the switch.
    stale(admin_engine, current.identity.tenant_id, current.session_id)
    switched = workspaces.switch_workspace(
        db, load_session(db, grant.token), grant.account_token, destination
    )
    assert switched.mfa_required
    human_page.context.add_cookies(
        [
            {
                "name": name,
                "value": value,
                "url": browser_gateway,
                "httpOnly": True,
                "sameSite": "Strict",
            }
            for name, value in (("eb_session", switched.token), ("eb_csrf", switched.csrf_token))
        ]
    )
    human_page.set_viewport_size({"width": 390, "height": 844})
    response = human_page.goto("/mfa")
    assert response is not None and response.ok
    human_page.wait_for_load_state("load")
    # The page's own checks; the skip link is not the first stop here, because the challenge
    # puts the cursor in the code field, as the sign-in's challenge always has.
    assert human_page.evaluate(AUDIT) == []
    assert human_page.locator("h1").inner_text() == "Verify to open Team"
    assert human_page.evaluate("document.activeElement.id") == "code"
    for scheme in ("light", "dark"):
        human_page.emulate_media(color_scheme=scheme)
        for width in (1280, 390):
            human_page.set_viewport_size({"width": width, "height": 900})
            readable(human_page, "/mfa", scheme)


@dataclass(frozen=True)
class _Offered:
    """A configured provider as `/login` sees one: a name, a label and a host. Nothing here is
    ever started, so nothing reaches a network."""

    name: str
    label: str
    authorization_origin: str

    def begin(self, flow):  # pragma: no cover - the audit never presses a button
        raise AssertionError("not started")

    def complete(self, code, flow, *, now):  # pragma: no cover
        raise AssertionError("not started")


def test_mi6_the_login_page_with_microsoft_passes_the_audit(chromium, db, runtime):
    """Three buttons, each with its own mark, in both schemes at 1280 and 390 px: axe-core
    finds nothing, the page's own checks pass, every text meets contrast and nothing scrolls
    sideways. The Microsoft mark is static markup, like the others."""
    from test_browser_console import AXE, AXE_RUN
    from test_browser_surfaces import ACTION_TIMEOUT_MS, serve

    from execbound.app import create_app
    from execbound.surfaces.human import HumanConfig
    from execbound.surfaces.tokens import TokenKeys

    if not AXE.exists():
        pytest.fail("axe-core is not installed: run `pnpm install` in console/ first")
    offered = (
        _Offered("google", "Google", "https://accounts.google.com"),
        _Offered("github", "GitHub", "https://github.com"),
        _Offered("microsoft", "Microsoft", "https://login.microsoftonline.com"),
    )

    def app(origin):
        keys = TokenKeys("browser-v1", {"browser-v1": secrets.token_bytes(32)})
        return create_app(db, runtime=runtime, human=HumanConfig(origin, keys, providers=offered))

    with serve(app) as origin, chromium.new_context(base_url=origin) as context:
        context.add_init_script(path=str(AXE))
        page = context.new_page()
        page.set_default_timeout(ACTION_TIMEOUT_MS)
        for scheme in ("light", "dark"):
            page.emulate_media(color_scheme=scheme)
            for width in (1280, 390):
                page.set_viewport_size({"width": width, "height": 900})
                audit(page, "/login")
                where = f"/login ({scheme}, {width} px)"
                # Measured once the fonts have loaded, so a target's size is its final one.
                page.evaluate("document.fonts.ready.then(() => true)")
                assert page.evaluate(AXE_RUN) == [], where
                buttons = page.locator("button.provider")
                assert buttons.all_inner_texts() == [
                    "Continue with Google",
                    "Continue with GitHub",
                    "Continue with Microsoft",
                ], where
                for index in range(3):
                    mark = buttons.nth(index).locator("svg.provider-mark")
                    assert mark.count() == 1, where
                    assert mark.get_attribute("aria-hidden") == "true", where
                    box = buttons.nth(index).bounding_box()
                    assert box is not None and box["height"] >= 44, where
                    assert box["x"] >= 0 and box["x"] + box["width"] <= width, where
                readable(page, "/login", scheme)
