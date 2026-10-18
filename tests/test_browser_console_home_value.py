# SPDX-License-Identifier: AGPL-3.0-only
"""Home's value card, the report, a lapsed record, a rule link, the board and the weekly
summary card in real Chromium (#678): HV16.

In light and dark, at 1280 and at 390 pixels, axe finds no WCAG 2.2 AA violation, the browser
reports no policy or Trusted Types violation and nothing scrolls sideways on Home with the card,
`/report`, a lapsed record's drawer, the Live board with a lapsed shot and My account with the
summary card. Once, at full width: a card number opens Activity with its outcome pinned and the
counted rows listed; the findings row opens the findings; the lapsed record reads lapsed; a
denial's rule link opens the rules page with that rule marked and in view; the CSV is an
attachment; switching the summary on shows "On" only from the server's answer; and an agent
labelled with markup renders as its characters.
"""

import re
from datetime import timedelta

from playwright.sync_api import expect
from sqlalchemy import text
from test_browser_console import AXE_RUN, settled, sign_in_as
from test_browser_console import console_gateway as console_gateway
from test_browser_console import console_page as console_page
from test_browser_surfaces import chromium as chromium
from test_execution import registry as registry
from test_execution import world as world
from test_home_value import (
    allowed_requests,
    deny_directly,
    held_requests,
    observe,
    ruleset_denial,
)
from test_protected_path import connector as connector
from test_protected_path import live_provider as live_provider
from test_runtime import runtime as runtime
from test_spaces_isolation import seed_monitoring

from execbound.transports import MailConfig

MARKUP = "<img src=x onerror=alert(1)>"


def clean(page, where: str) -> None:
    settled(page)
    assert page.evaluate(AXE_RUN) == [], where
    assert page.evaluate("window.__violations") == [], where
    assert page.evaluate("document.documentElement.scrollWidth <= window.innerWidth"), (
        f"{where} scrolls sideways"
    )


def seed(db, runtime, admin_engine, world):
    """A lapsed approval, a denial under rules, a limit and a busy refusal, an observed
    request, an open finding, an agent labelled with markup and an administrator's address."""
    tenant = world["identity"].tenant_id
    bundle, refused = ruleset_denial(db, runtime, admin_engine, world)
    [lapsed] = held_requests(db, admin_engine, world, 1)
    now = world["clock"].now()
    with admin_engine.begin() as conn:
        conn.execute(
            text(
                "UPDATE execbound.approvals SET created_at=:c, expires_at=:e "
                "WHERE tenant_id=:t AND execution_id=:x"
            ),
            {
                "t": tenant,
                "x": lapsed.execution_id,
                "c": now - timedelta(minutes=10),
                "e": now - timedelta(minutes=1),
            },
        )
        conn.execute(
            text("UPDATE execbound.principals SET label=:l WHERE tenant_id=:t AND principal_id=:p"),
            {"t": tenant, "p": world["identity"].principal_id, "l": MARKUP},
        )
        conn.execute(
            text(
                "UPDATE execbound.principals SET email='admin@example.org' "
                "WHERE tenant_id=:t AND principal_id=:p"
            ),
            {"t": tenant, "p": world["admin"].principal_id},
        )
        conn.execute(text("SELECT set_config('execbound.tenant_id', :t, true)"), {"t": str(tenant)})
        space = conn.execute(
            text("SELECT space_id FROM execbound.spaces WHERE tenant_id=:t"), {"t": tenant}
        ).scalar_one()
        seed_monitoring(conn, tenant, space, world["admin"].principal_id)
    limit, busy, watched = allowed_requests(db, admin_engine, world, 3)
    deny_directly(admin_engine, world, limit.execution_id, {"reasons": ["HARD_LIMIT:r1"]})
    deny_directly(admin_engine, world, busy.execution_id, {"reason": "RESOURCE_BUSY"})
    observe(admin_engine, world, watched.execution_id, "DENY", ["NOT_AUTHORIZED"])
    runtime.mail = MailConfig(
        "localhost",
        2525,
        "tls",
        "relay-user",
        "relay-password-0123456789",
        "summaries@example.com",
        weekly_summary=True,
    )
    return {"bundle": bundle, "refused": refused, "lapsed": lapsed}


def test_hv16_home_the_report_a_lapse_a_rule_the_board_and_the_summary(
    console_page, admin_engine, world, db, runtime, live_provider
):
    seeded = seed(db, runtime, admin_engine, world)
    page = console_page
    sign_in_as(page, admin_engine, world["admin"])

    page.goto("/")
    card = page.locator("section.value-card")
    expect(card.get_by_role("heading", name="What ExecBound did")).to_be_visible()
    observe_section = card.locator("section.value-observe")
    expect(observe_section).to_contain_text("Observe mode: nothing was enforced")
    expect(card.get_by_text("Counts of what ExecBound recorded.", exact=False)).to_be_visible()
    findings = page.locator("li", has_text="open finding").get_by_role("link", name="Review")
    expect(findings).to_have_attribute("href", "/monitor?view=findings")
    # The markup label is its characters, never an element.
    assert page.locator("img[src='x']").count() == 0
    card.get_by_role("link", name="1 refused by an impact limit, open in Activity").click()
    expect(page).to_have_url(re.compile(r"/activity\?.*outcome=refused_limit"))
    expect(page.get_by_role("button", name="Remove the outcome filter")).to_contain_text(
        "Refused by an impact limit"
    )
    table = page.get_by_role("table", name=re.compile("Activity"))
    expect(table.get_by_role("row")).to_have_count(2)
    expect(table).to_contain_text(MARKUP)

    page.goto(f"/?open={seeded['lapsed'].execution_id}")
    drawer = page.get_by_role("dialog")
    expect(drawer).to_contain_text("Lapsed at")
    expect(drawer).to_contain_text("Approval lapsed")
    page.keyboard.press("Escape")

    page.goto(f"/?open={seeded['refused'].execution_id}")
    rule = page.get_by_role("dialog").get_by_role(
        "link", name=re.compile("Rule isolate-never-domain-controller in Policy version")
    )
    expect(rule).to_be_visible()
    rule.click()
    expect(page).to_have_url(re.compile(r"/rules\?rule=isolate-never-domain-controller$"))
    marked = page.locator("li[aria-current='true']")
    expect(marked).to_have_count(1)
    expect(marked).to_contain_text("isolate-never-domain-controller")
    expect(marked).to_be_in_viewport()

    page.goto("/report")
    expect(page.get_by_role("heading", level=1)).to_have_text("What ExecBound did")
    # The observe section sits straight under the page's h1 here, so its heading is an h2.
    expect(
        page.get_by_role("heading", level=2, name="Observe mode: nothing was enforced")
    ).to_be_visible()
    href = page.get_by_role("link", name="Download CSV").get_attribute("href") or ""
    assert href.startswith("/api/console/v1/report.csv?")
    download = page.request.get(href)
    assert download.status == 200
    assert download.headers["content-disposition"].startswith("attachment;")
    assert download.headers["content-type"].startswith("text/csv")

    page.goto("/board")
    expect(page.get_by_text("lapsed before a decision").first).to_be_visible()

    page.goto("/settings")
    summary = page.locator("section", has=page.get_by_role("heading", name="Weekly summary"))
    expect(summary).to_contain_text("admin@example.org")
    expect(summary).to_contain_text("Off")
    with page.expect_response(re.compile(r"/settings/weekly-summary$")) as answered:
        summary.get_by_role("button", name="Turn on the weekly summary").click()
    assert answered.value.status == 200
    expect(summary).to_contain_text("On")

    # Each page is audited once its data has rendered, not while it still reads "Loading":
    # the report's observe heading, for one, exists only after the report arrives.
    pages = [
        ("/", "home", lambda: page.locator("section.value-card section.value-observe")),
        ("/report", "report", lambda: page.locator("section.value-observe")),
        # The drawer over Activity: Home's day headings under a modal backdrop are the
        # foundation's to audit, and the drawer's own content is the same on either page.
        (
            f"/activity?open={seeded['lapsed'].execution_id}",
            "lapsed drawer",
            lambda: page.get_by_role("dialog").get_by_text("Lapsed at", exact=False).first,
        ),
        ("/board", "board", lambda: page.get_by_text("lapsed before a decision").first),
        (
            "/settings",
            "my account",
            lambda: page.get_by_role("heading", name="Weekly summary", exact=True),
        ),
    ]
    for scheme in ("dark", "light"):
        page.emulate_media(color_scheme=scheme)
        for width, height in ((1280, 900), (390, 844)):
            page.set_viewport_size({"width": width, "height": height})
            for path, name, ready in pages:
                page.goto(path)
                expect(ready()).to_be_visible()
                clean(page, f"{name} at {width} in {scheme}")
