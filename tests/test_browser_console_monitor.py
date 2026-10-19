# SPDX-License-Identifier: AGPL-3.0-only
"""Monitoring in the console in real Chromium (#333).

The six views under one heading, the view in the address so back restores it, collected rows
shown as metadata with none of the fixture's secrets, a finding acknowledged from the page with
the sidebar's count following, the Scout agent views with a hostile display name as text, and
an approver at the address getting the boundary with the shell intact. Since #678 also: a
finding opened by its address, governing from the Monitoring agent page and back, and every
view of the daily queue clean in both schemes at desktop and phone width (MQ9, MQ12). Since
#31 also: Alert settings listing a findings destination and its deliveries, in both schemes
at both widths (MQ11).
"""

import re
from datetime import timedelta

from monitoring_fixtures import HOSTILE_NAME
from playwright.sync_api import expect
from secret_shapes import SLACK
from space_fixtures import default_space, make_space, place
from sqlalchemy import text
from test_browser_console import AXE_RUN, settled, sign_in_as
from test_browser_console import console_gateway as console_gateway
from test_browser_console import console_page as console_page
from test_browser_surfaces import FITS
from test_browser_surfaces import chromium as chromium
from test_console_api_monitoring import seed_agent, seed_tines
from test_execution import registry as registry
from test_execution import world as world
from test_monitoring_acknowledgement import raise_finding, tines_connection_of
from test_protected_path import connector as connector
from test_protected_path import live_provider as live_provider
from test_runtime import runtime as runtime
from test_scout_run import agent, detailed_scenario
from test_tines_collection import SECRETS

from execbound.monitoring import worker
from execbound.monitoring.store import COLLECTION_HEALTH_RULE as RUN
from execbound.notifications import Destination


def clean(page, what):
    settled(page)
    violations = page.evaluate(AXE_RUN)
    assert violations == [], (what, violations)
    assert page.evaluate("window.__violations") == [], what


def test_every_view_shows_collected_metadata_and_a_finding_is_acknowledged_from_the_page(
    console_page, admin_engine, world, db
):
    seed_tines(db, world)
    seed_agent(db, world, scenario=detailed_scenario(agents=[agent(1, displayName=HOSTILE_NAME)]))
    sign_in_as(console_page, admin_engine, world["admin"])
    console_page.goto("/monitor")
    expect(console_page.get_by_role("heading", level=1)).to_have_text("Monitoring")
    assert console_page.url.endswith("/monitor")
    tines = console_page.locator("section").filter(has_text="Synthetic Tines tenant")
    expect(tines.get_by_role("heading", name="Synthetic Tines tenant")).to_be_visible()
    expect(tines.get_by_text("Collecting")).to_be_visible()
    expect(tines.get_by_role("cell", name="ai audit")).to_be_visible()
    expect(tines).to_contain_text("An ordinary action's effect is not an audit record")
    expect(
        console_page.get_by_role("heading", name="Phishing triage <b>source</b>")
    ).to_be_visible()
    assert console_page.locator("b").count() == 0
    clean(console_page, "connections")
    sidebar = console_page.get_by_role("navigation", name="Main")
    pill = sidebar.get_by_role("link", name="Monitoring").locator(".pill")
    expect(pill).to_be_visible()
    open_before = int(pill.inner_text())
    assert open_before >= 1

    tabs = console_page.get_by_role("navigation", name="Monitoring views")
    tabs.get_by_role("link", name="Inventory").click()
    expect(console_page).to_have_url(re.compile(r"/monitor\?view=inventory$"))
    stories = console_page.get_by_role("table", name=re.compile("Discovered stories"))
    expect(stories).to_contain_text("Phishing triage")
    expect(stories).to_contain_text("Instrumented")
    expect(stories).to_contain_text("Outbound actions, no reporting source")
    expect(stories).to_contain_text("Coverage unknown")
    expect(stories).to_contain_text("Disabled in the platform")
    expect(
        console_page.get_by_role("table", name=re.compile("Discovered credentials"))
    ).to_contain_text("okta_api")
    content = console_page.content()
    for secret in SECRETS:
        assert secret not in content, secret
    clean(console_page, "inventory")

    tabs.get_by_role("link", name="External activity").click()
    body = console_page.get_by_role("table", name=re.compile("Recent observations"))
    expect(body).to_contain_text("Collected")
    expect(body).to_contain_text("StoryUpdated")
    expect(body).to_contain_text("Platform-recorded; effect unverified")
    clean(console_page, "activity")

    tabs.get_by_role("link", name="Findings").click()
    expect(console_page).to_have_url(re.compile(r"view=findings$"))
    expect(console_page.get_by_text("Detection profile version 1 active since")).to_be_visible()
    # The queue opens on the open findings, one compact row each; a row opens in place.
    rows = console_page.get_by_role("list", name="Findings").get_by_role("listitem")
    count_before = rows.count()
    assert count_before == open_before
    rows.first.get_by_role("button", name="Show details").click()
    expect(rows.first.get_by_text("Rule", exact=True)).to_be_visible()
    console_page.get_by_role("button", name="Acknowledge finding").click()
    expect(
        console_page.get_by_role("status").filter(has_text="Finding acknowledged.")
    ).to_be_visible()
    # Acknowledged, it leaves the open queue once the server says so.
    expect(rows).to_have_count(count_before - 1)
    if open_before > 1:
        expect(pill).to_have_text(str(open_before - 1))
    else:
        expect(pill).to_have_count(0)
    clean(console_page, "findings")

    # The back button restores the view, because the view is the address.
    console_page.go_back()
    expect(console_page).to_have_url(re.compile(r"view=activity$"))
    expect(
        console_page.get_by_role("table", name=re.compile("Recent observations"))
    ).to_be_visible()

    tabs.get_by_role("link", name="Agents").click()
    expect(
        console_page.get_by_text(
            "counts actors the connections could enumerate, not the actors that exist"
        )
    ).to_be_visible()
    table = console_page.get_by_role("table", name=re.compile("Actors the connections list"))
    expect(table).to_contain_text("payroll")
    expect(table).to_contain_text("Agent identity")
    expect(table).to_contain_text("1 sponsor")
    assert console_page.locator("script:has-text('alert')").count() == 0
    assert "<script>alert" not in console_page.content()
    clean(console_page, "agents")
    table.get_by_role("link", name=re.compile("payroll")).click()
    expect(console_page).to_have_url(re.compile(r"/monitor/agents/[0-9a-f-]{36}$"))
    expect(console_page.get_by_role("heading", level=1)).to_have_text(HOSTILE_NAME)
    expect(console_page.get_by_role("navigation", name="Breadcrumb")).to_contain_text("Monitoring")
    reach = console_page.get_by_role("table", name=re.compile("Every path this agent"))
    expect(reach).to_contain_text("identity.disable")
    expect(reach).to_contain_text("Grant")
    expect(reach).to_contain_text("Inferred")
    expect(reach).to_contain_text("Unknown")
    expect(
        console_page.get_by_text(
            "nothing ExecBound operates stands between this agent and its own credential"
        )
    ).to_be_visible()
    grants = console_page.get_by_role("table", name=re.compile("Directory grants"))
    expect(grants).to_contain_text("allAllowed")
    expect(grants).to_contain_text("The blueprint")
    expect(grants).to_contain_text("Not established")
    expect(console_page.get_by_text("the reviewed catalog cannot explain")).to_be_visible()
    clean(console_page, "agent detail")
    console_page.get_by_role("link", name="Back to monitored agents").click()
    expect(console_page).to_have_url(re.compile(r"/monitor\?view=agents$"))


def test_an_agents_page_is_clean_in_dark_and_at_phone_width(console_page, admin_engine, world, db):
    seed_agent(db, world, scenario=detailed_scenario(agents=[agent(1, displayName=HOSTILE_NAME)]))
    sign_in_as(console_page, admin_engine, world["admin"])
    console_page.goto("/monitor?view=agents")
    table = console_page.get_by_role("table", name=re.compile("Actors the connections list"))
    table.get_by_role("link", name=re.compile("payroll")).click()
    expect(console_page).to_have_url(re.compile(r"/monitor/agents/[0-9a-f-]{36}$"))
    path = "/monitor/agents/" + console_page.url.rsplit("/monitor/agents/", 1)[1]
    for scheme, width, height in (("dark", 1280, 900), ("light", 390, 844), ("dark", 390, 844)):
        console_page.emulate_media(color_scheme=scheme)
        console_page.set_viewport_size({"width": width, "height": height})
        console_page.goto(path)
        expect(console_page.get_by_role("heading", level=1)).to_have_text(HOSTILE_NAME)
        clean(console_page, f"agent detail, {scheme} at {width}")
        assert console_page.evaluate(FITS), (scheme, width)


def test_the_views_are_clean_in_light_at_phone_width_and_an_approver_gets_the_boundary(
    console_page, admin_engine, world, db
):
    seed_tines(db, world)
    console_page.emulate_media(color_scheme="light")
    console_page.set_viewport_size({"width": 390, "height": 844})
    sign_in_as(console_page, admin_engine, world["admin"])
    for view in ("connections", "inventory", "agents", "activity", "findings", "alerts"):
        console_page.goto("/monitor" + ("" if view == "connections" else f"?view={view}"))
        expect(console_page.get_by_role("heading", level=1)).to_have_text("Monitoring")
        current = console_page.get_by_role("navigation", name="Monitoring views").locator(
            "[aria-current=page]"
        )
        expect(current).to_have_count(1)
        clean(console_page, f"{view} on a phone")
        assert console_page.evaluate(FITS), view
    # A view that does not exist is Connections, and the address is left as typed.
    console_page.goto("/monitor?view=nothing")
    expect(console_page.get_by_role("heading", name="Synthetic Tines tenant")).to_be_visible()

    sign_in_as(console_page, admin_engine, world["human"])
    console_page.goto("/monitor")
    expect(console_page.get_by_role("heading", level=1)).to_have_text(
        "You don't have access to this"
    )
    expect(console_page.get_by_role("navigation", name="Main, phone")).to_be_visible()
    assert console_page.evaluate("window.__violations") == []


def fenced(conn, tenant):
    conn.execute(text("SELECT set_config('execbound.tenant_id', :t, true)"), {"t": str(tenant)})


def acknowledged_one(admin_engine, world):
    """The oldest finding acknowledged by the world's administrator, as the store would leave it."""
    tenant = world["admin"].tenant_id
    with admin_engine.begin() as conn:
        fenced(conn, tenant)
        finding = conn.execute(
            text(
                "SELECT finding_id FROM execbound.monitor_findings WHERE tenant_id=:t "
                "ORDER BY created_at, finding_id LIMIT 1"
            ),
            {"t": tenant},
        ).scalar_one()
        conn.execute(
            text(
                "UPDATE execbound.monitor_findings SET acknowledged_at=now(), acknowledged_by=:p "
                "WHERE tenant_id=:t AND finding_id=:f"
            ),
            {"t": tenant, "p": world["admin"].principal_id, "f": finding},
        )
    return str(finding)


def overdue(admin_engine, world):
    """Every connection's last run and sync a day and an hour old: a collector that stopped."""
    tenant = world["admin"].tenant_id
    with admin_engine.begin() as conn:
        fenced(conn, tenant)
        conn.execute(
            text(
                "UPDATE execbound.monitor_connections SET last_run_at=:at, last_sync_at=:at "
                "WHERE tenant_id=:t"
            ),
            {"t": tenant, "at": world["clock"].now() - timedelta(hours=25)},
        )


def test_mq12_a_finding_link_opens_it_pinned_and_expanded(console_page, admin_engine, world, db):
    seed_tines(db, world)
    finding = acknowledged_one(admin_engine, world)
    sign_in_as(console_page, admin_engine, world["admin"])
    console_page.goto(f"/monitor?view=findings&open={finding}")
    pinned = console_page.get_by_role("region", name="Opened from a link")
    expect(pinned).to_be_visible()
    expect(pinned.get_by_role("button", name="Hide details")).to_have_attribute(
        "aria-expanded", "true"
    )
    expect(pinned).to_contain_text("Acknowledged")
    clean(console_page, "a finding opened by link")
    chips = console_page.get_by_role("group", name="Findings to show")
    chips.get_by_role("button", name="All").click()
    expect(console_page).to_have_url(re.compile(r"state=all"))
    listed = console_page.get_by_role("list", name="Findings")
    expect(listed.get_by_text("Acknowledged", exact=True).first).to_be_visible()
    chips.get_by_role("button", name=re.compile(r"^Open")).click()
    expect(console_page).to_have_url(re.compile(r"state=open"))
    assert f"open={finding}" not in console_page.url
    assert console_page.evaluate("window.__violations") == []


def test_mq9_govern_from_the_monitoring_agent_page(console_page, admin_engine, world, db):
    _, agent_id = seed_agent(db, world)
    sign_in_as(console_page, admin_engine, world["admin"])
    console_page.goto(f"/monitor/agents/{agent_id}")
    card = console_page.locator("section").filter(
        has=console_page.get_by_role("heading", name="Govern this agent")
    )
    expect(card.get_by_text("Operator commands")).to_be_visible()
    card.get_by_role("link", name="Govern this agent").click()
    expect(console_page).to_have_url(re.compile(rf"/agents/{agent_id}$"))
    # The agent page offers the govern form; it is not submitted here, because governing
    # issues a key, which the directory's own Chromium pass covers.
    expect(console_page.get_by_role("button", name="Govern this agent")).to_be_visible()
    # A discovered agent's Overview carries what the source lists, with the way back (#678).
    console_page.get_by_role("link", name="This agent's Monitoring page").click()
    expect(console_page).to_have_url(re.compile(rf"/monitor/agents/{agent_id}$"))
    assert console_page.evaluate("window.__violations") == []


def test_mq12_monitoring_is_clean_in_both_schemes_at_1280_and_390(
    console_page, admin_engine, world, db
):
    seed_tines(db, world)
    _, agent_id = seed_agent(db, world)
    finding = acknowledged_one(admin_engine, world)
    overdue(admin_engine, world)
    sign_in_as(console_page, admin_engine, world["admin"])
    pages = [
        (f"/monitor?view=findings&open={finding}", "region", "Opened from a link"),
        ("/monitor?focus=quiet", "heading", "Synthetic Tines tenant"),
        ("/monitor?view=inventory&story=%224001%22", "table", "Discovered stories"),
        ("/monitor?view=alerts", "heading", "Where findings appear"),
        (f"/monitor/agents/{agent_id}", "heading", "Govern this agent"),
    ]
    for scheme in ("light", "dark"):
        for width, height in ((1280, 900), (390, 844)):
            console_page.emulate_media(color_scheme=scheme)
            console_page.set_viewport_size({"width": width, "height": height})
            for path, role, name in pages:
                console_page.goto(path)
                expect(console_page.get_by_role(role, name=re.compile(name)).first).to_be_visible()
                if "focus=quiet" in path:
                    marked = console_page.locator(".monitor-marked")
                    expect(marked).to_have_count(1)
                    expect(marked).to_contain_text("Collection overdue")
                if "story=" in path:
                    expect(console_page.locator("tr[aria-current='true']")).to_have_count(1)
                if "alerts" in path:
                    # Every delivery is listed outside the receiver, which opens to be audited.
                    expect(
                        console_page.get_by_role("table", name=re.compile("Finding deliveries"))
                    ).to_be_visible()
                    console_page.get_by_text("Local test receiver").click()
                    expect(
                        console_page.locator("details", has_text="Local test receiver")
                    ).to_have_attribute("open", "")
                what = f"{path} in {scheme} at {width}"
                clean(console_page, what)
                # Neither the document nor `main` scrolls sideways (#31).
                assert console_page.evaluate(FITS), what


def open_in(admin_engine, tenant, space):
    """How many open findings a space holds, as the sidebar counts them for a session in it."""
    with admin_engine.begin() as conn:
        fenced(conn, tenant)
        return conn.execute(
            text(
                "SELECT count(*) FROM execbound.monitor_findings "
                "WHERE tenant_id=:t AND space_id=:s AND acknowledged_at IS NULL"
            ),
            {"t": tenant, "s": space},
        ).scalar_one()


def more_findings(db, admin_engine, world, count):
    """`count` more open collection findings on the seeded Tines connection."""
    tenant, clock = world["admin"].tenant_id, world["clock"]
    connection = tines_connection_of(admin_engine, tenant)
    for index in range(count):
        raise_finding(db, tenant, clock.now(), RUN, f"Bulk finding {index}", connection=connection)


def test_mq16_bulk_acknowledgement_confirms_and_reports_each(console_page, admin_engine, world, db):
    seed_tines(db, world)
    more_findings(db, admin_engine, world, 3)
    tenant = world["admin"].tenant_id
    sign_in_as(console_page, admin_engine, world["admin"])
    console_page.goto("/monitor?view=findings")
    rows = console_page.get_by_role("list", name="Findings").get_by_role("listitem")
    expect(rows.first).to_be_visible()
    first, second = rows.nth(0), rows.nth(1)
    titles = [row.locator(".finding-title strong").inner_text() for row in (first, second)]
    # The disclosure names the finding it controls.
    controls = second.get_by_role("button", name="Show details").get_attribute("aria-controls")
    assert controls is not None and controls.startswith("finding-")
    moved = controls.removeprefix("finding-")
    first.get_by_role("checkbox").check()
    second.get_by_role("checkbox").check()
    ask = console_page.get_by_role("button", name="Acknowledge selected (2)")
    expect(ask).to_be_visible()

    # Meanwhile the second finding moves to another space, and this session looks at the
    # default one: the page still lists it, and the server answers it as not there.
    with admin_engine.begin() as conn:
        fenced(conn, tenant)
        own = default_space(conn, tenant)
        other = make_space(conn, tenant, "Customer B")
        place(conn, tenant, "monitor_findings", "finding_id", moved, other)
        conn.execute(
            text(
                "UPDATE execbound.human_sessions SET current_space_id=:s "
                "WHERE tenant_id=:t AND principal_id=:p"
            ),
            {"s": own, "t": tenant, "p": world["admin"].principal_id},
        )
    open_here = open_in(admin_engine, tenant, own)
    assert open_here >= 2

    ask.click()
    expect(
        console_page.get_by_text("Acknowledge 2 findings? An acknowledgement cannot be undone.")
    ).to_be_visible()
    confirm = console_page.get_by_role("button", name="Acknowledge 2 findings")
    expect(confirm).to_be_focused()
    confirm.click()
    results = console_page.get_by_role("status", name="Acknowledgement results")
    expect(results).to_contain_text(
        "Acknowledged 1. 1 is not in the space you are viewing or no longer exists."
    )
    # The seeded findings share a title, so the two rows may too: count each title.
    for title in set(titles):
        expect(results.get_by_text(title, exact=True)).to_have_count(titles.count(title))
    pill = (
        console_page.get_by_role("navigation", name="Main")
        .get_by_role("link", name=re.compile("Monitoring"))
        .locator(".pill")
    )
    expect(pill).to_have_text(str(open_here - 1))
    assert open_in(admin_engine, tenant, own) == open_here - 1
    assert open_in(admin_engine, tenant, other) == 1
    clean(console_page, "bulk results")


def test_mq16_bulk_views_are_clean_in_both_schemes_at_1280_and_390(
    console_page, admin_engine, world, db
):
    seed_tines(db, world)
    more_findings(db, admin_engine, world, 6)
    sign_in_as(console_page, admin_engine, world["admin"])
    for scheme in ("light", "dark"):
        for width, height in ((1280, 900), (390, 844)):
            console_page.emulate_media(color_scheme=scheme)
            console_page.set_viewport_size({"width": width, "height": height})
            console_page.goto("/monitor?view=findings")
            rows = console_page.get_by_role("list", name="Findings").get_by_role("listitem")
            rows.first.get_by_role("checkbox").check()
            console_page.get_by_role("button", name="Acknowledge selected (1)").click()
            expect(console_page.get_by_role("button", name="Acknowledge 1 finding")).to_be_focused()
            for what in ("confirmation", "results"):
                if what == "results":
                    console_page.get_by_role("button", name="Acknowledge 1 finding").click()
                    expect(
                        console_page.get_by_role("status", name="Acknowledgement results")
                    ).to_contain_text("Acknowledged 1.")
                label = f"bulk {what} in {scheme} at {width}"
                clean(console_page, label)
                assert console_page.evaluate(FITS), label


RIVAL = "Rival Holdings"
MAILBOX = "soc-findings@example.com"
RIVAL_URL, RIVAL_SECRET = "https://alerts.example.net/execbound/rival", "r1v4l-" + "q" * 32
# The Slack webhook's secret, its path's last segment, which no page may show.
SLACK_SECRET = SLACK.rsplit("/", 1)[1]


def alert_destinations(admin_engine, world, seeded, slack):
    """Alert settings with three findings destinations: `slack` for every Space, an email
    destination for this workspace's default Space and a Space of another workspace, and a
    webhook for that other Space alone, which receives no findings (#31). Returns the
    destinations, the other workspace's Space and the default Space's name."""
    tenant = world["admin"].tenant_id
    elsewhere = next(other for other in seeded["tenants"] if other != tenant)
    with admin_engine.begin() as conn:
        fenced(conn, elsewhere)
        rival = make_space(conn, elsewhere, RIVAL)
    with admin_engine.begin() as conn:
        fenced(conn, tenant)
        own = default_space(conn, tenant)
        name = conn.execute(
            text("SELECT name FROM execbound.spaces WHERE tenant_id = :t AND space_id = :s"),
            {"t": tenant, "s": own},
        ).scalar_one()
    findings = frozenset({"findings"})
    destinations = (
        slack,
        Destination(
            "soc-email",
            tenant,
            "",
            "",
            kind="email",
            to=MAILBOX,
            classes=findings,
            spaces=frozenset({own, rival}),
        ),
        Destination(
            "rival-only",
            tenant,
            RIVAL_URL,
            RIVAL_SECRET,
            classes=findings,
            spaces=frozenset({rival}),
        ),
    )
    return destinations, rival, name


def destinations_listed(admin_engine, tenant):
    """Each listed delivery's destination as the delivery table names it, sorted, since the
    comparison is of the sorted cells: every row but a routed intent, an intent not routed named
    "Not routed"."""
    with admin_engine.begin() as conn:
        fenced(conn, tenant)
        listed = conn.execute(
            text(
                "SELECT destination_id FROM execbound.monitor_deliveries "
                "WHERE tenant_id = :t AND state <> 'ROUTED'"
            ),
            {"t": tenant},
        ).scalars()
        return sorted(destination or "Not routed" for destination in listed)


def check_alert_settings(page, *, every, rival, own, listed):
    """What Alert settings shows in either edition for `alert_destinations`: each destination
    by id, host, rules and Spaces, the destination for another workspace's Space alone saying
    it receives no findings, every delivery naming its destination and the intent routed after
    the others "Not routed"; never an address, a secret, nor that Space's name or identifier."""
    destinations = page.get_by_role("table", name=re.compile("Findings destinations"))
    expect(destinations).to_contain_text("rival-only")
    # Rendered, so the page is checked for what it must never hold before anything else.
    content = page.content()
    for private in (
        SLACK_SECRET,
        "/services/",
        MAILBOX,
        RIVAL_SECRET,
        "/execbound/rival",
        RIVAL,
        str(rival),
    ):
        assert private not in content, private
    expect(destinations).to_contain_text("soc-slack")
    expect(destinations).to_contain_text("hooks.slack.com")
    expect(destinations).to_contain_text(every)
    slack, email, alone = (
        destinations.get_by_role("row").filter(has_text=item)
        for item in ("soc-slack", "soc-email", "rival-only")
    )
    expect(slack).to_contain_text("Every Space")
    expect(email).to_contain_text(own)
    expect(email).to_contain_text("1 unknown Space ID")
    expect(email).not_to_contain_text("Receives no findings")
    expect(alone).to_contain_text("alerts.example.net")
    expect(alone).to_contain_text("1 unknown Space ID")
    expect(alone.get_by_text("Receives no findings")).to_be_visible()
    deliveries = page.get_by_role("table", name=re.compile("Finding deliveries"))
    named = deliveries.locator('td[data-label="Destination"]')
    expect(named.filter(has_text="Not routed")).to_have_count(1)
    expect(named.filter(has_text="soc-slack").first).to_be_visible()
    assert sorted(named.all_inner_texts()) == listed


def test_mq11_alert_settings_lists_destinations_and_deliveries_in_both_schemes(
    console_page, admin_engine, world, db, runtime, seeded
):
    """MQ11 in the core build (#31): findings destinations and their deliveries on Alert
    settings, one for another workspace's Space alone that receives no findings and an intent
    not routed among them, with no address, secret or other workspace's Space in the page,
    clean under axe in light and dark at 1280 and 390 px with no policy violation and no
    sideways scroll. The hosted half is the hosted service's own browser test."""
    seed_tines(db, world)
    tenant = world["admin"].tenant_id
    slack = Destination(
        "soc-slack",
        tenant,
        SLACK,
        "",
        kind="slack",
        classes=frozenset({"approvals", "findings"}),
        rules=frozenset({"sensitive-action.v2", "monitored-path-change.v1"}),
    )
    runtime.notifications, rival, own = alert_destinations(admin_engine, world, seeded, slack)
    worker.route_findings(db, world["admin"], runtime.notifications, clock=runtime.clock)
    # Raised after the router ran, so it waits unrouted.
    more_findings(db, admin_engine, world, 1)
    listed = destinations_listed(admin_engine, tenant)
    sign_in_as(console_page, admin_engine, world["admin"])
    for scheme in ("light", "dark"):
        for width, height in ((1280, 900), (390, 844)):
            console_page.emulate_media(color_scheme=scheme)
            console_page.set_viewport_size({"width": width, "height": height})
            console_page.goto("/monitor?view=alerts")
            check_alert_settings(
                console_page,
                every="monitored-path-change.v1, sensitive-action.v2",
                rival=rival,
                own=own,
                listed=listed,
            )
            what = f"alert settings in {scheme} at {width}"
            clean(console_page, what)
            assert console_page.evaluate(FITS), what
