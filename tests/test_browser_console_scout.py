# SPDX-License-Identifier: AGPL-3.0-only
"""Scout's to-do list and the synthetic directory in real Chromium (#355, step 4): SR29 to SR31.

The synthetic directory added and collected, then labelled on every page it touches: Connections,
Monitoring's Agents, the agent page, Findings, Agent connections and an actor's page there, each
clean of accessibility violations and fitting at desktop and phone width in both schemes, with
neither Govern nor Bind offered for its actor. The Agents view in its order,
an actor's open paths accepted from its row with a reason and a period and shown as accepted,
and a Tines tenant's egress recorded from its connection's card.
"""

import re
from datetime import timedelta

import httpx
from playwright.sync_api import expect
from test_browser_console import AXE_RUN, FITS, settled, sign_in_as
from test_browser_console import console_gateway as console_gateway
from test_browser_console import console_page as console_page
from test_browser_surfaces import chromium as chromium
from test_console_api_monitoring import seed_tines
from test_execution import registry as registry
from test_execution import world as world
from test_monitoring_store import FixedClock
from test_protected_path import connector as connector
from test_protected_path import live_provider as live_provider
from test_runtime import runtime as runtime

from execbound.monitoring import graph, synthetic
from execbound.monitoring import store as monitor_store
from execbound.monitoring.models import DetectionProfile
from execbound.surfaces.sessions import issue_session, load_session


def clean(page, what):
    settled(page)
    violations = page.evaluate(AXE_RUN)
    assert violations == [], (what, violations)
    assert page.evaluate("window.__violations") == [], what


def synthetic_workspace(db, world):
    """The world's workspace with a profile and its synthetic directory collected twice, an hour
    apart, on a clock of the collections' own."""
    admin, clock = world["admin"], world["clock"]
    monitor_store.set_profile(
        db,
        admin,
        DetectionProfile(
            sensitive_actions=("identity.disable", "identity.revoke_sessions"),
            restricted_targets=(),
        ),
        clock=clock,
    )
    session = load_session(db, issue_session(db, admin, clock=clock).token, clock=clock)
    connection_id = synthetic.add(db, session, clock=clock)
    collecting = FixedClock(clock.now())
    for index in range(2):
        if index:
            collecting.value += timedelta(hours=1)
        with httpx.Client() as unused:
            graph.run(db, admin, connection_id=connection_id, client=unused, clock=collecting)
    return connection_id


def test_sr31_the_synthetic_directory_is_labelled_on_every_page_it_touches(
    console_page, admin_engine, world, db
):
    synthetic_workspace(db, world)
    sign_in_as(console_page, admin_engine, world["admin"])
    console_page.goto("/monitor?view=agents")
    table = console_page.get_by_role("table", name=re.compile("Actors the connections list"))
    expect(table).to_contain_text("Synthetic offboarding automation")
    table.get_by_role("link", name="Synthetic offboarding automation").click()
    expect(console_page).to_have_url(re.compile(r"/monitor/agents/[0-9a-f-]{36}$"))
    agent_id = console_page.url.rsplit("/monitor/agents/", 1)[1]
    detail = "/monitor/agents/" + agent_id
    connections = "/agents/" + agent_id
    findings = "/monitor?view=findings&state=all"
    pages = [
        ("/monitor", re.compile("Nothing in it is real")),
        ("/monitor?view=agents", re.compile("exists\\s+only in ExecBound")),
        (detail, re.compile("comes from the synthetic directory")),
        (findings, None),
        ("/agents", re.compile("Synthetic directory")),
        (connections, re.compile("synthetic directory, which exists only in ExecBound")),
    ]
    for scheme, width, height in (("light", 1280, 900), ("dark", 390, 844)):
        console_page.emulate_media(color_scheme=scheme)
        console_page.set_viewport_size({"width": width, "height": height})
        for path, label in pages:
            console_page.goto(path)
            if label is None:
                # Each finding's own badge, not the connection line an inventory summary carries,
                # which names the connection's label whatever the badge does.
                rows = console_page.locator(".finding-meta")
                expect(rows.first).to_be_visible()
                badges = rows.locator(".badge").filter(has_text=re.compile("^Synthetic directory$"))
                expect(badges).to_have_count(rows.count())
            else:
                # A phone lays a table out as cards, and hides the cells it restates.
                expect(
                    console_page.get_by_text(label).locator("visible=true").first
                ).to_be_visible()
            what = f"{path} in {scheme} at {width}"
            clean(console_page, what)
            assert console_page.evaluate(FITS), what
    # Connecting a real directory waits until it is removed, and none of its actors is governed
    # or bound, on its Monitoring page or on Agent connections.
    console_page.goto("/monitor")
    expect(console_page.get_by_text("Remove it before connecting Microsoft Entra")).to_be_visible()
    expect(console_page.get_by_role("button", name="Add a synthetic directory")).to_have_count(0)
    console_page.goto(detail)
    expect(console_page.get_by_role("heading", name="Govern this agent")).to_have_count(0)
    console_page.goto(connections)
    source = console_page.get_by_text("Synthetic directory · classic service principal")
    expect(source).to_be_visible()
    expect(console_page.get_by_role("button", name="Govern this agent")).to_have_count(0)
    expect(console_page.get_by_role("button", name="Bind")).to_have_count(0)


def test_sr30_an_actor_s_open_paths_are_accepted_from_its_row(
    console_page, admin_engine, world, db
):
    synthetic_workspace(db, world)
    sign_in_as(console_page, admin_engine, world["admin"])
    console_page.goto("/monitor?view=agents")
    table = console_page.get_by_role("table", name=re.compile("Actors the connections list"))
    # What did something comes first.
    first = table.locator("tbody tr").first
    expect(first).to_contain_text("Synthetic offboarding automation")
    expect(first).to_contain_text("Anthropic, seen in its sign-ins")
    row = table.locator("tbody tr").filter(has_text="Synthetic reporting script")
    expect(row).to_contain_text("Unattributed")
    row.get_by_role("button", name="Accept").click()
    dialog = console_page.get_by_role("dialog")
    expect(dialog.get_by_role("checkbox")).to_have_count(1)
    dialog.get_by_label("Reason").select_option("GOVERNANCE_PLANNED")
    dialog.get_by_label("Accept for").select_option("30")
    clean(console_page, "the Accept dialog")
    dialog.get_by_role("button", name="Accept 1 path").click()
    expect(dialog).to_have_count(0)
    expect(row).to_contain_text("1 accepted path")
    expect(row.get_by_role("button", name="Accept")).to_have_count(0)


def test_sr27_a_tines_tenant_s_egress_is_recorded_from_its_card(
    console_page, admin_engine, world, db
):
    seed_tines(db, world)
    sign_in_as(console_page, admin_engine, world["admin"])
    console_page.goto("/monitor")
    card = console_page.locator("section").filter(
        has=console_page.get_by_role("heading", name="Synthetic Tines tenant")
    )
    expect(card).to_contain_text("None recorded")
    card.get_by_role("button", name="Record egress").click()
    dialog = console_page.get_by_role("dialog")
    dialog.get_by_label("Egress addresses").fill("18.200.10.20\n18.200.10.21")
    clean(console_page, "the egress dialog")
    dialog.get_by_role("button", name="Record addresses").click()
    expect(dialog).to_have_count(0)
    expect(card).to_contain_text("18.200.10.20, 18.200.10.21")
