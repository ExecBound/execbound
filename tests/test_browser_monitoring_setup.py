# SPDX-License-Identifier: AGPL-3.0-only
"""A newcomer can configure a collector and distinguish registration from reporting."""

from playwright.sync_api import expect
from test_browser_console import console_gateway as console_gateway
from test_browser_console import console_page as console_page
from test_browser_console import sign_in_as
from test_browser_console_monitor import clean
from test_browser_surfaces import chromium as chromium
from test_console_api_monitoring import seed_tines
from test_console_api_monitoring_setup import register
from test_execution import registry as registry
from test_execution import world as world
from test_protected_path import connector as connector
from test_protected_path import live_provider as live_provider
from test_runtime import runtime as runtime


def test_empty_setup_generates_commands_and_registration_stays_awaiting_sync(
    console_page, db, admin_engine, world
):
    sign_in_as(console_page, admin_engine, world["admin"])
    console_page.goto("/monitor")
    console_page.get_by_role("button", name="Connect a source").click()
    dialog = console_page.get_by_role("dialog", name="Connect a source")
    expect(dialog).to_contain_text("Customer-operated collector")
    dialog.get_by_role("button", name="Continue").click()
    expect(dialog).to_contain_text("minimum access")
    dialog.get_by_role("button", name="Continue").click()
    expect(dialog.get_by_label("Registration command")).to_contain_text("create-connection")
    expect(dialog.get_by_label("Environment template")).to_contain_text("REPLACE_WITH_READ_ONLY")
    connection = register(db, world)
    dialog.get_by_role("textbox", name="Connection ID returned by registration").fill(
        str(connection)
    )
    expect(dialog.get_by_label("Collection command")).to_contain_text(str(connection))
    dialog.get_by_role("button", name="Verify connection").click()
    dialog.get_by_role("button", name="Check connection").click()
    expect(dialog).to_contain_text("Registered — awaiting first sync")
    expect(dialog).not_to_contain_text("Reporting — first sync verified")
    clean(console_page, "monitoring setup awaiting sync")
    dialog.get_by_role("button", name="Done").click()
    expect(dialog).not_to_be_visible()


def test_existing_connection_reports_only_the_persisted_sync_and_keeps_connect_available(
    console_page, db, admin_engine, world
):
    seed_tines(db, world)
    sign_in_as(console_page, admin_engine, world["admin"])
    console_page.set_viewport_size({"width": 390, "height": 844})
    console_page.goto("/monitor")
    expect(console_page.get_by_role("button", name="Connect a source")).to_be_visible()
    console_page.get_by_role("button", name="Verify connection").click()
    dialog = console_page.get_by_role("dialog", name="Connect a source")
    dialog.get_by_role("button", name="Check connection").click()
    expect(dialog).to_contain_text("Reporting — first sync verified")
    expect(dialog).to_contain_text("does not prove complete coverage")
    clean(console_page, "monitoring setup reporting on a phone")
    assert console_page.evaluate("document.documentElement.scrollWidth <= window.innerWidth")
