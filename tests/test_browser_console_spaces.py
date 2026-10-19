# SPDX-License-Identifier: AGPL-3.0-only
"""SP12: the console's spaces in real Chromium.

The switcher reads the **space over the tenant** in both colour schemes at 1280 and at 390
pixels, axe-core finds no violation of WCAG 2.2 AA on it or on its dialogs, and the browser
reports zero policy or Trusted Types violations. The popover is reachable and dismissable by
the keyboard alone. A switch clears the query cache and asks every read again, rather than
leaving one space's rows rendered under another space's name. An approval link opens in the
space that owns the approval, whatever the session was looking at, and so does the one the
Activity drawer offers for a record of another space, which it offers to a person who only
reads the space on screen but decides approvals in another. And a space a tenant named
with markup is rendered as text, like every other string that came from a person.

Nothing here describes a space as isolation, because it is not one: the tenant is the one
security boundary and a space is ownership and view inside it.
"""

import re

import httpx
import pytest
from playwright.sync_api import expect
from space_fixtures import default_space, make_space, seat
from sqlalchemy import text
from test_browser_console import AXE_RUN, audit, settled, sign_in_as
from test_browser_console import console_gateway as console_gateway
from test_browser_console import console_page as console_page
from test_browser_surfaces import FITS
from test_browser_surfaces import chromium as chromium
from test_execution import registry as registry
from test_execution import request
from test_execution import world as world
from test_protected_path import connector as connector
from test_protected_path import live_provider as live_provider
from test_runtime import runtime as runtime

from execbound import access_control as access

# A tenant may call a space anything; the console renders the name and never parses it.
SOUTHBANK = "Southbank <b>Ltd</b>"
API = "/api/console/v1/"


@pytest.fixture
def two_spaces(admin_engine, world):
    """A second space, with the approver seated in both and the administrator in neither.

    An administrator with no membership at all is a *tenant administrator*, which is what
    keeps "All spaces" theirs; the approver belongs to two, which is what lets a record of
    one be opened while the session is looking at the other.
    """
    tenant = world["identity"].tenant_id
    with admin_engine.begin() as conn:
        first = default_space(conn, tenant)
        second = make_space(conn, tenant, SOUTHBANK, created_by=world["admin"].principal_id)
        seat(conn, tenant, first, world["human"].principal_id)
        seat(conn, tenant, second, world["human"].principal_id)
    return {"default": first, "second": second}


@pytest.fixture
def agent(console_gateway, seeded):
    with httpx.Client(
        base_url=console_gateway,
        headers={"Authorization": "Bearer " + seeded["tokens"][0]},
        trust_env=False,
    ) as client:
        yield client


def audit_here(page, where):
    """The audit of the page as it stands, without navigating away from what is open."""
    settled(page)
    violations = page.evaluate(AXE_RUN)
    assert violations == [], (where, violations)
    policy = page.evaluate("window.__violations")
    assert policy == [], (where, policy)
    assert page.evaluate(FITS), (where, "horizontal scroll")


def switcher(page):
    return page.get_by_role("button", name=re.compile(r"^Space .* change space$"))


def open_switcher(page):
    switcher(page).click()
    expect(page.get_by_role("listbox", name="Spaces")).to_be_visible()


@pytest.mark.parametrize("scheme", ["dark", "light"])
@pytest.mark.parametrize("width", [1280, 390])
def test_sp12_the_switcher_reads_the_space_over_the_tenant_and_is_clean(
    console_page, admin_engine, world, two_spaces, scheme, width
):
    console_page.emulate_media(color_scheme=scheme)
    console_page.set_viewport_size({"width": width, "height": 844 if width == 390 else 900})
    sign_in_as(console_page, admin_engine, world["human"])
    console_page.goto("/")
    expect(console_page.get_by_role("heading", level=1)).to_have_text("Home")
    block = switcher(console_page)
    expect(block).to_have_attribute("aria-haspopup", "listbox")
    # The space is the strong line, on every width.
    expect(block).to_contain_text("All spaces")
    # The tenant is the boundary and stays readable beside it: in the detail slot under the
    # space on a desktop, and in the popover on a phone, whose top bar has no room for a
    # second line. A space is ownership and view inside that tenant, never a boundary.
    if width > 767:
        expect(block).to_contain_text("Synthetic")
    audit_here(console_page, (scheme, width, "closed"))
    open_switcher(console_page)
    expect(console_page.locator(".switcher-tenant")).to_contain_text("Synthetic")
    audit_here(console_page, (scheme, width, "open"))
    options = console_page.get_by_role("option")
    expect(options.filter(has_text="All spaces")).to_be_visible()
    expect(options.filter(has_text="Southbank")).to_be_visible()


def test_sp12_the_popover_is_reachable_and_dismissable_by_the_keyboard_alone(
    console_page, admin_engine, world, two_spaces
):
    sign_in_as(console_page, admin_engine, world["human"])
    console_page.goto("/")
    expect(console_page.get_by_role("heading", level=1)).to_have_text("Home")
    block = switcher(console_page)
    block.focus()
    console_page.keyboard.press("Enter")
    listbox = console_page.get_by_role("listbox", name="Spaces")
    expect(listbox).to_be_visible()
    # The filter takes focus, and Down reaches the first space without a pointer.
    expect(console_page.get_by_label("Filter spaces")).to_be_focused()
    # Wait for the server's list: "All spaces", then the two this person belongs to.
    expect(console_page.get_by_role("option")).to_have_count(3)
    console_page.keyboard.press("ArrowDown")
    first = console_page.get_by_role("option").first
    expect(first).to_be_focused()
    console_page.keyboard.press("ArrowDown")
    expect(console_page.get_by_role("option").nth(1)).to_be_focused()
    console_page.keyboard.press("Escape")
    expect(listbox).to_have_count(0)
    expect(block).to_be_focused()
    assert console_page.evaluate("window.__violations") == []


def test_sp12_a_switch_clears_the_cache_and_reads_every_count_again(
    console_page, admin_engine, world, two_spaces, agent, live_provider
):
    sign_in_as(console_page, admin_engine, world["human"])
    pending = agent.post("/v1/execute", json=request(world).model_dump(mode="json")).json()
    assert pending["state"] == "PENDING_APPROVAL"
    console_page.goto("/approvals")
    expect(console_page.get_by_role("heading", level=1)).to_have_text("Approvals")
    settled(console_page)
    # The queue holds the default space's approval, and the count pill says so.
    expect(console_page.get_by_role("navigation", name="Main")).to_contain_text("1")
    asked: list[str] = []
    console_page.on("request", lambda call: asked.append(call.url))
    open_switcher(console_page)
    console_page.get_by_role("option").filter(has_text="Southbank").click()
    expect(console_page.get_by_role("status").filter(has_text="Now in Southbank")).to_be_visible()
    # A space named with markup is text: the toast, the switcher and the crumb all say so.
    assert console_page.locator("b").count() == 0
    expect(console_page.get_by_role("navigation", name="Breadcrumb")).to_contain_text(
        f"{SOUTHBANK} · Synthetic"
    )
    settled(console_page)
    # Every read was asked again after the switch, rather than an invalidate leaving the
    # other space's rows on screen while a refetch ran.
    assert any(f"{API}session" in url for url in asked), asked
    assert any(f"{API}approvals" in url for url in asked), asked
    # The other space holds nothing of the first one's.
    expect(console_page.get_by_text("Nothing is waiting for you.").first).to_be_visible()
    audit_here(console_page, "after the switch")


def test_sp12_an_approval_link_opens_in_the_space_that_owns_it(
    console_page, admin_engine, world, two_spaces, agent, live_provider
):
    """Membership decides, and the current space is only a view."""
    sign_in_as(console_page, admin_engine, world["human"])
    pending = agent.post("/v1/execute", json=request(world).model_dump(mode="json")).json()
    console_page.goto("/approvals")
    expect(console_page.get_by_role("heading", level=1)).to_have_text("Approvals")
    settled(console_page)
    open_switcher(console_page)
    console_page.get_by_role("option").filter(has_text="Southbank").click()
    expect(console_page.get_by_role("status").filter(has_text="Now in Southbank")).to_be_visible()
    # The link is followed while the session is looking at the other space.
    response = console_page.goto(f"/approvals/{pending['approval_id']}")
    assert response is not None and response.ok
    expect(console_page.get_by_role("heading", level=2, name="device-01")).to_be_visible()
    # The shell follows the record into the space that owns it and says so.
    expect(console_page.get_by_role("status").filter(has_text="Now in Default")).to_be_visible()
    expect(console_page.get_by_role("navigation", name="Breadcrumb")).to_contain_text(
        "Default · Synthetic"
    )
    expect(switcher(console_page)).to_contain_text("Default")
    assert console_page.evaluate("window.__violations") == []


@pytest.mark.parametrize("who", ["human", "admin"])
def test_sp12_the_activity_drawer_opens_its_approval_in_the_space_that_owns_it(
    console_page, admin_engine, world, two_spaces, agent, live_provider, who
):
    """From one space's Activity, a record another space owns opens by its own id, and the
    drawer's approval link opens that approval itself, which moves the session to its space."""
    if who == "admin":
        # A tenant administrator who also decides this target, so the approval is theirs to read.
        with admin_engine.begin() as conn:
            conn.execute(
                text(
                    "INSERT INTO execbound.approval_scopes "
                    "(tenant_id,approver_id,canonical_target_id,action,space_id) "
                    "VALUES (:t,:p,:c,'endpoint.isolate',:s)"
                ),
                {
                    "t": world["identity"].tenant_id,
                    "p": world["admin"].principal_id,
                    "c": world["canonical"],
                    "s": two_spaces["default"],
                },
            )
    sign_in_as(console_page, admin_engine, world[who])
    pending = agent.post("/v1/execute", json=request(world).model_dump(mode="json")).json()
    assert pending["state"] == "PENDING_APPROVAL"
    console_page.goto("/activity")
    expect(console_page.get_by_role("heading", level=1)).to_have_text("Activity")
    settled(console_page)
    open_switcher(console_page)
    console_page.get_by_role("option").filter(has_text="Southbank").click()
    expect(console_page.get_by_role("status").filter(has_text="Now in Southbank")).to_be_visible()
    # Southbank's Activity lists nothing of Default's; the record is opened by its own id.
    console_page.goto(f"/activity?open={pending['execution_id']}")
    drawer = console_page.get_by_role("dialog", name=re.compile("Isolate endpoint"))
    expect(drawer).to_contain_text("Waiting for a person")
    drawer.get_by_role("link", name="Open in Approvals").click()
    expect(console_page).to_have_url(re.compile(rf"/approvals/{pending['approval_id']}$"))
    expect(console_page.get_by_role("heading", level=2, name="device-01")).to_be_visible()
    # The approval names its space, and the shell follows it there and says so.
    expect(console_page.get_by_role("status").filter(has_text="Now in Default")).to_be_visible()
    expect(console_page.get_by_role("navigation", name="Breadcrumb")).to_contain_text(
        "Default · Synthetic"
    )
    expect(switcher(console_page)).to_contain_text("Default")
    assert console_page.evaluate("window.__violations") == []


def test_sp12_a_viewer_of_this_space_who_decides_in_another_is_offered_the_approval(
    console_page, db, admin_engine, world, agent, live_provider
):
    """The case the drawer asks `canAnywhere` for: the person only reads the space on screen
    and decides approvals in the space that owns the record. Asked of the current space alone,
    the drawer would hide the link from the one person the approval waits for."""
    tenant = world["identity"].tenant_id
    with admin_engine.begin() as conn:
        first = default_space(conn, tenant)
        second = make_space(conn, tenant, SOUTHBANK, created_by=world["admin"].principal_id)
    # Managed roles, so the seat the approver was provisioned with no longer decides: an
    # Approver in Default and a Viewer in Southbank.
    with db.transaction(tenant) as conn:
        access.set_roles_in(
            conn,
            tenant,
            world["admin"].principal_id,
            "user",
            world["human"].principal_id,
            [{"role": "approver", "space_id": first}, {"role": "viewer", "space_id": second}],
            "A viewer of Southbank who decides in Default",
        )
    sign_in_as(console_page, admin_engine, world["human"])
    pending = agent.post("/v1/execute", json=request(world).model_dump(mode="json")).json()
    assert pending["state"] == "PENDING_APPROVAL"
    console_page.goto("/activity")
    expect(console_page.get_by_role("heading", level=1)).to_have_text("Activity")
    settled(console_page)
    open_switcher(console_page)
    console_page.get_by_role("option").filter(has_text="Southbank").click()
    expect(console_page.get_by_role("status").filter(has_text="Now in Southbank")).to_be_visible()
    # What the session says while it looks at Southbank: it may read here and decide nowhere
    # here, while it decides approvals in some space.
    session = console_page.request.get(API + "session")
    assert session.ok, session.status
    view = session.json()
    assert view["space"]["space_id"] == str(second)
    assert view["access"]["space_permissions"][str(second)] == ["console.read"]
    assert "approvals.decide" in view["access"]["space_permissions"][str(first)]
    assert "approvals.decide" in view["access"]["permissions"]
    console_page.goto(f"/activity?open={pending['execution_id']}")
    drawer = console_page.get_by_role("dialog", name=re.compile("Isolate endpoint"))
    expect(drawer).to_contain_text("Waiting for a person")
    drawer.get_by_role("link", name="Open in Approvals").click()
    expect(console_page).to_have_url(re.compile(rf"/approvals/{pending['approval_id']}$"))
    expect(console_page.get_by_role("heading", level=2, name="device-01")).to_be_visible()
    expect(console_page.get_by_role("status").filter(has_text="Now in Default")).to_be_visible()
    expect(switcher(console_page)).to_contain_text("Default")
    assert console_page.evaluate("window.__violations") == []


def test_sp12_the_spaces_page_and_its_dialogs_are_clean(
    console_page, admin_engine, world, two_spaces
):
    sign_in_as(console_page, admin_engine, world["admin"])
    audit(console_page, "/spaces", "Spaces")
    # Both spaces are the tenant administrator's to see, and a markup name is text.
    expect(console_page.get_by_role("button", name=f"Open {SOUTHBANK}")).to_be_visible()
    assert console_page.locator("table b").count() == 0
    console_page.get_by_role("button", name="New space").click()
    expect(console_page.get_by_role("dialog", name="New space")).to_be_visible()
    audit_here(console_page, "the create dialog")
    console_page.keyboard.press("Escape")
    expect(console_page.get_by_role("dialog")).to_have_count(0)
    console_page.get_by_role("button", name=f"Open {SOUTHBANK}").click()
    expect(console_page.get_by_role("button", name="Assign a person")).to_be_visible()
    console_page.get_by_role("button", name="Assign a person").click()
    dialog = console_page.get_by_role("dialog", name=re.compile("^Assign a person to "))
    expect(dialog).to_be_visible()
    # The dialog says in words what a first membership does to a tenant administrator.
    expect(dialog).to_contain_text("narrows them to it")
    audit_here(console_page, "the assign dialog")
    # The only person left to assign is the tenant's last administrator, and narrowing them
    # away is refused as its own sentence rather than as "something changed first".
    dialog.get_by_role("button", name="Assign").click()
    expect(console_page.get_by_text(re.compile("no tenant administrator"))).to_be_visible()
    assert console_page.evaluate("window.__violations") == []


def test_sp12_an_archived_space_is_readable_and_takes_no_new_member(
    console_page, admin_engine, world, two_spaces
):
    sign_in_as(console_page, admin_engine, world["admin"])
    console_page.goto("/spaces")
    expect(console_page.get_by_role("heading", level=1)).to_have_text("Spaces")
    console_page.get_by_role("button", name=f"Open {SOUTHBANK}").click()
    console_page.get_by_role("button", name=f"Archive {SOUTHBANK}").click()
    dialog = console_page.get_by_role("dialog", name=re.compile("^Archive "))
    expect(dialog).to_contain_text("Nothing is deleted")
    dialog.get_by_role("textbox").fill("The customer left")
    dialog.get_by_role("button", name="Archive", exact=True).click()
    expect(console_page.get_by_role("status").filter(has_text="takes no new work")).to_be_visible()
    # It keeps its history and stays readable; it simply takes no new member.
    expect(console_page.get_by_role("button", name="Assign a person")).to_be_disabled()
    expect(console_page.get_by_role("button", name=f"Unarchive {SOUTHBANK}")).to_be_visible()
    settled(console_page)
    assert console_page.evaluate("window.__violations") == []
