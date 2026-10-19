# SPDX-License-Identifier: AGPL-3.0-only
"""Real Chromium against the teammate invitation acceptance pages (#487): the link and the
accept form; and an Approver invited into a reviewer group, from the invite dialog to their
first decision (AR8).

These are the pages a person meets from an email, before any session exists, so what matters
is what a real browser actually does with the fragment: it never reaches the wire, it never
lands in history or storage, and the page's own script is what moves it into the form. The
pattern is the signup pages' own real-browser tests, which moved with those pages to a plugin.
"""

import re
import secrets
from dataclasses import dataclass
from uuid import UUID

import pytest
from console_api_fixtures import API, console_client
from playwright.sync_api import expect
from sqlalchemy import text
from test_approval_group_rules import remove_individual_scope
from test_browser_console import AXE_RUN, settled, sign_in_as
from test_browser_console import console_gateway as console_gateway
from test_browser_console import console_page as console_page
from test_browser_surfaces import ACTION_TIMEOUT_MS, FITS, serve
from test_browser_surfaces import chromium as chromium
from test_execution import registry as registry
from test_execution import request
from test_execution import world as world
from test_migration_without_bypass import fenced
from test_protected_path import connector as connector
from test_protected_path import live_provider as live_provider
from test_runtime import runtime as runtime
from test_teammate_invitations import CHOSEN, bare_runtime, link, send, workspace

from execbound.app import create_app
from execbound.execution import admit
from execbound.surfaces.human import HumanConfig
from execbound.surfaces.tokens import TokenKeys
from execbound.transports import MailConfig

pytestmark = pytest.mark.integration


def invite_gateway_app(db, origin):
    return create_app(
        db,
        runtime=bare_runtime(db),
        human=HumanConfig(origin, TokenKeys("browser-v1", {"browser-v1": secrets.token_bytes(32)})),
    )


@pytest.fixture
def invite_gateway(db):
    with serve(lambda origin: invite_gateway_app(db, origin)) as origin:
        yield origin


@pytest.fixture
def page(chromium, invite_gateway):
    # Authentication stays in this fresh context's memory: no trace, no HAR, no video and no
    # storage-state file, so nothing a person typed is written to disk by the test.
    with chromium.new_context(
        base_url=invite_gateway, viewport={"width": 1440, "height": 1000}
    ) as context:
        opened = context.new_page()
        opened.set_default_timeout(ACTION_TIMEOUT_MS)
        yield opened


@dataclass(frozen=True)
class SeenRequest:
    url: str
    referer: str | None
    post_data: str | None


def test_ti20_the_fragment_leaves_the_address_bar_and_never_reaches_the_server(
    page, db, admin_engine
):
    where = workspace(admin_engine)
    _, token = link(db, where)
    seen_requests: list[SeenRequest] = []
    page.on(
        "request",
        lambda request: seen_requests.append(
            SeenRequest(request.url, request.headers.get("referer"), request.post_data)
        ),
    )
    baseline = page.evaluate("window.history.length")

    page.goto(f"/join#{token}")
    expect(page).to_have_url(re.compile(r"/join$"))
    assert "#" not in page.url
    # `replaceState`, not `pushState`: one ordinary navigation entry, never a second one
    # carrying the token in its URL for a "back" press to return to.
    assert page.evaluate("window.history.length") == baseline + 1
    assert page.evaluate("document.getElementById('invite-token').value") == token
    assert page.evaluate("window.localStorage.length") == 0
    assert page.evaluate("window.sessionStorage.length") == 0
    assert all(token not in seen.url for seen in seen_requests)
    assert all(token not in (seen.referer or "") for seen in seen_requests)

    page.get_by_role("button", name="Continue").click()
    expect(page.get_by_role("heading", level=1)).to_have_text("Join the workspace.")
    assert all(token not in seen.url for seen in seen_requests)
    assert all(token not in (seen.referer or "") for seen in seen_requests)

    # T4.31's own count, this feature's shape: the token reaches exactly one request body, the
    # `POST /join` the page's own script builds, and no URL and no Referer, on every request
    # seen so far, including the GET that rendered the page's own form. This count would
    # become 2 if the test went on to submit the accept form, since the token also travels in
    # that POST's own hidden field.
    carrying = [seen for seen in seen_requests if seen.post_data and token in seen.post_data]
    assert len(carrying) == 1, seen_requests
    assert carrying[0].url.endswith("/join")


def test_ti21_invite_pages_fit_a_phone(page, db, admin_engine, tmp_path):
    where = workspace(admin_engine)
    _, token = link(db, where)
    page.set_viewport_size({"width": 390, "height": 844})

    # A separate tab for the bare page: navigating from `/join` to `/join#token` on the same
    # tab is a same-document, fragment-only navigation in a real browser, which never reloads
    # the document and so never reruns the page's own `defer` script. A person's first visit
    # is always a fresh top-level navigation straight to the link with its fragment, which the
    # next block exercises; this block is only the no-fragment landing on its own.
    bare = page.context.new_page()
    bare.set_viewport_size({"width": 390, "height": 844})
    bare.goto("/join")
    expect(bare.get_by_role("heading", level=1)).to_be_visible()
    assert bare.evaluate(FITS)
    bare.screenshot(path=str(tmp_path / "invite_open.png"))
    bare.close()

    page.goto(f"/join#{token}")
    expect(page).to_have_url(re.compile(r"/join$"))
    assert page.evaluate(FITS)
    page.screenshot(path=str(tmp_path / "invite_open_token.png"))

    page.get_by_role("button", name="Continue").click()
    expect(page.get_by_role("heading", level=1)).to_have_text("Join the workspace.")
    assert page.evaluate(FITS)
    page.screenshot(path=str(tmp_path / "invite_accept.png"))


def test_the_accept_post_passes_the_strict_origin_check_in_real_chromium(page, db, admin_engine):
    """With `no-referrer` reverted to the site's `same-origin` default, as on the signup
    pages, a same-origin form POST keeps its real Origin, so the shared strict check in
    `RequestGuards.boundary` admits it without a relaxation. `/join`'s own exchange POST is
    already covered getting here; this drives all the way through `/join/accept`.
    """
    where = workspace(admin_engine)
    _, token = link(db, where, email="chromium-new@example.org")
    statuses: dict[str, int] = {}
    page.on(
        "response",
        lambda response: (
            statuses.update({response.url: response.status})
            if response.request.method == "POST"
            else None
        ),
    )

    page.goto(f"/join#{token}")
    page.get_by_role("button", name="Continue").click()
    expect(page.get_by_role("heading", level=1)).to_have_text("Join the workspace.")
    page.get_by_label("Password", exact=True).fill(CHOSEN)
    page.get_by_label("Confirm password").fill(CHOSEN)
    page.get_by_role("button", name="Accept").click()
    page.wait_for_load_state("networkidle")

    join_status = next(v for k, v in statuses.items() if k.endswith("/join"))
    accept_status = next(v for k, v in statuses.items() if k.endswith("/join/accept"))
    assert join_status != 403, statuses
    assert accept_status != 403, statuses
    assert accept_status == 303, statuses


# --- AR8: an Approver invited into a reviewer group (#678) ------------------------------------


def reviewer_group_and_rule(db, runtime, admin_engine, world):
    """A reviewer group with no roles of its own and a rule routing the world's endpoint to it,
    made through the console API as an administrator would; the world's own individual
    assignment is removed, so only the group can decide."""
    remove_individual_scope(admin_engine, world)
    with console_client(db, runtime, admin_engine, world["admin"]) as client:
        made = client.post(
            API + "/access/groups",
            {"name": "Night shift", "description": None, "reason": "Route endpoint reviews"},
        )
        assert made.status_code == 200, made.text
        group = made.json()["group_id"]
        space = client.get(API + "/access").json()["spaces"][0]["space_id"]
        rule = client.post(
            API + "/approval-rules",
            {
                "name": "Production endpoint response",
                "group_id": group,
                "space_id": space,
                "actions": ["endpoint.isolate"],
                "targets": [str(world["canonical"])],
                "reason": "Route endpoint requests to the night shift",
            },
        )
        assert rule.status_code == 200, rule.text
    return UUID(group), UUID(space)


def open_invite_dialog(page, email, space, group_label):
    page.goto("/people")
    expect(page.get_by_role("heading", level=1)).to_have_text("Users")
    page.get_by_role("button", name="Invite teammate").click()
    dialog = page.get_by_role("dialog", name="Invite a teammate")
    dialog.get_by_label("Email").fill(email)
    dialog.get_by_label("Role").select_option("approver")
    dialog.get_by_label("Space").select_option(str(space))
    dialog.get_by_label("Reviewer group").select_option(label=group_label)
    expect(dialog.get_by_text("Production endpoint response: ")).to_be_visible()
    return dialog


def test_ar8_an_invited_approver_joins_the_group_and_decides(
    console_page, console_gateway, chromium, db, runtime, admin_engine, world, monkeypatch
):
    # The Users page offers to invite only where a relay is configured. Nothing listens on this
    # one; the link is minted here instead, as a send would mint it.
    monkeypatch.setattr(
        runtime,
        "mail",
        MailConfig("localhost", 1, "tls", "relay", "relay-password", "execbound@example.test"),
    )
    group, space = reviewer_group_and_rule(db, runtime, admin_engine, world)
    email = "night-reviewer@example.org"
    sign_in_as(console_page, admin_engine, world["admin"])
    dialog = open_invite_dialog(console_page, email, space, "Night shift · No roles")
    dialog.get_by_role("button", name="Invite", exact=True).click()
    expect(dialog).to_be_hidden()
    listed = console_page.get_by_role("table", name=re.compile("Teammate invitations"))
    expect(listed.get_by_role("cell", name=email)).to_be_visible()
    expect(listed.get_by_text("Reviewer group: Night shift")).to_be_visible()

    tenant = world["admin"].tenant_id
    with admin_engine.begin() as conn:
        fenced(conn, tenant)
        invitation = conn.execute(
            text(
                "SELECT invitation_id, reviewer_group_id FROM execbound.workspace_invitations "
                "WHERE tenant_id = :t AND email = :e AND state = 'PENDING'"
            ),
            {"t": tenant, "e": email},
        ).one()
    assert invitation.reviewer_group_id == group
    token = send(db, tenant, invitation.invitation_id)
    held = admit(db, world["identity"], request(world), world["clock"])
    assert held.view.state == "PENDING_APPROVAL"

    with chromium.new_context(
        base_url=console_gateway, viewport={"width": 1280, "height": 900}
    ) as context:
        joining = context.new_page()
        joining.set_default_timeout(ACTION_TIMEOUT_MS)
        joining.goto(f"/join#{token}")
        joining.get_by_role("button", name="Continue").click()
        expect(joining.get_by_role("heading", level=1)).to_have_text("Join the workspace.")
        joining.get_by_label("Password", exact=True).fill(CHOSEN)
        joining.get_by_label("Confirm password").fill(CHOSEN)
        joining.get_by_role("button", name="Accept").click()
        expect(joining).to_have_url(re.compile(r"/approvals$"))
        expect(joining.get_by_role("heading", level=1)).to_have_text("Approvals")

        joining.goto(f"/approvals/{held.view.approval_id}")
        approve = joining.get_by_role("button", name=re.compile(r"^Approve\b"))
        expect(approve).to_be_visible()
        with joining.expect_response(
            lambda response: (
                response.request.method == "POST"
                and response.url.endswith(f"/approvals/{held.view.approval_id}/decision")
            )
        ) as decided:
            approve.click()
        assert decided.value.status == 200, decided.value.json()

    with admin_engine.begin() as conn:
        fenced(conn, tenant)
        member = conn.execute(
            text(
                "SELECT m.principal_id FROM execbound.access_group_members m "
                "JOIN execbound.principals p "
                "  ON p.tenant_id = m.tenant_id AND p.principal_id = m.principal_id "
                "WHERE m.tenant_id = :t AND m.group_id = :g AND p.email = :e"
            ),
            {"t": tenant, "g": group, "e": email},
        ).one_or_none()
    assert member is not None
    committed = admit(db, world["identity"], request(world), world["clock"])
    assert committed.view.state == "DISPATCH_COMMITTED"
    assert committed.ticket is not None


@pytest.mark.parametrize("scheme", ["dark", "light"])
def test_ar8_the_invite_dialog_is_accessible(
    console_page, db, runtime, admin_engine, world, monkeypatch, scheme
):
    monkeypatch.setattr(
        runtime,
        "mail",
        MailConfig("localhost", 1, "tls", "relay", "relay-password", "execbound@example.test"),
    )
    _, space = reviewer_group_and_rule(db, runtime, admin_engine, world)
    console_page.emulate_media(color_scheme=scheme)
    sign_in_as(console_page, admin_engine, world["admin"])
    for width, height in ((1280, 900), (390, 844)):
        console_page.set_viewport_size({"width": width, "height": height})
        dialog = open_invite_dialog(
            console_page, "a11y@example.org", space, "Night shift · No roles"
        )
        settled(console_page)
        assert console_page.evaluate(AXE_RUN) == [], (scheme, width)
        assert console_page.evaluate("window.__violations") == [], (scheme, width)
        assert console_page.evaluate(FITS), (scheme, width, "horizontal scroll")
        expect(dialog).to_be_in_viewport()
        dialog.get_by_role("button", name="Cancel").click()
        expect(dialog).to_be_hidden()
