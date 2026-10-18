# SPDX-License-Identifier: AGPL-3.0-only
"""The customer's identity provider in real Chromium: `/invite`, the tenant settings card and
My account's directory identity card.

Three surfaces, in both colour schemes, at 1280 and at 390 pixels. `/invite` is the one page a
person who has never signed in here ever sees, so it is held to the bar the other pre-session
pages are: every control named, the skip link first under the keyboard, no sideways scroll and
the contrast the tokens promise. The tenant settings card is audited with axe-core inside the
console, with a provider actually registered, because a card that reads well empty and badly
once it has a state is a card nobody checked.

The directory is scripted in process, so nothing here reaches a network.
"""

import re
import secrets
from datetime import timedelta

import pytest
from idp_fixtures import (
    CLIENT_ID,
    CLIENT_SECRET,
    ISSUER,
    NAME,
    SUBJECT,
    USERNAME,
    StandIn,
    directory_key,
    discovery_document,
)
from playwright.sync_api import expect
from test_browser_accessibility import audit as page_audit
from test_browser_accessibility import readable
from test_browser_console import AXE, COLLECT, sign_in_as
from test_browser_console import audit as console_audit
from test_browser_surfaces import chromium as chromium
from test_browser_surfaces import serve
from test_execution import provision_credential
from test_execution import registry as registry
from test_execution import world as world
from test_protected_path import connector as connector
from test_protected_path import live_provider as live_provider
from test_runtime import runtime as runtime

from execbound import access_control as access
from execbound import directory_store as store
from execbound.app import create_app
from execbound.directory import DirectoryAccount, DirectoryConfig, Discovery
from execbound.envelope import KEY_BYTES, KeyRing
from execbound.identity import authenticate
from execbound.surfaces import console as console_module
from execbound.surfaces.human import HumanConfig
from execbound.surfaces.tokens import TokenKeys

pytestmark = pytest.mark.integration

RING = KeyRing("dir-v1", {"dir-v1": b"\x55" * KEY_BYTES})
# Who removes a link, as My account's directory card says it to each kind of person.
# `directory_unlink` refuses a principal whose kind or effective kind is an administrator's, so
# an approver is unlinked on their page under Users and an administrator from no console page.
UNLINKED_BY_AN_ADMINISTRATOR = "Unlinking is an administrator action"
NOT_FROM_THE_CONSOLE = "An administrator's link is not removed from the console."


@pytest.fixture(scope="module")
def key():
    return directory_key()


@pytest.fixture
def settings(key):
    return DirectoryConfig(RING, "http://127.0.0.1", StandIn(key).client())


def directory_app(db, runtime, origin, settings):
    keys = TokenKeys("browser-v1", {"browser-v1": secrets.token_bytes(32)})
    # The redirect URI follows the origin the server was actually bound to, so the card shows
    # what a customer would paste rather than a placeholder.
    bound = DirectoryConfig(settings.ring, origin, settings.http)
    return create_app(db, runtime=runtime, human=HumanConfig(origin, keys, directory=bound))


@pytest.fixture
def directory_gateway(db, runtime, settings):
    if console_module.load_build() is None:
        pytest.fail("No console build is packaged: run `pnpm build` in console/ first")
    if not AXE.exists():
        pytest.fail("axe-core is not installed: run `pnpm install` in console/ first")
    with serve(lambda origin: directory_app(db, runtime, origin, settings)) as origin:
        yield origin


@pytest.fixture
def page(chromium, directory_gateway):
    with chromium.new_context(
        base_url=directory_gateway, viewport={"width": 1280, "height": 900}
    ) as context:
        opened = context.new_page()
        opened.set_default_timeout(8000)
        opened.add_init_script(COLLECT)
        opened.add_init_script(path=str(AXE))
        yield opened


@pytest.fixture
def registered(db, runtime, world, settings, directory_gateway):
    """A provider an administrator registered, verified and enabled in this tenant."""
    identity = world["admin"]
    document = discovery_document()
    provider = store.register(
        db,
        settings,
        identity.tenant_id,
        identity.principal_id,
        name="Contoso",
        client_id=CLIENT_ID,
        client_secret=CLIENT_SECRET,
        subject_claim="oid",
        discovery=Discovery(
            ISSUER,
            document["authorization_endpoint"],
            document["token_endpoint"],
            document["jwks_uri"],
            None,
        ),
        clock=runtime.clock,
    )
    store.link_self(
        db,
        identity.tenant_id,
        identity.principal_id,
        provider,
        DirectoryAccount(SUBJECT, NAME, USERNAME, "refresh"),
        clock=runtime.clock,
    )
    store.set_state(
        db, identity.tenant_id, identity.principal_id, provider, "enabled", clock=runtime.clock
    )
    return provider


@pytest.mark.parametrize("scheme", ["light", "dark"])
@pytest.mark.parametrize("width", [1280, 390])
def test_the_invitation_page_reads_and_is_labelled_in_both_schemes(page, scheme, width):
    page.emulate_media(color_scheme=scheme)
    page.set_viewport_size({"width": width, "height": 900 if width == 1280 else 844})
    readable(page, "/invite", scheme)
    page_audit(page, "/invite")
    expect(page.get_by_role("heading", level=1)).to_have_text("Redeem your invitation.")
    # Every control is named, and the code field is one a password manager will not fill in.
    field = page.get_by_label("Invitation code")
    expect(field).to_have_attribute("type", "password")
    expect(field).to_have_attribute("autocomplete", "off")
    assert page.evaluate("document.documentElement.scrollWidth <= window.innerWidth")


def test_the_invitation_page_says_one_sentence_for_a_code_that_is_not_one(page):
    page.goto("/invite")
    page.get_by_label("Invitation code").fill("not-a-code")
    page.get_by_role("button", name="Continue").click()
    expect(page.get_by_role("alert")).to_have_text("This invitation is not valid.")
    # And it still names nothing about any tenant.
    assert "Contoso" not in page.content()


@pytest.mark.parametrize("scheme", ["dark", "light"])
def test_the_tenant_sign_in_card_is_clean_with_a_provider_registered(
    page, admin_engine, world, registered, scheme
):
    page.emulate_media(color_scheme=scheme)
    sign_in_as(page, admin_engine, world["admin"])
    console_audit(page, "/tenant", "Workspace settings")
    expect(page.get_by_text("Enabled")).to_be_visible()
    expect(page.get_by_text("Contoso", exact=True)).to_be_visible()
    # The two values a person is meant to copy are on the page as fields they can select.
    expect(page.get_by_label(re.compile("Redirect URI"))).to_have_value(
        re.compile(r"/login/directory/callback$")
    )
    expect(page.get_by_label(re.compile("sign-in address"))).to_have_value(
        re.compile(rf"/login/directory/{registered}$")
    )
    # Nothing on the page is the client secret.
    assert CLIENT_SECRET not in page.content()
    page.set_viewport_size({"width": 390, "height": 844})
    console_audit(page, "/tenant", "Workspace settings")


def test_a_remembered_provider_puts_one_button_on_the_sign_in_page(
    page, admin_engine, world, registered
):
    """The button follows the browser, so a stranger's sign-in page shows nothing extra."""
    page.goto("/login")
    assert "Continue with Contoso" not in page.content()
    page.context.add_cookies(
        [
            {
                "name": "eb_directory",
                "value": str(registered),
                "url": page.url,
                "httpOnly": True,
                "sameSite": "Lax",
            }
        ]
    )
    page.goto("/login")
    expect(page.get_by_role("button", name=re.compile("Continue with Contoso"))).to_be_visible()
    page_audit(page, "/login")


@pytest.mark.parametrize("scheme", ["dark", "light"])
def test_my_accounts_directory_identity_card_is_clean_before_and_after_linking(
    page, db, runtime, admin_engine, world, registered, scheme
):
    """An approver is offered `Link my identity` through the enabled provider; once linked, the
    card shows the link with the directory's hints as text and offers nothing to press."""
    approver = world["human"]
    page.emulate_media(color_scheme=scheme)
    sign_in_as(page, admin_engine, approver)
    card = page.locator("section", has=page.get_by_role("heading", name="Directory identity"))
    for width, height in ((1280, 900), (390, 844)):
        page.set_viewport_size({"width": width, "height": height})
        console_audit(page, "/settings", "My account")
        expect(card.get_by_role("button", name="Link my identity")).to_be_visible()
        expect(card.get_by_text(UNLINKED_BY_AN_ADMINISTRATOR, exact=False)).to_be_visible()
        expect(card.get_by_text(NOT_FROM_THE_CONSOLE)).to_have_count(0)
    store.link_self(
        db,
        approver.tenant_id,
        approver.principal_id,
        registered,
        DirectoryAccount(
            "77777777-0000-4000-8000-0000000000cc", "Sam <b>Lee</b>", "sam@contoso.example", "r"
        ),
        clock=runtime.clock,
    )
    for width, height in ((1280, 900), (390, 844)):
        page.set_viewport_size({"width": width, "height": height})
        console_audit(page, "/settings", "My account")
        expect(card.get_by_text("You linked it yourself")).to_be_visible()
        expect(card.get_by_text("Sam <b>Lee</b>")).to_be_visible()
        expect(card.get_by_role("button", name="Link my identity")).to_have_count(0)
    assert card.locator("b").count() == 0


def test_my_account_tells_an_administrator_their_link_is_not_removed_from_the_console(
    page, admin_engine, world, registered
):
    """The card told every viewer that unlinking is an administrator action taken on their page
    under Users, which no console page does for an administrator: `directory_unlink` refuses
    their link. It tells an administrator what is true for them, and promises nothing else."""
    page.emulate_media(color_scheme="light")
    sign_in_as(page, admin_engine, world["admin"])
    console_audit(page, "/settings", "My account")
    card = page.locator("section", has=page.get_by_role("heading", name="Directory identity"))
    expect(card.get_by_text("Linked", exact=True)).to_be_visible()
    expect(card.get_by_text(NOT_FROM_THE_CONSOLE)).to_be_visible()
    expect(card.get_by_text(UNLINKED_BY_AN_ADMINISTRATOR, exact=False)).to_have_count(0)


def test_my_account_tells_a_person_made_an_administrator_by_a_role_the_same(
    page, db, runtime, admin_engine, world, registered
):
    """Who is an administrator is the effective kind: a person granted the administrator role on
    the access page keeps `HUMAN_APPROVER` on their principal row, and `directory_unlink`
    refuses their link all the same, so the card says to them what it says to any
    administrator."""
    admin = world["admin"]
    person = world["human"]
    with db.transaction(admin.tenant_id) as conn:
        access.set_roles_in(
            conn,
            admin.tenant_id,
            admin.principal_id,
            "user",
            person.principal_id,
            [{"role": "administrator", "space_id": None}],
            "Test access change",
        )
    # The promotion revoked the person's earlier credentials (0047), so they sign in afresh.
    with admin_engine.begin() as conn:
        token = provision_credential(
            conn, person.tenant_id, person.principal_id, runtime.clock.now(), timedelta(hours=2)
        )
    promoted = authenticate(db, token)
    assert promoted.kind == "ADMIN"
    page.emulate_media(color_scheme="light")
    sign_in_as(page, admin_engine, promoted)
    console_audit(page, "/settings", "My account")
    card = page.locator("section", has=page.get_by_role("heading", name="Directory identity"))
    expect(card.get_by_role("button", name="Link my identity")).to_be_visible()
    expect(card.get_by_text(NOT_FROM_THE_CONSOLE)).to_be_visible()
    expect(card.get_by_text(UNLINKED_BY_AN_ADMINISTRATOR, exact=False)).to_have_count(0)
