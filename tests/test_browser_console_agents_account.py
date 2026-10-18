# SPDX-License-Identifier: AGPL-3.0-only
"""Agents, keys and account security in real Chromium (#678).

An agent key's lifetime is chosen, never preselected; a key is rotated from the agent's page,
the new key is shown once with where it goes, and the old key stays live and reads as replaced.
The page and the dialogs are axe-clean in both schemes at 1280 and 390 pixels, scroll nowhere
sideways, and record no Content Security Policy or Trusted Types violation.
"""

import base64
import hashlib
import re
import secrets
from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import UUID

import pytest
from browser_network import launched
from browser_recovery import watched
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from playwright.sync_api import Error as PlaywrightError
from playwright.sync_api import expect
from sqlalchemy import text
from test_agents_bindings import found as found
from test_browser_console import AXE, AXE_RUN, COLLECT, settled, sign_in_as
from test_browser_console import console_gateway as console_gateway
from test_browser_console import console_page as console_page
from test_browser_console_directory import TOKEN, agent_name, nowhere
from test_browser_surfaces import ACTION_TIMEOUT_MS, self_signed, serve
from test_browser_surfaces import chromium as chromium
from test_execution import provision_credential
from test_execution import registry as registry
from test_execution import world as world
from test_human_surface import credential
from test_protected_path import connector as connector
from test_protected_path import live_provider as live_provider
from test_runtime import runtime as runtime

from execbound import mfa
from execbound.app import create_app
from execbound.envelope import KeyRing
from execbound.surfaces import console as console_module
from execbound.surfaces.human import HumanConfig
from execbound.surfaces.sessions import issue_session, load_session
from execbound.surfaces.tokens import TokenKeys

pytestmark = pytest.mark.integration

WIDTHS = (("light", 1280, 900), ("dark", 1280, 900), ("light", 390, 844), ("dark", 390, 844))


def clean(page, label) -> None:
    """Axe-clean in both schemes at both widths, no sideways scroll, no policy violation."""
    for scheme, width, height in WIDTHS:
        page.emulate_media(color_scheme=scheme)
        page.set_viewport_size({"width": width, "height": height})
        settled(page)
        assert page.evaluate(AXE_RUN) == [], (label, scheme, width)
        assert page.evaluate(
            "document.documentElement.scrollWidth <= document.documentElement.clientWidth"
        ), (label, scheme, width)
    page.set_viewport_size({"width": 1280, "height": 900})
    page.emulate_media(color_scheme="light")
    assert page.evaluate("window.__violations") == [], label


def key_number(engine, credential) -> int:
    with engine.connect() as conn:
        return int(
            conn.execute(
                text("SELECT number FROM execbound.credentials WHERE credential_id = :c"),
                {"c": credential},
            ).scalar_one()
        )


def test_ak6_issue_and_rotate_a_key_in_both_schemes(console_page, admin_engine, world):
    page = console_page
    sign_in_as(page, admin_engine, world["admin"])
    mine = str(world["identity"].principal_id)
    old = key_number(admin_engine, world["identity"].credential_id)
    page.goto(f"/agents/{mine}")
    expect(page.get_by_role("heading", level=1)).to_have_text(agent_name(admin_engine, mine))

    # No lifetime is chosen for the person; the key waits for one (AK1).
    issue = page.get_by_role("button", name="Issue another API key")
    expect(page.get_by_label("API key expires after")).to_have_value("")
    expect(issue).to_be_disabled()
    clean(page, "agent page")
    page.get_by_label("API key expires after").select_option("720")
    issue.click()
    shown = page.get_by_role("dialog", name="Copy the API key now")
    first = shown.get_by_label("API key (copy it now)").input_value()
    assert TOKEN.fullmatch(first), first
    shown.get_by_role("button", name="I have copied it").click()
    expect(shown).to_be_hidden()
    nowhere(page, first)

    # The world's key authenticated as the fixtures were built and expires within the hour.
    keys = page.get_by_role("table", name=re.compile("Every API key of this agent"))
    row = keys.get_by_role("row").filter(
        has=page.get_by_role("cell", name=f"Key {old}", exact=True)
    )
    expect(row.get_by_text("Expires soon")).to_be_visible()
    expect(row).not_to_contain_text("Never used")
    row.get_by_role("button", name=f"Rotate key {old}").click()
    asking = page.get_by_role("dialog", name=re.compile(f"^Rotate key {old} for "))
    expect(asking).to_contain_text(f"Key {old} keeps working until you revoke it")
    confirm = asking.get_by_role("button", name="Issue the new key")
    expect(confirm).to_be_disabled()
    clean(page, "rotate dialog")
    asking.get_by_label("Lifetime").select_option("2160")
    confirm.click()
    shown = page.get_by_role("dialog", name="Copy the API key now")
    expect(shown).to_contain_text(f"Next, put this key where key {old} is used")
    rotated = shown.get_by_label("API key (copy it now)").input_value()
    assert TOKEN.fullmatch(rotated), rotated
    clean(page, "rotated key dialog")
    shown.get_by_role("button", name="I have copied it").click()
    expect(shown).to_be_hidden()
    expect(row).to_contain_text("live, replaced by a newer key")
    # The replaced key has no notice: only an unreplaced key needs one.
    expect(page.get_by_role("link", name=re.compile(f"^Key {old} for "))).to_have_count(0)
    nowhere(page, rotated)
    clean(page, "agent page after rotation")


# The passkey step-up in Chromium (SU14): a secure context whose relying party is a name, so
# the console is served over `https://localhost` with a throwaway certificate, and a virtual
# authenticator stands in for the person's device.

RING = KeyRing("test", {"test": b"m" * 32})


@pytest.fixture
def secure_certificate(tmp_path):
    return self_signed(tmp_path)


@pytest.fixture
def secure_chromium(chromium, secure_certificate):
    # Context-wide ignore_https_errors can leave Chromium rejecting speculative
    # TLS connections (crbug.com/488043). Accept only this fixture's throwaway public key,
    # before any connection starts; no system certificate store or real browser is changed.
    certificate = x509.load_pem_x509_certificate(Path(secure_certificate[0]).read_bytes())
    public_key = certificate.public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    pin = base64.b64encode(hashlib.sha256(public_key).digest()).decode("ascii")
    with launched(
        chromium.browser_type, args=[f"--ignore-certificate-errors-spki-list={pin}"]
    ) as browser:
        yield watched(browser)


@pytest.fixture
def secure_gateway(db, runtime, secure_certificate):
    if console_module.load_build() is None:
        pytest.fail("No console build is packaged: run `pnpm build` in console/ first")

    def app(origin):
        keys = TokenKeys("browser-v1", {"browser-v1": secrets.token_bytes(32)})
        return create_app(db, runtime=runtime, human=HumanConfig(origin, keys, mfa=RING))

    with serve(app, tls=secure_certificate) as origin:
        yield origin


@pytest.fixture
def secure_page(secure_chromium, secure_gateway):
    with secure_chromium.new_context(
        base_url=secure_gateway,
        viewport={"width": 1280, "height": 900},
    ) as context:
        opened = context.new_page()
        opened.set_default_timeout(ACTION_TIMEOUT_MS)
        opened.add_init_script(COLLECT)
        opened.add_init_script(path=str(AXE))
        cdp = context.new_cdp_session(opened)
        cdp.send("WebAuthn.enable")
        cdp.send(
            "WebAuthn.addVirtualAuthenticator",
            {
                "options": {
                    "protocol": "ctap2",
                    "transport": "internal",
                    "hasResidentKey": True,
                    "hasUserVerification": True,
                    "isUserVerified": True,
                    "automaticPresenceSimulation": True,
                }
            },
        )
        yield opened


def test_the_passkey_browser_rejects_an_unrelated_certificate(
    secure_chromium, db, runtime, tmp_path
):
    other = tmp_path / "unrelated"
    other.mkdir()

    def app(origin):
        keys = TokenKeys("browser-v1", {"browser-v1": secrets.token_bytes(32)})
        return create_app(db, runtime=runtime, human=HumanConfig(origin, keys, mfa=RING))

    with (
        serve(app, tls=self_signed(other)) as origin,
        secure_chromium.new_context() as context,
    ):
        page = context.new_page()
        with pytest.raises(PlaywrightError, match="net::ERR_CERT_AUTHORITY_INVALID"):
            page.goto(origin)


def stale(admin_engine, tenant) -> None:
    """Age every session's verified factor past the step-up's thirty minutes. The row moves,
    not the clock: the credential functions refuse a clock far from the database's own."""
    with admin_engine.begin() as conn:
        conn.execute(
            text(
                "UPDATE execbound.session_assurance SET verified_at = verified_at - :age "
                "WHERE tenant_id = :t"
            ),
            {"age": timedelta(minutes=31), "t": tenant},
        )


def test_su14_a_passkey_steps_up_a_key_revocation_over_the_agent_page(
    secure_page, db, runtime, admin_engine, world
):
    page = secure_page
    tenant, admin = world["admin"].tenant_id, world["admin"].principal_id
    runtime.clock.value = datetime.now(UTC)
    # An authenticator confirmed before this browser signs in.
    setup = load_session(
        db, issue_session(db, world["admin"], clock=runtime.clock).token, clock=runtime.clock
    )
    seed = mfa.begin_enrollment(db, setup, RING, clock=runtime.clock)
    step = int(runtime.clock.now().timestamp() // 30)
    mfa.confirm_enrollment(db, setup, RING, mfa.totp(seed, step), clock=runtime.clock)
    # Two more keys for the world's agent, to revoke.
    agent = world["identity"].principal_id
    with admin_engine.begin() as conn:
        keys = [
            UUID(
                provision_credential(
                    conn, tenant, agent, runtime.clock.now(), timedelta(days=30)
                ).split(".")[2]
            )
            for _ in range(2)
        ]
        numbers = [
            conn.execute(
                text("SELECT number FROM execbound.credentials WHERE credential_id = :c"),
                {"c": key},
            ).scalar_one()
            for key in keys
        ]

    # Sign in, give the second step a code from the next time step, and save a passkey.
    page.goto("/login?setup=1")
    page.get_by_label("Setup credential").fill(credential(admin_engine, world["admin"]))
    page.get_by_role("button", name="Continue setup").click()
    expect(page.get_by_role("heading", level=1)).to_have_text("Two-step verification")
    runtime.clock.value += timedelta(seconds=30)
    page.get_by_label("Authentication code").fill(mfa.totp(seed, step + 1))
    page.get_by_role("button", name="Verify", exact=True).click()
    expect(page).not_to_have_url(re.compile(r"/mfa$"))
    page.goto("/account/security")
    page.get_by_role("button", name="Add a passkey").click()
    page.get_by_role("button", name="Continue with device").click()
    expect(page.get_by_text("Passkey added.")).to_be_visible()

    # More than thirty minutes on: revoking a key asks, in place, naming the change.
    stale(admin_engine, tenant)
    page.goto(f"/agents/{agent}")
    expect(page.get_by_role("heading", level=1)).to_have_text(agent_name(admin_engine, agent))
    page.evaluate("window.__stayed = true")
    agent_label = agent_name(admin_engine, agent)
    for index, number in enumerate(numbers):
        if index == 1:
            stale(admin_engine, tenant)
        page.get_by_role("button", name=f"Revoke key {number}", exact=True).click()
        confirming = page.get_by_role("dialog", name=f"Revoke API key {number}?")
        confirming.get_by_role("button", name="Revoke", exact=True).click()
        asking = page.get_by_role("dialog", name="Verify your identity")
        expect(asking).to_contain_text(
            f"To revoke key {number} for {agent_label}, confirm it is you."
        )
        passkey = asking.get_by_role("button", name="Use a passkey")
        expect(passkey).to_be_visible()
        if index == 1:
            # The question is clean in both schemes, at desktop and phone widths.
            for scheme, width, height in WIDTHS:
                page.emulate_media(color_scheme=scheme)
                page.set_viewport_size({"width": width, "height": height})
                settled(page)
                assert page.evaluate(AXE_RUN) == [], (scheme, width)
                assert page.evaluate(
                    "document.documentElement.scrollWidth <= document.documentElement.clientWidth"
                ), (scheme, width)
                expect(asking).to_be_in_viewport()
            page.set_viewport_size({"width": 1280, "height": 900})
            page.emulate_media(color_scheme="light")
        # One click: the options this question fetched as it opened are unspent.
        passkey.click()
        expect(asking).to_be_hidden()
        expect(confirming).to_be_hidden()
        row = page.get_by_role("row").filter(
            has=page.get_by_role("cell", name=f"Key {number}", exact=True)
        )
        expect(row).to_contain_text("revoked")
    assert page.evaluate("window.__stayed") is True
    assert page.evaluate("window.__violations") == []
    with admin_engine.connect() as conn:
        revoked = conn.execute(
            text(
                "SELECT count(*) FROM execbound.credentials "
                "WHERE credential_id = ANY(:k) AND revoked_at IS NOT NULL"
            ),
            {"k": keys},
        ).scalar_one()
        verified = conn.execute(
            text(
                "SELECT count(*) FROM execbound.audit_events WHERE tenant_id = :t "
                "AND kind = 'account_security.verified' AND payload ->> 'method' = 'passkey' "
                "AND actor_id = :a"
            ),
            {"t": tenant, "a": admin},
        ).scalar_one()
    assert revoked == 2
    assert verified == 2


@pytest.fixture
def factor_page(chromium, db, runtime):
    """The console on a deployment with account security, over the cleartext loopback origin
    every other browser test uses: second-factor status needs no WebAuthn."""
    if console_module.load_build() is None:
        pytest.fail("No console build is packaged: run `pnpm build` in console/ first")

    def app(origin):
        keys = TokenKeys("browser-v1", {"browser-v1": secrets.token_bytes(32)})
        return create_app(db, runtime=runtime, human=HumanConfig(origin, keys, mfa=RING))

    with (
        serve(app) as origin,
        chromium.new_context(base_url=origin, viewport={"width": 1280, "height": 900}) as context,
    ):
        opened = context.new_page()
        opened.set_default_timeout(ACTION_TIMEOUT_MS)
        opened.add_init_script(COLLECT)
        opened.add_init_script(path=str(AXE))
        yield opened


def test_ak11_people_settings_and_home_show_second_factor_status(factor_page, admin_engine, world):
    from test_key_last_used import legacy_factor

    page = factor_page
    tenant = world["admin"].tenant_id
    legacy_factor(admin_engine, tenant, world["human"].principal_id, enabled=True)
    sign_in_as(page, admin_engine, world["admin"])

    page.goto("/people")
    users = page.get_by_role("table", name=re.compile("Users matching the filters"))
    expect(users.get_by_role("columnheader", name="Second factor")).to_be_visible()
    expect(users).to_contain_text("Enrolled")
    expect(users).to_contain_text("None")
    clean(page, "users")

    page.goto(f"/people/{world['human'].principal_id}")
    sign_in_card = page.get_by_role("region", name="Sign-in").or_(
        page.locator("section").filter(has=page.get_by_role("heading", level=2, name="Sign-in"))
    )
    expect(sign_in_card.first).to_contain_text("Second factor")
    expect(sign_in_card.first).to_contain_text("Enrolled")
    expect(page.get_by_role("heading", level=3, name="Decisions")).to_be_visible()
    clean(page, "person")

    page.goto("/settings")
    card = page.locator("section").filter(
        has=page.get_by_role("heading", level=2, name="Multi-factor authentication")
    )
    expect(card).to_contain_text("Authenticator app")
    expect(card.get_by_role("link", name="Add a second factor")).to_have_attribute(
        "href", "/account/security"
    )
    clean(page, "my account")

    page.goto("/")
    notice = page.get_by_role("heading", level=2, name="Your account has no second factor")
    expect(notice).to_be_visible()
    clean(page, "home")
    page.get_by_role("button", name="Dismiss").click()
    expect(notice).to_have_count(0)
    page.reload()
    expect(page.get_by_role("heading", level=1)).to_be_visible()
    settled(page)
    expect(notice).to_have_count(0)


def test_ak7_the_agent_page_sections_open_and_read_in_both_schemes(
    console_page, admin_engine, world, found
):
    from test_agents_bindings import BIND
    from test_people_pages import call

    page = console_page
    sign_in_as(page, admin_engine, world["admin"])
    page.goto("/agents")
    page.get_by_role("button", name="Add agent").click()
    adding = page.get_by_role("dialog")
    adding.get_by_label("Agent host").select_option("mcp")
    adding.get_by_role("button", name="Continue").click()
    adding.get_by_label("Agent name").fill("Sections agent")
    with admin_engine.connect() as conn:
        space = conn.execute(
            text("SELECT space_id FROM execbound.spaces WHERE tenant_id = :t"),
            {"t": world["admin"].tenant_id},
        ).scalar_one()
    adding.get_by_label("Space", exact=True).select_option(str(space))
    adding.get_by_role("button", name="Create agent and connect").click()
    # A new agent opens on Connection, with the steps and the key form.
    expect(page).to_have_url(re.compile(r"/agents/[0-9a-f-]{36}\?section=connection$"))
    agent = page.url.split("/agents/")[1].split("?")[0]
    expect(page.get_by_role("heading", level=2, name="Connect this agent")).to_be_visible()
    expect(page.get_by_label("API key expires after")).to_be_visible()
    strip = page.get_by_role("navigation", name="Agent sections")
    expect(strip.get_by_role("link", name="Connection")).to_have_attribute("aria-current", "page")
    for name, section, heading in (
        ("Overview", "overview", "Summary"),
        ("Permissions", "permissions", "Permissions"),
        ("Activity", "activity", "Recent activity"),
        ("Advanced", "advanced", "Deactivate"),
        ("Connection", "connection", "API keys"),
    ):
        strip.get_by_role("link", name=name).click()
        expect(page).to_have_url(re.compile(rf"/agents/{agent}\?section={section}$"))
        expect(page.get_by_role("heading", level=2, name=heading, exact=True)).to_be_visible()
        expect(strip.get_by_role("link", name=name)).to_have_attribute("aria-current", "page")
        clean(page, section)
    # Back restores the section before.
    page.go_back()
    expect(page).to_have_url(re.compile(rf"/agents/{agent}\?section=advanced$"))
    expect(page.get_by_role("heading", level=2, name="Deactivate", exact=True)).to_be_visible()
    # A link through a bound agent's monitoring id lands on its principal and keeps the section.
    discovered = found["agents"][0]["agent_id"]
    call(
        admin_engine,
        world["admin"].tenant_id,
        BIND,
        {"a": world["admin"].principal_id, "g": discovered, "p": agent},
    )
    page.goto(f"/agents/{discovered}?section=permissions")
    expect(page).to_have_url(re.compile(rf"/agents/{agent}\?section=permissions$"))
    expect(page.get_by_role("heading", level=2, name="Permissions", exact=True)).to_be_visible()
    assert page.evaluate("window.__violations") == []
