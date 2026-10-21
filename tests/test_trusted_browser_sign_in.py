# SPDX-License-Identifier: AGPL-3.0-only
"""Trusting a browser at sign-in, and a later sign-in on it skipping the code (#859).

The sign-in factor prompt offers "Trust this browser for 30 days". A code, a recovery code or
a passkey verified with the box ticked grants a trust (`trusted_browsers.grant`) and sets the
Lax trust cookie; `GET /mfa`, where every sign-in that owes a factor lands, applies a cookie
that still holds (`trusted_browsers.apply`) and goes straight on. The trust satisfies the
sign-in factor and nothing more: a step-up-guarded console change still asks for a code, and
"Sign out other devices" and a replaced factor end it. Real PostgreSQL, over the ASGI client.
"""

import json
import re
from dataclasses import replace
from datetime import timedelta
from html import unescape

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import text
from test_passkeys import assertion, registration
from test_sign_in_surface import (
    ORIGIN,
    StandIn,
    account,
    form_values,
    landed_at,
    sign_in,
    started,
)
from test_sign_in_surface import bound_provider as bound_provider
from test_sign_in_surface import config as config
from test_sign_in_surface import connector as connector
from test_sign_in_surface import live_provider as live_provider
from test_sign_in_surface import providers as providers
from test_sign_in_surface import registry as registry
from test_sign_in_surface import runtime as runtime
from test_sign_in_surface import signed_up as signed_up
from test_sign_in_surface import world as world
from test_trusted_browsers import aged, trust_rows

from execbound import mfa, passkeys, trusted_browsers
from execbound.app import create_app
from execbound.envelope import KeyRing
from execbound.surfaces.human import landing
from execbound.surfaces.sessions import load_session

pytestmark = pytest.mark.integration

RING = KeyRing("test", {"test": b"m" * 32})
API = "/api/console/v1"
VERIFY = "/account/security/verify"
PASSKEY_START = "/account/security/passkey/authenticate/start"
PASSKEY_FINISH = "/account/security/passkey/authenticate/finish"
BOX = "Trust this browser for 30 days"
TRUST = "eb_trust"
THIRTY_DAYS = int(timedelta(days=30).total_seconds())


def step(runtime) -> int:
    return int(runtime.clock.now().timestamp() // 30)


@pytest.fixture
def app(db, runtime, config):
    return create_app(db, runtime=runtime, human=replace(config, mfa=RING))


@pytest.fixture
def browser(app):
    """One browser: its cookie jar is the browser's, the trust cookie among them."""
    with TestClient(app, base_url=ORIGIN, follow_redirects=False) as client:
        yield client


@pytest.fixture
def enrolled(db, runtime, signed_up, browser):
    """The approver with an authenticator confirmed on a session of their own, and a passkey
    registered on it. Registering moves the account's version, which ends any trust before
    it, so it is done here, before any test grants one."""
    assert sign_in(browser).status_code == 303
    session = load_session(db, browser.cookies.get("eb_session"), clock=runtime.clock)
    assert session.account_id is not None
    seed = mfa.begin_enrollment(db, session, RING, clock=runtime.clock)
    codes = mfa.confirm_enrollment(
        db, session, RING, mfa.totp(seed, step(runtime)), clock=runtime.clock
    )
    options = passkeys.begin(db, session, ORIGIN, "register", clock=runtime.clock)
    private, identifier, response = registration(options)
    assert passkeys.complete(db, session, ORIGIN, "register", response, clock=runtime.clock)
    browser.cookies.clear()
    # The next time step, so a code from it is never a replay of the one above.
    runtime.clock.value += timedelta(seconds=30)
    return {
        "seed": seed,
        "codes": codes,
        "private": private,
        "identifier": identifier,
        "account": session.account_id,
        "tenant": session.identity.tenant_id,
    }


def challenge(client):
    """A password sign-in that owes the code, and the code prompt it lands on."""
    answer = sign_in(client)
    assert answer.status_code == 303 and answer.headers["location"] == "/mfa", answer.text
    page = client.get("/mfa")
    assert page.status_code == 200 and "<h1>Two-step verification</h1>" in page.text
    return page


def trust_cookies(answer):
    return [c for c in answer.headers.get_list("set-cookie") if c.startswith(TRUST + "=")]


def verified(client, runtime, enrolled, method, *, trust):
    """Finish a sign-in from its code prompt with `method`, ticking the box when `trust`."""
    page = challenge(client)
    ticked = {"trust": "on"} if trust else {}
    if method == "passkey":
        begun = client.post(
            PASSKEY_START, data=form_values(page.text, PASSKEY_START), headers={"Origin": ORIGIN}
        )
        assert begun.status_code == 200, begun.text
        assert BOX in begun.text
        options = json.loads(
            unescape(re.search(r'id="passkey-options" value="([^"]*)"', begun.text).group(1))
        )
        sent = assertion(options, enrolled["private"], enrolled["identifier"])
        fields = {**form_values(begun.text, PASSKEY_FINISH), "credential": json.dumps(sent)}
        return client.post(PASSKEY_FINISH, data={**fields, **ticked}, headers={"Origin": ORIGIN})
    code = mfa.totp(enrolled["seed"], step(runtime)) if method == "totp" else enrolled["codes"][0]
    fields = {**form_values(page.text, VERIFY), "code": code}
    assert "trust" not in fields, "an unticked box is never posted"
    return client.post(VERIFY, data={**fields, **ticked}, headers={"Origin": ORIGIN})


def assurance(admin_engine, client, db, runtime):
    session = load_session(db, client.cookies.get("eb_session"), clock=runtime.clock)
    with admin_engine.begin() as conn:
        return (
            conn.execute(
                text(
                    "SELECT method, verified_at FROM execbound.session_assurance "
                    "WHERE tenant_id=:t AND session_id=:s"
                ),
                {"t": session.identity.tenant_id, "s": session.session_id},
            )
            .mappings()
            .one()
        )


def trusted_sign_ins(admin_engine, tenant):
    """The workspace's `account_security.trusted_sign_in` records, oldest first."""
    with admin_engine.begin() as conn:
        return list(
            conn.execute(
                text(
                    "SELECT payload FROM execbound.audit_events WHERE tenant_id=:t "
                    "AND kind='account_security.trusted_sign_in' ORDER BY sequence"
                ),
                {"t": tenant},
            ).scalars()
        )


def skips_the_code(client):
    """A password sign-in on this browser that goes straight on from `/mfa`."""
    answer = sign_in(client)
    assert answer.headers["location"] == "/mfa"
    assert client.get(API + "/settings").status_code == 401
    onward = client.get("/mfa")
    assert onward.status_code == 303, onward.text
    assert onward.headers["location"] == landing("HUMAN_APPROVER")
    issued = onward.headers.get_list("set-cookie")
    assert any(c.startswith("eb_session=") for c in issued)
    assert any(c.startswith("eb_csrf=") for c in issued)
    # The account cookie the sign-in set is kept: trust issues no new one and clears none.
    assert not any(c.startswith("eb_account=") for c in issued)
    assert client.get(API + "/settings").status_code == 200
    return onward


def asks_for_the_code(client):
    answer = sign_in(client)
    assert answer.headers["location"] == "/mfa"
    page = client.get("/mfa")
    assert page.status_code == 200 and "<h1>Two-step verification</h1>" in page.text
    assert client.get(API + "/settings").status_code == 401


@pytest.mark.parametrize("method", ["totp", "recovery", "passkey"])
def test_tb_ticking_the_box_sets_the_cookie_and_the_next_sign_in_skips_the_code(
    browser, db, runtime, admin_engine, enrolled, method
):
    page = challenge(browser)
    # One box in each of the code and recovery forms, unticked.
    assert page.text.count(BOX) == 2
    assert page.text.count('<input type="checkbox" name="trust" value="on">') == 2
    assert " checked" not in page.text
    done = verified(browser, runtime, enrolled, method, trust=True)
    assert done.status_code == 303, done.text
    assert done.headers["location"] == landing("HUMAN_APPROVER")
    [cookie] = trust_cookies(done)
    attributes = [part.strip().lower() for part in cookie.split(";")]
    assert "httponly" in attributes and "path=/" in attributes
    # Lax: a provider's sign-in finishes on a cross-site navigation, which Strict is not sent on.
    assert "samesite=lax" in attributes
    age = int(next(a for a in attributes if a.startswith("max-age=")).split("=")[1])
    assert THIRTY_DAYS - 60 <= age <= THIRTY_DAYS
    value = cookie.split(";", 1)[0].split("=", 1)[1]
    assert value.startswith("tb1.") and value not in done.text
    original = assurance(admin_engine, browser, db, runtime)
    assert original["method"] == method
    # A sign-in that entered its code is not a trusted one, and records none.
    assert trusted_sign_ins(admin_engine, enrolled["tenant"]) == []

    skips_the_code(browser)
    # The trusted sign-in's assurance keeps the original verification's time, never now.
    trusted = assurance(admin_engine, browser, db, runtime)
    assert trusted["method"] == "trusted"
    assert trusted["verified_at"] == original["verified_at"]
    # And the workspace's chain records it: the session, the trust, and the verification
    # behind it, by its own method and time.
    session = load_session(db, browser.cookies.get("eb_session"), clock=runtime.clock)
    [granted] = trusted_browsers.listed(db, session, clock=runtime.clock)
    assert trusted_sign_ins(admin_engine, enrolled["tenant"]) == [
        {
            "session_id": str(session.session_id),
            "browser_id": str(granted.browser_id),
            "method": method,
            "verified_at": original["verified_at"].isoformat(timespec="microseconds"),
        }
    ]


def test_tb_an_unticked_box_sets_no_cookie(browser, runtime, enrolled):
    done = verified(browser, runtime, enrolled, "totp", trust=False)
    assert done.status_code == 303 and trust_cookies(done) == []
    assert browser.cookies.get(TRUST) is None
    asks_for_the_code(browser)


def test_tb_a_tampered_cookie_shows_the_code_prompt(browser, runtime, admin_engine, enrolled):
    done = verified(browser, runtime, enrolled, "recovery", trust=True)
    value = trust_cookies(done)[0].split(";", 1)[0].split("=", 1)[1]
    tampered = value[:-1] + ("A" if value[-1] != "A" else "B")
    browser.cookies.set(TRUST, tampered, domain="127.0.0.1", path="/")
    asks_for_the_code(browser)
    browser.cookies.set(TRUST, "not a trust", domain="127.0.0.1", path="/")
    asks_for_the_code(browser)
    # A cookie that satisfied nothing records no trusted sign-in.
    assert trusted_sign_ins(admin_engine, enrolled["tenant"]) == []


def test_tb_a_refused_grant_still_signs_in(browser, runtime, admin_engine, world, enrolled):
    """A workspace that forbids trust refuses the grant; the person still signs in, without
    a cookie, and the next sign-in asks for the code."""
    with admin_engine.begin() as conn:
        conn.execute(
            text(
                "INSERT INTO execbound.account_security_policy(tenant_id,requirement,changed_at,"
                "changed_by,allow_trusted_browsers) VALUES(:t,'optional',now(),:p,false) "
                "ON CONFLICT(tenant_id) DO UPDATE SET allow_trusted_browsers=false"
            ),
            {"t": enrolled["tenant"], "p": world["admin"].principal_id},
        )
    done = verified(browser, runtime, enrolled, "totp", trust=True)
    assert done.status_code == 303, done.text
    assert done.headers["location"] == landing("HUMAN_APPROVER")
    assert trust_cookies(done) == []
    assert browser.get(API + "/settings").status_code == 200
    asks_for_the_code(browser)


def test_tb_a_workspace_that_forbids_trust_offers_no_box(browser, admin_engine, world, enrolled):
    """Where the administrator forbids trust, none of the three ways to verify offers the box:
    the code form, the recovery form and the passkey form."""
    page = challenge(browser)
    assert page.text.count(BOX) == 2
    with admin_engine.begin() as conn:
        conn.execute(
            text(
                "INSERT INTO execbound.account_security_policy(tenant_id,requirement,changed_at,"
                "changed_by,allow_trusted_browsers) VALUES(:t,'optional',now(),:p,false) "
                "ON CONFLICT(tenant_id) DO UPDATE SET allow_trusted_browsers=false"
            ),
            {"t": enrolled["tenant"], "p": world["admin"].principal_id},
        )
    page = challenge(browser)
    assert BOX not in page.text and 'name="trust"' not in page.text
    # Both ways to enter a code are still there, without it.
    assert page.text.count('action="/account/security/verify"') == 2
    begun = browser.post(
        PASSKEY_START, data=form_values(page.text, PASSKEY_START), headers={"Origin": ORIGIN}
    )
    assert begun.status_code == 200, begun.text
    assert 'id="passkey-finish"' in begun.text
    assert BOX not in begun.text and 'name="trust"' not in begun.text


def test_tb_the_box_is_not_offered_once_signed_in(browser, runtime, enrolled):
    """Account security's own verification is not a sign-in, and offers no box; a box posted
    to it anyway trusts nothing."""
    verified(browser, runtime, enrolled, "recovery", trust=False)
    page = browser.get("/account/security")
    assert page.status_code == 200 and BOX not in page.text
    runtime.clock.value += timedelta(seconds=30)
    fields = form_values(page.text, VERIFY)
    again = browser.post(
        VERIFY,
        data={**fields, "code": mfa.totp(enrolled["seed"], step(runtime)), "trust": "on"},
        headers={"Origin": ORIGIN},
    )
    assert again.status_code == 200, again.text
    assert trust_cookies(again) == []
    refused = browser.post(
        VERIFY,
        data={**fields, "code": "000000", "trust": "yes"},
        headers={"Origin": ORIGIN},
    )
    assert refused.status_code == 403


def console_post(client, path, body):
    """A console change as the console sends it: the CSRF token, the Origin, JSON, and the
    workspace the page was loaded for, which an account session's change must name."""
    csrf = client.get(API + "/session").json()["csrf_token"]
    session_id = client.cookies.get("eb_session").split(".")[2]
    return client.post(
        API + path,
        content=json.dumps(body).encode(),
        headers={
            "Origin": ORIGIN,
            "X-CSRF-Token": csrf,
            "Content-Type": "application/json",
            "X-ExecBound-Workspace": session_id,
        },
    )


def test_tb_trusted_sign_in_still_asks_for_step_up(browser, runtime, admin_engine, enrolled):
    """Review Focus 1: two days after the grant, a trusted sign-in still answers a
    step-up-guarded change `MFA_REQUIRED`, because its assurance keeps the original time and
    method `trusted` is never fresh."""
    done = verified(browser, runtime, enrolled, "recovery", trust=True)
    assert trust_cookies(done)
    aged(admin_engine, enrolled["account"], timedelta(days=2))
    skips_the_code(browser)
    # `/invitations` is the hosted plugin's and is not served here; changing one's own
    # password is a step-up-guarded change every signed-in person may make.
    refused = console_post(browser, "/settings/password", {})
    assert refused.status_code == 401, refused.text
    assert refused.json()["code"] == "MFA_REQUIRED"
    # A code entered now satisfies it: the refusal was the step-up's, and trust is no code.
    runtime.clock.value += timedelta(seconds=30)
    answered = console_post(
        browser, "/session/verify", {"code": mfa.totp(enrolled["seed"], step(runtime))}
    )
    assert answered.status_code == 200, answered.text
    assert console_post(browser, "/settings/password", {}).json().get("code") != "MFA_REQUIRED"


def test_tb_sign_out_other_devices_ends_every_trust(db, runtime, config, browser, enrolled):
    """Review Focus 3: two browsers trusted, then "Sign out other devices" from one of them;
    neither skips the code afterwards, the one that asked included."""
    verified(browser, runtime, enrolled, "recovery", trust=True)
    # A second browser, on an app of its own: one app's lifespan runs once.
    second_app = create_app(db, runtime=runtime, human=replace(config, mfa=RING))
    with TestClient(second_app, base_url=ORIGIN, follow_redirects=False) as other:
        second = dict(enrolled, codes=enrolled["codes"][1:])
        assert trust_cookies(verified(other, runtime, second, "recovery", trust=True))
        skips_the_code(other)
        skips_the_code(browser)
        ended = console_post(browser, "/settings/sessions/revoke-others", {})
        assert ended.status_code == 200, ended.text
        asks_for_the_code(other)
        asks_for_the_code(browser)


def test_tb_a_replaced_factor_ends_trust(browser, db, runtime, admin_engine, enrolled):
    """Review Focus 4: replacing the authenticator ends the trust granted with the old one.
    The trust's row is still there, unexpired and never removed: what ends it is the factor's
    version moving past the one it was granted at."""
    done = verified(browser, runtime, enrolled, "recovery", trust=True)
    assert trust_cookies(done)
    session = load_session(db, browser.cookies.get("eb_session"), clock=runtime.clock)
    seed = mfa.begin_enrollment(db, session, RING, clock=runtime.clock)
    runtime.clock.value += timedelta(seconds=30)
    mfa.confirm_enrollment(db, session, RING, mfa.totp(seed, step(runtime)), clock=runtime.clock)
    [row] = trust_rows(admin_engine, enrolled["account"])
    assert row["revoked_at"] is None and row["expires_at"] > runtime.clock.now()
    asks_for_the_code(browser)


@pytest.mark.parametrize("providers", [[StandIn(account=account())]], indirect=True)
def test_tb_provider_sign_in_honours_trust(browser, runtime, providers, bound_provider, enrolled):
    """A Google-style sign-in returns on a cross-site navigation and lands on `/mfa`, which
    applies the Lax trust cookie like any other sign-in that owes the factor."""
    done = verified(browser, runtime, enrolled, "recovery", trust=True)
    assert trust_cookies(done)
    for name in ("eb_session", "eb_csrf"):
        browser.cookies.delete(name)
    state = started(browser).headers["location"].split("state=", 1)[1]
    back = browser.get(f"/login/google/callback?code=the-code&state={state}")
    assert landed_at(back) == "/mfa"
    assert browser.get(API + "/settings").status_code == 401
    onward = browser.get("/mfa")
    assert onward.status_code == 303, onward.text
    assert onward.headers["location"] == landing("HUMAN_APPROVER")
    assert browser.get(API + "/settings").status_code == 200


def test_tb_the_trust_lists_the_browser_that_was_trusted(browser, db, runtime, enrolled):
    """The grant records this browser's fixed device label from its User-Agent."""
    browser.headers["User-Agent"] = (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36"
    )
    verified(browser, runtime, enrolled, "recovery", trust=True)
    session = load_session(db, browser.cookies.get("eb_session"), clock=runtime.clock)
    [trust] = trusted_browsers.listed(db, session, clock=runtime.clock)
    assert trust.label == "Chrome on Windows"
