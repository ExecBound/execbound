# SPDX-License-Identifier: AGPL-3.0-only
"""The console's step-up in place (decided 28 September 2026): `POST /session/verify`.

A console change the step-up refuses answers `MFA_REQUIRED`. The console then asks for a code
over the page, sends it here, and sends the refused change again once. This route verifies the
code with the same `mfa.verify_factor` the account security page calls and rotates the session
and its CSRF token with the same `mfa.rotate_verified_session`, so it verifies nothing a new
way; it answers the new CSRF token, which the console holds in memory as it holds the one the
session route hands over. Real PostgreSQL throughout.
"""

from contextlib import contextmanager
from dataclasses import replace
from datetime import timedelta

import pytest
from console_api_fixtures import (
    API,
    ORIGIN,
    assert_no_secrets,
    console_client,
    console_config,
    refusals,
)
from fastapi.testclient import TestClient
from sqlalchemy import text
from test_execution import provision_identity
from test_human_surface import credential, form_values
from test_passkeys import assertion, registration
from test_sign_in_surface import NEW_PASSWORD, PASSWORD, sign_in
from test_sign_in_surface import config as config
from test_sign_in_surface import connector as connector
from test_sign_in_surface import live_provider as live_provider
from test_sign_in_surface import providers as providers
from test_sign_in_surface import registry as registry
from test_sign_in_surface import runtime as runtime
from test_sign_in_surface import signed_up as signed_up
from test_sign_in_surface import world as world

from execbound import mfa, passkeys
from execbound.app import create_app
from execbound.envelope import KeyRing
from execbound.surfaces.console_api.guards import (
    STEP_UP_EXACT,
    STEP_UP_NESTED,
    STEP_UP_PREFIXES,
    steps_up,
)
from execbound.surfaces.console_api.token_rules import TOKEN_ALLOWED, TOKEN_REFUSED
from execbound.surfaces.sessions import SessionError, issue_session, load_session

pytestmark = pytest.mark.integration

RING = KeyRing("test", {"test": b"m" * 32})
VERIFY = API + "/session/verify"
ISSUE = API + "/settings/tokens/issue"
WRONG = "000000"


def step(runtime) -> int:
    return int(runtime.clock.now().timestamp() // 30)


def events(admin_engine, tenant, kind) -> int:
    with admin_engine.connect() as conn:
        return int(
            conn.execute(
                text("SELECT count(*) FROM execbound.audit_events WHERE tenant_id=:t AND kind=:k"),
                {"t": tenant, "k": kind},
            ).scalar_one()
        )


def tokens_issued(admin_engine, tenant) -> int:
    with admin_engine.connect() as conn:
        return int(
            conn.execute(
                text("SELECT count(*) FROM execbound.personal_access_tokens WHERE tenant_id=:t"),
                {"t": tenant},
            ).scalar_one()
        )


def stale(admin_engine, tenant, session_id, minutes=31) -> None:
    """Age this session's verified factor past the step-up's thirty minutes. The row is moved,
    not the clock: the token issue function refuses a clock far from the database's own. The
    injected clock carries the window itself in `test_mfa_sessions.py` and the browser test."""
    with admin_engine.begin() as conn:
        conn.execute(
            text(
                "UPDATE execbound.session_assurance SET verified_at = verified_at - :age "
                "WHERE tenant_id = :t AND session_id = :s"
            ),
            {"age": timedelta(minutes=minutes), "t": tenant, "s": session_id},
        )


@contextmanager
def enrolled_admin(db, runtime, admin_engine, world):
    """The fixture administrator, signed in, with an authenticator confirmed on this session
    and verified long enough ago that a change asks again."""
    with console_client(
        db, runtime, admin_engine, world["admin"], config=console_config(mfa=RING)
    ) as client:
        session = load_session(db, client.client.cookies.get("eb_session"), clock=runtime.clock)
        seed = mfa.begin_enrollment(db, session, RING, clock=runtime.clock)
        codes = mfa.confirm_enrollment(
            db, session, RING, mfa.totp(seed, step(runtime)), clock=runtime.clock
        )
        stale(admin_engine, world["admin"].tenant_id, session.session_id)
        # The next time step, so a code from it is never a replay of the one above.
        runtime.clock.value += timedelta(seconds=30)
        yield client, seed, codes, session


@pytest.mark.parametrize("method", ["POST"])
def test_only_a_signed_in_person_reaches_it(db, runtime, seeded, admin_engine, world, method):
    results = refusals(db, runtime, seeded, admin_engine, world, VERIFY, method)
    assert results["bearer"].status_code == 403
    assert results["bearer"].json()["code"] == "FORBIDDEN"
    assert results["audited"] == 1
    missing = results["no_session"]
    assert missing.status_code == 401 and missing.json()["code"] == "SESSION_REQUIRED"
    assert missing.headers["content-type"].startswith("application/json")


def test_the_token_the_origin_and_the_body_are_checked_first(db, runtime, admin_engine, world):
    with enrolled_admin(db, runtime, admin_engine, world) as (client, seed, _, _):
        code = mfa.totp(seed, step(runtime))
        wrong = client.post(VERIFY, {"code": code}, csrf="wrong")
        assert wrong.status_code == 403 and wrong.json()["code"] == "INVALID_CSRF"
        elsewhere = client.post(VERIFY, {"code": code}, origin="http://evil.example")
        assert elsewhere.status_code == 403
        assert client.post(VERIFY, {"code": code}, content_type="text/plain").status_code == 415
        unknown = client.post(VERIFY, {"code": code, "remember": True})
        assert unknown.status_code == 400 and unknown.json()["code"] == "INVALID_BODY"
        long = client.post(VERIFY, {"code": "1" * 65})
        assert long.status_code == 400 and long.json()["fields"] == ["code"]
        assert client.get(VERIFY).status_code == 405
        # None of those reached a factor: the code is still unused and still works.
        assert client.post(VERIFY, {"code": code}).status_code == 200


def test_a_wrong_code_says_so_and_changes_nothing(db, runtime, admin_engine, world):
    tenant = world["admin"].tenant_id
    with enrolled_admin(db, runtime, admin_engine, world) as (client, _, _, session):
        failed = events(admin_engine, tenant, "account_security.verification_failed")
        before = client.client.cookies.get("eb_session")
        refused = client.post(VERIFY, {"code": WRONG})
        assert refused.status_code == 400, refused.text
        assert refused.json() == {
            "code": "INVALID_FACTOR",
            "detail": "That code could not be used.",
        }
        assert_no_secrets(refused)
        # The attempt is recorded as the security page records one, and counts toward its lock.
        assert events(admin_engine, tenant, "account_security.verification_failed") == failed + 1
        assert client.client.cookies.get("eb_session") == before
        load_session(db, before, clock=runtime.clock)
        still = client.post(ISSUE, {"name": "ci", "lifetime": "8"})
        assert still.status_code == 401 and still.json()["code"] == "MFA_REQUIRED"


def test_a_current_code_rotates_the_session_and_the_change_goes_through_resent_once(
    db, runtime, admin_engine, world
):
    tenant = world["admin"].tenant_id
    with enrolled_admin(db, runtime, admin_engine, world) as (client, seed, _, session):
        issued = tokens_issued(admin_engine, tenant)
        refused = client.post(ISSUE, {"name": "ci", "lifetime": "8"})
        assert refused.status_code == 401 and refused.json()["code"] == "MFA_REQUIRED"
        assert tokens_issued(admin_engine, tenant) == issued

        verified_before = events(admin_engine, tenant, "account_security.verified")
        old_token, old_csrf = client.client.cookies.get("eb_session"), client.csrf
        answer = client.post(VERIFY, {"code": mfa.totp(seed, step(runtime))})
        assert answer.status_code == 200, answer.text
        assert answer.headers["cache-control"] == "no-store"
        new_csrf = answer.json()["csrf_token"]
        assert set(answer.json()) == {"csrf_token"}
        assert new_csrf != old_csrf and len(new_csrf) >= 32
        # The session and the CSRF cookie both rotate, as the security page rotates them, and
        # the old session is gone.
        new_token = client.client.cookies.get("eb_session")
        assert new_token != old_token
        assert client.client.cookies.get("eb_csrf") == new_csrf
        cookies = [
            c
            for c in answer.headers.get_list("set-cookie")
            if c.startswith(("eb_session=", "eb_csrf="))
        ]
        assert len(cookies) == 2
        assert all("HttpOnly" in c and "SameSite=strict" in c for c in cookies)
        with pytest.raises(SessionError):
            load_session(db, old_token, clock=runtime.clock)
        assert load_session(db, new_token, clock=runtime.clock).session_id == session.session_id
        assert events(admin_engine, tenant, "account_security.verified") == verified_before + 1

        # The change sent again with the token it first carried is refused and does nothing.
        replayed = client.post(ISSUE, {"name": "ci", "lifetime": "8"}, csrf=old_csrf)
        assert replayed.status_code == 403 and replayed.json()["code"] == "INVALID_CSRF"
        assert tokens_issued(admin_engine, tenant) == issued
        # Sent again with the new one, it goes through.
        client.csrf = new_csrf
        resent = client.post(ISSUE, {"name": "ci", "lifetime": "8"})
        assert resent.status_code == 200, resent.text
        assert tokens_issued(admin_engine, tenant) == issued + 1
        # And the session route now hands over the same new token.
        assert client.get(API + "/session").json()["csrf_token"] == new_csrf


def test_a_recovery_code_steps_up_once(db, runtime, admin_engine, world):
    tenant = world["admin"].tenant_id
    with enrolled_admin(db, runtime, admin_engine, world) as (client, _, codes, session):
        used = events(admin_engine, tenant, "account_security.recovery_used")
        answer = client.post(VERIFY, {"code": codes[0]})
        assert answer.status_code == 200, answer.text
        client.csrf = answer.json()["csrf_token"]
        assert events(admin_engine, tenant, "account_security.recovery_used") == used + 1
        assert client.post(ISSUE, {"name": "ci", "lifetime": "8"}).status_code == 200
        stale(admin_engine, tenant, session.session_id)
        again = client.post(VERIFY, {"code": codes[0]})
        assert again.status_code == 400 and again.json()["code"] == "INVALID_FACTOR"
        overview = mfa.security_overview(
            db,
            load_session(db, client.client.cookies.get("eb_session"), clock=runtime.clock),
            clock=runtime.clock,
        )
        assert overview["recovery_remaining"] == 9


def test_five_wrong_codes_lock_verification_as_the_page_does(db, runtime, admin_engine, world):
    with enrolled_admin(db, runtime, admin_engine, world) as (client, seed, _, _):
        for _ in range(5):
            assert client.post(VERIFY, {"code": WRONG}).json()["code"] == "INVALID_FACTOR"
        locked = client.post(VERIFY, {"code": mfa.totp(seed, step(runtime))})
        assert locked.status_code == 400 and locked.json()["code"] == "INVALID_FACTOR"
        assert client.post(ISSUE, {"name": "ci", "lifetime": "8"}).json()["code"] == "MFA_REQUIRED"


def test_a_session_still_signing_in_is_left_to_the_mfa_page(db, runtime, admin_engine, world):
    """The second step of signing in stays a page of its own: a session with no verified
    factor at all cannot use this route to finish signing in."""
    with enrolled_admin(db, runtime, admin_engine, world) as (_, seed, _, _):
        app = create_app(db, runtime=runtime, human=console_config(mfa=RING))
        with TestClient(app, base_url=ORIGIN, follow_redirects=False) as fresh:
            _, values = form_values(fresh.get("/login").text, "/session")
            values["credential"] = credential(admin_engine, world["admin"])
            signed = fresh.post("/session", data=values, headers={"Origin": ORIGIN})
            assert signed.headers["location"] == "/mfa"
            answer = fresh.post(
                VERIFY,
                content=b'{"code": "%s"}' % mfa.totp(seed, step(runtime)).encode(),
                headers={
                    "Origin": ORIGIN,
                    "Content-Type": "application/json",
                    "X-CSRF-Token": fresh.cookies.get("eb_csrf"),
                },
            )
            assert answer.status_code == 401 and answer.json()["code"] == "MFA_REQUIRED"


def test_without_a_factor_or_account_security_it_refuses(db, runtime, admin_engine, world):
    with console_client(
        db, runtime, admin_engine, world["admin"], config=console_config(mfa=RING)
    ) as client:
        none = client.post(VERIFY, {"code": WRONG})
        assert none.status_code == 409 and none.json()["code"] == "CONFLICT"
    with console_client(db, runtime, admin_engine, world["admin"]) as client:
        off = client.post(VERIFY, {"code": WRONG})
        assert off.status_code == 503 and off.json()["code"] == "UNAVAILABLE"


def test_an_account_changes_its_password_twenty_minutes_on_and_after_stepping_up(
    db, runtime, config, signed_up, admin_engine
):
    """An account's password change is checked twice, by the console's step-up and by the
    definer function beneath it (0067); the two read the same thirty minutes, so a change at
    minute twenty goes through, and one at minute thirty-one goes through after a code."""
    settings = replace(config, mfa=RING)
    with TestClient(
        create_app(db, runtime=runtime, human=settings), base_url=ORIGIN, follow_redirects=False
    ) as client:
        assert sign_in(client).status_code == 303
        session = load_session(db, client.cookies.get("eb_session"), clock=runtime.clock)
        assert session.account_id is not None
        seed = mfa.begin_enrollment(db, session, RING, clock=runtime.clock)
        mfa.confirm_enrollment(
            db, session, RING, mfa.totp(seed, step(runtime)), clock=runtime.clock
        )

        def view():
            opened = client.get(API + "/session")
            assert opened.status_code == 200, opened.text
            return opened.json()

        def age(minutes):
            for _ in range(minutes // 5):
                runtime.clock.value += timedelta(minutes=5)
                view()

        def change(current, new, csrf):
            return client.post(
                API + "/settings/password",
                json={"current": current, "new": new},
                headers={
                    "Origin": ORIGIN,
                    "X-CSRF-Token": csrf,
                    "X-ExecBound-Workspace": view()["generation"],
                },
            )

        age(20)
        changed = change(PASSWORD, NEW_PASSWORD, view()["csrf_token"])
        assert changed.status_code == 200, changed.text

        age(15)
        csrf = view()["csrf_token"]
        third = "a third passphrase, just as long"
        refused = change(NEW_PASSWORD, third, csrf)
        assert refused.status_code == 401 and refused.json()["code"] == "MFA_REQUIRED"
        runtime.clock.value += timedelta(seconds=30)
        answer = client.post(
            VERIFY,
            json={"code": mfa.totp(seed, step(runtime))},
            headers={
                "Origin": ORIGIN,
                "X-CSRF-Token": csrf,
                "X-ExecBound-Workspace": view()["generation"],
            },
        )
        assert answer.status_code == 200, answer.text
        assert change(NEW_PASSWORD, third, csrf).json()["code"] == "INVALID_CSRF"
        resent = change(NEW_PASSWORD, third, answer.json()["csrf_token"])
        assert resent.status_code == 200, resent.text


def test_the_security_page_states_the_same_thirty_minutes(db, runtime, admin_engine, world):
    with enrolled_admin(db, runtime, admin_engine, world) as (client, _, _, _):
        page = client.get("/account/security")
        assert page.status_code == 200
        assert "Verification lasts thirty minutes." in page.text
        assert "lasts five minutes" not in page.text


# The hosted plugin's sandbox pool: its routes are the plugin's, and its own tests hold them.
PLUGIN_PREFIXES = {"/api/console/v1/invitations"}


# Who approves a request and who acts in a space, stepped up since 3 October 2026. A placeholder
# id is enough: the step-up refuses before the route reads its body or looks anything up.
PLACEHOLDER = "00000000-0000-4000-8000-000000000001"
APPROVAL_CHANGES = (
    API + "/approval-rules",
    API + f"/approval-rules/{PLACEHOLDER}",
    API + f"/approval-rules/{PLACEHOLDER}/disable",
    API + "/approvers/assign",
    API + "/approvers/unassign",
    API + f"/spaces/{PLACEHOLDER}/members/assign",
    API + f"/spaces/{PLACEHOLDER}/members/unassign",
)


def test_who_approves_and_who_acts_in_a_space_ask_for_a_recent_factor(
    db, runtime, admin_engine, world
):
    """An approval rule and an approver assignment decide who may approve a request, and a
    space's membership who may act in it, so a session whose factor was verified more than
    thirty minutes ago changes none of them until it verifies again (THREAT_MODEL.md T4.48),
    as for people, access and credentials. Renaming a space is not one of them and is never
    asked. Once a code is verified none of the seven is refused for the step-up; each then
    answers its placeholder body by its own validation, so the refusal was the step-up alone."""
    with enrolled_admin(db, runtime, admin_engine, world) as (client, seed, _codes, _session):
        for path in APPROVAL_CHANGES:
            refused = client.post(path, {})
            assert (refused.status_code, refused.json()["code"]) == (401, "MFA_REQUIRED"), path
        renamed = client.post(API + f"/spaces/{PLACEHOLDER}/rename", {})
        assert renamed.json().get("code") != "MFA_REQUIRED"

        verified = client.post(VERIFY, {"code": mfa.totp(seed, step(runtime))})
        assert verified.status_code == 200, verified.text
        client.csrf = verified.json()["csrf_token"]
        for path in APPROVAL_CHANGES:
            answered = client.post(path, {})
            assert answered.json().get("code") != "MFA_REQUIRED", (path, answered.text)


# What admission decides with, and whether it enforces at all, stepped up since #678.
# Installing or refreshing the samples activates the starter policy, so both ask too.
POLICY_CHANGES = (
    API + f"/policy/{PLACEHOLDER}/activate",
    API + "/tenant/mode",
    API + "/samples",
    API + "/samples/refresh",
)
# The rest of a policy's lifecycle stays outside the step-up, and removing the samples only
# tightens.
POLICY_UNASKED = (
    API + f"/policy/{PLACEHOLDER}/validate",
    API + f"/policy/{PLACEHOLDER}/retire",
    API + f"/policy/{PLACEHOLDER}/preview",
    API + f"/policy/{PLACEHOLDER}/rules",
    API + "/policy",
    API + "/samples/remove",
)


def test_activating_a_policy_and_changing_the_mode_ask_for_a_recent_factor(
    db, runtime, admin_engine, world
):
    """Activation decides what every agent in a Space may do, and the mode decides whether
    anything is enforced, so neither goes through on a factor verified more than thirty
    minutes ago (THREAT_MODEL.md T4.48). The refusal comes before the body is read:
    an empty body is answered MFA_REQUIRED, not INVALID_BODY. The mode route asks in both
    directions, because the set is path-based and checked before the body is read."""
    tenant = world["admin"].tenant_id
    with enrolled_admin(db, runtime, admin_engine, world) as (client, seed, _codes, _session):
        changed = ("tenant.mode_changed", "policy.bundle_activated")
        before = [events(admin_engine, tenant, kind) for kind in changed]
        for path in POLICY_CHANGES:
            refused = client.post(path, {})
            assert (refused.status_code, refused.json()["code"]) == (401, "MFA_REQUIRED"), path
        for mode in ("OBSERVE", "ENFORCE"):
            refused = client.post(API + "/tenant/mode", {"mode": mode, "reason": "Pilot"})
            assert (refused.status_code, refused.json()["code"]) == (401, "MFA_REQUIRED"), mode
        assert [events(admin_engine, tenant, kind) for kind in changed] == before
        for path in POLICY_UNASKED:
            answered = client.post(path, {})
            assert answered.json().get("code") != "MFA_REQUIRED", (path, answered.text)
        verified = client.post(VERIFY, {"code": mfa.totp(seed, step(runtime))})
        assert verified.status_code == 200, verified.text
        client.csrf = verified.json()["csrf_token"]
        for path in POLICY_CHANGES:
            answered = client.post(path, {})
            assert answered.json().get("code") != "MFA_REQUIRED", (path, answered.text)


def test_every_step_up_prefix_covers_a_change_core_serves():
    """A prefix that matches no route steps nothing up and no request fails, so nothing notices:
    the directory's routes are `/tenant/sign-in`, and a `/sign-in/` prefix left registering and
    switching a tenant's identity provider without a recent factor until 2 October 2026. Every
    console API route is classified for tokens, so the two sets are the whole route table."""
    changes = {path for path, method in TOKEN_ALLOWED | TOKEN_REFUSED if method != "GET"}
    for prefix in STEP_UP_PREFIXES:
        covered = [path for path in changes if path.startswith(prefix)]
        if prefix in PLUGIN_PREFIXES:
            assert covered == [], f"{prefix} is the hosted plugin's, but core serves {covered}"
        else:
            assert covered, f"{prefix} steps up no route core serves"
    for prefix, part in STEP_UP_NESTED:
        covered = [path for path in changes if path.startswith(prefix) and part in path]
        assert covered, f"{prefix}...{part} steps up no route core serves"
    for path in STEP_UP_EXACT:
        assert path in changes, f"{path} steps up no route core serves"
    stepped = {path for path in changes if steps_up(path)}
    assert {
        "/api/console/v1/tenant/sign-in",
        "/api/console/v1/tenant/sign-in/{provider_id}/state",
        "/api/console/v1/approval-rules",
        "/api/console/v1/approvers/assign",
        "/api/console/v1/spaces/{space_id}/members/assign",
        "/api/console/v1/policy/{bundle_id}/activate",
        "/api/console/v1/tenant/mode",
        "/api/console/v1/samples",
        "/api/console/v1/samples/refresh",
        # Connecting Tines, replacing a connection's key and revoking it (#678).
        "/api/console/v1/monitor/connections/tines",
        "/api/console/v1/monitor/connections/{connection_id}/key",
        "/api/console/v1/monitor/connections/{connection_id}/revoke",
    } <= stepped
    # The rest of a policy's lifecycle, and removing the samples, stay outside it.
    assert (
        not {
            "/api/console/v1/policy/{bundle_id}/validate",
            "/api/console/v1/policy/{bundle_id}/retire",
            "/api/console/v1/policy/{bundle_id}/preview",
            "/api/console/v1/policy/{bundle_id}/rules",
            "/api/console/v1/policy",
            "/api/console/v1/samples/remove",
        }
        & stepped
    )
    # A space's own changes other than its membership stay outside the step-up.
    assert "/api/console/v1/spaces/{space_id}/rename" not in stepped
    # Asking for a collection and changing a schedule within its bounds widen nothing.
    assert (
        not {
            "/api/console/v1/monitor/connections/{connection_id}/collect",
            "/api/console/v1/monitor/connections/{connection_id}/schedule",
            "/api/console/v1/monitor/findings/acknowledge",
        }
        & stepped
    )


# The passkey half of the step-up (#678): options, then an assertion, through the account
# security page's own `passkeys.begin` and `passkeys.complete`, then the same rotation the code
# path makes. Every finish attempt that finds a usable challenge spends it.

OPTIONS = API + "/session/verify/passkey/options"
PASSKEY = API + "/session/verify/passkey"


def failures(admin_engine, tenant, principal) -> int:
    """The factor's own failure count, which the five-attempt lock reads."""
    with admin_engine.connect() as conn:
        return int(
            conn.execute(
                text(
                    "SELECT COALESCE((SELECT failures FROM execbound.user_factors "
                    "WHERE tenant_id = :t AND principal_id = :p), "
                    "(SELECT failures FROM execbound.account_factors "
                    "WHERE tenant_id = :t AND principal_id = :p))"
                ),
                {"t": tenant, "p": principal},
            ).scalar_one()
        )


def verified_by_passkey(admin_engine, tenant) -> int:
    with admin_engine.connect() as conn:
        return int(
            conn.execute(
                text(
                    "SELECT count(*) FROM execbound.audit_events WHERE tenant_id = :t "
                    "AND kind = 'account_security.verified' AND payload ->> 'method' = 'passkey'"
                ),
                {"t": tenant},
            ).scalar_one()
        )


@contextmanager
def passkey_admin(db, runtime, admin_engine, world):
    """The fixture administrator with an authenticator and one passkey saved while fresh, then
    verified long enough ago that a change asks again."""
    with console_client(
        db, runtime, admin_engine, world["admin"], config=console_config(mfa=RING)
    ) as client:
        session = load_session(db, client.client.cookies.get("eb_session"), clock=runtime.clock)
        seed = mfa.begin_enrollment(db, session, RING, clock=runtime.clock)
        mfa.confirm_enrollment(
            db, session, RING, mfa.totp(seed, step(runtime)), clock=runtime.clock
        )
        options = passkeys.begin(db, session, ORIGIN, "register", clock=runtime.clock)
        private, identifier, response = registration(options)
        assert passkeys.complete(db, session, ORIGIN, "register", response, clock=runtime.clock)
        stale(admin_engine, world["admin"].tenant_id, session.session_id)
        yield client, private, identifier, session


def fetch_options(client) -> dict:
    answer = client.post(OPTIONS, {})
    assert answer.status_code == 200, answer.text
    assert answer.headers["cache-control"] == "no-store"
    return answer.json()["options"]


def test_a_passkey_rotates_the_session_and_the_change_goes_through_resent_once(
    db, runtime, admin_engine, world
):
    tenant = world["admin"].tenant_id
    with passkey_admin(db, runtime, admin_engine, world) as (client, private, identifier, session):
        issued = tokens_issued(admin_engine, tenant)
        refused = client.post(ISSUE, {"name": "ci", "lifetime": "8"})
        assert refused.status_code == 401 and refused.json()["code"] == "MFA_REQUIRED"
        options = fetch_options(client)
        assert options["challenge"] and options["allowCredentials"]
        assert options["userVerification"] == "required"
        before = verified_by_passkey(admin_engine, tenant)
        old_token, old_csrf = client.client.cookies.get("eb_session"), client.csrf
        answer = client.post(PASSKEY, {"credential": assertion(options, private, identifier)})
        assert answer.status_code == 200, answer.text
        assert answer.headers["cache-control"] == "no-store"
        assert set(answer.json()) == {"csrf_token"}
        new_csrf = answer.json()["csrf_token"]
        assert new_csrf != old_csrf
        new_token = client.client.cookies.get("eb_session")
        assert new_token != old_token and client.client.cookies.get("eb_csrf") == new_csrf
        with pytest.raises(SessionError):
            load_session(db, old_token, clock=runtime.clock)
        assert load_session(db, new_token, clock=runtime.clock).session_id == session.session_id
        assert verified_by_passkey(admin_engine, tenant) == before + 1

        replayed = client.post(ISSUE, {"name": "ci", "lifetime": "8"}, csrf=old_csrf)
        assert replayed.status_code == 403 and replayed.json()["code"] == "INVALID_CSRF"
        assert tokens_issued(admin_engine, tenant) == issued
        client.csrf = new_csrf
        resent = client.post(ISSUE, {"name": "ci", "lifetime": "8"})
        assert resent.status_code == 200, resent.text
        assert tokens_issued(admin_engine, tenant) == issued + 1


def second_session_options(db, runtime, world):
    """Options fetched by another session of the same person."""
    other = load_session(
        db,
        issue_session(db, world["admin"], clock=runtime.clock).token,
        clock=runtime.clock,
        allow_pending_mfa=True,
    )
    return passkeys.begin(db, other, ORIGIN, "authenticate", clock=runtime.clock)


def another_accounts_passkey(db, runtime, admin_engine, world):
    """A passkey saved to a second administrator's account, with its private key."""
    tenant = world["admin"].tenant_id
    other = provision_identity(admin_engine, db, tenant, "ADMIN", runtime.clock.now())
    session = load_session(
        db, issue_session(db, other, clock=runtime.clock).token, clock=runtime.clock
    )
    seed = mfa.begin_enrollment(db, session, RING, clock=runtime.clock)
    mfa.confirm_enrollment(db, session, RING, mfa.totp(seed, step(runtime)), clock=runtime.clock)
    options = passkeys.begin(db, session, ORIGIN, "register", clock=runtime.clock)
    private, identifier, response = registration(options)
    assert passkeys.complete(db, session, ORIGIN, "register", response, clock=runtime.clock)
    return private, identifier


@pytest.mark.parametrize("fault", ["origin", "verification", "account", "other_session"])
def test_an_assertion_that_fails_verification_counts_and_is_audited(
    db, runtime, admin_engine, world, fault
):
    tenant, principal = world["admin"].tenant_id, world["admin"].principal_id
    with passkey_admin(db, runtime, admin_engine, world) as (client, private, identifier, _):
        options = fetch_options(client)
        if fault == "origin":
            sent = assertion(options, private, identifier, origin="https://evil.example")
        elif fault == "verification":
            sent = assertion(options, private, identifier, uv=False)
        elif fault == "account":
            stranger, stranger_id = another_accounts_passkey(db, runtime, admin_engine, world)
            sent = assertion(options, stranger, stranger_id)
        else:
            sent = assertion(second_session_options(db, runtime, world), private, identifier)
        failed = events(admin_engine, tenant, "account_security.verification_failed")
        counted = failures(admin_engine, tenant, principal)
        before = client.client.cookies.get("eb_session")
        refused = client.post(PASSKEY, {"credential": sent})
        assert refused.status_code == 400, refused.text
        assert refused.json()["code"] == "INVALID_FACTOR"
        assert events(admin_engine, tenant, "account_security.verification_failed") == failed + 1
        assert failures(admin_engine, tenant, principal) == counted + 1
        assert client.client.cookies.get("eb_session") == before
        still = client.post(ISSUE, {"name": "ci", "lifetime": "8"})
        assert still.status_code == 401 and still.json()["code"] == "MFA_REQUIRED"


def test_a_spent_or_missing_challenge_is_refused_without_counting(db, runtime, admin_engine, world):
    tenant, principal = world["admin"].tenant_id, world["admin"].principal_id
    with passkey_admin(db, runtime, admin_engine, world) as (client, private, identifier, session):

        def refused_quietly(sent):
            failed = events(admin_engine, tenant, "account_security.verification_failed")
            counted = failures(admin_engine, tenant, principal)
            before = client.client.cookies.get("eb_session")
            answer = client.post(PASSKEY, {"credential": sent})
            assert answer.status_code == 400, answer.text
            assert answer.json()["code"] == "INVALID_FACTOR"
            assert events(admin_engine, tenant, "account_security.verification_failed") == failed
            assert failures(admin_engine, tenant, principal) == counted
            assert client.client.cookies.get("eb_session") == before

        # No options fetched by this session yet: there is no challenge to answer.
        refused_quietly(assertion(second_session_options(db, runtime, world), private, identifier))
        # Options that expired before the assertion arrived.
        options = fetch_options(client)
        with admin_engine.begin() as conn:
            conn.execute(
                text(
                    "UPDATE execbound.passkey_challenges SET expires_at = :n "
                    "WHERE tenant_id = :t AND session_id = :s"
                ),
                # Expired on the injected clock the route reads.
                {
                    "n": runtime.clock.now() - timedelta(seconds=1),
                    "t": tenant,
                    "s": session.session_id,
                },
            )
        refused_quietly(assertion(options, private, identifier))
        # A valid assertion succeeds once; the same one replayed finds its challenge spent.
        options = fetch_options(client)
        valid = assertion(options, private, identifier)
        assert client.post(PASSKEY, {"credential": valid}).status_code == 200
        client.csrf = client.client.cookies.get("eb_csrf")
        refused_quietly(valid)
        # Fresh options and a fresh assertion still succeed.
        options = fetch_options(client)
        later = assertion(options, private, identifier, count=2)
        again = client.post(PASSKEY, {"credential": later})
        assert again.status_code == 200, again.text


def test_the_lock_refuses_a_valid_passkey_silently(db, runtime, admin_engine, world):
    tenant = world["admin"].tenant_id
    with passkey_admin(db, runtime, admin_engine, world) as (client, private, identifier, _):
        for _ in range(5):
            options = fetch_options(client)
            sent = assertion(options, private, identifier, uv=False)
            assert client.post(PASSKEY, {"credential": sent}).status_code == 400
        verified = events(admin_engine, tenant, "account_security.verified")
        failed = events(admin_engine, tenant, "account_security.verification_failed")
        options = fetch_options(client)
        locked = client.post(PASSKEY, {"credential": assertion(options, private, identifier)})
        assert locked.status_code == 400 and locked.json()["code"] == "INVALID_FACTOR"
        assert events(admin_engine, tenant, "account_security.verified") == verified
        assert events(admin_engine, tenant, "account_security.verification_failed") == failed


def test_options_without_a_saved_passkey_conflict(db, runtime, admin_engine, world):
    with enrolled_admin(db, runtime, admin_engine, world) as (client, _, _, _):
        answer = client.post(OPTIONS, {})
        assert answer.status_code == 409 and answer.json()["code"] == "CONFLICT"


def test_the_passkey_routes_check_the_request_first(db, runtime, seeded, admin_engine, world):
    with passkey_admin(db, runtime, admin_engine, world) as (client, private, identifier, _):
        options = fetch_options(client)
        sent = assertion(options, private, identifier)
        for path, body in ((OPTIONS, {}), (PASSKEY, {"credential": sent})):
            wrong = client.post(path, body, csrf="wrong")
            assert wrong.status_code == 403 and wrong.json()["code"] == "INVALID_CSRF"
            assert client.post(path, body, origin="http://evil.example").status_code == 403
            assert client.post(path, body, content_type="text/plain").status_code == 415
            unknown = client.post(path, {**body, "remember": True})
            assert unknown.status_code == 400 and unknown.json()["code"] == "INVALID_BODY"
            assert client.get(path).status_code == 405
        long = client.post(PASSKEY, {"credential": {**sent, "id": "a" * 1025}})
        assert long.status_code == 400 and long.json()["code"] == "INVALID_BODY"
        # None of those reached the challenge: the assertion still succeeds.
        assert client.post(PASSKEY, {"credential": sent}).status_code == 200
    for path in (OPTIONS, PASSKEY):
        results = refusals(db, runtime, seeded, admin_engine, world, path, "POST")
        assert results["bearer"].status_code == 403
        assert results["bearer"].json()["code"] == "FORBIDDEN"
        assert results["no_session"].status_code == 401
    assert (API + "/session/verify/passkey/options", "POST") in TOKEN_REFUSED
    assert (API + "/session/verify/passkey", "POST") in TOKEN_REFUSED
