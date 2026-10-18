# SPDX-License-Identifier: AGPL-3.0-only
"""A browser cannot reach the console using a first-factor-only session."""

import re
import xml.etree.ElementTree as ET
from dataclasses import replace

import pytest
from fastapi.testclient import TestClient
from test_sign_in_surface import (
    ADDRESS,
    ORIGIN,
    PASSWORD,
    form_values,
    sign_in,
)
from test_sign_in_surface import (
    config as config,
)
from test_sign_in_surface import (
    connector as connector,
)
from test_sign_in_surface import (
    live_provider as live_provider,
)
from test_sign_in_surface import (
    providers as providers,
)
from test_sign_in_surface import (
    registry as registry,
)
from test_sign_in_surface import (
    runtime as runtime,
)
from test_sign_in_surface import (
    signed_up as signed_up,
)
from test_sign_in_surface import (
    world as world,
)

from execbound.app import create_app
from execbound.envelope import KeyRing
from execbound.mfa import totp
from execbound.surfaces.human import landing

pytestmark = pytest.mark.integration


@pytest.fixture
def secured(db, runtime, config):
    settings = replace(config, mfa=KeyRing("test", {"test": b"m" * 32}))
    with TestClient(
        create_app(db, runtime=runtime, human=settings), base_url=ORIGIN, follow_redirects=False
    ) as client:
        yield client


def test_enroll_login_gate_recovery_and_csrf(secured, signed_up, runtime):
    assert sign_in(secured).status_code == 303
    page = secured.get("/account/security")
    assert page.status_code == 200
    fields = form_values(page.text, "/account/security/enroll")
    denied = secured.post(
        "/account/security/enroll", data=fields, headers={"Origin": "https://evil.example"}
    )
    assert denied.status_code == 403
    setup = secured.post("/account/security/enroll", data=fields, headers={"Origin": ORIGIN})
    svg = ET.fromstring(re.search(r"<svg\b.*?</svg>", setup.text, re.DOTALL).group(0))
    assert {node.tag.rsplit("}", 1)[-1] for node in svg.iter()} <= {"svg", "path", "rect"}
    assert not any(
        key.lower().startswith("on") or "href" in key.lower()
        for node in svg.iter()
        for key in node.attrib
    )
    assert "otpauth" not in ET.tostring(svg, encoding="unicode")
    seed = re.search(r"<code>([A-Z2-7]{32})</code>", setup.text).group(1)
    fields = form_values(setup.text, "/account/security/confirm")
    done = secured.post(
        "/account/security/confirm",
        data={**fields, "code": totp(seed, int(runtime.clock.now().timestamp() // 30))},
        headers={"Origin": ORIGIN},
    )
    assert "Save your recovery codes" in done.text
    recovery = re.findall(r"<code>([a-f0-9]{4}(?:-[a-f0-9]{4}){5})</code>", done.text)
    assert len(recovery) == 10
    assert secured.get("/api/console/v1/settings").status_code == 200
    assert sign_in(secured, ADDRESS, PASSWORD).headers["location"] == "/mfa"
    blocked = secured.get("/api/console/v1/settings")
    assert blocked.status_code == 401 and blocked.json()["code"] == "MFA_REQUIRED"
    page = secured.get("/mfa")
    # The second step of signing in is its own page: one code, and nothing to manage.
    assert "<h1>Two-step verification</h1>" in page.text
    assert 'autocomplete="one-time-code"' in page.text and "Recovery code" in page.text
    for managed in ("Organization requirement", "Replace authenticator", "Add a passkey"):
        assert managed not in page.text, managed
    fields = form_values(page.text, "/account/security/verify")
    wrong = secured.post(
        "/account/security/verify", data={**fields, "code": "000000"}, headers={"Origin": ORIGIN}
    )
    assert wrong.status_code == 200 and "<h1>Two-step verification</h1>" in wrong.text
    assert "That code could not be used" in wrong.text
    assert secured.get("/api/console/v1/settings").status_code == 401
    fields = form_values(wrong.text, "/account/security/verify")
    completed = secured.post(
        "/account/security/verify", data={**fields, "code": recovery[0]}, headers={"Origin": ORIGIN}
    )
    # Accepted, it goes straight on to where a sign-in lands, with the rotated session.
    assert completed.status_code == 303, completed.text
    assert completed.headers["location"] == landing("HUMAN_APPROVER")
    assert any(c.startswith("eb_session=") for c in completed.headers.get_list("set-cookie"))
    assert secured.get("/api/console/v1/settings").status_code == 200
    assert seed not in completed.text and recovery[0] not in completed.text
    assert completed.headers["Cache-Control"] == "no-store"
    # A deliberate visit afterwards is Account security, with the way back in plain sight.
    managed = secured.get("/account/security")
    assert "<h1>Account security</h1>" in managed.text
    assert '<p class="back"><a href="/settings">Back to ExecBound</a></p>' in managed.text
    assert '<a class="btn" href="/settings">Continue to ExecBound</a>' in managed.text


@pytest.mark.parametrize("classic", [False, True])
def test_mfa_preserves_approval_destination_after_owner_password_change(
    secured, signed_up, runtime, db, world, classic
):
    from datetime import UTC, datetime

    from execbound import mfa
    from execbound.passwords import change_password
    from execbound.surfaces.sessions import load_session

    sign_in(secured)
    session = load_session(db, secured.cookies.get("eb_session"), clock=runtime.clock)
    ring = KeyRing("test", {"test": b"m" * 32})
    seed = mfa.begin_enrollment(db, session, ring, clock=runtime.clock)
    recovery = mfa.confirm_enrollment(
        db,
        session,
        ring,
        totp(seed, int(runtime.clock.now().timestamp() // 30)),
        clock=runtime.clock,
    )
    runtime.clock.value = datetime.now(UTC)
    change_password(
        db, session.identity, PASSWORD, PASSWORD + " renewed", session=session, clock=runtime.clock
    )
    secured.cookies.clear()
    path = "/approvals/abcdef01-0000-4000-8000-000000000001" + ("/classic" if classic else "")
    redirect = secured.get(path, headers={"Accept": "text/html"})
    page = secured.get(redirect.headers["location"])
    fields = form_values(page.text, "/session/password")
    result = secured.post(
        "/session/password",
        data={**fields, "email": ADDRESS, "password": PASSWORD + " renewed"},
        headers={"Origin": ORIGIN},
    )
    assert result.headers["location"] == "/mfa"
    assert secured.get("/api/console/v1/settings").status_code == 401
    page = secured.get("/mfa")
    fields = form_values(page.text, "/account/security/verify")
    completed = secured.post(
        "/account/security/verify",
        data={**fields, "code": recovery[0]},
        headers={"Origin": ORIGIN},
    )
    assert completed.status_code == 303 and completed.headers["location"] == path
    assert any(
        "eb_review_return=" in cookie and "Max-Age=0" in cookie
        for cookie in completed.headers.get_list("set-cookie")
    )
    assert secured.get("/api/console/v1/settings").status_code == 200


def test_sn6_the_second_step_returns_to_any_console_page(
    db, runtime, config, signed_up, tmp_path, monkeypatch
):
    from uuid import uuid4

    from test_console_serving import write_build

    from execbound import mfa
    from execbound.surfaces import console as console_module
    from execbound.surfaces.sessions import load_session

    root = write_build(tmp_path / "console_dist")
    monkeypatch.setattr(console_module, "build_root", lambda: root)
    ring = KeyRing("test", {"test": b"m" * 32})
    settings = replace(config, mfa=ring)
    with TestClient(
        create_app(db, runtime=runtime, human=settings), base_url=ORIGIN, follow_redirects=False
    ) as client:
        sign_in(client)
        session = load_session(db, client.cookies.get("eb_session"), clock=runtime.clock)
        seed = mfa.begin_enrollment(db, session, ring, clock=runtime.clock)
        recovery = mfa.confirm_enrollment(
            db,
            session,
            ring,
            totp(seed, int(runtime.clock.now().timestamp() // 30)),
            clock=runtime.clock,
        )
        client.cookies.clear()
        assert sign_in(client).headers["location"] == "/mfa"
        place = f"/policy/{uuid4()}/rules"
        pending = client.get(place, headers={"Accept": "text/html"})
        assert pending.status_code == 303 and pending.headers["location"] == "/mfa"
        hints = [
            cookie
            for cookie in pending.headers.get_list("set-cookie")
            if cookie.startswith("eb_review_return=")
        ]
        assert len(hints) == 1 and hints[0].split(";")[0].split(":")[2] == place
        page = client.get("/mfa")
        fields = form_values(page.text, "/account/security/verify")
        completed = client.post(
            "/account/security/verify",
            data={**fields, "code": recovery[0]},
            headers={"Origin": ORIGIN},
        )
        assert completed.status_code == 303 and completed.headers["location"] == place


def test_sn12_the_page_says_a_code_was_just_used(secured, signed_up, runtime, db):
    from execbound import mfa
    from execbound.surfaces.sessions import load_session

    sign_in(secured)
    session = load_session(db, secured.cookies.get("eb_session"), clock=runtime.clock)
    ring = KeyRing("test", {"test": b"m" * 32})
    seed = mfa.begin_enrollment(db, session, ring, clock=runtime.clock)
    used = totp(seed, int(runtime.clock.now().timestamp() // 30))
    mfa.confirm_enrollment(db, session, ring, used, clock=runtime.clock)
    secured.cookies.clear()
    assert sign_in(secured).headers["location"] == "/mfa"
    page = secured.get("/mfa")
    fields = form_values(page.text, "/account/security/verify")
    again = secured.post(
        "/account/security/verify", data={**fields, "code": used}, headers={"Origin": ORIGIN}
    )
    assert again.status_code == 200
    assert (
        "That code was just used. Wait for the next code from your authenticator app, then "
        "enter it." in again.text
    )
    assert "That code could not be used" not in again.text
    assert secured.get("/api/console/v1/settings").status_code == 401


def test_sn13_the_challenge_after_a_switch_names_the_workspace(
    db, runtime, config, admin_engine, seeded
):
    from sqlalchemy import text
    from test_console_api_step_up import stale
    from test_workspace_switching import member_pair

    from execbound import mfa, workspaces
    from execbound.resolution.models import SystemClock
    from execbound.surfaces.sessions import load_session

    runtime.clock = SystemClock()
    ring = KeyRing("test", {"test": b"m" * 32})
    grant, current, _, other = member_pair(db, admin_engine, seeded)
    second = seeded["tenants"][1]
    seed = mfa.begin_enrollment(db, current, ring)
    mfa.confirm_enrollment(
        db, current, ring, totp(seed, int(SystemClock().now().timestamp() // 30))
    )
    with admin_engine.begin() as conn:
        conn.execute(
            text("UPDATE execbound.tenants SET name='<b>Team</b>' WHERE tenant_id=:t"),
            {"t": second},
        )
        conn.execute(
            text(
                "INSERT INTO execbound.account_security_policy "
                "(tenant_id,requirement,changed_at,changed_by) VALUES(:t,'all',now(),:p)"
            ),
            {"t": second, "p": other},
        )
    # A code entered within the step-up window would be carried through the switch, so the
    # one entered here is aged past it and the destination asks again.
    stale(admin_engine, seeded["tenants"][0], current.session_id)
    current = load_session(db, grant.token)
    switched = workspaces.switch_workspace(db, current, grant.account_token, second)
    assert switched.mfa_required
    settings = replace(config, mfa=ring)
    with TestClient(
        create_app(db, runtime=runtime, human=settings), base_url=ORIGIN, follow_redirects=False
    ) as client:
        client.cookies.set("eb_session", switched.token, domain="127.0.0.1")
        client.cookies.set("eb_csrf", switched.csrf_token, domain="127.0.0.1")
        page = client.get("/mfa")
        assert page.status_code == 200
        escaped = "Verify to open &lt;b&gt;Team&lt;/b&gt;"
        assert f"<title>{escaped} · ExecBound</title>" in page.text
        assert f"<h1>{escaped}</h1>" in page.text
        assert (
            "Enter the 6-digit code from your authenticator app to open &lt;b&gt;Team&lt;/b&gt;."
            in page.text
        )
        assert "<b>Team</b>" not in page.text
        assert "Two-step verification" not in page.text
        assert "to finish signing in" not in page.text

        # A session issued at sign-in, whichever workspace it opens, keeps the sign-in wording.
        client.cookies.clear()
        assert (
            sign_in(client, "member@example.test", "a retained example passphrase").headers[
                "location"
            ]
            == "/mfa"
        )
        signing_in = client.get("/mfa")
        assert "<h1>Two-step verification</h1>" in signing_in.text
        assert "to finish signing in." in signing_in.text
        assert "Verify to open" not in signing_in.text
