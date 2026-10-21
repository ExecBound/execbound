# SPDX-License-Identifier: AGPL-3.0-only
"""Trusted browsers in the console and on Account security (#859).

My account lists the account's live trusts, marks the one this browser holds, and removes one
or all of them with no step-up, since removing only tightens. Entering another workspace on a
trusted browser asks for nothing more: the workspace list says so and the switch goes straight
on. A workspace administrator may forbid trust on Account security, and a sign-in there then
asks for the code whatever cookie the browser holds. Real PostgreSQL, over the ASGI client.
"""

import json
from datetime import timedelta
from uuid import uuid4

import pytest
from console_api_fixtures import API, ORIGIN, assert_no_secrets, console_config
from fastapi.testclient import TestClient
from sqlalchemy import text
from test_console_api_step_up import stale
from test_runtime import connector as connector
from test_runtime import live_provider as live_provider
from test_runtime import registry as registry
from test_runtime import runtime as runtime
from test_runtime import world as world
from test_sign_in_surface import form_values
from test_trusted_browsers import (
    aged,
    browser_of,
    granted,
    signed_in_again,
    trust_rows,
)
from test_workspace_accounts import adopt, enroll
from test_workspace_switching import RING, assurance_of, verified_pair

from execbound import trusted_browsers
from execbound.app import create_app
from execbound.passwords import sign_in_with_password
from execbound.resolution.models import SystemClock
from execbound.surfaces.sessions import issue_session

pytestmark = pytest.mark.integration

TRUST = "eb_trust"
POLICY = "/account/security/trusted_browsers"
SWITCH = "Allow trusted browsers in this workspace"
PASSWORD = "a retained example passphrase"  # nosec B105 - The test fixture's own passphrase.


def browser(db, runtime, grant, *, trust=None):
    """A TestClient holding this grant's cookies, and the trust cookie when given."""
    client = TestClient(
        create_app(db, runtime=runtime, human=console_config(mfa=RING)),
        base_url=ORIGIN,
        follow_redirects=False,
    )
    client.cookies.set("eb_session", grant.token, domain="127.0.0.1")
    client.cookies.set("eb_csrf", grant.csrf_token, domain="127.0.0.1")
    if grant.account_token is not None:
        client.cookies.set("eb_account", grant.account_token, domain="127.0.0.1")
    if trust is not None:
        client.cookies.set(TRUST, trust, domain="127.0.0.1")
    return client


def posted(client, path, body):
    session = client.get(API + "/session").json()
    return client.post(
        path,
        content=json.dumps(body).encode(),
        headers={
            "Origin": ORIGIN,
            "X-CSRF-Token": session["csrf_token"],
            "X-ExecBound-Workspace": session["generation"],
            "Content-Type": "application/json",
        },
    )


def forbid(engine, tenant, principal):
    """The workspace's administrator turned trusted browsers off, written as the definer
    function writes it."""
    with engine.begin() as conn:
        conn.execute(
            text(
                "INSERT INTO execbound.account_security_policy"
                "(tenant_id,requirement,changed_at,changed_by,allow_trusted_browsers) "
                "VALUES(:t,'optional',now(),:p,false) ON CONFLICT(tenant_id) "
                "DO UPDATE SET allow_trusted_browsers=false"
            ),
            {"t": tenant, "p": principal},
        )


def trusted_sign_ins(engine, tenant):
    """The workspace's `account_security.trusted_sign_in` records, oldest first."""
    with engine.begin() as conn:
        return list(
            conn.execute(
                text(
                    "SELECT payload FROM execbound.audit_events WHERE tenant_id=:t "
                    "AND kind='account_security.trusted_sign_in' ORDER BY sequence"
                ),
                {"t": tenant},
            ).scalars()
        )


def test_tb_my_account_lists_and_removes_trust(db, runtime, admin_engine, seeded):
    runtime.clock = SystemClock()
    grant, current, account, _, _ = verified_pair(db, admin_engine, seeded)
    first, _, _ = granted(db, admin_engine, current)
    second, expires, _ = granted(db, admin_engine, current)
    with browser(db, runtime, grant, trust=second) as client:
        read = client.get(API + "/settings")
        assert read.status_code == 200, read.text
        assert_no_secrets(read)
        security = read.json()["security"]
        assert security["trust_allowed"] is True
        listed = security["trusted"]
        # Newest first, this browser's own trust marked, and nothing of the cookie or its hash.
        assert [item["browser_id"] for item in listed] == [
            str(browser_of(second)),
            str(browser_of(first)),
        ]
        assert [item["this_browser"] for item in listed] == [True, False]
        assert set(listed[0]) == {
            "browser_id",
            "label",
            "created_at",
            "last_used_at",
            "expires_at",
            "this_browser",
        }
        assert listed[0]["label"] == "Chrome on Windows"
        assert listed[0]["last_used_at"] is None
        hashes = [row["token_hash"] for row in trust_rows(admin_engine, account)]
        for secret in (first, second, *hashes):
            assert secret.split(".")[-1] not in read.text

        # Removing only tightens, so a factor verified long ago is not asked for again.
        stale(admin_engine, current.identity.tenant_id, current.session_id, minutes=40)
        bad = posted(client, API + "/settings/trusted-browsers/remove", {"browser_id": "x"})
        assert bad.status_code == 400 and bad.json()["fields"] == ["browser_id"]
        extra = posted(
            client,
            API + "/settings/trusted-browsers/remove",
            {"browser_id": str(browser_of(first)), "all": True},
        )
        assert extra.status_code == 400 and extra.json()["fields"] == ["all"]
        removed = posted(
            client,
            API + "/settings/trusted-browsers/remove",
            {"browser_id": str(browser_of(first))},
        )
        assert removed.status_code == 200, removed.text
        assert [item["browser_id"] for item in removed.json()["security"]["trusted"]] == [
            str(browser_of(second))
        ]
        # Removing another browser's trust leaves this browser's cookie alone.
        assert not [c for c in removed.headers.get_list("set-cookie") if c.startswith(TRUST)]
        # One that is gone, or was never the account's, changes nothing.
        again = posted(
            client, API + "/settings/trusted-browsers/remove", {"browser_id": str(uuid4())}
        )
        assert again.status_code == 200
        assert len(again.json()["security"]["trusted"]) == 1

        # A trust is granted only on a recent verification: put it back for a third.
        stale(admin_engine, current.identity.tenant_id, current.session_id, minutes=-40)
        granted(db, admin_engine, current)
        assert posted(client, API + "/settings/trusted-browsers/remove-all", {"x": 1}).json()[
            "fields"
        ] == ["x"]
        emptied = posted(client, API + "/settings/trusted-browsers/remove-all", {})
        assert emptied.status_code == 200, emptied.text
        assert emptied.json()["security"]["trusted"] == []
        # This browser's trust went with the rest, so its cookie is cleared as well.
        [cleared] = [c for c in emptied.headers.get_list("set-cookie") if c.startswith(TRUST)]
        assert 'eb_trust=""' in cleared or "Max-Age=0" in cleared
        # Each addition and removal is a security notice on the account.
        notices = [item["message"] for item in client.get(API + "/account").json()["notifications"]]
        assert notices.count("A trusted browser was added") == 3
        assert notices.count("A trusted browser was removed") == 3
    _, pending = signed_in_again(db)
    for cookie in (first, second):
        assert trusted_browsers.apply(db, pending, cookie, clock=runtime.clock) is None
    assert expires > runtime.clock.now()


def test_tb_removing_this_browsers_trust_clears_its_cookie(db, runtime, admin_engine, seeded):
    runtime.clock = SystemClock()
    grant, current, _, _, _ = verified_pair(db, admin_engine, seeded)
    mine, _, _ = granted(db, admin_engine, current)
    with browser(db, runtime, grant, trust=mine) as client:
        removed = posted(
            client, API + "/settings/trusted-browsers/remove", {"browser_id": str(browser_of(mine))}
        )
        assert removed.status_code == 200, removed.text
        assert [c for c in removed.headers.get_list("set-cookie") if c.startswith(TRUST)]
        assert removed.json()["security"]["trusted"] == []


def test_tb_a_trusted_browser_enters_another_workspace_with_no_code(
    db, runtime, admin_engine, seeded
):
    runtime.clock = SystemClock()
    a, b = seeded["tenants"]
    grant, current, account, other, _ = verified_pair(db, admin_engine, seeded)
    cookie, _, _ = granted(db, admin_engine, current)
    # Days later: the code behind the trust is far older than the switch would carry.
    aged(admin_engine, account, timedelta(days=2))
    stale(admin_engine, a, current.session_id, minutes=40)

    def entry(client):
        [item] = [
            item
            for item in client.get(API + "/session/workspaces").json()["workspaces"]
            if item["tenant_id"] == str(b)
        ]
        return item["entry"], item["waiting_state"]

    with browser(db, runtime, grant) as plain:
        assert entry(plain) == ("factor", "withheld")
        # A malformed cookie is no trust at all.
        plain.cookies.set(TRUST, "tb1.nothing", domain="127.0.0.1")
        assert entry(plain) == ("factor", "withheld")
    with browser(db, runtime, grant, trust=cookie) as client:
        # Entering asks nothing more, so the count of waiting approvals crosses too.
        assert entry(client) == ("open", "counted")
        switched = posted(client, API + "/session/workspace", {"tenant_id": str(b)})
        assert switched.status_code == 200, switched.text
        assert switched.json()["location"] == "/"
        selected = client.get(API + "/session")
        assert selected.status_code == 200, selected.text
        assert selected.json()["tenant"]["tenant_id"] == str(b)
        session_id = selected.json()["generation"]
        assured = assurance_of(admin_engine, b, session_id)
        # The trust's own verification, two days old, never now: a step-up there still asks.
        assert assured["method"] == "trusted"
        assert assured["verified_at"] < runtime.clock.now() - timedelta(days=1)
    [row] = trust_rows(admin_engine, account)
    assert row["last_used_at"] is not None
    # The workspace entered records the trusted entry in its own chain, with the trust's
    # original verification; the workspace left records none.
    assert trusted_sign_ins(admin_engine, b) == [
        {
            "session_id": session_id,
            "browser_id": str(browser_of(cookie)),
            "method": row["method"],
            "verified_at": row["verified_at"].isoformat(timespec="microseconds"),
        }
    ]
    assert trusted_sign_ins(admin_engine, a) == []


def test_tb_a_workspace_that_forbids_trust_is_entered_with_a_code(
    db, runtime, admin_engine, seeded
):
    runtime.clock = SystemClock()
    a, b = seeded["tenants"]
    grant, current, _, other, _ = verified_pair(db, admin_engine, seeded)
    cookie, _, _ = granted(db, admin_engine, current)
    stale(admin_engine, a, current.session_id, minutes=40)
    forbid(admin_engine, b, other)
    with browser(db, runtime, grant, trust=cookie) as client:
        workspaces = client.get(API + "/session/workspaces").json()["workspaces"]
        [item] = [item for item in workspaces if item["tenant_id"] == str(b)]
        assert item["entry"] == "factor"
        switched = posted(client, API + "/session/workspace", {"tenant_id": str(b)})
        assert switched.status_code == 200, switched.text
        assert switched.json()["location"] == "/mfa"
        assert client.get(API + "/session").status_code == 401
    assert trusted_sign_ins(admin_engine, b) == []


def test_tb_the_admin_switch_forbids_trust_in_that_workspace(db, runtime, admin_engine, seeded):
    runtime.clock = SystemClock()
    a = seeded["tenants"][0]
    grant, current, _, _, _ = verified_pair(db, admin_engine, seeded)
    cookie, _, _ = granted(db, admin_engine, current)
    with browser(db, runtime, grant) as admin:
        page = admin.get("/account/security")
        assert page.status_code == 200, page.text
        assert SWITCH in page.text
        values = form_values(page.text, POLICY)
        assert values.pop("allow") == "on", "allowed by default, so the box starts ticked"
        # Anything but a ticked box's own value is refused before anything is written.
        for wrong in ({"allow": "yes"}, {"allow": "on", "requirement": "all"}):
            refused = admin.post(POLICY, data={**values, **wrong}, headers={"Origin": ORIGIN})
            assert refused.status_code == 403
        off = admin.post(POLICY, data=values, headers={"Origin": ORIGIN})
        assert off.status_code == 200, off.text
        assert "Your security settings were updated." in off.text
        assert 'name="allow" value="on" checked' not in off.text
    with db.transaction(a) as conn:
        assert not trusted_browsers.allowed(conn, a)

    def sign_in_page():
        pending, _ = signed_in_again(db)
        with browser(db, runtime, pending, trust=cookie) as fresh:
            return fresh.get("/mfa")

    # With it off, a sign-in on the trusted browser is asked for the code all the same.
    asked = sign_in_page()
    assert asked.status_code == 200
    assert "<h1>Two-step verification</h1>" in asked.text

    # Turning it back on is allowed only to an administrator who verified recently.
    stale(admin_engine, a, current.session_id, minutes=40)
    with browser(db, runtime, grant) as admin:
        values = form_values(admin.get("/account/security").text, POLICY)
        late = admin.post(POLICY, data={**values, "allow": "on"}, headers={"Origin": ORIGIN})
        assert late.status_code == 200
        assert "Verify your identity below first." in late.text
    with db.transaction(a) as conn:
        assert not trusted_browsers.allowed(conn, a)
    assert sign_in_page().status_code == 200

    stale(admin_engine, a, current.session_id, minutes=-40)
    with browser(db, runtime, grant) as admin:
        values = form_values(admin.get("/account/security").text, POLICY)
        on = admin.post(POLICY, data={**values, "allow": "on"}, headers={"Origin": ORIGIN})
        assert on.status_code == 200
        assert 'name="allow" value="on" checked' in on.text
    assert sign_in_page().status_code == 303


def test_tb_only_a_workspace_administrator_sees_or_uses_the_switch(
    db, runtime, admin_engine, seeded
):
    from execbound import mfa
    from execbound.surfaces.sessions import load_session

    runtime.clock = SystemClock()
    tenant = seeded["tenants"][0]
    principal, _ = enroll(admin_engine, tenant, email="approver@example.test")
    adopt(db, tenant, principal)
    grant = issue_session(db, sign_in_with_password(db, "approver@example.test", PASSWORD))
    session = load_session(db, grant.token)
    seed = mfa.begin_enrollment(db, session, RING)
    mfa.confirm_enrollment(
        db, session, RING, mfa.totp(seed, int(SystemClock().now().timestamp()) // 30)
    )
    with browser(db, runtime, grant) as approver:
        page = approver.get("/account/security")
        assert page.status_code == 200, page.text
        assert SWITCH not in page.text
        values = form_values(page.text, "/account/security/recovery")
        refused = approver.post(POLICY, data=values, headers={"Origin": ORIGIN})
        assert refused.status_code == 403
    with db.transaction(tenant) as conn:
        assert trusted_browsers.allowed(conn, tenant)


def second_account(db, engine, seeded):
    """Account B, an administrator of the second workspace with an authenticator verified on
    its session, and a trust of its own: its grant, session, account and cookie."""
    from execbound import mfa
    from execbound.surfaces.sessions import load_session

    tenant = seeded["tenants"][1]
    principal, _ = enroll(engine, tenant, email="second@example.test", kind="ADMIN")
    account = adopt(db, tenant, principal)
    grant = issue_session(db, sign_in_with_password(db, "second@example.test", PASSWORD))
    session = load_session(db, grant.token)
    seed = mfa.begin_enrollment(db, session, RING)
    mfa.confirm_enrollment(
        db, session, RING, mfa.totp(seed, int(SystemClock().now().timestamp()) // 30)
    )
    session = load_session(db, grant.token)
    cookie, _, _ = granted(db, engine, session)
    return grant, session, account, cookie


def test_tb_one_account_cannot_remove_another_accounts_trust(db, runtime, admin_engine, seeded):
    """Account B, on a browser holding account A's trust cookie (a shared desktop), posts A's
    real browser id to Remove and then Remove all: only B's own trust goes. A's is still
    listed, still applies and has no removal recorded, and its cookie is left in the browser."""
    from test_trusted_browsers import security_events

    runtime.clock = SystemClock()
    _, current, account, _, _ = verified_pair(db, admin_engine, seeded)
    theirs, _, _ = granted(db, admin_engine, current)
    grant, _, other, mine = second_account(db, admin_engine, seeded)
    assert other != account
    with browser(db, runtime, grant, trust=theirs) as client:
        view = client.get(API + "/settings").json()["security"]["trusted"]
        # B sees only its own trust, and A's cookie marks none of B's rows.
        assert [item["browser_id"] for item in view] == [str(browser_of(mine))]
        assert [item["this_browser"] for item in view] == [False]
        removed = posted(
            client,
            API + "/settings/trusted-browsers/remove",
            {"browser_id": str(browser_of(theirs))},
        )
        assert removed.status_code == 200, removed.text
        assert len(removed.json()["security"]["trusted"]) == 1
        # Nothing of B's was removed, so A's cookie in this browser is left alone.
        assert [c for c in removed.headers.get_list("set-cookie") if c.startswith(TRUST)] == []
        emptied = posted(client, API + "/settings/trusted-browsers/remove-all", {})
        assert emptied.status_code == 200, emptied.text
        assert emptied.json()["security"]["trusted"] == []
        assert [c for c in emptied.headers.get_list("set-cookie") if c.startswith(TRUST)] == []
    listed = trusted_browsers.listed(db, current, clock=runtime.clock)
    assert [trust.browser_id for trust in listed] == [browser_of(theirs)]
    assert "trusted_browser_removed" not in security_events(admin_engine, account)
    assert security_events(admin_engine, other).count("trusted_browser_removed") == 1
    # A's trust still skips A's factor at A's next sign-in.
    _, pending = signed_in_again(db)
    assert trusted_browsers.apply(db, pending, theirs, clock=runtime.clock) is not None
