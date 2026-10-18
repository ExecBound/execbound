# SPDX-License-Identifier: AGPL-3.0-only
"""Turning the weekly summary on and off under My account (#678): HV12.

The person's own row only, audited both ways; refused with no address, unavailable where the
deployment does not send it, refused to a personal access token, and with the harness's own
refusals. An account in two workspaces has its account's address in both, although its
principal in the second holds none.
"""

import pytest
from console_api_fixtures import API, ORIGIN, console_client, console_config, refusals
from sqlalchemy import text
from test_execution import registry as registry  # noqa: F401
from test_execution import world as world  # noqa: F401
from test_migration_without_bypass import fenced
from test_protected_path import connector as connector  # noqa: F401
from test_protected_path import live_provider as live_provider  # noqa: F401
from test_runtime import runtime as runtime  # noqa: F401
from test_workspace_accounts import adopt, enroll, second_membership

from execbound.transports import MailConfig

PATH = API + "/settings/weekly-summary"


def relay(**changes) -> MailConfig:
    return MailConfig(
        "localhost",
        2525,
        "tls",
        "relay-user",
        "relay-password-0123456789",
        "summaries@example.com",
        **{"weekly_summary": True, **changes},
    )


def events(admin_engine, tenant, kind):
    with admin_engine.connect() as conn:
        return list(
            conn.execute(
                text(
                    "SELECT payload FROM execbound.audit_events WHERE tenant_id=:t AND kind=:k "
                    "ORDER BY sequence"
                ),
                {"t": tenant, "k": kind},
            ).scalars()
        )


def subscription(admin_engine, tenant, principal):
    with admin_engine.connect() as conn:
        return (
            conn.execute(
                text(
                    "SELECT * FROM execbound.weekly_summary_subscriptions "
                    "WHERE tenant_id=:t AND principal_id=:p"
                ),
                {"t": tenant, "p": principal},
            )
            .mappings()
            .one_or_none()
        )


def set_email(admin_engine, tenant, principal, email):
    with admin_engine.begin() as conn:
        fenced(conn, tenant)
        conn.execute(
            text("UPDATE execbound.principals SET email=:e WHERE tenant_id=:t AND principal_id=:p"),
            {"t": tenant, "p": principal, "e": email},
        )


def test_hv12_the_route_refuses_as_every_route_does(db, runtime, seeded, admin_engine, world):
    results = refusals(db, runtime, seeded, admin_engine, world, PATH, "POST")
    assert results["bearer"].status_code == 403 and results["bearer"].json()["code"] == "FORBIDDEN"
    assert results["audited"] == 1
    missing = results["no_session"]
    assert missing.status_code == 401 and missing.json()["code"] == "SESSION_REQUIRED"
    runtime.mail = relay()
    with console_client(db, runtime, admin_engine, world["admin"]) as page:
        body = {"subscribed": True}
        wrong = page.post(PATH, body, csrf="wrong")
        assert wrong.status_code == 403 and wrong.json()["code"] == "INVALID_CSRF"
        assert page.post(PATH, body, origin="http://evil.example").status_code == 403
        assert page.post(PATH, body, content_type="text/plain").status_code == 415
        unknown = page.post(
            PATH, {"subscribed": True, "principal_id": str(world["human"].principal_id)}
        )
        assert unknown.status_code == 400 and unknown.json()["code"] == "INVALID_BODY"
        twice = page.post(PATH, raw=b'{"subscribed": true, "subscribed": false}')
        assert twice.status_code == 400 and twice.json()["code"] == "INVALID_BODY"
        assert page.get(PATH).status_code == 405


def test_hv12_on_off_and_on_again_writes_the_persons_own_row_and_audits_it(
    db, runtime, admin_engine, world
):
    tenant, who = world["identity"].tenant_id, world["admin"].principal_id
    runtime.mail = relay()
    set_email(admin_engine, tenant, who, "admin@example.org")
    with console_client(db, runtime, admin_engine, world["admin"]) as page:
        before = page.get(API + "/settings").json()["weekly_summary"]
        assert before == {"available": True, "subscribed": False, "address": "admin@example.org"}
        on = page.post(PATH, {"subscribed": True})
        assert on.status_code == 200, on.text
        assert on.json()["weekly_summary"]["subscribed"] is True
        row = subscription(admin_engine, tenant, who)
        assert row["ended_at"] is None and row["ended_via"] is None
        again = page.post(PATH, {"subscribed": True})
        assert again.status_code == 409 and again.json()["code"] == "CONFLICT"
        off = page.post(PATH, {"subscribed": False})
        assert off.json()["weekly_summary"]["subscribed"] is False
        assert subscription(admin_engine, tenant, who)["ended_via"] == "SETTINGS"
        assert page.post(PATH, {"subscribed": True}).json()["weekly_summary"]["subscribed"] is True
    assert len(events(admin_engine, tenant, "weekly_summary.subscribed")) == 2
    assert events(admin_engine, tenant, "weekly_summary.unsubscribed") == [{"via": "settings"}]
    # Nobody else's row was touched.
    assert subscription(admin_engine, tenant, world["human"].principal_id) is None


def test_hv12_without_an_address_it_is_refused_and_creates_nothing(
    db, runtime, admin_engine, world
):
    tenant, who = world["identity"].tenant_id, world["admin"].principal_id
    runtime.mail = relay()
    with console_client(db, runtime, admin_engine, world["admin"]) as page:
        assert page.get(API + "/settings").json()["weekly_summary"]["address"] is None
        refused = page.post(PATH, {"subscribed": True})
        assert refused.status_code == 409 and refused.json()["code"] == "CONFLICT"
    assert subscription(admin_engine, tenant, who) is None
    assert events(admin_engine, tenant, "weekly_summary.subscribed") == []


@pytest.mark.parametrize("mail", [None, relay(weekly_summary=False)])
def test_hv12_a_deployment_that_does_not_send_it_offers_nothing(
    db, runtime, admin_engine, world, mail
):
    runtime.mail = mail
    set_email(
        admin_engine, world["identity"].tenant_id, world["admin"].principal_id, "a@example.org"
    )
    with console_client(db, runtime, admin_engine, world["admin"]) as page:
        assert page.get(API + "/settings").json()["weekly_summary"]["available"] is False
        refused = page.post(PATH, {"subscribed": True})
        assert refused.status_code == 503 and refused.json()["code"] == "UNAVAILABLE"


def test_hv12_an_account_in_two_workspaces_has_its_address_in_both(
    db, runtime, admin_engine, seeded
):
    from fastapi.testclient import TestClient
    from test_workspace_switching import member_pair

    from execbound import workspaces
    from execbound.app import create_app
    from execbound.resolution.models import SystemClock
    from execbound.surfaces.sessions import load_session

    runtime.clock = SystemClock()
    runtime.mail = relay()
    grant, current, account, other = member_pair(db, admin_engine, seeded)
    with admin_engine.begin() as conn:
        fenced(conn, seeded["tenants"][1])
        conn.execute(
            text("UPDATE execbound.principals SET kind='ADMIN' WHERE principal_id=:p"),
            {"p": other},
        )
    switched = workspaces.switch_workspace(db, current, grant.account_token, seeded["tenants"][1])
    assert load_session(db, switched.token).identity.principal_id == other
    with TestClient(
        create_app(db, runtime=runtime, human=console_config()), base_url=ORIGIN
    ) as client:
        client.cookies.set("eb_session", switched.token, domain="127.0.0.1")
        client.cookies.set("eb_csrf", switched.csrf_token, domain="127.0.0.1")
        # The account's own cookie is unchanged by a switch; only the session's rotates.
        client.cookies.set("eb_account", grant.account_token, domain="127.0.0.1")
        headers = {"Origin": ORIGIN, "X-Execbound-Workspace": str(switched.session_id)}
        view = client.get(API + "/settings", headers=headers)
        assert view.status_code == 200, view.text
        assert view.json()["weekly_summary"]["address"] == "member@example.test"
        on = client.post(
            PATH,
            json={"subscribed": True},
            headers={**headers, "X-CSRF-Token": switched.csrf_token},
        )
        assert on.status_code == 200, on.text
    assert subscription(admin_engine, seeded["tenants"][1], other) is not None
    assert account is not None
    # The same account's address in its first workspace, read the same way.
    first_tenant = seeded["tenants"][0]
    with db.transaction(first_tenant) as conn:
        from execbound.weekly_summary import resolve_address

        assert (
            resolve_address(conn, first_tenant, grant.identity.principal_id)
            == "member@example.test"
        )


def test_hv12_resolve_address_reads_an_account_before_the_principal(db, admin_engine, seeded):
    from execbound.weekly_summary import resolve_address

    first, second = seeded["tenants"]
    principal, _ = enroll(admin_engine, first, kind="ADMIN", email="first@example.test")
    account = adopt(db, first, principal)
    other = second_membership(admin_engine, seeded, account)
    with db.transaction(second) as conn:
        assert resolve_address(conn, second, other) == "first@example.test"
    lone, _ = enroll(admin_engine, first, kind="ADMIN", email="lone@example.test")
    with db.transaction(first) as conn:
        assert resolve_address(conn, first, lone) == "lone@example.test"
