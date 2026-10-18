# SPDX-License-Identifier: AGPL-3.0-only
"""Personal data and administrative queues keep the existing tenant/session boundaries."""

import pytest
from console_api_fixtures import API, console_client
from sqlalchemy import text
from test_execution import registry as registry
from test_execution import world as world
from test_protected_path import connector as connector
from test_protected_path import live_provider as live_provider
from test_runtime import runtime as runtime

pytestmark = pytest.mark.integration


def test_account_event_kinds_are_registered():
    """Enumerate both dynamic audit helpers' closed source sets, including passkey callers."""
    import ast
    import inspect

    from execbound import accounts, mfa, passkeys
    from execbound.replay.verify import _INFORMATIONAL

    def values(node):
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            return {node.value}
        if isinstance(node, ast.IfExp):
            return values(node.body) | values(node.orelse)
        if isinstance(node, ast.Subscript) and isinstance(node.value, ast.Dict):
            return set().union(*(values(value) for value in node.value.values))
        pytest.fail(f"Unbounded account-security event kind: {ast.dump(node)}")

    security = set()
    for module in (mfa, passkeys):
        for node in ast.walk(ast.parse(inspect.getsource(module))):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
                if node.func.id == "_event":
                    security.update("account_security." + kind for kind in values(node.args[2]))
    account = set()
    for node in ast.walk(ast.parse(inspect.getsource(accounts.change))):
        if (
            isinstance(node, ast.Compare)
            and isinstance(node.left, ast.Name)
            and node.left.id == "operation"
            and len(node.ops) == 1
            and isinstance(node.ops[0], ast.Eq)
        ):
            account.update("account." + kind for kind in values(node.comparators[0]))
    assert security and account
    assert (security | account) <= _INFORMATIONAL


def test_account_and_factor_changes_remain_replayable(db, runtime, admin_engine, world):
    from execbound import mfa
    from execbound.envelope import KeyRing
    from execbound.replay.export import export_history
    from execbound.replay.verify import verify_export
    from execbound.surfaces.sessions import load_session

    identity = world["admin"]
    ring = KeyRing("test", {"test": b"m" * 32})
    with console_client(db, runtime, admin_engine, identity) as client:
        assert client.post(API + "/account/profile", {"name": "Synthetic admin"}).status_code == 200
        session = load_session(db, client.client.cookies.get("eb_session"), clock=runtime.clock)
        seed = mfa.begin_enrollment(db, session, ring, clock=runtime.clock)
        mfa.confirm_enrollment(
            db,
            session,
            ring,
            mfa.totp(seed, int(runtime.clock.now().timestamp() // 30)),
            clock=runtime.clock,
        )
    history = export_history(db, identity)
    verified = verify_export(history, history.head)
    assert "UNKNOWN_EVENT_SEMANTICS" not in verified.issues
    assert verified.complete, verified.issues
    kinds = {event.event.kind for event in verified.events}
    assert {
        "account.profile",
        "account_security.enrollment_started",
        "account_security.factor_enabled",
    } <= kinds


def test_member_preferences_requests_and_admin_response(db, runtime, admin_engine, world):
    with console_client(db, runtime, admin_engine, world["human"]) as client:
        assert (
            client.post(API + "/account/requests", {"kind": "close_workspace"}).status_code == 403
        )
        assert client.get(API + "/account/requests").status_code == 403
        assert client.get(API + "/account/plan").status_code == 404
        response = client.post(API + "/account/requests", {"kind": "data_access"})
        request = response.json()["requests"][0]
    with console_client(db, runtime, admin_engine, world["admin"]) as client:
        assert len(client.get(API + "/account/requests").json()) == 1
        result = client.post(
            API + "/account/requests/resolve",
            {
                "request_id": request["request_id"],
                "state": "completed",
                "response": "Synthetic export delivered securely.",
            },
        )
        assert result.status_code == 200, result.text
        # The plan view is a plugin's (#496). The console's plan card reads this
        # refusal's code, not its status, to render nothing.
        plan = client.get(API + "/account/plan")
        assert plan.status_code == 404 and plan.json()["code"] == "NOT_FOUND"
    with console_client(db, runtime, admin_engine, world["human"]) as client:
        assert client.get(API + "/account").json()["requests"][0]["state"] == "completed"


def test_security_notices_use_safe_labels_instead_of_event_payloads(
    db, runtime, admin_engine, world
):
    from execbound.audit import append_event

    identity = world["human"]
    with db.transaction(identity.tenant_id) as conn:
        append_event(
            conn,
            identity.tenant_id,
            identity.principal_id,
            "account_security.passkey_added",
            {"untrusted": "secret-never-render"},
        )
    with console_client(db, runtime, admin_engine, identity) as client:
        result = client.get(API + "/account")
        assert "A passkey was added" in result.text
        assert "secret-never-render" not in result.text


def test_credential_issuance_routes_require_the_same_recent_mfa(db, runtime, admin_engine, world):
    from datetime import timedelta

    from execbound import mfa
    from execbound.envelope import KeyRing
    from execbound.surfaces.sessions import load_session

    ring = KeyRing("test", {"test": b"m" * 32})
    with console_client(db, runtime, admin_engine, world["admin"]) as client:
        session = load_session(db, client.client.cookies.get("eb_session"), clock=runtime.clock)
        seed = mfa.begin_enrollment(db, session, ring, clock=runtime.clock)
        mfa.confirm_enrollment(
            db,
            session,
            ring,
            mfa.totp(seed, int(runtime.clock.now().timestamp() // 30)),
            clock=runtime.clock,
        )
        # Past the step-up's thirty minutes on the injected clock, reading the session every
        # five minutes as an open console does, so the idle limit keeps renewing it.
        for _ in range(7):
            runtime.clock.value += timedelta(minutes=5)
            assert client.get(API + "/session").status_code == 200
        agent = str(world["identity"].principal_id)
        for path, body in [
            ("/credentials/issue", {"principal": agent, "lifetime": "1"}),
            (f"/agents/{agent}/credentials/issue", {"lifetime": "1"}),
        ]:
            response = client.post(API + path, body)
            assert response.status_code == 401, (path, response.text)
            assert response.json()["code"] == "MFA_REQUIRED"


def test_pending_privacy_requests_stay_actionable_after_many_resolutions(
    db, runtime, admin_engine, world
):
    from sqlalchemy import text

    with console_client(db, runtime, admin_engine, world["admin"]) as client:
        pending = client.post(API + "/account/requests", {"kind": "data_access"}).json()[
            "requests"
        ][0]
        with admin_engine.begin() as conn:
            conn.execute(
                text("""
              INSERT INTO execbound.account_requests
                (tenant_id,request_id,principal_id,kind,state,requested_at,closed_at,closed_by,response)
              SELECT :t,gen_random_uuid(),:p,'close_account','completed',
                clock_timestamp()+i*interval '1 second',clock_timestamp(),:p,'Handled'
              FROM generate_series(1,101) i
            """),
                {"t": world["admin"].tenant_id, "p": world["admin"].principal_id},
            )
        queue = client.get(API + "/account/requests").json()
        assert any(row["request_id"] == pending["request_id"] for row in queue)
        own = client.get(API + "/account").json()["requests"]
        assert any(row["request_id"] == pending["request_id"] for row in own)


def test_cf8_a_queued_request_names_its_requester(db, runtime, admin_engine, world):
    """The administrator's queue names the requester by number and kind (#678), so an
    unlabelled person reads "User 2" rather than an id."""
    with console_client(db, runtime, admin_engine, world["human"]) as client:
        assert client.post(API + "/account/requests", {"kind": "data_access"}).status_code == 200
    with admin_engine.connect() as conn:
        number = conn.execute(
            text("SELECT number FROM execbound.principals WHERE principal_id=:p"),
            {"p": world["human"].principal_id},
        ).scalar_one()
    with console_client(db, runtime, admin_engine, world["admin"]) as client:
        [queued] = client.get(API + "/account/requests").json()
    assert queued["principal_id"] == str(world["human"].principal_id)
    assert (queued["name"], queued["number"], queued["principal_kind"]) == (
        None,
        number,
        "HUMAN_APPROVER",
    )
    assert queued["kind"] == "data_access"


def test_a_password_reset_reads_as_its_own_notice_and_only_once(db, admin_engine, seeded):
    """The account's security notices label a `password_reset` event (#678), from a session
    opened after it, once and with its time; an account without one reads none."""
    from datetime import UTC, datetime, timedelta

    from signup_fixtures import RETAINED as RETAINED_PASSWORD
    from sqlalchemy import text
    from test_workspace_accounts import adopt, enroll

    from execbound.accounts import overview
    from execbound.passwords import sign_in_with_password
    from execbound.surfaces.sessions import issue_session, load_session

    tenant = seeded["tenants"][0]
    principal, _ = enroll(admin_engine, tenant, email="noticed@example.test", kind="ADMIN")
    account = adopt(db, tenant, principal)
    at = datetime.now(UTC) - timedelta(minutes=1)
    grant = issue_session(db, sign_in_with_password(db, "noticed@example.test", RETAINED_PASSWORD))
    before = overview(db, load_session(db, grant.token))["notifications"]
    assert all(notice["message"] != "Password reset from an emailed link" for notice in before)
    with admin_engine.begin() as conn:
        conn.execute(
            text(
                "INSERT INTO execbound.user_security_events(account_id, kind, occurred_at) "
                "VALUES (:a, 'password_reset', :at)"
            ),
            {"a": account, "at": at},
        )
    fresh = issue_session(db, sign_in_with_password(db, "noticed@example.test", RETAINED_PASSWORD))
    notices = overview(db, load_session(db, fresh.token))["notifications"]
    reset = [n for n in notices if n["message"] == "Password reset from an emailed link"]
    assert len(reset) == 1 and reset[0]["at"] == at
