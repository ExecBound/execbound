# SPDX-License-Identifier: AGPL-3.0-only
"""The settings area of the console API (#333, #253).

`/settings` is personal: what a person is, the credential they signed in with, every session
signed in as them, and one change that ends the other sessions and no one else's. `/tenant` is
an administrator's: the mode, the deadline, the stop and the read-only block, changed through
the store functions the command line calls so the audit events are the command line's. Every
route inherits the harness's refusals; the cases here are the pages' own.
"""

import json
import math
import os
import secrets
import sys
from datetime import timedelta
from uuid import UUID, uuid4

import pytest
from console_api_fixtures import (
    API,
    ORIGIN,
    assert_no_secrets,
    console_client,
    refusals,
)
from space_fixtures import default_space, make_space
from sqlalchemy import text
from test_emergency_stop import audit
from test_execution import registry as registry
from test_execution import world as world
from test_human_surface import credential, form_values, pending
from test_human_surface import human_app as human_app
from test_human_surface import human_client as human_client
from test_human_surface import human_config as human_config
from test_protected_path import connector as connector
from test_protected_path import live_provider as live_provider
from test_runtime import runtime as runtime

from execbound.cli import main
from execbound.notifications import Destination
from execbound.runtime import Runtime
from execbound.surfaces.sessions import SessionError, issue_session, load_session
from execbound.surfaces.tokens import TokenKeys

ROUTES = [
    (API + "/settings", "GET"),
    (API + "/settings/sessions/revoke-others", "POST"),
    (API + "/settings/password", "POST"),
    (API + "/tenant", "GET"),
    (API + "/tenant/mode", "POST"),
    (API + "/tenant/deadline", "POST"),
    (API + "/tenant/stop", "POST"),
    (API + "/tenant/resume", "POST"),
]


def test_settings_shows_this_device_and_ends_only_the_other_sessions_of_this_person(
    db, runtime, admin_engine, world
):
    tenant = world["identity"].tenant_id
    with console_client(db, runtime, admin_engine, world["human"]) as approver:
        first = approver.get(API + "/settings")
        assert first.status_code == 200, first.text
        assert_no_secrets(first)
        view = first.json()
        assert view["identity"]["kind"] == "HUMAN_APPROVER"
        assert view["identity"]["principal_id"] == str(world["human"].principal_id)
        assert view["identity"]["credential_id"] == str(world["human"].credential_id)
        assert (
            view["tenant_name"]
            and view["credential"]["expires_at"] > view["credential"]["issued_at"]
        )
        assert [row["current"] for row in view["sessions"]] == [True]
        assert view["others"] == 0

        other = issue_session(
            runtime.db, world["human"], clock=runtime.clock, label="Chrome on Windows"
        )
        stranger = issue_session(
            runtime.db, world["admin"], clock=runtime.clock, label="Safari on iPhone"
        )
        view = approver.get(API + "/settings").json()
        assert view["others"] == 1
        assert sorted((row["label"], row["current"]) for row in view["sessions"]) == [
            ("Chrome on Windows", False),
            ("Other", True),
        ]
        # Another person's session is not this person's, whatever the device.
        assert "Safari on iPhone" not in json.dumps(view)

        ended = approver.post(API + "/settings/sessions/revoke-others", {})
        assert ended.status_code == 200, ended.text
        assert_no_secrets(ended)
        assert ended.json()["others"] == 0 and len(ended.json()["sessions"]) == 1
        with pytest.raises(SessionError):
            load_session(runtime.db, other.token, clock=runtime.clock)
        assert load_session(runtime.db, stranger.token, clock=runtime.clock).session_id == (
            stranger.session_id
        )
        # This device stays signed in.
        assert approver.get(API + "/settings").status_code == 200
        # The body is the confirmation and nothing else.
        assert approver.post(
            API + "/settings/sessions/revoke-others", {"session_id": str(other.session_id)}
        ).json()["fields"] == ["session_id"]
    revoked = [
        event
        for event in audit(admin_engine, tenant, "human_session.revoked")
        if event.get("reason") == "OTHER_DEVICES"
    ]
    assert [event["session_id"] for event in revoked] == [str(other.session_id)]
    with console_client(db, runtime, admin_engine, world["admin"]) as admin:
        assert admin.get(API + "/settings").json()["identity"]["kind"] == "ADMIN"


def test_the_tenant_routes_refuse_an_approver_and_read_for_an_administrator(
    db, runtime, admin_engine, world
):
    with console_client(db, runtime, admin_engine, world["human"]) as approver:
        refused = approver.get(API + "/tenant")
        assert refused.status_code == 403 and refused.json()["code"] == "FORBIDDEN"
        for path in ("/tenant/mode", "/tenant/deadline", "/tenant/stop", "/tenant/resume"):
            posted = approver.post(API + path, {"garbage": True})
            assert posted.status_code == 403 and posted.json()["code"] == "FORBIDDEN", path
    with console_client(db, runtime, admin_engine, world["admin"]) as admin:
        response = admin.get(API + "/tenant")
        assert response.status_code == 200, response.text
        assert_no_secrets(response)
        view = response.json()
        assert view["tenant_id"] == str(world["identity"].tenant_id) and view["tenant_name"]
        assert view["mode"] == {"value": "ENFORCE", "changed": None}
        assert view["deadline"]["seconds"] == 120
        assert view["deadline"]["bounds"] == {"min": 120, "max": 3600}
        assert view["stop"] is None
        assert view["bundle_id"] == str(world["bundle"].bundle_id)
        assert "sandbox" not in view
        assert view["monitoring"] == {
            "sources": 0,
            "reporting": 0,
            "stale": 0,
            "overdue": 0,
            "open_findings": 0,
        }
        assert view["destinations"] == []


def test_a_mode_change_appends_the_event_the_command_line_does_and_the_shell_reads_it(
    db, runtime, admin_engine, world
):
    tenant = world["identity"].tenant_id
    admin_id = world["admin"].principal_id
    with console_client(db, runtime, admin_engine, world["admin"]) as admin:
        changed = admin.post(
            API + "/tenant/mode", {"mode": "OBSERVE", "reason": "Onboarding trial"}
        )
        assert changed.status_code == 200, changed.text
        assert_no_secrets(changed)
        view = changed.json()
        assert view["mode"]["value"] == "OBSERVE"
        assert view["mode"]["changed"]["by"] == str(admin_id)
        assert admin.get(API + "/session").json()["tenant"]["mode"] == "OBSERVE"
        event = audit(admin_engine, tenant, "tenant.mode_changed")[-1]
        assert event["reason"] == "Onboarding trial" and event["principal_id"] == str(admin_id)
        again = admin.post(API + "/tenant/mode", {"mode": "OBSERVE", "reason": "Again"})
        assert again.status_code == 409 and again.json()["code"] == "CONFLICT"
        assert "Again" not in again.text
        for bad in ({"mode": "AUDIT", "reason": "x"}, {"mode": "ENFORCE", "reason": "   "}):
            refused = admin.post(API + "/tenant/mode", bad)
            assert refused.status_code == 400 and refused.json()["code"] == "INVALID_BODY", bad
        assert admin.post(API + "/tenant/mode", {"mode": "AUDIT", "reason": "x"}).json()[
            "fields"
        ] == ["mode"]
        assert admin.post(API + "/tenant/mode", {"mode": "ENFORCE", "reason": " "}).json()[
            "fields"
        ] == ["reason"]
        back = admin.post(API + "/tenant/mode", {"mode": "ENFORCE", "reason": "Go live"})
        assert back.status_code == 200 and back.json()["mode"]["value"] == "ENFORCE"
    assert [e["reason"] for e in audit(admin_engine, tenant, "tenant.mode_changed")] == [
        "Onboarding trial",
        "Go live",
    ]


def test_the_deadline_refuses_119_3601_and_text_before_any_store_function(
    db, runtime, admin_engine, world
):
    tenant = world["identity"].tenant_id
    with console_client(db, runtime, admin_engine, world["admin"]) as admin:
        for bad in ("119", "3601", "soon", "", "1e3", "12345678901", 119, None):
            refused = admin.post(API + "/tenant/deadline", {"deadline": bad, "reason": "Try"})
            assert refused.status_code == 400, (bad, refused.text)
            assert refused.json()["code"] == "INVALID_BODY"
            assert refused.json()["fields"] == ["deadline"], bad
            assert bad in ("", None) or str(bad) not in refused.text
        assert audit(admin_engine, tenant, "tenant.approval_deadline_changed") == []
        off = admin.post(API + "/tenant/deadline", {"deadline": "off", "reason": "Small team"})
        assert off.status_code == 200, off.text
        assert off.json()["deadline"]["seconds"] is None
        assert off.json()["deadline"]["changed"]["by"] == str(world["admin"].principal_id)
        assert admin.get(API + "/session").json()["tenant"]["approval_deadline_seconds"] == 120
        later = admin.post(API + "/tenant/deadline", {"deadline": " 600 ", "reason": "Ten minutes"})
        assert later.status_code == 200 and later.json()["deadline"]["seconds"] == 600
        same = admin.post(API + "/tenant/deadline", {"deadline": "600", "reason": "Same"})
        assert same.status_code == 409 and same.json()["code"] == "CONFLICT"
    seconds = [
        e["seconds"] for e in audit(admin_engine, tenant, "tenant.approval_deadline_changed")
    ]
    assert seconds == [None, 600]


def test_a_stop_from_the_console_is_the_command_line_stop(
    db, runtime, admin_engine, world, human_client, tmp_path, monkeypatch, capsys
):
    tenant = world["identity"].tenant_id
    admin_id = world["admin"].principal_id
    view = pending(runtime, world)
    classic = f"/approvals/{view.approval_id}/classic"
    decide, decision = form_values(human_client.get(classic).text, "/decide")
    with console_client(db, runtime, admin_engine, world["admin"]) as admin:
        stopped = admin.post(API + "/tenant/stop", {"reason": "Contain <b>agent 7</b>"})
        assert stopped.status_code == 200, stopped.text
        assert_no_secrets(stopped)
        stop = stopped.json()["stop"]
        assert stop["reason"] == "Contain <b>agent 7</b>" and stop["stopped_by"] == str(admin_id)
        assert stop["committed"] == 0 and UUID(stop["stop_id"])
        assert stopped.headers["content-type"].startswith("application/json")
        # The page behind the console sees the same stop: the banner is up and there is no
        # decision form on it at all.
        paused = human_client.get(classic).text
        assert "Emergency stop active" in paused and 'class="decision' not in paused
        replayed = human_client.post(
            decide, data={**decision, "decision": "APPROVE"}, headers={"Origin": ORIGIN}
        )
        assert replayed.status_code == 423
        again = admin.post(API + "/tenant/stop", {"reason": "Twice"})
        assert again.status_code == 409 and again.json()["code"] == "CONFLICT"
        resumed = admin.post(API + "/tenant/resume", {"reason": "Reviewed"})
        assert resumed.status_code == 200 and resumed.json()["stop"] is None
        assert "Emergency stop active" not in human_client.get(classic).text
        assert admin.post(API + "/tenant/resume", {"reason": "Nothing"}).status_code == 409
        # Extra fields and an empty reason never reach the store function.
        refused = admin.post(API + "/tenant/stop", {"reason": "x", "force": True})
        assert refused.status_code == 400 and refused.json()["fields"] == ["force"]
        assert admin.post(API + "/tenant/stop", {"reason": ""}).json()["fields"] == ["reason"]

    # The same event as the command line, key for key.
    monkeypatch.setenv("DATABASE_URL", os.environ["TEST_DATABASE_URL"])
    monkeypatch.setenv("MIGRATION_DATABASE_URL", os.environ["TEST_MIGRATION_DATABASE_URL"])
    admin_file = tmp_path / "admin.token"
    admin_file.write_text(credential(admin_engine, world["admin"]), encoding="utf-8")
    common = ("--tenant", str(tenant), "--credential-file", str(admin_file))

    def run(*argv):
        monkeypatch.setattr(sys, "argv", ["execbound", *argv])
        main()
        return json.loads(capsys.readouterr().out)

    run("tenant-stop", *common, "--reason", "Incident 7")
    run("tenant-resume", *common, "--reason", "Resolved")
    activations = audit(admin_engine, tenant, "tenant.stop_activated")
    releases = audit(admin_engine, tenant, "tenant.stop_released")
    assert [event["reason"] for event in activations] == ["Contain <b>agent 7</b>", "Incident 7"]
    assert [event["reason"] for event in releases] == ["Reviewed", "Resolved"]
    console, cli = activations
    assert set(console) == set(cli)
    assert console["principal_id"] == cli["principal_id"] == str(admin_id)
    assert console["credential_id"] and cli["credential_id"]
    assert console["dispatch_committed"] == cli["dispatch_committed"] == 0
    assert console["replay"]["version"] == cli["replay"]["version"]
    assert set(releases[0]) == set(releases[1])


def test_destinations_are_id_kind_host_and_approvers_and_never_the_address_or_secret(
    db, admin_engine, world, connector
):
    tenant = world["identity"].tenant_id
    secret = "s3cr3t-" + secrets.token_urlsafe(30)
    destinations = (
        Destination(
            destination_id="soc",
            tenant_id=tenant,
            url="https://alerts.example.net/execbound/hook",
            secret=secret,
        ),
        Destination(
            destination_id="oncall",
            tenant_id=tenant,
            url="https://hooks.slack.com/services/T0/B0/" + secrets.token_urlsafe(20),
            secret="",
            kind="slack",
            approvers=frozenset({world["human"].principal_id}),
        ),
        Destination(
            destination_id="elsewhere",
            tenant_id=uuid4(),
            url="https://alerts.example.org/other",
            secret=secret,
        ),
        Destination(
            destination_id="audit",
            tenant_id=tenant,
            url="https://siem.example.net/execbound/events",
            secret=secret,
            kind="security-events",
        ),
    )
    keys = TokenKeys("pending-v1", {"pending-v1": secrets.token_bytes(32)})
    runtime = Runtime(db, [connector], clock=world["clock"], keys=keys, notifications=destinations)
    with console_client(db, runtime, admin_engine, world["admin"]) as admin:
        response = admin.get(API + "/tenant")
        assert response.status_code == 200, response.text
        assert_no_secrets(response)
        assert response.json()["destinations"] == [
            {
                "destination_id": "soc",
                "kind": "webhook",
                "host": "alerts.example.net",
                "approvers": None,
                "messages": ["pending"],
            },
            {
                "destination_id": "oncall",
                "kind": "slack",
                "host": "hooks.slack.com",
                "approvers": 1,
                "messages": ["pending"],
            },
            {
                "destination_id": "audit",
                "kind": "security-events",
                "host": "siem.example.net",
                "approvers": None,
                "messages": [],
            },
        ]
        assert secret not in response.text and "/execbound/hook" not in response.text
        assert "/services/" not in response.text and "elsewhere" not in response.text


# Approval delivery on the settings read (#678, AY15).


def seed_delivery(admin_engine, world, approval_id, destination_id, **row):
    """One notification row, written as the owner with the times the case needs."""
    now = world["clock"].now()
    created = now - row.pop("age", timedelta(days=1))
    lag = row.pop("lag", None)
    state = row.pop("state", "DELIVERED" if lag is not None else "FAILED")
    values = {
        "t": row.pop("tenant", world["identity"].tenant_id),
        "n": uuid4(),
        "a": approval_id,
        "d": destination_id,
        "k": row.pop("kind", "approval.pending"),
        "o": row.pop("outcome", None),
        "c": row.pop("closed_at", None),
        "s": state,
        "created": created,
        "delivered": None if lag is None else created + timedelta(seconds=lag),
        "e": row.pop("error", None),
    }
    assert not row
    with admin_engine.begin() as conn:
        conn.execute(
            text(
                "INSERT INTO execbound.approval_notifications (tenant_id, notification_id, "
                "approval_id, destination_id, kind, outcome, closed_at, state, attempts, "
                "created_at, next_attempt_at, delivered_at, last_error) VALUES (:t, :n, :a, :d, "
                ":k, :o, :c, :s, 1, :created, :created, :delivered, :e)"
            ),
            values,
        )


def expected_p90(lags):
    """`percentile_cont(0.9)`'s linear interpolation, rounded up to a whole second."""
    ordered = sorted(lags)
    position = 0.9 * (len(ordered) - 1)
    low = math.floor(position)
    high = min(low + 1, len(ordered) - 1)
    return math.ceil(round(ordered[low] + (ordered[high] - ordered[low]) * (position - low), 6))


def test_ay15_the_tenant_read_reports_a_week_of_announcement_delivery(
    db, admin_engine, world, connector, seeded
):
    tenant = world["identity"].tenant_id
    destinations = (
        Destination(
            destination_id="soc",
            tenant_id=tenant,
            url="https://alerts.example.net/hook",
            secret="s3cr3t-" + secrets.token_urlsafe(30),
            messages=frozenset({"closed", "pending"}),
        ),
        Destination(
            destination_id="audit",
            tenant_id=tenant,
            url="https://siem.example.net/events",
            secret="s3cr3t-" + secrets.token_urlsafe(30),
            kind="security-events",
        ),
    )
    keys = TokenKeys("pending-v1", {"pending-v1": secrets.token_bytes(32)})
    runtime = Runtime(db, [connector], clock=world["clock"], keys=keys, notifications=destinations)
    approval = pending(runtime, world).approval_id
    lags = [10, 20, 30, 40, 90]
    for day, lag in enumerate(lags, start=1):
        seed_delivery(admin_engine, world, approval, f"d{lag}", lag=lag, age=timedelta(days=day))
    seed_delivery(admin_engine, world, approval, "lapsed", error="LAPSED_BEFORE_DELIVERY")
    seed_delivery(admin_engine, world, approval, "closed", error="APPROVAL_CLOSED")
    seed_delivery(admin_engine, world, approval, "refused", error="MAIL_REFUSED")
    seed_delivery(admin_engine, world, approval, "old", lag=5, age=timedelta(days=8))
    seed_delivery(
        admin_engine,
        world,
        approval,
        "d10",
        lag=1,
        kind="approval.closed",
        outcome="APPROVED",
        closed_at=world["clock"].now(),
    )
    # Another workspace's delivery, written without its approval chain: the read names its
    # own tenant, and the fence holds it there.
    with admin_engine.begin() as conn:
        conn.execute(text("SET LOCAL session_replication_role = replica"))
        conn.execute(
            text(
                "INSERT INTO execbound.approval_notifications (tenant_id, notification_id, "
                "approval_id, destination_id, state, attempts, created_at, next_attempt_at, "
                "delivered_at) VALUES (:t, :n, :a, 'soc', 'DELIVERED', 1, :c, :c, :c)"
            ),
            {"t": seeded["tenants"][1], "n": uuid4(), "a": uuid4(), "c": world["clock"].now()},
        )
    assert expected_p90(lags) == 70
    with console_client(db, runtime, admin_engine, world["admin"]) as admin:
        response = admin.get(API + "/tenant")
        assert response.status_code == 200, response.text
        assert_no_secrets(response)
        view = response.json()
        assert view["delivery"] == {
            "window_days": 7,
            "delivered": 5,
            "median_seconds": 30,
            "p90_seconds": expected_p90(lags),
            "slowest_seconds": 90,
            "lapsed": 1,
            "failed": 1,
        }
        assert [d["messages"] for d in view["destinations"]] == [["pending", "closed"], []]
        with admin_engine.begin() as conn:
            conn.execute(
                text(
                    "DELETE FROM execbound.approval_notifications "
                    "WHERE tenant_id=:t AND destination_id='d90'"
                ),
                {"t": tenant},
            )
        fewer = admin.get(API + "/tenant").json()["delivery"]
        assert fewer["delivered"] == 4 and fewer["slowest_seconds"] == 40
        assert fewer["median_seconds"] is None and fewer["p90_seconds"] is None
    with console_client(db, runtime, admin_engine, world["human"]) as approver:
        refused = approver.get(API + "/tenant")
        assert refused.status_code == 403 and "delivery" not in refused.text


def test_ay15_with_nothing_delivered_the_figures_are_empty(db, runtime, admin_engine, world):
    with console_client(db, runtime, admin_engine, world["admin"]) as admin:
        assert admin.get(API + "/tenant").json()["delivery"] == {
            "window_days": 7,
            "delivered": 0,
            "median_seconds": None,
            "p90_seconds": None,
            "slowest_seconds": None,
            "lapsed": 0,
            "failed": 0,
        }


@pytest.mark.parametrize("path,method", ROUTES)
def test_every_settings_route_refuses_a_bearer_credential_and_a_missing_session(
    db, runtime, seeded, admin_engine, world, path, method
):
    results = refusals(db, runtime, seeded, admin_engine, world, path, method)
    assert results["bearer"].status_code == 403, (path, results["bearer"].text)
    assert results["bearer"].json()["code"] == "FORBIDDEN"
    assert results["audited"] == 1, path
    missing = results["no_session"]
    assert missing.status_code == 401 and missing.json()["code"] == "SESSION_REQUIRED", path
    assert missing.headers["content-type"].startswith("application/json")


def test_a_tenant_change_needs_the_token_the_origin_and_json(db, runtime, admin_engine, world):
    body = {"reason": "Try"}
    with console_client(db, runtime, admin_engine, world["admin"]) as admin:
        wrong = admin.post(API + "/tenant/stop", body, csrf="wrong")
        assert wrong.status_code == 403 and wrong.json()["code"] == "INVALID_CSRF"
        elsewhere = admin.post(API + "/tenant/stop", body, origin="http://evil.example")
        assert elsewhere.status_code == 403
        assert admin.post(API + "/tenant/stop", body, content_type="text/plain").status_code == 415
        assert admin.post(API + "/tenant/stop", raw=b"not json").json()["code"] == "INVALID_BODY"
        assert admin.get(API + "/tenant/stop").status_code == 405
        assert admin.post(API + "/tenant", {}).status_code == 405
        assert admin.get(API + "/tenant").json()["stop"] is None


def test_the_session_carries_the_stop_for_everyone(db, runtime, admin_engine, world):
    """The banner every route shows reads the session, so the stop travels with it."""
    from execbound.replay.verify import reject_secrets

    with (
        console_client(db, runtime, admin_engine, world["admin"]) as admin,
        console_client(db, runtime, admin_engine, world["human"]) as approver,
    ):
        assert approver.get(API + "/session").json()["stop"] is None
        stopped = admin.post(API + "/tenant/stop", {"reason": "Contain agent 7"})
        assert stopped.status_code == 200, stopped.text
        view = approver.get(API + "/session").json()
        assert view["stop"]["stop_id"] == stopped.json()["stop"]["stop_id"]
        assert view["stop"]["reason"] == "Contain agent 7"
        assert view["stop"]["stopped_by"] == str(world["admin"].principal_id)
        assert set(view["stop"]) == {
            "stop_id",
            "stopped_at",
            "stopped_by",
            "reason",
            "stopped_by_ref",
        }
        # An approver is not told who the administrator is (#678).
        assert view["stop"]["stopped_by_ref"] is None
        view.pop("csrf_token")
        reject_secrets(view)
        assert admin.get(API + "/session").json()["stop"]["reason"] == "Contain agent 7"
        assert admin.post(API + "/tenant/resume", {"reason": "Reviewed"}).status_code == 200
        assert approver.get(API + "/session").json()["stop"] is None


# A person's own password (regular sign-in).


def test_a_person_changes_their_own_password_and_only_with_the_current_one(
    db, runtime, admin_engine, world
):
    """The route names no principal: the identity comes from the session, so there is
    nothing here for an administrator to aim at somebody else."""
    from datetime import timedelta

    from test_execution import provision_credential

    from execbound.identity import authenticate
    from execbound.passwords import issue_reset, redeem_reset, set_email

    tenant = world["identity"].tenant_id
    person = world["human"].principal_id
    set_email(db, tenant, world["admin"].principal_id, person, "dana@example.com")
    minted = issue_reset(db, tenant, world["admin"].principal_id, person, clock=runtime.clock)
    redeem_reset(db, minted.code, "a decent passphrase", clock=runtime.clock)
    # Redeeming a code is a recovery, so it revoked every credential this person held. A
    # fresh one stands in for the sign-in the person would do next.
    with admin_engine.begin() as conn:
        conn.execute(text("SELECT set_config('execbound.tenant_id', :t, true)"), {"t": str(tenant)})
        token = provision_credential(conn, tenant, person, runtime.clock.now(), timedelta(hours=2))
    with console_client(db, runtime, admin_engine, authenticate(db, token)) as approver:
        view = approver.get(API + "/settings").json()
        assert view["email"] == "dana@example.com"
        assert view["has_password"] is True
        wrong = approver.post(
            API + "/settings/password",
            {"current": "not it at all", "new": "an entirely different one"},
        )
        assert wrong.status_code == 400
        assert wrong.json()["code"] == "INVALID_BODY"
        assert wrong.json().get("fields") == ["current"]
        weak = approver.post(
            API + "/settings/password", {"current": "a decent passphrase", "new": "short"}
        )
        assert weak.status_code == 400
        changed = approver.post(
            API + "/settings/password",
            {"current": "a decent passphrase", "new": "an entirely different one"},
        )
        assert changed.status_code == 200, changed.text
        assert changed.json()["has_password"] is True
        assert_no_secrets(changed)
    from execbound.identity import AuthenticationFailed as Refused
    from execbound.passwords import sign_in_with_password

    assert sign_in_with_password(
        db, "dana@example.com", "an entirely different one", clock=runtime.clock
    )
    with pytest.raises(Refused):
        sign_in_with_password(db, "dana@example.com", "a decent passphrase", clock=runtime.clock)


def test_a_person_with_no_password_cannot_set_one_through_the_change_route(
    db, runtime, admin_engine, world
):
    """The write refuses a person holding none, so this door never becomes a way to set a
    password without the one-time code an administrator issued."""
    with console_client(db, runtime, admin_engine, world["human"]) as approver:
        assert approver.get(API + "/settings").json()["has_password"] is False
        refused = approver.post(
            API + "/settings/password",
            {"current": "anything at all", "new": "an entirely different one"},
        )
        assert refused.status_code == 400
        assert refused.json()["code"] == "INVALID_BODY"


# A person's own second-factor status on My account (#678, AK10).


def test_ak10_my_account_states_the_factor_its_passkeys_and_recovery_codes(
    db, runtime, admin_engine, world
):
    from console_api_fixtures import console_config
    from test_console_api_tokens import auth, bearer, minted
    from test_passkeys import ORIGIN as PASSKEY_ORIGIN
    from test_passkeys import registration

    from execbound import mfa, passkeys
    from execbound.envelope import KeyRing

    ring = KeyRing("test", {"test": b"m" * 32})
    config = console_config(mfa=ring)
    # A deployment without account security says so.
    with console_client(db, runtime, admin_engine, world["admin"]) as client:
        assert client.get(API + "/settings").json()["security"]["available"] is False
    # Minted before the factor exists, since minting signs in a session of its own.
    token = minted(runtime, world)
    with console_client(db, runtime, admin_engine, world["admin"], config=config) as client:
        none = client.get(API + "/settings").json()["security"]
        assert none == {
            "authenticator": False,
            "passkeys": 0,
            "recovery_remaining": 0,
            "requirement": "optional",
            "available": True,
        }
        session = load_session(db, client.client.cookies.get("eb_session"), clock=runtime.clock)
        seed = mfa.begin_enrollment(db, session, ring, clock=runtime.clock)
        step = int(runtime.clock.now().timestamp() // 30)
        codes = mfa.confirm_enrollment(db, session, ring, mfa.totp(seed, step), clock=runtime.clock)
        for _ in range(2):
            options = passkeys.begin(db, session, PASSKEY_ORIGIN, "register", clock=runtime.clock)
            _, _, response = registration(options)
            assert passkeys.complete(
                db, session, PASSKEY_ORIGIN, "register", response, clock=runtime.clock
            )
        pending_grant = issue_session(db, world["admin"], clock=runtime.clock)
        pending_session = load_session(
            db, pending_grant.token, clock=runtime.clock, allow_pending_mfa=True
        )
        for code in codes[:3]:
            assert mfa.verify_factor(db, pending_session, ring, code, clock=runtime.clock)
        answer = client.get(API + "/settings")
        assert answer.status_code == 200, answer.text
        assert answer.json()["security"] == {
            "authenticator": True,
            "passkeys": 2,
            "recovery_remaining": 7,
            "requirement": "optional",
            "available": True,
        }
        # No sealed seed, recovery digest or passkey identifier reaches the answer.
        with admin_engine.connect() as conn:
            secrets_held = [
                str(value)
                for value in conn.execute(
                    text(
                        "SELECT sealed FROM execbound.account_factors WHERE principal_id = :p "
                        "UNION ALL SELECT jsonb_array_elements_text(recovery_hashes) "
                        "FROM execbound.account_factors WHERE principal_id = :p "
                        "UNION ALL SELECT credential_id FROM execbound.account_passkeys "
                        "WHERE principal_id = :p"
                    ),
                    {"p": world["admin"].principal_id},
                ).scalars()
            ]
        assert secrets_held
        assert not any(value in answer.text for value in secrets_held)
        # A personal access token reads its owner's own status.
        with bearer(client, token) as plain:
            read = plain.get(API + "/settings", headers=auth(token))
            assert read.status_code == 200, read.text
            assert read.json()["security"] == answer.json()["security"]


def _windows(view):
    """The tenant view's windows, as (space name, action, bound, what limits it, known)."""
    return [
        (space["name"], item["action"], item["bound_seconds"], item["limited_by"], item["known"])
        for space in view["approval_windows"]
        for item in space["actions"]
    ]


def test_ar9_the_tenant_view_carries_approval_windows(db, runtime, admin_engine, world):
    """The world's bundle is the endpoint pack written as custom Cedar: its approval policies
    may hold an isolation, so the window is read but the action is not known to be held."""
    with console_client(db, runtime, admin_engine, world["admin"]) as admin:
        view = admin.get(API + "/tenant").json()
        (space,) = view["approval_windows"]
        assert space["name"] == "Default"
        assert space["bundle_id"] == str(world["bundle"].bundle_id)
        assert space["actions"] == [
            {
                "action": "endpoint.isolate",
                "action_label": runtime.catalog.actions.action("endpoint.isolate").label,
                "context_seconds": 300,
                "bound_seconds": 120,
                "limited_by": "deadline",
                "source_kinds": ["incident", "inventory"],
                "known": False,
            }
        ]
        longer = admin.post(API + "/tenant/deadline", {"deadline": "3600", "reason": "An hour"})
        assert longer.status_code == 200, longer.text
        assert _windows(longer.json()) == [("Default", "endpoint.isolate", 300, "context", False)]
        off = admin.post(API + "/tenant/deadline", {"deadline": "off", "reason": "Plan clock"})
        assert _windows(off.json()) == [("Default", "endpoint.isolate", 300, "context", False)]
        # Every tenant mutation answers with the view, so each carries the same windows.
        observed = admin.post(API + "/tenant/mode", {"mode": "OBSERVE", "reason": "Trial"})
        assert _windows(observed.json()) == _windows(off.json())
        stopped = admin.post(API + "/tenant/stop", {"reason": "Drill"})
        assert stopped.status_code == 200, stopped.text
        assert _windows(stopped.json()) == _windows(off.json())
        resumed = admin.post(API + "/tenant/resume", {"reason": "Drill over"})
        assert _windows(resumed.json()) == _windows(admin.get(API + "/tenant").json())


def test_the_windows_follow_the_current_space(db, runtime, admin_engine, world):
    tenant = world["identity"].tenant_id
    with admin_engine.begin() as conn:
        first = default_space(conn, tenant)
        second = make_space(conn, tenant, "Branch office")
        # Archived: it takes no new work, so nothing is held there.
        archived = make_space(conn, tenant, "Closed office")
        conn.execute(
            text(
                "UPDATE execbound.spaces SET archived_at = now() WHERE tenant_id=:t AND space_id=:s"
            ),
            {"t": tenant, "s": archived},
        )
    with console_client(db, runtime, admin_engine, world["admin"]) as admin:
        every = admin.get(API + "/tenant").json()["approval_windows"]
        # By name; the Space with no selection is listed with no bundle and nothing held.
        assert [(space["name"], space["bundle_id"], space["actions"]) for space in every] == [
            ("Branch office", None, []),
            ("Default", str(world["bundle"].bundle_id), every[1]["actions"]),
        ]
        assert [item["action"] for item in every[1]["actions"]] == ["endpoint.isolate"]
        assert admin.post(API + "/session/space", {"space_id": str(second)}).status_code == 200
        (only,) = admin.get(API + "/tenant").json()["approval_windows"]
        assert (only["space_id"], only["bundle_id"], only["actions"]) == (str(second), None, [])
        assert admin.post(API + "/session/space", {"space_id": str(first)}).status_code == 200
        (only,) = admin.get(API + "/tenant").json()["approval_windows"]
        assert only["space_id"] == str(first) and only["actions"] == every[1]["actions"]
