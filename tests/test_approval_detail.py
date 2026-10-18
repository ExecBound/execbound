# SPDX-License-Identifier: AGPL-3.0-only
"""Approval detail page: frozen context, obligations, expiry, a bounded comment, clear states."""

from datetime import timedelta
from uuid import uuid4

from fastapi.testclient import TestClient
from sqlalchemy import text
from test_approval_quorum import activate, quorum_bundle, second_approver
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

from execbound.app import create_app

ORIGIN = {"Origin": "http://127.0.0.1"}


def detail(client, approval_id):
    """The classic approval page, which is the server-rendered one that stays (#333)."""
    return client.get(f"/approvals/{approval_id}/classic")


def approval_state(engine, approval_id):
    with engine.begin() as conn:
        return conn.execute(
            text("SELECT state FROM execbound.approvals WHERE approval_id=:a"), {"a": approval_id}
        ).scalar_one()


def test_detail_shows_context_obligations_limits_and_expiry(human_client, runtime, world):
    view = pending(runtime, world)
    listing = human_client.get("/api/console/v1/approvals")
    assert listing.status_code == 200
    assert str(view.approval_id) in listing.text
    page = detail(human_client, view.approval_id)
    assert (
        page.status_code == 200 and "script-src 'self'" in page.headers["Content-Security-Policy"]
    )
    body = page.text
    assert "device-01" in body and str(world["canonical"]) in body
    assert "Authoritative context" in body and "environment" in body and "production" in body
    assert "inventory" in body and "Observed" in body and "valid until" in body
    assert "Approval policy:" in body and "Limit exceeded" not in body
    assert "Impact limits" in body and "targets per" in body
    assert "until this approval expires" in body and " s</strong>" in body
    assert "approvals recorded" not in body
    path, values = form_values(body, "/decide")
    assert path == f"/approvals/{view.approval_id}/decide"
    assert 'name="comment"' in body


def test_a_decision_with_a_comment_is_recorded_in_the_audit_event(
    human_client, runtime, world, admin_engine, live_provider
):
    tenant = world["identity"].tenant_id
    view = pending(runtime, world)
    path, values = form_values(detail(human_client, view.approval_id).text, "/decide")
    values.update(decision="APPROVE", comment="  Confirmed with the on-call lead <b>7</b>  ")
    assert human_client.post(path, data=values, headers=ORIGIN).status_code == 303
    [approved] = [
        t for t in audit(admin_engine, tenant, "approval.transition") if t["to_state"] == "APPROVED"
    ]
    assert approved["comment"] == "Confirmed with the on-call lead <b>7</b>"
    page = detail(human_client, view.approval_id)
    assert page.status_code == 200 and "This approval is approved" in page.text
    assert "/decide" not in page.text
    assert pending(runtime, world).state == "EXECUTED"
    assert live_provider.store.resource(tenant, world["canonical"]).mutation_count == 1
    settled = detail(human_client, view.approval_id).text
    assert "consumed" in settled and "executed" in settled and "/decide" not in settled


def test_a_decision_without_a_comment_leaves_the_payload_unchanged(
    human_client, runtime, world, admin_engine
):
    tenant = world["identity"].tenant_id
    view = pending(runtime, world)
    path, values = form_values(detail(human_client, view.approval_id).text, "/decide")
    values.update(decision="DENY", comment="")
    assert human_client.post(path, data=values, headers=ORIGIN).status_code == 303
    [denied] = [
        t for t in audit(admin_engine, tenant, "approval.transition") if t["to_state"] == "DENIED"
    ]
    assert "comment" not in denied
    assert "denied" in detail(human_client, view.approval_id).text


def test_comments_are_bounded_and_never_carry_secrets(human_client, runtime, world, admin_engine):
    view = pending(runtime, world)
    path, values = form_values(detail(human_client, view.approval_id).text, "/decide")
    for comment in ("x" * 501, "Bearer eb1.aaaa.bbbb.cccc", "line\x00break"):
        attempt = {**values, "decision": "APPROVE", "comment": comment}
        assert human_client.post(path, data=attempt, headers=ORIGIN).status_code == 400
        assert approval_state(admin_engine, view.approval_id) == "PENDING"
    assert (
        human_client.post(
            path, data={**values, "decision": "APPROVE", "note": "x"}, headers=ORIGIN
        ).status_code
        == 400
    )
    assert approval_state(admin_engine, view.approval_id) == "PENDING"


def test_an_expired_approval_shows_its_state_and_takes_no_decision(human_client, runtime, world):
    view = pending(runtime, world)
    path, values = form_values(detail(human_client, view.approval_id).text, "/decide")
    world["clock"].value += timedelta(seconds=121)
    page = detail(human_client, view.approval_id)
    assert page.status_code == 200 and "This approval has expired" in page.text
    assert "/decide" not in page.text
    values["decision"] = "APPROVE"
    assert human_client.post(path, data=values, headers=ORIGIN).status_code >= 400


def test_quorum_progress_and_no_form_after_an_own_decision(
    human_client, runtime, world, db, admin_engine
):
    activate(db, world, quorum_bundle(world))
    second_approver(admin_engine, db, world)
    view = pending(runtime, world)
    page = detail(human_client, view.approval_id)
    assert "0 of 2 approvals recorded" in page.text
    path, values = form_values(page.text, "/decide")
    values.update(decision="APPROVE", comment="First of two")
    assert human_client.post(path, data=values, headers=ORIGIN).status_code == 303
    page = detail(human_client, view.approval_id)
    assert (
        "1 of 2 approvals recorded" in page.text
        and "Your decision (approve) is recorded" in page.text
    )
    assert "Decisions so far" in page.text and "/decide" not in page.text
    assert human_client.post(path, data=values, headers=ORIGIN).status_code == 409
    [recorded] = audit(admin_engine, world["identity"].tenant_id, "approval.decision_recorded")
    assert recorded["comment"] == "First of two"


def test_foreign_unknown_and_unassigned_human_requests_are_refused(
    human_client, db, human_config, runtime, world, admin_engine
):
    view = pending(runtime, world)
    assert detail(human_client, uuid4()).status_code == 404
    assert human_client.get("/approvals/not-a-uuid/classic").status_code == 404
    with admin_engine.begin() as conn:
        conn.execute(
            text("UPDATE execbound.approval_scopes SET active=false WHERE approver_id=:p"),
            {"p": world["human"].principal_id},
        )
    assert detail(human_client, view.approval_id).status_code == 404
    admin_app = create_app(db, runtime=runtime, human=human_config)
    with TestClient(admin_app, base_url="http://127.0.0.1", follow_redirects=False) as admin:
        _, values = form_values(admin.get("/login?setup=1").text, "/session")
        values["credential"] = credential(admin_engine, world["admin"])
        assert admin.post("/session", data=values, headers=ORIGIN).status_code == 303
        assert detail(admin, view.approval_id).status_code == 404


def test_the_classic_page_is_the_same_page_and_still_decides(
    human_client, db, human_config, runtime, world, admin_engine
):
    """`/approvals/{id}/classic` is the no-script fallback of the rebuilt console (#333)."""
    view = pending(runtime, world)
    classic = human_client.get(f"/approvals/{view.approval_id}/classic")
    assert classic.status_code == 200
    assert classic.text == detail(human_client, view.approval_id).text
    path, values = form_values(classic.text, "/decide")
    assert path == f"/approvals/{view.approval_id}/decide"
    assert human_client.get(f"/approvals/{uuid4()}/classic").status_code == 404
    assert human_client.get("/approvals/not-a-uuid/classic").status_code == 404
    admin_app = create_app(db, runtime=runtime, human=human_config)
    with TestClient(admin_app, base_url="http://127.0.0.1", follow_redirects=False) as admin:
        _, login = form_values(admin.get("/login?setup=1").text, "/session")
        login["credential"] = credential(admin_engine, world["admin"])
        assert admin.post("/session", data=login, headers=ORIGIN).status_code == 303
        assert admin.get(f"/approvals/{view.approval_id}/classic").status_code == 404
    values.update(decision="DENY", comment="From the basic page")
    assert human_client.post(path, data=values, headers=ORIGIN).status_code == 303
    assert approval_state(admin_engine, view.approval_id) == "DENIED"
    assert "denied" in human_client.get(f"/approvals/{view.approval_id}/classic").text


def test_provider_markup_renders_as_literal_text(human_client, runtime, world, admin_engine):
    markup = "<b>device</b><script>alert(1)</script>"
    with admin_engine.begin() as conn:
        conn.execute(
            text(
                "UPDATE execbound.resources SET provider_id=:m "
                "WHERE tenant_id=:t AND resource_id=:r"
            ),
            {"m": markup, "t": world["identity"].tenant_id, "r": world["target"]},
        )
    view = pending(runtime, world)
    body = detail(human_client, view.approval_id).text
    assert markup not in body and "&lt;script&gt;alert(1)&lt;/script&gt;" in body
