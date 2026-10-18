# SPDX-License-Identifier: AGPL-3.0-only
"""Review permission belongs to a signed-in person, including an administrator."""

import pytest
from console_api_fixtures import API, console_client
from space_fixtures import make_space, seat
from sqlalchemy import text
from test_approval_quorum import activate, quorum_bundle
from test_console_api_approvals import decide, detail
from test_execution import registry as registry
from test_execution import world as world
from test_human_surface import classic, pending
from test_protected_path import connector as connector
from test_protected_path import live_provider as live_provider
from test_runtime import runtime as runtime

from execbound.execution import decide_approval
from execbound.execution.models import ExecutionError
from execbound.replay.export import export_history
from execbound.replay.verify import verify_export

pytestmark = pytest.mark.integration


def not_reviewing(response) -> None:
    """An administrator reads an approval they are not assigned to as a record waiting on
    someone else, with nothing to decide with (#678)."""
    assert response.status_code == 200, response.text
    assert response.json()["reviewing"] is False and response.json()["continuation"] is None


def grant(client, world, *, active=True):
    principal = world["admin"].principal_id
    suffix = "assign" if active else "unassign"
    response = client.post(
        f"{API}/people/{principal}/scopes/{suffix}",
        {"target": str(world["canonical"]), "action": "endpoint.isolate"},
    )
    assert response.status_code == 200, response.text
    return response.json()


@pytest.mark.parametrize("surface", ["console", "classic"])
def test_existing_admin_reviews_only_assigned_actions_and_resume_keeps_the_same_identity(
    db, runtime, admin_engine, world, surface
):
    view = pending(runtime, world)
    with console_client(db, runtime, admin_engine, world["admin"]) as client:
        queue = client.get(API + "/approvals")
        assert queue.status_code == 200 and queue.json()["items"] == []
        not_reviewing(detail(client, view.approval_id))
        person = grant(client, world)
        assert len(person["scopes"]) == 1
        assert person["person"]["kind"] == "ADMIN"
        assert [item["approval_id"] for item in client.get(API + "/approvals").json()["items"]] == [
            str(view.approval_id)
        ]
        opened = detail(client, view.approval_id)
        assert opened.status_code == 200
        if surface == "console":
            reviewed = decide(client, view.approval_id, opened.json()["continuation"])
            assert reviewed.status_code == 200, reviewed.text
        else:
            path, fields = classic(client.client, view.approval_id)
            reviewed = client.client.post(
                path,
                data={**fields, "decision": "APPROVE"},
                headers={"Origin": "http://127.0.0.1"},
            )
            assert reviewed.status_code == 303
        resumed = pending(runtime, world)
        assert resumed.state == "EXECUTED" and resumed.execution_id == view.execution_id
        assert pending(runtime, world).execution_id == view.execution_id
    with admin_engine.connect() as conn:
        assert (
            conn.execute(
                text("SELECT principal_id FROM execbound.approval_decisions WHERE approval_id=:a"),
                {"a": view.approval_id},
            ).scalar_one()
            == world["admin"].principal_id
        )
    retained = export_history(db, world["admin"], clock=world["clock"])
    verify_export(retained, retained.head)


@pytest.mark.parametrize("when", ["before_decision", "before_resume"])
def test_revoking_an_admin_review_assignment_prevents_the_effect(
    db, runtime, admin_engine, world, when
):
    view = pending(runtime, world)
    with console_client(db, runtime, admin_engine, world["admin"]) as client:
        grant(client, world)
        opened = detail(client, view.approval_id).json()
        if when == "before_resume":
            assert decide(client, view.approval_id, opened["continuation"]).status_code == 200
        grant(client, world, active=False)
        not_reviewing(detail(client, view.approval_id))
        if when == "before_decision":
            assert decide(client, view.approval_id, opened["continuation"]).status_code == 404
        else:
            assert pending(runtime, world).state == "STALE_AUTHORIZATION"
    with admin_engine.connect() as conn:
        assert (
            conn.execute(
                text("SELECT count(*) FROM execbound.execution_impact WHERE execution_id=:e"),
                {"e": view.execution_id},
            ).scalar_one()
            == 0
        )


def test_an_agent_never_acquires_review_authority(db, runtime, admin_engine, world):
    view = pending(runtime, world)
    with console_client(db, runtime, admin_engine, world["admin"]) as client:
        response = client.post(
            f"{API}/people/{world['identity'].principal_id}/scopes/assign",
            {"target": str(world["canonical"]), "action": "endpoint.isolate"},
        )
        assert response.status_code == 404
    with pytest.raises(ExecutionError) as refused:
        decide_approval(db, world["identity"], view.approval_id, "APPROVE", world["clock"])
    assert refused.value.code == "INVALID_IDENTITY"


def test_an_admin_assignment_in_another_space_does_not_allow_review(
    db, runtime, admin_engine, world
):
    view = pending(runtime, world)
    with console_client(db, runtime, admin_engine, world["admin"]) as client:
        grant(client, world)
        with admin_engine.begin() as conn:
            other = make_space(conn, world["admin"].tenant_id, "Other customer")
            conn.execute(
                text("UPDATE execbound.approval_scopes SET space_id=:s WHERE approver_id=:p"),
                {"s": other, "p": world["admin"].principal_id},
            )
        assert client.get(API + "/approvals").json()["items"] == []
        not_reviewing(detail(client, view.approval_id))
    with pytest.raises(ExecutionError) as refused:
        decide_approval(db, world["admin"], view.approval_id, "APPROVE", world["clock"])
    assert refused.value.code == "NOT_FOUND"


def test_scoped_home_and_board_do_not_count_a_grant_from_another_space(
    db, runtime, admin_engine, world
):
    pending(runtime, world)
    with admin_engine.begin() as conn:
        other = make_space(conn, world["human"].tenant_id, "Other customer")
        conn.execute(
            text("UPDATE execbound.approval_scopes SET space_id=:s WHERE approver_id=:p"),
            {"s": other, "p": world["human"].principal_id},
        )
    with console_client(db, runtime, admin_engine, world["human"]) as client:
        assert client.get(API + "/overview").json()["pending_approvals"] == 0
        assert client.get(API + "/approvals").json()["items"] == []
        board = client.get(API + "/board").json()
        assert board["window"]["requests"] == 0 and board["shots"] == []


@pytest.mark.parametrize("narrow_after_decision", [False, True])
def test_mixed_human_quorum_keeps_the_admin_identity_and_rechecks_space_access(
    db, runtime, admin_engine, world, narrow_after_decision
):
    activate(db, world, quorum_bundle(world))
    view = pending(runtime, world)
    with console_client(db, runtime, admin_engine, world["admin"]) as client:
        grant(client, world)
        opened = detail(client, view.approval_id).json()
        assert decide(client, view.approval_id, opened["continuation"]).status_code == 200
    assert pending(runtime, world).state == "PENDING_APPROVAL"
    decide_approval(db, world["human"], view.approval_id, "APPROVE", world["clock"])
    if narrow_after_decision:
        with admin_engine.begin() as conn:
            other = make_space(conn, world["admin"].tenant_id, "Other customer")
            seat(conn, world["admin"].tenant_id, other, world["admin"].principal_id, "ADMIN")
    result = pending(runtime, world)
    assert result.state == ("STALE_AUTHORIZATION" if narrow_after_decision else "EXECUTED")
    retained = export_history(db, world["admin"], clock=world["clock"])
    verify_export(retained, retained.head)
