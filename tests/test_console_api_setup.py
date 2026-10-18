# SPDX-License-Identifier: AGPL-3.0-only
"""`GET /api/console/v1/setup`: one Space's setup steps, an administrator's read (#678).

The route answers the session's Space, held to the reader's visibility and to the `ADMIN`
role in it; a personal access token answers the Space it names, held to its owner's. Every
value is a record read at request time, and the read writes nothing.
"""

import re
from datetime import UTC, datetime
from uuid import uuid4

import pytest
from console_api_fixtures import API, assert_no_secrets, console_client, refusals
from sample_fixtures import agent_identity, empty_workspace, offline_runtime, person
from sample_fixtures import sample_key as sample_key
from space_fixtures import make_space, seat
from sqlalchemy import text
from test_console_api_samples import ask, by_effect, fenced
from test_console_api_tokens import application, auth, minted_for
from test_execution import provision_identity
from test_human_surface import human_config as human_config
from test_runtime import connector as connector
from test_runtime import live_provider as live_provider
from test_runtime import registry as registry
from test_runtime import runtime as runtime
from test_runtime import world as world

from execbound import samples
from execbound.execution.modes import set_enforcement_mode

pytestmark = pytest.mark.integration

SETUP = API + "/setup"


def head(admin_engine, tenant):
    with admin_engine.begin() as conn:
        fenced(conn, tenant)
        return conn.execute(
            text("SELECT sequence FROM execbound.audit_heads WHERE tenant_id = :t"), {"t": tenant}
        ).scalar_one_or_none()


def by_key(view):
    return {item["key"]: item for item in view["milestones"]}


def second_space(admin_engine, tenant, name="Customer B"):
    with admin_engine.begin() as conn:
        fenced(conn, tenant)
        return make_space(conn, tenant, name)


def test_the_setup_route_is_an_administrators(db, admin_engine, seeded, sample_key):
    workspace = empty_workspace(admin_engine, db)
    approver = person(admin_engine, db, workspace)
    with console_client(db, offline_runtime(db, sample_key), admin_engine, approver) as reviewer:
        refused = reviewer.get(SETUP)
        assert (refused.status_code, refused.json()["code"]) == (403, "FORBIDDEN")


def test_the_setup_route_refuses_a_bearer_credential_and_a_missing_session(
    db, runtime, seeded, admin_engine, world
):
    results = refusals(db, runtime, seeded, admin_engine, world, SETUP, "GET")
    assert results["bearer"].status_code == 403 and results["audited"] == 1
    assert results["no_session"].status_code == 401


def test_an_empty_workspace_reads_five_milestones_to_do(db, admin_engine, seeded, sample_key):
    workspace = empty_workspace(admin_engine, db)
    with console_client(
        db, offline_runtime(db, sample_key), admin_engine, workspace.admin
    ) as admin:
        before = head(admin_engine, workspace.tenant_id)
        response = admin.get(SETUP)
        after = head(admin_engine, workspace.tenant_id)
    assert response.status_code == 200, response.text
    assert_no_secrets(response)
    view = response.json()
    assert view["state"] == "ready"
    assert view["space_id"] == str(workspace.space_id)
    assert view["connected"] is False
    assert [item["key"] for item in view["milestones"]] == [
        "policy",
        "agent_key",
        "first_request",
        "reviewer",
        "first_decision",
    ]
    assert all(item["state"] == "todo" and item["record"] is None for item in view["milestones"])
    assert (view["done"], view["required"], view["next"]) == (0, 5, "policy")
    assert view["observed"] is None
    assert after == before


def test_samples_and_a_request_read_back_as_records(db, admin_engine, seeded, sample_key):
    workspace = empty_workspace(admin_engine, db)
    installed = samples.install(db, workspace.admin, available=True)
    agent = agent_identity(admin_engine, db, workspace)
    asked = ask(db, agent, by_effect(installed)["deny"], "sample-dc")
    with console_client(
        db, offline_runtime(db, sample_key), admin_engine, workspace.admin
    ) as admin:
        response = admin.get(SETUP)
    assert response.status_code == 200, response.text
    assert_no_secrets(response)
    view = response.json()
    steps = by_key(view)
    assert view["connected"] is True
    assert steps["policy"]["record"] == {
        "kind": "bundle",
        "id": str(installed.bundle_id),
        "request_ref": None,
    }
    assert steps["agent_key"]["record"]["id"] == str(agent.principal_id)
    assert steps["reviewer"]["record"] == {
        "kind": "approver",
        "id": str(workspace.admin.principal_id),
        "request_ref": None,
    }
    first = steps["first_request"]["record"]
    assert first["id"] == str(asked.view.execution_id)
    assert re.fullmatch(r"EB-\d+", first["request_ref"])
    assert [
        steps[key]["state"] for key in ("policy", "agent_key", "first_request", "reviewer")
    ] == ["done"] * 4
    assert (view["done"], view["required"], view["next"]) == (4, 5, "first_decision")
    # No hostname of any sample target reaches the answer.
    assert "sample.invalid" not in response.text


def test_all_spaces_in_a_workspace_with_two_reads_choose_space(
    db, admin_engine, seeded, sample_key
):
    workspace = empty_workspace(admin_engine, db)
    second = second_space(admin_engine, workspace.tenant_id)
    with console_client(
        db, offline_runtime(db, sample_key), admin_engine, workspace.admin
    ) as admin:
        view = admin.get(SETUP).json()
        assert (view["state"], view["milestones"], view["space_id"]) == ("choose_space", [], None)
        assert view["next"] is None
        assert admin.post(API + "/session/space", {"space_id": str(second)}).status_code == 200
        chosen = admin.get(SETUP).json()
    assert (chosen["state"], chosen["space_id"]) == ("ready", str(second))
    assert all(item["state"] == "todo" for item in chosen["milestones"])


def test_an_administrator_seated_as_a_reviewer_may_not_read_a_spaces_setup(
    db, admin_engine, seeded, sample_key
):
    workspace = empty_workspace(admin_engine, db)
    seated = provision_identity(admin_engine, db, workspace.tenant_id, "ADMIN", datetime.now(UTC))
    with admin_engine.begin() as conn:
        fenced(conn, workspace.tenant_id)
        seat(conn, workspace.tenant_id, workspace.space_id, seated.principal_id, "HUMAN_APPROVER")
    with console_client(db, offline_runtime(db, sample_key), admin_engine, seated) as reviewer:
        refused = reviewer.get(SETUP)
    assert (refused.status_code, refused.json()["code"]) == (403, "FORBIDDEN")


def test_a_token_reads_its_named_space_and_is_refused_one_it_cannot_see(
    db, runtime, admin_engine, world, seeded
):
    tenant = world["admin"].tenant_id
    second = second_space(admin_engine, tenant)
    with admin_engine.begin() as conn:
        foreign = conn.execute(
            text(
                "SELECT space_id FROM execbound.spaces WHERE tenant_id = :t "
                "ORDER BY created_at LIMIT 1"
            ),
            {"t": seeded["tenants"][1]},
        ).scalar_one()
    token = minted_for(runtime, world["admin"])
    with application(db, runtime) as client:
        named = client.get(SETUP, headers={**auth(token), "X-ExecBound-Space": str(second)})
        assert named.status_code == 200, named.text
        assert named.json()["space_id"] == str(second)
        unseen = client.get(SETUP, headers={**auth(token), "X-ExecBound-Space": str(foreign)})
        assert (unseen.status_code, unseen.json()["code"]) == (422, "SPACE_REQUIRED")
        unknown = client.get(SETUP, headers={**auth(token), "X-ExecBound-Space": str(uuid4())})
        assert (unknown.status_code, unknown.json()["code"]) == (422, "SPACE_REQUIRED")


def test_observe_mode_adds_this_spaces_observed_counts(db, admin_engine, seeded, sample_key):
    workspace = empty_workspace(admin_engine, db)
    installed = samples.install(db, workspace.admin, available=True)
    with console_client(
        db, offline_runtime(db, sample_key), admin_engine, workspace.admin
    ) as admin:
        assert admin.get(SETUP).json()["observed"] is None
        set_enforcement_mode(db, workspace.admin, "OBSERVE", "Pilot")
        agent = agent_identity(admin_engine, db, workspace)
        ask(db, agent, by_effect(installed)["deny"], "observe-dc")
        observed = admin.get(SETUP).json()["observed"]
    assert (observed["eligible"], observed["held"], observed["denied"]) == (0, 0, 1)
    assert observed["since"]


def test_samples_are_placed_only_in_the_default_space_for_a_workspace_wide_reader(
    db, admin_engine, seeded, sample_key
):
    workspace = empty_workspace(admin_engine, db)
    second = second_space(admin_engine, workspace.tenant_id)
    runtime = offline_runtime(db, sample_key)
    with console_client(db, runtime, admin_engine, workspace.admin) as admin:
        assert (
            admin.post(API + "/session/space", {"space_id": str(workspace.space_id)}).status_code
            == 200
        )
        here = admin.get(SETUP).json()
        assert (here["samples_here"], here["default_space_id"]) == (True, str(workspace.space_id))
        assert admin.post(API + "/session/space", {"space_id": str(second)}).status_code == 200
        there = admin.get(SETUP).json()
        assert (there["samples_here"], there["default_space_id"]) == (
            False,
            str(workspace.space_id),
        )
    scoped = provision_identity(admin_engine, db, workspace.tenant_id, "ADMIN", datetime.now(UTC))
    with admin_engine.begin() as conn:
        fenced(conn, workspace.tenant_id)
        seat(conn, workspace.tenant_id, second, scoped.principal_id, "ADMIN")
    with console_client(db, runtime, admin_engine, scoped) as space_admin:
        view = space_admin.get(SETUP).json()
    assert (view["state"], view["space_id"]) == ("ready", str(second))
    assert (view["samples_here"], view["default_space_id"]) == (False, None)


def test_needs_enforcing_reads_back_through_the_route(db, admin_engine, seeded, sample_key):
    workspace = empty_workspace(admin_engine, db)
    samples.install(db, workspace.admin, available=True)
    set_enforcement_mode(db, workspace.admin, "OBSERVE", "Pilot")
    with console_client(
        db, offline_runtime(db, sample_key), admin_engine, workspace.admin
    ) as admin:
        view = admin.get(SETUP).json()
    assert by_key(view)["first_decision"]["state"] == "needs_enforcing"
    assert view["next"] != "first_decision"
    assert view["done"] < view["required"]
