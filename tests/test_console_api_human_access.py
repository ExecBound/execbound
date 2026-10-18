# SPDX-License-Identifier: AGPL-3.0-only
"""New access/routing endpoints preserve the console's session-only mutation boundary."""

from uuid import uuid4

import pytest
from console_api_fixtures import API, assert_no_secrets, console_client, refusals
from test_execution import registry as registry
from test_execution import world as world
from test_protected_path import connector as connector
from test_protected_path import live_provider as live_provider
from test_runtime import runtime as runtime

ZERO = "00000000-0000-0000-0000-000000000000"
ROLE = {"grants": [], "reason": "Test access"}
GROUP = {"name": "Test team", "description": None, "reason": "Test group"}
RULE = {
    "name": "Test rule",
    "space_id": ZERO,
    "group_id": ZERO,
    "actions": ["endpoint.isolate"],
    "targets": [ZERO],
    "reason": "Test routing",
}
ROUTES = [
    ("/access", "GET", None),
    (f"/access/users/{ZERO}/roles", "POST", ROLE),
    ("/access/groups", "POST", GROUP),
    (f"/access/groups/{ZERO}", "POST", GROUP),
    (f"/access/groups/{ZERO}/members", "POST", {"members": [], "reason": "Test members"}),
    (f"/access/groups/{ZERO}/roles", "POST", ROLE),
    ("/approval-rules", "GET", None),
    ("/approval-rules", "POST", RULE),
    (f"/approval-rules/{ZERO}", "POST", RULE),
    (f"/approval-rules/{ZERO}/disable", "POST", {"reason": "Test disable"}),
    ("/approval-coverage", "GET", None),
    ("/approval-coverage/unrouted", "GET", None),
]


@pytest.mark.parametrize("path,method,body", ROUTES)
def test_access_endpoints_refuse_bearer_missing_session_and_non_admin(
    db,
    runtime,
    seeded,
    admin_engine,
    world,
    path,
    method,
    body,
):
    result = refusals(db, runtime, seeded, admin_engine, world, API + path, method)
    assert result["bearer"].status_code == 403
    assert result["audited"] == 1
    assert result["no_session"].status_code == 401
    with console_client(db, runtime, admin_engine, world["human"]) as client:
        response = client.get(API + path) if method == "GET" else client.post(API + path, body)
        assert response.status_code == 403, (path, response.text)
        assert_no_secrets(response)


def test_each_new_mutation_needs_origin_and_csrf(db, runtime, admin_engine, world):
    with console_client(db, runtime, admin_engine, world["admin"]) as client:
        for path, method, body in ROUTES:
            if method == "GET":
                continue
            assert client.post(API + path, body, csrf=None).status_code == 403
            assert (
                client.post(API + path, body, origin="https://untrusted.invalid").status_code == 403
            )
            assert client.post(API + path, body, content_type="text/plain").status_code == 415


def test_unknown_members_and_spaces_do_not_change_group_roles(db, runtime, admin_engine, world):
    with console_client(db, runtime, admin_engine, world["admin"]) as client:
        response = client.post(API + "/access/groups", GROUP)
        assert response.status_code == 200, response.text
        identifier = response.json()["group_id"]
        assert client.post(
            API + f"/access/groups/{identifier}/members",
            {
                "members": [str(uuid4())],
                "reason": "Invalid member",
            },
        ).status_code in {400, 404}
        assert (
            client.post(
                API + f"/access/groups/{identifier}/roles",
                {
                    "grants": [{"role": "viewer", "space_id": str(uuid4())}],
                    "reason": "Invalid Space",
                },
            ).status_code
            == 404
        )
        group = client.get(API + "/access").json()["groups"][0]
        assert group["members"] == [] and group["roles"] == []


def test_last_admin_returns_actionable_error_and_remains_signed_in(
    db, runtime, admin_engine, world
):
    with console_client(db, runtime, admin_engine, world["admin"]) as client:
        response = client.post(API + f"/access/users/{world['admin'].principal_id}/roles", ROLE)
        assert response.status_code == 409
        assert response.json()["code"] == "LAST_ADMIN"
        assert client.get(API + "/session").status_code == 200


def test_space_role_from_json_is_accepted(db, runtime, admin_engine, world):
    with console_client(db, runtime, admin_engine, world["admin"]) as client:
        space = client.get(API + "/access").json()["spaces"][0]["space_id"]
        response = client.post(
            API + f"/access/users/{world['human'].principal_id}/roles",
            {
                "grants": [{"role": "viewer", "space_id": space}],
                "reason": "Read-only Space access",
            },
        )
        assert response.status_code == 200, response.text
    with console_client(db, runtime, admin_engine, world["human"]) as client:
        access = client.get(API + "/session").json()["access"]
        assert access["permissions"] == ["console.read"]
        assert set(access["space_permissions"]) == {space}


def test_self_demotion_succeeds_then_invalidates_old_session(db, runtime, admin_engine, world):
    with console_client(db, runtime, admin_engine, world["admin"]) as client:
        assert (
            client.post(
                API + f"/access/users/{world['human'].principal_id}/roles",
                {
                    "grants": [{"role": "administrator", "space_id": None}],
                    "reason": "Transfer administration",
                },
            ).status_code
            == 200
        )
        response = client.post(
            API + f"/access/users/{world['admin'].principal_id}/roles",
            {
                "grants": [{"role": "viewer", "space_id": None}],
                "reason": "Finish administration transfer",
            },
        )
        assert response.status_code == 200 and response.json() == {"changed": True}
        assert client.get(API + "/session").status_code == 401
