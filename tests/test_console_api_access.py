# SPDX-License-Identifier: AGPL-3.0-only
"""The Credentials and Approver scopes areas of the console API (#333).

Every route through the harness, then the pages' behaviour as JSON: the cross-cutting
credential list with its labels, a credential issued to an existing principal or to a new agent
or approver created for it, never to an administrator, and revoked with a typed refusal the
second time; the scope matrix with the approvers, targets and actions the form offers, and an
assignment made and withdrawn through the approvers page's own function.
"""

import pytest
from console_api_fixtures import API, assert_no_secrets, console_client, refusals
from sqlalchemy import text
from test_console_api_agents import without_token
from test_emergency_stop import audit
from test_execution import registry as registry
from test_execution import world as world
from test_protected_path import connector as connector
from test_protected_path import live_provider as live_provider
from test_runtime import runtime as runtime

from execbound.identity import AuthenticationFailed, authenticate

CREDENTIALS = API + "/credentials"
APPROVERS = API + "/approvers"
ZERO = "00000000-0000-0000-0000-000000000000"
ROUTES = [
    (CREDENTIALS, "GET", None),
    (f"{CREDENTIALS}/issue", "POST", {"principal": "new:AGENT", "lifetime": "8"}),
    (f"{CREDENTIALS}/{ZERO}/revoke", "POST", {}),
    (APPROVERS, "GET", None),
    (
        f"{APPROVERS}/assign",
        "POST",
        {"approver": ZERO, "target": ZERO, "action": "endpoint.isolate"},
    ),
    (
        f"{APPROVERS}/unassign",
        "POST",
        {"approver": ZERO, "target": ZERO, "action": "endpoint.isolate"},
    ),
]


@pytest.mark.parametrize("path,method", [(path, method) for path, method, _ in ROUTES])
def test_every_route_refuses_a_bearer_and_no_session(
    db, runtime, seeded, admin_engine, world, path, method
):
    results = refusals(db, runtime, seeded, admin_engine, world, path, method)
    assert results["bearer"].status_code == 403 and results["bearer"].json()["code"] == "FORBIDDEN"
    assert results["audited"] == 1
    assert results["no_session"].status_code == 401


def test_an_approver_is_refused_on_every_route(db, runtime, admin_engine, world):
    with console_client(db, runtime, admin_engine, world["human"]) as approver:
        for path, method, body in ROUTES:
            response = approver.get(path) if method == "GET" else approver.post(path, body)
            assert response.status_code == 403, (path, response.text)
            assert response.json()["code"] == "FORBIDDEN"
            assert_no_secrets(response)


def test_the_credential_list_issues_to_anyone_but_an_administrator_and_revokes(
    db, runtime, admin_engine, world, seeded
):
    tenant = world["identity"].tenant_id
    agent, human, admin = (str(world[key].principal_id) for key in ("identity", "human", "admin"))
    with admin_engine.begin() as conn:
        conn.execute(
            text("UPDATE execbound.principals SET label = 'Dana' WHERE principal_id = :p"),
            {"p": world["human"].principal_id},
        )
    with console_client(db, runtime, admin_engine, world["admin"]) as client:
        page = client.get(CREDENTIALS)
        assert page.status_code == 200, page.text
        assert_no_secrets(page)
        body = page.json()
        principals = {row["principal_id"]: row for row in body["principals"]}
        assert {agent, human, admin} <= set(principals)
        assert str(seeded["principals"][1]) not in principals
        assert principals[human]["label"] == "Dana" and principals[human]["live"] == 1
        assert principals[admin]["kind"] == "ADMIN"
        rows = {row["principal_id"]: row for row in body["credentials"]}
        assert rows[human]["label"] == "Dana" and rows[human]["state"] == "live"
        assert rows[admin]["kind"] == "ADMIN" and body["live"] == len(body["credentials"])
        # A bad principal choice is a body fault; an administrator is refused by the function.
        bad = client.post(f"{CREDENTIALS}/issue", {"principal": "new:ADMIN", "lifetime": "8"})
        assert bad.status_code == 400 and bad.json()["fields"] == ["principal"]
        refused = client.post(f"{CREDENTIALS}/issue", {"principal": admin, "lifetime": "8"})
        assert refused.status_code == 400 and refused.json()["code"] == "INVALID_PRINCIPAL"
        assert "token" not in refused.json()
        elsewhere = client.post(
            f"{CREDENTIALS}/issue", {"principal": str(seeded["principals"][1]), "lifetime": "8"}
        )
        assert elsewhere.status_code == 400 and elsewhere.json()["code"] == "INVALID_PRINCIPAL"
        # An existing approver, then a new agent created for its credential.
        issued = client.post(f"{CREDENTIALS}/issue", {"principal": human, "lifetime": "24"})
        assert issued.status_code == 200 and issued.headers["cache-control"] == "no-store"
        first = without_token(issued)
        token = issued.json()["token"]
        assert first["principal_id"] == human and first["kind"] == "HUMAN_APPROVER"
        assert authenticate(runtime.db, token).principal_id == world["human"].principal_id
        made = client.post(f"{CREDENTIALS}/issue", {"principal": "new:AGENT", "lifetime": "1"})
        assert made.status_code == 200
        second = without_token(made)
        assert second["kind"] == "AGENT" and second["principal_id"] not in principals
        created = audit(admin_engine, tenant, "principal.created")[-1]
        assert created["principal_id"] == second["principal_id"] and created["kind"] == "AGENT"
        listed = client.get(CREDENTIALS)
        assert token not in listed.text and made.json()["token"] not in listed.text
        assert listed.json()["live"] == body["live"] + 2
        # Revoke, and a typed refusal the second time and for an administrator's own.
        revoked = client.post(f"{CREDENTIALS}/{first['credential_id']}/revoke", {})
        assert revoked.status_code == 200, revoked.text
        assert_no_secrets(revoked)
        states = {row["credential_id"]: row["state"] for row in revoked.json()["credentials"]}
        assert states[first["credential_id"]] == "revoked"
        with pytest.raises(AuthenticationFailed):
            authenticate(runtime.db, token)
        again = client.post(f"{CREDENTIALS}/{first['credential_id']}/revoke", {})
        assert again.status_code == 409 and again.json()["code"] == "CONFLICT"
        own = rows[admin]["credential_id"]
        assert client.post(f"{CREDENTIALS}/{own}/revoke", {}).status_code == 409
        assert client.post(f"{CREDENTIALS}/{ZERO}/revoke", {}).status_code == 409
        assert client.post(f"{CREDENTIALS}/not-an-id/revoke", {}).status_code == 404
        assert client.post(f"{CREDENTIALS}/{own}/revoke", {"x": 1}).json()["fields"] == ["x"]


def test_scopes_are_assigned_and_unassigned_by_approver_target_and_action(
    db, runtime, admin_engine, world, seeded
):
    tenant = world["identity"].tenant_id
    human = str(world["human"].principal_id)
    canonical = str(world["canonical"])
    with console_client(db, runtime, admin_engine, world["admin"]) as client:
        page = client.get(APPROVERS)
        assert page.status_code == 200, page.text
        assert_no_secrets(page)
        body = page.json()
        assert {row["principal_id"] for row in body["approvers"]} == {
            human,
            str(world["admin"].principal_id),
        }
        assert [row["canonical_target_id"] for row in body["targets"]] == [canonical]
        assert body["targets"][0]["labels"]
        assert "endpoint.isolate" in body["actions"] and body["actions"] == sorted(body["actions"])
        [row] = body["assignments"]
        assert row["approver_id"] == human and row["action"] == "endpoint.isolate"
        assert (
            row["canonical_target_id"] == canonical
            and row["labels"] == body["targets"][0]["labels"]
        )
        bad = client.post(
            f"{APPROVERS}/assign",
            {"approver": human, "target": "nope", "action": "endpoint.isolate"},
        )
        assert bad.status_code == 400 and bad.json()["fields"] == ["target"]
        unknown = client.post(
            f"{APPROVERS}/assign", {"approver": human, "target": canonical, "action": "no.such"}
        )
        assert unknown.status_code == 400 and unknown.json()["fields"] == ["action"]
        elsewhere = client.post(
            f"{APPROVERS}/assign",
            {
                "approver": str(seeded["principals"][1]),
                "target": canonical,
                "action": "endpoint.isolate",
            },
        )
        assert elsewhere.status_code in {400, 409} and "token" not in elsewhere.json()
        assigned = client.post(
            f"{APPROVERS}/assign",
            {"approver": human, "target": canonical, "action": "endpoint.lift_isolation"},
        )
        assert assigned.status_code == 200, assigned.text
        assert sorted(row["action"] for row in assigned.json()["assignments"]) == [
            "endpoint.isolate",
            "endpoint.lift_isolation",
        ]
        event = audit(admin_engine, tenant, "approval_scope.assigned")[-1]
        assert event["approver_id"] == human and event["action"] == "endpoint.lift_isolation"
        unassigned = client.post(
            f"{APPROVERS}/unassign",
            {"approver": human, "target": canonical, "action": "endpoint.lift_isolation"},
        )
        assert unassigned.status_code == 200
        assert [row["action"] for row in unassigned.json()["assignments"]] == ["endpoint.isolate"]
        again = client.post(
            f"{APPROVERS}/unassign",
            {"approver": human, "target": canonical, "action": "endpoint.lift_isolation"},
        )
        assert again.status_code == 409 and again.json()["code"] == "CONFLICT"
        assert audit(admin_engine, tenant, "approval_scope.revoked")[-1]["approver_id"] == human
