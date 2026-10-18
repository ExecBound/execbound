# SPDX-License-Identifier: AGPL-3.0-only
"""Group membership and approval rules are live authority, including after a decision."""

from uuid import UUID, uuid4

import pytest
from console_api_fixtures import API, console_client
from sqlalchemy import text
from test_execution import registry as registry
from test_execution import request
from test_execution import world as world
from test_protected_path import connector as connector
from test_protected_path import live_provider as live_provider
from test_runtime import runtime as runtime

from execbound import approval_rules
from execbound.execution import admit, decide_approval
from execbound.execution.models import ExecutionError


def setup_group(client, world):
    response = client.post(
        API + "/access/groups",
        {
            "name": "Incident responders",
            "description": "Review endpoint actions",
            "reason": "Set up the response team",
        },
    )
    assert response.status_code == 200, response.text
    group = response.json()["group_id"]
    response = client.post(
        API + f"/access/groups/{group}/members",
        {
            "members": [str(world["human"].principal_id)],
            "reason": "Add the on-call reviewer",
        },
    )
    assert response.status_code == 200, response.text
    response = client.post(
        API + f"/access/groups/{group}/roles",
        {
            "grants": [{"role": "approver", "space_id": None}],
            "reason": "Allow reviewing",
        },
    )
    assert response.status_code == 200, response.text
    return group


def rule(client, world, group, **changes):
    space = client.get(API + "/access").json()["spaces"][0]["space_id"]
    body = {
        "name": "Endpoint response",
        "group_id": group,
        "space_id": space,
        "actions": ["endpoint.isolate"],
        "targets": [str(world["canonical"])],
        "reason": "Route endpoint requests to the response team",
        **changes,
    }
    return client.post(API + "/approval-rules", body)


def remove_individual_scope(admin_engine, world):
    with admin_engine.begin() as conn:
        conn.execute(
            text("DELETE FROM execbound.approval_scopes WHERE approver_id=:p"),
            {"p": world["human"].principal_id},
        )


def test_group_rule_grants_exact_scope_and_membership_revocation_blocks_resume(
    db,
    runtime,
    admin_engine,
    world,
    live_provider,
    connector,
):
    remove_individual_scope(admin_engine, world)
    with console_client(db, runtime, admin_engine, world["admin"]) as client:
        group = setup_group(client, world)
        created = rule(client, world, group)
        assert created.status_code == 200, created.text
        pending = admit(db, world["identity"], request(world), world["clock"])
        decide_approval(db, world["human"], pending.view.approval_id, "APPROVE", world["clock"])
        removed = client.post(
            API + f"/access/groups/{group}/members",
            {
                "members": [],
                "reason": "Reviewer has left the response team",
            },
        )
        assert removed.status_code == 200, removed.text
        resumed = admit(db, world["identity"], request(world), world["clock"])
        assert resumed.view.state == "STALE_AUTHORIZATION"
        assert resumed.ticket is None
        assert (
            live_provider.store.resource(
                world["identity"].tenant_id, world["canonical"]
            ).mutation_count
            == 0
        )


def test_rule_revocation_and_unknown_target_never_grant_review(db, runtime, admin_engine, world):
    remove_individual_scope(admin_engine, world)
    with console_client(db, runtime, admin_engine, world["admin"]) as client:
        group = setup_group(client, world)
        assert rule(client, world, group, targets=[str(uuid4())]).status_code == 400
        response = rule(client, world, group)
        assert response.status_code == 200, response.text
        rule_id = response.json()["rule_id"]
        assert UUID(rule_id)
        assert (
            client.post(
                API + f"/approval-rules/{rule_id}/disable",
                {
                    "reason": "Retire this routing rule",
                },
            ).status_code
            == 200
        )
        pending = admit(db, world["identity"], request(world), world["clock"])
        with pytest.raises(ExecutionError) as refused:
            decide_approval(db, world["human"], pending.view.approval_id, "APPROVE", world["clock"])
        assert refused.value.code == "NOT_FOUND"


def test_rule_payload_is_bounded_and_does_not_accept_unmapped_actions():
    with pytest.raises(approval_rules.ApprovalRuleError):
        approval_rules.validate_choices(["unknown.delete"], [uuid4()])
    with pytest.raises(approval_rules.ApprovalRuleError):
        approval_rules.validate_choices(["endpoint.isolate"], [])
