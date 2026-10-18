# SPDX-License-Identifier: AGPL-3.0-only
"""Unused groups can be removed without silently withdrawing any current access."""

from concurrent.futures import ThreadPoolExecutor
from threading import Barrier
from uuid import uuid4

import pytest
from console_api_fixtures import API, console_client, refusals
from sqlalchemy import text
from test_approval_group_rules import rule, setup_group
from test_execution import registry as registry
from test_execution import world as world
from test_protected_path import connector as connector
from test_protected_path import live_provider as live_provider
from test_runtime import runtime as runtime

from execbound import access_control as access


def test_group_cleanup_refuses_members_roles_and_active_rules_then_removes_disabled_routing(
    db, runtime, admin_engine, world
):
    with console_client(db, runtime, admin_engine, world["admin"]) as client:
        group = setup_group(client, world)
        path = f"{API}/access/groups/{group}"
        body = {"reason": "Remove completed test group"}
        assert client.post(path + "/delete", body).status_code == 409
        assert (
            client.post(path + "/members", {"members": [], "reason": "Remove members"}).status_code
            == 200
        )
        assert client.post(path + "/delete", body).status_code == 409
        assert (
            client.post(path + "/roles", {"grants": [], "reason": "Remove roles"}).status_code
            == 200
        )
        created = rule(client, world, group).json()["rule_id"]
        assert client.post(path + "/delete", body).status_code == 409
        assert client.post(f"{API}/approval-rules/{created}/disable", body).status_code == 200
        assert client.post(path + "/delete", {"reason": " "}).status_code == 400
        assert client.post(path + "/delete", body).status_code == 200
        assert not any(g["group_id"] == group for g in client.get(API + "/access").json()["groups"])
        assert not any(
            r["rule_id"] == created for r in client.get(API + "/approval-rules").json()["rules"]
        )
        assert client.post(path + "/delete", body).status_code == 404
    with db.transaction(world["admin"].tenant_id) as conn:
        event = conn.execute(
            text("SELECT payload FROM execbound.audit_events WHERE kind='access.delete_group'")
        ).scalar_one()
        assert event["subject_id"] == group
        assert event["reason"] == body["reason"]


@pytest.mark.parametrize("identity", ["human", "identity"])
def test_cleanup_cannot_be_called_without_current_administrator_permission(db, world, identity):
    with pytest.raises(access.AccessError, match="FORBIDDEN"):
        with db.transaction(world[identity].tenant_id) as conn:
            access._change(
                conn,
                world[identity].tenant_id,
                world[identity].principal_id,
                "delete_group",
                world[identity].principal_id,
                {},
                "Not allowed",
            )


def test_group_deletion_is_serialized_with_membership_changes(db, world):
    actor = world["admin"]
    with db.transaction(actor.tenant_id) as conn:
        group = access._change(
            conn,
            actor.tenant_id,
            actor.principal_id,
            "create_group",
            None,
            {"name": "Concurrent cleanup"},
            "Create group",
        )
    gate = Barrier(2)

    def change(operation):
        gate.wait()
        body = {"members": [world["human"].principal_id]} if operation == "set_members" else {}
        try:
            with db.transaction(actor.tenant_id) as conn:
                access._change(
                    conn,
                    actor.tenant_id,
                    actor.principal_id,
                    operation,
                    group,
                    body,
                    "Concurrent change",
                )
            return operation
        except access.AccessError as exc:
            return exc.code

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = set(pool.map(change, ["delete_group", "set_members"]))
    assert results in ({"delete_group", "NOT_FOUND"}, {"set_members", "GROUP_IN_USE"})
    with db.transaction(actor.tenant_id) as conn:
        count = conn.execute(
            text("SELECT count(*) FROM execbound.access_group_members WHERE group_id=:g"),
            {"g": group},
        ).scalar_one()
        assert count == (1 if "set_members" in results else 0)


def test_cleanup_is_session_only_and_refuses_another_tenants_group(
    db, runtime, admin_engine, world, seeded
):
    foreign = uuid4()
    tenant = world["admin"].tenant_id
    with admin_engine.begin() as conn:
        other = conn.execute(
            text("SELECT tenant_id FROM execbound.tenants WHERE tenant_id<>:t LIMIT 1"),
            {"t": tenant},
        ).scalar_one()
        conn.execute(
            text(
                "INSERT INTO execbound.access_groups(tenant_id,group_id,name) "
                "VALUES(:t,:g,'Other tenant')"
            ),
            {"t": other, "g": foreign},
        )
    path = f"{API}/access/groups/{foreign}/delete"
    answers = refusals(db, runtime, seeded, admin_engine, world, path, "POST")
    assert answers["bearer"].status_code == 403
    assert answers["no_session"].status_code == 401
    with console_client(db, runtime, admin_engine, world["admin"]) as client:
        assert client.post(path, {"reason": "Missing CSRF"}, csrf=None).status_code == 403
        assert (
            client.post(
                path, {"reason": "Wrong origin"}, origin="https://foreign.invalid"
            ).status_code
            == 403
        )
        assert client.post(path, {"reason": "Cannot delete foreign group"}).status_code == 404
    with admin_engine.connect() as conn:
        assert (
            conn.execute(
                text("SELECT count(*) FROM execbound.access_groups WHERE group_id=:g"),
                {"g": foreign},
            ).scalar_one()
            == 1
        )
