# SPDX-License-Identifier: AGPL-3.0-only
"""Group routing notifications use the approval's authoritative execution Space."""

from console_api_fixtures import console_client
from space_fixtures import make_space
from sqlalchemy import text
from test_approval_group_rules import remove_individual_scope, rule, setup_group
from test_approval_notifications import notifying as notifying
from test_approval_notifications import pending, rows
from test_execution import registry as registry
from test_execution import world as world
from test_monitoring_worker import receiver as receiver
from test_protected_path import connector as connector
from test_protected_path import live_provider as live_provider

from execbound.notifications import approval_message


def test_another_spaces_group_neither_receives_nor_counts_for_this_approval(
    db, world, admin_engine, notifying, receiver
):
    tenant = world["identity"].tenant_id
    remove_individual_scope(admin_engine, world)
    with admin_engine.begin() as conn:
        conn.execute(text("SELECT set_config('execbound.tenant_id', :t, true)"), {"t": str(tenant)})
        other_space = make_space(conn, tenant, "Other customer")
    with console_client(db, notifying, admin_engine, world["admin"]) as client:
        group = setup_group(client, world)
        response = rule(client, world, group, space_id=str(other_space))
        assert response.status_code == 200, response.text
        view = pending(notifying, world)
        # Tenant-wide operator channels remain eligible; the other Space's reviewer
        # destination must not receive the resource, action, request or approval IDs.
        assert [row["destination_id"] for row in rows(admin_engine, tenant)] == ["everyone"]
        with db.transaction(tenant) as conn:
            approval = dict(
                conn.execute(
                    text("SELECT * FROM execbound.approvals WHERE tenant_id=:t AND approval_id=:a"),
                    {"t": tenant, "a": view.approval_id},
                )
                .mappings()
                .one()
            )
            message = approval_message(conn, tenant, approval, "/approvals")
            assert message.assigned_approvers == 0


def test_the_current_spaces_group_is_counted_and_notified(
    db, world, admin_engine, notifying, receiver
):
    tenant = world["identity"].tenant_id
    remove_individual_scope(admin_engine, world)
    with console_client(db, notifying, admin_engine, world["admin"]) as client:
        group = setup_group(client, world)
        response = rule(client, world, group)
        assert response.status_code == 200, response.text
        view = pending(notifying, world)
        assert [row["destination_id"] for row in rows(admin_engine, tenant)] == [
            "assigned",
            "everyone",
        ]
        with db.transaction(tenant) as conn:
            approval = dict(
                conn.execute(
                    text("SELECT * FROM execbound.approvals WHERE tenant_id=:t AND approval_id=:a"),
                    {"t": tenant, "a": view.approval_id},
                )
                .mappings()
                .one()
            )
            message = approval_message(conn, tenant, approval, "/approvals")
            assert message.assigned_approvers == 1
