# SPDX-License-Identifier: AGPL-3.0-only
"""A role in one Space does not widen a legacy reviewer's reads in another."""

from datetime import timedelta

from space_fixtures import default_space, make_space, place, seat
from sqlalchemy import text
from test_execution import registry as registry
from test_execution import targets
from test_execution import world as world
from test_protected_path import connector as connector
from test_protected_path import live_provider as live_provider
from test_runtime import runtime as runtime
from test_spaces_isolation import seed_monitoring, session_for

from execbound import access_control as access
from execbound.execution import admit
from execbound.requests import ExternalCase
from execbound.surfaces import board, dashboard, human
from execbound.surfaces.console_api.search import search


def test_a_group_role_only_widens_reads_in_its_assigned_space(db, runtime, admin_engine, world):
    tenant = world["identity"].tenant_id
    actor, reviewer = world["admin"], world["human"]
    case = ExternalCase(source="tines", case_id="INC-MIXED-SPACES")
    admitted = [
        admit(
            db,
            world["identity"],
            wire.model_copy(update={"external_case": case}),
            world["clock"],
        ).view.execution_id
        for wire in targets(admin_engine, world, count=3, production=True)
    ]
    visible_a, visible_b, hidden_b = admitted
    with admin_engine.begin() as conn:
        conn.execute(text("SELECT set_config('execbound.tenant_id', :t, true)"), {"t": str(tenant)})
        first = default_space(conn, tenant)
        second = make_space(conn, tenant, "Legacy review only")
        seat(conn, tenant, second, reviewer.principal_id)
        for execution in (visible_b, hidden_b):
            place(conn, tenant, "executions", "execution_id", execution, second)
        place(conn, tenant, "approval_scopes", "approver_id", reviewer.principal_id, second)
        conn.execute(
            text("UPDATE execbound.executions SET created_at=:n WHERE execution_id=:e"),
            {"e": hidden_b, "n": world["clock"].now() + timedelta(seconds=1)},
        )
        conn.execute(
            text(
                "UPDATE execbound.approval_scopes SET active=false WHERE tenant_id=:t "
                "AND canonical_target_id=(SELECT canonical_target_id FROM execbound.executions "
                "WHERE tenant_id=:t AND execution_id=:e)"
            ),
            {"t": tenant, "e": hidden_b},
        )
        seed_monitoring(conn, tenant, first, actor.principal_id)
        seed_monitoring(conn, tenant, second, actor.principal_id)
    session = session_for(db, reviewer, world["clock"])
    with db.transaction(tenant) as conn:
        group = access._change(
            conn,
            tenant,
            actor.principal_id,
            "create_group",
            None,
            {"name": "Readers of A", "description": None},
            "Test group",
        )
        access._change(
            conn,
            tenant,
            actor.principal_id,
            "set_members",
            group,
            {"members": [reviewer.principal_id]},
            "Add reviewer",
        )
        access.set_roles_in(
            conn,
            tenant,
            actor.principal_id,
            "group",
            group,
            [{"role": "viewer", "space_id": first}],
            "Read only A",
        )

    def assert_reads(expected, monitoring):
        assert {row["execution_id"] for row in human.records(runtime, session)} == expected
        assert {row["execution_id"] for row in human.records(runtime, session, reviewing=True)} == {
            visible_b
        }
        snapshot = board.for_session(runtime, session)
        assert {shot.execution_id for shot in snapshot.shots} == expected
        assert sum(snapshot.counts.values()) == len(expected)
        assert snapshot.last_request_at == world["clock"].now()
        assert snapshot.watching is monitoring
        assert len(snapshot.observations) == int(monitoring)
        assert sum(dashboard.overview(runtime, session)["counts"].values()) == len(expected)
        for execution in admitted:
            found = {row.execution_id for row in search(runtime, session, str(execution))}
            assert (execution in found) is (execution in expected)
        for execution in expected:
            detail = human.records(runtime, session, execution_id=execution)[0]
            assert {row["execution_id"] for row in detail["related_requests"]} == expected - {
                execution
            }
        # Approval details never inherit a related row through the broad Viewer grant.
        review = human.records(runtime, session, execution_id=visible_b, reviewing=True)[0]
        assert review["related_requests"] == []

    assert_reads({visible_a, visible_b}, True)
    with db.transaction(tenant) as conn:
        access._change(
            conn,
            tenant,
            actor.principal_id,
            "set_members",
            group,
            {"members": []},
            "Revoke group access",
        )
    assert_reads({visible_b}, False)
