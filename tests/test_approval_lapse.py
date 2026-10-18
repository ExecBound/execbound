# SPDX-License-Identifier: AGPL-3.0-only
"""An approval nobody answered is ended by the recovery run (#426's kernel half).

AX1 to AX10. The measurement AX1 freezes is the one its row in `docs/ACCEPTANCE_TESTS.md`
records: a pending approval reserves nothing and claims nothing, so the sweep releases
nothing, and what it repairs is a lifecycle that otherwise never terminates and the two
counts a person reads. Every row here is on real PostgreSQL, and the race is two threads
against one tenant fence.
"""

from concurrent.futures import ThreadPoolExecutor
from datetime import timedelta
from threading import Barrier
from uuid import UUID

import pytest
from sqlalchemy import text
from test_approval_deadline import deadline, long_facts
from test_execution import activate as activate  # noqa: F401
from test_execution import registry as registry  # noqa: F401
from test_execution import request, targets
from test_execution import world as world  # noqa: F401
from test_human_surface import human_app as human_app  # noqa: F401
from test_human_surface import human_client as human_client  # noqa: F401
from test_human_surface import human_config as human_config  # noqa: F401
from test_protected_path import connector as connector  # noqa: F401
from test_protected_path import live_provider as live_provider  # noqa: F401
from test_runtime import api as api  # noqa: F401
from test_runtime import runtime as runtime  # noqa: F401

from execbound.execution import admit, decide_approval, store
from execbound.execution.models import ExecutionError
from execbound.recovery_run import expire_approval, recover, select_lapsed_approvals
from execbound.replay.export import export_history
from execbound.replay.simulate import simulate
from execbound.replay.verify import verify_export
from execbound.surfaces.dashboard import overview
from execbound.surfaces.human import records

GRACE = timedelta(seconds=300)
DEADLINE = 600


def ring(world, connector):
    return {(world["identity"].tenant_id, world["account"]): connector}


def held(engine, tenant, execution_id):
    """Every reservation-shaped row this execution owns, read directly."""
    with engine.begin() as conn:
        params = {"t": tenant, "e": execution_id}
        return {
            "impact": conn.execute(
                text(
                    "SELECT count(*) FROM execbound.execution_impact "
                    "WHERE tenant_id=:t AND execution_id=:e"
                ),
                params,
            ).scalar_one(),
            "claims": conn.execute(
                text(
                    "SELECT count(*) FROM execbound.resource_claims "
                    "WHERE tenant_id=:t AND execution_id=:e AND released_at IS NULL"
                ),
                params,
            ).scalar_one(),
        }


def usage(db, world, execution_id):
    """Projected usage for every rule of the active bundle, as admission would count it."""
    tenant = world["identity"].tenant_id
    with db.transaction(tenant) as conn:
        bundle = store.active_bundle(conn, tenant)
        snapshot = store.usage(
            conn,
            world["identity"],
            bundle,
            world["clock"],
            frozen=store.frozen(store.read(conn, tenant, execution_id)),
        )
    return [(count.confirmed_targets, count.unresolved_targets) for count in snapshot.counts]


def states(engine, tenant, execution_id):
    with engine.begin() as conn:
        params = {"t": tenant, "e": execution_id}
        return (
            conn.execute(
                text(
                    "SELECT state FROM execbound.executions WHERE tenant_id=:t AND execution_id=:e"
                ),
                params,
            ).scalar_one(),
            conn.execute(
                text(
                    "SELECT state FROM execbound.approvals WHERE tenant_id=:t AND execution_id=:e"
                ),
                params,
            ).scalar_one(),
        )


def chain(engine, tenant, kind, to_state=None):
    """The audit events of one kind, oldest first, narrowed to one destination state."""
    with engine.begin() as conn:
        rows = conn.execute(
            text(
                "SELECT payload FROM execbound.audit_events "
                "WHERE tenant_id=:t AND kind=:k ORDER BY sequence"
            ),
            {"t": tenant, "k": kind},
        ).scalars()
        payloads = [row for row in rows]
    if to_state is None:
        return payloads
    return [row for row in payloads if row.get("to_state") == to_state]


def lapse(db, world, *, seconds=DEADLINE, beyond=GRACE + timedelta(seconds=1)):
    """One pending approval whose deadline passed, and the run's grace on top of it."""
    long_facts(db, world)
    deadline(db, world, seconds)
    admission = admit(db, world["identity"], request(world), world["clock"])
    assert admission.view.state == "PENDING_APPROVAL"
    world["clock"].value += timedelta(seconds=seconds) + beyond
    return admission.view


def test_ax1_a_lapsed_approval_holds_no_reservation_and_no_claim(db, world, admin_engine):
    """The measurement AX1's row in `docs/ACCEPTANCE_TESTS.md` records, frozen: a pending
    approval reserves nothing, so what the sweep repairs is never capacity."""
    tenant = world["identity"].tenant_id
    view = lapse(db, world, beyond=timedelta(hours=36))
    assert states(admin_engine, tenant, view.execution_id) == ("PENDING_APPROVAL", "PENDING")
    assert held(admin_engine, tenant, view.execution_id) == {"impact": 0, "claims": 0}
    assert usage(db, world, view.execution_id) == [(0, 0), (0, 0)]
    # Nothing in the chain says it lapsed, which is the defect.
    assert chain(admin_engine, tenant, "approval.transition") == []


def test_ax2_the_sweep_ends_it_exactly_as_a_late_touch_would(
    db, world, admin_engine, connector, live_provider
):
    tenant = world["identity"].tenant_id
    view = lapse(db, world)
    counts = recover(db, world["admin"], ring(world, connector), clock=world["clock"])
    assert counts.expired == 1
    assert states(admin_engine, tenant, view.execution_id) == ("STALE_AUTHORIZATION", "EXPIRED")
    [transition] = chain(admin_engine, tenant, "approval.transition", "EXPIRED")
    assert transition["from_state"] == "PENDING"
    assert transition["approval_id"] == str(view.approval_id)
    assert transition["plan_hash"] == view.plan_hash
    [stale] = chain(admin_engine, tenant, "execution.transition", "STALE_AUTHORIZATION")
    assert stale["from_state"] == "PENDING_APPROVAL"
    # It released nothing because it holds nothing, and it created nothing either.
    assert held(admin_engine, tenant, view.execution_id) == {"impact": 0, "claims": 0}
    assert usage(db, world, view.execution_id) == [(0, 0), (0, 0)]
    assert live_provider.store.resource(tenant, world["canonical"]).mutation_count == 0


def test_ax3_the_sweep_is_idempotent(db, world, admin_engine, connector):
    tenant = world["identity"].tenant_id
    view = lapse(db, world)
    assert recover(db, world["admin"], ring(world, connector), clock=world["clock"]).expired == 1
    before = chain(admin_engine, tenant, "approval.transition")
    for _ in range(2):
        world["clock"].value += timedelta(seconds=30)
        again = recover(db, world["admin"], ring(world, connector), clock=world["clock"])
        assert again.expired == 0
    assert chain(admin_engine, tenant, "approval.transition") == before
    assert states(admin_engine, tenant, view.execution_id) == ("STALE_AUTHORIZATION", "EXPIRED")
    assert (
        select_lapsed_approvals(db, world["admin"], grace=GRACE, limit=50, clock=world["clock"])
        == []
    )


def test_ax4_an_approval_still_inside_its_deadline_is_untouched(db, world, admin_engine, connector):
    tenant = world["identity"].tenant_id
    long_facts(db, world)
    deadline(db, world, DEADLINE)
    view = admit(db, world["identity"], request(world), world["clock"]).view
    world["clock"].value += timedelta(seconds=DEADLINE - 60)
    assert (
        select_lapsed_approvals(db, world["admin"], grace=GRACE, limit=50, clock=world["clock"])
        == []
    )
    assert recover(db, world["admin"], ring(world, connector), clock=world["clock"]).expired == 0
    assert states(admin_engine, tenant, view.execution_id) == ("PENDING_APPROVAL", "PENDING")
    # Past the deadline but inside the run's grace: still not this run's row.
    world["clock"].value += timedelta(seconds=120)
    assert recover(db, world["admin"], ring(world, connector), clock=world["clock"]).expired == 0
    assert states(admin_engine, tenant, view.execution_id) == ("PENDING_APPROVAL", "PENDING")


def test_ax5_a_decided_approval_is_never_swept(
    api, db, world, admin_engine, connector, live_provider
):
    """An approved-and-consumed execution and a denied one both stay as they are."""
    tenant = world["identity"].tenant_id
    long_facts(db, world)
    deadline(db, world, DEADLINE)
    body = request(world).model_dump(mode="json")
    first = api.post("/v1/execute", json=body).json()
    decide_approval(db, world["human"], first["approval_id"], "APPROVE", world["clock"])
    assert api.post("/v1/execute", json=body).json()["state"] == "EXECUTED"
    executed = UUID(first["execution_id"])
    [other] = targets(admin_engine, world, 1, production=True)
    denied = admit(db, world["identity"], other, world["clock"]).view
    decide_approval(db, world["human"], denied.approval_id, "DENY", world["clock"])
    assert states(admin_engine, tenant, denied.execution_id) == ("DENIED", "DENIED")
    world["clock"].value += timedelta(seconds=DEADLINE) + GRACE + timedelta(seconds=1)
    assert recover(db, world["admin"], ring(world, connector), clock=world["clock"]).expired == 0
    assert states(admin_engine, tenant, executed) == ("EXECUTED", "CONSUMED")
    assert states(admin_engine, tenant, denied.execution_id) == ("DENIED", "DENIED")
    assert live_provider.store.resource(tenant, world["canonical"]).mutation_count == 1


def test_ax6_an_approved_approval_the_agent_never_consumed_lapses_too(
    db, world, admin_engine, connector, live_provider
):
    tenant = world["identity"].tenant_id
    long_facts(db, world)
    deadline(db, world, DEADLINE)
    view = admit(db, world["identity"], request(world), world["clock"]).view
    decide_approval(db, world["human"], view.approval_id, "APPROVE", world["clock"])
    assert states(admin_engine, tenant, view.execution_id) == ("PENDING_APPROVAL", "APPROVED")
    world["clock"].value += timedelta(seconds=DEADLINE) + GRACE + timedelta(seconds=1)
    assert recover(db, world["admin"], ring(world, connector), clock=world["clock"]).expired == 1
    assert states(admin_engine, tenant, view.execution_id) == ("STALE_AUTHORIZATION", "EXPIRED")
    [transition] = chain(admin_engine, tenant, "approval.transition", "EXPIRED")
    assert transition["from_state"] == "APPROVED"
    assert live_provider.store.resource(tenant, world["canonical"]).mutation_count == 0


def test_ax7_a_decision_after_the_deadline_is_refused_without_any_sweep(
    db, world, admin_engine, live_provider
):
    """Consume time, not sweep time: the window before a run can never be decided in."""
    tenant = world["identity"].tenant_id
    view = lapse(db, world, beyond=timedelta(seconds=1))
    late = decide_approval(db, world["human"], view.approval_id, "APPROVE", world["clock"])
    assert (late.state, late.approval_state) == ("STALE_AUTHORIZATION", "EXPIRED")
    assert states(admin_engine, tenant, view.execution_id) == ("STALE_AUTHORIZATION", "EXPIRED")
    # And the agent's own retry in that window gets the same answer, with no mutation.
    retry = admit(db, world["identity"], request(world), world["clock"])
    assert retry.view.state == "STALE_AUTHORIZATION" and retry.ticket is None
    assert live_provider.store.resource(tenant, world["canonical"]).mutation_count == 0
    with pytest.raises(ExecutionError) as refused:
        decide_approval(db, world["human"], view.approval_id, "APPROVE", world["clock"])
    assert refused.value.code == "INVALID_STATE"


def test_ax8_a_decision_racing_the_sweep_ends_the_row_exactly_once(
    db, world, admin_engine, connector
):
    tenant = world["identity"].tenant_id
    view = lapse(db, world)
    barrier = Barrier(2)

    def sweep():
        barrier.wait(timeout=10)
        return recover(db, world["admin"], ring(world, connector), clock=world["clock"]).expired

    def decide():
        barrier.wait(timeout=10)
        try:
            return decide_approval(db, world["human"], view.approval_id, "APPROVE", world["clock"])
        except ExecutionError as error:
            return error.code

    with ThreadPoolExecutor(max_workers=2) as pool:
        swept = pool.submit(sweep)
        decided = pool.submit(decide)
        outcomes = (swept.result(timeout=30), decided.result(timeout=30))
    # Whoever took the fence first, the row ends once and the loser adds nothing.
    assert states(admin_engine, tenant, view.execution_id) == ("STALE_AUTHORIZATION", "EXPIRED")
    assert len(chain(admin_engine, tenant, "approval.transition", "EXPIRED")) == 1
    assert len(chain(admin_engine, tenant, "execution.transition", "STALE_AUTHORIZATION")) == 1
    outcome = outcomes[1]
    assert outcome == "INVALID_STATE" or (
        outcome.state == "STALE_AUTHORIZATION" and outcome.approval_state == "EXPIRED"
    )
    assert held(admin_engine, tenant, view.execution_id) == {"impact": 0, "claims": 0}


def test_ax8b_a_decision_inside_the_deadline_always_beats_the_sweep(db, world, admin_engine):
    """The sweep re-reads the deadline under the fence, so it can never take a live row."""
    tenant = world["identity"].tenant_id
    long_facts(db, world)
    deadline(db, world, DEADLINE)
    view = admit(db, world["identity"], request(world), world["clock"]).view
    world["clock"].value += timedelta(seconds=DEADLINE - 60)
    barrier = Barrier(2)

    def sweep():
        barrier.wait(timeout=10)
        return expire_approval(db, world["admin"], view.execution_id, world["clock"])

    def decide():
        barrier.wait(timeout=10)
        return decide_approval(db, world["human"], view.approval_id, "APPROVE", world["clock"])

    with ThreadPoolExecutor(max_workers=2) as pool:
        swept = pool.submit(sweep)
        decided = pool.submit(decide)
        assert swept.result(timeout=30) is False
        assert decided.result(timeout=30).approval_state == "APPROVED"
    assert states(admin_engine, tenant, view.execution_id) == ("PENDING_APPROVAL", "APPROVED")
    assert chain(admin_engine, tenant, "approval.transition", "EXPIRED") == []


def test_ax9_the_pending_view_the_overview_and_the_sidebar_agree_after_the_sweep(
    db, world, runtime, admin_engine, connector
):
    from execbound.surfaces import sessions

    view = lapse(db, world)
    approver = sessions.load_session(
        db,
        sessions.issue_session(db, world["human"], clock=world["clock"]).token,
        clock=world["clock"],
    )
    admin = sessions.load_session(
        db,
        sessions.issue_session(db, world["admin"], clock=world["clock"]).token,
        clock=world["clock"],
    )
    # Before the sweep the row is already out of Pending and in Lapsed (#428), and the
    # overview classifies it by the deadline on the server's clock (#678): it is not
    # pending, and it is counted as lapsed before a decision until the sweep ends it.
    assert [row["execution_id"] for row in records(runtime, approver, pending=True)] == []
    assert [row["execution_id"] for row in records(runtime, approver, lapsed=True)] == [
        view.execution_id
    ]
    assert overview(runtime, admin)["pending"] == 0
    assert overview(runtime, admin)["lapsed"] == 1
    assert recover(db, world["admin"], ring(world, connector), clock=world["clock"]).expired == 1
    assert records(runtime, approver, pending=True) == []
    # It never disappears: a lapsed approval is a fact somebody should be able to read.
    assert [row["execution_id"] for row in records(runtime, approver, lapsed=True)] == [
        view.execution_id
    ]
    assert overview(runtime, admin)["pending"] == 0
    assert overview(runtime, admin)["lapsed"] == 0
    assert overview(runtime, admin)["counts"].get("STALE_AUTHORIZATION") == 1


def test_ax10_the_swept_row_replays(db, world, connector):
    view = lapse(db, world)
    assert recover(db, world["admin"], ring(world, connector), clock=world["clock"]).expired == 1
    history = export_history(db, world["admin"], world["clock"])
    report = simulate(verify_export(history, history.head))
    assert report.complete and not report.issues
    assert view.execution_id is not None
