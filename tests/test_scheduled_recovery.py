# SPDX-License-Identifier: AGPL-3.0-only
"""Scheduled recovery with no workspace credential (#503): SJ2, SJ4, SJ6, SJ7, SJ13, defect 2.

The helpers and fixtures are the recovery tests' own (`tests/test_recovery_run.py`), so a
scheduled run is measured against exactly what an administrator's run is measured against.
SJ2's signup workspace cases are in the plugin's own tests.
"""

from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta
from threading import Barrier
from uuid import uuid4

import pytest
from checkpoint_fixtures import checkpoint, grant_row, long_lived_admin, report, retained
from checkpoint_fixtures import gate_world as gate_world
from checkpoint_fixtures import owner as owner
from sqlalchemy import text
from test_approval_deadline import deadline, long_facts
from test_approval_lapse import DEADLINE
from test_execution import FixtureJournal, targets
from test_execution import registry as registry
from test_execution import world as world
from test_protected_path import connector as connector
from test_protected_path import live_provider as live_provider
from test_recovery_run import (
    GRACE,
    gate_ring,
    invocations,
    lost_response,
    provider_paths,
    ring,
    state_of,
)

from execbound import notifications, recovery_run
from execbound.assistant import turns
from execbound.db import UnsafeDatabaseRole
from execbound.execution import admit
from execbound.execution.models import ACT_WINDOW, ExecutionError
from execbound.execution.reconciliation import reconcile
from execbound.execution.scheduled import ScheduledActor, enlist
from execbound.provider.gateway import reconcile_operation
from execbound.recovery_run import RecoveryStopped, SweepFailed, recover, recover_scheduled

pytestmark = pytest.mark.integration


def fenced(conn, tenant):
    # Limits nothing on an `admin_engine` connection, whose owner bypasses row security
    # (see tenant_fence).
    conn.execute(text("SELECT set_config('execbound.tenant_id', :t, true)"), {"t": str(tenant)})


def actor_kinds(engine, tenant, kind) -> list[str]:
    """The kind of the actor of every `kind` event in the tenant's chain, oldest first."""
    with engine.begin() as conn:
        fenced(conn, tenant)
        return (
            conn.execute(
                text(
                    "SELECT p.kind FROM execbound.audit_events e JOIN execbound.principals p "
                    "ON p.tenant_id = e.tenant_id AND p.principal_id = e.actor_id "
                    "WHERE e.tenant_id = :t AND e.kind = :k ORDER BY e.sequence"
                ),
                {"t": tenant, "k": kind},
            )
            .scalars()
            .all()
        )


def actor_events(engine, tenant, kind) -> list[tuple[str, dict]]:
    """The actor's kind and the payload of every `kind` event in the tenant's chain, oldest
    first."""
    with engine.begin() as conn:
        fenced(conn, tenant)
        return [
            (row.kind, row.payload)
            for row in conn.execute(
                text(
                    "SELECT p.kind, e.payload FROM execbound.audit_events e "
                    "JOIN execbound.principals p "
                    "ON p.tenant_id = e.tenant_id AND p.principal_id = e.actor_id "
                    "WHERE e.tenant_id = :t AND e.kind = :k ORDER BY e.sequence"
                ),
                {"t": tenant, "k": kind},
            )
        ]


def scheduler_count(engine, tenant) -> int:
    with engine.begin() as conn:
        fenced(conn, tenant)
        return conn.execute(
            text(
                "SELECT count(*) FROM execbound.principals WHERE tenant_id = :t AND kind = 'SYSTEM'"
            ),
            {"t": tenant},
        ).scalar_one()


def test_sj7_a_scheduled_actor_never_asks_for_a_tombstone(
    db, world, admin_engine, live_provider, connector
):
    tenant = world["identity"].tenant_id
    admission = admit(db, world["identity"], targets(admin_engine, world, 1)[0], world["clock"])
    assert admission.view.state == "DISPATCH_COMMITTED"
    actor = enlist(db, ScheduledActor(tenant), world["clock"])
    with pytest.raises(ExecutionError) as refused:
        reconcile_operation(
            db,
            actor,
            admission.view.execution_id,
            connector,
            reason="Scheduled recovery test",
            cancel_if_missing=True,
            clock=world["clock"],
        )
    assert refused.value.code == "INVALID_IDENTITY"
    paths = provider_paths(live_provider)
    assert "/v1/cancel" not in paths and "/v1/journal" not in paths
    assert state_of(admin_engine, admission.view.execution_id) == "DISPATCH_COMMITTED"
    # The refusal is retained, and names the scheduler: `_rejection` swallows its own
    # failures, so only this shows that it still admits the scheduled actor. A scheduled
    # actor has no credential, so the payload names none.
    rejected = [
        payload
        for kind, payload in actor_events(admin_engine, tenant, "execution.rejected")
        if kind == "SYSTEM"
    ]
    assert rejected == [{"operation": "provider.reconcile", "reason": "INVALID_IDENTITY"}]
    assert "actor_credential_id" not in rejected[0]
    assert actor_events(admin_engine, tenant, "execution.reconciliation_requested") == []


def test_sj4_a_scheduled_actor_settles_a_lost_response_from_the_journal(
    db, world, admin_engine, live_provider, connector
):
    tenant = world["identity"].tenant_id
    winner = lost_response(db, world, live_provider)
    # Without a principal the actor may not write anything, so it cannot reconcile yet.
    with pytest.raises(ExecutionError) as unenlisted:
        reconcile_operation(
            db,
            ScheduledActor(tenant),
            winner.view.execution_id,
            connector,
            reason="Scheduled recovery test",
            clock=world["clock"],
        )
    assert unenlisted.value.code == "INVALID_IDENTITY"
    # An actor with nothing to attribute is not retained.
    assert actor_events(admin_engine, tenant, "execution.rejected") == []
    actor = enlist(db, ScheduledActor(tenant), world["clock"])
    view = reconcile_operation(
        db,
        actor,
        winner.view.execution_id,
        connector,
        reason="Scheduled recovery test",
        clock=world["clock"],
    )
    assert view.state == "EXECUTED"
    assert invocations(live_provider) == 1
    assert actor_kinds(admin_engine, tenant, "execution.reconciliation_requested") == ["SYSTEM"]
    # The settlement is the scheduler's too.
    assert actor_kinds(admin_engine, tenant, "execution.transition")[-1] == "SYSTEM"
    assert scheduler_count(admin_engine, tenant) == 1


def test_reconcile_refuses_a_scheduled_actor_with_nothing_to_attribute(db, world, admin_engine):
    """`reconcile`'s own guard, which `reconcile_operation`'s runs ahead of: the scheduled
    check admits an actor with no principal on the workspace alone, so only the guard keeps
    one from settling with evidence that would otherwise settle the operation."""
    tenant = world["identity"].tenant_id
    admission = admit(db, world["identity"], targets(admin_engine, world, 1)[0], world["clock"])
    with pytest.raises(ExecutionError) as refused:
        reconcile(
            db,
            ScheduledActor(tenant),
            admission.view.execution_id,
            reason="Scheduled recovery test",
            evidence=b"test-journal-proof",
            verifier=FixtureJournal("FAILED_NOT_EXECUTED"),
            clock=world["clock"],
        )
    assert refused.value.code == "INVALID_IDENTITY"
    assert state_of(admin_engine, admission.view.execution_id) == "DISPATCH_COMMITTED"
    assert actor_events(admin_engine, tenant, "execution.rejected") == []


class Ahead:
    """The system clock moved forward: what a scheduled run sees once a deadline has passed."""

    def __init__(self, by: timedelta) -> None:
        self.by = by

    def now(self) -> datetime:
        return datetime.now(UTC) + self.by


class SideEffect:
    """A connector that does one thing to the world on its first journal lookup, then answers."""

    def __init__(self, inner, effect) -> None:
        self.inner, self.effect, self.done = inner, effect, False

    def lookup(self, command):
        if not self.done:
            self.done = True
            self.effect()
        return self.inner.lookup(command)

    def __getattr__(self, name):
        return getattr(self.inner, name)


class ClosingSource:
    """A connection source, as `Runtime` is, that does one thing to the world as the first
    operation's connection closes: after that operation has settled and made its last check,
    and before the next operation's recheck."""

    def __init__(self, connector, effect) -> None:
        self.connector, self.effect, self.done = connector, effect, False

    @contextmanager
    def connection(self, tenant_id, account_id):
        try:
            yield self.connector
        finally:
            if not self.done:
                self.done = True
                self.effect()

    def evidence_verifier(self, tenant_id, account_id):
        return None


def test_sj7_the_scheduled_run_refuses_cancellation_before_reading_anything(db, world, monkeypatch):
    # Before the guard, the first selection's own check refused a scheduled actor with the
    # same code, so the code alone cannot say where the refusal came from.
    def read(*args, **kwargs):
        raise AssertionError("The scheduled run read before refusing cancellation")

    for selection in ("select_unsettled", "select_held_claims", "select_lapsed_approvals"):
        monkeypatch.setattr(recovery_run, selection, read)
    with pytest.raises(ExecutionError) as refused:
        recover(
            db,
            ScheduledActor(world["identity"].tenant_id),
            {},
            cancel_unattempted=True,
            clock=world["clock"],
        )
    assert refused.value.code == "INVALID_IDENTITY"


def test_sj4_a_mapped_workspace_settles_under_the_scheduler(
    db, world, admin_engine, live_provider, connector
):
    tenant = world["identity"].tenant_id
    winner = lost_response(db, world, live_provider)
    world["clock"].value += GRACE + timedelta(seconds=1)
    counts = recover(db, ScheduledActor(tenant), ring(world, connector), clock=world["clock"])
    assert (counts.examined, counts.executed, counts.unresolved) == (1, 1, 0)
    assert state_of(admin_engine, winner.view.execution_id) == "EXECUTED"
    assert invocations(live_provider) == 1
    assert actor_kinds(admin_engine, tenant, "execution.reconciliation_requested") == ["SYSTEM"]
    assert actor_kinds(admin_engine, tenant, "principal.created")[-1:] == ["SYSTEM"]


def test_a_workspace_with_nothing_due_gains_no_scheduler_principal(db, world, admin_engine):
    tenant = world["identity"].tenant_id
    counts = recover(db, ScheduledActor(tenant), {}, clock=world["clock"])
    assert counts.examined == counts.released == counts.expired == 0
    assert scheduler_count(admin_engine, tenant) == 0


def test_sj2_grants_sweep_and_claims_release_under_the_scheduler(db, gate_world, admin_engine):
    world = gate_world
    tenant = world["identity"].tenant_id
    swept = checkpoint(db, world)
    window = grant_row(admin_engine, tenant, swept.view.execution_id)["report_expires_at"]
    world["clock"].value = window
    counts = recover(db, ScheduledActor(tenant), gate_ring(world), clock=world["clock"])
    assert (counts.examined, counts.swept) == (1, 1)
    assert state_of(admin_engine, swept.view.execution_id) == "INDETERMINATE"
    assert actor_kinds(admin_engine, tenant, "execution.transition")[-1] == "SYSTEM"


def test_sj2_a_settled_assertion_s_claim_is_released_under_the_scheduler(
    db, gate_world, admin_engine
):
    world = gate_world
    tenant = world["identity"].tenant_id
    granted = checkpoint(db, world)
    grant = granted.view.checkpoint
    assert grant is not None
    assert report(db, world, granted.view.execution_id, grant.report_secret).state == "EXECUTED"
    world["clock"].value += GRACE + ACT_WINDOW + timedelta(seconds=2)
    counts = recover(db, ScheduledActor(tenant), gate_ring(world), clock=world["clock"])
    assert (counts.examined, counts.released) == (0, 1)
    row = retained(admin_engine, tenant, granted.view.execution_id)
    assert (row.state, row.tier, row.impact) == ("EXECUTED", "ASSERTED", "CONFIRMED")
    assert row.released_at is not None
    assert actor_kinds(admin_engine, tenant, "execution.claim_released") == ["SYSTEM"]


def second_operation(db, world, admin_engine):
    """A never-attempted operation admitted a second after the lost response, so the run's
    selection (oldest first) reaches it second. `lost_response` cannot be called twice: its
    request's idempotency key would return the first execution."""
    world["clock"].value += timedelta(seconds=1)
    admission = admit(db, world["identity"], targets(admin_engine, world, 1)[0], world["clock"])
    assert admission.view.state == "DISPATCH_COMMITTED"
    return admission.view.execution_id


def revoke(engine, identity):
    with engine.begin() as conn:
        conn.execute(
            text("UPDATE execbound.credentials SET revoked_at = now() WHERE credential_id = :c"),
            {"c": identity.credential_id},
        )


def deactivate(engine, tenant):
    with engine.begin() as conn:
        fenced(conn, tenant)
        conn.execute(
            text("UPDATE execbound.tenants SET active = false WHERE tenant_id = :t"),
            {"t": tenant},
        )


def test_defect_2_an_admin_revoked_between_two_operations_stops_the_run(
    db, world, admin_engine, live_provider, connector
):
    first = lost_response(db, world, live_provider)
    second = second_operation(db, world, admin_engine)
    world["clock"].value += GRACE + timedelta(seconds=1)
    effect = SideEffect(connector, lambda: revoke(admin_engine, world["admin"]))
    ring_ = {(world["identity"].tenant_id, world["account"]): effect}
    with pytest.raises(RecoveryStopped) as stopped:
        recover(db, world["admin"], ring_, clock=world["clock"])
    assert stopped.value.code == "INVALID_IDENTITY"
    # The operation in flight when the credential was revoked is the one it costs; the run
    # stopped at the next operation's recheck.
    assert (stopped.value.counts.examined, stopped.value.counts.unresolved) == (1, 1)
    assert provider_paths(live_provider).count("/v1/journal") == 1
    assert state_of(admin_engine, first.view.execution_id) == "INDETERMINATE"
    assert state_of(admin_engine, second) == "DISPATCH_COMMITTED"


def test_defect_2_an_admin_revoked_between_two_expiries_stops_the_run(
    db, world, admin_engine, monkeypatch
):
    """The approval loop's own recheck. An administrator's refusal inside `expire_approval`
    is a `PolicyStoreError`, which `_attempted` takes as a row it could not move, so without
    the recheck the run would go on to the next approval and finish as if nothing happened."""
    long_facts(db, world)
    deadline(db, world, DEADLINE)
    one, two = targets(admin_engine, world, 2, production=True)
    first = admit(db, world["identity"], one, world["clock"])
    world["clock"].value += timedelta(seconds=1)
    second = admit(db, world["identity"], two, world["clock"])
    assert first.view.state == second.view.state == "PENDING_APPROVAL"
    assert first.view.execution_id != second.view.execution_id
    world["clock"].value += timedelta(seconds=DEADLINE) + GRACE + timedelta(seconds=1)
    original = recovery_run.expire_approval

    def expire_then_revoke(db_, admin, execution_id, clock):
        answer = original(db_, admin, execution_id, clock)
        revoke(admin_engine, world["admin"])
        return answer

    monkeypatch.setattr(recovery_run, "expire_approval", expire_then_revoke)
    with pytest.raises(RecoveryStopped) as stopped:
        recover(db, world["admin"], {}, clock=world["clock"])
    assert stopped.value.code == "INVALID_IDENTITY"
    assert stopped.value.counts.expired == 1
    assert state_of(admin_engine, first.view.execution_id) == "STALE_AUTHORIZATION"
    assert state_of(admin_engine, second.view.execution_id) == "PENDING_APPROVAL"


def test_defect_2_an_admin_revoked_between_two_claim_releases_stops_the_run(
    db, gate_world, admin_engine, monkeypatch
):
    """The claim loop's own recheck, on RC19's setup with two settled assertions. As with
    an expiry, an administrator's refusal inside `release_claim` is a `PolicyStoreError`,
    which `_attempted` takes as a claim it could not release, so without the recheck the
    run would go on and finish as if nothing happened."""
    world = gate_world
    tenant = world["identity"].tenant_id
    # The act window outlives the world's own administrator, as the report window does in
    # RC14.
    world["admin"] = long_lived_admin(admin_engine, db, world)
    grants = []
    for action in targets(admin_engine, world, count=2):
        # A second apart, so the selection (oldest first) reaches them in this order rather
        # than by execution id.
        world["clock"].value += timedelta(seconds=1)
        granted = checkpoint(db, world, action=action)
        grant = granted.view.checkpoint
        assert grant is not None
        assert report(db, world, granted.view.execution_id, grant.report_secret).state == (
            "EXECUTED"
        )
        grants.append(granted.view.execution_id)
    first, second = grants
    world["clock"].value += ACT_WINDOW + GRACE + timedelta(seconds=1)
    original = recovery_run.release_claim

    def release_then_revoke(db_, admin, execution_id, clock):
        answer = original(db_, admin, execution_id, clock)
        revoke(admin_engine, world["admin"])
        return answer

    monkeypatch.setattr(recovery_run, "release_claim", release_then_revoke)
    with pytest.raises(RecoveryStopped) as stopped:
        recover(db, world["admin"], gate_ring(world), clock=world["clock"])
    assert stopped.value.code == "INVALID_IDENTITY"
    assert stopped.value.counts.released == 1
    assert retained(admin_engine, tenant, first).released_at == world["clock"].now()
    assert retained(admin_engine, tenant, second).released_at is None


def test_sj6_a_workspace_deactivated_inside_an_operation_stops_the_run_there(
    db, world, admin_engine, live_provider, connector
):
    """Deactivated after the first operation's lookup and before its settlement: the
    scheduled check inside that settlement refuses, and the run stops at once."""
    tenant = world["identity"].tenant_id
    first = lost_response(db, world, live_provider)
    second = second_operation(db, world, admin_engine)
    world["clock"].value += GRACE + timedelta(seconds=1)
    ring_ = {
        (tenant, world["account"]): SideEffect(connector, lambda: deactivate(admin_engine, tenant))
    }
    with pytest.raises(RecoveryStopped) as stopped:
        recover(db, ScheduledActor(tenant), ring_, clock=world["clock"])
    assert stopped.value.code == "INVALID_IDENTITY"
    # The operation the refusal interrupted is the one it costs, counted unresolved as an
    # administrator's would be; nothing is settled and there is no second lookup.
    assert (stopped.value.counts.examined, stopped.value.counts.unresolved) == (1, 1)
    assert provider_paths(live_provider).count("/v1/journal") == 1
    assert state_of(admin_engine, first.view.execution_id) == "INDETERMINATE"
    assert state_of(admin_engine, second) == "DISPATCH_COMMITTED"


def test_sj6_a_workspace_deactivated_between_two_operations_stops_at_the_next(
    db, world, admin_engine, live_provider, connector
):
    """Deactivated as the first operation's connection closes, after its settlement and its
    last check: only the recheck before the next operation can see it."""
    tenant = world["identity"].tenant_id
    first = lost_response(db, world, live_provider)
    second = second_operation(db, world, admin_engine)
    world["clock"].value += GRACE + timedelta(seconds=1)
    source = ClosingSource(connector, lambda: deactivate(admin_engine, tenant))
    with pytest.raises(RecoveryStopped) as stopped:
        recover(db, ScheduledActor(tenant), source, clock=world["clock"])
    assert stopped.value.code == "INVALID_IDENTITY"
    # The first operation's settlement stands; the second is never reached.
    assert (stopped.value.counts.examined, stopped.value.counts.executed) == (1, 1)
    assert state_of(admin_engine, first.view.execution_id) == "EXECUTED"
    assert state_of(admin_engine, second) == "DISPATCH_COMMITTED"
    assert provider_paths(live_provider).count("/v1/journal") == 1


def test_sj13_two_scheduled_runs_at_once_settle_once_and_make_one_scheduler(
    db, world, admin_engine, live_provider, connector, monkeypatch
):
    tenant = world["identity"].tenant_id
    winner = lost_response(db, world, live_provider)
    world["clock"].value += GRACE + timedelta(seconds=1)
    selected = Barrier(2)
    original_select = recovery_run.select_unsettled

    def select_together(*args, **kwargs):
        rows = original_select(*args, **kwargs)
        # Force the overlap after both real reads, as RC7 does: two threads alone may let
        # the first settle before the second selects anything, and then only one enlists.
        selected.wait(timeout=10)
        return rows

    monkeypatch.setattr(recovery_run, "select_unsettled", select_together)
    with ThreadPoolExecutor(2) as pool_:
        results = list(
            pool_.map(
                lambda _: recover(
                    db, ScheduledActor(tenant), ring(world, connector), clock=world["clock"]
                ),
                range(2),
            )
        )
    # Both runs found the operation, so both enlisted. Both may report it executed: the
    # second reads the settlement the first committed, as RC7 allows. What must hold is one
    # settlement, one mutation and one scheduler.
    assert [result.examined for result in results] == [1, 1]
    assert sum(result.executed for result in results) >= 1
    assert state_of(admin_engine, winner.view.execution_id) == "EXECUTED"
    with admin_engine.begin() as conn:
        fenced(conn, tenant)
        settled = conn.execute(
            text(
                "SELECT count(*) FROM execbound.audit_events WHERE tenant_id = :t "
                "AND kind = 'execution.transition' AND payload ->> 'to_state' = 'EXECUTED'"
            ),
            {"t": tenant},
        ).scalar_one()
    assert settled == 1
    assert invocations(live_provider) == 1
    assert scheduler_count(admin_engine, tenant) == 1
    assert actor_kinds(admin_engine, tenant, "principal.created").count("SYSTEM") == 1


def old_turn(engine, tenant, principal):
    """An assistant turn completed 31 days ago by the database's own clock."""
    with engine.begin() as conn:
        fenced(conn, tenant)
        conn.execute(
            text(
                "INSERT INTO execbound.assistant_turns"
                "(tenant_id, turn_id, principal_id, context_kind, question, state, model, "
                "created_at, completed_at) VALUES (:t, :u, :p, 'question', 'Why?', "
                "'COMPLETED', 'test-model', now() - interval '31 days', "
                "now() - interval '31 days')"
            ),
            {"t": tenant, "u": uuid4(), "p": principal},
        )


def test_a_failed_sweep_keeps_what_the_pass_had_already_done(db, world, admin_engine, monkeypatch):
    """Settling fails after `recover` has expired an approval: the refusal carries the expiry,
    and the retirement that still ran, so the report says what the workspace's pass did."""
    tenant = world["identity"].tenant_id
    long_facts(db, world)
    deadline(db, world, DEADLINE)
    [target] = targets(admin_engine, world, 1, production=True)
    held = admit(db, world["identity"], target, world["clock"])
    assert held.view.state == "PENDING_APPROVAL"
    world["clock"].value += timedelta(seconds=DEADLINE) + GRACE + timedelta(seconds=1)
    old_turn(admin_engine, tenant, world["admin"].principal_id)

    def refuse(*args, **kwargs):
        raise ExecutionError("INVALID_NOTIFICATION")

    monkeypatch.setattr(notifications, "settle_orphaned", refuse)
    with pytest.raises(SweepFailed) as failed:
        recover_scheduled(db, tenant, {}, clock=world["clock"])
    assert failed.value.code == "INVALID_NOTIFICATION"
    report = vars(failed.value.counts)
    assert (report["expired"], report["assistant_turns_retired"]) == (1, 1)
    assert "notifications_settled" not in report
    assert state_of(admin_engine, held.view.execution_id) == "STALE_AUTHORIZATION"


def test_an_unsafe_database_role_is_never_one_sweep_s_failure(db, world, monkeypatch):
    def unsafe(*args, **kwargs):
        raise UnsafeDatabaseRole("test")

    monkeypatch.setattr(turns, "retire_due_turns", unsafe)
    with pytest.raises(UnsafeDatabaseRole):
        recover_scheduled(db, world["identity"].tenant_id, {}, clock=world["clock"])
