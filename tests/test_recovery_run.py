# SPDX-License-Identifier: AGPL-3.0-only
"""Scheduled recovery of committed but unsettled operations: RC1 to RC12 on the live provider."""

import json
import os
import sys
from concurrent.futures import ThreadPoolExecutor
from datetime import timedelta
from pathlib import Path
from threading import Barrier
from uuid import UUID

import pytest
from checkpoint_fixtures import (
    again,
    checkpoint,
    force_state,
    grant_row,
    long_lived_admin,
    report,
    retained,
)
from checkpoint_fixtures import gate_world as gate_world
from checkpoint_fixtures import owner as owner
from sqlalchemy import text
from test_execution import registry as registry
from test_execution import targets
from test_execution import world as world
from test_human_surface import credential
from test_protected_path import approved, resource
from test_protected_path import connector as connector
from test_protected_path import live_provider as live_provider
from test_resolution import request

from execbound import recovery_run
from execbound.cli import main
from execbound.execution import activate_stop, admit, take_dispatch
from execbound.execution.models import ACT_WINDOW, ExecutionError
from execbound.provider.connector import ConnectionConfig, MockConnector
from execbound.provider.gateway import dispatch_owned
from execbound.recovery_run import recover, release_claim, select_held_claims

GRACE = timedelta(seconds=300)


def ring(world, connector):
    return {(world["identity"].tenant_id, world["account"]): connector}


def provider_paths(live_provider):
    path = Path(live_provider.environment["TEST_PROVIDER_REQUESTS"])
    return path.read_text().splitlines() if path.exists() else []


def invocations(live_provider):
    path = Path(live_provider.environment["TEST_PROVIDER_INVOCATIONS"])
    return len(path.read_text().splitlines()) if path.exists() else 0


def state_of(engine, execution_id):
    with engine.connect() as conn:
        return conn.execute(
            text("SELECT state FROM execbound.executions WHERE execution_id=:e"),
            {"e": execution_id},
        ).scalar_one()


def audit_count(engine, tenant, kind):
    with engine.begin() as conn:
        conn.execute(text("SELECT set_config('execbound.tenant_id', :t, true)"), {"t": str(tenant)})
        return conn.execute(
            text("SELECT count(*) FROM execbound.audit_events WHERE tenant_id=:t AND kind=:k"),
            {"t": tenant, "k": kind},
        ).scalar_one()


def lost_response(db, world, live_provider, mode="crash_after_commit"):
    """Effect committed at the provider, response lost: the operation is INDETERMINATE."""
    live_provider.restart(mode)
    config = live_provider.config
    short = MockConnector(
        ConnectionConfig(
            config.tenant_id,
            config.account_id,
            config.origin,
            config.dispatch_token,
            config.control_token,
            config.evidence_keys,
            timeout_seconds=0.15,
        )
    )
    try:
        winner = approved(db, world)
        assert dispatch_owned(db, winner.ticket, short, world["clock"]).state == "INDETERMINATE"
    finally:
        short.close()
    live_provider.restart()
    return winner


def test_rc1_effect_with_lost_response_settles_from_the_retained_journal(
    db, world, admin_engine, live_provider, connector
):
    tenant = world["identity"].tenant_id
    winner = lost_response(db, world, live_provider)
    assert resource(live_provider, world).mutation_count == 1
    world["clock"].value += GRACE + timedelta(seconds=1)
    counts = recover(db, world["admin"], ring(world, connector), clock=world["clock"])
    assert (counts.examined, counts.executed, counts.unresolved) == (1, 1, 0)
    assert state_of(admin_engine, winner.view.execution_id) == "EXECUTED"
    assert resource(live_provider, world).mutation_count == 1 and invocations(live_provider) == 1
    assert audit_count(admin_engine, tenant, "execution.reconciliation_requested") == 1
    assert recover(db, world["admin"], ring(world, connector), clock=world["clock"]).examined == 0


def test_rc2_rc3_never_attempted_operations_cancel_only_when_enabled(
    db, world, admin_engine, live_provider, connector
):
    tenant = world["identity"].tenant_id
    admission = admit(db, world["identity"], targets(admin_engine, world, 1)[0], world["clock"])
    assert admission.ticket is not None and admission.view.state == "DISPATCH_COMMITTED"
    world["clock"].value += GRACE + timedelta(seconds=1)
    counts = recover(db, world["admin"], ring(world, connector), clock=world["clock"])
    assert (counts.examined, counts.unresolved, counts.cancelled) == (1, 1, 0)
    assert state_of(admin_engine, admission.view.execution_id) == "DISPATCH_COMMITTED"
    assert "/v1/journal" not in provider_paths(live_provider)
    assert audit_count(admin_engine, tenant, "execution.reconciliation_requested") == 0
    counts = recover(
        db, world["admin"], ring(world, connector), cancel_unattempted=True, clock=world["clock"]
    )
    assert (counts.examined, counts.cancelled) == (1, 1)
    assert state_of(admin_engine, admission.view.execution_id) == "FAILED_NOT_EXECUTED"
    assert invocations(live_provider) == 0 and "/v1/cancel" in provider_paths(live_provider)
    with pytest.raises(ExecutionError):
        take_dispatch(db, admission.ticket, world["clock"])


def test_rc4_attempted_operation_without_a_journal_is_never_cancelled(
    db, world, admin_engine, live_provider, connector
):
    winner = approved(db, world)
    take_dispatch(db, winner.ticket, world["clock"])
    world["clock"].value += GRACE + timedelta(seconds=1)
    counts = recover(
        db, world["admin"], ring(world, connector), cancel_unattempted=True, clock=world["clock"]
    )
    assert (counts.examined, counts.unresolved, counts.cancelled) == (1, 1, 0)
    assert state_of(admin_engine, winner.view.execution_id) == "INDETERMINATE"
    assert "/v1/journal" in provider_paths(live_provider)
    assert "/v1/cancel" not in provider_paths(live_provider)
    assert invocations(live_provider) == 0
    assert resource(live_provider, world).mutation_count == 0


def test_rc5_the_grace_period_skips_fresh_operations(
    db, world, admin_engine, live_provider, connector
):
    winner = lost_response(db, world, live_provider)
    counts = recover(db, world["admin"], ring(world, connector), clock=world["clock"])
    assert counts.examined == 0
    assert state_of(admin_engine, winner.view.execution_id) == "INDETERMINATE"
    world["clock"].value += GRACE + timedelta(seconds=1)
    assert recover(db, world["admin"], ring(world, connector), clock=world["clock"]).executed == 1


def test_rc6_refused_evidence_leaves_the_operation_unsettled(
    db, world, admin_engine, live_provider, connector, monkeypatch
):
    tenant = world["identity"].tenant_id
    winner = lost_response(db, world, live_provider)
    genuine = connector.lookup
    monkeypatch.setattr(connector, "lookup", lambda command: genuine(command)[:-4] + b"beef")
    world["clock"].value += GRACE + timedelta(seconds=1)
    counts = recover(db, world["admin"], ring(world, connector), clock=world["clock"])
    assert (counts.examined, counts.unresolved, counts.executed) == (1, 1, 0)
    assert state_of(admin_engine, winner.view.execution_id) == "INDETERMINATE"
    assert audit_count(admin_engine, tenant, "execution.rejected") >= 1
    with admin_engine.connect() as conn:
        assert (
            conn.execute(
                text("SELECT state FROM execbound.execution_impact WHERE execution_id=:e"),
                {"e": winner.view.execution_id},
            ).scalar_one()
            == "UNRESOLVED"
        )


def test_rc7_concurrent_runs_settle_once(
    db, world, admin_engine, live_provider, connector, monkeypatch
):
    tenant = world["identity"].tenant_id
    winner = lost_response(db, world, live_provider)
    world["clock"].value += GRACE + timedelta(seconds=1)
    selected = Barrier(2)
    original_select = recovery_run.select_unsettled

    def select_together(*args, **kwargs):
        rows = original_select(*args, **kwargs)
        # Force overlap after both real reads; scheduling two threads alone may allow
        # the first to settle before the second has selected anything to recover.
        selected.wait(timeout=10)
        return rows

    monkeypatch.setattr(recovery_run, "select_unsettled", select_together)
    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(
            pool.map(
                lambda _: recover(db, world["admin"], ring(world, connector), clock=world["clock"]),
                range(2),
            )
        )
    # Both runs observe the settled state; the fence guarantees one settlement and one event.
    assert all(r.examined == 1 for r in results) and sum(r.executed for r in results) >= 1
    assert state_of(admin_engine, winner.view.execution_id) == "EXECUTED"
    # Each run may audit its own request (the lookup runs outside the fence, as it does for
    # two administrators), but the fence allows exactly one settlement.
    assert 1 <= audit_count(admin_engine, tenant, "execution.reconciliation_requested") <= 2
    with admin_engine.begin() as conn:
        conn.execute(text("SELECT set_config('execbound.tenant_id', :t, true)"), {"t": str(tenant)})
        settled = conn.execute(
            text(
                "SELECT count(*) FROM execbound.audit_events WHERE tenant_id=:t "
                "AND kind='execution.transition' AND payload->>'to_state'='EXECUTED' "
                "AND payload->>'execution_id'=:e"
            ),
            {"t": tenant, "e": str(winner.view.execution_id)},
        ).scalar_one()
    assert settled == 1
    assert resource(live_provider, world).mutation_count == 1


def test_rc8_only_a_current_admin_may_run_recovery(
    db, world, admin_engine, live_provider, connector
):
    lost_response(db, world, live_provider)
    world["clock"].value += GRACE + timedelta(seconds=1)
    for actor in (world["identity"], world["human"]):
        with pytest.raises(ExecutionError) as refused:
            recover(db, actor, ring(world, connector), clock=world["clock"])
        assert refused.value.code == "INVALID_IDENTITY"
    with admin_engine.begin() as conn:
        conn.execute(
            text("UPDATE execbound.credentials SET revoked_at=now() WHERE credential_id=:c"),
            {"c": world["admin"].credential_id},
        )
    with pytest.raises(ExecutionError):
        recover(db, world["admin"], ring(world, connector), clock=world["clock"])
    assert "/v1/journal" not in provider_paths(live_provider)


def test_rc9_recovery_is_scoped_to_the_tenant(
    db, world, admin_engine, seeded, live_provider, connector
):
    from test_execution import provision_identity

    winner = lost_response(db, world, live_provider)
    world["clock"].value += GRACE + timedelta(seconds=1)
    other = provision_identity(
        admin_engine, db, seeded["tenants"][1], "ADMIN", world["clock"].now()
    )
    assert recover(db, other, ring(world, connector), clock=world["clock"]).examined == 0
    assert state_of(admin_engine, winner.view.execution_id) == "INDETERMINATE"


def test_rc10_an_emergency_stop_does_not_block_recovery(
    db, world, admin_engine, live_provider, connector
):
    winner = lost_response(db, world, live_provider)
    activate_stop(db, world["admin"], "Incident", world["clock"])
    world["clock"].value += GRACE + timedelta(seconds=1)
    assert recover(db, world["admin"], ring(world, connector), clock=world["clock"]).executed == 1
    assert state_of(admin_engine, winner.view.execution_id) == "EXECUTED"


def test_rc11_rc12_limit_order_and_missing_connectors(
    db, world, admin_engine, live_provider, connector
):
    requests = targets(admin_engine, world, 3)
    admissions = [admit(db, world["identity"], r, world["clock"]) for r in requests]
    assert all(a.view.state == "DISPATCH_COMMITTED" for a in admissions)
    world["clock"].value += GRACE + timedelta(seconds=1)
    counts = recover(db, world["admin"], ring(world, connector), limit=2, clock=world["clock"])
    assert (counts.examined, counts.unresolved) == (2, 2)
    counts = recover(db, world["admin"], {}, clock=world["clock"])
    assert (counts.examined, counts.skipped_no_connector) == (3, 3)
    for admission in admissions:
        assert state_of(admin_engine, admission.view.execution_id) == "DISPATCH_COMMITTED"


def test_rc13_cli_runs_recovery_under_the_private_configuration(
    db, world, admin_engine, live_provider, tmp_path, monkeypatch, capsys
):
    tenant, account = world["identity"].tenant_id, world["account"]
    winner = lost_response(db, world, live_provider)
    with admin_engine.begin() as conn:
        conn.execute(
            text(
                "UPDATE execbound.executions SET changed_at = changed_at - interval '10 minutes' "
                "WHERE execution_id=:e"
            ),
            {"e": winner.view.execution_id},
        )
    config = live_provider.config
    private = tmp_path / "private.json"
    private.write_text(
        json.dumps(
            {
                "origin": "http://127.0.0.1:8000",
                "active_key_id": "k1",
                "continuation_keys": {"k1": "11" * 32},
                "connectors": [
                    {
                        "tenant_id": str(tenant),
                        "account_id": str(account),
                        "origin": config.origin,
                        "dispatch_token": config.dispatch_token,
                        "control_token": config.control_token,
                        "evidence_keys": {k: v.hex() for k, v in config.evidence_keys.items()},
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    monkeypatch.setenv("EXECBOUND_RUNTIME_CONFIG", str(private))
    monkeypatch.setenv("DATABASE_URL", os.environ["TEST_DATABASE_URL"])
    admin_file, human_file = tmp_path / "admin.token", tmp_path / "human.token"
    admin_file.write_text(credential(admin_engine, world["admin"]), encoding="utf-8")
    human_file.write_text(credential(admin_engine, world["human"]), encoding="utf-8")
    command = ["execbound", "recover", "--tenant", str(tenant), "--credential-file"]
    monkeypatch.setattr(sys, "argv", [*command, str(human_file)])
    with pytest.raises(SystemExit) as caught:
        main()
    assert caught.value.code == 2 and "INVALID_IDENTITY" in capsys.readouterr().err
    monkeypatch.setattr(sys, "argv", [*command, str(admin_file)])
    main()
    printed = json.loads(capsys.readouterr().out)
    assert UUID(printed["run_id"]) and printed["examined"] == 1 and printed["executed"] == 1
    assert state_of(admin_engine, winner.view.execution_id) == "EXECUTED"


# The scheduled run's checkpoint branch. A grant has no connector by construction,
# so before this branch existed every checkpoint was skipped as an execution the run had
# nothing to ask, and an unreported one stayed committed for as long as the tenant did.


class NeverAsked:
    """A connector the run must not reach for a checkpoint; touching it fails the test."""

    def __getattr__(self, name):
        raise AssertionError(f"The recovery run asked a connector to {name} a checkpoint")


def live_claims(engine, tenant, execution_id):
    """Unreleased claims on the target of one execution: what admission refuses a request for."""
    with engine.begin() as conn:
        conn.execute(text("SELECT set_config('execbound.tenant_id', :t, true)"), {"t": str(tenant)})
        return conn.execute(
            text(
                "SELECT count(*) FROM execbound.resource_claims WHERE tenant_id=:t "
                "AND released_at IS NULL AND canonical_target_id = ("
                "SELECT canonical_target_id FROM execbound.executions "
                "WHERE tenant_id=:t AND execution_id=:e)"
            ),
            {"t": tenant, "e": execution_id},
        ).scalar_one()


def gate_ring(world):
    """A connector configured for the Gate account, as a later operator change would leave it.

    Admission refuses a Gate mapping whose account is already in the runtime's inventory,
    so this is the configuration that arrives after the grants do. It is what proves the
    checkpoint branch is taken before the connector is looked up at all: the run's own
    skip for a missing connector would answer the same way for the wrong reason.
    """
    return {(world["identity"].tenant_id, world["account"]): NeverAsked()}


def test_rc14_an_unreported_grant_sweeps_into_retained_uncertainty(db, gate_world, admin_engine):
    world = gate_world
    tenant = world["identity"].tenant_id
    world["admin"] = long_lived_admin(admin_engine, db, world)
    granted = checkpoint(db, world)
    window = grant_row(admin_engine, tenant, granted.view.execution_id)["report_expires_at"]
    # Still inside its report window: the executor may yet report, so the run examines the
    # grant and leaves it exactly as admission committed it.
    world["clock"].value = window - timedelta(seconds=1)
    counts = recover(db, world["admin"], gate_ring(world), clock=world["clock"])
    # Not due is not an anomaly: the run says the grant is open rather than unresolved,
    # so an operator alerting on `unresolved` is not alerted on every live grant the
    # moment it is older than the grace period.
    assert (counts.examined, counts.swept, counts.open_grants, counts.unresolved) == (1, 0, 1, 0)
    assert counts.skipped_no_connector == 0
    assert state_of(admin_engine, granted.view.execution_id) == "DISPATCH_COMMITTED"
    world["clock"].value = window
    counts = recover(db, world["admin"], gate_ring(world), clock=world["clock"])
    assert (counts.examined, counts.swept, counts.unresolved) == (1, 1, 0)
    assert (counts.open_grants, counts.uncertain_grants) == (0, 0)
    assert state_of(admin_engine, granted.view.execution_id) == "INDETERMINATE"
    # Retained uncertainty: the impact stays charged and the claim stays held, which is
    # what keeps the grant counted and its target unavailable until something settles it.
    row = retained(admin_engine, tenant, granted.view.execution_id)
    assert (row.impact, row.released_at, row.tier) == ("UNRESOLVED", None, None)
    assert audit_count(admin_engine, tenant, "execution.reconciliation_requested") == 0
    # A swept grant is uncertain and not settled, so once the sweep's own transition is
    # older than the grace period it is selected and examined again; there is nothing left
    # to sweep, and the run leaves it alone rather than sweeping it a second time. It is
    # counted as the retained uncertainty it is and never as an unresolved row: only an
    # administrator can move it, so an alert on `unresolved` would fire on every run from
    # here to the end of the tenant's history with nothing anyone could do to clear it.
    for _ in range(3):
        world["clock"].value += GRACE + timedelta(seconds=1)
        repeated = recover(db, world["admin"], gate_ring(world), clock=world["clock"])
        assert (repeated.examined, repeated.swept, repeated.unresolved) == (1, 0, 0)
        assert (repeated.uncertain_grants, repeated.open_grants) == (1, 0)
        assert state_of(admin_engine, granted.view.execution_id) == "INDETERMINATE"


def test_rc15_a_claim_an_assertion_settled_is_released_after_the_act_window(
    db, gate_world, admin_engine
):
    world = gate_world
    tenant = world["identity"].tenant_id
    granted = checkpoint(db, world)
    grant = granted.view.checkpoint
    assert grant is not None
    assert report(db, world, granted.view.execution_id, grant.report_secret).state == "EXECUTED"
    settled = retained(admin_engine, tenant, granted.view.execution_id)
    assert (settled.tier, settled.impact, settled.released_at) == ("ASSERTED", "CONFIRMED", None)
    # Inside the act window the executor may still be acting on its grant, so the claim it
    # took is exactly what stops the same target being re-requested on the executor's word.
    counts = recover(db, world["admin"], gate_ring(world), clock=world["clock"])
    assert (counts.examined, counts.released) == (0, 0)
    # A held claim denies the target to the next request rather than refusing it, which is
    # the guard an assertion must not be able to talk its way past.
    denied = checkpoint(db, world, action=again(request(world)))
    assert denied.view.state == "DENIED"
    # Both halves of the act-window rule, past the run's own grace period so that the
    # grace is not what answers: the selection does not offer the claim, and the fenced
    # read refuses it. Either alone would answer the run the same way.
    world["clock"].value += GRACE + timedelta(seconds=1)
    assert select_held_claims(db, world["admin"], grace=GRACE, limit=50, clock=world["clock"]) == []
    assert release_claim(db, world["admin"], granted.view.execution_id, world["clock"]) is False
    assert recover(db, world["admin"], gate_ring(world), clock=world["clock"]).released == 0
    assert retained(admin_engine, tenant, granted.view.execution_id).released_at is None
    world["clock"].value += ACT_WINDOW + timedelta(seconds=1)
    counts = recover(db, world["admin"], gate_ring(world), clock=world["clock"])
    assert (counts.examined, counts.released) == (0, 1)
    row = retained(admin_engine, tenant, granted.view.execution_id)
    assert row.released_at == world["clock"].now()
    # Only the claim moves: the assertion still settled the execution and still charged it.
    assert (row.state, row.tier, row.impact) == ("EXECUTED", "ASSERTED", "CONFIRMED")
    assert audit_count(admin_engine, tenant, "execution.claim_released") == 1
    # The target is available again, asserted as the predicate admission's own busy check
    # reads: no live claim on the canonical target. A fresh request for it is not the
    # assertion here, because the act window outlives the context the plan is frozen from,
    # so a request a quarter of an hour later is refused for staleness whatever the claim
    # says.
    assert live_claims(admin_engine, tenant, denied.view.execution_id) == 0
    # A second run finds nothing left to release and appends nothing.
    assert recover(db, world["admin"], gate_ring(world), clock=world["clock"]).released == 0
    assert audit_count(admin_engine, tenant, "execution.claim_released") == 1


def test_rc16_concurrent_runs_release_a_settled_grants_claim_once(db, gate_world, admin_engine):
    # Real connections and a real fence rather than sequential calls: two scheduled runs
    # overlap in a deployment that runs more than one, and a claim released twice would
    # append a second event saying a target was freed that was already free.
    world = gate_world
    tenant = world["identity"].tenant_id
    granted = checkpoint(db, world)
    grant = granted.view.checkpoint
    assert grant is not None
    assert report(db, world, granted.view.execution_id, grant.report_secret).state == "EXECUTED"
    world["clock"].value += ACT_WINDOW + timedelta(seconds=1)
    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(
            pool.map(
                lambda _: recover(db, world["admin"], gate_ring(world), clock=world["clock"]),
                range(2),
            )
        )
    assert sum(result.released for result in results) == 1
    assert audit_count(admin_engine, tenant, "execution.claim_released") == 1
    assert retained(admin_engine, tenant, granted.view.execution_id).released_at is not None


def test_rc17_a_terminal_grant_no_settlement_wrote_keeps_its_claim(db, gate_world, admin_engine):
    # The release is for the claim an assertion settled and for nothing else. A row in a
    # terminal state carrying no settlement tier is a shape no settlement produces — only
    # the test seam that forces a state does — and it is exactly the case a release keyed
    # on the state alone would free, on no evidence at all.
    world = gate_world
    tenant = world["identity"].tenant_id
    granted = checkpoint(db, world)
    force_state(db, world, granted.view.execution_id, "EXECUTED")
    world["clock"].value += ACT_WINDOW + timedelta(seconds=1)
    assert recover(db, world["admin"], gate_ring(world), clock=world["clock"]).released == 0
    # Both halves again: the tier is what the selection asks for and what the fenced read
    # asks for, and a run answers 0 whichever of the two refused.
    assert select_held_claims(db, world["admin"], grace=GRACE, limit=50, clock=world["clock"]) == []
    assert release_claim(db, world["admin"], granted.view.execution_id, world["clock"]) is False
    row = retained(admin_engine, tenant, granted.view.execution_id)
    assert (row.tier, row.released_at) == (None, None)
    assert audit_count(admin_engine, tenant, "execution.claim_released") == 0


def test_rc18_a_released_claim_keeps_the_tenants_history_replayable(db, gate_world, admin_engine):
    # A new audit kind that replay does not classify makes the whole tenant's history
    # unsupported, which is a larger failure than anything this run settles. The asserted
    # settlement beside it replays as the recorded transition it is, so the whole history is
    # complete and the assertion is what this holds.
    from execbound.replay.export import export_history
    from execbound.replay.simulate import simulate
    from execbound.replay.verify import verify_export

    world = gate_world
    granted = checkpoint(db, world)
    grant = granted.view.checkpoint
    assert grant is not None
    assert report(db, world, granted.view.execution_id, grant.report_secret).state == "EXECUTED"
    world["clock"].value += ACT_WINDOW + timedelta(seconds=1)
    assert recover(db, world["admin"], gate_ring(world), clock=world["clock"]).released == 1
    history = export_history(db, world["admin"], world["clock"])
    assert "execution.claim_released" in {event.kind for event in history.events}
    report_of = simulate(verify_export(history, history.head))
    assert "UNKNOWN_EVENT_SEMANTICS" not in report_of.issues
    assert report_of.complete, report_of.issues
    assert {row.settlement_tier for row in report_of.decisions} == {"ASSERTED"}


def test_rc19_releasing_one_claim_leaves_every_other_claim_of_the_tenant_held(
    db, gate_world, admin_engine
):
    """The release names one execution, and nothing else in the tenant moves with it.

    Both tests that cover the release ran in a world holding exactly one claim, so an
    UPDATE that freed every unreleased claim of the tenant passed all of them. That wrong
    implementation frees the targets of live grants and of dispatched operations still in
    flight, on the evidence of one unrelated asserted settlement, which is the single
    unresolved mutation guard gone. The second grant here is live, is about another
    target, and is untouched by anything the first one's settlement says.
    """
    world = gate_world
    tenant = world["identity"].tenant_id
    world["admin"] = long_lived_admin(admin_engine, db, world)
    first, second = targets(admin_engine, world, count=2)
    settled = checkpoint(db, world, action=first)
    grant = settled.view.checkpoint
    assert grant is not None
    outstanding = checkpoint(db, world, action=second)
    assert outstanding.view.checkpoint is not None
    assert report(db, world, settled.view.execution_id, grant.report_secret).state == "EXECUTED"
    world["clock"].value += ACT_WINDOW + GRACE + timedelta(seconds=1)
    counts = recover(db, world["admin"], gate_ring(world), clock=world["clock"])
    assert counts.released == 1
    released = retained(admin_engine, tenant, settled.view.execution_id)
    assert released.released_at == world["clock"].now()
    # The other grant is still live, still charges its scopes and still holds its target.
    held = retained(admin_engine, tenant, outstanding.view.execution_id)
    assert (held.state, held.impact, held.released_at) == (
        "DISPATCH_COMMITTED",
        "UNRESOLVED",
        None,
    )
    assert live_claims(admin_engine, tenant, outstanding.view.execution_id) == 1
    # It was examined and deliberately left alone, which is what the run reports it as.
    assert (counts.examined, counts.open_grants, counts.unresolved) == (1, 1, 0)


def test_rc20_a_grant_that_moved_between_the_selection_and_the_sweep_is_not_unresolved(
    db, gate_world, admin_engine, monkeypatch
):
    """`unresolved` means a grant that was due and would not move, so a grant that moved
    is not one.

    The selection takes no fence and the sweep takes one per row, so minutes can pass
    between them: the executor's own report can land while its window is still open and
    the window can close before the row is reached. Classified from the selection's
    snapshot, that settled execution was counted unresolved — the one count an operator
    alerts on, raised by a row that is finished. The sweep reads the row under the fence
    and is what says what the grant was, so what a run reports about a grant is what was
    true when it looked at it.
    """
    world = gate_world
    tenant = world["identity"].tenant_id
    world["admin"] = long_lived_admin(admin_engine, db, world)
    granted = checkpoint(db, world)
    grant = granted.view.checkpoint
    assert grant is not None
    execution_id = granted.view.execution_id
    window = grant_row(admin_engine, tenant, execution_id)["report_expires_at"]
    # Selected inside its window, past the run's grace period, as a live grant is.
    world["clock"].value = window - timedelta(seconds=1)
    selection = recovery_run.select_unsettled

    def report_between(*args, **kwargs):
        rows = selection(*args, **kwargs)
        assert report(db, world, execution_id, grant.report_secret).state == "EXECUTED"
        world["clock"].value = window + timedelta(seconds=1)
        return rows

    monkeypatch.setattr(recovery_run, "select_unsettled", report_between)
    counts = recover(db, world["admin"], gate_ring(world), clock=world["clock"])
    assert (counts.examined, counts.settled_grants) == (1, 1)
    assert (counts.unresolved, counts.swept, counts.open_grants, counts.uncertain_grants) == (
        0,
        0,
        0,
        0,
    )
    # Nothing was done to it: the sweep has no edge out of a settled state and did not
    # take one, and the report the executor made is what the execution still says.
    assert state_of(admin_engine, execution_id) == "EXECUTED"
    settled = retained(admin_engine, tenant, execution_id)
    assert (settled.tier, settled.impact) == ("ASSERTED", "CONFIRMED")
