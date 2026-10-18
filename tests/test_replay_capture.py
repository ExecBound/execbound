# SPDX-License-Identifier: AGPL-3.0-only
"""Future replay input is captured with the decision in the same fenced transaction."""

from datetime import datetime, timedelta

import pytest
from sqlalchemy import event, text
from sqlalchemy.exc import OperationalError
from test_execution import finish, request
from test_execution import registry as registry
from test_execution import world as world

from execbound.execution import admit, decide_approval
from execbound.execution.models import ExecutionError


def captured(engine):
    with engine.connect() as conn:
        return (
            conn.execute(
                text(
                    "SELECT payload FROM execbound.audit_events "
                    "WHERE kind='execution.evaluated' ORDER BY sequence"
                )
            )
            .scalars()
            .all()
        )


def test_admission_records_bound_historical_evaluation(db, world, admin_engine):
    original = request(world)
    pending = admit(db, world["identity"], original, world["clock"])
    records = captured(admin_engine)
    assert len(records) == 1
    record = records[0]
    assert record["version"] == 1 and record["stage"] == "ADMISSION"
    assert record["execution_id"] == str(pending.view.execution_id)
    assert record["canonical_target_id"] == str(world["canonical"])
    assert record["decision"]["plan_hash"] == pending.view.plan_hash
    assert record["decision"]["effect"] == "REQUIRE_APPROVAL"
    assert datetime.fromisoformat(record["semantic_time"]) == world["clock"].now()
    assert record["identity"]["credential_id"] == str(world["identity"].credential_id)
    assert datetime.fromisoformat(record["identity"]["expires_at"]) == world["identity"].expires_at
    # Membership is recorded on every capture, empty or not, so replay can tell a decision
    # counted without groups from one recorded before groups existed.
    assert record["identity"]["groups"] == []
    normalized = record["frozen"]["request"]
    assert normalized["operation_ref"] == original.operation_ref
    assert normalized["target"] == {"kind": "canonical", "value": str(world["target"])}
    assert normalized["idempotency_key"] != original.idempotency_key
    assert normalized["claimed_context"]["incident_id"] == str(world["incident"])
    assert normalized["claimed_context"]["severity"] is None
    assert record["approval"] is None and record["reviewer"] is None


def test_proposed_review_and_verified_approval_are_distinct(db, world, admin_engine):
    pending = admit(db, world["identity"], request(world), world["clock"])
    decide_approval(db, world["human"], pending.view.approval_id, "APPROVE", world["clock"])
    admitted = admit(db, world["identity"], request(world), world["clock"])
    assert admitted.ticket is not None
    records = captured(admin_engine)
    assert [record["stage"] for record in records] == [
        "ADMISSION",
        "APPROVAL_REVIEW",
        "ADMISSION",
        "ADMISSION",
    ]
    review, committed, final_check = records[1:]
    assert review["human_decision"] == "APPROVE"
    assert review["reviewer"]["principal_id"] == str(world["human"].principal_id)
    assert review["approval"]["status"] == "PROPOSED"
    assert committed["approval"]["status"] == "VERIFIED"
    assert committed["approval"]["approver"]["principal_id"] == str(world["human"].principal_id)
    assert committed["approval"]["action"] == "endpoint.isolate"
    assert committed["approval"]["plan_hash"] == pending.view.plan_hash
    assert final_check["approval"] == committed["approval"]
    assert final_check["decision"]["effect"] == "ELIGIBLE"
    # Only the agent's identity carries the memberships that were counted; a reviewer's or
    # an approver's identity never does.
    assert review["identity"]["groups"] == [] and committed["identity"]["groups"] == []
    assert "groups" not in review["reviewer"]
    assert "groups" not in committed["approval"]["approver"]
    assert all("groups" not in approver for approver in committed["approval"]["approvers"])


def test_capture_failure_rolls_back_admission_before_any_dispatch(db, world, admin_engine):
    def fail(conn, cursor, statement, parameters, context, executemany):
        if (
            "INSERT INTO execbound.audit_events" in statement
            and parameters.get("kind") == "execution.evaluated"
        ):
            raise OperationalError("Synthetic capture failure", None, None)

    event.listen(db.engine, "before_cursor_execute", fail)
    try:
        with pytest.raises(ExecutionError):
            admit(db, world["identity"], request(world), world["clock"])
    finally:
        event.remove(db.engine, "before_cursor_execute", fail)
    assert captured(admin_engine) == []
    with admin_engine.connect() as conn:
        for table in ("executions", "execution_impact", "resource_claims", "approvals"):
            assert conn.execute(text(f"SELECT count(*) FROM execbound.{table}")).scalar_one() == 0


def test_semantic_transition_time_matches_retained_confirmation(db, world, admin_engine):
    pending = admit(db, world["identity"], request(world), world["clock"])
    decide_approval(db, world["human"], pending.view.approval_id, "APPROVE", world["clock"])
    committed = admit(db, world["identity"], request(world), world["clock"])
    finished = finish(db, world, committed)
    assert finished.state == "EXECUTED"
    with admin_engine.connect() as conn:
        transition = conn.execute(
            text(
                "SELECT payload FROM execbound.audit_events WHERE kind='execution.transition' "
                "AND payload->>'to_state'='EXECUTED'"
            )
        ).scalar_one()
        retained = conn.execute(
            text("SELECT confirmed_at FROM execbound.execution_impact WHERE execution_id=:e"),
            {"e": finished.execution_id},
        ).scalar_one()
        assert transition["replay"]["version"] == 1
        assert datetime.fromisoformat(transition["replay"]["semantic_time"]) == retained
        assert (
            conn.execute(
                text("SELECT changed_at FROM execbound.executions WHERE execution_id=:e"),
                {"e": finished.execution_id},
            ).scalar_one()
            == retained
        )


def test_capture_preserves_distinct_live_clock_samples(db, world, admin_engine):
    class TickClock:
        value = world["clock"].now()

        def now(self):
            self.value += timedelta(microseconds=1)
            return self.value

    live_clock = TickClock()
    pending = admit(db, world["identity"], request(world), live_clock)
    assert pending.view.state == "PENDING_APPROVAL"
    record = captured(admin_engine)[0]
    usage = datetime.fromisoformat(record["usage_time"])
    started = datetime.fromisoformat(record["semantic_time"])
    finished = datetime.fromisoformat(record["finished_time"])
    assert usage < started < finished < live_clock.value
