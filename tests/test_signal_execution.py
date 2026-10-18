# SPDX-License-Identifier: AGPL-3.0-only
"""Decisions on the signal, end to end."""

from datetime import timedelta
from uuid import UUID

import pytest
from signal_fixtures import ADMIT, admit_params, signal_fields
from signal_fixtures import post_signal as admit_signal
from signal_fixtures import signal_world as signal_world
from sqlalchemy import event, text
from test_execution import request
from test_execution import world as world
from test_migration_without_bypass import fenced
from test_protected_path import connector as connector
from test_protected_path import live_provider as live_provider
from test_resolution import registry as registry
from test_runtime import api as api
from test_runtime import runtime as runtime

from execbound.execution import decide_approval
from execbound.execution.models import ExecutionError
from execbound.provisioning import revoke_signal_source


def post_signal(db, world, verdict, **changes):
    """Admit one record and insist it was accepted, so no refusal below is an intake one."""
    result = admit_signal(db, world, verdict, **changes)
    assert result.get("accepted") is True, result
    return result


def body(world, **changes):
    return request(world, **changes).model_dump(mode="json")


def mutations(live_provider, world):
    return live_provider.store.resource(
        world["identity"].tenant_id, world["canonical"]
    ).mutation_count


def approve(db, world, pending):
    return decide_approval(
        db, world["human"], UUID(pending["approval_id"]), "APPROVE", world["clock"]
    )


def revoke(admin_engine, world):
    """The owner command, at the world's clock."""
    revoke_signal_source(
        admin_engine,
        world["identity"].tenant_id,
        world["source"],
        world["admin"].principal_id,
        now=world["clock"].now(),
    )


def rows(admin_engine, world, table, execution_id=None):
    """Every row of one of this tenant's tables, or of one execution's rows in it."""
    query = f"SELECT * FROM execbound.{table} WHERE tenant_id = :t"
    params = {"t": world["identity"].tenant_id}
    if execution_id is not None:
        query += " AND execution_id = :e"
        params["e"] = execution_id
    with admin_engine.begin() as conn:
        fenced(conn, world["identity"].tenant_id)
        return [dict(row) for row in conn.execute(text(query), params).mappings()]


def rejections(admin_engine, world):
    """The reasons every refused admission of this tenant was audited with."""
    with admin_engine.begin() as conn:
        fenced(conn, world["identity"].tenant_id)
        return (
            conn.execute(
                text(
                    "SELECT payload->>'reason' FROM execbound.audit_events "
                    "WHERE tenant_id = :t AND kind = 'execution.rejected'"
                ),
                {"t": world["identity"].tenant_id},
            )
            .scalars()
            .all()
        )


def test_a_compromised_host_is_isolated_without_review(api, signal_world, live_provider, db):
    post_signal(db, signal_world, "Medium")
    response = api.post("/v1/execute", json=body(signal_world))
    assert (response.status_code, response.json()["state"]) == (200, "EXECUTED")
    assert mutations(live_provider, signal_world) == 1


@pytest.mark.parametrize("verdict", ["None", "Informational", "Low"])
def test_anything_less_goes_to_review(api, signal_world, live_provider, db, verdict):
    post_signal(db, signal_world, verdict)
    response = api.post("/v1/execute", json=body(signal_world))
    assert (response.status_code, response.json()["state"]) == (202, "PENDING_APPROVAL")
    assert mutations(live_provider, signal_world) == 0


def test_no_signal_is_refused_audited_and_nothing_runs(
    api, signal_world, live_provider, admin_engine
):
    response = api.post("/v1/execute", json=body(signal_world))
    assert response.status_code == 503
    assert mutations(live_provider, signal_world) == 0
    assert "INVALID_CONTEXT" in rejections(admin_engine, signal_world)
    # Refused before anything was recorded: no execution, and so no approval to rescue it.
    assert rows(admin_engine, signal_world, "executions") == []
    assert rows(admin_engine, signal_world, "approvals") == []


def test_a_heartbeat_of_the_same_verdict_keeps_the_approval(api, signal_world, live_provider, db):
    post_signal(db, signal_world, "None")
    pending = api.post("/v1/execute", json=body(signal_world)).json()
    signal_world["clock"].value += timedelta(seconds=60)
    post_signal(db, signal_world, "None")
    assert api.post("/v1/execute", json=body(signal_world)).json()["state"] == "PENDING_APPROVAL"
    approve(db, signal_world, pending)
    executed = api.post("/v1/execute", json=body(signal_world))
    assert executed.json()["state"] == "EXECUTED"
    assert mutations(live_provider, signal_world) == 1


def test_a_verdict_the_mapping_reads_alike_keeps_the_approval(api, signal_world, live_provider, db):
    """The approval is bound to the mapped value, not to the producer's verdict.

    The operator's table reads `None` and `Informational` alike, as `no_detection`, so a person
    who approved on one approved what the other says too.
    """
    post_signal(db, signal_world, "None")
    pending = api.post("/v1/execute", json=body(signal_world)).json()
    signal_world["clock"].value += timedelta(seconds=30)
    post_signal(db, signal_world, "Informational")
    assert api.post("/v1/execute", json=body(signal_world)).json()["state"] == "PENDING_APPROVAL"
    assert approve(db, signal_world, pending).approval_state == "APPROVED"
    executed = api.post("/v1/execute", json=body(signal_world)).json()
    assert (executed["state"], executed["execution_id"]) == ("EXECUTED", pending["execution_id"])
    assert mutations(live_provider, signal_world) == 1


def test_compromised_arriving_while_a_person_decides_cancels_the_approval(
    api, signal_world, live_provider, db
):
    post_signal(db, signal_world, "None")
    pending = api.post("/v1/execute", json=body(signal_world)).json()
    signal_world["clock"].value += timedelta(seconds=30)
    post_signal(db, signal_world, "High")
    assert approve(db, signal_world, pending).state == "STALE_AUTHORIZATION"
    assert mutations(live_provider, signal_world) == 0
    # A new request resolves afresh, and the verdict now isolates without review.
    fresh = api.post("/v1/execute", json=body(signal_world, idempotency_key="after-compromise"))
    assert fresh.json()["state"] == "EXECUTED"
    assert mutations(live_provider, signal_world) == 1


def test_an_approval_cannot_rescue_a_revoked_source(
    api, signal_world, live_provider, db, admin_engine
):
    post_signal(db, signal_world, "None")
    pending = api.post("/v1/execute", json=body(signal_world)).json()
    revoke(admin_engine, signal_world)
    assert approve(db, signal_world, pending).state == "STALE_AUTHORIZATION"
    assert mutations(live_provider, signal_world) == 0


def test_an_approved_request_cannot_run_on_a_revoked_source(
    api, signal_world, live_provider, db, admin_engine
):
    post_signal(db, signal_world, "None")
    pending = api.post("/v1/execute", json=body(signal_world)).json()
    assert approve(db, signal_world, pending).approval_state == "APPROVED"
    revoke(admin_engine, signal_world)
    again = api.post("/v1/execute", json=body(signal_world))
    assert (again.status_code, again.json()["state"]) == (200, "STALE_AUTHORIZATION")
    assert mutations(live_provider, signal_world) == 0


def pending_on_an_ageing_record(api, db, world, admin_engine):
    """A pending approval whose plan the signal ends first: its 300 seconds run out 50 seconds
    after the request, long before the inventory and incident facts beside it."""
    observed = world["clock"].now() - timedelta(seconds=250)
    post_signal(db, world, "None", observed_at=observed)
    pending = api.post("/v1/execute", json=body(world)).json()
    [approval] = rows(admin_engine, world, "approvals")
    assert approval["expires_at"] == observed + timedelta(seconds=300)
    return pending


def test_a_person_may_decide_while_the_signal_holds(
    api, signal_world, live_provider, db, admin_engine
):
    pending = pending_on_an_ageing_record(api, db, signal_world, admin_engine)
    signal_world["clock"].value += timedelta(seconds=30)
    assert approve(db, signal_world, pending).approval_state == "APPROVED"
    executed = api.post("/v1/execute", json=body(signal_world)).json()
    assert executed["state"] == "EXECUTED"
    assert mutations(live_provider, signal_world) == 1


def test_a_decision_after_the_signal_goes_stale_is_refused(
    api, signal_world, live_provider, db, admin_engine
):
    pending = pending_on_an_ageing_record(api, db, signal_world, admin_engine)
    signal_world["clock"].value += timedelta(seconds=60)
    assert approve(db, signal_world, pending).state == "STALE_AUTHORIZATION"
    assert mutations(live_provider, signal_world) == 0


def test_a_record_after_dispatch_changes_nothing(
    api, signal_world, live_provider, db, admin_engine
):
    post_signal(db, signal_world, "High")
    executed = api.post("/v1/execute", json=body(signal_world)).json()
    assert executed["state"] == "EXECUTED"
    tables = ("execution_impact", "resource_claims")
    settled = [rows(admin_engine, signal_world, t, executed["execution_id"]) for t in tables]
    assert all(settled)
    # Strictly newer than the record the isolation was decided on, so it is the source's word.
    signal_world["clock"].value += timedelta(seconds=30)
    post_signal(db, signal_world, "None")
    again = api.get("/v1/executions/" + executed["execution_id"]).json()
    assert again == executed
    assert api.post("/v1/execute", json=body(signal_world)).json() == executed
    # The record is live: a new request resolves on it and now goes to review.
    fresh = api.post("/v1/execute", json=body(signal_world, idempotency_key="after-dispatch"))
    assert (fresh.status_code, fresh.json()["state"]) == (202, "PENDING_APPROVAL")
    # Settlement never reads a signal (SG16): the executed request's impact and claim stand.
    assert [rows(admin_engine, signal_world, t, executed["execution_id"]) for t in tables] == (
        settled
    )
    assert mutations(live_provider, signal_world) == 1


@pytest.mark.parametrize(
    "decided,arriving",
    [("Medium", "None"), ("None", "High"), ("Medium", "High")],
    ids=["without_review", "approved", "same_value"],
)
def test_a_record_arriving_while_dispatch_is_committed_refuses(
    api, signal_world, live_provider, db, admin_engine, decided, arriving
):
    """The re-attestation inside the transaction that commits dispatch reads the record.

    `signal_admit` locks only its source's row, so a record can commit in the middle of an
    admission. One that changes the value commits just as the reservation is written; the
    closing re-attestation must see it and refuse, and nothing reaches the provider. The
    control is a record the mapping reads as the same value (`Medium` and `High` are both
    `compromised`): admitted by the same hook at the same moment, it refuses nothing, so the
    refusal comes from the changed value and never from the hook's own admission.
    """
    tenant, now = signal_world["identity"].tenant_id, signal_world["clock"].now()
    post_signal(db, signal_world, decided, observed_at=now - timedelta(seconds=10))
    if decided == "None":
        pending = api.post("/v1/execute", json=body(signal_world)).json()
        assert approve(db, signal_world, pending).approval_state == "APPROVED"
    admitted = []

    def arrive(conn, cursor, statement, parameters, context, executemany):
        if admitted or "INSERT INTO execbound.execution_impact" not in statement:
            return
        fields = signal_fields(
            signal_world["account"], now, verdict=arriving, event_id="device-01:arriving"
        )
        with admin_engine.begin() as owner:
            fenced(owner, tenant)
            params = admit_params(signal_world["source"], signal_world["token"], now, **fields)
            admitted.append(owner.execute(ADMIT, params).scalar_one())

    event.listen(db.engine, "before_cursor_execute", arrive)
    try:
        response = api.post("/v1/execute", json=body(signal_world))
    finally:
        event.remove(db.engine, "before_cursor_execute", arrive)
    assert [result.get("accepted") for result in admitted] == [True]
    if (decided, arriving) == ("Medium", "High"):
        assert (response.status_code, response.json()["state"]) == (200, "EXECUTED")
        assert rejections(admin_engine, signal_world) == []
        assert mutations(live_provider, signal_world) == 1
        return
    assert response.status_code == 503
    assert "STALE_AUTHORIZATION" in rejections(admin_engine, signal_world)
    assert rows(admin_engine, signal_world, "execution_impact") == []
    assert rows(admin_engine, signal_world, "resource_claims") == []
    assert mutations(live_provider, signal_world) == 0
    if decided == "None":
        # The refusal rolled the consumption back with everything else, and the next attempt
        # re-attests against the record that arrived, which changed the approved value.
        [approval] = rows(admin_engine, signal_world, "approvals")
        assert approval["state"] != "CONSUMED"
        again = api.post("/v1/execute", json=body(signal_world))
        assert (again.status_code, again.json()["state"]) == (200, "STALE_AUTHORIZATION")
        assert mutations(live_provider, signal_world) == 0


# An agent retrying a request that is still pending reaches the pending re-attestation in
# admission by three routes: the same request again; the same key with the target spelled
# another way, which admission resolves afresh before it compares the intent; and another key
# for the same intent, which finds the pending execution by that intent.
RETRIES = ["same_request", "same_key_other_spelling", "another_key"]


def retried(world, retry):
    if retry == "same_key_other_spelling":
        return body(world, target={"kind": "canonical", "value": str(world["target"])})
    if retry == "another_key":
        return body(world, idempotency_key="retry-2")
    return body(world)


@pytest.mark.parametrize("retry", RETRIES)
def test_an_agent_retrying_on_a_heartbeat_stays_pending(
    api, signal_world, live_provider, db, retry
):
    post_signal(db, signal_world, "None")
    pending = api.post("/v1/execute", json=body(signal_world)).json()
    signal_world["clock"].value += timedelta(seconds=60)
    post_signal(db, signal_world, "None")
    again = api.post("/v1/execute", json=retried(signal_world, retry))
    assert (again.status_code, again.json()["state"], again.json()["execution_id"]) == (
        202,
        "PENDING_APPROVAL",
        pending["execution_id"],
    )
    # The approval the person is looking at is still the one that authorizes the work.
    approve(db, signal_world, pending)
    executed = api.post("/v1/execute", json=body(signal_world)).json()
    assert (executed["state"], executed["execution_id"]) == ("EXECUTED", pending["execution_id"])
    assert mutations(live_provider, signal_world) == 1


@pytest.mark.parametrize("retry", RETRIES)
def test_an_agent_retrying_on_a_changed_value_goes_stale(
    api, signal_world, live_provider, db, retry
):
    post_signal(db, signal_world, "None")
    pending = api.post("/v1/execute", json=body(signal_world)).json()
    signal_world["clock"].value += timedelta(seconds=30)
    # `suspect` still requires review, so only the bound value, not the policy's answer,
    # can end the pending approval.
    post_signal(db, signal_world, "Low")
    again = api.post("/v1/execute", json=retried(signal_world, retry))
    assert (again.status_code, again.json()["state"], again.json()["execution_id"]) == (
        200,
        "STALE_AUTHORIZATION",
        pending["execution_id"],
    )
    # The approval ended with it: nobody can now approve work decided on the old value.
    with pytest.raises(ExecutionError) as refused:
        approve(db, signal_world, pending)
    assert refused.value.code == "INVALID_STATE"
    assert mutations(live_provider, signal_world) == 0


def test_a_newest_record_observed_after_the_decision_refuses(
    api, signal_world, live_provider, db, admin_engine
):
    post_signal(db, signal_world, "None")
    pending = api.post("/v1/execute", json=body(signal_world)).json()
    # The producer's clock runs ahead of the gateway's, within the 60 seconds the intake
    # allows. The verdict is the same, so only the record's time can refuse: its newest word
    # is one the decision cannot have seen, and the earlier record it replaced is not read.
    now = signal_world["clock"].now()
    post_signal(db, signal_world, "None", observed_at=now + timedelta(seconds=30))
    again = api.post("/v1/execute", json=body(signal_world))
    assert (again.status_code, again.json()["state"]) == (200, "STALE_AUTHORIZATION")
    fresh = api.post("/v1/execute", json=body(signal_world, idempotency_key="while-ahead"))
    assert fresh.status_code == 503
    assert "INVALID_CONTEXT" in rejections(admin_engine, signal_world)
    assert mutations(live_provider, signal_world) == 0
    # Once the decision's clock reaches the observation the record is read again.
    signal_world["clock"].value = now + timedelta(seconds=30)
    later = api.post("/v1/execute", json=body(signal_world, idempotency_key="caught-up"))
    assert (later.status_code, later.json()["state"]) == (202, "PENDING_APPROVAL")
    assert later.json()["execution_id"] != pending["execution_id"]


@pytest.mark.parametrize("retry", ["same_key_other_spelling", "another_key"])
def test_a_retry_resolved_afresh_refuses_a_record_ahead_of_the_decision(
    api, signal_world, live_provider, db, admin_engine, retry
):
    """Both retries admission resolves afresh refuse before they reach the pending execution.

    What that leaves pending is not a property this test holds; only that nothing runs, the
    refusal is audited and a person's decision on the old record is refused too.
    """
    post_signal(db, signal_world, "None")
    pending = api.post("/v1/execute", json=body(signal_world)).json()
    now = signal_world["clock"].now()
    post_signal(db, signal_world, "None", observed_at=now + timedelta(seconds=30))
    assert api.post("/v1/execute", json=retried(signal_world, retry)).status_code == 503
    assert "INVALID_CONTEXT" in rejections(admin_engine, signal_world)
    assert mutations(live_provider, signal_world) == 0
    assert approve(db, signal_world, pending).state == "STALE_AUTHORIZATION"
    assert mutations(live_provider, signal_world) == 0
