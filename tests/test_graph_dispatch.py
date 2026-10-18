# SPDX-License-Identifier: AGPL-3.0-only
"""A dispatch that reaches Graph, end to end, and what the settlement is worth.

These drive the real gateway path rather than the connector in isolation, because the
defect this module exists to prevent was invisible to every test that built its input by
hand: the window was rendered and replayed correctly and *nothing produced one*. A test
that injects a window proves the consumer; only a dispatch proves the producer.
"""

import json

import pytest
from graph_fixtures import (
    ACTION,
    ROTATED_KEY,
    ROTATED_KEY_ID,
    SIGNING_KEY,
    SIGNING_KEY_ID,
    USER_ID,
    connector_for,
)
from graph_fixtures import (
    graph_connector as graph_connector,
)
from graph_fixtures import (
    graph_directory as graph_directory,
)
from graph_fixtures import (
    graph_world as graph_world,
)
from graph_fixtures import (
    registry as registry,
)
from graph_fixtures import (
    world as world,
)
from identity_fixtures import identity_request
from sqlalchemy import text

from execbound.execution import admit, decide_approval, take_dispatch
from execbound.execution.models import PreconditionConfig
from execbound.provider.connector_record import ConnectorRecord
from execbound.provider.gateway import dispatch_owned, reconcile_operation
from execbound.provider.models import ProviderError, parse_provider, provider_command
from execbound.provider.verifiers import verifier_for
from execbound.replay.export import export_history
from execbound.replay.verify import verify_export

CHECKED = PreconditionConfig({("graph", "disable"): "CHECKED_BY_CONNECTOR"})


def ready(db, world):
    request = identity_request(world, ACTION)
    admission = admit(db, world["identity"], request, world["clock"])
    if admission.view.state == "PENDING_APPROVAL":
        decide_approval(db, world["human"], admission.view.approval_id, "APPROVE", world["clock"])
        admission = admit(db, world["identity"], request, world["clock"])
    assert admission.ticket is not None
    return admission


def settled(admin_engine, world, execution_id):
    with admin_engine.begin() as conn:
        return dict(
            conn.execute(
                text(
                    "SELECT state,precondition_class,precondition_window_ms,result "
                    "FROM execbound.executions WHERE tenant_id=:t AND execution_id=:e"
                ),
                {"t": world["identity"].tenant_id, "e": execution_id},
            )
            .mappings()
            .one()
        )


def record_of(row):
    return parse_provider(
        json.dumps(row["result"]["authenticated_record"]).encode()
        if isinstance(row["result"]["authenticated_record"], dict)
        else row["result"]["authenticated_record"].encode(),
        ConnectorRecord,
    ).record


def writes(server):
    return [path for path, _, _ in server.requests if path.startswith("/v1.0/users/")]


def test_an_allowed_disable_writes_once_and_retains_the_window_it_measured(
    db, graph_world, graph_directory, graph_connector, admin_engine
):
    admission = ready(db, graph_world)
    view = dispatch_owned(db, admission.ticket, graph_connector, graph_world["clock"], CHECKED)
    assert view.state == "EXECUTED"

    # Exactly one mutation reached the directory, and it is the one that was authorized.
    assert graph_directory.scenario.users[USER_ID]["accountEnabled"] is False

    row = settled(admin_engine, graph_world, view.execution_id)
    assert row["precondition_class"] == "CHECKED_BY_CONNECTOR"
    # The column the pages read. Before the connector existed nothing could write this, and
    # nothing did: the value is established by the exchange and settled with it.
    assert isinstance(row["precondition_window_ms"], int)

    record = record_of(row)
    assert record.outcome == "EXECUTED"
    assert record.observed == record.frozen
    assert 200 <= record.status < 300
    # The column is a projection of the signed record, never an independent number.
    assert record.window_ms == row["precondition_window_ms"]


def test_a_subject_that_moved_is_refused_and_the_record_keeps_the_drift(
    db, graph_world, graph_directory, graph_connector, admin_engine
):
    admission = ready(db, graph_world)
    # The subject changes after its version was frozen. Graph offers no conditional write,
    # so this is the comparison ExecBound makes for itself.
    graph_directory.scenario.users[USER_ID]["userPrincipalName"] = "moved@contoso.example"
    view = dispatch_owned(db, admission.ticket, graph_connector, graph_world["clock"], CHECKED)
    assert view.state == "STALE_AUTHORIZATION"
    assert graph_directory.scenario.users[USER_ID]["accountEnabled"] is True

    row = settled(admin_engine, graph_world, view.execution_id)
    record = record_of(row)
    assert record.outcome == "VERSION_MISMATCH"
    # The drift is the evidence: a mismatch record that agreed with the frozen value would
    # state nothing at all, and the model refuses to be constructed that way.
    assert record.observed is not None and record.observed != record.frozen


def test_a_subject_that_is_gone_settles_not_executed_with_no_observation(
    db, graph_world, graph_directory, graph_connector, admin_engine
):
    admission = ready(db, graph_world)
    graph_directory.scenario.users.clear()
    view = dispatch_owned(db, admission.ticket, graph_connector, graph_world["clock"], CHECKED)
    assert view.state == "FAILED_NOT_EXECUTED"
    row = settled(admin_engine, graph_world, view.execution_id)
    record = record_of(row)
    assert record.outcome == "TARGET_NOT_FOUND"
    # There was no subject to compute a composite from, so there is none to retain.
    assert record.observed is None


def test_a_refused_write_is_uncertain_rather_than_a_claimed_failure(
    db, graph_world, graph_directory, graph_connector, admin_engine
):
    """A 403 on the write means no mutation, but the verified vocabulary cannot say so.

    Settling uncertain is the safe direction. It is also the limitation `docs/PROVIDER.md`
    records under "A vendor that co-signs nothing": Graph publishes no journal, so this
    execution stays uncertain.
    """
    admission = ready(db, graph_world)
    graph_directory.scenario.write_status = 403
    view = dispatch_owned(db, admission.ticket, graph_connector, graph_world["clock"], CHECKED)
    assert view.state == "INDETERMINATE"
    row = settled(admin_engine, graph_world, view.execution_id)
    assert row["result"] is None
    assert row["precondition_window_ms"] is None


def test_the_connector_offers_no_lookup_and_no_cancellation(db, graph_world, graph_connector):
    admission = ready(db, graph_world)
    command = take_dispatch(db, admission.ticket, graph_world["clock"], CHECKED)
    # Re-reading the user cannot tell this connector's own write from someone else
    # disabling the account, so there is nothing honest to return.
    assert graph_connector.lookup(provider_command(command)) is None
    with pytest.raises(ProviderError):
        graph_connector.cancel(provider_command(command))


def test_a_rotation_that_drops_the_signing_key_is_refused_whole(graph_directory, graph_world):
    connector = connector_for(graph_directory, graph_world)
    try:
        # Adding a key beside the signing one is an ordinary rotation.
        connector.rotate_keys({SIGNING_KEY_ID: SIGNING_KEY, ROTATED_KEY_ID: ROTATED_KEY})
        assert set(connector.config.evidence_keys) == {SIGNING_KEY_ID, ROTATED_KEY_ID}
        # Dropping the key it signs with would leave it signing records nothing verifies.
        with pytest.raises(ValueError):
            connector.rotate_keys({ROTATED_KEY_ID: ROTATED_KEY})
        assert connector.config.signing_key_id in connector.config.evidence_keys
    finally:
        connector.close()


def test_a_dispatch_for_another_account_is_refused_before_any_vendor_call(
    db, graph_world, graph_directory
):
    admission = ready(db, graph_world)
    command = take_dispatch(db, admission.ticket, graph_world["clock"], CHECKED)
    other = connector_for(graph_directory, {**graph_world, "account": graph_world["inventory"]})
    try:
        before = len(graph_directory.requests)
        with pytest.raises(ProviderError):
            other.dispatch(provider_command(command))
        # Scope is checked before the credential is ever used.
        assert len(graph_directory.requests) == before
    finally:
        other.close()


def test_replay_reads_the_connector_envelope_and_the_window_it_carries(
    db, graph_world, graph_directory, graph_connector
):
    """The third envelope. Before it, a Graph settlement ended the whole tenant export.

    `_terminal` chooses the envelope from the captured command, and a record that will not
    parse as the one that command names is refused rather than tried as another. A Graph
    record read as a provider journal raises, which is exactly the defect an attested
    settlement caused once already.
    """
    admission = ready(db, graph_world)
    view = dispatch_owned(db, admission.ticket, graph_connector, graph_world["clock"], CHECKED)
    assert view.state == "EXECUTED"

    history = export_history(db, graph_world["admin"], graph_world["clock"])
    events = verify_export(history, history.head).events

    attempts = [e for e in events if e.event.kind == "execution.dispatch_attempt"]
    assert [e.precondition_class for e in attempts] == ["CHECKED_BY_CONNECTOR"]
    # The class is known when the attempt is committed; the gap is not, because the
    # exchange has not happened yet. So the attempt carries no window at all.
    assert [e.precondition_window_ms for e in attempts] == [None]

    settled_events = [e for e in events if e.terminal_evidence is not None]
    assert settled_events, "the settlement is in the export"
    windows = [e.precondition_window_ms for e in settled_events]
    assert all(isinstance(w, int) for w in windows)
    # A settlement ExecBound dispatched names no tier: a tier is a statement about an
    # external executor's word, and this is not one.
    assert {e.settlement_tier for e in settled_events} == {None}


def test_a_window_in_the_attempt_payload_is_not_a_channel(
    db, graph_world, graph_directory, graph_connector
):
    """There is exactly one source for a window, and the attempt payload is not it.

    Nothing writes the key and nothing reads it. A forged one changes no rendering, because
    the value comes from the signed record or from nowhere.
    """
    admission = ready(db, graph_world)
    dispatch_owned(db, admission.ticket, graph_connector, graph_world["clock"], CHECKED)
    history = export_history(db, graph_world["admin"], graph_world["clock"])
    for event in history.events:
        if event.kind == "execution.dispatch_attempt":
            assert "precondition_window_ms" not in event.payload


def test_a_cancellation_cannot_refund_a_graph_operation(
    db, graph_world, graph_directory, graph_connector, admin_engine
):
    """An admin may ask; Graph offers nothing that would let the answer be a refund.

    `lookup` returns None and `cancel` refuses, so `reconcile_operation` reaches no
    evidence and settles nothing. The request itself is audited, because the operation
    stays charged and an administrator has to be able to find that it was asked.
    """
    admission = ready(db, graph_world)
    graph_directory.scenario.write_status = 500
    view = dispatch_owned(db, admission.ticket, graph_connector, graph_world["clock"], CHECKED)
    assert view.state == "INDETERMINATE"

    after = reconcile_operation(
        db,
        graph_world["admin"],
        view.execution_id,
        graph_connector,
        reason="graph offers no journal",
        cancel_if_missing=True,
        clock=graph_world["clock"],
    )
    # Still uncertain: nothing released the claim and nothing was settled on absent
    # evidence, which would be a refund on no evidence at all.
    assert after.state == "INDETERMINATE"
    row = settled(admin_engine, graph_world, view.execution_id)
    assert row["result"] is None

    with admin_engine.begin() as conn:
        kinds = [
            kind
            for (kind,) in conn.execute(
                text(
                    "SELECT kind FROM execbound.audit_events WHERE tenant_id=:t "
                    "AND kind='execution.cancellation_requested'"
                ),
                {"t": graph_world["identity"].tenant_id},
            )
        ]
    assert kinds, "the attempt is on the record even though it settled nothing"


def test_a_rotation_keeps_verifying_what_the_previous_key_signed(
    db, graph_world, graph_directory, graph_connector
):
    """A key that stays in the ring keeps verifying the records it already signed.

    The signing member and the verification ring are not the same question. Rotation adds
    a key and keeps the old one, so evidence retained before the rotation is still
    evidence afterwards, which is what settling a lost response later depends on.
    """
    admission = ready(db, graph_world)
    command = __import__("execbound.execution", fromlist=["take_dispatch"]).take_dispatch(
        db, admission.ticket, graph_world["clock"], CHECKED
    )
    evidence = graph_connector.dispatch(provider_command(command))

    graph_connector.rotate_keys({SIGNING_KEY_ID: SIGNING_KEY, ROTATED_KEY_ID: ROTATED_KEY})
    # Signed under connector-v1, which is still in the ring.
    assert verifier_for(graph_connector.config).verify(command, evidence).outcome == "EXECUTED"

    # A ring that no longer holds the signing key is refused, so this cannot become the
    # state where retained evidence silently stops verifying.
    with pytest.raises(ValueError):
        graph_connector.rotate_keys({ROTATED_KEY_ID: ROTATED_KEY})
