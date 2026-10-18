# SPDX-License-Identifier: AGPL-3.0-only
"""Identity settlement survives commit failure and rejects unrelated terminal proof."""

from contextlib import contextmanager
from uuid import uuid4

import httpx
import pytest
from identity_fixtures import ACTIONS, identity_request
from identity_fixtures import identity_connector as identity_connector
from identity_fixtures import identity_provider as identity_provider
from identity_fixtures import identity_world as identity_world
from identity_fixtures import registry as registry
from identity_fixtures import world as world
from sqlalchemy import text
from test_identity_execution import impact, invocations, ready, state

from execbound.execution import admit, get_execution, reconcile, store, take_dispatch
from execbound.execution.models import ExecutionError
from execbound.operations import PRODUCTION_ACTIONS
from execbound.provider.gateway import dispatch_owned, reconcile_operation
from execbound.provider.models import SignedJournal, provider_command
from execbound.provider.verifiers import verifier_for


@contextmanager
def failed_outcome_commit(admin_engine):
    """A real deferred trigger fails COMMIT after terminal writes and audit insertion."""
    with admin_engine.begin() as conn:
        conn.execute(
            text("""
            CREATE FUNCTION execbound.synthetic_identity_outcome_failure()
            RETURNS trigger LANGUAGE plpgsql AS $$
            BEGIN
                RAISE EXCEPTION 'Synthetic identity outcome commit failure';
            END;
            $$
        """)
        )
        conn.execute(
            text("""
            CREATE CONSTRAINT TRIGGER synthetic_identity_outcome_failure
            AFTER INSERT ON execbound.execution_events
            DEFERRABLE INITIALLY DEFERRED FOR EACH ROW
            WHEN (NEW.to_state = 'EXECUTED')
            EXECUTE FUNCTION execbound.synthetic_identity_outcome_failure()
        """)
        )
    try:
        yield
    finally:
        with admin_engine.begin() as conn:
            conn.execute(
                text("""
                DROP TRIGGER synthetic_identity_outcome_failure ON execbound.execution_events
            """)
            )
            conn.execute(text("DROP FUNCTION execbound.synthetic_identity_outcome_failure()"))


def assert_unresolved(db, engine, world, execution_id, action):
    assert impact(engine, execution_id) == (action, "UNRESOLVED")
    with db.transaction(world["identity"].tenant_id) as conn:
        row = store.read(conn, world["identity"].tenant_id, execution_id)
        assert row["state"] in {"DISPATCH_COMMITTED", "INDETERMINATE"}
        assert row["result"] is None
        assert (
            conn.execute(
                text("""
            SELECT released_at FROM execbound.resource_claims WHERE execution_id=:e
        """),
                {"e": execution_id},
            ).scalar_one()
            is None
        )
        assert (
            conn.execute(
                text("""
            SELECT count(*) FROM execbound.execution_events
            WHERE execution_id=:e AND to_state IN ('EXECUTED','FAILED_NOT_EXECUTED')
        """),
                {"e": execution_id},
            ).scalar_one()
            == 0
        )


@pytest.mark.parametrize("action", ACTIONS)
def test_effect_then_audit_commit_failure_preserves_guard_and_exact_recovery(
    db, identity_world, identity_provider, identity_connector, admin_engine, action
):
    world = identity_world
    admission = ready(db, world, action)
    with failed_outcome_commit(admin_engine):
        result = dispatch_owned(db, admission.ticket, identity_connector, world["clock"])
    assert result.state == "INDETERMINATE"
    assert state(identity_provider, world).mutation_count == 1
    assert len(invocations(identity_provider)) == 1
    assert_unresolved(db, admin_engine, world, result.execution_id, action)
    with db.transaction(world["identity"].tenant_id) as conn:
        assert (
            conn.execute(
                text("""
            SELECT count(*) FROM execbound.audit_events
            WHERE payload->>'execution_id'=:e AND payload->>'to_state'='EXECUTED'
        """),
                {"e": str(result.execution_id)},
            ).scalar_one()
            == 0
        )
        command = store.command(store.read(conn, world["identity"].tenant_id, result.execution_id))
    journal = identity_provider.store.lookup(provider_command(command))
    assert journal is not None and journal.outcome == "EXECUTED"
    assert (
        admit(db, world["identity"], identity_request(world, action), world["clock"]).ticket is None
    )
    recovered = reconcile_operation(
        db,
        world["admin"],
        result.execution_id,
        identity_connector,
        reason="Recover exact identity proof after synthetic COMMIT failure",
        clock=world["clock"],
    )
    assert recovered.state == "EXECUTED"
    assert impact(admin_engine, result.execution_id) == (action, "CONFIRMED")
    assert state(identity_provider, world).mutation_count == 1
    assert len(invocations(identity_provider)) == 1


@pytest.mark.parametrize("action", ACTIONS)
@pytest.mark.parametrize("later_method", ["dispatch", "cancel"])
def test_later_signed_operation_cannot_settle_or_refund_original_effect(
    db,
    identity_world,
    identity_provider,
    identity_connector,
    admin_engine,
    monkeypatch,
    action,
    later_method,
):
    world = identity_world
    admission = ready(db, world, action)
    command = take_dispatch(db, admission.ticket, world["clock"])
    # The independent provider has committed; simulate a gateway interruption before settlement.
    identity_connector.dispatch(provider_command(command))
    assert state(identity_provider, world).mutation_count == 1
    original = provider_command(command)
    other_action = ACTIONS[(ACTIONS.index(action) + 1) % len(ACTIONS)]
    other_binding = PRODUCTION_ACTIONS.binding(original.provider, other_action)
    later = original.model_copy(
        update={
            "operation_id": uuid4(),
            "execution_id": uuid4(),
            "action": other_action,
            "provider_operation": other_binding.provider_operation,
            "expected_version": state(identity_provider, world).version,
        }
    )
    later_record = getattr(identity_provider.store, later_method)(later)
    with httpx.Client(trust_env=False, follow_redirects=False) as client:
        response = client.post(
            identity_provider.config.origin + "/v1/journal",
            content=later.model_dump_json(),
            headers={"Authorization": "Bearer " + identity_provider.config.dispatch_token},
        )
    assert response.status_code == 200
    signed = SignedJournal.model_validate_json(response.content)
    assert signed.record == later_record
    assert signed.record.outcome == (
        "EXECUTED" if later_method == "dispatch" else "CANCELLED_NOT_EXECUTED"
    )
    # A valid signature from the right account still cannot authorize a different operation.
    with pytest.raises(ExecutionError):
        reconcile(
            db,
            world["admin"],
            admission.view.execution_id,
            reason="Attempt substituted later identity journal",
            evidence=response.content,
            verifier=verifier_for(identity_connector.config),
            clock=world["clock"],
        )
    assert_unresolved(db, admin_engine, world, admission.view.execution_id, action)
    with monkeypatch.context() as patch:
        patch.setattr(identity_connector, "lookup", lambda _: response.content)
        with pytest.raises(ExecutionError):
            reconcile_operation(
                db,
                world["admin"],
                admission.view.execution_id,
                identity_connector,
                reason="Attempt substituted lookup response",
                clock=world["clock"],
            )
    assert_unresolved(db, admin_engine, world, admission.view.execution_id, action)
    expected_mutations = 2 if later_method == "dispatch" else 1
    assert state(identity_provider, world).mutation_count == expected_mutations
    recovered = reconcile_operation(
        db,
        world["admin"],
        admission.view.execution_id,
        identity_connector,
        reason="Read the original operation's retained identity journal",
        clock=world["clock"],
    )
    assert recovered.state == "EXECUTED"
    assert impact(admin_engine, admission.view.execution_id) == (action, "CONFIRMED")
    assert state(identity_provider, world).mutation_count == expected_mutations
    assert len(invocations(identity_provider)) == 1


@pytest.mark.parametrize("action", ACTIONS)
def test_current_identity_state_with_absent_journal_preserves_original_impact(
    db, identity_world, identity_provider, identity_connector, admin_engine, action
):
    world = identity_world
    admission = ready(db, world, action)
    command = take_dispatch(db, admission.ticket, world["clock"])
    # Independent state happens to reflect the requested effect without this operation's proof.
    identity_provider.store.reprovision_resource(
        world["identity"].tenant_id,
        world["canonical"],
        "out-of-band-state",
        account_enabled=action != "identity.disable",
        session_generation=19,
    )
    assert identity_provider.store.lookup(provider_command(command)) is None
    unknown = reconcile_operation(
        db,
        world["admin"],
        admission.view.execution_id,
        identity_connector,
        reason="Inspect current state without operation evidence",
        clock=world["clock"],
    )
    assert unknown.state == "INDETERMINATE"
    assert_unresolved(db, admin_engine, world, admission.view.execution_id, action)
    for raw in (
        b'{"account_enabled":false,"session_generation":19}',
        b'{"status":"not_found"}',
    ):
        with pytest.raises(ExecutionError):
            reconcile(
                db,
                world["admin"],
                admission.view.execution_id,
                reason="Attempt current-state inference",
                evidence=raw,
                verifier=verifier_for(identity_connector.config),
                clock=world["clock"],
            )
        assert_unresolved(db, admin_engine, world, admission.view.execution_id, action)
    assert (
        get_execution(db, world["identity"], admission.view.execution_id, world["clock"]).state
        == "INDETERMINATE"
    )
    assert invocations(identity_provider) == []


@pytest.mark.parametrize("action", ACTIONS)
@pytest.mark.parametrize("privilege", ["privileged", "tier0"])
def test_existing_privileged_identity_is_denied_without_provider_effect(
    db, identity_world, identity_provider, admin_engine, action, privilege
):
    world = identity_world
    with admin_engine.begin() as conn:
        conn.execute(
            text("""
            UPDATE execbound.resources SET privilege_class=:privilege
            WHERE tenant_id=:tenant AND resource_id=:resource
        """),
            {
                "privilege": privilege,
                "tenant": world["identity"].tenant_id,
                "resource": world["target"],
            },
        )
    denied = admit(db, world["identity"], identity_request(world, action), world["clock"])
    assert denied.view.state == "DENIED" and denied.ticket is None
    assert denied.view.approval_id is None
    assert state(identity_provider, world).mutation_count == 0
    assert invocations(identity_provider) == []
    with admin_engine.connect() as conn:
        assert (
            conn.execute(
                text("""
            SELECT count(*) FROM execbound.execution_impact WHERE execution_id=:execution
        """),
                {"execution": denied.view.execution_id},
            ).scalar_one()
            == 0
        )
