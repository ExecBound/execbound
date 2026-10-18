# SPDX-License-Identifier: AGPL-3.0-only
"""A self-consistent file is not sufficient proof of valid historical authority."""

from datetime import timedelta
from uuid import uuid4

import pytest
from replay_fixtures import (
    asserted_outcome,
    chain_export,
    executor_evidence,
    make_capture,
    replay_case,
    terminal_evidence,
    transition_event,
)

from execbound.replay.verify import ReplayValidationError, verify_export


@pytest.mark.parametrize(
    "kind",
    [
        "access.create_group",
        "access.update_group",
        "access.delete_group",
        "access.set_members",
        "access.group_member_added",
        "access.set_user_roles",
        "access.set_group_roles",
        "approval_rule.changed",
    ],
)
def test_human_access_changes_keep_audit_history_replayable(kind):
    export = chain_export([(kind, {"reason": "Review team access"})])
    history = verify_export(export, export.head)
    assert history.complete and history.issues == ()
    assert history.events[0].capture is None
    assert history.events[0].terminal_evidence is None


@pytest.mark.parametrize(
    "attack", ["edit", "delete", "reverse", "truncate", "duplicate", "head", "foreign"]
)
def test_original_chain_and_independent_head_reject_corruption(attack):
    export = chain_export([("demo.provisioned", {"ordinal": n}) for n in range(3)])
    expected = export.head
    events = list(export.events)
    if attack == "edit":
        events[1] = events[1].model_copy(update={"payload": {"ordinal": 9}})
    elif attack == "delete":
        del events[1]
    elif attack == "reverse":
        events.reverse()
    elif attack == "truncate":
        events.pop()
    elif attack == "duplicate":
        events.insert(1, events[1])
    elif attack == "head":
        export = export.model_copy(
            update={"head": expected.model_copy(update={"event_hash": "0" * 64})}
        )
    else:
        expected = expected.model_copy(update={"tenant_id": uuid4()})
    export = export.model_copy(update={"events": tuple(events)})
    with pytest.raises(ReplayValidationError):
        verify_export(export, expected)


@pytest.mark.parametrize("field", ["execution_id", "operation_id", "canonical_target_id"])
def test_capture_cannot_change_attempted_command_identity(field):
    from test_replay_scenarios import observed

    case = replay_case()
    capture = make_capture(case)
    entries = observed(capture)
    entries[1] = capture.model_copy(update={field: uuid4()})
    export = chain_export(entries, (case["bundle"],))
    if field == "execution_id":
        from execbound.replay.simulate import simulate

        # Different execution IDs are distinct records; chronology exposes the missing links.
        assert not simulate(verify_export(export, export.head)).complete
    else:
        with pytest.raises(ReplayValidationError):
            verify_export(export, export.head)


@pytest.mark.parametrize(
    "field,value",
    [
        ("resource_provider_id", "another-device"),
        ("resource_version", "another-version"),
        ("mapping_version", "different-v2"),
        ("context_contract_version", "different-v2"),
    ],
)
def test_frozen_field_edit_requires_its_original_plan_binding(field, value):
    case = replay_case()
    capture = make_capture(case)
    payload = capture.model_dump(mode="json")
    payload["frozen"][field] = value
    export = chain_export(
        [("execution.evaluated", payload)],
        (case["bundle"],),
        actor_id=capture.identity.principal_id,
    )
    with pytest.raises(ReplayValidationError):
        verify_export(export, export.head)


def test_historical_credential_cannot_be_used_before_it_was_issued():
    case = replay_case()
    capture = make_capture(case)
    capture = capture.model_copy(
        update={
            "identity": capture.identity.model_copy(
                update={"issued_at": capture.semantic_time + timedelta(seconds=1)}
            )
        }
    )
    export = chain_export([capture], (case["bundle"],))
    with pytest.raises(ReplayValidationError, match="Replay input unavailable"):
        verify_export(export, export.head)


@pytest.mark.parametrize(
    "field,value",
    [
        pytest.param("tenant_id", str(uuid4()), id="tenant_id"),
        pytest.param("account_id", str(uuid4()), id="account_id"),
        pytest.param("canonical_target_id", str(uuid4()), id="canonical_target_id"),
        pytest.param("resource_provider_id", "replacement-device", id="resource_provider_id"),
        pytest.param("expected_version", "replacement-version", id="expected_version"),
        pytest.param("operation_id", str(uuid4()), id="operation_id"),
        pytest.param("execution_id", str(uuid4()), id="execution_id"),
        pytest.param("intent_hash", "1" * 64, id="intent_hash"),
        pytest.param("plan_hash", "2" * 64, id="plan_hash"),
    ],
)
def test_rehashed_structurally_valid_journal_still_must_bind_every_command_field(field, value):
    import hashlib
    import json

    from execbound.provider.models import ProviderCommand

    case = replay_case()
    capture = make_capture(case)
    proof = terminal_evidence(capture).model_dump(mode="json")
    signed = json.loads(proof["authenticated_record"])
    signed["record"]["command"][field] = value
    command = ProviderCommand.model_validate_json(json.dumps(signed["record"]["command"]))
    signed["record"]["command_hash"] = command.command_hash
    proof["authenticated_record"] = json.dumps(signed)
    proof["proof_digest"] = hashlib.sha256(proof["authenticated_record"].encode()).hexdigest()
    if field in proof:
        proof[field] = value
    export = chain_export(
        [capture, transition_event(capture, "DISPATCH_COMMITTED", "EXECUTED", evidence=proof)],
        (case["bundle"],),
    )
    with pytest.raises(ReplayValidationError):
        verify_export(export, export.head)


def test_capture_is_typed_and_verified_against_immutable_bundle():
    case = replay_case()
    capture = make_capture(case)
    export = chain_export([capture], (case["bundle"],))
    history = verify_export(export, export.head)
    assert history.complete and history.events[0].capture == capture
    assert history.events[0].semantic_time == capture.semantic_time


@pytest.mark.parametrize("field,value", [("plan_hash", "a" * 64), ("content_hash", "b" * 64)])
def test_rehashed_capture_cannot_substitute_bundle_or_plan_binding(field, value):
    case = replay_case()
    capture = make_capture(case)
    payload = capture.model_dump(mode="json")
    payload["decision"][field] = value
    export = chain_export([("execution.evaluated", payload)], (case["bundle"],))
    with pytest.raises(ReplayValidationError):
        verify_export(export, export.head)


@pytest.mark.parametrize("field", ["tenant_id", "actor_id"])
def test_capture_must_match_event_scope_and_actor(field):
    case = replay_case()
    capture = make_capture(case)
    options = {field: uuid4()}
    export = chain_export([capture], (case["bundle"],), **options)
    with pytest.raises(ReplayValidationError):
        verify_export(export, export.head)


@pytest.mark.parametrize(
    "field,value",
    [
        ("dispatch_token", "synthetic-private"),
        ("owner_hash", "1" * 64),
        ("signing_key_hex", "2" * 64),
        ("csrf_token", "synthetic-private"),
        ("authorization", "Bearer synthetic-private"),
        ("note", "Bearer synthetic-private"),
    ],
)
def test_export_refuses_secret_payloads_without_rewriting_chain(field, value):
    export = chain_export([("demo.provisioned", {"nested": [{field: value}]})])
    with pytest.raises(ReplayValidationError) as exc:
        verify_export(export, export.head)
    assert "synthetic-private" not in str(exc.value)
    assert exc.value.__context__ is None


def test_missing_referenced_bundle_is_not_silently_ignored():
    capture = make_capture()
    export = chain_export([capture])
    with pytest.raises(ReplayValidationError):
        verify_export(export, export.head)


def test_policy_event_content_hash_must_match_exported_bundle():
    case = replay_case()
    bundle = case["bundle"]
    export = chain_export(
        [
            (
                "policy.bundle_activated",
                {"bundle_id": str(bundle.bundle_id), "content_hash": "c" * 64},
            )
        ],
        (bundle,),
    )
    with pytest.raises(ReplayValidationError):
        verify_export(export, export.head)


def test_legacy_transition_is_partial_instead_of_inventing_semantic_time():
    capture = make_capture()
    kind, payload = transition_event(capture, "RESERVED", "DISPATCH_COMMITTED")
    del payload["replay"]
    export = chain_export([(kind, payload)], tenant_id=capture.identity.tenant_id)
    history = verify_export(export, export.head)
    assert not history.complete
    assert history.events[0].completeness == "LEGACY"
    assert history.events[0].semantic_time is None


def test_unknown_consequential_event_is_explicitly_unsupported():
    export = chain_export([("execution.future_release", {"execution_id": str(uuid4())})])
    history = verify_export(export, export.head)
    assert not history.complete and history.events[0].completeness == "UNSUPPORTED"


def test_terminal_proof_has_structural_binding_but_no_provider_mac_claim():
    case = replay_case("identity.revoke_sessions")
    capture = make_capture(case)
    proof = terminal_evidence(capture)
    export = chain_export(
        [
            capture,
            transition_event(
                capture,
                "DISPATCH_COMMITTED",
                "EXECUTED",
                semantic_time=capture.semantic_time + timedelta(seconds=1),
                evidence=proof.model_dump(mode="json"),
            ),
        ],
        (case["bundle"],),
    )
    history = verify_export(export, export.head)
    assert history.events[1].terminal_evidence == proof


@pytest.mark.parametrize("change", ["digest", "command", "transition", "outcome"])
def test_rehashed_terminal_payload_cannot_substitute_execution_evidence(change):
    case = replay_case("identity.disable")
    capture = make_capture(case)
    proof = terminal_evidence(capture).model_dump(mode="json")
    if change == "digest":
        proof["proof_digest"] = "d" * 64
    elif change == "command":
        proof["operation_id"] = str(uuid4())
    elif change == "transition":
        import hashlib
        import json

        record = json.loads(proof["authenticated_record"])
        record["record"]["identity_transition"]["after"]["account_enabled"] = True
        proof["authenticated_record"] = json.dumps(record)
        proof["proof_digest"] = hashlib.sha256(proof["authenticated_record"].encode()).hexdigest()
    else:
        proof["reason"] = "CANCELLED_NOT_EXECUTED"
        proof["outcome"] = "FAILED_NOT_EXECUTED"
    export = chain_export(
        [capture, transition_event(capture, "DISPATCH_COMMITTED", "EXECUTED", evidence=proof)],
        (case["bundle"],),
    )
    with pytest.raises(ReplayValidationError):
        verify_export(export, export.head)


def test_executed_lift_binds_the_frozen_arguments_through_verification():
    """The attempted command rebuilt from history carries the plan's arguments."""
    import hashlib
    import json

    from soc_fixtures import lift_scenario
    from test_replay_scenarios import observed

    from execbound.provider.models import ProviderCommand

    case = lift_scenario(reason="false_positive", incident_status="CLOSED")
    capture = make_capture(case)
    assert capture.decision.effect == "ELIGIBLE"
    assert capture.frozen.intent.arguments.root == {"reason": "false_positive"}
    export = chain_export(observed(capture), (case["bundle"],))
    history = verify_export(export, export.head)
    assert history.complete
    [proof] = [event.terminal_evidence for event in history.events if event.terminal_evidence]
    recorded = json.loads(proof.authenticated_record)["record"]["command"]
    assert recorded["arguments"] == {"reason": "false_positive"}
    # A journal whose arguments differ from the frozen plan is not that plan's evidence.
    tampered = terminal_evidence(capture).model_dump(mode="json")
    signed = json.loads(tampered["authenticated_record"])
    signed["record"]["command"]["arguments"] = {"reason": "remediated"}
    command = ProviderCommand.model_validate_json(json.dumps(signed["record"]["command"]))
    signed["record"]["command_hash"] = command.command_hash
    tampered["authenticated_record"] = json.dumps(signed)
    tampered["proof_digest"] = hashlib.sha256(tampered["authenticated_record"].encode()).hexdigest()
    entries = observed(capture)
    entries[-1] = transition_event(capture, "DISPATCH_COMMITTED", "EXECUTED", evidence=tampered)
    substituted = chain_export(entries, (case["bundle"],))
    with pytest.raises(ReplayValidationError):
        verify_export(substituted, substituted.head)


@pytest.mark.parametrize("change", ["digest", "proof", "reason"])
def test_rehashed_attested_payload_cannot_substitute_an_executors_record(change):
    """The same substitutions as the journal's, against the record an executor signed.

    The retained evidence and the record inside it are two statements, and what ties them
    together is this comparison: the record is checked against the transition and the
    frozen plan, and the evidence is checked against the record. Editing the evidence alone
    leaves the record saying what it always said.
    """
    case = replay_case()
    capture = make_capture(case)
    proof = executor_evidence(capture).model_dump(mode="json")
    if change == "digest":
        proof["proof_digest"] = "d" * 64
    elif change == "proof":
        # The account the evidence names is nowhere in the transition, so the record it
        # was taken from is the only thing that binds it.
        proof["account_id"] = str(uuid4())
    else:
        proof["reason"] = "CANCELLED_NOT_EXECUTED"
        proof["outcome"] = "FAILED_NOT_EXECUTED"
    export = chain_export(
        [
            capture,
            transition_event(
                capture, "DISPATCH_COMMITTED", "EXECUTED", evidence=proof, tier="ATTESTED"
            ),
        ],
        (case["bundle"],),
    )
    with pytest.raises(ReplayValidationError) as refusal:
        verify_export(export, export.head)
    assert refusal.value.code == "INVALID_TERMINAL_EVIDENCE"


@pytest.mark.parametrize("settlement", ["asserted", "attested"])
def test_a_settlement_without_its_authority_capture_is_partial(settlement):
    """Retained evidence whose account nothing in the export binds is flagged, not read past.

    `_bound` compares the operation and both hashes against the transition, and the account
    against the frozen command — which is in the export exactly when the execution's
    authority capture is. A settlement arriving without one is therefore an assertion or a
    record whose account was checked against nothing, and the history says so rather than
    reporting a complete one.

    This holds the property and not the line that produces it. Two conditions in
    `_verified_events` reach the same issue for a settlement like this, and measurement
    says the second subsumes the first: `commands` is a superset of `seen_captures`, so a
    settlement with no frozen command has no capture either, and the issue is appended
    twice. Narrowing the evidence-and-assertion condition leaves this test passing; what
    would fail it is nothing flagging the history at all.
    """
    case = replay_case()
    case["bundle"] = case["bundle"].model_copy(update={"approval_policies": ""})
    capture = make_capture(case)
    if settlement == "asserted":
        spoken = asserted_outcome(capture)
        payload = {"asserted": spoken.model_dump(mode="json"), "tier": "ASSERTED"}
    else:
        proof = executor_evidence(capture)
        payload = {"evidence": proof.model_dump(mode="json"), "tier": "ATTESTED"}
    kind, body = transition_event(capture, "DISPATCH_COMMITTED", "EXECUTED", **payload)
    export = chain_export([(kind, body)], (case["bundle"],), tenant_id=capture.identity.tenant_id)
    history = verify_export(export, export.head)
    assert not history.complete
    assert history.events[0].completeness == "LEGACY"
    assert "MISSING_AUTHORITY_CAPTURE" in history.events[0].issues
