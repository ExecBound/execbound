# SPDX-License-Identifier: AGPL-3.0-only
"""Pure replay comparisons preserve baseline proof and unobserved outcomes."""

import json
from dataclasses import replace
from datetime import timedelta
from uuid import uuid4

import pytest
from replay_fixtures import (
    approved_entries,
    asserted_outcome,
    executor_evidence,
    make_capture,
    make_history,
    replay_case,
    terminal_evidence,
    transition_event,
)
from soc_fixtures import lift_scenario

from execbound.policy.models import ContextSetting, LimitRule, LimitSelector, ProjectedUsage
from execbound.replay.history import index_history
from execbound.replay.report import render_report, report_json
from execbound.replay.simulate import simulate
from execbound.replay.verify import ReplayValidationError
from execbound.resolution.models import plan_hash


def observed(capture, *, terminal="EXECUTED"):
    initial = transition_event(
        capture,
        None,
        "ATTEMPTED",
        frozen=capture.frozen.model_dump(mode="json", exclude={"request"}),
        operation_ref=capture.frozen.request.operation_ref,
        canonical_target_id=str(capture.canonical_target_id),
        bundle_id=str(capture.bundle_id),
    )
    if capture.decision.effect == "DENY":
        return [initial, capture, transition_event(capture, "ATTEMPTED", "DENIED")]
    if capture.decision.effect == "REQUIRE_APPROVAL":
        return [initial, capture]
    result = [
        initial,
        capture,
        transition_event(capture, "ATTEMPTED", "RESERVED", approved=False),
        transition_event(capture, "RESERVED", "DISPATCH_COMMITTED"),
    ]
    if terminal is None:
        result.append(transition_event(capture, "DISPATCH_COMMITTED", "INDETERMINATE"))
    else:
        proof = terminal_evidence(capture, outcome=terminal)
        result.append(
            transition_event(
                capture, "DISPATCH_COMMITTED", proof.outcome, evidence=proof.model_dump(mode="json")
            )
        )
    return result


def next_case(case, *, confirmed=0, seconds=1, same_target=False):
    old = case["resolved"]
    now = case["clock"].now() + timedelta(seconds=seconds)
    target = old.intent.target_id if same_target else uuid4()
    provider_id = old.resource_provider_id if same_target else str(target)
    incident = uuid4()
    identity = replace(case["identity"], expires_at=now + timedelta(hours=1))
    facts = tuple(
        f.model_copy(
            update={
                "source_object_id": str(incident)
                if f.name.startswith("incident_")
                else provider_id,
                "observed_at": now - timedelta(seconds=60),
                "valid_until": now + timedelta(seconds=240),
            }
        )
        for f in old.facts
    )
    frozen = old.model_copy(
        update={
            "intent": old.intent.model_copy(update={"target_id": target}),
            "resource_provider_id": provider_id,
            "facts": facts,
            "resolved_at": now,
            "valid_until": now + timedelta(seconds=240),
            "request": old.request.model_copy(
                update={
                    "target": old.request.target.model_copy(update={"value": str(target)}),
                    "claimed_context": old.request.claimed_context.model_copy(
                        update={"incident_id": incident}
                    ),
                    "idempotency_key": str(uuid4()),
                }
            ),
        }
    )
    usage = case["usage"].model_copy(
        update={
            "counts": tuple(
                ProjectedUsage(
                    rule_id=rule.rule_id,
                    confirmed_targets=confirmed if frozen.intent.action in rule.action_names else 0,
                    unresolved_targets=0,
                )
                for rule in case["bundle"].limits
            )
        }
    )
    return {
        **case,
        "identity": identity,
        "resolved": frozen,
        "usage": usage,
        "clock": type(case["clock"])(now),
    }


@pytest.mark.parametrize(
    "action",
    ["endpoint.isolate", "identity.disable", "identity.enable", "identity.revoke_sessions"],
)
def test_baseline_replays_all_action_contracts_and_deterministic_reports(action):
    case = replay_case(action)
    if action == "identity.enable":
        # A captured custom historical policy lets this case isolate operation accounting.
        case["bundle"] = case["bundle"].model_copy(update={"approval_policies": ""})
    capture = make_capture(case)
    history = make_history(observed(capture), (case["bundle"],))
    report = simulate(history)
    assert report.complete, report.issues
    assert len(report.decisions) == 1
    result = report.decisions[0].baseline
    assert result.effect == "ELIGIBLE" and result.outcome == "EXECUTED"
    assert result.provenance == "RECORDED_GATEWAY_EVIDENCE"
    assert all(count.confirmed_targets == 0 for count in result.counts)
    assert report_json(report) == report_json(simulate(history))
    assert action in render_report(report)


def test_candidate_lower_ceiling_recomputes_previous_charges_without_refunding_baseline():
    case = replay_case()
    first, second = make_capture(case), make_capture(next_case(case, confirmed=1))
    history = make_history([*observed(first), *observed(second)], (case["bundle"],))
    candidate = case["bundle"].model_copy(
        update={
            "bundle_id": uuid4(),
            "limits": tuple(
                rule.model_copy(update={"max_targets": 1}) if rule.scope == "tenant" else rule
                for rule in case["bundle"].limits
            ),
        }
    )
    report = simulate(history, candidate)
    assert report.complete, report.issues
    assert [row.baseline.outcome for row in report.decisions] == ["EXECUTED", "EXECUTED"]
    assert report.decisions[0].candidate.outcome == "EXECUTED"
    assert report.decisions[0].candidate.provenance == "FIXED_HISTORY_PROJECTION"
    assert report.decisions[1].candidate.effect == "DENY"
    assert report.decisions[1].candidate.outcome == "NOT_EXECUTED"
    assert "EFFECT" in report.decisions[1].differences


def test_historical_denial_newly_permitted_creates_unknown_outcome_and_dependent_range():
    case = replay_case()
    case["bundle"] = case["bundle"].model_copy(
        update={"authorization_policies": "forbid(principal, action, resource);"}
    )
    first, second = make_capture(case), make_capture(next_case(case))
    history = make_history([*observed(first), *observed(second)], (case["bundle"],))
    candidate = case["bundle"].model_copy(
        update={
            "bundle_id": uuid4(),
            "authorization_policies": "permit(principal, action, resource);",
            "limits": tuple(
                rule.model_copy(update={"max_targets": 1}) if rule.scope == "tenant" else rule
                for rule in case["bundle"].limits
            ),
        }
    )
    report = simulate(history, candidate)
    assert report.decisions[0].baseline.outcome == "NOT_EXECUTED"
    assert report.decisions[0].candidate.effect == "UNRESOLVED"
    assert "UNOBSERVED_ACTION_OR_TIMING" in report.decisions[0].candidate.reasons
    assert report.decisions[1].candidate.effect == "UNRESOLVED"
    assert "UNCERTAIN_LIMIT" in report.decisions[1].candidate.reasons
    assert first.execution_id in report.decisions[1].candidate.dependencies
    assert any(count.possible_targets == 1 for count in report.decisions[1].candidate.counts)


def test_candidate_new_approval_is_unknown_and_never_reuses_observed_success():
    case = replay_case()
    capture = make_capture(case)
    history = make_history(observed(capture), (case["bundle"],))
    candidate = case["bundle"].model_copy(
        update={
            "bundle_id": uuid4(),
            "approval_policies": "permit(principal, action, resource);",
        }
    )
    result = simulate(history, candidate).decisions[0]
    assert result.baseline.outcome == "EXECUTED"
    assert result.candidate.effect == result.candidate.outcome == "UNRESOLVED"
    assert "UNKNOWN_HUMAN_APPROVAL" in result.candidate.reasons


def test_missing_candidate_contract_and_original_uncertainty_never_infer_success():
    case = replay_case()
    capture = make_capture(case)
    history = make_history(observed(capture, terminal=None), (case["bundle"],))
    candidate = case["bundle"].model_copy(
        update={
            "mappings": tuple(
                mapping.model_copy(update={"mapping_version": "unobserved-v2"})
                for mapping in case["bundle"].mappings
            )
        }
    )
    result = simulate(history, candidate).decisions[0]
    assert result.baseline.outcome == "INDETERMINATE"
    assert result.candidate.effect == result.candidate.outcome == "UNRESOLVED"
    assert "UNSUPPORTED_CANDIDATE_CONTEXT" in result.candidate.reasons


def test_unknown_historical_capture_stays_incomplete():
    case = replay_case()
    capture = make_capture(case)
    history = make_history([observed(capture)[0]], (case["bundle"],))
    report = simulate(history)
    assert not report.complete
    assert report.decisions == ()


@pytest.mark.parametrize(
    "action",
    ["endpoint.isolate", "identity.disable", "identity.enable", "identity.revoke_sessions"],
)
def test_exact_human_approval_chronology_replays_and_counts_total_only(action):
    case = replay_case(action, production=True)
    entries = approved_entries(case)
    following = next_case(case, confirmed=1)
    following["usage"] = following["usage"].model_copy(
        update={
            "counts": tuple(
                count.model_copy(update={"confirmed_targets": 0})
                if rule.budget == "autonomous"
                else count
                for count, rule in zip(
                    following["usage"].counts, case["bundle"].limits, strict=True
                )
            )
        }
    )
    report = simulate(make_history([*entries, *approved_entries(following)], (case["bundle"],)))
    assert report.complete, report.issues
    assert [item.baseline.effect for item in report.decisions[:3]] == [
        "REQUIRE_APPROVAL",
        "ELIGIBLE",
        "ELIGIBLE",
    ]
    assert all(item.baseline.outcome == "EXECUTED" for item in report.decisions[:3])
    for count, rule in zip(
        report.decisions[-1].baseline.counts, case["bundle"].limits, strict=True
    ):
        assert count.confirmed_targets == (
            1 if rule.action == action and rule.budget == "total" else 0
        )


@pytest.mark.parametrize("missing", [3, 4, 6])
def test_proposed_review_or_missing_approval_transition_cannot_authorize_reservation(missing):
    case = replay_case(production=True)
    entries = approved_entries(case)
    del entries[missing]
    report = simulate(make_history(entries, (case["bundle"],)))
    assert not report.complete
    assert report.decisions[-1].baseline.effect == "UNRESOLVED"


@pytest.mark.parametrize(
    "field,value",
    [
        pytest.param("expires_at", "2026-09-14T18:00:00+00:00", id="expires_at"),
        pytest.param("principal_id", str(uuid4()), id="principal_id"),
        pytest.param("bundle_id", str(uuid4()), id="bundle_id"),
        pytest.param("decided_by", str(uuid4()), id="decided_by"),
        pytest.param("decided_credential_id", str(uuid4()), id="decided_credential_id"),
    ],
)
def test_changed_approval_binding_cannot_be_consumed(field, value):
    from execbound.replay.verify import ReplayValidationError

    case = replay_case(production=True)
    entries = approved_entries(case)
    kind, payload = entries[6]
    entries[6] = (kind, {**payload, "binding": {**payload["binding"], field: value}})
    try:
        history = make_history(entries, (case["bundle"],))
    except ReplayValidationError:
        return
    report = simulate(history)
    assert not report.complete
    assert report.decisions[-1].baseline.effect == "UNRESOLVED"


def test_candidate_changed_plan_cannot_reuse_consumed_human_approval():
    case = replay_case(production=True)
    history = make_history(approved_entries(case), (case["bundle"],))
    candidate = case["bundle"].model_copy(update={"bundle_id": uuid4()})
    report = simulate(history, candidate)
    assert report.complete, report.issues
    assert report.decisions[-1].baseline.outcome == "EXECUTED"
    assert report.decisions[-1].candidate.effect == "UNRESOLVED"
    assert "UNKNOWN_HUMAN_APPROVAL" in report.decisions[-1].candidate.reasons


def test_ten_eleven_and_twenty_twenty_one_reconstructed_from_prior_transitions():
    case = replay_case()
    entries = []
    for number in range(21):
        current = next_case(case, confirmed=number, seconds=number)
        current["usage"] = current["usage"].model_copy(
            update={
                "counts": tuple(
                    count.model_copy(update={"confirmed_targets": min(number, 10)})
                    if rule.budget == "autonomous"
                    else count
                    for count, rule in zip(
                        current["usage"].counts, current["bundle"].limits, strict=True
                    )
                )
            }
        )
        if 10 <= number < 20:
            entries.extend(approved_entries(current))
        else:
            entries.extend(observed(make_capture(current)))
    report = simulate(make_history(entries, (case["bundle"],)))
    assert report.complete, report.issues
    assert report.decisions[9].baseline.effect == "ELIGIBLE"
    assert report.decisions[10].baseline.effect == "REQUIRE_APPROVAL"
    assert report.decisions[-1].baseline.effect == "DENY"
    assert "HARD_LIMIT:tenant-total-isolation" in report.decisions[-1].baseline.reasons
    assert [count.confirmed_targets for count in report.decisions[-1].baseline.counts] == [10, 20]


def test_suppressed_success_invalidates_later_snapshot_of_same_target():
    from test_policy_evaluation import change_fact

    case = replay_case()
    first = make_capture(case)
    following = next_case(case, confirmed=1, same_target=True)
    following["resolved"] = change_fact(following["resolved"], "criticality", value=2)
    second = make_capture(following, canonical_target_id=first.canonical_target_id)
    candidate = case["bundle"].model_copy(
        update={
            "bundle_id": uuid4(),
            "authorization_policies": (
                "permit(principal, action, resource) when { resource.criticality == 2 };"
            ),
        }
    )
    report = simulate(
        make_history([*observed(first), *observed(second)], (case["bundle"],)), candidate
    )
    assert report.complete, report.issues
    assert report.decisions[0].candidate.effect == "DENY"
    assert report.decisions[1].candidate.effect == "UNRESOLVED"
    assert "CHANGED_PREREQUISITE" in report.decisions[1].candidate.reasons
    assert report.decisions[1].candidate.dependencies == (first.execution_id,)


def test_unknown_state_change_propagates_but_provable_cedar_denial_still_wins():
    case = replay_case()
    capture = make_capture(case)
    candidate = case["bundle"].model_copy(
        update={"authorization_policies": "forbid(principal, action, resource);"}
    )
    history = make_history([("budget.future_release", {}), *observed(capture)], (case["bundle"],))
    report = simulate(history, candidate)
    assert not report.complete
    assert report.decisions[0].baseline.effect == "UNRESOLVED"
    assert report.decisions[0].candidate.effect == "DENY"
    assert "NOT_AUTHORIZED" in report.decisions[0].candidate.reasons


def test_unknown_approval_from_prior_denial_reserves_possible_impact_for_next_decision():
    case = replay_case()
    case["bundle"] = case["bundle"].model_copy(
        update={"authorization_policies": "forbid(principal, action, resource);"}
    )
    first, second = make_capture(case), make_capture(next_case(case))
    candidate = case["bundle"].model_copy(
        update={
            "bundle_id": uuid4(),
            "authorization_policies": "permit(principal, action, resource);",
            "approval_policies": "permit(principal, action, resource);",
            "limits": tuple(
                rule.model_copy(update={"max_targets": 1}) if rule.scope == "tenant" else rule
                for rule in case["bundle"].limits
            ),
        }
    )
    report = simulate(
        make_history([*observed(first), *observed(second)], (case["bundle"],)), candidate
    )
    assert "UNKNOWN_HUMAN_APPROVAL" in report.decisions[0].candidate.reasons
    assert "UNCERTAIN_LIMIT" in report.decisions[1].candidate.reasons
    assert first.execution_id in report.decisions[1].candidate.dependencies


def test_equal_or_backward_audit_wall_time_does_not_reorder_semantic_decisions():
    from replay_fixtures import chain_export

    from execbound.audit import GENESIS, _event_hash
    from execbound.replay.models import AuditEvent
    from execbound.replay.verify import verify_export

    case = replay_case()
    first, second = make_capture(case), make_capture(next_case(case, confirmed=1))
    export = chain_export([*observed(first), *observed(second)], (case["bundle"],))
    events, previous = [], GENESIS
    for event in export.events:
        row = event.audit_row()
        row.update(
            occurred_at=first.semantic_time - timedelta(seconds=event.sequence // 2),
            previous_hash=previous,
        )
        row["event_hash"] = _event_hash(row)
        events.append(AuditEvent(**row))
        previous = row["event_hash"]
    export = export.model_copy(
        update={
            "events": tuple(events),
            "head": export.head.model_copy(update={"event_hash": previous}),
        }
    )
    report = simulate(verify_export(export, export.head))
    assert report.complete, report.issues
    assert [row.baseline.counts[0].confirmed_targets for row in report.decisions] == [0, 1]


def test_suppressed_indeterminate_dispatch_makes_same_target_busy_denial_counterfactual():
    from test_policy_evaluation import change_fact

    case = replay_case()
    first = make_capture(case)
    following = next_case(case, same_target=True)
    following["resolved"] = change_fact(following["resolved"], "criticality", value=2)
    following["usage"] = following["usage"].model_copy(
        update={
            "counts": tuple(
                count.model_copy(update={"unresolved_targets": 1})
                for count in following["usage"].counts
            )
        }
    )
    second = make_capture(following, canonical_target_id=first.canonical_target_id)
    entries = [
        *observed(first, terminal=None),
        observed(second)[0],
        second,
        transition_event(second, "ATTEMPTED", "DENIED", reason="RESOURCE_BUSY"),
    ]
    history = make_history(entries, (case["bundle"],))
    same = simulate(history, case["bundle"])
    assert same.complete, same.issues
    assert same.decisions[1].candidate.effect == "DENY"
    assert same.decisions[1].candidate.reasons == ("RESOURCE_BUSY",)
    candidate = case["bundle"].model_copy(
        update={
            "bundle_id": uuid4(),
            "authorization_policies": (
                "permit(principal, action, resource) when { resource.criticality == 2 };"
            ),
        }
    )
    changed = simulate(history, candidate)
    assert changed.decisions[1].baseline.outcome == "NOT_EXECUTED"
    assert changed.decisions[1].candidate.effect == "UNRESOLVED"
    assert first.execution_id in changed.decisions[1].candidate.dependencies


def test_candidate_longer_window_recharges_retained_confirmations():
    case = replay_case()
    # Give this fixture equal windows so baseline counts are zero at the next snapshot.
    case["bundle"] = case["bundle"].model_copy(
        update={
            "limits": tuple(
                rule.model_copy(update={"window_seconds": 900}) for rule in case["bundle"].limits
            )
        }
    )
    first, second = make_capture(case), make_capture(next_case(case, seconds=900))
    candidate = case["bundle"].model_copy(
        update={
            "bundle_id": uuid4(),
            "limits": tuple(
                rule.model_copy(
                    update={
                        "rule_id": "replacement-" + str(n),
                        "window_seconds": 901,
                        "max_targets": 1,
                        "on_exceed": "DENY",
                    }
                )
                for n, rule in enumerate(case["bundle"].limits)
            ),
        }
    )
    report = simulate(
        make_history([*observed(first), *observed(second)], (case["bundle"],)), candidate
    )
    assert report.complete, report.issues
    assert all(count.confirmed_targets == 0 for count in report.decisions[1].baseline.counts)
    assert all(count.confirmed_targets == 1 for count in report.decisions[1].candidate.counts)
    assert report.decisions[1].candidate.effect == "DENY"


def test_actual_policy_start_and_finish_samples_preserve_expiry_denial():
    from execbound.policy.evaluate import evaluate
    from execbound.replay.simulate import Samples

    case = replay_case()
    first = make_capture(case)
    finish = case["resolved"].valid_until
    decision = evaluate(**{**case, "clock": Samples(first.semantic_time, finish)})
    capture = first.model_copy(update={"finished_time": finish, "decision": decision})
    history = make_history(observed(capture), (case["bundle"],))
    result = simulate(history).decisions[0].baseline
    assert result.effect == "DENY"
    assert result.reasons == ("INVALID_CONTEXT",)


@pytest.mark.parametrize(
    "corruption",
    ["unbacked_approval", "missing_reservation", "invalid_reservation", "missing_terminal_proof"],
)
def test_invalid_authoritative_history_taints_later_counts_and_candidate_guards(corruption):
    case = replay_case()
    first = make_capture(case)
    entries = observed(first)
    if corruption == "unbacked_approval":
        kind, payload = entries[2]
        entries[2] = (kind, {**payload, "approved": True})
    elif corruption == "missing_reservation":
        del entries[2]
    elif corruption == "invalid_reservation":
        kind, payload = entries[2]
        entries[2] = (kind, {**payload, "from_state": "DENIED"})
    else:
        kind, payload = entries[-1]
        entries[-1] = (kind, {key: value for key, value in payload.items() if key != "evidence"})
    following = next_case(case, confirmed=1)
    following["usage"] = following["usage"].model_copy(
        update={
            "counts": tuple(
                count.model_copy(update={"confirmed_targets": 0})
                if rule.budget == "autonomous"
                else count
                for count, rule in zip(
                    following["usage"].counts, case["bundle"].limits, strict=True
                )
            )
        }
    )
    second = make_capture(following)
    report = simulate(
        make_history([*entries, *observed(second)], (case["bundle"],)), case["bundle"]
    )
    assert not report.complete
    for result in (report.decisions[1].baseline, report.decisions[1].candidate):
        assert result.effect == "UNRESOLVED"
        assert "INCOMPLETE_PRIOR_HISTORY" in result.reasons
        assert first.execution_id in result.dependencies
        assert all(count.confirmed_targets == 0 for count in result.counts)
        assert all(count.possible_targets == 1 for count in result.counts)


def test_invalid_history_does_not_turn_an_untrusted_charge_into_a_proved_hard_denial():
    case = replay_case()
    first = make_capture(case)
    entries = observed(first)
    kind, payload = entries[2]
    entries[2] = (kind, {**payload, "from_state": "DENIED"})
    second = make_capture(next_case(case, confirmed=1))
    candidate = case["bundle"].model_copy(
        update={
            "limits": tuple(
                rule.model_copy(update={"max_targets": 1, "on_exceed": "DENY"})
                for rule in case["bundle"].limits
            )
        }
    )
    report = simulate(make_history([*entries, *observed(second)], (case["bundle"],)), candidate)
    assert report.decisions[1].candidate.effect == "UNRESOLVED"
    assert first.execution_id in report.decisions[1].candidate.dependencies


@pytest.mark.parametrize("mismatch", ["hard_denial", "reason_only"])
def test_recomputed_decision_mismatch_taints_subsequent_retained_history(mismatch):
    from test_policy_evaluation import change_fact

    case = replay_case()
    first_case = case
    if mismatch == "hard_denial":
        first_case = {**case, "resolved": change_fact(case["resolved"], "criticality", value=4)}
    first = make_capture(first_case)
    first = first.model_copy(
        update={
            "decision": first.decision.model_copy(
                update={
                    "effect": "ELIGIBLE",
                    "reasons": () if mismatch == "hard_denial" else ("NOT_AUTHORIZED",),
                }
            )
        }
    )
    second = make_capture(next_case(case, confirmed=1))
    history = make_history([*observed(first), *observed(second)], (case["bundle"],))
    report = simulate(history, case["bundle"])
    assert "RECORDED_DECISION_MISMATCH" in report.decisions[0].baseline.reasons
    later = report.decisions[1]
    assert later.baseline.effect == later.candidate.effect == "UNRESOLVED"
    assert "RECORDED_DECISION_MISMATCH" in report.issues
    assert first.execution_id in later.baseline.dependencies
    assert all(
        count.confirmed_targets == 0 and count.possible_targets == 1
        for count in later.baseline.counts
    )
    assert "INCOMPLETE_PRIOR_HISTORY" in later.baseline.reasons
    assert "INCOMPLETE_PRIOR_HISTORY" in later.candidate.reasons


def candidate_with_max_age(case, max_age):
    setting = ContextSetting(
        context_contract_version="endpoint-isolation.v1",
        source_kind="inventory",
        max_age_seconds=max_age,
        permitted_writers=("inventory_sync",),
    )
    return case["bundle"].model_copy(update={"bundle_id": uuid4(), "context_settings": (setting,)})


@pytest.mark.parametrize("max_age,effect", [(120, "DENY"), (900, "ELIGIBLE")])
def test_candidate_context_max_age_bounds_frozen_history(max_age, effect):
    case = replay_case()
    history = make_history(observed(make_capture(case)), (case["bundle"],))
    result = simulate(history, candidate_with_max_age(case, max_age)).decisions[0]
    assert result.baseline.effect == "ELIGIBLE"
    assert result.candidate.effect == effect


def test_candidate_longer_max_age_cannot_extend_expired_frozen_validity():
    case = replay_case()
    fact = case["resolved"].fact("environment")
    assert fact.valid_until == fact.observed_at + timedelta(seconds=300)
    # The recorded decision is the real result at a semantic time after frozen validity.
    late = {**case, "clock": type(case["clock"])(fact.observed_at + timedelta(seconds=301))}
    capture = make_capture(late)
    assert capture.decision.plan_hash is None
    # Admission records the frozen plan hash even when evaluation denies before binding it.
    entries = observed(capture)
    assert entries[0][1]["plan_hash"] == plan_hash(capture.frozen, case["bundle"].security_versions)
    history = make_history(entries, (case["bundle"],))
    candidate = case["bundle"].model_copy(
        update={
            "bundle_id": uuid4(),
            "context_settings": tuple(
                ContextSetting(
                    context_contract_version="endpoint-isolation.v1",
                    source_kind=kind,
                    max_age_seconds=3600,
                    permitted_writers=writers,
                )
                for kind, writers in (
                    ("incident", ("soc_analyst",)),
                    ("inventory", ("inventory_sync",)),
                )
            ),
        }
    )
    report = simulate(history, candidate)
    assert report.complete, report.issues
    result = report.decisions[0]
    assert result.baseline.effect == "DENY" and result.baseline.reasons == ("INVALID_CONTEXT",)
    assert result.candidate.effect == "DENY"
    assert "INVALID_CONTEXT" in result.candidate.reasons


def test_candidate_context_settings_above_ceiling_are_invalid():
    case = replay_case()
    history = make_history(observed(make_capture(case)), (case["bundle"],))
    result = simulate(history, candidate_with_max_age(case, 3601)).decisions[0]
    assert result.candidate.effect == "DENY"
    assert "POLICY_ERROR" in result.candidate.reasons


def test_candidate_can_forbid_lift_isolation_by_argument():
    case = lift_scenario(reason="remediated", incident_status="CLOSED")
    capture = make_capture(case)
    assert capture.decision.effect == "REQUIRE_APPROVAL"
    history = make_history(observed(capture), (case["bundle"],))
    forbid = (
        '\nforbid(principal, action == ExecBound::Action::"endpoint.lift_isolation", resource)\n'
        'when { context.arguments.reason == "remediated" };\n'
    )
    candidate = case["bundle"].model_copy(
        update={
            "bundle_id": uuid4(),
            "authorization_policies": case["bundle"].authorization_policies + forbid,
        }
    )
    report = simulate(history, candidate)
    row = report.decisions[0]
    assert row.recorded_effect == "REQUIRE_APPROVAL"
    assert row.candidate.effect == "DENY" and "EFFECT" in row.differences
    assert row.arguments.root == {"reason": "remediated"}
    assert json.loads(report_json(report))["decisions"][0]["arguments"] == {"reason": "remediated"}
    assert "Arguments: reason=remediated" in render_report(report)
    baseline = simulate(history)
    assert "arguments" in json.loads(report_json(baseline))["decisions"][0]
    isolate = replay_case()
    isolate_history = make_history(observed(make_capture(isolate)), (isolate["bundle"],))
    isolate_report = simulate(isolate_history)
    assert "arguments" not in json.loads(report_json(isolate_report))["decisions"][0]


def limit(**changes):
    """A ceiling of one isolation, denied when exceeded, qualified by ``changes``."""
    return LimitRule(
        **{
            "rule_id": "scoped",
            "action": "endpoint.isolate",
            "scope": "principal",
            "window_seconds": 3600,
            "max_targets": 1,
            "budget": "total",
            "on_exceed": "DENY",
            **changes,
        }
    )


def with_limits(case, *rules):
    """A candidate keeping the original rules beside ``rules``, as a new bundle."""
    return case["bundle"].model_copy(
        update={"bundle_id": uuid4(), "limits": (*case["bundle"].limits, *rules)}
    )


def sequence(case, *memberships):
    """Consecutive isolations one second apart, each capture recording its membership."""
    captures = [make_capture(case, groups=memberships[0])]
    for number, groups in enumerate(memberships[1:], start=1):
        following = next_case(case, confirmed=number, seconds=number)
        captures.append(make_capture(following, groups=groups))
    return captures


def executed(*captures, case):
    return make_history(
        [entry for capture in captures for entry in observed(capture)], (case["bundle"],)
    )


def count(result, rule_id):
    return next(
        (item.confirmed_targets, item.unresolved_targets)
        for item in result.counts
        if item.rule_id == rule_id
    )


def test_sl9_candidate_group_rule_counts_captured_membership_like_the_kernel():
    case = replay_case()
    squad = uuid4()
    # Two isolations as a member, then one after leaving the group, all executed.
    member, again, leaver = sequence(case, (squad,), (squad,), ())
    history = executed(member, again, leaver, case=case)
    candidate = with_limits(case, limit(rule_id="squad", scope="group", group_id=squad))
    report = simulate(history, candidate)
    assert report.complete, report.issues
    assert [row.baseline.effect for row in report.decisions] == ["ELIGIBLE"] * 3
    assert all(row.baseline.outcome == "EXECUTED" for row in report.decisions)
    first, second, third = (row.candidate for row in report.decisions)
    # The first isolation is within the group ceiling and reproduces the baseline.
    assert first.effect == "ELIGIBLE" and first.outcome == "EXECUTED"
    assert first.provenance == "FIXED_HISTORY_PROJECTION" and count(first, "squad") == (0, 0)
    # The second is the group's second unit: denied on the retained membership alone.
    assert second.effect == "DENY" and second.reasons == ("HARD_LIMIT:squad",)
    assert second.outcome == "NOT_EXECUTED" and count(second, "squad") == (1, 0)
    assert "EFFECT" in report.decisions[1].differences
    # The leaver is outside the scope: the group's count is still one, and the rule
    # neither charges nor caps an isolation its retained membership does not cover.
    assert third.effect == "ELIGIBLE" and third.outcome == "EXECUTED"
    assert count(third, "squad") == (1, 0)
    assert all("UNKNOWN_GROUP_MEMBERSHIP" not in row.candidate.reasons for row in report.decisions)
    assert report_json(report) == report_json(simulate(history, candidate))


def test_sl9_legacy_captures_make_a_candidate_group_rule_unknown_and_keep_the_baseline():
    case = replay_case()
    squad = uuid4()
    first, second = sequence(case, None, None)
    history = executed(first, second, case=case)
    candidate = with_limits(case, limit(rule_id="squad", scope="group", group_id=squad))
    report = simulate(history, candidate)
    # The baseline reproduces the kernel's decisions, which counted no membership either.
    assert report.complete, report.issues
    for row in report.decisions:
        assert row.baseline.effect == row.recorded_effect == "ELIGIBLE"
        assert row.baseline.outcome == "EXECUTED"
        assert "UNKNOWN_GROUP_MEMBERSHIP" not in row.baseline.reasons
        # The candidate cannot tell whether its rule applied, and the units it could not
        # count are never room in the budget: unresolved, not assumed eligible.
        assert row.candidate.effect == row.candidate.outcome == "UNRESOLVED"
        assert "UNKNOWN_GROUP_MEMBERSHIP" in row.candidate.reasons
        assert count(row.candidate, "squad") == (0, 0)
        assert "EFFECT" in row.differences
    assert "UNKNOWN_GROUP_MEMBERSHIP" in render_report(report)
    assert report_json(report) == report_json(simulate(history, candidate))
    # The same captures are certain for a candidate without a group rule.
    plain = simulate(history, with_limits(case, limit(rule_id="wide", max_targets=5)))
    assert plain.complete, plain.issues
    assert all(row.candidate.effect == "ELIGIBLE" for row in plain.decisions)
    assert count(plain.decisions[1].candidate, "wide") == (1, 0)


def test_sl9_unknown_membership_of_a_retained_unit_is_a_lower_bound_not_room():
    case = replay_case()
    squad = uuid4()
    legacy, member, outsider = sequence(case, None, (squad,), ())
    history = executed(legacy, member, outsider, case=case)
    report = simulate(
        history, with_limits(case, limit(rule_id="squad", scope="group", group_id=squad))
    )
    assert report.complete, report.issues
    first, second, third = (row.candidate for row in report.decisions)
    assert first.effect == "UNRESOLVED" and "UNKNOWN_GROUP_MEMBERSHIP" in first.reasons
    # The member's isolation could not count the legacy unit, so its zero is a lower
    # bound and is not taken as room under the ceiling of one.
    assert second.effect == "UNRESOLVED" and "UNKNOWN_GROUP_MEMBERSHIP" in second.reasons
    assert count(second, "squad") == (0, 0)
    # A non-member is outside the rule, so the unknown membership does not concern it.
    assert third.effect == "ELIGIBLE" and third.outcome == "EXECUTED"
    assert "UNKNOWN_GROUP_MEMBERSHIP" not in third.reasons


def test_sl9_lower_bound_denial_stands_over_a_legacy_unit():
    case = replay_case()
    squad = uuid4()
    # A member's isolation executes, a legacy unit is retained, then the member asks again.
    member, legacy, again = sequence(case, (squad,), None, (squad,))
    history = executed(member, legacy, again, case=case)
    candidate = with_limits(case, limit(rule_id="squad", scope="group", group_id=squad))
    report = simulate(history, candidate)
    assert report.complete, report.issues
    first, second, third = (row.candidate for row in report.decisions)
    assert first.effect == "ELIGIBLE" and first.outcome == "EXECUTED"
    assert second.effect == "UNRESOLVED" and "UNKNOWN_GROUP_MEMBERSHIP" in second.reasons
    # The member's own first unit already fills the ceiling of one. The legacy unit could
    # only raise that count, so the denial at the lower bound stands with nothing unknown.
    assert third.effect == "DENY" and third.reasons == ("HARD_LIMIT:squad",)
    assert third.outcome == "NOT_EXECUTED" and count(third, "squad") == (1, 0)
    assert report_json(report) == report_json(simulate(history, candidate))


def test_sl9_account_and_selector_candidates_reconstruct_retained_attributes():
    from test_policy_evaluation import change_fact

    case = replay_case()
    account = case["resolved"].intent.account_id
    first = make_capture(case)
    elevated = next_case(case, confirmed=1)
    elevated["resolved"] = change_fact(elevated["resolved"], "criticality", value=2)
    second = make_capture(elevated)
    third = make_capture(next_case(case, confirmed=2, seconds=2))
    history = executed(first, second, third, case=case)
    candidate = with_limits(
        case,
        limit(rule_id="mine", scope="account", account_id=account),
        limit(rule_id="elsewhere", scope="account", account_id=uuid4()),
        limit(
            rule_id="routine",
            scope="selector",
            selector=LimitSelector(fact="criticality", equals=1),
        ),
    )
    report = simulate(history, candidate)
    assert report.complete, report.issues
    assert [row.baseline.effect for row in report.decisions] == ["ELIGIBLE"] * 3
    results = [row.candidate for row in report.decisions]
    assert [result.effect for result in results] == ["ELIGIBLE", "DENY", "DENY"]
    # The second isolation is the account's second unit. Its criticality of two is outside
    # the selector, which counts the first unit but neither charges nor caps this one.
    assert results[1].reasons == ("HARD_LIMIT:mine",)
    assert count(results[1], "mine") == (1, 0) and count(results[1], "routine") == (1, 0)
    # The third, at criticality one again, exceeds both: the denied second unit was never
    # charged, so each count is still the first unit alone.
    assert results[2].reasons == ("HARD_LIMIT:mine", "HARD_LIMIT:routine")
    assert count(results[2], "mine") == (1, 0) and count(results[2], "routine") == (1, 0)
    # Another account's rule counts nothing here: every unit retains the frozen account.
    assert all(count(result, "elsewhere") == (0, 0) for result in results)
    assert all("UNKNOWN_GROUP_MEMBERSHIP" not in result.reasons for result in results)
    assert report_json(report) == report_json(simulate(history, candidate))


@pytest.mark.parametrize(
    "rule",
    [
        pytest.param(
            limit(scope="selector", selector=LimitSelector(fact="owner", equals="soc")),
            id="fact_no_contract_carries",
        ),
        pytest.param(
            limit(scope="selector", selector=LimitSelector(fact="criticality", equals="high")),
            id="value_outside_the_domain",
        ),
        pytest.param(limit(actions=("endpoint.isolate", "endpoint.unplug")), id="unknown_action"),
    ],
)
def test_sl9_candidate_rule_the_catalog_cannot_serve_is_a_policy_error(rule):
    case = replay_case()
    history = make_history(observed(make_capture(case)), (case["bundle"],))
    result = simulate(history, with_limits(case, rule)).decisions[0]
    assert result.baseline.effect == "ELIGIBLE"
    assert result.candidate.effect == "DENY" and result.candidate.reasons == ("POLICY_ERROR",)


# A checkpoint is an execution ExecBound decided and did not dispatch, so its history is
# the ordinary one up to DISPATCH_COMMITTED and differs only in what settles it: an
# executor's signed record at tier ATTESTED, the executor's bare word at tier ASSERTED, or
# nothing at all while the grant is outstanding.


def refused(entries, bundle):
    with pytest.raises(ReplayValidationError) as refusal:
        make_history(entries, (bundle,))
    return refusal.value.code


def gate_case():
    case = replay_case()
    case["bundle"] = case["bundle"].model_copy(update={"approval_policies": ""})
    return case, make_capture(case)


def gate_entries(capture, settlement, **evidence):
    """One checkpoint's recorded history, ending in ``settlement``.

    ``settlement`` is the transition the report leaves behind — a settled state with its
    retained evidence, INDETERMINATE for an assertion that settles nothing, or None for a
    grant nobody has reported.
    """
    entries = [
        transition_event(
            capture,
            None,
            "ATTEMPTED",
            frozen=capture.frozen.model_dump(mode="json", exclude={"request"}),
            canonical_target_id=str(capture.canonical_target_id),
            bundle_id=str(capture.bundle_id),
        ),
        capture,
        transition_event(capture, "ATTEMPTED", "RESERVED", approved=False),
        transition_event(capture, "RESERVED", "DISPATCH_COMMITTED"),
    ]
    if settlement is not None:
        entries.append(transition_event(capture, "DISPATCH_COMMITTED", settlement, **evidence))
    return entries


def attested_entries(capture, *, outcome="EXECUTED", **changes):
    proof = executor_evidence(capture, outcome=outcome)
    state = "STALE_AUTHORIZATION" if outcome == "VERSION_MISMATCH" else proof.outcome
    payload = {"evidence": proof.model_dump(mode="json"), "tier": "ATTESTED", **changes}
    return gate_entries(capture, state, **payload)


def asserted_entries(capture, *, outcome="EXECUTED", **changes):
    spoken = asserted_outcome(capture, outcome=outcome)
    settled = spoken.outcome == "EXECUTED"
    payload = {"asserted": spoken.model_dump(mode="json"), **changes}
    if settled and "tier" not in changes:
        payload["tier"] = "ASSERTED"
    return gate_entries(capture, "EXECUTED" if settled else "INDETERMINATE", **payload)


def test_an_attested_checkpoint_replays_from_the_executors_own_envelope():
    # The blocker in one history: the retained record is a SignedOutcome and parsing it as
    # a provider journal is what made verification raise, which ended the tenant's export.
    case, capture = gate_case()
    history = make_history(attested_entries(capture), (case["bundle"],))
    assert history.complete, history.issues
    settlement = history.events[-1]
    assert settlement.settlement_tier == "ATTESTED"
    assert settlement.terminal_evidence is not None
    assert settlement.asserted_outcome is None
    report = simulate(history)
    assert report.complete, report.issues
    (decision,) = report.decisions
    assert decision.baseline.outcome == "EXECUTED"
    assert decision.baseline.provenance == "RECORDED_EXECUTOR_EVIDENCE"
    assert decision.settlement_tier == "ATTESTED"
    assert "ATTESTED" in render_report(report)


def test_an_attested_version_mismatch_settles_stale_authority_at_its_tier():
    # The precondition the plan froze failed at the vendor and the executor signed that it
    # did: a settlement, at the tier its evidence supports, of an action nobody performed.
    case, capture = gate_case()
    history = make_history(attested_entries(capture, outcome="VERSION_MISMATCH"), (case["bundle"],))
    assert history.complete, history.issues
    report = simulate(history)
    assert report.complete, report.issues
    (decision,) = report.decisions
    assert decision.baseline.outcome == "FAILED_NOT_EXECUTED"
    assert decision.baseline.provenance == "RECORDED_EXECUTOR_EVIDENCE"
    assert decision.settlement_tier == "ATTESTED"


def test_an_asserted_settlement_is_a_recorded_transition_and_never_gateway_evidence():
    case, capture = gate_case()
    history = make_history(asserted_entries(capture), (case["bundle"],))
    assert history.complete, history.issues
    settlement = history.events[-1]
    assert settlement.terminal_evidence is None
    assert settlement.asserted_outcome is not None
    assert settlement.settlement_tier == "ASSERTED"
    index = index_history(history)
    (row,) = index.executions.values()
    # Nothing an executor said is verification, and a settled assertion is not missing its
    # evidence either: the assertion is the record, and the tier is what says so.
    assert row.terminal_verified is False
    assert row.settlement_tier == "ASSERTED"
    assert row.issues == set()
    report = simulate(history)
    assert report.complete, report.issues
    (decision,) = report.decisions
    assert decision.baseline.outcome == "EXECUTED"
    assert decision.baseline.provenance == "RECORDED_TRANSITION"
    assert decision.settlement_tier == "ASSERTED"
    assert "ASSERTED" in render_report(report)
    assert report_json(simulate(history)) == report_json(report)


@pytest.mark.parametrize("outcome", ["CANCELLED_NOT_EXECUTED", "VERSION_MISMATCH"])
def test_an_assertion_that_settles_nothing_replays_as_retained_uncertainty(outcome):
    case, capture = gate_case()
    history = make_history(asserted_entries(capture, outcome=outcome), (case["bundle"],))
    assert history.complete, history.issues
    assert history.events[-1].settlement_tier is None
    report = simulate(history)
    assert report.complete, report.issues
    (decision,) = report.decisions
    assert decision.baseline.outcome == "INDETERMINATE"
    assert decision.baseline.provenance == "RECORDED_TRANSITION"
    assert decision.settlement_tier is None


def test_an_unreported_grant_replays_as_retained_uncertainty():
    case, capture = gate_case()
    history = make_history(gate_entries(capture, None), (case["bundle"],))
    assert history.complete, history.issues
    report = simulate(history)
    assert report.complete, report.issues
    (decision,) = report.decisions
    assert decision.baseline.outcome == "INDETERMINATE"
    assert decision.baseline.provenance == "RECORDED_TRANSITION"
    assert decision.settlement_tier is None


def test_a_settlements_retained_record_must_be_the_envelope_its_tier_names():
    # The tier is read before either envelope is parsed, so each is refused as the other:
    # a provider journal under ATTESTED, and an executor's record under no tier at all.
    case, capture = gate_case()
    journal = terminal_evidence(capture).model_dump(mode="json")
    assert (
        refused(
            gate_entries(capture, "EXECUTED", evidence=journal, tier="ATTESTED"), case["bundle"]
        )
        == "INVALID_EXPORT"
    )
    executor = executor_evidence(capture).model_dump(mode="json")
    assert refused(gate_entries(capture, "EXECUTED", evidence=executor), case["bundle"]) == (
        "INVALID_EXPORT"
    )


def test_a_settlement_names_one_kind_of_evidence_and_a_tier_names_evidence():
    case, capture = gate_case()
    proof = executor_evidence(capture).model_dump(mode="json")
    spoken = asserted_outcome(capture).model_dump(mode="json")
    assert (
        refused(
            gate_entries(capture, "EXECUTED", evidence=proof, asserted=spoken, tier="ATTESTED"),
            case["bundle"],
        )
        == "INVALID_TERMINAL_EVIDENCE"
    )
    assert (
        refused(gate_entries(capture, "EXECUTED", tier="ASSERTED"), case["bundle"])
        == "INVALID_SETTLEMENT_TIER"
    )
    assert (
        refused(gate_entries(capture, "EXECUTED", evidence=proof, tier="PROVEN"), case["bundle"])
        == "INVALID_SETTLEMENT_TIER"
    )
    # A journal under the tier that means the executor's bare word: refused as the pairing
    # it breaks, rather than verified as a journal and then reported as unverifiable.
    journal = terminal_evidence(capture).model_dump(mode="json")
    assert (
        refused(
            gate_entries(capture, "EXECUTED", evidence=journal, tier="ASSERTED"), case["bundle"]
        )
        == "INVALID_SETTLEMENT_TIER"
    )
    assert (
        refused(gate_entries(capture, "EXECUTED", asserted=spoken, tier="ATTESTED"), case["bundle"])
        == "INVALID_SETTLEMENT_TIER"
    )
    # An executor's own envelope retained under the tier that means a provider's journal:
    # `_terminal` routes PROVIDER_VERIFIED straight to `_journal`, which tries to parse it
    # as a `SignedJournal` and fails, since neither model's fields align with the other's.
    assert (
        refused(
            gate_entries(capture, "EXECUTED", evidence=proof, tier="PROVIDER_VERIFIED"),
            case["bundle"],
        )
        == "INVALID_EXPORT"
    )
    # The executor's bare word under the tier that means a provider's journal: the widened
    # `_settlement` guard refuses PROVIDER_VERIFIED beside an `asserted` payload exactly as
    # it already refused ATTESTED beside one.
    assert (
        refused(
            gate_entries(capture, "EXECUTED", asserted=spoken, tier="PROVIDER_VERIFIED"),
            case["bundle"],
        )
        == "INVALID_SETTLEMENT_TIER"
    )


def test_an_assertion_never_settles_a_non_execution_in_a_replayed_history():
    # The assertion rule of `docs/CHECKPOINT.md` ("What each report settles"), over untrusted
    # bytes: a history claiming that the executor's bare word settled a non-execution is
    # claiming a refund nothing in the kernel writes.
    case, capture = gate_case()
    spoken = asserted_outcome(capture, outcome="CANCELLED_NOT_EXECUTED").model_dump(mode="json")
    assert (
        refused(
            gate_entries(capture, "FAILED_NOT_EXECUTED", asserted=spoken, tier="ASSERTED"),
            case["bundle"],
        )
        == "INVALID_ASSERTED_SETTLEMENT"
    )
    executed = asserted_outcome(capture).model_dump(mode="json")
    assert (
        refused(
            gate_entries(capture, "INDETERMINATE", asserted=executed, tier="ASSERTED"),
            case["bundle"],
        )
        == "INVALID_TERMINAL_STATE"
    )


@pytest.mark.parametrize("field", ["operation_id", "account_id", "intent_hash", "plan_hash"])
def test_retained_evidence_of_either_tier_must_name_the_authorized_operation(field):
    case, capture = gate_case()
    other = {
        "operation_id": uuid4(),
        "account_id": uuid4(),
        "intent_hash": "c" * 64,
        "plan_hash": "d" * 64,
    }[field]
    spoken = asserted_outcome(capture, **{field: other}).model_dump(mode="json")
    assert (
        refused(gate_entries(capture, "EXECUTED", asserted=spoken, tier="ASSERTED"), case["bundle"])
        == "INVALID_ASSERTED_OUTCOME"
    )
    proof = executor_evidence(capture, **{field: other}).model_dump(mode="json")
    assert (
        refused(gate_entries(capture, "EXECUTED", evidence=proof, tier="ATTESTED"), case["bundle"])
        == "INVALID_TERMINAL_EVIDENCE"
    )


def test_a_report_of_an_operation_execbound_dispatched_names_no_tier():
    # The byte-compatibility half: a tier is a statement about an external executor's word,
    # so every report of the path ExecBound dispatches carries no such key at all.
    case, capture = gate_case()
    history = make_history(observed(capture), (case["bundle"],))
    report = simulate(history)
    assert report.complete, report.issues
    (decision,) = json.loads(report_json(report))["decisions"]
    assert "settlement_tier" not in decision
    assert decision["baseline"]["provenance"] == "RECORDED_GATEWAY_EVIDENCE"
    assert "ATTESTED" not in render_report(report)


def test_an_asserted_settlement_charges_the_same_unit_the_kernel_charged():
    """The direction of the asserted settlement, which only a later decision can see.

    The ledger settles an assertion as an execution, because the kernel confirms that
    impact and a replay that counted it as a non-execution would count the tenant's history
    differently from the store and make every later decision in that tenant contradict its
    recorded one. Settled at all is not the property: a non-execution is settled too and
    counts nothing, so the second decision here reads the confirmed count the kernel
    recorded, and a candidate ceiling of one is what the difference costs.
    """
    case, first = gate_case()
    second = make_capture(next_case(case, confirmed=1))
    history = make_history([*asserted_entries(first), *observed(second)], (case["bundle"],))
    assert history.complete, history.issues
    report = simulate(history)
    assert report.complete, report.issues
    assert [row.settlement_tier for row in report.decisions] == ["ASSERTED", None]
    later = report.decisions[-1].baseline
    assert later.effect == "ELIGIBLE"
    assert [(item.confirmed_targets, item.unresolved_targets) for item in later.counts] == [
        (1, 0),
        (1, 0),
    ]
    # The same unit under a candidate ceiling of one: the assertion fills it, so the later
    # decision is denied. A refund in replay's ledger would leave it eligible.
    alternative = simulate(history, with_limits(case, limit()))
    assert alternative.complete, alternative.issues
    proposed = alternative.decisions[-1].candidate
    assert proposed.effect == "DENY" and proposed.reasons == ("HARD_LIMIT:scoped",)
    assert count(proposed, "scoped") == (1, 0)


def test_a_report_naming_a_tier_says_what_offline_replay_did_not_check():
    """The limitation the tier owes an operator, and the bytes it may not move.

    `RECORDED_EXECUTOR_EVIDENCE` reports a settlement the provider line does not describe:
    that line names the HMAC ExecBound does not load, and an attested checkpoint rests on
    an Ed25519 signature ExecBound checked once, at settlement, against a key no export
    carries. A fourth unconditional entry would move every existing report's bytes, so it
    is attached to the same fact the tier is.
    """
    case, capture = gate_case()
    ordinary = simulate(make_history(observed(capture), (case["bundle"],)))
    assert len(ordinary.limitations) == 3
    assert not any("executor" in line for line in ordinary.limitations)
    for entries in (attested_entries(capture), asserted_entries(capture)):
        report = simulate(make_history(entries, (case["bundle"],)))
        assert report.complete, report.issues
        assert report.limitations[:3] == ordinary.limitations
        assert "no executor public keys are loaded" in report.limitations[3]
        assert report.limitations[3] in render_report(report)
    # An assertion that settled nothing names no tier and claims no evidence, so it keeps
    # the three lines and the bytes every report before this work had.
    uncertain = simulate(
        make_history(asserted_entries(capture, outcome="CANCELLED_NOT_EXECUTED"), (case["bundle"],))
    )
    assert uncertain.limitations == ordinary.limitations
