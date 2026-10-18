# SPDX-License-Identifier: AGPL-3.0-only
"""Replay policy against recorded history using independent in-memory ledgers."""

from dataclasses import dataclass
from datetime import datetime
from typing import Any
from uuid import UUID

from execbound.contracts import (
    PRODUCTION_CATALOG,
    Catalog,
    validate_bundle_contracts,
    validate_selector,
)
from execbound.execution.models import AssertedOutcome, TerminalEvidence
from execbound.policy.cedar import validate_policy_sets
from execbound.policy.evaluate import evaluate
from execbound.policy.models import BundleContent, PolicyEvaluation, UsageSnapshot
from execbound.replay.history import ExecutionHistory, execution_id, index_history
from execbound.replay.ledger import Ledger
from execbound.replay.models import DecisionCapture, VerifiedHistory
from execbound.replay.report import (
    DecisionComparison,
    EvaluationResult,
    ReplayReport,
    RuleCount,
    limitations,
)
from execbound.replay.verify import ReplayValidationError, verify_export
from execbound.resolution.models import ResolvedRequest, scalar_facts
from execbound.signals.replay import SignalEvidenceUnavailable, rederive, unknown_facts


@dataclass
class Samples:
    start: datetime
    finish: datetime
    sampled: bool = False

    def now(self) -> datetime:
        value = self.finish if self.sampled else self.start
        self.sampled = True
        return value


def _counts(lower: UsageSnapshot, upper: UsageSnapshot) -> tuple[RuleCount, ...]:
    return tuple(
        RuleCount(
            rule_id=low.rule_id,
            confirmed_targets=low.confirmed_targets,
            unresolved_targets=low.unresolved_targets,
            possible_targets=high.unresolved_targets - low.unresolved_targets,
        )
        for low, high in zip(lower.counts, upper.counts, strict=True)
    )


def _attributes(
    captured: DecisionCapture, plan: ResolvedRequest | None, catalog: Catalog
) -> dict[str, Any]:
    """The scope attributes of one unit, from its captured identity and one reading of its plan.

    The baseline ledger passes the recorded plan. The what-if ledger passes the candidate's
    reading of it, because the kernel under the candidate would have retained the unit with
    that reading, or None when the plan does not carry what that reading needs: the unit's
    signal facts are then unknown, and no selector over one of them counts it.
    """
    unknown = unknown_facts(captured.frozen, catalog) if plan is None else frozenset()
    facts = scalar_facts(captured.frozen if plan is None else plan)
    return {
        "account_id": captured.frozen.intent.account_id,
        "facts": {name: value for name, value in facts.items() if name not in unknown},
        "groups": captured.identity.groups,
        "space_id": captured.identity.space,
        "unknown_facts": unknown,
    }


def _evaluate(
    capture: DecisionCapture,
    bundle: BundleContent,
    usage: UsageSnapshot,
    catalog: Catalog,
    resolved: ResolvedRequest | None = None,
) -> PolicyEvaluation:
    approval = capture.approval
    same_plan = bundle.content_hash == capture.decision.content_hash
    return evaluate(
        bundle=bundle,
        identity=capture.identity.to_identity(),
        resolved=resolved if resolved is not None else capture.frozen,
        usage=usage,
        clock=Samples(capture.semantic_time, capture.finished_time),
        approval=approval.to_verified_approval() if approval is not None and same_plan else None,
        catalog=catalog,
    )


def _result(decision: PolicyEvaluation, counts: tuple[RuleCount, ...]) -> EvaluationResult:
    return EvaluationResult(
        effect=decision.effect,
        reasons=decision.reasons,
        obligation_ids=decision.obligation_ids,
        bundle_id=decision.bundle_id,
        content_hash=decision.content_hash,
        plan_hash=decision.plan_hash,
        counts=counts,
    )


def _unknown(
    result: EvaluationResult, reason: str, dependencies: tuple[UUID, ...] = ()
) -> EvaluationResult:
    return result.model_copy(
        update={
            "effect": "UNRESOLVED",
            "reasons": tuple(sorted(set((*result.reasons, reason)))),
            "dependencies": tuple(sorted(set((*result.dependencies, *dependencies)), key=str)),
            "outcome": "UNRESOLVED",
            "provenance": "UNKNOWN",
        }
    )


def _verified_provenance(row: ExecutionHistory) -> str:
    """Which kind of verified evidence settled this execution, kept apart in the report.

    A provider's journal is the gateway's record of what the provider's own API answered,
    made by a different party from the one whose budget is at stake. What it carries beyond
    that varies with the reason it states, and this function sees more reasons than the
    executed one: `JournalRecord.consistent` requires one mutation and a resulting version
    differing from the expected one for EXECUTED, no mutation and such a version for
    VERSION_MISMATCH, and no mutation and no resulting version at all for
    CANCELLED_NOT_EXECUTED and TARGET_NOT_FOUND — and those two settle FAILED_NOT_EXECUTED,
    which arrives here through the branch above. The recording party is what all four have
    in common.

    An executor's record is an authenticated statement about an action ExecBound never
    dispatched: it says who spoke, and never that the vendor did anything. Reporting the
    second as the first would be the overclaim the tiers exist to prevent, so an attested
    checkpoint carries its own provenance.

    A provider-verified checkpoint is settled from the same `SignedJournal` a dispatched
    operation's settlement carries, but the party who recorded it is the provider acting for
    an external executor rather than ExecBound's own gateway, so it keeps its own provenance
    apart from `RECORDED_GATEWAY_EVIDENCE` too.
    """
    if row.settlement_tier == "ATTESTED":
        return "RECORDED_EXECUTOR_EVIDENCE"
    if row.settlement_tier == "PROVIDER_VERIFIED":
        return "RECORDED_PROVIDER_EVIDENCE"
    return "RECORDED_GATEWAY_EVIDENCE"


def _outcome(
    result: EvaluationResult, row: ExecutionHistory, *, candidate: bool = False
) -> EvaluationResult:
    if result.effect == "UNRESOLVED":
        return result
    if row.observed:
        # Nothing ran through the gateway either way; the decision is the whole record.
        return result.model_copy(
            update={"outcome": "OBSERVED", "provenance": "RECORDED_TRANSITION"}
        )
    if row.state in {"EXECUTED", "FAILED_NOT_EXECUTED"} and row.terminal_verified:
        outcome = row.state
        provenance = "FIXED_HISTORY_PROJECTION" if candidate else _verified_provenance(row)
    elif row.state == "STALE_AUTHORIZATION" and row.terminal_verified:
        outcome = "FAILED_NOT_EXECUTED"
        provenance = "FIXED_HISTORY_PROJECTION" if candidate else _verified_provenance(row)
    elif row.state == "EXECUTED" and row.settlement_tier == "ASSERTED":
        # The executor's word, which ExecBound charged the budget on and could not check.
        # It is the recorded transition it is, never gateway evidence and never proof.
        outcome = "EXECUTED"
        provenance = "FIXED_HISTORY_PROJECTION" if candidate else "RECORDED_TRANSITION"
    elif row.state == "FAILED_EFFECT_UNKNOWN" and row.settlement_tier == "ASSERTED":
        # The same word, stating that the call did not succeed and saying nothing about
        # whether the vendor acted. Reported as the state it is rather than as either
        # EXECUTED or FAILED_NOT_EXECUTED, both of which would claim what it does not.
        outcome = "FAILED_EFFECT_UNKNOWN"
        provenance = "FIXED_HISTORY_PROJECTION" if candidate else "RECORDED_TRANSITION"
    elif row.state in {"DENIED", "STALE_AUTHORIZATION"} and row.approved is None:
        outcome, provenance = "NOT_EXECUTED", "RECORDED_TRANSITION"
    elif row.state in {"RESERVED", "DISPATCH_COMMITTED", "INDETERMINATE"}:
        outcome, provenance = "INDETERMINATE", "RECORDED_TRANSITION"
    elif row.state == "PENDING_APPROVAL":
        outcome, provenance = "PENDING", "RECORDED_TRANSITION"
    else:
        outcome, provenance = "UNRESOLVED", "UNKNOWN"
    return result.model_copy(update={"outcome": outcome, "provenance": provenance})


def _compatible(candidate: BundleContent, original: BundleContent) -> bool:
    return (
        candidate.tenant_id == original.tenant_id
        and candidate.mappings == original.mappings
        and candidate.cedar_schema == original.cedar_schema
    )


def simulate(
    history: VerifiedHistory,
    candidate: BundleContent | None = None,
    *,
    catalog: Catalog = PRODUCTION_CATALOG,
) -> ReplayReport:
    # Frozen models still permit model_copy/construct: never trust derived verification flags.
    history = verify_export(history.export, history.export.head)
    if candidate is not None:
        try:
            candidate = BundleContent.model_validate_json(candidate.model_dump_json())
            if candidate.tenant_id != history.export.tenant_id:
                raise ValueError()
        except (ValueError, TypeError):
            raise ReplayValidationError("INVALID_CANDIDATE") from None
    index = index_history(history)
    tainted_executions = {identifier for identifier, row in index.executions.items() if row.issues}
    issues = set((*history.issues, *index.issues))
    original_bundles = {bundle.bundle_id: bundle for bundle in history.export.bundles}
    baseline, hypothetical = Ledger(history.export.tenant_id), Ledger(history.export.tenant_id)
    decisions: list[DecisionComparison] = []
    captures: dict[UUID, DecisionCapture] = {}
    # The candidate's reading of each execution's latest captured plan, or None when the plan
    # does not carry what that reading needs. The what-if ledger retains units by it.
    readings: dict[UUID, ResolvedRequest | None] = {}
    admissions: dict[UUID, EvaluationResult] = {}
    uncertain_executions: set[UUID] = set()
    divergent_targets: dict[UUID, set[UUID]] = {}
    gap = False
    candidate_valid = True
    if candidate is not None:
        try:
            validate_policy_sets(
                schema=candidate.cedar_schema,
                authorization=candidate.authorization_policies,
                approval=candidate.approval_policies,
            )
            contracts = [catalog.contract(m.context_contract_version) for m in candidate.mappings]
            validate_bundle_contracts(
                contracts=contracts,
                cedar_schema=candidate.cedar_schema,
                settings=candidate.context_settings,
            )
            # As far as the catalog allows offline: every listed action must exist and a
            # selector must name a fact the serving contracts carry. Group and account
            # existence cannot be checked here; a candidate rule for a group no capture
            # recorded simply applies to nobody.
            for rule in candidate.limits:
                for name in rule.action_names:
                    catalog.actions.action(name)
                if rule.selector is not None:
                    validate_selector(
                        contracts=contracts,
                        actions=rule.action_names,
                        fact=rule.selector.fact,
                        equals=rule.selector.equals,
                    )
        except ValueError:
            candidate_valid = False
    for entry in history.events:
        event, capture = entry.event, entry.capture
        identifier = capture.execution_id if capture is not None else execution_id(event.payload)
        if identifier in tainted_executions:
            # An inconsistent authority/transition path cannot supply a trusted
            # classification, reservation or refund to any later decision.
            gap = True
            issues.update(index.executions[identifier].issues)
        if entry.completeness == "UNSUPPORTED" or (
            entry.completeness != "COMPLETE"
            and event.kind.startswith(("execution.", "approval.", "policy."))
        ):
            gap = True
            issues.update(entry.issues or ("INCOMPLETE_HISTORY",))
        if capture is not None:
            captures[capture.execution_id] = capture
            row = index.executions[capture.execution_id]
            original = original_bundles[capture.bundle_id]
            local_issues = index.capture_issues.get(event.sequence, ())
            try:
                # The baseline reproduces what the kernel did with what it had: a unit
                # without recorded membership never counted, so the unknown rules are
                # a candidate-only uncertainty and are ignored here.
                low, high, deps, _ = baseline.usage(
                    original,
                    capture.identity.to_identity(),
                    capture.usage_time,
                    frozen=capture.frozen,
                    groups=capture.identity.groups,
                    space_id=capture.identity.space,
                    action=capture.frozen.intent.action,
                    observed=capture.mode == "OBSERVE",
                )
                measured = _evaluate(capture, original, low, catalog)
                base = _result(measured, _counts(low, high))
                if measured != capture.decision:
                    # A coherent hash chain does not make a recorded policy result
                    # authoritative when independent recomputation contradicts it.
                    # Apply the same forward taint as invalid transition chronology
                    # before any reservation, settlement or candidate cache can use it.
                    tainted_executions.add(capture.execution_id)
                    row.issues.add("RECORDED_DECISION_MISMATCH")
                    issues.add("RECORDED_DECISION_MISMATCH")
                    gap = True
                    base = _unknown(base, "RECORDED_DECISION_MISMATCH")
                if deps or gap:
                    base = _unknown(base, "INCOMPLETE_PRIOR_HISTORY", deps)
                for problem in local_issues:
                    base = _unknown(base, problem)
            except ValueError:
                gap = True
                base = EvaluationResult(
                    effect="UNRESOLVED",
                    reasons=("INVALID_SEMANTIC_HISTORY",),
                    bundle_id=original.bundle_id,
                    content_hash=original.content_hash,
                )
            alt = None
            if candidate is not None:
                # Unknown until the candidate's reading is derived, so a plan whose reading
                # fails for any reason retains its unit with its signal facts unknown.
                readings[capture.execution_id] = None
                try:
                    # A signal fact is a reading of frozen records through a mapping, so the
                    # candidate's own entry is re-applied first: evaluation refuses a value
                    # the evaluated bundle's mapping does not produce.
                    candidate_plan = rederive(capture.frozen, candidate, catalog)
                    readings[capture.execution_id] = candidate_plan
                    low, high, deps, unknown = hypothetical.usage(
                        candidate,
                        capture.identity.to_identity(),
                        capture.usage_time,
                        frozen=candidate_plan,
                        groups=capture.identity.groups,
                        space_id=capture.identity.space,
                        action=capture.frozen.intent.action,
                        observed=capture.mode == "OBSERVE",
                    )
                    lower = _evaluate(capture, candidate, low, catalog, candidate_plan)
                    upper = _evaluate(capture, candidate, high, catalog, candidate_plan)
                    alt = _result(lower, _counts(low, high))
                    if unknown and alt.effect != "DENY":
                        # A candidate group rule whose applicability or count rests on
                        # membership nobody recorded: a lower bound is never room in the
                        # budget, and a denial at that lower bound still stands.
                        # A candidate rule whose applicability or count rests on
                        # membership or a space nobody recorded. `UNKNOWN_SPACE` is its
                        # own reason, because a capture with no recorded space is a
                        # different gap from one with no recorded membership.
                        # A candidate rule over a signal fact whose count rests on an
                        # earlier unit the candidate cannot read is the same kind of gap,
                        # named for the evidence that is missing.
                        scopes = {
                            rule.scope for rule in candidate.limits if rule.rule_id in unknown
                        }
                        if "selector" in scopes:
                            alt = _unknown(alt, "SIGNAL_EVIDENCE_UNAVAILABLE")
                        if scopes - {"selector"}:
                            alt = _unknown(
                                alt,
                                "UNKNOWN_SPACE"
                                if "space" in scopes
                                else "UNKNOWN_GROUP_MEMBERSHIP",
                            )
                    if not _compatible(candidate, original):
                        alt = _unknown(alt, "UNSUPPORTED_CANDIDATE_CONTEXT")
                    elif not candidate_valid:
                        alt = alt.model_copy(
                            update={"effect": "DENY", "reasons": ("POLICY_ERROR",)}
                        )
                    elif lower.effect == "DENY":
                        # Lower-bound denial is already true for every larger possible usage.
                        pass
                    elif gap or base.effect == "UNRESOLVED":
                        alt = _unknown(alt, "INCOMPLETE_PRIOR_HISTORY", deps)
                    elif (lower.effect, lower.obligation_ids, lower.reasons) != (
                        upper.effect,
                        upper.obligation_ids,
                        upper.reasons,
                    ):
                        alt = _unknown(alt, "UNCERTAIN_LIMIT", deps)
                    elif (
                        candidate.content_hash != original.content_hash
                        and lower.effect == "REQUIRE_APPROVAL"
                    ):
                        alt = _unknown(alt, "UNKNOWN_HUMAN_APPROVAL")
                    if alt.effect != "DENY":
                        target_deps = set(divergent_targets.get(capture.canonical_target_id, ()))
                        guard_deps = hypothetical.guards(
                            capture.canonical_target_id, excluding=capture.execution_id
                        )
                        target_deps.update(
                            value
                            for value in guard_deps
                            if hypothetical.impacts[value].state == "HYPOTHETICAL"
                        )
                        if capture.execution_id in uncertain_executions:
                            target_deps.add(capture.execution_id)
                        if target_deps:
                            alt = _unknown(alt, "CHANGED_PREREQUISITE", tuple(target_deps))
                        elif guard_deps and alt.effect == "ELIGIBLE":
                            alt = alt.model_copy(
                                update={"effect": "DENY", "reasons": ("RESOURCE_BUSY",)}
                            )
                    if (
                        alt.effect == "ELIGIBLE"
                        and (
                            capture.decision.effect != "ELIGIBLE"
                            or row.state in {"ATTEMPTED", "DENIED"}
                            or (row.state == "STALE_AUTHORIZATION" and not row.terminal_verified)
                        )
                        and capture.stage == "ADMISSION"
                    ):
                        alt = _unknown(alt, "UNOBSERVED_ACTION_OR_TIMING")
                except SignalEvidenceUnavailable:
                    # The candidate needs a record or an attestation the plan never froze.
                    # Caught before ValueError, which it is: nothing here can say what the
                    # candidate would have read, so neither a value nor a denial is invented.
                    alt = EvaluationResult(
                        effect="UNRESOLVED",
                        reasons=("SIGNAL_EVIDENCE_UNAVAILABLE",),
                        bundle_id=candidate.bundle_id,
                        content_hash=candidate.content_hash,
                    )
                    # In the evaluated path's order, so the report names the more basic
                    # problem: a candidate that cannot be compared says so, and one that is
                    # invalid denies as POLICY_ERROR whatever it would have read.
                    if not _compatible(candidate, original):
                        alt = _unknown(alt, "UNSUPPORTED_CANDIDATE_CONTEXT")
                    elif not candidate_valid:
                        alt = alt.model_copy(
                            update={"effect": "DENY", "reasons": ("POLICY_ERROR",)}
                        )
                except ValueError:
                    alt = EvaluationResult(
                        effect="UNRESOLVED",
                        reasons=("INVALID_SEMANTIC_HISTORY",),
                        bundle_id=candidate.bundle_id,
                        content_hash=candidate.content_hash,
                    )
            for problem in row.issues:
                base = _unknown(base, problem)
                if alt is not None and alt.effect != "DENY":
                    alt = _unknown(alt, problem)
            if row.issues:
                baseline.uncertain(
                    capture.execution_id,
                    capture.identity.principal_id,
                    capture.frozen.intent.action,
                    capture.canonical_target_id,
                    capture.usage_time,
                    **_attributes(capture, capture.frozen, catalog),
                )
            # Cache the fully checked decision. Applying chronology problems
            # only to the rendered result would leave an eligible cached claim.
            if alt is not None and capture.stage == "ADMISSION":
                admissions[capture.execution_id] = alt
                if alt.effect == "UNRESOLVED":
                    uncertain_executions.add(capture.execution_id)
                    hypothetical.uncertain(
                        capture.execution_id,
                        capture.identity.principal_id,
                        capture.frozen.intent.action,
                        capture.canonical_target_id,
                        capture.usage_time,
                        **_attributes(capture, readings[capture.execution_id], catalog),
                    )
            base = _outcome(base, row)
            if alt is not None:
                if alt.effect == "DENY":
                    alt = alt.model_copy(
                        update={"outcome": "NOT_EXECUTED", "provenance": "HYPOTHETICAL_DENIAL"}
                    )
                else:
                    alt = _outcome(alt, row, candidate=True)
            differences = (
                ()
                if alt is None
                else tuple(
                    name.upper()
                    for name in (
                        "effect",
                        "outcome",
                        "obligation_ids",
                        "plan_hash",
                        "counts",
                        "reasons",
                        "dependencies",
                    )
                    if getattr(base, name) != getattr(alt, name)
                )
            )
            decisions.append(
                DecisionComparison(
                    sequence=event.sequence,
                    execution_id=capture.execution_id,
                    operation_id=capture.operation_id,
                    canonical_target_id=capture.canonical_target_id,
                    action=capture.frozen.intent.action,
                    arguments=capture.frozen.intent.arguments,
                    stage=capture.stage,
                    semantic_time=capture.semantic_time,
                    recorded_effect=capture.decision.effect,
                    baseline=base,
                    candidate=alt,
                    differences=differences,
                    mode=capture.mode,
                    settlement_tier=row.settlement_tier,
                )
            )
        if event.kind != "execution.transition":
            continue
        identifier = execution_id(event.payload)
        if identifier is None:
            gap = True
            continue
        if identifier in tainted_executions:
            # Preserve the possible unit and guard; even a structurally valid
            # terminal proof cannot repair missing/invalid authority chronology.
            continue
        captured = captures.get(identifier)
        after = event.payload.get("to_state")
        at = entry.semantic_time
        if after not in {
            "RESERVED",
            "OBSERVED",
            "EXECUTED",
            "FAILED_NOT_EXECUTED",
            "STALE_AUTHORIZATION",
            # A positive enumeration a hundred lines above the settlement itself: without
            # the new state here the transition is skipped and the ledger is never told
            # the impact was confirmed, so every later decision's counts in the export
            # would contradict the recorded ones.
            "FAILED_EFFECT_UNKNOWN",
        }:
            continue
        if captured is None or at is None:
            gap = True
            issues.add("MISSING_IMPACT_HISTORY")
            continue
        try:
            if after == "OBSERVED":
                if captured.decision.effect != "DENY":
                    baseline.observe(
                        identifier,
                        captured.identity.principal_id,
                        captured.frozen.intent.action,
                        captured.canonical_target_id,
                        captured.decision.effect == "REQUIRE_APPROVAL",
                        at,
                        **_attributes(captured, captured.frozen, catalog),
                    )
                if candidate is not None:
                    admission = admissions.get(identifier)
                    if admission is not None and admission.effect in {
                        "ELIGIBLE",
                        "REQUIRE_APPROVAL",
                    }:
                        hypothetical.observe(
                            identifier,
                            captured.identity.principal_id,
                            captured.frozen.intent.action,
                            captured.canonical_target_id,
                            admission.effect == "REQUIRE_APPROVAL",
                            at,
                            **_attributes(captured, readings.get(identifier), catalog),
                        )
                    elif admission is None or admission.effect != "DENY":
                        hypothetical.uncertain(
                            identifier,
                            captured.identity.principal_id,
                            captured.frozen.intent.action,
                            captured.canonical_target_id,
                            at,
                            **_attributes(captured, readings.get(identifier), catalog),
                        )
                        uncertain_executions.add(identifier)
            elif after == "RESERVED":
                approved = event.payload.get("approved")
                if type(approved) is not bool:
                    raise ValueError()
                baseline.reserve(
                    identifier,
                    captured.identity.principal_id,
                    captured.frozen.intent.action,
                    captured.canonical_target_id,
                    approved,
                    at,
                    **_attributes(captured, captured.frozen, catalog),
                )
                if candidate is not None:
                    admission = admissions.get(identifier)
                    if admission is not None and admission.effect == "ELIGIBLE":
                        hypothetical.reserve(
                            identifier,
                            captured.identity.principal_id,
                            captured.frozen.intent.action,
                            captured.canonical_target_id,
                            approved and candidate.content_hash == captured.decision.content_hash,
                            at,
                            **_attributes(captured, readings.get(identifier), catalog),
                        )
                    elif admission is not None and admission.effect == "DENY":
                        # Until recorded nonexecution settles the observed path, suppressing
                        # its dispatch makes later same-target snapshots counterfactual.
                        divergent_targets.setdefault(captured.canonical_target_id, set()).add(
                            identifier
                        )
                    elif admission is None or admission.effect != "DENY":
                        hypothetical.uncertain(
                            identifier,
                            captured.identity.principal_id,
                            captured.frozen.intent.action,
                            captured.canonical_target_id,
                            at,
                            **_attributes(captured, readings.get(identifier), catalog),
                        )
                        uncertain_executions.add(identifier)
            elif identifier in baseline.impacts:
                # An asserted settlement moves the same unit the kernel moved: it confirms
                # the impact, because charging for an action that may have happened is the
                # safe direction, and the ledger has to charge it too or every later
                # decision's counts would contradict the recorded ones. What it does not
                # do is release the canonical claim, which no ledger here models.
                settled: TerminalEvidence | AssertedOutcome | None = entry.terminal_evidence
                if settled is None:
                    settled = entry.asserted_outcome
                if settled is None:
                    raise ValueError()
                # A failure whose effect is not established charges the same impact a
                # reported success charges, so the only outcome that writes NONEXECUTION
                # here is the one the kernel writes it for.
                executed = settled.outcome != "FAILED_NOT_EXECUTED"
                # The one second settlement: a verified non-execution over a row an
                # assertion settled. It is told from an ordinary one by the transition's
                # own `from_state`, which `store.event` writes into every
                # `execution.transition` payload, and it takes `Ledger.correct` rather than
                # `settle`, which refuses a second settlement in either direction.
                correcting = event.payload.get("from_state") == "FAILED_EFFECT_UNKNOWN"
                if correcting:
                    baseline.correct(identifier, at)
                else:
                    baseline.settle(identifier, executed, at)
                if not executed:
                    divergent_targets.get(captured.canonical_target_id, set()).discard(identifier)
                hypothetical_impact = hypothetical.impacts.get(identifier)
                if hypothetical_impact is not None and hypothetical_impact.state != "HYPOTHETICAL":
                    if correcting:
                        hypothetical.correct(identifier, at)
                    else:
                        hypothetical.settle(identifier, executed, at)
                elif candidate is not None and executed:
                    divergent_targets.setdefault(captured.canonical_target_id, set()).add(
                        identifier
                    )
        except ValueError:
            gap = True
            issues.add("INVALID_IMPACT_HISTORY")
    for row in index.executions.values():
        issues.update(row.issues)
    if gap:
        issues.add("INCOMPLETE_HISTORY")
    complete = (
        history.complete
        and not issues
        and all(
            row.baseline.effect != "UNRESOLVED" and row.baseline.outcome != "UNRESOLVED"
            for row in decisions
        )
    )
    return ReplayReport(
        tenant_id=history.export.tenant_id,
        head_sequence=history.export.head.sequence,
        head_hash=history.export.head.event_hash,
        stop_periods=history.stop_periods,
        mode="COMPARISON" if candidate else "BASELINE",
        complete=complete,
        candidate_hash=candidate.content_hash if candidate else None,
        decisions=tuple(decisions),
        issues=tuple(sorted(issues)),
        limitations=limitations(tuple(decisions)),
    )
