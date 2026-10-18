# SPDX-License-Identifier: AGPL-3.0-only
"""Deterministic offline evidence and hypothetical-policy reports."""

from typing import Literal
from uuid import UUID

from pydantic import AwareDatetime, Field

from execbound.audit import canonical_json
from execbound.execution.models import Digest, SettlementTier
from execbound.operations import ActionName
from execbound.replay.models import StopPeriod
from execbound.requests import Arguments, StrictModel


class RuleCount(StrictModel):
    rule_id: str
    confirmed_targets: int = Field(ge=0)
    unresolved_targets: int = Field(ge=0)
    possible_targets: int = Field(ge=0)


class EvaluationResult(StrictModel):
    effect: Literal["DENY", "REQUIRE_APPROVAL", "ELIGIBLE", "UNRESOLVED"]
    reasons: tuple[str, ...]
    obligation_ids: tuple[str, ...] = ()
    bundle_id: UUID | None = None
    content_hash: Digest | None = None
    plan_hash: Digest | None = None
    counts: tuple[RuleCount, ...] = ()
    dependencies: tuple[UUID, ...] = ()
    outcome: Literal[
        "EXECUTED",
        "FAILED_NOT_EXECUTED",
        "FAILED_EFFECT_UNKNOWN",
        "INDETERMINATE",
        "NOT_EXECUTED",
        "PENDING",
        "OBSERVED",
        "UNRESOLVED",
    ] = "UNRESOLVED"
    provenance: Literal[
        "RECORDED_GATEWAY_EVIDENCE",
        # An external executor's record, verified against a key the tenant registered and
        # retained. It is kept apart from a provider's journal because it establishes who
        # spoke and never what the vendor did; the settlement tier below says the same
        # thing about the same row from the execution's side.
        "RECORDED_EXECUTOR_EVIDENCE",
        # A provider's journal of an operation it performed for an external executor,
        # verified under the deployment's journal key when it settled.
        "RECORDED_PROVIDER_EVIDENCE",
        "RECORDED_TRANSITION",
        "FIXED_HISTORY_PROJECTION",
        "HYPOTHETICAL_DENIAL",
        "UNKNOWN",
    ] = "UNKNOWN"


class DecisionComparison(StrictModel):
    sequence: int = Field(ge=1)
    execution_id: UUID
    operation_id: UUID
    canonical_target_id: UUID
    action: ActionName
    arguments: Arguments = Field(default_factory=Arguments, exclude_if=lambda value: not value.root)
    stage: Literal["ADMISSION", "APPROVAL_REVIEW"]
    semantic_time: AwareDatetime
    recorded_effect: Literal["DENY", "REQUIRE_APPROVAL", "ELIGIBLE"]
    baseline: EvaluationResult
    candidate: EvaluationResult | None = None
    differences: tuple[str, ...] = ()
    # Serialized only for observed decisions, so existing reports are unchanged.
    mode: Literal["ENFORCE", "OBSERVE"] = Field(
        default="ENFORCE", exclude_if=lambda value: value == "ENFORCE"
    )
    # What ExecBound could check about an externally executed operation's settlement:
    # ATTESTED for a record or a JWS it verified against a registered executor key,
    # PROVIDER_VERIFIED for a journal it verified under the provider's own journal key, and
    # ASSERTED for the executor's word alone. Serialized only when the execution settled at
    # a tier, so every report of operations ExecBound dispatched is unchanged.
    settlement_tier: SettlementTier | None = Field(
        default=None, exclude_if=lambda value: value is None
    )


_LIMITATIONS = (
    "Offline replay creates no executable authorization and performs no provider operations.",
    "Provider authenticity is gateway-recorded provenance; no HMAC signing keys are loaded.",
    "Candidate outcomes use recorded snapshots; alternate external reality is not established.",
)
# What the three above do not cover, once a report can name an external executor's word.
# The provider line names the HMAC alone, so an operator reading an attested checkpoint was
# told nothing about the signature ExecBound checked when it settled and does not check
# here (Ed25519 for a record, ES256 for a JWS), nor about a provider-verified checkpoint's
# journal MAC, which the provider line does cover; and nothing about an assertion having
# been checked by nobody at all.
_EXECUTOR_LIMITATION = (
    "Executor attestation is gateway-recorded provenance; no executor public keys are "
    "loaded, and an asserted outcome was never verified."
)


def limitations(decisions: tuple[DecisionComparison, ...]) -> tuple[str, ...]:
    """The limitation lines this report owes, which is the three above and sometimes a fourth.

    Conditional rather than unconditional, and on the same fact the tier itself is
    serialized on: a fourth entry on every report would move the bytes of every report of
    operations ExecBound dispatched, which is the compatibility `settlement_tier`'s
    ``exclude_if`` keeps. A report naming no tier claims nothing about an external
    executor — its settlements are the provider journals the second line already covers,
    and an unreported grant and an assertion that settled nothing are recorded transitions
    that claim no evidence at all — so it keeps the three lines it has always had.
    """
    if any(row.settlement_tier is not None for row in decisions):
        return (*_LIMITATIONS, _EXECUTOR_LIMITATION)
    return _LIMITATIONS


class ReplayReport(StrictModel):
    version: Literal[1] = 1
    tenant_id: UUID
    head_sequence: int = Field(ge=0)
    head_hash: Digest
    mode: Literal["BASELINE", "COMPARISON"]
    complete: bool
    candidate_hash: Digest | None = None
    decisions: tuple[DecisionComparison, ...]
    issues: tuple[str, ...] = ()
    # Emergency stop periods explain windows without decisions; they are not policy.
    stop_periods: tuple[StopPeriod, ...] = ()
    # The three every report carries; `limitations` above adds the fourth for a report that
    # names a settlement tier, and simulate passes what it returns.
    limitations: tuple[str, ...] = _LIMITATIONS


def report_json(report: ReplayReport) -> str:
    return canonical_json(report.model_dump(mode="json")) + "\n"


def render_report(report: ReplayReport) -> str:
    lines = [
        f"Replay {report.mode.lower()} for tenant {report.tenant_id}",
        f"History: sequence {report.head_sequence}, head {report.head_hash}",
        "Evidence completeness: " + ("complete" if report.complete else "partial / unresolved"),
    ]
    if report.candidate_hash is not None:
        lines.append(f"Hypothetical bundle: {report.candidate_hash}")
    for period in report.stop_periods:
        released = period.released_at.isoformat() if period.released_at else "still active"
        lines.append(
            f"Emergency stop {period.stop_id}: {period.activated_at.isoformat()} to {released}"
        )
    for item in report.decisions:
        lines.extend(
            [
                "",
                f"Sequence {item.sequence}: {item.action} ({item.stage}"
                f"{', observed only' if item.mode == 'OBSERVE' else ''})",
                f"Execution: {item.execution_id}; recorded policy: {item.recorded_effect}",
                f"Baseline: {item.baseline.effect}; outcome: {item.baseline.outcome} "
                f"({item.baseline.provenance})",
            ]
        )
        if item.settlement_tier is not None:
            # The tier named, rather than left to be read out of the provenance: what an
            # externally executed operation's settlement rests on is the thing an operator
            # reading this report has to know. ATTESTED is a verified signature and never
            # proof that the vendor did anything; PROVIDER_VERIFIED is independent evidence
            # from a party other than the executor, which is stronger but still the
            # provider's own account of itself, not something this offline process reproves.
            evidence = {
                "ATTESTED": "an executor-signed record",
                "PROVIDER_VERIFIED": "a provider-signed journal",
            }.get(item.settlement_tier, "the executor's own word, unverifiable")
            lines.append(f"Externally executed; settled {item.settlement_tier}: {evidence}")
        if item.arguments.root:
            lines.append(
                "Arguments: "
                + ", ".join(f"{k}={v}" for k, v in sorted(item.arguments.root.items()))
            )
        for label, result in (("Baseline", item.baseline), ("Candidate", item.candidate)):
            if result is None:
                continue
            if label == "Candidate":
                lines.append(
                    f"Candidate: {result.effect}; outcome: {result.outcome} ({result.provenance})"
                )
            if result.reasons:
                lines.append(f"{label} reasons: " + ", ".join(result.reasons))
            for count in result.counts:
                lines.append(
                    f"{label} {count.rule_id}: {count.confirmed_targets} confirmed, "
                    f"{count.unresolved_targets} unresolved, 0..{count.possible_targets} possible"
                )
            if result.dependencies:
                lines.append(
                    f"{label} uncertainty depends on: " + ", ".join(map(str, result.dependencies))
                )
        if item.differences:
            lines.append("Differences: " + ", ".join(item.differences))
    if report.issues:
        lines.extend(["", "Issues: " + ", ".join(report.issues)])
    lines.extend(["", *report.limitations])
    return "\n".join(lines) + "\n"
