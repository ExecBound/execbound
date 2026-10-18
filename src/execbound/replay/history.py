# SPDX-License-Identifier: AGPL-3.0-only
"""Index retained chronology without querying mutable live projections."""

from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any
from uuid import UUID

from execbound.execution.models import SettlementTier, transition_allowed
from execbound.replay.models import DecisionCapture, VerifiedHistory

_APPROVAL_TRANSITIONS = {
    "PENDING": {"APPROVED", "DENIED", "EXPIRED", "INVALIDATED"},
    "APPROVED": {"CONSUMED", "EXPIRED", "INVALIDATED"},
}
_APPROVAL_BINDING = (
    "approval_id",
    "principal_id",
    "bundle_id",
    "plan_hash",
    "obligation_ids",
    "expires_at",
    "created_at",
)


def _same_binding(left: Mapping[str, Any], right: Mapping[str, Any]) -> bool:
    return all(left.get(key) == right.get(key) for key in _APPROVAL_BINDING)


def _captured_binding(capture: DecisionCapture, binding: Mapping[str, Any]) -> bool:
    approval = capture.approval
    if approval is None:
        return False
    try:
        return (
            UUID(str(binding["approval_id"])) == approval.approval_id
            and UUID(str(binding["principal_id"])) == approval.principal_id
            and UUID(str(binding["bundle_id"])) == approval.bundle_id
            and binding["plan_hash"] == approval.plan_hash
            and tuple(binding["obligation_ids"]) == approval.obligation_ids
            and datetime.fromisoformat(str(binding["expires_at"])) == approval.expires_at
        )
    except (ValueError, KeyError, TypeError):
        return False


@dataclass
class ExecutionHistory:
    execution_id: UUID
    operation_id: UUID | None = None
    intent_hash: str | None = None
    plan_hash: str | None = None
    state: str | None = None
    latest_capture: DecisionCapture | None = None
    approved: bool | None = None
    terminal_time: datetime | None = None
    # Whether a verifier's evidence settled this execution: a provider's journal, or an
    # external executor's record checked against a key the tenant registered. An
    # assertion is never verification, so a settlement at tier ASSERTED leaves this false
    # and `settlement_tier` is what says the execution settled at all.
    terminal_verified: bool = False
    settlement_tier: SettlementTier | None = None
    observed: bool = False
    issues: set[str] = field(default_factory=set)


@dataclass
class HistoryIndex:
    executions: dict[UUID, ExecutionHistory] = field(default_factory=dict)
    capture_issues: dict[int, tuple[str, ...]] = field(default_factory=dict)
    issues: set[str] = field(default_factory=set)


def execution_id(payload: Mapping[str, Any]) -> UUID | None:
    value = payload.get("execution_id")
    try:
        return UUID(str(value)) if value is not None else None
    except ValueError:
        return None


def index_history(history: VerifiedHistory) -> HistoryIndex:
    index = HistoryIndex()
    approvals: dict[UUID, tuple[str, UUID, Mapping[str, Any]]] = {}
    used_approvals: set[UUID] = set()
    for entry in history.events:
        event, capture = entry.event, entry.capture
        if event.kind == "execution.evaluated" and capture is not None:
            row = index.executions.setdefault(
                capture.execution_id, ExecutionHistory(capture.execution_id)
            )
            problems: set[str] = set()
            if row.state not in {"ATTEMPTED", "PENDING_APPROVAL"}:
                problems.add("INVALID_DECISION_SEQUENCE")
            if (row.operation_id is not None and row.operation_id != capture.operation_id) or (
                row.plan_hash is not None
                and capture.stage == "ADMISSION"
                and capture.decision.effect == "ELIGIBLE"
                and capture.decision.plan_hash is not None
                and row.plan_hash != capture.decision.plan_hash
            ):
                problems.add("CHANGED_EXECUTION_BINDING")
            if capture.approval is not None and capture.approval.status == "VERIFIED":
                previous = approvals.get(capture.approval.approval_id)
                if (
                    previous is None
                    or previous[0] != "APPROVED"
                    or previous[1] != capture.execution_id
                    or not _captured_binding(capture, previous[2])
                    or previous[2].get("decided_by") != str(capture.approval.approver.principal_id)
                    or previous[2].get("decided_credential_id")
                    != str(capture.approval.approver.credential_id)
                    or capture.approval.approval_id in used_approvals
                ):
                    problems.add("MISSING_APPROVAL_TRANSITION")
            if capture.stage == "APPROVAL_REVIEW":
                pending = [
                    binding
                    for state, owner, binding in approvals.values()
                    if state == "PENDING" and owner == capture.execution_id
                ]
                if len(pending) != 1 or (
                    capture.approval is not None and not _captured_binding(capture, pending[0])
                ):
                    problems.add("MISSING_APPROVAL_TRANSITION")
            index.capture_issues[event.sequence] = tuple(sorted(problems))
            row.issues.update(problems)
            row.latest_capture = capture
            continue
        if event.kind not in {"execution.transition", "approval.transition"}:
            continue
        identifier = execution_id(event.payload)
        if identifier is None:
            index.issues.add("INVALID_EXECUTION_REFERENCE")
            continue
        row = index.executions.setdefault(identifier, ExecutionHistory(identifier))
        payload = event.payload
        if event.kind == "approval.transition":
            if row.latest_capture is not None and row.latest_capture.mode == "OBSERVE":
                row.issues.add("OBSERVED_WITH_EFFECT")
            binding = payload.get("binding")
            try:
                approval_id = UUID(str(payload["approval_id"]))
                if not isinstance(binding, Mapping):
                    raise ValueError()
                next_state = str(payload["to_state"])
                previous = approvals.get(approval_id)
                if (
                    previous is None
                    or previous[1] != identifier
                    or previous[0] != payload.get("from_state")
                    or next_state not in _APPROVAL_TRANSITIONS.get(previous[0], set())
                    or not _same_binding(previous[2], binding)
                    or binding.get("approval_id") != str(approval_id)
                    or binding.get("plan_hash") != row.plan_hash
                    or payload.get("plan_hash") != row.plan_hash
                ):
                    raise ValueError()
                if next_state in {"APPROVED", "DENIED"}:
                    review = row.latest_capture
                    if (
                        review is None
                        or review.stage != "APPROVAL_REVIEW"
                        or review.reviewer is None
                        or review.human_decision
                        != ("APPROVE" if next_state == "APPROVED" else "DENY")
                        or review.decision.effect == "DENY"
                        or binding.get("decided_by") != str(review.reviewer.principal_id)
                        or binding.get("decided_credential_id")
                        != str(review.reviewer.credential_id)
                        or event.actor_id != review.reviewer.principal_id
                        or binding.get("decided_at") is None
                    ):
                        raise ValueError()
                    decided_at = datetime.fromisoformat(str(binding["decided_at"]))
                    if (
                        entry.semantic_time is None
                        or not review.finished_time <= decided_at <= entry.semantic_time
                        or decided_at >= datetime.fromisoformat(str(binding["expires_at"]))
                    ):
                        raise ValueError()
                if next_state == "CONSUMED":
                    admission = row.latest_capture
                    if (
                        previous[0] != "APPROVED"
                        or approval_id in used_approvals
                        or admission is None
                        or admission.stage != "ADMISSION"
                        or admission.approval is None
                        or admission.approval.status != "VERIFIED"
                        or admission.approval.approval_id != approval_id
                        or admission.decision.effect != "ELIGIBLE"
                        or event.actor_id != admission.identity.principal_id
                        or any(
                            previous[2].get(key) != binding.get(key)
                            for key in ("decided_by", "decided_credential_id", "decided_at")
                        )
                    ):
                        raise ValueError()
                    used_approvals.add(approval_id)
                approvals[approval_id] = (next_state, identifier, binding)
            except (ValueError, KeyError, TypeError):
                row.issues.add("INVALID_APPROVAL_SEQUENCE")
            continue
        before, after = payload.get("from_state"), str(payload.get("to_state"))
        if (row.state is None and (before is not None or after != "ATTEMPTED")) or (
            row.state is not None
            and (before != row.state or not transition_allowed(str(before), after))
        ):
            row.issues.add("INVALID_TRANSITION_SEQUENCE")
        for name in ("operation_id", "intent_hash", "plan_hash"):
            value = payload.get(name)
            try:
                parsed = UUID(str(value)) if name == "operation_id" else str(value)
                previous_value = getattr(row, name)
                if value is None or (previous_value is not None and previous_value != parsed):
                    raise ValueError()
                setattr(row, name, parsed)
            except ValueError:
                row.issues.add("CHANGED_EXECUTION_BINDING")
        if after == "PENDING_APPROVAL":
            binding = payload.get("approval")
            try:
                if not isinstance(binding, Mapping):
                    raise ValueError()
                approval_id = UUID(str(binding["approval_id"]))
                latest = row.latest_capture
                if (
                    approval_id in approvals
                    or latest is None
                    or latest.decision.effect != "REQUIRE_APPROVAL"
                    or binding.get("principal_id") != str(latest.identity.principal_id)
                    or binding.get("bundle_id") != str(latest.bundle_id)
                    or binding.get("plan_hash") != row.plan_hash
                    or tuple(binding.get("obligation_ids", ())) != latest.decision.obligation_ids
                    or binding.get("decided_by") is not None
                    or binding.get("decided_credential_id") is not None
                ):
                    raise ValueError()
                approvals[approval_id] = ("PENDING", identifier, binding)
            except (ValueError, KeyError):
                row.issues.add("MISSING_APPROVAL_BINDING")
        if after == "RESERVED":
            latest = row.latest_capture
            approved = payload.get("approved")
            if type(approved) is not bool:
                row.issues.add("MISSING_IMPACT_CLASSIFICATION")
            else:
                row.approved = approved
            if (
                latest is None
                or latest.stage != "ADMISSION"
                or latest.decision.effect != "ELIGIBLE"
            ):
                row.issues.add("MISSING_COMMIT_DECISION")
            elif approved and (
                latest.approval is None
                or latest.approval.status != "VERIFIED"
                or latest.approval.approval_id not in used_approvals
            ):
                row.issues.add("MISSING_APPROVAL_CONSUMPTION")
            elif not approved and latest.approval is not None:
                row.issues.add("INVALID_IMPACT_CLASSIFICATION")
        latest = row.latest_capture
        if before == "OBSERVED":
            row.issues.add("OBSERVED_WITH_EFFECT")
        if after == "OBSERVED":
            # An observed execution ends with its recorded decision and nothing else.
            row.observed = True
            shown = payload.get("observed")
            if (
                latest is None
                or latest.stage != "ADMISSION"
                or latest.mode != "OBSERVE"
                or latest.approval is not None
                or not isinstance(shown, Mapping)
                or shown.get("effect") != latest.decision.effect
            ):
                row.issues.add("OBSERVED_WITH_EFFECT")
        elif after != "ATTEMPTED" and latest is not None and latest.mode == "OBSERVE":
            row.issues.add("OBSERVED_WITH_EFFECT")
        row.state = after
        # The gate has two sides, and a correction arrives on the side the states alone do
        # not describe. A verified non-execution over a settled FAILED_EFFECT_UNKNOWN row
        # settles at FAILED_NOT_EXECUTED, which the first set holds, or at
        # STALE_AUTHORIZATION for an attested VERSION_MISMATCH, which reaches the second
        # set with `before == "FAILED_EFFECT_UNKNOWN"`. Leaving that out of the `before` set
        # left `terminal_time`, `terminal_verified` and `settlement_tier` holding what the
        # asserted settlement wrote, so the export reported a row the live one contradicts
        # and `ReplayReport.complete` was false for that tenant's whole window — for good,
        # because audit events are append-only.
        if after in {"EXECUTED", "FAILED_NOT_EXECUTED", "FAILED_EFFECT_UNKNOWN"} or (
            after == "STALE_AUTHORIZATION"
            and before in {"DISPATCH_COMMITTED", "INDETERMINATE", "FAILED_EFFECT_UNKNOWN"}
        ):
            row.terminal_time = entry.semantic_time
            row.terminal_verified = entry.terminal_evidence is not None
            row.settlement_tier = entry.settlement_tier
            if entry.semantic_time is None or (
                # A settled assertion is retained evidence of the only kind an assertion
                # can be, so it is not a settlement whose evidence went missing. What it
                # is worth is the tier above, which every reader of this row can see.
                entry.terminal_evidence is None and entry.asserted_outcome is None
            ):
                row.issues.add("MISSING_TERMINAL_EVIDENCE")
        if entry.completeness != "COMPLETE":
            row.issues.update(entry.issues or ("INCOMPLETE_EXECUTION_HISTORY",))
    for row in index.executions.values():
        if row.latest_capture is None:
            row.issues.add("MISSING_AUTHORITY_CAPTURE")
    return index
