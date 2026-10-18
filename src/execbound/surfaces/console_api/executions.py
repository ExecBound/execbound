# SPDX-License-Identifier: AGPL-3.0-only
"""Executions for the console's Activity page and the drawer: list, detail, reconcile.

Every read is `records`, the bounded read behind today's Activity and Approvals pages, so an
approver sees exactly the rows their scopes admit and an administrator the tenant's, with the
same fence and the same rechecks; the routes add words. A row's reasons name the rule that
raised them where a code carries one (a shared limit's id, a review rule's id through the
compiled bundle's positional obligations) and a sentence for the rest; its facts carry their
source and when they were observed; its timeline is the record's own transitions and the
decisions recorded on its approval, in the order they happened.

The one change here is `reconcile`, an administrator's settlement of one uncertain record,
which is the page's `POST /activity/{id}/reconcile` with a JSON body: the same continuation
the page's form carries, re-read under the fence by `continuation_row`, and then the same
two functions with the same evidence rules, `settle_grant` from the pasted evidence for a
checkpoint (an executor's signed record, an ES256 attestation, or the provider's own
journal of the exact command), and `reconcile_operation` through the connector for a
dispatch ExecBound made. Nothing here decides; a record without evidence stays what it is.
"""

import re
from collections.abc import Callable, Iterable, Mapping
from datetime import datetime, timedelta
from typing import Any, Literal
from uuid import UUID

from fastapi import APIRouter, Query, Request
from pydantic import BaseModel, ConfigDict, Field
from starlette.concurrency import run_in_threadpool

from execbound.execution import _correctable, store
from execbound.execution.models import AuthorityCheck, ExecutionError, ExecutionView
from execbound.operations import PRODUCTION_ACTIONS
from execbound.personal_tokens import TokenSession
from execbound.policy.models import BundleContent, LimitRule
from execbound.policy.rulesets import project, review_rule_ids
from execbound.policy.rulesets import sentence as rule_sentence
from execbound.provider.gateway import reconcile_operation
from execbound.requests import ExternalCase
from execbound.resolution.models import ResolvedRequest, scalar_facts
from execbound.runtime import Runtime
from execbound.surfaces import outcomes
from execbound.surfaces.console_api.errors import ApiError
from execbound.surfaces.console_api.guards import ApiGuards, json_body
from execbound.surfaces.console_api.policy import rules_readable
from execbound.surfaces.console_api.principals import PrincipalKind, principal_kind
from execbound.surfaces.human import (
    ACTIVITY_STATES,
    PAGE_SIZE,
    HumanConfig,
    _form_state,
    continuation_row,
    decode_cursor,
    dispatched_precondition,
    encode_cursor,
    limit_label,
    records,
    settle_grant,
    signal_source_labels,
    signal_sources,
)
from execbound.surfaces.names import PrincipalFacts, principal_name
from execbound.surfaces.request_context import DeliveryView, RelatedRequest
from execbound.surfaces.sessions import Session, SessionError, check_session
from execbound.surfaces.tokens import InvalidContinuation

EXECUTION_QUERY = frozenset(
    {"state", "action", "agent", "target", "since", "from", "outcome", "cursor", "limit"}
)
SINCE = {"1h": 1, "24h": 24, "7d": 168, "30d": 720}
# How far back `from` may reach: the longest range the report covers, and a day to spare
# for the viewer's calendar (#678).
FROM_MAX = timedelta(days=31)
CURSOR_MAX = 200
UNCERTAIN = frozenset({"DISPATCH_COMMITTED", "INDETERMINATE"})

# The word a state is shown as; the badge's colour is the client's, from the state.
STATE_WORDS = {
    "ATTEMPTED": "Attempted",
    "RESERVED": "Reserved",
    "PENDING_APPROVAL": "Held",
    "DISPATCH_COMMITTED": "Committed",
    "INDETERMINATE": "Unsettled",
    "EXECUTED": "Executed",
    "FAILED_NOT_EXECUTED": "Not executed",
    "FAILED_EFFECT_UNKNOWN": "Effect unknown",
    "DENIED": "Denied",
    "STALE_AUTHORIZATION": "Stale",
    "OBSERVED": "Observed",
}

# One sentence per code the kernel records as a reason. A code names no rule; the two that
# do (`HARD_LIMIT:<id>` and the obligations) are handled beside the bundle below.
SENTENCES = {
    "NOT_AUTHORIZED": (
        "No rule in the active bundle permits this action for this plan, or a deny rule matched it."
    ),
    "APPROVAL_REQUIRED": "A person has to approve it before it can run.",
    "INVALID_CONTEXT": "The trusted context expired before the decision was made.",
    "INVALID_IDENTITY": "The agent's identity or credential did not hold.",
    "INVALID_BUNDLE": (
        "The active policy cannot authorize this request: it names the action at a mapping "
        "that has since changed, or it is not this workspace's."
    ),
    "INVALID_USAGE": "The shared impact counters could not be read.",
    "POLICY_ERROR": "The policy could not be evaluated.",
    "INVALID_APPROVAL": "The approval did not match the frozen plan.",
    "CHANGED_OBLIGATIONS": "The obligations changed after the approval was recorded.",
    "RESOURCE_BUSY": "Another operation still holds this target.",
    "INCONCLUSIVE_JOURNAL": "The provider's journal held no terminal evidence.",
    "EXECUTOR_REPORT": "The executor reported the outcome itself.",
    "REPORTED_FAILURE": "The executor reported that its call failed.",
    "CONTEXT_EXPIRED": "The frozen context expired before dispatch.",
    "APPROVAL_EXPIRED": "The approval ran out of time before anybody decided it.",
    # How a settled outcome was settled. The same code labels an executed record, one that
    # failed before any effect and one the provider refused on the target's version, so each
    # sentence says who answered and never what the answer was.
    "PROVIDER_RESPONSE": "The provider's own response confirmed this outcome.",
    "UNREPORTED_GRANT": "The executor's report window closed without a report.",
    "INVALID_ARGUMENTS": "The frozen arguments no longer match the action's catalog entry.",
    "DEPENDENCY_UNAVAILABLE": "The decision could not be made because of an unexpected error.",
    "HUMAN_DENIED": "A reviewer refused this request.",
}
# A recorded reason shaped like a code: an upper-case name, and for the codes that carry one
# a rule id after a colon. Anything else is the free-text note a reconciliation records.
CODE_SHAPE = re.compile(r"[A-Z][A-Z0-9_]*(?::\S+)?")
# Codes that say the evaluation itself failed. Recorded beside `NOT_AUTHORIZED`, they mean
# the kernel denied closed without deciding on any rule, so no rule is read for it.
EVALUATION_FAILURES = frozenset({"POLICY_ERROR", "DEPENDENCY_UNAVAILABLE"})
OBSERVED_WORDS = {
    "ELIGIBLE": "have been eligible to run",
    "REQUIRE_APPROVAL": "have needed a person's approval",
    "DENY": "have been denied",
}


class AgentView(BaseModel):
    """A principal on a record: its id, label, kind and the workspace's counting number, so
    the console names it "Agent 3" or "User 3" when it has no label (#678)."""

    principal_id: UUID
    label: str | None
    kind: PrincipalKind | None
    number: int | None


class TargetView(BaseModel):
    canonical_target_id: UUID
    provider_id: str
    resource_class: str
    environment: str | None
    # Whether a sample account served this request (#420); the console shows a Sample badge.
    sample: bool = False


class ReasonView(BaseModel):
    code: str
    rule_id: str | None
    sentence: str
    rules: list[str] = Field(default_factory=list)
    """The rule ids the sentence names: a ruleset's rules a denial reading matched, a review
    rule, or a limit's. `rule_id` keeps its meaning, the id the kernel recorded (#678)."""


class ApprovalView(BaseModel):
    approval_id: UUID
    state: str
    expires_at: datetime
    required_approvers: int
    recorded: int
    lapsed: bool = False
    """The deadline passed before anybody decided it, by the server's clock (#678)."""
    unused: bool = False
    """A person approved it and the agent did not use it before the deadline (#678)."""


class ReconcileView(BaseModel):
    available: bool
    kind: Literal["provider", "record", "correction"] | None
    continuation: str | None


class ExecutionSummary(BaseModel):
    request_ref: str
    external_case: ExternalCase | None
    execution_id: UUID
    created_at: datetime
    changed_at: datetime
    state: str
    state_label: str
    action: str
    action_label: str
    target: TargetView
    agent: AgentView
    approval: ApprovalView | None
    reasons: list[ReasonView]
    reconcile: ReconcileView


class ArgumentView(BaseModel):
    name: str
    value: str


class SignalRecordView(BaseModel):
    """One frozen record a signal fact rested on, for an administrator.

    Every field the plan froze and nothing else: the envelope's attributes never enter a plan.
    """

    source_id: UUID
    registration_version: int
    attests_liveness: bool
    source_event_id: str
    record_digest: str
    producer_name: str
    producer_version: str
    verdict: str
    confidence: int
    observed_at: datetime
    received_at: datetime
    # The producer's own expiry, where it sent one.
    expires_at: datetime | None = None


class FactView(BaseModel):
    name: str
    value: str
    origin: str
    source_kind: str
    source_object_id: str
    source_version: str
    observed_at: datetime
    valid_until: datetime
    # A signal fact's capability and its source's registered label; None for every other fact.
    capability: str | None = None
    source_label: str | None = None
    # The records a signal fact was mapped from. None for every other fact, and for anyone but
    # an administrator.
    records: list[SignalRecordView] | None = None


class TimelineEntry(BaseModel):
    at: datetime
    kind: Literal["transition", "decision", "delivery"]
    state: str | None
    actor: AgentView | None
    sentence: str


class NoteView(BaseModel):
    label: str
    text: str


class ExecutionDetail(ExecutionSummary):
    bundle_id: UUID
    """The policy version this request was decided under."""
    policy_readable: bool
    """Whether this reader may open that version's rules: exactly what the rules read
    answers, and nothing else about the bundle (#678)."""
    related_requests: list[RelatedRequest]
    deliveries: list[DeliveryView]
    arguments: list[ArgumentView]
    facts: list[FactView]
    obligations: list[ReasonView]
    limits: list[ReasonView]
    timeline: list[TimelineEntry]
    checkpoint: list[NoteView]
    carriers: list[list[NoteView]]
    # What this record's own dispatch carried, for a record ExecBound dispatched itself.
    # A record an external executor was granted has `checkpoint` above instead, whose
    # `precondition` sentence is the grant's; the two are different statements and a
    # record never carries both.
    dispatch: str | None
    observed_effect: str | None
    plan_hash: str
    valid_until: datetime


class ExecutionPage(BaseModel):
    items: list[ExecutionSummary]
    next_cursor: str | None


class ReconcileRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    continuation: str = Field(min_length=1, max_length=4096)
    reason: str = Field(min_length=1, max_length=500)
    cancel_if_missing: bool = False
    record: str | None = Field(default=None, max_length=8000)


class ReconcileResult(BaseModel):
    execution_id: UUID
    state: str
    state_label: str


def words(value: object) -> str:
    """A frozen scalar as text; booleans read as the arguments block prints them."""
    if type(value) is bool:
        return "true" if value else "false"
    return str(value)


def identifier(value: str) -> UUID:
    """A path identifier in its canonical spelling, or the same 404 an unknown one gets."""
    try:
        parsed = UUID(value)
    except ValueError:
        raise ApiError("NOT_FOUND") from None
    if str(parsed) != value:
        raise ApiError("NOT_FOUND")
    return parsed


def limit_sentence(rule: LimitRule, scope: str | None = None) -> str:
    exceed = "a person decides" if rule.on_exceed == "REQUIRE_APPROVAL" else "it is denied"
    return (
        f"{scope or limit_label(rule, {})}: at most {rule.max_targets} {rule.budget} targets "
        f"per {rule.window_seconds} seconds; over that, {exceed}."
    )


def _joined(words: list[str]) -> str:
    return words[0] if len(words) == 1 else ", ".join(words[:-1]) + " and " + words[-1]


def denial_view(
    codes: frozenset[str], bundle: BundleContent, frozen: ResolvedRequest | None
) -> ReasonView | None:
    """`NOT_AUTHORIZED`, read from the rules of the bundle the plan was decided under.

    The kernel records the code and keeps no rule id, so the rules are read here: the frozen
    bundle's rules over the frozen facts and arguments, with the precedence its compiled Cedar
    has by construction (a bundle whose Cedar is not its rules' compilation is refused at
    validation and activation). `tests/test_pack_rulesets.py` holds that reading equal to the
    kernel's decision on every input of the shipped packs, and
    `tests/test_rule_reading_operators.py` for the operators those packs do not write. The
    sentence names every deny rule the request matches, or says that no rule allows it, as a
    reading of the rules and never as a rule id the kernel recorded, so `rule_id` stays None.

    None, and the recorded sentence stands, when the evaluation itself failed (Cedar's error
    records `POLICY_ERROR` beside `NOT_AUTHORIZED` and decides on no rule), when the bundle
    carries no rules or the plan is not at hand, when a fact or argument the rules read is
    missing, or when the reading does not deny.
    """
    if codes & EVALUATION_FAILURES or bundle.ruleset is None or frozen is None:
        return None
    reading = project(
        bundle.ruleset,
        frozen.intent.action,
        scalar_facts(frozen),
        dict(frozen.intent.arguments.root),
    )
    if reading.effect != "deny" or reading.unknown:
        return None
    if not reading.rules:
        sentence = "No rule allows this action for this request's facts and arguments."
    else:
        rules = {rule.id: rule for rule in bundle.ruleset.rules}
        noun = "rule" if len(reading.rules) == 1 else "rules"
        sentence = (
            f"This request matches the deny {noun} {_joined(list(reading.rules))}: "
            + " ".join(rule_sentence(rules[rule_id]) for rule_id in reading.rules)
        )
    return ReasonView(
        code="NOT_AUTHORIZED", rule_id=None, sentence=sentence, rules=list(reading.rules)
    )


def reason_views(
    codes: Iterable[object], bundle: BundleContent, frozen: ResolvedRequest | None = None
) -> list[ReasonView]:
    """The codes a transition recorded, each with the rule it names and a sentence."""
    limits = {rule.rule_id: rule for rule in bundle.limits}
    recorded = [str(raw) for raw in codes]
    views = []
    for code in recorded:
        rule_id: str | None = None
        sentence = SENTENCES.get(code, "")
        if code == "NOT_AUTHORIZED":
            denial = denial_view(frozenset(recorded), bundle, frozen)
            if denial is not None:
                views.append(denial)
                continue
        elif not CODE_SHAPE.fullmatch(code):
            # Only a reconciliation records words rather than a code; a note an administrator
            # wrote in the shape of a code is read as a code and keeps the generic sentence.
            sentence = f"Settled by reconciliation, noting: {code}"
        if code.startswith("HARD_LIMIT:"):
            rule_id = code.partition(":")[2]
            rule = limits.get(rule_id)
            sentence = (
                limit_sentence(rule)
                if rule is not None
                else "A shared limit the bundle no longer carries."
            )
        views.append(
            ReasonView(
                code=code,
                rule_id=rule_id,
                sentence=sentence,
                rules=[rule_id] if rule_id is not None else [],
            )
        )
    return views


def obligation_views(obligations: Iterable[object], bundle: BundleContent) -> list[ReasonView]:
    """The obligations a decision raised: a limit's rule, or a review rule by its position."""
    limits = {rule.rule_id: rule for rule in bundle.limits}
    reviews: Mapping[str, str] = {}
    rules: dict[str, Any] = {}
    if bundle.ruleset is not None:
        reviews = review_rule_ids(bundle.ruleset)
        rules = {rule.id: rule for rule in bundle.ruleset.rules}
    views = []
    for raw in obligations:
        code = str(raw)
        rule_id: str | None = None
        sentence = "An obligation of the bundle."
        if code.startswith("limit:"):
            rule_id = code.partition(":")[2]
            rule = limits.get(rule_id)
            sentence = (
                limit_sentence(rule)
                if rule is not None
                else "A shared limit the bundle no longer carries."
            )
        elif code.startswith("policy:"):
            rule_id = reviews.get(code)
            sentence = (
                rule_sentence(rules[rule_id])
                if rule_id is not None and rule_id in rules
                else "An approval policy of the compiled bundle."
            )
        views.append(
            ReasonView(
                code=code,
                rule_id=rule_id,
                sentence=sentence,
                rules=[rule_id] if rule_id is not None else [],
            )
        )
    return views


def codes_of(payload: Mapping[str, Any]) -> list[str]:
    reasons = payload.get("reasons")
    if isinstance(reasons, list):
        return [str(reason) for reason in reasons]
    reason = payload.get("reason")
    return [str(reason)] if reason else []


def event_sentence(event: Mapping[str, Any], row: Mapping[str, Any]) -> str:
    payload = event["payload"] if isinstance(event["payload"], dict) else {}
    state = str(event["to_state"])
    codes = codes_of(payload)
    tail = f" {', '.join(codes)}." if codes else "."
    if state == "ATTEMPTED":
        return "Request received and the plan frozen."
    if state == "PENDING_APPROVAL":
        obligations = payload.get("obligations")
        count = len(obligations) if isinstance(obligations, list) else 0
        return f"Held for a person: {count} obligation{'' if count == 1 else 's'}."
    if state == "RESERVED":
        return "Impact reserved" + (" under the approval." if payload.get("approved") else ".")
    if state == "DISPATCH_COMMITTED":
        return (
            "Granted to the executor."
            if row["report_expires_at"] is not None
            else "Dispatch committed."
        )
    if state == "EXECUTED":
        tier = payload.get("tier")
        return "Executed." + (f" Evidence tier {tier}." if tier else "")
    if state == "DENIED":
        return "Denied:" + tail if codes else "Denied."
    if state == "STALE_AUTHORIZATION":
        return "Authorization went stale:" + tail if codes else "Authorization went stale."
    if state == "OBSERVED":
        observed = payload.get("observed")
        effect = observed.get("effect") if isinstance(observed, dict) else None
        return (
            f"Observed only: it would {OBSERVED_WORDS[effect]}."
            if effect in OBSERVED_WORDS
            else "Observed only."
        )
    if state == "INDETERMINATE":
        return "The provider's answer is unknown" + (":" + tail if codes else ".")
    if state == "FAILED_NOT_EXECUTED":
        return "Failed before any effect" + (":" + tail if codes else ".")
    if state == "FAILED_EFFECT_UNKNOWN":
        return "Reported as failed; the effect is unknown."
    return state.replace("_", " ").capitalize() + "."


def decision_codes(row: Mapping[str, Any]) -> tuple[list[str], list[str]]:
    """The reasons and the obligations of the row's current state, from its own history."""
    if row["state"] == "OBSERVED":
        result = row.get("result") or {}
        observed = result.get("observed") if isinstance(result, dict) else None
        if isinstance(observed, dict):
            return (
                [str(code) for code in observed.get("reasons") or []],
                [str(code) for code in observed.get("obligation_ids") or []],
            )
    reasons: list[str] = []
    obligations: list[str] = []
    for event in row.get("events") or []:
        payload = event["payload"] if isinstance(event["payload"], dict) else {}
        if event["to_state"] == row["state"]:
            reasons = codes_of(payload)
        if event["to_state"] == "PENDING_APPROVAL" and isinstance(payload.get("obligations"), list):
            obligations = [str(code) for code in payload["obligations"]]
    approval = row.get("approval")
    if approval:
        obligations = [str(code) for code in approval["obligation_ids"]]
    if row["state"] == "PENDING_APPROVAL" and not reasons:
        # The transition into this state records the obligations and the approval, not the
        # evaluation's one reason for holding; it is the reason the kernel gives.
        reasons = ["APPROVAL_REQUIRED"]
    return reasons, obligations


def agent_view(principal_id: UUID, principals: Mapping[UUID, PrincipalFacts]) -> AgentView:
    """The principal as the facts the record read inside its fence give it; a principal the
    facts do not hold has no label, kind or number."""
    found = principals.get(principal_id)
    if found is None:
        return AgentView(principal_id=principal_id, label=None, kind=None, number=None)
    return AgentView(
        principal_id=principal_id,
        label=found.label or None,
        kind=principal_kind(found.kind),
        number=found.number,
    )


def target_view(row: Mapping[str, Any]) -> TargetView:
    frozen = row["frozen_model"]
    environment = row["environment"]
    return TargetView(
        canonical_target_id=row["canonical_target_id"],
        provider_id=frozen.resource_provider_id,
        resource_class=words(row["resource_class"]),
        environment=None if environment is None else words(environment),
        sample=bool(row.get("sample", False)),
    )


def approval_view(row: Mapping[str, Any], now: datetime) -> ApprovalView | None:
    """The record's approval, with a lapse classified on the server's clock (#678).

    The two classes `outcomes.PREDICATES` reads: past its deadline is an approval the recovery
    run already recorded `EXPIRED`, or one still `PENDING` or `APPROVED` past `expires_at`
    while the request waits for the sweep; it lapsed if nobody decided it, and was unused if
    a person did. Nothing is written.
    """
    approval = row["approval"]
    if not approval:
        return None
    state = str(approval["state"])
    past = state == "EXPIRED" or (
        state in {"PENDING", "APPROVED"}
        and now >= approval["expires_at"]
        and row["state"] == "PENDING_APPROVAL"
    )
    decided = approval.get("decided_at") is not None
    return ApprovalView(
        approval_id=approval["approval_id"],
        state=state,
        expires_at=approval["expires_at"],
        required_approvers=int(approval.get("required_approvers", 1) or 1),
        recorded=sum(1 for decided in row["decisions"] if decided["decision"] == "APPROVE"),
        lapsed=past and not decided,
        unused=past and decided,
    )


def reconcile_view(
    row: Mapping[str, Any], session: Session, continuation: Callable[[], str] | None
) -> ReconcileView:
    """Which settlement an administrator is offered for this row, as the page decides it."""
    correctable = _correctable(dict(row))
    # A personal access token is never offered a settlement it is refused by route.
    available = (
        session.identity.kind == "ADMIN"
        and not isinstance(session, TokenSession)
        and (row["state"] in UNCERTAIN or correctable)
    )
    if not available:
        return ReconcileView(available=False, kind=None, continuation=None)
    if row["report_expires_at"] is None:
        kind: Literal["provider", "record", "correction"] = "provider"
    else:
        kind = "correction" if correctable else "record"
    return ReconcileView(
        available=True,
        kind=kind,
        continuation=continuation() if continuation is not None else None,
    )


def summary(row: Mapping[str, Any], session: Session, now: datetime) -> ExecutionSummary:
    principals = row.get("principals") or {}
    reasons, _ = decision_codes(row)
    frozen = row["frozen_model"]
    return ExecutionSummary(
        request_ref=row["request_ref"],
        external_case=row["external_case"],
        execution_id=row["execution_id"],
        created_at=row["created_at"],
        changed_at=row["changed_at"],
        state=str(row["state"]),
        state_label=STATE_WORDS.get(str(row["state"]), str(row["state"])),
        action=frozen.intent.action,
        action_label=str(row["action_label"]),
        target=target_view(row),
        agent=agent_view(row["principal_id"], principals),
        approval=approval_view(row, now),
        reasons=reason_views(reasons, row["bundle"], frozen),
        reconcile=reconcile_view(row, session, None),
    )


def notes(label: object) -> list[NoteView]:
    """A label dataclass's sentences as (label, text) pairs, absent fields left out."""
    if label is None:
        return []
    return [
        NoteView(label=name.replace("_", " ").capitalize(), text=str(value))
        for name, value in vars(label).items()
        if value is not None
    ]


def chained(events: Iterable[Mapping[str, Any]]) -> list[Mapping[str, Any]]:
    """The transitions in the order they happened: by time, and along the state chain where
    two share an instant, since a record's history is one chain from no state onward and an
    event id says nothing about order."""
    remaining = sorted(events, key=lambda event: event["created_at"])
    ordered: list[Mapping[str, Any]] = []
    state: str | None = None
    while remaining:
        pick = next((event for event in remaining if event["from_state"] == state), remaining[0])
        remaining.remove(pick)
        ordered.append(pick)
        state = str(pick["to_state"])
    return ordered


# The timeline's two sentences for each notification kind: queued, then delivered.
DELIVERY_SENTENCES = {
    "approval.pending": ("Review notification queued.", "Review notification delivered."),
    "approval.reminder": ("Reminder queued.", "Reminder delivered."),
    "approval.closed": ("Outcome message queued.", "Outcome message delivered."),
}


def request_timeline(row: Mapping[str, Any]) -> list[TimelineEntry]:
    principals: Mapping[UUID, PrincipalFacts] = row.get("principals") or {}
    events = chained(row.get("events") or [])
    timeline = [
        TimelineEntry(
            at=event["created_at"],
            kind="transition",
            state=str(event["to_state"]),
            actor=agent_view(event["actor_id"], principals),
            sentence=event_sentence(event, row),
        )
        for event in events
    ]
    # A decision belongs after the transition that held the record for it, which is where
    # it lands when the two share an instant; otherwise time orders the timeline.
    rank = {id(entry): float(index) for index, entry in enumerate(timeline)}
    held_rank = (
        max(
            (
                index
                for index, event in enumerate(events)
                if event["to_state"] == "PENDING_APPROVAL"
            ),
            default=len(events),
        )
        + 0.5
    )
    for decided in row["decisions"]:
        facts = principals.get(decided["principal_id"])
        who = (
            "an approver"
            if facts is None
            else principal_name(facts.kind, facts.label, facts.number, decided["principal_id"])
        )
        verb = "Approved" if decided["decision"] == "APPROVE" else "Refused"
        timeline.append(
            TimelineEntry(
                at=decided["decided_at"],
                kind="decision",
                state=None,
                actor=agent_view(decided["principal_id"], principals),
                sentence=f"{verb} by {who}.",
            )
        )
    for delivery in row.get("deliveries", []):
        # Each message kind has its own words, so a follow-up never reads as another review
        # notification (#678).
        queued, delivered = DELIVERY_SENTENCES[delivery.get("kind", "approval.pending")]
        timeline.append(
            TimelineEntry(
                at=delivery["created_at"],
                kind="delivery",
                state=None,
                actor=None,
                sentence=queued,
            )
        )
        if delivery["delivered_at"] is not None:
            timeline.append(
                TimelineEntry(
                    at=delivery["delivered_at"],
                    kind="delivery",
                    state=None,
                    actor=None,
                    sentence=delivered,
                )
            )
    timeline.sort(key=lambda entry: (entry.at, rank.get(id(entry), held_rank)))
    return timeline


def detail(
    row: Mapping[str, Any],
    session: Session,
    continuation: Callable[[], str] | None,
    sources: Mapping[UUID, str],
    now: datetime,
    policy_readable: bool = False,
) -> ExecutionDetail:
    reasons, obligations = decision_codes(row)
    frozen = row["frozen_model"]
    timeline = request_timeline(row)
    observed_effect = None
    if row["state"] == "OBSERVED":
        result = row.get("result") or {}
        observed = result.get("observed") if isinstance(result, dict) else None
        if isinstance(observed, dict) and observed.get("effect"):
            observed_effect = str(observed["effect"])
    base = summary(row, session, now)
    # The page admits an approver too, and a viewer; the frozen records are an administrator's,
    # as settlement is.
    administrator = session.identity.kind == "ADMIN"
    return ExecutionDetail(
        related_requests=row.get("related_requests", []),
        deliveries=row.get("deliveries", []),
        **base.model_dump(),
        bundle_id=row["bundle_id"],
        policy_readable=policy_readable,
        arguments=[ArgumentView(name=name, value=words(value)) for name, value in row["arguments"]],
        facts=[
            FactView(
                name=fact.name,
                value=words(fact.value),
                origin=fact.origin,
                source_kind=fact.source_kind,
                source_object_id=fact.source_object_id,
                source_version=fact.source_version,
                observed_at=fact.observed_at,
                valid_until=fact.valid_until,
                capability=fact.signal.capability if fact.signal is not None else None,
                source_label=sources.get(fact.source_id) if fact.source_kind == "signal" else None,
                records=[
                    SignalRecordView(
                        source_id=item.source_id,
                        registration_version=item.registration_version,
                        attests_liveness=item.attests_liveness,
                        source_event_id=item.source_event_id,
                        record_digest=item.record_digest,
                        producer_name=item.producer_name,
                        producer_version=item.producer_version,
                        verdict=item.verdict,
                        confidence=item.confidence,
                        observed_at=item.observed_at,
                        received_at=item.received_at,
                        expires_at=item.expires_at,
                    )
                    for item in fact.signal.records
                ]
                if fact.signal is not None and administrator
                else None,
            )
            for fact in frozen.facts
        ],
        obligations=obligation_views(obligations, row["bundle"]),
        limits=[
            ReasonView(
                code=item["rule"].rule_id,
                rule_id=item["rule"].rule_id,
                sentence=limit_sentence(item["rule"], str(item["scope"])),
                rules=[item["rule"].rule_id],
            )
            for item in row["applicable_limits"]
        ],
        timeline=timeline,
        checkpoint=notes(row.get("checkpoint")),
        dispatch=None if row.get("checkpoint") is not None else dispatched_precondition(row),
        carriers=[notes(carrier) for carrier in row.get("carriers") or []],
        observed_effect=observed_effect,
        plan_hash=str(row["plan_hash"]),
        valid_until=frozen.valid_until,
    ).model_copy(update={"reconcile": reconcile_view(row, session, continuation)})


def list_filters(request: Request, now: datetime) -> dict[str, Any]:
    """The list's query, validated strictly; anything unexpected is a typed 400."""
    values = dict(request.query_params.multi_items())
    filters: dict[str, Any] = {
        "state": None,
        "action": None,
        "principal": None,
        "target": None,
        "since": None,
        "outcome": None,
        "cursor": None,
        "limit": PAGE_SIZE,
    }
    try:
        if values.get("state"):
            if values["state"] not in ACTIVITY_STATES:
                raise ValueError("Unknown state")
            filters["state"] = values["state"]
        if values.get("action"):
            if values["action"] not in PRODUCTION_ACTIONS.names:
                raise ValueError("Unknown action")
            filters["action"] = values["action"]
        for key, name in (("agent", "principal"), ("target", "target")):
            if values.get(key):
                parsed = UUID(values[key])
                if str(parsed) != values[key]:
                    raise ValueError("Malformed identifier")
                filters[name] = parsed
        if values.get("since"):
            if values["since"] not in SINCE:
                raise ValueError("Unsupported window")
            filters["since"] = now - timedelta(hours=SINCE[values["since"]])
        if values.get("outcome"):
            # A closed key; the statement binds it and never formats it.
            if values["outcome"] not in outcomes.OUTCOMES:
                raise ValueError("Unknown outcome")
            filters["outcome"] = values["outcome"]
        if "from" in values:
            # An instant with its zone, as the report's `since` is, within the report's reach;
            # never beside the relative window it would contradict.
            if "since" in values or len(values["from"]) > 40:
                raise ValueError("Two windows")
            start = datetime.fromisoformat(values["from"])
            if start.tzinfo is None or not now - FROM_MAX <= start <= now:
                raise ValueError("Window out of bounds")
            filters["since"] = start
        if values.get("cursor"):
            if len(values["cursor"]) > CURSOR_MAX:
                raise ValueError("Cursor too long")
            filters["cursor"] = decode_cursor(values["cursor"])
        if values.get("limit"):
            limit = int(values["limit"])
            if not 1 <= limit <= PAGE_SIZE or str(limit) != values["limit"]:
                raise ValueError("Limit out of bounds")
            filters["limit"] = limit
    except (ValueError, TypeError, UnicodeDecodeError):
        raise ApiError("INVALID_REQUEST") from None
    return filters


def authority(runtime: Runtime, session: Session) -> AuthorityCheck:
    def check(conn: Any) -> None:
        try:
            check_session(conn, session, runtime.clock)
        except SessionError:
            raise ExecutionError("INVALID_IDENTITY") from None

    return check


def _reconcile_dispatched(
    runtime: Runtime,
    session: Session,
    execution_id: UUID,
    account: UUID,
    body: ReconcileRequest,
) -> ExecutionView:
    """Settle a dispatch ExecBound made, through the connection that serves its account.

    A configured connector, or the sample connection derived for an active sample account
    (#420), so an unsettled sample request has the same exit every other one has.
    """
    with runtime.connection(session.identity.tenant_id, account) as connector:
        if connector is None:
            raise ExecutionError("CONNECTOR_UNAVAILABLE")
        return reconcile_operation(
            runtime.db,
            session.identity,
            execution_id,
            connector,
            reason=body.reason,
            cancel_if_missing=body.cancel_if_missing,
            clock=runtime.clock,
            authority_check=authority(runtime, session),
            verifier=runtime.evidence_verifier(session.identity.tenant_id, account),
        )


def execution_routes(
    routes: APIRouter, runtime: Runtime, config: HumanConfig, guards: ApiGuards
) -> None:
    @routes.get("/executions", response_model=ExecutionPage, operation_id="listExecutions")
    async def list_executions(
        request: Request,
        state: str | None = None,
        action: str | None = None,
        agent: str | None = None,
        target: str | None = None,
        since: str | None = None,
        outcome: str | None = None,
        from_: str | None = Query(default=None, alias="from"),
        cursor: str | None = None,
        limit: int | None = None,
    ) -> ExecutionPage:
        """`outcome` is a key of the value report's classification and `from` an instant with
        its zone, at most 31 days back: the list a report's count opens (#678)."""
        session, _ = await guards.session(request, query=EXECUTION_QUERY)
        filters = list_filters(request, runtime.clock.now())
        page = int(filters.pop("limit"))
        rows = await run_in_threadpool(
            records, runtime, session, limit=page + 1, enriched=True, **filters
        )
        next_cursor = None
        if len(rows) > page:
            rows = rows[:page]
            last = rows[-1]
            next_cursor = encode_cursor(last["created_at"], last["execution_id"])
        now = store.now(runtime.clock)
        return ExecutionPage(
            items=[summary(row, session, now) for row in rows], next_cursor=next_cursor
        )

    @routes.get(
        "/executions/{execution_id}", response_model=ExecutionDetail, operation_id="readExecution"
    )
    async def read_execution(request: Request, execution_id: str) -> ExecutionDetail:
        session, csrf = await guards.session(request)
        wanted = identifier(execution_id)
        rows = await run_in_threadpool(
            records, runtime, session, execution_id=wanted, enriched=True
        )
        if not rows:
            # Outside the approver's scope, another tenant's or unknown: the same answer.
            raise ApiError("NOT_FOUND")
        row = rows[0]

        def continuation() -> str:
            return _form_state(config, session, csrf, row, "execution.reconcile", runtime)

        # Never for a personal access token, whose session id and CSRF token (its own id and
        # nothing) are known to whoever holds it; settling is refused to a token by route too.
        offered = (
            continuation
            if runtime.clock.now() < session.expires_at and not isinstance(session, TokenSession)
            else None
        )
        sources = await run_in_threadpool(
            signal_source_labels, runtime, session, signal_sources(row)
        )
        # The same authority the rules page applies, so the drawer offers a rule link only
        # where the page it opens would answer this reader.
        readable = await run_in_threadpool(rules_readable, runtime, session, row["bundle_id"])
        return detail(row, session, offered, sources, store.now(runtime.clock), readable)

    @routes.post(
        "/executions/{execution_id}/reconcile",
        response_model=ReconcileResult,
        operation_id="reconcileExecution",
        openapi_extra=json_body(ReconcileRequest),
    )
    async def reconcile_execution(request: Request, execution_id: str) -> ReconcileResult:
        session, body = await guards.mutation(request, ReconcileRequest, max_bytes=16384)
        if session.identity.kind != "ADMIN":
            raise ApiError("FORBIDDEN")
        wanted = identifier(execution_id)
        # The guard compared this header with the session's token; the nonce the
        # continuation was signed with is derived from the same value.
        csrf = request.headers.get("x-csrf-token", "")
        try:
            row = await run_in_threadpool(
                continuation_row,
                runtime,
                config,
                session,
                csrf,
                body.continuation,
                "execution.reconcile",
            )
            if row["execution_id"] != wanted:
                raise InvalidContinuation
        except InvalidContinuation:
            await run_in_threadpool(runtime.reject, session.identity, "INVALID_CONTINUATION")
            raise ApiError("INVALID_CONTINUATION") from None
        # A grant settles from its own checkpoint evidence (an executor's signed record,
        # an ES256 attestation, or a provider's signed journal, whichever the pasted bytes
        # turn out to be), and never from a dispatch's connector evidence, so exactly one of
        # the two fields belongs to each row; the cancellation the connector path offers is
        # refused for a grant here as `reconcile_operation` refuses it in the kernel.
        grant = row["report_expires_at"] is not None
        if grant != (body.record is not None) or (grant and body.cancel_if_missing):
            raise ApiError("INVALID_BODY", fields=["record"] if grant else ["record"])
        if grant:
            assert body.record is not None
            try:
                view = await run_in_threadpool(
                    settle_grant,
                    runtime,
                    session,
                    row,
                    body.reason,
                    body.record.encode(),
                    authority(runtime, session),
                )
            except ExecutionError as exc:
                if exc.code == "INVALID_EVIDENCE":
                    # The administrator supplied the record: a record that does not verify
                    # is this caller's own input, not a dependency failure.
                    raise ApiError("INVALID_BODY", fields=["record"]) from None
                if exc.code == "INVALID_REASON":
                    # `reconciliation.reconcile` screens the transition reason for text
                    # shaped like a password, key or token; unmapped, it would fall
                    # to the generic `ExecutionError` handler and answer 503.
                    raise ApiError("INVALID_BODY", fields=["reason"]) from None
                raise
        else:
            try:
                view = await run_in_threadpool(
                    _reconcile_dispatched,
                    runtime,
                    session,
                    row["execution_id"],
                    row["frozen_model"].intent.account_id,
                    body,
                )
            except ExecutionError as exc:
                if exc.code == "INVALID_REASON":
                    # `reconcile_operation` screens the same reason; same answer.
                    raise ApiError("INVALID_BODY", fields=["reason"]) from None
                raise
        return ReconcileResult(
            execution_id=view.execution_id,
            state=view.state,
            state_label=STATE_WORDS.get(view.state, view.state),
        )
