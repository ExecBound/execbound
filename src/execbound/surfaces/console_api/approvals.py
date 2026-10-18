# SPDX-License-Identifier: AGPL-3.0-only
"""`/api/console/v1/approvals`: the queue, one approval in words, and the decision.

The three routes (#333) are the approval
pages over JSON: the list is `records()` with the same scope, fence and bound the Approvals
page reads with, the detail is that read for one approval, and the decision calls
`decide_approval` exactly as the form does, with the same signed continuation bound to the
session, the execution, the approval and the frozen plan. The decision route requires an
explicit review assignment for every human account, administrators included; an administrator
may read the list's `others` and `lapsed` views and an approval's detail without one, as
described below.

The list has four views. `pending` is what this approver can still decide, and holds only
approvals whose deadline has not passed; `decided` is today's decisions; `lapsed` is the
approvals that ran out of time undecided (#426);
`others` is an administrator's "Waiting on others": the pending approvals in the spaces they
are looking at that they are not assigned to decide (#678). An administrator's `lapsed` reads
every visible space, not only their own assignments, because a lapsed approval can never be
decided and the person who sets the deadline needs to see every one.
An approval that lapsed is a fact somebody should be able to read, so it moves between two
views rather than out of every one, and the page says when it lapsed. `lapsed` holds it on
both sides of the recovery run's sweep: still `PENDING` past its deadline, which is what the
row reads as between the expiry and the next run, and `EXPIRED` once the run has ended it.

What the detail adds over the page is words rather than authority: the frozen plan as a
sentence, each fact with its source and its age, each obligation with the rule that raised
it and that rule's sentence when the bundle carries a ruleset, the quorum with the decisions
recorded, the deadline with which clock set it, and whether the catalog names an action
that reverses this one. Every string that came from an agent, a provider or a label travels
as data; the client renders it as text.

An administrator who is not assigned to an approval can read its detail, answered with
`reviewing` false and no continuation, so there is something to read and a link to copy to
the person who should decide; the decision route is unchanged and refuses them (#678). For
an administrator each item also says how many people can decide it (`reviewers`), how many
of those have not decided yet (`reviewers_left`) and whether the reader is one of them; every
other reader gets `null`, so an approver learns nothing about other people's assignments.
"""

import hmac
import math
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from functools import partial
from typing import Any, Literal
from uuid import UUID

from fastapi import APIRouter, Request
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import text
from starlette.concurrency import run_in_threadpool

from execbound import access_control
from execbound.execution import decide_approval, store
from execbound.execution.models import ExecutionError, StopState
from execbound.logging_schema import log_event
from execbound.notifications import DeliveryTimes
from execbound.operations import CatalogError
from execbound.personal_tokens import TokenSession
from execbound.policy.rulesets import review_rule_ids, sentence
from execbound.requests import ExternalCase
from execbound.runtime import Runtime
from execbound.spaces import space_names, visible_spaces
from execbound.surfaces.console_api.errors import ApiError
from execbound.surfaces.console_api.executions import STATE_WORDS, TimelineEntry, request_timeline
from execbound.surfaces.console_api.guards import ApiGuards
from execbound.surfaces.console_api.principals import PrincipalKind, principal_kind
from execbound.surfaces.console_api.viewer_time import utc_offset as parse_offset
from execbound.surfaces.dashboard import viewer_midnight
from execbound.surfaces.human import (
    PAGE_SIZE,
    HumanConfig,
    _form_state,
    _nonce,
    active_stop,
    authority_guard,
    deadline_clock,
    decode_cursor,
    encode_cursor,
    signal_source_labels,
    signal_sources,
    tenant_mode,
)
from execbound.surfaces.human import (
    records as read_records,
)
from execbound.surfaces.names import PrincipalFacts, principal_name
from execbound.surfaces.request_context import DeliveryView, RelatedRequest
from execbound.surfaces.sessions import Session, check_session
from execbound.surfaces.tokens import MAX_TOKEN_LENGTH, InvalidContinuation, verify

Decision = Literal["APPROVE", "DENY"]
View = Literal["pending", "decided", "lapsed", "others"]
VIEWS: tuple[View, ...] = ("pending", "decided", "lapsed", "others")
Status = Literal["pending", "decided", "expired", "paused", "settled"]
Scalar = str | int | bool


class ApprovalAgent(BaseModel):
    principal_id: UUID
    label: str | None
    # The workspace's counting number, so an unlabelled agent reads "Agent 3" (#678).
    number: int | None


# A message delivered closer to the deadline than this gave its approver too little time to
# answer, and an administrator's Lapsed view flags it (#678).
LATE_DELIVERY_SECONDS = 30


class ApprovalDelivery(BaseModel):
    """What happened to the approval's announcements, and when the last one arrived.

    The counts are over `approval.pending` rows only. `lapsed` is a message closed unsent
    because the approval lapsed first; `closed`, one the approval's decision beat; and
    `withdrawn`, one whose request stopped being valid before anyone decided it. `margin_seconds`
    is the deadline less the last delivery, in whole seconds, negative when the message arrived
    after it. `late` is true when a message lapsed unsent or arrived within
    `LATE_DELIVERY_SECONDS` of the deadline, or after it.
    """

    delivered: int
    pending: int
    failed: int
    lapsed: int
    closed: int
    withdrawn: int
    last_delivered_at: datetime | None
    margin_seconds: int | None
    late: bool


class ApprovalItem(BaseModel):
    """One row of the queue; the detail carries the same item first."""

    approval_id: UUID
    request_ref: str
    external_case: ExternalCase | None
    execution_id: UUID
    action: str
    action_label: str
    target: str
    resource_class: Scalar
    environment: Scalar | None
    agent: ApprovalAgent
    created_at: datetime
    expires_at: datetime
    total_seconds: int
    deadline_clock: Literal["approval deadline", "context validity"]
    approval_state: str
    execution_state: str
    # The request's state in words, as the record pages say it, so no client lower-cases a
    # recorded code into a sentence (#678).
    execution_state_label: str
    required: int
    recorded: int
    mine: Decision | None
    decided_at: datetime | None
    # Whether the approvers were told, in words: an
    # operator watching a queue that is not moving needs to know whether the message went
    # out at all. Delivery changes nothing about the decision, and this changes nothing
    # about delivery; it is the count `records()` already read, in words.
    notified: str | None
    # For an administrator only, and null for every other reader (#678): how many people
    # hold an assignment that lets them decide this approval and can open it in its space,
    # how many of those have not decided it yet, and whether the reader is one of them.
    reviewers: int | None = None
    reviewers_left: int | None = None
    assigned_to_you: bool | None = None
    # How many people could decide it when it was held, as admission recorded it (#678): for a
    # reader with workspace-wide `access.manage` only, and null for every other reader and for
    # an approval held before the record existed. A lapsed row says why it lapsed with it.
    reviewers_at_hold: int | None = None
    # Every reader's own message, against the deadline (#678); null when nobody outside the
    # console was ever told.
    delivery: ApprovalDelivery | None = None


class ApprovalList(BaseModel):
    view: View
    items: list[ApprovalItem]
    next_cursor: str | None
    server_time: datetime


class ApprovalFact(BaseModel):
    name: str
    value: Scalar
    origin: str
    source_kind: str
    source_object_id: str
    source_version: str
    permitted_writers: list[str]
    observed_at: datetime
    valid_until: datetime
    age_seconds: int
    # A signal fact's producer, by the label its registration carries, and the capability it
    # answers. None for every other fact. Never the envelope's attributes, which no plan
    # holds, and never the records, which an administrator reads on the execution.
    capability: str | None = None
    source_label: str | None = None


class ApprovalObligation(BaseModel):
    id: str
    kind: Literal["policy", "limit", "other"]
    rule_id: str | None
    sentence: str


class ApprovalDecisionRecord(BaseModel):
    principal_id: UUID
    label: str | None
    kind: PrincipalKind | None
    number: int | None
    decision: Decision
    decided_at: datetime


class ApprovalQuorum(BaseModel):
    required: int
    recorded: int
    decisions: list[ApprovalDecisionRecord]
    mine: Decision | None


class ApprovalDeadline(BaseModel):
    created_at: datetime
    expires_at: datetime
    total_seconds: int
    clock: Literal["approval deadline", "context validity"]


class ApprovalEffect(BaseModel):
    sentence: str
    provider: str
    provider_operation: str
    resource_version: str
    mapping_version: str
    precondition: str | None
    reversible: bool
    reversed_by: str | None


class ApprovalLimit(BaseModel):
    rule_id: str
    scope: str
    max_targets: int
    budget: str
    window_seconds: int
    on_exceed: str
    actions: str


class ApprovalArgument(BaseModel):
    name: str
    value: Scalar


class StopView(BaseModel):
    stopped_at: datetime
    reason: str


class ApprovalSpace(BaseModel):
    """The space that owns this approval, which the console opens the link in."""

    space_id: UUID
    name: str


class ApprovalDetail(BaseModel):
    timeline: list[TimelineEntry]
    related_requests: list[RelatedRequest]
    deliveries: list[DeliveryView]
    item: ApprovalItem
    status: Status
    sentence: str
    plan_hash: str
    canonical_target_id: UUID
    arguments: list[ApprovalArgument]
    facts: list[ApprovalFact]
    obligations: list[ApprovalObligation]
    quorum: ApprovalQuorum
    deadline: ApprovalDeadline
    effect: ApprovalEffect
    limits: list[ApprovalLimit]
    notices: list[str]
    mode: Literal["ENFORCE", "OBSERVE"]
    stop: StopView | None
    # Which space owns this approval. A single record is authorised by membership and
    # answered whatever the session's current space is, so the answer has to say which space
    # it came from: the shell then switches the session to it and says so, and an approval
    # link opens in the space that owns it rather than 404ing.
    space: ApprovalSpace | None
    # False only for an administrator reading an approval they are not assigned to decide;
    # such a read never carries a continuation (#678).
    reviewing: bool
    # For an administrator: the space of their own review of this action on this target when
    # it is held in another space, since assigning themselves here moves it. Null otherwise.
    your_review_elsewhere: ApprovalSpace | None
    # This deployment's own address for the approval, built from identifiers only: a loaded
    # plugin's approval link, or `/approvals/{approval_id}`.
    link_path: str
    continuation: str | None
    server_time: datetime


class DecisionBody(BaseModel):
    model_config = ConfigDict(extra="forbid")

    decision: Decision
    comment: str = Field(default="", max_length=500)
    continuation: str = Field(min_length=1, max_length=MAX_TOKEN_LENGTH)


class DecisionResult(BaseModel):
    approval_id: UUID
    decision: Decision
    approval_state: str
    execution_state: str
    required: int
    recorded: int


def _quorum(row: dict[str, Any], session: Session) -> tuple[int, int, Decision | None]:
    approval = row["approval"]
    required = int(approval.get("required_approvers", 1) or 1)
    recorded = sum(1 for decided in row["decisions"] if decided["decision"] == "APPROVE")
    mine = next(
        (
            decided["decision"]
            for decided in row["decisions"]
            if decided["principal_id"] == session.identity.principal_id
        ),
        None,
    )
    return required, recorded, mine


@dataclass(frozen=True)
class _Coverage:
    reviewers: int
    reviewers_left: int
    mine: bool


def _item(
    row: dict[str, Any],
    session: Session,
    principals: Mapping[UUID, PrincipalFacts],
    coverage: Mapping[UUID, _Coverage] | None = None,
    hold_record: bool = False,
) -> ApprovalItem:
    approval = row["approval"]
    frozen = row["frozen_model"]
    required, recorded, mine = _quorum(row, session)
    clock = deadline_clock(row)
    assert clock is not None
    which: Literal["approval deadline", "context validity"] = (
        "context validity" if clock == "context validity" else "approval deadline"
    )
    agent = principals.get(row["principal_id"])
    covered = None if coverage is None else coverage.get(approval["approval_id"])
    return ApprovalItem(
        request_ref=row["request_ref"],
        external_case=row["external_case"],
        approval_id=approval["approval_id"],
        execution_id=row["execution_id"],
        action=frozen.intent.action,
        action_label=row["action_label"],
        target=frozen.resource_provider_id,
        resource_class=row["resource_class"],
        environment=row["environment"],
        agent=ApprovalAgent(
            principal_id=row["principal_id"],
            label=agent.label or None if agent is not None else None,
            number=agent.number if agent is not None else None,
        ),
        created_at=approval["created_at"],
        expires_at=approval["expires_at"],
        total_seconds=max(
            0, int((approval["expires_at"] - approval["created_at"]).total_seconds())
        ),
        deadline_clock=which,
        approval_state=str(approval["state"]),
        execution_state=str(row["state"]),
        execution_state_label=STATE_WORDS.get(str(row["state"]), str(row["state"])),
        required=required,
        recorded=recorded,
        mine=mine,
        decided_at=approval.get("decided_at"),
        notified=delivery(row.get("notifications")),
        delivery=delivery_view(
            row.get("notifications"), row.get("delivery_times"), approval["expires_at"]
        ),
        reviewers=None if covered is None else covered.reviewers,
        reviewers_left=None if covered is None else covered.reviewers_left,
        assigned_to_you=None if covered is None else covered.mine,
        reviewers_at_hold=approval.get("reviewers_at_hold") if hold_record else None,
    )


# Who can decide each approval: the assignments `effective_approval_scopes` already holds to
# the decide permission in the approval's space, narrowed to people who can also open the
# record there, the SQL form of `principal_allows`, which the decision checks again. The ids
# are approvals `records()` has just returned, never a caller's list.
_COVERAGE = """
SELECT a.approval_id,
       count(DISTINCT s.approver_id) AS reviewers,
       count(DISTINCT s.approver_id) FILTER (WHERE NOT EXISTS (
           SELECT 1 FROM execbound.approval_decisions d
           WHERE d.tenant_id=a.tenant_id AND d.approval_id=a.approval_id
           AND d.principal_id=s.approver_id)) AS reviewers_left,
       coalesce(bool_or(s.approver_id = :p), false) AS mine
FROM execbound.approvals a
JOIN execbound.executions e ON e.tenant_id=a.tenant_id AND e.execution_id=a.execution_id
LEFT JOIN execbound.effective_approval_scopes s
  ON s.tenant_id=e.tenant_id AND s.canonical_target_id=e.canonical_target_id
 AND s.space_id=e.space_id AND s.action=e.frozen -> 'intent' ->> 'action' AND s.active
 AND execbound.access_has_permission(s.approver_id, 'console.read', e.space_id, false)
WHERE a.tenant_id=:t AND a.approval_id = ANY(CAST(:ids AS uuid[]))
GROUP BY a.approval_id
"""


def _review_coverage(
    runtime: Runtime, session: Session, rows: list[dict[str, Any]]
) -> dict[UUID, _Coverage] | None:
    """Each approval's reviewers, for an administrator reader; None for anyone else."""
    identity = session.identity
    if identity.kind != "ADMIN":
        return None
    ids = [row["approval"]["approval_id"] for row in rows if row["approval"]]
    if not ids:
        return {}
    with runtime.db.transaction(identity.tenant_id) as conn:
        store.identity_check(conn, identity, runtime.clock, "ADMIN")
        check_session(conn, session, runtime.clock)
        return {
            found["approval_id"]: _Coverage(
                int(found["reviewers"]), int(found["reviewers_left"]), bool(found["mine"])
            )
            for found in conn.execute(
                text(_COVERAGE),
                {"t": identity.tenant_id, "p": identity.principal_id, "ids": ids},
            ).mappings()
        }


def _reads_hold_record(runtime: Runtime, session: Session) -> bool:
    """Whether the reader may see the hold-time count: workspace-wide `access.manage`.

    An approver is never told how many other people could decide something, and an
    administrator narrowed to Spaces is not shown a fact about who can review elsewhere.
    """
    identity = session.identity
    if identity.kind != "ADMIN":
        return False
    with runtime.db.transaction(identity.tenant_id) as conn:
        return access_control.has_permission(
            conn, identity.tenant_id, identity.principal_id, "access.manage"
        )


def _review_elsewhere(
    runtime: Runtime, session: Session, row: dict[str, Any]
) -> ApprovalSpace | None:
    """The space of an administrator's own review of this action and target, if not this one.

    `approval_scopes` is keyed without the space, so assigning themselves in this approval's
    space moves that review; the page says so before the write. Read for an administrator
    only, and only a space they may see.
    """
    identity = session.identity
    if identity.kind != "ADMIN":
        return None
    with runtime.db.transaction(identity.tenant_id) as conn:
        store.identity_check(conn, identity, runtime.clock, "ADMIN")
        check_session(conn, session, runtime.clock)
        held = conn.execute(
            text(
                "SELECT space_id FROM execbound.approval_scopes WHERE tenant_id=:t "
                "AND approver_id=:p AND canonical_target_id=:c AND action=:a AND active "
                "AND space_id IS DISTINCT FROM :s"
            ),
            {
                "t": identity.tenant_id,
                "p": identity.principal_id,
                "c": row["canonical_target_id"],
                "a": row["frozen_model"].intent.action,
                "s": row.get("space_id"),
            },
        ).scalar_one_or_none()
        if held is None:
            return None
        space = UUID(str(held))
        visibility = visible_spaces(conn, session)
        if not (visibility.everything or space in visibility.spaces):
            return None
        name = space_names(conn, identity.tenant_id).get(space)
    return None if name is None else ApprovalSpace(space_id=space, name=name)


def _link_path(runtime: Runtime, session: Session, approval_id: UUID) -> str:
    links = runtime.plugins.approval_links
    if links is None:
        return f"/approvals/{approval_id}"
    return links.path(session.identity.tenant_id, approval_id)


def delivery(counts: Mapping[str, int] | None) -> str | None:
    """What the approvers were told, in words; None where nothing was ever sent.

    A message closed unsent because the approval lapsed first is left out; one the decision
    beat, or whose request was withdrawn, still counts as a failure, as it always has.
    """
    if not counts:
        return None
    delivered, pending = (int(counts.get(k, 0)) for k in ("delivered", "pending"))
    failed = sum(int(counts.get(k, 0)) for k in ("failed", "closed", "withdrawn"))
    total = delivered + pending + failed
    if total == 0:
        return None
    said = []
    if delivered:
        said.append(f"notified {delivered} of {total} destinations")
    if pending:
        said.append("notification pending")
    if failed:
        said.append("notification failed")
    return " · ".join(said)


def delivery_view(
    counts: Mapping[str, int] | None, times: DeliveryTimes | None, expires_at: datetime
) -> ApprovalDelivery | None:
    """The announcements' counts and when the last arrived, against the deadline."""
    if not counts:
        return None
    keys = ("delivered", "pending", "failed", "lapsed", "closed", "withdrawn")
    found = {key: int(counts.get(key, 0)) for key in keys}
    if sum(found.values()) == 0:
        return None
    last = times.last_delivered_at if times is not None else None
    margin = None if last is None else math.floor((expires_at - last).total_seconds())
    late = found["lapsed"] > 0 or (margin is not None and margin < LATE_DELIVERY_SECONDS)
    return ApprovalDelivery(**found, last_delivered_at=last, margin_seconds=margin, late=late)


def _status(row: dict[str, Any], session: Session, stop: StopState | None, now: datetime) -> Status:
    approval = row["approval"]
    _, _, mine = _quorum(row, session)
    if approval["state"] == "EXPIRED":
        # It ran out of time, whether a late touch ended it or the recovery run's sweep
        # did, and saying so is more use than the generic settled sentence. The row reads
        # the same on both sides of that sweep.
        return "expired"
    if approval["state"] != "PENDING" or row["state"] != "PENDING_APPROVAL":
        return "settled"
    if now >= approval["expires_at"]:
        # Before the sweep too, and for a person who approved part of the quorum: it no
        # longer waits for anyone (#678).
        return "expired"
    if mine is not None:
        return "decided"
    if stop is not None:
        return "paused"
    return "pending"


def _obligations(row: dict[str, Any]) -> list[ApprovalObligation]:
    """Each obligation with the rule behind it, in the words the rules pages use."""
    ruleset = row["bundle"].ruleset
    reviews = review_rule_ids(ruleset) if ruleset is not None else {}
    rules = {rule.id: rule for rule in ruleset.rules} if ruleset is not None else {}
    limits = {item["rule"].rule_id: item for item in row["applicable_limits"]}
    result: list[ApprovalObligation] = []
    for obligation in row["approval"]["obligation_ids"]:
        if obligation.startswith("policy:"):
            rule_id = reviews.get(obligation)
            rule = rules.get(rule_id) if rule_id is not None else None
            words = (
                sentence(rule)
                if rule is not None
                else "The approval policy " + obligation[len("policy:") :] + " requires a person."
            )
            result.append(
                ApprovalObligation(id=obligation, kind="policy", rule_id=rule_id, sentence=words)
            )
        elif obligation.startswith("limit:"):
            rule_id = obligation[len("limit:") :]
            found = limits.get(rule_id)
            words = (
                f"The limit {rule_id} is exceeded: {found['scope']} allows "
                f"{found['rule'].max_targets} {found['rule'].budget} targets per "
                f"{found['rule'].window_seconds} seconds."
                if found is not None
                else f"The limit {rule_id} is exceeded."
            )
            result.append(
                ApprovalObligation(id=obligation, kind="limit", rule_id=rule_id, sentence=words)
            )
        else:
            result.append(
                ApprovalObligation(id=obligation, kind="other", rule_id=None, sentence=obligation)
            )
    return result


def _notices(row: dict[str, Any]) -> list[str]:
    """What the page says about an externally executed or platform-carried record, as text."""
    lines: list[str] = []
    gate = row.get("checkpoint")
    if gate is not None:
        lines.append(gate.notice)
        lines.append("Grant: " + gate.grant)
        lines.append("Report window: " + gate.report_window)
        lines.append("Precondition: " + gate.precondition)
        lines.append("Evidence tier: " + gate.tier)
        lines.append("Target claim: " + gate.claim)
        for extra in (gate.effect, gate.guidance, gate.correction):
            if extra:
                lines.append(extra)
    for index, carrier in enumerate(row.get("carriers", ())):
        if index == 0:
            lines.append(carrier.notice)
        lines.append("Control point execution: " + carrier.control_point)
        lines.append("Tool the platform named: " + carrier.tool)
        lines.append("Platform end user: " + carrier.user)
        lines.append("Extension answered: " + carrier.answered)
        lines.append("Platform reported: " + carrier.reported)
        for title, value in (
            ("Reported code", carrier.code),
            ("Reported error", carrier.error),
            ("Reported metadata", carrier.metadata),
        ):
            if value:
                lines.append(f"{title}: {value}")
    return lines


def _effect(row: dict[str, Any], runtime: Runtime) -> ApprovalEffect:
    frozen = row["frozen_model"]
    intent = frozen.intent
    reversed_by = None
    try:
        spec = runtime.catalog.actions.action(intent.action)
        if spec.reversed_by is not None:
            reversed_by = runtime.catalog.actions.action(spec.reversed_by).label
    except CatalogError:
        reversed_by = None
    words = (
        f"If approved, ExecBound sends {intent.provider_operation} to {intent.provider} for "
        f"{frozen.resource_provider_id} once, against resource version "
        f"{frozen.resource_version} under mapping {frozen.mapping_version}. "
    )
    words += (
        f"Reversible by {reversed_by}."
        if reversed_by is not None
        else "The catalog names no action that reverses this one."
    )
    return ApprovalEffect(
        sentence=words,
        provider=intent.provider,
        provider_operation=intent.provider_operation,
        resource_version=frozen.resource_version,
        mapping_version=frozen.mapping_version,
        precondition=row.get("precondition"),
        reversible=reversed_by is not None,
        reversed_by=reversed_by,
    )


@dataclass(frozen=True)
class _Decider:
    label: str | None
    kind: PrincipalKind | None
    number: int | None


def _decider(principal_id: UUID, principals: Mapping[UUID, PrincipalFacts]) -> _Decider:
    found = principals.get(principal_id)
    if found is None:
        return _Decider(None, None, None)
    return _Decider(found.label or None, principal_kind(found.kind), found.number)


def _sentence(item: ApprovalItem) -> str:
    who = principal_name("AGENT", item.agent.label, item.agent.number, item.agent.principal_id)
    where = (
        f"a {item.environment} {item.resource_class}"
        if item.environment is not None
        else f"a {item.resource_class}"
    )
    when = item.created_at.astimezone(UTC).strftime("%H:%M:%S")
    return f"{item.action_label} on {item.target}, {where}, requested by {who} at {when} UTC."


def _detail(
    row: dict[str, Any],
    session: Session,
    csrf: str,
    runtime: Runtime,
    config: HumanConfig,
    stop: StopState | None,
    mode: str,
    space: ApprovalSpace | None,
    sources: dict[UUID, str],
    *,
    reviewing: bool,
    coverage: Mapping[UUID, _Coverage] | None = None,
    elsewhere: ApprovalSpace | None = None,
    hold_record: bool = False,
) -> ApprovalDetail:
    now = runtime.clock.now()
    approval = row["approval"]
    frozen = row["frozen_model"]
    principals: Mapping[UUID, PrincipalFacts] = row.get("principals") or {}
    item = _item(row, session, principals, coverage, hold_record)
    status = _status(row, session, stop, now)
    required, recorded, mine = _quorum(row, session)
    continuation = None
    # Never for a personal access token: a continuation is bound to the session's id and CSRF
    # token, which for a token are its own id and nothing, both known to whoever holds it. The
    # route table refuses a token the decision; this keeps the second barrier structural.
    # Never for a read outside the reader's own review scope either: an administrator reading
    # an approval waiting on someone else has nothing to decide with (#678).
    if (
        status == "pending"
        and reviewing
        and now < session.expires_at
        and not isinstance(session, TokenSession)
    ):
        continuation = _form_state(config, session, csrf, row, "approval.decide", runtime)
    return ApprovalDetail(
        timeline=request_timeline(row),
        related_requests=row.get("related_requests", []),
        deliveries=row.get("deliveries", []),
        item=item,
        status=status,
        sentence=_sentence(item),
        plan_hash=row["plan_hash"],
        canonical_target_id=row["canonical_target_id"],
        arguments=[ApprovalArgument(name=name, value=value) for name, value in row["arguments"]],
        facts=[
            ApprovalFact(
                name=fact.name,
                value=fact.value,
                origin=fact.origin,
                source_kind=fact.source_kind,
                source_object_id=fact.source_object_id,
                source_version=fact.source_version,
                permitted_writers=list(fact.permitted_writers),
                observed_at=fact.observed_at,
                valid_until=fact.valid_until,
                age_seconds=max(0, int((now - fact.observed_at).total_seconds())),
                capability=fact.signal.capability if fact.signal is not None else None,
                source_label=sources.get(fact.source_id) if fact.source_kind == "signal" else None,
            )
            for fact in frozen.facts
        ],
        obligations=_obligations(row),
        quorum=ApprovalQuorum(
            required=required,
            recorded=recorded,
            decisions=[
                ApprovalDecisionRecord(
                    principal_id=decided["principal_id"],
                    label=_decider(decided["principal_id"], principals).label,
                    kind=_decider(decided["principal_id"], principals).kind,
                    number=_decider(decided["principal_id"], principals).number,
                    decision=decided["decision"],
                    decided_at=decided["decided_at"],
                )
                for decided in row["decisions"]
            ],
            mine=mine,
        ),
        deadline=ApprovalDeadline(
            created_at=approval["created_at"],
            expires_at=approval["expires_at"],
            total_seconds=item.total_seconds,
            clock=item.deadline_clock,
        ),
        effect=_effect(row, runtime),
        limits=[
            ApprovalLimit(
                rule_id=found["rule"].rule_id,
                scope=found["scope"],
                max_targets=found["rule"].max_targets,
                budget=found["rule"].budget,
                window_seconds=found["rule"].window_seconds,
                on_exceed=found["rule"].on_exceed,
                actions=found["actions"],
            )
            for found in row["applicable_limits"]
        ],
        notices=_notices(row),
        mode="OBSERVE" if mode == "OBSERVE" else "ENFORCE",
        stop=StopView(stopped_at=stop.stopped_at, reason=stop.reason) if stop else None,
        space=space,
        reviewing=reviewing,
        your_review_elsewhere=elsewhere,
        link_path=_link_path(runtime, session, approval["approval_id"]),
        continuation=continuation,
        server_time=now,
    )


def _approval_id(value: str) -> UUID:
    try:
        identifier = UUID(value)
    except ValueError:
        raise ApiError("NOT_FOUND") from None
    if str(identifier) != value:
        raise ApiError("NOT_FOUND")
    return identifier


records = partial(read_records, reviewing=True, enriched=True, delivery=True)


def _approver(session: Session) -> None:
    if session.identity.kind not in {"HUMAN_APPROVER", "ADMIN"}:
        raise ApiError("FORBIDDEN")


def _space_of(runtime: Runtime, session: Session, row: dict[str, Any]) -> ApprovalSpace | None:
    """The owning space's id and name, read inside the fence as inert text."""
    owner = row.get("space_id")
    if owner is None:
        return None
    space = UUID(str(owner))
    with runtime.db.transaction(session.identity.tenant_id) as conn:
        name = space_names(conn, session.identity.tenant_id).get(space)
    return None if name is None else ApprovalSpace(space_id=space, name=name)


def approval_routes(
    routes: APIRouter, runtime: Runtime, config: HumanConfig, guards: ApiGuards
) -> None:
    @routes.get("/approvals", response_model=ApprovalList, operation_id="listApprovals")
    async def list_approvals(
        request: Request,
        view: str = "pending",
        cursor: str | None = None,
        utc_offset: str | None = None,
    ) -> ApprovalList:
        """`utc_offset` is the viewer's minutes east of UTC; with it **Decided today** starts
        at the viewer's midnight. It is parsed for every view, so a malformed value is refused
        whichever view it came with, and read only by `decided`."""
        current, _ = await guards.session(
            request, query=frozenset({"view", "cursor", "utc_offset"})
        )
        _approver(current)
        if view not in VIEWS:
            raise ApiError("INVALID_REQUEST")
        administrator = current.identity.kind == "ADMIN"
        if view == "others" and not administrator:
            # Waiting on others is an administrator's view; `records()` refuses it too.
            raise ApiError("FORBIDDEN")
        offset = parse_offset(request.query_params.get("utc_offset"))
        after = None
        if cursor is not None:
            try:
                if len(cursor) > 200:
                    raise ValueError("Cursor too long")
                after = decode_cursor(cursor)
            except (ValueError, TypeError, UnicodeDecodeError):
                raise ApiError("INVALID_REQUEST") from None
        now = runtime.clock.now()
        if view == "pending":
            rows = await run_in_threadpool(
                records, runtime, current, pending=True, cursor=after, limit=PAGE_SIZE + 1
            )
        elif view == "others":
            rows = await run_in_threadpool(
                records,
                runtime,
                current,
                pending=True,
                others=True,
                reviewing=False,
                cursor=after,
                limit=PAGE_SIZE + 1,
            )
        elif view == "lapsed":
            # An administrator's lapsed view covers every visible space, not only their own
            # assignments: a lapsed approval can never be decided, so the wider read grants
            # nothing Activity does not already show.
            rows = await run_in_threadpool(
                records,
                runtime,
                current,
                lapsed=True,
                reviewing=not administrator,
                cursor=after,
                limit=PAGE_SIZE + 1,
            )
        else:
            rows = await run_in_threadpool(
                records,
                runtime,
                current,
                decided_since=viewer_midnight(now, offset),
                cursor=after,
                limit=PAGE_SIZE + 1,
            )
        next_cursor = None
        if len(rows) > PAGE_SIZE:
            rows = rows[:PAGE_SIZE]
            next_cursor = encode_cursor(rows[-1]["created_at"], rows[-1]["execution_id"])
        rows = [row for row in rows if row["approval"]]
        coverage = await run_in_threadpool(_review_coverage, runtime, current, rows)
        hold_record = await run_in_threadpool(_reads_hold_record, runtime, current)
        return ApprovalList(
            view=view,
            items=[
                _item(row, current, row.get("principals") or {}, coverage, hold_record)
                for row in rows
            ],
            next_cursor=next_cursor,
            server_time=now,
        )

    @routes.get(
        "/approvals/{approval_id}", response_model=ApprovalDetail, operation_id="readApproval"
    )
    async def read_approval(request: Request, approval_id: str) -> ApprovalDetail:
        current, csrf = await guards.session(request)
        _approver(current)
        identifier = _approval_id(approval_id)
        rows = await run_in_threadpool(records, runtime, current, approval_id=identifier)
        reviewing = True
        if (not rows or not rows[0]["approval"]) and current.identity.kind == "ADMIN":
            # An administrator not assigned to it reads it as a named record, by membership,
            # and gets no continuation (#678). An approver's out-of-scope read stays NOT_FOUND.
            rows = await run_in_threadpool(
                records, runtime, current, approval_id=identifier, reviewing=False
            )
            reviewing = False
        if not rows or not rows[0]["approval"]:
            # Outside the reader's scope or unknown: the same answer either way.
            raise ApiError("NOT_FOUND")
        row = rows[0]
        coverage = await run_in_threadpool(_review_coverage, runtime, current, [row])
        hold_record = await run_in_threadpool(_reads_hold_record, runtime, current)
        elsewhere = await run_in_threadpool(_review_elsewhere, runtime, current, row)
        stop = await run_in_threadpool(active_stop, runtime, current)
        mode = await run_in_threadpool(tenant_mode, runtime, current)
        space = await run_in_threadpool(_space_of, runtime, current, row)
        sources = await run_in_threadpool(
            signal_source_labels, runtime, current, signal_sources(row)
        )
        return _detail(
            row,
            current,
            csrf,
            runtime,
            config,
            stop,
            mode,
            space,
            sources,
            reviewing=reviewing,
            coverage=coverage,
            elsewhere=elsewhere,
            hold_record=hold_record,
        )

    @routes.post(
        "/approvals/{approval_id}/decision",
        response_model=DecisionResult,
        operation_id="decideApproval",
        # The body is read by the mutation guard rather than by FastAPI, so it is declared
        # here for the document alone: the generated client then types it.
        openapi_extra={
            "requestBody": {
                "required": True,
                "content": {"application/json": {"schema": DecisionBody.model_json_schema()}},
            }
        },
    )
    async def decide(request: Request, approval_id: str) -> DecisionResult:
        current, body = await guards.mutation(request, DecisionBody)
        _approver(current)
        identifier = _approval_id(approval_id)
        identity = current.identity
        # The token the mutation guard just compared with the session's; the nonce binds the
        # continuation to exactly that pair, as the form's hidden field does.
        csrf = request.headers.get("x-csrf-token", "")
        now = runtime.clock.now()
        try:
            claim = verify(
                body.continuation,
                config.keys,
                tenant_id=identity.tenant_id,
                principal_id=identity.principal_id,
                credential_id=identity.credential_id,
                audience="approval.decide",
                now=now,
            )
            if claim.approval_id != identifier or not hmac.compare_digest(
                claim.nonce, _nonce(current, csrf)
            ):
                raise InvalidContinuation
        except InvalidContinuation:
            await run_in_threadpool(runtime.reject, identity, "INVALID_CONTINUATION")
            # A continuation lives as long as the approval does, so the usual reason a valid
            # session's token fails is that the approval expired; say so when the row says so.
            rows = await run_in_threadpool(records, runtime, current, approval_id=identifier)
            if rows and rows[0]["approval"] and now >= rows[0]["approval"]["expires_at"]:
                raise ApiError("APPROVAL_EXPIRED") from None
            raise ApiError("INVALID_CONTINUATION") from None
        rows = await run_in_threadpool(records, runtime, current, execution_id=claim.execution_id)
        if not rows or not rows[0]["approval"]:
            # The record the continuation names is outside this approver's scope now, or gone.
            await run_in_threadpool(runtime.reject, identity, "INVALID_CONTINUATION")
            raise ApiError("NOT_FOUND")
        row = rows[0]
        if row["plan_hash"] != claim.plan_hash or row["approval"]["approval_id"] != identifier:
            await run_in_threadpool(runtime.reject, identity, "INVALID_CONTINUATION")
            raise ApiError("INVALID_CONTINUATION")
        comment = body.comment.strip()
        try:
            await run_in_threadpool(
                decide_approval,
                runtime.db,
                identity,
                identifier,
                body.decision,
                runtime.clock,
                authority_check=authority_guard(runtime, current),
                catalog=runtime.catalog,
                comment=comment or None,
            )
        except ExecutionError as exc:
            if exc.code == "TENANT_STOPPED":
                raise ApiError("STOPPED") from None
            if exc.code == "INVALID_COMMENT":
                raise ApiError("INVALID_BODY", fields=["comment"]) from None
            if exc.code == "INVALID_STATE":
                _, _, mine = _quorum(row, current)
                raise ApiError("ALREADY_DECIDED" if mine is not None else "CONFLICT") from None
            if exc.code == "NOT_FOUND":
                raise ApiError("NOT_FOUND") from None
            raise
        log_event(
            "approval.decided",
            tenant_id=identity.tenant_id,
            principal_id=identity.principal_id,
            approval_id=identifier,
            decision=body.decision,
        )
        after = await run_in_threadpool(records, runtime, current, execution_id=claim.execution_id)
        if not after or not after[0]["approval"]:
            # Decided, and no longer readable in this scope: the decision stands as recorded.
            return DecisionResult(
                approval_id=identifier,
                decision=body.decision,
                approval_state="DECIDED",
                execution_state="UNKNOWN",
                required=0,
                recorded=0,
            )
        required, recorded, _ = _quorum(after[0], current)
        return DecisionResult(
            approval_id=identifier,
            decision=body.decision,
            approval_state=str(after[0]["approval"]["state"]),
            execution_state=str(after[0]["state"]),
            required=required,
            recorded=recorded,
        )
