# SPDX-License-Identifier: AGPL-3.0-only
"""`/api/console/v1/policy`: the Policy pages' functions, answered as JSON.

Every route wraps what `surfaces/policy_pages.py` calls today — `list_bundles`, `read_bundle`,
`create_bundle`, `validate_bundle`, `activate_bundle`, `retire_bundle` and `preview_bundle` —
under the same authority (an administrator's session), the same fence and the same bounds. The
store rechecks the current ADMIN inside its own transaction for every one of them, so this
module parses, composes and refuses; it decides nothing
(#333).

Two things here are not on the Jinja page and are worth naming:

* **The meters.** A bundle's limits are shown with how much of each the tenant is using now,
  counted by the statement the Agents page's meters already use, so admission's own arithmetic
  is what a person reads. Only a scope with one tenant-wide answer carries a number; the rest
  say how they are counted instead of showing a figure that is not theirs.
* **The preview is its own route.** The Jinja detail runs a preview inside the page render for
  a VALIDATED bundle; here `GET /policy/{id}` never replays history and `POST /policy/{id}/preview`
  does, with the window the person chose. Replay executes no provider and changes no live budget,
  approval or execution state, as it does not on the page.
"""

import json
from dataclasses import replace
from datetime import datetime, timedelta
from typing import Any, Literal, Self
from uuid import UUID, uuid4

from fastapi import APIRouter, Request
from pydantic import BaseModel, ConfigDict, Field, ValidationError, model_validator
from sqlalchemy import text
from sqlalchemy.engine import Connection
from sqlalchemy.exc import SQLAlchemyError
from starlette.concurrency import run_in_threadpool

from execbound.contracts import Signal
from execbound.policy.compare import Comparison, Direction, Side, compare
from execbound.policy.models import (
    MAX_CONDITIONS,
    MAX_NOTE,
    MAX_RULES,
    MAX_VALUES,
    BundleContent,
    ConditionOperator,
    LimitRule,
    MappingRef,
    Rule,
    RuleEffect,
    Ruleset,
)
from execbound.policy.preview import preview_bundle, preview_scope
from execbound.policy.rulesets import (
    MAX_RULESET_FILE_BYTES,
    RulesetDocumentError,
    RulesetError,
    _ordered,
    parse_ruleset_document,
    review_rule_ids,
    rules_for,
    ruleset_bundle,
    sentence,
    writable_fields,
)
from execbound.policy.store import (
    BundleRecord,
    BundleSummary,
    PolicyStoreError,
    _policy_identity,
    activate_bundle,
    change_draft_rules,
    create_bundle,
    list_bundles,
    read_bundle,
    retire_bundle,
    validate_bundle,
)
from execbound.runtime import Runtime
from execbound.samples import sample_bundles
from execbound.spaces import (
    SpaceError,
    Visibility,
    is_archived,
    space_clause,
    visible_spaces,
    write_space,
)
from execbound.surfaces import policy_pages as pages
from execbound.surfaces.agents_pages import action_label, window_label
from execbound.surfaces.console_api.directory import UUID_PATTERN, body_of, parse_uuid
from execbound.surfaces.console_api.errors import ApiError
from execbound.surfaces.console_api.guards import ApiGuards
from execbound.surfaces.console_api.policy_starters import editable_copy, first_policy, source_rules
from execbound.surfaces.human import HumanConfig
from execbound.surfaces.sessions import Session, check_session

# The windows the preview offers. A closed set rather than a number, so the client's type is
# exact and a value outside it is refused by the model before the store sees a timedelta.
WINDOWS: dict[str, timedelta] = {
    "1h": timedelta(hours=1),
    "24h": timedelta(hours=24),
    "7d": timedelta(days=7),
    "30d": timedelta(days=30),
}
Window = Literal["1h", "24h", "7d", "30d"]
BundleState = Literal["DRAFT", "VALIDATED", "ACTIVE", "RETIRED"]
# The body cap the guard enforces for this area: a pasted bundle is the largest thing the
# console sends, and `parse_document` refuses anything over 512 KB itself.
DOCUMENT_BYTES = pages.MAX_DOCUMENT_BYTES + 4096
# The create route's cap. A rules file travels as an escaped JSON string, and valid JSON
# escapes to at most twice its length (a quote, a backslash, a newline, a return and a tab
# each become two characters; no other control character may appear in valid JSON), so a
# file within `MAX_RULESET_FILE_BYTES` never answers 413. Each source still bounds its own
# field, so only the outer read grows.
CREATE_BYTES = 2 * MAX_RULESET_FILE_BYTES + 4096


class CreateBundle(BaseModel):
    """A new draft: pasted JSON, a copy of the active bundle, or a rules file.

    A copy is the paste: the active content is dumped, given a new identity and read back
    through the page's own `parse_document`, so one path creates every draft and a copy
    carries the ruleset a bundle written as rules holds. A rules file is the `Ruleset`
    document `ruleset-compile` reads, compiled here over this Space's own mappings (#678);
    `ruleset` is bounded in characters, and the parser bounds it in bytes.
    """

    model_config = ConfigDict(extra="forbid")

    source: Literal["document", "active", "bundle", "template", "ruleset"]
    document: str = Field(default="", max_length=pages.MAX_DOCUMENT_BYTES)
    ruleset: str = Field(default="", max_length=MAX_RULESET_FILE_BYTES)
    # The guard validates decoded JSON with strict Python validation. Like other console
    # bodies, keep identifiers as bounded strings and parse them at the store boundary.
    bundle_id: str | None = Field(default=None, pattern=UUID_PATTERN)
    template: Literal["current-protections", "review-all", "security-response"] | None = None

    @model_validator(mode="after")
    def document_belongs_to_its_source(self) -> Self:
        if (self.source == "document") != bool(self.document):
            raise ValueError("A document is the `document` source and nothing else")
        if (self.source == "ruleset") != bool(self.ruleset):
            raise ValueError("A rules file is the `ruleset` source and nothing else")
        if (self.source == "template") != (self.template is not None):
            raise ValueError("A template is required only for the template source")
        if self.source == "bundle" and self.bundle_id is None:
            raise ValueError("A bundle copy requires its identity")
        if self.source in ("document", "active", "ruleset") and self.bundle_id is not None:
            raise ValueError("This source does not accept a bundle identity")
        if self.template == "security-response" and self.bundle_id is not None:
            raise ValueError("A first policy uses configured mappings, not another bundle")
        return self


class Confirmed(BaseModel):
    """A step a person confirmed; `confirm` must be true, as the page's checkbox must be ticked."""

    model_config = ConfigDict(extra="forbid")

    confirm: Literal[True]


class ActivateBody(BaseModel):
    """An activation a person confirmed, with what changed and why (#678). The store
    screens the reason (stripped, 1 to 500 characters, nothing shaped like a secret) and
    records it on the activation event only, never in the bundle."""

    model_config = ConfigDict(extra="forbid")

    confirm: Literal[True]
    reason: str = Field(min_length=1, max_length=500)


class PreviewBody(BaseModel):
    model_config = ConfigDict(extra="forbid")

    window: Window = "24h"


class BundleRow(BaseModel):
    bundle_id: UUID
    content_hash: str
    state: BundleState
    changed_at: datetime
    active: bool
    # The starter policy sample targets installed (#420); the console shows a Sample badge.
    sample: bool = False
    # The reason the latest activation in a Space the reader can see recorded, if any.
    note: str | None = None


class PolicyPage(BaseModel):
    bundles: list[BundleRow]
    active: UUID | None
    starter_available: bool = False
    starter_hint: str = ""


class MappingRow(BaseModel):
    operation_ref: str
    account_id: UUID
    mapping_version: str
    schema_version: str
    context_contract_version: str
    observe_only: bool
    external_executor: bool
    # The catalog action a ref serves when the ref is another name for it; absent (null) when
    # the ref is the action's own name, exactly as the bundle's mapping carries it.
    action: str | None = None


class LimitMeter(BaseModel):
    """One limit rule with the use admission would count against it.

    `used` is `None` where the rule's scope has no single tenant-wide figure; `counted` says
    which, in the words the page prints, so a blank meter is explained rather than empty.
    """

    rule_id: str
    scope: str
    scope_label: str
    actions: list[str]
    labels: list[str]
    window: str
    window_seconds: int
    max_targets: int
    budget: str
    on_exceed: str
    used: int | None
    counted: str


class QuorumRow(BaseModel):
    rule_id: str
    obligation: str
    required: int
    # The rule behind the obligation when the bundle carries a ruleset, so the page names it
    # rather than printing the engine's positional identifier.
    rule: str | None


class ContextSettingRow(BaseModel):
    context_contract_version: str
    source_kind: str
    max_age_seconds: int
    permitted_writers: list[str]


class RuleRow(BaseModel):
    """How one rule reads. Labelled on the page as the rules' wording, never as the decision,
    which is the kernel's and is made from the compiled policy below it."""

    id: str
    action: str
    effect: str
    sentence: str
    note: str | None


class CompiledPolicy(BaseModel):
    """The compiled bundle, read-only. It is what the kernel executes; the rules are its source."""

    cedar_schema: str
    authorization_policies: str
    approval_policies: str


class ActivationNote(BaseModel):
    """The latest activation of a bundle in a Space the reader can see: when, by whom, and
    the reason recorded with it. `reason` is null for an activation that gave none (the CLI
    without `--reason`, quickstart, the samples). The reason is a person's text and the
    console renders it as text."""

    at: datetime
    by_id: UUID
    by_label: str | None
    by_number: int | None
    reason: str | None


class RulesFileSummary(BaseModel):
    """Whether this policy's rules download as a rules file, and what the file leaves out
    because it names this workspace's own records: the budgets counted for a named group,
    account or Space, and the context settings."""

    available: bool
    omitted_budgets: list[str]
    omitted_context: bool


class RulesFileView(BaseModel):
    """A policy's rules as the file `ruleset-compile` reads, with what it leaves out."""

    filename: str
    ruleset: dict[str, Any]
    omitted_budgets: list[str]
    omitted_context: bool


class BundleDetail(BaseModel):
    bundle_id: UUID
    content_hash: str
    state: BundleState
    active: bool
    changed_at: datetime | None
    mappings: list[MappingRow]
    limits: list[LimitMeter]
    quorum: list[QuorumRow]
    context_settings: list[ContextSettingRow]
    # Empty for a bundle created from a document: it has no ruleset, and the compiled policy
    # below is the only statement of what it does.
    rules: list[RuleRow]
    written_as_rules: bool
    compiled: CompiledPolicy
    form_available: bool = False
    rules_origin: Literal["rules", "recognized-seed", "cedar"] = "cedar"
    # The starter policy sample targets installed (#420); the console shows a Sample badge.
    sample: bool = False
    activation: ActivationNote | None = None
    rules_file: RulesFileSummary = RulesFileSummary(
        available=False, omitted_budgets=[], omitted_context=False
    )


class ChangedDecisionRow(BaseModel):
    execution_id: UUID
    action: str
    semantic_time: datetime
    baseline_effect: str
    baseline_reasons: list[str]
    candidate_effect: str
    candidate_reasons: list[str]
    # The rule ids behind the candidate's obligations, when the candidate carries a ruleset.
    rule_ids: list[str]
    differences: list[str]
    required_approvers: int


class BundlePreviewView(BaseModel):
    """What the candidate would have decided over the tenant's own recent frozen history.

    `available` is false when the history could not be exported or verified; the page says so
    rather than showing zeroes, exactly as the Jinja page's note does.
    """

    bundle_id: UUID
    content_hash: str
    state: BundleState
    window: Window
    window_seconds: int
    available: bool
    considered: int
    baseline_effects: dict[str, int]
    candidate_effects: dict[str, int]
    changed: list[ChangedDecisionRow]
    complete: bool
    issues: list[str]
    # Whose decisions were counted: the workspace's, or only the Spaces the reader manages.
    scope: Literal["workspace", "spaces"]


Change = Literal["added", "removed", "changed"]
WhyNot = Literal["no-space", "no-active", "is-active", "cedar"]


class RuleChangeView(BaseModel):
    """One rule that differs, with how each side reads; `before` or `after` is null when the
    rule is added or removed."""

    change: Change
    rule_id: str
    action: str
    before_effect: str | None
    after_effect: str | None
    before: str | None
    after: str | None
    fields: list[str]
    direction: Direction


class BudgetChangeView(BaseModel):
    """One budget that differs, each side's ceiling in words."""

    change: Change
    rule_id: str
    before: str | None
    after: str | None
    fields: list[str]
    direction: Direction


class ActionChangeView(BaseModel):
    """An action the policy newly maps (wider when one of its own allow rules names it) or no
    longer maps."""

    change: Literal["added", "removed"]
    action: str
    direction: Direction


class MappingChangeView(BaseModel):
    change: Change
    action: str
    operation_ref: str
    account_id: UUID
    fields: list[str]
    direction: Direction


class ContextChangeView(BaseModel):
    change: Change
    contract: str
    source_kind: str
    fields: list[str]
    direction: Direction


class SignalChangeView(BaseModel):
    change: Change
    contract: str
    capability: str
    direction: Direction


class PolicyComparison(BaseModel):
    """How a policy differs from the one active in the reader's Space, as the rules read.

    Never a decision: the preview shows what would actually have decided differently. A change
    that adds a connector account, declares an external executor or turns off observe-only is
    a change here too, so such a draft never reads as no change. `why_not` says why nothing
    was compared: no single Space chosen, no active policy there, this is the active policy,
    or one side is written in Cedar rather than as rules.
    """

    against: UUID | None
    comparable: bool
    why_not: WhyNot | None
    rules: list[RuleChangeView]
    budgets: list[BudgetChangeView]
    actions_added: list[str]
    actions_removed: list[str]
    actions: list[ActionChangeView]
    mappings: list[MappingChangeView]
    context: list[ContextChangeView]
    signals: list[SignalChangeView]
    wider: int
    narrower: int
    unclear: int


# A store refusal, as the API's typed code and, where the store named one, its location.
REFUSALS: dict[str, str] = {
    "INVALID_IDENTITY": "FORBIDDEN",
    "INVALID_STATE": "CONFLICT",
    "NO_ACTIVE_BUNDLE": "CONFLICT",
    "INVALID_BUNDLE": "INVALID_BUNDLE",
    "INVALID_COMPONENT": "INVALID_BUNDLE",
    "RULESET_MISMATCH": "INVALID_BUNDLE",
    "INVALID_WINDOW": "INVALID_BODY",
    # The one field of a bundle's own content a person actually typed, found to be shaped
    # like a secret: a bad value at its field, like `INVALID_WINDOW`, never a structural
    # defect of the bundle like `INVALID_BUNDLE` below.
    "INVALID_TEXT": "INVALID_BODY",
    # An activation's reason that is blank, too long or shaped like a secret, named by its
    # field and never quoted (THREAT_MODEL.md T7.7).
    "INVALID_REASON": "INVALID_BODY",
    "INVALID_CLOCK": "UNAVAILABLE",
    "SPACE_ARCHIVED": "SPACE_ARCHIVED",
}


def refused(exc: PolicyStoreError) -> ApiError:
    """The typed refusal for a store code; anything unlisted is unavailability.

    `INVALID_BUNDLE` reads a bundle that cannot be used as it stands: its components no longer
    match the tenant's provisioning, or its compiled policy disagrees with its rules. The store
    names the component or the field, and that name is the only detail carried out, because it
    is the bundle's own structure and never a database or policy diagnostic.
    """
    code = REFUSALS.get(exc.code, "UNAVAILABLE")
    return ApiError(code, fields=[exc.location] if exc.location else None)


def _mappings(content: BundleContent) -> list[MappingRow]:
    return [
        MappingRow(
            operation_ref=item.operation_ref,
            account_id=item.account_id,
            mapping_version=item.mapping_version,
            schema_version=item.schema_version,
            context_contract_version=item.context_contract_version,
            observe_only=item.observe_only,
            external_executor=item.external_executor,
            action=item.action,
        )
        for item in content.mappings
    ]


def _quorum(content: BundleContent) -> list[QuorumRow]:
    names = dict(review_rule_ids(content.ruleset)) if content.ruleset else {}
    return [
        QuorumRow(
            rule_id=rule.rule_id,
            obligation=rule.obligation,
            required=rule.required,
            rule=names.get(rule.obligation),
        )
        for rule in content.quorum or ()
    ]


def _settings(content: BundleContent) -> list[ContextSettingRow]:
    return [
        ContextSettingRow(
            context_contract_version=setting.context_contract_version,
            source_kind=setting.source_kind,
            max_age_seconds=setting.max_age_seconds,
            permitted_writers=list(setting.permitted_writers),
        )
        for setting in content.context_settings or ()
    ]


def _rules(content: BundleContent) -> list[RuleRow]:
    ruleset = content.ruleset
    if ruleset is None:
        return []
    return [
        RuleRow(
            id=rule.id,
            action=rule.action,
            effect=rule.effect,
            sentence=sentence(rule),
            note=rule.note,
        )
        for rule in ruleset.rules
    ]


def _meters(rows: list[dict[str, Any]]) -> list[LimitMeter]:
    return [
        LimitMeter(
            rule_id=row["rule"].rule_id,
            scope=row["rule"].scope,
            scope_label=row["scope"],
            actions=list(row["rule"].action_names),
            labels=row["labels"],
            window=row["window"],
            window_seconds=row["rule"].window_seconds,
            max_targets=row["rule"].max_targets,
            budget=row["rule"].budget,
            on_exceed=row["rule"].on_exceed,
            used=row["used"],
            counted=row["counted"],
        )
        for row in rows
    ]


def _detail(
    record: BundleRecord, summary: BundleSummary | None, meters: list[dict[str, Any]]
) -> BundleDetail:
    content = record.content
    return BundleDetail(
        bundle_id=content.bundle_id,
        content_hash=content.content_hash,
        state=record.state,
        active=bool(summary and summary.active),
        changed_at=summary.changed_at if summary else None,
        mappings=_mappings(content),
        limits=_meters(meters),
        quorum=_quorum(content),
        context_settings=_settings(content),
        rules=_rules(content),
        written_as_rules=content.ruleset is not None,
        compiled=CompiledPolicy(
            cedar_schema=content.cedar_schema,
            authorization_policies=content.authorization_policies,
            approval_policies=content.approval_policies,
        ),
    )


def _scope_in(
    conn: Connection, runtime: Runtime, session: Session
) -> tuple[UUID | None, Visibility]:
    try:
        _policy_identity(conn, session.identity, runtime.clock)
    except PolicyStoreError as exc:
        raise refused(exc) from None
    check_session(conn, session, runtime.clock)
    visibility = visible_spaces(conn, session)
    try:
        selected = write_space(conn, session.identity.tenant_id, visibility)
    except SpaceError:
        selected = None
    return selected, replace(visibility, current=selected)


def _writable_scope(runtime: Runtime, session: Session) -> UUID:
    with runtime.db.transaction(session.identity.tenant_id) as conn:
        selected, visibility = _scope_in(conn, runtime, session)
        if selected is None:
            raise ApiError("CONFLICT")
        if not visibility.everything and visibility.roles.get(selected) != "ADMIN":
            raise ApiError("FORBIDDEN")
        if is_archived(conn, session.identity.tenant_id, selected):
            raise ApiError("SPACE_ARCHIVED")
        return selected


def _scoped_summaries(
    runtime: Runtime, session: Session, *, space: UUID | None = None
) -> tuple[UUID | None, tuple[BundleSummary, ...]]:
    """List only owned/offered bundles; active always means selected in this Space."""
    with runtime.db.transaction(session.identity.tenant_id) as conn:
        selected, visibility = _scope_in(conn, runtime, session)
        if space is not None:
            if not visibility.allows(space):
                raise ApiError("FORBIDDEN")
            selected = space
            visibility = replace(visibility, current=space)
        # Only fixed predicates and literal aliases; request values remain bound.
        scope = space_clause(visibility, "c", offered=True)
        allowed = set(
            conn.execute(
                text(
                    "SELECT c.bundle_id FROM execbound.policy_bundle_contents c "
                    "WHERE c.tenant_id=:t" + scope.sql  # nosec B608 - fixed predicate; all values bound
                ),
                {"t": session.identity.tenant_id, **scope.params},
            ).scalars()
        )
    summaries = list_bundles(runtime.db, session.identity, runtime.clock, space=selected)
    return selected, tuple(
        item if selected is not None else replace(item, active=False)
        for item in summaries
        if item.bundle_id in allowed
    )


def _sample_bundles(runtime: Runtime, session: Session) -> frozenset[UUID]:
    """The starter bundles sample targets installed in this tenant, for the Sample badge."""
    with runtime.db.transaction(session.identity.tenant_id) as conn:
        check_session(conn, session, runtime.clock)
        return sample_bundles(conn, session.identity.tenant_id)


def _visible_bundle(runtime: Runtime, session: Session, bundle_id: UUID) -> None:
    _, summaries = _scoped_summaries(runtime, session)
    if not any(item.bundle_id == bundle_id for item in summaries):
        raise ApiError("NOT_FOUND")


# The latest activation of each listed bundle in a Space the reader can see. The literal
# `kind` matches the partial index `audit_events_policy_activation` (migration 0076), so each
# id is one short index range rather than a walk of the tenant's events.
_NOTES = (
    "SELECT DISTINCT ON (a.payload ->> 'bundle_id') "
    "a.payload ->> 'bundle_id' AS bundle_id, a.occurred_at, a.actor_id, "
    "a.payload ->> 'reason' AS reason "
    "FROM execbound.audit_events a "
    "WHERE a.tenant_id = :t AND a.kind = 'policy.bundle_activated' "
    "AND a.payload ->> 'bundle_id' = ANY(CAST(:ids AS text[]))"
)
_NOTES_ORDER = " ORDER BY a.payload ->> 'bundle_id', a.sequence DESC"


def _activation_notes(
    conn: Connection, tenant: UUID, bundle_ids: list[UUID], visibility: Visibility
) -> dict[UUID, ActivationNote]:
    """Per bundle, its latest activation in a Space the reader can see, with the actor's
    label and number. The space predicate is `space_clause`'s fixed text, as every other
    space-filtered read here; an activation in a Space the reader cannot see is not read."""
    if not bundle_ids:
        return {}
    scope = space_clause(visibility, "a")
    statement = _NOTES + scope.sql + _NOTES_ORDER  # nosec B608 - fixed predicate; values bound
    rows = conn.execute(
        text(statement),
        {"t": tenant, "ids": sorted(str(item) for item in bundle_ids), **scope.params},
    ).all()
    actors = {row.actor_id for row in rows}
    people = {
        row.principal_id: row
        for row in conn.execute(
            text(
                "SELECT principal_id, label, number FROM execbound.principals "
                "WHERE tenant_id = :t AND principal_id = ANY(CAST(:ids AS uuid[]))"
            ),
            {"t": tenant, "ids": sorted(str(item) for item in actors)},
        )
    }
    notes: dict[UUID, ActivationNote] = {}
    for row in rows:
        person = people.get(row.actor_id)
        notes[UUID(row.bundle_id)] = ActivationNote(
            at=row.occurred_at,
            by_id=row.actor_id,
            by_label=person.label if person else None,
            by_number=person.number if person else None,
            reason=row.reason,
        )
    return notes


def _notes(
    runtime: Runtime, session: Session, bundle_ids: list[UUID]
) -> dict[UUID, ActivationNote]:
    with runtime.db.transaction(session.identity.tenant_id, snapshot=True) as conn:
        _, visibility = _scope_in(conn, runtime, session)
        return _activation_notes(conn, session.identity.tenant_id, bundle_ids, visibility)


def _writable_bundle(
    runtime: Runtime, session: Session, bundle_id: UUID, *, offered: bool = False
) -> UUID:
    selected = _writable_scope(runtime, session)
    with runtime.db.transaction(session.identity.tenant_id) as conn:
        _, visibility = _scope_in(conn, runtime, session)
        # Only fixed predicates and literal aliases; request values remain bound.
        scope = space_clause(replace(visibility, current=selected), "c", offered=offered)
        found = conn.execute(
            text(
                "SELECT 1 FROM execbound.policy_bundle_contents c "
                "WHERE c.tenant_id=:t AND c.bundle_id=:b" + scope.sql  # nosec B608 - fixed predicate; all values bound
            ),
            {"t": session.identity.tenant_id, "b": bundle_id, **scope.params},
        ).scalar_one_or_none()
        if found is None:
            raise ApiError("NOT_FOUND")
    return selected


def read_detail(runtime: Runtime, session: Session, bundle_id: UUID) -> BundleDetail:
    """One bundle as the detail page reads it: the record, its lifecycle row, and the meters."""
    identity = session.identity
    try:
        _, summaries = _scoped_summaries(runtime, session)
        if not any(item.bundle_id == bundle_id for item in summaries):
            raise ApiError("NOT_FOUND")
        record = read_bundle(runtime.db, identity, bundle_id, runtime.clock)
    except PolicyStoreError as exc:
        if exc.code == "INVALID_IDENTITY":
            raise ApiError("FORBIDDEN") from None
        # A bundle of another tenant, or none, is the same answer: there is nothing here.
        raise ApiError("NOT_FOUND") from None
    summary = next((item for item in summaries if item.bundle_id == bundle_id), None)
    meters = pages.limit_meters(runtime, session, record.content)
    detail = _detail(record, summary, meters)
    try:
        recognized = source_rules(record.content, runtime.catalog)
    except (ValueError, KeyError):
        recognized = None
    detail.form_available = recognized is not None and all(
        limit.scope in ("principal", "tenant") and limit.actions is None
        for limit in record.content.limits
    )
    detail.sample = bundle_id in _sample_bundles(runtime, session)
    detail.activation = _notes(runtime, session, [bundle_id]).get(bundle_id)
    detail.rules_file = _rules_file_summary(record.content)
    if recognized is not None:
        detail.rules_origin = "rules" if record.content.ruleset else "recognized-seed"
        detail.rules = [
            RuleRow(
                id=rule.id,
                action=rule.action,
                effect=rule.effect,
                sentence=sentence(rule),
                note=rule.note,
            )
            for rule in recognized.rules
        ]
    return detail


def _missing_or_invalid(
    runtime: Runtime, session: Session, bundle_id: UUID, exc: PolicyStoreError
) -> ApiError:
    """Tell a bundle that is not this tenant's from stored content that no longer matches.

    The store answers `INVALID_BUNDLE` for both, and the first is a 404 everywhere else on
    this API, so the record is read back to find out which happened rather than reporting the
    wrong one. The read is the administrator's own snapshot read, so it can see nothing a
    transition could not.
    """
    try:
        read_bundle(runtime.db, session.identity, bundle_id, runtime.clock)
    except PolicyStoreError:
        return ApiError("NOT_FOUND")
    return refused(exc)


def _transition(
    runtime: Runtime,
    session: Session,
    step: str,
    bundle_id: UUID,
    reason: str | None = None,
) -> BundleDetail:
    space = _writable_bundle(runtime, session, bundle_id, offered=step == "activate")
    try:
        if step == "activate":
            activate_bundle(
                runtime.db, session.identity, bundle_id, runtime.clock, space=space, reason=reason
            )
        else:
            action = {"validate": validate_bundle, "retire": retire_bundle}
            action[step](runtime.db, session.identity, bundle_id, runtime.clock)
    except PolicyStoreError as exc:
        if exc.code == "INVALID_BUNDLE":
            raise _missing_or_invalid(runtime, session, bundle_id, exc) from None
        raise refused(exc) from None
    return read_detail(runtime, session, bundle_id)


def policy_routes(
    routes: APIRouter, runtime: Runtime, config: HumanConfig, guards: ApiGuards
) -> None:
    @routes.get("/policy", response_model=PolicyPage, operation_id="listPolicy")
    async def list_policy(request: Request) -> PolicyPage:
        session, _ = await guards.session(request)
        try:
            selected, summaries = await run_in_threadpool(_scoped_summaries, runtime, session)
        except PolicyStoreError as exc:
            raise refused(exc) from None
        active_id = next((item.bundle_id for item in summaries if item.active), None)
        starter_available, starter_hint = False, ""
        if selected is None:
            starter_hint = "Choose a Space before starting or copying a policy."
        elif active_id is None:
            try:
                await run_in_threadpool(_first_policy, runtime, session)
                starter_available = True
            except ApiError as exc:
                if exc.status_code == 403:
                    starter_hint = "A Space administrator can create a policy here."
                elif exc.code == "SPACE_ARCHIVED":
                    starter_hint = "Restore this Space before creating a policy."
                elif exc.status_code != 400:
                    raise
                else:
                    starter_hint = (
                        "Connect a protected endpoint or identity provider and register its action "
                        "mappings on the server. Then return here to create the first policy."
                    )
        marked = await run_in_threadpool(_sample_bundles, runtime, session)
        notes = await run_in_threadpool(
            _notes, runtime, session, [item.bundle_id for item in summaries]
        )
        return PolicyPage(
            bundles=[
                BundleRow(
                    bundle_id=item.bundle_id,
                    content_hash=item.content_hash,
                    state=item.state,
                    changed_at=item.changed_at,
                    active=item.active,
                    sample=item.bundle_id in marked,
                    note=notes[item.bundle_id].reason if item.bundle_id in notes else None,
                )
                for item in summaries
            ],
            active=active_id,
            starter_available=starter_available,
            starter_hint=starter_hint,
        )

    @routes.post(
        "/policy",
        response_model=BundleDetail,
        operation_id="createPolicyBundle",
        openapi_extra=body_of(CreateBundle),
    )
    async def create_policy_bundle(request: Request) -> BundleDetail:
        session, body = await guards.mutation(request, CreateBundle, max_bytes=CREATE_BYTES)
        return await run_in_threadpool(_create, runtime, session, body)

    @routes.get("/policy/{bundle_id}", response_model=BundleDetail, operation_id="readPolicyBundle")
    async def read_policy_bundle(request: Request, bundle_id: str) -> BundleDetail:
        session, _ = await guards.session(request)
        return await run_in_threadpool(read_detail, runtime, session, parse_uuid(bundle_id))

    @routes.post(
        "/policy/{bundle_id}/validate",
        response_model=BundleDetail,
        operation_id="validatePolicyBundle",
        openapi_extra=body_of(Confirmed),
    )
    async def validate_policy_bundle(request: Request, bundle_id: str) -> BundleDetail:
        session, _ = await guards.mutation(request, Confirmed)
        return await run_in_threadpool(
            _transition, runtime, session, "validate", parse_uuid(bundle_id)
        )

    @routes.post(
        "/policy/{bundle_id}/activate",
        response_model=BundleDetail,
        operation_id="activatePolicyBundle",
        openapi_extra=body_of(ActivateBody),
    )
    async def activate_policy_bundle(request: Request, bundle_id: str) -> BundleDetail:
        session, body = await guards.mutation(request, ActivateBody)
        return await run_in_threadpool(
            _transition, runtime, session, "activate", parse_uuid(bundle_id), body.reason
        )

    @routes.post(
        "/policy/{bundle_id}/retire",
        response_model=BundleDetail,
        operation_id="retirePolicyBundle",
        openapi_extra=body_of(Confirmed),
    )
    async def retire_policy_bundle(request: Request, bundle_id: str) -> BundleDetail:
        session, _ = await guards.mutation(request, Confirmed)
        return await run_in_threadpool(
            _transition, runtime, session, "retire", parse_uuid(bundle_id)
        )

    @routes.post(
        "/policy/{bundle_id}/preview",
        response_model=BundlePreviewView,
        operation_id="previewPolicyBundle",
        openapi_extra=body_of(PreviewBody),
    )
    async def preview_policy_bundle(request: Request, bundle_id: str) -> BundlePreviewView:
        session, body = await guards.mutation(request, PreviewBody)
        return await run_in_threadpool(_preview, runtime, session, parse_uuid(bundle_id), body)

    @routes.get(
        "/policy/{bundle_id}/ruleset",
        response_model=RulesFileView,
        operation_id="readPolicyRulesFile",
    )
    async def read_policy_rules_file(request: Request, bundle_id: str) -> RulesFileView:
        session, _ = await guards.session(request)
        return await run_in_threadpool(_rules_file, runtime, session, parse_uuid(bundle_id))

    @routes.get(
        "/policy/{bundle_id}/compare",
        response_model=PolicyComparison,
        operation_id="comparePolicyBundle",
    )
    async def compare_policy_bundle(request: Request, bundle_id: str) -> PolicyComparison:
        session, _ = await guards.session(request)
        return await run_in_threadpool(_compare, runtime, session, parse_uuid(bundle_id))

    @routes.get(
        "/policy/{bundle_id}/rules", response_model=RulesView, operation_id="readPolicyRules"
    )
    async def read_policy_rules(request: Request, bundle_id: str) -> RulesView:
        session, _ = await guards.session(request)
        return await run_in_threadpool(read_rules, runtime, session, parse_uuid(bundle_id))

    @routes.post(
        "/policy/{bundle_id}/rules",
        response_model=RulesView,
        operation_id="changePolicyRules",
        openapi_extra=body_of(RulesetBody),
    )
    async def change_policy_rules(request: Request, bundle_id: str) -> RulesView:
        session, body = await guards.mutation(request, RulesetBody)
        return await run_in_threadpool(_change_rules, runtime, session, parse_uuid(bundle_id), body)


def _ceiling_words(rule: LimitRule) -> str:
    """A budget's ceiling as a sentence: "10 autonomous targets per 1 hour, then denied"."""
    then = "denied" if rule.on_exceed == "DENY" else "held for a person"
    return (
        f"{rule.max_targets} {rule.budget} targets per {window_label(rule.window_seconds)}, "
        f"then {then}"
    )


def _side(content: BundleContent, runtime: Runtime) -> Side | None:
    """One side as compared: the stored ruleset, or the reviewed rules a recognized seed
    reads as, with what the content carries beside them. None for a policy in Cedar alone."""
    try:
        ruleset = content.ruleset or source_rules(content, runtime.catalog)
    except (ValueError, KeyError):
        ruleset = None
    if ruleset is None:
        return None
    return Side(
        ruleset=ruleset,
        mappings=content.mappings,
        context_settings=content.context_settings,
        signal_mappings=content.signal_mappings,
    )


def _rule_action(after: Rule | None, before: Rule | None) -> str:
    """The action a changed rule governs: the candidate's, else the one it replaced."""
    for rule in (after, before):
        if rule is not None:
            return rule.action
    return ""


def _not_compared(against: UUID | None, why_not: WhyNot) -> PolicyComparison:
    return PolicyComparison(
        against=against,
        comparable=False,
        why_not=why_not,
        rules=[],
        budgets=[],
        actions_added=[],
        actions_removed=[],
        actions=[],
        mappings=[],
        context=[],
        signals=[],
        wider=0,
        narrower=0,
        unclear=0,
    )


def _comparison_view(against: UUID, result: Comparison) -> PolicyComparison:
    return PolicyComparison(
        against=against,
        comparable=True,
        why_not=None,
        rules=[
            RuleChangeView(
                change=item.change,
                rule_id=item.rule_id,
                action=_rule_action(item.after, item.before),
                before_effect=item.before.effect if item.before else None,
                after_effect=item.after.effect if item.after else None,
                before=sentence(item.before) if item.before else None,
                after=sentence(item.after) if item.after else None,
                fields=list(item.fields),
                direction=item.direction,
            )
            for item in result.rules
        ],
        budgets=[
            BudgetChangeView(
                change=item.change,
                rule_id=item.rule_id,
                before=_ceiling_words(item.before) if item.before else None,
                after=_ceiling_words(item.after) if item.after else None,
                fields=list(item.fields),
                direction=item.direction,
            )
            for item in result.budgets
        ],
        actions_added=list(result.actions_added),
        actions_removed=list(result.actions_removed),
        actions=[
            ActionChangeView(change=item.change, action=item.action, direction=item.direction)
            for item in result.actions
        ],
        mappings=[
            MappingChangeView(
                change=item.change,
                action=item.action,
                operation_ref=item.operation_ref,
                account_id=item.account_id,
                fields=list(item.fields),
                direction=item.direction,
            )
            for item in result.mappings
        ],
        context=[
            ContextChangeView(
                change=item.change,
                contract=item.contract,
                source_kind=item.source_kind,
                fields=list(item.fields),
                direction=item.direction,
            )
            for item in result.context
        ],
        signals=[
            SignalChangeView(
                change=item.change,
                contract=item.contract,
                capability=item.capability,
                direction=item.direction,
            )
            for item in result.signals
        ],
        wider=result.count("wider"),
        narrower=result.count("narrower"),
        unclear=result.count("unclear"),
    )


def _compare(runtime: Runtime, session: Session, bundle_id: UUID) -> PolicyComparison:
    """A policy against the one active in the reader's current Space, as the rules read.

    The candidate is read as the detail reads it, so another Space's policy that is not
    offered answers 404. The active side is this Space's selection, which the reader can
    always read. Nothing is replayed.
    """
    identity = session.identity
    try:
        selected, summaries = _scoped_summaries(runtime, session)
        if not any(item.bundle_id == bundle_id for item in summaries):
            raise ApiError("NOT_FOUND")
        candidate = read_bundle(runtime.db, identity, bundle_id, runtime.clock)
        if selected is None:
            return _not_compared(None, "no-space")
        active_id = next((item.bundle_id for item in summaries if item.active), None)
        if active_id is None:
            return _not_compared(None, "no-active")
        if active_id == bundle_id:
            return _not_compared(active_id, "is-active")
        active = read_bundle(runtime.db, identity, active_id, runtime.clock)
    except PolicyStoreError as exc:
        if exc.code == "INVALID_IDENTITY":
            raise ApiError("FORBIDDEN") from None
        raise ApiError("NOT_FOUND") from None
    ours, theirs = _side(candidate.content, runtime), _side(active.content, runtime)
    if ours is None or theirs is None:
        return _not_compared(active_id, "cedar")
    return _comparison_view(active_id, compare(ours, theirs))


def _create(runtime: Runtime, session: Session, body: CreateBundle) -> BundleDetail:
    """A draft from the person's JSON, or from the active bundle read back as that JSON."""
    identity = session.identity
    space = _writable_scope(runtime, session)
    source_id = None
    document = body.document
    if body.source == "ruleset":
        document = _ruleset_document(runtime, session, body.ruleset, space)
    elif body.template == "security-response":
        try:
            _, summaries = _scoped_summaries(runtime, session, space=space)
        except PolicyStoreError as exc:
            raise refused(exc) from None
        if any(item.active for item in summaries):
            raise ApiError("CONFLICT")
        document = _first_policy(runtime, session, space=space).model_dump_json()
    elif body.source in ("active", "bundle", "template"):
        try:
            _, summaries = _scoped_summaries(runtime, session, space=space)
            if body.bundle_id is not None:
                source_id = parse_uuid(body.bundle_id)
                if not any(item.bundle_id == source_id for item in summaries):
                    raise ApiError("NOT_FOUND")
            else:
                active = next((item for item in summaries if item.active), None)
                if active is None:
                    raise PolicyStoreError("NO_ACTIVE_BUNDLE")
                source_id = active.bundle_id
            record = read_bundle(runtime.db, identity, source_id, runtime.clock)
        except PolicyStoreError as exc:
            raise refused(exc) from None
        if body.source == "template":
            try:
                converted = editable_copy(
                    record.content, runtime.catalog, review_all=body.template == "review-all"
                )
            except (ValueError, KeyError):
                converted = None
            if converted is None:
                raise ApiError("INVALID_BODY", fields=["template"])
            record = BundleRecord(converted, "DRAFT")
        document = record.content.model_dump_json()
    content, problems = pages.parse_document(_with_new_identity(document), identity.tenant_id)
    if content is None:
        if body.source == "ruleset":
            # A file within its own limit can still compile to a bundle over the document's.
            raise ApiError("INVALID_BODY", fields=["ruleset"])
        # The locations `parse_document` names, under the field the document arrived in.
        raise ApiError("INVALID_BODY", fields=["document." + item for item in problems][:8])
    try:
        record = create_bundle(
            runtime.db, identity, content, runtime.clock, space=space, source_bundle_id=source_id
        )
    except PolicyStoreError as exc:
        if exc.code == "INVALID_IDENTITY":
            raise ApiError("FORBIDDEN") from None
        raise refused(exc) from None
    return read_detail(runtime, session, record.content.bundle_id)


def _space_mappings(
    runtime: Runtime, session: Session, space: UUID
) -> tuple[tuple[MappingRef, ...], frozenset[str]]:
    """The active mappings this Space owns or is offered, and the actions only a mapping under
    a signal contract serves.

    A mapping whose contract has a signal fact is left out of the first: it needs the bundle's
    `signal_mappings`, the operator's verdict table and admitted producers, which neither the
    starter nor a rules file can write. Left in beside a v1 mapping, it would fail the whole
    policy. Its action is named in the second, so a rules file naming it is told so.
    """
    try:
        with runtime.db.transaction(session.identity.tenant_id) as conn:
            _, visibility = _scope_in(conn, runtime, session)
            if not visibility.everything and visibility.roles.get(space) != "ADMIN":
                raise ApiError("FORBIDDEN")
            # Only fixed predicates and literal aliases; request values remain bound.
            scope = space_clause(replace(visibility, current=space), "a", offered=True)
            rows = (
                conn.execute(
                    text(
                        """
                SELECT m.operation_ref, m.account_id, m.mapping_version,
                       m.schema_version, m.context_contract_version, m.action
                FROM execbound.operation_mappings m
                JOIN execbound.connector_accounts a USING (tenant_id, account_id, provider)
                WHERE m.tenant_id = :tenant AND m.active AND a.active
            """
                        + scope.sql  # nosec B608 - fixed predicate; all values bound
                        + " ORDER BY m.operation_ref"
                    ),
                    {"tenant": session.identity.tenant_id, **scope.params},
                )
                .mappings()
                .all()
            )
        usable: list[MappingRef] = []
        signal_only: set[str] = set()
        for row in rows:
            # A ref that is another name for its action carries that action, as
            # `ruleset-compile` writes it, so rules name the action and the ref stays the
            # operator's.
            mapping = MappingRef.model_validate(
                {**row, "action": row["action"] if row["action"] != row["operation_ref"] else None}
            )
            if any(
                isinstance(spec.storage, Signal)
                for spec in runtime.catalog.contract(row["context_contract_version"]).facts
            ):
                signal_only.add(mapping.action_name)
            else:
                usable.append(mapping)
        served = {mapping.action_name for mapping in usable}
        return tuple(usable), frozenset(signal_only - served)
    except (ValueError, KeyError):
        raise ApiError("INVALID_BODY", fields=["mappings"]) from None
    except SQLAlchemyError:
        raise ApiError("UNAVAILABLE") from None


def _first_policy(
    runtime: Runtime, session: Session, *, space: UUID | None = None
) -> BundleContent:
    """Use only the selected Space's owned or explicitly offered connector mappings."""
    selected = space or _writable_scope(runtime, session)
    mappings, _ = _space_mappings(runtime, session, selected)
    try:
        return first_policy(session.identity.tenant_id, mappings, runtime.catalog)
    except (ValueError, KeyError):
        raise ApiError("INVALID_BODY", fields=["mappings"]) from None


# The budget scopes that name one of this workspace's own records: a group, a connector
# account or a Space. A rules file leaves them out going out and refuses them coming in.
_QUALIFIED_SCOPES = {"group": "group_id", "account": "account_id", "space": "space_id"}
# At most this many locations in one refusal, as the pasted document's refusals.
_MAX_LOCATIONS = 8


def _rules_file_summary(content: BundleContent) -> RulesFileSummary:
    ruleset = content.ruleset
    if ruleset is None:
        return RulesFileSummary(available=False, omitted_budgets=[], omitted_context=False)
    return RulesFileSummary(
        available=True,
        omitted_budgets=[
            budget.rule_id for budget in ruleset.budgets if budget.scope in _QUALIFIED_SCOPES
        ],
        omitted_context=ruleset.context is not None,
    )


def _rules_file(runtime: Runtime, session: Session, bundle_id: UUID) -> RulesFileView:
    """A policy's stored rules as the file `ruleset-compile` reads, read as the detail is.

    Left out, because they name this workspace's own records: every budget counted for a
    group, an account or a Space, and the context settings. Nothing else in a `Ruleset`
    carries a record identifier. A policy with no stored rules (custom Cedar, or a recognized
    seed before an editable draft of it exists) answers CONFLICT.
    """
    try:
        _visible_bundle(runtime, session, bundle_id)
        record = read_bundle(runtime.db, session.identity, bundle_id, runtime.clock)
    except PolicyStoreError as exc:
        if exc.code == "INVALID_IDENTITY":
            raise ApiError("FORBIDDEN") from None
        raise ApiError("NOT_FOUND") from None
    ruleset = record.content.ruleset
    if ruleset is None:
        raise ApiError("CONFLICT")
    summary = _rules_file_summary(record.content)
    kept = tuple(budget for budget in ruleset.budgets if budget.scope not in _QUALIFIED_SCOPES)
    return RulesFileView(
        filename=f"execbound-rules-{str(bundle_id)[:8]}.json",
        ruleset=ruleset.model_copy(update={"budgets": kept, "context": None}).model_dump(
            mode="json"
        ),
        omitted_budgets=summary.omitted_budgets,
        omitted_context=summary.omitted_context,
    )


def _file_budget_index(raw: bytes) -> dict[str, int]:
    """Each budget's position in the file as written: `Ruleset` sorts budgets by id, and a
    refusal names the place in the person's own file."""
    try:
        budgets = json.loads(raw.decode("utf-8")).get("budgets") or []
    except (ValueError, AttributeError):
        return {}
    return {
        item["rule_id"]: index
        for index, item in enumerate(budgets)
        if isinstance(item, dict) and isinstance(item.get("rule_id"), str)
    }


def _action_locations(ruleset: Ruleset, budget_index: dict[str, int]) -> list[tuple[str, str]]:
    """Every action the file names, with its location, rules then budgets, in file order."""
    named: list[tuple[str, str]] = [
        (rule.action, f"ruleset.rules.{index}.action") for index, rule in enumerate(ruleset.rules)
    ]
    budgets = sorted(
        enumerate(ruleset.budgets), key=lambda pair: budget_index.get(pair[1].rule_id, pair[0])
    )
    for position, budget in budgets:
        index = budget_index.get(budget.rule_id, position)
        named.append((budget.action, f"ruleset.budgets.{index}.action"))
        for item, action in enumerate(budget.actions or ()):
            named.append((action, f"ruleset.budgets.{index}.actions.{item}"))
    return named


def _unmapped(
    named: list[tuple[str, str]], served: set[str], signal_only: frozenset[str]
) -> tuple[str, list[str]] | None:
    """The refusal for actions this Space cannot serve: `INVALID_BODY` where no mapping serves
    one, else `SIGNAL_MAPPING_ONLY` where only a signal-contract mapping does."""
    missing = [(action, where) for action, where in named if action not in served]
    if not missing:
        return None
    absent = [where for action, where in missing if action not in signal_only]
    if absent:
        return "INVALID_BODY", absent[:_MAX_LOCATIONS]
    return "SIGNAL_MAPPING_ONLY", [where for _, where in missing][:_MAX_LOCATIONS]


def _ruleset_document(runtime: Runtime, session: Session, text_body: str, space: UUID) -> str:
    """A draft's document from a rules file, over this Space's own mappings (#678).

    In order, and the first failure answers: parse it as `ruleset-compile` does; refuse what
    names another workspace's records (a qualified budget, the context); resolve every action
    against this Space's own or offered mappings; compile over only the mappings that serve
    the file's actions, with no context and no signal mappings. The caller then creates it
    through the one path every draft takes, so the creation scope, the archived-Space refusal
    and the people's text screen all apply, and it lands as a DRAFT and nothing more.
    """
    raw = text_body.encode("utf-8")
    try:
        ruleset = parse_ruleset_document(raw)
    except RulesetDocumentError as exc:
        fields = [
            "ruleset" if location == "<root>" else f"ruleset.{location}"
            for location in exc.locations
        ]
        raise ApiError("INVALID_BODY", fields=fields[:_MAX_LOCATIONS]) from None
    budget_index = _file_budget_index(raw)
    qualified = [
        f"ruleset.budgets.{budget_index.get(budget.rule_id, position)}.{field}"
        for position, budget in enumerate(ruleset.budgets)
        for scope, field in _QUALIFIED_SCOPES.items()
        if budget.scope == scope or getattr(budget, field) is not None
    ]
    if ruleset.context is not None:
        qualified.append("ruleset.context")
    if qualified:
        raise ApiError("INVALID_BODY", fields=sorted(set(qualified))[:_MAX_LOCATIONS])
    usable, signal_only = _space_mappings(runtime, session, space)
    named = _action_locations(ruleset, budget_index)
    refusal = _unmapped(named, {mapping.action_name for mapping in usable}, signal_only)
    if refusal is not None:
        code, fields = refusal
        raise ApiError(code, fields=fields)
    wanted = {action for action, _ in named}
    mappings = tuple(mapping for mapping in usable if mapping.action_name in wanted)
    try:
        content = ruleset_bundle(
            ruleset,
            tenant_id=session.identity.tenant_id,
            bundle_id=uuid4(),
            mappings=mappings,
            catalog=runtime.catalog,
        )
    except RulesetError as error:
        raise _compile_refusal(error, ruleset, mappings, named) from None
    return content.model_dump_json()


def _compile_refusal(
    error: RulesetError,
    ruleset: Ruleset,
    mappings: tuple[MappingRef, ...],
    named: list[tuple[str, str]],
) -> ApiError:
    """The compiler's refusal at the file's own location. A refusal at `mappings.<n>` means
    two mappings this Space offers for the file's actions cannot share one policy: it is named
    at the first place the file names mapping n's action, so the person learns which action
    and what to do (`ruleset-compile --ref` chooses one). A rule's location is the compiler's
    emission order, which is turned back into the file's."""
    parts = error.location.split(".")
    if parts[0] == "mappings" and len(parts) > 1 and parts[1].isdigit():
        index = int(parts[1])
        action = mappings[index].action_name if index < len(mappings) else None
        where = next((place for named_action, place in named if named_action == action), None)
        return ApiError("MAPPINGS_CONFLICT", fields=[where or "ruleset"])
    if parts[0] == "rules" and len(parts) > 1 and parts[1].isdigit():
        emitted = _ordered(ruleset.rules)
        position = int(parts[1])
        if position < len(emitted):
            parts[1] = str(ruleset.rules.index(emitted[position]))
    return ApiError("INVALID_BODY", fields=["ruleset." + ".".join(parts)])


def _with_new_identity(document: str) -> str:
    """The pasted text with a fresh `bundle_id`, so a copy is a new bundle and not a collision.

    Only the one key is replaced, and only when the text is a JSON object; anything else is
    handed to `parse_document` exactly as it arrived, so its refusals stay the page's.
    """
    try:
        value = json.loads(document)
    except ValueError:
        return document
    if type(value) is not dict:
        return document
    value["bundle_id"] = str(uuid4())
    return json.dumps(value)


def _preview(
    runtime: Runtime, session: Session, bundle_id: UUID, body: PreviewBody
) -> BundlePreviewView:
    # Who may preview, and over which decisions, is `preview_scope`'s: a workspace-wide
    # administrator over the workspace, anyone else holding `policy.manage` over the Spaces
    # where they hold it (#678). The bundle must be one this reader may read.
    with runtime.db.transaction(session.identity.tenant_id) as conn:
        check_session(conn, session, runtime.clock)
    window = WINDOWS[body.window]
    try:
        _visible_bundle(runtime, session, bundle_id)
        record = read_bundle(runtime.db, session.identity, bundle_id, runtime.clock)
    except PolicyStoreError as exc:
        if exc.code == "INVALID_IDENTITY":
            raise ApiError("FORBIDDEN") from None
        raise ApiError("NOT_FOUND") from None
    names = dict(review_rule_ids(record.content.ruleset)) if record.content.ruleset else {}
    try:
        preview = preview_bundle(
            runtime.db,
            session.identity,
            bundle_id,
            window=window,
            clock=runtime.clock,
            catalog=runtime.catalog,
        )
    except PolicyStoreError as exc:
        if exc.code != "PREVIEW_UNAVAILABLE":
            raise refused(exc) from None
        try:
            scope = preview_scope(runtime.db, session.identity, runtime.clock)
        except PolicyStoreError as scoped:
            raise refused(scoped) from None
        # The page says the preview is unavailable rather than showing zeroes as a result.
        return BundlePreviewView(
            scope=scope,
            bundle_id=bundle_id,
            content_hash=record.content.content_hash,
            state=record.state,
            window=body.window,
            window_seconds=int(window.total_seconds()),
            available=False,
            considered=0,
            baseline_effects={},
            candidate_effects={},
            changed=[],
            complete=False,
            issues=[],
        )
    return BundlePreviewView(
        scope=preview.scope,
        bundle_id=preview.bundle_id,
        content_hash=preview.content_hash,
        state=record.state,
        window=body.window,
        window_seconds=preview.window_seconds,
        available=True,
        considered=preview.considered,
        baseline_effects=dict(preview.baseline_effects),
        candidate_effects=dict(preview.candidate_effects),
        changed=[
            ChangedDecisionRow(
                execution_id=change.execution_id,
                action=change.action,
                semantic_time=change.semantic_time,
                baseline_effect=change.baseline_effect,
                baseline_reasons=list(change.baseline_reasons),
                candidate_effect=change.candidate_effect,
                candidate_reasons=list(change.candidate_reasons),
                rule_ids=[
                    names[obligation]
                    for obligation in change.candidate_obligations
                    if obligation in names
                ],
                differences=list(change.differences),
                required_approvers=change.required_approvers,
            )
            for change in preview.changed
        ],
        complete=preview.complete,
        issues=list(preview.issues),
    )


# ---------------------------------------------------------------------------
# The rules of a draft (#273), kept where
# the console can read them back rather than in a hidden form field.
#
# One read and one write. The write takes the whole ruleset rather than one edit at a time:
# adding a rule, removing one, changing a note, setting a quorum and adding a budget are then
# the same operation with the same refusal, the same audit event and the same atomicity, and
# the location a refusal names is the location inside the ruleset the person is looking at.
# ---------------------------------------------------------------------------


class ConditionBody(BaseModel):
    """One condition as JSON. The model's own tuples cannot be validated strictly from a JSON
    array, so the body is declared with lists here and read back through `Ruleset` itself,
    which is what applies every bound and every rule of the model."""

    model_config = ConfigDict(extra="forbid")

    kind: Literal["fact", "argument"]
    name: str = Field(max_length=64)
    operator: ConditionOperator
    values: list[str | int | bool] = Field(min_length=1, max_length=MAX_VALUES)


class RuleBody(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str = Field(max_length=80)
    action: str = Field(max_length=80)
    effect: RuleEffect
    when: list[ConditionBody] = Field(default_factory=list, max_length=MAX_CONDITIONS)
    quorum: int | None = None
    note: str | None = Field(default=None, max_length=MAX_NOTE)


class BudgetBody(BaseModel):
    model_config = ConfigDict(extra="forbid")

    rule_id: str = Field(max_length=80)
    action: str = Field(max_length=80)
    # The form offers each agent, the whole tenant, and one group, connector account or space
    # named by its qualifier below; a selector budget, or one over several actions, still
    # reaches a bundle through pasted JSON, and the page says so.
    scope: Literal["principal", "tenant", "group", "account", "space"]
    # Bounded strings, as every console body carries an identifier: `Ruleset` parses them,
    # with the model's own rule that a scope and its qualifier come together or not at all,
    # and the route accepts only a qualifier the read offered (`_unoffered`).
    group_id: str | None = Field(default=None, pattern=UUID_PATTERN)
    account_id: str | None = Field(default=None, pattern=UUID_PATTERN)
    space_id: str | None = Field(default=None, pattern=UUID_PATTERN)
    window_seconds: int = Field(ge=1)
    max_targets: int = Field(ge=1)
    budget: Literal["autonomous", "total"]
    on_exceed: Literal["DENY", "REQUIRE_APPROVAL"]


class RulesetBody(BaseModel):
    model_config = ConfigDict(extra="forbid")

    rules: list[RuleBody] = Field(min_length=1, max_length=MAX_RULES)
    budgets: list[BudgetBody] = Field(default_factory=list, max_length=MAX_RULES)


class ConditionRow(BaseModel):
    kind: str
    name: str
    operator: str
    values: list[str | int | bool]


class RuleView(BaseModel):
    id: str
    action: str
    effect: RuleEffect
    sentence: str
    note: str | None
    quorum: int | None
    when: list[ConditionRow]


class ActionRules(BaseModel):
    """One action's rules, in the order the compiler writes them."""

    action: str
    label: str
    rules: list[RuleView]


class BudgetView(BaseModel):
    rule_id: str
    action: str
    actions: list[str]
    scope: str
    # The group, account or space the budget is counted for, the one its scope names; the
    # other two are null, as all three are for any other scope.
    group_id: UUID | None
    account_id: UUID | None
    space_id: UUID | None
    # The words for that qualifier: the group's or space's name, or the account's provider and
    # identifier prefix. A qualifier the read does not offer is shown by its identifier.
    qualifier: str | None
    window: str
    window_seconds: int
    max_targets: int
    budget: str
    on_exceed: str
    # Whether the form can show and restate this budget. A selector budget, one over several
    # actions, or one counted for a group, account or space the read does not offer is
    # read-only here, which keeps the whole draft read-only and names this budget, rather than
    # offering an edit every save would refuse (#678).
    editable: bool


class QualifierOption(BaseModel):
    id: UUID
    label: str


class QualifierOptions(BaseModel):
    """What a single-action budget of this bundle may be counted for, besides each agent and
    the whole tenant, as `_qualifiers` reads it inside the tenant's fence."""

    groups: list[QualifierOption]
    accounts: list[QualifierOption]
    spaces: list[QualifierOption]


class ChoiceView(BaseModel):
    kind: str
    name: str
    cedar_type: str
    operators: list[str]
    values: list[str | int | bool]
    minimum: int | None
    maximum: int | None


class ActionFields(BaseModel):
    action: str
    label: str
    choices: list[ChoiceView]


class RulesView(BaseModel):
    """A draft's rules, and everything the form needs to add one the compiler will accept."""

    bundle_id: UUID
    content_hash: str
    state: BundleState
    # A draft carrying a ruleset can be edited; anything else is read here and changed by
    # copying it to a new draft, which the page says.
    editable: bool
    written_as_rules: bool
    groups: list[ActionRules]
    budgets: list[BudgetView]
    # The groups, accounts and spaces the budget form's qualifier selects offer, and the only
    # ones the write accepts.
    qualifiers: QualifierOptions
    fields: list[ActionFields]
    compiled: CompiledPolicy


def _rule_view(rule: Rule) -> RuleView:
    return RuleView(
        id=rule.id,
        action=rule.action,
        effect=rule.effect,
        sentence=sentence(rule),
        note=rule.note,
        quorum=rule.quorum,
        when=[
            ConditionRow(
                kind=condition.kind,
                name=condition.name,
                operator=condition.operator,
                values=list(condition.values),
            )
            for condition in rule.when
        ],
    )


def _qualifiers(runtime: Runtime, session: Session, content: BundleContent) -> QualifierOptions:
    """The groups, accounts and spaces a budget of this bundle may name (#273).

    Groups are the tenant's principal groups, which are tenant-level by design: a group may
    hold agents of several spaces. Accounts are the active connector accounts the bundle's own
    mappings name, because every candidate admitted under this bundle uses one of them, so a
    budget on any other account would never charge anything. Spaces are those the bundle may
    serve, the space that owns it or every space once it is offered tenant-wide, narrowed to
    the ones this person may see, so a name is never read here that the space switcher would
    not show them. Every statement names the tenant and runs under its fence: another
    tenant's group, account or space is never among them, and the write accepts nothing these
    lists leave out. Validation and activation still check every qualifier again (T5.11).
    """
    tenant = session.identity.tenant_id
    mapped = sorted({str(mapping.account_id) for mapping in content.mappings})
    with runtime.db.transaction(tenant) as conn:
        _, visibility = _scope_in(conn, runtime, session)
        groups = [
            QualifierOption(id=row.group_id, label=row.name)
            for row in conn.execute(
                text(
                    "SELECT group_id, name FROM execbound.principal_groups "
                    "WHERE tenant_id=:t ORDER BY name, group_id"
                ),
                {"t": tenant},
            )
        ]
        accounts = [
            QualifierOption(id=row.account_id, label=f"{row.provider} ({str(row.account_id)[:8]})")
            for row in conn.execute(
                text(
                    "SELECT account_id, provider FROM execbound.connector_accounts "
                    "WHERE tenant_id=:t AND active AND account_id = ANY(CAST(:a AS uuid[])) "
                    "ORDER BY provider, account_id"
                ),
                {"t": tenant, "a": mapped},
            )
        ]
        owner = conn.execute(
            text(
                "SELECT space_id, offered_tenant_wide FROM execbound.policy_bundle_contents "
                "WHERE tenant_id=:t AND bundle_id=:b"
            ),
            {"t": tenant, "b": content.bundle_id},
        ).one_or_none()
        spaces = [
            # An archived space keeps its budgets, as the store keeps them, so it is offered
            # and says so rather than leaving a budget over it with nothing to show.
            QualifierOption(
                id=row.space_id,
                label=row.name if row.archived_at is None else f"{row.name} (archived)",
            )
            for row in conn.execute(
                text(
                    "SELECT space_id, name, archived_at FROM execbound.spaces "
                    "WHERE tenant_id=:t ORDER BY name, space_id"
                ),
                {"t": tenant},
            )
            if owner is not None
            and (owner.offered_tenant_wide or row.space_id == owner.space_id)
            and visibility.allows(row.space_id)
        ]
    return QualifierOptions(groups=groups, accounts=accounts, spaces=spaces)


def _qualifier(rule: LimitRule, qualifiers: QualifierOptions) -> str | None:
    """The words for the group, account or space a budget names; its identifier when the
    read does not offer it, and nothing for a scope that names none."""
    for value, options in (
        (rule.group_id, qualifiers.groups),
        (rule.account_id, qualifiers.accounts),
        (rule.space_id, qualifiers.spaces),
    ):
        if value is not None:
            return next((option.label for option in options if option.id == value), str(value))
    return None


def _unoffered(body: RulesetBody, qualifiers: QualifierOptions) -> list[str]:
    """Where the body names a group, account or space the read did not offer, in the order
    the budgets were written, so the refusal is at the field the person is looking at."""
    offered = {
        "group_id": {str(option.id) for option in qualifiers.groups},
        "account_id": {str(option.id) for option in qualifiers.accounts},
        "space_id": {str(option.id) for option in qualifiers.spaces},
    }
    return [
        f"ruleset.budgets.{index}.{name}"
        for index, budget in enumerate(body.budgets)
        for name, ids in offered.items()
        if (value := getattr(budget, name)) is not None and value not in ids
    ]


def _rules_view(runtime: Runtime, record: BundleRecord, qualifiers: QualifierOptions) -> RulesView:
    content = record.content
    ruleset = content.ruleset
    # Rules are about actions, and several refs may serve one: each action once, in the order
    # the bundle's mappings first name it.
    served = list(dict.fromkeys(mapping.action_name for mapping in content.mappings))
    fields = writable_fields(content.mappings, catalog=runtime.catalog)
    groups = [
        ActionRules(
            action=action,
            label=action_label(runtime, action),
            rules=[_rule_view(rule) for rule in rules_for(ruleset, action)] if ruleset else [],
        )
        for action in served
    ]
    return RulesView(
        bundle_id=content.bundle_id,
        content_hash=content.content_hash,
        state=record.state,
        editable=record.state == "DRAFT" and ruleset is not None,
        written_as_rules=ruleset is not None,
        groups=groups,
        budgets=[
            BudgetView(
                rule_id=rule.rule_id,
                action=rule.action,
                actions=list(rule.action_names),
                scope=rule.scope,
                group_id=rule.group_id,
                account_id=rule.account_id,
                space_id=rule.space_id,
                qualifier=_qualifier(rule, qualifiers),
                window=window_label(rule.window_seconds),
                window_seconds=rule.window_seconds,
                max_targets=rule.max_targets,
                budget=rule.budget,
                on_exceed=rule.on_exceed,
                editable=_expressible(rule) and _offered(rule, qualifiers),
            )
            for rule in (ruleset.budgets if ruleset else ())
        ],
        qualifiers=qualifiers,
        fields=[
            ActionFields(
                action=action,
                label=action_label(runtime, action),
                choices=[
                    ChoiceView(
                        kind=choice.kind,
                        name=choice.name,
                        cedar_type=choice.cedar_type,
                        operators=list(choice.operators),
                        values=list(choice.values),
                        minimum=choice.minimum,
                        maximum=choice.maximum,
                    )
                    for choice in fields.get(action, ())
                ],
            )
            for action in served
        ],
        compiled=CompiledPolicy(
            cedar_schema=content.cedar_schema,
            authorization_policies=content.authorization_policies,
            approval_policies=content.approval_policies,
        ),
    )


def _expressible(rule: LimitRule) -> bool:
    """Whether the form can state this budget: one action, counted for each agent, the whole
    tenant, or one group, account or space. A selector budget and one over several actions
    are not, and a draft carrying either is read but not changed, so no edit can drop one."""
    return rule.scope != "selector" and rule.actions is None


def _offered(rule: LimitRule, qualifiers: QualifierOptions) -> bool:
    """Whether the group, account or space this budget names is one the read offers, as
    `_unoffered` requires of every budget a write states. One the read no longer offers (a
    group the owner removed, a space the draft does not serve or the person may not see) could
    only be restated for the write to refuse, so the read names that budget as the one the form
    cannot change, and the draft is read but not changed there (#678)."""
    for value, options in (
        (rule.group_id, qualifiers.groups),
        (rule.account_id, qualifiers.accounts),
        (rule.space_id, qualifiers.spaces),
    ):
        if value is not None and all(option.id != value for option in options):
            return False
    return True


def _ruleset_of(body: RulesetBody) -> Ruleset:
    """The body as the real model, so every bound and rule of `Ruleset` decides, not this API.

    Read through JSON, as the pages do, because strict Python validation refuses a list where
    the model declares a tuple. A fault answers `INVALID_BODY` with the model's own field
    location under `ruleset`, never the value at fault.
    """
    payload = {
        "rules": [rule.model_dump(mode="json") for rule in body.rules],
        "budgets": [budget.model_dump(mode="json") for budget in body.budgets],
    }
    try:
        return Ruleset.model_validate_json(json.dumps(payload))
    except ValidationError as error:
        fields = sorted(
            {"ruleset." + ".".join(str(part) for part in item["loc"]) for item in error.errors()}
        )
        raise ApiError("INVALID_BODY", fields=fields[:8]) from None


def _readable_bundle(runtime: Runtime, session: Session, bundle_id: UUID) -> BundleRecord:
    """The rules read's whole authority: the bundle visible among this session's spaces, read
    under the reader's own policy permission.

    One helper behind the rules page and the drawer's rule link (`rules_readable`), so the
    link is offered exactly where the page it opens would answer (#678).
    """
    try:
        _visible_bundle(runtime, session, bundle_id)
        return read_bundle(runtime.db, session.identity, bundle_id, runtime.clock)
    except PolicyStoreError as exc:
        if exc.code == "INVALID_IDENTITY":
            raise ApiError("FORBIDDEN") from None
        raise ApiError("NOT_FOUND") from None


def rules_readable(runtime: Runtime, session: Session, bundle_id: UUID) -> bool:
    """Whether `GET /policy/{bundle_id}/rules` would answer this session; says nothing else
    about the bundle."""
    try:
        _readable_bundle(runtime, session, bundle_id)
    except ApiError:
        return False
    return True


def read_rules(runtime: Runtime, session: Session, bundle_id: UUID) -> RulesView:
    record = _readable_bundle(runtime, session, bundle_id)
    return _rules_view(runtime, record, _qualifiers(runtime, session, record.content))


def _change_rules(
    runtime: Runtime, session: Session, bundle_id: UUID, body: RulesetBody
) -> RulesView:
    _writable_bundle(runtime, session, bundle_id)
    ruleset = _ruleset_of(body)
    try:
        current = read_bundle(runtime.db, session.identity, bundle_id, runtime.clock)
        if not all(_expressible(limit) for limit in current.content.limits):
            raise ApiError("INVALID_BODY", fields=["ruleset.budgets"])
        if current.content.ruleset is not None:
            try:
                recognized = source_rules(current.content, runtime.catalog)
            except RulesetError as error:
                if error.location.startswith("mappings."):
                    # The draft's own mappings cannot compile together (a pasted document is
                    # stored uncompiled): a defect of the bundle, at the bundle's own field,
                    # never of the rules the caller sent.
                    raise ApiError("INVALID_BUNDLE", fields=[error.location]) from None
                recognized = None
            except (ValueError, KeyError):
                recognized = None
            if recognized is None:
                raise ApiError("INVALID_BODY", fields=["ruleset"])
        unoffered = _unoffered(body, _qualifiers(runtime, session, current.content))
        if unoffered:
            # Never the identifier at fault, which may be another tenant's: only where it is.
            raise ApiError("INVALID_BODY", fields=unoffered[:8])
        record = change_draft_rules(
            runtime.db,
            session.identity,
            bundle_id,
            ruleset,
            runtime.clock,
            catalog=runtime.catalog,
        )
    except PolicyStoreError as exc:
        if exc.code == "INVALID_RULESET":
            # The compiler's location, under the field the ruleset arrived in: an undeclared
            # fact, a wrong type or a value outside its domain says where it was written.
            raise ApiError(
                "INVALID_BODY", fields=["ruleset." + exc.location if exc.location else "ruleset"]
            ) from None
        if exc.code == "INVALID_BUNDLE":
            raise _missing_or_invalid(runtime, session, bundle_id, exc) from None
        raise refused(exc) from None
    return _rules_view(runtime, record, _qualifiers(runtime, session, record.content))
