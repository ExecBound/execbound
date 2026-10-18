# SPDX-License-Identifier: AGPL-3.0-only
"""Rules from a sentence: what a person meant, drafted as a rule they then submit.

The assistant never writes a rule. It reads the draft the person is editing, with that
person's own authority, and answers with a `Rule` the compiler has already accepted against
that draft, its sentence, and its conditions in the words the editor parses. The page
pre-fills its add-a-rule form with them beside the original words; the administrator submits
it, and the draft then goes through validation and preview like any other, whose changed
decisions are the check that the rule does what was meant.

Two things make a proposal safe to offer. The model's answer is constrained to the rule
model's own JSON schema and validated by the same validator the form uses, so nothing that is
not a rule can reach the page. And it is compiled with the draft's other rules against the
draft's mappings before it is offered, so a rule naming a fact the contract does not declare,
a value outside its domain or an action the draft does not map is refused here with the field
that caused it rather than at validation
(#330, version 2).
"""

import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any
from uuid import UUID

from pydantic import ValidationError

from execbound.assistant import ASKED
from execbound.assistant.client import ModelError, Transport, Usage, parse_response
from execbound.assistant.config import AssistantConfig
from execbound.assistant.loop import start_turn
from execbound.assistant.turns import AssistantError, complete_turn
from execbound.audit import acted_with, append_event
from execbound.policy.models import BundleContent, Rule, Ruleset
from execbound.policy.rulesets import (
    FieldChoice,
    RulesetError,
    compile_ruleset,
    condition_line,
    rule_schema,
    sentence,
    writable_fields,
)
from execbound.policy.store import PolicyStoreError, read_bundle
from execbound.runtime import Runtime
from execbound.secrets import find_secrets
from execbound.surfaces.sessions import Session

MAX_WORDS = 500
MAX_PROPOSAL_TOKENS = 1_000

INSTRUCTIONS = "\n".join(
    (
        "You draft one ExecBound policy rule from what a person describes. You do not write",
        "it anywhere: your answer is offered to them as a pre-filled form, which they read",
        "and submit themselves.",
        "",
        "Rules you follow without exception:",
        "1. Answer with exactly one rule in the schema you were given, and nothing else.",
        "2. Use only the actions listed below, and in a condition name only the facts and",
        "   arguments listed for that action, with an operator and a value that list admits.",
        "   Never invent a fact, an argument, an action or a value.",
        "3. effect is ALLOW to permit, DENY to refuse outright, or REVIEW to require a",
        "   person. A DENY always beats an ALLOW, so a rule that says 'never' is a DENY and",
        "   needs no exception written into it. quorum is how many approvers a REVIEW needs,",
        "   and belongs only on a REVIEW.",
        "4. id is a short lowercase name with hyphens that says what the rule does, and must",
        "   not be one of the draft's existing ids.",
        "5. A condition is a single comparison. Several conditions on one rule all have to",
        "   hold. If what the person described needs two rules, draft the one that carries",
        "   the effect they asked for.",
        "6. note is optional, at most one sentence, and is inert text: it reaches no policy.",
        "",
    )
)


class ProposalError(AssistantError):
    """A proposal that cannot be offered, with the field locations that caused it."""

    def __init__(self, code: str, locations: Sequence[str] = ()) -> None:
        super().__init__(code)
        self.locations = tuple(locations)


@dataclass(frozen=True)
class Proposal:
    """One rule the compiler has accepted against the draft, as the page needs it."""

    rule: Rule
    sentence: str
    lines: tuple[str, ...]
    usage: Usage


def _field_words(choice: FieldChoice) -> str:
    operators = "/".join(choice.operators)
    if choice.values:
        admits = ", ".join(
            str(value).lower() if type(value) is bool else str(value) for value in choice.values
        )
        allowed = f"one of: {admits}"
    elif choice.minimum is not None:
        allowed = f"a whole number from {choice.minimum} to {choice.maximum}"
    else:
        allowed = "a value of its type"
    return f"  - {choice.kind} {choice.name} ({choice.cedar_type}), {operators}, {allowed}"


def draft_digest(content: BundleContent, *, catalog: Any) -> str:
    """The draft as the model may read it: its actions, their fields, and its rule ids.

    Nothing of the tenant's beyond the ids the person is already looking at; the fields are
    the catalog's own declaration, which is the same for every tenant.
    """
    fields = writable_fields(content.mappings, catalog=catalog)
    lines = ["Actions this draft serves, and what a condition on each may name:"]
    for action, choices in sorted(fields.items()):
        lines.append(f"- {action}")
        lines.extend(_field_words(choice) for choice in choices)
    ruleset = content.ruleset
    existing = sorted(rule.id for rule in ruleset.rules) if ruleset else []
    lines.append("")
    lines.append(
        "Ids already used in this draft (choose a different one): "
        + (", ".join(existing) if existing else "none")
    )
    return "\n".join(lines) + "\n"


def build_request(config: AssistantConfig, digest: str, words: str) -> dict[str, Any]:
    """One call, one rule. No tools: the draft's own contract is the whole of what it needs."""
    return {
        "model": config.model,
        "max_tokens": MAX_PROPOSAL_TOKENS,
        "system": [
            {"type": "text", "text": INSTRUCTIONS, "cache_control": {"type": "ephemeral"}},
            {"type": "text", "text": digest},
        ],
        "output_config": {
            "effort": config.effort,
            "format": {"type": "json_schema", "schema": rule_schema()},
        },
        "messages": [{"role": "user", "content": words}],
    }


def _draft(runtime: Runtime, session: Session, bundle_id: UUID) -> BundleContent:
    """The draft this person is editing, or the refusal the rules page would make."""
    try:
        record = read_bundle(runtime.db, session.identity, bundle_id, runtime.clock)
    except PolicyStoreError as exc:
        raise AssistantError("INVALID_TURN" if exc.code == "NOT_FOUND" else exc.code) from None
    if record.state != "DRAFT" or record.content.ruleset is None:
        # Only a draft written as rules has rules to add one to; the page says the same.
        raise AssistantError("INVALID_STATE")
    try:
        compile_ruleset(record.content.ruleset, record.content.mappings, catalog=runtime.catalog)
    except RulesetError:
        # A draft whose own rules or mappings do not compile has nothing a new rule could be
        # checked against, and its defect is the draft's, not a model's answer: refused
        # before a turn is opened or anything is sent.
        raise AssistantError("INVALID_STATE") from None
    return record.content


def _validated(raw: str, content: BundleContent, catalog: Any) -> Rule:
    """The model's JSON as a rule the compiler accepts against this draft, or a refusal."""
    try:
        rule = Rule.model_validate_json(raw)
    except ValidationError as exc:
        locations = sorted({".".join(str(part) for part in item["loc"]) for item in exc.errors()})
        raise ProposalError("INVALID_PROPOSAL", locations[:8]) from None
    # The model's answer is untrusted text. Its id is written into the chain as `proposed`,
    # and a rule the person submits becomes bundle content, which the replay export checks
    # too; an event the export's secret check flags fails that tenant's export at its window
    # for good. So the whole rule is screened, not only its id, and refused like any other
    # unusable answer, naming the field and not what was in it.
    found = find_secrets(rule.model_dump(mode="json"))
    if found:
        fields = sorted({re.split(r"[.\[]", item.path, maxsplit=1)[0] for item in found})
        raise ProposalError("INVALID_PROPOSAL", fields[:8])
    ruleset = content.ruleset
    assert ruleset is not None  # `_draft` refused a draft without one
    if any(existing.id == rule.id for existing in ruleset.rules):
        raise ProposalError("INVALID_PROPOSAL", ["id"]) from None
    try:
        compile_ruleset(
            Ruleset(rules=(*ruleset.rules, rule), budgets=ruleset.budgets),
            content.mappings,
            catalog=catalog,
        )
    except RulesetError as error:
        # The compiler counts the rules it was given, so its location names the rule's
        # position in that set; what the page needs is the field inside the new rule.
        _, _, field = error.location.partition(".")
        _, _, inner = field.partition(".")
        raise ProposalError("INVALID_PROPOSAL", [inner or field or "when"]) from None
    except ValidationError:
        raise ProposalError("INVALID_PROPOSAL", ["when"]) from None
    return rule


def propose_rule(
    runtime: Runtime,
    config: AssistantConfig,
    transport: Transport,
    session: Session,
    bundle_id: UUID,
    words: str,
) -> Proposal:
    """Draft one rule for this draft from these words, and record the turn that did it.

    The turn row is the same row an answer gets, so the tenant switch, the caps, the privacy
    and the retention are one mechanism rather than two; what it stores is the rule's own
    sentence, which is what the person was shown.
    """
    content = _draft(runtime, session, bundle_id)
    digest = draft_digest(content, catalog=runtime.catalog)
    turn = start_turn(
        runtime,
        config,
        session,
        context_kind="policy_change",
        context_id=bundle_id,
        question=words[:MAX_WORDS],
    )
    usage = Usage()

    def failed(reason: str) -> None:
        complete_turn(
            runtime.db,
            session.identity,
            turn.turn_id,
            state="FAILED",
            reason=reason,
            usage=usage,
            clock=runtime.clock,
        )

    try:
        response = parse_response(transport.send(build_request(config, digest, words)))
    except ModelError:
        failed("MODEL_ERROR")
        raise ProposalError("MODEL_ERROR") from None
    usage = response.usage
    if response.stop_reason == "max_tokens":
        failed("TOKEN_LIMIT")
        raise ProposalError("TOKEN_LIMIT") from None
    try:
        rule = _validated(response.text, content, runtime.catalog)
    except ProposalError:
        # The row says a model error because that is what it was: the answer was not usable.
        failed("MODEL_ERROR")
        raise
    reads = sentence(rule)
    complete_turn(
        runtime.db,
        session.identity,
        turn.turn_id,
        state="COMPLETED",
        answer={"paragraphs": [{"text": reads, "ids": [rule.id]}], "cannot_answer": False},
        cited_ids=[rule.id],
        usage=usage,
        clock=runtime.clock,
    )
    identity = session.identity
    with runtime.db.transaction(identity.tenant_id) as conn:
        append_event(
            conn,
            identity.tenant_id,
            identity.principal_id,
            ASKED,
            {
                "turn_id": str(turn.turn_id),
                "context_kind": "policy_change",
                "context_id": str(bundle_id),
                "tools": [],
                "rows": 0,
                "model": config.model,
                "input_tokens": usage.input_tokens,
                "cached_tokens": usage.cache_read_input_tokens,
                "output_tokens": usage.output_tokens,
                "proposed": rule.id,
                **acted_with(identity.credential_id),
            },
        )
    return Proposal(
        rule=rule,
        sentence=reads,
        lines=tuple(condition_line(condition) for condition in rule.when),
        usage=usage,
    )


def proposal_fields(proposal: Proposal) -> Mapping[str, Any]:
    """The rule as the add-a-rule form takes it, beside the words the page shows."""
    return {
        "id": proposal.rule.id,
        "action": proposal.rule.action,
        "effect": proposal.rule.effect,
        "quorum": proposal.rule.quorum,
        "note": proposal.rule.note,
        "when": [
            {
                "kind": condition.kind,
                "name": condition.name,
                "operator": condition.operator,
                "values": list(condition.values),
            }
            for condition in proposal.rule.when
        ],
    }
