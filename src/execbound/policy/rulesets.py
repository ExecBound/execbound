# SPDX-License-Identifier: AGPL-3.0-only
"""Rules a customer writes, compiled deterministically into the bundle the kernel executes.

A ruleset is the bundle's *source*. It is stored inside bundle content, and for a bundle that
carries one the Cedar sets, limits and quorum are the compiler's output rather than anything a
person typed. Validation and activation recompile and refuse a mismatch, so the policy text can
never say something the rules do not.

**The kernel never reads a ruleset.** It reads the compiled bundle, exactly as it reads a bundle
written by hand. Nothing here runs on the admission path, and no safety behaviour depends on the
compiler beyond validation refusing a mismatch. That is what keeps a rule editor outside the
security boundary: a ruleset cannot express anything a bundle could not already express, so
hard-denial precedence and default deny are untouched by construction.
"""

import json
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Literal
from uuid import UUID

from execbound.contracts import (
    PRODUCTION_CATALOG,
    Catalog,
    ContextContract,
    ContractError,
    FactSpec,
)
from execbound.domains import (
    BooleanDomain,
    IntegerDomain,
    ScalarValue,
    StringDomain,
    value_in_domain,
)
from execbound.operations import ArgumentSpec, CatalogError
from execbound.policy.models import (
    BundleContent,
    Condition,
    ContextSetting,
    LimitRule,
    MappingRef,
    QuorumRule,
    Rule,
    Ruleset,
)
from execbound.policy.schema import cedar_schema, entity_attributes
from execbound.signals.models import SignalMapping

# The Cedar operator each condition compiles to. `in` is absent deliberately: Cedar's own `in`
# is entity-hierarchy membership, not set membership over scalars, so a list compiles to a
# parenthesised disjunction instead of borrowing an operator that means something else.
_COMPARISON = {"is": "==", "is_not": "!=", "at_least": ">=", "at_most": "<="}
_ORDERED = {"at_least", "at_most"}


# One size limit for a rules file, in bytes: `ruleset-compile` reads with it, and the console
# refuses a larger file at the field `ruleset`. The same 512 KB the bundle file has always had.
MAX_RULESET_FILE_BYTES = 512 * 1024


class RulesetDocumentError(ValueError):
    """A rules document that cannot be read; `locations` name fields, never values.

    `reason` says which kind of fault it was, so `ruleset-compile` keeps its own words:
    `unreadable` (too large, not UTF-8, not JSON, or a key repeated), `not-object`, or
    `invalid` (the model refused it). `problems` carries the model's own messages beside each
    location, for that command only; the console reads the locations and nothing else.
    """

    def __init__(
        self,
        locations: tuple[str, ...],
        *,
        reason: Literal["unreadable", "not-object", "invalid"] = "unreadable",
        problems: tuple[str, ...] = (),
    ) -> None:
        self.locations = locations
        self.reason = reason
        self.problems = problems
        super().__init__("Ruleset document is invalid")


def parse_ruleset_document(raw: bytes) -> Ruleset:
    """The one reading of a rules file, for `ruleset-compile` and the console alike.

    It refuses a document over `MAX_RULESET_FILE_BYTES` bytes, one that is not UTF-8 JSON, one
    that repeats a key anywhere, and one that is not an object, each at `<root>`; then it
    validates `Ruleset`, whose faults are named by their dotted locations.
    """
    from pydantic import ValidationError

    from execbound.requests import _unique_object

    if len(raw) > MAX_RULESET_FILE_BYTES:
        raise RulesetDocumentError(("<root>",))
    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=_unique_object)
    except Exception:
        raise RulesetDocumentError(("<root>",)) from None
    if type(value) is not dict:
        raise RulesetDocumentError(("<root>",), reason="not-object")
    try:
        return Ruleset.model_validate_json(json.dumps(value))
    except ValidationError as exc:
        errors = exc.errors(include_input=False, include_url=False)
        locations = tuple(
            ".".join(str(part) for part in error["loc"]) or "<root>" for error in errors
        )
        problems = tuple(
            f"{location}: {error['msg']}" for location, error in zip(locations, errors, strict=True)
        )
        raise RulesetDocumentError(locations, reason="invalid", problems=problems) from None


class RulesetError(ValueError):
    """A ruleset that cannot be compiled, carrying the field that caused it."""

    def __init__(self, message: str, location: str) -> None:
        super().__init__(message)
        self.location = location


@dataclass(frozen=True)
class CompiledPolicy:
    """The five bundle components a ruleset produces, and nothing else."""

    cedar_schema: str
    authorization_policies: str
    approval_policies: str
    limits: tuple[LimitRule, ...]
    quorum: tuple[QuorumRule, ...] | None


def _ordered(rules: Sequence[Rule]) -> list[Rule]:
    """Canonical emission order, independent of the order the rules were written in.

    Two rulesets with the same rules compile to the same bytes, which is what lets validation
    compare a recompile against stored content directly rather than semantically.
    """
    return sorted(rules, key=lambda rule: (rule.effect, rule.id))


def _literal(value: ScalarValue) -> str:
    if type(value) is bool:
        return "true" if value else "false"
    if type(value) is int:
        return str(value)
    # Cedar string syntax is JSON's; the domain already bounds which strings can appear, so
    # this escapes a known-good value rather than sanitising an arbitrary one.
    return '"' + str(value).replace("\\", "\\\\").replace('"', '\\"') + '"'


def _subject(condition: Condition) -> str:
    return (
        f"resource.{condition.name}"
        if condition.kind == "fact"
        else f"context.arguments.{condition.name}"
    )


def _expression(condition: Condition) -> str:
    subject = _subject(condition)
    if condition.operator == "in":
        inner = " || ".join(f"{subject} == {_literal(value)}" for value in condition.values)
        return f"({inner})"
    return f"{subject} {_COMPARISON[condition.operator]} {_literal(condition.values[0])}"


def _declared(
    rule: Rule, index: int, contract: ContextContract, arguments: Mapping[str, ArgumentSpec]
) -> None:
    """Every condition names something declared, typed and in domain, or the rule is refused."""
    for position, condition in enumerate(rule.when):
        location = f"rules.{index}.when.{position}"
        spec: FactSpec | ArgumentSpec | None
        if condition.kind == "fact":
            spec = next((f for f in contract.facts if f.name == condition.name), None)
            if spec is None:
                raise RulesetError(f"Unknown fact: {condition.name}", location)
        else:
            spec = arguments.get(condition.name)
            if spec is None:
                raise RulesetError(f"Unknown argument: {condition.name}", location)
        if condition.operator in _ORDERED and spec.cedar_type != "Long":
            raise RulesetError(f"{condition.operator} needs a Long", location)
        for value in condition.values:
            if not value_in_domain(spec.cedar_type, spec.domain, value):
                raise RulesetError("Value outside the declared domain", location)


def _policy(rule: Rule, *, permit: bool, fenced: bool) -> str:
    """One Cedar policy for one rule; the tenant fence is part of every permit, as by hand."""
    effect = "permit" if permit else "forbid"
    head = f'{effect}(principal, action == ExecBound::Action::"{rule.action}", resource)'
    clauses = [_expression(condition) for condition in rule.when]
    if fenced:
        clauses.insert(0, "principal.tenant == resource.tenant")
    if not clauses:
        # A forbid with no conditions applies to the action outright. Emitting an empty
        # `when {}` would not parse, and inventing a condition would narrow the rule.
        return f"{head};"
    return f"{head}\nwhen {{ {' && '.join(clauses)} }};"


def compile_ruleset(
    ruleset: Ruleset,
    mappings: Sequence[MappingRef],
    *,
    catalog: Catalog = PRODUCTION_CATALOG,
) -> CompiledPolicy:
    """The five components this ruleset means, deterministically.

    ``mappings`` decides which actions exist for this bundle and which contract describes each,
    so a rule naming an action the tenant does not map is refused here rather than compiling to
    a policy about an action nothing can dispatch. A mapping serves its `action_name`: its
    ref when that is the action's own name, else the action it names, which the store holds
    to the tenant's mapping row. Several refs may serve one action on one contract; one action
    under two contracts would need one Cedar entity to mean two things, and is refused.
    """
    actions = catalog.actions
    contracts: dict[str, ContextContract] = {}
    # The first mapping to serve each action.
    serving: dict[str, MappingRef] = {}
    # The first mapping to describe each Cedar entity type, and the attributes it gives it.
    described: dict[str, tuple[MappingRef, dict[str, dict[str, str]]]] = {}
    for index, mapping in enumerate(mappings):
        location = f"mappings.{index}"
        action = mapping.action_name
        try:
            spec = actions.action(action)
        except CatalogError:
            raise RulesetError(
                f"Operation ref is not a catalog action: {mapping.operation_ref}"
                if mapping.action is None
                else f"Mapping action is not a catalog action: {action}",
                location,
            ) from None
        try:
            contract = catalog.for_operation(
                mapping.context_contract_version, action, spec.resource_type
            )
        except ContractError:
            raise RulesetError(
                f"Contract {mapping.context_contract_version} does not serve: {action}",
                location,
            ) from None
        server = serving.setdefault(action, mapping)
        if server.context_contract_version != mapping.context_contract_version:
            raise RulesetError(
                f"Mappings {server.operation_ref} ({server.context_contract_version}) and "
                f"{mapping.operation_ref} ({mapping.context_contract_version}) serve {action} "
                "under different contracts and cannot share a bundle",
                location,
            )
        # The comparison `cedar_schema` makes, with its own description of the entity, made
        # here first so a caller is told which mapping to leave out rather than that the
        # schema could not be built.
        attributes = entity_attributes(contract)
        first = described.setdefault(contract.cedar_entity_type, (mapping, attributes))
        if first[1] != attributes:
            raise RulesetError(
                f"Mappings {first[0].operation_ref} ({first[0].context_contract_version}) and "
                f"{mapping.operation_ref} ({mapping.context_contract_version}) describe the "
                f"{contract.cedar_entity_type} entity differently and cannot share a bundle",
                location,
            )
        contracts[action] = contract
    authorization: list[str] = []
    approval: list[str] = []
    quorum: list[QuorumRule] = []
    for index, rule in enumerate(_ordered(ruleset.rules)):
        if rule.action not in contracts:
            raise RulesetError(f"No mapping serves: {rule.action}", f"rules.{index}.action")
        arguments = {argument.name: argument for argument in actions.action(rule.action).arguments}
        _declared(rule, index, contracts[rule.action], arguments)
        if rule.effect == "REVIEW":
            # The obligation is Cedar's own identifier for the policy about to be appended,
            # which is its position in this set. Engine ids are what evaluation reports and
            # what replay compares; an `@id` annotation is neither unique nor trusted here,
            # and `tests/test_cedar.py` holds that line deliberately.
            if rule.quorum is not None:
                quorum.append(
                    QuorumRule(
                        rule_id=rule.id,
                        obligation=f"policy:policy{len(approval)}",
                        required=rule.quorum,
                    )
                )
            approval.append(_policy(rule, permit=True, fenced=False))
        else:
            authorization.append(
                _policy(rule, permit=rule.effect == "ALLOW", fenced=rule.effect == "ALLOW")
            )
    if not authorization:
        raise RulesetError("No rule authorizes anything", "rules")
    return CompiledPolicy(
        cedar_schema=cedar_schema(contracts, actions=actions),
        authorization_policies="\n".join(authorization) + "\n",
        approval_policies=("\n".join(approval) + "\n") if approval else "",
        limits=ruleset.budgets,
        quorum=tuple(quorum) or None,
    )


def ruleset_bundle(
    ruleset: Ruleset,
    *,
    tenant_id: UUID,
    bundle_id: UUID,
    mappings: Sequence[MappingRef],
    context_settings: tuple[ContextSetting, ...] | None = None,
    signal_mappings: tuple[SignalMapping, ...] | None = None,
    catalog: Catalog = PRODUCTION_CATALOG,
) -> BundleContent:
    """A bundle whose five components are exactly what ``ruleset`` compiles to, carrying it.

    The one place a ruleset becomes bundle content, so the components and the source can
    never be assembled inconsistently. The store recompiles at validation and activation and
    refuses a mismatch; a bundle built here passes that check by construction.

    `context_settings` and `signal_mappings` are not compiled from rules; they are carried, so
    a caller must pass what the bundle already has.
    """
    compiled = compile_ruleset(ruleset, mappings, catalog=catalog)
    return BundleContent(
        tenant_id=tenant_id,
        bundle_id=bundle_id,
        cedar_schema=compiled.cedar_schema,
        authorization_policies=compiled.authorization_policies,
        approval_policies=compiled.approval_policies,
        mappings=tuple(mappings),
        limits=compiled.limits,
        context_settings=context_settings,
        quorum=compiled.quorum,
        ruleset=ruleset,
        signal_mappings=signal_mappings,
    )


_EFFECT_WORD = {"ALLOW": "Allow", "DENY": "Deny", "REVIEW": "Review"}
_OPERATOR_WORD = {
    "is": "is",
    "is_not": "is not",
    "in": "is one of",
    "at_least": "is at least",
    "at_most": "is at most",
}


def _value_words(values: tuple[str | int | bool, ...]) -> str:
    return ", ".join(str(value).lower() if type(value) is bool else str(value) for value in values)


def sentence(rule: Rule) -> str:
    """One plain sentence for a rule, as the pages show it beside the Cedar it compiles to.

    Labelled on the page as how the rules read, never as the decision, which is the kernel's
    and is made from the compiled bundle. The note is not part of the sentence.
    """
    head = f"{_EFFECT_WORD[rule.effect]} {rule.action}"
    if rule.effect == "REVIEW" and rule.quorum is not None:
        head += f" ({rule.quorum} approvers)"
    if not rule.when:
        return f"{head} always."
    clauses = [
        f"{condition.name} {_OPERATOR_WORD[condition.operator]} {_value_words(condition.values)}"
        for condition in rule.when
    ]
    joined = clauses[0] if len(clauses) == 1 else ", ".join(clauses[:-1]) + " and " + clauses[-1]
    return f"{head} when {joined}."


def condition_line(condition: Condition) -> str:
    """One condition in the words the rules editor parses, which are the words it prints.

    The inverse of `surfaces/policy_pages.py`'s `parse_conditions`: `role is workstation`,
    `argument reason is false_positive`, `criticality is at least 3`,
    `role is one of server, domain_controller`. Written here beside `sentence()` so the two
    wordings cannot drift from the compiler or from each other, and held to the parser by a
    round trip in `tests/test_rulesets.py` rather than by inspection.
    """
    prefix = "argument " if condition.kind == "argument" else ""
    return (
        f"{prefix}{condition.name} {_OPERATOR_WORD[condition.operator]} "
        f"{_value_words(condition.values)}"
    )


def review_rule_ids(ruleset: Ruleset) -> Mapping[str, str]:
    """The obligation the engine raises for each REVIEW rule, mapped back to the rule's id.

    Obligations are Cedar's positional identifiers, assigned in the order the compiler writes
    the approval set; this walks that same order, so a preview can say which rule changed an
    answer rather than printing `policy:policy2`. Tested against the engine, not restated.
    """
    reviews = [rule for rule in _ordered(ruleset.rules) if rule.effect == "REVIEW"]
    return {f"policy:policy{index}": rule.id for index, rule in enumerate(reviews)}


def rules_for(ruleset: Ruleset, action: str) -> tuple[Rule, ...]:
    """The rules about one action, in the order the compiler writes them."""
    return tuple(rule for rule in _ordered(ruleset.rules) if rule.action == action)


@dataclass(frozen=True)
class Projection:
    """What the rules say about one action over one set of facts, as they read.

    Not a decision. The kernel decides from the compiled bundle over attested facts, and it
    also weighs limits, quorum and the approvals people give, none of which a rule sees. This
    is a page's reading of the rules for a person, and every page that shows one labels it so.
    ``rules`` names the rules the reading rests on: the denials that applied, else the allows
    and the reviews that applied. ``unknown`` names the facts or arguments no value was given
    for, whose rules were left out of the reading rather than guessed at.
    """

    effect: str
    rules: tuple[str, ...]
    unknown: tuple[str, ...] = ()


def _holds(condition: Condition, value: ScalarValue) -> bool:
    expected = condition.values
    if condition.operator == "in":
        return any(type(value) is type(item) and value == item for item in expected)
    first = expected[0]
    if condition.operator in _ORDERED:
        if type(value) is not int or type(first) is not int:
            return False
        return value >= first if condition.operator == "at_least" else value <= first
    same = type(value) is type(first) and value == first
    return same if condition.operator == "is" else not same


def applies(
    rule: Rule,
    facts: Mapping[str, ScalarValue],
    arguments: Mapping[str, ScalarValue] | None = None,
) -> tuple[bool, tuple[str, ...]]:
    """Whether every condition of ``rule`` holds, and the names no value was given for.

    A rule with a missing name never holds: the answer is (False, names), so a caller can say
    which facts it lacked rather than report an effect it could not read. Values are compared
    with their type, so an integer 1 is not the boolean true and a text "4" is not the
    number 4, exactly as Cedar would refuse the comparison.
    """
    missing: list[str] = []
    holds = True
    for condition in rule.when:
        source = facts if condition.kind == "fact" else (arguments or {})
        if condition.name not in source:
            missing.append(condition.name)
            continue
        if not _holds(condition, source[condition.name]):
            holds = False
    return (holds and not missing), tuple(missing)


def project(
    ruleset: Ruleset,
    action: str,
    facts: Mapping[str, ScalarValue],
    arguments: Mapping[str, ScalarValue] | None = None,
) -> Projection:
    """Read the rules about ``action`` over ``facts``: a denial wins, then an allow is needed,
    and a review that applies makes the reading "require approval".

    The same precedence the compiled bundle has by construction: a forbid beats every permit,
    nothing is permitted by default, and an approval-set permit adds an obligation. Read from
    the rules, not from Cedar, so the words match the sentences the pages print.
    """
    denies: list[str] = []
    allows: list[str] = []
    reviews: list[str] = []
    unknown: list[str] = []
    for rule in rules_for(ruleset, action):
        holds, missing = applies(rule, facts, arguments)
        for name in missing:
            if name not in unknown:
                unknown.append(name)
        if not holds:
            continue
        {"ALLOW": allows, "DENY": denies, "REVIEW": reviews}[rule.effect].append(rule.id)
    if denies:
        return Projection("deny", tuple(denies), tuple(unknown))
    if not allows:
        return Projection("deny", (), tuple(unknown))
    if reviews:
        return Projection("require approval", tuple(allows + reviews), tuple(unknown))
    return Projection("allow", tuple(allows), tuple(unknown))


# What a condition may say about one declared fact or argument. The rule editor's selects are
# built from this and from nothing else, so the form cannot offer a name the compiler does not
# know or a value outside the declared domain (#273,
# step 3). It is a projection of the catalog, never a second copy of it: the compiler still
# checks every condition through `_declared`, and this only decides what a person is shown.
_ORDERED_OPERATORS = ("is", "is_not", "in", "at_least", "at_most")
_UNORDERED_OPERATORS = ("is", "is_not", "in")


@dataclass(frozen=True)
class FieldChoice:
    """One thing a condition may name, with the operators and values its type admits."""

    kind: str
    name: str
    cedar_type: str
    operators: tuple[str, ...]
    # A closed set for a String, both bounds for a Long, both truth values for a Boolean.
    values: tuple[ScalarValue, ...]
    minimum: int | None = None
    maximum: int | None = None


def _choice(kind: str, spec: FactSpec | ArgumentSpec) -> FieldChoice:
    domain = spec.domain
    operators = _ORDERED_OPERATORS if spec.cedar_type == "Long" else _UNORDERED_OPERATORS
    values: tuple[ScalarValue, ...] = ()
    minimum: int | None = None
    maximum: int | None = None
    if isinstance(domain, StringDomain):
        values = tuple(sorted(domain.values))
    elif isinstance(domain, IntegerDomain):
        minimum, maximum = domain.minimum, domain.maximum
    elif isinstance(domain, BooleanDomain):
        values = (False, True)
    return FieldChoice(
        kind=kind,
        name=spec.name,
        cedar_type=spec.cedar_type,
        operators=operators,
        values=values,
        minimum=minimum,
        maximum=maximum,
    )


def writable_fields(
    mappings: Sequence[MappingRef], *, catalog: Catalog = PRODUCTION_CATALOG
) -> dict[str, tuple[FieldChoice, ...]]:
    """For each action a bundle's mappings serve, everything a rule's condition may name.

    The contract's facts first, then the action's arguments, each in its declared order, so
    the form reads the way the catalog does. An action the bundle does not map is absent, which
    is the same answer the compiler gives a rule naming one. Keyed by the action a mapping
    serves, never its ref; the first mapping to serve an action describes it, as in the
    compiler, which refuses a second that would describe it differently.
    """
    actions = catalog.actions
    fields: dict[str, tuple[FieldChoice, ...]] = {}
    for mapping in mappings:
        action = mapping.action_name
        if action in fields:
            continue
        spec = actions.action(action)
        contract = catalog.for_operation(
            mapping.context_contract_version, action, spec.resource_type
        )
        fields[action] = tuple(
            [_choice("fact", fact) for fact in contract.facts]
            + [_choice("argument", argument) for argument in spec.arguments]
        )
    return fields


def rule_schema() -> dict[str, object]:
    """The rule model's JSON schema, as one object.

    Exported here rather than reached for through the model, because it is a contract two
    other things read: the console's add-a-rule form, and the assistant's "Describe a rule"
    (#330), whose answer is validated by
    the same validator the form uses. Nothing else about the model is public.
    """
    return dict(Rule.model_json_schema())
