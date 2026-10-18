# SPDX-License-Identifier: AGPL-3.0-only
"""How a candidate policy differs from the active one, as the rules read (#678).

A pure comparison of two sides of a policy: their typed rulesets, and the parts of their
content the rules do not carry (the action mappings, the effective context settings and the
signal mappings). It never parses Cedar and imports nothing from a surface: whoever builds a
`Side` decides which ruleset it reads, and a side with none is not compared.

Each change carries a direction, which is a reading of the rules and never a decision: the
kernel decides from the compiled policy, and the preview is what shows what would actually have
decided differently. A change whose parts point both ways reads "unclear".
"""

from collections.abc import Callable, Hashable, Iterable
from dataclasses import dataclass
from typing import Literal
from uuid import UUID

from execbound.policy.models import ContextSetting, LimitRule, MappingRef, Rule, Ruleset
from execbound.signals.models import SignalMapping

Direction = Literal["wider", "narrower", "unclear", "none"]
Change = Literal["added", "removed", "changed"]

# A change that allows more sorts first, then one that allows less, then one to check.
_RANK: dict[Direction, int] = {"wider": 0, "narrower": 1, "unclear": 2, "none": 3}
# How much an effect allows, so a move up the scale is wider.
_EFFECT_RANK = {"DENY": 0, "REVIEW": 1, "ALLOW": 2}


@dataclass(frozen=True)
class Side:
    """One bundle as compared: its rules, and what its content carries beside them."""

    ruleset: Ruleset
    mappings: tuple[MappingRef, ...]
    context_settings: tuple[ContextSetting, ...] | None
    signal_mappings: tuple[SignalMapping, ...] | None


@dataclass(frozen=True)
class RuleChange:
    change: Change
    rule_id: str
    before: Rule | None
    after: Rule | None
    fields: tuple[str, ...]  # of "action", "effect", "when", "quorum", "note"
    direction: Direction


@dataclass(frozen=True)
class BudgetChange:
    change: Change
    rule_id: str
    before: LimitRule | None
    after: LimitRule | None
    fields: tuple[str, ...]  # "max_targets", "window_seconds", "on_exceed", "budget", "scope"
    direction: Direction


@dataclass(frozen=True)
class ActionChange:
    change: Literal["added", "removed"]
    action: str
    direction: Direction


@dataclass(frozen=True)
class MappingChange:
    change: Change
    operation_ref: str
    account_id: UUID
    action: str
    # of "observe_only", "external_executor", "mapping_version", "schema_version",
    # "context_contract_version", "action"
    fields: tuple[str, ...]
    direction: Direction


@dataclass(frozen=True)
class ContextChange:
    change: Change
    contract: str
    source_kind: str
    fields: tuple[str, ...]  # "max_age_seconds", "permitted_writers"
    direction: Direction


@dataclass(frozen=True)
class SignalChange:
    change: Change
    contract: str
    capability: str
    direction: Direction  # always "unclear"


@dataclass(frozen=True)
class Comparison:
    rules: tuple[RuleChange, ...]
    budgets: tuple[BudgetChange, ...]
    actions: tuple[ActionChange, ...]
    mappings: tuple[MappingChange, ...]
    context: tuple[ContextChange, ...]
    signals: tuple[SignalChange, ...]

    @property
    def actions_added(self) -> tuple[str, ...]:
        return tuple(item.action for item in self.actions if item.change == "added")

    @property
    def actions_removed(self) -> tuple[str, ...]:
        return tuple(item.action for item in self.actions if item.change == "removed")

    def directions(self) -> tuple[Direction, ...]:
        """Every change's direction, over every section."""
        return tuple(
            item.direction
            for section in (
                self.rules,
                self.budgets,
                self.actions,
                self.mappings,
                self.context,
                self.signals,
            )
            for item in section
        )

    def count(self, direction: Direction) -> int:
        return sum(1 for item in self.directions() if item == direction)


def combine(*parts: Direction) -> Direction:
    """One direction for a change made of several: both ways is unclear; otherwise the
    strongest of wider or narrower, then unclear, then none."""
    if "wider" in parts and "narrower" in parts:
        return "unclear"
    strongest: tuple[Direction, ...] = ("wider", "narrower", "unclear")
    for direction in strongest:
        if direction in parts:
            return direction
    return "none"


def _scale(before: float, after: float, *, wider_when_higher: bool) -> Direction:
    if before == after:
        return "none"
    return "wider" if (after > before) == wider_when_higher else "narrower"


def _rule(before: Rule, after: Rule) -> tuple[tuple[str, ...], Direction]:
    fields: list[str] = []
    parts: list[Direction] = []
    if before.action != after.action:
        fields.append("action")
        parts.append("unclear")
    if before.effect != after.effect:
        fields.append("effect")
        parts.append(
            _scale(_EFFECT_RANK[before.effect], _EFFECT_RANK[after.effect], wider_when_higher=True)
        )
    if before.when != after.when:
        fields.append("when")
        parts.append("unclear")
    if before.quorum != after.quorum:
        fields.append("quorum")
        # No quorum is one approver; fewer approvers is wider.
        parts.append(_scale(before.quorum or 1, after.quorum or 1, wider_when_higher=False))
    if before.note != after.note:
        fields.append("note")
    return tuple(fields), combine(*parts)


_QUALIFIERS = ("scope", "action", "actions", "group_id", "account_id", "selector", "space_id")


def _budget(before: LimitRule, after: LimitRule) -> tuple[tuple[str, ...], Direction]:
    fields: list[str] = []
    parts: list[Direction] = []
    if before.max_targets != after.max_targets:
        fields.append("max_targets")
        parts.append(_scale(before.max_targets, after.max_targets, wider_when_higher=True))
    if before.window_seconds != after.window_seconds:
        fields.append("window_seconds")
        # A shorter window forgets sooner, so it admits more.
        parts.append(_scale(before.window_seconds, after.window_seconds, wider_when_higher=False))
    if before.on_exceed != after.on_exceed:
        fields.append("on_exceed")
        parts.append("wider" if after.on_exceed == "REQUIRE_APPROVAL" else "narrower")
    if before.budget != after.budget:
        fields.append("budget")
        parts.append("wider" if after.budget == "autonomous" else "narrower")
    if any(getattr(before, name) != getattr(after, name) for name in _QUALIFIERS):
        fields.append("scope")
        parts.append("unclear")
    return tuple(fields), combine(*parts)


def _mapping(before: MappingRef, after: MappingRef) -> tuple[tuple[str, ...], Direction]:
    fields: list[str] = []
    parts: list[Direction] = []
    if before.observe_only != after.observe_only:
        fields.append("observe_only")
        parts.append("narrower" if after.observe_only else "wider")
    if before.external_executor != after.external_executor:
        fields.append("external_executor")
        # A checkpoint grant lets the act happen outside ExecBound after approval.
        parts.append("wider" if after.external_executor else "narrower")
    for name in ("mapping_version", "schema_version", "context_contract_version", "action"):
        if getattr(before, name) != getattr(after, name):
            fields.append(name)
            parts.append("unclear")
    return tuple(fields), combine(*parts)


def _setting(before: ContextSetting, after: ContextSetting) -> tuple[tuple[str, ...], Direction]:
    fields: list[str] = []
    parts: list[Direction] = []
    if before.max_age_seconds != after.max_age_seconds:
        fields.append("max_age_seconds")
        parts.append(_scale(before.max_age_seconds, after.max_age_seconds, wider_when_higher=True))
    added = set(after.permitted_writers) - set(before.permitted_writers)
    removed = set(before.permitted_writers) - set(after.permitted_writers)
    if added or removed:
        fields.append("permitted_writers")
        if added:
            parts.append("wider")
        if removed:
            parts.append("narrower")
    return tuple(fields), combine(*parts)


def _pairs[Key: Hashable, Item](
    before: Iterable[Item], after: Iterable[Item], key: Callable[[Item], Key]
) -> list[tuple[Key, Item | None, Item | None]]:
    """Every key of either side, in a stable order, with the item each side has for it."""
    left = {key(item): item for item in before}
    right = {key(item): item for item in after}
    keys = sorted(set(left) | set(right), key=str)
    return [(name, left.get(name), right.get(name)) for name in keys]


def _ordered[Item](
    items: Iterable[Item], key: Callable[[Item], tuple[int, str]]
) -> tuple[Item, ...]:
    return tuple(sorted(items, key=key))


def compare(candidate: Side, active: Side) -> Comparison:
    """How the candidate differs from the active side, as the rules and mappings read."""
    rules: list[RuleChange] = []
    for rule_id, before, after in _pairs(
        active.ruleset.rules, candidate.ruleset.rules, lambda rule: rule.id
    ):
        if before is None and after is not None:
            direction: Direction = "wider" if after.effect == "ALLOW" else "narrower"
            rules.append(RuleChange("added", rule_id, None, after, (), direction))
        elif after is None and before is not None:
            direction = "narrower" if before.effect == "ALLOW" else "wider"
            rules.append(RuleChange("removed", rule_id, before, None, (), direction))
        elif before is not None and after is not None and before != after:
            fields, direction = _rule(before, after)
            rules.append(RuleChange("changed", rule_id, before, after, fields, direction))

    budgets: list[BudgetChange] = []
    for rule_id, old, new in _pairs(
        active.ruleset.budgets, candidate.ruleset.budgets, lambda budget: budget.rule_id
    ):
        if old is None and new is not None:
            budgets.append(BudgetChange("added", rule_id, None, new, (), "narrower"))
        elif new is None and old is not None:
            budgets.append(BudgetChange("removed", rule_id, old, None, (), "wider"))
        elif old is not None and new is not None and old != new:
            fields, direction = _budget(old, new)
            budgets.append(BudgetChange("changed", rule_id, old, new, fields, direction))

    served_before = {mapping.action_name for mapping in active.mappings}
    served_after = {mapping.action_name for mapping in candidate.mappings}
    allowed = {rule.action for rule in candidate.ruleset.rules if rule.effect == "ALLOW"}
    actions = [
        ActionChange("added", action, "wider" if action in allowed else "none")
        for action in sorted(served_after - served_before)
    ] + [
        ActionChange("removed", action, "narrower")
        for action in sorted(served_before - served_after)
    ]

    # A mapping whose action is itself added or removed is reported once, under the actions.
    both = served_before & served_after
    mappings: list[MappingChange] = []
    for (ref, account), old_map, new_map in _pairs(
        (item for item in active.mappings if item.action_name in both),
        (item for item in candidate.mappings if item.action_name in both),
        lambda item: (item.operation_ref, item.account_id),
    ):
        if old_map is None and new_map is not None:
            mappings.append(MappingChange("added", ref, account, new_map.action_name, (), "wider"))
        elif new_map is None and old_map is not None:
            mappings.append(
                MappingChange("removed", ref, account, old_map.action_name, (), "narrower")
            )
        elif old_map is not None and new_map is not None and old_map != new_map:
            fields, direction = _mapping(old_map, new_map)
            mappings.append(
                MappingChange("changed", ref, account, new_map.action_name, fields, direction)
            )

    context: list[ContextChange] = []
    for (contract, kind), old_setting, new_setting in _pairs(
        active.context_settings or (),
        candidate.context_settings or (),
        lambda item: (item.context_contract_version, item.source_kind),
    ):
        if old_setting is None or new_setting is None:
            change: Change = "added" if old_setting is None else "removed"
            context.append(ContextChange(change, contract, kind, (), "unclear"))
        elif old_setting != new_setting:
            fields, direction = _setting(old_setting, new_setting)
            context.append(ContextChange("changed", contract, kind, fields, direction))

    signals: list[SignalChange] = []
    for (contract, capability), old_signal, new_signal in _pairs(
        active.signal_mappings or (),
        candidate.signal_mappings or (),
        lambda item: (item.context_contract_version, item.capability),
    ):
        if old_signal is None or new_signal is None:
            change = "added" if old_signal is None else "removed"
            signals.append(SignalChange(change, contract, capability, "unclear"))
        elif old_signal != new_signal:
            signals.append(SignalChange("changed", contract, capability, "unclear"))

    return Comparison(
        rules=_ordered(rules, lambda item: (_RANK[item.direction], item.rule_id)),
        budgets=_ordered(budgets, lambda item: (_RANK[item.direction], item.rule_id)),
        actions=_ordered(actions, lambda item: (_RANK[item.direction], item.action)),
        mappings=_ordered(
            mappings,
            lambda item: (_RANK[item.direction], f"{item.operation_ref}:{item.account_id}"),
        ),
        context=_ordered(
            context, lambda item: (_RANK[item.direction], f"{item.contract}:{item.source_kind}")
        ),
        signals=_ordered(
            signals, lambda item: (_RANK[item.direction], f"{item.contract}:{item.capability}")
        ),
    )
