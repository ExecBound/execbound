# SPDX-License-Identifier: AGPL-3.0-only
"""How a candidate policy differs from the active one, as the rules read (#678; PL6).

`policy/compare.py` is pure: no database, no Cedar, no surface. Each case below is one direction
`policy/compare.py` assigns, built from the endpoint pack's ruleset and one mapping, and a
candidate that differs from it in exactly one way.
"""

import ast
from dataclasses import replace
from pathlib import Path
from uuid import UUID, uuid4

import pytest

from execbound.policy.compare import Side, combine, compare
from execbound.policy.models import ContextSetting, LimitRule, MappingRef, Rule
from execbound.signals.models import SignalMapping, SignalThreshold
from execbound_harness.demo import ENDPOINT_RULESET

ACCOUNT = UUID("44444444-4444-4444-8444-444444444444")
OTHER_ACCOUNT = UUID("55555555-5555-4555-8555-555555555555")
ISOLATE = MappingRef(
    operation_ref="endpoint.isolate",
    account_id=ACCOUNT,
    mapping_version="map-v1",
    schema_version="action.v1",
    context_contract_version="endpoint-isolation.v1",
)
LIFT = MappingRef(
    operation_ref="endpoint.lift_isolation",
    account_id=ACCOUNT,
    mapping_version="map-v1",
    schema_version="action.v1",
    context_contract_version="endpoint-recovery.v1",
)
SETTING = ContextSetting(
    context_contract_version="endpoint-isolation.v1",
    source_kind="inventory",
    max_age_seconds=300,
    permitted_writers=("cmdb",),
)
ACTIVE = Side(
    ruleset=ENDPOINT_RULESET,
    mappings=(ISOLATE,),
    context_settings=(SETTING,),
    signal_mappings=None,
)


def rule(rule_id: str) -> Rule:
    return next(item for item in ENDPOINT_RULESET.rules if item.id == rule_id)


def budget(rule_id: str) -> LimitRule:
    return next(item for item in ENDPOINT_RULESET.budgets if item.rule_id == rule_id)


def with_rules(*rules: Rule) -> Side:
    return replace(ACTIVE, ruleset=ENDPOINT_RULESET.model_copy(update={"rules": rules}))


def changing_rule(rule_id: str, **changes) -> Side:
    rules = tuple(
        item.model_copy(update=changes) if item.id == rule_id else item
        for item in ENDPOINT_RULESET.rules
    )
    return with_rules(*rules)


def with_budgets(*budgets: LimitRule) -> Side:
    return replace(ACTIVE, ruleset=ENDPOINT_RULESET.model_copy(update={"budgets": budgets}))


def changing_budget(rule_id: str, **changes) -> Side:
    return with_budgets(
        *(
            item.model_copy(update=changes) if item.rule_id == rule_id else item
            for item in ENDPOINT_RULESET.budgets
        )
    )


def only_rule(side: Side):
    result = compare(side, ACTIVE)
    [change] = result.rules
    assert result.budgets == () and result.mappings == () and result.actions == ()
    return change


def only_budget(side: Side):
    result = compare(side, ACTIVE)
    [change] = result.budgets
    assert result.rules == ()
    return change


ALLOW_LIFT = Rule(id="allow-lift", action="endpoint.isolate", effect="ALLOW")


def test_an_added_allow_is_wider_and_an_added_deny_narrower():
    added = only_rule(with_rules(*ENDPOINT_RULESET.rules, ALLOW_LIFT))
    assert (added.change, added.direction, added.after) == ("added", "wider", ALLOW_LIFT)
    deny = ALLOW_LIFT.model_copy(update={"id": "deny-more", "effect": "DENY"})
    assert only_rule(with_rules(*ENDPOINT_RULESET.rules, deny)).direction == "narrower"
    review = ALLOW_LIFT.model_copy(update={"id": "review-more", "effect": "REVIEW"})
    assert only_rule(with_rules(*ENDPOINT_RULESET.rules, review)).direction == "narrower"


def test_a_removed_deny_is_wider_and_a_removed_allow_narrower():
    kept = tuple(
        item for item in ENDPOINT_RULESET.rules if item.id != "isolate-never-domain-controller"
    )
    removed = only_rule(with_rules(*kept))
    assert (removed.change, removed.direction) == ("removed", "wider")
    kept = tuple(item for item in ENDPOINT_RULESET.rules if item.effect != "ALLOW")
    assert only_rule(with_rules(*kept)).direction == "narrower"


@pytest.mark.parametrize(
    ("rule_id", "before", "after", "direction"),
    [
        ("isolate-never-domain-controller", "DENY", "REVIEW", "wider"),
        ("isolate-never-domain-controller", "DENY", "ALLOW", "wider"),
        ("isolate-production-needs-review", "REVIEW", "ALLOW", "wider"),
        ("isolate-production-needs-review", "REVIEW", "DENY", "narrower"),
        ("isolate-workstation-open-critical", "ALLOW", "REVIEW", "narrower"),
    ],
)
def test_an_effect_moving_toward_allow_is_wider(rule_id, before, after, direction):
    assert rule(rule_id).effect == before
    change = only_rule(changing_rule(rule_id, effect=after))
    assert (change.change, change.fields, change.direction) == ("changed", ("effect",), direction)


def test_a_lower_quorum_is_wider_and_a_higher_one_narrower():
    review = "isolate-production-needs-review"
    three = changing_rule(review, quorum=3)
    assert only_rule(three).direction == "narrower"
    lowered = compare(changing_rule(review, quorum=2), three)
    [change] = lowered.rules
    assert (change.fields, change.direction) == (("quorum",), "wider")
    # Removing a quorum leaves one approver, which is fewer.
    assert compare(ACTIVE, three).rules[0].direction == "wider"


def test_a_changed_condition_or_action_is_unclear_and_a_note_alone_none():
    when = changing_rule(
        "isolate-workstation-open-critical", when=rule("isolate-never-domain-controller").when
    )
    assert (only_rule(when).fields, only_rule(when).direction) == (("when",), "unclear")
    acted = changing_rule("isolate-never-criticality-4", action="endpoint.lift_isolation")
    assert only_rule(acted).direction == "unclear"
    noted = only_rule(changing_rule("isolate-never-criticality-4", note="Tier 4 is the vault"))
    assert (noted.fields, noted.direction) == (("note",), "none")


def test_budgets_added_removed_and_changed():
    tenant = budget("tenant-total-isolation")
    assert only_budget(with_budgets(budget("principal-autonomous-isolation"))).direction == "wider"
    extra = tenant.model_copy(update={"rule_id": "tenant-total-extra"})
    assert only_budget(with_budgets(*ENDPOINT_RULESET.budgets, extra)).direction == "narrower"
    raised = only_budget(changing_budget("tenant-total-isolation", max_targets=40))
    assert (raised.fields, raised.direction) == (("max_targets",), "wider")
    lowered = only_budget(changing_budget("tenant-total-isolation", max_targets=10))
    assert lowered.direction == "narrower"
    shorter = only_budget(changing_budget("principal-autonomous-isolation", window_seconds=600))
    assert (shorter.fields, shorter.direction) == (("window_seconds",), "wider")
    held = only_budget(changing_budget("tenant-total-isolation", on_exceed="REQUIRE_APPROVAL"))
    assert (held.fields, held.direction) == (("on_exceed",), "wider")
    autonomous = only_budget(changing_budget("tenant-total-isolation", budget="autonomous"))
    assert (autonomous.fields, autonomous.direction) == (("budget",), "wider")
    scoped = only_budget(changing_budget("tenant-total-isolation", scope="principal"))
    assert (scoped.fields, scoped.direction) == (("scope",), "unclear")


def test_a_change_pointing_both_ways_is_unclear():
    both = only_budget(
        changing_budget("tenant-total-isolation", max_targets=40, window_seconds=3600)
    )
    assert set(both.fields) == {"max_targets", "window_seconds"}
    assert both.direction == "unclear"
    assert combine("wider", "narrower") == "unclear"
    assert combine("none", "wider", "unclear") == "wider"
    assert combine("none", "unclear") == "unclear"
    assert combine() == "none"


def test_an_action_added_with_an_allow_is_wider_and_without_one_none():
    lift_allowed = Rule(id="lift-ok", action="endpoint.lift_isolation", effect="ALLOW")
    served = replace(with_rules(*ENDPOINT_RULESET.rules, lift_allowed), mappings=(ISOLATE, LIFT))
    result = compare(served, ACTIVE)
    assert result.actions_added == ("endpoint.lift_isolation",)
    assert [item.direction for item in result.actions] == ["wider"]
    # The new action's mapping is reported once, under the actions, never also as a mapping.
    assert result.mappings == ()
    bare = compare(replace(ACTIVE, mappings=(ISOLATE, LIFT)), ACTIVE)
    assert [item.direction for item in bare.actions] == ["none"]
    removed = compare(ACTIVE, replace(ACTIVE, mappings=(ISOLATE, LIFT)))
    assert removed.actions_removed == ("endpoint.lift_isolation",)
    assert [item.direction for item in removed.actions] == ["narrower"]


def test_a_second_account_for_a_served_action_is_a_mapping_that_allows_more():
    second = ISOLATE.model_copy(update={"account_id": OTHER_ACCOUNT})
    result = compare(replace(ACTIVE, mappings=(ISOLATE, second)), ACTIVE)
    [change] = result.mappings
    assert (change.change, change.account_id, change.direction) == ("added", OTHER_ACCOUNT, "wider")
    assert result.count("wider") == 1
    back = compare(ACTIVE, replace(ACTIVE, mappings=(ISOLATE, second)))
    assert back.mappings[0].direction == "narrower"


@pytest.mark.parametrize(
    ("field", "before", "after", "direction"),
    [
        ("external_executor", False, True, "wider"),
        ("external_executor", True, False, "narrower"),
        ("observe_only", True, False, "wider"),
        ("observe_only", False, True, "narrower"),
        ("mapping_version", "map-v1", "map-v2", "unclear"),
        ("context_contract_version", "endpoint-isolation.v1", "endpoint-isolation.v2", "unclear"),
    ],
)
def test_a_mapping_change_reads_its_direction(field, before, after, direction):
    old = ISOLATE.model_copy(update={field: before})
    new = ISOLATE.model_copy(update={field: after})
    result = compare(replace(ACTIVE, mappings=(new,)), replace(ACTIVE, mappings=(old,)))
    [change] = result.mappings
    assert (change.change, change.fields, change.direction) == ("changed", (field,), direction)
    # A mapping-only candidate never reads as no change.
    assert result.directions() != ()


def test_context_is_read_from_the_effective_settings_not_the_rulesets_own():
    writer = replace(
        ACTIVE,
        context_settings=(SETTING.model_copy(update={"permitted_writers": ("cmdb", "edr")}),),
    )
    [change] = compare(writer, ACTIVE).context
    assert (change.fields, change.direction) == (("permitted_writers",), "wider")
    younger = replace(
        ACTIVE, context_settings=(SETTING.model_copy(update={"max_age_seconds": 60}),)
    )
    assert compare(younger, ACTIVE).context[0].direction == "narrower"
    older = replace(ACTIVE, context_settings=(SETTING.model_copy(update={"max_age_seconds": 900}),))
    assert compare(older, ACTIVE).context[0].direction == "wider"
    added = replace(
        ACTIVE,
        context_settings=(
            SETTING,
            SETTING.model_copy(update={"context_contract_version": "endpoint-recovery.v1"}),
        ),
    )
    assert [(item.change, item.direction) for item in compare(added, ACTIVE).context] == [
        ("added", "unclear")
    ]
    # The same change made only to the ruleset's own context block reports nothing.
    ruled = replace(
        ACTIVE,
        ruleset=ENDPOINT_RULESET.model_copy(
            update={"context": (SETTING.model_copy(update={"permitted_writers": ("edr",)}),)}
        ),
    )
    assert compare(ruled, ACTIVE).context == ()


def signal(**changes) -> SignalMapping:
    fields = {
        "context_contract_version": "endpoint-isolation.v2",
        "capability": "resource_compromise.v1",
        "admitted_sources": (uuid4(),),
        "thresholds": (SignalThreshold(verdict="High", value="compromised"),),
    }
    fields.update(changes)
    return SignalMapping(**fields)


def test_a_signal_mapping_added_removed_or_changed_is_unclear():
    mapped = signal()
    added = compare(replace(ACTIVE, signal_mappings=(mapped,)), ACTIVE)
    assert [(item.change, item.direction) for item in added.signals] == [("added", "unclear")]
    removed = compare(ACTIVE, replace(ACTIVE, signal_mappings=(mapped,)))
    assert [(item.change, item.direction) for item in removed.signals] == [("removed", "unclear")]
    other = mapped.model_copy(update={"admitted_sources": (uuid4(),)})
    changed = compare(
        replace(ACTIVE, signal_mappings=(other,)), replace(ACTIVE, signal_mappings=(mapped,))
    )
    assert [(item.change, item.direction) for item in changed.signals] == [("changed", "unclear")]


def test_nothing_changed_is_an_empty_comparison_and_wider_sorts_first():
    assert compare(ACTIVE, ACTIVE).directions() == ()
    deny = ALLOW_LIFT.model_copy(update={"id": "a-deny", "effect": "DENY"})
    allow = ALLOW_LIFT.model_copy(update={"id": "z-allow"})
    result = compare(with_rules(*ENDPOINT_RULESET.rules, deny, allow), ACTIVE)
    assert [item.rule_id for item in result.rules] == ["z-allow", "a-deny"]
    assert (result.count("wider"), result.count("narrower")) == (1, 1)


def test_the_comparison_imports_nothing_from_a_surface():
    path = Path(__file__).resolve().parents[1] / "src" / "execbound" / "policy" / "compare.py"
    names: list[str] = []
    for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
        if isinstance(node, ast.ImportFrom) and node.module is not None:
            names.append(node.module)
        elif isinstance(node, ast.Import):
            names.extend(alias.name for alias in node.names)
    assert names and not any(name.startswith("execbound.surfaces") for name in names)
