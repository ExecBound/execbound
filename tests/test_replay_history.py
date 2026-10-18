# SPDX-License-Identifier: AGPL-3.0-only
"""Chronological reconstruction uses retained facts rather than live counters."""

from datetime import UTC, datetime, timedelta
from uuid import UUID

import pytest
from replay_fixtures import replay_case

from execbound.identity import Identity
from execbound.policy.models import LimitRule, LimitSelector
from execbound.replay.ledger import Ledger
from execbound.resolution.models import scalar_facts
from execbound_harness.demo import endpoint_bundle

NOW = datetime(2026, 9, 14, 12, tzinfo=UTC)
TENANT = UUID(int=1)
PRINCIPAL = UUID(int=2)
ACCOUNT = UUID(int=4)
OTHER_ACCOUNT = UUID(int=6)
GROUP = UUID(int=7)
OTHER_GROUP = UUID(int=8)
IDENTITY = Identity(TENANT, PRINCIPAL, UUID(int=3), "AGENT", NOW + timedelta(days=1))


def frozen_plan(**intent):
    """The demo fixture's frozen plan, addressed to this module's tenant and principal."""
    resolved = replay_case()["resolved"]
    return resolved.model_copy(
        update={
            "intent": resolved.intent.model_copy(
                update={
                    "tenant_id": TENANT,
                    "principal_id": PRINCIPAL,
                    "account_id": ACCOUNT,
                    **intent,
                }
            )
        }
    )


FROZEN = frozen_plan()
FACTS = scalar_facts(FROZEN)


def charge(
    ledger,
    number,
    *,
    approved=False,
    action="endpoint.isolate",
    principal=PRINCIPAL,
    account=ACCOUNT,
    facts=None,
    groups=(),
    unknown_facts=frozenset(),
):
    ledger.reserve(
        UUID(int=number),
        principal,
        action,
        UUID(int=number + 1000),
        approved,
        NOW,
        account_id=account,
        facts=FACTS if facts is None else facts,
        groups=groups,
        unknown_facts=unknown_facts,
    )


def hypothetical(ledger, number, *, action="endpoint.isolate", account=ACCOUNT, groups=()):
    ledger.uncertain(
        UUID(int=number),
        PRINCIPAL,
        action,
        UUID(int=number + 1000),
        NOW,
        account_id=account,
        facts=FACTS,
        groups=groups,
    )


def observation(ledger, number, *, groups=(), unknown_facts=frozenset()):
    """An observed isolation that would have executed, counted by observe-mode usage only."""
    ledger.observe(
        UUID(int=number),
        PRINCIPAL,
        "endpoint.isolate",
        UUID(int=number + 1000),
        False,
        NOW,
        account_id=ACCOUNT,
        facts=FACTS,
        groups=groups,
        unknown_facts=unknown_facts,
    )


def bundle(*rules):
    content = endpoint_bundle(TENANT, ACCOUNT, mapping_version="map-v1", bundle_id=UUID(int=5))
    return content.model_copy(update={"limits": tuple(rules)}) if rules else content


def counts(ledger, now=NOW, **changes):
    content = bundle()
    if changes:
        content = content.model_copy(
            update={"limits": tuple(rule.model_copy(update=changes) for rule in content.limits)}
        )
    lower, upper, dependencies, unknown = ledger.usage(
        content, IDENTITY, now, frozen=FROZEN, groups=()
    )
    assert unknown == ()
    return {c.rule_id: c for c in lower.counts}, {c.rule_id: c for c in upper.counts}, dependencies


def rule(**changes):
    """A total ceiling of three on isolation that escalates, qualified by ``changes``."""
    return LimitRule(
        **{
            "rule_id": "scoped",
            "action": "endpoint.isolate",
            "scope": "principal",
            "window_seconds": 3600,
            "max_targets": 3,
            "budget": "total",
            "on_exceed": "REQUIRE_APPROVAL",
            **changes,
        }
    )


def scoped(ledger, *rules, groups=(), frozen=FROZEN, action=None, now=NOW, observed=False):
    """Each rule's (confirmed, unresolved) bounds, the dependencies and the unknown rules."""
    lower, upper, dependencies, unknown = ledger.usage(
        bundle(*rules),
        IDENTITY,
        now,
        frozen=frozen,
        groups=groups,
        action=action,
        observed=observed,
    )
    assert lower.account_id == upper.account_id == frozen.intent.account_id
    assert lower.groups == upper.groups == tuple(sorted(groups or (), key=str))
    return (
        {c.rule_id: (c.confirmed_targets, c.unresolved_targets) for c in lower.counts},
        {c.rule_id: (c.confirmed_targets, c.unresolved_targets) for c in upper.counts},
        dependencies,
        unknown,
    )


def test_ledger_charges_once_and_converts_reservation_without_double_count():
    ledger = Ledger(TENANT)
    charge(ledger, 10)
    charge(ledger, 10)
    low, high, deps = counts(ledger)
    assert all(c.unresolved_targets == 1 and c.confirmed_targets == 0 for c in low.values())
    assert low == high and deps == ()
    ledger.settle(UUID(int=10), True, NOW)
    ledger.settle(UUID(int=10), True, NOW)
    low, _, _ = counts(ledger)
    assert all(c.unresolved_targets == 0 and c.confirmed_targets == 1 for c in low.values())


def test_unresolved_reservations_never_age_out_but_confirmed_use_open_lower_boundary():
    ledger = Ledger(TENANT)
    charge(ledger, 10)
    charge(ledger, 11)
    ledger.settle(UUID(int=11), True, NOW)
    low, _, _ = counts(ledger, NOW + timedelta(days=2))
    assert all(c.unresolved_targets == 1 and c.confirmed_targets == 0 for c in low.values())
    low, _, _ = counts(ledger, NOW + timedelta(seconds=900))
    assert low["tenant-total-isolation"].confirmed_targets == 0
    assert low["principal-autonomous-isolation"].confirmed_targets == 1
    low, _, _ = counts(ledger, NOW + timedelta(seconds=900), window_seconds=901)
    assert all(c.confirmed_targets == 1 for c in low.values())


def test_rule_changes_principals_and_approved_classification_recompute_from_history():
    ledger = Ledger(TENANT)
    charge(ledger, 10, approved=True)
    charge(ledger, 11, principal=UUID(int=99))
    charge(ledger, 12, action="identity.enable")
    for n in (10, 11, 12):
        ledger.settle(UUID(int=n), True, NOW)
    low, _, _ = counts(ledger)
    assert low["tenant-total-isolation"].confirmed_targets == 2
    assert low["principal-autonomous-isolation"].confirmed_targets == 0
    low, _, _ = counts(ledger, NOW + timedelta(days=1), window_seconds=172800)
    assert low["tenant-total-isolation"].confirmed_targets == 2


def test_unknown_hypothetical_unit_contributes_only_upper_bound_and_never_expires():
    ledger = Ledger(TENANT)
    hypothetical(ledger, 10)
    low, high, deps = counts(ledger, NOW + timedelta(days=10))
    assert all(c.unresolved_targets == 0 for c in low.values())
    assert all(c.unresolved_targets == 1 for c in high.values())
    assert deps == (UUID(int=10),)
    assert ledger.guards(UUID(int=1010)) == (UUID(int=10),)


def test_nonexecution_releases_only_its_own_unit_and_inverse_action_never_refunds():
    ledger = Ledger(TENANT)
    charge(ledger, 10)
    charge(ledger, 11)
    charge(ledger, 12, action="identity.enable")
    ledger.settle(UUID(int=10), True, NOW)
    ledger.settle(UUID(int=11), False, NOW)
    ledger.settle(UUID(int=12), True, NOW)
    low, _, _ = counts(ledger)
    assert all(c.confirmed_targets == 1 and c.unresolved_targets == 0 for c in low.values())
    assert ledger.guards(UUID(int=1011)) == ()
    with pytest.raises(ValueError):
        ledger.settle(UUID(int=10), False, NOW)


def test_conflicting_charge_unknown_settlement_foreign_scope_and_backward_clock_fail():
    ledger = Ledger(TENANT)
    charge(ledger, 10)
    with pytest.raises(ValueError):
        charge(ledger, 10, approved=True)
    with pytest.raises(ValueError):
        charge(ledger, 10, groups=(GROUP,))
    with pytest.raises(ValueError):
        ledger.settle(UUID(int=999), True, NOW)
    with pytest.raises(ValueError):
        ledger.settle(UUID(int=10), True, NOW - timedelta(seconds=1))
    ledger.settle(UUID(int=10), True, NOW)
    with pytest.raises(ValueError):
        counts(ledger, NOW - timedelta(seconds=1))


def test_unresolved_is_counted_despite_backward_creation_time_and_other_action_future_is_ignored():
    ledger = Ledger(TENANT)
    charge(ledger, 10)
    charge(ledger, 11, action="identity.disable")
    ledger.settle(UUID(int=11), True, NOW + timedelta(seconds=10))
    low, _, _ = counts(ledger, NOW - timedelta(seconds=1))
    assert all(
        count.unresolved_targets == 1 and count.confirmed_targets == 0 for count in low.values()
    )


def test_confirmed_future_timestamp_respects_rule_scope_and_budget():
    ledger = Ledger(TENANT)
    charge(ledger, 10, approved=True, principal=UUID(int=99))
    ledger.settle(UUID(int=10), True, NOW + timedelta(seconds=1))
    # No matching principal-autonomous history exists for this querying agent.
    content = endpoint_bundle(TENANT, ACCOUNT, mapping_version="map-v1")
    principal_only = content.model_copy(update={"limits": (content.limits[0],)})
    lower, upper, deps, unknown = ledger.usage(
        principal_only, IDENTITY, NOW, frozen=FROZEN, groups=()
    )
    assert lower == upper and deps == () and unknown == ()
    assert lower.counts[0].confirmed_targets == 0
    with pytest.raises(ValueError, match="Backward replay semantic clock"):
        ledger.usage(content, IDENTITY, NOW, frozen=FROZEN, groups=())


def test_group_scope_counts_units_by_their_retained_membership_not_by_the_asker():
    ledger = Ledger(TENANT)
    charge(ledger, 10, groups=(GROUP,))
    charge(ledger, 11, principal=UUID(int=99), groups=(GROUP, OTHER_GROUP))
    charge(ledger, 12, groups=())
    charge(ledger, 13, groups=(OTHER_GROUP,))
    ledger.settle(UUID(int=10), True, NOW)
    # One counter for every agent that reaches the group, whatever the asker's own groups.
    for groups in ((), (GROUP,), (OTHER_GROUP, GROUP)):
        low, high, deps, unknown = scoped(
            ledger, rule(scope="group", group_id=GROUP), groups=groups
        )
        assert low == high == {"scoped": (1, 1)} and deps == () and unknown == ()
    low, _, _, unknown = scoped(ledger, rule(scope="group", group_id=OTHER_GROUP), groups=(GROUP,))
    assert low == {"scoped": (0, 2)} and unknown == ()
    # A group nobody recorded counts nothing and is not unknown either.
    low, _, _, unknown = scoped(ledger, rule(scope="group", group_id=UUID(int=66)), groups=(GROUP,))
    assert low == {"scoped": (0, 0)} and unknown == ()


def test_legacy_unit_without_membership_never_counts_and_is_unknown_when_the_rule_applies():
    ledger = Ledger(TENANT)
    charge(ledger, 10, groups=None)
    charge(ledger, 11, groups=(GROUP,))
    group_rule = rule(scope="group", group_id=GROUP)
    # A member asks: the legacy unit is skipped, so the count is only a lower bound.
    low, high, _, unknown = scoped(ledger, group_rule, groups=(GROUP,))
    assert low == high == {"scoped": (0, 1)} and unknown == ("scoped",)
    # A non-member asks: the rule does not apply to it, so the lower bound is no concern.
    low, _, _, unknown = scoped(ledger, group_rule, groups=())
    assert low == {"scoped": (0, 1)} and unknown == ()
    # A capture without recorded membership is a member of nothing, and every group rule
    # for its action is unknown even over an empty ledger; other scopes stay certain.
    low, _, _, unknown = scoped(
        Ledger(TENANT), group_rule, rule(rule_id="tenant", scope="tenant"), groups=None
    )
    assert low == {"scoped": (0, 0), "tenant": (0, 0)} and unknown == ("scoped",)
    other_action = rule(rule_id="other", action="identity.enable", scope="group", group_id=GROUP)
    _, _, _, unknown = scoped(ledger, other_action, groups=None)
    assert unknown == ()
    # A hypothetical unit without membership is skipped from both bounds as well.
    hypothetical(ledger, 12, groups=None)
    low, high, deps, unknown = scoped(ledger, group_rule, groups=(GROUP,))
    assert low == high == {"scoped": (0, 1)} and deps == () and unknown == ("scoped",)
    # The legacy unit still counts toward every scope whose attribute it carries.
    low, _, _, unknown = scoped(
        ledger,
        rule(scope="tenant"),
        rule(rule_id="mine", scope="principal"),
        rule(rule_id="account", scope="account", account_id=ACCOUNT),
        groups=(GROUP,),
    )
    assert low == {"scoped": (0, 2), "mine": (0, 2), "account": (0, 2)} and unknown == ()


def test_legacy_unit_that_would_not_have_counted_leaves_the_group_rule_known():
    ledger = Ledger(TENANT)
    group_rule = rule(scope="group", group_id=GROUP)
    member = {"groups": (GROUP,)}
    # A legacy non-execution never counted toward anything: no lower bound for a member.
    charge(ledger, 10, groups=None)
    ledger.settle(UUID(int=10), False, NOW)
    low, high, deps, unknown = scoped(ledger, group_rule, **member)
    assert low == high == {"scoped": (0, 0)} and deps == () and unknown == ()
    # A legacy confirmation at the window's edge is outside it and would not have counted
    # either; one second earlier it would have, so only then is the count a lower bound.
    charge(ledger, 11, groups=None)
    ledger.settle(UUID(int=11), True, NOW)
    edge = NOW + timedelta(seconds=3600)
    low, high, deps, unknown = scoped(ledger, group_rule, now=edge, **member)
    assert low == high == {"scoped": (0, 0)} and deps == () and unknown == ()
    _, _, _, unknown = scoped(ledger, group_rule, now=edge - timedelta(seconds=1), **member)
    assert unknown == ("scoped",)
    # A legacy observation counts only under an observe-mode evaluation, so only there
    # would it have counted: known under enforcement, unknown under observation.
    watching = Ledger(TENANT)
    observation(watching, 12, groups=None)
    _, _, _, unknown = scoped(watching, group_rule, **member)
    assert unknown == ()
    low, _, _, unknown = scoped(watching, group_rule, observed=True, **member)
    assert low == {"scoped": (0, 0)} and unknown == ("scoped",)


def test_unit_with_an_unknown_signal_reading_that_would_not_have_counted_leaves_the_rule_known():
    # A candidate that cannot read an earlier unit's signal fact cannot say whether a selector
    # over that fact counts it; only a unit that would have counted by state and window
    # makes the count a lower bound, exactly as unrecorded membership does for a group.
    suspect = FROZEN.model_copy(
        update={
            "facts": (
                *FROZEN.facts,
                FROZEN.fact("role").model_copy(
                    update={"name": "compromise", "value": "suspect", "source_kind": "signal"}
                ),
            )
        }
    )
    capped = rule(scope="selector", selector=LimitSelector(fact="compromise", equals="suspect"))
    unread = frozenset({"compromise"})
    ledger = Ledger(TENANT)
    # A non-execution never counted toward anything, whatever it was read as.
    charge(ledger, 10, unknown_facts=unread)
    ledger.settle(UUID(int=10), False, NOW)
    low, high, deps, unknown = scoped(ledger, capped, frozen=suspect)
    assert low == high == {"scoped": (0, 0)} and deps == () and unknown == ()
    # A confirmation at the window's edge is outside it; one second earlier it is inside,
    # and only then is the count a lower bound.
    charge(ledger, 11, unknown_facts=unread)
    ledger.settle(UUID(int=11), True, NOW)
    edge = NOW + timedelta(seconds=3600)
    low, high, deps, unknown = scoped(ledger, capped, frozen=suspect, now=edge)
    assert low == high == {"scoped": (0, 0)} and deps == () and unknown == ()
    _, _, _, unknown = scoped(ledger, capped, frozen=suspect, now=edge - timedelta(seconds=1))
    assert unknown == ("scoped",)
    # An observation counts only under an observe-mode evaluation: known under enforcement,
    # unknown under observation.
    watching = Ledger(TENANT)
    observation(watching, 12, unknown_facts=unread)
    _, _, _, unknown = scoped(watching, capped, frozen=suspect)
    assert unknown == ()
    low, _, _, unknown = scoped(watching, capped, frozen=suspect, observed=True)
    assert low == {"scoped": (0, 0)} and unknown == ("scoped",)
    # A candidate the selector does not apply to is not made unknown by the unit either.
    _, _, _, unknown = scoped(watching, capped, observed=True)
    assert unknown == ()


def test_hypothetical_unit_outside_the_candidate_scope_is_not_a_dependency():
    ledger = Ledger(TENANT)
    hypothetical(ledger, 10, groups=(GROUP,))
    hypothetical(ledger, 11, account=OTHER_ACCOUNT)
    squad = rule(scope="group", group_id=GROUP)
    elsewhere = rule(rule_id="elsewhere", scope="account", account_id=OTHER_ACCOUNT)
    # A member's decision can turn on the group's hypothetical unit; the other account's
    # rule cannot affect a candidate on this account. Both units stay in the upper bounds.
    low, high, deps, unknown = scoped(ledger, squad, elsewhere, groups=(GROUP,))
    assert low == {"scoped": (0, 0), "elsewhere": (0, 0)}
    assert high == {"scoped": (0, 1), "elsewhere": (0, 1)}
    assert deps == (UUID(int=10),) and unknown == ()
    # A non-member is outside the group rule as well: no dependency at all.
    _, high, deps, unknown = scoped(ledger, squad, elsewhere, groups=())
    assert high == {"scoped": (0, 1), "elsewhere": (0, 1)} and deps == () and unknown == ()
    # On the other account the account rule's unit is the dependency instead.
    _, _, deps, _ = scoped(
        ledger, squad, elsewhere, groups=(), frozen=frozen_plan(account_id=OTHER_ACCOUNT)
    )
    assert deps == (UUID(int=11),)


def test_account_scope_counts_only_units_of_the_rule_account_from_any_principal():
    ledger = Ledger(TENANT)
    charge(ledger, 10, account=ACCOUNT)
    charge(ledger, 11, account=OTHER_ACCOUNT, principal=UUID(int=99))
    charge(ledger, 12, account=OTHER_ACCOUNT)
    low, _, _, unknown = scoped(
        ledger,
        rule(scope="account", account_id=ACCOUNT),
        rule(rule_id="other", scope="account", account_id=OTHER_ACCOUNT),
        rule(rule_id="nobody", scope="account", account_id=UUID(int=66)),
    )
    assert low == {"scoped": (0, 1), "other": (0, 2), "nobody": (0, 0)} and unknown == ()
    # The snapshot's account is the frozen intent's, whatever the rules name.
    low, _, _, _ = scoped(
        ledger,
        rule(scope="account", account_id=ACCOUNT),
        frozen=frozen_plan(account_id=OTHER_ACCOUNT),
    )
    assert low == {"scoped": (0, 1)}


def test_selector_scope_matches_retained_facts_by_exact_type_and_value():
    ledger = Ledger(TENANT)
    charge(ledger, 10, facts={**FACTS, "criticality": 1})
    charge(ledger, 11, facts={**FACTS, "criticality": True})
    charge(ledger, 12, facts={**FACTS, "criticality": "1"})
    charge(
        ledger, 13, facts={name: value for name, value in FACTS.items() if name != "criticality"}
    )
    charge(ledger, 14, facts={})

    def selector(rule_id, fact, equals):
        return rule(
            rule_id=rule_id, scope="selector", selector=LimitSelector(fact=fact, equals=equals)
        )

    low, high, _, unknown = scoped(
        ledger,
        selector("long", "criticality", 1),
        selector("boolean", "criticality", True),
        selector("string", "criticality", "1"),
        selector("development", "environment", "development"),
        selector("production", "environment", "production"),
    )
    assert low == high
    assert low == {
        "long": (0, 1),
        "boolean": (0, 1),
        "string": (0, 1),
        "development": (0, 4),
        "production": (0, 0),
    }
    assert unknown == ()


def test_multi_action_rule_counts_every_listed_action_and_depends_on_each():
    ledger = Ledger(TENANT)
    charge(ledger, 10)
    charge(ledger, 11, action="identity.enable")
    hypothetical(ledger, 12, action="identity.enable")
    pair = rule(rule_id="pair", actions=("endpoint.isolate", "identity.enable"))
    single = rule(rule_id="single")
    low, high, deps, unknown = scoped(ledger, pair, single, action="endpoint.isolate")
    assert low == {"pair": (0, 2), "single": (0, 1)}
    assert high == {"pair": (0, 3), "single": (0, 1)}
    assert deps == (UUID(int=12),) and unknown == ()
    # The hypothetical unit is a dependency of every rule that lists the asked action.
    _, _, deps, _ = scoped(ledger, single, action="identity.enable")
    assert deps == ()
    _, _, deps, _ = scoped(ledger, pair, action="identity.enable")
    assert deps == (UUID(int=12),)


@pytest.mark.parametrize("scope", ["group", "account", "selector"])
def test_autonomous_budget_exempts_approved_units_in_every_scope(scope):
    ledger = Ledger(TENANT)
    charge(ledger, 10, approved=True, groups=(GROUP,))
    charge(ledger, 11, groups=(GROUP,))
    qualifier = {
        "group": {"group_id": GROUP},
        "account": {"account_id": ACCOUNT},
        "selector": {"selector": LimitSelector(fact="role", equals="workstation")},
    }[scope]
    low, _, _, unknown = scoped(
        ledger,
        rule(rule_id="autonomous", scope=scope, budget="autonomous", **qualifier),
        rule(rule_id="total", scope=scope, budget="total", **qualifier),
        groups=(GROUP,),
    )
    assert low == {"autonomous": (0, 1), "total": (0, 2)} and unknown == ()
