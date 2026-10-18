# SPDX-License-Identifier: AGPL-3.0-only
"""AR9: which actions a bundle can hold and how long a held request for each can wait (#678).

`holds` and `windows` are pure reads over bundle content and the context catalog, so most cases
build a bundle in memory: written as rules by the compiler, or by hand as a custom Cedar bundle.
A figure is an upper bound: the smallest validity over the kinds of fact a mapping's contract
resolves, read through the bundle's own context settings as admission reads them, capped by the
deadline. The console case, with the tenant view on real PostgreSQL, is in
`test_console_api_settings.py`.
"""

from dataclasses import replace
from uuid import uuid4

from execbound.approval_routing import Hold, Window, holds, windows
from execbound.contracts import (
    ENDPOINT_ISOLATION_V1,
    ENDPOINT_RECOVERY_V1,
    IDENTITY_CONTROL_V1,
    PRODUCTION_CATALOG,
    Catalog,
    SourceDefaults,
)
from execbound.policy.models import ContextSetting, LimitRule, MappingRef, QuorumRule, Rule, Ruleset
from execbound.policy.rulesets import ruleset_bundle
from execbound_harness.demo import endpoint_bundle

TENANT = uuid4()
ACCOUNT = uuid4()
ISOLATE = "endpoint.isolate"
LIFT = "endpoint.lift_isolation"


def mapping(ref: str, contract: str = "endpoint-isolation.v1", **changes) -> MappingRef:
    return MappingRef(
        operation_ref=ref,
        account_id=ACCOUNT,
        mapping_version="map-v1",
        schema_version="action.v1",
        context_contract_version=contract,
        **changes,
    )


def custom(**changes):
    """The endpoint pack written by hand: Cedar approval policies and one hold-on-exceed limit."""
    return endpoint_bundle(TENANT, ACCOUNT, mapping_version="map-v1").model_copy(update=changes)


def review(rule_id: str, quorum: int | None = None) -> Rule:
    return Rule(id=rule_id, action=ISOLATE, effect="REVIEW", quorum=quorum)


# A REVIEW rule holds what a rule allows; the compiler refuses a ruleset that allows nothing.
ALLOW = Rule(id="allow-isolate", action=ISOLATE, effect="ALLOW")


def rules(*written: Rule, budgets: tuple[LimitRule, ...] = (), mappings=None):
    return ruleset_bundle(
        Ruleset(rules=(*written, ALLOW), budgets=budgets),
        tenant_id=TENANT,
        bundle_id=uuid4(),
        mappings=mappings or (mapping(ISOLATE),),
    )


def limit(rule_id: str, on_exceed: str, actions: tuple[str, ...] | None = None) -> LimitRule:
    return LimitRule(
        rule_id=rule_id,
        action=ISOLATE,
        scope="tenant",
        window_seconds=3600,
        max_targets=5,
        budget="total",
        on_exceed=on_exceed,
        actions=actions,
    )


# A contract whose incident facts expire before its inventory facts, and one whose facts last
# fifteen minutes: neither ships, so each is in a catalog built for the case.
SHORT_INCIDENT = replace(
    ENDPOINT_ISOLATION_V1,
    version="endpoint-short-incident.v1",
    bind_incident_claim=True,
    sources={
        "inventory": SourceDefaults(600, 3600, ("inventory_sync",)),
        "incident": SourceDefaults(180, 3600, ("soc_analyst",)),
    },
)
LONG = replace(
    ENDPOINT_ISOLATION_V1,
    version="endpoint-long.v1",
    bind_incident_claim=True,
    sources={
        "inventory": SourceDefaults(900, 3600, ("inventory_sync",)),
        "incident": SourceDefaults(900, 3600, ("soc_analyst",)),
    },
)
CASES = Catalog((ENDPOINT_ISOLATION_V1, ENDPOINT_RECOVERY_V1, SHORT_INCIDENT, LONG))


def test_a_review_rule_holds_its_action_with_its_quorum():
    bundle = rules(review("prod-review", 2))
    assert holds(bundle) == (
        Hold(action=ISOLATE, held_by=("rule:prod-review",), known=True, required=2, upto=False),
    )


def test_two_review_rules_on_one_action_take_the_largest_quorum():
    bundle = rules(review("first", 2), review("second", 3), review("third"))
    (held,) = holds(bundle)
    assert held.held_by == ("rule:first", "rule:second", "rule:third")
    assert (held.required, held.known, held.upto) == (3, True, False)


def test_a_limit_that_asks_for_approval_holds_every_action_it_names():
    both = (ISOLATE, LIFT)
    bundle = rules(
        Rule(id="allow-lift", action=LIFT, effect="ALLOW"),
        budgets=(limit("isolations-per-hour", "REQUIRE_APPROVAL", both),),
        mappings=(mapping(ISOLATE), mapping(LIFT, "endpoint-recovery.v1")),
    )
    assert holds(bundle) == tuple(
        Hold(
            action=action,
            held_by=("limit:isolations-per-hour",),
            known=True,
            required=1,
            upto=False,
        )
        for action in sorted(both)
    )


def test_a_limit_that_denies_holds_nothing():
    bundle = rules(budgets=(limit("cap", "DENY"),))
    assert holds(bundle) == ()
    assert windows(bundle, PRODUCTION_CATALOG, 120) == ()


def test_an_observe_only_mapping_is_never_listed():
    bundle = rules(review("prod-review"), mappings=(mapping(ISOLATE, observe_only=True),))
    assert holds(bundle) == ()
    assert windows(bundle, PRODUCTION_CATALOG, 3600) == ()


def test_a_custom_policy_that_can_hold_reads_unknown_up_to_its_largest_quorum():
    quorum = (
        QuorumRule(rule_id="two", obligation="policy:policy0", required=2),
        QuorumRule(rule_id="three", obligation="policy:policy1", required=3),
    )
    (held,) = holds(custom(quorum=quorum))
    assert held.action == ISOLATE
    # The pack's own hold-on-exceed limit, read as written, and the approval policies.
    assert held.held_by == ("limit:principal-autonomous-isolation", "policy")
    assert (held.known, held.required, held.upto) == (False, 3, True)
    # Without quorum rules, every obligation needs one person.
    (single,) = holds(custom())
    assert (single.known, single.required, single.upto) == (False, 1, False)


def test_a_custom_quorum_on_a_limit_obligation_is_that_limits_quorum():
    bundle = custom(
        approval_policies="",
        quorum=(
            QuorumRule(
                rule_id="pair", obligation="limit:principal-autonomous-isolation", required=2
            ),
        ),
    )
    assert holds(bundle) == (
        Hold(
            action=ISOLATE,
            held_by=("limit:principal-autonomous-isolation",),
            known=True,
            required=2,
            upto=False,
        ),
    )


def test_a_custom_bundle_with_no_approval_policies_and_no_hold_limit_holds_nothing():
    bundle = custom(approval_policies="", limits=(limit("cap", "DENY"),))
    assert holds(bundle) == ()


def test_ar9_the_deadline_caps_the_context_and_off_leaves_the_context():
    bundle = rules(review("prod-review"))
    kinds = ("incident", "inventory")
    assert windows(bundle, PRODUCTION_CATALOG, 120) == (
        Window(ISOLATE, 300, 120, "deadline", kinds, True),
    )
    assert windows(bundle, PRODUCTION_CATALOG, 3600) == (
        Window(ISOLATE, 300, 300, "context", kinds, True),
    )
    assert windows(bundle, PRODUCTION_CATALOG, None) == (
        Window(ISOLATE, 300, 300, "context", kinds, True),
    )
    # A deadline equal to the context leaves the context as what limits it.
    assert windows(bundle, PRODUCTION_CATALOG, 300)[0].limited_by == "context"


def test_ar9_a_bundle_setting_overrides_the_contract_default_as_admission_reads_it():
    settings = tuple(
        ContextSetting(
            context_contract_version="endpoint-isolation.v1",
            source_kind=kind,
            max_age_seconds=600,
            permitted_writers=writers,
        )
        for kind, writers in (("inventory", ("inventory_sync",)), ("incident", ("soc_analyst",)))
    )
    bundle = rules(review("prod-review")).model_copy(update={"context_settings": settings})
    assert windows(bundle, PRODUCTION_CATALOG, 3600) == (
        Window(ISOLATE, 600, 600, "context", ("incident", "inventory"), True),
    )
    # Only one kind raised: the other still limits the figure.
    raised = rules(review("prod-review")).model_copy(update={"context_settings": settings[:1]})
    assert windows(raised, PRODUCTION_CATALOG, 3600) == (
        Window(ISOLATE, 300, 300, "context", ("incident",), True),
    )


def test_ar9_a_shorter_incident_figure_wins():
    bundle = custom(mappings=(mapping(ISOLATE, SHORT_INCIDENT.version),))
    assert windows(bundle, CASES, 3600) == (
        Window(ISOLATE, 180, 180, "context", ("incident",), False),
    )


def test_ar9_an_unknown_contract_gives_no_figure():
    bundle = rules(review("prod-review"))
    without = Catalog((IDENTITY_CONTROL_V1,))
    assert windows(bundle, without, 120) == (Window(ISOLATE, None, None, "unknown", (), True),)
    # One unknown mapping among several leaves the action's upper bound unknown.
    two = custom(
        mappings=(mapping(ISOLATE), mapping("isolate-elsewhere", "missing.v1", action=ISOLATE))
    )
    assert windows(two, CASES, 120)[0].limited_by == "unknown"


def test_ar9_an_action_served_by_two_contracts_takes_the_larger_bound():
    bundle = custom(
        mappings=(mapping(ISOLATE), mapping("isolate-long", LONG.version, action=ISOLATE))
    )
    assert windows(bundle, CASES, 3600) == (
        Window(ISOLATE, 900, 900, "context", ("incident", "inventory"), False),
    )
    assert windows(bundle, CASES, 600) == (
        Window(ISOLATE, 900, 600, "deadline", ("incident", "inventory"), False),
    )
