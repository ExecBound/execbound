# SPDX-License-Identifier: AGPL-3.0-only
"""The rules read as the kernel decides for every operator, not only the two the packs write.

`project()` is what the welcome page, an agent's page and an activity record's denial print as
how the rules read, and `tests/test_pack_rulesets.py` holds it equal to the kernel's policy
decision over every input of the shipped packs. Those packs write only `is` and `in`. A
customer's rule may write `is_not`, `at_least` or `at_most`, and the Defender scenario's review
rule is `compromise is_not compromised` (#478). This holds the reading to the kernel for those
too, exhaustively, with the kernel's decision through the real `evaluate` as the reference:

- every condition the rule editor can write with one of the three, on every field an action's
  rules may name and at every value its domain holds, the bounds included, each as its own
  review rule, so the review rules the reading names are compared one by one with the
  obligations Cedar raised, on every input of every SOC action;
- the three in every effect and in conjunction, so the precedence the reading follows is held
  to the kernel's with them in it;
- a Long argument, which no production action declares, through the synthetic probe action;
- and the Defender scenario's committed rules over every input, every compromise value
  included.
"""

from datetime import timedelta
from pathlib import Path
from uuid import UUID, uuid4

import pytest
from pydantic import TypeAdapter
from soc_fixtures import (
    PROBE_ACTION,
    PROBE_OPERATION,
    TEST_ACTIONS,
    TEST_CATALOG,
    scenario,
)
from test_pack_rulesets import READING, facts_of, inputs

from execbound.cli import load_ruleset_file
from execbound.contracts import ENDPOINT_ISOLATION_V2, PRODUCTION_CATALOG, SIGNAL_WRITER
from execbound.operations import PRODUCTION_ACTIONS
from execbound.policy import evaluate as evaluator
from execbound.policy.models import BundleContent, Condition, MappingRef, Rule, Ruleset
from execbound.policy.rulesets import (
    FieldChoice,
    compile_ruleset,
    project,
    review_rule_ids,
    ruleset_bundle,
    writable_fields,
)
from execbound.resolution.models import SignalEvidence, SignalRecord, TrustedFact
from execbound.signals.models import SignalMapping, SignalThreshold
from execbound_harness.soc_demo import SOC_ACTIONS

OPERATORS = ("is_not", "at_least", "at_most")
ALLOW_ALWAYS = "allow-always"
# What the kernel may answer on the policy alone. Anything else (a context, argument or bundle
# refusal) would be a decision the rules were never asked about, so it fails the test rather
# than counting as a denial the reading happened to match.
POLICY_REASONS = ((), ("APPROVAL_REQUIRED",), ("NOT_AUTHORIZED",))


def one_mapping(action, *, operation_ref=None, version=None, catalog_actions=PRODUCTION_ACTIONS):
    """The mappings of a bundle serving `action` alone, as a function of the call's accounts."""
    spec = catalog_actions.action(action)

    def mappings(endpoint_account, identity_account, mapping_version):
        return (
            MappingRef(
                operation_ref=operation_ref or action,
                action=action if operation_ref else None,
                account_id=endpoint_account
                if spec.resource_type == "endpoint"
                else identity_account,
                mapping_version=mapping_version,
                schema_version="action.v1",
                context_contract_version=version or spec.context_contract_version,
            ),
        )

    return mappings


def bundles(ruleset, mappings, *, catalog=PRODUCTION_CATALOG, **carried):
    """A bundle factory with `soc_bundle`'s signature for `ruleset`, compiled once.

    `scenario` calls a factory with fresh accounts every time; compilation depends on the
    mappings' contract versions and not on the accounts, so only the bundle is built per call.
    """
    compiled = compile_ruleset(ruleset, mappings(uuid4(), uuid4(), "map-v1"), catalog=catalog)

    def build(tenant, endpoint_account, identity_account, *, mapping_version, bundle_id=None):
        return BundleContent(
            tenant_id=tenant,
            bundle_id=bundle_id or uuid4(),
            cedar_schema=compiled.cedar_schema,
            authorization_policies=compiled.authorization_policies,
            approval_policies=compiled.approval_policies,
            mappings=mappings(endpoint_account, identity_account, mapping_version),
            limits=compiled.limits,
            quorum=compiled.quorum,
            ruleset=ruleset,
            **carried,
        )

    # What the store, the CLI and the editor build from a ruleset, and nothing else.
    sample = build(uuid4(), uuid4(), uuid4(), mapping_version="map-v1")
    assert sample == ruleset_bundle(
        ruleset,
        tenant_id=sample.tenant_id,
        bundle_id=sample.bundle_id,
        mappings=sample.mappings,
        catalog=catalog,
        **carried,
    )
    return build


def domain(field: FieldChoice):
    """Every value a field can hold: a closed set as listed, a Long from bound to bound."""
    if field.cedar_type == "Long":
        assert field.minimum is not None and field.maximum is not None
        return tuple(range(field.minimum, field.maximum + 1))
    assert field.values
    return field.values


def conditions(fields):
    """Every condition the editor can write with `is_not`, `at_least` or `at_most`."""
    for field in fields:
        for operator in OPERATORS:
            if operator in field.operators:
                for value in domain(field):
                    yield Condition(
                        kind=field.kind, name=field.name, operator=operator, values=(value,)
                    )


def rule_id(condition):
    value = str(condition.values[0]).lower()
    return f"{condition.kind}.{condition.name}.{condition.operator}.{value}"


def review_each(action, fields):
    """Allow `action` outright, and review it under each condition as a rule of its own.

    Nothing is ever denied, so on every input the kernel's obligations say exactly which
    conditions Cedar found true, and the reading's review rules say which the reading did.
    """
    return Ruleset(
        rules=(
            Rule(id=ALLOW_ALWAYS, action=action, effect="ALLOW"),
            *(
                Rule(id=rule_id(condition), action=action, effect="REVIEW", when=(condition,))
                for condition in conditions(fields)
            ),
        )
    )


def compare(ruleset, decided, reading, where):
    """The reading says what the kernel decided, and names the review rules Cedar applied."""
    assert decided.reasons in POLICY_REASONS, (where, decided)
    assert reading.unknown == (), (where, reading)
    assert reading.effect == READING[decided.effect], (where, reading, decided)
    if reading.effect == "deny":
        return set()
    obligations = review_rule_ids(ruleset)
    raised = {obligations[obligation] for obligation in decided.obligation_ids}
    allows = {rule.id for rule in ruleset.rules if rule.effect == "ALLOW"}
    assert set(reading.rules) - allows == raised, (where, reading, decided)
    assert set(reading.rules) & allows, (where, reading)
    return raised


def assert_discriminates(ruleset, raised_somewhere, quiet_somewhere, fields):
    """Every review rule was raised on some input, and every one that is not true of its whole
    domain (`at_least` its minimum, `at_most` its maximum) was quiet on another."""
    reviews = {rule.id for rule in ruleset.rules if rule.effect == "REVIEW"}
    assert raised_somewhere == reviews
    always = {
        rule_id(Condition(kind=f.kind, name=f.name, operator=operator, values=(bound,)))
        for f in fields
        if f.cedar_type == "Long"
        for operator, bound in (("at_least", f.minimum), ("at_most", f.maximum))
    }
    assert quiet_somewhere == reviews - always


@pytest.mark.parametrize("action", SOC_ACTIONS)
def test_every_condition_of_the_other_operators_reads_as_the_kernel_applies_it(action):
    mappings = one_mapping(action)
    fields = writable_fields(mappings(uuid4(), uuid4(), "map-v1"))[action]
    ruleset = review_each(action, fields)
    build = bundles(ruleset, mappings)
    reviews = {rule.id for rule in ruleset.rules if rule.effect == "REVIEW"}
    raised_somewhere, quiet_somewhere = set(), set()
    for case in inputs(action):
        decided = evaluator.evaluate(**scenario(action, bundle=build, **case))
        reading = project(ruleset, action, facts_of(case), case["arguments"])
        raised = compare(ruleset, decided, reading, (action, case))
        raised_somewhere |= raised
        quiet_somewhere |= reviews - raised
    assert_discriminates(ruleset, raised_somewhere, quiet_somewhere, fields)


def test_a_long_argument_reads_as_the_kernel_applies_it_at_every_value():
    """No production action declares a Long argument; the compiler admits `at_least` and
    `at_most` on one all the same, so the synthetic probe's `depth` (1 to 5) stands in. Its
    rules read nothing but `depth`, so its five values are their whole input space."""
    mappings = one_mapping(
        PROBE_ACTION, operation_ref=PROBE_OPERATION, catalog_actions=TEST_ACTIONS
    )
    fields = writable_fields(mappings(uuid4(), uuid4(), "map-v1"), catalog=TEST_CATALOG)[
        PROBE_ACTION
    ]
    arguments = tuple(field for field in fields if field.kind == "argument")
    assert [(field.name, field.cedar_type) for field in arguments] == [("depth", "Long")]
    ruleset = review_each(PROBE_ACTION, arguments)
    build = bundles(ruleset, mappings, catalog=TEST_CATALOG)
    reviews = {rule.id for rule in ruleset.rules if rule.effect == "REVIEW"}
    raised_somewhere, quiet_somewhere = set(), set()
    for depth in domain(arguments[0]):
        case = scenario(
            PROBE_ACTION,
            arguments={"depth": depth},
            classification=("role", "workstation"),
            actions=TEST_ACTIONS,
            bundle=build,
            operation_ref=PROBE_OPERATION,
        )
        decided = evaluator.evaluate(**case, catalog=TEST_CATALOG)
        reading = project(ruleset, PROBE_ACTION, {}, {"depth": depth})
        raised = compare(ruleset, decided, reading, depth)
        raised_somewhere |= raised
        quiet_somewhere |= reviews - raised
    assert_discriminates(ruleset, raised_somewhere, quiet_somewhere, arguments)


def precedence(action, fields):
    """The three operators in every effect and in conjunction, over one action's own fields.

    Two allows, two reviews and two denials whose conditions overlap, so an input can meet an
    allow, a review and a denial at once and the precedence decides it: a denial wins, an
    allow is needed, and an applicable review means approval.
    """
    classification = fields[0]
    first = domain(classification)[0]

    def fact(name, operator, value):
        return Condition(kind="fact", name=name, operator=operator, values=(value,))

    rules = [
        Rule(
            id="allow-open-from-1",
            action=action,
            effect="ALLOW",
            when=(fact("incident_status", "is_not", "CLOSED"), fact("criticality", "at_least", 1)),
        ),
        Rule(
            id="allow-quiet-at-0",
            action=action,
            effect="ALLOW",
            when=(fact("criticality", "at_most", 0), fact("is_production", "is_not", True)),
        ),
        Rule(
            id="review-production-up-to-2",
            action=action,
            effect="REVIEW",
            when=(fact("is_production", "is_not", False), fact("criticality", "at_most", 2)),
        ),
        Rule(
            id="review-from-4",
            action=action,
            effect="REVIEW",
            when=(fact("criticality", "at_least", 4),),
        ),
        Rule(
            id="deny-severe-unless-first",
            action=action,
            effect="DENY",
            when=(
                fact(classification.name, "is_not", first),
                fact("incident_severity", "is_not", "LOW"),
                fact("criticality", "at_least", 3),
            ),
        ),
        Rule(
            id="deny-closed-up-to-1",
            action=action,
            effect="DENY",
            when=(fact("incident_status", "is_not", "OPEN"), fact("criticality", "at_most", 1)),
        ),
    ]
    for field in fields:
        if field.kind == "argument":
            rules.append(
                Rule(
                    id="review-unless-first-argument",
                    action=action,
                    effect="REVIEW",
                    when=(
                        Condition(
                            kind="argument",
                            name=field.name,
                            operator="is_not",
                            values=(domain(field)[0],),
                        ),
                    ),
                )
            )
    return Ruleset(rules=tuple(rules))


@pytest.mark.parametrize("action", SOC_ACTIONS)
def test_the_other_operators_in_every_effect_read_as_the_kernel_decides(action):
    mappings = one_mapping(action)
    fields = writable_fields(mappings(uuid4(), uuid4(), "map-v1"))[action]
    ruleset = precedence(action, fields)
    build = bundles(ruleset, mappings)
    denies = {rule.id for rule in ruleset.rules if rule.effect == "DENY"}
    seen = set()
    named = set()
    for case in inputs(action):
        decided = evaluator.evaluate(**scenario(action, bundle=build, **case))
        reading = project(ruleset, action, facts_of(case), case["arguments"])
        compare(ruleset, decided, reading, (action, case))
        if reading.effect == "deny":
            assert set(reading.rules) <= denies, (action, case, reading)
        seen.add(reading.effect)
        named.update(reading.rules)
    # Not vacuous: every effect was reached and every rule was the one a reading rested on.
    assert seen == set(READING.values()), seen
    assert named == {rule.id for rule in ruleset.rules}


SCENARIO = Path(__file__).resolve().parents[1] / "integrations" / "mde-producer" / "scenario"
DEFENDER = load_ruleset_file(SCENARIO / "rules.json")
SOURCE = UUID(int=478)
# The committed verdict table never reads a verdict as `clean`, which only a source attesting
# liveness may report. The rules read the fact, and the fact's domain has `clean` in it, so
# this table is the committed one with `None` read as `clean`, from a source that attests
# liveness: every value the fact can hold is reached through the kernel's own recomputation.
COMMITTED = TypeAdapter(tuple[SignalThreshold, ...]).validate_json(
    (SCENARIO / "thresholds.json").read_text(encoding="utf-8")
)
THRESHOLDS = tuple(
    SignalThreshold.model_validate({**row.model_dump(), "value": "clean"})
    if row.verdict == "None"
    else row
    for row in COMMITTED
)
VERDICT = {
    "clean": "None",
    "no_detection": "Informational",
    "suspect": "Low",
    "compromised": "High",
}


def compromise(value, now):
    """The `compromise` fact as resolution freezes it: one record from the one admitted source,
    whose verdict the bundle's table reads as `value`. Evaluation recomputes the value from the
    record and refuses the plan if the two differ, so a wrong pairing here cannot pass."""
    record = SignalRecord(
        source_id=SOURCE,
        registration_version=1,
        attests_liveness=True,
        source_event_id="device-01:1",
        record_digest="a" * 64,
        producer_name="execbound-mde-producer",
        producer_version="0.1.0",
        verdict=VERDICT[value],
        confidence=1000,
        observed_at=now - timedelta(seconds=60),
        received_at=now - timedelta(seconds=60),
    )
    return TrustedFact(
        name="compromise",
        value=value,
        origin="RESOLVED",
        source_id=SOURCE,
        source_kind="signal",
        source_object_id="device-01",
        source_version="1",
        permitted_writers=(SIGNAL_WRITER,),
        observed_at=record.observed_at,
        valid_until=now + timedelta(seconds=240),
        signal=SignalEvidence(capability="resource_compromise.v1", records=(record,)),
    )


def test_the_defender_scenario_rules_read_as_the_kernel_decides_on_every_input():
    """The scenario's rules as committed, compiled as `ruleset-compile` compiles them onto an
    `endpoint-isolation.v2` mapping, over every input of `endpoint.isolate` and every value the
    `compromise` fact can hold. The review rule is `compromise is_not compromised`."""
    action = "endpoint.isolate"
    mappings = one_mapping(action, version=ENDPOINT_ISOLATION_V2.version)
    fields = writable_fields(mappings(uuid4(), uuid4(), "map-v1"))[action]
    values = next(domain(field) for field in fields if field.name == "compromise")
    assert set(values) == set(VERDICT)
    build = bundles(
        DEFENDER,
        mappings,
        context_settings=DEFENDER.context,
        signal_mappings=(
            SignalMapping(
                context_contract_version=ENDPOINT_ISOLATION_V2.version,
                capability="resource_compromise.v1",
                admitted_sources=(SOURCE,),
                thresholds=THRESHOLDS,
            ),
        ),
    )
    seen = set()
    for case in inputs(action):
        for value in values:
            built = scenario(action, bundle=build, **case)
            resolved = built["resolved"]
            built["resolved"] = resolved.model_copy(
                update={
                    "context_contract_version": ENDPOINT_ISOLATION_V2.version,
                    "facts": (*resolved.facts, compromise(value, resolved.resolved_at)),
                }
            )
            decided = evaluator.evaluate(**built)
            facts = {**facts_of(case), "compromise": value}
            reading = project(DEFENDER, action, facts, case["arguments"])
            compare(DEFENDER, decided, reading, (case, value))
            # What `project()` reads, which the welcome page, an agent's page and an activity
            # record's denial print (the rules editor's read-back of the condition is held in
            # tests/test_console_api_rules_signal.py), and the scenario's own claim: isolation
            # without review only when Defender reports the host compromised, never a domain
            # controller, and only for an open incident.
            if case["incident_status"] != "OPEN" or case["classification"] == (
                "role",
                "domain_controller",
            ):
                assert reading.effect == "deny", (case, value, reading)
            elif value == "compromised":
                assert reading.effect == "allow", (case, value, reading)
            else:
                assert reading.rules == (
                    "isolate-open-incident",
                    "isolate-review-unless-compromised",
                ), (case, value, reading)
            seen.add(reading.effect)
    assert seen == set(READING.values()), seen
