# SPDX-License-Identifier: AGPL-3.0-only
"""The console's reason views name what the record can support, and nothing it cannot (#545).

A reason view is the code a transition recorded, the rule it names and a sentence. Two gaps
from the hosted sample walkthrough: every executed row fell back to "A reason was recorded
without a plain-language explanation", because the code a provider's own answer settles with
had no sentence; and a denial could not say which rule denied it, because the kernel records
`NOT_AUTHORIZED` and keeps no rule id. The first is words. The second is a reading of the
frozen bundle's rules over the frozen facts and arguments, which `tests/test_pack_rulesets.py`
holds equal to the kernel's decision on every input of the shipped packs: the sentence names
every deny rule the request matches, or says that no rule allows it, and the view claims
nothing when Cedar itself failed, when a fact the rules read is missing, when the reading does
not deny or when the bundle carries no rules. The reading is never passed off as a recorded
rule id, so `rule_id` stays None.
"""

from uuid import uuid4

import pytest
from soc_fixtures import scenario

from execbound.policy import evaluate as evaluator
from execbound.policy.rulesets import sentence as rule_sentence
from execbound.resolution.models import ResolvedRequest
from execbound.surfaces.console_api.executions import SENTENCES, reason_views
from execbound_harness.soc_demo import SOC_RULESET, soc_bundle, soc_ruleset_bundle

LEGACY = SENTENCES["NOT_AUTHORIZED"]


def decided(action, *, bundle=soc_ruleset_bundle, **case):
    """The kernel's own evaluation of one frozen plan, and the plan and bundle it read."""
    inputs = scenario(action, bundle=bundle, **case)
    return evaluator.evaluate(**inputs), inputs["resolved"], inputs["bundle"]


def without(resolved: ResolvedRequest, name: str) -> ResolvedRequest:
    return resolved.model_copy(
        update={"facts": tuple(fact for fact in resolved.facts if fact.name != name)}
    )


RULES = {rule.id: rule for rule in SOC_RULESET.rules}
DOMAIN_CONTROLLER = "isolate-never-domain-controller"
CRITICALITY_FOUR = "isolate-never-criticality-4"


def test_a_denial_names_the_deny_rule_its_frozen_facts_match():
    # Criticality 1, so only the domain controller rule matches, although the criticality
    # rule is another deny rule for the same action and sorts first.
    result, resolved, bundle = decided(
        "endpoint.isolate",
        arguments={},
        classification=("role", "domain_controller"),
        environment="production",
        criticality=1,
    )
    assert result.effect == "DENY" and result.reasons == ("NOT_AUTHORIZED",)
    assert {DOMAIN_CONTROLLER, CRITICALITY_FOUR} <= set(RULES)
    [view] = reason_views(result.reasons, bundle, resolved)
    assert view.code == "NOT_AUTHORIZED" and view.rule_id is None
    # The rules the reading matched, for the console's rule link (#678); still no rule id.
    assert view.rules == [DOMAIN_CONTROLLER]
    assert view.sentence == (
        f"This request matches the deny rule {DOMAIN_CONTROLLER}: "
        f"{rule_sentence(RULES[DOMAIN_CONTROLLER])}"
    )


def test_a_denial_two_deny_rules_match_names_both():
    result, resolved, bundle = decided(
        "endpoint.isolate",
        arguments={},
        classification=("role", "domain_controller"),
        environment="production",
        criticality=4,
    )
    assert result.reasons == ("NOT_AUTHORIZED",)
    [view] = reason_views(result.reasons, bundle, resolved)
    # The reading lists the rules it matched by id.
    first, second = sorted((DOMAIN_CONTROLLER, CRITICALITY_FOUR))
    assert view.rules == [first, second] and view.rule_id is None
    assert view.sentence == (
        f"This request matches the deny rules {first} and {second}: "
        f"{rule_sentence(RULES[first])} {rule_sentence(RULES[second])}"
    )


def test_a_denial_cedar_failed_to_decide_names_no_rule():
    # Cedar's error records POLICY_ERROR beside NOT_AUTHORIZED: the kernel denied closed and
    # decided on no rule, even where the facts would read as a deny.
    _, resolved, bundle = decided(
        "endpoint.isolate",
        arguments={},
        classification=("role", "domain_controller"),
        environment="production",
    )
    views = reason_views(["POLICY_ERROR", "NOT_AUTHORIZED"], bundle, resolved)
    assert [view.sentence for view in views] == [SENTENCES["POLICY_ERROR"], LEGACY]
    assert all(view.rules == [] for view in views)


def test_a_denial_the_rules_would_allow_keeps_the_recorded_sentence():
    # A reading that does not deny cannot explain a denial: some cause outside the rules did.
    result, resolved, bundle = decided(
        "endpoint.isolate",
        arguments={},
        classification=("role", "workstation"),
        environment="development",
    )
    assert result.effect == "ELIGIBLE"
    [view] = reason_views(["NOT_AUTHORIZED"], bundle, resolved)
    assert view.rule_id is None and view.sentence == LEGACY
    assert view.rules == []


def test_a_denial_no_rule_allows_says_so_and_names_no_rule():
    # Walk the inputs until the kernel denies with no deny rule matching: nothing allowed it.
    found = None
    for role in ("workstation", "server", "domain_controller"):
        for environment in ("development", "staging", "production"):
            for status in ("OPEN", "CLOSED"):
                result, resolved, bundle = decided(
                    "endpoint.isolate",
                    arguments={},
                    classification=("role", role),
                    environment=environment,
                    incident_status=status,
                )
                if result.effect != "DENY":
                    continue
                [view] = reason_views(result.reasons, bundle, resolved)
                assert view.code == "NOT_AUTHORIZED" and view.rule_id is None
                if not view.sentence.startswith("This request matches the deny rule"):
                    found = view
    assert found is not None, "no input the SOC pack denies without a deny rule"
    assert found.sentence == "No rule allows this action for this request's facts and arguments."
    assert found.rules == []


def test_a_denial_claims_nothing_when_a_fact_the_rules_read_is_missing():
    result, resolved, bundle = decided(
        "endpoint.isolate",
        arguments={},
        classification=("role", "domain_controller"),
        environment="production",
    )
    [view] = reason_views(result.reasons, bundle, without(resolved, "role"))
    assert view.rule_id is None and view.sentence == LEGACY


def test_a_denial_under_a_bundle_without_rules_keeps_the_recorded_sentence():
    result, resolved, bundle = decided(
        "endpoint.isolate",
        bundle=soc_bundle,
        arguments={},
        classification=("role", "domain_controller"),
        environment="production",
    )
    assert bundle.ruleset is None and result.reasons == ("NOT_AUTHORIZED",)
    [view] = reason_views(result.reasons, bundle, resolved)
    assert view.rule_id is None and view.sentence == LEGACY


def test_a_view_without_the_frozen_plan_names_no_rule():
    result, _, bundle = decided(
        "endpoint.isolate",
        arguments={},
        classification=("role", "domain_controller"),
        environment="production",
    )
    [view] = reason_views(result.reasons, bundle)
    assert view.rule_id is None and view.sentence == LEGACY


@pytest.mark.parametrize(
    "code",
    [
        # The codes a settled outcome records: the provider's own answer, an executor's
        # report, and a report window that closed with none.
        "PROVIDER_RESPONSE",
        "EXECUTOR_REPORT",
        "REPORTED_FAILURE",
        "UNREPORTED_GRANT",
        "INCONCLUSIVE_JOURNAL",
        # The evaluation's own refusals and a reviewer's.
        "INVALID_ARGUMENTS",
        "DEPENDENCY_UNAVAILABLE",
        "HUMAN_DENIED",
    ],
)
def test_every_settlement_and_evaluation_code_has_a_sentence(code):
    _, _, bundle = decided("endpoint.isolate", arguments={}, classification=("role", "server"))
    [view] = reason_views([code], bundle)
    assert view.sentence and view.rule_id is None, code


def test_an_executed_record_says_the_providers_answer_confirmed_it():
    _, _, bundle = decided("endpoint.isolate", arguments={}, classification=("role", "server"))
    [view] = reason_views(["PROVIDER_RESPONSE"], bundle)
    assert view.sentence == "The provider's own response confirmed this outcome."


def test_a_reconciliation_note_is_shown_as_the_note_it_is():
    _, _, bundle = decided("endpoint.isolate", arguments={}, classification=("role", "server"))
    note = f"Scheduled recovery {uuid4()}"
    [view] = reason_views([note], bundle)
    assert view.code == note and view.rule_id is None
    assert view.sentence == f"Settled by reconciliation, noting: {note}"
    # A code-shaped reason is never mistaken for a note, known or not.
    for code in ("HARD_LIMIT:isolate-budget", "SOME_FUTURE_CODE"):
        [coded] = reason_views([code], bundle)
        assert not coded.sentence.startswith("Settled by reconciliation"), code
