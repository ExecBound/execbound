# SPDX-License-Identifier: AGPL-3.0-only
"""The packs as rulesets decide every possible input exactly as the hand-written packs did.

This is the acceptance for step 2 of #273, and it is exhaustive rather than sampled: the
contracts' fact domains are small enough to enumerate in full, so every combination of
classification, environment, incident status and severity, criticality and argument value is
evaluated under both bundles through the real `evaluate` and the decisions compared. A pack
whose ruleset diverged from its Cedar on any input fails here, with the input printed.
"""

import itertools
from functools import cache

import pytest
from soc_fixtures import scenario

from execbound.policy import evaluate as evaluator
from execbound.policy.rulesets import compile_ruleset, project, ruleset_bundle
from execbound_harness.demo import ENDPOINT_RULESET, endpoint_bundle, endpoint_ruleset_bundle
from execbound_harness.identity_demo import (
    IDENTITY_ACTIONS,
    IDENTITY_RULESET,
    identity_bundle,
    identity_ruleset_bundle,
)
from execbound_harness.soc_demo import SOC_ACTIONS, SOC_RULESET, soc_bundle, soc_ruleset_bundle

ENVIRONMENTS = ("development", "staging", "production")
STATUSES = ("OPEN", "CLOSED")
SEVERITIES = ("LOW", "MEDIUM", "HIGH", "CRITICAL")
CRITICALITIES = tuple(range(5))
ARGUMENTS = {
    "endpoint.lift_isolation": ({"reason": "false_positive"}, {"reason": "remediated"}),
    "identity.reset_password": (
        {"require_change_at_next_sign_in": True},
        {"require_change_at_next_sign_in": False},
    ),
}


def classifications(action):
    if action.startswith("endpoint."):
        return tuple(("role", role) for role in ("workstation", "server", "domain_controller"))
    return tuple(("privilege_class", p) for p in ("standard", "privileged", "tier0"))


def inputs(action):
    for classification, environment, status, severity, criticality, arguments in itertools.product(
        classifications(action),
        ENVIRONMENTS,
        STATUSES,
        SEVERITIES,
        CRITICALITIES,
        ARGUMENTS.get(action, ({},)),
    ):
        yield {
            "arguments": arguments,
            "classification": classification,
            "environment": environment,
            "incident_status": status,
            "incident_severity": severity,
            "criticality": criticality,
        }


# `scenario` takes a bundle factory with `soc_bundle`'s signature and calls it with fresh ids
# every time. Compilation depends on the mappings' contract versions and not on the ids, so
# the compiled components are computed once per pack and only the bundle is assembled per call.
PACKS = {
    "soc": (SOC_ACTIONS, soc_bundle, SOC_RULESET),
    "endpoint": (
        ("endpoint.isolate",),
        lambda t, e, i, **kw: endpoint_bundle(t, e, **kw),
        ENDPOINT_RULESET,
    ),
    "identity": (
        IDENTITY_ACTIONS,
        lambda t, e, i, **kw: identity_bundle(t, i, **kw),
        IDENTITY_RULESET,
    ),
}


@cache
def _compiled(pack):
    _, handwritten, ruleset = PACKS[pack]
    from uuid import uuid4

    base = handwritten(uuid4(), uuid4(), uuid4(), mapping_version="map-v1")
    return compile_ruleset(ruleset, base.mappings)


def compiled_factory(pack):
    _, handwritten, ruleset = PACKS[pack]

    def factory(tenant, endpoint_account, identity_account, *, mapping_version, bundle_id=None):
        base = handwritten(
            tenant,
            endpoint_account,
            identity_account,
            mapping_version=mapping_version,
            bundle_id=bundle_id,
        )
        c = _compiled(pack)
        return base.model_copy(
            update={
                "cedar_schema": c.cedar_schema,
                "authorization_policies": c.authorization_policies,
                "approval_policies": c.approval_policies,
                "limits": c.limits,
                "quorum": c.quorum,
                "ruleset": ruleset,
            }
        )

    return factory


def decision(result):
    # Obligation ids differ by construction: a hand-written approval with `||` is one Cedar
    # policy and one positional id, the ruleset is two rules and two ids. What must agree is
    # whether review is owed, not which identifier names it.
    return result.effect, result.reasons, bool(result.obligation_ids)


@pytest.mark.parametrize("pack", sorted(PACKS))
def test_the_pack_as_a_ruleset_decides_every_input_as_the_hand_written_pack_did(pack):
    actions, handwritten, _ = PACKS[pack]
    compiled = compiled_factory(pack)
    seen, total = set(), 0
    for action in actions:
        for case in inputs(action):
            before = evaluator.evaluate(**scenario(action, bundle=handwritten, **case))
            after = evaluator.evaluate(**scenario(action, bundle=compiled, **case))
            assert decision(before) == decision(after), (
                action,
                case,
                decision(before),
                decision(after),
            )
            seen.add(before.effect)
            total += 1
    # Not vacuous: every effect the kernel can reach was reached, and nothing was skipped.
    assert seen == {"ELIGIBLE", "DENY", "REQUIRE_APPROVAL"}, seen
    assert total == sum(
        len(classifications(a))
        * len(ENVIRONMENTS)
        * len(STATUSES)
        * len(SEVERITIES)
        * len(CRITICALITIES)
        * len(ARGUMENTS.get(a, ({},)))
        for a in actions
    )


@pytest.mark.parametrize(
    ("build", "ruleset"),
    [
        (lambda t, e, i: soc_ruleset_bundle(t, e, i, mapping_version="map-v1"), SOC_RULESET),
        (lambda t, e, i: endpoint_ruleset_bundle(t, e, mapping_version="map-v1"), ENDPOINT_RULESET),
        (lambda t, e, i: identity_ruleset_bundle(t, i, mapping_version="map-v1"), IDENTITY_RULESET),
    ],
    ids=["soc", "endpoint", "identity"],
)
def test_each_pack_bundle_is_what_its_ruleset_compiles_to(build, ruleset):
    """The store recompiles at validation and activation; a pack bundle must pass that check."""
    from uuid import uuid4

    bundle = build(uuid4(), uuid4(), uuid4())
    assert bundle.ruleset is ruleset
    again = ruleset_bundle(
        ruleset, tenant_id=bundle.tenant_id, bundle_id=bundle.bundle_id, mappings=bundle.mappings
    )
    assert again == bundle
    # The store compares the stored bundle's limits with the compiler's raw output, and
    # `BundleContent` sorts what it stores. Both sides of `again == bundle` are stored forms,
    # so only this comparison can show a compiler emitting budgets in another order.
    raw = compile_ruleset(ruleset, bundle.mappings)
    assert raw.limits == bundle.limits
    assert [rule.rule_id for rule in raw.limits] == sorted(rule.rule_id for rule in raw.limits)


# What a page prints for each effect the kernel can reach on the policy alone.
READING = {"ELIGIBLE": "allow", "DENY": "deny", "REQUIRE_APPROVAL": "require approval"}


def facts_of(case):
    """The case as the facts a page would hold: the contract's names, the contract's types."""
    name, value = case["classification"]
    return {
        name: value,
        "environment": case["environment"],
        "criticality": case["criticality"],
        "is_production": case["environment"] == "production",
        "incident_status": case["incident_status"],
        "incident_severity": case["incident_severity"],
    }


@pytest.mark.parametrize("pack", sorted(PACKS))
def test_the_rules_read_over_every_input_as_the_kernel_decides_it(pack):
    """The pages' reading of the rules says what the compiled bundle decides, on every input.

    `project` is what the welcome page and the Agents page print beside "as the rules read",
    and this is what licenses that label: over the whole input space the reading and the
    kernel's policy decision agree, a reading owing review names a review rule, and no
    reading is made with a fact missing. Limits, quorum and people are outside both.
    """
    actions, _, ruleset = PACKS[pack]
    compiled = compiled_factory(pack)
    reviews = {rule.id for rule in ruleset.rules if rule.effect == "REVIEW"}
    seen = set()
    for action in actions:
        for case in inputs(action):
            decided = evaluator.evaluate(**scenario(action, bundle=compiled, **case))
            reading = project(ruleset, action, facts_of(case), case["arguments"])
            assert reading.unknown == (), (action, case, reading)
            assert reading.effect == READING[decided.effect], (action, case, reading, decided)
            if reading.effect != "deny":
                assert reading.rules, (action, case)
            if reading.effect == "require approval":
                assert set(reading.rules) & reviews, (action, case, reading)
            seen.add(reading.effect)
    assert seen == set(READING.values()), seen
