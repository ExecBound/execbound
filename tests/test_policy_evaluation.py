# SPDX-License-Identifier: AGPL-3.0-only
from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest
from soc_fixtures import TEST_CATALOG, lift_scenario, probe_scenario, reset_scenario

from execbound.identity import Identity
from execbound.policy import evaluate as evaluator
from execbound.policy.models import LimitRule, ProjectedUsage, UsageSnapshot
from execbound.requests import ActionRequest, Arguments, ClaimedContext, ResourceSelector
from execbound.resolution.models import CanonicalIntent, ResolvedRequest, TrustedFact
from execbound_harness.demo import endpoint_bundle


class Clock:
    def __init__(self, now):
        self.value = now

    def now(self):
        return self.value


@pytest.fixture
def scenario():
    tenant, principal, account, target, source, incident = (uuid4() for _ in range(6))
    now = datetime.now(UTC)
    identity = Identity(tenant, principal, uuid4(), "AGENT", now + timedelta(hours=1))
    facts = []
    for name, value in (
        ("role", "workstation"),
        ("environment", "development"),
        ("criticality", 1),
        ("is_production", False),
        ("incident_status", "OPEN"),
        ("incident_severity", "CRITICAL"),
    ):
        is_incident = name.startswith("incident_")
        facts.append(
            TrustedFact(
                name=name,
                value=value,
                origin="DERIVED" if name == "is_production" else "RESOLVED",
                source_id=incident if is_incident else source,
                source_kind="incident" if is_incident else "inventory",
                source_object_id=str(incident) if is_incident else "device-01",
                source_version="incident-v1" if is_incident else "resource-v1",
                permitted_writers=("soc_analyst",) if is_incident else ("inventory_sync",),
                observed_at=now - timedelta(seconds=60),
                valid_until=now + timedelta(seconds=240),
                dependencies=("environment",) if name == "is_production" else (),
            )
        )
    resolved = ResolvedRequest(
        request=ActionRequest(
            operation_ref="endpoint.isolate",
            target=ResourceSelector(kind="canonical", value=str(target)),
            arguments=Arguments(),
            idempotency_key="example",
            claimed_context=ClaimedContext(criticality=4, severity="LOW", role="domain_controller"),
        ),
        intent=CanonicalIntent(
            tenant_id=tenant,
            principal_id=principal,
            account_id=account,
            target_id=target,
            arguments=Arguments(),
        ),
        resource_provider_id="device-01",
        resource_version="resource-v1",
        mapping_version="map-v1",
        facts=tuple(facts),
        resolved_at=now,
        valid_until=now + timedelta(seconds=240),
    )
    bundle = endpoint_bundle(tenant, account, mapping_version="map-v1")
    usage = UsageSnapshot(
        tenant_id=tenant,
        principal_id=principal,
        bundle_id=bundle.bundle_id,
        account_id=account,
        counts=tuple(
            ProjectedUsage(rule_id=rule.rule_id, confirmed_targets=0, unresolved_targets=0)
            for rule in bundle.limits
        ),
    )
    return {
        "bundle": bundle,
        "identity": identity,
        "resolved": resolved,
        "usage": usage,
        "clock": Clock(now),
    }


def change_fact(resolved, name, **changes):
    return resolved.model_copy(
        update={
            "facts": tuple(
                f.model_copy(update=changes) if f.name == name else f for f in resolved.facts
            )
        }
    )


def evaluate(scenario, **changes):
    return evaluator.evaluate(**{**scenario, **changes})


def limit(**changes):
    """A small-ceiling isolation rule; scoped tests override the scope and its qualifier."""
    values = {
        "rule_id": "scoped",
        "action": "endpoint.isolate",
        "scope": "principal",
        "window_seconds": 3600,
        "max_targets": 3,
        "budget": "total",
        "on_exceed": "REQUIRE_APPROVAL",
    }
    return LimitRule(**{**values, **changes})


def scoped(case, *rules, groups=()):
    """The case's bundle with only ``rules``, each already at its ceiling, and memberships."""
    base = case["usage"]
    usage = UsageSnapshot(
        tenant_id=base.tenant_id,
        principal_id=base.principal_id,
        bundle_id=base.bundle_id,
        account_id=base.account_id,
        groups=groups,
        counts=tuple(
            ProjectedUsage(
                rule_id=rule.rule_id, confirmed_targets=rule.max_targets, unresolved_targets=0
            )
            for rule in rules
        ),
    )
    return {"bundle": case["bundle"].model_copy(update={"limits": rules}), "usage": usage}


def test_eligible_requires_valid_authorization_and_ignores_claims(scenario):
    result = evaluate(scenario)
    assert result.effect == "ELIGIBLE" and result.obligation_ids == ()
    assert len(result.plan_hash) == 64


def test_production_requires_actual_matching_approval(scenario):
    resolved = change_fact(scenario["resolved"], "environment", value="production")
    resolved = change_fact(resolved, "is_production", value=True)
    result = evaluate(scenario, resolved=resolved)
    assert result.effect == "REQUIRE_APPROVAL"
    assert result.obligation_ids == ("policy:policy0",)


@pytest.mark.parametrize(
    "name,value",
    [
        ("role", "domain_controller"),
        ("criticality", 4),
        ("incident_status", "CLOSED"),
        ("incident_severity", "LOW"),
    ],
)
def test_demo_hard_exclusions_and_missing_authorization_deny(scenario, name, value):
    result = evaluate(scenario, resolved=change_fact(scenario["resolved"], name, value=value))
    assert result.effect == "DENY" and result.obligation_ids == ()


@pytest.mark.parametrize(
    "confirmed,outstanding,effect",
    [(9, 0, "ELIGIBLE"), (10, 0, "REQUIRE_APPROVAL"), (8, 2, "REQUIRE_APPROVAL")],
)
def test_soft_limit_counts_reserved_and_proposed_target(scenario, confirmed, outstanding, effect):
    usage = scenario["usage"].model_copy(
        update={
            "counts": tuple(
                c.model_copy(
                    update={"confirmed_targets": confirmed, "unresolved_targets": outstanding}
                )
                if c.rule_id.startswith("principal")
                else c
                for c in scenario["usage"].counts
            )
        }
    )
    result = evaluate(scenario, usage=usage)
    assert result.effect == effect


@pytest.mark.parametrize("reverse", [False, True])
def test_hard_limit_wins_over_policy_and_soft_approvals(scenario, reverse):
    bundle = scenario["bundle"]
    if reverse:
        bundle = bundle.model_copy(update={"limits": tuple(reversed(bundle.limits))})
    usage = scenario["usage"].model_copy(
        update={
            "counts": tuple(
                c.model_copy(update={"confirmed_targets": 20}) for c in scenario["usage"].counts
            )
        }
    )
    resolved = change_fact(
        change_fact(scenario["resolved"], "environment", value="production"),
        "is_production",
        value=True,
    )
    result = evaluate(scenario, bundle=bundle, usage=usage, resolved=resolved)
    assert result.effect == "DENY" and result.obligation_ids == ()
    assert "HARD_LIMIT:tenant-total-isolation" in result.reasons


@pytest.mark.parametrize("field", ["tenant_id", "principal_id", "bundle_id"])
def test_usage_must_match_identity_and_bundle(scenario, field):
    result = evaluate(scenario, usage=scenario["usage"].model_copy(update={field: uuid4()}))
    assert result.effect == "DENY" and "INVALID_USAGE" in result.reasons


def test_usage_must_cover_every_rule(scenario):
    result = evaluate(
        scenario,
        usage=scenario["usage"].model_copy(update={"counts": scenario["usage"].counts[:1]}),
    )
    assert result.effect == "DENY"


@pytest.mark.parametrize(
    "change",
    [
        {"value": True},
        {"value": "4"},
        {"value": 5},
        {"permitted_writers": ("agent",)},
        {"source_version": "other"},
        {"source_kind": "incident"},
        {"source_object_id": "other"},
        {"origin": "DERIVED"},
    ],
)
def test_invalid_inventory_facts_fail_closed(scenario, change):
    result = evaluate(scenario, resolved=change_fact(scenario["resolved"], "criticality", **change))
    assert result.effect == "DENY" and "INVALID_CONTEXT" in result.reasons


def test_derived_fact_must_match_its_source(scenario):
    assert (
        evaluate(
            scenario, resolved=change_fact(scenario["resolved"], "is_production", value=True)
        ).effect
        == "DENY"
    )


def test_duplicate_or_missing_facts_deny(scenario):
    facts = scenario["resolved"].facts
    for changed in (facts[:-1], facts + facts[:1]):
        assert (
            evaluate(
                scenario, resolved=scenario["resolved"].model_copy(update={"facts": changed})
            ).effect
            == "DENY"
        )


@pytest.mark.parametrize(
    "field,value",
    [("mapping_version", "new-map"), ("valid_until", datetime(2000, 1, 1, tzinfo=UTC))],
)
def test_stale_mapping_or_evidence_deny(scenario, field, value):
    assert (
        evaluate(scenario, resolved=scenario["resolved"].model_copy(update={field: value})).effect
        == "DENY"
    )


def test_a_bundle_mapping_naming_another_action_than_the_plan_denies(scenario):
    """The frozen plan's action is its mapping row's; a bundle naming another one for the
    ref cannot authorize it, however it came to be loaded."""
    mapping = scenario["bundle"].mappings[0]
    elsewhere = mapping.model_copy(update={"action": "endpoint.lift_isolation"})
    bundle = scenario["bundle"].model_copy(update={"mappings": (elsewhere,)})
    denied = evaluate(scenario, bundle=bundle)
    assert (denied.effect, denied.reasons) == ("DENY", ("INVALID_BUNDLE",))
    assert evaluate(scenario).effect == "ELIGIBLE"


def test_policy_errors_cannot_be_waived_by_matching_approval(scenario):
    bundle = scenario["bundle"].model_copy(
        update={
            "authorization_policies": (
                "permit(principal, action, resource); forbid(principal, action, resource) "
                "when { 9223372036854775807 + 1 > 0 };"
            ),
            "approval_policies": "permit(principal, action, resource);",
        }
    )
    result = evaluate(scenario, bundle=bundle)
    assert result.effect == "DENY" and result.obligation_ids == ()


def test_approval_evaluation_error_also_denies(scenario):
    bundle = scenario["bundle"].model_copy(
        update={
            "approval_policies": (
                "permit(principal, action, resource) when { 9223372036854775807 + 1 > 0 };"
            )
        }
    )
    assert evaluate(scenario, bundle=bundle).effect == "DENY"


def test_expiry_during_policy_evaluation_denies(scenario, monkeypatch):
    original = evaluator.evaluate_policy_sets

    def slow(**kwargs):
        result = original(**kwargs)
        scenario["clock"].value += timedelta(seconds=241)
        return result

    monkeypatch.setattr(evaluator, "evaluate_policy_sets", slow)
    assert evaluate(scenario).effect == "DENY"


def test_identity_scope_and_role_cannot_be_replaced(scenario):
    identity = scenario["identity"]
    for changed in (
        Identity(
            uuid4(), identity.principal_id, identity.credential_id, "AGENT", identity.expires_at
        ),
        Identity(
            identity.tenant_id,
            identity.principal_id,
            identity.credential_id,
            "ADMIN",
            identity.expires_at,
        ),
    ):
        assert evaluate(scenario, identity=changed).effect == "DENY"


def test_no_approval_boolean_can_bypass_obligations(scenario):
    with pytest.raises(TypeError):
        evaluator.evaluate(**scenario, approved=True)


@pytest.mark.parametrize("budget", ["autonomous", "total"])
@pytest.mark.parametrize("on_exceed", ["DENY", "REQUIRE_APPROVAL"])
def test_each_budget_uses_its_declared_exceed_effect(scenario, budget, on_exceed):
    rule = (
        scenario["bundle"].limits[0].model_copy(update={"budget": budget, "on_exceed": on_exceed})
    )
    bundle = scenario["bundle"].model_copy(update={"limits": (rule,)})
    usage = scenario["usage"].model_copy(
        update={
            "counts": (
                ProjectedUsage(
                    rule_id=rule.rule_id, confirmed_targets=rule.max_targets, unresolved_targets=0
                ),
            )
        }
    )
    result = evaluate(scenario, bundle=bundle, usage=usage)
    assert result.effect == ("DENY" if on_exceed == "DENY" else "REQUIRE_APPROVAL")


def test_caller_claim_changes_cannot_change_cedar_entities(scenario, monkeypatch):
    captured = []
    original = evaluator.evaluate_policy_sets

    def observe(**kwargs):
        captured.append((kwargs["request"], kwargs["entities"]))
        return original(**kwargs)

    monkeypatch.setattr(evaluator, "evaluate_policy_sets", observe)
    first = evaluate(scenario)
    resolved = scenario["resolved"].model_copy(
        update={
            "request": scenario["resolved"].request.model_copy(
                update={"claimed_context": ClaimedContext(severity="CRITICAL", criticality=0)}
            )
        }
    )
    second = evaluate(scenario, resolved=resolved)
    assert captured[0] == captured[1]
    assert first == second


def test_empty_approval_set_does_not_create_an_obligation(scenario):
    bundle = scenario["bundle"].model_copy(update={"approval_policies": ""})
    resolved = change_fact(
        change_fact(scenario["resolved"], "environment", value="production"),
        "is_production",
        value=True,
    )
    assert evaluate(scenario, bundle=bundle, resolved=resolved).effect == "ELIGIBLE"


@pytest.mark.parametrize(
    "case,effect",
    [
        (lift_scenario(), "ELIGIBLE"),
        (lift_scenario(incident_status="OPEN"), "ELIGIBLE"),
        (lift_scenario(reason="remediated"), "REQUIRE_APPROVAL"),
        (lift_scenario(reason="remediated", incident_status="OPEN"), "DENY"),
        (lift_scenario(environment="production"), "REQUIRE_APPROVAL"),
        (reset_scenario(), "ELIGIBLE"),
        (reset_scenario(require_change=False), "REQUIRE_APPROVAL"),
        (reset_scenario(privilege_class="privileged"), "DENY"),
        (reset_scenario(severity="LOW"), "DENY"),
        (reset_scenario(environment="production"), "REQUIRE_APPROVAL"),
    ],
    ids=[
        "lift false positive closed",
        "lift false positive open",
        "lift remediated needs approval",
        "lift remediated open denied",
        "lift production needs approval",
        "reset standard high",
        "reset without forced change needs approval",
        "reset privileged denied",
        "reset low severity denied",
        "reset production needs approval",
    ],
)
def test_soc_pack_reads_arguments_from_the_cedar_context(case, effect):
    result = evaluator.evaluate(**case)
    assert result.effect == effect, result.reasons
    if effect == "DENY":
        assert result.reasons == ("NOT_AUTHORIZED",)
    if effect == "REQUIRE_APPROVAL":
        # An argument-driven approval policy, not an incidental limit obligation.
        assert result.reasons == ("APPROVAL_REQUIRED",)
        assert result.obligation_ids
        assert all(obligation.startswith("policy:") for obligation in result.obligation_ids)
        assert not any(obligation.startswith("limit:") for obligation in result.obligation_ids)


@pytest.mark.parametrize(
    "arguments", [{}, {"reason": "other"}, {"reason": "remediated", "extra": 1}, {"reason": 1}]
)
def test_frozen_arguments_outside_the_spec_deny_with_invalid_arguments(arguments):
    case = lift_scenario()
    intent = case["resolved"].intent.model_copy(update={"arguments": Arguments(arguments)})
    case["resolved"] = case["resolved"].model_copy(update={"intent": intent})
    result = evaluator.evaluate(**case)
    assert result.effect == "DENY" and result.reasons == ("INVALID_ARGUMENTS",)


@pytest.mark.parametrize(
    "depth,effect,reasons",
    [(3, "ELIGIBLE", ()), (2, "DENY", ("NOT_AUTHORIZED",)), (6, "DENY", ("INVALID_ARGUMENTS",))],
    ids=["depth meets the threshold", "depth below the threshold", "depth outside the domain"],
)
def test_injected_catalog_action_reaches_cedar_with_its_long_argument(depth, effect, reasons):
    # The synthetic action exists only in the test catalog, so a Long argument decides
    # authorization here without the production catalog declaring one.
    result = evaluator.evaluate(**probe_scenario(depth=depth), catalog=TEST_CATALOG)
    assert result.effect == effect and result.reasons == reasons
    assert result.obligation_ids == ()


def test_mismatched_frozen_operation_tuple_denies_as_invalid_context():
    case = lift_scenario()
    intent = case["resolved"].intent.model_copy(update={"provider": "mock_entra"})
    case["resolved"] = case["resolved"].model_copy(update={"intent": intent})
    result = evaluator.evaluate(**case)
    assert result.effect == "DENY" and result.reasons == ("INVALID_CONTEXT",)


@pytest.mark.parametrize("on_exceed", ["REQUIRE_APPROVAL", "DENY"])
def test_group_rule_applies_only_to_members(scenario, on_exceed):
    group = uuid4()
    rule = limit(rule_id="triage-isolation", scope="group", group_id=group, on_exceed=on_exceed)
    member = evaluate(scenario, **scoped(scenario, rule, groups=(uuid4(), group)))
    if on_exceed == "DENY":
        assert member.effect == "DENY" and member.reasons == ("HARD_LIMIT:triage-isolation",)
    else:
        assert member.effect == "REQUIRE_APPROVAL"
        assert member.obligation_ids == ("limit:triage-isolation",)
    for groups in ((), (uuid4(),)):
        outsider = evaluate(scenario, **scoped(scenario, rule, groups=groups))
        assert outsider.effect == "ELIGIBLE" and outsider.obligation_ids == ()


def test_usage_groups_must_be_identifiers(scenario):
    snapshot = scenario["usage"].model_copy(update={"groups": ("not-a-group",)})
    result = evaluate(scenario, usage=snapshot)
    assert result.effect == "DENY" and result.reasons == ("INVALID_USAGE",)


def test_account_rule_applies_only_to_the_frozen_account(scenario):
    account = scenario["resolved"].intent.account_id
    own = limit(rule_id="own-account", scope="account", account_id=account)
    other = limit(rule_id="other-account", scope="account", account_id=uuid4())
    result = evaluate(scenario, **scoped(scenario, own, other))
    assert result.effect == "REQUIRE_APPROVAL" and result.obligation_ids == ("limit:own-account",)
    result = evaluate(scenario, **scoped(scenario, other))
    assert result.effect == "ELIGIBLE" and result.obligation_ids == ()


def test_selector_rule_reads_frozen_facts_exactly(scenario):
    production = limit(
        rule_id="production-isolation",
        scope="selector",
        selector={"fact": "environment", "equals": "production"},
    )
    exact = limit(
        rule_id="criticality-one",
        scope="selector",
        selector={"fact": "criticality", "equals": 1},
    )
    coerced = limit(
        rule_id="criticality-true",
        scope="selector",
        selector={"fact": "criticality", "equals": True},
    )
    case = scoped(scenario, production, exact, coerced)
    # A development plan with criticality 1: only the exact Long selector matches; the
    # boolean True is not the Long 1, and the environment is not production.
    result = evaluate(scenario, **case)
    assert result.effect == "REQUIRE_APPROVAL"
    assert result.obligation_ids == ("limit:criticality-one",)
    resolved = change_fact(
        change_fact(scenario["resolved"], "environment", value="production"),
        "is_production",
        value=True,
    )
    result = evaluate(scenario, **case, resolved=resolved)
    assert result.effect == "REQUIRE_APPROVAL"
    assert result.obligation_ids == (
        "limit:criticality-one",
        "limit:production-isolation",
        "policy:policy0",
    )
    result = evaluate(scenario, **scoped(scenario, production, coerced))
    assert result.effect == "ELIGIBLE" and result.obligation_ids == ()


def test_multi_action_budget_charges_every_listed_action(scenario):
    pair = limit(rule_id="isolation-pair", actions=("endpoint.isolate", "endpoint.lift_isolation"))
    lift = lift_scenario()
    # An isolation under the demo pack and a lift under the SOC pack draw on the one rule.
    for case in (scenario, lift):
        result = evaluate(case, **scoped(case, pair))
        assert result.effect == "REQUIRE_APPROVAL", result.reasons
        assert result.obligation_ids == ("limit:isolation-pair",)
    isolate_only = limit(rule_id="isolation-only")
    result = evaluate(lift, **scoped(lift, isolate_only))
    assert result.effect == "ELIGIBLE" and result.obligation_ids == ()


def test_usage_account_must_match_the_frozen_intent(scenario):
    usage = scenario["usage"].model_copy(update={"account_id": uuid4()})
    result = evaluate(scenario, usage=usage)
    assert result.effect == "DENY" and result.reasons == ("INVALID_USAGE",)


def test_scoped_rule_with_unknown_action_in_its_list_is_invalid_usage(scenario):
    # Validation precedes applicability: the candidate is not even a member of the
    # group, and the bundle defect still denies before any rule is applied.
    rule = limit(
        rule_id="unknown-listed",
        scope="group",
        group_id=uuid4(),
        actions=("endpoint.isolate", "endpoint.vanish"),
    )
    result = evaluate(scenario, **scoped(scenario, rule))
    assert result.effect == "DENY" and result.reasons == ("INVALID_USAGE",)
