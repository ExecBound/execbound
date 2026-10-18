# SPDX-License-Identifier: AGPL-3.0-only
"""All identity actions use the real Cedar engine and action-scoped impact."""

import json
from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest

from execbound.identity import Identity
from execbound.operations import PRODUCTION_ACTIONS
from execbound.policy.approval import VerifiedApproval
from execbound.policy.evaluate import evaluate
from execbound.policy.models import BundleContent, ProjectedUsage, UsageSnapshot
from execbound.requests import ActionRequest, Arguments, ClaimedContext, ResourceSelector
from execbound.resolution.models import CanonicalIntent, ResolvedRequest, TrustedFact, plan_hash
from execbound_harness.demo import endpoint_bundle
from execbound_harness.identity_demo import identity_bundle

ACTIONS = ("identity.disable", "identity.enable", "identity.revoke_sessions")


class FixedClock:
    def __init__(self, value):
        self.value = value

    def now(self):
        return self.value


def scenario(action="identity.disable", production=False):
    tenant, principal, account, target, inventory, incident = (uuid4() for _ in range(6))
    now = datetime.now(UTC)
    identity = Identity(tenant, principal, uuid4(), "AGENT", now + timedelta(hours=1))
    spec = PRODUCTION_ACTIONS.bound("mock_entra", action)
    bundle = identity_bundle(tenant, account, mapping_version="map-v1")
    facts = []
    for name, value in (
        ("privilege_class", "standard"),
        ("environment", "production" if production else "development"),
        ("criticality", 1),
        ("is_production", production),
        ("incident_status", "OPEN"),
        ("incident_severity", "CRITICAL"),
    ):
        is_incident = name.startswith("incident_")
        facts.append(
            TrustedFact(
                name=name,
                value=value,
                origin="DERIVED" if name == "is_production" else "RESOLVED",
                source_id=incident if is_incident else inventory,
                source_kind="incident" if is_incident else "inventory",
                source_object_id=str(incident) if is_incident else "identity-01",
                source_version="incident-v1" if is_incident else "resource-v1",
                permitted_writers=("soc_analyst",) if is_incident else ("inventory_sync",),
                observed_at=now - timedelta(seconds=60),
                valid_until=now + timedelta(seconds=240),
                dependencies=("environment",) if name == "is_production" else (),
            )
        )
    resolved = ResolvedRequest(
        request=ActionRequest(
            operation_ref=action,
            target=ResourceSelector(kind="canonical", value=str(target)),
            arguments=Arguments(),
            idempotency_key="identity-policy",
            claimed_context=ClaimedContext(
                incident_id=incident, role="domain_controller", severity="LOW", criticality=4
            ),
        ),
        intent=CanonicalIntent(
            tenant_id=tenant,
            principal_id=principal,
            account_id=account,
            target_id=target,
            arguments=Arguments(),
            provider=spec.provider,
            resource_type=spec.resource_type,
            action=spec.action,
            provider_operation=spec.provider_operation,
        ),
        context_contract_version=spec.context_contract_version,
        resource_provider_id="identity-01",
        resource_version="resource-v1",
        mapping_version="map-v1",
        facts=tuple(facts),
        resolved_at=now,
        valid_until=now + timedelta(seconds=240),
    )
    return dict(
        bundle=bundle,
        identity=identity,
        resolved=resolved,
        usage=usage_for(bundle, identity, resolved),
        clock=FixedClock(now),
    )


def usage_for(bundle, identity, resolved):
    return UsageSnapshot(
        tenant_id=identity.tenant_id,
        principal_id=identity.principal_id,
        bundle_id=bundle.bundle_id,
        account_id=resolved.intent.account_id,
        counts=tuple(
            ProjectedUsage(rule_id=r.rule_id, confirmed_targets=0, unresolved_targets=0)
            for r in bundle.limits
        ),
    )


def changed_fact(resolved, fact_name, **changes):
    return resolved.model_copy(
        update={
            "facts": tuple(
                f.model_copy(update=changes) if f.name == fact_name else f for f in resolved.facts
            )
        }
    )


def matching_approval(case, obligations):
    identity, bundle, resolved = (case[k] for k in ("identity", "bundle", "resolved"))
    return VerifiedApproval(
        uuid4(),
        identity.tenant_id,
        identity.principal_id,
        bundle.bundle_id,
        plan_hash(resolved, bundle.security_versions),
        obligations,
        resolved.valid_until,
    )


@pytest.mark.parametrize("action", ACTIONS)
@pytest.mark.parametrize("production", [False, True])
def test_each_action_uses_explicit_authorization_and_approval(action, production):
    case = scenario(action, production)
    result = evaluate(**case)
    expected = "REQUIRE_APPROVAL" if action == "identity.enable" or production else "ELIGIBLE"
    assert result.effect == expected, result.reasons
    if expected == "REQUIRE_APPROVAL":
        assert len(result.obligation_ids) == 1
        approved = evaluate(**case, approval=matching_approval(case, result.obligation_ids))
        assert approved.effect == "ELIGIBLE"


@pytest.mark.parametrize("action", ACTIONS)
@pytest.mark.parametrize(
    "field,value",
    [
        ("privilege_class", "privileged"),
        ("privilege_class", "tier0"),
        ("criticality", 4),
    ],
)
def test_hard_identity_exclusion_wins_over_broad_permit_and_approval(action, field, value):
    case = scenario(action, True)
    case["resolved"] = changed_fact(case["resolved"], field, value=value)
    case["bundle"] = case["bundle"].model_copy(
        update={
            "authorization_policies": case["bundle"].authorization_policies
            + "\npermit(principal, action, resource);",
            "approval_policies": "permit(principal, action, resource);",
        }
    )
    result = evaluate(**case, approval=matching_approval(case, ("policy:policy0",)))
    assert result.effect == "DENY" and "NOT_AUTHORIZED" in result.reasons


@pytest.mark.parametrize("action", ACTIONS)
@pytest.mark.parametrize(
    "changes",
    [
        {"value": "unknown"},
        {"value": True},
        {"permitted_writers": ("agent",)},
        {"source_kind": "incident"},
        {"source_version": "other"},
        {"origin": "DERIVED"},
        {"dependencies": ("role",)},
        {"source_object_id": "other"},
    ],
)
def test_privilege_evidence_is_required_fresh_and_independent(action, changes):
    case = scenario(action)
    case["resolved"] = changed_fact(case["resolved"], "privilege_class", **changes)
    result = evaluate(**case)
    assert result.effect == "DENY" and "INVALID_CONTEXT" in result.reasons


@pytest.mark.parametrize("action", ACTIONS)
@pytest.mark.parametrize("change", ["missing", "expired", "future", "wrong_incident", "role"])
def test_incomplete_or_stale_identity_evidence_denies(action, change):
    case = scenario(action)
    resolved = case["resolved"]
    if change == "missing":
        resolved = resolved.model_copy(
            update={"facts": tuple(f for f in resolved.facts if f.name != "privilege_class")}
        )
    elif change == "role":
        resolved = changed_fact(resolved, "privilege_class", name="role", value="workstation")
    elif change == "wrong_incident":
        resolved = resolved.model_copy(
            update={
                "request": resolved.request.model_copy(
                    update={"claimed_context": ClaimedContext(incident_id=uuid4())}
                )
            }
        )
    else:
        key = "valid_until" if change == "expired" else "observed_at"
        resolved = changed_fact(
            resolved,
            "privilege_class",
            **{key: case["clock"].now() + timedelta(seconds=0 if change == "expired" else 1)},
        )
    case["resolved"] = resolved
    result = evaluate(**case)
    assert result.effect == "DENY" and "INVALID_CONTEXT" in result.reasons


@pytest.mark.parametrize("action", ACTIONS)
@pytest.mark.parametrize(
    "field,value", [("incident_status", "CLOSED"), ("incident_severity", "HIGH")]
)
def test_each_action_needs_open_critical_incident(action, field, value):
    case = scenario(action)
    case["resolved"] = changed_fact(case["resolved"], field, value=value)
    assert evaluate(**case).effect == "DENY"


@pytest.mark.parametrize(
    "field,value",
    [
        ("provider", "mock_crowdstrike"),
        ("provider_operation", "enable"),
        ("resource_type", "endpoint"),
        ("action", "endpoint.isolate"),
    ],
)
def test_copied_cross_family_intent_cannot_authorize(field, value):
    case = scenario()
    case["resolved"] = case["resolved"].model_copy(
        update={"intent": case["resolved"].intent.model_copy(update={field: value})}
    )
    assert evaluate(**case).effect == "DENY"


@pytest.mark.parametrize("action", ACTIONS)
def test_only_current_action_limits_apply_but_all_counts_are_required(action):
    case = scenario(action)
    bundle = case["bundle"]
    counts = tuple(
        count.model_copy(update={"confirmed_targets": 1000})
        if next(r for r in bundle.limits if r.rule_id == count.rule_id).action != action
        else count
        for count in case["usage"].counts
    )
    case["usage"] = case["usage"].model_copy(update={"counts": counts})
    assert evaluate(**case).effect == (
        "REQUIRE_APPROVAL" if action == "identity.enable" else "ELIGIBLE"
    )
    for bad_counts in (
        counts[:-1],
        counts + counts[:1],
        tuple(
            c.model_copy(update={"confirmed_targets": True}) if c == counts[0] else c
            for c in counts
        ),
    ):
        assert (
            evaluate(
                **{**case, "usage": case["usage"].model_copy(update={"counts": bad_counts})}
            ).effect
            == "DENY"
        )


@pytest.mark.parametrize("action", ACTIONS)
def test_each_action_has_independent_hard_and_autonomous_limits(action):
    case = scenario(action)
    limits = [r for r in case["bundle"].limits if r.action == action]
    assert {r.scope for r in limits} == {"principal", "tenant"}
    for scope in ("principal", "tenant"):
        rule = next(r for r in limits if r.scope == scope)
        case["usage"] = usage_for(case["bundle"], case["identity"], case["resolved"])
        case["usage"] = case["usage"].model_copy(
            update={
                "counts": tuple(
                    c.model_copy(update={"confirmed_targets": rule.max_targets})
                    if c.rule_id == rule.rule_id
                    else c
                    for c in case["usage"].counts
                )
            }
        )
        result = evaluate(**case)
        assert result.effect == ("DENY" if scope == "tenant" else "REQUIRE_APPROVAL")


def test_invalid_nonmatching_rule_cannot_hide_in_complete_usage_snapshot():
    case = scenario()
    case["bundle"] = case["bundle"].model_copy(
        update={
            "limits": tuple(
                rule.model_copy(update={"action": "identity.unknown"})
                if rule.action == "identity.enable"
                else rule
                for rule in case["bundle"].limits
            )
        }
    )
    result = evaluate(**case)
    assert result.effect == "DENY" and "INVALID_USAGE" in result.reasons


@pytest.mark.parametrize("action", ACTIONS)
def test_mixed_endpoint_and_identity_bundle_evaluates_each_family(action):
    case = scenario(action)
    identity_pack = case["bundle"]
    endpoint_pack = endpoint_bundle(case["identity"].tenant_id, uuid4(), mapping_version="map-v1")
    identity_schema = json.loads(identity_pack.cedar_schema)["ExecBound"]
    endpoint_schema = json.loads(endpoint_pack.cedar_schema)["ExecBound"]
    schema = {
        "ExecBound": {
            key: {**endpoint_schema[key], **identity_schema[key]}
            for key in ("entityTypes", "actions")
        }
    }
    mixed = BundleContent(
        tenant_id=identity_pack.tenant_id,
        bundle_id=identity_pack.bundle_id,
        cedar_schema=json.dumps(schema),
        authorization_policies=endpoint_pack.authorization_policies
        + identity_pack.authorization_policies,
        approval_policies=endpoint_pack.approval_policies + identity_pack.approval_policies,
        mappings=endpoint_pack.mappings + identity_pack.mappings,
        limits=endpoint_pack.limits + identity_pack.limits,
    )
    case.update(bundle=mixed, usage=usage_for(mixed, case["identity"], case["resolved"]))
    assert evaluate(**case).effect == (
        "REQUIRE_APPROVAL" if action == "identity.enable" else "ELIGIBLE"
    )
    from test_policy_evaluation import scenario as endpoint_scenario

    endpoint_case = endpoint_scenario.__wrapped__()
    endpoint_resolved = endpoint_case["resolved"]
    endpoint_identity = endpoint_case["identity"]
    endpoint_pack = endpoint_bundle(
        endpoint_identity.tenant_id, endpoint_resolved.intent.account_id, mapping_version="map-v1"
    )
    endpoint_mixed = mixed.model_copy(
        update={
            "tenant_id": endpoint_identity.tenant_id,
            "mappings": endpoint_pack.mappings + identity_pack.mappings,
        }
    )
    endpoint_case.update(
        bundle=endpoint_mixed,
        usage=usage_for(endpoint_mixed, endpoint_identity, endpoint_resolved),
    )
    assert evaluate(**endpoint_case).effect == "ELIGIBLE"
