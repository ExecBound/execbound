# SPDX-License-Identifier: AGPL-3.0-only
"""Synthetic identity policies for three explicitly scoped protected mock actions."""

from uuid import UUID, uuid4

from execbound.audit import canonical_json
from execbound.operations import ActionName
from execbound.policy.models import (
    BundleContent,
    LimitRule,
    MappingRef,
    Rule,
    Ruleset,
)
from execbound.policy.rulesets import ruleset_bundle
from execbound_harness.demo import fact

IDENTITY_ACTIONS: tuple[ActionName, ...] = (
    "identity.disable",
    "identity.enable",
    "identity.revoke_sessions",
)

CEDAR_SCHEMA = canonical_json(
    {
        "ExecBound": {
            "entityTypes": {
                "Agent": {
                    "shape": {"type": "Record", "attributes": {"tenant": {"type": "String"}}}
                },
                "Identity": {
                    "shape": {
                        "type": "Record",
                        "attributes": {
                            "tenant": {"type": "String"},
                            "account": {"type": "String"},
                            "privilege_class": {"type": "String"},
                            "environment": {"type": "String"},
                            "criticality": {"type": "Long"},
                            "incident_status": {"type": "String"},
                            "incident_severity": {"type": "String"},
                            "is_production": {"type": "Boolean"},
                        },
                    }
                },
            },
            "actions": {
                action: {
                    "appliesTo": {
                        "principalTypes": ["Agent"],
                        "resourceTypes": ["Identity"],
                        "context": {"type": "Record", "attributes": {}},
                    }
                }
                for action in IDENTITY_ACTIONS
            },
        },
    }
)

AUTHORIZATION = "\n".join(
    f'''
permit(principal, action == ExecBound::Action::"{action}", resource)
when {{
    principal.tenant == resource.tenant && resource.privilege_class == "standard" &&
    resource.incident_status == "OPEN" && resource.incident_severity == "CRITICAL"
}};
forbid(principal, action == ExecBound::Action::"{action}", resource)
when {{ resource.privilege_class == "privileged" || resource.privilege_class == "tier0" ||
        resource.criticality == 4 }};
'''
    for action in IDENTITY_ACTIONS
)

APPROVAL = """
permit(principal, action == ExecBound::Action::"identity.enable", resource);
permit(principal, action == ExecBound::Action::"identity.disable", resource)
when { resource.is_production };
permit(principal, action == ExecBound::Action::"identity.revoke_sessions", resource)
when { resource.is_production };
"""


def identity_bundle(
    tenant_id: UUID,
    account_id: UUID,
    *,
    mapping_version: str,
    bundle_id: UUID | None = None,
) -> BundleContent:
    return BundleContent(
        tenant_id=tenant_id,
        bundle_id=bundle_id or uuid4(),
        cedar_schema=CEDAR_SCHEMA,
        authorization_policies=AUTHORIZATION,
        approval_policies=APPROVAL,
        mappings=tuple(
            MappingRef(
                operation_ref=action,
                account_id=account_id,
                mapping_version=mapping_version,
                schema_version="action.v1",
                context_contract_version="identity-control.v1",
            )
            for action in IDENTITY_ACTIONS
        ),
        limits=tuple(
            rule
            for action in IDENTITY_ACTIONS
            for rule in (
                LimitRule(
                    rule_id=f"principal-autonomous-{action.replace('.', '-')}",
                    action=action,
                    scope="principal",
                    window_seconds=3600,
                    max_targets=10,
                    budget="autonomous",
                    on_exceed="REQUIRE_APPROVAL",
                ),
                LimitRule(
                    rule_id=f"tenant-total-{action.replace('.', '-')}",
                    action=action,
                    scope="tenant",
                    window_seconds=900,
                    max_targets=20,
                    budget="total",
                    on_exceed="DENY",
                ),
            )
        ),
    )


def identity_control_rules(
    action: str, *, severities: tuple[str, ...], reviews: tuple[Rule, ...]
) -> tuple[Rule, ...]:
    """One identity action as rules: permit a standard identity on an open incident of the
    named severities; forbid a privileged or tier-0 identity, or criticality 4, outright."""
    slug = action.split(".")[1].replace("_", "-")
    return (
        Rule(
            id=f"{slug}-standard-open-severe",
            action=action,
            effect="ALLOW",
            when=(
                fact("privilege_class", "is", "standard"),
                fact("incident_status", "is", "OPEN"),
                fact("incident_severity", "in", *severities),
            ),
        ),
        Rule(
            id=f"{slug}-never-privileged",
            action=action,
            effect="DENY",
            when=(fact("privilege_class", "in", "privileged", "tier0"),),
        ),
        Rule(
            id=f"{slug}-never-criticality-4",
            action=action,
            effect="DENY",
            when=(fact("criticality", "is", 4),),
        ),
        *reviews,
    )


def production_review(action: str) -> Rule:
    slug = action.split(".")[1].replace("_", "-")
    return Rule(
        id=f"{slug}-production-needs-review",
        action=action,
        effect="REVIEW",
        when=(fact("is_production", "is", True),),
    )


def identity_budgets(actions: tuple[str, ...]) -> tuple[LimitRule, ...]:
    rules: list[LimitRule] = []
    for action in actions:
        slug = action.replace(".", "-")
        rules.append(
            LimitRule(
                rule_id=f"principal-autonomous-{slug}",
                action=action,
                scope="principal",
                window_seconds=3600,
                max_targets=10,
                budget="autonomous",
                on_exceed="REQUIRE_APPROVAL",
            )
        )
        rules.append(
            LimitRule(
                rule_id=f"tenant-total-{slug}",
                action=action,
                scope="tenant",
                window_seconds=900,
                max_targets=20,
                budget="total",
                on_exceed="DENY",
            )
        )
    return tuple(rules)


IDENTITY_CONTROL_RULES: tuple[Rule, ...] = (
    *identity_control_rules(
        "identity.disable",
        severities=("CRITICAL",),
        reviews=(production_review("identity.disable"),),
    ),
    # Enabling an identity always needs a person, whatever the environment.
    *identity_control_rules(
        "identity.enable",
        severities=("CRITICAL",),
        reviews=(Rule(id="enable-always-needs-review", action="identity.enable", effect="REVIEW"),),
    ),
    *identity_control_rules(
        "identity.revoke_sessions",
        severities=("CRITICAL",),
        reviews=(production_review("identity.revoke_sessions"),),
    ),
)
IDENTITY_RULESET = Ruleset(rules=IDENTITY_CONTROL_RULES, budgets=identity_budgets(IDENTITY_ACTIONS))


def identity_ruleset_bundle(
    tenant_id: UUID,
    account_id: UUID,
    *,
    mapping_version: str,
    bundle_id: UUID | None = None,
) -> BundleContent:
    """The pack as the compiler builds it from its ruleset, carrying the ruleset.

    ``identity_bundle`` is the same pack written by hand and stays the default fixtures derive
    variants from: a bundle whose components are then edited is a hand-written bundle by
    definition, and a ruleset bundle edited that way is exactly what validation refuses.
    ``tests/test_pack_rulesets.py`` proves the two decide every possible input alike.
    """
    base = identity_bundle(
        tenant_id, account_id, mapping_version=mapping_version, bundle_id=bundle_id
    )
    return ruleset_bundle(
        IDENTITY_RULESET, tenant_id=tenant_id, bundle_id=base.bundle_id, mappings=base.mappings
    )
