# SPDX-License-Identifier: AGPL-3.0-only
"""Synthetic endpoint policy pack for the first protected mock path."""

from uuid import UUID, uuid4

from execbound.audit import canonical_json
from execbound.policy.models import (
    BundleContent,
    Condition,
    ConditionOperator,
    LimitRule,
    MappingRef,
    Rule,
    Ruleset,
)
from execbound.policy.rulesets import ruleset_bundle

CEDAR_SCHEMA = canonical_json(
    {
        "ExecBound": {
            "entityTypes": {
                "Agent": {
                    "shape": {"type": "Record", "attributes": {"tenant": {"type": "String"}}}
                },
                "Endpoint": {
                    "shape": {
                        "type": "Record",
                        "attributes": {
                            "tenant": {"type": "String"},
                            "account": {"type": "String"},
                            "role": {"type": "String"},
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
                "endpoint.isolate": {
                    "appliesTo": {
                        "principalTypes": ["Agent"],
                        "resourceTypes": ["Endpoint"],
                        "context": {"type": "Record", "attributes": {}},
                    }
                }
            },
        }
    }
)

AUTHORIZATION = """
permit(principal, action == ExecBound::Action::"endpoint.isolate", resource)
when {
    principal.tenant == resource.tenant && resource.role == "workstation" &&
    resource.incident_status == "OPEN" && resource.incident_severity == "CRITICAL"
};
forbid(principal, action == ExecBound::Action::"endpoint.isolate", resource)
when { resource.role == "domain_controller" || resource.criticality == 4 };
"""

APPROVAL = """
permit(principal, action == ExecBound::Action::"endpoint.isolate", resource)
when { resource.is_production };
"""


def endpoint_bundle(
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
        mappings=(
            MappingRef(
                operation_ref="endpoint.isolate",
                account_id=account_id,
                mapping_version=mapping_version,
                schema_version="action.v1",
                context_contract_version="endpoint-isolation.v1",
            ),
        ),
        limits=(
            LimitRule(
                rule_id="principal-autonomous-isolation",
                action="endpoint.isolate",
                scope="principal",
                window_seconds=3600,
                max_targets=10,
                budget="autonomous",
                on_exceed="REQUIRE_APPROVAL",
            ),
            LimitRule(
                rule_id="tenant-total-isolation",
                action="endpoint.isolate",
                scope="tenant",
                window_seconds=900,
                max_targets=20,
                budget="total",
                on_exceed="DENY",
            ),
        ),
    )


def fact(name: str, operator: ConditionOperator, *values: str | int | bool) -> Condition:
    """A condition on a fact of the action's contract; the packs' rules are written with these."""
    return Condition(kind="fact", name=name, operator=operator, values=values)


def argument(name: str, operator: ConditionOperator, *values: str | int | bool) -> Condition:
    return Condition(kind="argument", name=name, operator=operator, values=values)


# The endpoint pack as rules: what AUTHORIZATION and APPROVAL above say, one rule per clause.
# A forbid with an `||` is two forbids, which is what the hand-written policy means.
ISOLATE_RULES: tuple[Rule, ...] = (
    Rule(
        id="isolate-workstation-open-critical",
        action="endpoint.isolate",
        effect="ALLOW",
        when=(
            fact("role", "is", "workstation"),
            fact("incident_status", "is", "OPEN"),
            fact("incident_severity", "is", "CRITICAL"),
        ),
    ),
    Rule(
        id="isolate-never-domain-controller",
        action="endpoint.isolate",
        effect="DENY",
        when=(fact("role", "is", "domain_controller"),),
    ),
    Rule(
        id="isolate-never-criticality-4",
        action="endpoint.isolate",
        effect="DENY",
        when=(fact("criticality", "is", 4),),
    ),
    Rule(
        id="isolate-production-needs-review",
        action="endpoint.isolate",
        effect="REVIEW",
        when=(fact("is_production", "is", True),),
    ),
)
ENDPOINT_RULESET = Ruleset(
    rules=ISOLATE_RULES,
    budgets=(
        LimitRule(
            rule_id="principal-autonomous-isolation",
            action="endpoint.isolate",
            scope="principal",
            window_seconds=3600,
            max_targets=10,
            budget="autonomous",
            on_exceed="REQUIRE_APPROVAL",
        ),
        LimitRule(
            rule_id="tenant-total-isolation",
            action="endpoint.isolate",
            scope="tenant",
            window_seconds=900,
            max_targets=20,
            budget="total",
            on_exceed="DENY",
        ),
    ),
)


def endpoint_ruleset_bundle(
    tenant_id: UUID,
    account_id: UUID,
    *,
    mapping_version: str,
    bundle_id: UUID | None = None,
) -> BundleContent:
    """The pack as the compiler builds it from its ruleset, carrying the ruleset.

    ``endpoint_bundle`` is the same pack written by hand and stays the default fixtures derive
    variants from: a bundle whose components are then edited is a hand-written bundle by
    definition, and a ruleset bundle edited that way is exactly what validation refuses.
    ``tests/test_pack_rulesets.py`` proves the two decide every possible input alike.
    """
    base = endpoint_bundle(
        tenant_id, account_id, mapping_version=mapping_version, bundle_id=bundle_id
    )
    return ruleset_bundle(
        ENDPOINT_RULESET, tenant_id=tenant_id, bundle_id=base.bundle_id, mappings=base.mappings
    )
