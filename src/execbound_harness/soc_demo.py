# SPDX-License-Identifier: AGPL-3.0-only
"""Synthetic SOC policy pack covering every production action on both mocks."""

from uuid import UUID, uuid4

from execbound.audit import canonical_json
from execbound.operations import PRODUCTION_ACTIONS, ActionName
from execbound.policy.models import (
    BundleContent,
    LimitRule,
    MappingRef,
    Rule,
    Ruleset,
)
from execbound.policy.rulesets import ruleset_bundle
from execbound_harness.demo import ISOLATE_RULES, argument, fact
from execbound_harness.identity_demo import (
    IDENTITY_CONTROL_RULES,
    identity_budgets,
    identity_control_rules,
    production_review,
)

SOC_ACTIONS: tuple[ActionName, ...] = (
    "endpoint.isolate",
    "endpoint.lift_isolation",
    "identity.disable",
    "identity.enable",
    "identity.revoke_sessions",
    "identity.reset_password",
)
_IDENTITY_CONTROL = ("identity.disable", "identity.enable", "identity.revoke_sessions")
_ENTITY_NAME = {"endpoint": "Endpoint", "identity": "Identity"}


def _entity(classification: str) -> dict[str, object]:
    return {
        "shape": {
            "type": "Record",
            "attributes": {
                "tenant": {"type": "String"},
                "account": {"type": "String"},
                classification: {"type": "String"},
                "environment": {"type": "String"},
                "criticality": {"type": "Long"},
                "incident_status": {"type": "String"},
                "incident_severity": {"type": "String"},
                "is_production": {"type": "Boolean"},
            },
        }
    }


def _context(action: str) -> dict[str, object]:
    spec = PRODUCTION_ACTIONS.action(action)
    if not spec.arguments:
        return {"type": "Record", "attributes": {}}
    return {
        "type": "Record",
        "attributes": {
            "arguments": {
                "type": "Record",
                "attributes": {
                    argument.name: {"type": argument.cedar_type} for argument in spec.arguments
                },
            }
        },
    }


def _applies_to(action: str) -> dict[str, object]:
    resource_type = PRODUCTION_ACTIONS.action(action).resource_type
    return {
        "appliesTo": {
            "principalTypes": ["Agent"],
            "resourceTypes": [_ENTITY_NAME[resource_type]],
            "context": _context(action),
        }
    }


CEDAR_SCHEMA = canonical_json(
    {
        "ExecBound": {
            "entityTypes": {
                "Agent": {
                    "shape": {"type": "Record", "attributes": {"tenant": {"type": "String"}}}
                },
                "Endpoint": _entity("role"),
                "Identity": _entity("privilege_class"),
            },
            "actions": {action: _applies_to(action) for action in SOC_ACTIONS},
        }
    }
)

AUTHORIZATION = (
    """
permit(principal, action == ExecBound::Action::"endpoint.isolate", resource)
when {
    principal.tenant == resource.tenant && resource.role == "workstation" &&
    resource.incident_status == "OPEN" && resource.incident_severity == "CRITICAL"
};
forbid(principal, action == ExecBound::Action::"endpoint.isolate", resource)
when { resource.role == "domain_controller" || resource.criticality == 4 };
permit(principal, action == ExecBound::Action::"endpoint.lift_isolation", resource)
when {
    principal.tenant == resource.tenant &&
    (resource.incident_status == "CLOSED" || context.arguments.reason == "false_positive")
};
"""
    + "\n".join(
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
        for action in _IDENTITY_CONTROL
    )
    + """
permit(principal, action == ExecBound::Action::"identity.reset_password", resource)
when {
    principal.tenant == resource.tenant && resource.privilege_class == "standard" &&
    resource.incident_status == "OPEN" &&
    (resource.incident_severity == "HIGH" || resource.incident_severity == "CRITICAL")
};
forbid(principal, action == ExecBound::Action::"identity.reset_password", resource)
when { resource.privilege_class == "privileged" || resource.privilege_class == "tier0" ||
        resource.criticality == 4 };
"""
)

APPROVAL = """
permit(principal, action == ExecBound::Action::"endpoint.isolate", resource)
when { resource.is_production };
permit(principal, action == ExecBound::Action::"endpoint.lift_isolation", resource)
when { resource.is_production || context.arguments.reason == "remediated" };
permit(principal, action == ExecBound::Action::"identity.enable", resource);
permit(principal, action == ExecBound::Action::"identity.disable", resource)
when { resource.is_production };
permit(principal, action == ExecBound::Action::"identity.revoke_sessions", resource)
when { resource.is_production };
permit(principal, action == ExecBound::Action::"identity.reset_password", resource)
when { resource.is_production || context.arguments.require_change_at_next_sign_in == false };
"""


def soc_bundle(
    tenant_id: UUID,
    endpoint_account_id: UUID,
    identity_account_id: UUID,
    *,
    mapping_version: str,
    bundle_id: UUID | None = None,
) -> BundleContent:
    accounts = {"endpoint": endpoint_account_id, "identity": identity_account_id}
    return BundleContent(
        tenant_id=tenant_id,
        bundle_id=bundle_id or uuid4(),
        cedar_schema=CEDAR_SCHEMA,
        authorization_policies=AUTHORIZATION,
        approval_policies=APPROVAL,
        mappings=tuple(
            MappingRef(
                operation_ref=action,
                account_id=accounts[PRODUCTION_ACTIONS.action(action).resource_type],
                mapping_version=mapping_version,
                schema_version="action.v1",
                context_contract_version=PRODUCTION_ACTIONS.action(action).context_contract_version,
            )
            for action in SOC_ACTIONS
        ),
        limits=tuple(
            rule
            for action in SOC_ACTIONS
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


# A permit with an `||` is two permits; an approval with one is two reviews.
LIFT_RULES: tuple[Rule, ...] = (
    Rule(
        id="lift-when-incident-closed",
        action="endpoint.lift_isolation",
        effect="ALLOW",
        when=(fact("incident_status", "is", "CLOSED"),),
    ),
    Rule(
        id="lift-when-false-positive",
        action="endpoint.lift_isolation",
        effect="ALLOW",
        when=(argument("reason", "is", "false_positive"),),
    ),
    Rule(
        id="lift-production-needs-review",
        action="endpoint.lift_isolation",
        effect="REVIEW",
        when=(fact("is_production", "is", True),),
    ),
    Rule(
        id="lift-remediated-needs-review",
        action="endpoint.lift_isolation",
        effect="REVIEW",
        when=(argument("reason", "is", "remediated"),),
    ),
)
RESET_PASSWORD_RULES: tuple[Rule, ...] = identity_control_rules(
    "identity.reset_password",
    severities=("HIGH", "CRITICAL"),
    reviews=(
        production_review("identity.reset_password"),
        Rule(
            id="reset-password-without-forced-change-needs-review",
            action="identity.reset_password",
            effect="REVIEW",
            when=(argument("require_change_at_next_sign_in", "is", False),),
        ),
    ),
)
SOC_RULESET = Ruleset(
    rules=ISOLATE_RULES + LIFT_RULES + IDENTITY_CONTROL_RULES + RESET_PASSWORD_RULES,
    budgets=identity_budgets(SOC_ACTIONS),
)


def soc_ruleset_bundle(
    tenant_id: UUID,
    endpoint_account_id: UUID,
    identity_account_id: UUID,
    *,
    mapping_version: str,
    bundle_id: UUID | None = None,
) -> BundleContent:
    """The pack as the compiler builds it from its ruleset, carrying the ruleset.

    ``soc_bundle`` is the same pack written by hand and stays the default fixtures derive
    variants from: a bundle whose components are then edited is a hand-written bundle by
    definition, and a ruleset bundle edited that way is exactly what validation refuses.
    ``tests/test_pack_rulesets.py`` proves the two decide every possible input alike.
    """
    base = soc_bundle(
        tenant_id,
        endpoint_account_id,
        identity_account_id,
        mapping_version=mapping_version,
        bundle_id=bundle_id,
    )
    return ruleset_bundle(
        SOC_RULESET, tenant_id=tenant_id, bundle_id=base.bundle_id, mappings=base.mappings
    )
