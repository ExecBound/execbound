# SPDX-License-Identifier: AGPL-3.0-only
"""SOC catalog fixtures: a synthetic Long-argument action, a second binding and test catalogs."""

import json
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from uuid import UUID, uuid4

from execbound.audit import canonical_json
from execbound.contracts import (
    ENDPOINT_ISOLATION_V1,
    ENDPOINT_RECOVERY_V1,
    IDENTITY_CONTROL_V1,
    IDENTITY_CREDENTIAL_V1,
    Catalog,
)
from execbound.domains import IntegerDomain
from execbound.identity import Identity
from execbound.operations import (
    PRODUCTION_ACTIONS,
    ActionCatalog,
    ActionSpec,
    ArgumentSpec,
    ProviderBinding,
)
from execbound.policy.models import BundleContent, MappingRef, ProjectedUsage, UsageSnapshot
from execbound.requests import ActionRequest, Arguments, ClaimedContext, ResourceSelector
from execbound.resolution.models import CanonicalIntent, ResolvedRequest, TrustedFact
from execbound_harness.soc_demo import CEDAR_SCHEMA as SOC_SCHEMA
from execbound_harness.soc_demo import soc_bundle

PROBE_ACTION = "endpoint.probe_test"
PROBE_OPERATION = "endpoint.probe.test"
PROBE_VERSION = "endpoint-probe.test"
PROBE = ActionSpec(
    PROBE_ACTION,
    "endpoint",
    "Probe endpoint (test)",
    (ArgumentSpec("depth", "Long", IntegerDomain(1, 5)),),
    PROBE_VERSION,
)
PROBE_CONTRACT = replace(
    ENDPOINT_ISOLATION_V1,
    version=PROBE_VERSION,
    actions=frozenset({PROBE_ACTION}),
    bind_incident_claim=True,
)
SECOND_PROVIDER = "mock_defender_test"
SECOND_OPERATION = "endpoint.isolate.defender"
SECOND_BINDING = ProviderBinding(SECOND_PROVIDER, "endpoint.isolate", "isolate")
TEST_ACTIONS = ActionCatalog(
    PRODUCTION_ACTIONS.specs + (PROBE,),
    PRODUCTION_ACTIONS.bindings
    + (ProviderBinding("mock_crowdstrike", PROBE_ACTION, "probe"), SECOND_BINDING),
)
TEST_CATALOG = Catalog(
    (
        ENDPOINT_ISOLATION_V1,
        ENDPOINT_RECOVERY_V1,
        IDENTITY_CONTROL_V1,
        IDENTITY_CREDENTIAL_V1,
        PROBE_CONTRACT,
    ),
    actions=TEST_ACTIONS,
)


def _probe_schema():
    """The SOC entity types with one synthetic action carrying a Long argument."""
    schema = json.loads(SOC_SCHEMA)
    schema["ExecBound"]["actions"] = {
        PROBE_ACTION: {
            "appliesTo": {
                "principalTypes": ["Agent"],
                "resourceTypes": ["Endpoint"],
                "context": {
                    "type": "Record",
                    "attributes": {
                        "arguments": {
                            "type": "Record",
                            "attributes": {"depth": {"type": "Long"}},
                        }
                    },
                },
            }
        }
    }
    return canonical_json(schema)


PROBE_SCHEMA = _probe_schema()
PROBE_AUTHORIZATION = (
    f'permit(principal, action == ExecBound::Action::"{PROBE_ACTION}", resource)\n'
    "when { principal.tenant == resource.tenant && context.arguments.depth >= 3 };\n"
)


def probe_bundle(
    tenant_id: UUID,
    endpoint_account_id: UUID,
    identity_account_id: UUID,
    *,
    mapping_version: str,
) -> BundleContent:
    """A bundle for the synthetic probe action alone; no approval policy and no limits."""
    return BundleContent(
        tenant_id=tenant_id,
        bundle_id=uuid4(),
        cedar_schema=PROBE_SCHEMA,
        authorization_policies=PROBE_AUTHORIZATION,
        approval_policies="",
        mappings=(
            MappingRef(
                operation_ref=PROBE_OPERATION,
                account_id=endpoint_account_id,
                mapping_version=mapping_version,
                schema_version="action.v1",
                context_contract_version=PROBE_VERSION,
            ),
        ),
        limits=(),
    )


class Clock:
    def __init__(self, now):
        self.value = now

    def now(self):
        return self.value


def scenario(
    action,
    *,
    arguments,
    classification,
    environment="development",
    incident_status="OPEN",
    incident_severity="CRITICAL",
    criticality=1,
    actions=PRODUCTION_ACTIONS,
    bundle=soc_bundle,
    operation_ref=None,
):
    """A frozen plan for one catalog action plus its bundle, ready for evaluate(**case).

    `actions` and `bundle` (a factory with `soc_bundle`'s signature) let a caller build
    the same plan around a test catalog; `operation_ref` defaults to the action name.
    """
    tenant, principal, endpoint_account, identity_account, target, source, incident = (
        uuid4() for _ in range(7)
    )
    now = datetime.now(UTC)
    identity = Identity(tenant, principal, uuid4(), "AGENT", now + timedelta(hours=1))
    spec = actions.action(action)
    provider = "mock_crowdstrike" if spec.resource_type == "endpoint" else "mock_entra"
    binding = actions.binding(provider, action)
    name, value = classification
    facts = []
    for fact_name, fact_value in (
        (name, value),
        ("environment", environment),
        ("criticality", criticality),
        ("is_production", environment == "production"),
        ("incident_status", incident_status),
        ("incident_severity", incident_severity),
    ):
        incident_fact = fact_name.startswith("incident_")
        facts.append(
            TrustedFact(
                name=fact_name,
                value=fact_value,
                origin="DERIVED" if fact_name == "is_production" else "RESOLVED",
                source_id=incident if incident_fact else source,
                source_kind="incident" if incident_fact else "inventory",
                source_object_id=str(incident) if incident_fact else "device-01",
                source_version="incident-v1" if incident_fact else "resource-v1",
                permitted_writers=("soc_analyst",) if incident_fact else ("inventory_sync",),
                observed_at=now - timedelta(seconds=60),
                valid_until=now + timedelta(seconds=240),
                dependencies=("environment",) if fact_name == "is_production" else (),
            )
        )
    account = endpoint_account if spec.resource_type == "endpoint" else identity_account
    resolved = ResolvedRequest(
        request=ActionRequest(
            operation_ref=operation_ref or action,
            target=ResourceSelector(kind="canonical", value=str(target)),
            arguments=Arguments(arguments),
            idempotency_key="soc-" + action,
            claimed_context=ClaimedContext(incident_id=incident),
        ),
        intent=CanonicalIntent(
            tenant_id=tenant,
            principal_id=principal,
            account_id=account,
            provider=binding.provider,
            provider_operation=binding.provider_operation,
            action=action,
            resource_type=spec.resource_type,
            target_id=target,
            arguments=Arguments(arguments),
        ),
        resource_provider_id="device-01",
        resource_version="resource-v1",
        mapping_version="map-v1",
        context_contract_version=spec.context_contract_version,
        facts=tuple(facts),
        resolved_at=now,
        valid_until=now + timedelta(seconds=240),
    )
    content = bundle(tenant, endpoint_account, identity_account, mapping_version="map-v1")
    usage = UsageSnapshot(
        tenant_id=tenant,
        principal_id=principal,
        bundle_id=content.bundle_id,
        account_id=account,
        counts=tuple(
            ProjectedUsage(rule_id=rule.rule_id, confirmed_targets=0, unresolved_targets=0)
            for rule in content.limits
        ),
    )
    return {
        "bundle": content,
        "identity": identity,
        "resolved": resolved,
        "usage": usage,
        "clock": Clock(now),
    }


def lift_scenario(*, reason="false_positive", incident_status="CLOSED", environment="development"):
    return scenario(
        "endpoint.lift_isolation",
        arguments={"reason": reason},
        classification=("role", "workstation"),
        environment=environment,
        incident_status=incident_status,
    )


def probe_scenario(*, depth):
    """The synthetic Long-argument action over the test catalog; evaluate with TEST_CATALOG."""
    return scenario(
        PROBE_ACTION,
        arguments={"depth": depth},
        classification=("role", "workstation"),
        actions=TEST_ACTIONS,
        bundle=probe_bundle,
        operation_ref=PROBE_OPERATION,
    )


def reset_scenario(
    *, require_change=True, privilege_class="standard", severity="HIGH", environment="development"
):
    return scenario(
        "identity.reset_password",
        arguments={"require_change_at_next_sign_in": require_change},
        classification=("privilege_class", privilege_class),
        environment=environment,
        incident_severity=severity,
    )
