# SPDX-License-Identifier: AGPL-3.0-only
"""Synthetic context contract proving the catalog is not endpoint/identity specific."""

from datetime import datetime
from types import MappingProxyType
from uuid import UUID, uuid4

from sqlalchemy import text

from execbound.audit import canonical_json
from execbound.contracts import (
    ENDPOINT_ISOLATION_V1,
    IDENTITY_CONTROL_V1,
    BooleanDomain,
    Catalog,
    ContextContract,
    Equals,
    FactRow,
    FactSpec,
    IntegerDomain,
    SourceDefaults,
    StringDomain,
)
from execbound.policy.models import BundleContent, ContextSetting, MappingRef

SYNTHETIC_VERSION = "endpoint-facts.test"
SYNTHETIC_OPERATION = "endpoint.isolate.facts"
SYNTHETIC = ContextContract(
    version=SYNTHETIC_VERSION,
    resource_type="endpoint",
    cedar_entity_type="Endpoint",
    actions=frozenset({"endpoint.isolate"}),
    incident="none",
    bind_incident_claim=False,
    display_fact="exposure",
    sources=MappingProxyType({"inventory": SourceDefaults(300, 3600, ("inventory_sync",))}),
    facts=(
        FactSpec(
            "exposure",
            "String",
            StringDomain(frozenset({"internal", "external"})),
            "inventory",
            FactRow(),
        ),
        FactSpec("risk_score", "Long", IntegerDomain(0, 100), "inventory", FactRow()),
        FactSpec("edr_managed", "Boolean", BooleanDomain(), "inventory", FactRow()),
        FactSpec(
            "is_external",
            "Boolean",
            BooleanDomain(),
            "inventory",
            None,
            Equals("exposure", "external"),
        ),
    ),
)
CATALOG = Catalog((ENDPOINT_ISOLATION_V1, IDENTITY_CONTROL_V1, SYNTHETIC))

SYNTHETIC_SCHEMA = canonical_json(
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
                            "exposure": {"type": "String"},
                            "risk_score": {"type": "Long"},
                            "edr_managed": {"type": "Boolean"},
                            "is_external": {"type": "Boolean"},
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
SYNTHETIC_AUTHORIZATION = """
permit(principal, action == ExecBound::Action::"endpoint.isolate", resource)
when { principal.tenant == resource.tenant && resource.edr_managed && resource.risk_score >= 50 };
forbid(principal, action == ExecBound::Action::"endpoint.isolate", resource)
when { resource.is_external };
"""
SYNTHETIC_FACTS = {"exposure": '"internal"', "risk_score": "70", "edr_managed": "true"}


def synthetic_bundle(
    tenant: UUID,
    account: UUID,
    *,
    bundle_id: UUID | None = None,
    approval_policies: str = "",
    context_settings: tuple[ContextSetting, ...] | None = None,
) -> BundleContent:
    return BundleContent(
        tenant_id=tenant,
        bundle_id=bundle_id or uuid4(),
        cedar_schema=SYNTHETIC_SCHEMA,
        authorization_policies=SYNTHETIC_AUTHORIZATION,
        approval_policies=approval_policies,
        mappings=(
            MappingRef(
                operation_ref=SYNTHETIC_OPERATION,
                account_id=account,
                mapping_version="map-v1",
                schema_version="action.v1",
                context_contract_version=SYNTHETIC_VERSION,
            ),
        ),
        limits=(),
        context_settings=context_settings,
    )


def seed_synthetic(
    engine,
    *,
    tenant: UUID,
    account: UUID,
    source: UUID,
    resource: UUID,
    observed: datetime,
    values: dict[str, str] | None = None,
) -> None:
    with engine.begin() as conn:
        conn.execute(
            text(
                "INSERT INTO execbound.operation_mappings "
                "(tenant_id, operation_ref, account_id, provider, resource_type, action, "
                "provider_operation, mapping_version, schema_version, context_contract_version) "
                "VALUES (:t, :op, :a, 'mock_crowdstrike', 'endpoint', 'endpoint.isolate', "
                "'contain', 'map-v1', 'action.v1', :version)"
            ),
            {"t": tenant, "op": SYNTHETIC_OPERATION, "a": account, "version": SYNTHETIC_VERSION},
        )
        for name, value in (values or SYNTHETIC_FACTS).items():
            conn.execute(
                text(
                    "INSERT INTO execbound.resource_facts "
                    "(tenant_id, account_id, provider, resource_type, resource_id, fact_name, "
                    "value, source_id, version, observed_at) "
                    "VALUES (:t, :a, 'mock_crowdstrike', 'endpoint', :r, :name, "
                    "CAST(:value AS jsonb), :s, 'fact-v1', :n)"
                ),
                {
                    "t": tenant,
                    "a": account,
                    "r": resource,
                    "name": name,
                    "value": value,
                    "s": source,
                    "n": observed,
                },
            )
