# SPDX-License-Identifier: AGPL-3.0-only
"""Cedar schemas and context settings checked against contracts (CC5, CC7)."""

import json
from uuid import uuid4

import pytest
from context_fixtures import SYNTHETIC, SYNTHETIC_SCHEMA, SYNTHETIC_VERSION
from soc_fixtures import TEST_CATALOG
from sqlalchemy import text
from test_execution import activate
from test_execution import world as world
from test_resolution import registry as registry
from test_resolution import seed_soc_mappings

from execbound.audit import canonical_json
from execbound.contracts import (
    ENDPOINT_ISOLATION_V1,
    ENDPOINT_RECOVERY_V1,
    IDENTITY_CONTROL_V1,
    IDENTITY_CREDENTIAL_V1,
    ContractError,
    validate_bundle_contracts,
    validate_selector,
)
from execbound.operations import PRODUCTION_ACTIONS
from execbound.policy.models import ContextSetting
from execbound.policy.store import (
    PolicyStoreError,
    activate_bundle,
    create_bundle,
    validate_bundle,
)
from execbound_harness.demo import CEDAR_SCHEMA as ENDPOINT_SCHEMA
from execbound_harness.identity_demo import CEDAR_SCHEMA as IDENTITY_SCHEMA
from execbound_harness.soc_demo import CEDAR_SCHEMA as SOC_SCHEMA
from execbound_harness.soc_demo import soc_bundle


def endpoint_schema(mutate):
    schema = json.loads(ENDPOINT_SCHEMA)
    mutate(schema["ExecBound"]["entityTypes"]["Endpoint"]["shape"]["attributes"])
    return canonical_json(schema)


def setting(**changes):
    values = {
        "context_contract_version": "endpoint-isolation.v1",
        "source_kind": "inventory",
        "max_age_seconds": 600,
        "permitted_writers": ("inventory_sync",),
        **changes,
    }
    return ContextSetting.model_validate(values)


SCHEMA_MUTATIONS = {
    "missing": lambda attrs: attrs.pop("account"),
    "extra": lambda attrs: attrs.update(owner={"type": "String"}),
    "mistyped": lambda attrs: attrs.update(account={"type": "Long"}),
    "optional": lambda attrs: attrs.update(account={"type": "String", "required": False}),
}


def test_existing_packs_match_their_contracts():
    validate_bundle_contracts(
        contracts=[ENDPOINT_ISOLATION_V1], cedar_schema=ENDPOINT_SCHEMA, settings=None
    )
    validate_bundle_contracts(
        contracts=[IDENTITY_CONTROL_V1], cedar_schema=IDENTITY_SCHEMA, settings=None
    )
    validate_bundle_contracts(contracts=[SYNTHETIC], cedar_schema=SYNTHETIC_SCHEMA, settings=None)


@pytest.mark.parametrize("name", sorted(SCHEMA_MUTATIONS))
def test_schema_must_match_contract_exactly(name):
    with pytest.raises(ContractError):
        validate_bundle_contracts(
            contracts=[ENDPOINT_ISOLATION_V1],
            cedar_schema=endpoint_schema(SCHEMA_MUTATIONS[name]),
            settings=None,
        )


def test_contracts_sharing_an_entity_type_must_agree():
    with pytest.raises(ContractError):
        validate_bundle_contracts(
            contracts=[ENDPOINT_ISOLATION_V1, SYNTHETIC],
            cedar_schema=ENDPOINT_SCHEMA,
            settings=None,
        )


@pytest.mark.parametrize(
    "settings",
    [
        (setting(max_age_seconds=3601),),
        (setting(context_contract_version="identity-control.v1"),),
        (setting(context_contract_version=SYNTHETIC_VERSION),),
    ],
    ids=["above-ceiling", "unused-contract", "unknown-contract"],
)
def test_settings_must_fit_used_contracts(settings):
    with pytest.raises(ContractError):
        validate_bundle_contracts(
            contracts=[ENDPOINT_ISOLATION_V1], cedar_schema=ENDPOINT_SCHEMA, settings=settings
        )


def test_settings_for_unused_source_kind_are_rejected():
    incident = setting(
        context_contract_version=SYNTHETIC_VERSION,
        source_kind="incident",
        permitted_writers=("soc_analyst",),
    )
    with pytest.raises(ContractError):
        validate_bundle_contracts(
            contracts=[SYNTHETIC], cedar_schema=SYNTHETIC_SCHEMA, settings=(incident,)
        )


@pytest.mark.parametrize(
    "contracts,actions,fact,equals",
    [
        ([ENDPOINT_ISOLATION_V1], ("endpoint.isolate",), "environment", "production"),
        ([ENDPOINT_ISOLATION_V1], ("endpoint.isolate",), "criticality", 4),
        ([ENDPOINT_ISOLATION_V1], ("endpoint.isolate",), "is_production", True),
        ([ENDPOINT_ISOLATION_V1], ("endpoint.isolate",), "incident_severity", "HIGH"),
        # A contract serving none of the actions is not consulted.
        ([IDENTITY_CONTROL_V1, ENDPOINT_ISOLATION_V1], ("endpoint.isolate",), "role", "server"),
        # Every serving contract of a multi-action rule carries the fact.
        (
            [ENDPOINT_ISOLATION_V1, ENDPOINT_RECOVERY_V1],
            ("endpoint.isolate", "endpoint.lift_isolation"),
            "environment",
            "production",
        ),
    ],
    ids=["string", "long", "boolean", "incident", "unserving-ignored", "multi-action"],
)
def test_selector_accepts_facts_every_serving_contract_admits(contracts, actions, fact, equals):
    validate_selector(contracts=contracts, actions=actions, fact=fact, equals=equals)


@pytest.mark.parametrize(
    "contracts,actions,fact,equals,message",
    [
        ([ENDPOINT_ISOLATION_V1], ("endpoint.isolate",), "exposure", "internal", "Unknown fact"),
        ([ENDPOINT_ISOLATION_V1], ("endpoint.isolate",), "environment", "prod", "outside"),
        ([ENDPOINT_ISOLATION_V1], ("endpoint.isolate",), "environment", 1, "outside"),
        ([ENDPOINT_ISOLATION_V1], ("endpoint.isolate",), "criticality", True, "outside"),
        ([ENDPOINT_ISOLATION_V1], ("endpoint.isolate",), "criticality", 5, "outside"),
        ([ENDPOINT_ISOLATION_V1], ("endpoint.isolate",), "is_production", 1, "outside"),
        ([ENDPOINT_ISOLATION_V1], ("identity.disable",), "environment", "production", "serves"),
        ([ENDPOINT_ISOLATION_V1], (), "environment", "production", "serves"),
        ([], ("endpoint.isolate",), "environment", "production", "serves"),
        # SYNTHETIC also serves endpoint.isolate but declares no environment fact, so a plan
        # resolved through its mapping would not carry the selector's fact.
        (
            [ENDPOINT_ISOLATION_V1, SYNTHETIC],
            ("endpoint.isolate",),
            "environment",
            "production",
            "Unknown fact",
        ),
        (
            [ENDPOINT_ISOLATION_V1, IDENTITY_CONTROL_V1],
            ("endpoint.isolate", "identity.disable"),
            "role",
            "server",
            "Unknown fact",
        ),
    ],
    ids=[
        "unknown-fact",
        "outside-domain",
        "long-for-string",
        "bool-for-long",
        "long-outside-range",
        "long-for-boolean",
        "unserved-action",
        "no-actions",
        "no-contracts",
        "fact-missing-from-one-serving-contract",
        "fact-missing-from-second-action",
    ],
)
def test_selector_rejects_unserved_unknown_or_out_of_domain_facts(
    contracts, actions, fact, equals, message
):
    with pytest.raises(ContractError, match=message):
        validate_selector(contracts=contracts, actions=actions, fact=fact, equals=equals)


@pytest.mark.parametrize("name", ["missing", "extra"])
def test_store_rejects_contract_schema_mismatch(db, world, name):
    with pytest.raises(PolicyStoreError) as caught:
        activate(db, world, cedar_schema=endpoint_schema(SCHEMA_MUTATIONS[name]))
    assert caught.value.code == "INVALID_COMPONENT"


def test_store_rejects_settings_above_ceiling(db, world):
    with pytest.raises(PolicyStoreError) as caught:
        activate(db, world, context_settings=(setting(max_age_seconds=3601),))
    assert caught.value.code == "INVALID_COMPONENT"


def test_store_accepts_valid_settings(db, world):
    bundle = activate(db, world, context_settings=(setting(max_age_seconds=900),))
    assert bundle.context_settings[0].max_age_seconds == 900


SOC_CONTRACTS = [
    ENDPOINT_ISOLATION_V1,
    ENDPOINT_RECOVERY_V1,
    IDENTITY_CONTROL_V1,
    IDENTITY_CREDENTIAL_V1,
]
SOC_OPERATIONS = [
    PRODUCTION_ACTIONS.bound(binding.provider, binding.action)
    for binding in PRODUCTION_ACTIONS.bindings
]


def soc_schema(mutate):
    schema = json.loads(SOC_SCHEMA)
    mutate(schema["ExecBound"]["actions"])
    return canonical_json(schema)


def lift_context(actions):
    return actions["endpoint.lift_isolation"]["appliesTo"]["context"]


def lift_attributes(actions):
    return lift_context(actions)["attributes"]


CONTEXT_MUTATIONS = {
    "missing arguments record": (
        lambda a: lift_attributes(a).pop("arguments"),
        "Action context differs from catalog",
    ),
    "extra context attribute": (
        lambda a: lift_attributes(a).update(note={"type": "String"}),
        "Action context differs from catalog",
    ),
    "unknown context key": (
        lambda a: lift_context(a).update(additionalAttributes=True),
        "Invalid action context",
    ),
    "mistyped argument": (
        lambda a: lift_attributes(a)["arguments"]["attributes"].update(reason={"type": "Long"}),
        "Action argument differs from catalog",
    ),
    "optional argument": (
        lambda a: lift_attributes(a)["arguments"]["attributes"].update(
            reason={"type": "String", "required": False}
        ),
        "Action argument differs from catalog",
    ),
    "optional arguments record": (
        lambda a: lift_attributes(a)["arguments"].update(required=False),
        "Invalid action arguments record",
    ),
    "extra argument": (
        lambda a: lift_attributes(a)["arguments"]["attributes"].update(ticket={"type": "String"}),
        "Action arguments differ from catalog",
    ),
    "missing argument": (
        lambda a: lift_attributes(a)["arguments"]["attributes"].pop("reason"),
        "Action arguments differ from catalog",
    ),
    "arguments on an argumentless action": (
        lambda a: a["endpoint.isolate"]["appliesTo"]["context"]["attributes"].update(
            arguments={"type": "Record", "attributes": {}}
        ),
        "Action context differs from catalog",
    ),
    "missing action": (lambda a: a.pop("identity.reset_password"), "Undeclared action"),
}


def test_soc_pack_and_existing_packs_match_their_action_contexts():
    validate_bundle_contracts(
        contracts=SOC_CONTRACTS, cedar_schema=SOC_SCHEMA, settings=None, operations=SOC_OPERATIONS
    )
    validate_bundle_contracts(
        contracts=[ENDPOINT_ISOLATION_V1],
        cedar_schema=ENDPOINT_SCHEMA,
        settings=None,
        operations=[PRODUCTION_ACTIONS.bound("mock_crowdstrike", "endpoint.isolate")],
    )
    validate_bundle_contracts(
        contracts=[IDENTITY_CONTROL_V1],
        cedar_schema=IDENTITY_SCHEMA,
        settings=None,
        operations=[
            PRODUCTION_ACTIONS.bound("mock_entra", action)
            for action in ("identity.disable", "identity.enable", "identity.revoke_sessions")
        ],
    )


@pytest.mark.parametrize("name", sorted(CONTEXT_MUTATIONS))
def test_action_context_must_match_the_catalog_exactly(name):
    mutation, message = CONTEXT_MUTATIONS[name]
    with pytest.raises(ContractError, match=message):
        validate_bundle_contracts(
            contracts=SOC_CONTRACTS,
            cedar_schema=soc_schema(mutation),
            settings=None,
            operations=SOC_OPERATIONS,
        )


def seeded_soc_bundle(admin_engine, world):
    """Provision both accounts and all six mappings, then build the SOC bundle over them."""
    seed_soc_mappings(admin_engine, world)
    identity_account = uuid4()
    tenant = world["identity"].tenant_id
    with admin_engine.begin() as conn:
        conn.execute(
            text(
                "INSERT INTO execbound.connector_accounts(tenant_id, account_id, provider, "
                "space_id) "
                "VALUES (:t, :a, 'mock_entra', "
                "(SELECT space_id FROM execbound.spaces WHERE tenant_id = :t))"
            ),
            {"t": tenant, "a": identity_account},
        )
        for action in (
            "identity.disable",
            "identity.enable",
            "identity.revoke_sessions",
            "identity.reset_password",
        ):
            spec = PRODUCTION_ACTIONS.bound("mock_entra", action)
            conn.execute(
                text(
                    "INSERT INTO execbound.operation_mappings "
                    "(tenant_id, operation_ref, account_id, provider, resource_type, action, "
                    "provider_operation, mapping_version, schema_version, "
                    "context_contract_version) "
                    "VALUES (:t, :action, :a, 'mock_entra', 'identity', :action, :operation, "
                    "'map-v1', 'action.v1', :contract)"
                ),
                {
                    "t": tenant,
                    "a": identity_account,
                    "action": action,
                    "operation": spec.provider_operation,
                    "contract": spec.context_contract_version,
                },
            )
    return soc_bundle(tenant, world["account"], identity_account, mapping_version="map-v1")


def test_soc_bundle_activates_through_the_store(db, world, admin_engine):
    bundle = seeded_soc_bundle(admin_engine, world)
    create_bundle(db, world["admin"], bundle, world["clock"])
    validate_bundle(db, world["admin"], bundle.bundle_id, world["clock"], catalog=TEST_CATALOG)
    activate_bundle(db, world["admin"], bundle.bundle_id, world["clock"], catalog=TEST_CATALOG)


def test_store_refuses_soc_schema_arguments_outside_the_catalog(db, world, admin_engine):
    # Pins the `operations=` wiring in policy/store._components: only the action-context
    # check against the catalog can refuse this bundle, because its Cedar policies still
    # validate against the mutated schema. Dropping the `arguments` record outright would
    # not reach that check: Cedar rejects the policies that read it first, which the store
    # also reports as INVALID_COMPONENT, but at the policies' location, where the catalog
    # check names none.
    mutation, _ = CONTEXT_MUTATIONS["extra argument"]
    bundle = seeded_soc_bundle(admin_engine, world).model_copy(
        update={"bundle_id": uuid4(), "cedar_schema": soc_schema(mutation)}
    )
    create_bundle(db, world["admin"], bundle, world["clock"])
    with pytest.raises(PolicyStoreError) as caught:
        validate_bundle(db, world["admin"], bundle.bundle_id, world["clock"], catalog=TEST_CATALOG)
    assert caught.value.code == "INVALID_COMPONENT"
    assert caught.value.location is None
