# SPDX-License-Identifier: AGPL-3.0-only
"""Context contract catalog construction and settings helpers (CC1)."""

from dataclasses import dataclass, replace
from types import MappingProxyType

import pytest

from execbound.contracts import (
    ENDPOINT_ISOLATION_V1,
    IDENTITY_CONTROL_V1,
    PRODUCTION_CATALOG,
    BooleanDomain,
    Catalog,
    Column,
    ContractError,
    Equals,
    FactRow,
    FactSpec,
    SourceDefaults,
    StringDomain,
    effective_source,
    value_matches,
)
from execbound.operations import PRODUCTION_ACTIONS, operation


def with_fact(contract, fact_name, **changes):
    return replace(
        contract,
        facts=tuple(replace(f, **changes) if f.name == fact_name else f for f in contract.facts),
    )


def without_incident(contract):
    return replace(
        contract,
        facts=tuple(f for f in contract.facts if f.source_kind != "incident"),
        sources=MappingProxyType({"inventory": contract.sources["inventory"]}),
    )


def with_source(contract, kind, defaults):
    return replace(contract, sources=MappingProxyType({**contract.sources, kind: defaults}))


def reordered(contract, names):
    by_name = {f.name: f for f in contract.facts}
    return replace(contract, facts=tuple(by_name[name] for name in names))


INVALID = {
    "duplicate fact": lambda c: replace(c, facts=c.facts + c.facts[:1]),
    "reserved fact name": lambda c: with_fact(c, "criticality", name="tenant"),
    "bad fact name": lambda c: with_fact(c, "criticality", name="Criticality"),
    "missing dependency": lambda c: with_fact(
        c, "is_production", derivation=Equals("missing", "production")
    ),
    "derived dependency": lambda c: replace(
        c,
        facts=c.facts
        + (
            FactSpec(
                "double",
                "Boolean",
                BooleanDomain(),
                "inventory",
                None,
                Equals("is_production", True),
            ),
        ),
    ),
    "derivation value outside domain": lambda c: with_fact(
        c, "is_production", derivation=Equals("environment", "moon")
    ),
    "derivation value of incompatible type": lambda c: with_fact(
        c, "is_production", derivation=Equals("environment", 5)
    ),
    "derived fact with storage": lambda c: with_fact(
        c, "is_production", storage=Column("environment")
    ),
    "resolved fact without storage": lambda c: with_fact(c, "criticality", storage=None),
    "unknown display fact": lambda c: replace(c, display_fact="missing"),
    "incident facts with none mode": lambda c: replace(
        c, incident="none", bind_incident_claim=False
    ),
    "required mode without incident facts": lambda c: without_incident(c),
    "claim binding without incident": lambda c: replace(
        without_incident(c), incident="none", bind_incident_claim=True
    ),
    "unsupported column": lambda c: with_fact(c, "role", storage=Column("hostname")),
    "column on wrong source kind": lambda c: with_fact(
        c, "incident_status", storage=Column("role")
    ),
    "row storage for incident fact": lambda c: with_fact(c, "incident_status", storage=FactRow()),
    "string domain for long": lambda c: with_fact(
        c, "criticality", domain=StringDomain(frozenset({"1"}))
    ),
    "empty string domain": lambda c: with_fact(c, "role", domain=StringDomain(frozenset())),
    "unknown action": lambda c: replace(c, actions=frozenset({"endpoint.explode"})),
    "action for another resource type": lambda c: replace(
        c, actions=frozenset({"identity.disable"})
    ),
    "no actions": lambda c: replace(c, actions=frozenset()),
    "max age above ceiling": lambda c: with_source(
        c, "inventory", SourceDefaults(3601, 3600, ("inventory_sync",))
    ),
    "empty default writers": lambda c: with_source(c, "inventory", SourceDefaults(300, 3600, ())),
    "unsorted default writers": lambda c: with_source(
        c, "incident", SourceDefaults(300, 3600, ("z_writer", "a_writer"))
    ),
    "defaults for unused source kind": lambda c: replace(
        c,
        incident="none",
        bind_incident_claim=False,
        facts=tuple(f for f in c.facts if f.source_kind != "incident"),
    ),
    "invalid entity type": lambda c: replace(c, cedar_entity_type="endpoint"),
    "unsupported cedar type": lambda c: replace(
        c, facts=c.facts + (FactSpec("flagged", "Bool", BooleanDomain(), "inventory", FactRow()),)
    ),
    "unknown incident mode": lambda c: replace(without_incident(c), incident="optional"),
    "derived fact before its dependency": lambda c: reordered(
        c,
        [
            "role",
            "is_production",
            "criticality",
            "environment",
            "incident_status",
            "incident_severity",
        ],
    ),
    "incident required without claim binding": lambda c: replace(
        c, version="endpoint-isolation.v2"
    ),
}


@pytest.mark.parametrize("name", sorted(INVALID))
def test_catalog_rejects_invalid_contract(name):
    with pytest.raises(ContractError):
        Catalog((INVALID[name](ENDPOINT_ISOLATION_V1),))


def test_catalog_rejects_duplicate_versions():
    with pytest.raises(ContractError):
        Catalog((ENDPOINT_ISOLATION_V1, ENDPOINT_ISOLATION_V1))


def test_endpoint_isolation_v1_exempt_from_claim_binding_rule():
    # The released endpoint-isolation.v1 keeps bind_incident_claim=False under its named exemption.
    Catalog((ENDPOINT_ISOLATION_V1,))
    # A differently versioned contract with the same shape is not exempted.
    with pytest.raises(ContractError):
        Catalog((replace(ENDPOINT_ISOLATION_V1, version="endpoint-isolation.v2"),))


def test_production_catalog_matches_operation_defaults():
    # Every action's default version is a production contract serving it. A second version
    # may serve an action without being its default: endpoint-isolation.v2 is chosen per
    # mapping, so a mapping never moves onto a producer silently.
    for name in PRODUCTION_ACTIONS.names:
        spec = operation(name)
        contract = PRODUCTION_CATALOG.for_operation(
            spec.context_contract_version, spec.action, spec.resource_type
        )
        assert contract.version == spec.context_contract_version
    for version in PRODUCTION_CATALOG.versions:
        contract = PRODUCTION_CATALOG.contract(version)
        for action in contract.actions:
            assert (
                PRODUCTION_CATALOG.for_operation(version, action, contract.resource_type)
                is contract
            )
    # The old guarantee, that every production contract is some action's default, now holds
    # for every version except the one deliberately chosen per mapping instead.
    default_versions = {
        operation(name).context_contract_version for name in PRODUCTION_ACTIONS.names
    }
    assert PRODUCTION_CATALOG.versions - default_versions == {"endpoint-isolation.v2"}
    assert operation("endpoint.isolate").context_contract_version == "endpoint-isolation.v1"


def test_v1_contracts_reproduce_current_rules():
    assert [f.name for f in ENDPOINT_ISOLATION_V1.facts] == [
        "role",
        "environment",
        "criticality",
        "is_production",
        "incident_status",
        "incident_severity",
    ]
    assert [f.name for f in IDENTITY_CONTROL_V1.facts] == [
        "privilege_class",
        "environment",
        "criticality",
        "is_production",
        "incident_status",
        "incident_severity",
    ]
    assert (ENDPOINT_ISOLATION_V1.bind_incident_claim, IDENTITY_CONTROL_V1.bind_incident_claim) == (
        False,
        True,
    )
    assert (ENDPOINT_ISOLATION_V1.display_fact, IDENTITY_CONTROL_V1.display_fact) == (
        "role",
        "privilege_class",
    )


@pytest.mark.parametrize(
    "version,action,resource_type",
    [
        ("missing.v1", "endpoint.isolate", "endpoint"),
        ("endpoint-isolation.v1", "identity.disable", "identity"),
        ("identity-control.v1", "identity.disable", "endpoint"),
    ],
)
def test_catalog_rejects_unserved_operations(version, action, resource_type):
    with pytest.raises(ContractError):
        PRODUCTION_CATALOG.for_operation(version, action, resource_type)


@pytest.mark.parametrize(
    "name,value,expected",
    [
        ("criticality", 4, True),
        ("criticality", 5, False),
        ("criticality", True, False),
        ("criticality", "4", False),
        ("role", "workstation", True),
        ("role", "laptop", False),
        ("is_production", False, True),
        ("is_production", 0, False),
    ],
)
def test_value_matches_exact_type_and_domain(name, value, expected):
    assert value_matches(ENDPOINT_ISOLATION_V1.fact(name), value) is expected


@dataclass(frozen=True)
class Setting:
    context_contract_version: str
    source_kind: str
    max_age_seconds: int
    permitted_writers: tuple[str, ...]


def test_effective_source_defaults_and_overrides():
    assert effective_source(ENDPOINT_ISOLATION_V1, None, "incident") == SourceDefaults(
        300, 3600, ("soc_analyst",)
    )
    override = Setting("endpoint-isolation.v1", "inventory", 900, ("cmdb_sync", "inventory_sync"))
    unrelated = Setting("identity-control.v1", "inventory", 60, ("inventory_sync",))
    assert effective_source(ENDPOINT_ISOLATION_V1, (unrelated, override), "inventory") == (
        SourceDefaults(900, 3600, ("cmdb_sync", "inventory_sync"))
    )


@pytest.mark.parametrize(
    "settings",
    [
        (Setting("endpoint-isolation.v1", "inventory", 3601, ("inventory_sync",)),),
        (Setting("endpoint-isolation.v1", "inventory", 0, ("inventory_sync",)),),
        (Setting("endpoint-isolation.v1", "inventory", 300, ()),),
        (Setting("endpoint-isolation.v1", "inventory", 300, ("Bad Writer",)),),
        (
            Setting("endpoint-isolation.v1", "inventory", 300, ("inventory_sync",)),
            Setting("endpoint-isolation.v1", "inventory", 600, ("inventory_sync",)),
        ),
    ],
)
def test_effective_source_rejects_invalid_settings(settings):
    with pytest.raises(ContractError):
        effective_source(ENDPOINT_ISOLATION_V1, settings, "inventory")


def test_production_catalog_has_recovery_and_credential_contracts():
    from execbound.contracts import ENDPOINT_RECOVERY_V1, IDENTITY_CREDENTIAL_V1

    assert PRODUCTION_CATALOG.versions == {
        "endpoint-isolation.v1",
        "endpoint-isolation.v2",
        "endpoint-recovery.v1",
        "identity-control.v1",
        "identity-credential.v1",
    }
    recovery = PRODUCTION_CATALOG.for_operation(
        "endpoint-recovery.v1", "endpoint.lift_isolation", "endpoint"
    )
    credential = PRODUCTION_CATALOG.for_operation(
        "identity-credential.v1", "identity.reset_password", "identity"
    )
    assert recovery is ENDPOINT_RECOVERY_V1 and credential is IDENTITY_CREDENTIAL_V1
    assert recovery.facts == ENDPOINT_ISOLATION_V1.facts
    assert credential.facts == IDENTITY_CONTROL_V1.facts
    assert recovery.bind_incident_claim and credential.bind_incident_claim
    with pytest.raises(ContractError):
        PRODUCTION_CATALOG.for_operation(
            "endpoint-isolation.v1", "endpoint.lift_isolation", "endpoint"
        )


def test_contract_actions_are_checked_against_the_injected_action_catalog():
    from execbound.operations import ActionCatalog

    with pytest.raises(ContractError, match="Unknown action"):
        Catalog((ENDPOINT_ISOLATION_V1,), actions=ActionCatalog((), ()))
    assert PRODUCTION_CATALOG.actions.names >= {"endpoint.isolate", "endpoint.lift_isolation"}
