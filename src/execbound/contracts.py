# SPDX-License-Identifier: AGPL-3.0-only
"""Versioned trusted-context contracts. Tenants tune settings; contracts change in code."""

import json
import re
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from types import MappingProxyType
from typing import Any, Literal, Protocol

from execbound.domains import BooleanDomain as BooleanDomain
from execbound.domains import CedarType as CedarType
from execbound.domains import Domain as Domain
from execbound.domains import DomainError, validate_domain, value_in_domain
from execbound.domains import IntegerDomain as IntegerDomain
from execbound.domains import StringDomain as StringDomain
from execbound.operations import PRODUCTION_ACTIONS, ActionCatalog, CatalogError, OperationSpec
from execbound.signals.capabilities import CapabilityError
from execbound.signals.capabilities import capability as signal_capability

SourceKind = Literal["inventory", "incident", "signal"]
IncidentMode = Literal["required", "none"]
FactValue = str | int | bool

MAX_CEILING_SECONDS = 86400
_FACT_NAME = re.compile(r"[a-z][a-z0-9_]{0,62}")
_VERSION = re.compile(r"[a-z][a-z0-9_.-]{0,79}")
_WRITER = re.compile(r"[a-z][a-z0-9_.-]{0,63}")
_ENTITY = re.compile(r"[A-Z][A-Za-z0-9]{0,62}")
COLUMNS: Mapping[SourceKind, frozenset[str]] = MappingProxyType(
    {
        "inventory": frozenset({"role", "privilege_class", "environment", "criticality"}),
        "incident": frozenset({"status", "severity"}),
        # A signal fact is read from security_signals through the bundle's mapping, never
        # from a column.
        "signal": frozenset(),
    }
)
# Who may write a signal fact is decided by the bundle's `signal_mappings`, by source id
# (see docs/SIGNALS.md). This one label stands where writer labels stand for the other kinds,
# so every writer check in resolution and evaluation runs unchanged.
SIGNAL_WRITER = "signal_mappings"
# Released before claim binding was required for incident-required contracts; the
# evaluator does not check it for this version, so resolution enforces the incident
# link through its query instead. See docs/CONTEXT_CONTRACTS.md.
LEGACY_UNBOUND_INCIDENT_CLAIMS: frozenset[str] = frozenset({"endpoint-isolation.v1"})


class ContractError(ValueError):
    """A catalog, mapping, fact or setting does not satisfy its context contract."""


@dataclass(frozen=True, slots=True)
class Column:
    column: str


@dataclass(frozen=True, slots=True)
class FactRow:
    pass


@dataclass(frozen=True, slots=True)
class Equals:
    dependency: str
    value: FactValue


@dataclass(frozen=True, slots=True)
class Signal:
    """A fact resolved from security signals for one capability."""

    capability: str


@dataclass(frozen=True, slots=True)
class FactSpec:
    name: str
    cedar_type: CedarType
    domain: Domain
    source_kind: SourceKind
    storage: Column | FactRow | Signal | None
    derivation: Equals | None = None


@dataclass(frozen=True, slots=True)
class SourceDefaults:
    max_age_seconds: int
    ceiling_seconds: int
    permitted_writers: tuple[str, ...]


@dataclass(frozen=True, slots=True, eq=False)
class ContextContract:
    version: str
    resource_type: Literal["endpoint", "identity"]
    cedar_entity_type: str
    actions: frozenset[str]
    incident: IncidentMode
    bind_incident_claim: bool
    display_fact: str
    sources: Mapping[SourceKind, SourceDefaults]
    facts: tuple[FactSpec, ...]

    @property
    def fact_names(self) -> frozenset[str]:
        return frozenset(spec.name for spec in self.facts)

    def fact(self, name: str) -> FactSpec:
        for spec in self.facts:
            if spec.name == name:
                return spec
        raise ContractError("Unknown fact")


class SourceSetting(Protocol):
    @property
    def context_contract_version(self) -> str: ...

    @property
    def source_kind(self) -> SourceKind: ...

    @property
    def max_age_seconds(self) -> int: ...

    @property
    def permitted_writers(self) -> tuple[str, ...]: ...


def _check(condition: bool, message: str) -> None:
    if not condition:
        raise ContractError(message)


def value_matches(spec: FactSpec, value: object) -> bool:
    return value_in_domain(spec.cedar_type, spec.domain, value)


def _writers_valid(writers: Sequence[str]) -> bool:
    return 1 <= len(writers) <= 16 and all(
        type(writer) is str and _WRITER.fullmatch(writer) for writer in writers
    )


def _validate_domain(spec: FactSpec) -> None:
    try:
        validate_domain(spec.cedar_type, spec.domain)
    except DomainError as error:
        raise ContractError(str(error)) from None


def _validate_contract(contract: ContextContract, actions: ActionCatalog) -> None:
    _check(bool(_VERSION.fullmatch(contract.version)), "Invalid contract version")
    _check(bool(_ENTITY.fullmatch(contract.cedar_entity_type)), "Invalid Cedar entity type")
    _check(contract.resource_type in {"endpoint", "identity"}, "Invalid resource type")
    _check(contract.incident in {"required", "none"}, "Invalid incident mode")
    _check(bool(contract.actions), "Contract serves no action")
    for action in contract.actions:
        try:
            action_spec = actions.action(action)
        except CatalogError:
            raise ContractError("Unknown action") from None
        _check(action_spec.resource_type == contract.resource_type, "Action resource type differs")
    names = [spec.name for spec in contract.facts]
    _check(bool(names) and len(set(names)) == len(names), "Missing or duplicate fact")
    by_name = {spec.name: spec for spec in contract.facts}
    seen: set[str] = set()
    for spec in contract.facts:
        _check(bool(_FACT_NAME.fullmatch(spec.name)), "Invalid fact name")
        _check(spec.name not in {"tenant", "account"}, "Reserved fact name")
        _validate_domain(spec)
        if spec.derivation is None:
            if isinstance(spec.storage, Column):
                _check(spec.storage.column in COLUMNS[spec.source_kind], "Unsupported column")
            elif isinstance(spec.storage, Signal):
                _check(spec.source_kind == "signal", "Signal storage needs the signal kind")
                try:
                    declared = signal_capability(spec.storage.capability)
                except CapabilityError:
                    raise ContractError("Unknown capability") from None
                # Only resource subjects are supported.
                _check(declared.subject == "resource", "Unsupported signal subject")
                _check(
                    spec.cedar_type == "String" and spec.domain == declared.domain,
                    "Signal fact domain differs from its capability",
                )
            else:
                _check(isinstance(spec.storage, FactRow), "Resolved fact needs storage")
                _check(spec.source_kind == "inventory", "Fact rows are inventory only")
            seen.add(spec.name)
            continue
        dependency = by_name.get(spec.derivation.dependency)
        if dependency is None or dependency.derivation is not None:
            raise ContractError("Invalid derivation dependency")
        _check(dependency.source_kind != "signal", "A fact cannot be derived from a signal")
        _check(spec.derivation.dependency in seen, "Derived fact listed before its dependency")
        _check(spec.storage is None and spec.cedar_type == "Boolean", "Invalid derivation")
        _check(spec.source_kind == dependency.source_kind, "Derivation source differs")
        _check(
            value_matches(dependency, spec.derivation.value),
            "Derivation value outside domain",
        )
        seen.add(spec.name)
    _check(contract.display_fact in by_name, "Unknown display fact")
    kinds = {spec.source_kind for spec in contract.facts}
    _check(("incident" in kinds) == (contract.incident == "required"), "Incident mode differs")
    _check(
        not contract.bind_incident_claim or contract.incident == "required",
        "Claim binding requires an incident",
    )
    _check(
        contract.incident != "required"
        or contract.bind_incident_claim
        or contract.version in LEGACY_UNBOUND_INCIDENT_CLAIMS,
        "Incident-required contracts must bind the incident claim",
    )
    _check(set(contract.sources) == kinds, "Source defaults differ from facts")
    signal_capabilities = [
        spec.storage.capability for spec in contract.facts if isinstance(spec.storage, Signal)
    ]
    _check(
        len(set(signal_capabilities)) == len(signal_capabilities),
        "Two facts for one capability",
    )
    if "signal" in contract.sources:
        _check(
            contract.sources["signal"].permitted_writers == (SIGNAL_WRITER,),
            "Signal writers are the bundle's mapping",
        )
    for defaults in contract.sources.values():
        _check(
            type(defaults.max_age_seconds) is int
            and type(defaults.ceiling_seconds) is int
            and 1 <= defaults.max_age_seconds <= defaults.ceiling_seconds <= MAX_CEILING_SECONDS,
            "Invalid source age",
        )
        _check(
            _writers_valid(defaults.permitted_writers)
            and tuple(sorted(set(defaults.permitted_writers))) == defaults.permitted_writers,
            "Invalid default writers",
        )


class Catalog:
    def __init__(
        self,
        contracts: Iterable[ContextContract],
        *,
        actions: ActionCatalog = PRODUCTION_ACTIONS,
    ) -> None:
        self._actions = actions
        catalog: dict[str, ContextContract] = {}
        for contract in contracts:
            _validate_contract(contract, actions)
            _check(contract.version not in catalog, "Duplicate contract version")
            catalog[contract.version] = contract
        self._contracts: Mapping[str, ContextContract] = MappingProxyType(catalog)

    @property
    def actions(self) -> ActionCatalog:
        return self._actions

    @property
    def versions(self) -> frozenset[str]:
        return frozenset(self._contracts)

    def contract(self, version: str) -> ContextContract:
        found = self._contracts.get(version) if type(version) is str else None
        if found is None:
            raise ContractError("Unknown context contract")
        return found

    def for_operation(self, version: str, action: str, resource_type: str) -> ContextContract:
        contract = self.contract(version)
        _check(
            action in contract.actions and resource_type == contract.resource_type,
            "Contract does not serve operation",
        )
        return contract


def effective_source(
    contract: ContextContract,
    settings: Sequence[SourceSetting] | None,
    source_kind: SourceKind,
) -> SourceDefaults:
    defaults = contract.sources.get(source_kind)
    if defaults is None:
        raise ContractError("Unused source kind")
    matches = [
        item
        for item in settings or ()
        if item.context_contract_version == contract.version and item.source_kind == source_kind
    ]
    _check(len(matches) <= 1, "Duplicate context setting")
    if not matches:
        return defaults
    setting = matches[0]
    if source_kind == "signal":
        _check(
            tuple(setting.permitted_writers) == (SIGNAL_WRITER,),
            "Signal writers are the bundle's mapping",
        )
    _check(
        type(setting.max_age_seconds) is int
        and 1 <= setting.max_age_seconds <= defaults.ceiling_seconds,
        "Setting exceeds ceiling",
    )
    _check(_writers_valid(setting.permitted_writers), "Invalid permitted writers")
    return SourceDefaults(
        setting.max_age_seconds, defaults.ceiling_seconds, tuple(setting.permitted_writers)
    )


_ENVIRONMENT = StringDomain(frozenset({"development", "staging", "production"}))
_DEFAULT_SOURCES: Mapping[SourceKind, SourceDefaults] = MappingProxyType(
    {
        "inventory": SourceDefaults(300, 3600, ("inventory_sync",)),
        "incident": SourceDefaults(300, 3600, ("soc_analyst",)),
    }
)


def _v1_facts(classification: FactSpec) -> tuple[FactSpec, ...]:
    return (
        classification,
        FactSpec("environment", "String", _ENVIRONMENT, "inventory", Column("environment")),
        FactSpec("criticality", "Long", IntegerDomain(0, 4), "inventory", Column("criticality")),
        FactSpec(
            "is_production",
            "Boolean",
            BooleanDomain(),
            "inventory",
            None,
            Equals("environment", "production"),
        ),
        FactSpec(
            "incident_status",
            "String",
            StringDomain(frozenset({"OPEN", "CLOSED"})),
            "incident",
            Column("status"),
        ),
        FactSpec(
            "incident_severity",
            "String",
            StringDomain(frozenset({"LOW", "MEDIUM", "HIGH", "CRITICAL"})),
            "incident",
            Column("severity"),
        ),
    )


_ROLE = FactSpec(
    "role",
    "String",
    StringDomain(frozenset({"workstation", "server", "domain_controller"})),
    "inventory",
    Column("role"),
)
_PRIVILEGE_CLASS = FactSpec(
    "privilege_class",
    "String",
    StringDomain(frozenset({"standard", "privileged", "tier0"})),
    "inventory",
    Column("privilege_class"),
)
ENDPOINT_ISOLATION_V1 = ContextContract(
    version="endpoint-isolation.v1",
    resource_type="endpoint",
    cedar_entity_type="Endpoint",
    actions=frozenset({"endpoint.isolate"}),
    incident="required",
    bind_incident_claim=False,
    display_fact="role",
    sources=_DEFAULT_SOURCES,
    facts=_v1_facts(_ROLE),
)
ENDPOINT_RECOVERY_V1 = ContextContract(
    version="endpoint-recovery.v1",
    resource_type="endpoint",
    cedar_entity_type="Endpoint",
    actions=frozenset({"endpoint.lift_isolation"}),
    incident="required",
    bind_incident_claim=True,
    display_fact="role",
    sources=_DEFAULT_SOURCES,
    facts=_v1_facts(_ROLE),
)
_SIGNAL_SOURCES: Mapping[SourceKind, SourceDefaults] = MappingProxyType(
    {**_DEFAULT_SOURCES, "signal": SourceDefaults(300, 3600, (SIGNAL_WRITER,))}
)
_COMPROMISE = FactSpec(
    "compromise",
    "String",
    signal_capability("resource_compromise.v1").domain,
    "signal",
    Signal("resource_compromise.v1"),
)
# v1's facts plus the EDR's corroboration of the target. A mapping opts in with
# `mapping-create --contract-version endpoint-isolation.v2`; the action's default stays v1.
# It shares `Endpoint` with endpoint-recovery.v1 and adds an attribute, so one bundle cannot
# map both.
ENDPOINT_ISOLATION_V2 = ContextContract(
    version="endpoint-isolation.v2",
    resource_type="endpoint",
    cedar_entity_type="Endpoint",
    actions=frozenset({"endpoint.isolate"}),
    incident="required",
    bind_incident_claim=True,
    display_fact="role",
    sources=_SIGNAL_SOURCES,
    facts=(*_v1_facts(_ROLE), _COMPROMISE),
)
IDENTITY_CONTROL_V1 = ContextContract(
    version="identity-control.v1",
    resource_type="identity",
    cedar_entity_type="Identity",
    actions=frozenset({"identity.disable", "identity.enable", "identity.revoke_sessions"}),
    incident="required",
    bind_incident_claim=True,
    display_fact="privilege_class",
    sources=_DEFAULT_SOURCES,
    facts=_v1_facts(_PRIVILEGE_CLASS),
)
IDENTITY_CREDENTIAL_V1 = ContextContract(
    version="identity-credential.v1",
    resource_type="identity",
    cedar_entity_type="Identity",
    actions=frozenset({"identity.reset_password"}),
    incident="required",
    bind_incident_claim=True,
    display_fact="privilege_class",
    sources=_DEFAULT_SOURCES,
    facts=_v1_facts(_PRIVILEGE_CLASS),
)
PRODUCTION_CATALOG = Catalog(
    (
        ENDPOINT_ISOLATION_V1,
        ENDPOINT_ISOLATION_V2,
        ENDPOINT_RECOVERY_V1,
        IDENTITY_CONTROL_V1,
        IDENTITY_CREDENTIAL_V1,
    )
)


def _validate_action_contexts(schema: dict[str, Any], operations: Sequence[OperationSpec]) -> None:
    """Each mapped action's Cedar context declares exactly the catalog's arguments."""
    try:
        actions = schema["ExecBound"]["actions"]
    except (KeyError, TypeError):
        raise ContractError("Invalid Cedar schema") from None
    _check(isinstance(actions, dict), "Invalid Cedar schema")
    for spec in operations:
        if spec.action not in actions:
            raise ContractError("Undeclared action")
        try:
            context = actions[spec.action]["appliesTo"]["context"]
        except (KeyError, TypeError):
            raise ContractError("Invalid action declaration") from None
        _check(
            isinstance(context, dict)
            and set(context) <= {"type", "attributes"}
            and context.get("type") == "Record"
            and isinstance(context.get("attributes"), dict),
            "Invalid action context",
        )
        declared = context["attributes"]
        if not spec.arguments:
            _check(declared == {}, "Action context differs from catalog")
            continue
        _check(set(declared) == {"arguments"}, "Action context differs from catalog")
        record = declared["arguments"]
        _check(
            isinstance(record, dict)
            and set(record) <= {"type", "required", "attributes"}
            and record.get("type") == "Record"
            and record.get("required", True) is True
            and isinstance(record.get("attributes"), dict),
            "Invalid action arguments record",
        )
        inner = record["attributes"]
        _check(set(inner) == spec.argument_names, "Action arguments differ from catalog")
        for argument in spec.arguments:
            item = inner[argument.name]
            _check(
                isinstance(item, dict)
                and set(item) <= {"type", "required"}
                and item.get("type") == argument.cedar_type
                and item.get("required", True) is True,
                "Action argument differs from catalog",
            )


def validate_bundle_contracts(
    *,
    contracts: Iterable[ContextContract],
    cedar_schema: str,
    settings: Sequence[SourceSetting] | None,
    operations: Sequence[OperationSpec] = (),
) -> None:
    used = {contract.version: contract for contract in contracts}
    _check(bool(used), "Bundle uses no context contract")
    try:
        schema = json.loads(cedar_schema)
        entity_types = schema["ExecBound"]["entityTypes"]
    except (ValueError, KeyError, TypeError):
        raise ContractError("Invalid Cedar schema") from None
    _check(isinstance(entity_types, dict), "Invalid Cedar schema")
    expected: dict[str, dict[str, str]] = {}
    for contract in used.values():
        attributes: dict[str, str] = {
            "tenant": "String",
            "account": "String",
            **{spec.name: spec.cedar_type for spec in contract.facts},
        }
        prior = expected.setdefault(contract.cedar_entity_type, attributes)
        _check(prior == attributes, "Contracts disagree on entity attributes")
    for entity, expected_attributes in expected.items():
        try:
            shape = entity_types[entity]["shape"]
            declared = shape["attributes"]
        except (KeyError, TypeError):
            raise ContractError("Missing contract entity") from None
        _check(
            isinstance(shape, dict)
            and shape.get("type") == "Record"
            and isinstance(declared, dict),
            "Invalid contract entity",
        )
        _check(set(declared) == set(expected_attributes), "Entity attributes differ from contract")
        for name, cedar_type in expected_attributes.items():
            item = declared[name]
            _check(
                isinstance(item, dict)
                and set(item) <= {"type", "required"}
                and item.get("type") == cedar_type
                and item.get("required", True) is True,
                "Entity attribute differs from contract",
            )
    _validate_action_contexts(schema, operations)
    seen: set[tuple[str, str]] = set()
    for setting in settings or ():
        key = (setting.context_contract_version, setting.source_kind)
        _check(key not in seen, "Duplicate context setting")
        seen.add(key)
        used_contract = used.get(setting.context_contract_version)
        if used_contract is None or setting.source_kind not in used_contract.sources:
            raise ContractError("Setting names an unused contract or source kind")
        effective_source(used_contract, settings, setting.source_kind)


def validate_selector(
    *,
    contracts: Iterable[ContextContract],
    actions: Iterable[str],
    fact: str,
    equals: object,
) -> None:
    """A selector must name a fact every contract serving its actions declares and admits.

    ``contracts`` are the contracts of the bundle's mappings. A selector over a fact no
    serving contract declares, or with a value outside a serving contract's domain, is
    refused so a rule can never name a fact the plan will not carry.
    """
    names = set(actions)
    serving = [contract for contract in contracts if contract.actions & names]
    _check(bool(serving), "Selector names actions no bundle contract serves")
    for contract in serving:
        spec = contract.fact(fact)
        _check(value_matches(spec, equals), "Selector value outside the fact domain")
