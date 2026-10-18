# SPDX-License-Identifier: Apache-2.0
"""Closed, immutable action catalog and provider bindings shared by every boundary."""

import re
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from types import MappingProxyType
from typing import Annotated, Literal

from pydantic import Field

from execbound_protocol.domains import (
    MAX_ARGUMENTS,
    BooleanDomain,
    CedarType,
    Domain,
    DomainError,
    ScalarValue,
    StringDomain,
    validate_domain,
    value_in_domain,
)

ACTION_PATTERN = r"^[a-z][a-z0-9_]{0,31}\.[a-z][a-z0-9_]{0,31}$"
NAME_PATTERN = r"^[a-z][a-z0-9_]{0,62}$"
ActionName = Annotated[str, Field(pattern=ACTION_PATTERN)]
ProviderName = Annotated[str, Field(pattern=NAME_PATTERN)]
ProviderOperation = Annotated[str, Field(pattern=NAME_PATTERN)]
ResourceType = Literal["endpoint", "identity"]
SchemaVersion = Literal["action.v1"]
_ACTION = re.compile(ACTION_PATTERN)
_NAME = re.compile(NAME_PATTERN)
_CONTRACT = re.compile(r"^[a-z][a-z0-9_.-]{0,79}$")


class CatalogError(ValueError):
    """An action, binding, argument or operation tuple is outside the catalog."""


@dataclass(frozen=True, slots=True)
class ArgumentSpec:
    name: str
    cedar_type: CedarType
    domain: Domain


@dataclass(frozen=True, slots=True)
class ActionSpec:
    action: str
    resource_type: ResourceType
    label: str
    arguments: tuple[ArgumentSpec, ...]
    context_contract_version: str
    # The catalog action that undoes this one, when the catalog has one, so a page can say
    # whether what an approver is about to allow can be taken back and by which action. It
    # is display data: nothing dispatches, plans or authorizes from it, and a released spec
    # gaining one keeps its name, its arguments and every frozen plan that names it.
    reversed_by: str | None = None

    @property
    def argument_names(self) -> frozenset[str]:
        return frozenset(argument.name for argument in self.arguments)


@dataclass(frozen=True, slots=True)
class ProviderBinding:
    provider: str
    action: str
    provider_operation: str
    schema_version: SchemaVersion = "action.v1"


@dataclass(frozen=True, slots=True)
class OperationSpec:
    """One action bound to one provider operation: the tuple every boundary rechecks."""

    provider: str
    resource_type: ResourceType
    action: str
    provider_operation: str
    schema_version: SchemaVersion
    context_contract_version: str
    label: str
    arguments: tuple[ArgumentSpec, ...]

    @property
    def argument_names(self) -> frozenset[str]:
        return frozenset(argument.name for argument in self.arguments)


def _check(condition: bool, message: str) -> None:
    if not condition:
        raise CatalogError(message)


def _validate_action(spec: ActionSpec) -> None:
    _check(type(spec.action) is str and bool(_ACTION.fullmatch(spec.action)), "Invalid action name")
    _check(spec.resource_type in {"endpoint", "identity"}, "Invalid resource type")
    _check(type(spec.label) is str and 1 <= len(spec.label) <= 80, "Invalid action label")
    _check(
        type(spec.context_contract_version) is str
        and bool(_CONTRACT.fullmatch(spec.context_contract_version)),
        "Invalid context contract version",
    )
    names = [argument.name for argument in spec.arguments]
    _check(len(names) <= MAX_ARGUMENTS, "Too many arguments")
    _check(len(set(names)) == len(names), "Duplicate argument")
    _check(names == sorted(names), "Arguments not in name order")
    for argument in spec.arguments:
        _check(
            type(argument.name) is str and bool(_NAME.fullmatch(argument.name)),
            "Invalid argument name",
        )
        try:
            validate_domain(argument.cedar_type, argument.domain)
        except DomainError:
            raise CatalogError("Invalid argument domain") from None


def _validate_reversals(specs: Mapping[str, ActionSpec]) -> None:
    for spec in specs.values():
        if spec.reversed_by is None:
            continue
        _check(spec.reversed_by in specs, "Reversal names an unknown action")
        _check(spec.reversed_by != spec.action, "An action cannot reverse itself")
        _check(
            specs[spec.reversed_by].resource_type == spec.resource_type,
            "A reversal must act on the same resource type",
        )


def _validate_binding(binding: ProviderBinding) -> None:
    _check(
        type(binding.provider) is str and bool(_NAME.fullmatch(binding.provider)),
        "Invalid provider name",
    )
    _check(
        type(binding.provider_operation) is str
        and bool(_NAME.fullmatch(binding.provider_operation)),
        "Invalid provider operation",
    )
    _check(binding.schema_version == "action.v1", "Unsupported schema version")


class ActionCatalog:
    def __init__(self, actions: Iterable[ActionSpec], bindings: Iterable[ProviderBinding]) -> None:
        specs: dict[str, ActionSpec] = {}
        for spec in actions:
            _validate_action(spec)
            _check(spec.action not in specs, "Duplicate action")
            specs[spec.action] = spec
        _validate_reversals(specs)
        bound: dict[tuple[str, str], ProviderBinding] = {}
        operations: set[tuple[str, str]] = set()
        for binding in bindings:
            _validate_binding(binding)
            _check(binding.action in specs, "Binding for unknown action")
            key = (binding.provider, binding.action)
            _check(key not in bound, "Duplicate provider binding")
            operation_key = (binding.provider, binding.provider_operation)
            _check(operation_key not in operations, "Duplicate provider operation")
            bound[key] = binding
            operations.add(operation_key)
        self._actions: Mapping[str, ActionSpec] = MappingProxyType(specs)
        self._bindings: Mapping[tuple[str, str], ProviderBinding] = MappingProxyType(bound)
        self._operations: frozenset[tuple[str, str]] = frozenset(operations)

    @property
    def names(self) -> frozenset[str]:
        return frozenset(self._actions)

    @property
    def provider_operations(self) -> frozenset[tuple[str, str]]:
        """Every (provider, provider operation) this catalog binds, the key it refuses twice."""
        return self._operations

    @property
    def specs(self) -> tuple[ActionSpec, ...]:
        return tuple(self._actions[name] for name in sorted(self._actions))

    @property
    def bindings(self) -> tuple[ProviderBinding, ...]:
        return tuple(self._bindings[key] for key in sorted(self._bindings))

    def action(self, name: str) -> ActionSpec:
        found = self._actions.get(name) if type(name) is str else None
        if found is None:
            raise CatalogError("Unknown action")
        return found

    def binding(self, provider: str, action: str) -> ProviderBinding:
        found = None
        if type(provider) is str and type(action) is str:
            found = self._bindings.get((provider, action))
        if found is None:
            raise CatalogError("Unknown provider binding")
        return found

    def bindings_for(self, provider: str) -> tuple[ProviderBinding, ...]:
        return tuple(binding for binding in self.bindings if binding.provider == provider)

    def bound(self, provider: str, action: str) -> OperationSpec:
        spec = self.action(action)
        binding = self.binding(provider, action)
        return OperationSpec(
            binding.provider,
            spec.resource_type,
            spec.action,
            binding.provider_operation,
            binding.schema_version,
            spec.context_contract_version,
            spec.label,
            spec.arguments,
        )

    def validate_operation(
        self,
        *,
        provider: str,
        resource_type: str,
        action: str,
        provider_operation: str,
        schema_version: str | None = None,
    ) -> OperationSpec:
        spec = self.bound(provider, action)
        if (resource_type, provider_operation) != (spec.resource_type, spec.provider_operation) or (
            schema_version is not None and schema_version != spec.schema_version
        ):
            raise CatalogError("Mismatched operation contract")
        return spec

    def normalize_arguments(
        self, action: str, arguments: Mapping[str, object]
    ) -> dict[str, ScalarValue]:
        """Exact key set, exact Python type and domain membership; no coercion or defaults."""
        spec = self.action(action)
        _check(isinstance(arguments, Mapping), "Invalid arguments")
        _check(set(arguments) == spec.argument_names, "Arguments differ from action")
        result: dict[str, ScalarValue] = {}
        for argument in spec.arguments:
            value = arguments[argument.name]
            _check(
                value_in_domain(argument.cedar_type, argument.domain, value),
                "Argument outside domain",
            )
            assert isinstance(value, (str, int, bool))
            result[argument.name] = value
        return result


_REASON = ArgumentSpec(
    "reason", "String", StringDomain(frozenset({"false_positive", "remediated"}))
)
_REQUIRE_CHANGE = ArgumentSpec("require_change_at_next_sign_in", "Boolean", BooleanDomain())
PRODUCTION_ACTIONS = ActionCatalog(
    actions=(
        ActionSpec(
            "endpoint.isolate",
            "endpoint",
            "Isolate endpoint",
            (),
            "endpoint-isolation.v1",
            reversed_by="endpoint.lift_isolation",
        ),
        ActionSpec(
            "endpoint.lift_isolation",
            "endpoint",
            "Lift endpoint isolation",
            (_REASON,),
            "endpoint-recovery.v1",
            reversed_by="endpoint.isolate",
        ),
        ActionSpec(
            "identity.disable",
            "identity",
            "Disable identity",
            (),
            "identity-control.v1",
            reversed_by="identity.enable",
        ),
        ActionSpec(
            "identity.enable",
            "identity",
            "Enable identity",
            (),
            "identity-control.v1",
            reversed_by="identity.disable",
        ),
        ActionSpec(
            "identity.revoke_sessions",
            "identity",
            "Revoke identity sessions",
            (),
            "identity-control.v1",
        ),
        ActionSpec(
            "identity.reset_password",
            "identity",
            "Reset identity password",
            (_REQUIRE_CHANGE,),
            "identity-credential.v1",
        ),
    ),
    bindings=(
        ProviderBinding("mock_crowdstrike", "endpoint.isolate", "contain"),
        ProviderBinding("mock_crowdstrike", "endpoint.lift_isolation", "lift_containment"),
        ProviderBinding("mock_entra", "identity.disable", "disable"),
        ProviderBinding("mock_entra", "identity.enable", "enable"),
        ProviderBinding("mock_entra", "identity.revoke_sessions", "revoke_sessions"),
        ProviderBinding("mock_entra", "identity.reset_password", "reset_password"),
        # The first real provider. Bindings are keyed by (provider, action), so this is
        # added beside the mock's rather than replacing it: an existing frozen plan keeps
        # `provider: mock_entra` in the bytes it was frozen with, and which provider serves
        # a request follows from the account, whose connector names it.
        ProviderBinding("graph", "identity.disable", "disable"),
    ),
)


def operation(action: str) -> ActionSpec:
    """Production action spec. Callers that need the provider read a binding instead."""
    return PRODUCTION_ACTIONS.action(action)


def validate_operation(
    *,
    provider: str,
    resource_type: str,
    action: str,
    provider_operation: str,
    schema_version: str | None = None,
) -> OperationSpec:
    return PRODUCTION_ACTIONS.validate_operation(
        provider=provider,
        resource_type=resource_type,
        action=action,
        provider_operation=provider_operation,
        schema_version=schema_version,
    )
