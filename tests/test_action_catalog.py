# SPDX-License-Identifier: AGPL-3.0-only
"""Action catalog construction, bindings and argument normalization (SA1)."""

from dataclasses import replace

import pytest

from execbound.domains import BooleanDomain, IntegerDomain, StringDomain
from execbound.operations import (
    PRODUCTION_ACTIONS,
    ActionCatalog,
    ActionSpec,
    ArgumentSpec,
    CatalogError,
    OperationSpec,
    ProviderBinding,
    operation,
    validate_operation,
)

ISOLATE = PRODUCTION_ACTIONS.action("endpoint.isolate")
LIFT = PRODUCTION_ACTIONS.action("endpoint.lift_isolation")
REASON = LIFT.arguments[0]
FLAG = ArgumentSpec("flag", "Boolean", BooleanDomain())


def catalog(actions=PRODUCTION_ACTIONS.specs, bindings=PRODUCTION_ACTIONS.bindings):
    return ActionCatalog(actions, bindings)


INVALID_ACTIONS = {
    "duplicate action": (ISOLATE, ISOLATE),
    "bad action name": (replace(ISOLATE, action="Endpoint.isolate"),),
    "missing family": (replace(ISOLATE, action="isolate"),),
    "bad resource type": (replace(ISOLATE, resource_type="mailbox"),),
    "empty label": (replace(ISOLATE, label=""),),
    "bad contract version": (replace(ISOLATE, context_contract_version="Bad Version"),),
    "duplicate argument": (replace(LIFT, arguments=(REASON, REASON)),),
    "unsorted arguments": (
        replace(LIFT, arguments=(ArgumentSpec("zeta", "Boolean", BooleanDomain()), FLAG)),
    ),
    "too many arguments": (
        replace(
            LIFT,
            arguments=tuple(
                ArgumentSpec(f"a{index:02d}", "Boolean", BooleanDomain()) for index in range(17)
            ),
        ),
    ),
    "bad argument name": (
        replace(LIFT, arguments=(ArgumentSpec("Reason", "String", REASON.domain),)),
    ),
    "empty string domain": (
        replace(LIFT, arguments=(ArgumentSpec("reason", "String", StringDomain(frozenset())),)),
    ),
    "reversed long bounds": (
        replace(LIFT, arguments=(ArgumentSpec("count", "Long", IntegerDomain(5, 1)),)),
    ),
    "domain type mismatch": (
        replace(LIFT, arguments=(ArgumentSpec("flag", "Boolean", IntegerDomain(0, 1)),)),
    ),
    "unsupported cedar type": (
        replace(LIFT, arguments=(ArgumentSpec("flag", "Set", BooleanDomain()),)),
    ),
}
INVALID_BINDINGS = {
    "unknown action": ProviderBinding("mock_entra", "identity.purge", "purge"),
    "duplicate provider action": ProviderBinding("mock_entra", "identity.disable", "disable_2"),
    "duplicate provider operation": ProviderBinding(
        "mock_entra", "identity.reset_password", "disable"
    ),
    "bad provider name": ProviderBinding("Mock-Entra", "identity.disable", "disable"),
    "bad operation name": ProviderBinding("mock_okta", "identity.disable", "Disable"),
    "unsupported schema": ProviderBinding("mock_okta", "identity.disable", "disable", "action.v2"),
}


@pytest.mark.parametrize("name", sorted(INVALID_ACTIONS))
def test_invalid_action_specs_are_rejected(name):
    with pytest.raises(CatalogError):
        catalog(actions=INVALID_ACTIONS[name], bindings=())


@pytest.mark.parametrize("name", sorted(INVALID_BINDINGS))
def test_invalid_bindings_are_rejected(name):
    with pytest.raises(CatalogError):
        catalog(bindings=PRODUCTION_ACTIONS.bindings + (INVALID_BINDINGS[name],))


def test_production_catalog_contents():
    assert PRODUCTION_ACTIONS.names == {
        "endpoint.isolate",
        "endpoint.lift_isolation",
        "identity.disable",
        "identity.enable",
        "identity.revoke_sessions",
        "identity.reset_password",
    }
    assert LIFT.arguments == (
        ArgumentSpec("reason", "String", StringDomain(frozenset({"false_positive", "remediated"}))),
    )
    assert operation("identity.reset_password").arguments == (
        ArgumentSpec("require_change_at_next_sign_in", "Boolean", BooleanDomain()),
    )
    assert all(
        not operation(name).arguments
        for name in PRODUCTION_ACTIONS.names - {LIFT.action, "identity.reset_password"}
    )
    assert {(b.provider, b.action, b.provider_operation) for b in PRODUCTION_ACTIONS.bindings} == {
        ("mock_crowdstrike", "endpoint.isolate", "contain"),
        ("mock_crowdstrike", "endpoint.lift_isolation", "lift_containment"),
        ("mock_entra", "identity.disable", "disable"),
        ("mock_entra", "identity.enable", "enable"),
        ("mock_entra", "identity.revoke_sessions", "revoke_sessions"),
        ("mock_entra", "identity.reset_password", "reset_password"),
        ("graph", "identity.disable", "disable"),
    }
    assert len(PRODUCTION_ACTIONS.bindings_for("mock_entra")) == 4
    assert PRODUCTION_ACTIONS.bindings_for("mock_okta") == ()
    # The real provider is bound beside the mock for the same action, not instead of it:
    # bindings are keyed by (provider, action), the account decides which one serves a
    # request, and an existing frozen plan keeps the provider it was frozen with.
    assert len(PRODUCTION_ACTIONS.bindings_for("graph")) == 1
    assert {b.provider for b in PRODUCTION_ACTIONS.bindings if b.action == "identity.disable"} == {
        "mock_entra",
        "graph",
    }


def test_bound_operation_and_validation():
    spec = validate_operation(
        provider="mock_crowdstrike",
        resource_type="endpoint",
        action="endpoint.lift_isolation",
        provider_operation="lift_containment",
        schema_version="action.v1",
    )
    assert spec == OperationSpec(
        "mock_crowdstrike",
        "endpoint",
        "endpoint.lift_isolation",
        "lift_containment",
        "action.v1",
        "endpoint-recovery.v1",
        "Lift endpoint isolation",
        (REASON,),
    )
    assert PRODUCTION_ACTIONS.bound("mock_crowdstrike", "endpoint.lift_isolation") == spec
    for changes in (
        {"resource_type": "identity"},
        {"provider_operation": "contain"},
        {"schema_version": "action.v2"},
        {"provider": "mock_entra"},
        {"action": "endpoint.unknown"},
    ):
        values = {
            "provider": "mock_crowdstrike",
            "resource_type": "endpoint",
            "action": "endpoint.lift_isolation",
            "provider_operation": "lift_containment",
            "schema_version": "action.v1",
            **changes,
        }
        with pytest.raises(CatalogError):
            validate_operation(**values)


@pytest.mark.parametrize(
    "action,arguments",
    [
        ("endpoint.lift_isolation", {}),
        ("endpoint.lift_isolation", {"reason": "other"}),
        ("endpoint.lift_isolation", {"reason": "remediated", "extra": True}),
        ("endpoint.lift_isolation", {"reason": True}),
        ("endpoint.isolate", {"reason": "remediated"}),
        ("identity.reset_password", {"require_change_at_next_sign_in": 1}),
        ("identity.reset_password", {"require_change_at_next_sign_in": "true"}),
        ("identity.reset_password", {}),
    ],
)
def test_normalize_arguments_rejects_shape_type_and_domain_mismatches(action, arguments):
    with pytest.raises(CatalogError):
        PRODUCTION_ACTIONS.normalize_arguments(action, arguments)


def test_normalize_arguments_accepts_exact_values():
    assert PRODUCTION_ACTIONS.normalize_arguments("endpoint.isolate", {}) == {}
    assert PRODUCTION_ACTIONS.normalize_arguments(
        "endpoint.lift_isolation", {"reason": "remediated"}
    ) == {"reason": "remediated"}
    assert PRODUCTION_ACTIONS.normalize_arguments(
        "identity.reset_password", {"require_change_at_next_sign_in": False}
    ) == {"require_change_at_next_sign_in": False}


PROBE = ActionSpec(
    "endpoint.probe_test",
    "endpoint",
    "Probe endpoint (test)",
    (ArgumentSpec("depth", "Long", IntegerDomain(1, 5)),),
    "endpoint-probe.test",
)


def test_synthetic_catalog_binds_one_action_to_several_providers():
    synthetic = ActionCatalog(
        PRODUCTION_ACTIONS.specs + (PROBE,),
        PRODUCTION_ACTIONS.bindings
        + (
            ProviderBinding("mock_crowdstrike", "endpoint.probe_test", "probe"),
            ProviderBinding("mock_defender_test", "endpoint.isolate", "isolate"),
        ),
    )
    assert (
        synthetic.binding("mock_defender_test", "endpoint.isolate").provider_operation == "isolate"
    )
    assert synthetic.binding("mock_crowdstrike", "endpoint.isolate").provider_operation == "contain"
    bound = synthetic.bound("mock_defender_test", "endpoint.isolate")
    assert bound.context_contract_version == "endpoint-isolation.v1"
    assert len(synthetic.bindings_for("mock_crowdstrike")) == 3
    assert synthetic.normalize_arguments("endpoint.probe_test", {"depth": 3}) == {"depth": 3}
    for arguments in ({"depth": 0}, {"depth": 6}, {"depth": "3"}, {"depth": True}):
        with pytest.raises(CatalogError):
            synthetic.normalize_arguments("endpoint.probe_test", arguments)


def test_normalize_arguments_rejects_non_mapping_input():
    with pytest.raises(CatalogError):
        PRODUCTION_ACTIONS.normalize_arguments("endpoint.isolate", None)
    with pytest.raises(CatalogError):
        PRODUCTION_ACTIONS.normalize_arguments(
            "endpoint.lift_isolation", [("reason", "remediated")]
        )


def test_unknown_lookups_raise():
    for name in ("endpoint.unknown", 5, None):
        with pytest.raises(CatalogError):
            PRODUCTION_ACTIONS.action(name)
    with pytest.raises(CatalogError):
        PRODUCTION_ACTIONS.binding("mock_entra", "endpoint.isolate")
    with pytest.raises(CatalogError):
        PRODUCTION_ACTIONS.normalize_arguments("endpoint.unknown", {})
