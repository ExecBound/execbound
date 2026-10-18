# SPDX-License-Identifier: AGPL-3.0-only
"""The SOC pack validates under Cedar and maps every production action once."""

import json
from uuid import uuid4

import pytest
from test_execution import world as world
from test_resolution import registry as registry

from execbound.operations import PRODUCTION_ACTIONS
from execbound.policy.cedar import validate_policy_sets
from execbound.policy.models import LimitRule
from execbound.policy.store import PolicyStoreError, create_bundle, validate_bundle
from execbound_harness.soc_demo import (
    APPROVAL,
    AUTHORIZATION,
    CEDAR_SCHEMA,
    SOC_ACTIONS,
    soc_bundle,
)


def test_soc_pack_validates_under_cedar():
    validate_policy_sets(schema=CEDAR_SCHEMA, authorization=AUTHORIZATION, approval=APPROVAL)


def test_soc_bundle_maps_every_production_action_once():
    endpoint, identity = uuid4(), uuid4()
    bundle = soc_bundle(uuid4(), endpoint, identity, mapping_version="map-v1")
    assert len(SOC_ACTIONS) == len(set(SOC_ACTIONS))
    assert set(SOC_ACTIONS) == PRODUCTION_ACTIONS.names
    assert {mapping.operation_ref for mapping in bundle.mappings} == PRODUCTION_ACTIONS.names
    for mapping in bundle.mappings:
        spec = PRODUCTION_ACTIONS.action(mapping.operation_ref)
        assert mapping.context_contract_version == spec.context_contract_version
        assert mapping.account_id == (endpoint if spec.resource_type == "endpoint" else identity)
    assert len(bundle.limits) == 12
    assert {
        (
            rule.action,
            rule.scope,
            rule.budget,
            rule.on_exceed,
            rule.window_seconds,
            rule.max_targets,
        )
        for rule in bundle.limits
    } == {
        (action, *authority)
        for action in SOC_ACTIONS
        for authority in (
            ("principal", "autonomous", "REQUIRE_APPROVAL", 3600, 10),
            ("tenant", "total", "DENY", 900, 20),
        )
    }


def test_every_soc_action_is_policed():
    for action in SOC_ACTIONS:
        head = f'action == ExecBound::Action::"{action}"'
        assert head in AUTHORIZATION
        assert head in APPROVAL


def test_soc_schema_declares_argument_contexts():
    actions = json.loads(CEDAR_SCHEMA)["ExecBound"]["actions"]
    contexts = {
        name: value["appliesTo"]["context"]["attributes"] for name, value in actions.items()
    }
    assert contexts["endpoint.lift_isolation"] == {
        "arguments": {"type": "Record", "attributes": {"reason": {"type": "String"}}}
    }
    assert contexts["identity.reset_password"] == {
        "arguments": {
            "type": "Record",
            "attributes": {"require_change_at_next_sign_in": {"type": "Boolean"}},
        }
    }
    assert all(
        contexts[name] == {}
        for name in (
            "endpoint.isolate",
            "identity.disable",
            "identity.enable",
            "identity.revoke_sessions",
        )
    )
    assert actions["endpoint.lift_isolation"]["appliesTo"]["resourceTypes"] == ["Endpoint"]
    assert actions["identity.reset_password"]["appliesTo"]["resourceTypes"] == ["Identity"]


def test_limit_rule_for_unknown_action_fails_bundle_validation(db, world):
    extra = LimitRule(
        rule_id="tenant-total-restore",
        action="endpoint.restore",
        scope="tenant",
        window_seconds=900,
        max_targets=20,
        budget="total",
        on_exceed="DENY",
    )
    bundle = world["bundle"].model_copy(
        update={"bundle_id": uuid4(), "limits": world["bundle"].limits + (extra,)}
    )
    create_bundle(db, world["admin"], bundle, world["clock"])
    with pytest.raises(PolicyStoreError) as failure:
        validate_bundle(db, world["admin"], bundle.bundle_id, world["clock"])
    assert failure.value.code == "INVALID_COMPONENT"
