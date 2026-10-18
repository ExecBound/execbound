# SPDX-License-Identifier: AGPL-3.0-only
from uuid import UUID, uuid4

import pytest
from pydantic import ValidationError

from execbound.policy.models import (
    BundleContent,
    ContextSetting,
    LimitRule,
    MappingRef,
    ProjectedUsage,
    UsageSnapshot,
)

ORIGINAL_MAPPING_KEYS = {
    "operation_ref",
    "account_id",
    "mapping_version",
    "schema_version",
    "context_contract_version",
}
ORIGINAL_RULE_KEYS = {
    "rule_id",
    "action",
    "scope",
    "window_seconds",
    "max_targets",
    "budget",
    "on_exceed",
}


def rule(**changes):
    return {
        "rule_id": "principal-isolation",
        "action": "endpoint.isolate",
        "scope": "principal",
        "window_seconds": 3600,
        "max_targets": 10,
        "budget": "autonomous",
        "on_exceed": "REQUIRE_APPROVAL",
        **changes,
    }


def content(**changes):
    return {
        "tenant_id": uuid4(),
        "bundle_id": uuid4(),
        "cedar_schema": "schema",
        "authorization_policies": "permit(principal, action, resource);",
        "approval_policies": "",
        "mappings": (
            {
                "operation_ref": "endpoint.isolate",
                "account_id": uuid4(),
                "mapping_version": "map-v1",
                "schema_version": "action.v1",
                "context_contract_version": "endpoint-isolation.v1",
            },
        ),
        "limits": (LimitRule(**rule()),),
        **changes,
    }


@pytest.mark.parametrize(
    "field", ["cedar_schema", "authorization_policies", "approval_policies", "mappings", "limits"]
)
def test_bundle_components_must_be_explicit(field):
    data = content()
    del data[field]
    with pytest.raises(ValidationError):
        BundleContent(**data)


@pytest.mark.parametrize("field", ["window_seconds", "max_targets"])
@pytest.mark.parametrize("value", [0, -1, True, 1.0, "10", 2**63])
def test_limit_rejects_invalid_integer(field, value):
    with pytest.raises(ValidationError):
        LimitRule(**rule(**{field: value}))


@pytest.mark.parametrize(
    "changes",
    [
        {"scope": "run"},
        {"budget": "daily"},
        {"on_exceed": "ALLOW"},
        {"selector": "production"},
        {"scope": "group"},
        {"scope": "account"},
        {"scope": "selector"},
        {"group_id": uuid4()},
        {"account_id": uuid4()},
        {"selector": {"fact": "environment", "equals": "production"}},
        {"scope": "group", "group_id": uuid4(), "account_id": uuid4()},
        {"scope": "group", "group_id": str(uuid4())},
        {"scope": "selector", "selector": {"fact": "environment", "equals": 1.5}},
        {"scope": "selector", "selector": {"fact": "environment", "equals": None}},
        {"scope": "selector", "selector": {"fact": "environment", "equals": ""}},
        {"scope": "selector", "selector": {"fact": "environment", "equals": "x" * 255}},
        {"scope": "selector", "selector": {"fact": "criticality", "equals": 2**63}},
        {"scope": "selector", "selector": {"fact": "Environment", "equals": "production"}},
        {"scope": "selector", "selector": {"fact": "environment"}},
        {"actions": ()},
        {"actions": ("identity.disable",)},
        {"actions": ("endpoint.isolate",) * 2},
        {"actions": ("endpoint.isolate",) + tuple(f"endpoint.step_{c}" for c in "abcdefgh")},
        {"actions": ["endpoint.isolate"]},
        {"actions": ("endpoint.isolate", "Endpoint.Isolate")},
    ],
)
def test_limit_rejects_unsupported_authority(changes):
    with pytest.raises(ValidationError):
        LimitRule(**rule(**changes))


def selector(fact, equals):
    return {"scope": "selector", "selector": {"fact": fact, "equals": equals}}


def test_scoped_rules_serialize_only_their_qualifiers():
    group, account = uuid4(), uuid4()
    grouped = LimitRule(**rule(scope="group", group_id=group)).model_dump(mode="json")
    assert grouped["group_id"] == str(group)
    assert set(grouped) == ORIGINAL_RULE_KEYS | {"group_id"}
    scoped = LimitRule(**rule(scope="account", account_id=account)).model_dump(mode="json")
    assert set(scoped) == ORIGINAL_RULE_KEYS | {"account_id"}
    selected = LimitRule(**rule(**selector("environment", "production"))).model_dump(mode="json")
    assert set(selected) == ORIGINAL_RULE_KEYS | {"selector"}
    assert selected["selector"] == {"fact": "environment", "equals": "production"}
    multi = LimitRule(**rule(actions=("endpoint.isolate", "endpoint.lift_isolation")))
    assert set(multi.model_dump(mode="json")) == ORIGINAL_RULE_KEYS | {"actions"}
    plain = LimitRule(**rule())
    assert set(plain.model_dump(mode="json")) == set(plain.model_dump()) == ORIGINAL_RULE_KEYS
    assert "actions" not in plain.model_dump_json()


def test_absent_qualifiers_keep_existing_bundle_bytes():
    # The literal bytes an unqualified rule serialized to before scopes existed; a
    # qualifier that leaked into the dump would change every retained content hash.
    assert LimitRule(**rule()).model_dump_json() == (
        '{"rule_id":"principal-isolation","action":"endpoint.isolate","scope":"principal",'
        '"window_seconds":3600,"max_targets":10,"budget":"autonomous",'
        '"on_exceed":"REQUIRE_APPROVAL"}'
    )
    values = content(
        limits=(LimitRule(**rule()), LimitRule(**rule(rule_id="tenant-isolation", scope="tenant")))
    )
    bundle = BundleContent(**values)
    rebuilt = BundleContent(
        **{
            **values,
            "limits": tuple(LimitRule.model_validate(item.model_dump()) for item in bundle.limits),
        }
    )
    assert rebuilt == bundle and rebuilt.content_hash == bundle.content_hash
    assert rebuilt.security_versions == bundle.security_versions
    scoped = BundleContent(
        **{
            **values,
            "limits": bundle.limits
            + (LimitRule(**rule(rule_id="group-isolation", scope="group", group_id=uuid4())),),
        }
    )
    assert scoped.security_versions.limits != bundle.security_versions.limits
    assert scoped.content_hash != bundle.content_hash
    unqualified = [item for item in scoped.limits if item.scope != "group"]
    assert [item.model_dump(mode="json") for item in unqualified] == [
        item.model_dump(mode="json") for item in bundle.limits
    ]
    restored = BundleContent.model_validate_json(scoped.model_dump_json())
    assert restored == scoped and restored.content_hash == scoped.content_hash


def test_actions_are_sorted_and_action_names_defaults_to_action():
    plain = LimitRule(**rule())
    assert plain.actions is None and plain.action_names == ("endpoint.isolate",)
    multi = LimitRule(**rule(actions=("endpoint.lift_isolation", "endpoint.isolate")))
    assert multi.actions == ("endpoint.isolate", "endpoint.lift_isolation")
    assert multi.action_names == multi.actions
    reordered = LimitRule(**rule(actions=("endpoint.isolate", "endpoint.lift_isolation")))
    assert reordered.model_dump_json() == multi.model_dump_json()


GROUP, ACCOUNT, OTHER = UUID(int=1), UUID(int=2), UUID(int=3)
FACTS = {"environment": "production", "criticality": 1, "is_production": True}
PAIR = {"actions": ("endpoint.isolate", "endpoint.lift_isolation")}


@pytest.mark.parametrize(
    "changes,candidate,expected",
    [
        ({}, {}, True),
        ({}, {"action": "endpoint.lift_isolation"}, False),
        ({"scope": "tenant"}, {"account_id": OTHER, "groups": ()}, True),
        ({"scope": "tenant"}, {"action": "identity.disable"}, False),
        (PAIR, {"action": "endpoint.lift_isolation"}, True),
        (PAIR, {"action": "identity.disable"}, False),
        ({**PAIR, "scope": "tenant"}, {"action": "endpoint.lift_isolation", "groups": ()}, True),
        ({"scope": "group", "group_id": GROUP}, {}, True),
        ({"scope": "group", "group_id": GROUP}, {"groups": (OTHER, GROUP)}, True),
        ({"scope": "group", "group_id": GROUP}, {"groups": (OTHER,)}, False),
        ({"scope": "group", "group_id": GROUP}, {"groups": ()}, False),
        ({"scope": "group", "group_id": GROUP}, {"action": "endpoint.lift_isolation"}, False),
        ({"scope": "account", "account_id": ACCOUNT}, {}, True),
        ({"scope": "account", "account_id": ACCOUNT}, {"account_id": OTHER}, False),
        ({"scope": "account", "account_id": ACCOUNT}, {"action": "identity.disable"}, False),
        (selector("environment", "production"), {}, True),
        (selector("environment", "staging"), {}, False),
        (selector("environment", "production"), {"facts": {}}, False),
        (selector("environment", "production"), {"action": "endpoint.lift_isolation"}, False),
        (selector("criticality", 1), {}, True),
        (selector("criticality", True), {}, False),
        (selector("is_production", 1), {}, False),
        (selector("is_production", True), {}, True),
        (selector("criticality", 0), {"facts": {"criticality": False}}, False),
        (selector("exposure", "internal"), {}, False),
    ],
)
def test_applies_to_covers_every_scope(changes, candidate, expected):
    attributes = {
        "action": "endpoint.isolate",
        "account_id": ACCOUNT,
        "groups": (GROUP,),
        "facts": FACTS,
        **candidate,
    }
    assert LimitRule(**rule(**changes)).applies_to(**attributes) is expected


def test_usage_snapshot_requires_account_and_sorts_groups():
    values = dict(tenant_id=uuid4(), principal_id=uuid4(), bundle_id=uuid4(), counts=())
    with pytest.raises(ValidationError):
        UsageSnapshot(**values)
    with pytest.raises(ValidationError):
        UsageSnapshot(**values, account_id=str(uuid4()))
    assert UsageSnapshot(**values, account_id=uuid4()).groups == ()
    low, high = UUID(int=10), UUID(int=11)
    assert UsageSnapshot(**values, account_id=uuid4(), groups=(high, low)).groups == (low, high)
    with pytest.raises(ValidationError):
        UsageSnapshot(**values, account_id=uuid4(), groups=(low, low))
    with pytest.raises(ValidationError):
        UsageSnapshot(**values, account_id=uuid4(), groups=[low])
    with pytest.raises(ValidationError):
        UsageSnapshot(**values, account_id=uuid4(), groups=tuple(UUID(int=i) for i in range(1, 66)))


def test_bundle_and_nested_limits_are_immutable_and_digest_bound():
    bundle = BundleContent(**content())
    restored = BundleContent.model_validate_json(bundle.model_dump_json())
    assert restored == bundle and restored.content_hash == bundle.content_hash
    with pytest.raises(ValidationError):
        bundle.limits[0].max_targets = 99
    with pytest.raises(ValidationError):
        bundle.approval_policies = "permit(principal, action, resource);"
    changed = BundleContent(
        **{**bundle.model_dump(), "approval_policies": "permit(principal, action, resource);"}
    )
    assert changed.content_hash != bundle.content_hash
    assert changed.security_versions.approval != bundle.security_versions.approval


def test_bundle_rejects_duplicate_rule_and_mapping_identity():
    with pytest.raises(ValidationError):
        BundleContent(**content(limits=(LimitRule(**rule()), LimitRule(**rule(max_targets=20)))))
    data = content()
    data["mappings"] *= 2
    with pytest.raises(ValidationError):
        BundleContent(**data)


def test_mapping_placements_are_exclusive():
    fields = content()["mappings"][0]
    assert MappingRef(**fields).observe_only is False
    assert MappingRef(**fields).external_executor is False
    assert MappingRef(**fields, observe_only=True).external_executor is False
    assert MappingRef(**fields, external_executor=True).observe_only is False
    # Observing reserves nothing and a checkpoint reserves everything a dispatch does; an
    # operation claiming both placements has none, so the content cannot be built at all.
    with pytest.raises(ValidationError):
        MappingRef(**fields, observe_only=True, external_executor=True)
    with pytest.raises(ValidationError):
        BundleContent(
            **content(mappings=({**fields, "observe_only": True, "external_executor": True},))
        )


def test_external_executor_serializes_only_when_set():
    fields = content()["mappings"][0]
    plain = MappingRef(**fields)
    assert set(plain.model_dump(mode="json")) == set(plain.model_dump()) == ORIGINAL_MAPPING_KEYS
    assert "external_executor" not in plain.model_dump_json()
    flagged = MappingRef(**fields, external_executor=True)
    dumped = flagged.model_dump(mode="json")
    assert set(dumped) == ORIGINAL_MAPPING_KEYS | {"external_executor"}
    assert dumped["external_executor"] is True
    assert MappingRef.model_validate_json(flagged.model_dump_json()) == flagged


def test_absent_external_executor_keeps_existing_bundle_bytes():
    # The literal bytes a mapping serialized to before checkpoints existed; a flag that
    # leaked into the dump would change every retained content hash and plan hash.
    account = uuid4()
    fields = {**content()["mappings"][0], "account_id": account}
    assert MappingRef(**fields).model_dump_json() == (
        '{"operation_ref":"endpoint.isolate",'
        f'"account_id":"{account}",'
        '"mapping_version":"map-v1","schema_version":"action.v1",'
        '"context_contract_version":"endpoint-isolation.v1"}'
    )
    values = content(mappings=(fields,))
    bundle = BundleContent(**values)
    rebuilt = BundleContent(
        **{**values, "mappings": tuple(item.model_dump() for item in bundle.mappings)}
    )
    assert rebuilt == bundle and rebuilt.content_hash == bundle.content_hash
    assert rebuilt.security_versions == bundle.security_versions
    flagged = BundleContent(**content(mappings=({**fields, "external_executor": True},)))
    assert flagged.content_hash != bundle.content_hash
    assert flagged.security_versions.bundle != bundle.security_versions.bundle
    # Nothing else moves: only the bundle digest covers a mapping.
    assert flagged.security_versions.limits == bundle.security_versions.limits
    restored = BundleContent.model_validate_json(flagged.model_dump_json())
    assert restored == flagged and restored.content_hash == flagged.content_hash
    assert restored.mappings[0].external_executor is True


def test_a_mapping_names_its_action_only_when_its_ref_is_another_name():
    """`mapping-create --ref` lets a ref differ from its action; the bundle can now say so.

    Absent, the ref is the action and the mapping serializes to the bytes it always did, so
    every retained bundle keeps its content hash. One spelling per meaning: a ref that is its
    own action does not also name it.
    """
    fields = content()["mappings"][0]
    plain = MappingRef(**fields)
    assert plain.action is None and plain.action_name == "endpoint.isolate"
    assert set(plain.model_dump(mode="json")) == set(plain.model_dump()) == ORIGINAL_MAPPING_KEYS
    assert '"action"' not in plain.model_dump_json()
    custom = MappingRef(
        **{**fields, "operation_ref": "isolate.corroborated"}, action="endpoint.isolate"
    )
    assert custom.action_name == "endpoint.isolate"
    assert custom.model_dump(mode="json")["action"] == "endpoint.isolate"
    assert MappingRef.model_validate_json(custom.model_dump_json()) == custom
    with pytest.raises(ValidationError):
        MappingRef(**fields, action="endpoint.isolate")
    with pytest.raises(ValidationError):
        MappingRef(**{**fields, "operation_ref": "isolate.corroborated"}, action="Isolate!")
    values = content(mappings=(fields,))
    bundle = BundleContent(**values)
    named = BundleContent(
        **content(
            mappings=(
                {**fields, "operation_ref": "isolate.corroborated", "action": "endpoint.isolate"},
            )
        )
    )
    assert named.content_hash != bundle.content_hash
    restored = BundleContent.model_validate_json(named.model_dump_json())
    assert restored == named and restored.content_hash == named.content_hash


def test_bundle_limit_order_has_stable_digest():
    data = content(
        limits=(LimitRule(**rule(rule_id="z-last")), LimitRule(**rule(rule_id="a-first")))
    )
    first = BundleContent(**data)
    second = BundleContent(**{**data, "limits": tuple(reversed(data["limits"]))})
    assert first.content_hash == second.content_hash


def test_empty_approval_is_explicit_and_empty_mappings_are_invalid():
    assert BundleContent(**content()).approval_policies == ""
    with pytest.raises(ValidationError):
        BundleContent(**content(mappings=()))


def test_bundle_text_limits_count_utf8_bytes():
    with pytest.raises(ValidationError):
        BundleContent(**content(cedar_schema="🙂" * 20000))


@pytest.mark.parametrize("value", [True, -1, 1.5, "1", 2**63])
def test_usage_counts_are_strict_and_nonnegative(value):
    with pytest.raises(ValidationError):
        ProjectedUsage(rule_id="limit", confirmed_targets=value, unresolved_targets=0)


def test_usage_cannot_duplicate_a_rule():
    count = ProjectedUsage(rule_id="limit", confirmed_targets=0, unresolved_targets=1)
    with pytest.raises(ValidationError):
        UsageSnapshot(
            tenant_id=uuid4(),
            principal_id=uuid4(),
            bundle_id=uuid4(),
            account_id=uuid4(),
            counts=(count, count),
        )


def setting(**changes):
    return {
        "context_contract_version": "endpoint-isolation.v1",
        "source_kind": "inventory",
        "max_age_seconds": 600,
        "permitted_writers": ("inventory_sync",),
        **changes,
    }


def test_absent_context_settings_keep_existing_bundle_bytes():
    values = content()
    bundle = BundleContent.model_validate(values)
    assert "context_settings" not in bundle.model_dump(mode="json")
    explicit = BundleContent.model_validate({**values, "context_settings": None})
    assert bundle.content_hash == explicit.content_hash


def test_context_settings_are_canonical_and_part_of_the_digest():
    values = content()
    incident = setting(source_kind="incident", permitted_writers=("soc_analyst",))
    first = BundleContent.model_validate({**values, "context_settings": (incident, setting())})
    second = BundleContent.model_validate({**values, "context_settings": (setting(), incident)})
    assert first.context_settings == second.context_settings
    assert first.content_hash == second.content_hash
    assert first.content_hash != BundleContent.model_validate(values).content_hash


@pytest.mark.parametrize(
    "changes",
    [
        {"max_age_seconds": 0},
        {"max_age_seconds": 86401},
        {"max_age_seconds": True},
        {"permitted_writers": ()},
        {"permitted_writers": ("inventory_sync", "inventory_sync")},
        {"permitted_writers": ("Inventory",)},
        {"source_kind": "cmdb"},
        {"context_contract_version": "Bad Version"},
    ],
)
def test_context_setting_rejects_invalid_values(changes):
    with pytest.raises(ValidationError):
        ContextSetting.model_validate(setting(**changes))


@pytest.mark.parametrize("settings", [(), (setting(), setting(max_age_seconds=900))])
def test_bundle_rejects_empty_or_duplicate_context_settings(settings):
    with pytest.raises(ValidationError):
        BundleContent.model_validate(content(context_settings=settings))


def test_writer_order_is_canonical():
    value = ContextSetting.model_validate(setting(permitted_writers=("zeta_sync", "alpha_sync")))
    assert value.permitted_writers == ("alpha_sync", "zeta_sync")
