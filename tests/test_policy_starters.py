# SPDX-License-Identifier: AGPL-3.0-only
"""Policy start options preserve every control and only convert reviewed legacy policy."""

import importlib.util
import json
from importlib import resources
from uuid import uuid4

import pytest

from execbound.contracts import PRODUCTION_CATALOG
from execbound.policy.models import ContextSetting, LimitRule, QuorumRule
from execbound.policy.rulesets import compile_ruleset
from execbound.surfaces.console_api import policy_starters
from execbound.surfaces.console_api.policy import CreateBundle
from execbound.surfaces.console_api.policy_starters import editable_copy, first_policy, source_rules
from execbound_harness.demo import ENDPOINT_RULESET, endpoint_bundle
from execbound_harness.fixtures import ENDPOINT_PROVIDER, IDENTITY_PROVIDER, combined_bundle
from execbound_harness.identity_demo import IDENTITY_RULESET, identity_bundle
from execbound_harness.soc_demo import SOC_RULESET, soc_bundle


def packs():
    tenant, endpoint, identity = uuid4(), uuid4(), uuid4()
    return [
        (endpoint_bundle(tenant, endpoint, mapping_version="map-v1"), ENDPOINT_RULESET.rules),
        (identity_bundle(tenant, identity, mapping_version="map-v1"), IDENTITY_RULESET.rules),
        (soc_bundle(tenant, endpoint, identity, mapping_version="map-v1"), SOC_RULESET.rules),
        (
            combined_bundle(
                "starter",
                tenant,
                {ENDPOINT_PROVIDER: str(endpoint), IDENTITY_PROVIDER: str(identity)},
            ),
            ENDPOINT_RULESET.rules + IDENTITY_RULESET.rules,
        ),
    ]


@pytest.mark.parametrize("base,expected", packs())
def test_only_the_reviewed_pack_sources_are_offered_as_rules(base, expected):
    source = source_rules(base, PRODUCTION_CATALOG)
    assert source is not None
    assert source.rules == expected
    converted = editable_copy(base, PRODUCTION_CATALOG)
    assert converted is not None and converted.bundle_id != base.bundle_id
    assert converted.mappings == base.mappings
    assert converted.limits == base.limits
    assert converted.context_settings == base.context_settings
    compiled = compile_ruleset(source, base.mappings)
    assert converted.authorization_policies == compiled.authorization_policies
    assert converted.approval_policies == compiled.approval_policies


@pytest.mark.parametrize("field", ["authorization_policies", "approval_policies", "cedar_schema"])
def test_a_modified_legacy_policy_is_never_silently_translated(field):
    base = packs()[0][0]
    changed = base.model_copy(update={field: getattr(base, field) + " "})
    assert source_rules(changed, PRODUCTION_CATALOG) is None
    assert editable_copy(changed, PRODUCTION_CATALOG) is None


def test_copy_preserves_placement_context_and_advanced_limits():
    base = packs()[0][0]
    base = base.model_copy(
        update={
            "mappings": tuple(
                m.model_copy(update={"external_executor": True}) for m in base.mappings
            ),
            "limits": (
                LimitRule(
                    rule_id="group-limit",
                    action="endpoint.isolate",
                    scope="group",
                    group_id=uuid4(),
                    actions=("endpoint.isolate",),
                    window_seconds=61,
                    max_targets=4,
                    budget="total",
                    on_exceed="DENY",
                ),
            ),
            "context_settings": (
                ContextSetting(
                    context_contract_version="endpoint-isolation.v1",
                    source_kind="inventory",
                    max_age_seconds=60,
                    permitted_writers=("inventory_sync",),
                ),
            ),
        }
    )
    copied = editable_copy(base, PRODUCTION_CATALOG)
    assert copied is not None
    assert copied.mappings == base.mappings
    assert copied.limits == copied.ruleset.budgets == base.limits
    assert copied.context_settings == base.context_settings


def test_custom_legacy_quorum_and_extra_mappings_refuse_conversion():
    base = packs()[0][0]
    changed = base.model_copy(
        update={"quorum": (QuorumRule(rule_id="custom", obligation="policy:policy0", required=2),)}
    )
    assert editable_copy(changed, PRODUCTION_CATALOG) is None
    changed = base.model_copy(update={"mappings": ()})
    assert editable_copy(changed, PRODUCTION_CATALOG) is None


def test_review_all_adds_obligations_without_replacing_original_controls():
    base = editable_copy(packs()[2][0], PRODUCTION_CATALOG)
    assert base is not None and base.ruleset is not None
    reviewed = editable_copy(base, PRODUCTION_CATALOG, review_all=True)
    assert reviewed is not None and reviewed.ruleset is not None
    assert reviewed.ruleset.rules[: len(base.ruleset.rules)] == base.ruleset.rules
    added = reviewed.ruleset.rules[len(base.ruleset.rules) :]
    assert {rule.action for rule in added} == {m.operation_ref for m in base.mappings}
    assert all(rule.effect == "REVIEW" and not rule.when for rule in added)
    assert reviewed.limits == base.limits


def test_review_all_retains_quorum_bound_to_existing_typed_rules():
    from execbound.policy.rulesets import ruleset_bundle

    base = packs()[0][0]
    ruleset = ENDPOINT_RULESET.model_copy(
        update={
            "rules": tuple(
                rule.model_copy(update={"quorum": 3}) if rule.effect == "REVIEW" else rule
                for rule in ENDPOINT_RULESET.rules
            ),
        }
    )
    base = ruleset_bundle(
        ruleset, tenant_id=base.tenant_id, bundle_id=base.bundle_id, mappings=base.mappings
    )
    reviewed = editable_copy(base, PRODUCTION_CATALOG, review_all=True)
    assert reviewed is not None and reviewed.ruleset is not None
    assert any(rule.required == 3 for rule in reviewed.quorum)
    assert (
        next(
            rule for rule in reviewed.ruleset.rules if rule.id == "isolate-production-needs-review"
        ).quorum
        == 3
    )


def test_a_ruleset_with_mismatched_compiled_policy_is_not_repaired_by_conversion():
    base = editable_copy(packs()[0][0], PRODUCTION_CATALOG)
    assert base is not None
    changed = base.model_copy(
        update={"authorization_policies": "forbid(principal, action, resource);"}
    )
    assert editable_copy(changed, PRODUCTION_CATALOG) is None


def test_first_policy_only_reaches_configured_actions_and_has_reviewed_controls():
    base = packs()[0][0]
    starter = first_policy(base.tenant_id, base.mappings, PRODUCTION_CATALOG)
    assert starter.mappings == base.mappings and starter.ruleset is not None
    assert starter.ruleset.rules == ENDPOINT_RULESET.rules
    assert {limit.action for limit in starter.limits} == {"endpoint.isolate"}
    assert len(starter.limits) == 2
    with pytest.raises(ValueError):
        first_policy(base.tenant_id, (), PRODUCTION_CATALOG)


@pytest.mark.parametrize(
    "body",
    [
        {"source": "template"},
        {"source": "active", "template": "review-all"},
        {"source": "bundle"},
        {"source": "document", "document": "{}", "bundle_id": str(uuid4())},
    ],
)
def test_starter_body_fields_cannot_be_silently_ignored(body):
    with pytest.raises(ValueError):
        CreateBundle.model_validate(body)


def test_existing_bundle_copy_is_accepted_by_the_strict_json_body_guard():
    identifier = str(uuid4())
    copied = CreateBundle.model_validate({"source": "bundle", "bundle_id": identifier}, strict=True)
    assert copied.bundle_id == identifier
    with pytest.raises(ValueError):
        CreateBundle.model_validate({"source": "bundle", "bundle_id": "not-a-uuid"}, strict=True)


def test_a_starter_over_a_ref_that_is_not_its_action_names_the_catalog_action():
    """The starters speak about actions; a mapping's ref is the operator's name for one."""
    base = packs()[0][0]
    custom = base.mappings[0].model_copy(
        update={"operation_ref": "isolate.corroborated", "action": "endpoint.isolate"}
    )
    starter = first_policy(base.tenant_id, (custom,), PRODUCTION_CATALOG)
    assert starter.mappings == (custom,) and starter.ruleset is not None
    assert starter.ruleset.rules == ENDPOINT_RULESET.rules
    assert {limit.action for limit in starter.limits} == {"endpoint.isolate"}
    assert compile_ruleset(starter.ruleset, starter.mappings).authorization_policies == (
        starter.authorization_policies
    )
    reviewed = editable_copy(starter, PRODUCTION_CATALOG, review_all=True)
    assert reviewed is not None and reviewed.ruleset is not None
    added = reviewed.ruleset.rules[len(starter.ruleset.rules) :]
    assert [(rule.action, rule.effect) for rule in added] == [("endpoint.isolate", "REVIEW")]
    # Two refs for one action add one review of that action, not two.
    both = first_policy(base.tenant_id, (*base.mappings, custom), PRODUCTION_CATALOG)
    reviewed = editable_copy(both, PRODUCTION_CATALOG, review_all=True)
    assert reviewed is not None and reviewed.ruleset is not None
    added = reviewed.ruleset.rules[len(both.ruleset.rules) :]
    assert [(rule.action, rule.effect) for rule in added] == [("endpoint.isolate", "REVIEW")]


def test_the_starter_packs_are_apache_data_read_from_the_package():
    """The packs are data under their own Apache-2.0 `LICENSE`, read from the installed package,
    so whoever copies them into their own policy has the licence beside them (#496). The module
    that held them as Python is gone."""
    starters = resources.files("execbound.data").joinpath("starters")
    licence = starters.joinpath("LICENSE").read_text(encoding="utf-8").splitlines()
    assert licence[1] == "SPDX-License-Identifier: Apache-2.0"
    rules = json.loads(starters.joinpath("rules.json").read_text(encoding="utf-8"))
    packs = json.loads(starters.joinpath("packs.json").read_text(encoding="utf-8"))
    assert (policy_starters.RULES, policy_starters.PACKS) == (rules, packs)
    assert sorted(packs) == ["combined", "endpoint", "identity", "soc"]
    assert importlib.util.find_spec("execbound.surfaces.console_api.policy_starter_data") is None
