# SPDX-License-Identifier: AGPL-3.0-only
"""Evaluation under context contracts and tenant settings (CC3, CC5, CC6, CC10)."""

from datetime import timedelta

import pytest
from context_fixtures import CATALOG, SYNTHETIC_OPERATION, SYNTHETIC_VERSION, synthetic_bundle
from test_policy_evaluation import change_fact, evaluate
from test_policy_evaluation import scenario as scenario

from execbound.policy import evaluate as evaluator
from execbound.policy.models import ContextSetting, UsageSnapshot


def setting(source_kind="inventory", max_age=300, writers=("inventory_sync",)):
    return ContextSetting(
        context_contract_version="endpoint-isolation.v1",
        source_kind=source_kind,
        max_age_seconds=max_age,
        permitted_writers=writers,
    )


@pytest.mark.parametrize(
    "max_age,effect", [(120, "DENY"), (240, "DENY"), (300, "ELIGIBLE"), (900, "ELIGIBLE")]
)
def test_bundle_max_age_bounds_frozen_validity(scenario, max_age, effect):
    bundle = scenario["bundle"].model_copy(update={"context_settings": (setting(max_age=max_age),)})
    assert evaluate(scenario, bundle=bundle).effect == effect


@pytest.mark.parametrize(
    "writers,effect", [(("soc_analyst",), "DENY"), (("incident_bot", "soc_analyst"), "ELIGIBLE")]
)
def test_incident_writer_allowlist_comes_from_bundle(scenario, writers, effect):
    resolved = change_fact(
        scenario["resolved"], "incident_status", permitted_writers=("incident_bot",)
    )
    resolved = change_fact(resolved, "incident_severity", permitted_writers=("incident_bot",))
    bundle = scenario["bundle"].model_copy(
        update={"context_settings": (setting(source_kind="incident", writers=writers),)}
    )
    assert evaluate(scenario, bundle=bundle, resolved=resolved).effect == effect


def test_longer_max_age_cannot_extend_frozen_validity(scenario):
    fact = scenario["resolved"].fact("environment")
    assert fact.valid_until == fact.observed_at + timedelta(seconds=300)
    bundle = scenario["bundle"].model_copy(
        update={
            "context_settings": (
                setting(source_kind="incident", max_age=3600, writers=("soc_analyst",)),
                setting(max_age=3600),
            )
        }
    )
    clock = type(scenario["clock"])(fact.observed_at + timedelta(seconds=301))
    result = evaluate(scenario, bundle=bundle, clock=clock)
    assert result.effect == "DENY" and result.reasons == ("INVALID_CONTEXT",)


def with_writers(resolved, source_kind, writers):
    return resolved.model_copy(
        update={
            "facts": tuple(
                f.model_copy(update={"permitted_writers": writers})
                if f.source_kind == source_kind
                else f
                for f in resolved.facts
            )
        }
    )


@pytest.mark.parametrize(
    "source_kind,writers",
    [
        ("inventory", ("inventory_sync", "inventory_sync")),
        ("incident", ("soc_analyst", "incident_bot")),
    ],
)
def test_fact_writer_tuples_must_be_canonical(scenario, source_kind, writers):
    canonical = tuple(sorted(set(writers)))
    bundle = scenario["bundle"].model_copy(
        update={"context_settings": (setting(source_kind=source_kind, writers=canonical),)}
    )
    accepted = with_writers(scenario["resolved"], source_kind, canonical)
    assert evaluate(scenario, bundle=bundle, resolved=accepted).effect == "ELIGIBLE"
    resolved = with_writers(scenario["resolved"], source_kind, writers)
    result = evaluate(scenario, bundle=bundle, resolved=resolved)
    assert result.effect == "DENY" and result.reasons == ("INVALID_CONTEXT",)


def test_unknown_contract_version_denies(scenario):
    resolved = scenario["resolved"].model_copy(update={"context_contract_version": "missing.v1"})
    bundle = scenario["bundle"].model_copy(
        update={
            "mappings": tuple(
                m.model_copy(update={"context_contract_version": "missing.v1"})
                for m in scenario["bundle"].mappings
            )
        }
    )
    result = evaluate(scenario, bundle=bundle, resolved=resolved)
    assert result.effect == "DENY" and "INVALID_CONTEXT" in result.reasons


@pytest.fixture
def synthetic(scenario):
    base = scenario["resolved"]
    template = base.fact("environment")
    facts = [
        template.model_copy(update={"name": name, "value": value, "source_version": "fact-v1"})
        for name, value in (("exposure", "internal"), ("risk_score", 70), ("edr_managed", True))
    ]
    facts.append(
        facts[0].model_copy(
            update={
                "name": "is_external",
                "value": False,
                "origin": "DERIVED",
                "dependencies": ("exposure",),
            }
        )
    )
    resolved = base.model_copy(
        update={
            "facts": tuple(facts),
            "context_contract_version": SYNTHETIC_VERSION,
            "request": base.request.model_copy(update={"operation_ref": SYNTHETIC_OPERATION}),
        }
    )
    bundle = synthetic_bundle(scenario["identity"].tenant_id, base.intent.account_id)
    usage = UsageSnapshot(
        tenant_id=scenario["identity"].tenant_id,
        principal_id=scenario["identity"].principal_id,
        bundle_id=bundle.bundle_id,
        account_id=base.intent.account_id,
        counts=(),
    )
    return {**scenario, "bundle": bundle, "resolved": resolved, "usage": usage, "catalog": CATALOG}


def run(case, **changes):
    return evaluator.evaluate(**{**case, **changes})


def test_synthetic_contract_facts_reach_cedar(synthetic):
    assert run(synthetic).effect == "ELIGIBLE"


@pytest.mark.parametrize("name,value", [("risk_score", 10), ("edr_managed", False)])
def test_synthetic_policy_denies_on_row_backed_facts(synthetic, name, value):
    assert (
        run(synthetic, resolved=change_fact(synthetic["resolved"], name, value=value)).effect
        == "DENY"
    )


def test_synthetic_derivation_must_match_and_forbid_applies(synthetic):
    external = change_fact(synthetic["resolved"], "exposure", value="external")
    assert run(synthetic, resolved=external).effect == "DENY"
    both = change_fact(external, "is_external", value=True)
    result = run(synthetic, resolved=both)
    assert result.effect == "DENY" and "NOT_AUTHORIZED" in result.reasons


def test_row_fact_must_describe_the_resolved_resource(synthetic):
    moved = change_fact(synthetic["resolved"], "risk_score", source_object_id="device-99")
    assert run(synthetic, resolved=moved).effect == "DENY"


def test_synthetic_contract_requires_the_injected_catalog(synthetic):
    assert run(synthetic, catalog=evaluator.PRODUCTION_CATALOG).effect == "DENY"
