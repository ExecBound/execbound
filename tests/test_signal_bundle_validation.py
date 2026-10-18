# SPDX-License-Identifier: AGPL-3.0-only
"""Validation and activation of signal_mappings (docs/SIGNALS.md, "Map its verdicts")."""

from uuid import uuid4

import pytest
from signal_fixtures import (
    CAPABILITY,
    MDE_THRESHOLDS,
    SIGNAL_RULES,
    V2,
    default_space,
    insert_source,
    move_to_v2,
    register,
    signal_bundle,
)
from sqlalchemy import text
from test_execution import world as world
from test_migration_without_bypass import fenced
from test_resolution import registry as registry

from execbound.contracts import PRODUCTION_CATALOG
from execbound.policy import store
from execbound.policy.models import MappingRef, Ruleset
from execbound.policy.rulesets import ruleset_bundle
from execbound.policy.store import (
    PolicyStoreError,
    activate_bundle,
    activate_new_bundle,
    create_bundle,
    validate_bundle,
)
from execbound.signals.capabilities import RESOURCE_COMPROMISE_V1, Capability
from execbound.signals.models import SignalMapping, SignalThreshold
from execbound.surfaces.console_api.policy_starters import editable_copy


@pytest.fixture
def v2(world, admin_engine):
    move_to_v2(admin_engine, world["identity"].tenant_id)
    return world


def validated(db, world, bundle, space=None):
    # With a second space in the tenant a draft must name its owner (`create_bundle` places
    # it in the tenant's only space otherwise), so the cross-space test passes one.
    create_bundle(db, world["admin"], bundle, world["clock"], space=space)
    return validate_bundle(db, world["admin"], bundle.bundle_id, world["clock"])


def refused_at(db, world, bundle, space=None):
    with pytest.raises(PolicyStoreError) as caught:
        validated(db, world, bundle, space)
    assert caught.value.code == "INVALID_COMPONENT"
    return caught.value.location


def test_a_well_formed_mapping_validates_and_activates(db, v2, admin_engine, tmp_path):
    source, _ = register(admin_engine, v2, tmp_path / "t")
    bundle = signal_bundle(v2["identity"].tenant_id, v2["account"], (source,))
    assert validated(db, v2, bundle).state == "VALIDATED"
    assert activate_bundle(db, v2["admin"], bundle.bundle_id, v2["clock"]).state == "ACTIVE"


def test_a_v2_bundle_without_its_entry_is_refused(db, v2):
    bundle = signal_bundle(v2["identity"].tenant_id, v2["account"], (uuid4(),), signal_mappings=())
    assert refused_at(db, v2, bundle) == "signal_mappings"


def test_an_unknown_or_revoked_source_is_refused_where_it_is_named(db, v2, admin_engine, tmp_path):
    assert (
        refused_at(db, v2, signal_bundle(v2["identity"].tenant_id, v2["account"], (uuid4(),)))
        == "signal_mappings.0.admitted_sources.0"
    )
    source, _ = register(admin_engine, v2, tmp_path / "t")
    with admin_engine.begin() as conn:
        fenced(conn, v2["identity"].tenant_id)
        conn.execute(
            text(
                "UPDATE execbound.signal_sources SET active = false, revoked_at = now(), "
                "revoked_by = created_by WHERE source_id = :s"
            ),
            {"s": source},
        )
    bundle = signal_bundle(v2["identity"].tenant_id, v2["account"], (source,))
    assert refused_at(db, v2, bundle) == "signal_mappings.0.admitted_sources.0"


def test_a_source_of_another_tenant_is_refused_as_an_unknown_one_is(db, v2, admin_engine, seeded):
    tenant, other = v2["identity"].tenant_id, seeded["tenants"][1]
    assert other != tenant
    with admin_engine.begin() as conn:
        fenced(conn, other)
        foreign, _ = insert_source(conn, other, seeded["principals"][1], v2["clock"].now())
    bundle = signal_bundle(tenant, v2["account"], (foreign,))
    assert refused_at(db, v2, bundle) == "signal_mappings.0.admitted_sources.0"


def test_a_deactivated_source_is_refused_where_it_is_named(db, v2, admin_engine, tmp_path):
    source, _ = register(admin_engine, v2, tmp_path / "t")
    with admin_engine.begin() as conn:
        fenced(conn, v2["identity"].tenant_id)
        conn.execute(
            text("UPDATE execbound.signal_sources SET active = false WHERE source_id = :s"),
            {"s": source},
        )
    bundle = signal_bundle(v2["identity"].tenant_id, v2["account"], (source,))
    assert refused_at(db, v2, bundle) == "signal_mappings.0.admitted_sources.0"


def test_a_source_not_registered_for_the_capability_subject_is_refused(
    db, v2, admin_engine, tmp_path, monkeypatch
):
    # Every registration holds the resource subject today (the table's own check), so a
    # capability about another subject is reached through the store's own lookup.
    elsewhere = Capability(
        name=CAPABILITY,
        subject="principal",
        values=RESOURCE_COMPROMISE_V1.values,
        clean=RESOURCE_COMPROMISE_V1.clean,
        no_detection=RESOURCE_COMPROMISE_V1.no_detection,
    )
    monkeypatch.setattr(store, "signal_capability", lambda name: elsewhere)
    source, _ = register(admin_engine, v2, tmp_path / "t")
    bundle = signal_bundle(v2["identity"].tenant_id, v2["account"], (source,))
    assert refused_at(db, v2, bundle) == "signal_mappings.0.admitted_sources.0"


def test_an_agent_forwarded_source_is_refused_in_a_required_mapping(db, v2, admin_engine, tmp_path):
    source, _ = register(admin_engine, v2, tmp_path / "t", input_path="agent_forwarded")
    bundle = signal_bundle(v2["identity"].tenant_id, v2["account"], (source,))
    assert refused_at(db, v2, bundle) == "signal_mappings.0.admitted_sources.0"


def test_clean_needs_a_source_that_attests_liveness(db, v2, admin_engine, tmp_path):
    rows = (
        SignalThreshold(verdict="None", value="clean"),
        SignalThreshold(verdict="High", value="compromised"),
    )
    quiet, _ = register(admin_engine, v2, tmp_path / "quiet")
    bundle = signal_bundle(v2["identity"].tenant_id, v2["account"], (quiet,), thresholds=rows)
    assert refused_at(db, v2, bundle) == "signal_mappings.0.thresholds.1"
    watching, _ = register(admin_engine, v2, tmp_path / "watching", attests_liveness=True)
    bundle = signal_bundle(v2["identity"].tenant_id, v2["account"], (watching,), thresholds=rows)
    assert validated(db, v2, bundle).state == "VALIDATED"


def test_a_capability_without_no_detection_needs_a_source_that_attests_liveness(
    db, v2, admin_engine, tmp_path, monkeypatch
):
    # No production capability lacks `no_detection` today, so this rule is reached
    # through the store's own lookup: such a capability has no value a source that cannot
    # attest liveness may report when it sees nothing, so it cannot take that source at all.
    strict = Capability(
        name="resource_compromise.v1",
        subject="resource",
        values=("clean", "suspect", "compromised"),
        clean="clean",
        no_detection=None,
    )
    monkeypatch.setattr(store, "signal_capability", lambda name: strict)
    rows = (
        SignalThreshold(verdict="Low", value="suspect"),
        SignalThreshold(verdict="High", value="compromised"),
    )
    quiet, _ = register(admin_engine, v2, tmp_path / "quiet")
    bundle = signal_bundle(v2["identity"].tenant_id, v2["account"], (quiet,), thresholds=rows)
    assert refused_at(db, v2, bundle) == "signal_mappings.0.admitted_sources.0"
    watching, _ = register(admin_engine, v2, tmp_path / "watching", attests_liveness=True)
    bundle = signal_bundle(v2["identity"].tenant_id, v2["account"], (watching,), thresholds=rows)
    assert validated(db, v2, bundle).state == "VALIDATED"


def test_a_source_of_another_space_is_refused_unless_offered(db, v2, admin_engine, tmp_path):
    tenant = v2["identity"].tenant_id
    other = uuid4()
    with admin_engine.begin() as conn:
        fenced(conn, tenant)
        home = default_space(conn, tenant)
        conn.execute(
            text(
                "INSERT INTO execbound.spaces (tenant_id, space_id, name, created_at, created_by) "
                "VALUES (:t, :s, 'Customer B', now(), :p)"
            ),
            {"t": tenant, "s": other, "p": v2["admin"].principal_id},
        )
    foreign, _ = register(admin_engine, v2, tmp_path / "foreign", space=other)
    assert (
        refused_at(db, v2, signal_bundle(tenant, v2["account"], (foreign,)), home)
        == "signal_mappings.0.admitted_sources.0"
    )
    shared, _ = register(admin_engine, v2, tmp_path / "shared", space=other, offered=True)
    bundle = signal_bundle(tenant, v2["account"], (shared,))
    assert validated(db, v2, bundle, home).state == "VALIDATED"


def test_activation_in_another_space_needs_a_source_that_space_can_use(
    db, v2, admin_engine, tmp_path
):
    tenant = v2["identity"].tenant_id
    other = uuid4()
    with admin_engine.begin() as conn:
        fenced(conn, tenant)
        home = default_space(conn, tenant)
        conn.execute(
            text(
                "INSERT INTO execbound.spaces (tenant_id, space_id, name, created_at, created_by) "
                "VALUES (:t, :s, 'Customer B', now(), :p)"
            ),
            {"t": tenant, "s": other, "p": v2["admin"].principal_id},
        )
    local, _ = register(admin_engine, v2, tmp_path / "local", space=home)
    bundle = signal_bundle(tenant, v2["account"], (local,))
    assert validated(db, v2, bundle, home).state == "VALIDATED"
    with pytest.raises(PolicyStoreError) as caught:
        activate_bundle(db, v2["admin"], bundle.bundle_id, v2["clock"], space=other)
    assert (caught.value.code, caught.value.location) == (
        "INVALID_COMPONENT",
        "signal_mappings.0.admitted_sources.0",
    )
    active = activate_bundle(db, v2["admin"], bundle.bundle_id, v2["clock"], space=home)
    assert active.state == "ACTIVE"


def test_a_bundle_created_and_activated_in_one_transaction_is_checked_too(db, v2, admin_engine):
    tenant = v2["identity"].tenant_id
    with admin_engine.begin() as conn:
        fenced(conn, tenant)
        home = default_space(conn, tenant)
        # `activate_new_bundle` never replaces a space's selection, so clear the world's.
        conn.execute(
            text("DELETE FROM execbound.space_policy_selection WHERE tenant_id = :t"),
            {"t": tenant},
        )
    bundle = signal_bundle(tenant, v2["account"], (uuid4(),), signal_mappings=())
    with pytest.raises(PolicyStoreError) as caught:
        with db.transaction(tenant) as conn:
            activate_new_bundle(conn, v2["admin"], bundle, v2["clock"], space=home)
    assert (caught.value.code, caught.value.location) == ("INVALID_COMPONENT", "signal_mappings")


def test_an_offered_bundle_admits_only_offered_sources(db, v2, admin_engine, tmp_path):
    tenant = v2["identity"].tenant_id
    local, _ = register(admin_engine, v2, tmp_path / "t")
    bundle = signal_bundle(tenant, v2["account"], (local,))
    create_bundle(db, v2["admin"], bundle, v2["clock"])
    with admin_engine.begin() as conn:
        fenced(conn, tenant)
        conn.execute(
            text(
                "UPDATE execbound.policy_bundle_contents SET offered_tenant_wide = true "
                "WHERE tenant_id = :t AND bundle_id = :b"
            ),
            {"t": tenant, "b": bundle.bundle_id},
        )
    with pytest.raises(PolicyStoreError) as caught:
        validate_bundle(db, v2["admin"], bundle.bundle_id, v2["clock"])
    assert (caught.value.code, caught.value.location) == (
        "INVALID_COMPONENT",
        "signal_mappings.0.admitted_sources.0",
    )


def test_an_entry_for_a_contract_the_bundle_does_not_map_is_refused(db, v2, admin_engine, tmp_path):
    source, _ = register(admin_engine, v2, tmp_path / "t")
    stray = SignalMapping(
        context_contract_version="endpoint-isolation.v1",
        capability="resource_compromise.v1",
        admitted_sources=(source,),
        thresholds=(SignalThreshold(verdict="High", value="compromised"),),
    )
    own = SignalMapping(
        context_contract_version=V2,
        capability="resource_compromise.v1",
        admitted_sources=(source,),
        thresholds=(SignalThreshold(verdict="High", value="compromised"),),
    )
    bundle = signal_bundle(
        v2["identity"].tenant_id, v2["account"], (source,), signal_mappings=(stray, own)
    )
    assert refused_at(db, v2, bundle) == "signal_mappings.0"


def test_an_entry_for_a_capability_its_contract_does_not_declare_is_refused(
    db, world, admin_engine, tmp_path
):
    # `world` maps isolation on endpoint-isolation.v1, which declares no signal fact.
    source, _ = register(admin_engine, world, tmp_path / "t")
    v1 = "endpoint-isolation.v1"
    reference = MappingRef(
        operation_ref="endpoint.isolate",
        account_id=world["account"],
        mapping_version="map-v1",
        schema_version="action.v1",
        context_contract_version=v1,
    )
    entry = SignalMapping(
        context_contract_version=v1,
        capability=CAPABILITY,
        admitted_sources=(source,),
        thresholds=MDE_THRESHOLDS,
    )
    bundle = ruleset_bundle(
        Ruleset(rules=SIGNAL_RULES.rules[:2]),
        tenant_id=world["identity"].tenant_id,
        bundle_id=uuid4(),
        mappings=(reference,),
        signal_mappings=(entry,),
    )
    assert refused_at(db, world, bundle) == "signal_mappings.0.capability"


def test_a_rule_edit_carries_the_mapping_forward(db, v2, admin_engine, tmp_path):
    from execbound.policy.store import change_draft_rules

    source, _ = register(admin_engine, v2, tmp_path / "t")
    bundle = signal_bundle(v2["identity"].tenant_id, v2["account"], (source,))
    create_bundle(db, v2["admin"], bundle, v2["clock"])
    changed = change_draft_rules(db, v2["admin"], bundle.bundle_id, bundle.ruleset, v2["clock"])
    assert changed.content.signal_mappings == bundle.signal_mappings


def test_a_copy_for_editing_carries_the_mapping_forward():
    bundle = signal_bundle(uuid4(), uuid4(), (uuid4(),))
    copy = editable_copy(bundle, PRODUCTION_CATALOG)
    assert copy is not None and copy.signal_mappings == bundle.signal_mappings
