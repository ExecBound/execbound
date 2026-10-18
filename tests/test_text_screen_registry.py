# SPDX-License-Identifier: AGPL-3.0-only
"""Operator text screened where the registry, the signal and context sources, the executor
key ring and trusted-context manifests write it (T7.7): refused with each boundary's
own existing code, quoting the value nowhere, and leaving no trace of the write it would
have made, exactly as tests/test_text_screen_reasons.py and tests/test_text_screen_names.py
prove for reasons, names and labels.

Most of the fields below are pattern-constrained rather than free text, so a sample from
`secret_shapes.FREE_TEXT` that a field's own character class or length bound would already
refuse makes a vacuous test: the refusal would prove the existing validation, not this
screen. Each section below first checks, in Python, which `FREE_TEXT` samples the field's
own regex or validator actually admits, and parametrizes only over those, each with the
sample's own readable id; `over_free_text` is used only for the few fields (`version`,
`mapping_version` and a manifest entry's own `version`/`provider_version`) whose own check
is a length bound every `FREE_TEXT` sample clears.

A manifest entry's fact values are not covered here: every string fact in both
`PRODUCTION_CATALOG` and the test fixtures' catalog is a closed, enumerated
`execbound.domains.StringDomain` (`environment`, `role`, `privilege_class`, the incident
`status` and `severity`, and the fixtures' own `exposure`), so no fact a manifest carries
ever admits free text at all. `parse_manifest`'s screen is exercised here through `version`,
`provider_version` and `provider_id` only: a fact value might seem to need covering too,
and this is the finding that it does not.
"""

from datetime import UTC, datetime, timedelta

import pytest
from checkpoint_fixtures import executor_public_key, register_key
from pydantic import ValidationError
from secret_shapes import AGENT_TOKEN, FREE_TEXT, FREE_TEXT_IDS, LOWER_STRIPE, STRIPE
from sqlalchemy import text
from test_context_provisioning import apply, entry, manifest
from test_execution import registry as registry
from test_execution import world as world
from test_signal_registration import register as register
from text_screen_helpers import (
    assert_nothing_found,
    assert_refused_unquoted,
    kind_count,
    over_free_text,
    row_count,
)

from execbound import administration, provisioning
from execbound.administration import _KEY_ID, _OPERATION_REF, AdministrationError
from execbound.provisioning import _PRODUCER, _SIGNAL_LABEL, _WRITER
from execbound.requests import ResourceSelector


def _admitted(kind, value):
    """Whether `ResourceSelector`'s own normalisation accepts this value for `kind`,
    exactly as `create_resource` and a manifest entry's `provider_id` field read it: a
    sample that fails here would already be refused by the existing validation, before
    this screen ever ran, which would make a test against it vacuous."""
    try:
        ResourceSelector(kind=kind, value=value)
    except ValidationError:
        return False
    return True


# -- Signal sources: provisioning.create_signal_source (label, producer) -------------------

SIGNAL_SOURCE_KIND = "signal_source.created"

# Filtered by the label's own pattern (`_SIGNAL_LABEL`, `[A-Za-z0-9][A-Za-z0-9 ._:-]{0,95}`)
# rather than a hand-picked exclusion list, so a `FREE_TEXT` sample added later that the
# pattern would already refuse (as it does `database-url`'s `@` and `slack`'s `/`) is left
# out automatically instead of reaching this screen's test for nothing.
_SIGNAL_LABEL_SAMPLES = [
    pytest.param(value, id=sample_id)
    for value, sample_id in zip(FREE_TEXT, FREE_TEXT_IDS, strict=True)
    if _SIGNAL_LABEL.fullmatch(value)
]


@pytest.mark.parametrize("label", _SIGNAL_LABEL_SAMPLES)
def test_a_signal_sources_label_shaped_like_a_secret_is_refused_unquoted(
    world, admin_engine, tmp_path, label
):
    tenant = world["identity"].tenant_id
    before = kind_count(admin_engine, tenant, SIGNAL_SOURCE_KIND)
    before_rows = row_count(admin_engine, tenant, "signal_sources")
    with pytest.raises(provisioning.ProvisioningError) as refused:
        register(admin_engine, world, tmp_path, label=label)
    assert_refused_unquoted(refused, "INVALID_LABEL", label)
    assert_nothing_found(admin_engine, tenant)
    assert kind_count(admin_engine, tenant, SIGNAL_SOURCE_KIND) == before
    assert row_count(admin_engine, tenant, "signal_sources") == before_rows
    assert not (tmp_path / "token").exists()


# `_PRODUCER` is `[a-z][a-z0-9_.-]{0,63}`: of `FREE_TEXT`, only a lowercase Stripe key fits
# (no dot, slash, space or uppercase letter survives it), so `LOWER_STRIPE` is the one
# sample that reaches this screen rather than the pattern check in front of it.
def test_a_signal_sources_producer_shaped_like_a_secret_is_refused_unquoted(
    world, admin_engine, tmp_path
):
    assert _PRODUCER.fullmatch(LOWER_STRIPE)
    tenant = world["identity"].tenant_id
    before = kind_count(admin_engine, tenant, SIGNAL_SOURCE_KIND)
    before_rows = row_count(admin_engine, tenant, "signal_sources")
    with pytest.raises(provisioning.ProvisioningError) as refused:
        register(admin_engine, world, tmp_path, producer=LOWER_STRIPE)
    assert_refused_unquoted(refused, "INVALID_PRODUCER", LOWER_STRIPE)
    assert_nothing_found(admin_engine, tenant)
    assert kind_count(admin_engine, tenant, SIGNAL_SOURCE_KIND) == before
    assert row_count(admin_engine, tenant, "signal_sources") == before_rows
    assert not (tmp_path / "token").exists()


def test_a_plain_signal_source_is_still_accepted(world, admin_engine, tmp_path):
    tenant = world["identity"].tenant_id
    before = kind_count(admin_engine, tenant, SIGNAL_SOURCE_KIND)
    before_rows = row_count(admin_engine, tenant, "signal_sources")
    register(admin_engine, world, tmp_path)
    assert kind_count(admin_engine, tenant, SIGNAL_SOURCE_KIND) == before + 1
    assert row_count(admin_engine, tenant, "signal_sources") == before_rows + 1
    assert (tmp_path / "token").exists()


# -- Context source writers: provisioning.create_context_source ----------------------------

CONTEXT_SOURCE_KIND = "context_source.created"


# `_WRITER` is the same pattern as `_PRODUCER` above, so `LOWER_STRIPE` is again the one
# `FREE_TEXT`-derived sample that is not already refused by the writer's own shape check.
# It is the second of two writers here, and never the only one, so this proves
# `secret_shaped(*labels)` checks every label the caller sent and not just the first.
def test_a_context_sources_writer_shaped_like_a_secret_is_refused_unquoted(world, admin_engine):
    assert _WRITER.fullmatch(LOWER_STRIPE)
    tenant = world["identity"].tenant_id
    before = kind_count(admin_engine, tenant, CONTEXT_SOURCE_KIND)
    before_rows = row_count(admin_engine, tenant, "context_sources")
    with pytest.raises(provisioning.ProvisioningError) as refused:
        provisioning.create_context_source(
            admin_engine,
            tenant,
            world["account"],
            "inventory",
            ["ops_team", LOWER_STRIPE],
            world["admin"].principal_id,
        )
    assert_refused_unquoted(refused, "INVALID_WRITER", LOWER_STRIPE)
    assert_nothing_found(admin_engine, tenant)
    assert kind_count(admin_engine, tenant, CONTEXT_SOURCE_KIND) == before
    assert row_count(admin_engine, tenant, "context_sources") == before_rows


def test_a_plain_context_sources_writer_is_still_accepted(world, admin_engine):
    tenant = world["identity"].tenant_id
    before = kind_count(admin_engine, tenant, CONTEXT_SOURCE_KIND)
    before_rows = row_count(admin_engine, tenant, "context_sources")
    source = provisioning.create_context_source(
        admin_engine,
        tenant,
        world["account"],
        "inventory",
        ["ops_team"],
        world["admin"].principal_id,
    )
    assert source is not None
    assert kind_count(admin_engine, tenant, CONTEXT_SOURCE_KIND) == before + 1
    assert row_count(admin_engine, tenant, "context_sources") == before_rows + 1


# -- Executor key ids: administration.register_executor_key and rotate_executor_key's new id


KEY_REGISTERED_KIND = "executor_key.registered"
KEY_ROTATED_KIND = "executor_key.rotated"
KEY_REVOKED_KIND = "executor_key.revoked"
KEY_COMPROMISED_KIND = "executor_key.compromised"


# `_KEY_ID` is `[a-zA-Z0-9_.-]{1,64}`: it admits upper and lower case, so a Stripe key fits
# its shape, but its 64-character bound is shorter than a JWT or an agent credential (both
# 79 characters), which the id's own length check already refuses. `STRIPE` is the one
# `FREE_TEXT` sample this screen, rather than that bound, is what refuses.
def test_a_registered_executor_keys_id_shaped_like_a_secret_is_refused_unquoted(
    world, admin_engine
):
    assert _KEY_ID.fullmatch(STRIPE)
    tenant = world["identity"].tenant_id
    before = kind_count(admin_engine, tenant, KEY_REGISTERED_KIND)
    before_rows = row_count(admin_engine, tenant, "executor_keys")
    with pytest.raises(AdministrationError) as refused:
        administration.register_executor_key(
            admin_engine,
            tenant,
            STRIPE,
            executor_public_key(),
            world["admin"].principal_id,
            now=world["clock"].now(),
        )
    assert_refused_unquoted(refused, "INVALID_KEY", STRIPE)
    assert_nothing_found(admin_engine, tenant)
    assert kind_count(admin_engine, tenant, KEY_REGISTERED_KIND) == before
    assert row_count(admin_engine, tenant, "executor_keys") == before_rows


def test_a_plain_registered_executor_keys_id_is_still_accepted(world, admin_engine):
    tenant = world["identity"].tenant_id
    before = kind_count(admin_engine, tenant, KEY_REGISTERED_KIND)
    before_rows = row_count(admin_engine, tenant, "executor_keys")
    administration.register_executor_key(
        admin_engine,
        tenant,
        "executor-v1",
        executor_public_key(),
        world["admin"].principal_id,
        now=world["clock"].now(),
    )
    assert kind_count(admin_engine, tenant, KEY_REGISTERED_KIND) == before + 1
    assert row_count(admin_engine, tenant, "executor_keys") == before_rows + 1


@pytest.fixture
def registered_key(world, admin_engine):
    """One plain executor key, registered the ordinary way (`checkpoint_fixtures`'s own
    helper), ready to be rotated away."""
    key_id = "executor-base"
    register_key(admin_engine, world, key_id)
    return key_id


def test_a_rotated_executor_keys_new_id_shaped_like_a_secret_is_refused_unquoted(
    world, admin_engine, registered_key
):
    assert _KEY_ID.fullmatch(STRIPE)
    tenant = world["identity"].tenant_id
    before = kind_count(admin_engine, tenant, KEY_ROTATED_KIND)
    before_rows = row_count(admin_engine, tenant, "executor_keys")
    with pytest.raises(AdministrationError) as refused:
        administration.rotate_executor_key(
            admin_engine,
            tenant,
            registered_key,
            STRIPE,
            executor_public_key(),
            world["admin"].principal_id,
            now=world["clock"].now(),
        )
    assert_refused_unquoted(refused, "INVALID_KEY", STRIPE)
    assert_nothing_found(admin_engine, tenant)
    assert kind_count(admin_engine, tenant, KEY_ROTATED_KIND) == before
    # The old key is untouched: a refused rotation retires nothing.
    assert row_count(admin_engine, tenant, "executor_keys") == before_rows
    assert _key_row(admin_engine, tenant, registered_key)["revoked_at"] is None


def test_a_plain_rotated_executor_keys_new_id_is_still_accepted(
    world, admin_engine, registered_key
):
    tenant = world["identity"].tenant_id
    before = kind_count(admin_engine, tenant, KEY_ROTATED_KIND)
    before_rows = row_count(admin_engine, tenant, "executor_keys")
    administration.rotate_executor_key(
        admin_engine,
        tenant,
        registered_key,
        "executor-next",
        executor_public_key(),
        world["admin"].principal_id,
        now=world["clock"].now(),
    )
    assert kind_count(admin_engine, tenant, KEY_ROTATED_KIND) == before + 1
    assert row_count(admin_engine, tenant, "executor_keys") == before_rows + 1
    # And the old one is retired: rotation is a real handover, not an addition beside it.
    assert _key_row(admin_engine, tenant, registered_key)["revoked_at"] is not None


def _insert_shaped_key(engine, tenant, key_id, now):
    """One executor key row holding a shaped id, written directly with `admin_engine`
    rather than through `register_executor_key`, which now refuses to create one: this is
    how a key whose id reached this shape before the screen existed (or by any route this
    function does not gate) is represented, so that revoking or reporting it compromised
    can be proven to still work on it."""
    with engine.begin() as conn:
        conn.execute(
            text(
                "INSERT INTO execbound.executor_keys "
                "(tenant_id, key_id, algorithm, public_key, created_at) "
                "VALUES (:t, :k, 'ED25519', :key, :now)"
            ),
            {"t": tenant, "k": key_id, "key": executor_public_key(), "now": now},
        )


def _key_row(engine, tenant, key_id):
    with engine.begin() as conn:
        return dict(
            conn.execute(
                text(
                    "SELECT revoked_at, revocation_reason FROM execbound.executor_keys "
                    "WHERE tenant_id = :t AND key_id = :k"
                ),
                {"t": tenant, "k": key_id},
            )
            .mappings()
            .one()
        )


def test_an_existing_keys_shaped_id_can_still_be_revoked(world, admin_engine):
    tenant = world["identity"].tenant_id
    now = world["clock"].now()
    _insert_shaped_key(admin_engine, tenant, STRIPE, now)
    before = kind_count(admin_engine, tenant, KEY_REVOKED_KIND)
    administration.revoke_executor_key(
        admin_engine, tenant, STRIPE, world["admin"].principal_id, now=now
    )
    assert kind_count(admin_engine, tenant, KEY_REVOKED_KIND) == before + 1
    row = _key_row(admin_engine, tenant, STRIPE)
    assert row["revoked_at"] is not None and row["revocation_reason"] == "RETIRED"


def test_an_existing_keys_shaped_id_can_still_be_reported_compromised(world, admin_engine):
    tenant = world["identity"].tenant_id
    now = world["clock"].now()
    _insert_shaped_key(admin_engine, tenant, LOWER_STRIPE, now)
    before = kind_count(admin_engine, tenant, KEY_COMPROMISED_KIND)
    administration.report_executor_key_compromise(
        admin_engine, tenant, LOWER_STRIPE, world["admin"].principal_id, now=now
    )
    assert kind_count(admin_engine, tenant, KEY_COMPROMISED_KIND) == before + 1
    row = _key_row(admin_engine, tenant, LOWER_STRIPE)
    assert row["revocation_reason"] == "COMPROMISED"


def test_an_existing_keys_shaped_id_can_still_be_rotated_away_from(world, admin_engine):
    # The old id names a key that already exists, exactly like a revocation's or a
    # compromise report's, and `rotate_executor_key` never refuses it on that account
    # (only the new id is screened); `executor_key.rotated` carries it as `previous_key_id`
    # unscreened (R34), which this proves still works for an id that reached this shape
    # before the screen existed.
    tenant = world["identity"].tenant_id
    now = world["clock"].now()
    _insert_shaped_key(admin_engine, tenant, STRIPE, now)
    before = kind_count(admin_engine, tenant, KEY_ROTATED_KIND)
    administration.rotate_executor_key(
        admin_engine,
        tenant,
        STRIPE,
        "executor-next",
        executor_public_key(),
        world["admin"].principal_id,
        now=now,
    )
    assert kind_count(admin_engine, tenant, KEY_ROTATED_KIND) == before + 1
    assert _key_row(admin_engine, tenant, STRIPE)["revoked_at"] is not None


# -- Registry entries: administration.create_resource and create_mapping -------------------

RESOURCE_CREATED_KIND = "resource.created"
MAPPING_CREATED_KIND = "mapping.created"

# Filtered by `ResourceSelector`'s own `provider_id` normalisation (`[A-Za-z0-9._:-]{1,128}`)
# rather than a hand-picked list: of `FREE_TEXT`, a Stripe key, a JWT and an agent credential
# fit (letters, digits, dots, dashes and the credential's own colons); a bearer value's
# space, a database URL's `://` and `@`, the Slack webhook's `/` and the embedded sample's
# spaces are all outside it, so `_admitted` leaves those four out on its own.
_PROVIDER_ID_SAMPLES = [
    pytest.param(value, id=sample_id)
    for value, sample_id in zip(FREE_TEXT, FREE_TEXT_IDS, strict=True)
    if _admitted("provider_id", value)
]


@pytest.mark.parametrize("provider_id", _PROVIDER_ID_SAMPLES)
def test_a_new_resources_provider_id_shaped_like_a_secret_is_refused_unquoted(
    world, admin_engine, provider_id
):
    tenant = world["identity"].tenant_id
    before = kind_count(admin_engine, tenant, RESOURCE_CREATED_KIND)
    before_rows = row_count(admin_engine, tenant, "resources")
    with pytest.raises(AdministrationError) as refused:
        administration.create_resource(
            admin_engine,
            tenant,
            world["account"],
            "endpoint",
            provider_id,
            world["inventory"],
            world["admin"].principal_id,
        )
    assert_refused_unquoted(refused, "INVALID_PROVIDER_ID", provider_id)
    assert_nothing_found(admin_engine, tenant)
    assert kind_count(admin_engine, tenant, RESOURCE_CREATED_KIND) == before
    assert row_count(admin_engine, tenant, "resources") == before_rows


@over_free_text("version")
def test_a_new_resources_version_shaped_like_a_secret_is_refused_unquoted(
    world, admin_engine, version
):
    tenant = world["identity"].tenant_id
    before = kind_count(admin_engine, tenant, RESOURCE_CREATED_KIND)
    before_rows = row_count(admin_engine, tenant, "resources")
    with pytest.raises(AdministrationError) as refused:
        administration.create_resource(
            admin_engine,
            tenant,
            world["account"],
            "endpoint",
            "device-97",
            world["inventory"],
            world["admin"].principal_id,
            version=version,
        )
    assert_refused_unquoted(refused, "INVALID_VERSION", version)
    assert_nothing_found(admin_engine, tenant)
    assert kind_count(admin_engine, tenant, RESOURCE_CREATED_KIND) == before
    assert row_count(admin_engine, tenant, "resources") == before_rows


# A hostname alias is lowercased and then checked label by label against a DNS label
# pattern with no underscore, so a Stripe key or a JWT (both carrying one) cannot match it
# at all; the agent credential's id carries only letters, digits, dots and dashes, so it is
# the one `FREE_TEXT` sample a hostname alias admits for this screen to refuse.
def test_a_new_resources_hostname_alias_shaped_like_a_secret_is_refused_unquoted(
    world, admin_engine
):
    assert _admitted("hostname", AGENT_TOKEN)
    tenant = world["identity"].tenant_id
    before = kind_count(admin_engine, tenant, RESOURCE_CREATED_KIND)
    before_rows = row_count(admin_engine, tenant, "resources")
    with pytest.raises(AdministrationError) as refused:
        administration.create_resource(
            admin_engine,
            tenant,
            world["account"],
            "endpoint",
            "device-98",
            world["inventory"],
            world["admin"].principal_id,
            hostname=AGENT_TOKEN,
        )
    assert_refused_unquoted(refused, "INVALID_ALIAS", AGENT_TOKEN)
    assert_nothing_found(admin_engine, tenant)
    assert kind_count(admin_engine, tenant, RESOURCE_CREATED_KIND) == before
    assert row_count(admin_engine, tenant, "resources") == before_rows


def test_a_plain_new_resource_is_still_accepted(world, admin_engine):
    tenant = world["identity"].tenant_id
    before = kind_count(admin_engine, tenant, RESOURCE_CREATED_KIND)
    before_rows = row_count(admin_engine, tenant, "resources")
    created = administration.create_resource(
        admin_engine,
        tenant,
        world["account"],
        "endpoint",
        "device-99",
        world["inventory"],
        world["admin"].principal_id,
        hostname="ws99.example",
    )
    assert created.aliases == ("hostname:ws99.example", "provider_id:device-99")
    assert kind_count(admin_engine, tenant, RESOURCE_CREATED_KIND) == before + 1
    assert row_count(admin_engine, tenant, "resources") == before_rows + 1


# `_OPERATION_REF` is `[a-z][a-z0-9_.-]{0,79}`. `LOWER_STRIPE` is not drawn from `FREE_TEXT`
# itself (nothing in it is lowercase-only), so the test below asserts it admitted by name;
# the rest is filtered from `FREE_TEXT` by the pattern itself, which the already-lowercase
# agent credential is the one member of to clear it (everything else carries a character the
# pattern excludes, or starts with one it does not accept as a first letter).
_OPERATION_REF_SAMPLES = [
    pytest.param(LOWER_STRIPE, id="lower-stripe"),
    *(
        pytest.param(value, id=sample_id)
        for value, sample_id in zip(FREE_TEXT, FREE_TEXT_IDS, strict=True)
        if _OPERATION_REF.fullmatch(value)
    ),
]


@pytest.mark.parametrize("operation_ref", _OPERATION_REF_SAMPLES)
def test_a_new_mappings_operation_ref_shaped_like_a_secret_is_refused_unquoted(
    world, admin_engine, operation_ref
):
    assert _OPERATION_REF.fullmatch(operation_ref)
    tenant = world["identity"].tenant_id
    before = kind_count(admin_engine, tenant, MAPPING_CREATED_KIND)
    before_rows = row_count(admin_engine, tenant, "operation_mappings")
    with pytest.raises(AdministrationError) as refused:
        administration.create_mapping(
            admin_engine,
            tenant,
            world["account"],
            "endpoint.lift_isolation",
            world["admin"].principal_id,
            operation_ref=operation_ref,
        )
    assert_refused_unquoted(refused, "INVALID_REFERENCE", operation_ref)
    assert_nothing_found(admin_engine, tenant)
    assert kind_count(admin_engine, tenant, MAPPING_CREATED_KIND) == before
    assert row_count(admin_engine, tenant, "operation_mappings") == before_rows


@over_free_text("mapping_version")
def test_a_new_mappings_version_shaped_like_a_secret_is_refused_unquoted(
    world, admin_engine, mapping_version
):
    tenant = world["identity"].tenant_id
    before = kind_count(admin_engine, tenant, MAPPING_CREATED_KIND)
    before_rows = row_count(admin_engine, tenant, "operation_mappings")
    with pytest.raises(AdministrationError) as refused:
        administration.create_mapping(
            admin_engine,
            tenant,
            world["account"],
            "endpoint.lift_isolation",
            world["admin"].principal_id,
            operation_ref="lift-ref",
            mapping_version=mapping_version,
        )
    assert_refused_unquoted(refused, "INVALID_VERSION", mapping_version)
    assert_nothing_found(admin_engine, tenant)
    assert kind_count(admin_engine, tenant, MAPPING_CREATED_KIND) == before
    assert row_count(admin_engine, tenant, "operation_mappings") == before_rows


def test_a_plain_new_mapping_is_still_accepted(world, admin_engine):
    tenant = world["identity"].tenant_id
    before = kind_count(admin_engine, tenant, MAPPING_CREATED_KIND)
    before_rows = row_count(admin_engine, tenant, "operation_mappings")
    created = administration.create_mapping(
        admin_engine,
        tenant,
        world["account"],
        "endpoint.lift_isolation",
        world["admin"].principal_id,
        operation_ref="lift-ref",
        mapping_version="map-v2",
    )
    assert (created.operation_ref, created.mapping_version) == ("lift-ref", "map-v2")
    assert kind_count(admin_engine, tenant, MAPPING_CREATED_KIND) == before + 1
    assert row_count(admin_engine, tenant, "operation_mappings") == before_rows + 1


# -- Context manifests: provisioning.parse_manifest, every entry ---------------------------

CONTEXT_IMPORTED_KIND = "context.imported"


def _manifest_counts(engine, tenant):
    # `resources` is left out: `import_manifest` never inserts into it at all. An unknown
    # provider id is counted as `unknown_resources` and skipped rather than written
    # (`_plan_writes`, provisioning.py), and a known one is only ever updated in place, so
    # that count could never move even in a successful import and no control could prove a
    # refusal left it alone: only a count the control actually moves belongs.
    return (
        row_count(engine, tenant, "resource_facts"),
        kind_count(engine, tenant, CONTEXT_IMPORTED_KIND),
    )


@pytest.mark.parametrize("provider_id", _PROVIDER_ID_SAMPLES)
def test_a_manifest_entrys_provider_id_shaped_like_a_secret_is_refused_unquoted(
    world, admin_engine, provider_id
):
    tenant = world["identity"].tenant_id
    before = _manifest_counts(admin_engine, tenant)
    observed = datetime.now(UTC) - timedelta(seconds=30)
    document = manifest(world, entry(observed, provider_id=provider_id))
    # `apply` parses the document and then imports it, in that order, so the refusal still
    # comes from `parse_manifest` and carries the same code and entry index; going through
    # it rather than calling `parse_manifest` alone is what makes `_manifest_counts` and
    # `assert_nothing_found` below mean something: `import_manifest` is the call that would
    # actually write, so only exercising the full path proves this screen is what stops it.
    with pytest.raises(provisioning.ProvisioningError) as refused:
        apply(admin_engine, world, document)
    assert_refused_unquoted(refused, "INVALID_MANIFEST", provider_id)
    assert refused.value.entry == 0
    assert_nothing_found(admin_engine, tenant)
    assert _manifest_counts(admin_engine, tenant) == before


def test_a_second_manifest_entrys_provider_id_shaped_like_a_secret_is_refused_at_its_own_index(
    world, admin_engine
):
    """One plain entry ahead of the shaped one, so a refusal naming entry 0 by accident
    (or by only ever checking the first entry) cannot pass this."""
    tenant = world["identity"].tenant_id
    before = _manifest_counts(admin_engine, tenant)
    observed = datetime.now(UTC) - timedelta(seconds=30)
    document = manifest(
        world,
        entry(observed, provider_id="device-01"),
        entry(observed, provider_id=STRIPE),
    )
    with pytest.raises(provisioning.ProvisioningError) as refused:
        apply(admin_engine, world, document)
    assert_refused_unquoted(refused, "INVALID_MANIFEST", STRIPE)
    assert refused.value.entry == 1
    assert_nothing_found(admin_engine, tenant)
    assert _manifest_counts(admin_engine, tenant) == before


@over_free_text("version")
def test_a_manifest_entrys_version_shaped_like_a_secret_is_refused_unquoted(
    world, admin_engine, version
):
    tenant = world["identity"].tenant_id
    before = _manifest_counts(admin_engine, tenant)
    observed = datetime.now(UTC) - timedelta(seconds=30)
    document = manifest(world, entry(observed, version=version))
    with pytest.raises(provisioning.ProvisioningError) as refused:
        apply(admin_engine, world, document)
    assert_refused_unquoted(refused, "INVALID_MANIFEST", version)
    assert refused.value.entry == 0
    assert_nothing_found(admin_engine, tenant)
    assert _manifest_counts(admin_engine, tenant) == before


@over_free_text("provider_version")
def test_a_manifest_entrys_provider_version_shaped_like_a_secret_is_refused_unquoted(
    world, admin_engine, provider_version
):
    tenant = world["identity"].tenant_id
    before = _manifest_counts(admin_engine, tenant)
    observed = datetime.now(UTC) - timedelta(seconds=30)
    document = manifest(world, entry(observed, provider_version=provider_version))
    with pytest.raises(provisioning.ProvisioningError) as refused:
        apply(admin_engine, world, document)
    assert_refused_unquoted(refused, "INVALID_MANIFEST", provider_version)
    assert refused.value.entry == 0
    assert_nothing_found(admin_engine, tenant)
    assert _manifest_counts(admin_engine, tenant) == before


def test_a_plain_manifest_still_imports(world, admin_engine):
    tenant = world["identity"].tenant_id
    # `import_manifest` never inserts into `resources`: an unknown provider id is counted
    # as `unknown_resources` and skipped, and `entry()`'s default provider_id ("device-01")
    # is one the registry fixture already seeded, so this import only updates its facts.
    # The three `ROW_FACTS` are `FactRow`-backed and so are the ones landing in
    # `resource_facts`, which is what moves alongside the event.
    before_resources = row_count(admin_engine, tenant, "resources")
    before_facts = row_count(admin_engine, tenant, "resource_facts")
    before_kind = kind_count(admin_engine, tenant, CONTEXT_IMPORTED_KIND)
    observed = datetime.now(UTC) - timedelta(seconds=30)
    document = manifest(world, entry(observed))
    result = apply(admin_engine, world, document)
    assert result.counts["applied"] == 1
    assert kind_count(admin_engine, tenant, CONTEXT_IMPORTED_KIND) == before_kind + 1
    assert row_count(admin_engine, tenant, "resources") == before_resources
    assert row_count(admin_engine, tenant, "resource_facts") == before_facts + 3
