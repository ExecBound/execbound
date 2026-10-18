# SPDX-License-Identifier: AGPL-3.0-only
"""Identity operations preserve exact provider families and trusted facts."""

import json
from datetime import timedelta
from uuid import uuid4

import pytest
from sqlalchemy import event, text
from test_resolution import registry as registry

from execbound.contracts import PRODUCTION_CATALOG
from execbound.execution.snapshot import attest_snapshot, resolve_snapshot
from execbound.operations import (
    PRODUCTION_ACTIONS,
    CatalogError,
    operation,
    validate_operation,
)
from execbound.requests import Arguments, InvalidRequest, parse_request
from execbound.resolution import ResolutionError, resolve_request, revalidate
from execbound.resolution.models import CanonicalIntent, intent_hash


@pytest.mark.parametrize(
    "action,provider,kind,provider_operation,contract",
    [
        ("endpoint.isolate", "mock_crowdstrike", "endpoint", "contain", "endpoint-isolation.v1"),
        ("identity.disable", "mock_entra", "identity", "disable", "identity-control.v1"),
        ("identity.enable", "mock_entra", "identity", "enable", "identity-control.v1"),
        (
            "identity.revoke_sessions",
            "mock_entra",
            "identity",
            "revoke_sessions",
            "identity-control.v1",
        ),
    ],
)
def test_catalog_binds_complete_operation(action, provider, kind, provider_operation, contract):
    spec = validate_operation(
        provider=provider,
        resource_type=kind,
        action=action,
        provider_operation=provider_operation,
        schema_version="action.v1",
    )
    assert (spec.provider, spec.resource_type, spec.action, spec.provider_operation) == (
        provider,
        kind,
        action,
        provider_operation,
    )
    assert spec.context_contract_version == contract == operation(action).context_contract_version
    assert spec.schema_version == "action.v1" and spec.arguments == ()


@pytest.mark.parametrize(
    "action", ["identity.disable", "identity.enable", "identity.revoke_sessions"]
)
@pytest.mark.parametrize(
    "field,value",
    [
        ("provider", "mock_crowdstrike"),
        ("resource_type", "endpoint"),
        ("provider_operation", "contain"),
        ("schema_version", "action.v2"),
    ],
)
def test_catalog_rejects_cross_family_tuples(action, field, value):
    spec = PRODUCTION_ACTIONS.bound("mock_entra", action)
    values = {
        name: getattr(spec, name)
        for name in (
            "provider",
            "resource_type",
            "action",
            "provider_operation",
            "schema_version",
        )
    }
    values[field] = value
    with pytest.raises(ValueError):
        validate_operation(**values)


@pytest.mark.parametrize(
    "action", ["identity.disable", "identity.enable", "identity.revoke_sessions"]
)
def test_catalog_rejects_cross_family_contract(action):
    with pytest.raises(ValueError):
        PRODUCTION_CATALOG.for_operation("endpoint-isolation.v1", action, "identity")


def test_mismatched_operation_tuples_are_rejected_by_the_catalog_not_the_model():
    values = dict(
        tenant_id=uuid4(),
        principal_id=uuid4(),
        account_id=uuid4(),
        target_id=uuid4(),
        arguments=Arguments(),
    )
    # The frozen model is structural; the tuple is rechecked at resolution, evaluation and dispatch.
    mismatched = CanonicalIntent(**values, action="identity.enable")
    assert mismatched.provider == "mock_crowdstrike"
    with pytest.raises(CatalogError):
        PRODUCTION_ACTIONS.validate_operation(
            provider=mismatched.provider,
            resource_type=mismatched.resource_type,
            action=mismatched.action,
            provider_operation=mismatched.provider_operation,
        )
    with pytest.raises(CatalogError):
        PRODUCTION_ACTIONS.validate_operation(
            provider="mock_entra",
            resource_type="identity",
            action="identity.enable",
            provider_operation="disable",
        )


@pytest.fixture
def identity_registry(registry, admin_engine):
    """Same provider identifiers in two provider accounts cannot share authority."""
    original = registry
    account, canonical = uuid4(), uuid4()
    params = {
        "old": original["account"],
        "new": account,
        "canonical": canonical,
        "now": original["clock"].now(),
        "target": original["target"],
    }
    with admin_engine.begin() as conn:
        conn.execute(
            text("""
            INSERT INTO execbound.connector_accounts
                (tenant_id,account_id,provider,space_id)
            SELECT tenant_id,:new,'mock_entra',space_id FROM execbound.connector_accounts
            WHERE account_id=:old
        """),
            params,
        )
        conn.execute(
            text("""
            INSERT INTO execbound.context_sources
            SELECT tenant_id,:new,source_id,kind,allowed_writers,active
            FROM execbound.context_sources WHERE account_id=:old
        """),
            params,
        )
        conn.execute(
            text("""
            INSERT INTO execbound.resources
            (tenant_id,account_id,provider,resource_type,resource_id,provider_id,version,
             source_id,role,privilege_class,environment,criticality,observed_at,active)
            SELECT tenant_id,:new,'mock_entra','identity',resource_id,provider_id,version,
                   source_id,NULL,'standard',environment,criticality,observed_at,active
            FROM execbound.resources WHERE account_id=:old
        """),
            params,
        )
        conn.execute(
            text("""
            INSERT INTO execbound.incidents
            SELECT tenant_id,:new,'mock_entra','identity',incident_id,resource_id,source_id,
                   version,status,severity,observed_at
            FROM execbound.incidents WHERE account_id=:old
        """),
            params,
        )
        for action in ("identity.disable", "identity.enable", "identity.revoke_sessions"):
            binding = PRODUCTION_ACTIONS.binding("mock_entra", action)
            conn.execute(
                text("""
                INSERT INTO execbound.operation_mappings
                SELECT tenant_id,:action,:new,'mock_entra','identity',:action,:operation,
                       mapping_version,'action.v1','identity-control.v1',active
                FROM execbound.operation_mappings WHERE account_id=:old
            """),
                {**params, "action": action, "operation": binding.provider_operation},
            )
        conn.execute(
            text("""
            INSERT INTO execbound.resource_aliases
            SELECT tenant_id,:alias,:new,'mock_entra','identity','provider_id','User-01',
                   resource_id,valid_from,expires_at
            FROM execbound.resource_aliases WHERE account_id=:old
        """),
            {**params, "alias": uuid4()},
        )
        conn.execute(
            text("""
            INSERT INTO execbound.canonical_targets (tenant_id,canonical_target_id,created_at)
            SELECT tenant_id,:canonical,:now FROM execbound.connector_accounts
            WHERE account_id=:new
        """),
            params,
        )
        conn.execute(
            text("""
            INSERT INTO execbound.resource_identities
            SELECT tenant_id,:new,'mock_entra','identity',:target,:canonical
            FROM execbound.connector_accounts WHERE account_id=:new
        """),
            params,
        )
    return {
        **original,
        "account": account,
        "endpoint_account": original["account"],
        "canonical": canonical,
    }


def identity_request(world, action="identity.disable", **changes):
    return parse_request(
        json.dumps(
            {
                "operation_ref": action,
                "target": {"kind": "provider_id", "value": "User-01"},
                "arguments": {},
                "idempotency_key": "identity-contract",
                "claimed_context": {
                    "incident_id": str(world["incident"]),
                    "severity": "LOW",
                    "role": "domain_controller",
                },
                **changes,
            }
        ).encode()
    )


def resolve_identity(db, world, action="identity.disable", **changes):
    return resolve_request(
        db, world["identity"], identity_request(world, action, **changes), world["clock"]
    )


@pytest.mark.parametrize(
    "action", ["identity.disable", "identity.enable", "identity.revoke_sessions"]
)
@pytest.mark.parametrize("kind", ["canonical", "provider_id"])
def test_identity_registry_and_snapshot_bind_same_authority(db, identity_registry, action, kind):
    world = identity_registry
    target = {"kind": kind, "value": str(world["target"]) if kind == "canonical" else "User-01"}
    request = identity_request(world, action, target=target)
    resolved = resolve_request(db, world["identity"], request, world["clock"])
    assert resolved.intent.account_id == world["account"] != world["endpoint_account"]
    assert resolved.intent.action == action
    assert resolved.fact("privilege_class").value == "standard"
    assert "role" not in {fact.name for fact in resolved.facts}
    assert resolved.fact("incident_severity").value == "CRITICAL"
    assert resolved.valid_until == world["clock"].now() + timedelta(seconds=240)
    with db.transaction(world["identity"].tenant_id) as conn:
        snapshot, canonical = resolve_snapshot(
            conn, world["identity"], request, world["clock"], signals=None
        )
        assert snapshot == resolved and canonical == world["canonical"]


@pytest.mark.parametrize(
    "selector",
    [
        {"kind": "hostname", "value": "ws01.example"},
        {"kind": "provider_id", "value": "user-01"},
    ],
)
def test_identity_selectors_do_not_normalize_email_or_hostname(db, identity_registry, selector):
    with pytest.raises(ResolutionError):
        resolve_identity(db, identity_registry, target=selector)


def test_identity_wire_rejects_unregistered_selectors():
    with pytest.raises(InvalidRequest):
        identity_request(
            {"incident": uuid4()}, target={"kind": "email", "value": "user@example.test"}
        )


def test_identity_wire_options_are_opaque_scalars_for_the_action_spec():
    """The wire bounds the shape only; the resolved action's catalog spec, not the request,
    decides which argument names an identity operation has."""
    request = identity_request({"incident": uuid4()}, arguments={"enabled": False})
    assert request.arguments.root == {"enabled": False}
    assert request.operation_ref == "identity.disable"


@pytest.mark.parametrize(
    "sql",
    [
        "UPDATE execbound.resources SET privilege_class=NULL WHERE provider='mock_entra'",
        "UPDATE execbound.resources SET environment=NULL WHERE provider='mock_entra'",
        "UPDATE execbound.resources SET criticality=NULL WHERE provider='mock_entra'",
        "UPDATE execbound.context_sources SET allowed_writers=ARRAY['agent'] "
        "WHERE kind='inventory'",
        "UPDATE execbound.context_sources SET active=false WHERE kind='inventory'",
        "UPDATE execbound.resources SET observed_at=observed_at-interval '5 minutes' "
        "WHERE provider='mock_entra'",
        "DELETE FROM execbound.incidents WHERE provider='mock_entra'",
    ],
)
def test_missing_or_untrusted_identity_facts_fail_both_reads(
    db, identity_registry, admin_engine, sql
):
    with admin_engine.begin() as conn:
        conn.execute(text(sql))
    with pytest.raises(ResolutionError):
        resolve_identity(db, identity_registry)
    with (
        pytest.raises(ResolutionError),
        db.transaction(identity_registry["identity"].tenant_id) as conn,
    ):
        resolve_snapshot(
            conn,
            identity_registry["identity"],
            identity_request(identity_registry),
            identity_registry["clock"],
            signals=None,
        )


@pytest.mark.parametrize(
    "field,value",
    [
        ("provider_operation", "enable"),
        ("context_contract_version", "endpoint-isolation.v1"),
        ("action", "endpoint.isolate"),
    ],
)
def test_invalid_stored_mapping_tuple_fails_both_reads(
    db, identity_registry, admin_engine, field, value
):
    with admin_engine.begin() as conn:
        conn.execute(
            text(
                f"UPDATE execbound.operation_mappings SET {field}=:value "
                "WHERE operation_ref='identity.disable'"
            ),
            {"value": value},
        )
    with pytest.raises(ResolutionError):
        resolve_identity(db, identity_registry)
    with (
        pytest.raises(ResolutionError),
        db.transaction(identity_registry["identity"].tenant_id) as conn,
    ):
        resolve_snapshot(
            conn,
            identity_registry["identity"],
            identity_request(identity_registry),
            identity_registry["clock"],
            signals=None,
        )


@pytest.mark.parametrize(
    "sql",
    [
        "UPDATE execbound.resources SET privilege_class='privileged' WHERE provider='mock_entra'",
        "UPDATE execbound.resources SET privilege_class='tier0' WHERE provider='mock_entra'",
        "UPDATE execbound.resources SET version='resource-v2' WHERE provider='mock_entra'",
        "UPDATE execbound.resource_aliases SET resource_id='00000000-0000-0000-0000-00000000001f' "
        "WHERE provider='mock_entra'",
        "UPDATE execbound.context_sources SET allowed_writers=ARRAY['agent'] "
        "WHERE kind='inventory'",
    ],
)
def test_changed_privilege_or_binding_invalidates_frozen_authority(
    db, identity_registry, admin_engine, sql
):
    world = identity_registry
    frozen = resolve_identity(db, world)
    with admin_engine.begin() as conn:
        conn.execute(text(sql))
    with pytest.raises(ResolutionError):
        revalidate(db, world["identity"], frozen, world["clock"])
    with pytest.raises(ResolutionError), db.transaction(world["identity"].tenant_id) as conn:
        attest_snapshot(
            conn, world["identity"], frozen, world["canonical"], world["clock"], signals=None
        )


def test_privilege_reattestation_cannot_extend_frozen_expiry(db, identity_registry, admin_engine):
    world = identity_registry
    frozen = resolve_identity(db, world)
    with admin_engine.begin() as conn:
        conn.execute(
            text("UPDATE execbound.resources SET observed_at=:now WHERE provider='mock_entra'"),
            {"now": world["clock"].now()},
        )
    assert revalidate(db, world["identity"], frozen, world["clock"]) is frozen
    world["clock"].value = frozen.valid_until
    with pytest.raises(ResolutionError):
        revalidate(db, world["identity"], frozen, world["clock"])


def test_foreign_tenant_alias_and_endpoint_incident_cannot_supply_identity_context(
    db, identity_registry, admin_engine
):
    world = identity_registry
    with admin_engine.begin() as conn:
        conn.execute(
            text(
                "DELETE FROM execbound.resource_aliases WHERE provider='mock_entra' "
                "AND tenant_id=:tenant"
            ),
            {"tenant": world["identity"].tenant_id},
        )
    with pytest.raises(ResolutionError):
        resolve_identity(db, world)
    with admin_engine.begin() as conn:
        conn.execute(
            text(
                "DELETE FROM execbound.incidents WHERE provider='mock_entra' AND tenant_id=:tenant"
            ),
            {"tenant": world["identity"].tenant_id},
        )
    with pytest.raises(ResolutionError):
        resolve_identity(db, world, target={"kind": "canonical", "value": str(world["target"])})


def test_expiry_during_privilege_snapshot_read_denies(db, identity_registry):
    world = identity_registry

    def advance(conn, cursor, statement, parameters, context, executemany):
        if "to_jsonb(m) AS mapping" in statement:
            world["clock"].value += timedelta(seconds=240)

    event.listen(db.engine, "after_cursor_execute", advance)
    try:
        with pytest.raises(ResolutionError), db.transaction(world["identity"].tenant_id) as conn:
            resolve_snapshot(
                conn, world["identity"], identity_request(world), world["clock"], signals=None
            )
    finally:
        event.remove(db.engine, "after_cursor_execute", advance)


def test_same_provider_foreign_account_alias_and_incident_stay_scoped(
    db, identity_registry, admin_engine
):
    world = identity_registry
    other = uuid4()
    params = {"old": world["account"], "new": other, "alias": uuid4()}
    with admin_engine.begin() as conn:
        conn.execute(
            text(
                "INSERT INTO execbound.connector_accounts "
                "(tenant_id, account_id, provider, active, space_id) "
                "SELECT tenant_id,:new,provider,active,space_id "
                "FROM execbound.connector_accounts WHERE account_id=:old"
            ),
            params,
        )
        for table, columns in (
            ("context_sources", "source_id,kind,allowed_writers,active"),
            (
                "resources",
                "provider,resource_type,resource_id,provider_id,version,source_id,"
                "role,environment,criticality,observed_at,active,privilege_class",
            ),
            (
                "incidents",
                "provider,resource_type,incident_id,resource_id,source_id,version,"
                "status,severity,observed_at",
            ),
            ("resource_identities", "provider,resource_type,resource_id,canonical_target_id"),
        ):
            conn.execute(
                text(
                    f"INSERT INTO execbound.{table} (tenant_id,account_id,{columns}) "
                    f"SELECT tenant_id,:new,{columns} FROM execbound.{table} "
                    "WHERE account_id=:old"
                ),
                params,
            )
        conn.execute(
            text("""
            INSERT INTO execbound.resource_aliases
            SELECT tenant_id,:alias,:new,provider,resource_type,kind,normalized_value,resource_id,
                   valid_from,expires_at FROM execbound.resource_aliases WHERE account_id=:old
        """),
            params,
        )
        conn.execute(
            text("""
            INSERT INTO execbound.operation_mappings
            SELECT tenant_id,'alternate.disable',:new,provider,resource_type,action,
                   provider_operation,mapping_version,schema_version,context_contract_version,active
            FROM execbound.operation_mappings WHERE account_id=:old
              AND operation_ref='identity.disable'
        """),
            params,
        )
    first = resolve_identity(db, world)
    second = resolve_identity(db, world, action="alternate.disable")
    assert first.intent.target_id == second.intent.target_id
    assert first.intent.account_id != second.intent.account_id == other
    assert intent_hash(first.intent) != intent_hash(second.intent)
    with admin_engine.begin() as conn:
        conn.execute(text("DELETE FROM execbound.resource_aliases WHERE account_id=:old"), params)
    with pytest.raises(ResolutionError):
        resolve_identity(db, world)
    assert resolve_identity(db, world, action="alternate.disable").intent.account_id == other
    with admin_engine.begin() as conn:
        conn.execute(text("DELETE FROM execbound.incidents WHERE account_id=:old"), params)
    with pytest.raises(ResolutionError):
        resolve_identity(db, world, target={"kind": "canonical", "value": str(world["target"])})
    assert resolve_identity(db, world, action="alternate.disable").intent.account_id == other
