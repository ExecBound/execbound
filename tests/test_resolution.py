# SPDX-License-Identifier: AGPL-3.0-only
import json
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta
from threading import Event
from uuid import UUID, uuid4

import pytest
from soc_fixtures import (
    PROBE_ACTION,
    PROBE_OPERATION,
    PROBE_VERSION,
    SECOND_OPERATION,
    SECOND_PROVIDER,
    TEST_CATALOG,
)
from sqlalchemy import event, text
from sqlalchemy.exc import DBAPIError

from execbound.contracts import PRODUCTION_CATALOG
from execbound.identity import authenticate, new_token
from execbound.policy.evaluate import evaluate
from execbound.policy.models import ProjectedUsage, UsageSnapshot
from execbound.policy.store import (
    activate_bundle,
    create_bundle,
    load_active_bundle,
    validate_bundle,
)
from execbound.requests import parse_request
from execbound.resolution import ResolutionError, issue_run, resolve_request, revalidate
from execbound.resolution import registry as registry_module
from execbound.resolution.models import SecurityVersions, intent_hash, plan_hash
from execbound_harness.demo import endpoint_bundle


class FixedClock:
    def __init__(self, now):
        self.value = now

    def now(self):
        return self.value


@pytest.fixture
def registry(db, seeded, admin_engine):
    now = datetime.now(UTC).replace(microsecond=0)
    ids = {
        key: UUID(int=value)
        for key, value in {
            "account": 10,
            "inventory": 20,
            "incident_source": 21,
            "target": 30,
            "other": 31,
            "incident": 40,
            "alias": 50,
        }.items()
    }
    with admin_engine.begin() as conn:
        for tenant in seeded["tenants"]:
            p = {
                **ids,
                "tenant": tenant,
                "now": now,
                "observed": now - timedelta(seconds=60),
                "expires": now + timedelta(days=1),
                "start": now - timedelta(days=1),
            }
            conn.execute(
                text(
                    "INSERT INTO execbound.connector_accounts(tenant_id, account_id, provider, "
                    "space_id) "
                    "VALUES (:tenant, :account, 'mock_crowdstrike', "
                    "(SELECT space_id FROM execbound.spaces WHERE tenant_id = :tenant))"
                ),
                p,
            )
            conn.execute(
                text(
                    "INSERT INTO execbound.context_sources "
                    "(tenant_id, account_id, source_id, kind, allowed_writers) "
                    "VALUES (:tenant, :account, :inventory, 'inventory', ARRAY['inventory_sync']), "
                    "(:tenant, :account, :incident_source, 'incident', ARRAY['soc_analyst'])"
                ),
                p,
            )
            conn.execute(
                text(
                    "INSERT INTO execbound.operation_mappings "
                    "(tenant_id, operation_ref, account_id, provider, resource_type, action, "
                    "provider_operation, mapping_version, schema_version, "
                    "context_contract_version) "
                    "VALUES (:tenant, 'endpoint.isolate', :account, 'mock_crowdstrike', "
                    "'endpoint', "
                    "'endpoint.isolate', 'contain', 'map-v1', 'action.v1', 'endpoint-isolation.v1')"
                ),
                p,
            )
            for resource_id, provider_id in (
                (ids["target"], "device-01"),
                (ids["other"], "device-02"),
            ):
                conn.execute(
                    text(
                        "INSERT INTO execbound.resources "
                        "(tenant_id, account_id, provider, resource_type, resource_id, "
                        "provider_id, version, source_id, role, environment, "
                        "criticality, observed_at) "
                        "VALUES (:tenant, :account, 'mock_crowdstrike', 'endpoint', :resource, "
                        ":provider_id, 'resource-v1', :inventory, 'workstation', 'production', "
                        "2, :observed)"
                    ),
                    {**p, "resource": resource_id, "provider_id": provider_id},
                )
            conn.execute(
                text(
                    "INSERT INTO execbound.resource_aliases "
                    "(tenant_id, alias_id, account_id, provider, resource_type, kind, "
                    "normalized_value, resource_id, valid_from, expires_at) "
                    "VALUES (:tenant, :alias, :account, 'mock_crowdstrike', 'endpoint', "
                    "'hostname', 'ws01.example', :target, :start, :expires)"
                ),
                p,
            )
            conn.execute(
                text(
                    "INSERT INTO execbound.incidents "
                    "(tenant_id, account_id, provider, resource_type, incident_id, resource_id, "
                    "source_id, version, status, severity, observed_at) "
                    "VALUES (:tenant, :account, 'mock_crowdstrike', 'endpoint', :incident, "
                    ":target, :incident_source, 'incident-v1', 'OPEN', 'CRITICAL', :observed)"
                ),
                p,
            )
    return {**ids, "clock": FixedClock(now), "identity": authenticate(db, seeded["tokens"][0])}


def request(registry, **changes):
    wire = {
        "operation_ref": "endpoint.isolate",
        "target": {"kind": "hostname", "value": "WS01.EXAMPLE."},
        "arguments": {},
        "idempotency_key": "retry-1",
        "claimed_context": {"incident_id": str(registry["incident"]), "severity": "LOW"},
    }
    wire.update(changes)
    return parse_request(json.dumps(wire).encode())


def resolve(db, registry, **changes):
    return resolve_request(
        db, registry["identity"], request(registry, **changes), registry["clock"]
    )


def test_resolves_scoped_target_and_independent_facts(db, registry):
    result = resolve(db, registry)
    assert result.intent.target_id == registry["target"]
    assert result.intent.account_id == registry["account"]
    assert result.fact("incident_severity").value == "CRITICAL"
    assert result.fact("is_production").value is True
    assert result.request.claimed_context.severity == "LOW"
    assert result.valid_until == registry["clock"].now() + timedelta(seconds=240)


def test_resolved_authority_evaluates_under_active_bundle(db, registry, admin_engine):
    # This fixture's normal clock is second-rounded; advance beyond credential issuance.
    registry["clock"].value = datetime.now(UTC)
    tenant = registry["identity"].tenant_id
    principal, credential = uuid4(), uuid4()
    token, digest = new_token(tenant, credential)
    expiry = registry["clock"].now() + timedelta(hours=1)
    with admin_engine.begin() as conn:
        conn.execute(
            text(
                "INSERT INTO execbound.principals (tenant_id, principal_id, kind) "
                "VALUES (:t, :p, 'ADMIN')"
            ),
            {"t": tenant, "p": principal},
        )
        conn.execute(
            text(
                "INSERT INTO execbound.credentials "
                "(tenant_id, credential_id, principal_id, token_hash, issued_at, expires_at) "
                "VALUES (:t, :c, :p, :h, :i, :e)"
            ),
            {
                "t": tenant,
                "c": credential,
                "p": principal,
                "h": digest,
                "i": registry["clock"].now(),
                "e": expiry,
            },
        )
    admin = authenticate(db, token)
    resolved = resolve(db, registry)
    hashes = []
    for _ in range(2):
        bundle = endpoint_bundle(tenant, registry["account"], mapping_version="map-v1")
        create_bundle(db, admin, bundle, registry["clock"])
        validate_bundle(db, admin, bundle.bundle_id, registry["clock"])
        activate_bundle(db, admin, bundle.bundle_id, registry["clock"])
        active = load_active_bundle(db, registry["identity"], registry["clock"])
        assert active == bundle
        usage = UsageSnapshot(
            tenant_id=tenant,
            principal_id=registry["identity"].principal_id,
            bundle_id=active.bundle_id,
            account_id=resolved.intent.account_id,
            counts=tuple(
                ProjectedUsage(rule_id=r.rule_id, confirmed_targets=0, unresolved_targets=0)
                for r in active.limits
            ),
        )
        result = evaluate(
            bundle=active,
            identity=registry["identity"],
            resolved=resolved,
            usage=usage,
            clock=registry["clock"],
        )
        assert result.effect == "REQUIRE_APPROVAL"
        assert result.obligation_ids == ("policy:policy0",)
        assert result.plan_hash == plan_hash(resolved, active.security_versions)
        hashes.append(result.plan_hash)
    assert hashes[0] != hashes[1]


def test_intent_hash_ignores_alias_retry_run_and_claims(db, registry):
    first = resolve(db, registry)
    run = issue_run(db, registry["identity"], registry["clock"])
    second = resolve(
        db,
        registry,
        target={"kind": "canonical", "value": str(registry["target"])},
        idempotency_key="another-key",
        run_id=str(run),
        claimed_context={"incident_id": str(registry["incident"]), "role": "domain_controller"},
    )
    assert intent_hash(first.intent) == intent_hash(second.intent)


def test_colliding_tenant_aliases_do_not_cross(db, seeded, registry):
    first = resolve(db, registry)
    second_identity = authenticate(db, seeded["tokens"][1])
    second = resolve_request(db, second_identity, request(registry), registry["clock"])
    assert first.intent.target_id == second.intent.target_id
    assert first.intent.tenant_id != second.intent.tenant_id
    assert intent_hash(first.intent) != intent_hash(second.intent)


@pytest.mark.parametrize(
    "sql",
    [
        "UPDATE execbound.incidents SET resource_id = '00000000-0000-0000-0000-00000000001f'",
        "UPDATE execbound.context_sources "
        "SET allowed_writers = ARRAY['soc_analyst', 'protected_agent'] WHERE kind = 'incident'",
        "UPDATE execbound.resources SET criticality = NULL",
        "UPDATE execbound.incidents SET observed_at = observed_at - interval '10 minutes'",
        "UPDATE execbound.resources SET observed_at = observed_at + interval '10 minutes'",
        "UPDATE execbound.resource_aliases SET expires_at = valid_from + interval '1 hour'",
        "UPDATE execbound.context_sources SET active = false",
        "UPDATE execbound.operation_mappings SET action = 'generic.http'",
        "UPDATE execbound.operation_mappings SET context_contract_version = 'unknown'",
        "UPDATE execbound.connector_accounts SET active = false",
        "UPDATE execbound.resources SET active = false",
        "UPDATE execbound.incidents SET severity = NULL",
        "UPDATE execbound.context_sources SET kind = 'inventory' WHERE kind = 'incident'",
        "UPDATE execbound.credentials SET revoked_at = now()",
        "UPDATE execbound.principals SET active = false",
    ],
)
def test_required_context_and_mapping_fail_closed(db, registry, admin_engine, sql):
    with admin_engine.begin() as conn:
        conn.execute(text(sql))
    with pytest.raises(ResolutionError):
        resolve(db, registry)


def test_claims_cannot_replace_missing_incident(db, registry):
    with pytest.raises(ResolutionError):
        resolve(db, registry, claimed_context={"severity": "CRITICAL"})


def test_unknown_operation_fails_without_foreign_disclosure(db, registry):
    with pytest.raises(ResolutionError, match="Resolution unavailable"):
        resolve(db, registry, operation_ref="other.operation")


def test_run_is_principal_scoped_and_expiring(db, seeded, registry):
    run = issue_run(db, registry["identity"], registry["clock"], lifetime_seconds=30)
    identity = authenticate(db, seeded["tokens"][1])
    with pytest.raises(ResolutionError):
        resolve_request(db, identity, request(registry, run_id=str(run)), registry["clock"])
    registry["clock"].value += timedelta(seconds=30)
    with pytest.raises(ResolutionError):
        resolve(db, registry, run_id=str(run))


def test_runtime_registry_is_read_only_and_scoped(db, registry, seeded):
    with pytest.raises(DBAPIError), db.transaction(seeded["tenants"][0]) as conn:
        conn.execute(text("UPDATE execbound.resources SET role = 'domain_controller'"))
    with db.transaction(seeded["tenants"][0]) as conn:
        assert conn.execute(
            text("SELECT DISTINCT tenant_id FROM execbound.resources")
        ).scalars().all() == [seeded["tenants"][0]]


def test_revalidation_keeps_original_snapshot_on_reattestation(db, registry, admin_engine):
    original = resolve(db, registry)
    with admin_engine.begin() as conn:
        conn.execute(
            text("UPDATE execbound.resources SET observed_at = :now"),
            {"now": registry["clock"].now()},
        )
    assert revalidate(db, registry["identity"], original, registry["clock"]) is original
    registry["clock"].value = original.valid_until
    with pytest.raises(ResolutionError) as error:
        revalidate(db, registry["identity"], original, registry["clock"])
    assert error.value.code == "STALE_AUTHORIZATION"


@pytest.mark.parametrize(
    "sql",
    [
        "UPDATE execbound.resources SET version = 'resource-v2'",
        "UPDATE execbound.resources SET environment = 'staging'",
        "UPDATE execbound.incidents SET version = 'incident-v2'",
        "UPDATE execbound.resource_aliases "
        "SET resource_id = '00000000-0000-0000-0000-00000000001f'",
        "UPDATE execbound.operation_mappings SET mapping_version = 'map-v2'",
    ],
)
def test_revalidation_detects_changed_bound_evidence(db, registry, admin_engine, sql):
    original = resolve(db, registry)
    with admin_engine.begin() as conn:
        conn.execute(text(sql))
    with pytest.raises(ResolutionError) as error:
        revalidate(db, registry["identity"], original, registry["clock"])
    assert error.value.code == "STALE_AUTHORIZATION"


def test_plan_hash_binds_security_versions_and_is_immutable(db, registry):
    result = resolve(db, registry)
    versions = SecurityVersions(bundle="b1", authorization="a1", approval="h1", limits="l1")
    other = SecurityVersions(bundle="b2", authorization="a1", approval="h1", limits="l1")
    assert plan_hash(result, versions) != plan_hash(result, other)
    with pytest.raises((AttributeError, ValueError)):
        result.fact("environment").value = "development"


def test_resolution_rejects_expiry_during_database_read(db, registry):
    def advance_clock(conn, cursor, statement, parameters, context, executemany):
        if "FROM execbound.resources r" in statement:
            registry["clock"].value += timedelta(seconds=240)

    event.listen(db.engine, "before_cursor_execute", advance_clock)
    try:
        with pytest.raises(ResolutionError):
            resolve(db, registry)
    finally:
        event.remove(db.engine, "before_cursor_execute", advance_clock)


def test_revalidation_rejects_old_expiry_during_fresh_reattestation(db, registry, admin_engine):
    original = resolve(db, registry)
    registry["clock"].value += timedelta(seconds=239)
    with admin_engine.begin() as conn:
        for table in ("resources", "incidents"):
            conn.execute(
                text(f"UPDATE execbound.{table} SET observed_at = :now"),
                {"now": registry["clock"].now()},
            )

    def advance_clock(conn, cursor, statement, parameters, context, executemany):
        if "FROM execbound.resources r" in statement:
            registry["clock"].value += timedelta(seconds=1)

    event.listen(db.engine, "before_cursor_execute", advance_clock)
    try:
        with pytest.raises(ResolutionError) as error:
            revalidate(db, registry["identity"], original, registry["clock"])
        assert error.value.code == "STALE_AUTHORIZATION"
    finally:
        event.remove(db.engine, "before_cursor_execute", advance_clock)


def test_hashes_are_independent_of_database_session_timezone(db, registry):
    zone = "UTC"

    def set_zone(conn, cursor, statement, parameters, context, executemany):
        if "set_config('execbound.tenant_id'" in statement:
            cursor.execute("SELECT set_config('TimeZone', %s, true)", (zone,))

    event.listen(db.engine, "before_cursor_execute", set_zone)
    try:
        first = resolve(db, registry)
        zone = "America/New_York"
        second = resolve(db, registry)
    finally:
        event.remove(db.engine, "before_cursor_execute", set_zone)
    versions = SecurityVersions(bundle="b1", authorization="a1", approval="h1", limits="l1")
    assert plan_hash(first, versions) == plan_hash(second, versions)
    assert second.fact("environment").observed_at.utcoffset() == timedelta(0)


def test_concurrent_registry_update_cannot_mix_snapshots(db, registry, admin_engine):
    reading = Event()
    committed = Event()

    def update_records():
        assert reading.wait(5), "Resolver did not reach the resource read"
        try:
            with admin_engine.begin() as conn:
                conn.execute(text("UPDATE execbound.resources SET version = 'resource-v2'"))
                conn.execute(text("UPDATE execbound.incidents SET severity = 'HIGH'"))
        finally:
            committed.set()

    def pause_read(conn, cursor, statement, parameters, context, executemany):
        if "FROM execbound.resources r" in statement:
            reading.set()
            assert committed.wait(5), "Concurrent update did not commit"

    event.listen(db.engine, "before_cursor_execute", pause_read)
    try:
        with ThreadPoolExecutor(max_workers=1) as executor:
            writer = executor.submit(update_records)
            original = resolve(db, registry)
            writer.result(timeout=5)
    finally:
        event.remove(db.engine, "before_cursor_execute", pause_read)
    assert original.resource_version == "resource-v1"
    assert original.fact("incident_severity").value == "CRITICAL"
    current = resolve(db, registry)
    assert current.resource_version == "resource-v2"
    assert current.fact("incident_severity").value == "HIGH"


def test_overlapping_aliases_fail_closed(db, registry, admin_engine):
    with admin_engine.begin() as conn:
        conn.execute(
            text("""
            INSERT INTO execbound.resource_aliases
            SELECT tenant_id, '00000000-0000-0000-0000-000000000033', account_id,
                   provider, resource_type, kind, normalized_value, resource_id,
                   valid_from, expires_at
            FROM execbound.resource_aliases
        """)
        )
    with pytest.raises(ResolutionError):
        resolve(db, registry)


def test_provider_id_alias_is_case_sensitive(db, registry, admin_engine):
    with admin_engine.begin() as conn:
        conn.execute(
            text("""
            INSERT INTO execbound.resource_aliases
            SELECT tenant_id, '00000000-0000-0000-0000-000000000033', account_id,
                   provider, resource_type, 'provider_id', 'Device-01', resource_id,
                   valid_from, expires_at
            FROM execbound.resource_aliases
        """)
        )
    result = resolve(db, registry, target={"kind": "provider_id", "value": "Device-01"})
    assert result.intent.target_id == registry["target"]
    with pytest.raises(ResolutionError):
        resolve(db, registry, target={"kind": "provider_id", "value": "device-01"})


@pytest.fixture
def other_account(registry, admin_engine):
    account = uuid4()
    params = {
        "tenant": registry["identity"].tenant_id,
        "old": registry["account"],
        "new": account,
    }
    with admin_engine.begin() as conn:
        conn.execute(
            text("""
                INSERT INTO execbound.connector_accounts
                    (tenant_id, account_id, provider, active, space_id)
                SELECT tenant_id, :new, provider, active, space_id
                  FROM execbound.connector_accounts
                 WHERE tenant_id = :tenant AND account_id = :old
            """),
            params,
        )
        for table, columns in (
            ("context_sources", "source_id, kind, allowed_writers, active"),
            (
                "resources",
                "provider, resource_type, resource_id, provider_id, version, source_id, "
                "role, environment, criticality, observed_at, active",
            ),
            (
                "incidents",
                "provider, resource_type, incident_id, resource_id, source_id, "
                "version, status, severity, observed_at",
            ),
        ):
            conn.execute(
                text(f"""
                    INSERT INTO execbound.{table} (tenant_id, account_id, {columns})
                    SELECT tenant_id, :new, {columns} FROM execbound.{table}
                    WHERE tenant_id = :tenant AND account_id = :old
                """),
                params,
            )
        conn.execute(
            text("""
                INSERT INTO execbound.resource_aliases
                SELECT tenant_id, '00000000-0000-0000-0000-000000000034', :new, provider,
                       resource_type, kind, normalized_value, resource_id, valid_from, expires_at
                FROM execbound.resource_aliases
                WHERE tenant_id = :tenant AND account_id = :old
            """),
            params,
        )
        conn.execute(
            text("""
                INSERT INTO execbound.operation_mappings
                SELECT tenant_id, 'alternate.isolate', :new, provider, resource_type, action,
                       provider_operation, mapping_version, schema_version,
                       context_contract_version, active
                FROM execbound.operation_mappings
                WHERE tenant_id = :tenant AND account_id = :old
            """),
            params,
        )
    return account


def test_same_ids_in_other_account_remain_distinct(db, registry, other_account):
    first = resolve(db, registry)
    second = resolve(db, registry, operation_ref="alternate.isolate")
    assert first.intent.target_id == second.intent.target_id
    assert first.intent.account_id != second.intent.account_id == other_account
    assert intent_hash(first.intent) != intent_hash(second.intent)


def test_other_account_incident_cannot_fill_required_context(
    db, registry, other_account, admin_engine
):
    with admin_engine.begin() as conn:
        conn.execute(
            text("DELETE FROM execbound.incidents WHERE account_id = :account"),
            {"account": registry["account"]},
        )
    with pytest.raises(ResolutionError):
        resolve(db, registry)
    assert (
        resolve(db, registry, operation_ref="alternate.isolate").intent.account_id == other_account
    )


def test_foreign_account_source_relationship_is_rejected(db, registry, other_account, admin_engine):
    source = uuid4()
    with admin_engine.begin() as conn:
        conn.execute(
            text("""
                INSERT INTO execbound.context_sources
                (tenant_id, account_id, source_id, kind, allowed_writers)
                VALUES (:tenant, :account, :source, 'inventory', ARRAY['inventory_sync'])
            """),
            {"tenant": registry["identity"].tenant_id, "account": other_account, "source": source},
        )
    with pytest.raises(DBAPIError), admin_engine.begin() as conn:
        conn.execute(
            text("UPDATE execbound.resources SET source_id = :source WHERE account_id = :account"),
            {"source": source, "account": registry["account"]},
        )


def test_revalidation_rejects_account_remapping(db, registry, other_account, admin_engine):
    original = resolve(db, registry)
    with admin_engine.begin() as conn:
        conn.execute(
            text("""
                UPDATE execbound.operation_mappings SET account_id = :account
                WHERE tenant_id = :tenant AND operation_ref = 'endpoint.isolate'
            """),
            {"account": other_account, "tenant": registry["identity"].tenant_id},
        )
    with pytest.raises(ResolutionError) as error:
        revalidate(db, registry["identity"], original, registry["clock"])
    assert error.value.code == "STALE_AUTHORIZATION"


def test_run_cannot_be_used_by_another_principal_in_same_tenant(db, registry, admin_engine):
    run = issue_run(db, registry["identity"], registry["clock"])
    tenant = registry["identity"].tenant_id
    principal, credential = uuid4(), uuid4()
    token, digest = new_token(tenant, credential)
    with admin_engine.begin() as conn:
        conn.execute(
            text("""
                INSERT INTO execbound.principals(tenant_id, principal_id, kind, space_id)
                VALUES (:tenant, :principal, 'AGENT', 
                    (SELECT space_id FROM execbound.spaces WHERE tenant_id = :tenant))
            """),
            {"tenant": tenant, "principal": principal},
        )
        conn.execute(
            text("""
                INSERT INTO execbound.credentials
                (tenant_id, credential_id, principal_id, token_hash, expires_at)
                VALUES (:tenant, :credential, :principal, :digest, :expiry)
            """),
            {
                "tenant": tenant,
                "credential": credential,
                "principal": principal,
                "digest": digest,
                "expiry": registry["identity"].expires_at,
            },
        )
    other = authenticate(db, token)
    with pytest.raises(ResolutionError) as error:
        resolve_request(db, other, request(registry, run_id=str(run)), registry["clock"])
    assert error.value.code == "INVALID_RUN"


@pytest.mark.parametrize("changed", ["alias", "run", "observation"])
def test_revalidation_rejects_shortened_or_regressing_evidence(db, registry, admin_engine, changed):
    run = issue_run(db, registry["identity"], registry["clock"], lifetime_seconds=200)
    original = resolve(db, registry, run_id=str(run))
    with admin_engine.begin() as conn:
        if changed == "alias":
            conn.execute(
                text("UPDATE execbound.resource_aliases SET expires_at = :expiry"),
                {"expiry": registry["clock"].now() + timedelta(seconds=30)},
            )
        elif changed == "run":
            conn.execute(
                text("UPDATE execbound.agent_runs SET expires_at = :expiry"),
                {"expiry": registry["clock"].now() + timedelta(seconds=30)},
            )
        else:
            # Run expiry still bounds the aggregate deadline; inspect each fact too.
            conn.execute(
                text(
                    "UPDATE execbound.resources SET observed_at = observed_at - interval '1 second'"
                )
            )
    with pytest.raises(ResolutionError) as error:
        revalidate(db, registry["identity"], original, registry["clock"])
    assert error.value.code == "STALE_AUTHORIZATION"


def seed_soc_mappings(engine, registry):
    """Lift and probe mappings on the endpoint account; a second-provider account and binding."""
    tenant = registry["identity"].tenant_id
    second_account = UUID(int=11)
    with engine.begin() as conn:
        for ref, action, operation, contract in (
            (
                "endpoint.lift_isolation",
                "endpoint.lift_isolation",
                "lift_containment",
                "endpoint-recovery.v1",
            ),
            (PROBE_OPERATION, PROBE_ACTION, "probe", PROBE_VERSION),
        ):
            conn.execute(
                text(
                    "INSERT INTO execbound.operation_mappings "
                    "(tenant_id, operation_ref, account_id, provider, resource_type, action, "
                    "provider_operation, mapping_version, schema_version, "
                    "context_contract_version) "
                    "VALUES (:t, :ref, :a, 'mock_crowdstrike', 'endpoint', :action, :operation, "
                    "'map-v1', 'action.v1', :contract)"
                ),
                {
                    "t": tenant,
                    "ref": ref,
                    "a": registry["account"],
                    "action": action,
                    "operation": operation,
                    "contract": contract,
                },
            )
        conn.execute(
            text(
                "INSERT INTO execbound.connector_accounts(tenant_id, account_id, provider, "
                "space_id) "
                "VALUES (:t, :a, :provider, "
                "(SELECT space_id FROM execbound.spaces WHERE tenant_id = :t))"
            ),
            {"t": tenant, "a": second_account, "provider": SECOND_PROVIDER},
        )
        conn.execute(
            text(
                "INSERT INTO execbound.operation_mappings "
                "(tenant_id, operation_ref, account_id, provider, resource_type, action, "
                "provider_operation, mapping_version, schema_version, context_contract_version) "
                "VALUES (:t, :ref, :a, :provider, 'endpoint', 'endpoint.isolate', 'isolate', "
                "'map-v1', 'action.v1', 'endpoint-isolation.v1')"
            ),
            {
                "t": tenant,
                "ref": SECOND_OPERATION,
                "a": second_account,
                "provider": SECOND_PROVIDER,
            },
        )
    return second_account


def test_lift_isolation_arguments_are_normalized_against_the_catalog(db, registry, admin_engine):
    seed_soc_mappings(admin_engine, registry)
    result = resolve(
        db, registry, operation_ref="endpoint.lift_isolation", arguments={"reason": "remediated"}
    )
    assert result.intent.action == "endpoint.lift_isolation"
    assert result.intent.provider_operation == "lift_containment"
    assert result.intent.arguments.root == {"reason": "remediated"}
    assert result.context_contract_version == "endpoint-recovery.v1"
    assert result.fact("incident_status").source_object_id == str(registry["incident"])


@pytest.mark.parametrize(
    "operation_ref,arguments",
    [
        ("endpoint.lift_isolation", {}),
        ("endpoint.lift_isolation", {"reason": "other"}),
        ("endpoint.lift_isolation", {"reason": "remediated", "extra": True}),
        ("endpoint.lift_isolation", {"reason": True}),
        ("endpoint.isolate", {"reason": "remediated"}),
        # Scenario Q: a second target named in arguments is rejected by normalization alone.
        ("endpoint.isolate", {"target": str(UUID(int=31))}),
        ("endpoint.isolate", {"device_id": "device-02"}),
    ],
)
def test_arguments_outside_the_action_spec_fail_before_facts(
    db, registry, admin_engine, operation_ref, arguments
):
    seed_soc_mappings(admin_engine, registry)
    # The scenario-Q cases name registry["other"]; keep the parametrized literal honest.
    assert str(UUID(int=31)) == str(registry["other"])
    with pytest.raises(ResolutionError) as failure:
        resolve(db, registry, operation_ref=operation_ref, arguments=arguments)
    assert failure.value.code == "INVALID_ARGUMENTS"


def test_synthetic_long_argument_resolves_only_with_its_catalog(db, registry, admin_engine):
    seed_soc_mappings(admin_engine, registry)
    result = resolve_request(
        db,
        registry["identity"],
        request(registry, operation_ref=PROBE_OPERATION, arguments={"depth": 3}),
        registry["clock"],
        catalog=TEST_CATALOG,
    )
    assert result.intent.action == PROBE_ACTION and result.intent.arguments.root == {"depth": 3}
    for depth in (0, 6, "3", True):
        with pytest.raises(ResolutionError) as failure:
            resolve_request(
                db,
                registry["identity"],
                request(registry, operation_ref=PROBE_OPERATION, arguments={"depth": depth}),
                registry["clock"],
                catalog=TEST_CATALOG,
            )
        assert failure.value.code == "INVALID_ARGUMENTS"
    with pytest.raises(ResolutionError) as failure:
        resolve(db, registry, operation_ref=PROBE_OPERATION, arguments={"depth": 3})
    assert failure.value.code == "INVALID_OPERATION"


def test_second_provider_binding_resolves_through_a_tenant_mapping(db, registry, admin_engine):
    seed_soc_mappings(admin_engine, registry)
    tenant = registry["identity"].tenant_id
    with db.transaction(tenant) as conn:
        row = registry_module.mapping(conn, tenant, SECOND_OPERATION, catalog=TEST_CATALOG)
        spec = registry_module.mapping_contract(row, catalog=TEST_CATALOG)
        assert (spec.provider, spec.provider_operation) == (SECOND_PROVIDER, "isolate")
        with pytest.raises(ResolutionError) as failure:
            registry_module.mapping(conn, tenant, SECOND_OPERATION, catalog=PRODUCTION_CATALOG)
        assert failure.value.code == "INVALID_OPERATION"
        with pytest.raises(ResolutionError):
            registry_module.mapping_contract(
                {**row, "provider": "mock_crowdstrike"}, catalog=TEST_CATALOG
            )
