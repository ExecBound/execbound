# SPDX-License-Identifier: AGPL-3.0-only
"""Trusted context provisioning: manifests, the importer, sources and the adapter (CP1 to CP12)."""

import contextlib
import copy
import errno
import hashlib
import json
import os
import sys
import time
from datetime import timedelta
from pathlib import Path
from types import MappingProxyType
from uuid import UUID, uuid4, uuid5

import pytest
from context_fixtures import CATALOG, SYNTHETIC_OPERATION, SYNTHETIC_VERSION, synthetic_bundle
from sqlalchemy import event, text
from sqlalchemy.exc import DBAPIError
from test_execution import provision_identity
from test_execution import world as world
from test_protected_path import connector as connector
from test_protected_path import live_provider as live_provider
from test_resolution import registry as registry
from test_resolution import request as v1_request

from execbound import administration as admin
from execbound import provisioning
from execbound.cli import main
from execbound.contracts import (
    PRODUCTION_CATALOG,
    Catalog,
    ContextContract,
    FactRow,
    FactSpec,
    SourceDefaults,
    StringDomain,
)
from execbound.db import check_runtime
from execbound.execution import admit
from execbound.policy.store import activate_bundle, create_bundle, validate_bundle
from execbound.requests import parse_request
from execbound.resolution import ResolutionError, resolve_request
from execbound.runtime import Runtime
from execbound_harness.context_manifests import AdapterError, incident_manifest, inventory_manifest

FIXTURES = Path(__file__).parent / "fixtures"
APPROVE_RISKY = (
    'permit(principal, action == ExecBound::Action::"endpoint.isolate", resource) '
    "when { resource.risk_score >= 60 };"
)
ROW_FACTS = {"exposure": "internal", "risk_score": 70, "edr_managed": True}
FACT_TABLES = ("context_sources", "resources", "incidents", "resource_facts")


@pytest.fixture
def owner(seeded):
    engine = admin.owner_engine(os.environ["TEST_MIGRATION_DATABASE_URL"])
    yield engine
    engine.dispose()


@pytest.fixture
def cli_env(monkeypatch):
    monkeypatch.setenv("DATABASE_URL", os.environ["TEST_DATABASE_URL"])
    monkeypatch.setenv("MIGRATION_DATABASE_URL", os.environ["TEST_MIGRATION_DATABASE_URL"])


def tenant_of(world):
    return world["identity"].tenant_id


def manifest(world, *entries, kind="inventory", **changes):
    source = world["inventory"] if kind == "inventory" else world["incident_source"]
    document = {
        "manifest": "execbound.context-manifest.v1",
        "tenant_id": str(tenant_of(world)),
        "account_id": str(world["account"]),
        "source_id": str(source),
        "kind": kind,
        "writer": "inventory_sync" if kind == "inventory" else "soc_analyst",
        "entries": list(entries),
    }
    document.update(changes)
    return document


def entry(observed, *, provider_id="device-01", version="snap-1", facts=None, **extra):
    item = {
        "provider": "mock_crowdstrike",
        "resource_type": "endpoint",
        "provider_id": provider_id,
        "version": version,
        "observed_at": observed.isoformat(),
        "facts": dict(ROW_FACTS if facts is None else facts),
    }
    item.update(extra)
    return item


def encode(document):
    return json.dumps(document).encode()


def apply(owner, world, document, **options):
    parsed = provisioning.parse_manifest(encode(document))
    options.setdefault("catalog", CATALOG)
    return provisioning.import_manifest(
        owner,
        tenant_of(world),
        parsed,
        world["admin"].principal_id,
        now=world["clock"].now(),
        **options,
    )


def refused(owner, world, document, **options):
    with pytest.raises(provisioning.ProvisioningError) as caught:
        apply(owner, world, document, **options)
    return caught.value


@contextlib.contextmanager
def statements(engine):
    """Every statement one engine sends while the block runs, one entry per round trip.

    A batched `executemany` is one entry, as it is one exchange with the server. Counting
    round trips says what seconds on a shared machine cannot: whether a bound is checked
    before the database is touched at all, and whether the importer's work per entry
    happens in the database or in a round trip of its own.
    """
    seen = []

    def record(conn, cursor, statement, parameters, context, executemany):
        seen.append(statement)

    event.listen(engine, "before_cursor_execute", record)
    try:
        yield seen
    finally:
        event.remove(engine, "before_cursor_execute", record)


def scoped(engine, tenant, statement, **params):
    # On `admin_engine` the fence limits nothing, since its owner bypasses row security (see
    # tenant_fence), so each statement names its tenant through `:t` as well.
    with engine.begin() as conn:
        conn.execute(text("SELECT set_config('execbound.tenant_id', :t, true)"), {"t": str(tenant)})
        return conn.execute(text(statement), {"t": tenant, **params}).mappings().all()


def fact_rows(engine, world, resource=None):
    rows = scoped(
        engine,
        tenant_of(world),
        "SELECT fact_name, value, version, source_id, observed_at FROM execbound.resource_facts "
        "WHERE tenant_id = :t AND resource_id = :r ORDER BY fact_name",
        r=resource or world["target"],
    )
    return {
        row["fact_name"]: (row["value"], row["version"], row["source_id"], row["observed_at"])
        for row in rows
    }


def resource_row(engine, world, resource=None):
    rows = scoped(
        engine,
        tenant_of(world),
        "SELECT * FROM execbound.resources WHERE tenant_id = :t AND resource_id = :r",
        r=resource or world["target"],
    )
    return dict(rows[0])


def incident_row(engine, world, incident):
    rows = scoped(
        engine,
        tenant_of(world),
        "SELECT * FROM execbound.incidents WHERE tenant_id = :t AND incident_id = :i",
        i=incident,
    )
    return dict(rows[0]) if rows else None


def audit_payloads(engine, tenant, kind):
    rows = scoped(
        engine,
        tenant,
        "SELECT payload, actor_id FROM execbound.audit_events "
        "WHERE tenant_id = :t AND kind = :k ORDER BY sequence",
        k=kind,
    )
    return [(row["actor_id"], row["payload"]) for row in rows]


def synthetic_mapping(engine, world):
    with engine.begin() as conn:
        conn.execute(
            text(
                "INSERT INTO execbound.operation_mappings "
                "(tenant_id, operation_ref, account_id, provider, resource_type, action, "
                "provider_operation, mapping_version, schema_version, context_contract_version) "
                "VALUES (:t, :op, :a, 'mock_crowdstrike', 'endpoint', 'endpoint.isolate', "
                "'contain', 'map-v1', 'action.v1', :version)"
            ),
            {
                "t": tenant_of(world),
                "op": SYNTHETIC_OPERATION,
                "a": world["account"],
                "version": SYNTHETIC_VERSION,
            },
        )


def synthetic_request(world, key="facts-1"):
    return parse_request(
        json.dumps(
            {
                "operation_ref": SYNTHETIC_OPERATION,
                "target": {"kind": "canonical", "value": str(world["target"])},
                "arguments": {},
                "idempotency_key": key,
            }
        ).encode()
    )


def resolve_synthetic(db, world):
    return resolve_request(
        db, world["identity"], synthetic_request(world), world["clock"], catalog=CATALOG
    )


def activate_synthetic(db, world, **changes):
    bundle = synthetic_bundle(tenant_of(world), world["account"], **changes)
    create_bundle(db, world["admin"], bundle, world["clock"])
    validate_bundle(db, world["admin"], bundle.bundle_id, world["clock"], catalog=CATALOG)
    activate_bundle(db, world["admin"], bundle.bundle_id, world["clock"], catalog=CATALOG)


def isolate_wire(world, incident, key):
    return json.dumps(
        {
            "operation_ref": "endpoint.isolate",
            "target": {"kind": "hostname", "value": "ws01.example"},
            "arguments": {},
            "idempotency_key": key,
            "claimed_context": {"incident_id": str(incident)},
        }
    ).encode()


def run_cli(monkeypatch, capsys, *argv):
    monkeypatch.setattr(sys, "argv", ["execbound", *argv])
    main()
    return json.loads(capsys.readouterr().out)


def refused_cli(monkeypatch, capsys, *argv):
    monkeypatch.setattr(sys, "argv", ["execbound", *argv])
    with pytest.raises(SystemExit) as caught:
        main()
    assert caught.value.code == 2
    return capsys.readouterr().err


def test_cp1_inventory_manifest_writes_facts_columns_and_audit(db, world, owner, admin_engine):
    synthetic_mapping(admin_engine, world)
    observed = world["clock"].now() - timedelta(seconds=30)
    document = manifest(
        world,
        entry(
            observed,
            facts={**ROW_FACTS, "environment": "staging", "criticality": 3},
            provider_version="resource-v2",
        ),
    )
    result = apply(owner, world, document)
    assert result.counts == {
        "entries": 1,
        "applied": 1,
        "unchanged": 0,
        "unknown_resources": 0,
        "facts_written": 5,
        "facts_retracted": 0,
        "resources_deactivated": 0,
        "incidents_created": 0,
        "incidents_updated": 0,
    }
    assert result.outcomes == ("applied",)
    rows = fact_rows(admin_engine, world)
    assert rows == {
        name: (value, "snap-1", world["inventory"], observed) for name, value in ROW_FACTS.items()
    }
    resource = resource_row(admin_engine, world)
    assert (resource["environment"], resource["criticality"], resource["role"]) == (
        "staging",
        3,
        "workstation",
    )
    assert (resource["version"], resource["observed_at"], resource["active"]) == (
        "resource-v2",
        observed,
        True,
    )

    resolved = resolve_synthetic(db, world)
    assert [(f.name, f.value, f.source_version) for f in resolved.facts][:3] == [
        ("exposure", "internal", "snap-1"),
        ("risk_score", 70, "snap-1"),
        ("edr_managed", True, "snap-1"),
    ]
    v1 = resolve_request(db, world["identity"], v1_request(world), world["clock"])
    facts = {f.name: (f.value, f.source_version) for f in v1.facts}
    assert facts["environment"] == ("staging", "resource-v2")
    assert facts["criticality"] == (3, "resource-v2")
    assert facts["is_production"] == (False, "resource-v2")
    assert v1.resource_version == "resource-v2"

    events = audit_payloads(admin_engine, tenant_of(world), "context.imported")
    assert len(events) == 1
    actor, payload = events[0]
    assert actor == world["admin"].principal_id
    assert payload["manifest_digest"] == hashlib.sha256(encode(document)).hexdigest()
    assert payload["source_id"] == str(world["inventory"])
    assert payload["writer"] == "inventory_sync" and payload["kind"] == "inventory"
    assert {key: payload[key] for key in result.counts} == result.counts
    assert "internal" not in json.dumps(payload)


def test_cp2_unchanged_content_keeps_versions_and_pending_approval(db, world, owner, admin_engine):
    synthetic_mapping(admin_engine, world)
    first = world["clock"].now() - timedelta(seconds=40)
    apply(owner, world, manifest(world, entry(first)))
    activate_synthetic(db, world, approval_policies=APPROVE_RISKY)
    request = synthetic_request(world)
    assert admit(db, world["identity"], request, world["clock"], catalog=CATALOG).view.state == (
        "PENDING_APPROVAL"
    )

    again = apply(owner, world, manifest(world, entry(first)))
    assert (again.counts["applied"], again.counts["unchanged"]) == (0, 1)
    assert again.outcomes == ("unchanged",)
    assert fact_rows(admin_engine, world) == {
        name: (value, "snap-1", world["inventory"], first) for name, value in ROW_FACTS.items()
    }

    later = world["clock"].now() - timedelta(seconds=20)
    relabelled = apply(owner, world, manifest(world, entry(later, version="snap-2")))
    assert (relabelled.counts["applied"], relabelled.counts["facts_written"]) == (1, 0)
    assert fact_rows(admin_engine, world) == {
        name: (value, "snap-1", world["inventory"], later) for name, value in ROW_FACTS.items()
    }
    retried = admit(db, world["identity"], request, world["clock"], catalog=CATALOG)
    assert retried.view.state == "PENDING_APPROVAL"
    assert len(audit_payloads(admin_engine, tenant_of(world), "context.imported")) == 3


def test_cp3_changed_fact_changes_only_its_version_and_stales_approval(
    db, world, owner, admin_engine
):
    synthetic_mapping(admin_engine, world)
    first = world["clock"].now() - timedelta(seconds=40)
    apply(owner, world, manifest(world, entry(first)))
    activate_synthetic(db, world, approval_policies=APPROVE_RISKY)
    request = synthetic_request(world)
    assert admit(db, world["identity"], request, world["clock"], catalog=CATALOG).view.state == (
        "PENDING_APPROVAL"
    )
    later = world["clock"].now() - timedelta(seconds=20)
    changed = apply(
        owner, world, manifest(world, entry(later, version="snap-2", facts={"risk_score": 80}))
    )
    assert changed.counts["facts_written"] == 1
    rows = fact_rows(admin_engine, world)
    assert rows["risk_score"] == (80, "snap-2", world["inventory"], later)
    assert rows["exposure"] == ("internal", "snap-1", world["inventory"], first)
    assert rows["edr_managed"] == (True, "snap-1", world["inventory"], first)
    retried = admit(db, world["identity"], request, world["clock"], catalog=CATALOG)
    assert retried.view.state == "STALE_AUTHORIZATION"


def test_cp4_regression_future_and_reused_version_refuse_everything(world, owner, admin_engine):
    now = world["clock"].now()
    apply(owner, world, manifest(world, entry(now - timedelta(seconds=30))))
    before = fact_rows(admin_engine, world), resource_row(admin_engine, world)
    cases = {
        "OBSERVATION_REGRESSION": entry(now - timedelta(seconds=45), version="snap-2"),
        "FUTURE_OBSERVATION": entry(now + timedelta(seconds=61), version="snap-2"),
        "VERSION_REUSED": entry(now - timedelta(seconds=10), facts={"risk_score": 5}),
    }
    for code, item in cases.items():
        error = refused(owner, world, manifest(world, item))
        assert (error.code, error.entry) == (code, 0), code
    assert (fact_rows(admin_engine, world), resource_row(admin_engine, world)) == before
    # The regression check also covers the resources row a column fact touches.
    error = refused(
        owner,
        world,
        manifest(world, entry(now - timedelta(seconds=90), facts={"environment": "staging"})),
    )
    assert error.code == "OBSERVATION_REGRESSION"
    assert len(audit_payloads(admin_engine, tenant_of(world), "context.imported")) == 1
    assert apply(
        owner, world, manifest(world, entry(now + timedelta(seconds=59), version="snap-3"))
    ).outcomes == ("applied",)


ROLE_ROW = ContextContract(
    version="role-row.test",
    resource_type="endpoint",
    cedar_entity_type="Endpoint",
    actions=frozenset({"endpoint.isolate"}),
    incident="none",
    bind_incident_claim=False,
    display_fact="role",
    sources=MappingProxyType({"inventory": SourceDefaults(300, 3600, ("inventory_sync",))}),
    facts=(
        FactSpec("role", "String", StringDomain(frozenset({"server"})), "inventory", FactRow()),
    ),
)


def test_cp5_fact_names_and_values_are_checked_against_the_catalog(world, owner, admin_engine):
    observed = world["clock"].now() - timedelta(seconds=30)
    cases = [
        ("UNKNOWN_FACT", {"exposure": "internal", "colour": "blue"}, {}),
        ("UNKNOWN_FACT", {"status": "OPEN"}, {}),
        ("DERIVED_FACT", {"is_production": True}, {}),
        ("DERIVED_FACT", {"is_external": False}, {}),
        ("INVALID_VALUE", {"exposure": "public"}, {}),
        ("INVALID_VALUE", {"risk_score": 101}, {}),
        ("INVALID_VALUE", {"risk_score": "70"}, {}),
        ("INVALID_VALUE", {"edr_managed": 1}, {}),
        ("INVALID_VALUE", {"criticality": True}, {}),
        ("INVALID_VALUE", {"role": "x" * 255}, {}),
        (
            "AMBIGUOUS_FACT",
            {"role": "server"},
            {
                "catalog": Catalog(
                    (*(CATALOG.contract(v) for v in sorted(CATALOG.versions)), ROLE_ROW)
                )
            },
        ),
    ]
    for code, facts, options in cases:
        catalog = options.get("catalog", CATALOG)
        error = refused(
            owner, world, manifest(world, entry(observed, facts=facts)), catalog=catalog
        )
        assert (error.code, error.entry) == (code, 0), (code, facts)
    assert fact_rows(admin_engine, world) == {}
    assert resource_row(admin_engine, world)["version"] == "resource-v1"
    assert audit_payloads(admin_engine, tenant_of(world), "context.imported") == []
    # Both v1 contracts declare the same column facts, so a value must satisfy both.
    assert (
        apply(
            owner, world, manifest(world, entry(observed, facts={"environment": "staging"}))
        ).counts["applied"]
        == 1
    )


def test_a_signal_fact_is_never_a_manifest_destination(world, owner, admin_engine):
    """`compromise` is a real fact of `endpoint-isolation.v2`, but its `signal` source kind
    is never a manifest kind. Serving the import from `PRODUCTION_CATALOG`, which
    declares the fact, proves it is the fact's own kind that keeps it unroutable, not simply
    that no contract in play names it.
    """
    observed = world["clock"].now() - timedelta(seconds=30)
    inventory = refused(
        owner,
        world,
        manifest(world, entry(observed, facts={"compromise": "compromised"})),
        catalog=PRODUCTION_CATALOG,
    )
    assert (inventory.code, inventory.entry) == ("UNKNOWN_FACT", 0)
    incident = refused(
        owner,
        world,
        manifest(
            world,
            entry(observed, facts={"compromise": "compromised"}, incident_id=str(uuid4())),
            kind="incident",
        ),
        catalog=PRODUCTION_CATALOG,
    )
    assert (incident.code, incident.entry) == ("UNKNOWN_FACT", 0)


def test_cp6_source_writer_tenant_and_actor_are_verified(db, world, owner, admin_engine):
    now = world["clock"].now()
    observed = now - timedelta(seconds=30)
    tenant = tenant_of(world)
    other_tenant = next(t for t in world_tenants(admin_engine) if t != tenant)
    other_admin = provision_identity(admin_engine, db, other_tenant, "ADMIN", now)
    only_here = provisioning.create_context_source(
        owner, tenant, world["account"], "inventory", ("cmdb_sync",), world["admin"].principal_id
    )
    foreign = manifest(world, entry(observed), tenant_id=str(other_tenant))
    foreign["source_id"] = str(only_here)
    foreign["writer"] = "cmdb_sync"
    cases = [
        ("INVALID_SOURCE", manifest(world, entry(observed), source_id=str(uuid4())), {}),
        (
            "INVALID_SOURCE",
            manifest(world, entry(observed), source_id=str(world["incident_source"])),
            {},
        ),
        ("INVALID_WRITER", manifest(world, entry(observed), writer="agent"), {}),
        ("INVALID_ACCOUNT", manifest(world, entry(observed), account_id=str(uuid4())), {}),
        ("TENANT_MISMATCH", manifest(world, entry(observed), tenant_id=str(other_tenant)), {}),
        (
            "INVALID_ACTOR",
            manifest(world, entry(observed)),
            {"actor": world["identity"].principal_id},
        ),
        ("INVALID_ACTOR", manifest(world, entry(observed)), {"actor": other_admin.principal_id}),
    ]
    for code, document, options in cases:
        parsed = provisioning.parse_manifest(encode(document))
        with pytest.raises(provisioning.ProvisioningError) as caught:
            provisioning.import_manifest(
                owner,
                tenant,
                parsed,
                options.get("actor", world["admin"].principal_id),
                now=now,
                catalog=CATALOG,
            )
        assert caught.value.code == code, code
    # A source that exists only in this tenant is invisible to another tenant's import.
    with pytest.raises(provisioning.ProvisioningError) as invisible:
        provisioning.import_manifest(
            owner,
            other_tenant,
            provisioning.parse_manifest(encode(foreign)),
            other_admin.principal_id,
            now=now,
            catalog=CATALOG,
        )
    assert invisible.value.code == "INVALID_SOURCE"
    for candidate in (tenant, other_tenant):
        assert (
            scoped(
                admin_engine,
                candidate,
                "SELECT count(*) AS n FROM execbound.resource_facts WHERE tenant_id = :t",
            )[0]["n"]
            == 0
        )
        assert audit_payloads(admin_engine, candidate, "context.imported") == []
    with db.transaction(tenant) as conn:
        assert (
            conn.execute(
                text("SELECT count(*) FROM execbound.context_sources WHERE source_id = :s"),
                {"s": only_here},
            ).scalar_one()
            == 1
        )


def world_tenants(engine):
    with engine.begin() as conn:
        return [row[0] for row in conn.execute(text("SELECT tenant_id FROM execbound.tenants"))]


def test_cp7_unknown_resources_are_skipped_unless_strict(world, owner, admin_engine):
    observed = world["clock"].now() - timedelta(seconds=30)
    document = manifest(world, entry(observed, provider_id="device-99"), entry(observed))
    result = apply(owner, world, document)
    assert result.outcomes == ("unknown_resource", "applied")
    assert (result.counts["unknown_resources"], result.counts["applied"]) == (1, 1)
    assert set(fact_rows(admin_engine, world)) == set(ROW_FACTS)
    error = refused(
        owner, world, manifest(world, entry(observed, provider_id="device-98")), strict=True
    )
    assert (error.code, error.entry) == ("UNKNOWN_RESOURCE", 0)
    assert len(audit_payloads(admin_engine, tenant_of(world), "context.imported")) == 1


def test_cp8_retraction_and_deactivation_fail_closed(db, world, owner, admin_engine):
    synthetic_mapping(admin_engine, world)
    now = world["clock"].now()
    apply(owner, world, manifest(world, entry(now - timedelta(seconds=40))))
    assert len(resolve_synthetic(db, world).facts) == 4
    retracted = apply(
        owner,
        world,
        manifest(
            world,
            entry(now - timedelta(seconds=30), version="snap-2", facts={}, retract=["edr_managed"]),
        ),
    )
    assert retracted.counts["facts_retracted"] == 1
    assert set(fact_rows(admin_engine, world)) == {"exposure", "risk_score"}
    with pytest.raises(ResolutionError) as missing:
        resolve_synthetic(db, world)
    assert missing.value.code == "INVALID_CONTEXT"

    nulled = apply(
        owner,
        world,
        manifest(
            world, entry(now - timedelta(seconds=20), version="snap-3", facts={}, retract=["role"])
        ),
    )
    assert nulled.counts["facts_retracted"] == 1
    assert resource_row(admin_engine, world)["role"] is None
    with pytest.raises(ResolutionError) as no_role:
        resolve_request(db, world["identity"], v1_request(world), world["clock"])
    assert no_role.value.code == "INVALID_CONTEXT"

    gone = apply(
        owner,
        world,
        manifest(
            world, entry(now - timedelta(seconds=10), version="snap-4", facts={}, active=False)
        ),
    )
    assert gone.counts["resources_deactivated"] == 1
    assert resource_row(admin_engine, world)["active"] is False
    with pytest.raises(ResolutionError) as inactive:
        resolve_request(db, world["identity"], v1_request(world), world["clock"])
    assert inactive.value.code == "INVALID_TARGET"


def test_cp9_incident_manifests_gate_the_v1_action(db, world, owner, admin_engine, connector):
    now = world["clock"].now()
    apply(
        owner,
        world,
        manifest(world, entry(now - timedelta(seconds=50), facts={"environment": "development"})),
    )
    incident = uuid4()
    opened = apply(
        owner,
        world,
        manifest(
            world,
            entry(
                now - timedelta(seconds=40),
                version="ticket-1",
                facts={"incident_status": "OPEN", "incident_severity": "CRITICAL"},
                incident_id=str(incident),
            ),
            kind="incident",
        ),
    )
    assert (opened.counts["incidents_created"], opened.counts["incidents_updated"]) == (1, 0)
    row = incident_row(admin_engine, world, incident)
    assert (row["status"], row["severity"], row["version"], row["source_id"]) == (
        "OPEN",
        "CRITICAL",
        "ticket-1",
        world["incident_source"],
    )
    runtime = Runtime(db, [connector], clock=world["clock"])
    assert resource_row(admin_engine, world)["version"] == "resource-v1"
    assert runtime.execute(world["identity"], isolate_wire(world, incident, "cp9-1")).state == (
        "EXECUTED"
    )

    closed = apply(
        owner,
        world,
        manifest(
            world,
            entry(
                now - timedelta(seconds=30),
                version="ticket-2",
                facts={"incident_status": "CLOSED", "incident_severity": "CRITICAL"},
                incident_id=str(incident),
            ),
            kind="incident",
        ),
    )
    assert (closed.counts["incidents_created"], closed.counts["incidents_updated"]) == (0, 1)
    assert incident_row(admin_engine, world, incident)["version"] == "ticket-2"
    assert runtime.execute(world["identity"], isolate_wire(world, incident, "cp9-2")).state == (
        "DENIED"
    )

    relink = refused(
        owner,
        world,
        manifest(
            world,
            entry(
                now - timedelta(seconds=20),
                provider_id="device-02",
                version="ticket-3",
                facts={"incident_status": "OPEN", "incident_severity": "HIGH"},
                incident_id=str(incident),
            ),
            kind="incident",
        ),
    )
    assert (relink.code, relink.entry) == ("INCIDENT_RELINKED", 0)
    assert incident_row(admin_engine, world, incident)["version"] == "ticket-2"
    shape = refused(
        owner,
        world,
        manifest(
            world,
            entry(
                now,
                facts={"incident_status": "OPEN", "incident_severity": "HIGH"},
                incident_id=str(incident),
                retract=["status"],
            ),
            kind="incident",
        ),
    )
    assert shape.code == "INVALID_MANIFEST"


def test_cp10_harness_adapter_produces_importable_manifests(db, world, owner, admin_engine):
    tenant, account, now = tenant_of(world), world["account"], world["clock"].now()
    tickets = json.loads((FIXTURES / "context-ticket-export.json").read_text(encoding="utf-8"))
    assets = json.loads((FIXTURES / "context-asset-export.json").read_text(encoding="utf-8"))

    def ago(seconds):
        return (now - timedelta(seconds=seconds)).isoformat()

    assets["exported_at"] = ago(30)
    assets["assets"][0]["updated_at"], assets["assets"][1]["updated_at"] = ago(120), ago(60)
    tickets["exported_at"] = ago(20)
    tickets["tickets"][0]["updated_at"], tickets["tickets"][1]["updated_at"] = ago(180), ago(600)

    inventory = inventory_manifest(
        assets, tenant=tenant, account=account, source=world["inventory"]
    )
    assert inventory["writer"] == "inventory_sync" and inventory["kind"] == "inventory"
    assert inventory["entries"][1]["active"] is False and "active" not in inventory["entries"][0]
    imported = apply(owner, world, inventory)
    assert imported.outcomes == ("applied", "applied")
    assert imported.counts["resources_deactivated"] == 1
    assert resource_row(admin_engine, world)["role"] == "server"
    assert resource_row(admin_engine, world, world["other"])["active"] is False
    assert fact_rows(admin_engine, world)["risk_score"][0] == 70

    incidents = incident_manifest(
        tickets, tenant=tenant, account=account, source=world["incident_source"]
    )
    assert incidents["writer"] == "soc_analyst"
    ticket = uuid5(world["incident_source"], "INC0010001:device-01")
    assert incidents["entries"][0]["incident_id"] == str(ticket)
    assert apply(owner, world, incidents).counts["incidents_created"] == 2
    resolved = resolve_request(
        db,
        world["identity"],
        v1_request(world, claimed_context={"incident_id": str(ticket)}),
        world["clock"],
    )
    facts = {f.name: f.value for f in resolved.facts}
    assert (facts["incident_status"], facts["incident_severity"], facts["role"]) == (
        "OPEN",
        "HIGH",
        "server",
    )
    assert incident_row(admin_engine, world, ticket)["version"] == ago(180)

    unmapped = copy.deepcopy(tickets)
    unmapped["tickets"][0]["state"] = "escalated"
    with pytest.raises(AdapterError):
        incident_manifest(unmapped, tenant=tenant, account=account, source=world["incident_source"])
    odd_priority = copy.deepcopy(tickets)
    odd_priority["tickets"][1]["priority"] = 9
    with pytest.raises(AdapterError):
        incident_manifest(
            odd_priority, tenant=tenant, account=account, source=world["incident_source"]
        )
    odd_class = copy.deepcopy(assets)
    odd_class["assets"][0]["class"] = "printer"
    with pytest.raises(AdapterError):
        inventory_manifest(odd_class, tenant=tenant, account=account, source=world["inventory"])


def test_cp11_source_commands_and_runtime_privileges(
    db, world, owner, admin_engine, monkeypatch, capsys, cli_env, tmp_path
):
    tenant, account, actor = tenant_of(world), world["account"], world["admin"].principal_id
    created = run_cli(
        monkeypatch,
        capsys,
        "context-source-create",
        "--tenant",
        str(tenant),
        "--account",
        str(account),
        "--kind",
        "inventory",
        "--writer",
        "inventory_sync",
        "--writer",
        "cmdb_sync",
        "--actor",
        str(actor),
    )
    wide = UUID(created["source_id"])
    assert created["kind"] == "inventory"
    assert created["allowed_writers"] == ["cmdb_sync", "inventory_sync"]
    rows = scoped(
        admin_engine,
        tenant,
        "SELECT kind, allowed_writers, active FROM execbound.context_sources "
        "WHERE tenant_id = :t AND source_id = :s",
        s=wide,
    )
    assert [dict(row) for row in rows] == [
        {"kind": "inventory", "allowed_writers": ["cmdb_sync", "inventory_sync"], "active": True}
    ]
    for writers in (["Agent!"], ["a", "a"], [], ["w"] * 17):
        with pytest.raises(provisioning.ProvisioningError) as bad:
            provisioning.create_context_source(owner, tenant, account, "inventory", writers, actor)
        assert bad.value.code == "INVALID_WRITER"
    with pytest.raises(provisioning.ProvisioningError) as bad_kind:
        provisioning.create_context_source(owner, tenant, account, "weather", ["x"], actor)
    assert bad_kind.value.code == "INVALID_KIND"
    with pytest.raises(provisioning.ProvisioningError) as bad_account:
        provisioning.create_context_source(owner, tenant, uuid4(), "inventory", ["x"], actor)
    assert bad_account.value.code == "INVALID_ACCOUNT"
    with pytest.raises(provisioning.ProvisioningError) as bad_actor:
        provisioning.create_context_source(
            owner, tenant, account, "inventory", ["x"], world["identity"].principal_id
        )
    assert bad_actor.value.code == "INVALID_ACTOR"

    # A second source whose only label the v1 contracts permit by default carries the import.
    narrow = provisioning.create_context_source(
        owner, tenant, account, "inventory", ["inventory_sync"], actor
    )
    observed = world["clock"].now() - timedelta(seconds=30)
    columns = {"role": "server", "environment": "staging", "criticality": 3}
    path = tmp_path / "manifest.json"
    path.write_bytes(encode(manifest(world, entry(observed, facts=columns), source_id=str(narrow))))
    report = tmp_path / "report.json"
    imported = run_cli(
        monkeypatch,
        capsys,
        "context-import",
        "--tenant",
        str(tenant),
        "--manifest",
        str(path),
        "--actor",
        str(actor),
        "--report",
        str(report),
    )
    assert imported["applied"] == 1 and imported["facts_written"] == 3
    assert json.loads(report.read_text(encoding="utf-8"))["outcomes"] == ["applied"]
    assert resource_row(admin_engine, world)["source_id"] == narrow
    resolved = resolve_request(db, world["identity"], v1_request(world), world["clock"])
    assert {(f.value, f.permitted_writers) for f in resolved.facts if f.name == "role"} == {
        ("server", ("inventory_sync",))
    }
    # The wide source's extra label stays outside the default allowlist until a bundle admits it.
    path.write_bytes(
        encode(
            manifest(
                world,
                entry(observed, facts=columns, version="snap-2"),
                source_id=str(wide),
                writer="cmdb_sync",
            )
        )
    )
    run_cli(
        monkeypatch,
        capsys,
        "context-import",
        "--tenant",
        str(tenant),
        "--manifest",
        str(path),
        "--actor",
        str(actor),
    )
    with pytest.raises(ResolutionError) as unlisted:
        resolve_request(db, world["identity"], v1_request(world), world["clock"])
    assert unlisted.value.code == "INVALID_CONTEXT"

    deactivated = run_cli(
        monkeypatch,
        capsys,
        "context-source-deactivate",
        "--tenant",
        str(tenant),
        "--source",
        str(wide),
        "--actor",
        str(actor),
    )
    assert deactivated == {"source_id": str(wide), "active": False}
    with pytest.raises(ResolutionError) as retired:
        resolve_request(db, world["identity"], v1_request(world), world["clock"])
    assert retired.value.code == "INVALID_CONTEXT"
    with pytest.raises(provisioning.ProvisioningError) as twice:
        provisioning.deactivate_context_source(owner, tenant, wide, actor)
    assert twice.value.code == "INVALID_SOURCE"
    kinds = [
        row["kind"]
        for row in scoped(
            admin_engine,
            tenant,
            "SELECT kind FROM execbound.audit_events WHERE tenant_id = :t ORDER BY sequence",
        )
    ]
    assert kinds[-5:] == [
        "context_source.created",
        "context_source.created",
        "context.imported",
        "context.imported",
        "context_source.deactivated",
    ]
    (_, created_payload), _ = audit_payloads(admin_engine, tenant, "context_source.created")
    assert created_payload == {
        "source_id": str(wide),
        "account_id": str(account),
        "kind": "inventory",
        "allowed_writers": ["cmdb_sync", "inventory_sync"],
    }
    err = refused_cli(
        monkeypatch,
        capsys,
        "context-import",
        "--tenant",
        str(tenant),
        "--manifest",
        str(path),
        "--actor",
        str(actor),
    )
    assert "Provisioning refused: INVALID_SOURCE." in err and "server" not in err
    (tmp_path / "bad.json").write_bytes(
        encode(manifest(world, entry(observed, facts={"colour": "blue"})))
    )
    err = refused_cli(
        monkeypatch,
        capsys,
        "context-import",
        "--tenant",
        str(tenant),
        "--manifest",
        str(tmp_path / "bad.json"),
        "--actor",
        str(actor),
    )
    assert "Provisioning refused: UNKNOWN_FACT at entry 0." in err and "blue" not in err
    err = refused_cli(
        monkeypatch,
        capsys,
        "context-import",
        "--tenant",
        str(tenant),
        "--manifest",
        str(tmp_path / "missing.json"),
        "--actor",
        str(actor),
    )
    assert "manifest file unavailable" in err

    with db.transaction(tenant) as conn:
        check_runtime(conn)
    for table in FACT_TABLES:
        for statement in (
            f"DELETE FROM execbound.{table}",
            f"UPDATE execbound.{table} SET tenant_id = tenant_id",
        ):
            with pytest.raises(DBAPIError), db.transaction(tenant) as conn:
                conn.execute(text(statement))
    with pytest.raises(DBAPIError), db.transaction(tenant) as conn:
        conn.execute(
            text(
                "INSERT INTO execbound.resource_facts (tenant_id, account_id, provider, "
                "resource_type, resource_id, fact_name, value, source_id, version, observed_at) "
                "VALUES (:t, :a, 'mock_crowdstrike', 'endpoint', :r, 'exposure', '\"x\"'::jsonb, "
                ":s, 'v', now())"
            ),
            {"t": tenant, "a": account, "r": world["target"], "s": world["inventory"]},
        )


def imported_state(admin_engine, world):
    """Everything an import of the world's device writes: its row, its facts and the audit."""
    return (
        resource_row(admin_engine, world),
        fact_rows(admin_engine, world),
        audit_payloads(admin_engine, tenant_of(world), "context.imported"),
    )


def import_argv(world, manifest_path, *extra):
    return (
        "context-import",
        "--tenant",
        str(tenant_of(world)),
        "--manifest",
        str(manifest_path),
        "--actor",
        str(world["admin"].principal_id),
        *extra,
    )


def test_a_report_path_that_cannot_be_created_refuses_the_import_with_no_write(
    db, world, owner, admin_engine, monkeypatch, capsys, cli_env, tmp_path
):
    """`--report` must be a new file. A path that already exists, or whose directory does not,
    is refused `REPORT_UNAVAILABLE` with nothing imported, as every other refusal of
    `context-import` is, and not after the import has committed and been audited."""
    observed = world["clock"].now() - timedelta(seconds=30)
    columns = {"role": "server", "environment": "staging", "criticality": 3}
    path = tmp_path / "manifest.json"
    path.write_bytes(encode(manifest(world, entry(observed, facts=columns))))
    existing = tmp_path / "existing.json"
    existing.write_text("an earlier report\n", encoding="utf-8")
    before = imported_state(admin_engine, world)
    for report in (existing, tmp_path / "missing" / "report.json"):
        err = refused_cli(monkeypatch, capsys, *import_argv(world, path, "--report", str(report)))
        assert err.splitlines()[0] == "Provisioning refused: REPORT_UNAVAILABLE."
        assert imported_state(admin_engine, world) == before
    assert existing.read_text(encoding="utf-8") == "an earlier report\n"
    assert not (tmp_path / "missing").exists()

    # Given a new path, the same manifest imports and its report is written.
    report = tmp_path / "report.json"
    imported = run_cli(monkeypatch, capsys, *import_argv(world, path, "--report", str(report)))
    assert imported["applied"] == 1 and imported["facts_written"] == 3
    assert json.loads(report.read_text(encoding="utf-8"))["outcomes"] == ["applied"]
    if os.name != "nt":
        assert oct(report.stat().st_mode & 0o777) == "0o600"
    assert imported_state(admin_engine, world) != before


def test_a_refused_import_leaves_no_report_behind(
    db, world, owner, admin_engine, monkeypatch, capsys, cli_env, tmp_path
):
    """The report file is created before the import, so a refused import must take it away
    again: a refusal while planning the entries, one inside the import's transaction, and one
    while parsing the manifest, before the report is created at all."""
    observed = world["clock"].now() - timedelta(seconds=30)
    columns = {"role": "server", "environment": "staging", "criticality": 3}
    refusals = {
        "UNKNOWN_FACT at entry 0": manifest(world, entry(observed, facts={"colour": "blue"})),
        "INVALID_SOURCE": manifest(world, entry(observed, facts=columns), source_id=str(uuid4())),
        "INVALID_MANIFEST": manifest(world, entry(observed, facts=columns), kind="weather"),
    }
    before = imported_state(admin_engine, world)
    for refusal, document in refusals.items():
        path = tmp_path / "manifest.json"
        path.write_bytes(encode(document))
        report = tmp_path / "report.json"
        err = refused_cli(monkeypatch, capsys, *import_argv(world, path, "--report", str(report)))
        assert err.splitlines()[0] == f"Provisioning refused: {refusal}."
        assert not report.exists()
        assert imported_state(admin_engine, world) == before
    assert sorted(tmp_path.iterdir()) == [tmp_path / "manifest.json"]


def test_a_report_that_cannot_be_written_after_the_import_says_the_import_stands(
    db, world, owner, admin_engine, monkeypatch, capsys, cli_env, tmp_path
):
    """The report is written once the import has committed, so a write failing there is no
    refusal and must not read as one, or as the owner connection or manifest file being
    unavailable, which says nothing was imported. The command says the import stands and the
    report was not written, prints the digest and counts it prints after any import, since
    re-importing would report every entry unchanged, and takes the partial file away."""
    observed = world["clock"].now() - timedelta(seconds=30)
    columns = {"role": "server", "environment": "staging", "criticality": 3}
    path = tmp_path / "manifest.json"
    path.write_bytes(encode(manifest(world, entry(observed, facts=columns))))
    report = tmp_path / "report.json"
    before = imported_state(admin_engine, world)

    def disk_fills(document, handle, **options):
        handle.write('{\n  "applied": 1,\n')
        handle.flush()
        raise OSError(errno.ENOSPC, "No space left on device")

    monkeypatch.setattr(provisioning.json, "dump", disk_fills)
    monkeypatch.setattr(
        sys, "argv", ["execbound", *import_argv(world, path, "--report", str(report))]
    )
    with pytest.raises(SystemExit) as caught:
        main()
    assert caught.value.code == 2
    out, err = capsys.readouterr()
    assert err.splitlines()[0] == (
        "Provisioning imported the manifest, but the report was not written: REPORT_UNAVAILABLE."
    )
    summary = json.loads(out)
    assert summary["manifest_digest"] == hashlib.sha256(path.read_bytes()).hexdigest()
    assert summary["applied"] == 1 and summary["facts_written"] == 3
    assert imported_state(admin_engine, world) != before
    assert sorted(tmp_path.iterdir()) == [tmp_path / "manifest.json"]


def test_cp12_bounds_are_checked_before_the_database(world, owner):
    now = world["clock"].now()
    observed = now - timedelta(seconds=30)
    too_many = manifest(
        world, *(entry(observed, provider_id=f"device-{i:05d}") for i in range(10_001))
    )
    duplicate = manifest(world, entry(observed), entry(observed, version="snap-2"))
    overlap = manifest(world, entry(observed, retract=["exposure"]))
    empty = manifest(world, entry(observed, facts={}))
    naive = manifest(world, entry(observed))
    naive["entries"][0]["observed_at"] = "2026-09-15T12:00:00"
    extra = manifest(world, entry(observed, colour="blue"))
    incident_shape = manifest(world, entry(observed, incident_id=str(uuid4())))
    incident_version = manifest(
        world,
        entry(observed, facts={"incident_status": "OPEN"}, provider_version="x"),
        kind="incident",
    )
    incident_version["entries"][0]["incident_id"] = str(uuid4())
    documents = (
        too_many,
        duplicate,
        overlap,
        empty,
        naive,
        extra,
        incident_shape,
        incident_version,
    )
    with statements(owner) as refusals:
        with pytest.raises(provisioning.ProvisioningError) as huge:
            provisioning.parse_manifest(b"[" + b" " * provisioning.MAX_MANIFEST_BYTES + b"]")
        assert huge.value.code == "MANIFEST_TOO_LARGE"
        for document in documents:
            with pytest.raises(provisioning.ProvisioningError) as bad:
                provisioning.parse_manifest(encode(document))
            assert bad.value.code == "INVALID_MANIFEST"
        with pytest.raises(provisioning.ProvisioningError) as bad_json:
            provisioning.parse_manifest(b"{not json")
        assert bad_json.value.code == "INVALID_MANIFEST"
    # Every bound above, the oversized manifest included, was refused without one
    # statement reaching the database.
    assert refusals == [], refusals


def seed_endpoints(admin_engine, world, provider_ids, observed):
    """Endpoints the inventory source already knows, in one statement, so an import can
    write facts for each without the importer's own work being what is seeded."""
    with admin_engine.begin() as conn:
        conn.execute(
            text("SELECT set_config('execbound.tenant_id', :t, true)"), {"t": str(tenant_of(world))}
        )
        conn.execute(
            text(
                "INSERT INTO execbound.resources (tenant_id, account_id, provider, resource_type, "
                "resource_id, provider_id, version, source_id, role, environment, criticality, "
                "observed_at) VALUES (:t, :a, 'mock_crowdstrike', 'endpoint', :r, :p, 'seed', "
                ":s, 'workstation', 'production', 1, :o)"
            ),
            [
                {
                    "t": tenant_of(world),
                    "a": world["account"],
                    "r": uuid4(),
                    "p": provider_id,
                    "s": world["inventory"],
                    "o": observed,
                }
                for provider_id in provider_ids
            ],
        )


def bulk_entries(observed, provider_ids):
    return (
        entry(observed, provider_id=provider_id, facts={"exposure": "internal", "criticality": 2})
        for provider_id in provider_ids
    )


def test_cp12_an_import_makes_as_many_round_trips_for_a_thousand_entries_as_for_ten(
    world, owner, admin_engine
):
    """CP12's round trips, on every run: what the importer sends the server does not grow
    with the manifest.

    The importer plans in Python and writes in set statements, so a manifest's entries
    reach the database in a fixed handful of round trips whatever it holds. Two imports of
    the same shape, ten entries and then a thousand, must make exactly as many; a
    regression to per-entry work makes the second about a thousand more, however fast or
    loaded the machine. No clock is read, so this needs no timing lock and is not `timed`:
    it is the half of the large import's claim that a run deselecting `timed` still checks.
    """
    observed = world["clock"].now() - timedelta(seconds=30)
    sent = {}
    for count, prefix in ((10, "few"), (1_000, "many")):
        provider_ids = [f"{prefix}-{i:05d}" for i in range(count)]
        seed_endpoints(admin_engine, world, provider_ids, observed - timedelta(seconds=60))
        document = manifest(world, *bulk_entries(observed, provider_ids))
        with statements(owner) as seen:
            result = apply(owner, world, document)
        assert result.counts["applied"] == count and result.counts["facts_written"] == 2 * count
        sent[count] = len(seen)
    assert sent[1_000] == sent[10], sent


@pytest.mark.timed
def test_cp12_a_ten_thousand_entry_manifest_imports_in_one_transaction_inside_its_ceiling(
    world, owner, admin_engine, timed_alone
):
    """CP12's large import: the largest manifest the bounds allow imports in one transaction.

    It takes the machine's timing lock, so it is `timed` (#747). What it asserts is the
    import and its ceiling in seconds; that the importer's round trips do not grow with the
    manifest is
    `test_cp12_an_import_makes_as_many_round_trips_for_a_thousand_entries_as_for_ten`, which
    reads no clock and is not `timed`.
    """
    observed = world["clock"].now() - timedelta(seconds=30)
    count = provisioning.MAX_ENTRIES
    bulk = [f"bulk-{i:05d}" for i in range(count - 2)]
    seed_endpoints(admin_engine, world, bulk, observed - timedelta(seconds=60))
    document = manifest(
        world,
        entry(observed, facts={"exposure": "internal", "risk_score": 1}),
        entry(observed, provider_id="device-02", facts={"exposure": "external"}),
        *bulk_entries(observed, bulk),
    )
    # Alone among the measured sections on this machine, so the seconds below are this
    # import rather than another suite's.
    with timed_alone("the ten thousand entry import") as machine:
        started = time.monotonic()
        result = apply(owner, world, document)
        elapsed = time.monotonic() - started
    assert result.counts["applied"] == count and result.counts["facts_written"] == 2 * count - 1
    # The timing lock keeps other measured sections on the same machine out, but a busy
    # machine still affects wall-clock time, so the seconds here are kept as a generous
    # ceiling rather than as a claim: this import is seconds of work on an idle machine and
    # far slower on a loaded one.
    assert elapsed < 180, f"{elapsed:.1f} s; {machine.note}"
    assert (
        scoped(
            admin_engine,
            tenant_of(world),
            "SELECT count(*) AS n FROM execbound.resource_facts WHERE tenant_id = :t",
        )[0]["n"]
        == count + 1
    )
