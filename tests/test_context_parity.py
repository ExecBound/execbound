# SPDX-License-Identifier: AGPL-3.0-only
"""Golden resolution and evaluation output for the v1 context contracts (CC2).

Generate once on unmodified code with EXECBOUND_WRITE_PARITY=1. Later changes
must reproduce the committed fixture byte for byte.
"""

import json
import os
from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import UUID

from sqlalchemy import text

from execbound.audit import canonical_json
from execbound.execution.snapshot import resolve_snapshot
from execbound.identity import authenticate, new_token
from execbound.policy.evaluate import evaluate
from execbound.policy.models import ProjectedUsage, UsageSnapshot
from execbound.requests import parse_request
from execbound.resolution import resolve_request
from execbound_harness.demo import endpoint_bundle
from execbound_harness.identity_demo import identity_bundle

FIXTURE = Path(__file__).parent / "fixtures" / "context-contracts-v1-parity.json"
NOW = datetime(2026, 9, 14, 12, 0, tzinfo=UTC)
TENANT, PRINCIPAL, CREDENTIAL = UUID(int=0x100), UUID(int=0x101), UUID(int=0x102)
# Every tenant has one space from migration 0041, and an agent is owned by it.
SPACE = UUID(int=0x103)
ACCOUNTS = {"mock_crowdstrike": UUID(int=0x110), "mock_entra": UUID(int=0x111)}
RESOURCE_TYPES = {"mock_crowdstrike": "endpoint", "mock_entra": "identity"}
SOURCES = {
    ("mock_crowdstrike", "inventory"): UUID(int=0x120),
    ("mock_crowdstrike", "incident"): UUID(int=0x121),
    ("mock_entra", "inventory"): UUID(int=0x122),
    ("mock_entra", "incident"): UUID(int=0x123),
}
MAPPINGS = (
    ("mock_crowdstrike", "endpoint.isolate", "contain", "endpoint-isolation.v1"),
    ("mock_entra", "identity.disable", "disable", "identity-control.v1"),
    ("mock_entra", "identity.enable", "enable", "identity-control.v1"),
    ("mock_entra", "identity.revoke_sessions", "revoke_sessions", "identity-control.v1"),
)
# name: (provider, operation_ref, class column, class value, environment, criticality)
CASES = {
    "ws-dev": ("mock_crowdstrike", "endpoint.isolate", "role", "workstation", "development", 1),
    "ws-prod": ("mock_crowdstrike", "endpoint.isolate", "role", "workstation", "production", 2),
    "dc-prod": (
        "mock_crowdstrike",
        "endpoint.isolate",
        "role",
        "domain_controller",
        "production",
        4,
    ),
    "user-dev": ("mock_entra", "identity.disable", "privilege_class", "standard", "development", 1),
    "user-prod": (
        "mock_entra",
        "identity.revoke_sessions",
        "privilege_class",
        "standard",
        "production",
        1,
    ),
    "user-enable": (
        "mock_entra",
        "identity.enable",
        "privilege_class",
        "standard",
        "development",
        1,
    ),
    "user-priv": (
        "mock_entra",
        "identity.disable",
        "privilege_class",
        "privileged",
        "development",
        1,
    ),
}
EXPECTED = {
    "ws-dev": "ELIGIBLE",
    "ws-prod": "REQUIRE_APPROVAL",
    "dc-prod": "DENY",
    "user-dev": "ELIGIBLE",
    "user-prod": "REQUIRE_APPROVAL",
    "user-enable": "REQUIRE_APPROVAL",
    "user-priv": "DENY",
}


class FixedClock:
    def __init__(self, now: datetime) -> None:
        self.value = now

    def now(self) -> datetime:
        return self.value


def _ids(index: int) -> tuple[UUID, UUID, UUID]:
    return UUID(int=0x200 + index), UUID(int=0x300 + index), UUID(int=0x400 + index)


def _seed(engine) -> str:
    token, digest = new_token(TENANT, CREDENTIAL)
    observed = NOW - timedelta(seconds=60)
    with engine.begin() as conn:

        def run(sql: str, **params: object) -> None:
            conn.execute(text(sql), params)

        run("INSERT INTO execbound.tenants(tenant_id, name) VALUES (:t, 'Parity')", t=TENANT)
        # Every tenant has one space from migration 0041, and an agent is owned by it.
        run(
            "INSERT INTO execbound.spaces"
            "(tenant_id, space_id, name, created_at, created_by) "
            "VALUES (:t, :s, 'Default', now(), :t)",
            t=TENANT,
            s=SPACE,
        )
        run(
            "INSERT INTO execbound.principals(tenant_id, principal_id, kind, space_id) "
            "VALUES (:t, :p, 'AGENT', "
            "(SELECT space_id FROM execbound.spaces WHERE tenant_id = :t))",
            t=TENANT,
            p=PRINCIPAL,
        )
        run(
            "INSERT INTO execbound.credentials "
            "(tenant_id, credential_id, principal_id, token_hash, issued_at, expires_at) "
            "VALUES (:t, :c, :p, :h, :issued, :expires)",
            t=TENANT,
            c=CREDENTIAL,
            p=PRINCIPAL,
            h=digest,
            issued=datetime(2026, 1, 1, tzinfo=UTC),
            expires=datetime(2099, 1, 1, tzinfo=UTC),
        )
        for provider, account in ACCOUNTS.items():
            run(
                "INSERT INTO execbound.connector_accounts(tenant_id, account_id, provider, "
                "space_id) "
                "VALUES (:t, :a, :provider, "
                "(SELECT space_id FROM execbound.spaces WHERE tenant_id = :t))",
                t=TENANT,
                a=account,
                provider=provider,
            )
            for kind, writer in (("inventory", "inventory_sync"), ("incident", "soc_analyst")):
                run(
                    "INSERT INTO execbound.context_sources "
                    "(tenant_id, account_id, source_id, kind, allowed_writers) "
                    "VALUES (:t, :a, :s, :kind, ARRAY[:writer])",
                    t=TENANT,
                    a=account,
                    s=SOURCES[(provider, kind)],
                    kind=kind,
                    writer=writer,
                )
        for provider, action, provider_operation, contract in MAPPINGS:
            run(
                "INSERT INTO execbound.operation_mappings "
                "(tenant_id, operation_ref, account_id, provider, resource_type, action, "
                "provider_operation, mapping_version, schema_version, context_contract_version) "
                "VALUES (:t, :action, :a, :provider, :rtype, :action, :operation, 'map-v1', "
                "'action.v1', :contract)",
                t=TENANT,
                action=action,
                a=ACCOUNTS[provider],
                provider=provider,
                rtype=RESOURCE_TYPES[provider],
                operation=provider_operation,
                contract=contract,
            )
        for index, (name, case) in enumerate(CASES.items()):
            provider, _, column, value, environment, criticality = case
            resource, incident, canonical = _ids(index)
            common = {
                "t": TENANT,
                "a": ACCOUNTS[provider],
                "provider": provider,
                "rtype": RESOURCE_TYPES[provider],
                "r": resource,
                "observed": observed,
            }
            run(
                "INSERT INTO execbound.resources "
                "(tenant_id, account_id, provider, resource_type, resource_id, provider_id, "
                f"version, source_id, {column}, environment, criticality, observed_at) "
                "VALUES (:t, :a, :provider, :rtype, :r, :name, 'resource-v1', :s, :value, "
                ":environment, :criticality, :observed)",
                **common,
                name=name,
                s=SOURCES[(provider, "inventory")],
                value=value,
                environment=environment,
                criticality=criticality,
            )
            run(
                "INSERT INTO execbound.canonical_targets(tenant_id, canonical_target_id, "
                "created_at) VALUES (:t, :c, :observed)",
                t=TENANT,
                c=canonical,
                observed=observed,
            )
            run(
                "INSERT INTO execbound.resource_identities "
                "(tenant_id, account_id, provider, resource_type, resource_id, "
                "canonical_target_id) VALUES (:t, :a, :provider, :rtype, :r, :c)",
                **{key: common[key] for key in ("t", "a", "provider", "rtype", "r")},
                c=canonical,
            )
            run(
                "INSERT INTO execbound.incidents "
                "(tenant_id, account_id, provider, resource_type, incident_id, resource_id, "
                "source_id, version, status, severity, observed_at) "
                "VALUES (:t, :a, :provider, :rtype, :i, :r, :s, 'incident-v1', 'OPEN', "
                "'CRITICAL', :observed)",
                **common,
                i=incident,
                s=SOURCES[(provider, "incident")],
            )
    return token


def _capture(db, engine) -> dict[str, object]:
    identity = authenticate(db, _seed(engine))
    output: dict[str, object] = {}
    for index, (name, case) in enumerate(CASES.items()):
        provider, operation_ref = case[0], case[1]
        resource, incident, _ = _ids(index)
        request = parse_request(
            json.dumps(
                {
                    "operation_ref": operation_ref,
                    "target": {"kind": "canonical", "value": str(resource)},
                    "arguments": {},
                    "idempotency_key": f"parity-{name}",
                    "claimed_context": {"incident_id": str(incident)},
                }
            ).encode()
        )
        resolved = resolve_request(db, identity, request, FixedClock(NOW))
        with db.transaction(TENANT) as conn:
            snapshot, canonical = resolve_snapshot(
                conn, identity, request, FixedClock(NOW), signals=None
            )
        builder = endpoint_bundle if provider == "mock_crowdstrike" else identity_bundle
        bundle = builder(
            TENANT, ACCOUNTS[provider], mapping_version="map-v1", bundle_id=UUID(int=0x500 + index)
        )
        usage = UsageSnapshot(
            tenant_id=TENANT,
            principal_id=PRINCIPAL,
            bundle_id=bundle.bundle_id,
            account_id=ACCOUNTS[provider],
            counts=tuple(
                ProjectedUsage(rule_id=rule.rule_id, confirmed_targets=0, unresolved_targets=0)
                for rule in bundle.limits
            ),
        )
        decisions = {
            label: evaluate(
                bundle=bundle,
                identity=identity,
                resolved=resolved,
                usage=usage,
                clock=FixedClock(moment),
            ).model_dump(mode="json")
            for label, moment in (("fresh", NOW), ("stale", NOW + timedelta(seconds=241)))
        }
        output[name] = {
            "resolved": resolved.model_dump(mode="json"),
            "snapshot": snapshot.model_dump(mode="json"),
            "canonical_target_id": str(canonical),
            **decisions,
        }
    return output


def test_v1_context_contract_parity(db, admin_engine, seeded):
    captured = _capture(db, admin_engine)
    assert {name: row["fresh"]["effect"] for name, row in captured.items()} == EXPECTED
    assert all(row["stale"]["effect"] == "DENY" for row in captured.values())
    encoded = canonical_json(captured)
    if os.environ.get("EXECBOUND_WRITE_PARITY") == "1":
        FIXTURE.write_text(
            json.dumps(json.loads(encoded), indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
    assert canonical_json(json.loads(FIXTURE.read_text(encoding="utf-8"))) == encoded
