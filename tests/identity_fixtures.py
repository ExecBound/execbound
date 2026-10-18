# SPDX-License-Identifier: AGPL-3.0-only
"""Synthetic identity inventory and a separate protected HTTP provider process."""

import hashlib
import json
import os
import secrets
from uuid import uuid4

import pytest
from conftest import remember_secret
from sqlalchemy import text
from test_execution import registry as registry
from test_execution import world as world
from test_protected_path import LiveProvider

from execbound.policy.store import activate_bundle, create_bundle, validate_bundle
from execbound.provider.connector import ConnectionConfig, MockConnector
from execbound.provider.identity_store import IdentityStore
from execbound.requests import parse_request
from execbound_harness.identity_demo import identity_bundle

ACTIONS = ("identity.disable", "identity.enable", "identity.revoke_sessions")


def identity_request(world, action="identity.disable", **changes):
    wire = {
        "operation_ref": action,
        "target": {"kind": "canonical", "value": str(world["target"])},
        "arguments": {},
        "idempotency_key": "identity-" + action,
        "claimed_context": {"incident_id": str(world["incident"])},
    }
    wire.update(changes)
    return parse_request(json.dumps(wire).encode())


def add_target(engine, world, *, production=False, provider_id=None):
    target = {**world, **{key: uuid4() for key in ("target", "canonical", "incident")}}
    target["provider_id"] = provider_id or str(target["target"])
    p = {
        **target,
        "t": world["identity"].tenant_id,
        "p": world["human"].principal_id,
        "n": world["clock"].now(),
        "environment": "production" if production else "development",
    }
    with engine.begin() as conn:
        conn.execute(text("INSERT INTO execbound.canonical_targets VALUES (:t,:canonical,:n)"), p)
        conn.execute(
            text("""INSERT INTO execbound.resources
                (tenant_id,account_id,provider,resource_type,resource_id,provider_id,
                 version,source_id,environment,criticality,privilege_class,observed_at)
                VALUES (:t,:account,'mock_entra','identity',:target,:provider_id,
                        'resource-v1',:inventory,:environment,1,'standard',:n)"""),
            p,
        )
        conn.execute(
            text("""INSERT INTO execbound.resource_identities
                VALUES (:t,:account,'mock_entra','identity',:target,:canonical)"""),
            p,
        )
        conn.execute(
            text("""INSERT INTO execbound.incidents
                (tenant_id,account_id,provider,resource_type,incident_id,resource_id,
                 source_id,version,status,severity,observed_at)
                VALUES (:t,:account,'mock_entra','identity',:incident,:target,
                        :incident_source,'incident-v1','OPEN','CRITICAL',:n)"""),
            p,
        )
        for action in ACTIONS:
            conn.execute(
                text("""INSERT INTO execbound.approval_scopes
                    (tenant_id,approver_id,canonical_target_id,action, space_id)
                    VALUES (:t,:p,:canonical,:action, 
                        (SELECT space_id FROM execbound.spaces WHERE tenant_id = :t))"""),
                {**p, "action": action},
            )
    return target


@pytest.fixture
def identity_world(world, db, admin_engine):
    result = {**world, **{key: uuid4() for key in ("account", "inventory", "incident_source")}}
    result["endpoint_world"] = world
    p = {**result, "t": world["identity"].tenant_id}
    with admin_engine.begin() as conn:
        conn.execute(
            text("""INSERT INTO execbound.connector_accounts
                (tenant_id,account_id,provider,space_id)
                VALUES (:t,:account,'mock_entra', 
                    (SELECT space_id FROM execbound.spaces WHERE tenant_id = :t))"""),
            p,
        )
        conn.execute(
            text("""INSERT INTO execbound.context_sources
                (tenant_id,account_id,source_id,kind,allowed_writers) VALUES
                (:t,:account,:inventory,'inventory',ARRAY['inventory_sync']),
                (:t,:account,:incident_source,'incident',ARRAY['soc_analyst'])"""),
            p,
        )
        for action in ACTIONS:
            conn.execute(
                text("""INSERT INTO execbound.operation_mappings
                    (tenant_id,operation_ref,account_id,provider,resource_type,action,
                     provider_operation,mapping_version,schema_version,context_contract_version)
                    VALUES (:t,:action,:account,'mock_entra','identity',:action,:operation,
                            'map-v1','action.v1','identity-control.v1')"""),
                {**p, "action": action, "operation": action.split(".")[1]},
            )
    result = add_target(admin_engine, result, provider_id="identity-01")
    bundle = identity_bundle(p["t"], result["account"], mapping_version="map-v1")
    create_bundle(db, world["admin"], bundle, world["clock"])
    validate_bundle(db, world["admin"], bundle.bundle_id, world["clock"])
    activate_bundle(db, world["admin"], bundle.bundle_id, world["clock"])
    result["bundle"] = bundle
    return result


@pytest.fixture
def identity_provider(tmp_path, identity_world):
    world = identity_world
    tenant, account = world["identity"].tenant_id, world["account"]
    dispatch, control, key = (
        secrets.token_urlsafe(32),
        secrets.token_urlsafe(32),
        secrets.token_bytes(32),
    )
    # The mock provider's credentials and the hex form of its journal signing key are
    # secrets this world mints; register them so no rendered output may repeat one.
    remember_secret(dispatch)
    remember_secret(control)
    remember_secret(key.hex())
    database, configfile = tmp_path / "identity.sqlite3", tmp_path / "identity-accounts.json"
    configfile.write_text(
        json.dumps(
            [
                {
                    "tenant_id": str(tenant),
                    "account_id": str(account),
                    "provider": "mock_entra",
                    "dispatch_token_hash": hashlib.sha256(dispatch.encode()).hexdigest(),
                    "control_token_hash": hashlib.sha256(control.encode()).hexdigest(),
                    "signing_key_hex": key.hex(),
                    "key_id": "identity-journal-v1",
                }
            ]
        )
    )
    state = IdentityStore(database)
    state.provision_resource(tenant, world["canonical"], "resource-v1")
    state.provision_representation(tenant, account, world["provider_id"], world["canonical"])
    provider = LiveProvider(
        state,
        {
            **os.environ,
            "EXECBOUND_MOCK_PROVIDER": "mock_entra",
            "EXECBOUND_MOCK_DATABASE_PATH": str(database),
            "EXECBOUND_MOCK_ACCOUNTS_PATH": str(configfile),
            "TEST_PROVIDER_INVOCATIONS": str(tmp_path / "identity-invocations.txt"),
            "TEST_PROVIDER_REQUESTS": str(tmp_path / "identity-requests.txt"),
        },
        tmp_path / "identity-provider.ready",
    )
    provider.start()
    provider.config = ConnectionConfig(
        tenant,
        account,
        f"http://127.0.0.1:{provider.port}",
        dispatch,
        control,
        {"identity-journal-v1": key},
        timeout_seconds=2,
        provider="mock_entra",
    )
    yield provider
    provider.stop()


@pytest.fixture
def identity_connector(identity_provider):
    connector = MockConnector(identity_provider.config)
    try:
        yield connector
    finally:
        connector.close()
