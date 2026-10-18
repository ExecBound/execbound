# SPDX-License-Identifier: AGPL-3.0-only
"""The gateway's half of sample targets (#420): configuration and connection resolution.

The one kernel change this unit makes is here: an active account marked `sample`, whose
provider has a `sample_providers` entry, counts as connected. Everything else holds as it did:
an account not marked `sample` never gets a derived connection, a configured connector resolves
exactly as before and is never closed by a lookup, and without a sample key a sample request is
refused before any decision exactly as an unconfigured account's is.
"""

import json
from copy import deepcopy
from uuid import uuid4

import pytest
from sample_fixtures import agent_identity, empty_workspace, offline_runtime
from sample_fixtures import sample_key as sample_key
from sqlalchemy import text
from test_surface_configuration import config as config
from test_surface_configuration import load

from execbound import samples
from execbound.db import Database
from execbound.execution.models import ExecutionError
from execbound.provider.connector import ConnectionConfig, MockConnector
from execbound.provider.sample_accounts import SAMPLE_KEY_ID, SampleProvider, sample_material
from execbound.runtime import Runtime
from execbound.surfaces.configuration import load_runtime, read_configuration, reload_keys
from execbound.surfaces.tokens import TokenKeys

SAMPLE_HEX = "5a" * 32
UNREACHABLE = "postgresql+psycopg://invalid:invalid@127.0.0.1:1/execbound"


def with_samples(config, **entry):
    changed = deepcopy(config)
    changed["sample_providers"] = {
        "mock_crowdstrike": {
            "origin": "http://127.0.0.1:8002",
            "sample_key": SAMPLE_HEX,
            **entry,
        }
    }
    return changed


def test_sm_runtime_the_sample_block_is_read_from_the_private_configuration(tmp_path, config):
    runtime, _ = load(tmp_path, with_samples(config))
    entry = runtime.sample_providers["mock_crowdstrike"]
    assert (entry.origin, entry.key, entry.timeout_seconds) == (
        "http://127.0.0.1:8002",
        bytes.fromhex(SAMPLE_HEX),
        5.0,
    )
    assert SAMPLE_HEX not in repr(entry)
    plain, _ = load(tmp_path, config)
    assert dict(plain.sample_providers) == {}


def test_sm_runtime_a_deployment_may_hold_only_sample_providers(tmp_path, config):
    only = with_samples(config)
    del only["connectors"]
    runtime, _ = load(tmp_path, only)
    assert dict(runtime.connectors) == {}
    assert "mock_crowdstrike" in runtime.sample_providers


@pytest.mark.parametrize(
    "failure",
    [
        "short key",
        "upper case key",
        "identity mock",
        "cleartext origin",
        "origin with a path",
        "unknown field",
        "a connector's evidence key",
        "the continuation key",
    ],
)
def test_sm_runtime_a_sample_block_it_cannot_trust_is_refused_without_diagnostics(
    tmp_path, config, failure
):
    changed = with_samples(config)
    entry = changed["sample_providers"]["mock_crowdstrike"]
    if failure == "short key":
        entry["sample_key"] = "5a" * 31
    elif failure == "upper case key":
        entry["sample_key"] = "5A" * 32
    elif failure == "identity mock":
        changed["sample_providers"] = {"mock_entra": entry}
    elif failure == "cleartext origin":
        entry["origin"] = "http://10.1.2.3:8002"
    elif failure == "origin with a path":
        entry["origin"] = "https://mock.example.net/v1"
    elif failure == "unknown field":
        entry["tenant_id"] = str(uuid4())
    elif failure == "a connector's evidence key":
        entry["sample_key"] = changed["connectors"][0]["evidence_keys"]["proof"]
    else:
        entry["sample_key"] = changed["continuation_keys"]["state-v1"]
    with pytest.raises(ValueError) as refused:
        load(tmp_path, changed)
    assert str(refused.value) == "Invalid runtime configuration"


def test_sm_runtime_a_changed_sample_key_is_a_restart_never_a_reload(tmp_path, config):
    path = tmp_path / "private.json"
    path.write_text(json.dumps(with_samples(config)), encoding="utf-8")
    db = Database(UNREACHABLE)
    runtime = None
    try:
        runtime, human = load_runtime(path, db)
        baseline = read_configuration(path)
        path.write_text(json.dumps(with_samples(config, sample_key="6b" * 32)), encoding="utf-8")
        reload = reload_keys(path, runtime, human, baseline)
        assert (reload.state, reload.code) == ("refused", "CONFIGURATION_CHANGED")
        assert runtime.sample_providers["mock_crowdstrike"].key == bytes.fromhex(SAMPLE_HEX)
    finally:
        if runtime is not None:
            for connector in runtime.connectors.values():
                connector.close()
        db.close()


def test_sm_runtime_a_rotation_may_not_take_up_the_sample_key(sample_key):
    tenant, account = uuid4(), uuid4()
    configured = MockConnector(
        ConnectionConfig(
            tenant, account, "http://127.0.0.1:9", "d" * 43, "c" * 43, {"journal-v1": b"\x01" * 32}
        )
    )
    keys = TokenKeys("state-v1", {"state-v1": b"\x02" * 32})
    db = Database(UNREACHABLE)
    try:
        runtime = Runtime(
            db,
            [configured],
            keys=keys,
            sample_providers=[SampleProvider("mock_crowdstrike", "http://127.0.0.1:9", sample_key)],
        )
        with pytest.raises(ValueError):
            runtime.rotate(keys, {(tenant, account): {"journal-v2": sample_key}})
        with pytest.raises(ValueError):
            runtime.rotate(
                TokenKeys("state-v2", {"state-v2": sample_key}),
                {(tenant, account): {"journal-v1": b"\x01" * 32}},
            )
        assert dict(runtime.connectors[(tenant, account)].config.evidence_keys) == {
            "journal-v1": b"\x01" * 32
        }
    finally:
        configured.close()
        db.close()


def test_sm_runtime_an_active_sample_account_counts_as_connected_only_with_a_key(
    db, admin_engine, seeded, sample_key
):
    workspace = empty_workspace(admin_engine, db)
    installed = samples.install(db, workspace.admin, available=True)
    account = installed.account_id
    assert account is not None
    keyed, plain = offline_runtime(db, sample_key), offline_runtime(db, None)
    assert keyed.available_accounts(workspace.tenant_id) == frozenset(
        {(account, "mock_crowdstrike")}
    )
    assert plain.available_accounts(workspace.tenant_id) == frozenset()
    material = sample_material(sample_key, workspace.tenant_id, account)
    with keyed.connection(workspace.tenant_id, account) as connector:
        assert isinstance(connector, MockConnector)
        assert connector.config.origin == "http://127.0.0.1:9"
        assert (connector.config.dispatch_token, connector.config.control_token) == (
            material.dispatch_token,
            material.control_token,
        )
        assert dict(connector.config.evidence_keys) == {SAMPLE_KEY_ID: material.journal_key}
        derived = connector
    assert derived._client.is_closed
    with plain.connection(workspace.tenant_id, account) as connector:
        assert connector is None
    samples.remove(db, workspace.admin, available=True)
    assert keyed.available_accounts(workspace.tenant_id) == frozenset()
    with keyed.connection(workspace.tenant_id, account) as connector:
        assert connector is None


def test_sm_runtime_an_account_not_marked_sample_never_gets_a_derived_connection(
    db, admin_engine, seeded, sample_key
):
    workspace = empty_workspace(admin_engine, db)
    ordinary = uuid4()
    with admin_engine.begin() as conn:
        conn.execute(
            text("SELECT set_config('execbound.tenant_id', :t, true)"),
            {"t": str(workspace.tenant_id)},
        )
        conn.execute(
            text(
                "INSERT INTO execbound.connector_accounts(tenant_id, account_id, provider, "
                "space_id) VALUES (:t, :a, 'mock_crowdstrike', :s)"
            ),
            {"t": workspace.tenant_id, "a": ordinary, "s": workspace.space_id},
        )
    keyed = offline_runtime(db, sample_key)
    assert keyed.available_accounts(workspace.tenant_id) == frozenset()
    with keyed.connection(workspace.tenant_id, ordinary) as connector:
        assert connector is None
    # Another workspace's sample account is not this workspace's, whatever it is asked as.
    other = empty_workspace(admin_engine, db)
    theirs = samples.install(db, other.admin, available=True).account_id
    assert theirs is not None
    with keyed.connection(workspace.tenant_id, theirs) as connector:
        assert connector is None
    assert (theirs, "mock_crowdstrike") not in keyed.available_accounts(workspace.tenant_id)


def test_sm_runtime_a_configured_connector_resolves_as_before_and_is_never_closed(db, sample_key):
    tenant, account = uuid4(), uuid4()
    configured = MockConnector(
        ConnectionConfig(
            tenant, account, "http://127.0.0.1:9", "d" * 43, "c" * 43, {"journal-v1": b"\x01" * 32}
        )
    )
    try:
        runtime = Runtime(
            db,
            [configured],
            sample_providers=[SampleProvider("mock_crowdstrike", "http://127.0.0.1:9", sample_key)],
        )
        assert runtime.available_accounts(tenant) == frozenset({(account, "mock_crowdstrike")})
        with runtime.connection(tenant, account) as connector:
            assert connector is configured
        assert not configured._client.is_closed
    finally:
        configured.close()


def dev_request(installed, key):
    dev = next(host for host in installed.hosts if host.effect == "allow")
    return json.dumps(
        {
            "operation_ref": "endpoint.isolate",
            "target": {"kind": "hostname", "value": dev.hostname},
            "arguments": {},
            "idempotency_key": key,
            "claimed_context": {"incident_id": str(dev.incident_id)},
        }
    ).encode()


def executions(admin_engine, tenant) -> int:
    with admin_engine.begin() as conn:
        conn.execute(text("SELECT set_config('execbound.tenant_id', :t, true)"), {"t": str(tenant)})
        return int(
            conn.execute(
                text("SELECT count(*) FROM execbound.executions WHERE tenant_id = :t"),
                {"t": tenant},
            ).scalar_one()
        )


def test_sm_runtime_without_a_sample_key_a_sample_request_is_refused_before_any_decision(
    db, admin_engine, seeded
):
    workspace = empty_workspace(admin_engine, db)
    installed = samples.install(db, workspace.admin, available=True)
    agent = agent_identity(admin_engine, db, workspace)
    with pytest.raises(ExecutionError) as refused:
        offline_runtime(db, None).execute(agent, dev_request(installed, "sample-no-key"))
    assert refused.value.code == "CONNECTOR_UNAVAILABLE"
    assert executions(admin_engine, workspace.tenant_id) == 0


def test_sm_runtime_a_tenant_holding_a_configured_connector_gets_no_sample_connection(
    db, admin_engine, seeded, sample_key
):
    """The endpoint mock refuses a sample token for any tenant it holds a configured account
    for, so the gateway derives no sample connection there either. A workspace whose slot was
    switched off in the database but is still in the private configuration keeps its sample
    account, and a request on it is refused at admission instead of being sent to a 401 and
    stranded INDETERMINATE, where Reconcile would meet the same 401 and removal would be
    refused for good. Every other tenant's sample connection is untouched."""
    workspace = empty_workspace(admin_engine, db)
    installed = samples.install(db, workspace.admin, available=True)
    account = installed.account_id
    other = empty_workspace(admin_engine, db)
    theirs = samples.install(db, other.admin, available=True).account_id
    assert account is not None and theirs is not None
    slot = uuid4()
    configured = MockConnector(
        ConnectionConfig(
            workspace.tenant_id,
            slot,
            "http://127.0.0.1:9",
            "d" * 43,
            "c" * 43,
            {"journal-v1": b"\x01" * 32},
        )
    )
    try:
        runtime = Runtime(
            db,
            [configured],
            keys=TokenKeys("samples-v1", {"samples-v1": b"\x03" * 32}),
            sample_providers=[SampleProvider("mock_crowdstrike", "http://127.0.0.1:9", sample_key)],
        )
        assert runtime.available_accounts(workspace.tenant_id) == frozenset(
            {(slot, "mock_crowdstrike")}
        )
        with runtime.connection(workspace.tenant_id, account) as connector:
            assert connector is None
        with runtime.connection(workspace.tenant_id, slot) as connector:
            assert connector is configured
        agent = agent_identity(admin_engine, db, workspace)
        with pytest.raises(ExecutionError) as refused:
            runtime.execute(agent, dev_request(installed, "sample-configured-tenant"))
        assert refused.value.code == "CONNECTOR_UNAVAILABLE"
        assert executions(admin_engine, workspace.tenant_id) == 0
        # Another workspace, with nothing configured, keeps its derived connection.
        assert runtime.available_accounts(other.tenant_id) == frozenset(
            {(theirs, "mock_crowdstrike")}
        )
        with runtime.connection(other.tenant_id, theirs) as connector:
            assert isinstance(connector, MockConnector)
            assert connector is not configured
    finally:
        configured.close()
