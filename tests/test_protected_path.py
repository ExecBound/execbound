# SPDX-License-Identifier: AGPL-3.0-only
"""Gateway PostgreSQL plus a separately authenticated real HTTP provider process."""

import dataclasses
import hashlib
import json
import os
import secrets
import socket
import subprocess
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path

import httpx
import pytest
from conftest import remember_secret
from sqlalchemy import text
from test_execution import admitted_plan, request
from test_execution import registry as registry
from test_execution import world as world

from execbound.execution import admit, decide_approval, get_execution, store, take_dispatch
from execbound.execution.models import ExecutionError
from execbound.provider.connector import ConnectionConfig, JournalVerifier, MockConnector
from execbound.provider.gateway import dispatch_owned, reconcile_operation
from execbound.provider.mock_store import MockStore
from execbound.provider.models import (
    JournalRecord,
    ProviderCommand,
    ProviderError,
    SignedJournal,
    provider_command,
    signature,
)
from execbound.provider.verifiers import verifier_for
from execbound.runtime import Runtime
from execbound.surfaces.tokens import TokenKeys


@dataclass
class LiveProvider:
    """A mock provider in a process of its own, at the port that process bound.

    The process binds the port itself, `0` on the first start so the kernel picks a free
    one and the same port on a restart, before anything else it does, and writes the number
    to `ready` once it is listening and its app is built. The fixture reads the port from
    there. Reserving a port here and releasing it for the process to bind left it free for
    the whole of the process's start, long enough for another xdist worker to take it, and a
    readiness that was any TCP connection to the port then answered for that other process.
    `config` is set by the fixture once the first start has said which port it is.
    """

    store: MockStore
    environment: dict = field(repr=False)
    ready: Path
    port: int = 0
    config: ConnectionConfig = field(init=False, repr=False)
    process: subprocess.Popen | None = field(default=None, repr=False)

    def start(self, mode="normal"):
        script = """
import os,socket,time
listener=socket.create_server(('127.0.0.1',int(os.environ['TEST_PROVIDER_PORT'])))
import uvicorn
from execbound.provider.mock_store import MockStore
from execbound.provider.mock_app import create_mock_app
from execbound.provider.identity_store import IdentityStore
Store=IdentityStore if os.environ.get('EXECBOUND_MOCK_PROVIDER')=='mock_entra' else MockStore
original=Store.dispatch
def dispatch(self,command):
    with open(os.environ['TEST_PROVIDER_INVOCATIONS'],'a') as journal:
        journal.write(str(command.operation_id)+'\\n')
    result=original(self,command)
    mode=os.environ.get('TEST_PROVIDER_FAILURE')
    if mode=='crash_after_commit': os._exit(0)
    if mode=='delay_after_commit': time.sleep(0.5)
    return result
Store.dispatch=dispatch
app=create_mock_app()
@app.middleware('http')
async def synthetic_response(request,call_next):
    from starlette.responses import Response
    with open(os.environ['TEST_PROVIDER_REQUESTS'],'a') as requests:
        requests.write(request.url.path+'\\n')
    mode=os.environ.get('TEST_PROVIDER_FAILURE')
    if request.url.path in {'/v1/contain','/v1/disable','/v1/enable','/v1/revoke_sessions'}:
        if mode=='redirect': return Response(status_code=307,headers={'Location':'/v1/contain'})
        if mode=='oversized': return Response('x'*40000,media_type='application/json')
        if mode=='malformed': return Response('{"failed":true}',media_type='application/json')
        if mode=='compressed':
            return Response('x',media_type='application/json',headers={'Content-Encoding':'gzip'})
    return await call_next(request)
ready=os.environ['TEST_PROVIDER_READY']
with open(ready+'.tmp','w') as report:
    report.write(str(listener.getsockname()[1]))
os.replace(ready+'.tmp',ready)
uvicorn.Server(uvicorn.Config(app,access_log=False,log_level='error')).run(sockets=[listener])
"""
        self.ready.unlink(missing_ok=True)
        log = self.ready.with_suffix(".log")
        with log.open("ab") as errors:
            self.process = subprocess.Popen(
                [sys.executable, "-c", script],
                env={
                    **self.environment,
                    "TEST_PROVIDER_FAILURE": mode,
                    "TEST_PROVIDER_PORT": str(self.port),
                    "TEST_PROVIDER_READY": str(self.ready),
                },
                stdout=subprocess.DEVNULL,
                stderr=errors,
                creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0,
            )
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            # The report is written whole, by a rename, only after the process holds the port.
            if self.ready.exists():
                self.port = int(self.ready.read_text())
                return
            if self.process.poll() is not None:
                last = log.read_text(errors="replace").strip().splitlines()[-1:]
                pytest.fail(
                    f"Protected mock process exited before readiness on port {self.port}: {last}"
                )
            time.sleep(0.05)
        pytest.fail("Protected mock did not become ready")

    def stop(self):
        if self.process and self.process.poll() is None:
            self.process.terminate()
            try:
                self.process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait(timeout=5)

    def restart(self, mode="normal"):
        self.stop()
        self.start(mode)


@pytest.fixture
def live_provider(tmp_path, world):
    tenant = world["identity"].tenant_id
    account = world["account"]
    dispatch, control = secrets.token_urlsafe(32), secrets.token_urlsafe(32)
    key = secrets.token_bytes(32)
    # The mock provider's credentials and the hex form of its journal signing key are
    # secrets this world mints; register them so no rendered output may repeat one.
    remember_secret(dispatch)
    remember_secret(control)
    remember_secret(key.hex())
    database = tmp_path / "provider.sqlite3"
    configfile = tmp_path / "provider-accounts.json"
    configfile.write_text(
        json.dumps(
            [
                {
                    "tenant_id": str(tenant),
                    "account_id": str(account),
                    "dispatch_token_hash": hashlib.sha256(dispatch.encode()).hexdigest(),
                    "control_token_hash": hashlib.sha256(control.encode()).hexdigest(),
                    "signing_key_hex": key.hex(),
                    "key_id": "journal-v1",
                }
            ]
        )
    )
    mock = MockStore(database)
    mock.provision_resource(tenant, world["canonical"], "resource-v1")
    mock.provision_representation(tenant, account, "device-01", world["canonical"])
    provider = LiveProvider(
        mock,
        {
            **os.environ,
            "EXECBOUND_MOCK_DATABASE_PATH": str(database),
            "EXECBOUND_MOCK_ACCOUNTS_PATH": str(configfile),
            "TEST_PROVIDER_INVOCATIONS": str(tmp_path / "invocations.txt"),
            "TEST_PROVIDER_REQUESTS": str(tmp_path / "requests.txt"),
        },
        tmp_path / "provider.ready",
    )
    provider.start()
    provider.config = ConnectionConfig(
        tenant,
        account,
        f"http://127.0.0.1:{provider.port}",
        dispatch,
        control,
        {"journal-v1": key},
        timeout_seconds=2,
    )
    yield provider
    provider.stop()


@pytest.fixture
def connector(live_provider):
    connector = MockConnector(live_provider.config)
    yield connector
    connector.close()


def approved(db, world):
    pending = admit(db, world["identity"], request(world), world["clock"])
    assert pending.ticket is None and pending.view.state == "PENDING_APPROVAL"
    decide_approval(db, world["human"], pending.view.approval_id, "APPROVE", world["clock"])
    return admit(db, world["identity"], request(world), world["clock"])


def resource(live_provider, world):
    return live_provider.store.resource(world["identity"].tenant_id, world["canonical"])


def test_production_approval_then_exactly_one_real_provider_mutation(
    db, world, live_provider, connector
):
    pending = admit(db, world["identity"], request(world), world["clock"])
    assert resource(live_provider, world).mutation_count == 0
    decide_approval(db, world["human"], pending.view.approval_id, "APPROVE", world["clock"])
    winner = admit(db, world["identity"], request(world), world["clock"])
    assert dispatch_owned(db, winner.ticket, connector, world["clock"]).state == "EXECUTED"
    assert resource(live_provider, world).mutation_count == 1
    assert admit(db, world["identity"], request(world), world["clock"]).ticket is None
    with pytest.raises(ExecutionError):
        dispatch_owned(db, winner.ticket, connector, world["clock"])
    assert resource(live_provider, world).mutation_count == 1
    with db.transaction(world["identity"].tenant_id) as conn:
        plan = admitted_plan(conn, world, winner)
        measured = store.usage(
            conn, world["identity"], world["bundle"], world["clock"], frozen=plan
        )
    assert sorted((c.confirmed_targets, c.unresolved_targets) for c in measured.counts) == [
        (0, 0),
        (1, 0),
    ]


@pytest.mark.parametrize("role,criticality", [("domain_controller", 2), ("workstation", 4)])
def test_authorization_forbid_produces_no_provider_invocation(
    db, world, live_provider, admin_engine, role, criticality
):
    with admin_engine.begin() as conn:
        conn.execute(
            text(
                "UPDATE execbound.resources SET role=:r,criticality=:c "
                "WHERE tenant_id=:t AND resource_id=:target"
            ),
            {
                "r": role,
                "c": criticality,
                "t": world["identity"].tenant_id,
                "target": world["target"],
            },
        )
    result = admit(db, world["identity"], request(world), world["clock"])
    assert result.view.state == "DENIED" and result.ticket is None
    assert resource(live_provider, world).mutation_count == 0
    assert not Path(live_provider.environment["TEST_PROVIDER_REQUESTS"]).exists()


def test_a_restart_onto_a_taken_port_fails_instead_of_talking_to_its_holder(live_provider):
    """The fixture once called a provider ready when any TCP connection to its port opened.
    A provider whose process could not bind the port, because another process held it, was
    then reported ready against that other process: on four xdist workers two workers'
    providers shared one port, and a test read requests another test had made. A port held
    by something else between the stop and the start must fail the restart, not pass it."""
    live_provider.stop()
    with socket.create_server(("127.0.0.1", live_provider.port)):
        with pytest.raises(pytest.fail.Exception, match="exited before readiness"):
            live_provider.start()


def test_a_request_to_the_providers_origin_reaches_its_own_process(live_provider):
    # The positive control for the refusal above: the port the origin names is the one this
    # provider's process bound, so a request to it lands in this provider's own request log.
    with httpx.Client(trust_env=False) as client:
        client.get(live_provider.config.origin + "/v1/port-probe")
    requests = Path(live_provider.environment["TEST_PROVIDER_REQUESTS"])
    assert requests.read_text().split() == ["/v1/port-probe"]


def test_a_connector_receives_the_frozen_provider_command(db, world, connector):
    """Connectors receive a `ProviderCommand`, never `DispatchCommand` (#496): the server
    freezes the command it dispatches and hands a connector exactly that, so nothing of the
    server's dispatch record, the frozen plan or its fence, reaches connector code."""
    received = []

    class Recording:
        config = connector.config

        def dispatch(self, command):
            received.append(command)
            return connector.dispatch(command)

    winner = approved(db, world)
    assert dispatch_owned(db, winner.ticket, Recording(), world["clock"]).state == "EXECUTED"
    with db.transaction(world["identity"].tenant_id) as conn:
        row = store.read(conn, world["identity"].tenant_id, winner.view.execution_id)
        frozen = provider_command(store.command(row))
    assert [type(command) for command in received] == [ProviderCommand]
    assert received == [frozen]


def test_the_verifier_comes_from_the_server_not_the_connector(db, world):
    """A connector cannot vouch for its own evidence. This one forges a journal under a key
    the operator never configured and carries a verifier that accepts exactly that key;
    the server verifies with the ring of the connection it configured, refuses the journal,
    and retains the execution as uncertain rather than settling it."""
    tenant, account = world["identity"].tenant_id, world["account"]
    forging = secrets.token_bytes(32)
    config = ConnectionConfig(
        tenant,
        account,
        "http://127.0.0.1:9",
        secrets.token_urlsafe(32),
        secrets.token_urlsafe(32),
        {"journal-v1": secrets.token_bytes(32)},
    )

    class Forger:
        def __init__(self):
            self.config = config
            self.verifier = JournalVerifier(tenant, account, {"journal-v1": forging})

        def dispatch(self, command):
            if not isinstance(command, ProviderCommand):
                command = provider_command(command)
            record = JournalRecord(
                command=command,
                command_hash=command.command_hash,
                outcome="EXECUTED",
                occurred_at=world["clock"].now(),
                resulting_version="resource-v2",
                mutation_count=1,
            )
            signed = SignedJournal(
                key_id="journal-v1",
                record=record,
                signature=signature(record, "journal-v1", forging),
            )
            return signed.model_dump_json().encode()

    winner = approved(db, world)
    assert dispatch_owned(db, winner.ticket, Forger(), world["clock"]).state == "INDETERMINATE"
    # The refusal is the server's evidence check, not some other failure on the way.
    with db.transaction(tenant) as conn:
        dispatched = store.command(store.read(conn, tenant, winner.view.execution_id))
    with pytest.raises(ProviderError) as refused:
        verifier_for(config).verify(dispatched, Forger().dispatch(dispatched))
    assert refused.value.code == "INVALID_EVIDENCE"


def forged_journal(command, key, clock):
    """A journal for `command` that claims execution, signed under `key`."""
    record = JournalRecord(
        command=command,
        command_hash=command.command_hash,
        outcome="EXECUTED",
        occurred_at=clock.now(),
        resulting_version="resource-v2",
        mutation_count=1,
    )
    signed = SignedJournal(
        key_id="journal-v1", record=record, signature=signature(record, "journal-v1", key)
    )
    return signed.model_dump_json().encode()


def test_reconciliation_settles_with_the_server_verifier_too(db, world):
    """The reconcile path as well as the dispatch path: a journal a connector forged, and
    the verifier it carries for it, settle nothing; the server's verifier refuses it."""
    tenant, account = world["identity"].tenant_id, world["account"]
    forging = secrets.token_bytes(32)
    config = ConnectionConfig(
        tenant,
        account,
        "http://127.0.0.1:9",
        secrets.token_urlsafe(32),
        secrets.token_urlsafe(32),
        {"journal-v1": secrets.token_bytes(32)},
    )

    class Forger:
        def __init__(self):
            self.config = config
            self.verifier = JournalVerifier(tenant, account, {"journal-v1": forging})

        def lookup(self, command):
            if not isinstance(command, ProviderCommand):
                command = provider_command(command)
            return forged_journal(command, forging, world["clock"])

    winner = approved(db, world)
    take_dispatch(db, winner.ticket, world["clock"])
    with pytest.raises(ExecutionError) as refused:
        reconcile_operation(
            db,
            world["admin"],
            winner.view.execution_id,
            Forger(),
            reason="Recover the forged journal",
            clock=world["clock"],
        )
    assert refused.value.code == "INVALID_EVIDENCE"
    assert get_execution(db, world["identity"], winner.view.execution_id).state != "EXECUTED"


def test_the_runtime_verifies_with_the_config_it_was_given_not_what_a_connector_reports(
    db, world, connector
):
    """A verifier built from `connector.config` would still trust the connector to report its
    own configuration. The runtime reads each connector's configuration once, validates that
    copy and builds its verifiers from it, so a connector that later reports a configuration
    holding a key of its own choosing vouches for nothing."""
    tenant, account = world["identity"].tenant_id, world["account"]
    runtime = Runtime(db, [connector], clock=world["clock"])
    winner = approved(db, world)
    dispatched = take_dispatch(db, winner.ticket, world["clock"])
    forging = secrets.token_bytes(32)
    forged = forged_journal(provider_command(dispatched), forging, world["clock"])
    connector.config = dataclasses.replace(connector.config, evidence_keys={"journal-v1": forging})

    assert verifier_for(connector.config).verify(dispatched, forged).outcome == "EXECUTED"
    with pytest.raises(ProviderError) as refused:
        runtime.evidence_verifier(tenant, account).verify(dispatched, forged)
    assert refused.value.code == "INVALID_EVIDENCE"


def test_a_rotation_reaches_the_runtimes_verifier_whatever_the_connector_does(db, world, connector):
    """The runtime rotates its own copy of a connection and rebuilds its verifier from it, so
    a connector that ignores `rotate_keys` cannot keep a retired key verifying, and a
    verifier handed out before the rotation answers with the rotated ring."""
    tenant, account = world["identity"].tenant_id, world["account"]
    keys = TokenKeys("continuation-v1", {"continuation-v1": secrets.token_bytes(32)})
    runtime = Runtime(db, [connector], clock=world["clock"], keys=keys)
    held = runtime.evidence_verifier(tenant, account)
    winner = approved(db, world)
    dispatched = take_dispatch(db, winner.ticket, world["clock"])
    retired = connector.config.evidence_keys["journal-v1"]
    signed_before = forged_journal(provider_command(dispatched), retired, world["clock"])
    assert held.verify(dispatched, signed_before).outcome == "EXECUTED"

    connector.rotate_keys = lambda evidence_keys: None
    runtime.rotate(keys, {(tenant, account): {"journal-v2": secrets.token_bytes(32)}})

    with pytest.raises(ProviderError) as refused:
        held.verify(dispatched, signed_before)
    assert refused.value.code == "INVALID_EVIDENCE"


def test_agent_cannot_call_any_protected_provider_control(db, world, seeded, live_provider):
    winner = approved(db, world)
    command = take_dispatch(db, winner.ticket, world["clock"])
    with httpx.Client(trust_env=False) as client:
        for path in ("/v1/contain", "/v1/journal", "/v1/cancel"):
            response = client.post(
                live_provider.config.origin + path,
                content=provider_command(command).model_dump_json(),
                headers={
                    "Authorization": "Bearer " + seeded["tokens"][0],
                    "Content-Type": "application/json",
                },
            )
            assert response.status_code == 401
            assert seeded["tokens"][0] not in response.text
    assert resource(live_provider, world).mutation_count == 0


def test_provider_version_changes_after_gateway_commit_fail_atomically(
    db, world, live_provider, connector
):
    winner = approved(db, world)
    # The provider's version changing under a committed gateway decision is an external
    # change, so it is a reset rather than a provisioning.
    live_provider.store.reprovision_resource(
        world["identity"].tenant_id, world["canonical"], "changed-v2"
    )
    result = dispatch_owned(db, winner.ticket, connector, world["clock"])
    assert result.state == "STALE_AUTHORIZATION"
    assert resource(live_provider, world).mutation_count == 0
    with db.transaction(world["identity"].tenant_id) as conn:
        row = store.read(conn, world["identity"].tenant_id, winner.view.execution_id)
        assert row["result"]["reason"] == "VERSION_MISMATCH"
        assert all(
            c.confirmed_targets == 0 and c.unresolved_targets == 0
            for c in store.usage(
                conn,
                world["identity"],
                world["bundle"],
                world["clock"],
                frozen=admitted_plan(conn, world, winner),
            ).counts
        )

    assert Path(live_provider.environment["TEST_PROVIDER_REQUESTS"]).read_text().splitlines() == [
        "/v1/contain"
    ]


@pytest.mark.parametrize("mode", ["delay_after_commit", "crash_after_commit"])
def test_effect_then_lost_response_reconciles_from_retained_journal(db, world, live_provider, mode):
    live_provider.restart(mode)
    config = live_provider.config
    short = ConnectionConfig(
        config.tenant_id,
        config.account_id,
        config.origin,
        config.dispatch_token,
        config.control_token,
        config.evidence_keys,
        timeout_seconds=0.15,
    )
    connector = MockConnector(short)
    try:
        winner = approved(db, world)
        result = dispatch_owned(db, winner.ticket, connector, world["clock"])
        assert result.state == "INDETERMINATE"
        assert resource(live_provider, world).mutation_count == 1
        assert (
            len(
                Path(live_provider.environment["TEST_PROVIDER_INVOCATIONS"])
                .read_text()
                .splitlines()
            )
            == 1
        )
        with pytest.raises(ExecutionError):
            take_dispatch(db, winner.ticket, world["clock"])
        live_provider.restart()
        settled = reconcile_operation(
            db,
            world["admin"],
            winner.view.execution_id,
            connector,
            reason="Verify operation after response loss",
            clock=world["clock"],
        )
        assert settled.state == "EXECUTED"
        assert resource(live_provider, world).mutation_count == 1
    finally:
        connector.close()


def test_missing_journal_does_not_refund_and_cancel_fences_delayed_dispatch(
    db, world, live_provider, connector
):
    winner = approved(db, world)
    delayed = take_dispatch(db, winner.ticket, world["clock"])
    unknown = reconcile_operation(
        db,
        world["admin"],
        winner.view.execution_id,
        connector,
        reason="Check interrupted send",
        clock=world["clock"],
    )
    assert unknown.state == "INDETERMINATE"
    with db.transaction(world["identity"].tenant_id) as conn:
        assert any(
            c.unresolved_targets == 1
            for c in store.usage(
                conn,
                world["identity"],
                world["bundle"],
                world["clock"],
                frozen=admitted_plan(conn, world, winner),
            ).counts
        )
    cancelled = reconcile_operation(
        db,
        world["admin"],
        winner.view.execution_id,
        connector,
        reason="Cancel operation with a durable tombstone",
        cancel_if_missing=True,
        clock=world["clock"],
    )
    assert cancelled.state == "FAILED_NOT_EXECUTED"
    late = connector.dispatch(provider_command(delayed))
    assert verifier_for(connector.config).verify(delayed, late).reason == "CANCELLED_NOT_EXECUTED"
    assert resource(live_provider, world).mutation_count == 0


def test_agent_reconciliation_rejected_before_provider_network(
    db, world, live_provider, connector, monkeypatch
):
    winner = approved(db, world)

    def forbidden(*args, **kwargs):
        pytest.fail("Agent caused provider control I/O")

    monkeypatch.setattr(connector, "lookup", forbidden)
    with pytest.raises(ExecutionError):
        reconcile_operation(
            db,
            world["identity"],
            winner.view.execution_id,
            connector,
            reason="Attempted cancellation",
            cancel_if_missing=True,
            clock=world["clock"],
        )
    assert resource(live_provider, world).mutation_count == 0
    with db.transaction(world["identity"].tenant_id) as conn:
        assert (
            conn.execute(
                text(
                    "SELECT count(*) FROM execbound.audit_events "
                    "WHERE kind='execution.rejected' "
                    "AND payload->>'operation'='provider.reconcile'"
                )
            ).scalar_one()
            == 1
        )


def test_no_database_connection_is_held_during_provider_io(
    db, world, live_provider, connector, monkeypatch
):
    winner = approved(db, world)
    actual = connector.dispatch

    def dispatch(command):
        assert db.engine.pool.checkedout() == 0
        return actual(command)

    monkeypatch.setattr(connector, "dispatch", dispatch)
    assert dispatch_owned(db, winner.ticket, connector, world["clock"]).state == "EXECUTED"


def test_settlement_audit_outage_keeps_impact_then_reconciliation_recovers(
    db, world, live_provider, connector, monkeypatch
):
    winner = approved(db, world)
    original = store.event

    def fail_terminal(conn, row, actor, before, after, clock, payload, *, semantic_time=None):
        if after == "EXECUTED":
            raise ValueError("synthetic outcome audit failure")
        return original(
            conn, row, actor, before, after, clock, payload, semantic_time=semantic_time
        )

    with monkeypatch.context() as context:
        context.setattr(store, "event", fail_terminal)
        assert dispatch_owned(db, winner.ticket, connector, world["clock"]).state == "INDETERMINATE"
    assert resource(live_provider, world).mutation_count == 1
    with db.transaction(world["identity"].tenant_id) as conn:
        assert any(
            c.unresolved_targets == 1
            for c in store.usage(
                conn,
                world["identity"],
                world["bundle"],
                world["clock"],
                frozen=admitted_plan(conn, world, winner),
            ).counts
        )
    assert (
        reconcile_operation(
            db,
            world["admin"],
            winner.view.execution_id,
            connector,
            reason="Recover outcome audit",
            clock=world["clock"],
        ).state
        == "EXECUTED"
    )


def test_inverse_change_never_refunds_original_impact(db, world, live_provider, connector):
    winner = approved(db, world)
    assert dispatch_owned(db, winner.ticket, connector, world["clock"]).state == "EXECUTED"
    live_provider.store.provision_resource(
        world["identity"].tenant_id, world["canonical"], "inverse-v3", contained=False
    )
    assert (
        reconcile_operation(
            db,
            world["admin"],
            winner.view.execution_id,
            connector,
            reason="Inspect after independent reversal",
            clock=world["clock"],
        ).state
        == "EXECUTED"
    )
    with db.transaction(world["identity"].tenant_id) as conn:
        assert any(
            c.confirmed_targets == 1
            for c in store.usage(
                conn,
                world["identity"],
                world["bundle"],
                world["clock"],
                frozen=admitted_plan(conn, world, winner),
            ).counts
        )


@pytest.mark.parametrize("mode", ["redirect", "oversized", "malformed", "compressed"])
def test_bad_transport_response_stays_uncertain_without_following_or_refunding(
    db, world, live_provider, connector, mode
):
    live_provider.restart(mode)
    winner = approved(db, world)
    assert dispatch_owned(db, winner.ticket, connector, world["clock"]).state == "INDETERMINATE"
    assert resource(live_provider, world).mutation_count == 0
    assert Path(live_provider.environment["TEST_PROVIDER_REQUESTS"]).read_text().splitlines() == [
        "/v1/contain"
    ]
    with db.transaction(world["identity"].tenant_id) as conn:
        assert any(
            c.unresolved_targets == 1
            for c in store.usage(
                conn,
                world["identity"],
                world["bundle"],
                world["clock"],
                frozen=admitted_plan(conn, world, winner),
            ).counts
        )


def test_connector_ignores_ambient_proxy_configuration(db, world, live_provider, monkeypatch):
    monkeypatch.setenv("HTTP_PROXY", "http://127.0.0.1:1")
    monkeypatch.setenv("ALL_PROXY", "http://127.0.0.1:1")
    monkeypatch.setenv("NO_PROXY", "")
    connector = MockConnector(live_provider.config)
    try:
        assert (
            dispatch_owned(db, approved(db, world).ticket, connector, world["clock"]).state
            == "EXECUTED"
        )
    finally:
        connector.close()


def test_revocation_during_journal_lookup_prevents_cancellation(
    db, world, live_provider, connector, admin_engine, monkeypatch
):
    winner = approved(db, world)
    original = connector.lookup

    def lookup(command):
        result = original(command)
        with admin_engine.begin() as conn:
            conn.execute(
                text("UPDATE execbound.credentials SET revoked_at=now() WHERE credential_id=:c"),
                {"c": world["admin"].credential_id},
            )
        return result

    def forbidden(*args):
        pytest.fail("Revoked administrator caused cancellation")

    monkeypatch.setattr(connector, "lookup", lookup)
    monkeypatch.setattr(connector, "cancel", forbidden)
    with pytest.raises(ExecutionError):
        reconcile_operation(
            db,
            world["admin"],
            winner.view.execution_id,
            connector,
            reason="Inspect interrupted request",
            cancel_if_missing=True,
            clock=world["clock"],
        )
    assert (
        get_execution(db, world["identity"], winner.view.execution_id, world["clock"]).state
        == "DISPATCH_COMMITTED"
    )
