# SPDX-License-Identifier: AGPL-3.0-only
"""The executor protocol's conformance module, run against both reference mocks (#37).

`execbound_protocol.conformance` is the Apache-2.0 module a vendor runs against its own
executor: it sends each published vector's command, and the commands derived from it, and
checks every answer against what version 1 requires (`docs/protocol/EXECUTOR_PROTOCOL.md`,
section 1.10). Here it runs against the two protected mocks, the endpoint mock and the identity
mock, which are the reference implementations, so the vectors and the module stay true to
the executors ExecBound actually dispatches to.

A module that passes everything proves nothing, so the second half of this file runs it
against deliberately broken mocks: one that ignores its journal, one that mutates again on a
repeated command, one that mutates twice, one that answers a changed command, one that ignores
the expected version, one that forgets an unknown target, one that forgets a cancellation, one
that takes the control credential for a dispatch, one that answers its journal to the dispatch
credential alone, one that moves the target after a mismatch, one that signs with a key outside
the ring, and one for each transition a vector records that misstates where it started. Each
must fail, for every vector of its provider that can show its fault, and at the check that
names it.
"""

import hashlib
import json
import socket
import sqlite3
import threading
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from uuid import uuid4

import pytest
import uvicorn
from execbound_connectors.accounts import ProviderAccount
from execbound_connectors.identity_store import IdentityStore, MockIdentity
from execbound_connectors.mock_app import create_mock_app
from execbound_connectors.mock_store import JournalStore, MockResource, MockStore
from execbound_protocol import conformance
from execbound_protocol.catalog import PRODUCTION_ACTIONS
from execbound_protocol.conformance import (
    CHECKS,
    Answer,
    Executor,
    Nonconformance,
    Vector,
    VectorError,
    check,
    http_send,
    load_vectors,
)
from execbound_protocol.provider import JournalRecord, ProviderCommand
from fastapi.testclient import TestClient

ROOT = Path(__file__).resolve().parents[1]
VECTORS = ROOT / "protocol" / "executor" / "v1" / "vectors"
DISPATCH, CONTROL = "conformance-dispatch-token", "conformance-control-token"


def vectors(name: str) -> tuple[Vector, ...]:
    return load_vectors((VECTORS / name).read_bytes())


# Every published vector file, and the provider whose executor it checks.
FILES = {
    "endpoint-contract-v1.json": "mock_crowdstrike",
    "endpoint-recovery-contract-v1.json": "mock_crowdstrike",
    "identity-contract-v1.json": "mock_entra",
    "identity-credential-contract-v1.json": "mock_entra",
}
ENDPOINT = tuple(
    vector
    for name, provider in FILES.items()
    if provider == "mock_crowdstrike"
    for vector in vectors(name)
)
IDENTITY = tuple(
    vector
    for name, provider in FILES.items()
    if provider == "mock_entra"
    for vector in vectors(name)
)


def test_the_published_vectors_load_and_hold_together():
    """Every vector is one command, the journal its capture returned for it, and the public
    test key that journal verifies under."""
    # Beside them, chapter 2's checkpoint report vectors, which another module checks
    # (`tests/test_checkpoint_report_conformance.py`).
    assert sorted(path.name for path in VECTORS.iterdir()) == sorted(
        [*FILES, "checkpoint-report-v1.json"]
    )
    assert [vector.name for vector in ENDPOINT] == ["endpoint.isolate", "endpoint.lift_isolation"]
    assert [vector.name for vector in IDENTITY] == [
        "identity.disable",
        "identity.enable",
        "identity.revoke_sessions",
        "identity.reset_password",
    ]
    for vector in (*ENDPOINT, *IDENTITY):
        assert vector.signed.record.command == vector.command
        assert vector.signed.record.outcome == "EXECUTED"
        assert len(vector.key) == 32


def test_the_vectors_cover_every_binding_the_protocol_reaches():
    """A binding no vector covers is one the module cannot check, so each provider ExecBound
    dispatches to over this protocol has a vector for every action the catalog binds to it."""
    for provider, found in (("mock_crowdstrike", ENDPOINT), ("mock_entra", IDENTITY)):
        bound = {binding.action for binding in PRODUCTION_ACTIONS.bindings_for(provider)}
        assert {vector.name for vector in found} == bound
        assert {vector.command.provider for vector in found} == {provider}


def test_a_vectors_start_state_is_every_transition_it_records():
    """`prepare` is told the whole state a vector's record starts from. A password reset
    records the identity it reset and the credential it changed, and the dispatch check
    compares both, so a start state naming only the first would leave an executor whose
    credential state was anywhere else failing with nothing to tell it why."""
    by_name = {vector.name: vector for vector in (*ENDPOINT, *IDENTITY)}
    assert by_name["endpoint.isolate"].before is None
    assert by_name["endpoint.lift_isolation"].before == {"contained": True}
    assert by_name["identity.disable"].before == {"account_enabled": True, "session_generation": 0}
    assert by_name["identity.reset_password"].before == {
        "account_enabled": True,
        "session_generation": 0,
        "password_generation": 0,
        "must_change_password": False,
    }


@pytest.mark.parametrize("found", [ENDPOINT, IDENTITY], ids=["endpoint", "identity"])
def test_one_account_serves_every_vector_of_a_provider(found: tuple[Vector, ...]):
    """A vendor configures one account for its provider: every vector names the same tenant,
    account and key, and one target, so `prepare` is all that differs between them."""
    assert len({vector.command.tenant_id for vector in found}) == 1
    assert len({vector.command.account_id for vector in found}) == 1
    assert len({(vector.key_id, vector.key) for vector in found}) == 1
    assert len({vector.command.canonical_target_id for vector in found}) == 1
    assert len({vector.command.resource_provider_id for vector in found}) == 1
    assert len({vector.command.operation_id for vector in found}) == len(found)


@pytest.mark.parametrize("name", sorted(FILES))
@pytest.mark.parametrize(
    "tamper",
    [
        lambda contract: contract["signed_journal"].update(signature="0" * 64),
        lambda contract: contract["signed_journal"]["record"]["command"].update(
            expected_version="another-version"
        ),
        lambda contract: contract.update(command_canonical=contract["command_canonical"] + " "),
    ],
    ids=["signature", "bound command", "command bytes"],
)
def test_a_vector_that_does_not_hold_together_is_refused(tamper, name: str):
    document = json.loads((VECTORS / name).read_bytes())
    load_vectors(json.dumps(document).encode())
    for contract in document["actions"].values() if "actions" in document else [document]:
        tamper(contract)
        contract["signed_journal_canonical"] = json.dumps(
            contract["signed_journal"], sort_keys=True, separators=(",", ":")
        )
    with pytest.raises(VectorError):
        load_vectors(json.dumps(document).encode())


def test_a_vector_file_is_read_as_strictly_as_a_provider_message():
    raw = (VECTORS / "endpoint-contract-v1.json").read_bytes()
    with pytest.raises(VectorError):
        load_vectors(raw.replace(b'"description"', b'"description": "x", "description"', 1))
    with pytest.raises(VectorError):
        load_vectors(b"[]")


# The reference mocks, configured as a vendor would configure its own executor under test: one
# account for the vectors' tenant and account, signing with the vectors' public test key.


@dataclass
class Mock:
    store: JournalStore
    account: ProviderAccount
    client: TestClient
    # A fault in how the executor answers rather than in what its store does: it wraps the
    # mock's own `send`, so the executor under test is the mock behind it.
    wrap: Callable[[conformance.Send], conformance.Send] | None = None


def account_for(vector: Vector, *, provider: str, signing_key: bytes | None = None):
    return ProviderAccount(
        tenant_id=vector.command.tenant_id,
        account_id=vector.command.account_id,
        dispatch_token_hash=hashlib.sha256(DISPATCH.encode()).hexdigest(),
        control_token_hash=hashlib.sha256(CONTROL.encode()).hexdigest(),
        signing_key=vector.key if signing_key is None else signing_key,
        key_id=vector.key_id,
        provider=provider,
    )


def endpoint_mock(tmp_path: Path, store_class=MockStore, signing_key=None, wrap=None) -> Mock:
    store = store_class(tmp_path / "endpoint.sqlite3")
    account = account_for(ENDPOINT[0], provider="mock_crowdstrike", signing_key=signing_key)
    app = create_mock_app(store, (account,), provider="mock_crowdstrike")
    return Mock(store, account, TestClient(app), wrap)


def identity_mock(tmp_path: Path, store_class=IdentityStore, wrap=None) -> Mock:
    store = store_class(tmp_path / "identity.sqlite3")
    account = account_for(IDENTITY[0], provider="mock_entra")
    app = create_mock_app(store, (account,), provider="mock_entra")
    return Mock(store, account, TestClient(app), wrap)


def client_send(client: TestClient) -> conformance.Send:
    def send(path: str, body: bytes, token: str) -> Answer:
        response = client.post(
            path,
            content=body,
            headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
        )
        return Answer(
            status=response.status_code,
            content_type=response.headers.get("content-type", ""),
            content_encoding=response.headers.get("content-encoding", "identity"),
            body=response.content,
        )

    return send


def prepare(store: JournalStore) -> Callable[[Vector], None]:
    """Put the vector's target at its expected version, in the state its transitions start
    from: what a vendor's own test harness does to its own executor before each vector."""

    def put(vector: Vector) -> None:
        command, before = vector.command, vector.before or {}
        if isinstance(store, IdentityStore):
            store.reprovision_resource(
                command.tenant_id,
                command.canonical_target_id,
                command.expected_version,
                account_enabled=before.get("account_enabled", True),
                session_generation=before.get("session_generation", 0),
            )
            if "password_generation" in before:
                # The mock provisions no credential state, so the harness writes it, as a
                # vendor's harness would through whatever its own directory offers.
                with store._transaction() as conn:
                    conn.execute(
                        "UPDATE resources SET password_generation = ?, must_change_password = ? "
                        "WHERE tenant_id = ? AND canonical_target_id = ?",
                        (
                            before["password_generation"],
                            int(before["must_change_password"]),
                            str(command.tenant_id),
                            str(command.canonical_target_id),
                        ),
                    )
        else:
            assert isinstance(store, MockStore)
            store.reprovision_resource(
                command.tenant_id,
                command.canonical_target_id,
                command.expected_version,
                contained=before.get("contained", False),
            )
        store.provision_representation(
            command.tenant_id,
            command.account_id,
            command.resource_provider_id,
            command.canonical_target_id,
        )

    return put


def mutations(store: JournalStore) -> Callable[[Vector], int]:
    def count(vector: Vector) -> int:
        command = vector.command
        resource = store.resource(command.tenant_id, command.canonical_target_id)  # type: ignore[attr-defined]
        return 0 if resource is None else resource.mutation_count

    return count


def executor(mock: Mock, *, counted: bool = True, send=None) -> Executor:
    send = send or client_send(mock.client)
    return Executor(
        send=mock.wrap(send) if mock.wrap is not None else send,
        dispatch_token=DISPATCH,
        control_token=CONTROL,
        prepare=prepare(mock.store),
        mutations=mutations(mock.store) if counted else None,
    )


@pytest.mark.parametrize("counted", [True, False], ids=["with the counter", "wire only"])
def test_the_endpoint_mock_conforms(tmp_path: Path, counted: bool):
    mock = endpoint_mock(tmp_path)
    for vector in ENDPOINT:
        assert check(vector, executor(mock, counted=counted)) == CHECKS
    # Each vector moved the target exactly twice: its own dispatch and the follow-up at the
    # version it produced. Everything else the module sent mutated nothing. Both vectors name
    # one target.
    target = ENDPOINT[0].command
    resource = mock.store.resource(target.tenant_id, target.canonical_target_id)
    assert resource is not None and resource.mutation_count == 4
    # The lift ran last and its follow-up lifted again, so the target ends uncontained.
    assert isinstance(resource, MockResource) and not resource.contained


@pytest.mark.parametrize("counted", [True, False], ids=["with the counter", "wire only"])
def test_the_identity_mock_conforms(tmp_path: Path, counted: bool):
    mock = identity_mock(tmp_path)
    for vector in IDENTITY:
        assert check(vector, executor(mock, counted=counted)) == CHECKS
    target = IDENTITY[0].command
    resource = mock.store.resource(target.tenant_id, target.canonical_target_id)
    # Four vectors on one target, two mutations each.
    assert resource is not None and resource.mutation_count == 8
    # The reset and its follow-up each counted one generation, and both forced a change.
    assert isinstance(resource, MockIdentity)
    assert (resource.password_generation, resource.must_change_password) == (2, True)


@pytest.mark.parametrize("vector", [*ENDPOINT, *IDENTITY], ids=lambda vector: vector.name)
def test_each_vector_conforms_alone_against_a_fresh_mock(tmp_path: Path, vector: Vector):
    """No vector depends on another having run first."""
    build = identity_mock if vector.command.provider == "mock_entra" else endpoint_mock
    assert check(vector, executor(build(tmp_path))) == CHECKS


@contextmanager
def served(app) -> Iterator[str]:
    ready = threading.Event()

    class ReadyServer(uvicorn.Server):
        async def startup(self, sockets=None):
            await super().startup(sockets=sockets)
            ready.set()

    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        origin = f"http://127.0.0.1:{sock.getsockname()[1]}"
        server = ReadyServer(uvicorn.Config(app, log_level="critical", access_log=False))
        thread = threading.Thread(target=server.run, kwargs={"sockets": [sock]}, daemon=True)
        thread.start()
        try:
            assert ready.wait(10) and server.started, "the mock did not become ready"
            yield origin
        finally:
            server.should_exit = True
            thread.join(timeout=10)
            assert not thread.is_alive(), "the mock did not stop"


def test_the_endpoint_mock_conforms_over_http(tmp_path: Path):
    """The same run through `http_send`, which is how a vendor points the module at a URL."""
    mock = endpoint_mock(tmp_path)
    app = create_mock_app(mock.store, (mock.account,), provider="mock_crowdstrike")
    with served(app) as origin:
        for vector in ENDPOINT:
            assert check(vector, executor(mock, send=http_send(origin))) == CHECKS


@pytest.mark.parametrize(
    "origin",
    [
        "ftp://127.0.0.1:8010",
        "http://127.0.0.1:8010/v1",
        "http://127.0.0.1:8010?tenant=other",
        "http://user:secret@127.0.0.1:8010",
        "127.0.0.1:8010",
    ],
)
def test_http_send_takes_an_origin_and_nothing_else(origin: str):
    with pytest.raises(ValueError):
        http_send(origin)


# Broken executors. Each is a reference mock with one fault, and the module must name it.


def bump(store: JournalStore, command: ProviderCommand, by: int = 1) -> None:
    """Apply a mutation the journal does not record: move the version and count it."""
    with store._transaction() as conn:
        conn.execute(
            "UPDATE resources SET version = ?, mutation_count = mutation_count + ? "
            "WHERE tenant_id = ? AND canonical_target_id = ?",
            (str(uuid4()), by, str(command.tenant_id), str(command.canonical_target_id)),
        )


class IgnoresTheJournal(MockStore):
    """Runs every command as though it had never been seen."""

    @staticmethod
    def _lookup(conn: sqlite3.Connection, command: ProviderCommand) -> JournalRecord | None:
        return None

    @staticmethod
    def _write_record(conn: sqlite3.Connection, record: JournalRecord) -> None:
        try:
            MockStore._write_record(conn, record)
        except sqlite3.IntegrityError:
            pass


class MutatesAgainOnRepeat(MockStore):
    """Answers a repeated command with the retained journal, and acts on the target again."""

    def dispatch(self, command: ProviderCommand) -> JournalRecord:
        repeated = self.lookup(command) is not None
        record = super().dispatch(command)
        if repeated:
            bump(self, command)
        return record


class IdentityMutatesAgainOnRepeat(IdentityStore):
    def dispatch(self, command: ProviderCommand) -> JournalRecord:
        repeated = self.lookup(command) is not None
        record = super().dispatch(command)
        if repeated:
            bump(self, command)
        return record


class MutatesTwice(MockStore):
    """Records one mutation and performs two."""

    def dispatch(self, command: ProviderCommand) -> JournalRecord:
        fresh = self.lookup(command) is None
        record = super().dispatch(command)
        if fresh and record.outcome == "EXECUTED":
            with self._transaction() as conn:
                conn.execute(
                    "UPDATE resources SET mutation_count = mutation_count + 1 "
                    "WHERE tenant_id = ? AND canonical_target_id = ?",
                    (str(command.tenant_id), str(command.canonical_target_id)),
                )
        return record


class AnswersAChangedCommand(MockStore):
    """Finds a retained operation by its id alone, so a changed command gets its journal."""

    @staticmethod
    def _lookup(conn: sqlite3.Connection, command: ProviderCommand) -> JournalRecord | None:
        row = conn.execute(
            "SELECT record_json FROM journal "
            "WHERE tenant_id = ? AND account_id = ? AND operation_id = ?",
            (str(command.tenant_id), str(command.account_id), str(command.operation_id)),
        ).fetchone()
        return None if row is None else JournalRecord.model_validate_json(row["record_json"])


class IgnoresTheVersion(MockStore):
    """Acts whatever version the target is at."""

    def dispatch(self, command: ProviderCommand) -> JournalRecord:
        if self.lookup(command) is None:
            with self._transaction() as conn:
                conn.execute(
                    "UPDATE resources SET version = ? "
                    "WHERE tenant_id = ? AND canonical_target_id = ?",
                    (
                        command.expected_version,
                        str(command.tenant_id),
                        str(command.canonical_target_id),
                    ),
                )
        return super().dispatch(command)


class ForgetsTheCancellation(MockStore):
    """Answers a cancellation and keeps no tombstone, so a late dispatch still acts."""

    def cancel(self, command: ProviderCommand) -> JournalRecord:
        existing = self.lookup(command)
        if existing is not None:
            return existing
        return JournalRecord(
            command=command,
            command_hash=command.command_hash,
            outcome="CANCELLED_NOT_EXECUTED",
            occurred_at=datetime.now(UTC),
            resulting_version=None,
            mutation_count=0,
        )


class ForgetsAnUnknownTarget(MockStore):
    """Answers TARGET_NOT_FOUND and keeps no record of it, so the operation is never settled."""

    @staticmethod
    def _write_record(conn: sqlite3.Connection, record: JournalRecord) -> None:
        if record.outcome != "TARGET_NOT_FOUND":
            MockStore._write_record(conn, record)


class MovesTheTargetAfterAMismatch(MockStore):
    """Answers a stale command VERSION_MISMATCH truthfully, then moves the target anyway.

    The mutation is not counted, so the counter cannot see it, and the mismatch it answered
    carries the version from before the move: only a later command at the version the
    vector's own dispatch produced can find that the target is no longer there.
    """

    def dispatch(self, command: ProviderCommand) -> JournalRecord:
        fresh = self.lookup(command) is None
        record = super().dispatch(command)
        if fresh and record.outcome == "VERSION_MISMATCH":
            bump(self, command, by=0)
        return record


class KeepsNoContainment(MockStore):
    """Keeps no containment state, so every lift starts from a target it reads as released."""

    def dispatch(self, command: ProviderCommand) -> JournalRecord:
        with self._transaction() as conn:
            conn.execute(
                "UPDATE resources SET contained = 0 "
                "WHERE tenant_id = ? AND canonical_target_id = ?",
                (str(command.tenant_id), str(command.canonical_target_id)),
            )
        return super().dispatch(command)


class KeepsNoForcedChange(IdentityStore):
    """Keeps no credential state of its own, so every reset starts from a forced change."""

    def dispatch(self, command: ProviderCommand) -> JournalRecord:
        with self._transaction() as conn:
            conn.execute(
                "UPDATE resources SET must_change_password = 1 "
                "WHERE tenant_id = ? AND canonical_target_id = ?",
                (str(command.tenant_id), str(command.canonical_target_id)),
            )
        return super().dispatch(command)


def takes_the_control_credential_for_a_dispatch(send: conformance.Send) -> conformance.Send:
    """An executor that admits either of the account's credentials on a dispatch route."""

    def wrapped(path: str, body: bytes, token: str) -> Answer:
        if path not in {conformance.JOURNAL, conformance.CANCEL} and token == CONTROL:
            token = DISPATCH
        return send(path, body, token)

    return wrapped


def answers_its_journal_to_dispatch_alone(send: conformance.Send) -> conformance.Send:
    """An executor that refuses `/v1/journal` to the control credential."""

    def wrapped(path: str, body: bytes, token: str) -> Answer:
        if path == conformance.JOURNAL and token == CONTROL:
            return Answer(status=401, content_type="application/json", body=b"{}")
        return send(path, body, token)

    return wrapped


@dataclass(frozen=True)
class Fault:
    """A broken executor, the check that must name its fault, and the vectors it is run on.

    `only` names the actions whose vectors can show the fault at all: a misstated start state
    shows only in a vector whose record carries the transition it starts.
    """

    build: Callable[[Path], Mock]
    expected: str
    counted: bool = True
    provider: str = "mock_crowdstrike"
    only: frozenset[str] | None = None


BROKEN: dict[str, Fault] = {
    "ignores the journal": Fault(lambda p: endpoint_mock(p, IgnoresTheJournal), "repeat"),
    "mutates again on a repeat": Fault(lambda p: endpoint_mock(p, MutatesAgainOnRepeat), "repeat"),
    # Without the counter, the moved version is what gives it away: the mismatch it is then
    # asked for no longer carries the version its own first dispatch produced.
    "mutates again on a repeat, wire only": Fault(
        lambda p: endpoint_mock(p, MutatesAgainOnRepeat), "version-mismatch", counted=False
    ),
    "identity mock mutates again on a repeat": Fault(
        lambda p: identity_mock(p, IdentityMutatesAgainOnRepeat), "repeat", provider="mock_entra"
    ),
    "mutates twice": Fault(lambda p: endpoint_mock(p, MutatesTwice), "dispatch"),
    "answers a changed command": Fault(
        lambda p: endpoint_mock(p, AnswersAChangedCommand), "conflict"
    ),
    "ignores the version": Fault(lambda p: endpoint_mock(p, IgnoresTheVersion), "version-mismatch"),
    "forgets an unknown target": Fault(
        lambda p: endpoint_mock(p, ForgetsAnUnknownTarget), "target-not-found"
    ),
    "forgets a cancellation": Fault(lambda p: endpoint_mock(p, ForgetsTheCancellation), "cancel"),
    "takes the control credential for a dispatch": Fault(
        lambda p: endpoint_mock(p, wrap=takes_the_control_credential_for_a_dispatch),
        "credentials",
    ),
    "identity mock takes the control credential for a dispatch": Fault(
        lambda p: identity_mock(p, wrap=takes_the_control_credential_for_a_dispatch),
        "credentials",
        provider="mock_entra",
    ),
    "answers its journal to the dispatch credential alone": Fault(
        lambda p: endpoint_mock(p, wrap=answers_its_journal_to_dispatch_alone), "lookup"
    ),
    "moves the target after a mismatch": Fault(
        lambda p: endpoint_mock(p, MovesTheTargetAfterAMismatch), "follow-up"
    ),
    "moves the target after a mismatch, wire only": Fault(
        lambda p: endpoint_mock(p, MovesTheTargetAfterAMismatch), "follow-up", counted=False
    ),
    "signs with a key outside the ring": Fault(
        lambda p: endpoint_mock(p, signing_key=b"\x01" * 32), "dispatch"
    ),
    "keeps no containment state": Fault(
        lambda p: endpoint_mock(p, KeepsNoContainment),
        "dispatch",
        only=frozenset({"endpoint.lift_isolation"}),
    ),
    "keeps no credential state": Fault(
        lambda p: identity_mock(p, KeepsNoForcedChange),
        "dispatch",
        provider="mock_entra",
        only=frozenset({"identity.reset_password"}),
    ),
}


def broken_cases() -> list[tuple[str, Vector]]:
    """Each fault against every vector of its provider that can show it."""
    cases = []
    for fault, case in sorted(BROKEN.items()):
        for vector in IDENTITY if case.provider == "mock_entra" else ENDPOINT:
            if case.only is None or vector.name in case.only:
                cases.append((fault, vector))
    return cases


@pytest.mark.parametrize(
    ("fault", "vector"),
    broken_cases(),
    ids=[f"{fault} - {vector.name}" for fault, vector in broken_cases()],
)
def test_a_broken_executor_fails_at_the_check_that_names_its_fault(
    tmp_path: Path, fault: str, vector: Vector
):
    case = BROKEN[fault]
    mock = case.build(tmp_path)
    assert mock.store.provider == case.provider == vector.command.provider
    with pytest.raises(Nonconformance) as raised:
        check(vector, executor(mock, counted=case.counted))
    assert raised.value.check == case.expected, str(raised.value)


def test_an_executor_that_has_seen_the_vector_is_told_to_start_from_a_fresh_journal(
    tmp_path: Path,
):
    mock = endpoint_mock(tmp_path)
    assert check(ENDPOINT[0], executor(mock)) == CHECKS
    with pytest.raises(Nonconformance) as raised:
        check(ENDPOINT[0], executor(mock))
    assert raised.value.check == "unknown-lookup"
    assert "fresh journal" in str(raised.value)


def test_every_check_is_one_the_module_names():
    assert len(set(CHECKS)) == len(CHECKS)
    assert all(isinstance(name, str) and name == name.lower() for name in CHECKS)
    assert {fault.expected for fault in BROKEN.values()} <= set(CHECKS)


def test_every_check_has_a_broken_executor_it_catches():
    """A check no broken executor fails could be deleted with every test still green. The
    first, `unknown-lookup`, is shown by the fresh-journal test above."""
    assert {fault.expected for fault in BROKEN.values()} == set(CHECKS) - {"unknown-lookup"}


def test_the_module_imports_nothing_but_the_protocol_and_the_standard_library():
    """Vendors install `execbound-protocol` alone; the module may not need the server, the
    connectors or an HTTP client the package does not depend on."""
    import ast
    import sys

    source = Path(conformance.__file__).read_text(encoding="utf-8")
    imported: set[str] = set()
    for node in ast.walk(ast.parse(source)):
        if isinstance(node, ast.Import):
            imported |= {alias.name.split(".")[0] for alias in node.names}
        elif isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
            imported.add(node.module.split(".")[0])
    assert imported - set(sys.stdlib_module_names) == {"execbound_protocol"}
