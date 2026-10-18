# SPDX-License-Identifier: AGPL-3.0-only
"""The provider protocol and the connectors stand without the server (#496).

`execbound-protocol` and `execbound-connectors` are Apache-2.0 packages beside the AGPL server.
A connector package must import nothing from `execbound`, so a vendor can build against them
without the server. The dependency runs one way: the server imports the connectors and the
protocol, the connectors import the protocol, and the protocol imports neither. These read
every module of both packages for an import, or a module name handed to `importlib`, that would
cross that line.
"""

import ast
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
PROTOCOL = ROOT / "protocol" / "src" / "execbound_protocol"
CONNECTORS = ROOT / "connectors" / "src" / "execbound_connectors"
SERVER = ("execbound", "execbound_harness")


def _top(name: str) -> str:
    return name.split(".", 1)[0]


def imported(tree: ast.AST) -> set[str]:
    """Every top-level package a module imports, or names to `importlib` or `__import__`."""
    found: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            found |= {_top(alias.name) for alias in node.names}
        elif isinstance(node, ast.ImportFrom) and not node.level and node.module:
            found.add(_top(node.module))
        elif isinstance(node, ast.Call) and node.args:
            function = node.func
            called = (
                function.attr
                if isinstance(function, ast.Attribute)
                else function.id
                if isinstance(function, ast.Name)
                else None
            )
            first = node.args[0]
            if called in {"import_module", "__import__"} and isinstance(first, ast.Constant):
                if isinstance(first.value, str):
                    found.add(_top(first.value))
    return found


def crossings(package: Path, forbidden: tuple[str, ...]) -> list[str]:
    """Each module of `package` that imports one of `forbidden`, with what it imports."""
    problems = []
    for path in sorted(package.rglob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        crossed = sorted(imported(tree) & set(forbidden))
        if crossed:
            problems.append(f"{path.relative_to(package).as_posix()}: imports {', '.join(crossed)}")
    return problems


def test_neither_package_imports_the_server():
    assert crossings(PROTOCOL, SERVER) == []
    assert crossings(CONNECTORS, SERVER) == []


def test_the_protocol_imports_neither_the_connectors_nor_the_server():
    assert crossings(PROTOCOL, (*SERVER, "execbound_connectors")) == []


@pytest.mark.parametrize(
    "source",
    [
        "from execbound.audit import canonical_json\n",
        "import execbound.provider.models\n",
        "import execbound_harness\n",
        "import importlib\nimportlib.import_module('execbound.provider.mock_app')\n",
        "from importlib import import_module\nimport_module('execbound_harness.fixtures')\n",
        "def late():\n    from execbound import operations\n",
    ],
)
def test_the_walk_refuses_a_planted_import(tmp_path: Path, source: str):
    """The positive control: over two packages that import nothing from the server, the walk
    above would pass whether it worked or not."""
    (tmp_path / "planted.py").write_text(source, encoding="utf-8")
    assert len(crossings(tmp_path, SERVER)) == 1


@pytest.mark.parametrize(
    "source",
    [
        "import execbound_protocol\n",
        "from execbound_protocol.catalog import PRODUCTION_ACTIONS\n",
        "from . import provider\n",
        "TEXT = 'execbound.executor.outcome'\n",
    ],
)
def test_the_walk_lets_the_protocol_and_signed_literals_through(tmp_path: Path, source: str):
    # A signed literal that reads like a module path, such as the executor outcome's domain,
    # is a value and not an import.
    (tmp_path / "kept.py").write_text(source, encoding="utf-8")
    assert crossings(tmp_path, SERVER) == []


def test_the_server_names_the_protocols_helpers():
    """Each helper the protocol shares with the server has one definition, in the protocol,
    and the server names that same object. A copy could drift, and a retained command is
    validated again when it is read, so a stricter model or a different canonical form would
    refuse history or move a hash."""
    from execbound_protocol import arguments, canonical, domains, outcomes, strict

    import execbound.audit
    import execbound.domains
    import execbound.requests
    from execbound.execution import models as execution
    from execbound.resolution import models as resolution

    shared = [
        (execbound.audit.canonical_json, canonical.canonical_json),
        (execbound.requests.StrictModel, strict.StrictModel),
        (execbound.requests._unique_object, strict._unique_object),
        (execbound.requests._reject_number, strict._reject_number),
        (execbound.requests.Arguments, arguments.Arguments),
        (execbound.requests.ArgumentName, arguments.ArgumentName),
        (execution.Digest, strict.Digest),
        (resolution.Digest, strict.Digest),
        (resolution.Version, strict.Version),
        (execution.TerminalOutcome, outcomes.TerminalOutcome),
        (execution.TerminalReason, outcomes.TerminalReason),
        (execution.TERMINAL_PAIRS, outcomes.TERMINAL_PAIRS),
        (execution.consistent_terminal, outcomes.consistent_terminal),
    ]
    assert all(server is protocol for server, protocol in shared)
    assert execbound.domains.__all__
    assert all(
        getattr(execbound.domains, name) is getattr(domains, name)
        for name in execbound.domains.__all__
    )


CATALOG_NAMES = [
    "ACTION_PATTERN",
    "NAME_PATTERN",
    "ActionName",
    "ProviderName",
    "ProviderOperation",
    "ResourceType",
    "SchemaVersion",
    "CatalogError",
    "ArgumentSpec",
    "ActionSpec",
    "ProviderBinding",
    "OperationSpec",
    "ActionCatalog",
    "PRODUCTION_ACTIONS",
    "operation",
    "validate_operation",
]


def test_there_is_one_production_catalog():
    """The catalog lives in the protocol whole, data included, because `ProviderCommand`
    validates every command against it and a retained command is validated again when read.
    Two catalogs could disagree about history; the server's module names the protocol's."""
    from execbound_protocol import catalog

    import execbound.operations

    assert all(
        getattr(execbound.operations, name) is getattr(catalog, name) for name in CATALOG_NAMES
    )
    assert sorted(execbound.operations.__all__) == sorted(CATALOG_NAMES)


def frozen_journals() -> list[tuple[str, dict, str, bytes]]:
    """Every journal the frozen contracts hold: (name, signed journal, its canonical bytes, key)."""
    import json

    fixtures = ROOT / "tests" / "fixtures"
    endpoint = json.loads((fixtures / "endpoint-contract-v1.json").read_text(encoding="utf-8"))
    identity = json.loads((fixtures / "identity-contract-v1.json").read_text(encoding="utf-8"))
    found = [
        (
            "endpoint.isolate",
            endpoint["signed_journal"],
            endpoint["signed_journal_canonical"],
            bytes.fromhex(endpoint["test_verification_key_hex"]),
        )
    ]
    for action, case in identity["actions"].items():
        found.append(
            (
                action,
                case["signed_journal"],
                case["signed_journal_canonical"],
                bytes.fromhex(identity["test_verification_key_hex"]),
            )
        )
    return found


@pytest.mark.parametrize(
    ("frozen", "canonical", "key"),
    [case[1:] for case in frozen_journals()],
    ids=[case[0] for case in frozen_journals()],
)
def test_a_journal_the_protocol_signs_is_the_frozen_journal_and_the_server_verifies_it(
    frozen: dict, canonical: str, key: bytes
):
    """The protocol's `sign_journal`, given a frozen journal's own record and key, writes that
    journal back byte for byte, and the server's `JournalVerifier` settles it: the move to
    the protocol changed no signed byte, and a provider built on the protocol alone signs
    what the server accepts."""
    import json

    from execbound_protocol.canonical import canonical_json
    from execbound_protocol.provider import JournalRecord, sign_journal

    from execbound.provider.connector import JournalVerifier

    record = JournalRecord.model_validate_json(json.dumps(frozen["record"]))
    signed = sign_journal(record, frozen["key_id"], key)

    assert canonical_json(signed.model_dump(mode="json")) == canonical
    command = record.command
    verifier = JournalVerifier(
        command.tenant_id, command.account_id, {frozen["key_id"]: key}, provider=command.provider
    )
    evidence = verifier.verify_command(command, canonical.encode())
    assert evidence.reason == record.outcome and evidence.operation_id == command.operation_id


def test_an_outcome_the_protocol_signs_is_one_the_server_attests():
    """An external executor signs its record with the protocol alone, and the server, which
    holds only the public key, attests it; a record changed after signing is refused, which
    is the control that the check can fail at all."""
    from datetime import UTC, datetime
    from uuid import uuid4

    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
    from execbound_protocol.executor import ExecutorRecord, recorded_outcome, sign_outcome

    from execbound.provider.executor import ExecutorKey, _signed_by

    private = Ed25519PrivateKey.generate()
    public = private.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw).hex()
    key = ExecutorKey("executor-v1", public, datetime(2026, 1, 1, tzinfo=UTC))
    record = ExecutorRecord(
        operation_id=uuid4(),
        account_id=uuid4(),
        intent_hash="a" * 64,
        plan_hash="b" * 64,
        outcome="EXECUTED",
        reason="EXECUTED",
        reported_at=datetime(2026, 10, 1, tzinfo=UTC),
    )
    signed = sign_outcome(record, "executor-v1", private)

    assert _signed_by(key, signed)
    assert recorded_outcome(signed.model_dump_json()) == record
    changed = signed.model_copy(
        update={"record": record.model_copy(update={"plan_hash": "c" * 64})}
    )
    assert not _signed_by(key, changed)


def test_the_server_names_the_protocols_records():
    """The record, envelope and JWS halves of the connector record and the executor outcome
    are the protocol's; the server's modules name the same objects and keep the verifiers."""
    from execbound_protocol import composite, connector_record, executor

    import execbound.provider.composite
    import execbound.provider.connector_record
    import execbound.provider.executor

    moved = {
        execbound.provider.connector_record: (
            connector_record,
            ["CONNECTOR_RECORD_V1", "ConnectorExchange", "ConnectorRecord", "sign_exchange"],
        ),
        execbound.provider.composite: (
            composite,
            ["CompositeDrift", "GRAPH_USER_FIELDS", "GRAPH_USER_V1", "graph_user_composite"],
        ),
        execbound.provider.executor: (
            executor,
            [
                "ExecutorRecord",
                "SignedOutcome",
                "outcome_message",
                "sign_outcome",
                "recorded_outcome",
                "OUTCOME_DOMAIN",
            ],
        ),
    }
    for server, (protocol, names) in moved.items():
        assert all(getattr(server, name) is getattr(protocol, name) for name in names)


def names_in_code(package: Path, name: str) -> list[str]:
    """Each module of `package` whose code, not its docstrings or comments, names `name`."""
    found = []
    for path in sorted(package.rglob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            used = (isinstance(node, ast.Name) and node.id == name) or (
                isinstance(node, ast.Attribute) and node.attr == name
            )
            defined = isinstance(node, ast.ClassDef | ast.FunctionDef) and node.name == name
            if used or defined:
                found.append(path.relative_to(package).as_posix())
                break
    return found


def test_neither_package_can_build_the_evidence_the_kernel_settles_on(tmp_path: Path):
    """`TerminalEvidence` is what a verifier hands the kernel to settle an execution. It is
    the server's alone: no connector or protocol module names it, so a connector can return
    bytes and nothing more, and the server decides what they prove."""
    assert names_in_code(PROTOCOL, "TerminalEvidence") == []
    assert names_in_code(CONNECTORS, "TerminalEvidence") == []
    (tmp_path / "planted.py").write_text("evidence = TerminalEvidence()\n", encoding="utf-8")
    assert names_in_code(tmp_path, "TerminalEvidence") == ["planted.py"]


SETTLING = {"dispatch_owned", "reconcile_operation"}


def settling_calls_without_a_verifier(root: Path) -> list[str]:
    """Each call under `root` to a gateway entry point that names no `verifier=`."""
    missing = []
    for path in sorted(root.rglob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            function = node.func
            name = (
                function.id
                if isinstance(function, ast.Name)
                else function.attr
                if isinstance(function, ast.Attribute)
                else None
            )
            if name in SETTLING and not any(k.arg == "verifier" for k in node.keywords):
                missing.append(f"{path.relative_to(root).as_posix()}:{node.lineno}")
    return missing


def test_every_server_caller_settles_with_the_runtimes_verifier(tmp_path: Path):
    """The gateway falls back to a verifier built from the connector's own configuration
    only for a caller that passes none, which is a test's. Every caller in the server passes
    the one the runtime holds, built from the configuration it validated and rotates."""
    assert settling_calls_without_a_verifier(ROOT / "src") == []
    (tmp_path / "planted.py").write_text(
        "dispatch_owned(db, ticket, connector, clock)\n", encoding="utf-8"
    )
    assert settling_calls_without_a_verifier(tmp_path) == ["planted.py:1"]


def test_the_old_mock_app_path_still_starts():
    """`docs/INSTALL.md` tells an operator to keep the `compose.yaml` their `init` wrote,
    and an install made before the connectors moved into their own package names
    `execbound.provider.mock_app:create_mock_app`. That string, as uvicorn resolves it, is
    the factory the connectors package defines."""
    from execbound_connectors.mock_app import create_mock_app
    from uvicorn.importer import import_from_string

    assert import_from_string("execbound.provider.mock_app:create_mock_app") is create_mock_app
    assert import_from_string("execbound_connectors.mock_app:create_mock_app") is create_mock_app


def test_the_server_names_the_connectors():
    """The mock connector, the Graph connector and client, the sample accounts, the mock
    stores and servers are the connectors package's; each old path names the same object."""
    from execbound_connectors import (
        accounts,
        graph,
        graph_connector,
        identity_store,
        mock,
        mock_store,
        samples,
    )

    import execbound.monitoring.graph
    import execbound.provider.connector
    import execbound.provider.graph
    import execbound.provider.graph_connector
    import execbound.provider.identity_store
    import execbound.provider.mock_store
    import execbound.provider.models
    import execbound.provider.sample_accounts

    shared = [
        (execbound.provider.connector.ConnectionConfig, mock.ConnectionConfig),
        (execbound.provider.connector.MockConnector, mock.MockConnector),
        (execbound.provider.models.ProviderAccount, accounts.ProviderAccount),
        (execbound.provider.models.sign_record, accounts.sign_record),
        (execbound.provider.graph.GraphUserWriter, graph.GraphUserWriter),
        (execbound.provider.graph_connector.GraphConnector, graph_connector.GraphConnector),
        (execbound.provider.sample_accounts.sample_connection, samples.sample_connection),
        (execbound.provider.mock_store.MockStore, mock_store.MockStore),
        (execbound.provider.identity_store.IdentityStore, identity_store.IdentityStore),
    ]
    assert all(server is connectors for server, connectors in shared)
    # The pinned Graph origins have one definition, and the monitoring collector names it.
    assert execbound.monitoring.graph.GRAPH_ORIGIN is graph.GRAPH_ORIGIN
    assert execbound.monitoring.graph.LOGIN_ORIGIN is graph.LOGIN_ORIGIN


def test_the_signal_envelope_is_the_protocols():
    """The SecuritySignal envelope moved into the protocol unchanged, as its own docstring
    said it would; the intake, its HTTP surface and the producers name the same objects."""
    from execbound_protocol import signals

    import execbound.signals.envelope

    assert execbound.signals.envelope.__all__
    assert all(
        getattr(execbound.signals.envelope, name) is getattr(signals, name)
        for name in execbound.signals.envelope.__all__
    )
