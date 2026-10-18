# SPDX-License-Identifier: AGPL-3.0-only
"""Replay's process boundary denies live capabilities and unrelated private files."""

import os
import subprocess
import sys
from pathlib import Path

import pytest
from test_replay_cli import inputs as inputs

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = r"""
import os,sys
from pathlib import Path
from unittest.mock import patch

def forbidden(*args, **kwargs):
    raise AssertionError("Live capability reached by replay")

def audit(event, args):
    # Import-time platform detection reads the local hostname on Windows.
    # Every actual socket creation, connection and DNS lookup remains denied.
    if event.startswith("socket.") and event != "socket.gethostname":
        forbidden()
    if event == "open" and isinstance(args[0], (str, bytes, os.PathLike)):
        path = Path(os.fsdecode(args[0]))
        if path.name in {".env", "private-canary.json", "provider-accounts.json"}:
            forbidden()
sys.addaudithook(audit)
from execbound import cli
from execbound.db import Database
from execbound.provider.connector import MockConnector
from execbound.provider.mock_store import MockStore
from execbound.provider.identity_store import IdentityStore
from execbound.execution import admit, decide_approval
from execbound.policy import store
from contextlib import ExitStack
with ExitStack() as stack:
    for target in ("dotenv.load_dotenv", "execbound.cli.load_dotenv",
                   "sqlalchemy.create_engine", "execbound.cli.create_engine",
                   "execbound.db.create_engine", "execbound.execution.admit",
                   "execbound.execution.decide_approval", "execbound.execution.take_dispatch",
                   "execbound.execution.record_outcome", "execbound.execution.reconcile",
                   "execbound.policy.store.activate_bundle", "execbound.policy.store.create_bundle",
                   "execbound.policy.store.validate_bundle"):
        stack.enter_context(patch(target, forbidden))
    for cls, names in ((Database,("__init__","transaction")),
                       (MockConnector,("__init__","dispatch","lookup","cancel")),
                       (MockStore,("__init__","dispatch","lookup","cancel")),
                       (IdentityStore,("__init__","dispatch","lookup","cancel"))):
        for name in names:
            stack.enter_context(patch.object(cls,name,forbidden))
    sys.argv = ["execbound", *sys.argv[1:]]
    cli.main()
"""


def isolated_replay(source, checkpoint, output, candidate=None):
    arguments = [
        "replay",
        "--input",
        str(source),
        "--trusted-head",
        str(checkpoint),
        "--output",
        str(output),
    ]
    if candidate is not None:
        arguments += ["--candidate", str(candidate)]
    return subprocess.run(
        [sys.executable, "-I", "-c", SCRIPT, *arguments],
        cwd=output.parent,
        env={
            **os.environ,
            "DATABASE_URL": "postgresql://private-canary@127.0.0.1:1/no",
            "MIGRATION_DATABASE_URL": "private-canary",
            "EXECBOUND_RUNTIME_CONFIG": str(output.parent / "private-canary.json"),
            "HTTP_PROXY": "http://127.0.0.1:1",
            "HTTPS_PROXY": "http://127.0.0.1:1",
        },
        capture_output=True,
        text=True,
        timeout=30,
        creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0,
    )


@pytest.mark.parametrize("mode", ["baseline", "candidate", "malformed"])
def test_subprocess_never_reads_secrets_connects_or_mutates(inputs, tmp_path, mode):
    from replay_fixtures import chain_export, replay_case

    source, checkpoint = inputs
    canaries = [
        tmp_path / name for name in (".env", "private-canary.json", "provider-accounts.json")
    ]
    for path in canaries:
        path.write_text("private-canary")
    candidate = None
    if mode == "candidate":
        case = replay_case()
        history = chain_export([], tenant_id=case["identity"].tenant_id)
        source.write_text(history.model_dump_json())
        checkpoint.write_text(history.head.model_dump_json())
        candidate = tmp_path / "candidate.json"
        candidate.write_text(case["bundle"].model_dump_json())
    if mode == "malformed":
        source.write_text('{"token":"private-canary"}')
    result = isolated_replay(source, checkpoint, tmp_path / "output", candidate)
    assert result.returncode == (2 if mode == "malformed" else 0), result.stderr
    assert "private-canary" not in result.stdout + result.stderr
    assert all(path.read_text() == "private-canary" for path in canaries)
    assert (tmp_path / "output").exists() == (mode != "malformed")
