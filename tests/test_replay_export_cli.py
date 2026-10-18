# SPDX-License-Identifier: AGPL-3.0-only
"""Current ADMIN credentials alone may create a scoped offline export."""

import os
import sys
from uuid import uuid4

import pytest
from conftest import current_test_database
from test_execution import registry as registry
from test_execution import world as world
from test_human_surface import credential
from test_replay_export import fingerprint

from execbound.cli import audit_export, main
from execbound.db import UnsafeDatabaseRole
from execbound.plugins import RUNTIME_CHECK_REFUSAL
from execbound.replay.export import ExportError
from execbound.replay.verify import parse_export


@pytest.mark.parametrize("scope", ["admin", "agent", "human", "foreign", "invalid"])
def test_export_cli_authenticates_and_preserves_live_state(
    scope, world, admin_engine, tmp_path, monkeypatch
):
    monkeypatch.setenv("DATABASE_URL", os.environ["TEST_DATABASE_URL"])
    identity = world[{"agent": "identity", "human": "human"}.get(scope, "admin")]
    private_file = tmp_path / "credential.txt"
    private_file.write_text(
        "private-canary" if scope == "invalid" else credential(admin_engine, identity)
    )
    output, checkpoint = tmp_path / "history.json", tmp_path / "head.json"
    tenant = uuid4() if scope == "foreign" else identity.tenant_id
    before = fingerprint(admin_engine)
    if scope == "admin":
        audit_export(tenant, private_file, output, checkpoint)
        assert parse_export(output.read_bytes()).tenant_id == tenant
    else:
        with pytest.raises(ExportError) as failure:
            audit_export(tenant, private_file, output, checkpoint)
        assert failure.value.__context__ is None
        assert not output.exists() and not checkpoint.exists()
    assert fingerprint(admin_engine) == before


def test_export_reads_a_restored_copy_by_name_without_a_rendered_url(
    world, admin_engine, tmp_path, monkeypatch
):
    """`--database` names a restored copy on the same server (#262).

    The point of the flag is that nobody has to build a second connection string with its
    password to read a restored copy, so the two routes must agree exactly.
    """
    monkeypatch.setenv("DATABASE_URL", os.environ["TEST_DATABASE_URL"])
    identity = world["admin"]
    private_file = tmp_path / "credential.txt"
    private_file.write_text(credential(admin_engine, identity))
    from_environment = tmp_path / "environment.json"
    from_flag = tmp_path / "flag.json"
    audit_export(identity.tenant_id, private_file, from_environment, tmp_path / "e.head.json")
    audit_export(
        identity.tenant_id,
        private_file,
        from_flag,
        tmp_path / "f.head.json",
        database=current_test_database(),
    )
    assert from_flag.read_bytes() == from_environment.read_bytes()


@pytest.mark.parametrize("name", ["execbound_absent", "Invalid/Name", ""])
def test_a_database_that_is_absent_or_misnamed_ends_in_the_generic_error(
    name, world, admin_engine, tmp_path, monkeypatch
):
    monkeypatch.setenv("DATABASE_URL", os.environ["TEST_DATABASE_URL"])
    identity = world["admin"]
    private_file = tmp_path / "credential.txt"
    private_file.write_text(credential(admin_engine, identity))
    output, checkpoint = tmp_path / "history.json", tmp_path / "head.json"
    with pytest.raises(ExportError) as failure:
        audit_export(identity.tenant_id, private_file, output, checkpoint, database=name)
    # No nested cause and no echo of the name: a refusal says nothing about the server.
    assert failure.value.__context__ is None
    assert name not in str(failure.value) if name else True
    assert not output.exists() and not checkpoint.exists()


def test_a_runtime_check_refusal_reads_as_the_emergency_stops_does(
    world, admin_engine, tmp_path, monkeypatch, capsys
):
    """A database the runtime check refuses, here one at another schema revision, reaches the
    command as that refusal rather than the generic export error, so `audit-export` says what
    the emergency stop's commands say (#496). Its messages are fixed strings, and
    nothing is written."""
    monkeypatch.setenv("DATABASE_URL", os.environ["TEST_DATABASE_URL"])
    monkeypatch.setattr("execbound.db.SCHEMA_REVISION", "0000_another_revision")
    identity = world["admin"]
    private_file = tmp_path / "credential.txt"
    private_file.write_text(credential(admin_engine, identity))
    output, checkpoint = tmp_path / "history.json", tmp_path / "head.json"
    with pytest.raises(UnsafeDatabaseRole, match="Database revision mismatch") as refused:
        audit_export(identity.tenant_id, private_file, output, checkpoint)
    assert refused.value.__context__ is None
    argv = ["execbound", "audit-export", "--tenant", str(identity.tenant_id)]
    argv += ["--credential-file", str(private_file), "--output", str(output)]
    monkeypatch.setattr(sys, "argv", argv)
    with pytest.raises(SystemExit) as caught:
        main()
    assert caught.value.code == 2
    printed = capsys.readouterr()
    assert printed.out == "" and RUNTIME_CHECK_REFUSAL.rstrip() in printed.err.splitlines()
    assert not output.exists() and not checkpoint.exists()
    assert not output.with_suffix(".head.json").exists()
