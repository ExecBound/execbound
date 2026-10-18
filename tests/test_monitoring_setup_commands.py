# SPDX-License-Identifier: AGPL-3.0-only
"""Guided setup command arguments reach the existing collector registration function."""

from types import SimpleNamespace
from uuid import uuid4

import pytest

from execbound.monitoring import commands


@pytest.mark.parametrize("provider", ["tines", "entra_agent_id"])
def test_connection_command_forwards_the_space_and_only_a_provider_fingerprint(
    tmp_path, monkeypatch, capsys, provider
):
    credential = tmp_path / "admin.txt"
    credential.write_text("fixture-admin", encoding="utf-8")
    key = tmp_path / "provider.env"
    key.write_text(
        "TINES_BASE_URL=https://fixture.tines.com\nTINES_API_KEY=fixture-read-secret\n"
        f"ENTRA_DIRECTORY_ID={uuid4()}\nENTRA_CLIENT_ID={uuid4()}\n"
        "ENTRA_CLIENT_SECRET=fixture-read-secret\n",
        encoding="utf-8",
    )
    space = uuid4()
    connection = uuid4()
    calls = []
    monkeypatch.setenv("DATABASE_URL", "unused")
    monkeypatch.setattr(commands, "load_dotenv", lambda: None)
    monkeypatch.setattr(commands, "Database", lambda url: SimpleNamespace(close=lambda: None))
    monkeypatch.setattr(commands, "authenticate", lambda *args: object())

    def create(*args, **kwargs):
        calls.append(kwargs)
        return connection

    monkeypatch.setattr(commands, "create_connection", create)
    monkeypatch.setattr(
        "sys.argv",
        [
            "monitor",
            "create-connection",
            "--credential-file",
            str(credential),
            "--key-file",
            str(key),
            "--kind",
            provider,
            "--label",
            "Guided setup",
            "--space",
            str(space),
        ],
    )
    commands.main()
    assert len(calls) == 1 and calls[0]["space"] == space
    assert "fixture-read-secret" not in str(calls)
    output = capsys.readouterr().out
    assert str(connection) in output and "secret" not in output
