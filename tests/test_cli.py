# SPDX-License-Identifier: AGPL-3.0-only
import json
import os

import pytest

from execbound.cli import seed_demo
from execbound.db import Database
from execbound.identity import authenticate


def test_demo_creates_two_isolated_expiring_identities(admin_engine, seeded, tmp_path):
    output = tmp_path / "demo.json"
    seed_demo(os.environ["TEST_MIGRATION_DATABASE_URL"], output)
    demo = json.loads(output.read_text())
    db = Database(os.environ["TEST_DATABASE_URL"])
    try:
        identities = [authenticate(db, item["agent_token"]) for item in demo["tenants"]]
        assert len(identities) == 2
        assert identities[0].tenant_id != identities[1].tenant_id
        assert all(identity.kind == "AGENT" for identity in identities)
    finally:
        db.close()


def test_demo_refuses_destination_override_before_connection(tmp_path, monkeypatch):
    def unexpected_connection(*args, **kwargs):
        raise AssertionError("Unsafe URL reached engine construction")

    monkeypatch.setattr("execbound.cli.create_engine", unexpected_connection)
    output = tmp_path / "demo.json"
    with pytest.raises(ValueError):
        seed_demo(
            "postgresql+psycopg://execbound_owner:secret@127.0.0.1/execbound"
            "?host=remote.example&dbname=production",
            output,
        )
    assert not output.exists()
