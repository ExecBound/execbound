# SPDX-License-Identifier: AGPL-3.0-only
"""No unexpected dependency diagnostic may pass through either MCP wire version."""

from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.exc import OperationalError

from execbound.app import create_app
from execbound.db import Database
from execbound.execution.models import ExecutionView
from execbound.identity import Identity
from execbound.runtime import Runtime


@pytest.mark.parametrize("version", ["2025-11-25", "2026-07-28", "http"])
@pytest.mark.parametrize("failure", ["execute", "present"])
def test_unexpected_errors_are_safe_at_adapter_boundary(monkeypatch, version, failure):
    db = Database("postgresql+psycopg://invalid:invalid@127.0.0.1:1/execbound")
    runtime = Runtime(db, [])
    identity = Identity(uuid4(), uuid4(), uuid4(), "AGENT", datetime.now(UTC) + timedelta(hours=1))
    monkeypatch.setattr("execbound.surfaces.http.authenticate", lambda *_: identity)
    monkeypatch.setattr(runtime, "reject", lambda *_: None)
    monkeypatch.setattr(
        runtime,
        "execute",
        lambda *_: ExecutionView(execution_id=uuid4(), state="EXECUTED", plan_hash="a" * 64),
    )

    def fail(*_):
        raise OperationalError(
            "SELECT private_column", {"secret": "PRIVATE_SENTINEL"}, Exception("PRIVATE_SENTINEL")
        )

    monkeypatch.setattr(runtime, failure, fail)
    try:
        with TestClient(
            create_app(db, runtime=runtime), base_url="http://127.0.0.1:8123"
        ) as client:
            headers = {
                "Authorization": "Bearer test",
                "Accept": "application/json, text/event-stream",
                "MCP-Protocol-Version": version,
                "MCP-Method": "tools/call",
                "MCP-Name": "execute",
            }
            if version == "http":
                response = client.post("/v1/execute", json={}, headers=headers)
                assert response.status_code == 503
            else:
                response = client.post(
                    "/mcp/",
                    json={
                        "jsonrpc": "2.0",
                        "id": "probe",
                        "method": "tools/call",
                        "params": {
                            "name": "execute",
                            "arguments": {"request": {}},
                            "_meta": {
                                "io.modelcontextprotocol/protocolVersion": version,
                                "io.modelcontextprotocol/clientCapabilities": {},
                            },
                        },
                    },
                    headers=headers,
                )
                assert response.status_code == 200, response.text
                assert response.json()["result"]["isError"] is True
            assert "PRIVATE_SENTINEL" not in response.text
            assert "private_column" not in response.text
    finally:
        db.close()
