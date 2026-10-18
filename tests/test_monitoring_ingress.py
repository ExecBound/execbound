# SPDX-License-Identifier: AGPL-3.0-only
"""A trial tunnel cannot expose the administrator, execution or discovery surfaces."""

import pytest
from fastapi.testclient import TestClient
from test_monitoring_transport import valid_event

from execbound.monitoring import store


@pytest.mark.parametrize(
    "method,path",
    [
        ("GET", "/login"),
        ("POST", "/session"),
        ("GET", "/monitor/activity"),
        ("POST", "/v1/execute"),
        ("POST", "/mcp"),
        ("GET", "/v1/me"),
        ("GET", "/health/ready"),
        ("GET", "/v1/monitor/events"),
        ("POST", "/v1/monitor/events/"),
        ("POST", "/v1/monitor/%65vents"),
    ],
)
def test_tunnel_has_only_the_exact_post_intake_route(monkeypatch, method, path):
    from execbound.monitoring.ingress import create_ingress

    monkeypatch.setattr(store, "ingest", lambda *a, **k: pytest.fail("Unexpected intake"))
    with TestClient(create_ingress(object())) as client:
        response = client.request(method, path, follow_redirects=False)
    assert response.status_code == 404
    assert "location" not in response.headers
    assert response.headers["cache-control"] == "no-store"


def test_intake_keeps_source_authentication_and_duplicate_semantics(monkeypatch):
    from execbound.monitoring.ingress import create_ingress
    from execbound.monitoring.models import MonitorError

    calls = []

    def ingest(db, token, event):
        calls.append(token)
        if token != "selected-source":
            raise MonitorError("INVALID_SOURCE")
        return {"observation_id": "test-observation", "duplicate": len(calls) > 2}

    monkeypatch.setattr(store, "ingest", ingest)
    with TestClient(create_ingress(object())) as client:
        for token, expected in (("wrong", 401), ("selected-source", 202), ("selected-source", 200)):
            response = client.post(
                "/v1/monitor/events",
                json=valid_event(),
                headers={"Authorization": "Bearer " + token},
            )
            assert response.status_code == expected
        assert client.post("/v1/monitor/events", json=valid_event()).status_code == 401
    assert len(calls) == 3
