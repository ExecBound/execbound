# SPDX-License-Identifier: AGPL-3.0-only
"""Real PostgreSQL intake and ADMIN surface boundary regressions."""

import secrets
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import text
from test_execution import provision_identity
from test_human_surface import credential, form_values
from test_monitoring_transport import valid_event

from execbound.app import create_app
from execbound.monitoring import store
from execbound.runtime import Runtime
from execbound.surfaces.human import HumanConfig
from execbound.surfaces.tokens import TokenKeys


@contextmanager
def signed_in(db, admin_engine, admin):
    """A console client signed in as one administrator, and its configuration."""
    config = HumanConfig(
        "http://127.0.0.1", TokenKeys("monitor", {"monitor": secrets.token_bytes(32)})
    )
    app = create_app(db, runtime=Runtime(db, []), human=config)
    with TestClient(app, base_url=config.origin, follow_redirects=False) as client:
        _, fields = form_values(client.get("/login").text, "/session")
        fields["credential"] = credential(admin_engine, admin)
        assert (
            client.post("/session", data=fields, headers={"Origin": config.origin}).status_code
            == 303
        )
        yield client, config


@pytest.fixture
def monitor_web(db, seeded, admin_engine):
    now = datetime.now(UTC)
    admin = provision_identity(admin_engine, db, seeded["tenants"][0], "ADMIN", now)
    source = store.create_source(
        db,
        admin,
        label="Tines <img src=x>",
        story_id="story-1",
        expires_at=now + timedelta(hours=1),
    )
    with signed_in(db, admin_engine, admin) as (client, config):
        yield client, admin, source, config


MONITOR = "/api/console/v1/monitor"


def token(client):
    """The session's own CSRF token, as the console reads it once and holds it."""
    answer = client.get("/api/console/v1/session")
    assert answer.status_code == 200, answer.text
    return answer.json()["csrf_token"]


def acknowledge(client, config, finding_id, **changes):
    """Acknowledge one finding the way the console does: JSON, the token, the exact origin."""
    headers = {
        "X-CSRF-Token": changes.pop("csrf", None) or token(client),
        **changes.pop("headers", {"Origin": config.origin}),
    }
    return client.post(
        f"{MONITOR}/findings/{finding_id}/acknowledge",
        json=changes.pop("body", {}),
        headers=headers,
    )


def post_event(client, source, **overrides):
    return client.post(
        "/v1/monitor/events",
        json=valid_event() | {"occurred_at": datetime.now(UTC).isoformat()} | overrides,
        headers={"Authorization": "Bearer " + source.token},
    )


def test_heartbeat_response_names_no_observation_and_retries_only_refresh(monitor_web, db):
    client, admin, source, _ = monitor_web
    body = {
        "version": 1,
        "event_id": "heartbeat-1",
        "story_id": "story-1",
        "kind": "heartbeat",
        "occurred_at": datetime.now(UTC).isoformat(),
    }
    for _ in range(2):
        response = client.post(
            "/v1/monitor/events", json=body, headers={"Authorization": "Bearer " + source.token}
        )
        assert response.status_code == 202
        assert response.json() == {"observation_id": None, "duplicate": False}
    assert store.evaluate_pending(db, admin) == 0
    snapshot = client.get(MONITOR).json()
    assert snapshot["observations"] == []
    assert snapshot["sources"][0]["accepted_count"] == 0
    assert snapshot["sources"][0]["last_heartbeat_at"] is not None


def test_a_source_keeps_ten_thousand_events_and_takes_heartbeats_after_them(
    monitor_web, admin_engine
):
    """The limit as the intake enforces it, with nothing patched: a source keeps 10,000 events
    over its life, the number the console's source card and the guides state, and is refused
    the next with `SOURCE_CAPACITY` while its heartbeats are still accepted."""
    client, admin, source, _ = monitor_web
    with admin_engine.begin() as conn:
        conn.execute(
            text(
                "UPDATE execbound.monitor_sources SET accepted_count = 9999 "
                "WHERE tenant_id = :t AND source_id = :s"
            ),
            {"t": admin.tenant_id, "s": source.source_id},
        )
    assert post_event(client, source, event_id="event-10000").status_code == 202
    refused = post_event(client, source, event_id="event-10001")
    assert (refused.status_code, refused.json()["code"]) == (429, "SOURCE_CAPACITY")
    beat = client.post(
        "/v1/monitor/events",
        json={
            "version": 1,
            "event_id": "beat",
            "story_id": "story-1",
            "kind": "heartbeat",
            "occurred_at": datetime.now(UTC).isoformat(),
        },
        headers={"Authorization": "Bearer " + source.token},
    )
    assert beat.status_code == 202, beat.text
    [row] = client.get(MONITOR).json()["sources"]
    assert row["accepted_count"] == 10_000
    assert row["last_heartbeat_at"] is not None


def test_event_to_finding_and_admin_ack_preserves_execution_state(monitor_web, db, admin_engine):
    client, admin, source, config = monitor_web
    before = {}
    with admin_engine.connect() as conn:
        for name in ("executions", "approvals", "execution_impact", "resource_claims"):
            before[name] = conn.execute(text(f"SELECT count(*) FROM execbound.{name}")).scalar_one()
    assert post_event(client, source).status_code == 202
    assert store.evaluate_pending(db, admin) == 1
    # One snapshot answers every view the console draws, under `no-store` and the console's
    # own policy, with every platform string travelling as data.
    page = client.get(MONITOR)
    assert page.status_code == 200
    assert page.headers["cache-control"] == "no-store"
    assert "Content-Security-Policy" in page.headers
    assert page.headers["content-type"].startswith("application/json")
    snapshot = page.json()
    assert {"connections", "sources", "observations", "findings"} <= set(snapshot)
    [finding] = snapshot["findings"]
    assert "identity.disable" in page.text
    assert finding["acknowledged_at"] is None
    answered = acknowledge(client, config, finding["finding_id"])
    assert answered.status_code == 200, answered.text
    [after] = answered.json()["findings"]
    assert after["acknowledged_at"] is not None
    with admin_engine.connect() as conn:
        for name, count in before.items():
            assert (
                conn.execute(text(f"SELECT count(*) FROM execbound.{name}")).scalar_one() == count
            )


@pytest.mark.parametrize("path", ["", "/agents"])
def test_monitor_pages_require_current_admin(monitor_web, admin_engine, path):
    client, admin, _, _ = monitor_web
    with admin_engine.begin() as conn:
        conn.execute(
            text(
                "UPDATE execbound.principals SET kind='HUMAN_APPROVER', space_id = NULL "
                "WHERE principal_id=:p"
            ),
            {"p": admin.principal_id},
        )
    assert client.get(MONITOR + path).status_code in {401, 403}


@pytest.mark.parametrize("case", ["origin", "csrf", "extra", "foreign"])
def test_acknowledgement_rejects_forgery(monitor_web, db, case):
    client, admin, source, config = monitor_web
    post_event(client, source)
    store.evaluate_pending(db, admin)
    [finding] = client.get(MONITOR).json()["findings"]
    changes: dict = {}
    finding_id = finding["finding_id"]
    if case == "origin":
        changes["headers"] = {"Origin": "https://evil.invalid"}
    elif case == "csrf":
        changes["csrf"] = "wrong"
    elif case == "extra":
        changes["body"] = {"tenant_id": "foreign"}
    else:
        finding_id = "00000000-0000-0000-0000-000000000000"
    refused = acknowledge(client, config, finding_id, **changes)
    assert refused.status_code in {400, 403, 404}, refused.status_code
    [after] = client.get(MONITOR).json()["findings"]
    assert after["acknowledged_at"] is None


@pytest.mark.parametrize("case", ["query", "authority", "compression", "content_type", "oversize"])
def test_monitor_http_rejects_unsafe_wire_before_storage(monitor_web, admin_engine, case):
    client, _, source, _ = monitor_web
    url = "/v1/monitor/events"
    headers = {"Authorization": "Bearer " + source.token, "Content-Type": "application/json"}
    body = "{}"
    if case == "query":
        url += "?tenant_id=other"
    elif case == "authority":
        headers["X-Tenant-Id"] = "other"
    elif case == "compression":
        headers["Content-Encoding"] = "gzip"
    elif case == "content_type":
        headers["Content-Type"] = "text/plain"
    else:
        body = " " * 17000
    assert client.post(url, content=body, headers=headers).status_code == 400
    with admin_engine.connect() as conn:
        assert (
            conn.execute(text("SELECT count(*) FROM execbound.monitor_observations")).scalar_one()
            == 0
        )


def test_source_token_cannot_execute_or_read_and_agent_cannot_ingest(monitor_web, seeded):
    client, _, source, _ = monitor_web
    headers = {"Authorization": "Bearer " + source.token}
    assert client.post("/v1/execute", json={}, headers=headers).status_code == 401
    assert client.get(MONITOR, headers=headers).status_code in {401, 403}
    response = client.post(
        "/v1/monitor/events",
        json=valid_event(),
        headers={"Authorization": "Bearer " + seeded["tokens"][0]},
    )
    assert response.status_code in {401, 403}
