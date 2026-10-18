# SPDX-License-Identifier: AGPL-3.0-only
"""Bounded request limits refuse floods before admission and never consume authority."""

import secrets
from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import text
from test_human_surface import credential, form_values
from test_human_surface import human_config as human_config
from test_runtime import connector as connector
from test_runtime import live_provider as live_provider
from test_runtime import registry as registry
from test_runtime import request
from test_runtime import world as world
from test_structured_logging import captured as captured
from test_structured_logging import records

from execbound import logging_schema
from execbound.app import create_app
from execbound.runtime import Runtime
from execbound.surfaces.limits import RequestLimiter, RequestLimits, credential_selector
from execbound.surfaces.tokens import TokenKeys

MCP_HEADERS = {
    "Accept": "application/json, text/event-stream",
    "MCP-Protocol-Version": "2026-07-28",
}
ORIGIN = {"Origin": "http://127.0.0.1"}


class Clock:
    def __init__(self, now):
        self.value = now

    def now(self):
        return self.value


def bearer(seeded, index):
    return {"Authorization": "Bearer " + seeded["tokens"][index]}


def missing_execution():
    return "/v1/executions/" + str(uuid4())


# Limiter unit behavior (no database)


def test_limiter_allows_exactly_the_configured_count_per_window():
    clock = Clock(datetime(2026, 9, 15, tzinfo=UTC))
    limiter = RequestLimiter(RequestLimits(agent_requests=3, agent_window_seconds=60), clock)
    assert [limiter.check("agent", "k") for _ in range(3)] == [None, None, None]
    assert limiter.check("agent", "k") == 60
    clock.value += timedelta(seconds=59)
    assert limiter.check("agent", "k") == 1
    clock.value += timedelta(seconds=1)
    assert limiter.check("agent", "k") is None


def test_limiter_keys_and_namespaces_are_independent():
    limiter = RequestLimiter(RequestLimits(agent_requests=1, login_attempts=1))
    assert limiter.check("agent", "a") is None
    assert limiter.check("agent", "a") is not None
    assert limiter.check("agent", "b") is None
    assert limiter.check("login", "a") is None
    assert limiter.check("client", "a") is None


def test_limiter_memory_stays_bounded_under_distinct_keys():
    limiter = RequestLimiter(RequestLimits(agent_requests=1, max_tracked_keys=32))
    for index in range(500):
        limiter.check("agent", f"key-{index}")
    assert len(limiter) <= 32


@pytest.mark.parametrize(
    "changes",
    [
        {"agent_requests": 0},
        {"agent_window_seconds": 0},
        {"login_window_seconds": 3601},
        {"client_requests": 1_000_001},
        {"max_tracked_keys": 0},
        {"agent_requests": True},
        {"token_requests": 0},
        {"token_window_seconds": 3601},
    ],
)
def test_invalid_limits_are_rejected(changes):
    with pytest.raises(ValueError):
        RequestLimits(**changes)


@pytest.mark.parametrize(
    "token",
    ["", "hs1.x.y.z", "eb1.not-a-uuid.also-not.secret", "eb1." + "a" * 200, 5, None],
)
def test_credential_selector_ignores_malformed_tokens(token):
    assert credential_selector(token) is None


def test_credential_selector_names_tenant_and_credential_without_the_secret():
    tenant, cred = uuid4(), uuid4()
    selector = credential_selector(f"eb1.{tenant}.{cred}.{secrets.token_urlsafe(32)}")
    assert selector == f"{tenant}:{cred}"
    assert credential_selector(f"eb1.{str(tenant).upper()}.{cred}.x") is None


# Surface behavior (real PostgreSQL through the test client)

AGENT_LIMITS = RequestLimits(agent_requests=3, agent_window_seconds=60, login_attempts=2)
CLIENT_LIMITS = RequestLimits(client_requests=2, client_window_seconds=60)


def limited_app(db, world, connector, human_config, limits):
    keys = TokenKeys("pending-v1", {"pending-v1": secrets.token_bytes(32)})
    runtime = Runtime(db, [connector], clock=world["clock"], keys=keys, limits=limits)
    return create_app(db, runtime=runtime, human=human_config)


@pytest.fixture
def client(db, world, connector, human_config, seeded):
    app = limited_app(db, world, connector, human_config, AGENT_LIMITS)
    with TestClient(app, base_url="http://127.0.0.1", follow_redirects=False) as client:
        yield client


@pytest.fixture
def client_limited(db, world, connector, human_config, seeded):
    app = limited_app(db, world, connector, human_config, CLIENT_LIMITS)
    with TestClient(app, base_url="http://127.0.0.1", follow_redirects=False) as client:
        yield client


def test_agent_requests_beyond_the_credential_limit_are_refused_then_reset(client, seeded, world):
    for _ in range(3):
        assert client.get(missing_execution(), headers=bearer(seeded, 0)).status_code == 404
    refused = client.get(missing_execution(), headers=bearer(seeded, 0))
    assert refused.status_code == 429
    assert refused.json() == {"detail": "Execution unavailable", "code": "RATE_LIMITED"}
    assert 1 <= int(refused.headers["Retry-After"]) <= 60
    # Another tenant's credential keeps its own budget.
    assert client.get(missing_execution(), headers=bearer(seeded, 1)).status_code == 404
    world["clock"].value += timedelta(seconds=60)
    assert client.get(missing_execution(), headers=bearer(seeded, 0)).status_code == 404


def test_refused_execute_requests_consume_nothing(client, seeded, world, db):
    tenant = world["identity"].tenant_id
    body = request(world).model_dump(mode="json")
    for _ in range(3):
        client.get(missing_execution(), headers=bearer(seeded, 0))
    refused = client.post("/v1/execute", json=body, headers=bearer(seeded, 0))
    assert refused.status_code == 429 and refused.json()["code"] == "RATE_LIMITED"
    with db.transaction(tenant) as conn:
        count = conn.execute(
            text("SELECT count(*) FROM execbound.executions WHERE tenant_id=:t"), {"t": tenant}
        ).scalar_one()
    assert count == 0
    world["clock"].value += timedelta(seconds=60)
    accepted = client.post("/v1/execute", json=body, headers=bearer(seeded, 0))
    assert accepted.status_code == 202 and accepted.json()["state"] == "PENDING_APPROVAL"


def test_mcp_shares_the_credential_budget_with_http(client, seeded):
    for _ in range(3):
        client.get(missing_execution(), headers=bearer(seeded, 0))
    envelope = {"jsonrpc": "2.0", "id": "probe", "method": "tools/list", "params": {}}
    refused = client.post("/mcp/", json=envelope, headers={**bearer(seeded, 0), **MCP_HEADERS})
    assert refused.status_code == 429
    assert refused.json() == {"detail": "Execution unavailable", "code": "RATE_LIMITED"}
    assert "Retry-After" in refused.headers


def test_login_attempts_beyond_the_limit_are_refused_even_with_the_right_secret(
    client, world, admin_engine
):
    token = credential(admin_engine, world["human"])
    human = world["human"]
    wrong = f"eb1.{human.tenant_id}.{human.credential_id}.{secrets.token_urlsafe(32)}"

    def attempt(value):
        _, values = form_values(client.get("/login").text, "/session")
        values["credential"] = value
        return client.post("/session", data=values, headers=ORIGIN)

    assert attempt(wrong).status_code == 401
    assert attempt(wrong).status_code == 401
    refused = attempt(token)
    assert refused.status_code == 429 and 1 <= int(refused.headers["Retry-After"]) <= 60
    world["clock"].value += timedelta(seconds=60)
    assert attempt(token).status_code == 303


def test_client_limit_applies_across_credentials_and_before_authentication(client_limited, seeded):
    assert client_limited.get(missing_execution(), headers=bearer(seeded, 0)).status_code == 404
    assert client_limited.get(missing_execution(), headers=bearer(seeded, 1)).status_code == 404
    refused = client_limited.get(
        missing_execution(), headers={"Authorization": "Bearer eb1.garbage"}
    )
    assert refused.status_code == 429 and refused.json()["code"] == "RATE_LIMITED"


def test_a_request_the_limit_refuses_is_logged_once_by_request_completed(client, seeded, captured):
    """There is no `request.refused` line: `request.completed` already carries every request's
    status and surface, the limit's 429 among them, so a flood of refused requests writes one
    line each rather than two. The line names no caller address and no credential."""
    for _ in range(3):
        client.get(missing_execution(), headers=bearer(seeded, 0))
    refused = client.get(missing_execution(), headers=bearer(seeded, 0))
    assert refused.status_code == 429
    [line] = [
        r for r in records(captured) if r.get("request_id") == refused.headers["X-Request-Id"]
    ]
    assert (line["event"], line["surface"], line["status"]) == ("request.completed", "http", 429)
    assert "request.refused" not in logging_schema.EVENTS
    assert seeded["tokens"][0] not in captured.getvalue()
    assert "testclient" not in captured.getvalue() and "127.0.0.1" not in captured.getvalue()
