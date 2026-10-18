# SPDX-License-Identifier: AGPL-3.0-only
"""Settings pages (#253): own sessions and credential; the tenant's mode, deadline and stop."""

import json
import os
from types import SimpleNamespace
from uuid import uuid4

import pytest
from alembic import command
from alembic.config import Config
from fastapi.testclient import TestClient
from sqlalchemy import text
from test_execution import registry as registry
from test_execution import world as world
from test_human_surface import credential, form_values
from test_human_surface import human_app as human_app
from test_human_surface import human_client as human_client
from test_human_surface import human_config as human_config
from test_protected_path import connector as connector
from test_protected_path import live_provider as live_provider
from test_runtime import runtime as runtime

from execbound.app import create_app
from execbound.db import UPDATE_COLUMNS, check_runtime
from execbound.notifications import Destination
from execbound.replay.verify import reject_secrets
from execbound.surfaces.sessions import (
    LABELS,
    device_label,
    issue_session,
    load_session,
)
from execbound.surfaces.settings_pages import tenant_overview

ORIGIN = {"Origin": "http://127.0.0.1"}

AGENTS = [
    (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/128.0.0.0 Safari/537.36",
        "Chrome on Windows",
    ),
    (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/128.0.0.0 Safari/537.36 Edg/128.0.0.0",
        "Edge on Windows",
    ),
    (
        "Mozilla/5.0 (iPhone; CPU iPhone OS 17_5 like Mac OS X) AppleWebKit/605.1.15 "
        "(KHTML, like Gecko) Version/17.5 Mobile/15E148 Safari/604.1",
        "Safari on iPhone",
    ),
    (
        "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/128.0.0.0 Mobile Safari/537.36",
        "Chrome on Android",
    ),
    ("Mozilla/5.0 (X11; Linux x86_64; rv:129.0) Gecko/20100101 Firefox/129.0", "Firefox on Linux"),
    (
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_5) AppleWebKit/605.1.15 (KHTML, like Gecko) "
        "Version/17.5 Safari/605.1.15",
        "Safari on Mac",
    ),
    ("testclient", "Other"),
    ("curl/8.9.1", "Other"),
    ("<script>alert(1)</script> Chrome/1 Windows", "Chrome on Windows"),
    ("x" * 2000, "Other"),
    (None, "Other"),
]


@pytest.fixture
def admin_client(db, runtime, human_config, world, admin_engine):
    # A second application instance: one instance's MCP session manager starts only once.
    app = create_app(db, runtime=runtime, human=human_config)
    with TestClient(app, base_url="http://127.0.0.1", follow_redirects=False) as client:
        _, values = form_values(client.get("/login").text, "/session")
        values["credential"] = credential(admin_engine, world["admin"])
        assert client.post("/session", data=values, headers=ORIGIN).status_code == 303
        yield client


@pytest.mark.parametrize("agent,label", AGENTS)
def test_device_labels_are_fixed_strings_and_never_the_header(agent, label):
    result = device_label(agent)
    assert result == label
    assert result in LABELS
    assert agent is None or result != agent


def test_the_tenant_overview_names_destinations_without_addresses_or_secrets(runtime, world):
    tenant = world["identity"].tenant_id
    grant = issue_session(runtime.db, world["admin"], clock=runtime.clock)
    session = load_session(runtime.db, grant.token, clock=runtime.clock)
    secret = "s3cr3t-" + "x" * 40
    destination = Destination(
        destination_id="soc",
        tenant_id=tenant,
        url="https://alerts.example.net/execbound/hook",
        secret=secret,
    )
    foreign = Destination(
        destination_id="elsewhere",
        tenant_id=uuid4(),
        url="https://alerts.example.org/other",
        secret=secret,
    )
    fake = SimpleNamespace(
        db=runtime.db,
        clock=runtime.clock,
        catalog=runtime.catalog,
        notifications=(destination, foreign),
    )
    data = tenant_overview(fake, session)
    assert data["destinations"] == [
        {
            "destination_id": "soc",
            "kind": "webhook",
            "host": "alerts.example.net",
            "approvers": None,
            "messages": ["pending"],
            "classes": ["approvals"],
        }
    ]
    reject_secrets(data["destinations"])
    dumped = json.dumps(data, default=str)
    assert secret not in dumped and "/execbound/hook" not in dumped


def test_the_label_migration_round_trips_and_the_runtime_catalog_is_unchanged(
    db, runtime, world, admin_engine
):
    tenant = world["identity"].tenant_id
    assert UPDATE_COLUMNS["human_sessions"] == {"revoked_at"}
    with db.transaction(tenant) as conn:
        check_runtime(conn)
    grant = issue_session(runtime.db, world["human"], clock=runtime.clock, label="Safari on iPad")
    with admin_engine.begin() as conn:
        conn.execute(
            text("SELECT set_config('execbound.tenant_id', :t, false)"), {"t": str(tenant)}
        )
        stored = conn.execute(
            text("SELECT label FROM execbound.human_sessions WHERE session_id=:s"),
            {"s": grant.session_id},
        ).scalar_one()
    assert stored == "Safari on iPad"
    config = Config("alembic.ini")
    config.attributes["database_url"] = os.environ["TEST_MIGRATION_DATABASE_URL"]
    command.downgrade(config, "0034_agent_owner_org")
    command.upgrade(config, "head")
    with db.transaction(tenant) as conn:
        check_runtime(conn)
