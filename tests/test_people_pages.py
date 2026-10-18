# SPDX-License-Identifier: AGPL-3.0-only
"""People page (PP1 to PP9): the list, the person, labels, credentials, sessions, deactivation."""

import os
import re

import pytest
from alembic import command
from alembic.config import Config
from fastapi.testclient import TestClient
from sqlalchemy import text
from sqlalchemy.exc import DBAPIError
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
from execbound.db import FUNCTIONS, check_runtime

ORIGIN = {"Origin": "http://127.0.0.1"}
TOKEN = re.compile(r'id="token"[^>]*value="([^"]+)"')


@pytest.fixture
def admin_client(db, runtime, human_config, world, admin_engine):
    # A second application instance: one instance's MCP session manager starts only once.
    app = create_app(db, runtime=runtime, human=human_config)
    with TestClient(app, base_url="http://127.0.0.1", follow_redirects=False) as client:
        _, values = form_values(client.get("/login").text, "/session")
        values["credential"] = credential(admin_engine, world["admin"])
        assert client.post("/session", data=values, headers=ORIGIN).status_code == 303
        yield client


def call(engine, tenant, statement, params):
    """One definer function under the tenant fence, the way the pages call it."""
    with engine.begin() as conn:
        conn.execute(text("SELECT set_config('execbound.tenant_id', :t, true)"), {"t": str(tenant)})
        return conn.execute(text(statement), params).scalar_one()


def refused(engine, tenant, statement, params):
    with pytest.raises(DBAPIError) as failure:
        call(engine, tenant, statement, params)
    return failure.value.orig.diag.message_primary


def post_form(html, action):
    """The csrf and hidden fields of the POST form with exactly this action."""
    for attrs, body in re.findall(r"<form([^>]*)>(.*?)</form>", html, re.S):
        if f'action="{action}"' in attrs and 'method="post"' in attrs:
            return dict(re.findall(r'<input[^>]*name="([^"]+)"[^>]*value="([^"]*)"', body))
    raise AssertionError(f"no POST form for {action}")


def person_path(world):
    return f"/admin/people/{world['human'].principal_id}"


def test_pp9_the_migration_round_trips_and_the_catalog_names_the_functions(db, world):
    tenant = world["identity"].tenant_id
    names = {name for name, _ in FUNCTIONS}
    assert {
        "admin_label_principal",
        "admin_deactivate_principal",
        "admin_reactivate_principal",
    } <= (names)
    with db.transaction(tenant) as conn:
        check_runtime(conn)
    config = Config("alembic.ini")
    config.attributes["database_url"] = os.environ["TEST_MIGRATION_DATABASE_URL"]
    command.downgrade(config, "0035_session_label")
    command.upgrade(config, "head")
    with db.transaction(tenant) as conn:
        check_runtime(conn)
