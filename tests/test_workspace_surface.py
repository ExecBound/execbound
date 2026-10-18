# SPDX-License-Identifier: AGPL-3.0-only
"""Browser workspace selection requires both CSRF and the displayed session generation.

Switching between an account's workspaces is part of the core server, so these run with no
plugin loaded. The workspace-scoped approval address a plugin's notification links to belongs
to that plugin, and is tested with it.
"""

import pytest
from console_api_fixtures import API, ORIGIN, console_config
from fastapi.testclient import TestClient
from test_runtime import connector as connector
from test_runtime import live_provider as live_provider
from test_runtime import registry as registry
from test_runtime import runtime as runtime
from test_runtime import world as world
from test_workspace_switching import member_pair

from execbound.app import create_app
from execbound.resolution.models import SystemClock

pytestmark = pytest.mark.integration


@pytest.mark.parametrize("path", [API + "/session", "/activity"])
def test_account_activity_renews_server_idle_timeout_without_reissuing_workspace_cookies(
    db, runtime, admin_engine, seeded, path
):
    from datetime import timedelta

    from starlette.responses import Response
    from test_human_sessions import FixedClock

    from execbound.surfaces.human import _session_cookies

    runtime.clock = FixedClock(SystemClock().now())
    grant, _, _, _ = member_pair(db, admin_engine, seeded)
    config = console_config()
    initial = _session_cookies(Response(), config, runtime, grant)
    session_cookie = next(
        value for value in initial.headers.getlist("set-cookie") if value.startswith("eb_session=")
    )
    # The browser retains the opaque cookie; the server still enforces fifteen minutes idle.
    with TestClient(create_app(db, runtime=runtime, human=config), base_url=ORIGIN) as client:
        client.cookies.set("eb_session", grant.token)
        client.cookies.set("eb_csrf", grant.csrf_token)
        client.cookies.set("eb_account", grant.account_token)
        runtime.clock.value += timedelta(minutes=9)
        response = client.get(path)
        assert response.status_code == 200
        # A delayed response from A must never overwrite cookies issued by a switch to B.
        assert not response.headers.get_list("set-cookie")
        assert int(session_cookie.split("Max-Age=")[1].split(";")[0]) > 15 * 60
        runtime.clock.value += timedelta(minutes=16)
        assert client.get(API + "/session").status_code == 401


def test_workspace_api_rotates_cookies_and_refuses_stale_generation(
    db, runtime, admin_engine, seeded
):
    runtime.clock = SystemClock()
    grant, _, _, _ = member_pair(db, admin_engine, seeded)
    with TestClient(
        create_app(db, runtime=runtime, human=console_config()), base_url=ORIGIN
    ) as client:
        client.cookies.set("eb_session", grant.token, domain="127.0.0.1")
        client.cookies.set("eb_csrf", grant.csrf_token, domain="127.0.0.1")
        client.cookies.set("eb_account", grant.account_token, domain="127.0.0.1")
        first = client.get(API + "/session").json()
        assert first["generation"] == str(grant.session_id)
        assert len(client.get(API + "/session/workspaces").json()["workspaces"]) == 2
        headers = {
            "Origin": ORIGIN,
            "X-CSRF-Token": first["csrf_token"],
            "X-ExecBound-Workspace": first["generation"],
        }
        payload = {"tenant_id": str(seeded["tenants"][1])}
        assert (
            client.post(
                API + "/session/workspace",
                json=payload,
                headers={**headers, "X-CSRF-Token": "stale"},
            ).status_code
            == 403
        )
        response = client.post(API + "/session/workspace", json=payload, headers=headers)
        assert response.status_code == 200, response.text
        # A switch enters the other workspace at its Home, which every session can open.
        assert response.json()["location"] == "/"
        # Cookies now select B. An old tab must not use B's current CSRF with A's form.
        current = client.get(API + "/session").json()
        assert current["tenant"]["tenant_id"] == str(seeded["tenants"][1])
        stale = client.post(
            API + "/session/workspace",
            json=payload,
            headers={**headers, "X-CSRF-Token": current["csrf_token"]},
        )
        assert stale.status_code == 409
        assert stale.json()["code"] == "WORKSPACE_CHANGED"
        assert (
            client.get(
                API + "/session", headers={"X-ExecBound-Workspace": first["generation"]}
            ).status_code
            == 409
        )


def test_workspace_cookie_alone_cannot_list_memberships(db, runtime, admin_engine, seeded):
    runtime.clock = SystemClock()
    grant, _, _, _ = member_pair(db, admin_engine, seeded)
    with TestClient(
        create_app(db, runtime=runtime, human=console_config()), base_url=ORIGIN
    ) as client:
        client.cookies.set("eb_session", grant.token)
        client.cookies.set("eb_csrf", grant.csrf_token)
        assert client.get(API + "/session/workspaces").status_code == 401
