# SPDX-License-Identifier: AGPL-3.0-only
"""Every console API route, walked from the route inventory (#333, CR1 and CR2).

Each route refuses an agent credential, audits it, and needs a session (CR1); every GET answers
without a secret, for an administrator and for an approver (CR2).

A test module that checks only its own routes leaves gaps, such as a refusal that is never shown to
reach the audit chain (CR1). This walks the route inventory instead, so every console API route,
including one added later, is held to the same three answers without anyone remembering to write
the lines: a bearer credential is refused and audited once as the agent it names, and a browser
with no session is told to sign in.

One application and one client serve the whole walk; building an application per route
costs about two seconds each and proves nothing more.
"""

import pytest
from console_api_fixtures import ORIGIN, console_client, console_config, rejections
from fastapi.testclient import TestClient
from test_human_surface import pending
from test_route_authority import AUTHORITY, CONSOLE, SAMPLE, SESSION
from test_runtime import connector as connector
from test_runtime import live_provider as live_provider
from test_runtime import registry as registry
from test_runtime import runtime as runtime
from test_runtime import world as world

from execbound.app import create_app
from execbound.replay.verify import reject_secrets

pytestmark = pytest.mark.integration

PREFIX = "/api/console/v1/"
# The assistant's routes exist only where a model is configured and are walked by its own
# tests; every other console API route is in the inventory, mostly in its console part.
ROUTES = sorted(
    (path, method)
    for (path, method), authority in {**AUTHORITY, **CONSOLE}.items()
    if path.startswith(PREFIX) and authority == SESSION
)


def test_the_inventory_has_console_api_routes_to_walk():
    # The account routes and the workspace session routes are core routes, so this walk
    # reaches them too.
    assert ("/api/console/v1/account", "GET") in ROUTES
    assert ("/api/console/v1/session/workspaces", "GET") in ROUTES
    assert ("/api/console/v1/account/profile", "POST") in ROUTES
    assert len(ROUTES) > 100


def test_every_console_api_route_refuses_and_audits_an_agent_credential(
    db, runtime, seeded, admin_engine, world
):
    app = create_app(db, runtime=runtime, human=console_config())
    bearer = {"Authorization": "Bearer " + seeded["tokens"][0], "Origin": ORIGIN}
    browser = {"Accept": "text/html", "Origin": ORIGIN, "Content-Type": "application/json"}
    wrong = []
    with TestClient(app, base_url=ORIGIN, follow_redirects=False) as client:
        for path, method in ROUTES:
            concrete = path.format(**SAMPLE)
            before = rejections(admin_engine, world["identity"])
            if method == "GET":
                refused = client.get(concrete, headers=bearer)
                anonymous = client.get(concrete, headers=browser)
            else:
                headers = {**bearer, "Content-Type": "application/json"}
                refused = client.post(concrete, content=b"{}", headers=headers)
                anonymous = client.post(concrete, content=b"{}", headers=browser)
            audited = rejections(admin_engine, world["identity"]) - before
            code = refused.json().get("code") if refused.status_code in {401, 403} else None
            if (
                refused.status_code not in {401, 403}
                or code not in {"FORBIDDEN", "SESSION_REQUIRED"}
                or audited != 1
                or anonymous.status_code != 401
            ):
                wrong.append(
                    (method, path, refused.status_code, code, audited, anonymous.status_code)
                )
    assert wrong == [], wrong


# The board's stream never ends by design, so a plain GET would hold the walk open; it is
# checked by the board's own tests, which read events from it.
STREAMS = {"/api/console/v1/board/stream"}


def test_every_console_api_read_answers_without_a_secret_for_both_kinds(
    db, runtime, admin_engine, world
):
    """The shared secret check over every GET the console API serves (CR2), with a held
    request in the tenant so the lists and the approval detail have something to say."""
    held = pending(runtime, world)
    ids = {**SAMPLE, "approval_id": str(held.approval_id), "execution_id": str(held.execution_id)}
    reads = [path for path, method in ROUTES if method == "GET" and path not in STREAMS]
    assert len(reads) > 30
    for identity in (world["admin"], world["human"]):
        with console_client(db, runtime, admin_engine, identity) as person:
            for path in reads:
                response = person.get(path.format(**ids))
                assert response.status_code < 500, (path, response.status_code, response.text)
                assert response.headers.get_list("set-cookie") == [], path
                if response.headers.get("content-type", "").startswith("application/json"):
                    body = response.json()
                    # The session route hands the page its CSRF token once, by design; the
                    # token is the one value on any route that is meant to be there.
                    if path.endswith("/session") and isinstance(body, dict):
                        body.pop("csrf_token", None)
                    reject_secrets(body)
                else:
                    reject_secrets(response.text)
