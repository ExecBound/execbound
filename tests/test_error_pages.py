# SPDX-License-Identifier: AGPL-3.0-only
"""Browser requests get an HTML error page with the same status; clients keep JSON."""

from urllib.parse import urlencode
from uuid import uuid4

from fastapi.testclient import TestClient
from test_execution import registry as registry
from test_execution import world as world
from test_human_surface import form_values, pending
from test_human_surface import human_app as human_app
from test_human_surface import human_client as human_client
from test_human_surface import human_config as human_config
from test_protected_path import connector as connector
from test_protected_path import live_provider as live_provider
from test_runtime import runtime as runtime

from execbound.app import create_app

ORIGIN = {"Origin": "http://127.0.0.1"}
HTML = {"Accept": "text/html,application/xhtml+xml"}


def test_anonymous_and_wrong_role_requests_get_pages_with_the_same_status(
    db, runtime, human_config, seeded, human_client
):
    with TestClient(
        create_app(db, runtime=runtime, human=human_config),
        base_url="http://127.0.0.1",
        follow_redirects=False,
    ) as anonymous:
        # Notification links preserve their destination through normal sign-in, including
        # the no-script classic page. The API still answers JSON to everyone.
        assert anonymous.get("/").headers["location"] == "/login"
        path = f"/approvals/{uuid4()}/classic"
        page = anonymous.get(path, headers=HTML)
        assert page.status_code == 303
        assert page.headers["location"] == "/login?" + urlencode({"review": path})
        assert "Content-Security-Policy" in page.headers
        assert anonymous.get("/api/console/v1/session").json()["code"] == "SESSION_REQUIRED"
    bearer = human_client.get(
        f"/approvals/{uuid4()}/classic",
        headers={**HTML, "Authorization": "Bearer " + seeded["tokens"][0]},
    )
    assert bearer.status_code == 403 and "This session cannot do that" in bearer.text
    missing = human_client.get(f"/approvals/{uuid4()}/classic", headers=HTML)
    assert missing.status_code == 404 and "Nothing is here" in missing.text


def test_a_replayed_decision_gets_a_page_and_api_paths_stay_json(human_client, runtime, world):
    view = pending(runtime, world)
    path, values = form_values(
        human_client.get(f"/approvals/{view.approval_id}/classic").text, "/decide"
    )
    values["decision"] = "DENY"
    assert human_client.post(path, data=values, headers=ORIGIN).status_code == 303
    replay = human_client.post(path, data=values, headers={**ORIGIN, **HTML})
    assert replay.status_code == 409 and "already been decided" in replay.text
    assert human_client.post(path, data=values, headers=ORIGIN).json()["code"] == "INVALID_STATE"
    api = human_client.get(f"/v1/executions/{uuid4()}", headers=HTML)
    assert api.status_code in {401, 403} and api.headers["content-type"].startswith(
        "application/json"
    )
