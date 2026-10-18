# SPDX-License-Identifier: AGPL-3.0-only
"""The value report's routes and the Activity filters it links to (#678): HV8 and HV9."""

import re
from datetime import timedelta
from uuid import uuid4

import pytest
from console_api_fixtures import (
    API,
    ORIGIN,
    assert_no_secrets,
    console_client,
    console_config,
    refusals,
)
from sqlalchemy import text
from test_approval_deadline import deadline, long_facts
from test_execution import activate as activate  # noqa: F401
from test_execution import registry as registry  # noqa: F401
from test_execution import world as world  # noqa: F401
from test_home_value import DEADLINE, held_requests
from test_protected_path import connector as connector  # noqa: F401
from test_protected_path import live_provider as live_provider  # noqa: F401
from test_runtime import runtime as runtime  # noqa: F401

from execbound.execution import decide_approval


def test_hv9_activity_refuses_an_outcome_or_window_it_does_not_know(
    db, world, runtime, admin_engine
):
    long_facts(db, world)
    deadline(db, world, DEADLINE)
    lapsing, approved = held_requests(db, admin_engine, world, 2)
    decide_approval(db, world["human"], approved.approval_id, "APPROVE", world["clock"])
    world["clock"].value += timedelta(seconds=DEADLINE + 1)
    # Inside its deadline: in neither list.
    [waiting] = held_requests(db, admin_engine, world, 1)
    now = world["clock"].now()
    with console_client(db, runtime, admin_engine, world["admin"]) as page:
        for query in (
            "outcome=nope",
            "from=" + (now + timedelta(minutes=5)).isoformat().replace("+", "%2B"),
            "from=" + (now - timedelta(days=32)).isoformat().replace("+", "%2B"),
            "from=2026-10-01T00:00:00",
            "from=" + (now - timedelta(days=1)).isoformat().replace("+", "%2B") + "&since=7d",
            "from=x",
            "from=",
        ):
            response = page.get(API + "/executions?" + query)
            assert response.status_code == 400, (query, response.text)
            assert response.json()["code"] == "INVALID_REQUEST", query
        since = (now - timedelta(days=1)).isoformat().replace("+", "%2B")
        lapsed = page.get(API + f"/executions?outcome=lapsed&from={since}").json()["items"]
        assert [item["execution_id"] for item in lapsed] == [str(lapsing.execution_id)]
        unused = page.get(API + "/executions?outcome=approved_unused").json()["items"]
        assert [item["execution_id"] for item in unused] == [str(approved.execution_id)]
        held = page.get(API + "/executions?outcome=lapsed&state=PENDING_APPROVAL").json()
        assert [item["execution_id"] for item in held["items"]] == [str(lapsing.execution_id)]
    assert waiting.approval_id is not None


ROUTES = (API + "/report", API + "/report.csv")


@pytest.mark.parametrize("path", ROUTES)
def test_hv8_the_report_routes_refuse_as_every_route_does(
    db, runtime, seeded, admin_engine, world, path
):
    results = refusals(db, runtime, seeded, admin_engine, world, path)
    assert results["bearer"].status_code == 403, results["bearer"].text
    assert results["bearer"].json()["code"] == "FORBIDDEN"
    assert results["audited"] == 1
    missing = results["no_session"]
    assert missing.status_code == 401 and missing.json()["code"] == "SESSION_REQUIRED"
    assert missing.headers["content-type"].startswith("application/json")


def test_hv8_the_report_answers_json_and_a_csv_no_spreadsheet_evaluates(
    db, world, runtime, admin_engine
):
    tenant = world["identity"].tenant_id
    with admin_engine.begin() as conn:
        conn.execute(
            text("UPDATE execbound.tenants SET name=:n WHERE tenant_id=:t"),
            {"t": tenant, "n": '=HYPERLINK("x")'},
        )
    with console_client(db, runtime, admin_engine, world["admin"]) as page:
        for path in ROUTES:
            for query in ("range=1y", "utc_offset=9999", "other=1"):
                refused = page.get(path + "?" + query)
                assert refused.status_code == 400, (path, query)
                assert refused.json()["code"] == "INVALID_REQUEST"
        report = page.get(API + "/report?range=30d&utc_offset=-240")
        assert report.status_code == 200, report.text
        assert_no_secrets(report)
        body = report.json()
        assert body["range"] == "30d" and body["space"] == "All spaces"
        assert body["mode"] == "ENFORCE"
        download = page.get(API + "/report.csv?range=7d")
        assert download.status_code == 200, download.text
        assert_no_secrets(download)
    assert download.headers["content-type"].startswith("text/csv")
    disposition = download.headers["content-disposition"]
    assert re.fullmatch(
        r'attachment; filename="execbound-report-7d-\d{4}-\d{2}-\d{2}\.csv"', disposition
    )
    assert download.headers["cache-control"] == "no-store"
    lines = download.text.splitlines()
    assert lines[0] == '"section","measure","value"'
    # Every cell quoted; the name a spreadsheet would evaluate is prefixed, and appears once.
    assert '"report","workspace","\'=HYPERLINK(""x"")"' in lines
    assert sum("HYPERLINK" in line for line in lines) == 1
    assert '"report","space","All spaces"' in lines
    assert all(line.startswith('"') and line.endswith('"') for line in lines)
    # Fixed copy only: none of the words a value report never uses.
    lowered = download.text.lower()
    for word in ("prevent", "attack", "threat", "blocked"):
        assert word not in lowered.replace("harm was prevented", ""), word


def test_hv8_the_csv_follows_the_workspace_the_tab_is_showing(db, runtime, admin_engine, seeded):
    from fastapi.testclient import TestClient
    from test_workspace_switching import member_pair

    from execbound.app import create_app
    from execbound.resolution.models import SystemClock

    runtime.clock = SystemClock()
    grant, _, _, _ = member_pair(db, admin_engine, seeded)
    with TestClient(
        create_app(db, runtime=runtime, human=console_config()), base_url=ORIGIN
    ) as client:
        client.cookies.set("eb_session", grant.token, domain="127.0.0.1")
        client.cookies.set("eb_csrf", grant.csrf_token, domain="127.0.0.1")
        client.cookies.set("eb_account", grant.account_token, domain="127.0.0.1")
        headers = {"Origin": ORIGIN}
        missing = client.get(API + "/report.csv", headers=headers)
        assert missing.status_code == 409 and missing.json()["code"] == "WORKSPACE_CHANGED"
        other = client.get(API + f"/report.csv?generation={uuid4()}", headers=headers)
        assert other.status_code == 409 and other.json()["code"] == "WORKSPACE_CHANGED"
        own = client.get(API + f"/report.csv?generation={grant.session_id}", headers=headers)
        assert own.status_code == 200, own.text
