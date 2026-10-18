# SPDX-License-Identifier: AGPL-3.0-only
"""`POST /welcome/example`: the fixed synthetic Cedar examples, core's own route (#333).

The rest of the Getting started page is a plugin's (#496), but the fixed policy example is
core's, so its tests need no plugin.
"""

import pytest
from console_api_fixtures import API, assert_no_secrets, console_client, refusals
from sqlalchemy import text
from test_execution import registry as registry
from test_execution import world as world
from test_protected_path import connector as connector
from test_protected_path import live_provider as live_provider
from test_runtime import runtime as runtime

pytestmark = pytest.mark.integration


@pytest.mark.parametrize(
    "scenario,decision",
    [
        ("workstation", "ALLOW"),
        ("domain_controller", "DENY"),
        ("production", "REQUIRE_APPROVAL"),
    ],
)
def test_safe_example_uses_fixed_policy_without_creating_execution_state(
    db, runtime, admin_engine, world, scenario, decision
):
    with console_client(db, runtime, admin_engine, world["admin"]) as admin:
        with admin_engine.connect() as conn:
            before = conn.execute(text("SELECT count(*) FROM execbound.executions")).scalar_one()
        result = admin.post(API + "/welcome/example", {"scenario": scenario})
        assert result.status_code == 200, result.text
        assert result.json()["decision"] == decision
        assert result.json()["executed"] is False
        assert "not your workspace policy" in result.json()["scope"]
        assert result.headers["cache-control"] == "no-store"
        assert_no_secrets(result)
        with admin_engine.connect() as conn:
            assert (
                conn.execute(text("SELECT count(*) FROM execbound.executions")).scalar_one()
                == before
            )
        for body in ({"scenario": "real"}, {"scenario": scenario, "target": "real-host"}):
            assert admin.post(API + "/welcome/example", body).status_code == 400


def test_safe_example_checks_admin_session_csrf_and_origin_before_evaluation(
    db, runtime, seeded, admin_engine, world, monkeypatch
):
    import execbound.surfaces.console_api.welcome as welcome_api

    def never_evaluate(*args, **kwargs):
        pytest.fail("An unauthorized request reached the policy example")

    monkeypatch.setattr(welcome_api, "example", never_evaluate)
    path = API + "/welcome/example"
    rejected = refusals(db, runtime, seeded, admin_engine, world, path, "POST")
    assert rejected["bearer"].status_code == 403
    assert rejected["no_session"].status_code == 401
    with console_client(db, runtime, admin_engine, world["human"]) as human:
        assert human.post(path, {"scenario": "workstation"}).status_code == 403
    with console_client(db, runtime, admin_engine, world["admin"]) as admin:
        assert admin.post(path, {"scenario": "workstation"}, csrf=None).status_code == 403
        assert (
            admin.post(
                path, {"scenario": "workstation"}, origin="https://elsewhere.invalid"
            ).status_code
            == 403
        )
