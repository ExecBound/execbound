# SPDX-License-Identifier: AGPL-3.0-only
"""Operations console: filtered, cursor-paginated activity, the uncertain queue, `reconcile`.

Activity is the console's page and `GET /api/console/v1/executions` is what it reads, so the
filters, the bounds and the cursor are asserted there — the same `records()` under the same
scope, fence and bound the Jinja listing used before the console replaced it (#333).
"""

import json
import os
import sys
from contextlib import contextmanager
from dataclasses import replace
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import text
from test_execution import registry as registry
from test_execution import targets
from test_execution import world as world
from test_human_surface import credential, form_values, pending
from test_human_surface import human_app as human_app
from test_human_surface import human_client as human_client
from test_human_surface import human_config as human_config
from test_protected_path import connector as connector
from test_protected_path import live_provider as live_provider
from test_runtime import runtime as runtime

from execbound.app import create_app
from execbound.cli import main
from execbound.execution import admit, decide_approval, set_enforcement_mode
from execbound.provider.connector import MockConnector
from execbound.runtime import Runtime

ORIGIN = {"Origin": "http://127.0.0.1"}
ACTIVITY = "/api/console/v1/executions"


def rows(client, query=""):
    """One page of Activity as the console reads it."""
    answer = client.get(ACTIVITY + query)
    assert answer.status_code == 200, (query, answer.text)
    return answer.json()


@contextmanager
def admin_client(db, runtime, human_config, admin_engine, world):
    app = create_app(db, runtime=runtime, human=human_config)
    with TestClient(app, base_url="http://127.0.0.1", follow_redirects=False) as client:
        _, values = form_values(client.get("/login").text, "/session")
        values["credential"] = credential(admin_engine, world["admin"])
        assert client.post("/session", data=values, headers=ORIGIN).status_code == 303
        yield client


def indeterminate(db, world, live_provider):
    live_provider.restart("delay_after_commit")
    slow = MockConnector(replace(live_provider.config, timeout_seconds=0.05))
    runtime = Runtime(db, [slow], clock=world["clock"])
    first = pending(runtime, world)
    decide_approval(db, world["human"], first.approval_id, "APPROVE", world["clock"])
    assert pending(runtime, world).state == "INDETERMINATE"
    return runtime, slow, first


def test_activity_filters_and_pages_for_an_administrator(
    db, runtime, human_config, world, admin_engine
):
    set_enforcement_mode(db, world["admin"], "OBSERVE", "Console test", world["clock"])
    for req in targets(admin_engine, world, count=55):
        assert admit(db, world["identity"], req, world["clock"]).view.state == "OBSERVED"
    set_enforcement_mode(db, world["admin"], "ENFORCE", "Console test done", world["clock"])
    agent = str(world["identity"].principal_id)
    with admin_client(db, runtime, human_config, admin_engine, world) as admin:
        page = rows(admin, "")
        assert len(page["items"]) == 50 and page["next_cursor"]
        second = rows(admin, "?cursor=" + page["next_cursor"])
        assert len(second["items"]) == 5 and second["next_cursor"] is None
        assert len(rows(admin, "?state=OBSERVED")["items"]) == 50
        assert rows(admin, "?state=DENIED")["items"] == []
        assert len(rows(admin, "?action=endpoint.isolate&since=1h")["items"]) == 50
        assert len(rows(admin, f"?agent={agent}")["items"]) == 50
        assert rows(admin, f"?agent={uuid4()}")["items"] == []
        assert len(rows(admin, "?state=&action=&agent=&since=")["items"]) == 50
        for bad in (
            "state=BOGUS",
            "action=nope",
            "agent=abc",
            "agent=" + agent.upper(),
            "since=7h",
            "cursor=!!!",
            "cursor=" + "a" * 201,
            "limit=0",
            "other=1",
            "state=OBSERVED&state=DENIED",
        ):
            assert admin.get(ACTIVITY + "?" + bad).status_code == 400, bad
        # The document a console route serves reads none of the query it carries, but a
        # duplicated key is still refused there, as it is on every page.
        assert admin.get("/activity?open=1&open=2").status_code == 400
        assert admin.get("/api/console/v1/approvals?state=OBSERVED").status_code in {400, 403}


def test_approver_activity_stays_scoped_when_filtered(human_client, runtime, world, admin_engine):
    pending(runtime, world)
    assert len(rows(human_client, "?state=PENDING_APPROVAL")["items"]) == 1
    with admin_engine.begin() as conn:
        conn.execute(
            text("UPDATE execbound.approval_scopes SET active=false WHERE approver_id=:p"),
            {"p": world["human"].principal_id},
        )
    assert rows(human_client, "?state=PENDING_APPROVAL")["items"] == []


def test_uncertain_queue_shows_dispatch_evidence_and_is_linked_from_home(
    db, world, live_provider, human_config, admin_engine
):
    runtime, slow, first = indeterminate(db, world, live_provider)
    try:
        with admin_client(db, runtime, human_config, admin_engine, world) as admin:
            # Home counts it, which is what the console links the queue from.
            overview = admin.get("/api/console/v1/overview?range=24h")
            assert overview.status_code == 200 and overview.json()["unsettled"] == 1
            queue = rows(admin, "?state=UNCERTAIN")
            assert len(queue["items"]) == 1
            [item] = queue["items"]
            assert item["execution_id"] == str(first.execution_id)
            record = admin.get(f"{ACTIVITY}/{first.execution_id}")
            assert record.status_code == 200
            detail = record.json()
            assert detail["reconcile"] is not None and detail["reconcile"]["kind"] == "provider"
            # The record says what happened and what is not known, and offers the
            # administrator the settlement rather than a retry.
            assert detail["state"] == "INDETERMINATE"
            timeline = [step["sentence"] for step in detail["timeline"]]
            assert "Dispatch committed." in timeline, timeline
            assert "The provider's answer is unknown." in timeline, timeline
            assert rows(admin, "?state=EXECUTED")["items"] == []
    finally:
        slow.close()


def test_reconcile_command_settles_one_operation_with_a_reason(
    db, world, live_provider, admin_engine, tmp_path, monkeypatch, capsys
):
    tenant, account = world["identity"].tenant_id, world["account"]
    runtime, slow, first = indeterminate(db, world, live_provider)
    slow.close()
    config = live_provider.config
    private = tmp_path / "private.json"
    private.write_text(
        json.dumps(
            {
                "origin": "http://127.0.0.1:8000",
                "active_key_id": "k1",
                "continuation_keys": {"k1": "11" * 32},
                "connectors": [
                    {
                        "tenant_id": str(tenant),
                        "account_id": str(account),
                        "origin": config.origin,
                        "dispatch_token": config.dispatch_token,
                        "control_token": config.control_token,
                        "evidence_keys": {k: v.hex() for k, v in config.evidence_keys.items()},
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    monkeypatch.setenv("EXECBOUND_RUNTIME_CONFIG", str(private))
    monkeypatch.setenv("DATABASE_URL", os.environ["TEST_DATABASE_URL"])
    admin_file, human_file = tmp_path / "admin.token", tmp_path / "human.token"
    admin_file.write_text(credential(admin_engine, world["admin"]), encoding="utf-8")
    human_file.write_text(credential(admin_engine, world["human"]), encoding="utf-8")

    def run(*argv):
        monkeypatch.setattr(sys, "argv", ["execbound", *argv])
        main()
        return json.loads(capsys.readouterr().out)

    def refused(*argv):
        monkeypatch.setattr(sys, "argv", ["execbound", *argv])
        with pytest.raises(SystemExit) as caught:
            main()
        assert caught.value.code == 2
        return capsys.readouterr().err

    common = ("--tenant", str(tenant), "--credential-file")
    execution = str(first.execution_id)
    assert "INVALID_IDENTITY" in refused(
        "reconcile", *common, str(human_file), "--execution", execution, "--reason", "No"
    )
    assert "NOT_FOUND" in refused(
        "reconcile", *common, str(admin_file), "--execution", str(uuid4()), "--reason", "Missing"
    )
    settled = run(
        "reconcile", *common, str(admin_file), "--execution", execution, "--reason", "Lost response"
    )
    assert settled["execution_id"] == execution and settled["state"] == "EXECUTED"
    assert runtime.status(world["identity"], first.execution_id).state == "EXECUTED"
    assert live_provider.store.resource(tenant, world["canonical"]).mutation_count == 1
    # Settlement is idempotent: a repeat returns the same terminal view and changes nothing.
    again = run(
        "reconcile", *common, str(admin_file), "--execution", execution, "--reason", "Again"
    )
    assert again["state"] == "EXECUTED"
    assert live_provider.store.resource(tenant, world["canonical"]).mutation_count == 1
