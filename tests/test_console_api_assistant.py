# SPDX-License-Identifier: AGPL-3.0-only
"""`/api/console/v1/assistant`: the routes the console's assistant panel is built on.

The engine's own behaviour is `tests/test_assistant_loop.py`; this is the surface. What it
holds: the addresses exist only where a model is configured, every refusal the shared harness
exercises, a turn that answers into its row with the loop running behind the response, a stream
that ends with the row's own ending, turns private to the person who asked, the explanation
that is recorded when opened, and the switch that is an administrator's with a reason.
"""

import json

import pytest
from console_api_fixtures import (
    API,
    ORIGIN,
    assert_no_secrets,
    console_client,
    console_config,
    rejections,
)
from fastapi.testclient import TestClient
from sqlalchemy import text
from test_assistant_loop import answer, call
from test_emergency_stop import audit
from test_execution import registry as registry
from test_execution import world as world
from test_human_surface import human_config as human_config
from test_human_surface import pending
from test_protected_path import connector as connector
from test_protected_path import live_provider as live_provider
from test_runtime import runtime as runtime

from execbound.app import create_app
from execbound.assistant.client import ScriptedTransport
from execbound.assistant.config import PROVIDER_RETENTION, AssistantConfig
from execbound.assistant.turns import set_tenant_switch

pytestmark = pytest.mark.integration

ASSISTANT = API + "/assistant"
BLOCK = AssistantConfig(api_key="console-test-key", person_hourly_turns=50)
ZERO_ONE = "00000000-0000-0000-0000-000000000001"
CONFIGURED = console_config(assistant_enabled=True)


@pytest.fixture
def configured(runtime):
    """A runtime whose operator configured a model, with a scripted provider behind it."""
    runtime.assistant = BLOCK
    runtime.assistant_transport = ScriptedTransport([])
    return runtime


def signed_in(db, runtime, admin_engine, identity):
    """A signed-in person on a console whose operator configured a model."""
    return console_client(db, runtime, admin_engine, identity, config=CONFIGURED)


def script(runtime, *steps):
    runtime.assistant_transport = ScriptedTransport(list(steps))
    return runtime.assistant_transport


def switched_on(db, world):
    set_tenant_switch(db, world["admin"], True, "Synthetic tenant", world["clock"])


def test_the_addresses_exist_only_where_a_model_is_configured(db, runtime, admin_engine, world):
    """Absent, not disabled: without the block the console serves no assistant address."""
    with console_client(db, runtime, admin_engine, world["admin"]) as console:
        assert console.get(ASSISTANT + "/turns").status_code == 404
        assert console.post(ASSISTANT + "/turns", {"question": "?"}).status_code == 404
    runtime.assistant = BLOCK
    with signed_in(db, runtime, admin_engine, world["admin"]) as console:
        # Present but not turned on for this tenant: the address exists and says so.
        listed = console.get(ASSISTANT + "/turns")
        assert listed.status_code == 200 and listed.json() == {"turns": []}
        refused = console.post(ASSISTANT + "/turns", {"question": "What changed today?"})
        assert refused.status_code == 409 and refused.json()["code"] == "ASSISTANT_OFF"
        assert_no_secrets(refused)


@pytest.mark.parametrize(
    ("path", "method"),
    [("/turns", "GET"), ("/turns", "POST"), ("/settings", "GET"), ("/settings", "POST")],
)
def test_every_route_makes_the_refusals_the_console_api_owes(
    db, configured, seeded, admin_engine, world, path, method
):
    """A bearer credential is refused and audited; no session is a typed 401 in JSON, even
    to a browser. The shared harness builds a console without a model, so this module makes
    the same two calls against its own construction."""
    app = create_app(db, runtime=configured, human=CONFIGURED)
    address = ASSISTANT + path
    before = rejections(admin_engine, world["identity"])
    with TestClient(app, base_url=ORIGIN, follow_redirects=False) as client:
        bearer = {
            "Authorization": "Bearer " + seeded["tokens"][0],
            "Origin": ORIGIN,
            "Content-Type": "application/json",
        }
        browser = {"Accept": "text/html", "Origin": ORIGIN, "Content-Type": "application/json"}
        if method == "GET":
            refused, anonymous = (
                client.get(address, headers=bearer),
                client.get(address, headers=browser),
            )
        else:
            refused = client.post(address, content=b"{}", headers=bearer)
            anonymous = client.post(address, content=b"{}", headers=browser)
    assert refused.status_code == 403 and refused.json()["code"] == "FORBIDDEN"
    assert rejections(admin_engine, world["identity"]) - before == 1
    assert anonymous.status_code == 401 and anonymous.json()["code"] == "SESSION_REQUIRED"
    assert anonymous.headers["content-type"].startswith("application/json")
    assert_no_secrets(refused)


def test_a_turn_answers_into_its_row_and_the_stream_ends_with_the_rows_own_ending(
    db, configured, admin_engine, world
):
    switched_on(db, world)
    bundle_id = str(world["bundle"].bundle_id)
    script(
        configured,
        call("get_policy"),
        answer(("The active policy allows isolating a workstation.", [bundle_id])),
    )
    with signed_in(db, configured, admin_engine, world["admin"]) as console:
        created = console.post(ASSISTANT + "/turns", {"question": "What does the policy allow?"})
        assert created.status_code == 200, created.text
        opened = created.json()
        # The response is the turn as it starts; the loop runs behind it.
        assert opened["state"] == "RUNNING" and opened["steps"] == []
        assert opened["question"] == "What does the policy allow?"
        assert opened["context_kind"] == "question" and opened["paragraphs"] == []
        turn_id = opened["turn_id"]
        done = console.get(f"{ASSISTANT}/turns/{turn_id}")
        assert done.status_code == 200
        finished = done.json()
        assert finished["state"] == "COMPLETED" and finished["reason"] is None
        assert finished["steps"] == ["Read the active policy"]
        assert finished["paragraphs"][0]["ids"] == [bundle_id]
        assert finished["cited_ids"] == [bundle_id] and finished["cannot_answer"] is False
        assert_no_secrets(done)
        stream = console.get(f"{ASSISTANT}/turns/{turn_id}/events")
        assert stream.status_code == 200
        assert stream.headers["content-type"].startswith("text/event-stream")
        assert stream.headers["cache-control"] == "no-store"
        events = [block for block in stream.text.split("\n\n") if block]
        assert events[0].startswith("event: step")
        assert json.loads(events[0].split("data: ", 1)[1])["text"] == "Read the active policy"
        assert events[-1].startswith("event: done")
        ending = json.loads(events[-1].split("data: ", 1)[1])
        assert ending["state"] == "COMPLETED" and ending["cited_ids"] == [bundle_id]
        assert ending["paragraphs"][0]["text"].startswith("The active policy allows")
        listed = console.get(ASSISTANT + "/turns").json()["turns"]
        assert [turn["turn_id"] for turn in listed] == [turn_id]


def test_a_contextual_turn_needs_a_record_the_person_can_read(
    db, configured, admin_engine, world, live_provider
):
    from demo_world import provision_mock

    switched_on(db, world)
    provision_mock(live_provider, admin_engine, world)
    waiting = pending(configured, world)
    approval_id = str(waiting.approval_id)
    script(
        configured,
        call("get_approval", {"approval_id": approval_id}),
        answer(("A production review required a person; one approver.", [approval_id])),
    )
    with signed_in(db, configured, admin_engine, world["human"]) as console:
        asked = console.post(
            ASSISTANT + "/turns", {"context_kind": "approval", "context_id": approval_id}
        )
        assert asked.status_code == 200, asked.text
        turn_id = asked.json()["turn_id"]
        assert asked.json()["context_kind"] == "approval"
        finished = console.get(f"{ASSISTANT}/turns/{turn_id}").json()
        assert finished["state"] == "COMPLETED" and finished["cited_ids"] == [approval_id]
        # Opening the explanation is recorded, so a later review sees which decisions were
        # made after reading one.
        marked = console.post(f"{ASSISTANT}/turns/{turn_id}/opened")
        assert marked.status_code == 200 and marked.json()["turn_id"] == turn_id
        payloads = audit(admin_engine, world["identity"].tenant_id, "assistant.explained")
        assert len(payloads) == 1 and payloads[0]["turn_id"] == turn_id
        assert payloads[0]["context_kind"] == "approval" and "question" not in payloads[0]
        # A context this person cannot read, and every body the request model refuses.
        hidden = console.post(
            ASSISTANT + "/turns", {"context_kind": "approval", "context_id": ZERO_ONE}
        )
        assert hidden.status_code == 404 and hidden.json()["code"] == "NOT_FOUND"
        for body in (
            {"context_kind": "approval"},
            {"context_kind": "question", "context_id": approval_id},
            {"context_kind": "everything", "question": "?"},
            {"question": ""},
            {"question": "?", "extra": 1},
            {},
        ):
            bad = console.post(ASSISTANT + "/turns", body)
            assert bad.status_code == 400, (body, bad.text)
            assert bad.json()["code"] in {"INVALID_BODY", "INVALID_REQUEST"}


def test_a_turn_is_the_askers_and_no_one_elses(db, configured, admin_engine, world):
    switched_on(db, world)
    script(configured, answer(("Nothing to report.", []), cannot_answer=True))
    with console_client(
        db, configured, admin_engine, world["human"], config=CONFIGURED
    ) as approver:
        turn_id = approver.post(ASSISTANT + "/turns", {"question": "Mine"}).json()["turn_id"]
    with signed_in(db, configured, admin_engine, world["admin"]) as admin:
        assert admin.get(f"{ASSISTANT}/turns/{turn_id}").status_code == 404
        assert admin.get(f"{ASSISTANT}/turns/{turn_id}/events").status_code == 404
        assert admin.post(f"{ASSISTANT}/turns/{turn_id}/opened").status_code == 404
        assert admin.get(ASSISTANT + "/turns").json() == {"turns": []}
        assert admin.get(f"{ASSISTANT}/turns/not-a-uuid").status_code == 404


def test_the_switch_is_the_administrators_with_a_reason_and_states_the_retention(
    db, configured, admin_engine, world
):
    switch = {"enabled": True, "reason": "x"}
    with console_client(
        db, configured, admin_engine, world["human"], config=CONFIGURED
    ) as approver:
        assert approver.get(ASSISTANT + "/settings").status_code == 403
        assert approver.post(ASSISTANT + "/settings", switch).status_code == 403
    with signed_in(db, configured, admin_engine, world["admin"]) as admin:
        before = admin.get(ASSISTANT + "/settings")
        assert before.status_code == 200
        assert before.json() == {
            "enabled": False,
            "model": "claude-sonnet-5",
            "provider_retention": PROVIDER_RETENTION,
            "person_hourly_turns": 50,
            "tenant_daily_tokens": 200000,
        }
        assert_no_secrets(before)
        turned = admin.post(ASSISTANT + "/settings", {"enabled": True, "reason": "Pilot"})
        assert turned.status_code == 200 and turned.json()["enabled"] is True
        again = admin.post(ASSISTANT + "/settings", {"enabled": True, "reason": "Pilot"})
        assert again.status_code == 409 and again.json()["code"] == "CONFLICT"
        for body in ({"enabled": True}, {"enabled": True, "reason": ""}, {"reason": "no state"}):
            bad = admin.post(ASSISTANT + "/settings", body)
            assert bad.status_code == 400, (body, bad.text)
        payloads = audit(admin_engine, world["identity"].tenant_id, "tenant.assistant_changed")
        assert [row["reason"] for row in payloads] == ["Pilot"]
        off = admin.post(ASSISTANT + "/settings", {"enabled": False, "reason": "Done"})
        assert off.json()["enabled"] is False
        stopped = admin.post(ASSISTANT + "/turns", {"question": "After the switch"})
        assert stopped.status_code == 409 and stopped.json()["code"] == "ASSISTANT_OFF"


def test_a_secret_in_tenant_data_ends_the_turn_and_the_row_says_so(
    db, configured, admin_engine, world
):
    switched_on(db, world)
    principal = world["identity"].principal_id
    marker = "A1B2C3D4E5F6G7H8"
    with admin_engine.begin() as conn:
        conn.execute(
            text("UPDATE execbound.principals SET label = :l WHERE principal_id = :p"),
            {"l": "Bearer " + marker, "p": principal},
        )
    transport = script(
        configured,
        call("get_agent", {"agent_principal_id": str(principal)}),
        answer(("never", [])),
    )
    with signed_in(db, configured, admin_engine, world["admin"]) as console:
        turn_id = console.post(ASSISTANT + "/turns", {"question": "This agent?"}).json()["turn_id"]
        finished = console.get(f"{ASSISTANT}/turns/{turn_id}")
        assert finished.json()["state"] == "FAILED"
        assert finished.json()["reason"] == "REFUSED_SECRET"
        assert marker not in json.dumps(transport.sent)
        assert_no_secrets(finished)
