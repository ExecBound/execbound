# SPDX-License-Identifier: AGPL-3.0-only
"""The denial notice, DN1 to DN3: an agent is told a denial's state and reference, never its cause.

A denied agent may be mistaken, prompt-injected or compromised, so its answer carries no map of
the policy: not the rule that matched, not the fact that put the target out of bounds, not the
budget that is spent, and never a reviewer's words. What it gets is `notice`, one fixed
sentence naming the request's reference, so it can stop and tell a person where to look
instead of guessing why (#545, `docs/THREAT_MODEL.md` T1.16). Every other state's answer is
unchanged, and observe mode keeps its reason codes on purpose (OB3). The second shipment adds
`denial`, whose `busy` and `limit` categories and their sentences DN4 to DN10 hold in
`tests/test_denial_categories.py`; here a limit denial carries its own sentence and every
other denial the withheld one.

Real PostgreSQL, the live endpoint provider, the HTTP routes through the application and MCP
over a real Streamable HTTP server.
"""

import ast
import json
import re
from datetime import timedelta
from pathlib import Path
from types import SimpleNamespace
from typing import Any, cast, get_args
from uuid import UUID, uuid4

import httpx
import pytest
from console_api_fixtures import API, console_client
from execbound_client import ExecBoundClient, execbound_action
from scope_fixtures import rule, scoped_bundle, transition_payload
from sqlalchemy import text
from test_execution import registry as registry
from test_execution import request, targets
from test_execution import world as world
from test_mcp_surface import gateway as gateway
from test_protected_path import connector as connector
from test_protected_path import live_provider as live_provider
from test_runtime import api as api
from test_runtime import runtime as runtime

from execbound.db import Database
from execbound.execution import decide_approval, set_enforcement_mode
from execbound.execution.models import ExecutionState, ExecutionView
from execbound.runtime import Runtime, denial_notice
from execbound.surfaces.agent_api_guide import ERROR_MEANINGS
from execbound.surfaces.agent_openapi import agent_api_document
from execbound.surfaces.http import ERROR_STATUS
from execbound.surfaces.mcp import TOOLS
from execbound.surfaces.recipes import render_recipe

ROOT = Path(__file__).resolve().parents[1]

# Pinned as words rather than read back from `denial_notice`, so a change to what every denied
# agent is told is a change to this line too, and a reason slipped into the sentence fails here.
NOTICE = (
    "Denied. The reason is recorded for a person, who can find it by searching the console "
    "for {reference}. Re-sending this request returns this same answer."
)
# The one a denial on a spent shared limit, and on nothing else, carries instead (DN4).
LIMIT_NOTICE = (
    "Denied because a shared limit is spent. Re-sending this request returns this same answer; "
    "a new request after the limit resets is decided afresh. A person can find it by searching "
    "the console for {reference}."
)
# What every agent instruction ExecBound ships says about a denial.
RELAY = "On a denial, stop and give the person its request_ref."
# The view's own members, which a denial keeps, plus the two the presenter adds.
DENIED_MEMBERS = {
    "request_ref",
    "execution_id",
    "state",
    "plan_hash",
    "approval_id",
    "approval_state",
    "denial",
    "notice",
}


def body(wire):
    return wire.model_dump(mode="json")


def domain_controller(engine, wire):
    """Make the resource ``wire`` names a domain controller, which the endpoint pack denies."""
    with engine.begin() as conn:
        conn.execute(
            text("UPDATE execbound.resources SET role='domain_controller' WHERE resource_id=:r"),
            {"r": wire.target.value},
        )


def development(engine, world):
    """Make the world's own target, the one the live provider holds, need no approval."""
    with engine.begin() as conn:
        conn.execute(
            text("UPDATE execbound.resources SET environment='development' WHERE resource_id=:r"),
            {"r": world["target"]},
        )


def mcp_call(gateway, token, name, arguments):
    """One `tools/call` over the real transport; the structured result, checked against its text."""
    rpc = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {
            "_meta": {
                "io.modelcontextprotocol/protocolVersion": "2026-07-28",
                "io.modelcontextprotocol/clientCapabilities": {},
            },
            "name": name,
            "arguments": arguments,
        },
    }
    response = httpx.post(
        gateway + "/mcp/",
        json=rpc,
        headers={
            "Authorization": "Bearer " + token,
            "Content-Type": "application/json",
            "Accept": "application/json, text/event-stream",
            "MCP-Protocol-Version": "2026-07-28",
            "MCP-Method": "tools/call",
            "MCP-Name": name,
        },
        trust_env=False,
    )
    assert response.status_code == 200, response.text
    messages = [
        json.loads(line[5:].strip())
        for line in response.text.splitlines()
        if line.startswith("data:")
    ] or [response.json()]
    result = messages[-1]["result"]
    # A denial is an answer, not a tool error, and the text a model reads is the same object.
    assert result["isError"] is False, result
    [content] = result["content"]
    assert json.loads(content["text"]) == result["structuredContent"]
    return result["structuredContent"]


def assert_denied(payload, recorded, denial="withheld"):
    """A denied answer: the view, the reference, the category and its fixed sentence, and
    nothing of why."""
    assert payload["state"] == "DENIED"
    assert re.fullmatch(r"EB-[1-9][0-9]*", payload["request_ref"])
    assert payload["denial"] == denial
    sentence = LIMIT_NOTICE if denial == "limit" else NOTICE
    assert payload["notice"] == sentence.format(reference=payload["request_ref"])
    assert set(payload) == DENIED_MEMBERS
    wire = json.dumps(payload)
    for reason in recorded:
        # The recorded code, and the rule id inside a limit's code, reach no member at all.
        for part in (reason, *reason.split(":")):
            assert part not in wire, part
    for leaked in ("NOT_AUTHORIZED", "HARD_LIMIT", "domain_controller", "isolation-budget"):
        assert leaked not in wire, leaked


def test_dn1_a_denied_answer_names_its_reference_and_nothing_of_why(
    api, gateway, runtime, world, seeded, db, admin_engine, live_provider
):
    tenant, token = world["identity"].tenant_id, seeded["tokens"][0]
    scoped_bundle(db, world, rule(rule_id="isolation-budget", max_targets=1, on_exceed="DENY"))
    tier_zero, second, third_target = targets(admin_engine, world, 3)
    domain_controller(admin_engine, tier_zero)
    development(admin_engine, world)

    # A deny rule, over MCP: the policy forbids isolating a domain controller.
    ruled = mcp_call(gateway, token, "execute", {"request": body(tier_zero)})
    recorded = transition_payload(admin_engine, tenant, ruled["execution_id"], "DENIED")
    assert recorded["reasons"] == ["NOT_AUTHORIZED"]
    assert_denied(ruled, recorded["reasons"])

    # The one isolation the budget allows runs, and the next is denied on the budget, over HTTP.
    executed = api.post("/v1/execute", json=body(request(world)))
    assert executed.status_code == 200 and executed.json()["state"] == "EXECUTED"
    limited = api.post("/v1/execute", json=body(second))
    assert limited.status_code == 200, limited.text
    recorded = transition_payload(admin_engine, tenant, limited.json()["execution_id"], "DENIED")
    assert recorded["reasons"] == ["HARD_LIMIT:isolation-budget"]
    assert_denied(limited.json(), recorded["reasons"], "limit")
    assert limited.json()["request_ref"] != ruled["request_ref"]

    # A retry and a status read on either surface answer the same bytes, notice included.
    assert api.post("/v1/execute", json=body(second)).content == limited.content
    assert api.get("/v1/executions/" + limited.json()["execution_id"]).content == limited.content
    assert api.get("/v1/executions/" + ruled["execution_id"]).json() == ruled
    status = mcp_call(
        gateway, token, "execution_status", {"execution_id": limited.json()["execution_id"]}
    )
    assert status == limited.json()
    assert mcp_call(gateway, token, "execute", {"request": body(tier_zero)}) == ruled

    # The Python client's tool summary, which the SDK examples hand a model, relays the
    # sentence and the reference, and nothing of why.
    third = body(third_target)
    client = ExecBoundClient("http://testserver", token, client=api)
    summary = json.loads(
        execbound_action(
            client,
            third["operation_ref"],
            third["target"]["kind"],
            third["target"]["value"],
            "client-denial",
            incident_id=third["claimed_context"]["incident_id"],
        )
    )
    assert summary["state"] == "DENIED" and summary["outcome"] == "final"
    assert summary["denial"] == "limit"
    assert summary["notice"] == LIMIT_NOTICE.format(reference=summary["request_ref"])
    assert "HARD_LIMIT" not in json.dumps(summary) and "isolation-budget" not in json.dumps(summary)

    # The notice's promise: an administrator searching the console for the reference finds the
    # denied request, and its record carries the reason the agent was never told.
    with console_client(db, runtime, admin_engine, world["admin"]) as person:
        for answer in (limited.json(), ruled):
            found = person.get(API + "/search", params={"q": answer["request_ref"]})
            assert found.status_code == 200, found.text
            [hit] = [row for row in found.json()["results"] if row["kind"] == "execution"]
            assert hit["execution_id"] == answer["execution_id"]
            assert hit["detail"] == "Request " + answer["request_ref"]
        record = person.get(API + "/executions/" + limited.json()["execution_id"]).json()
        assert "HARD_LIMIT:isolation-budget" in {reason["code"] for reason in record["reasons"]}


def test_dn1_a_reviewers_refusal_shows_as_the_approval_state_and_never_as_the_comment(
    api, gateway, world, seeded, db, admin_engine, live_provider
):
    """A person's refusal was already visible as `approval_state` DENIED, and stays so; the
    comment the reviewer wrote reaches the record and never the agent."""
    tenant, token = world["identity"].tenant_id, seeded["tokens"][0]
    pending = api.post("/v1/execute", json=body(request(world)))
    assert pending.status_code == 202, pending.text
    comment = "Refused-7f3c: payroll close, keep the host online"
    decided = decide_approval(
        db,
        world["human"],
        UUID(pending.json()["approval_id"]),
        "DENY",
        world["clock"],
        comment=comment,
    )
    assert decided.state == "DENIED"
    recorded = transition_payload(admin_engine, tenant, decided.execution_id, "DENIED")
    assert recorded["reason"] == "HUMAN_DENIED"
    with admin_engine.connect() as conn:
        kept = conn.execute(
            text(
                "SELECT count(*) FROM execbound.audit_events "
                "WHERE tenant_id=:t AND strpos(payload::text, :c) > 0"
            ),
            {"t": tenant, "c": "Refused-7f3c"},
        ).scalar_one()
    assert kept > 0, "the comment was never recorded, so its absence below would prove nothing"

    execution = pending.json()["execution_id"]
    resent = api.post("/v1/execute", json=body(request(world)))
    answers = [
        resent.json(),
        api.get("/v1/executions/" + execution).json(),
        mcp_call(gateway, token, "execute", {"request": body(request(world))}),
        mcp_call(gateway, token, "execution_status", {"execution_id": execution}),
    ]
    assert resent.status_code == 200
    for answer in answers:
        assert answer["state"] == "DENIED" and answer["approval_state"] == "DENIED"
        assert answer["denial"] == "withheld"
        assert answer["notice"] == NOTICE.format(reference=answer["request_ref"])
        assert set(answer) == DENIED_MEMBERS
        wire = json.dumps(answer)
        for leaked in ("Refused-7f3c", "payroll", "online", "HUMAN_DENIED"):
            assert leaked not in wire, leaked


def test_dn1_a_denied_view_without_a_reference_still_says_nothing_of_why(runtime, world):
    """Every stored view carries its reference (`store.view`, over a NOT NULL column); a view
    built without one, as a test double builds it, still gets a sentence with no cause in it."""
    view = ExecutionView(execution_id=uuid4(), state="DENIED", plan_hash="a" * 64)
    payload = runtime.present(world["identity"], view)
    assert payload["notice"] == (
        "Denied. The reason is recorded for a person, who can find it in the console. "
        "Re-sending this request returns this same answer."
    )
    assert payload["notice"] == denial_notice(None)
    assert denial_notice("EB-12") == NOTICE.format(reference="EB-12")


def test_dn2_no_other_state_carries_a_notice(
    api, gateway, world, seeded, db, admin_engine, live_provider
):
    token = seeded["tokens"][0]
    # Pending, over HTTP and read back over MCP.
    pending = api.post("/v1/execute", json=body(request(world)))
    assert pending.status_code == 202 and pending.json()["state"] == "PENDING_APPROVAL"
    assert "notice" not in pending.json()
    status = mcp_call(
        gateway, token, "execution_status", {"execution_id": pending.json()["execution_id"]}
    )
    assert status["state"] == "PENDING_APPROVAL" and "notice" not in status

    # Stale: the approval's deadline passes before anyone decides, and the retry learns it.
    world["clock"].value += timedelta(seconds=121)
    stale = api.post("/v1/execute", json=body(request(world)))
    assert stale.status_code == 200 and stale.json()["state"] == "STALE_AUTHORIZATION"
    assert "notice" not in stale.json()

    # Executed, over MCP, once the same target needs no approval.
    development(admin_engine, world)
    wire = body(request(world, idempotency_key="executed"))
    executed = mcp_call(gateway, token, "execute", {"request": wire})
    assert executed["state"] == "EXECUTED" and "notice" not in executed

    # Observed: a would-be denial keeps its reason codes and gets no notice (OB3).
    set_enforcement_mode(db, world["admin"], "OBSERVE", "Onboarding", world["clock"])
    [tier_zero] = targets(admin_engine, world, 1)
    domain_controller(admin_engine, tier_zero)
    observed = api.post("/v1/execute", json=body(tier_zero))
    assert observed.status_code == 200 and observed.json()["state"] == "OBSERVED"
    assert observed.json()["observed"]["effect"] == "DENY"
    assert "NOT_AUTHORIZED" in observed.json()["observed"]["reasons"]
    assert "notice" not in observed.json()


@pytest.mark.parametrize("state", get_args(ExecutionState))
def test_dn2_the_presenter_adds_a_notice_to_a_denial_and_to_no_other_state(state):
    """Every state the model has, through the presenter with no keys and no database: a
    denial gains its category and sentence, withheld for a view that records none, and every
    other view is answered exactly as serialized."""
    runtime = Runtime(cast(Database, SimpleNamespace(capacity=1)), [])
    view = ExecutionView(request_ref="EB-7", execution_id=uuid4(), state=state, plan_hash="a" * 64)
    payload = runtime.present(cast(Any, None), view)
    if state == "DENIED":
        assert payload == {
            **view.model_dump(mode="json"),
            "denial": "withheld",
            "notice": NOTICE.format(reference="EB-7"),
        }
    else:
        assert "notice" not in payload and "denial" not in payload
        assert payload == view.model_dump(mode="json")


def test_dn3_the_execute_tool_says_where_actions_come_from_and_to_relay_the_reference():
    (execute,) = [tool for tool in TOOLS if tool.name == "execute"]
    description = execute.description
    assert description is not None
    assert "Call list_actions for the operation_ref values your space offers" in description
    assert "A denial's reason is kept for a person" in description
    assert "request_ref" in description and "rather than guessing why" in description
    # Every agent reads this on every tool listing, so it stays a paragraph.
    assert len(description) < 800, len(description)


def test_dn3_the_guide_withholds_the_reason_and_answers_a_busy_target_as_a_denial():
    document = agent_api_document()
    guide = document["info"]["description"]
    # The rule, its reason and what to do.
    assert "never the reason itself" in guide
    assert "no map of the policy" in guide
    assert "a reviewer's words stay with people" in guide
    assert "give the person the `request_ref`" in guide
    assert json.dumps(denial_notice("EB-12")) in guide
    # A busy target is a denial the kernel records, never a 409 an agent should retry after.
    assert "RESOURCE_BUSY" not in ERROR_STATUS and "RESOURCE_BUSY" not in ERROR_MEANINGS
    rows = re.findall(r"^\| (\d{3}) \| `([A-Z_]+)` \|", guide, re.M)
    assert rows and "RESOURCE_BUSY" not in {code for _, code in rows}
    assert "Retry after that execution settles" not in guide
    assert "A target another execution still holds is answered the same way" in guide
    # What the notice promises, and what it does not: the same request, not a new one.
    assert "Retrying gets the same decision" not in guide
    assert "Re-sending the same request returns the same answer" in guide
    assert "whether to make one is the person's call" in guide
    # The disclosure the view has always made, stated rather than hidden.
    assert "`approval_state` is `DENIED` when a reviewer refused the request" in guide
    # Observe mode's exception covers an observe-only mapping as well as a workspace.
    assert "whether the whole workspace observes or only the mapping" in guide
    # The reasons table lists what a denial records: a reviewer's refusal, never a hold.
    reasons = guide[guide.index("The reasons a denial records") : guide.index("## Errors")]
    listed = set(re.findall(r"^\| `([A-Z_]+)(?::<rule id>)?` \|", reasons, re.M))
    # Exactly the codes a DENIED transition carries: `policy/evaluate.py`'s denials but
    # `INVALID_APPROVAL`, which admission ends as stale, then admission's busy target and a
    # reviewer's refusal. `APPROVAL_REQUIRED` holds a request and never denies one.
    assert listed == {
        "NOT_AUTHORIZED",
        "HARD_LIMIT",
        "INVALID_CONTEXT",
        "INVALID_ARGUMENTS",
        "INVALID_IDENTITY",
        "INVALID_BUNDLE",
        "INVALID_USAGE",
        "POLICY_ERROR",
        "DEPENDENCY_UNAVAILABLE",
        "RESOURCE_BUSY",
        "HUMAN_DENIED",
    }
    # The policy's own row covers each cause the evaluator denies with it (#545): a policy
    # naming the action at a mapping that has since changed, and one that is another
    # workspace's. Admission refuses the first for a new or changed request before any
    # decision, and the row stays for a held request.
    assert (
        "| `INVALID_BUNDLE` | The active policy cannot authorize this request: it names the action "
        "at a mapping that has since changed, or it is not this workspace's. |" in reasons
    )
    assert "does not belong to this workspace" not in guide
    # The published schema describes the member, on a denial alone.
    notice = document["components"]["schemas"]["ExecutionView"]["properties"]["notice"]
    assert notice["type"] == "string"
    assert notice["description"].startswith("Present only on a DENIED execution")
    assert notice["examples"][-1] == denial_notice("EB-12")


def shipped(source):
    """A recipe as the welcome page renders it, or a client example as it is published."""
    if source.endswith((".txt", ".sh", ".json")):
        return render_recipe(source, "https://sandbox.example")
    return (ROOT / source).read_text(encoding="utf-8")


@pytest.mark.parametrize(
    "source",
    [
        "openai_agents.py.txt",
        "clients/python/examples/openai_agents_tool.py",
        "clients/python/examples/claude_agent_sdk_tool.py",
    ],
)
def test_dn3_every_agent_instruction_shipped_tells_it_to_relay_the_reference(source):
    assert RELAY in shipped(source)


def test_dn3_the_claude_agent_sdk_recipe_names_the_example_that_relays():
    recipe = shipped("claude_agent_sdk.sh")
    assert "clients/python/examples/claude_agent_sdk_tool.py" in recipe
    assert RELAY in shipped("clients/python/examples/claude_agent_sdk_tool.py")


def test_dn3_nothing_in_the_gateway_raises_a_busy_target_as_an_error():
    """A busy target is a recorded denial. A code missing from `ERROR_STATUS` is answered 503
    outside the published code enum, so a raise of it would be silent; this finds one."""
    offenders = []
    for path in sorted((ROOT / "src").rglob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                callee = node.func
                name = callee.id if isinstance(callee, ast.Name) else getattr(callee, "attr", "")
                arguments = [*node.args, *(keyword.value for keyword in node.keywords)]
                busy = any(
                    isinstance(a, ast.Constant) and a.value == "RESOURCE_BUSY" for a in arguments
                )
                if busy and (name.endswith("Error") or name == "RateLimited"):
                    offenders.append(f"{path.relative_to(ROOT)}:{node.lineno} raises it")
            if isinstance(node, ast.Dict):
                for key, value in zip(node.keys, node.values, strict=True):
                    if (
                        isinstance(key, ast.Constant)
                        and key.value == "RESOURCE_BUSY"
                        and isinstance(value, ast.Constant)
                        and type(value.value) is int
                    ):
                        offenders.append(f"{path.relative_to(ROOT)}:{node.lineno} maps it")
    assert offenders == []
    assert "RESOURCE_BUSY" not in ERROR_STATUS
