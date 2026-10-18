# SPDX-License-Identifier: AGPL-3.0-only
"""Denial categories and refusal causes, DN4 to DN10 (#545).

An agent is told a denial's state, its reference and one of three categories. `busy` says
another request holds the target and `limit` says a shared limit covering the request is
spent, whatever else was recorded beside it (the product decision of September 28, 2026), so
`limit` carries no per-target policy verdict; every other denial is `withheld`, and nothing
names the rule, the limit, its window, a count, a fact or the other execution. The category is
read from the recorded DENIED transition, so the first answer, a re-send and a status read
agree byte for byte (`docs/THREAT_MODEL.md` T1.16).

A request refused before any plan was frozen now audits its own cause (`INVALID_OPERATION`,
`INVALID_TARGET`, `INVALID_CONTEXT` and the rest) instead of the generic
`DEPENDENCY_OR_CONTEXT_UNAVAILABLE`, and the agent's answer does not change at all. The
board, which reads those refusals for people, now reads the code where the audit writes it, and
words and counts a denial by a limit by the rule that tells its agent `limit`.

Real PostgreSQL, the live endpoint provider, the HTTP routes through the application and MCP
over a real Streamable HTTP server.
"""

import ast
import json
import re
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace
from typing import Any, cast, get_args
from uuid import UUID, uuid4

import httpx
import pytest
from console_api_fixtures import API, console_client
from execbound_client import ExecBoundClient, Outcome, execbound_action, summarize
from scope_fixtures import agent, audit_payloads, rule, scoped_bundle, transition_payload
from sqlalchemy import event, text
from sqlalchemy.exc import OperationalError
from test_denial_notice import body, development, domain_controller, mcp_call
from test_execution import registry as registry
from test_execution import request, targets
from test_execution import world as world
from test_mcp_surface import gateway as gateway
from test_protected_path import connector as connector
from test_protected_path import live_provider as live_provider
from test_runtime import api as api
from test_runtime import runtime as runtime

from execbound.db import Database
from execbound.execution import (
    admission,
    admit,
    approvals,
    decide_approval,
    set_enforcement_mode,
    store,
)
from execbound.execution.models import (
    DenialCategory,
    ExecutionError,
    ExecutionState,
    ExecutionView,
)
from execbound.getting_started import progress
from execbound.provider.gateway import dispatch_owned
from execbound.resolution.registry import RESOLUTION_CODES, ResolutionError
from execbound.runtime import Runtime, denial_notice
from execbound.surfaces import board
from execbound.surfaces.agent_api_guide import STATES
from execbound.surfaces.agent_openapi import agent_api_document
from execbound.surfaces.console_api import board as console_board

ROOT = Path(__file__).resolve().parents[1]

# Pinned as words, as DN1 pins the withheld sentence, so a change to what a denied agent is
# told is a change here too.
NOTICES: dict[str, str] = {
    "busy": (
        "Denied because another request holds this target. Re-sending this request returns "
        "this same answer; a new request after that one settles may be decided differently. "
        "A person can find it by searching the console for {reference}."
    ),
    "limit": (
        "Denied because a shared limit is spent. Re-sending this request returns this same "
        "answer; a new request after the limit resets is decided afresh. A person can find it "
        "by searching the console for {reference}."
    ),
    "withheld": (
        "Denied. The reason is recorded for a person, who can find it by searching the console "
        "for {reference}. Re-sending this request returns this same answer."
    ),
}
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
# What no denied answer may carry, whatever its category: the recorded codes, the rule id, the
# limit's name and the fact a deny rule read.
NEVER = ("NOT_AUTHORIZED", "HARD_LIMIT", "RESOURCE_BUSY", "isolation-budget", "domain_controller")
# The one answer every refusal before a plan gets, whatever its cause.
UNAVAILABLE = b'{"detail":"Execution unavailable","code":"EXECUTION_UNAVAILABLE"}'


def codes(payload):
    """A transition's recorded codes, under either key the kernel writes them with."""
    if isinstance(payload.get("reasons"), list):
        return list(payload["reasons"])
    return [payload["reason"]] if payload.get("reason") else []


def assert_categorized(payload, category, others=()):
    """A denied answer: the view, the category and its sentence, and nothing of the detail."""
    assert payload["state"] == "DENIED"
    assert set(payload) == DENIED_MEMBERS
    assert payload["denial"] == category
    assert payload["notice"] == NOTICES[category].format(reference=payload["request_ref"])
    wire = json.dumps(payload)
    for leaked in NEVER:
        assert leaked not in wire, leaked
    for other in others:
        # Another execution's id or reference, matched whole so EB-1 is not found in EB-12.
        assert not re.search(rf"(?<![\w-]){re.escape(str(other))}(?![\w-])", wire), other


def spend(api, db, world, admin_engine, rule_id="isolation-budget"):
    """Spend a principal budget of one: the world's own target executes over HTTP."""
    scoped_bundle(db, world, rule(rule_id=rule_id, max_targets=1, on_exceed="DENY"))
    development(admin_engine, world)
    executed = api.post("/v1/execute", json=body(request(world, idempotency_key="spend")))
    assert executed.status_code == 200 and executed.json()["state"] == "EXECUTED", executed.text


@pytest.mark.parametrize("first", ["http", "mcp"])
@pytest.mark.parametrize(
    ("case", "category", "recorded"),
    [
        ("busy", "busy", ["RESOURCE_BUSY"]),
        ("limit", "limit", ["HARD_LIMIT:isolation-budget"]),
        ("mixed", "limit", ["HARD_LIMIT:isolation-budget", "NOT_AUTHORIZED"]),
        ("policy", "withheld", ["NOT_AUTHORIZED"]),
    ],
)
def test_dn4_a_denial_names_its_category_and_nothing_more(
    case,
    category,
    recorded,
    first,
    api,
    gateway,
    db,
    world,
    seeded,
    admin_engine,
    connector,
    live_provider,
):
    tenant, token = world["identity"].tenant_id, seeded["tokens"][0]
    others: list[Any] = []
    holding = None
    if case == "busy":
        # Another agent holds the world's own target: admitted and committed, never
        # dispatched, so its canonical claim is live when this agent asks for the same target.
        development(admin_engine, world)
        holding = admit(
            db,
            agent(admin_engine, db, world),
            request(world, idempotency_key="holder"),
            world["clock"],
        )
        assert holding.view.state == "DISPATCH_COMMITTED" and holding.ticket is not None
        others = [holding.view.execution_id, holding.view.request_ref]
        wire = body(request(world))
    elif case == "limit":
        spend(api, db, world, admin_engine)
        [second] = targets(admin_engine, world, 1)
        wire = body(second)
    elif case == "mixed":
        # A deny rule and a spent limit together are `limit`, exactly as the limit alone is:
        # the agent is told nothing of whether the policy would allow this target.
        spend(api, db, world, admin_engine)
        [tier_zero] = targets(admin_engine, world, 1)
        domain_controller(admin_engine, tier_zero)
        wire = body(tier_zero)
    else:
        [tier_zero] = targets(admin_engine, world, 1)
        domain_controller(admin_engine, tier_zero)
        wire = body(tier_zero)

    if first == "http":
        answer = api.post("/v1/execute", json=wire)
        assert answer.status_code == 200, answer.text
        payload, raw = answer.json(), answer.content
    else:
        payload, raw = mcp_call(gateway, token, "execute", {"request": wire}), None
    # The kernel's own record is what the category is read from.
    assert codes(transition_payload(admin_engine, tenant, payload["execution_id"], "DENIED")) == (
        recorded
    )
    assert_categorized(payload, category, others)

    def agree():
        """A re-send and a status read, on both surfaces, answer exactly the first answer."""
        execution = payload["execution_id"]
        resent = api.post("/v1/execute", json=wire)
        status = api.get("/v1/executions/" + execution)
        assert resent.status_code == status.status_code == 200
        assert resent.content == status.content
        if raw is not None:
            assert resent.content == raw
        assert resent.json() == payload
        assert mcp_call(gateway, token, "execute", {"request": wire}) == payload
        assert mcp_call(gateway, token, "execution_status", {"execution_id": execution}) == (
            payload
        )

    agree()
    if holding is not None:
        # The holder settles and its claim is released. The recorded answer does not move:
        # a re-send and a status read still say busy, because the category is the record's.
        settled = dispatch_owned(db, holding.ticket, connector, world["clock"])
        assert settled.state == "EXECUTED"
        with admin_engine.connect() as conn:
            live = conn.execute(
                text(
                    "SELECT count(*) FROM execbound.resource_claims "
                    "WHERE tenant_id=:t AND released_at IS NULL"
                ),
                {"t": tenant},
            ).scalar_one()
        assert live == 0
        agree()
        # What the notice promises: a new request after that one settles is decided afresh.
        fresh = api.post("/v1/execute", json=body(request(world, idempotency_key="after")))
        assert fresh.json()["state"] != "DENIED", fresh.text


def test_dn4_a_reviewers_refusal_and_the_clients_summary_carry_the_category(
    api, gateway, db, world, seeded, admin_engine, live_provider
):
    """A person's refusal is withheld like any other; the client's summary relays the
    category beside the notice, and nothing of why."""
    token = seeded["tokens"][0]
    pending = api.post("/v1/execute", json=body(request(world)))
    assert pending.status_code == 202, pending.text
    decide_approval(
        db,
        world["human"],
        UUID(pending.json()["approval_id"]),
        "DENY",
        world["clock"],
        comment="Refused-9d2e: keep it up",
    )
    refused = api.get("/v1/executions/" + pending.json()["execution_id"]).json()
    assert refused["approval_state"] == "DENIED"
    assert_categorized(refused, "withheld")
    assert "Refused-9d2e" not in json.dumps(refused)
    assert mcp_call(gateway, token, "execute", {"request": body(request(world))}) == refused

    spend(api, db, world, admin_engine, rule_id="isolation-budget")
    [second] = targets(admin_engine, world, 1)
    third = body(second)
    client = ExecBoundClient("http://testserver", token, client=api)
    summary = json.loads(
        execbound_action(
            client,
            third["operation_ref"],
            third["target"]["kind"],
            third["target"]["value"],
            "client-limit",
            incident_id=third["claimed_context"]["incident_id"],
        )
    )
    assert summary["state"] == "DENIED" and summary["denial"] == "limit"
    assert summary["notice"] == NOTICES["limit"].format(reference=summary["request_ref"])
    assert "isolation-budget" not in json.dumps(summary)


def test_dn4_under_a_spent_limit_an_allowed_and_a_forbidden_target_answer_alike(
    api, db, world, admin_engine, live_provider
):
    """That decision, in the agent's own terms: once a limit that is not scoped by a
    target's facts is spent, a target the policy allows and a target a rule forbids get the
    same answer, so the category is no per-target probe of the policy."""
    tenant = world["identity"].tenant_id
    spend(api, db, world, admin_engine)
    allowed, forbidden = targets(admin_engine, world, 2)
    domain_controller(admin_engine, forbidden)
    answers = [api.post("/v1/execute", json=body(wire)) for wire in (allowed, forbidden)]
    recorded = [
        codes(transition_payload(admin_engine, tenant, answer.json()["execution_id"], "DENIED"))
        for answer in answers
    ]
    assert recorded == [
        ["HARD_LIMIT:isolation-budget"],
        ["HARD_LIMIT:isolation-budget", "NOT_AUTHORIZED"],
    ]

    def without_identifiers(answer):
        payload = answer.json()
        own = {"execution_id", "plan_hash", "request_ref", "notice"}
        shown = {key: value for key, value in payload.items() if key not in own}
        return shown, payload["notice"].replace(payload["request_ref"], "EB-n")

    assert without_identifiers(answers[0]) == without_identifiers(answers[1])
    assert all(answer.json()["denial"] == "limit" for answer in answers)


@pytest.mark.parametrize("state", get_args(ExecutionState))
def test_dn5_the_presenter_adds_a_category_to_a_denial_and_to_no_other_state(state):
    """Every state the model has, with no keys and no database: a denial gains its category
    and sentence, a denial with no recorded category is withheld, and every other view is
    answered exactly as serialized."""
    runtime = Runtime(cast(Database, SimpleNamespace(capacity=1)), [])
    if state != "DENIED":
        view = ExecutionView(
            request_ref="EB-7", execution_id=uuid4(), state=state, plan_hash="a" * 64
        )
        payload = runtime.present(cast(Any, None), view)
        assert "notice" not in payload and "denial" not in payload
        assert payload == view.model_dump(mode="json")
        # A category can only ever sit on a denial.
        with pytest.raises(ValueError):
            ExecutionView(execution_id=uuid4(), state=state, plan_hash="a" * 64, denial="withheld")
        return
    categories: tuple[DenialCategory | None, ...] = (*get_args(DenialCategory), None)
    for category in categories:
        view = ExecutionView(
            request_ref="EB-7",
            execution_id=uuid4(),
            state="DENIED",
            plan_hash="a" * 64,
            denial=category,
        )
        # The category is excluded from the view's own serialization, as `observed` is.
        assert "denial" not in view.model_dump(mode="json")
        shown = category or "withheld"
        assert runtime.present(cast(Any, None), view) == {
            **view.model_dump(mode="json"),
            "denial": shown,
            "notice": NOTICES[shown].format(reference="EB-7"),
        }


@pytest.mark.parametrize(
    ("recorded", "category"),
    [
        ({"reason": "RESOURCE_BUSY"}, "busy"),
        ({"reasons": ["HARD_LIMIT:isolation-budget"]}, "limit"),
        ({"reasons": ["HARD_LIMIT:isolation-budget", "HARD_LIMIT:tenant-total"]}, "limit"),
        ({"reasons": ["HARD_LIMIT:isolation-budget", "NOT_AUTHORIZED"]}, "limit"),
        ({"reasons": ["HARD_LIMIT:tenant-total", "INVALID_CONTEXT"]}, "limit"),
        ({"reasons": ["HARD_LIMIT:tenant-total", "INVALID_USAGE"]}, "limit"),
        ({"reasons": ["HARD_LIMIT:tenant-total", "NOT_AUTHORIZED", "POLICY_ERROR"]}, "limit"),
        ({"reasons": ["NOT_AUTHORIZED"]}, "withheld"),
        ({"reasons": ["RESOURCE_BUSY", "NOT_AUTHORIZED"]}, "withheld"),
        ({"reason": "HUMAN_DENIED"}, "withheld"),
        ({"reasons": []}, "withheld"),
        ({}, "withheld"),
    ],
)
def test_dn6_the_category_is_limit_for_any_recorded_limit_and_busy_only_alone(recorded, category):
    """`limit` for any recorded limit, whatever sits beside it, and `busy` for the busy reason
    alone; everything else is withheld, and each sentence names none of it."""
    assert store.denial_category(recorded) == category
    sentence = denial_notice("EB-12", category)
    assert sentence == NOTICES[category].format(reference="EB-12")
    for code in codes(recorded):
        for part in (code, *code.split(":")):
            assert part not in sentence, part
    # The fallback without a reference keeps the first shipment's pattern.
    assert "EB-" not in denial_notice(None, category)
    assert "in the console" in denial_notice(None, category)


def test_dn7_the_guide_and_schema_document_the_three_categories():
    document = agent_api_document()
    guide = document["info"]["description"]
    for category in get_args(DenialCategory):
        assert f"`{category}`" in guide
        assert json.dumps(denial_notice("EB-12", category)) in guide
    assert "another request holds the target" in guide
    assert "a shared limit is spent" in guide
    assert "never names the rule" in guide
    # The decision: a limit is reported whatever else denied the request.
    assert "whenever a spent limit is among the recorded reasons, whatever else is" in guide
    assert "may be decided differently" not in NOTICES["limit"]
    [denied] = [row for row in STATES if row[0] == "DENIED"]
    assert "`busy` or `limit`" in denied[2] and "the limit resets is decided afresh" in denied[2]
    assert "Re-sending the same request returns the same answer" in denied[2]
    assert "`request_ref`" in denied[2]
    member = document["components"]["schemas"]["ExecutionView"]["properties"]["denial"]
    assert member["type"] == "string"
    assert member["enum"] == list(get_args(DenialCategory))
    assert member["description"].startswith("Present only on a DENIED execution")


def refused_by_admission(admin_engine, tenant):
    return [
        payload
        for payload in audit_payloads(admin_engine, tenant, "execution.rejected")
        if payload["operation"] == "admit"
    ]


def mcp_refusal(gateway, token, wire):
    """One `execute` over the real transport that the gateway refuses; the refusal itself."""
    rpc = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {
            "_meta": {
                "io.modelcontextprotocol/protocolVersion": "2026-07-28",
                "io.modelcontextprotocol/clientCapabilities": {},
            },
            "name": "execute",
            "arguments": {"request": wire},
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
            "MCP-Name": "execute",
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
    assert result["isError"] is True
    [content] = result["content"]
    return content["text"]


def test_dn8_a_refusal_before_any_plan_audits_its_own_cause_and_answers_as_before(
    api, gateway, db, world, seeded, admin_engine, live_provider
):
    tenant, token = world["identity"].tenant_id, seeded["tokens"][0]
    # A real target with an incident of its own, asked for under the world's incident.
    [elsewhere] = targets(admin_engine, world, 1)
    claimed = body(elsewhere)
    claimed["claimed_context"] = {"incident_id": str(world["incident"])}
    cases = [
        (
            "an unknown action",
            body(request(world, operation_ref="nothing.mapped")),
            "INVALID_OPERATION",
        ),
        (
            "an unknown canonical target",
            body(request(world, target={"kind": "canonical", "value": str(uuid4())})),
            "INVALID_TARGET",
        ),
        (
            "an unknown hostname",
            body(request(world, target={"kind": "hostname", "value": "ghost.example"})),
            "INVALID_TARGET",
        ),
        ("an incident the inventory does not hold on the target", claimed, "INVALID_CONTEXT"),
        (
            "a run the agent was never issued",
            body(request(world, run_id=str(uuid4()))),
            "INVALID_RUN",
        ),
    ]
    told = set()
    for label, wire, cause in cases:
        before = len(refused_by_admission(admin_engine, tenant))
        answered = api.post("/v1/execute", json=wire)
        # The agent's answer is the bytes it always was, whatever the cause.
        assert answered.status_code == 503, label
        assert answered.content == UNAVAILABLE, label
        told.add(mcp_refusal(gateway, token, wire))
        recorded = refused_by_admission(admin_engine, tenant)[before:]
        # One per surface, each exactly the operation and the cause: no caller string.
        assert recorded == [{"operation": "admit", "reason": cause}] * 2, label
    # Over MCP too, one refusal for every cause, and the same one HTTP gives.
    [text_answer] = told
    assert json.loads(text_answer) == json.loads(UNAVAILABLE)
    # Last, because it moves the clock: the trusted facts are no longer fresh.
    world["clock"].value += timedelta(seconds=301)
    before = len(refused_by_admission(admin_engine, tenant))
    stale = api.post("/v1/execute", json=body(request(world, idempotency_key="stale")))
    assert stale.status_code == 503 and stale.content == UNAVAILABLE
    assert refused_by_admission(admin_engine, tenant)[before:] == [
        {"operation": "admit", "reason": "INVALID_CONTEXT"}
    ]


def test_dn8_every_refusal_after_the_mapping_costs_the_same_statements(db, world, admin_engine):
    """The audit's cause is read from the coherent statement's own row, so no cause costs a
    round trip another does not: a known target under the wrong incident and an unknown
    target run exactly the same statements, in the same order. An operation the space does
    not offer is refused earlier still, before the mapping read, and every such operation
    costs the same statements (LA3). Also: an ambiguous alias is `INVALID_TARGET`, and a
    target that resolves with a live run but no single coherent row falls through to
    `INVALID_CONTEXT`."""
    tenant = world["identity"].tenant_id
    [elsewhere] = targets(admin_engine, world, 1)
    with admin_engine.begin() as conn:
        # Two live hostname aliases for one name: ambiguous, whichever resource each names.
        for resource in (world["target"], world["other"]):
            conn.execute(
                text(
                    "INSERT INTO execbound.resource_aliases (tenant_id, alias_id, account_id, "
                    "provider, resource_type, kind, normalized_value, resource_id, valid_from, "
                    "expires_at) VALUES (:t, :a, :account, 'mock_crowdstrike', 'endpoint', "
                    "'hostname', 'twin.example', :r, :start, :end)"
                ),
                {
                    "t": tenant,
                    "a": uuid4(),
                    "account": world["account"],
                    "r": resource,
                    "start": world["clock"].now() - timedelta(days=1),
                    "end": world["clock"].now() + timedelta(days=1),
                },
            )
    cases = {
        "a known target under another target's incident": (
            request(
                world,
                target={"kind": "canonical", "value": elsewhere.target.value},
                claimed_context={"incident_id": str(world["incident"])},
            ),
            "INVALID_CONTEXT",
        ),
        "an unknown canonical target": (
            request(world, target={"kind": "canonical", "value": str(uuid4())}),
            "INVALID_TARGET",
        ),
        "an unknown hostname": (
            request(world, target={"kind": "hostname", "value": "ghost.example"}),
            "INVALID_TARGET",
        ),
        "an ambiguous hostname": (
            request(world, target={"kind": "hostname", "value": "twin.example"}),
            "INVALID_TARGET",
        ),
        "a run the agent was never issued": (request(world, run_id=str(uuid4())), "INVALID_RUN"),
        # The registry's second resource is active in the mapping's account but has no
        # canonical identity row, so the coherent statement has no row for it.
        "a resolved target with no coherent row": (
            request(world, target={"kind": "canonical", "value": str(world["other"])}),
            "INVALID_CONTEXT",
        ),
    }
    costs = {}
    statements: list[str] = []

    def counted(conn, cursor, statement, parameters, context, executemany):
        statements.append(statement)

    for label, (wire, cause) in cases.items():
        statements.clear()
        before = len(refused_by_admission(admin_engine, tenant))
        event.listen(db.engine, "before_cursor_execute", counted)
        try:
            with pytest.raises(ExecutionError) as refused:
                admit(db, world["identity"], wire, world["clock"])
        finally:
            event.remove(db.engine, "before_cursor_execute", counted)
        assert refused.value.code == "EXECUTION_UNAVAILABLE", label
        assert refused_by_admission(admin_engine, tenant)[before:] == [
            {"operation": "admit", "reason": cause}
        ], label
        costs[label] = tuple(statements)
    assert len({len(cost) for cost in costs.values()}) == 1, {k: len(v) for k, v in costs.items()}
    assert len(set(costs.values())) == 1


@pytest.mark.parametrize(
    "failure",
    [
        OperationalError("SELECT 1", {}, Exception("connection reset")),
        ValueError("unexpected"),
        # A code outside the closed list is never recorded as given, whatever carried it.
        ResolutionError("caller-chosen text"),
    ],
)
def test_dn8_a_dependency_failure_or_an_unlisted_code_keeps_the_generic_reason(
    failure, api, world, admin_engine, monkeypatch, live_provider
):
    tenant = world["identity"].tenant_id

    def broken(*args, **kwargs):
        raise failure

    monkeypatch.setattr(admission, "resolve_snapshot", broken)
    answered = api.post("/v1/execute", json=body(request(world)))
    assert answered.status_code == 503 and answered.content == UNAVAILABLE
    assert refused_by_admission(admin_engine, tenant) == [
        {"operation": "admit", "reason": "DEPENDENCY_OR_CONTEXT_UNAVAILABLE"}
    ]


@pytest.mark.parametrize(
    ("code", "recorded"),
    [
        ("STALE_AUTHORIZATION", "STALE_AUTHORIZATION"),
        # Outside the closed list, the reviewer path keeps its own generic reason, as it did
        # before #545, rather than admission's.
        ("caller-chosen text", "DEPENDENCY_UNAVAILABLE"),
    ],
)
def test_dn8_a_reviewers_decision_that_fails_reattestation_audits_its_cause(
    code, recorded, db, world, admin_engine, monkeypatch, live_provider
):
    """The human path follows the same rule: a resolution failure after the decision is
    recorded as its own code, and the reviewer's answer is the generic refusal it was."""
    tenant = world["identity"].tenant_id
    pending = admit(db, world["identity"], request(world), world["clock"])
    assert pending.view.state == "PENDING_APPROVAL"
    attest = approvals.attest_snapshot
    calls = []

    def drifted(*args, **kwargs):
        # The review's first attestation holds; the recheck after the decision does not.
        calls.append(1)
        if len(calls) > 1:
            raise ResolutionError(code)
        return attest(*args, **kwargs)

    monkeypatch.setattr(approvals, "attest_snapshot", drifted)
    with pytest.raises(ExecutionError) as refused:
        decide_approval(db, world["human"], pending.view.approval_id, "APPROVE", world["clock"])
    assert refused.value.code == "EXECUTION_UNAVAILABLE"
    decided = [
        payload
        for payload in audit_payloads(admin_engine, tenant, "execution.rejected")
        if payload["operation"] == "decide_approval"
    ]
    assert decided == [{"operation": "decide_approval", "reason": recorded}]


def test_dn9_every_resolution_code_the_kernel_raises_is_one_the_audit_records():
    """The audit records a resolution failure's own code only from a closed list, so no
    string a caller sent can ever become a reason; this finds a code raised outside it. The
    one code not written as a literal is the snapshot's refusal-path classification, whose
    own literals are read instead."""
    raised = set()
    for path in sorted((ROOT / "src").rglob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            if isinstance(node, ast.FunctionDef) and node.name == "_unresolved":
                raised |= {
                    returned.value.value
                    for returned in ast.walk(node)
                    if isinstance(returned, ast.Return) and isinstance(returned.value, ast.Constant)
                }
            if (
                isinstance(node, ast.Call)
                and isinstance(node.func, ast.Name)
                and node.func.id == "ResolutionError"
            ):
                if not node.args:
                    raised.add(ResolutionError().code)
                    continue
                [argument] = node.args
                if isinstance(argument, ast.Call):
                    # Only the classification, which returns a code it read from a refusal
                    # `registry.resource` raised or one of its own literals.
                    assert getattr(argument.func, "id", None) == "_unresolved", (
                        f"{path}:{node.lineno}"
                    )
                    continue
                assert isinstance(argument, ast.Constant), f"{path}:{node.lineno}"
                raised.add(argument.value)
    assert {"INVALID_RUN", "INVALID_CONTEXT", "INVALID_TARGET", "INVALID_OPERATION"} <= raised
    assert raised <= RESOLUTION_CODES, raised - RESOLUTION_CODES
    assert "DEPENDENCY_OR_CONTEXT_UNAVAILABLE" not in RESOLUTION_CODES


def test_dn10_the_board_reads_a_refusals_cause_where_the_audit_writes_it(
    db, world, seeded, admin_engine, api, gateway, live_provider
):
    """The board's refusal entries carry the recorded code. Its reader selected a key the
    audit never wrote, so every refusal on the board had an empty cause. It also read every
    `execution.rejected` event as a request refused before a decision, so a reviewer's, an
    administrator's and a surface's refusals were drawn as agent requests, and an MCP
    refusal, which writes a `surface` event beside admission's, was counted twice."""
    tenant, token = world["identity"].tenant_id, seeded["tokens"][0]
    for wire in (
        body(request(world, operation_ref="nothing.mapped")),
        body(request(world, target={"kind": "canonical", "value": str(uuid4())})),
    ):
        assert api.post("/v1/execute", json=wire).status_code == 503
    # Over MCP: one admission refusal and one surface refusal for the same request.
    mcp_refusal(
        gateway, token, body(request(world, target={"kind": "hostname", "value": "x.test"}))
    )
    # Refusals that are not an agent's request being refused before a decision.
    with pytest.raises(ExecutionError):
        decide_approval(db, world["human"], uuid4(), "APPROVE", world["clock"])
    with pytest.raises(ExecutionError):
        set_enforcement_mode(db, world["admin"], "SOMETIMES", "Not a mode", world["clock"])
    malformed = api.post("/v1/execute", content=b"{}", headers={"Content-Type": "text/plain"})
    assert malformed.status_code == 400
    operations = {
        payload["operation"]
        for payload in audit_payloads(admin_engine, tenant, "execution.rejected")
    }
    # Each kind of refusal the board must leave out was really recorded, so its absence below
    # is the reader's filter and not a refusal that never happened.
    assert {"admit", "surface", "decide_approval", "set_enforcement_mode"} <= operations
    now = datetime.now(UTC) + timedelta(seconds=5)
    with db.transaction(tenant, snapshot=True) as conn:
        read = board.read(conn, tenant, world["admin"].principal_id, False, now)
    short = [shot for shot in read.shots if shot.phase == "short"]
    assert sorted(shot.detail for shot in short) == [
        "INVALID_OPERATION",
        "INVALID_TARGET",
        "INVALID_TARGET",
    ]
    assert all(shot.word == "refused before a decision" for shot in short)
    # The window's "refused before a decision" figure is the same three.
    assert console_board.view(read, now).window.refused == 3


def test_dn10_the_board_words_and_counts_a_denial_by_a_limit_as_the_agent_is_told(
    api, db, runtime, world, admin_engine, live_provider
):
    """The board's `limit` word and its "by a limit" figure read a denial's recorded codes by
    the rule the agent's category is read by, `store.denial_category`. Their reader selected
    the singular `reason` and looked for `limit:`, which is an approval obligation's prefix and
    no denial's, while the policy records a spent limit under `reasons` as
    `HARD_LIMIT:<rule id>`: neither the word nor the figure ever fired."""
    tenant = world["identity"].tenant_id
    # A rule's denial with no limit beside it, recorded before any limit exists.
    [ruled] = targets(admin_engine, world, 1)
    domain_controller(admin_engine, ruled)
    plain = api.post("/v1/execute", json=body(ruled))
    assert plain.status_code == 200, plain.text
    spend(api, db, world, admin_engine)
    limited, mixed = targets(admin_engine, world, 2)
    domain_controller(admin_engine, mixed)
    denied = [plain.json()] + [
        api.post("/v1/execute", json=body(wire)).json() for wire in (limited, mixed)
    ]
    assert [
        codes(transition_payload(admin_engine, tenant, answer["execution_id"], "DENIED"))
        for answer in denied
    ] == [
        ["NOT_AUTHORIZED"],
        ["HARD_LIMIT:isolation-budget"],
        ["HARD_LIMIT:isolation-budget", "NOT_AUTHORIZED"],
    ]
    assert [answer["denial"] for answer in denied] == ["withheld", "limit", "limit"]

    now = datetime.now(UTC) + timedelta(seconds=5)
    with db.transaction(tenant, snapshot=True) as conn:
        read = board.read(conn, tenant, world["admin"].principal_id, False, now)
    words = {str(shot.execution_id): shot.word for shot in read.shots}
    assert [words[answer["execution_id"]] for answer in denied] == ["denied", "limit", "limit"]
    assert read.window_limited == 2
    window = console_board.view(read, now).window
    assert (window.denied, window.limited) == (3, 2)
    assert console_board.view(read, now).today.limited is None

    # The console's own route carries the same words and the same figure.
    with console_client(db, runtime, admin_engine, world["admin"]) as person:
        response = person.get(API + "/board")
    assert response.status_code == 200, response.text
    snapshot = response.json()
    words = {shot["execution_id"]: shot["word"] for shot in snapshot["shots"]}
    assert [words[answer["execution_id"]] for answer in denied] == ["denied", "limit", "limit"]
    assert (snapshot["window"]["denied"], snapshot["window"]["limited"]) == (3, 2)


def test_dn10_getting_started_counts_a_claim_refused_under_either_code(db, seeded):
    """The welcome page's "claim refused" step: the specific code a claim refusal now records,
    and the generic code it recorded before, which history keeps. An unknown action is not a
    refused claim."""
    from execbound.audit import append_event

    tenant, actor = seeded["tenants"][0], seeded["principals"][0]
    with db.transaction(tenant) as conn:
        for reason in ("INVALID_OPERATION", "INVALID_TARGET"):
            append_event(
                conn, tenant, actor, "execution.rejected", {"operation": "admit", "reason": reason}
            )
        assert progress(conn, tenant)["claim_refused"] is None
        append_event(
            conn,
            tenant,
            actor,
            "execution.rejected",
            {"operation": "admit", "reason": "INVALID_CONTEXT"},
        )
        assert progress(conn, tenant)["claim_refused"] is not None
    with db.transaction(seeded["tenants"][1]) as conn:
        append_event(
            conn,
            seeded["tenants"][1],
            seeded["principals"][1],
            "execution.rejected",
            {"operation": "admit", "reason": "DEPENDENCY_OR_CONTEXT_UNAVAILABLE"},
        )
        assert progress(conn, seeded["tenants"][1])["claim_refused"] is not None


def test_dn10_the_client_summary_passes_only_a_known_category():
    """The client hands a model the category a denial carries and nothing it does not know."""
    for category, kept in (("busy", True), ("limit", True), ("withheld", True), ("x", False)):
        outcome = Outcome(
            {
                "request_ref": "EB-3",
                "execution_id": str(uuid4()),
                "state": "DENIED",
                "plan_hash": "a" * 64,
                "denial": category,
                "notice": "n",
            }
        )
        summary = summarize(outcome)
        assert ("denial" in summary) is kept
        if kept:
            assert summary["denial"] == category
