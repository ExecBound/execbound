# SPDX-License-Identifier: AGPL-3.0-only
"""Secret-shaped text a caller writes never reaches the tenant's audit chain.

The audit export refuses a window holding an event the secret check flags, and a refused
window fails the destination's cursor for good: `export-resume` reads the same event again.
So text an agent, a control point or a model writes into an audit payload must never be
able to look like a secret, or one request would stop the tenant's export permanently.
The values below are synthetic, and each is one shape `execbound.secrets` recognises.
"""

import json

import pytest
from arcade_fixtures import GOVERNED_TOOL, arcade_client, post, pre
from arcade_fixtures import arcade_world as arcade_world
from checkpoint_fixtures import audit_kinds
from checkpoint_fixtures import owner as owner
from sqlalchemy import text
from test_assistant_rules import BLOCK, WORDS, draft, proposal, script, session_of
from test_assistant_rules import configured as configured
from test_event_export import cursor, destination
from test_execution import registry as registry
from test_execution import world as world
from test_monitoring_worker import receiver as receiver
from test_protected_path import connector as connector
from test_protected_path import live_provider as live_provider
from test_resolution import request
from test_runtime import api as api
from test_runtime import runtime as runtime

from execbound.assistant.proposals import ProposalError, propose_rule
from execbound.export import export_events
from execbound.secrets import find_secrets

STRIPE = "sk_live_51ABCdefGHIjklMNOpqrSTU"
JWT = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.dBjftJeZ4CVPmB92K27uhbUJU1p1r_wW1gFWFOEjXk"
AGENT_TOKEN = "eb1.3f2504e0-4f89-11d3-9a0c-0305e82c3301.5a1a2b3c-4d5e-6f70-8192-a3b4c5d6e7f8.x"
BEARER = "Bearer abc12345x"
SLACK = "https://hooks.slack.com/services/T00000000/B00000000/XXXXXXXXXXXXXXXX"
CASE = {"source": "tines", "case_id": "INC-4821"}


def chain(admin_engine, tenant):
    """The tenant's audit payloads as stored text. The engine bypasses row security, so the
    tenant is named in the statement rather than trusted to a fence."""
    with admin_engine.connect() as conn:
        return [
            row[0]
            for row in conn.execute(
                text(
                    "SELECT payload::text FROM execbound.audit_events "
                    "WHERE tenant_id=:t ORDER BY sequence"
                ),
                {"t": tenant},
            )
        ]


def exports(db, world, admin_engine, receiver):
    """Export the tenant's whole chain in one pass and answer the destination's state and
    recorded error. An active cursor with lag left would prove nothing about the rest."""
    targets = [destination(world, receiver, "siem")]
    result = export_events(db, world["admin"], targets, limit=1000, clock=world["clock"])
    row = cursor(admin_engine, world["identity"].tenant_id, "siem")
    if result["siem"]["state"] == "ACTIVE":
        assert result["siem"]["lag"] == 0
    return result["siem"]["state"], row["last_error"]


@pytest.mark.parametrize(
    "case",
    [
        {**CASE, "case_id": STRIPE},
        {**CASE, "case_id": JWT[:80]},
        {**CASE, "case_id": AGENT_TOKEN},
        {**CASE, "case_id": BEARER},
        {**CASE, "source": STRIPE.lower()},
        {**CASE, "url": SLACK},
        {**CASE, "url": "https://lab.tines.com/cases/" + STRIPE},
    ],
    ids=["case-stripe", "case-jwt", "case-agent-token", "case-bearer", "source", "url", "path"],
)
def test_secret_shaped_case_text_is_refused_and_the_export_carries_on(
    api, db, world, admin_engine, receiver, case
):
    # The case fields admit each of these on their own: what refuses them is the screen.
    assert find_secrets(case, limit=1)
    tenant = world["identity"].tenant_id
    malformed = api.post("/v1/execute", json={})
    before = chain(admin_engine, tenant)
    answer = api.post(
        "/v1/execute", json=request(world, external_case=case).model_dump(mode="json")
    )
    # Answered as a body that is not a request at all is answered, and quoting nothing.
    assert (answer.status_code, answer.json()) == (400, malformed.json())
    for value in case.values():
        assert value not in answer.text
    with admin_engine.connect() as conn:
        count = conn.execute(
            text("SELECT count(*) FROM execbound.executions WHERE tenant_id=:t"), {"t": tenant}
        ).scalar_one()
    assert count == 0
    # The refusal is audited as every refused request is: by its reason and nothing else.
    added = chain(admin_engine, tenant)[len(before) :]
    assert [json.loads(payload)["reason"] for payload in added] == ["INVALID_REQUEST"]
    assert not any(find_secrets(json.loads(payload), limit=1) for payload in added)
    assert exports(db, world, admin_engine, receiver) == ("ACTIVE", None)


def test_a_retry_carrying_secret_shaped_case_text_is_refused_and_the_first_case_stands(
    api, db, world, admin_engine, receiver
):
    first = api.post("/v1/execute", json=request(world, external_case=CASE).model_dump(mode="json"))
    assert first.status_code == 202
    retry = request(world, external_case={**CASE, "case_id": STRIPE}).model_dump(mode="json")
    answer = api.post("/v1/execute", json=retry)
    assert (answer.status_code, answer.json()["code"]) == (400, "INVALID_REQUEST")
    with admin_engine.connect() as conn:
        frozen = conn.execute(
            text("SELECT frozen FROM execbound.executions WHERE tenant_id=:t"),
            {"t": world["identity"].tenant_id},
        ).scalar_one()
    assert frozen["request"]["external_case"] == {**CASE, "url": None}
    assert exports(db, world, admin_engine, receiver) == ("ACTIVE", None)


@pytest.mark.parametrize(
    "changes",
    [
        {"reference": "INC-4821 " + STRIPE},
        {"reference": JWT},
        {"idempotency_key": STRIPE},
        {"idempotency_key": AGENT_TOKEN},
    ],
    ids=["reference-stripe", "reference-jwt", "key-stripe", "key-agent-token"],
)
def test_request_text_the_chain_never_carries_cannot_stop_the_export(
    api, db, world, admin_engine, receiver, changes
):
    """`reference` and the key reach the frozen request and the key table, and no audit
    payload. This pins that: whatever admission makes of them, the chain stays exportable,
    so a later change that copies either into an event fails here rather than in a tenant.
    """
    body = request(world).model_dump(mode="json")
    if "reference" in changes:
        body.pop("idempotency_key")
    assert api.post("/v1/execute", json={**body, **changes}).status_code == 202
    tenant = world["identity"].tenant_id
    with admin_engine.connect() as conn:
        frozen = conn.execute(
            text("SELECT frozen FROM execbound.executions WHERE tenant_id=:t"), {"t": tenant}
        ).scalar_one()
    [(field, value)] = changes.items()
    assert frozen["request"][field] == value
    assert not any(find_secrets(json.loads(p), limit=1) for p in chain(admin_engine, tenant))
    assert exports(db, world, admin_engine, receiver) == ("ACTIVE", None)


def test_a_contradiction_withholds_a_secret_shaped_tool_identity_and_is_still_recorded(
    db, arcade_world, seeded, admin_engine, receiver
):
    """A post hook is the platform's statement and is never refused for what it says
    (docs/ARCADE.md), and a contradiction is the only evidence a denied call ran anyway.
    So the contradiction is appended, and the identity the platform reported is withheld
    from it rather than copied into the chain."""
    world, tenant = arcade_world, arcade_world["identity"].tenant_id
    with admin_engine.begin() as conn:
        # The pack permits an isolation only on an endpoint whose risk is at least 50.
        conn.execute(
            text(
                "UPDATE execbound.resource_facts SET value='10'::jsonb "
                "WHERE tenant_id=:t AND fact_name='risk_score'"
            ),
            {"t": tenant},
        )
    reported = {**GOVERNED_TOOL, "toolkit": STRIPE, "metadata": {"behavior": {}}}
    with arcade_client(db, world, seeded) as driver:
        assert pre(driver).json()["code"] == "CHECK_FAILED"
        assert post(driver, success=True, tool=reported).json() == {"code": "OK"}
    recorded = [payload for kind, payload in audit_kinds(admin_engine, tenant) if "contra" in kind]
    assert [item["contradiction"] for item in recorded][:1] == ["DENIED_CALL"]
    for item in recorded:
        assert item["tool_identity"] == "WITHHELD"
        assert not {"toolkit", "tool_name", "tool_version"} & set(item)
    assert STRIPE not in json.dumps([payload for _, payload in audit_kinds(admin_engine, tenant)])
    assert exports(db, world, admin_engine, receiver) == ("ACTIVE", None)


@pytest.mark.parametrize(
    "changes",
    [{"id": STRIPE.lower()}, {"id": "review-" + STRIPE.lower()}],
    ids=["stripe", "embedded"],
)
def test_a_proposal_carrying_secret_shaped_text_is_refused_before_the_chain(
    db, configured, world, admin_engine, receiver, changes
):
    """The model's rule id is written into `assistant.asked` as `proposed`. A model answer is
    untrusted text like any other, so one shaped like a secret is refused as a proposal the
    compiler would refuse is, naming the field and never the value."""
    content = draft(db, world)
    script(configured, proposal(**changes))
    session = session_of(db, world, world["admin"])
    with pytest.raises(ProposalError) as refused:
        propose_rule(
            configured, BLOCK, configured.assistant_transport, session, content.bundle_id, WORDS
        )
    assert refused.value.code == "INVALID_PROPOSAL"
    assert refused.value.locations == ("id",)
    assert changes["id"] not in repr(refused.value)
    tenant = world["identity"].tenant_id
    assert not any(find_secrets(json.loads(p), limit=1) for p in chain(admin_engine, tenant))
    assert exports(db, world, admin_engine, receiver) == ("ACTIVE", None)
