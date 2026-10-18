# SPDX-License-Identifier: AGPL-3.0-only
"""Rules from a sentence: what the assistant may offer an administrator, and what it may not.

A proposal is not a write. What this holds is that the answer is a rule the compiler has
already accepted against that person's own draft, that its conditions read back through the
editor's own parser as the same conditions, that anything the compiler would refuse is refused
here with the field that caused it, and that the draft is exactly as it was either way.
"""

import json

import pytest
from console_api_fixtures import API, assert_no_secrets, console_client, console_config
from test_execution import registry as registry
from test_execution import world as world
from test_human_surface import human_config as human_config
from test_protected_path import connector as connector
from test_protected_path import live_provider as live_provider
from test_runtime import runtime as runtime

from execbound.assistant.client import ScriptedTransport, scripted_message, text_message
from execbound.assistant.config import AssistantConfig
from execbound.assistant.proposals import ProposalError, propose_rule
from execbound.assistant.turns import list_turns, set_tenant_switch
from execbound.policy.rulesets import condition_line, ruleset_bundle
from execbound.policy.store import create_bundle, list_bundles
from execbound.surfaces.policy_pages import parse_conditions
from execbound.surfaces.sessions import issue_session, load_session
from execbound_harness.demo import ENDPOINT_RULESET

pytestmark = pytest.mark.integration

RULES = API + "/assistant/rules"
BLOCK = AssistantConfig(api_key="rules-test-key", person_hourly_turns=50)
CONFIGURED = console_config(assistant_enabled=True)
ISOLATE = "endpoint.isolate"
WORDS = "never isolate anything in production without two people agreeing"


@pytest.fixture
def configured(runtime):
    runtime.assistant = BLOCK
    runtime.assistant_transport = ScriptedTransport([])
    return runtime


def draft(db, world):
    """A draft written as rules, which is the only kind that has rules to add one to."""
    set_tenant_switch(db, world["admin"], True, "Synthetic tenant", world["clock"])
    content = ruleset_bundle(
        ENDPOINT_RULESET,
        tenant_id=world["identity"].tenant_id,
        bundle_id=__import__("uuid").uuid4(),
        mappings=world["bundle"].mappings,
    )
    return create_bundle(db, world["admin"], content, world["clock"]).content


def proposal(**changes):
    rule = {
        "id": "review-production-isolation",
        "action": ISOLATE,
        "effect": "REVIEW",
        "quorum": 2,
        "when": [{"kind": "fact", "name": "is_production", "operator": "is", "values": [True]}],
    }
    rule.update(changes)
    return scripted_message(text_message(json.dumps(rule)))


def script(runtime, *steps):
    runtime.assistant_transport = ScriptedTransport(list(steps))
    return runtime.assistant_transport


def session_of(db, world, identity):
    grant = issue_session(db, identity, clock=world["clock"])
    return load_session(db, grant.token, clock=world["clock"])


def bundles(db, world):
    return {item.bundle_id: item.state for item in list_bundles(db, world["admin"], world["clock"])}


def test_a_proposal_is_a_rule_the_compiler_took_read_back_in_the_editors_own_words(
    db, configured, world, admin_engine
):
    content = draft(db, world)
    before = bundles(db, world)
    transport = script(configured, proposal())
    session = session_of(db, world, world["admin"])
    offered = propose_rule(configured, BLOCK, transport, session, content.bundle_id, WORDS)
    assert offered.rule.id == "review-production-isolation"
    assert offered.rule.effect == "REVIEW" and offered.rule.quorum == 2
    assert offered.sentence == ("Review endpoint.isolate (2 approvers) when is_production is true.")
    assert offered.lines == ("is_production is true",)
    # The lines are the editor's own grammar: they parse back to the same conditions.
    contracts = {
        mapping.operation_ref: configured.catalog.for_operation(
            mapping.context_contract_version,
            mapping.operation_ref,
            configured.catalog.actions.action(mapping.operation_ref).resource_type,
        )
        for mapping in content.mappings
    }
    parsed, problems = parse_conditions("\n".join(offered.lines), ISOLATE, contracts, configured)
    assert problems == [] and list(parsed) == list(offered.rule.when)
    assert [condition_line(c) for c in parsed] == list(offered.lines)
    # Nothing was written: the draft is the draft, and no bundle was added.
    assert bundles(db, world) == before
    # The turn is the person's own, completed, carrying the rule's sentence.
    turns = list_turns(db, world["admin"], world["clock"])
    assert len(turns) == 1 and turns[0].state == "COMPLETED"
    assert turns[0].context_kind == "policy_change" and turns[0].context_id == content.bundle_id
    assert turns[0].answer["paragraphs"][0]["text"] == offered.sentence
    assert turns[0].cited_ids == ("review-production-isolation",)
    # The model was told what this draft serves and which ids it already uses, and no more.
    sent = json.dumps(transport.sent)
    assert "is_production" in sent and "isolate-never-domain-controller" in sent
    assert WORDS in sent and "tenant_id" not in sent


@pytest.mark.parametrize(
    ("changes", "location"),
    [
        (
            {"when": [{"kind": "fact", "name": "hostname", "operator": "is", "values": ["x"]}]},
            "when",
        ),
        (
            {"when": [{"kind": "fact", "name": "role", "operator": "is", "values": ["laptop"]}]},
            "when",
        ),
        ({"action": "endpoint.explode"}, "action"),
        ({"id": "isolate-never-domain-controller"}, "id"),
        ({"effect": "MAYBE"}, "effect"),
        ({"quorum": 0}, "quorum"),
    ],
)
def test_a_proposal_the_compiler_would_refuse_is_refused_here_with_its_field(
    db, configured, world, changes, location
):
    content = draft(db, world)
    before = bundles(db, world)
    script(configured, proposal(**changes))
    session = session_of(db, world, world["admin"])
    with pytest.raises(ProposalError) as refused:
        propose_rule(configured, BLOCK, transport_of(configured), session, content.bundle_id, WORDS)
    assert refused.value.code == "INVALID_PROPOSAL"
    assert location in " ".join(refused.value.locations), refused.value.locations
    assert bundles(db, world) == before
    turns = list_turns(db, world["admin"], world["clock"])
    assert turns[0].state == "FAILED" and turns[0].reason == "MODEL_ERROR"


def transport_of(runtime):
    return runtime.assistant_transport


def test_an_answer_that_is_not_a_rule_at_all_is_refused_and_nothing_is_written(
    db, configured, world
):
    content = draft(db, world)
    for answer in (
        scripted_message(text_message("not json")),
        scripted_message(text_message(json.dumps({"id": "x"}))),
        scripted_message(text_message(json.dumps([{"id": "x"}]))),
    ):
        script(configured, answer)
        session = session_of(db, world, world["admin"])
        with pytest.raises(ProposalError) as refused:
            propose_rule(
                configured, BLOCK, transport_of(configured), session, content.bundle_id, WORDS
            )
        assert refused.value.code == "INVALID_PROPOSAL"


def test_only_a_draft_written_as_rules_can_be_drafted_into(db, configured, world, admin_engine):
    from uuid import uuid4

    set_tenant_switch(db, world["admin"], True, "Synthetic", world["clock"])
    session = session_of(db, world, world["admin"])
    script(configured, proposal())
    # The active bundle of this world is written by hand: it has no rules to add one to.
    with pytest.raises(Exception) as refused:
        propose_rule(
            configured,
            BLOCK,
            transport_of(configured),
            session,
            world["bundle"].bundle_id,
            WORDS,
        )
    assert getattr(refused.value, "code", "") == "INVALID_STATE"
    with pytest.raises(Exception) as missing:
        propose_rule(configured, BLOCK, transport_of(configured), session, uuid4(), WORDS)
    # A bundle this tenant does not have reads as the store's own refusal, the same one the
    # policy pages make, rather than as something the assistant decided.
    assert getattr(missing.value, "code", "") == "INVALID_BUNDLE"
    # Neither attempt reached the model.
    assert transport_of(configured).sent == []


def test_the_route_offers_the_form_to_an_administrator_and_refuses_everyone_else(
    db, configured, world, admin_engine
):
    content = draft(db, world)
    script(configured, proposal())
    with console_client(db, configured, admin_engine, world["human"], config=CONFIGURED) as human:
        body = {"bundle_id": str(content.bundle_id), "words": WORDS}
        assert human.post(RULES, body).status_code == 403
    with console_client(db, configured, admin_engine, world["admin"], config=CONFIGURED) as admin:
        answered = admin.post(RULES, {"bundle_id": str(content.bundle_id), "words": WORDS})
        assert answered.status_code == 200, answered.text
        offered = answered.json()
        assert offered["rule"]["id"] == "review-production-isolation"
        assert offered["rule"]["effect"] == "REVIEW" and offered["rule"]["quorum"] == 2
        assert offered["rule"]["when"] == [
            {"kind": "fact", "name": "is_production", "operator": "is", "values": [True]}
        ]
        assert offered["lines"] == ["is_production is true"]
        assert offered["words"] == WORDS
        assert "approvers" in offered["sentence"]
        assert_no_secrets(answered)
        # The refusal a person can act on, with the field that caused it.
        script(configured, proposal(action="endpoint.explode"))
        refused = admin.post(RULES, {"bundle_id": str(content.bundle_id), "words": WORDS})
        assert refused.status_code == 409 and refused.json()["code"] == "INVALID_PROPOSAL"
        assert refused.json()["fields"], refused.text
        for body in (
            {"bundle_id": "not-a-uuid", "words": WORDS},
            {"bundle_id": str(content.bundle_id)},
            {"bundle_id": str(content.bundle_id), "words": ""},
            {"bundle_id": str(content.bundle_id), "words": WORDS, "extra": 1},
        ):
            bad = admin.post(RULES, body)
            assert bad.status_code == 400, (body, bad.text)


def test_a_draft_whose_own_rules_cannot_compile_is_refused_before_a_turn_or_a_model_call(
    db, configured, world
):
    """Nothing a new rule could be checked against: refused as the draft's state, not the
    model's answer, and with no turn opened and nothing sent."""
    from uuid import uuid4

    from execbound.policy.models import MappingRef

    set_tenant_switch(db, world["admin"], True, "Synthetic tenant", world["clock"])
    content = ruleset_bundle(
        ENDPOINT_RULESET,
        tenant_id=world["identity"].tenant_id,
        bundle_id=uuid4(),
        mappings=world["bundle"].mappings,
    )
    # One action under two contracts: the draft's own mappings cannot compile together.
    conflicting = MappingRef(
        **content.mappings[0].model_dump(exclude={"operation_ref", "context_contract_version"}),
        operation_ref="isolate.corroborated",
        action=ISOLATE,
        context_contract_version="endpoint-isolation.v2",
    )
    content = content.model_copy(update={"mappings": (*content.mappings, conflicting)})
    create_bundle(db, world["admin"], content, world["clock"])
    transport = script(configured, proposal())
    session = session_of(db, world, world["admin"])
    with pytest.raises(Exception) as refused:
        propose_rule(configured, BLOCK, transport, session, content.bundle_id, WORDS)
    assert getattr(refused.value, "code", "") == "INVALID_STATE"
    assert not isinstance(refused.value, ProposalError)
    assert transport.sent == []
    assert list(list_turns(db, world["admin"], world["clock"])) == []
