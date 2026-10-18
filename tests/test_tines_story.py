# SPDX-License-Identifier: AGPL-3.0-only
"""The committed Tines story: what it sends, what it never carries, and what it cannot do.

The story is a caller, not a component of the kernel, so these tests do not prove any
security property of ExecBound. What they hold is narrower and still worth holding: that the
file we publish speaks the gateway's actual contract, that it carries no secret and no tenant
of ours, and that the three rules it exists to demonstrate are still written into it.
"""

import json
import re
from pathlib import Path

import pytest
from test_tines_monitor_story import _value

from execbound.requests import ActionRequest

STORY = Path(__file__).resolve().parents[1] / "integrations/tines/execbound-governed-action.json"
BODY = Path(__file__).resolve().parent / "fixtures/tines-governed-action-body.json"
BODY_VIA_SEND_TO_STORY = (
    Path(__file__).resolve().parent / "fixtures/tines-governed-action-body-via-send-to-story.json"
)
RAW = STORY.read_text()
EXPORT = json.loads(RAW)
ACTIONS = {agent["name"]: agent for agent in EXPORT["agents"]}
EXECUTE = ACTIONS["Execute"]["options"]


@pytest.mark.parametrize(
    ("fixture", "reference"),
    [(BODY, "INC-12345/verify-reimport"), (BODY_VIA_SEND_TO_STORY, "INC-2001")],
    ids=["direct webhook post", "send to story from an AI Agent story"],
)
def test_the_rendered_wire_body_is_one_the_gateway_accepts(fixture, reference):
    """Captured from the action log of a live run, parsed by the gateway's own model.

    This is the test that fails when either side drifts. A change to `ActionRequest` that the
    story does not follow, or a change to the story that the gateway would refuse, breaks here
    rather than at a customer's first isolation. There are two bodies because there are two
    ways in: the second was captured after an AI Agent story handed its decision over by Send
    to Story, which is the path the story is for and the one that was broken until it was run.
    """
    request = ActionRequest.model_validate_json(fixture.read_text())
    assert request.operation_ref == "endpoint.isolate"
    assert request.target.kind == "hostname"
    assert request.claimed_context.incident_id is not None
    # The story sends a reference and no key; the gateway derives the key, so this story and
    # the Python client given the same ticket land on the same intent.
    assert request.reference == reference
    assert request.idempotency_key


def test_prepare_reads_the_send_to_story_shape_and_falls_back_to_the_bare_one():
    """A Send to Story delivers the payload under `body`; a direct post is the body itself.

    The first live run through an AI Agent story reached the gateway with every field empty
    because Prepare read `entry.reference` and the reference was at `entry.body.reference`;
    only the placeholder credential's 401 hid it. Every field now reads the wrapped form first.
    """
    payload = ACTIONS["Prepare"]["options"]["payload"]
    for field in (
        "operation_ref",
        "target_kind",
        "target_value",
        "reference",
        "incident_id",
        "arguments",
        "wait_seconds",
        "external_case",
    ):
        assert f"entry.body.{field}" in payload[field], field
        assert f"DEFAULT(entry.body.{field}, entry.{field})" in payload[field], field


def test_the_story_sends_a_reference_and_never_its_own_key():
    """Exactly one of the two is permitted, and a key beside a reference is refused."""
    sent = json.loads(_value(EXECUTE["payload"], {"prepare": {"reference": "000123"}}))
    assert sent["reference"] == "000123"
    assert "idempotency_key" not in sent


@pytest.mark.parametrize("field", ["target", "claimed_context", "arguments", "external_case"])
def test_every_nested_value_stays_an_object_on_the_wire(field):
    """A pill would stringify the object and the gateway's strict parser would refuse it."""
    sent = json.loads(
        _value(
            EXECUTE["payload"],
            {
                "prepare": {
                    "target_kind": "hostname",
                    "target_value": "lab-01",
                    "incident_id": "0001",
                    "arguments": {"wait": 3},
                    "external_case": {"system": "tines", "id": "0002"},
                }
            },
        )
    )
    assert isinstance(sent[field], dict)
    assert "<<" not in EXECUTE["payload"]


def test_the_credential_and_origin_are_referenced_and_never_written_in():
    assert EXECUTE["headers"]["Authorization"] == "Bearer <<CREDENTIAL.execbound>>"
    assert EXECUTE["url"] == "<<RESOURCE.execbound_origin>>/v1/execute"


def test_the_send_is_never_retried_by_the_platform():
    """`fail_on_status` would re-run a possibly committed send for thirty days.

    A re-send has to be this story's decision, taken with the same reference, because a 503
    after a send is not proof of non-execution.
    """
    assert EXECUTE["fail_on_status"] is False
    assert EXECUTE["retry_on_status"] == [429]
    # An empty list silences every rejection, so a refusal would read as success.
    assert EXECUTE["log_error_on_status"]


def test_the_story_carries_no_secret_no_origin_and_no_tenant():
    """It is published, so it must be safe to publish.

    An export carries more of its tenant than it looks: this file arrived with a service
    account's email in `recipients` and the tenant identifier inside every action's
    `origin_story_identifier`. Both are scrubbed, and this is what keeps them scrubbed the
    next time the story is rebuilt and re-exported.
    """
    assert "https://" not in RAW
    assert "tines.com" not in RAW
    assert re.search(r"[\w.+-]+@[\w-]+\.[\w.]+", RAW) is None
    assert EXPORT["recipients"] == []
    assert {agent["origin_story_identifier"] for agent in EXPORT["agents"]} == {None}
    entry = ACTIONS["Entry"]["options"]
    # A committed webhook path and secret would let anyone post into the tenant that
    # exported it. Tines does not regenerate them on import; the README says to set them.
    assert entry["path"] == ""
    assert entry["secret"] == ""


def test_the_story_cannot_approve_and_holds_no_decision_of_its_own():
    """The one property a governed-action caller must not have.

    Every action is an entry, one send, a branch on the answer, or the report. Nothing posts
    to an approval route, and no branch turns a refusal or a pending answer into a send.
    """
    assert {action["type"] for action in EXPORT["agents"]} == {
        "Agents::WebhookAgent",
        "Agents::EventTransformationAgent",
        "Agents::HTTPRequestAgent",
        "Agents::TriggerAgent",
    }
    # One outbound call in the whole story, and it is the execute endpoint. Asserting the
    # single URL is the property; scanning the file for the word "approve" is not, since the
    # story's own description uses it to say what it cannot do.
    requests = [a for a in EXPORT["agents"] if a["type"] == "Agents::HTTPRequestAgent"]
    assert len(requests) == 1
    assert requests[0]["options"]["url"] == "<<RESOURCE.execbound_origin>>/v1/execute"


def test_an_uncertain_answer_is_never_reported_as_a_refusal():
    """The distinction the whole contract rests on.

    A refusal states that nothing happened; an uncertain answer states that whether anything
    happened is not established. Reporting the second as the first invites exactly the retry
    under a new key that the contract forbids, so the mapping is asserted rather than trusted.
    """
    outcome = ACTIONS["Outcome"]["options"]["payload"]["outcome"]
    for state in ("DISPATCH_COMMITTED", "INDETERMINATE", "FAILED_EFFECT_UNKNOWN"):
        assert f'"{state}", "uncertain"' in outcome
    # No answer at all, and a 503, are uncertain for the same reason.
    assert '"HTTP-503", "uncertain"' in outcome
    assert '"HTTP-", "uncertain"' in outcome
    message = ACTIONS["Outcome"]["options"]["payload"]["message"]
    assert "Never resend under a new key" in message


@pytest.mark.parametrize(
    "event",
    json.loads((BODY.parent / "tines-transport-failures.json").read_text()),
    ids=lambda event: event["case"],
)
def test_native_transport_failures_stop_as_uncertain_without_another_send(event):
    """Live Tines emits status 0 for DNS failure and exhausted HTTP retries.

    Routing that envelope to Refused loses uncertainty and its operator instruction. It
    must reach Outcome directly, not the 503 resend loop, after the native retry budget.
    The regex checks exercise the captured wire status; the live trial checks Tines itself.
    """
    status = str(event["execute"]["status"])
    uncertain = ACTIONS["Transport uncertain?"]["options"]
    assert uncertain["must_match"] == "1"
    assert any(
        rule["path"] == "<<execute.status>>"
        and rule["type"] == "regex"
        and re.fullmatch(rule["value"], status)
        for rule in uncertain["rules"]
    )
    [refused] = ACTIONS["Refused?"]["options"]["rules"]
    assert refused["type"] == "!regex" and re.fullmatch(refused["value"], status)
    [unavailable] = ACTIONS["Unavailable?"]["options"]["rules"]
    assert re.fullmatch(unavailable["value"], status) is None
    names = [agent["name"] for agent in EXPORT["agents"]]
    assert any(
        names[link["source"]] == "Execute" and names[link["receiver"]] == "Transport uncertain?"
        for link in EXPORT["links"]
    )
    receivers = {
        names[link["receiver"]]
        for link in EXPORT["links"]
        if names[link["source"]] == "Transport uncertain?"
    }
    assert receivers == {"Outcome"}
    outcome = ACTIONS["Outcome"]["options"]["payload"]
    for field in ("outcome", "message"):
        assert '"HTTP-0", "uncertain"' in outcome[field]
    assert event["expected_code"] in outcome["code"]
    assert EXECUTE["retry_on_status"] == [429] and EXECUTE["retries"] == 5


@pytest.mark.parametrize("status", [500, 501, 502, 504, 507, 520, 522, 524, 599])
def test_server_errors_never_claim_refusal_or_start_an_extra_retry_loop(status):
    """An intermediary can replace a committed result with a non-JSON 5xx response."""
    uncertain = ACTIONS["Transport uncertain?"]["options"]["rules"]
    assert any(re.fullmatch(rule["value"], str(status)) for rule in uncertain)
    [refused] = ACTIONS["Refused?"]["options"]["rules"]
    assert re.fullmatch(refused["value"], str(status))
    [retry] = ACTIONS["Unavailable?"]["options"]["rules"]
    assert re.fullmatch(retry["value"], str(status)) is None
    payload = ACTIONS["Outcome"]["options"]["payload"]
    guard = "AND(DEFAULT(execute.status, 0) >= 500, DEFAULT(execute.status, 0) <= 599)"
    assert payload["outcome"].startswith(f'=IF({guard}, "uncertain", ')
    assert f'IF({guard}, "uncertain", ' in payload["message"]
    assert "HTTP_RESPONSE_UNCERTAIN" in payload["code"]


def test_a_tool_call_can_ask_for_an_immediate_answer():
    """An AI Agent calling this as a tool cannot act on a pending answer and its call times out.

    So the wait budget is an input, defaulting to the tenant's approval deadline. A tool call
    passes 0 and gets `pending` straight back instead of the story polling on its behalf; a
    deterministic caller omits it and waits as before. Both deadline branches read the
    prepared value, never the resource directly, so the override cannot be bypassed.
    """
    prepare = ACTIONS["Prepare"]["options"]["payload"]
    # The caller's value, from either delivery shape, and only then the tenant's resource.
    assert prepare["wait_seconds"] == (
        "=DEFAULT(DEFAULT(entry.body.wait_seconds, entry.wait_seconds), "
        "RESOURCE.execbound_wait_seconds)"
    )
    for name in ("Within deadline?", "Deadline passed?"):
        for rule in ACTIONS[name]["options"]["rules"]:
            assert "prepare.wait_seconds" in rule["path"]
            assert "RESOURCE.execbound_wait_seconds" not in rule["path"]
    # The pending message is written for a model reading it: the safe way to check again is
    # the same reference, and a new one would be a new intent.
    message = ACTIONS["Outcome"]["options"]["payload"]["message"]
    assert "call again with the same reference, never a new one" in message


def test_pending_deadlines_read_cumulative_seconds_from_the_date_diff_object():
    """Tines rejected the three-positional-argument form in both live pending branches.

    DATE_DIFF takes two dates and returns an object. Its top-level seconds are cumulative;
    units.seconds would wrap at a minute and keep a long wait alive. This is a wire-formula
    guard, not a substitute for running both branches in Tines (see the live trial record).
    """
    paths = []
    for name, answer in (("Within deadline?", "^yes$"), ("Deadline passed?", "^no$")):
        [rule] = ACTIONS[name]["options"]["rules"]
        paths.append(rule["path"])
        assert 'GET(DATE_DIFF(prepare.started_at, NOW()), "seconds")' in rule["path"]
        assert "units.seconds" not in rule["path"]
        assert "< prepare.wait_seconds" in rule["path"]
        assert rule["type"] == "regex" and rule["value"] == answer
    assert paths[0] == paths[1]


def test_pending_outcomes_preserve_the_gateways_flat_approval_fields():
    """A live pending response carried the link, but Outcome read a nonexistent nesting.

    The model calling this story needs that link to hand the pending action to a person.
    Pending, approved and terminal answers all share these top-level fields in the HTTP API.
    """
    payload = ACTIONS["Outcome"]["options"]["payload"]
    assert payload["approval_state"] == "=DEFAULT(execute.body.approval_state, null)"
    assert payload["approval_url"] == "=DEFAULT(execute.body.approval_url, null)"


def test_the_entry_and_the_exits_are_the_declared_ones():
    guids = {agent["guid"]: agent["name"] for agent in EXPORT["agents"]}
    assert guids[EXPORT["entry_agent_guid"]] == "Entry"
    assert [guids[guid] for guid in EXPORT["exit_agent_guids"]] == [
        "Outcome",
        "Refused: no reference",
    ]


def test_a_missing_reference_is_refused_before_any_call():
    """The rule the README states, now held by the wiring rather than by the sentence.

    The reference is what the gateway derives the idempotency key from, so a request without
    one is not an intent this story can send under the same key twice. Both gates read the
    prepared value; the only way from Prepare to Execute is through the one that requires it;
    the refusal is a second exit in Outcome's shape, so a caller reads one contract. Fired live
    without a reference: Entry, Prepare, No reference?, Refused: no reference, and no Execute.
    """
    names = [agent["name"] for agent in EXPORT["agents"]]
    links = {(names[link["source"]], names[link["receiver"]]) for link in EXPORT["links"]}
    assert ("Prepare", "Has reference?") in links and ("Has reference?", "Execute") in links
    assert ("Prepare", "No reference?") in links and (
        "No reference?",
        "Refused: no reference",
    ) in links
    assert ("Prepare", "Execute") not in links
    for name, negate in (("Has reference?", False), ("No reference?", True)):
        [rule] = ACTIONS[name]["options"]["rules"]
        assert rule == {
            "type": "!regex" if negate else "regex",
            "path": "<<prepare.reference>>",
            "value": "^.+$",
        }
    refusal = ACTIONS["Refused: no reference"]["options"]["payload"]
    assert refusal["outcome"] == "refused" and refusal["code"] == "MISSING_REFERENCE"
    assert set(refusal) == set(ACTIONS["Outcome"]["options"]["payload"])


# --- the caller story ------------------------------------------------------------------

CALLER = Path(__file__).resolve().parents[1] / "integrations/tines/execbound-ai-agent-caller.json"
CALLER_RAW = CALLER.read_text()
CALLER_EXPORT = json.loads(CALLER_RAW)
CALLER_ACTIONS = {agent["name"]: agent for agent in CALLER_EXPORT["agents"]}


def test_the_caller_story_hands_every_decision_to_the_governed_story():
    """An agent that decides to act cannot skip the checkpoint: the call is wired, not offered.

    Ran end to end on 2026-09-18: the alert, the agent's decision, the gate on it, the Send to
    Story into the governed story, and the outcome back.
    """
    names = [agent["name"] for agent in CALLER_EXPORT["agents"]]
    links = [(names[link["source"]], names[link["receiver"]]) for link in CALLER_EXPORT["links"]]
    assert set(links) == {
        ("Alert", "Triage agent"),
        ("Triage agent", "Act?"),
        ("Act?", "Govern via ExecBound"),
        ("Govern via ExecBound", "Result"),
    }
    [agent] = [a for a in CALLER_EXPORT["agents"] if a["type"] == "Agents::LLMAgent"]
    assert agent["options"]["mode"] == "task"  # empty is accepted at save and refused at run time
    assert agent["options"]["output_schema"]["properties"]["operation_ref"]["enum"]
    assert (
        '"operation_ref": "endpoint.isolate"' in agent["options"]["prompt"]
    )  # the schema is a hint
    send = CALLER_ACTIONS["Govern via ExecBound"]["options"]
    assert (
        send["story"] == "<<STORY.execbound_govern_an_action>>"
    )  # the integer id fails at run time
    assert send["payload"]["wait_seconds"] == 0
    assert send["payload"]["reference"].startswith("=DEFAULT(triage_agent.output.reference")


def test_the_caller_story_carries_no_secret_no_origin_and_no_tenant():
    assert "https://" not in CALLER_RAW and "tines.com" not in CALLER_RAW
    assert re.search(r"[\w.+-]+@[\w-]+\.[\w.]+", CALLER_RAW) is None
    assert CALLER_EXPORT["recipients"] == []
    # A caller carries the target story's metadata too, recipients included.
    assert all(sub["recipients"] == [] for sub in CALLER_EXPORT["send_to_stories"])
    assert {agent["origin_story_identifier"] for agent in CALLER_EXPORT["agents"]} == {None}
    # The embedded copy of the governed story names no tenant it was exported from either.
    assert {
        agent["origin_story_identifier"]
        for sub in CALLER_EXPORT["send_to_stories"]
        for agent in sub["agents"]
    } == {None}
    assert (
        CALLER_ACTIONS["Alert"]["options"]["path"] == ""
        and CALLER_ACTIONS["Alert"]["options"]["secret"] == ""
    )
    # The lab tenant's own chat-mode agent, and the page identifier it carries, are not
    # published.
    assert "url_identifier" not in CALLER_RAW


def test_the_caller_embeds_the_governed_story_as_it_is_committed():
    """Tines imports the caller with the story it sends to, so the embedded copy is what a
    reader gets. A copy older than the committed governed story would import behaviour the
    governed story's own tests no longer describe."""
    [embedded] = CALLER_EXPORT["send_to_stories"]
    assert embedded["guid"] == EXPORT["guid"]
    assert {key: embedded[key] for key in embedded} == {key: EXPORT[key] for key in embedded}


def test_all_exported_webhooks_including_embedded_stories_have_no_delivery_secret():
    def inspect(value):
        if isinstance(value, dict):
            if value.get("type") == "Agents::WebhookAgent":
                if value["options"].get("secret") or value["options"].get("path"):
                    raise AssertionError("Exported webhook carries delivery credentials")
            for nested in value.values():
                inspect(nested)
        elif isinstance(value, list):
            for nested in value:
                inspect(nested)

    for path in CALLER.parent.glob("*.json"):
        inspect(json.loads(path.read_text(encoding="utf-8")))


def test_case_and_human_reference_do_not_replace_the_retry_reference():
    case = {"system": "tines", "id": "000123"}
    sent = json.loads(
        _value(EXECUTE["payload"], {"prepare": {"external_case": case, "reference": "0002"}})
    )
    assert sent["external_case"] == case
    assert sent["reference"] == "0002"
    assert ACTIONS["Outcome"]["options"]["payload"]["request_ref"] == (
        "=DEFAULT(execute.body.request_ref, null)"
    )
