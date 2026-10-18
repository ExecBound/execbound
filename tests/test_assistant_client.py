# SPDX-License-Identifier: AGPL-3.0-only
"""The assistant's provider client and renderer, without a database or a model.

The request shape is the contract the design pins; the transports are the seam; the renderer
decides what may become a link and what may not be said.
"""

import json

import httpx
import pytest

from execbound.assistant.client import (
    HttpTransport,
    ModelError,
    ScriptedTransport,
    ToolSpec,
    build_request,
    parse_response,
    scripted_message,
    text_message,
    tool_use,
)
from execbound.assistant.config import AssistantConfig
from execbound.assistant.render import ANSWER_SCHEMA, RenderError, parse_answer, recommends

CONFIG = AssistantConfig(api_key="test-key")
TOOL = ToolSpec(
    "get_execution",
    "One execution by id.",
    {"execution_id": {"type": "string", "description": "The execution's id"}},
    required=("execution_id",),
)
BEL = chr(7)


def request(question: str) -> dict:
    return build_request(
        CONFIG,
        fixed_instructions="FIXED",
        catalog_digest="CATALOG",
        tools=[TOOL],
        messages=[{"role": "user", "content": question}],
        answer_schema=ANSWER_SCHEMA,
    )


def prefix(body: dict) -> str:
    return json.dumps({k: v for k, v in body.items() if k != "messages"}, sort_keys=True)


def test_the_request_carries_the_shape_the_design_pins_and_a_stable_cached_prefix():
    first, second = request("Why was device-01 denied?"), request("Show me today's approvals.")
    body = first
    assert body["model"] == "claude-sonnet-5" and body["max_tokens"] == 2000
    assert body["tool_choice"] == {"type": "auto"}
    assert body["output_config"]["effort"] == "low"
    assert body["output_config"]["format"] == {"type": "json_schema", "schema": ANSWER_SCHEMA}
    tool = body["tools"][0]
    assert tool["strict"] is True and tool["input_schema"]["additionalProperties"] is False
    assert tool["input_schema"]["required"] == ["execution_id"]
    # The cache breakpoint closes the fixed part; the question comes after it.
    assert body["system"][-1]["cache_control"] == {"type": "ephemeral"}
    assert "cache_control" not in body["system"][0]
    assert body["messages"][-1]["role"] == "user"
    # No assistant prefill, ever.
    assert all(message["role"] == "user" for message in body["messages"])
    assert prefix(first) == prefix(second)
    assert first["messages"] != second["messages"]


def test_a_config_refuses_what_it_cannot_run_with():
    with pytest.raises(ValueError):
        AssistantConfig(api_key="")
    with pytest.raises(ValueError):
        AssistantConfig(api_key="k", effort="max")
    with pytest.raises(ValueError):
        AssistantConfig(api_key="k", max_tool_calls=0)
    with pytest.raises(ValueError):
        AssistantConfig(api_key="k", base_url="http://model.example")
    assert "test-key" not in repr(CONFIG)


def test_a_response_is_read_for_its_text_tool_calls_and_usage():
    parsed = parse_response(
        scripted_message(
            text_message("Reading."),
            tool_use("toolu_1", "get_execution", {"execution_id": "abc"}),
            stop_reason="tool_use",
        )
    )
    assert parsed.stop_reason == "tool_use" and parsed.text == "Reading."
    assert [(c.id, c.name, dict(c.arguments)) for c in parsed.tool_calls] == [
        ("toolu_1", "get_execution", {"execution_id": "abc"})
    ]
    assert parsed.usage.input_tokens == 100 and parsed.usage.output_tokens == 50
    with pytest.raises(ModelError) as refused:
        parse_response({"content": "not a list", "stop_reason": "end_turn"})
    assert refused.value.code == "INVALID_RESPONSE"


def test_the_scripted_transport_replays_records_and_runs_dry():
    transport = ScriptedTransport(
        [scripted_message(text_message("one")), ModelError("RATE_LIMITED"), lambda b: b]
    )
    assert parse_response(transport.send({"n": 1})).text == "one"
    with pytest.raises(ModelError) as raised:
        transport.send({"n": 2})
    assert raised.value.code == "RATE_LIMITED"
    assert transport.send({"n": 3}) == {"n": 3}
    with pytest.raises(ModelError) as dry:
        transport.send({"n": 4})
    assert dry.value.code == "SCRIPT_EXHAUSTED"
    assert [b["n"] for b in transport.sent] == [1, 2, 3, 4]


@pytest.mark.parametrize(
    ("status", "code"),
    [(429, "RATE_LIMITED"), (500, "SERVER_ERROR"), (529, "SERVER_ERROR"), (400, "BAD_REQUEST")],
)
def test_the_http_transport_maps_a_provider_status_to_a_code_and_quotes_nothing(status, code):
    seen = {}

    def handler(req: httpx.Request) -> httpx.Response:
        seen["headers"] = dict(req.headers)
        seen["url"] = str(req.url)
        return httpx.Response(status, json={"error": {"message": "the request said: secret"}})

    transport = HttpTransport(CONFIG, transport=httpx.MockTransport(handler))
    with pytest.raises(ModelError) as raised:
        transport.send({"model": "x"})
    assert raised.value.code == code and "secret" not in str(raised.value)
    assert seen["url"] == "https://api.anthropic.com/v1/messages"
    assert seen["headers"]["x-api-key"] == "test-key"
    assert seen["headers"]["anthropic-version"] == "2023-06-01"


def test_the_http_transport_returns_a_message_and_maps_a_timeout():
    ok = HttpTransport(
        CONFIG,
        transport=httpx.MockTransport(
            lambda req: httpx.Response(200, json=scripted_message(text_message("hi")))
        ),
    )
    assert parse_response(ok.send({})).text == "hi"

    def slow(req: httpx.Request) -> httpx.Response:
        raise httpx.ReadTimeout("slow", request=req)

    with pytest.raises(ModelError) as raised:
        HttpTransport(CONFIG, transport=httpx.MockTransport(slow)).send({})
    assert raised.value.code == "TIMEOUT"


def answer(*paragraphs, cannot_answer=False):
    return json.dumps(
        {
            "paragraphs": [{"text": t, "ids": list(ids)} for t, ids in paragraphs],
            "cannot_answer": cannot_answer,
        }
    )


def test_an_answer_keeps_only_the_ids_this_turn_saw_and_no_control_characters():
    raw = answer(
        (
            "The request 11111111 was denied by rule" + BEL + " isolate-never-domain-controller.",
            ["11111111", "99999999"],
        ),
        ("   ", []),
    )
    parsed = parse_answer(raw, seen_ids={"11111111"}, approval_context=False)
    assert len(parsed.paragraphs) == 1
    assert parsed.paragraphs[0].ids == ("11111111",)
    assert BEL not in parsed.paragraphs[0].text
    assert "99999999" not in parsed.paragraphs[0].ids
    assert parsed.cannot_answer is False


def test_an_answer_off_the_schema_is_refused_as_invalid():
    for raw in (
        "not json",
        json.dumps({"paragraphs": [], "cannot_answer": False}),
        json.dumps({"paragraphs": [{"text": "x", "ids": [], "link": "y"}], "cannot_answer": False}),
        json.dumps({"paragraphs": [{"text": "x" * 2001, "ids": []}], "cannot_answer": False}),
    ):
        with pytest.raises(RenderError) as raised:
            parse_answer(raw, seen_ids=(), approval_context=False)
        assert raised.value.code == "INVALID_ANSWER"
    empty = parse_answer(answer(cannot_answer=True), seen_ids=(), approval_context=False)
    assert empty.cannot_answer and empty.paragraphs == ()


@pytest.mark.parametrize(
    "text",
    [
        "Given the facts, you should approve this one.",
        "It is SAFE   TO APPROVE.",
        "I recommend refusing until the incident is confirmed.",
        "This should be denied.",
    ],
)
def test_a_recommendation_in_an_approval_context_fails_the_answer_and_nowhere_else(text):
    assert recommends(text)
    with pytest.raises(RenderError) as raised:
        parse_answer(answer((text, [])), seen_ids=(), approval_context=True)
    assert raised.value.code == "RECOMMENDATION"
    # The same words about a past decision, outside an approval, are an explanation.
    assert parse_answer(answer((text, [])), seen_ids=(), approval_context=False).paragraphs


def test_the_explanation_words_the_design_allows_are_not_recommendations():
    for text in (
        "The rule review-production required a person because is_production is true.",
        "Two approvers are needed and the deadline is in 9 minutes.",
        "The action is reversible: lift_isolation restores the endpoint.",
        "The approver denied it at 10:02.",
    ):
        assert not recommends(text), text
