# SPDX-License-Identifier: AGPL-3.0-only
"""Tines sends identifiers verbatim by serializing JSON before its HTTP action."""

import json
from pathlib import Path

import pytest
from test_tines_monitor_story import _value

from execbound.requests import ActionRequest

ROOT = Path(__file__).resolve().parents[1] / "integrations/tines"


@pytest.mark.parametrize(
    "name",
    ["execbound-governed-action.json", "execbound-gate.json", "execbound-ai-agent-caller.json"],
)
def test_execute_keeps_digit_identifiers_and_argument_types(name):
    story = json.loads((ROOT / name).read_text())
    if name == "execbound-ai-agent-caller.json":
        [story] = story["send_to_stories"]
    options = next(a["options"] for a in story["agents"] if a["name"] == "Execute")
    assert "content_type" not in options
    assert options["headers"]["Content-Type"] == "application/json"
    prepared = {
        "operation_ref": "endpoint.isolate",
        "reference": "000123",
        "target_kind": "provider_id",
        "target_value": "001004",
        "incident_id": "00000000-0000-0000-0000-000000000007",
        "arguments": {"number": 4, "flag": True, "text": "0042"},
        "external_case": None,
    }
    raw = _value(options["payload"], {"prepare": prepared})
    parsed = ActionRequest.model_validate_json(raw)
    assert parsed.reference == "000123"
    assert parsed.target.value == "001004"
    assert str(parsed.claimed_context.incident_id) == prepared["incident_id"]
    assert parsed.arguments.root == prepared["arguments"]


def test_gate_vendor_command_and_reports_are_serialized_without_coercion():
    story = json.loads((ROOT / "execbound-gate.json").read_text())
    payload = {
        "operation_id": "0001",
        "expected_version": "0002",
        "arguments": {"active": False, "count": 3},
    }
    events = {"grant": {"provider_command": payload}, "select_report": {"body": payload}}
    requests = [
        a
        for a in story["agents"]
        if a["type"] == "Agents::HTTPRequestAgent" and a["options"]["method"] == "post"
    ]
    assert len(requests) >= 3
    for action in requests:
        options = action["options"]
        assert "content_type" not in options, action["name"]
        assert options["payload"].startswith("=TO_JSON("), action["name"]
        assert options["headers"]["Content-Type"] == "application/json"
        if action["name"] == "Vendor call":
            assert json.loads(_value(options["payload"], events)) == payload
