# SPDX-License-Identifier: AGPL-3.0-only
"""The agent SDK tool examples run through their SDKs against a real gateway (#250).

Each example in clients/python/examples/ is imported as written and driven by a scripted
model in a separate interpreter (tests/sdk_examples_probe.py), with the SDKs from
.tools/sdk-examples. The model first lists the actions its space offers, and the listing
names the action it then asks for; the action tool asks for a held action and waits while a
person approves it from here, the same ticket asked again returns the same execution without
acting twice, and a request for a host the inventory does not hold comes back refused. All
the while the agent's event loop keeps running: a tool that blocked it while the person
decided would stall everything else the agent does. This is what the integrations manifest
cites to call these two rows fixture-tested.
"""

import json
import re
import subprocess
import sys
import time
from pathlib import Path

import pytest
from test_action_listing import LISTED_ISOLATE
from test_examples import approve_pending, mutation_count
from test_mcp_surface import gateway as gateway
from test_runtime import connector as connector
from test_runtime import live_provider as live_provider
from test_runtime import registry as registry
from test_runtime import request
from test_runtime import runtime as runtime
from test_runtime import world as world

ROOT = Path(__file__).resolve().parents[1]
PINS = dict(
    re.findall(
        r"^([a-z-]+)==(\S+)$",
        (ROOT / "tests" / "sdk-examples.in").read_text(encoding="utf-8"),
        re.M,
    )
)
# Each example's tools as the model is offered them: the listing, then the action.
TOOLS = {
    "openai-agents": ["execbound_list_actions_tool", "execbound_action_tool"],
    "claude-agent-sdk": ["execbound_list_actions", "execbound_action"],
}


def run_probe(config, db, world):
    """Start the probe, approve the one request it holds, and return its report."""
    probe = subprocess.Popen(  # noqa: S603 - this interpreter, our own probe, JSON on stdin
        [sys.executable, str(ROOT / "tests" / "sdk_examples_probe.py")],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        cwd=ROOT,
    )
    assert probe.stdin is not None
    probe.stdin.write(json.dumps(config))
    probe.stdin.close()
    approved = None
    deadline = time.monotonic() + 90
    while probe.poll() is None and time.monotonic() < deadline:
        if approved is None:
            approved = approve_pending(db, world)
        time.sleep(0.2)
    stdout, stderr = probe.communicate(timeout=30)
    assert probe.returncode == 0, stderr[-4000:]
    return json.loads(stdout.strip().splitlines()[-1]), approved


@pytest.mark.parametrize("sdk", sorted(TOOLS))
def test_the_sdk_tool_example_lists_then_waits_for_a_person_and_acts_once(
    gateway, db, world, seeded, live_provider, sdk
):
    body = request(world).model_dump(mode="json")
    action = {
        "operation_ref": body["operation_ref"],
        "target_kind": body["target"]["kind"],
        "target_value": body["target"]["value"],
        "ticket": "INC-4821",
        "incident_id": body["claimed_context"]["incident_id"],
    }
    # Well formed, so the client sends it, and naming a host the inventory does not hold,
    # so the gateway refuses it before any decision.
    unknown = {**action, "target_value": "nobody.example.", "ticket": "INC-4822"}
    listing, act = TOOLS[sdk]
    config = {
        "sdk": sdk,
        "url": gateway,
        "token": seeded["tokens"][0],
        "calls": [
            {"tool": listing, "arguments": {}},
            *({"tool": act, "arguments": arguments} for arguments in (action, action, unknown)),
        ],
    }
    report, approved = run_probe(config, db, world)
    assert report["sdk"] == sdk and report["version"] == PINS[sdk]
    assert report["tools"] == TOOLS[sdk]
    listed, first, again, refused = report["results"]
    # The model learns the action it names from its space's listing rather than guessing,
    # and the listing names no target.
    assert listed == {"outcome": "listed", "actions": [LISTED_ISOLATE]}
    assert [entry["operation_ref"] for entry in listed["actions"]] == [action["operation_ref"]]
    # The tool waited while the action was held, then returned what happened.
    assert approved is not None
    # It waited without holding the agent's event loop, which kept ticking all along; the
    # client polls a held action every two seconds, so a tool that blocked the loop while
    # it waited would leave it standing still for at least that long.
    assert report["stall"] < 1.0, report["stall"]
    assert first["outcome"] == "final" and first["state"] == "EXECUTED", first
    # The ticket, not the model's wording, keys the intent: asking again acts no further.
    assert again["execution_id"] == first["execution_id"] and again["state"] == "EXECUTED"
    assert mutation_count(live_provider, world) == 1
    # An unresolvable target is context the gateway cannot establish, so it fails closed
    # before any decision; the model reads a refusal, and nothing reached the provider.
    assert refused == {"outcome": "refused", "status": 503, "code": "EXECUTION_UNAVAILABLE"}
