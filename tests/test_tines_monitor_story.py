# SPDX-License-Identifier: AGPL-3.0-only
"""TM1 to TM4: the importable Tines Monitor example story, held to the intake's contract.

The story's bodies are Tines formulas. The evaluator below covers exactly the subset the
story uses (OBJECT, APPEND, TEXT, TO_JSON, DATE, NOW, IF, DEFAULT, AND, SWITCH, comparisons,
string and integer literals, null and event paths), so each body is built the way Tines
builds it and then handed to the intake's own parser rather than pattern-matched.
"""

import json
import re
import subprocess
import sys
from datetime import UTC, datetime
from pathlib import Path

import pytest

from execbound.monitoring.http import parse_event
from execbound.monitoring.models import TINES_OPERATIONS, ObservationEvent
from execbound.monitoring.store import SENSITIVE_ACTIONS

ROOT = Path(__file__).resolve().parents[1]
STORY = ROOT / "integrations/tines/execbound-monitor.json"
RAW = STORY.read_text()
EXPORT = json.loads(RAW)
ACTIONS = {agent["name"]: agent for agent in EXPORT["agents"]}
NAMES = [agent["name"] for agent in EXPORT["agents"]]
REQUESTS = [agent for agent in EXPORT["agents"] if agent["type"] == "Agents::HTTPRequestAgent"]
# The Tines story id is an integer, and digit-only, which is what exposed Tines' JSON smart
# validation in the live trial: sent with `content_type: json` it arrived as a number.
STORY_ID = 147205
NOW = datetime(2026, 9, 25, 18, 4, 31, tzinfo=UTC)


def _edges():
    edges = {}
    for link in EXPORT["links"]:
        edges.setdefault(NAMES[link["source"]], []).append(NAMES[link["receiver"]])
    return edges


def _downstream(start):
    edges, seen, stack = _edges(), set(), [start]
    while stack:
        name = stack.pop()
        if name not in seen:
            seen.add(name)
            stack.extend(edges.get(name, []))
    return seen


_TOKEN = re.compile(
    r'\s*(?:(?P<string>"[^"]*")|(?P<number>-?\d+)|(?P<op>>=|<=|=|>|<)'
    r"|(?P<punct>[(),])|(?P<name>[A-Za-z_][A-Za-z0-9_.]*))"
)


def _tokens(formula):
    found, position, text = [], 0, formula.rstrip()
    while position < len(text):
        match = _TOKEN.match(text, position)
        assert match is not None, text[position:]
        found.append((match.lastgroup, match.group(match.lastgroup)))
        position = match.end()
    return found


def _parse(formula):
    tokens = _tokens(formula)

    def expression(i):
        left, i = primary(i)
        if i < len(tokens) and tokens[i][0] == "op":
            right, end = primary(i + 1)
            return ("op", tokens[i][1], left, right), end
        return left, i

    def primary(i):
        kind, value = tokens[i]
        if kind == "string":
            return ("literal", value[1:-1]), i + 1
        if kind == "number":
            return ("literal", int(value)), i + 1
        assert kind == "name", tokens[i]
        if value == "null":
            return ("literal", None), i + 1
        if i + 1 < len(tokens) and tokens[i + 1] == ("punct", "("):
            arguments, i = [], i + 2
            while tokens[i] != ("punct", ")"):
                argument, i = expression(i)
                arguments.append(argument)
                if tokens[i] == ("punct", ","):
                    i += 1
            return ("call", value, arguments), i + 1
        return ("path", value), i + 1

    tree, end = expression(0)
    assert end == len(tokens), formula
    return tree


def _present(value):
    return value is not None and value != "" and value != [] and value != {}


def _evaluate(node, events):
    kind = node[0]
    if kind == "literal":
        return node[1]
    if kind == "path":
        value = events
        for part in node[1].split("."):
            value = value.get(part) if isinstance(value, dict) else None
        return value
    if kind == "op":
        _, op, left, right = node
        a, b = _evaluate(left, events), _evaluate(right, events)
        if op == "=":
            return a == b
        if a is None or b is None:
            return False
        return {">=": a >= b, "<=": a <= b, ">": a > b, "<": a < b}[op]
    _, name, arguments = node
    if name == "IF":
        condition, then, *otherwise = arguments
        branch = then if _evaluate(condition, events) else (otherwise or [("literal", None)])[0]
        return _evaluate(branch, events)
    if name == "SWITCH":
        subject = _evaluate(arguments[0], events)
        pairs = arguments[1:]
        for index in range(0, len(pairs) - 1, 2):
            if _evaluate(pairs[index], events) == subject:
                return _evaluate(pairs[index + 1], events)
        return _evaluate(pairs[-1], events) if len(pairs) % 2 else None
    values = [_evaluate(argument, events) for argument in arguments]
    if name == "OBJECT":
        return {values[i]: values[i + 1] for i in range(0, len(values), 2)}
    if name == "APPEND":
        return "".join(values)
    if name == "TEXT":
        return str(values[0])
    if name == "TO_JSON":
        return json.dumps(values[0])
    if name == "NOW":
        return events["__now__"]
    if name == "DATE":
        return values[0].strftime(values[1])
    if name == "DEFAULT":
        return values[0] if _present(values[0]) else values[1]
    if name == "AND":
        return all(values)
    raise AssertionError(f"Unsupported formula function {name}")


def _value(formula, events):
    assert formula.startswith("="), formula
    return _evaluate(_parse(formula[1:]), events)


def _payload(name, events):
    payload = ACTIONS[name]["options"]["payload"]
    if isinstance(payload, str):
        return _value(payload, events)
    return {
        key: _value(value, events) if isinstance(value, str) and value.startswith("=") else value
        for key, value in payload.items()
    }


def _matches(name, events):
    """A trigger's rules the way Tines applies them: every rule, a regex search on the text."""
    rules = ACTIONS[name]["options"]["rules"]
    assert ACTIONS[name]["options"]["must_match"] == str(len(rules))
    for rule in rules:
        path = re.fullmatch(r"<<([a-z_.]+)>>", rule["path"]).group(1)
        text = _evaluate(("path", path), events)
        found = re.search(rule["value"], "" if text is None else str(text), re.IGNORECASE)
        if (found is None) == (rule["type"] == "regex"):
            return False
    return True


def _result_run(status, target="lab-ws-01"):
    """The events a result run carries once `Build result` has run on `Act`'s answer."""
    events = {"__now__": NOW, "META": {"story": {"id": STORY_ID}, "event": {"id": 9001}}}
    events["entry"] = {"target": target}
    events["prepare"] = _payload("Prepare", events)
    events["act"] = {} if status is None else {"status": status}
    events["build_result"] = _payload("Build result", events)
    return events


def _heartbeat_run():
    events = {"__now__": NOW, "META": {"story": {"id": STORY_ID}, "event": {"id": 9002}}}
    events["heartbeat"] = _payload("Heartbeat", events)
    events["build_heartbeat"] = _payload("Build heartbeat", events)
    return events


def test_tm1_the_committed_story_is_what_the_generator_writes():
    checked = subprocess.run(
        [sys.executable, str(ROOT / "integrations/tines/tines_monitor_story.py"), "--check"],
        check=False,
    )
    assert checked.returncode == 0


def test_tm2_the_story_names_its_credentials_and_resources_and_nothing_else():
    assert set(re.findall(r"CREDENTIAL\.(\w+)", RAW)) == {
        "execbound_monitor_source",
        "execbound_lab_vendor",
    }
    assert set(re.findall(r"RESOURCE\.(\w+)", RAW)) == {
        "execbound_monitor_origin",
        "execbound_lab_vendor_origin",
    }
    assert not re.search(r"https?://", RAW)
    assert not re.search(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", RAW)
    assert not re.search(r"\b(mo1|eb1)\.", RAW)
    entry = ACTIONS["Entry"]["options"]
    assert entry["path"] == "" and entry["secret"] == "" and entry["include_headers"] is False


def test_tm3_every_request_sends_json_text_the_way_tines_leaves_it_alone():
    """`content_type: json` makes Tines send a digit-only story id as a number."""
    assert {agent["name"] for agent in REQUESTS} == {"Act", "Report"}
    for agent in REQUESTS:
        options = agent["options"]
        assert "content_type" not in options, agent["name"]
        assert options["payload"].startswith("=TO_JSON("), agent["name"]
        assert options["headers"]["Content-Type"] == "application/json"
        assert re.fullmatch(r"Bearer <<CREDENTIAL\.\w+>>", options["headers"]["Authorization"])
        assert options["disable_redirect_follow"] is True
        assert options["emit_failure_event"] is True
        assert options["fail_on_status"] is False
        assert options["method"] == "post"
    report, act = ACTIONS["Report"]["options"], ACTIONS["Act"]["options"]
    assert report["url"] == "<<RESOURCE.execbound_monitor_origin>>/v1/monitor/events"
    assert report["headers"]["Authorization"] == "Bearer <<CREDENTIAL.execbound_monitor_source>>"
    assert act["headers"]["Authorization"] == "Bearer <<CREDENTIAL.execbound_lab_vendor>>"
    # The effect is never re-sent; the report is, because the intake records it once.
    assert act["retries"] == 0 and act["retry_on_status"] == []
    assert report["retries"] == 3 and report["retry_on_status"] == [429, 500, 502, 503, 504]


@pytest.mark.parametrize(
    ("status", "outcome"),
    [(200, "success"), (204, "success"), (503, "error"), (401, "error"), (0, "unknown")],
)
def test_tm4_each_result_is_a_body_the_intake_accepts(status, outcome):
    events = _result_run(status)
    sent = _payload("Report", events)
    event = parse_event(sent.encode())
    assert event == ObservationEvent(
        event_id=f"tines-{STORY_ID}-9001",
        story_id=str(STORY_ID),
        occurred_at=NOW.replace(microsecond=0),
        kind="tool_result",
        action="endpoint.isolate",
        target_ref="lab-ws-01",
        outcome=outcome,
    )
    # A re-run of the report on the same event rebuilds byte-identical text.
    assert _payload("Report", _result_run(status)) == sent


def test_tm4_the_reported_action_is_one_the_rules_treat_as_sensitive():
    body = _result_run(200)["build_result"]["body"]
    assert body["action"] in SENSITIVE_ACTIONS
    assert body["action"] not in TINES_OPERATIONS


def test_tm4_a_target_the_intake_would_refuse_never_reaches_the_action():
    assert _matches("Has target?", _result_run(200, "lab-ws-01"))
    for target in ("", "user@example.com", "a" * 97, "two words", None):
        events = _result_run(200, target)
        assert not _matches("Has target?", events), target
    assert _downstream("Has target?") >= {"Act", "Report"}


def test_tm4_the_heartbeat_is_a_body_the_intake_accepts_with_a_minute_stamp():
    events = _heartbeat_run()
    event = parse_event(_payload("Report", events).encode())
    assert event.kind == "heartbeat"
    assert event.story_id == str(STORY_ID)
    assert event.event_id == f"hb-{STORY_ID}-20260925T1804"
    assert event.occurred_at == NOW.replace(second=0)
    assert (event.action, event.target_ref, event.outcome) == (None, None, None)
    assert "build_result" not in events


def test_tm4_the_heartbeat_is_scheduled_inside_the_sources_interval_and_joins_the_report():
    assert ACTIONS["Heartbeat"]["schedule"] == [{"cron": "*/5 * * * *", "timezone": "Etc/UTC"}]
    scheduled = [agent["name"] for agent in EXPORT["agents"] if agent.get("schedule")]
    assert scheduled == ["Heartbeat"]
    assert "Report" in _downstream("Heartbeat") and "Report" in _downstream("Entry")
    # One connected set of actions is one Tines flow; Community Edition allows three.
    assert _downstream("Entry") | _downstream("Heartbeat") == set(NAMES)
    assert "Act" not in _downstream("Heartbeat")


@pytest.mark.parametrize(
    ("status", "exit_name", "reason"),
    [
        (202, "Reported", "recorded"),
        (200, "Reported", "duplicate"),
        (401, "Reporting failed", "auth_lost"),
        (409, "Reporting failed", "conflict"),
        (0, "Reporting failed", "unreachable"),
        (400, "Reporting failed", "not_recorded"),
        (404, "Reporting failed", "not_recorded"),
        (429, "Reporting failed", "not_recorded"),
        (503, "Reporting failed", "not_recorded"),
    ],
)
def test_tm4_every_report_status_reaches_exactly_one_exit(status, exit_name, reason):
    events = _result_run(200)
    events["report"] = {"status": status, "body": {"code": "X", "observation_id": "o-1"}}
    reached = [name for name in ("Recorded?", "Not recorded?") if _matches(name, events)]
    assert len(reached) == 1
    assert _edges()[reached[0]] == [exit_name]
    emitted = _payload(exit_name, events)
    assert emitted[{"Reported": "reported", "Reporting failed": "reason"}[exit_name]] == reason
    assert emitted["event_id"] == f"tines-{STORY_ID}-9001"
    assert emitted["kind"] == "tool_result"


def test_tm4_an_accepted_heartbeat_reports_freshness_without_an_observation():
    events = _heartbeat_run()
    events["report"] = {"status": 202, "body": {"observation_id": None, "duplicate": False}}
    assert _matches("Recorded?", events)
    emitted = _payload("Reported", events)
    assert emitted["reported"] == "refreshed"
    assert emitted["kind"] == "heartbeat"
    assert emitted["observation_id"] is None


def test_tm4_a_failed_heartbeat_names_itself():
    events = _heartbeat_run()
    events["report"] = {"status": 401, "body": {"code": "INVALID_SOURCE"}}
    emitted = _payload("Reporting failed", events)
    assert emitted["kind"] == "heartbeat" and emitted["reason"] == "auth_lost"
    assert emitted["code"] == "INVALID_SOURCE"


def test_tm4_no_exit_carries_a_credential_or_the_sent_body():
    for name in ("Reported", "Reporting failed"):
        text = json.dumps(ACTIONS[name]["options"]["payload"])
        assert "CREDENTIAL" not in text and "Authorization" not in text, name
        assert "TO_JSON" not in text, name
