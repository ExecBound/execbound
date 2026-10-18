# SPDX-License-Identifier: AGPL-3.0-only
"""TG15: the importable Gate story, checked the way the Execute story is checked."""

import json
import re
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
STORY = ROOT / "integrations/tines/execbound-gate.json"
RAW = STORY.read_text()
EXPORT = json.loads(RAW)
ACTIONS = {agent["name"]: agent for agent in EXPORT["agents"]}
EXECUTE_STORY = json.loads((ROOT / "integrations/tines/execbound-governed-action.json").read_text())
EXECUTE_ACTIONS = {agent["name"]: agent for agent in EXECUTE_STORY["agents"]}


def _downstream(start):
    names = [agent["name"] for agent in EXPORT["agents"]]
    edges = {}
    for link in EXPORT["links"]:
        edges.setdefault(names[link["source"]], []).append(names[link["receiver"]])
    seen, stack = set(), [start]
    while stack:
        name = stack.pop()
        if name not in seen:
            seen.add(name)
            stack.extend(edges.get(name, []))
    return seen


def test_the_committed_story_is_what_the_generator_writes():
    checked = subprocess.run(
        [sys.executable, str(ROOT / "integrations/tines/tines_gate_story.py"), "--check"],
        check=False,
    )
    assert checked.returncode == 0


def test_the_story_names_its_credentials_and_resources_and_nothing_else():
    assert set(re.findall(r"CREDENTIAL\.(\w+)", RAW)) == {
        "execbound_gate",
        "execbound_gate_vendor",
        "execbound_gate_signing",
    }
    assert set(re.findall(r"RESOURCE\.(\w+)", RAW)) <= {
        "execbound_origin",
        "execbound_vendor_origin",
        "execbound_gate_key_id",
        "execbound_poll_seconds",
        "execbound_wait_seconds",
    }
    assert not re.search(r"https?://", RAW)
    assert not re.search(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", RAW)


def test_the_decision_request_is_the_execute_storys_wire_body():
    gate, execute = ACTIONS["Execute"]["options"], EXECUTE_ACTIONS["Execute"]["options"]
    assert gate["payload"] == execute["payload"]
    assert gate["url"] == execute["url"]
    assert gate["headers"]["Authorization"] == "Bearer <<CREDENTIAL.execbound_gate>>"


def test_the_vendor_call_is_the_grants_command_sent_once():
    vendor = ACTIONS["Vendor call"]["options"]
    assert vendor["payload"] == "=TO_JSON(grant.provider_command)"
    assert vendor["retries"] == 0 and vendor["retry_on_status"] == []
    assert vendor["headers"]["Authorization"] == "Bearer <<CREDENTIAL.execbound_gate_vendor>>"
    assert "prepare." not in json.dumps(vendor)
    grant = ACTIONS["Grant"]["options"]["payload"]
    assert "prepare." not in json.dumps(grant)


def test_a_regrant_and_a_missing_command_never_reach_the_vendor():
    assert "Vendor call" not in _downstream("Regranted?")
    assert "Vendor call" not in _downstream("No provider command?")
    assert "Vendor call" not in _downstream("Act window closed?")
    assert "Lookup journal" in _downstream("Vendor uncertain?")
    assert "Vendor call" not in _downstream("Lookup journal")


def test_no_exit_carries_the_secret_or_the_signature():
    for name in ("Outcome", "Needs administrator", "Refused: no reference"):
        payload = ACTIONS[name]["options"]["payload"]
        text = json.dumps(payload)
        assert "report_secret" not in text, name
        assert "JWT_SIGN" not in text and "sign_non_execution" not in text, name
        assert not {"attestation", "journal", "record", "binding"} & set(payload), name


def test_every_report_body_carries_exactly_one_kind_of_evidence():
    kinds = {
        "Report journal": "journal",
        "Report lookup": "journal",
        "Report attestation": "attestation",
        "Report unknown": "reported_at",
    }
    for name, kind in kinds.items():
        body = ACTIONS[name]["options"]["payload"]["body"]
        present = [
            key for key in ("journal", "attestation", "reported_at", "record") if f'"{key}"' in body
        ]
        assert present == [kind], name


def test_the_signature_is_es256_under_the_signing_credential_and_the_resource_kid():
    sign = ACTIONS["Sign non-execution"]["options"]["payload"]["attestation"]
    assert sign.startswith("=JWT_SIGN(")
    assert 'CREDENTIAL.execbound_gate_signing, "ES256"' in sign
    assert 'OBJECT("kid", RESOURCE.execbound_gate_key_id)' in sign
    for claim in (
        "domain",
        "version",
        "operation_id",
        "account_id",
        "intent_hash",
        "plan_hash",
        "outcome",
        "reason",
        "reported_at",
    ):
        assert f'"{claim}"' in sign, claim


def test_the_entry_and_the_exits_are_the_declared_ones():
    guids = {agent["name"]: agent["guid"] for agent in EXPORT["agents"]}
    assert EXPORT["entry_agent_guid"] == guids["Entry"]
    assert set(EXPORT["exit_agent_guids"]) == {
        guids[n] for n in ("Outcome", "Needs administrator", "Refused: no reference")
    }


def test_the_diagram_layout_names_only_this_storys_actions():
    """A layout keyed by another story's action guids positions nothing Tines can find."""
    layout = json.loads(EXPORT["diagram_layout"])
    assert set(layout) <= {agent["guid"] for agent in EXPORT["agents"]}


# The exits' fields are Tines formulas, and what they say on each path is the contract an
# operator reads. The evaluator below covers exactly the subset those formulas use (IF,
# IS_PRESENT, DEFAULT, AND, OR, SWITCH, comparisons, string and integer literals, null and
# event paths) so each path's answer can be read rather than pattern-matched. An event
# path an action did not run on is absent, as in Tines, and absent compares unequal.
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
    if name == "IS_PRESENT":
        return _present(values[0])
    if name == "DEFAULT":
        return values[0] if _present(values[0]) else values[1]
    if name == "AND":
        return all(values)
    if name == "OR":
        return any(values)
    raise AssertionError(f"Unsupported formula function {name}")


def _exit(name, events):
    """What one exit emits for the events of one path through the story."""
    payload = ACTIONS[name]["options"]["payload"]
    return {
        key: _evaluate(_parse(value[1:]), events)
        if isinstance(value, str) and value.startswith("=")
        else value
        for key, value in payload.items()
    }


NEEDS_ADMINISTRATOR = (
    "Stop. Hand this execution to an ExecBound administrator; never resend under a new "
    "reference and never repeat the vendor call."
)
ALREADY_RECORDED = "This reference already has a recorded result; this run did not call the vendor."
GRANTED = {
    "prepare": {"reference": "INC-1"},
    "execute": {
        "status": 202,
        "body": {"state": "DISPATCH_COMMITTED", "execution_id": "e-1", "request_ref": "EB-1"},
    },
    "grant": {"execution_id": "e-1", "act_open": "yes", "has_command": "yes"},
}
# Each path that reaches a report, as the events the report's exit can read.
PATHS = {
    "unknown after a vendor conflict": {
        **GRANTED,
        "vendor_call": {"status": 409},
        "report_unknown": {"body": {"outcome": "UNKNOWN"}},
        "report": {"status": 200, "body": {"state": "INDETERMINATE"}},
    },
    "unknown after a lookup found nothing": {
        **GRANTED,
        "vendor_call": {"status": 0},
        "lookup_journal": {"status": 404},
        "report_unknown": {"body": {"outcome": "UNKNOWN"}},
        "report": {"status": 200, "body": {"state": "INDETERMINATE"}},
    },
    "act window closed": {
        **GRANTED,
        "grant": {**GRANTED["grant"], "act_open": "no"},
        "report_attestation": {"body": {"outcome": "FAILED_NOT_EXECUTED"}},
        "report": {"status": 200, "body": {"state": "FAILED_NOT_EXECUTED"}},
    },
    "vendor refused": {
        **GRANTED,
        "vendor_call": {"status": 403},
        "report_attestation": {"body": {"outcome": "FAILED_NOT_EXECUTED"}},
        "report": {"status": 200, "body": {"state": "FAILED_NOT_EXECUTED"}},
    },
    "vendor journal": {
        **GRANTED,
        "vendor_call": {"status": 200},
        "report_journal": {"body": {"outcome": "EXECUTED"}},
        "report": {"status": 200, "body": {"state": "EXECUTED"}},
    },
    "journal found by lookup": {
        **GRANTED,
        "vendor_call": {"status": 502},
        "lookup_journal": {"status": 200},
        "report_lookup": {"body": {"outcome": "EXECUTED"}},
        "report": {"status": 200, "body": {"state": "EXECUTED"}},
    },
}


@pytest.mark.parametrize(
    "path", ["unknown after a vendor conflict", "unknown after a lookup found nothing"]
)
def test_a_report_that_settled_nothing_hands_the_execution_to_an_administrator(path):
    """An UNKNOWN report is accepted and settles nothing, so the story must stop there.

    The gateway answers 200 with state INDETERMINATE, which reaches `Outcome` through
    `Reported?`. What that exit says is the administrator hand-off and a code, never that
    ExecBound settled the report, and it names no tier because nothing settled at one.
    """
    emitted = _exit("Outcome", PATHS[path])
    assert emitted["outcome"] == "needs_administrator"
    assert emitted["message"] == NEEDS_ADMINISTRATOR
    assert emitted["code"] == "VENDOR_OUTCOME_UNKNOWN"
    assert emitted["tier"] is None


def test_the_act_window_closed_path_never_says_the_vendor_was_called():
    emitted = _exit("Outcome", PATHS["act window closed"])
    assert emitted["outcome"] == "final"
    assert emitted["message"].startswith("The vendor was not called")
    assert "called once" not in emitted["message"]
    assert emitted["vendor_status"] is None
    assert (emitted["tier"], emitted["code"]) == ("ATTESTED", None)


@pytest.mark.parametrize(
    ("path", "tier"),
    [
        ("vendor refused", "ATTESTED"),
        ("vendor journal", "PROVIDER_VERIFIED"),
        ("journal found by lookup", "PROVIDER_VERIFIED"),
    ],
)
def test_a_settled_report_after_the_vendor_call_names_its_tier(path, tier):
    emitted = _exit("Outcome", PATHS[path])
    assert emitted["outcome"] == "final"
    assert emitted["message"] == "The vendor was called once and ExecBound settled the report."
    assert (emitted["tier"], emitted["code"]) == (tier, None)


@pytest.mark.parametrize("path", ["vendor journal", "journal found by lookup", "act window closed"])
def test_a_refused_report_names_no_tier(path):
    """`tier` says what settled, so a report the gateway refused names none.

    The evidence the story built is still in its events, which is exactly why the tier must
    be read from the gateway's acceptance and not from which report body was assembled.
    """
    refused = {**PATHS[path], "report": {"status": 400, "body": {"code": "INVALID_RECORD"}}}
    emitted = _exit("Needs administrator", refused)
    assert emitted["outcome"] == "needs_administrator"
    assert emitted["message"] == NEEDS_ADMINISTRATOR
    assert (emitted["tier"], emitted["code"]) == (None, "INVALID_RECORD")


def test_every_http_action_emits_an_event_on_a_transport_failure():
    """Tines emits nothing for a timeout or a DNS failure unless the action says to.

    Its default emits an event for an HTTP error status only, so a timed-out vendor call
    stopped the live trial's run with no event, and the journal lookup that status 0 routes
    to never ran. Every HTTP action here must emit, or a lost response strands a grant.
    """
    requests = [a for a in EXPORT["agents"] if a["type"] == "Agents::HTTPRequestAgent"]
    assert {a["name"] for a in requests} == {"Execute", "Vendor call", "Lookup journal", "Report"}
    assert all(a["options"]["emit_failure_event"] is True for a in requests)


def test_a_report_the_gateway_never_answered_is_handed_over_as_such():
    """A report lost in transport says so; the vendor's outcome is already in the journal."""
    lost = {**PATHS["vendor journal"], "report": {"status": 0, "body": ""}}
    emitted = _exit("Needs administrator", lost)
    assert (emitted["outcome"], emitted["code"]) == ("needs_administrator", "REPORT_NOT_ACCEPTED")
    assert emitted["tier"] is None


@pytest.mark.parametrize(
    ("state", "outcome"),
    [
        ("EXECUTED", "final"),
        ("FAILED_NOT_EXECUTED", "final"),
        ("FAILED_EFFECT_UNKNOWN", "uncertain"),
    ],
)
def test_a_retry_of_a_settled_reference_reports_the_recorded_result(state, outcome):
    """Sending a settled reference again answers 200 with the recorded state and no grant.

    The first run called the vendor and reported; this run did neither, so the exit says the
    recorded result under the Execute story's outcome for that state, and says this run did
    not call the vendor. It names no tier because this run settled nothing (found in the
    live trial, where a retry of an executed reference exited as "refused").
    """
    retried = {
        "prepare": {"reference": "GATE-1"},
        "execute": {"status": 200, "body": {"state": state, "execution_id": "e-1"}},
    }
    emitted = _exit("Outcome", retried)
    assert emitted["outcome"] == outcome
    assert emitted["state"] == state
    assert emitted["message"] == ALREADY_RECORDED
    assert (emitted["tier"], emitted["vendor_status"]) == (None, None)


def test_every_exit_formula_is_one_the_evaluator_reads():
    """The evaluator is exercised on every field of every exit, so none is skipped silently."""
    for name in ("Outcome", "Needs administrator", "Refused: no reference"):
        for path in PATHS.values():
            _exit(name, path)
        _exit(name, {})


def test_the_gate_story_carries_no_secret_no_origin_and_no_tenant():
    """It is published, and Getting started offers it as a download (#678), so it must be safe
    to publish, held exactly as the Execute story is."""
    assert "https://" not in RAW
    assert "tines.com" not in RAW
    assert re.search(r"[\w.+-]+@[\w-]+\.[\w.]+", RAW) is None
    assert EXPORT["recipients"] == []
    # The generator writes one fixed identifier naming the story, never an exporting tenant;
    # the Execute story's export carried its tenant there and is scrubbed to None.
    assert {agent["origin_story_identifier"] for agent in EXPORT["agents"]} == {
        "cloud:execbound:gate"
    }
    entry = ACTIONS["Entry"]["options"]
    assert entry["path"] == ""
    assert entry["secret"] == ""
