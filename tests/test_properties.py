# SPDX-License-Identifier: AGPL-3.0-only
"""Property-based and fuzz checks for the parsing and canonicalization boundaries.

These complement the example-based tests. Strict wire models must reject unknown or
mismatched input, canonical hashes must be stable under equivalent inputs and differ
for meaningful changes, contract domains must accept exactly their values, and the
raw parsers must never raise anything but their documented error.
"""

import json
import string
from datetime import UTC, datetime, timedelta, timezone
from uuid import uuid4

import pytest
from hypothesis import assume, given, settings
from hypothesis import strategies as st
from replay_fixtures import replay_case

from execbound.audit import canonical_json
from execbound.contracts import (
    BooleanDomain,
    ContractError,
    FactSpec,
    IntegerDomain,
    StringDomain,
    _validate_domain,
    value_matches,
)
from execbound.domains import LONG_MAX, LONG_MIN
from execbound.execution.models import ExecutionError
from execbound.monitoring import http as monitoring_http
from execbound.monitoring.models import MonitorError, ObservationEvent
from execbound.requests import MAX_REQUEST_BYTES, ActionRequest, InvalidRequest, parse_request
from execbound.resolution.models import CanonicalIntent, binding_hash, intent_hash, plan_hash
from execbound.surfaces import mcp

# One bounded profile for this module: no example database on disk, no per-example
# deadline (CI hosts vary) and a fixed example budget that keeps the module fast.
settings.register_profile("execbound", database=None, deadline=None, max_examples=150)
settings.load_profile("execbound")

JSON_LONGS = st.integers(min_value=LONG_MIN, max_value=LONG_MAX)
JSON_SCALARS = st.none() | st.booleans() | JSON_LONGS | st.text(max_size=40)
JSON_VALUES = st.recursive(
    JSON_SCALARS,
    lambda inner: (
        st.lists(inner, max_size=5) | st.dictionaries(st.text(max_size=12), inner, max_size=5)
    ),
    max_leaves=30,
)
OPERATION_REFS = st.from_regex(r"\A[a-z][a-z0-9_.-]{0,79}\Z")
IDEMPOTENCY_KEYS = st.from_regex(r"\A[A-Za-z0-9._:-]{1,128}\Z")
PROVIDER_IDS = st.from_regex(r"\A[A-Za-z0-9._:-]{1,128}\Z")
IDENTIFIERS = st.from_regex(r"\A[A-Za-z0-9._:-]{1,96}\Z")
ACTIONS = st.from_regex(r"\A[A-Za-z0-9._:-]{1,64}\Z")
DNS_LABELS = st.text(
    alphabet=string.ascii_lowercase + string.digits + "-", min_size=1, max_size=63
).filter(lambda label: label[0] != "-" and label[-1] != "-")
OFFSETS = st.builds(
    timezone,
    st.timedeltas(min_value=timedelta(hours=-23), max_value=timedelta(hours=23)).map(
        lambda delta: timedelta(minutes=int(delta.total_seconds() // 60))
    ),
)
AWARE_TIMES = st.datetimes(min_value=datetime(2000, 1, 1), timezones=OFFSETS)


def reordered(value):
    """The same JSON value with every object's keys in reverse order."""
    if type(value) is dict:
        return {key: reordered(value[key]) for key in reversed(list(value))}
    if type(value) is list:
        return [reordered(item) for item in value]
    return value


@st.composite
def hostname_inputs(draw):
    """A hostname with random case and an optional trailing dot, and its canonical form."""
    labels = draw(st.lists(DNS_LABELS, min_size=1, max_size=6))
    canonical = ".".join(labels)
    assume(len(canonical) <= 253)
    flags = draw(st.lists(st.booleans(), min_size=len(canonical), max_size=len(canonical)))
    raw = "".join(c.upper() if flag else c for c, flag in zip(canonical, flags, strict=True))
    if draw(st.booleans()):
        raw += "."
    return raw, canonical


@st.composite
def selector_inputs(draw):
    kind = draw(st.sampled_from(["hostname", "canonical", "provider_id"]))
    if kind == "hostname":
        raw, expected = draw(hostname_inputs())
    elif kind == "canonical":
        expected = str(draw(st.uuids()))
        flags = draw(st.lists(st.booleans(), min_size=36, max_size=36))
        raw = "".join(c.upper() if flag else c for c, flag in zip(expected, flags, strict=True))
    else:
        raw = expected = draw(PROVIDER_IDS)
    return kind, raw, expected


@st.composite
def request_payloads(draw):
    """A valid wire request as a JSON object, plus the normalized target value."""
    kind, raw, expected = draw(selector_inputs())
    payload = {
        "operation_ref": draw(OPERATION_REFS),
        "target": {"kind": kind, "value": raw},
        "arguments": {},
        "idempotency_key": draw(IDEMPOTENCY_KEYS),
    }
    if draw(st.booleans()):
        payload["run_id"] = str(draw(st.uuids()))
    context = {}
    if draw(st.booleans()):
        context["incident_id"] = str(draw(st.uuids()))
    for name, choices in (
        ("severity", ("LOW", "MEDIUM", "HIGH", "CRITICAL")),
        ("environment", ("development", "staging", "production")),
        ("role", ("workstation", "server", "domain_controller")),
    ):
        if draw(st.booleans()):
            context[name] = draw(st.sampled_from(choices))
    if draw(st.booleans()):
        context["criticality"] = draw(st.integers(min_value=0, max_value=4))
    if context or draw(st.booleans()):
        payload["claimed_context"] = context
    return payload, expected


@st.composite
def event_payloads(draw):
    """A valid monitoring event as a JSON object."""
    kind = draw(st.sampled_from(["tool_result", "heartbeat"]))
    payload = {
        "version": 1,
        "event_id": draw(IDENTIFIERS),
        "story_id": draw(IDENTIFIERS),
        "occurred_at": draw(AWARE_TIMES).isoformat(),
        "kind": kind,
    }
    if kind == "tool_result":
        payload["action"] = draw(ACTIONS)
        payload["outcome"] = draw(st.sampled_from(["success", "error", "unknown"]))
        if draw(st.booleans()):
            payload["target_ref"] = draw(IDENTIFIERS)
    return payload


def encoded(payload) -> bytes:
    return json.dumps(payload).encode("utf-8")


# Canonical JSON


@given(JSON_VALUES)
def test_canonical_json_is_key_order_independent_and_round_trips(value):
    text = canonical_json(value)
    assert json.loads(text) == value
    assert canonical_json(json.loads(text)) == text
    assert canonical_json(reordered(value)) == text


@given(st.floats(allow_nan=True, allow_infinity=True) | st.floats(allow_nan=False))
def test_canonical_json_rejects_every_float(number):
    with pytest.raises(ValueError):
        canonical_json(number)
    with pytest.raises(ValueError):
        canonical_json({"value": [number]})


@given(st.dictionaries(st.integers() | st.booleans() | st.none(), st.integers(), min_size=1))
def test_canonical_json_rejects_non_string_keys(mapping):
    with pytest.raises(ValueError):
        canonical_json(mapping)


# Wire requests


@given(request_payloads())
def test_valid_requests_parse_normalize_and_round_trip(case):
    payload, expected = case
    request = parse_request(encoded(payload))
    assert isinstance(request, ActionRequest)
    assert request.target.value == expected
    assert parse_request(encoded(reordered(payload))) == request
    assert parse_request(request.model_dump_json().encode("utf-8")) == request


# Every closed wire object. "arguments" is deliberately absent: it is an open map of
# bounded scalars whose names belong to the resolved action's catalog spec, checked
# during resolution rather than at the wire boundary. tests/test_requests.py covers the
# names and values it accepts and rejects.
@given(
    request_payloads(),
    st.sampled_from(["", "target", "claimed_context"]),
    st.text(alphabet=string.ascii_letters + "_", min_size=1, max_size=20),
    JSON_SCALARS,
)
def test_unknown_keys_anywhere_are_rejected(case, level, key, value):
    payload, _ = case
    known = {
        "": {
            "operation_ref",
            "target",
            "arguments",
            "idempotency_key",
            "run_id",
            "claimed_context",
        },
        "target": {"kind", "value"},
        "claimed_context": {"incident_id", "severity", "environment", "role", "criticality"},
    }
    assume(key not in known[level])
    container = payload if level == "" else payload.setdefault(level, {})
    container[key] = value
    with pytest.raises(InvalidRequest):
        parse_request(encoded(payload))


@given(
    request_payloads(), st.sampled_from(["operation_ref", "target", "arguments", "idempotency_key"])
)
def test_missing_required_fields_are_rejected(case, field):
    payload, _ = case
    del payload[field]
    with pytest.raises(InvalidRequest):
        parse_request(encoded(payload))


@given(
    request_payloads(),
    st.sampled_from(["operation_ref", "target", "arguments", "idempotency_key", "run_id"]),
    st.integers() | st.booleans() | st.none() | st.lists(st.integers(), max_size=2),
)
def test_mismatched_field_types_are_rejected(case, field, value):
    payload, _ = case
    assume(not (field == "run_id" and value is None))
    payload[field] = value
    with pytest.raises(InvalidRequest):
        parse_request(encoded(payload))


@given(request_payloads(), st.floats(allow_nan=False, allow_infinity=False))
def test_float_numbers_are_rejected_even_when_integral(case, number):
    payload, _ = case
    payload.setdefault("claimed_context", {})["criticality"] = number
    with pytest.raises(InvalidRequest):
        parse_request(encoded(payload))


@given(request_payloads())
def test_duplicate_keys_are_rejected(case):
    payload, _ = case
    text = json.dumps(payload)
    duplicated = text[:-1] + ', "idempotency_key": "duplicate"}'
    with pytest.raises(InvalidRequest):
        parse_request(duplicated.encode("utf-8"))


@given(st.binary(max_size=MAX_REQUEST_BYTES + 64))
def test_parse_request_raises_only_invalid_request_for_arbitrary_bytes(raw):
    try:
        result = parse_request(raw)
    except InvalidRequest:
        return
    assert isinstance(result, ActionRequest)
    assert len(raw) <= MAX_REQUEST_BYTES


@given(JSON_VALUES)
def test_parse_request_raises_only_invalid_request_for_arbitrary_json(value):
    try:
        result = parse_request(encoded(value))
    except InvalidRequest:
        return
    assert isinstance(result, ActionRequest)


# Canonical hashes


@given(
    st.sampled_from(["tenant_id", "principal_id", "account_id", "target_id"]),
    st.uuids(),
)
@settings(max_examples=50)
def test_intent_hash_is_stable_under_revalidation_and_changes_with_identity(field, replacement):
    intent = replay_case()["resolved"].intent
    revalidated = CanonicalIntent.model_validate_json(intent.model_dump_json())
    assert intent_hash(revalidated) == intent_hash(intent)
    assume(getattr(intent, field) != replacement)
    assert intent_hash(intent.model_copy(update={field: replacement})) != intent_hash(intent)


@given(st.integers(min_value=-86400, max_value=86400), IDEMPOTENCY_KEYS)
@settings(max_examples=50)
def test_plan_hash_ignores_only_the_request_and_resolution_time(delta, key):
    case = replay_case()
    resolved, versions = case["resolved"], case["bundle"].security_versions
    equivalent = resolved.model_copy(
        update={
            "resolved_at": resolved.resolved_at + timedelta(seconds=delta),
            "request": resolved.request.model_copy(update={"idempotency_key": key}),
        }
    )
    assert plan_hash(equivalent, versions) == plan_hash(resolved, versions)


@given(
    st.sampled_from(
        [
            "resource_version",
            "mapping_version",
            "context_contract_version",
            "resource_provider_id",
            "valid_until",
            "alias_id",
            "fact_value",
            "versions",
        ]
    ),
    st.integers(min_value=1, max_value=86400),
)
@settings(max_examples=50)
def test_plan_hash_changes_with_every_frozen_authority_field(field, seed):
    case = replay_case()
    resolved, versions = case["resolved"], case["bundle"].security_versions
    changed_versions = versions
    if field == "valid_until":
        changed = resolved.model_copy(
            update={"valid_until": resolved.valid_until + timedelta(seconds=seed)}
        )
    elif field == "alias_id":
        changed = resolved.model_copy(update={"alias_id": uuid4()})
    elif field == "fact_value":
        facts = list(resolved.facts)
        facts[0] = facts[0].model_copy(update={"value": f"changed-{seed}"})
        changed = resolved.model_copy(update={"facts": tuple(facts)})
    elif field == "versions":
        changed = resolved
        changed_versions = versions.model_copy(update={"limits": f"limits-{seed}"})
    else:
        changed = resolved.model_copy(update={field: f"{field}-{seed}"})
    assert plan_hash(changed, changed_versions) != plan_hash(resolved, versions)


@given(st.integers(min_value=-86400, max_value=86400), st.integers(min_value=1, max_value=86400))
@settings(max_examples=50)
def test_binding_hash_ignores_timestamps_and_validity_but_not_values(delta, seed):
    resolved = replay_case()["resolved"]
    shifted_facts = tuple(
        fact.model_copy(
            update={
                "observed_at": fact.observed_at + timedelta(seconds=delta),
                "valid_until": fact.valid_until + timedelta(seconds=delta),
            }
        )
        for fact in resolved.facts
    )
    shifted = resolved.model_copy(
        update={
            "facts": shifted_facts,
            "valid_until": resolved.valid_until + timedelta(seconds=delta),
            "resolved_at": resolved.resolved_at + timedelta(seconds=delta),
        }
    )
    assert binding_hash(shifted) == binding_hash(resolved)
    facts = list(resolved.facts)
    facts[-1] = facts[-1].model_copy(update={"value": f"changed-{seed}"})
    assert binding_hash(resolved.model_copy(update={"facts": tuple(facts)})) != binding_hash(
        resolved
    )
    facts = list(resolved.facts)
    facts[-1] = facts[-1].model_copy(update={"source_version": f"v-{seed}"})
    assert binding_hash(resolved.model_copy(update={"facts": tuple(facts)})) != binding_hash(
        resolved
    )


# Context contract domains


def spec(cedar_type, domain):
    return FactSpec("fact", cedar_type, domain, "inventory", None)


@given(JSON_LONGS, JSON_LONGS, JSON_LONGS, st.booleans())
def test_integer_domains_accept_exactly_their_range(first, second, candidate, flag):
    minimum, maximum = sorted((first, second))
    integer = spec("Long", IntegerDomain(minimum, maximum))
    assert value_matches(integer, candidate) is (minimum <= candidate <= maximum)
    assert value_matches(integer, flag) is False
    assert value_matches(integer, str(candidate)) is False
    _validate_domain(integer)


@given(JSON_LONGS, JSON_LONGS)
def test_integer_domains_outside_long_or_inverted_are_invalid(first, second):
    assume(first != second)
    minimum, maximum = sorted((first, second))
    with pytest.raises(ContractError):
        _validate_domain(spec("Long", IntegerDomain(maximum, minimum)))
    with pytest.raises(ContractError):
        _validate_domain(spec("Long", IntegerDomain(minimum, LONG_MAX + 1)))
    with pytest.raises(ContractError):
        _validate_domain(spec("Long", IntegerDomain(LONG_MIN - 1, maximum)))


@given(
    st.frozensets(st.text(min_size=1, max_size=254), min_size=1, max_size=8), st.text(max_size=254)
)
def test_string_domains_accept_exactly_their_members(members, candidate):
    string_spec = spec("String", StringDomain(members))
    _validate_domain(string_spec)
    assert value_matches(string_spec, candidate) is (candidate in members)
    assert value_matches(string_spec, 1) is False
    assert value_matches(string_spec, True) is False


@given(st.text(min_size=255, max_size=300))
def test_string_domains_with_an_overlong_or_no_member_are_invalid(overlong):
    with pytest.raises(ContractError):
        _validate_domain(spec("String", StringDomain(frozenset({overlong}))))
    with pytest.raises(ContractError):
        _validate_domain(spec("String", StringDomain(frozenset())))


@given(JSON_LONGS, st.text(max_size=10), st.booleans())
def test_boolean_domains_accept_only_booleans(number, text, flag):
    boolean = spec("Boolean", BooleanDomain())
    _validate_domain(boolean)
    assert value_matches(boolean, flag) is True
    assert value_matches(boolean, number) is False
    assert value_matches(boolean, text) is False


# Monitoring intake


@given(event_payloads())
def test_valid_events_parse_and_normalize_time_to_utc(payload):
    event = monitoring_http.parse_event(encoded(payload))
    assert isinstance(event, ObservationEvent)
    assert event.occurred_at.tzinfo is UTC
    assert event.occurred_at.isoformat() != "" and event.kind == payload["kind"]
    assert monitoring_http.parse_event(encoded(reordered(payload))) == event


@given(event_payloads(), st.sampled_from(["action", "target_ref", "outcome"]))
def test_heartbeats_cannot_carry_tool_result_fields(payload, field):
    assume(payload["kind"] == "heartbeat")
    payload[field] = "success" if field == "outcome" else "value"
    with pytest.raises(MonitorError) as caught:
        monitoring_http.parse_event(encoded(payload))
    assert caught.value.code == "INVALID_EVENT"


@given(event_payloads(), st.sampled_from(["action", "outcome"]))
def test_tool_results_require_action_and_outcome(payload, field):
    assume(payload["kind"] == "tool_result")
    del payload[field]
    with pytest.raises(MonitorError) as caught:
        monitoring_http.parse_event(encoded(payload))
    assert caught.value.code == "INVALID_EVENT"


@given(
    event_payloads(),
    st.text(alphabet=string.ascii_letters + "_", min_size=1, max_size=16),
    JSON_SCALARS,
)
def test_events_with_unknown_keys_are_rejected(payload, key, value):
    assume(
        key
        not in {
            "version",
            "event_id",
            "story_id",
            "occurred_at",
            "kind",
            "action",
            "target_ref",
            "outcome",
        }
    )
    payload[key] = value
    with pytest.raises(MonitorError) as caught:
        monitoring_http.parse_event(encoded(payload))
    assert caught.value.code == "INVALID_EVENT"


@given(st.binary(max_size=monitoring_http.MAX_EVENT_BYTES + 64))
def test_parse_event_raises_only_invalid_event_for_arbitrary_bytes(raw):
    try:
        result = monitoring_http.parse_event(raw)
    except MonitorError as caught:
        assert caught.code == "INVALID_EVENT"
        return
    assert isinstance(result, ObservationEvent)
    assert len(raw) <= monitoring_http.MAX_EVENT_BYTES


@given(JSON_VALUES)
def test_parse_event_raises_only_invalid_event_for_arbitrary_json(value):
    try:
        result = monitoring_http.parse_event(encoded(value))
    except MonitorError as caught:
        assert caught.code == "INVALID_EVENT"
        return
    assert isinstance(result, ObservationEvent)


# MCP envelope


@given(st.binary(max_size=mcp.MAX_MCP_BYTES + 64))
def test_validate_envelope_raises_only_invalid_request_for_arbitrary_bytes(raw):
    try:
        body = mcp.validate_envelope(raw)
    except ExecutionError as caught:
        assert caught.code == "INVALID_REQUEST"
        return
    assert isinstance(body, dict) and body["jsonrpc"] == "2.0"
    assert 0 < len(raw) <= mcp.MAX_MCP_BYTES


@given(
    st.integers(min_value=0, max_value=10**9) | st.text(max_size=128),
    st.sampled_from(["inputResponses", "requestState", "task"]),
    JSON_VALUES,
)
def test_envelopes_with_protocol_decision_fields_are_rejected(identifier, field, value):
    body = {
        "jsonrpc": "2.0",
        "id": identifier,
        "method": "tools/call",
        "params": {"name": "execute", "arguments": {}},
    }
    assert mcp.validate_envelope(encoded(body)) == body
    body["params"][field] = value
    with pytest.raises(ExecutionError) as caught:
        mcp.validate_envelope(encoded(body))
    assert caught.value.code == "INVALID_REQUEST"


@given(JSON_VALUES.filter(lambda value: not isinstance(value, dict)))
def test_a_tool_calls_arguments_may_be_absent_and_are_an_object_when_present(value):
    body = {"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": "list_actions"}}
    assert mcp.validate_envelope(encoded(body)) == body
    body["params"]["arguments"] = value
    with pytest.raises(ExecutionError) as caught:
        mcp.validate_envelope(encoded(body))
    assert caught.value.code == "INVALID_REQUEST"
