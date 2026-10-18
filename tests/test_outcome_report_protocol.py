# SPDX-License-Identifier: AGPL-3.0-only
"""The server parses a checkpoint report through the published protocol model (#37).

The report an external executor sends to `POST /v1/executions/{id}/outcome` is defined once, in
the Apache-2.0 `execbound_protocol.report` module, and `protocol/executor/v1/` publishes its
JSON Schema. The server reads every report through that model: `execution.outcomes` names it
rather than keeping a copy, so the published schema is the one the route validates with and a
change to either is a change to both. `parse_report` keeps everything it did before the model
moved: the size bound, the strict syntax pass before validation, one refusal code for every
malformed body, and no exception context that could carry the report secret.
"""

import json
from pathlib import Path

import pytest
from execbound_protocol import report as protocol
from pydantic import ValidationError

from execbound.execution import models, outcomes
from execbound.execution.models import ExecutionError
from execbound.execution.outcomes import parse_report
from execbound.requests import MAX_REQUEST_BYTES

ROOT = Path(__file__).resolve().parents[1]
SCHEMA = ROOT / "protocol" / "executor" / "v1" / "checkpoint-report.schema.json"
SECRET = "report-secret-" + "x" * 30
BINDING = {
    "operation_id": "00000000-0000-0000-0000-000000000017",
    "account_id": "00000000-0000-0000-0000-000000000003",
    "intent_hash": "a" * 64,
    "plan_hash": "b" * 64,
}
RECORD = {
    "version": 1,
    **BINDING,
    "outcome": "EXECUTED",
    "reason": "EXECUTED",
    "reported_at": "2026-10-09T00:00:00Z",
}
ENVELOPE = {"version": 1, "key_id": "executor-v1", "record": RECORD, "signature": "c" * 128}
REPORTED = {"report_secret": SECRET, "reported_at": "2026-10-09T00:00:00+00:00"}

ADMITTED = {
    "unknown": {**REPORTED, "outcome": "UNKNOWN"},
    "asserted execution": {**REPORTED, "outcome": "EXECUTED", "reason": "EXECUTED"},
    "asserted failure": {
        **REPORTED,
        "outcome": "FAILED_EFFECT_UNKNOWN",
        "reason": "REPORTED_FAILURE",
    },
    "asserted non-execution": {
        **REPORTED,
        "outcome": "FAILED_NOT_EXECUTED",
        "reason": "TARGET_NOT_FOUND",
    },
    "signed record": {
        "report_secret": SECRET,
        "outcome": "EXECUTED",
        "reason": "EXECUTED",
        "record": ENVELOPE,
    },
    "attestation": {
        "report_secret": SECRET,
        "outcome": "FAILED_NOT_EXECUTED",
        "reason": "VERSION_MISMATCH",
        "attestation": "aaaa.bbbb.cccc",
    },
    "journal": {
        "report_secret": SECRET,
        "outcome": "EXECUTED",
        "reason": "EXECUTED",
        "journal": {"version": 1},
    },
}
REFUSED = {
    "unnamed field": {**ADMITTED["asserted execution"], "act": "a-continuation-token"},
    "no secret": {"outcome": "UNKNOWN", "reported_at": REPORTED["reported_at"]},
    "short secret": {**ADMITTED["unknown"], "report_secret": "too-short"},
    "secret spelling": {**ADMITTED["unknown"], "report_secret": SECRET + "/"},
    "unknown outcome": {**REPORTED, "outcome": "DONE"},
    "unknown reason": {**REPORTED, "outcome": "EXECUTED", "reason": "SUCCEEDED"},
    "unpaired reason": {**REPORTED, "outcome": "EXECUTED", "reason": "VERSION_MISMATCH"},
    "unknown with a reason": {**REPORTED, "outcome": "UNKNOWN", "reason": "REPORTED_FAILURE"},
    "unknown with evidence": {"report_secret": SECRET, "outcome": "UNKNOWN", "record": ENVELOPE},
    "terminal outcome without a reason": {**REPORTED, "outcome": "EXECUTED"},
    "signed reported failure": {
        "report_secret": SECRET,
        "outcome": "FAILED_EFFECT_UNKNOWN",
        "reason": "REPORTED_FAILURE",
        "record": ENVELOPE,
    },
    "two pieces of evidence": {
        **ADMITTED["signed record"],
        "attestation": "aaaa.bbbb.cccc",
    },
    "a time beside evidence": {**ADMITTED["signed record"], **REPORTED},
    "neither a time nor evidence": {
        "report_secret": SECRET,
        "outcome": "EXECUTED",
        "reason": "EXECUTED",
    },
    "a time without an offset": {**ADMITTED["unknown"], "reported_at": "2026-10-09T00:00:00"},
    "attestation spelling": {**ADMITTED["attestation"], "attestation": "not-a-compact-jws"},
    "record not an object": {**ADMITTED["signed record"], "record": "a signed outcome"},
    "secret not a string": {**ADMITTED["unknown"], "report_secret": 12345},
}


def test_the_server_names_the_protocol_model_and_its_types():
    """No copy: the route, the agent OpenAPI document and the published schema read one model,
    and the grant's secret and the asserted outcome read the same vocabulary."""
    assert outcomes.OutcomeReport is protocol.OutcomeReport
    assert outcomes.JwsToken is protocol.JwsToken
    assert models.ReportSecret is protocol.ReportSecret
    assert models.ReportedResult is protocol.ReportedResult
    assert models.AssertedReason is protocol.AssertedReason
    assert protocol.MAX_REPORT_BYTES == MAX_REQUEST_BYTES


def test_the_published_schema_is_the_one_the_route_validates_with():
    published = json.loads(SCHEMA.read_text(encoding="utf-8"))
    assert published == outcomes.OutcomeReport.model_json_schema()


@pytest.mark.parametrize("name", sorted(ADMITTED))
def test_a_report_the_server_admits_the_protocol_model_admits(name: str):
    raw = json.dumps(ADMITTED[name]).encode()
    parsed = parse_report(raw)
    assert isinstance(parsed, protocol.OutcomeReport)
    assert parsed == protocol.OutcomeReport.model_validate_json(raw)


@pytest.mark.parametrize("name", sorted(REFUSED))
def test_a_report_the_protocol_model_refuses_the_server_refuses_alike(name: str):
    raw = json.dumps(REFUSED[name]).encode()
    with pytest.raises(ValidationError):
        protocol.OutcomeReport.model_validate_json(raw)
    with pytest.raises(ExecutionError) as raised:
        parse_report(raw)
    assert raised.value.code == "INVALID_REQUEST"
    # Raised outside the handler: no validation detail, and so no secret, rides along.
    assert raised.value.__context__ is None and raised.value.__cause__ is None
    assert SECRET not in repr(raised.value)


@pytest.mark.parametrize(
    "raw",
    [
        b"",
        b'{"report_secret":"' + SECRET.encode() + b'","report_secret":"' + SECRET.encode() + b'"}',
        json.dumps({**ADMITTED["unknown"], "reported_at": 1.5}).encode(),
        b'{"outcome": NaN}',
        b"\xff",
        json.dumps({**ADMITTED["unknown"], "padding": "x" * MAX_REQUEST_BYTES}).encode(),
    ],
    ids=["empty", "repeated key", "fraction", "not a number", "not UTF-8", "over the bound"],
)
def test_the_parser_keeps_its_own_syntax_and_size_refusals(raw: bytes):
    """What the model never sees: the server's own pass over the bytes, refused the same."""
    with pytest.raises(ExecutionError) as raised:
        parse_report(raw)
    assert raised.value.code == "INVALID_REQUEST"
    assert raised.value.__context__ is None and raised.value.__cause__ is None


def test_the_signed_and_evidence_properties_read_the_one_piece_of_evidence():
    signed = parse_report(json.dumps(ADMITTED["signed record"]).encode())
    assert signed.signed == ("record",)
    assert signed.evidence == json.dumps(ENVELOPE, sort_keys=True, separators=(",", ":")).encode()
    attested = parse_report(json.dumps(ADMITTED["attestation"]).encode())
    assert (attested.signed, attested.evidence) == (("attestation",), b"aaaa.bbbb.cccc")
    bare = parse_report(json.dumps(ADMITTED["unknown"]).encode())
    assert (bare.signed, bare.evidence) == ((), None)
