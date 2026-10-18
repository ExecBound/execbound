# SPDX-License-Identifier: AGPL-3.0-only
"""The checkpoint report's conformance module, run against the vectors' own executor (#37).

`execbound_protocol.checkpoint_conformance` is the Apache-2.0 module a vendor runs against the
reports its own executor writes: given a vector's grant and scenario, the executor writes a
report, and the module reads it as the outcome route reads it and checks what it would settle
(`docs/protocol/EXECUTOR_PROTOCOL.md`, section 2.10). Here it reads the reports of the vectors'
own executor, `checkpoint_vectors.Scenario.report`, which wrote the published file and which
`tests/test_checkpoint_report_server.py` holds to the server.

A module that passes everything proves nothing, so most of this file runs it against
deliberately broken executors: one that writes a number with a fraction, one that sends two
pieces of evidence, one that pairs REPORTED_FAILURE with an outcome that refunds, one that
reports UNKNOWN as a terminal outcome, one that adds a field of its own, one that presents
another grant's secret, one that signs with a key outside the ring, one that signs for another
grant, one that reports EXECUTED while its signed evidence says otherwise, one that claims a
signed tier with no signature, one that reports a refused conditional write as a missing target,
and one that reports a cancellation as a missing target. Each must fail, for every vector that
can show its fault, at the check that names it.
"""

import ast
import dataclasses
import json
import sys
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any

import pytest
from checkpoint_vectors import (
    BY_NAME,
    ED25519_SEED,
    FAULTS_BY_NAME,
    INDEX,
    OUTSIDE_ED25519_SEED,
    OUTSIDE_ES256_SCALAR,
    OUTSIDE_JOURNAL_KEY,
    PUBLISHED,
    REFUSAL_INDEX,
    SCENARIOS,
    Scenario,
    attestation,
    body,
    ed25519_public,
    es256_public,
    fixed_grant,
    instant,
    journal,
    published,
    record,
    reported_at,
    ring,
    ring_key,
)
from execbound_protocol import checkpoint_conformance
from execbound_protocol.checkpoint_conformance import (
    CHECKS,
    REFUSED_AS,
    Grant,
    Nonconformance,
    RingKey,
    Settlement,
    Vector,
    VectorError,
    check,
    load_vectors,
    read_report,
    refused,
    settlement,
)
from execbound_protocol.executor import parse_jws
from execbound_protocol.report import MAX_REPORT_BYTES, OutcomeReport

from execbound.execution.models import ExecutionError
from execbound.execution.outcomes import parse_report

VECTORS = published()
RING = ring(VECTORS)
BY_VECTOR = {vector.name: vector for vector in VECTORS.vectors}
ANOTHER_EXECUTION = "00000000-0000-4000-8000-000000000999"


def test_the_published_vectors_load_and_hold_together():
    """Every vector is one grant, the report the vectors' executor wrote for it, which that
    executor writes again byte for byte, and what it settles; every refusal names the shared
    grant but one, a journal under UNAVAILABLE, which names a grant of its own."""
    assert [vector.name for vector in VECTORS.vectors] == sorted(BY_NAME)
    assert len(VECTORS.vectors) == 24 and len(VECTORS.refusals) == 31
    assert set(VECTORS.executor_keys) == {"conformance-ed25519", "conformance-es256"}
    for vector in VECTORS.vectors:
        scenario = BY_NAME[vector.name]
        assert body(scenario.report(vector.grant)) == vector.report, vector.name
        assert check(vector, vector.report, RING) == CHECKS, vector.name
        assert dataclasses.asdict(vector.settles) == scenario.settles
    assert len({vector.grant.binding.operation_id for vector in VECTORS.vectors}) == 24
    shared = {refusal.name: refusal.grant for refusal in VECTORS.refusals}
    own = shared.pop("journal-under-an-unavailable-grant")
    common = next(iter(shared.values()))
    assert all(grant == common for grant in shared.values())
    assert common.wire["precondition_class"] == "ENFORCED_BY_PROVIDER"
    assert own.wire["precondition_class"] == "UNAVAILABLE" and own.provider_command is None
    assert own.binding.operation_id != common.binding.operation_id
    classes = {vector.grant.wire["precondition_class"] for vector in VECTORS.vectors}
    assert classes == {"ENFORCED_BY_PROVIDER", "ASSERTED_BY_EXECUTOR", "UNAVAILABLE"}
    for vector in VECTORS.vectors:
        assert vector.grant.wire["precondition_class"] == BY_NAME[vector.name].precondition_class


def test_each_published_test_key_derives_its_published_public_key():
    """The private halves are published so an executor can sign as the vectors' executor did,
    which it can only if each derives the public half the vectors are verified under."""
    derive = {"ED25519": ed25519_public, "ES256": es256_public}
    for key_id, key in VECTORS.executor_keys.items():
        assert derive[key.algorithm](key.private_key) == key.public_key, key_id
    assert set(VECTORS.journal_keys) == {"conformance-journal"}


def test_the_grant_instant_has_microseconds():
    """So the vectors that sign the grant's own second sign a time before its exact instant."""
    for vector in VECTORS.vectors:
        assert vector.grant.granted_at.microsecond != 0
        if not BY_NAME[vector.name].whole_second:
            continue
        stated = vector.statement
        if stated.attestation is not None:
            signed_at = parse_jws(stated.attestation).claims.reported_at
        else:
            assert stated.record is not None
            signed_at = datetime.fromisoformat(stated.record["record"]["reported_at"])
        assert signed_at == vector.grant.granted_at.replace(microsecond=0), vector.name
        assert signed_at < vector.grant.granted_at, vector.name


def test_each_refusal_is_refused_at_its_own_check_and_code():
    for refusal in VECTORS.refusals:
        found = refused(refusal, RING)
        assert found.check == refusal.check, refusal.name
        assert found.code == refusal.code == REFUSED_AS[found.check], refusal.name
        assert FAULTS_BY_NAME[refusal.name].check == refusal.check
        assert body(FAULTS_BY_NAME[refusal.name].report(refusal.grant)) == refusal.report


def test_the_refusals_reach_every_check_a_report_body_alone_can_fail():
    """The secret is the one refusal of `read_report` a body cannot show: it needs the grant
    to be another than the one the report was written for."""
    reached = {refused(refusal, RING).check for refusal in VECTORS.refusals}
    assert reached == {name for name, code in REFUSED_AS.items() if code != "INVALID_REPORT"}


def test_the_file_never_carries_an_attestation_as_a_compact_token():
    """An attestation is written as its three segments and joined by the loader, so the file
    holds no dot-joined token a secret scanner would read as a credential."""
    text = PUBLISHED.read_text(encoding="utf-8")
    for vector in VECTORS.vectors:
        token = vector.statement.attestation
        if token is not None:
            assert token not in text
            assert token.split(".")[2] in text


def _tampered(change: Callable[[dict[str, Any]], None]) -> bytes:
    document = json.loads(PUBLISHED.read_bytes())
    change(document)
    return json.dumps(document).encode()


@pytest.mark.parametrize(
    "change",
    [
        lambda d: d["vectors"]["record-executed"]["settles"].update(claim="HELD"),
        lambda d: d["vectors"]["asserted-executed"]["settles"].update(tier="ATTESTED"),
        lambda d: d["vectors"]["record-executed"]["report"].update(report_secret="x" * 40),
        lambda d: d["vectors"]["journal-executed"]["report"]["journal"].update(signature="0" * 64),
        lambda d: d["vectors"]["record-executed"]["report"]["record"]["record"].update(
            operation_id="00000000-0000-4000-8000-000000000999"
        ),
        lambda d: d["vectors"]["record-executed"]["grant"].update(regranted=True),
        lambda d: d["vectors"]["record-executed"]["grant"]["binding"].update(plan_hash="0" * 64),
        lambda d: d["vectors"]["record-executed"].update(granted_at="2026-10-15T09:00:00"),
        lambda d: d["vectors"]["unknown"]["report"].update(reason="REPORTED_FAILURE"),
        lambda d: d["refusals"]["reports"]["unknown-field"].update(code="INVALID_RECORD"),
        lambda d: d["refusals"]["reports"]["no-evidence"].update(check="pairing"),
        lambda d: d["refusals"]["reports"]["journal-for-another-command"].update(check="signature"),
        lambda d: d["refusals"]["reports"]["record-outside-the-ring"].update(check="binding"),
        lambda d: d["refusals"]["reports"]["no-evidence"]["report"].update(
            reported_at="2026-10-15T09:02:00Z"
        ),
        lambda d: d["refusals"]["reports"]["journal-under-an-unavailable-grant"].pop("granted_at"),
        lambda d: [
            d["refusals"]["reports"]["journal-under-an-unavailable-grant"].pop(key)
            for key in ("execution_id", "granted_at", "grant")
        ],
        lambda d: d["refusals"]["reports"]["no-evidence"].update(
            {key: d["refusals"][key] for key in ("execution_id", "granted_at", "grant")}
            | {"grant": {**d["refusals"]["grant"], "regranted": True}}
        ),
        lambda d: d["executor_keys"]["conformance-ed25519"].update(public_key="00"),
        lambda d: d.update(version=2),
    ],
    ids=[
        "a claim the table does not release",
        "a tier an assertion does not reach",
        "another secret",
        "a journal that does not verify",
        "a record for another operation",
        "a re-grant",
        "a binding the command does not carry",
        "a grant time with no offset",
        "a vector that is not a report",
        "a refusal under another code",
        "a refusal at an earlier check",
        "a refusal at another check of its code",
        "a signature refusal published as another",
        "a refusal that is admitted",
        "a refusal's own grant missing one of its keys",
        "a refusal moved off its own grant",
        "a refusal's own grant that is no first grant",
        "a key of the wrong length",
        "an unserved version",
    ],
)
def test_a_vector_file_that_does_not_hold_together_is_refused(change):
    load_vectors(_tampered(lambda document: None))
    with pytest.raises(VectorError):
        load_vectors(_tampered(change))


def test_a_file_whose_refusals_all_share_one_grant_reads_as_it_did():
    """A refusal names a grant of its own only when its fault needs one, so a file written
    before any did, every refusal for the shared grant, still loads, every refusal under it."""
    earlier = _tampered(
        lambda d: d["refusals"]["reports"].pop("journal-under-an-unavailable-grant")
    )
    loaded = load_vectors(earlier)
    assert len(loaded.refusals) == len(VECTORS.refusals) - 1
    assert all(refusal.grant == loaded.refusals[0].grant for refusal in loaded.refusals)


def test_a_vector_file_is_read_as_strictly_as_a_report():
    raw = PUBLISHED.read_bytes()
    with pytest.raises(VectorError):
        load_vectors(raw.replace(b'"version": 1', b'"version": 1, "version": 1', 1))
    with pytest.raises(VectorError):
        load_vectors(b"[]")


def test_a_grant_is_read_only_when_it_describes_one_operation():
    grant = VECTORS.vectors[0].grant
    Grant.read(grant.execution_id, dict(grant.wire), grant.granted_at)
    command = dict(grant.wire["provider_command"])
    for changed in (
        {**grant.wire, "report_secret": None},
        {**grant.wire, "operation_id": "00000000-0000-4000-8000-000000000999"},
        {**grant.wire, "provider_command": {**command, "execution_id": str(ANOTHER_EXECUTION)}},
        {**grant.wire, "provider_command": {**command, "expected_version": "resource-v1"}},
        {**grant.wire, "binding": {**grant.wire["binding"], "extra": "x"}},
    ):
        with pytest.raises(VectorError):
            Grant.read(grant.execution_id, changed, grant.granted_at)
    for field, value in (
        ("provider", "mock_entra"),
        ("provider_operation", "lift_containment"),
        ("action", "endpoint.lift_isolation"),
        ("resource_provider_id", "another-device"),
        ("precondition_class", "UNAVAILABLE"),
        ("expected_version", None),
    ):
        with pytest.raises(VectorError):
            Grant.read(grant.execution_id, {**grant.wire, field: value}, grant.granted_at)
    with pytest.raises(VectorError):
        Grant.read(grant.execution_id, dict(grant.wire), grant.granted_at.replace(tzinfo=None))
    # An UNAVAILABLE grant carries neither a version nor a command, and nothing else.
    bare = BY_VECTOR["class-unavailable-attestation-executed"].grant
    assert bare.provider_command is None and "provider_command" not in bare.wire
    for changed in (
        {**bare.wire, "expected_version": "resource-v7"},
        {**bare.wire, "provider_command": dict(command)},
        {**bare.wire, "precondition_class": "ENFORCED_BY_PROVIDER"},
    ):
        with pytest.raises(VectorError):
            Grant.read(bare.execution_id, changed, bare.granted_at)


def test_a_journal_under_a_grant_with_no_provider_command_binds_nothing():
    """Section 2.6: a journal is for exactly the grant's `provider_command`, which a grant under
    UNAVAILABLE does not carry, so the module has nothing to bind one to."""
    name = "class-unavailable-attestation-executed"
    vector = BY_VECTOR[name]
    # The command ExecBound would have sent for this very grant, had its class carried one: the
    # same operation, execution and hashes at the frozen version, so the test pins the module to
    # refusing what the route accepts today rather than a journal for some other operation.
    command = fixed_grant(INDEX[name], name).provider_command
    assert command is not None
    stand_in = dataclasses.replace(vector.grant, provider_command=command)
    report = {
        "report_secret": vector.grant.report_secret,
        "outcome": "EXECUTED",
        "reason": "EXECUTED",
        "journal": journal(stand_in, "EXECUTED"),
    }
    with pytest.raises(Nonconformance) as raised:
        read_report(vector.grant, body(report), RING, VECTORS.journal_keys)
    assert raised.value.check == "binding"


# The vectors' executor is not the only one that conforms.


def test_an_executor_signing_with_its_own_key_conforms_under_its_own_ring():
    """A vendor's executor signs with a key of its own and names its public half in the ring;
    the vectors' test key is a default, not a requirement."""
    own = bytes(range(0x10, 0x30))
    own_ring = {"vendor-key-1": ring_key("ED25519", ed25519_public(own))}
    for vector in VECTORS.vectors:
        scenario = BY_NAME[vector.name]
        if scenario.evidence != "record":
            continue
        report = scenario.report(vector.grant) | {
            "record": record(
                vector.grant,
                scenario.outcome,
                scenario.reason or "",
                seed=own,
                key_id="vendor-key-1",
            )
        }
        assert check(vector, body(report), own_ring) == CHECKS
        with pytest.raises(Nonconformance) as raised:
            check(vector, body(report), RING)
        assert raised.value.check == "signature"


def test_an_executor_that_signs_only_es256_conforms_to_the_record_vectors():
    """A platform that cannot sign Ed25519 attests instead: the tier is what a vector asks for,
    and both envelopes are the executor's own signature."""
    for vector in VECTORS.vectors:
        scenario = BY_NAME[vector.name]
        if scenario.evidence != "record":
            continue
        report = scenario.report(vector.grant)
        del report["record"]
        report["attestation"] = attestation(vector.grant, scenario.outcome, scenario.reason or "")
        assert check(vector, body(report), RING) == CHECKS


# Broken executors. Each writes the report its scenario calls for with one fault, and the module
# must name it.


SIGNED = ("record", "attestation", "journal")
ANOTHER_GRANT = fixed_grant(REFUSAL_INDEX + 1, "another grant")


def _evidence(
    kind: str,
    grant: Grant,
    outcome: str,
    reason: str,
    *,
    outside: bool = False,
) -> dict[str, Any]:
    """Signed evidence of `kind` for a statement, under the ring's keys or keys outside it."""
    if kind == "record":
        seed = OUTSIDE_ED25519_SEED if outside else ED25519_SEED
        return {"record": record(grant, outcome, reason, seed=seed)}
    if kind == "attestation":
        if outside:
            return {"attestation": attestation(grant, outcome, reason, scalar=OUTSIDE_ES256_SCALAR)}
        return {"attestation": attestation(grant, outcome, reason)}
    if outside:
        return {"journal": journal(grant, reason, key=OUTSIDE_JOURNAL_KEY)}
    return {"journal": journal(grant, reason)}


def _resigned(scenario: Scenario, grant: Grant, **options: Any) -> dict[str, Any]:
    report = scenario.report(grant)
    assert scenario.reason is not None
    return report | _evidence(
        scenario.evidence, grant, scenario.outcome, scenario.reason, **options
    )


def fraction(scenario: Scenario, grant: Grant) -> str:
    return json.dumps(scenario.report(grant) | {"reported_at": 1792054920.5})


def two_pieces(scenario: Scenario, grant: Grant) -> dict[str, Any]:
    report = scenario.report(grant)
    if scenario.evidence == "reported_at":
        return report | {"record": record(grant, "EXECUTED", "EXECUTED")}
    assert scenario.reason is not None
    other = "attestation" if scenario.evidence == "record" else "record"
    return report | _evidence(other, grant, scenario.outcome, scenario.reason)


def refunding_failure(scenario: Scenario, grant: Grant) -> dict[str, Any]:
    return scenario.report(grant) | {"outcome": "FAILED_NOT_EXECUTED", "reason": "REPORTED_FAILURE"}


def terminal_unknown(scenario: Scenario, grant: Grant) -> dict[str, Any]:
    return scenario.report(grant) | {
        "outcome": "UNKNOWN",
        "reason": scenario.reason or "REPORTED_FAILURE",
    }


def own_field(scenario: Scenario, grant: Grant) -> dict[str, Any]:
    return scenario.report(grant) | {"act": "the-act-token-it-was-answered-with"}


def another_secret(scenario: Scenario, grant: Grant) -> dict[str, Any]:
    return scenario.report(grant) | {"report_secret": ANOTHER_GRANT.report_secret}


def outside_the_ring(scenario: Scenario, grant: Grant) -> dict[str, Any]:
    return _resigned(scenario, grant, outside=True)


def for_another_grant(scenario: Scenario, grant: Grant) -> dict[str, Any]:
    return _resigned(scenario, ANOTHER_GRANT) | {"report_secret": grant.report_secret}


def executed_while_signed_otherwise(scenario: Scenario, grant: Grant) -> dict[str, Any]:
    stated = "TARGET_NOT_FOUND" if scenario.reason == "EXECUTED" else scenario.reason
    assert stated is not None
    signed = _evidence(scenario.evidence, grant, "FAILED_NOT_EXECUTED", stated)
    return scenario.report(grant) | {"outcome": "EXECUTED", "reason": "EXECUTED"} | signed


def unsigned(scenario: Scenario, grant: Grant) -> dict[str, Any]:
    report = scenario.report(grant)
    for name in SIGNED:
        report.pop(name, None)
    return report | {"reported_at": instant(reported_at(grant))}


def missing_target(scenario: Scenario, grant: Grant) -> dict[str, Any]:
    if scenario.evidence == "reported_at":
        return scenario.report(grant) | {"reason": "TARGET_NOT_FOUND"}
    return (
        scenario.report(grant)
        | _evidence(scenario.evidence, grant, "FAILED_NOT_EXECUTED", "TARGET_NOT_FOUND")
        | {"reason": "TARGET_NOT_FOUND"}
    )


@dataclass(frozen=True)
class Broken:
    """A broken executor, the check that must name its fault, and the vectors that show it."""

    write: Callable[[Scenario, Grant], dict[str, Any] | str]
    expected: str
    shows: Callable[[Scenario], bool] = lambda scenario: True


BROKEN: dict[str, Broken] = {
    "writes a number with a fraction": Broken(
        fraction, "body", lambda scenario: scenario.evidence == "reported_at"
    ),
    "sends two pieces of evidence": Broken(two_pieces, "evidence"),
    "pairs REPORTED_FAILURE with an outcome that refunds": Broken(
        refunding_failure,
        "pairing",
        lambda scenario: (
            scenario.evidence == "reported_at"
            and scenario.outcome in {"FAILED_EFFECT_UNKNOWN", "UNKNOWN"}
        ),
    ),
    "reports UNKNOWN as a terminal outcome": Broken(terminal_unknown, "pairing"),
    "adds a field of its own": Broken(own_field, "model"),
    "presents another grant's secret": Broken(another_secret, "secret"),
    "signs with a key outside the ring": Broken(
        outside_the_ring, "signature", lambda scenario: scenario.evidence in SIGNED
    ),
    "signs for another grant": Broken(
        for_another_grant, "binding", lambda scenario: scenario.evidence in SIGNED
    ),
    "reports EXECUTED while its signed evidence says otherwise": Broken(
        executed_while_signed_otherwise,
        "agreement",
        lambda scenario: scenario.evidence in SIGNED,
    ),
    "claims a signed tier with no signature": Broken(
        unsigned, "tier", lambda scenario: scenario.evidence in SIGNED
    ),
    "reports a refused conditional write as a missing target": Broken(
        missing_target,
        "settlement",
        lambda scenario: scenario.evidence in SIGNED and scenario.reason == "VERSION_MISMATCH",
    ),
    "reports a cancellation as a missing target": Broken(
        missing_target, "statement", lambda scenario: scenario.reason == "CANCELLED_NOT_EXECUTED"
    ),
}


def broken_cases() -> list[tuple[str, str]]:
    return [
        (fault, scenario.name)
        for fault, case in sorted(BROKEN.items())
        for scenario in SCENARIOS
        if case.shows(scenario)
    ]


@pytest.mark.parametrize(
    ("fault", "name"), broken_cases(), ids=[f"{f} - {n}" for f, n in broken_cases()]
)
def test_a_broken_executor_fails_at_the_check_that_names_its_fault(fault: str, name: str):
    case, vector = BROKEN[fault], BY_VECTOR[name]
    raw = body(case.write(BY_NAME[name], vector.grant))
    with pytest.raises(Nonconformance) as raised:
        check(vector, raw, RING)
    assert raised.value.check == case.expected, str(raised.value)
    assert raised.value.code == REFUSED_AS.get(case.expected)


def test_every_broken_executor_shows_on_some_vector():
    assert {fault for fault, _ in broken_cases()} == set(BROKEN)


def test_every_check_is_one_the_module_names():
    assert len(set(CHECKS)) == len(CHECKS)
    assert all(isinstance(name, str) and name == name.lower() for name in CHECKS)
    assert set(REFUSED_AS) == set(CHECKS) - {"tier", "settlement", "statement"}
    assert set(REFUSED_AS.values()) == {"INVALID_REQUEST", "INVALID_REPORT", "INVALID_RECORD"}


def test_every_check_has_a_broken_executor_it_catches():
    """A check no broken executor fails could be deleted with every test still green."""
    assert {case.expected for case in BROKEN.values()} == set(CHECKS)


def test_the_module_refuses_a_body_exactly_where_the_servers_parser_does():
    """`body`, `evidence` and `pairing` name a fault the published model would refuse anyway,
    and with `model` they are the parse: every report they refuse, the server's own parser
    refuses as `INVALID_REQUEST`, and every report they admit, it admits. The server's parser
    needs no database, so this holds every report this file and the vectors write."""
    reports = [refusal.report for refusal in VECTORS.refusals]
    reports += [vector.report for vector in VECTORS.vectors]
    reports += [
        body(BROKEN[fault].write(BY_NAME[name], BY_VECTOR[name].grant))
        for fault, name in broken_cases()
    ]
    parsed = refused_here = 0
    for raw in reports:
        try:
            read_report(BY_VECTOR["unknown"].grant, raw, RING, VECTORS.journal_keys)
        except Nonconformance as found:
            if found.code == "INVALID_REQUEST":
                refused_here += 1
                with pytest.raises(ExecutionError) as raised:
                    parse_report(raw)
                assert raised.value.code == "INVALID_REQUEST"
                continue
        parsed += 1
        assert parse_report(raw) == OutcomeReport.model_validate_json(raw)
    assert refused_here >= 30 and parsed >= 100


# The settlement function is section 2.8; the vectors and the server hold it to the table.


def padded(raw: bytes, size: int) -> bytes:
    """A report with JSON whitespace before its closing brace, to exactly `size` bytes."""
    return raw[:-1] + b" " * (size - len(raw)) + b"}"


def test_the_body_bound_is_the_routes():
    """A report of exactly 16,384 bytes is read, and one byte more is not, here and in the
    server's own parser."""
    vector = BY_VECTOR["asserted-executed"]
    exact, over = (
        padded(vector.report, MAX_REPORT_BYTES),
        padded(vector.report, MAX_REPORT_BYTES + 1),
    )
    assert check(vector, exact, RING) == CHECKS
    parse_report(exact)
    with pytest.raises(Nonconformance) as raised:
        check(vector, over, RING)
    assert raised.value.check == "body" and raised.value.code == "INVALID_REQUEST"
    with pytest.raises(ExecutionError) as refused_here:
        parse_report(over)
    assert refused_here.value.code == "INVALID_REQUEST"


def test_settlement_refuses_evidence_it_was_not_shown():
    signed = BY_VECTOR["record-executed"].statement
    bare = BY_VECTOR["asserted-executed"].statement
    assert settlement(signed, verified=False) is None
    with pytest.raises(ValueError):
        settlement(bare, verified=True)
    with pytest.raises(TypeError):
        settlement(signed, verified=1)
    with pytest.raises(ValueError):
        Settlement("DISPATCH_COMMITTED", None, "CHARGED", "HELD")


def test_a_ring_key_names_its_scheme():
    with pytest.raises(ValueError):
        RingKey("HMAC", lambda signed, message: True)
    always = {"conformance-ed25519": RingKey("ED25519", lambda signed, message: True)}
    vector = BY_VECTOR["record-executed"]
    # A verifier is believed only when it answers exactly True, and one that raises is a no.
    truthy = {"conformance-ed25519": RingKey("ED25519", lambda signed, message: 1)}
    raising = {"conformance-ed25519": RingKey("ED25519", lambda signed, message: 1 / 0 == 0)}
    assert check(vector, vector.report, always) == CHECKS
    for keys in (truthy, raising):
        with pytest.raises(Nonconformance) as raised:
            check(vector, vector.report, keys)
        assert raised.value.check == "signature"


def test_a_harness_passes_its_own_grant_in_the_vectors_place():
    """`check` reads a report for the vector's grant; a harness that issues its own grant hands
    the module the vector with that grant, as the server test does."""
    vector = BY_VECTOR["attestation-version-mismatch"]
    mine = fixed_grant(REFUSAL_INDEX + 2, "a harness grant")
    raw = body(BY_NAME[vector.name].report(mine))
    assert check(dataclasses.replace(vector, grant=mine), raw, RING) == CHECKS
    with pytest.raises(Nonconformance) as raised:
        check(vector, raw, RING)
    assert raised.value.check == "secret"


def test_the_module_imports_nothing_but_the_protocol_and_the_standard_library():
    """Vendors install `execbound-protocol` alone; the module may not need the server, the
    connectors or a cryptographic library the package does not depend on."""
    source = Path(checkpoint_conformance.__file__).read_text(encoding="utf-8")
    imported: set[str] = set()
    for node in ast.walk(ast.parse(source)):
        if isinstance(node, ast.Import):
            imported |= {alias.name.split(".")[0] for alias in node.names}
        elif isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
            imported.add(node.module.split(".")[0])
    assert imported - set(sys.stdlib_module_names) == {"execbound_protocol"}


def test_a_vector_is_frozen():
    vector: Vector = VECTORS.vectors[0]
    with pytest.raises(dataclasses.FrozenInstanceError):
        vector.report = b"{}"
