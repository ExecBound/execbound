# SPDX-License-Identifier: AGPL-3.0-only
"""The executor protocol's published files, version 1 (#37).

`protocol/executor/v1/` publishes the executor protocol's wire objects for anyone building an
executor: a JSON Schema for each, generated from the protocol package's own models, for the
command and signed journal of chapter 1 and the checkpoint report and its signed evidence of
chapter 2, and the golden contracts, one or more for each catalog binding the protocol reaches,
as chapter 1's conformance vectors, and chapter 2's checkpoint report vectors. The functions
here are the generator; the tests hold the committed files equal to what it writes, so a schema
cannot drift from the model that parses the object, a chapter 1 vector cannot drift from the
frozen fixture the compatibility tests settle (`tests/test_endpoint_upgrade_compatibility.py`,
`tests/test_identity_compatibility.py`, `tests/test_soc_contract_compatibility.py`), and the
checkpoint report vectors cannot drift from `tests/checkpoint_vectors.py`, which writes them and
which `tests/test_checkpoint_report_server.py` holds to the server.

After a deliberate change to one of the models, rewrite the directory and commit what changed:

    uv run python tests/test_executor_protocol_v1.py

This file imports the protocol package, the standard library, pydantic, pytest, jsonschema and,
through `checkpoint_vectors`, cryptography, and nothing of the server.
"""

import base64
import json
import tomllib
from pathlib import Path
from typing import Any

import checkpoint_vectors
import pytest
from execbound_protocol.executor import ExecutorRecord, JwsClaims, JwsHeader, SignedOutcome
from execbound_protocol.provider import JournalRecord, ProviderCommand, SignedJournal
from execbound_protocol.report import OutcomeReport
from jsonschema import Draft202012Validator
from pydantic import BaseModel, ValidationError

ROOT = Path(__file__).resolve().parents[1]
DIRECTORY = ROOT / "protocol" / "executor" / "v1"
FIXTURES = ROOT / "tests" / "fixtures"
README = "README.md"
REGENERATE = "uv run python tests/test_executor_protocol_v1.py"

# Each schema the directory publishes, and the model it is generated from.
SCHEMAS: dict[str, type[BaseModel]] = {
    # Chapter 1: what ExecBound sends an executor it dispatches to, and what comes back.
    "command.schema.json": ProviderCommand,
    "journal.schema.json": JournalRecord,
    "signed-journal.schema.json": SignedJournal,
    # Chapter 2: what an executor holding its own vendor credential reports, and the signed
    # statement its report can carry, as an Ed25519 envelope or as the JWS's two halves.
    "checkpoint-report.schema.json": OutcomeReport,
    "executor-record.schema.json": ExecutorRecord,
    "signed-outcome.schema.json": SignedOutcome,
    "jws-header.schema.json": JwsHeader,
    "jws-claims.schema.json": JwsClaims,
}
# The frozen golden fixtures, copied byte for byte. The originals stay where they are.
VECTORS = (
    "endpoint-contract-v1.json",
    "endpoint-recovery-contract-v1.json",
    "identity-contract-v1.json",
    "identity-credential-contract-v1.json",
)
# Chapter 2's vectors, written by the vectors' own executor rather than copied from a fixture.
CHECKPOINT_VECTORS = "checkpoint-report-v1.json"


def schema_bytes(model: type[BaseModel]) -> bytes:
    """A model's JSON Schema as the directory holds it: sorted keys, two-space indent."""
    return (json.dumps(model.model_json_schema(), indent=2, sort_keys=True) + "\n").encode()


def published() -> dict[str, bytes]:
    """Every generated file of the directory, by its path there, and its exact bytes."""
    files = {name: schema_bytes(model) for name, model in SCHEMAS.items()}
    files |= {f"vectors/{name}": (FIXTURES / name).read_bytes() for name in VECTORS}
    files[f"vectors/{CHECKPOINT_VECTORS}"] = checkpoint_vectors.document_bytes()
    return files


def write() -> None:
    for name, data in published().items():
        path = DIRECTORY / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)


def committed(name: str) -> bytes:
    path = DIRECTORY / name
    assert path.is_file(), f"protocol/executor/v1/{name} is missing; run `{REGENERATE}`"
    return path.read_bytes()


def validator(name: str) -> Draft202012Validator:
    return Draft202012Validator(json.loads(committed(name)))


def problems(name: str, value: Any) -> list[str]:
    return [error.message for error in validator(name).iter_errors(value)]


@pytest.mark.parametrize("name", sorted(SCHEMAS))
def test_each_schema_is_its_model(name):
    assert committed(name) == schema_bytes(SCHEMAS[name]), (
        f"protocol/executor/v1/{name} is not {SCHEMAS[name].__name__}'s schema; "
        f"run `{REGENERATE}` and commit the change"
    )


@pytest.mark.parametrize("name", VECTORS)
def test_each_vector_is_its_frozen_fixture_byte_for_byte(name):
    assert committed(f"vectors/{name}") == (FIXTURES / name).read_bytes(), (
        f"protocol/executor/v1/vectors/{name} differs from tests/fixtures/{name}, "
        "which is frozen; copy the fixture, never the other way round"
    )


def test_the_checkpoint_vectors_are_what_their_generator_writes_byte_for_byte():
    assert committed(f"vectors/{CHECKPOINT_VECTORS}") == checkpoint_vectors.document_bytes(), (
        f"protocol/executor/v1/vectors/{CHECKPOINT_VECTORS} is not what "
        f"tests/checkpoint_vectors.py writes; run `{REGENERATE}` and commit the change"
    )


def test_the_directory_publishes_nothing_else():
    found = {
        path.relative_to(DIRECTORY).as_posix() for path in DIRECTORY.rglob("*") if path.is_file()
    }
    assert found == {*published(), README}


def test_the_readme_names_every_published_file():
    text = (DIRECTORY / README).read_text(encoding="utf-8")
    for name in published():
        assert f"`{name}`" in text, name


def test_the_package_ships_none_of_the_directory():
    """The schemas and vectors are published beside `execbound-protocol`, not inside it.

    Hatch reads an include pattern as gitignore does, so an unanchored `README.md` would also
    match this directory's README and carry it into the source distribution.
    """
    project = tomllib.loads((ROOT / "protocol" / "pyproject.toml").read_text(encoding="utf-8"))
    targets = project["tool"]["hatch"]["build"]["targets"]
    assert targets["wheel"]["packages"] == ["src/execbound_protocol"]
    include = targets["sdist"]["include"]
    assert include and all(pattern.startswith("/") for pattern in include), include
    assert not any(pattern.startswith("/executor") for pattern in include)


def _contracts() -> list[tuple[str, dict[str, Any]]]:
    """Every vector's contract, labelled: a file holds one at its top level, as the endpoint
    contract does, or one per action under `actions`."""
    found: list[tuple[str, dict[str, Any]]] = []
    for name in VECTORS:
        document = json.loads(committed(f"vectors/{name}"))
        if "actions" in document:
            found += sorted(document["actions"].items())
        else:
            found.append((name, document))
    return found


def _wire_objects() -> list[tuple[str, str, dict[str, Any]]]:
    """Each vector's command, record and signed journal as the wire carries them, with the
    schema each one is published under."""
    objects = []
    for label, contract in _contracts():
        signed = json.loads(contract["signed_journal_canonical"])
        assert signed == contract["signed_journal"]
        objects += [
            (f"{label} command", "command.schema.json", json.loads(contract["command_canonical"])),
            (f"{label} record", "journal.schema.json", signed["record"]),
            (f"{label} signed journal", "signed-journal.schema.json", signed),
        ]
    return objects


def test_every_vector_meets_the_published_schemas():
    objects = _wire_objects()
    # Two endpoint contracts and four identity actions, three objects each.
    assert len(objects) == 18
    for label, schema, value in objects:
        assert problems(schema, value) == [], label


def _decoded(segment: str) -> Any:
    return json.loads(base64.urlsafe_b64decode(segment + "=" * (-len(segment) % 4)))


def test_every_checkpoint_vector_meets_the_published_schemas():
    """Each report, refused ones aside, meets the report's schema, and the evidence it carries
    meets its own: a signed outcome and its record, a JWS's header and claims, or a signed
    journal and its record."""
    loaded = checkpoint_vectors.published()
    checked: list[str] = []
    for vector in loaded.vectors:
        report = json.loads(vector.report)
        assert problems("checkpoint-report.schema.json", report) == [], vector.name
        checked.append("report")
        if "record" in report:
            assert problems("signed-outcome.schema.json", report["record"]) == [], vector.name
            assert problems("executor-record.schema.json", report["record"]["record"]) == []
            checked += ["signed outcome", "executor record"]
        if "attestation" in report:
            header, claims, _ = report["attestation"].split(".")
            assert problems("jws-header.schema.json", _decoded(header)) == [], vector.name
            assert problems("jws-claims.schema.json", _decoded(claims)) == [], vector.name
            checked += ["jws header", "jws claims"]
        if "journal" in report:
            assert problems("signed-journal.schema.json", report["journal"]) == [], vector.name
            assert problems("journal.schema.json", report["journal"]["record"]) == []
            checked += ["signed journal", "journal"]
        if vector.grant.provider_command is not None:
            command = dict(vector.grant.wire["provider_command"])
            assert problems("command.schema.json", command) == [], vector.name
            checked.append("command")
    # 24 reports and the 22 grant commands outside UNAVAILABLE; six records, six attestations
    # and four journals, two objects each.
    assert len(checked) == 24 + 22 + (6 + 6 + 4) * 2


@pytest.mark.parametrize(
    "change",
    [
        {"callback_url": "https://executor.test/hook"},
        {"version": 2},
        {"version": "1"},
        {"intent_hash": "A" * 64},
        {"expected_version": ""},
    ],
    ids=[
        "unnamed field",
        "unserved version",
        "version as text",
        "digest spelling",
        "empty expected version",
    ],
)
def test_the_command_schema_refuses_what_the_model_refuses(change):
    """A field the model does not name, a version it does not serve, and a malformed value fail
    the published schema as they fail the parser."""
    command = _wire_objects()[0][2]
    assert problems("command.schema.json", command) == []
    ProviderCommand.model_validate_json(json.dumps(command))
    changed = {**command, **change}
    assert problems("command.schema.json", changed) != []
    with pytest.raises(ValidationError):
        ProviderCommand.model_validate_json(json.dumps(changed))


# Chapter 2. None of these needs a real signature: a schema and a parser read a signature's
# shape, and the verifier, which is the server's, checks what it signs.
SECRET = "report-secret-" + "x" * 30
BINDING = {
    "operation_id": "00000000-0000-0000-0000-000000000017",
    "account_id": "00000000-0000-0000-0000-000000000003",
    "intent_hash": "a" * 64,
    "plan_hash": "b" * 64,
}
STATEMENT = {
    **BINDING,
    "outcome": "EXECUTED",
    "reason": "EXECUTED",
    "reported_at": "2026-10-09T00:00:00Z",
}
RECORD = {"version": 1, **STATEMENT}
ENVELOPE = {"version": 1, "key_id": "executor-v1", "record": RECORD, "signature": "c" * 128}
HEADER = {"alg": "ES256", "kid": "executor-es256"}
CLAIMS = {"domain": "execbound.executor.outcome", "version": 1, **STATEMENT}
REPORTED = {"report_secret": SECRET, "reported_at": "2026-10-09T00:00:00+00:00"}


def test_every_chapter_two_object_meets_its_published_schema():
    """A report in each of its shapes, and the signed statement each signed shape carries."""
    reports = [
        {**REPORTED, "outcome": "UNKNOWN"},
        {**REPORTED, "outcome": "EXECUTED", "reason": "EXECUTED"},
        {**REPORTED, "outcome": "FAILED_EFFECT_UNKNOWN", "reason": "REPORTED_FAILURE"},
        {"report_secret": SECRET, "outcome": "EXECUTED", "reason": "EXECUTED", "record": ENVELOPE},
        {
            "report_secret": SECRET,
            "outcome": "EXECUTED",
            "reason": "EXECUTED",
            "attestation": "aaaa.bbbb.cccc",
        },
        {
            "report_secret": SECRET,
            "outcome": "EXECUTED",
            "reason": "EXECUTED",
            "journal": json.loads(_contracts()[0][1]["signed_journal_canonical"]),
        },
    ]
    for report in reports:
        assert problems("checkpoint-report.schema.json", report) == [], report
        OutcomeReport.model_validate_json(json.dumps(report))
    for name, value, model in (
        ("executor-record.schema.json", RECORD, ExecutorRecord),
        ("signed-outcome.schema.json", ENVELOPE, SignedOutcome),
        ("jws-header.schema.json", HEADER, JwsHeader),
        ("jws-claims.schema.json", CLAIMS, JwsClaims),
    ):
        assert problems(name, value) == [], name
        model.model_validate_json(json.dumps(value))


@pytest.mark.parametrize(
    "change",
    [
        {"act": "a-continuation-token"},
        {"report_secret": "too-short"},
        {"report_secret": SECRET + "/"},
        {"outcome": "DONE"},
        {"reason": "SUCCEEDED"},
        {"attestation": "not-a-compact-jws"},
    ],
    ids=[
        "unnamed field",
        "short secret",
        "secret spelling",
        "unknown outcome",
        "unknown reason",
        "attestation spelling",
    ],
)
def test_the_report_schema_refuses_what_the_model_refuses(change):
    report = {**REPORTED, "outcome": "EXECUTED", "reason": "EXECUTED"}
    changed = {**report, **change}
    assert problems("checkpoint-report.schema.json", changed) != []
    with pytest.raises(ValidationError):
        OutcomeReport.model_validate_json(json.dumps(changed))


@pytest.mark.parametrize(
    "report",
    [
        {**REPORTED, "outcome": "EXECUTED", "reason": "VERSION_MISMATCH"},
        {**REPORTED, "outcome": "UNKNOWN", "reason": "REPORTED_FAILURE"},
        {"report_secret": SECRET, "outcome": "UNKNOWN", "record": ENVELOPE},
        {
            "report_secret": SECRET,
            "outcome": "FAILED_EFFECT_UNKNOWN",
            "reason": "REPORTED_FAILURE",
            "record": ENVELOPE,
        },
        {
            "report_secret": SECRET,
            "outcome": "EXECUTED",
            "reason": "EXECUTED",
            "record": ENVELOPE,
            "attestation": "aaaa.bbbb.cccc",
        },
        {**REPORTED, "outcome": "EXECUTED", "reason": "EXECUTED", "record": ENVELOPE},
        {"report_secret": SECRET, "outcome": "EXECUTED", "reason": "EXECUTED"},
    ],
    ids=[
        "unpaired reason",
        "unknown with a reason",
        "unknown with evidence",
        "signed reported failure",
        "two pieces of evidence",
        "a time beside evidence",
        "neither a time nor evidence",
    ],
)
def test_the_rules_the_report_schema_cannot_say_are_the_models(report):
    """These are the readme's "what the schemas cannot say" for the report: the pairing of
    outcome and reason, one piece of evidence, and a time exactly when there is none. Each
    meets the published schema and is refused by the model."""
    assert problems("checkpoint-report.schema.json", report) == []
    with pytest.raises(ValidationError):
        OutcomeReport.model_validate_json(json.dumps(report))


if __name__ == "__main__":
    write()
