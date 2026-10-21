# SPDX-License-Identifier: AGPL-3.0-only
"""Versioned replay regression fixtures: one sanitized history and its expected decisions.

A fixture holds a sanitized export, its trusted head, up to eight candidate bundles and the
classified outcome replay gave every decision when the fixture was recorded. The check
replays the same files offline and fails on any difference. It compares that projection and
never the wording of `report.md`, so a sentence can change without churning a fixture and a
decision cannot.

`sanitize.py` builds a fixture from an export; this module reads, checks and re-records one.
Neither touches a database, a provider or the environment.
"""

import json
import os
from collections.abc import Sequence
from pathlib import Path
from typing import Annotated, Any, Literal
from uuid import UUID

from pydantic import Field, model_validator

from execbound.execution.models import Digest
from execbound.policy.models import BundleContent
from execbound.replay.fixture_keys import SIGNERS, evidence_kinds, signed_by_fixture_keys
from execbound.replay.models import MAX_EXPORT_BYTES, ReplayExport, TrustedHead, VerifiedHistory
from execbound.replay.pseudonyms import is_sanitized
from execbound.replay.report import DecisionComparison, EvaluationResult, ReplayReport, RuleCount
from execbound.replay.runner import read_bounded, strict_json, write_new
from execbound.replay.simulate import simulate
from execbound.replay.verify import ReplayValidationError, verify_export
from execbound.requests import StrictModel
from execbound.secrets import find_secrets

FORMAT: Literal["execbound.replay-fixture"] = "execbound.replay-fixture"
MAX_CANDIDATES = 8
# The export's own bound is on its compact form; a fixture is written indented, which
# costs about half again, and carries its candidates and expectations beside it.
MAX_FIXTURE_BYTES = 2 * MAX_EXPORT_BYTES  # 128 MiB
Code = Annotated[str, Field(max_length=200)]


class FixtureError(ValueError):
    """A refusal that names a closed code and never a value or a path."""

    def __init__(self, code: str = "FIXTURE_UNAVAILABLE") -> None:
        self.code = code
        super().__init__("Replay fixture unavailable")


class ExpectedResult(StrictModel):
    """What replay classified for one decision, without the hashes that only bind it."""

    effect: Code
    reasons: tuple[str, ...] = Field(max_length=256)
    obligation_ids: tuple[str, ...] = Field(max_length=1024)
    outcome: Code
    provenance: Code
    counts: tuple[RuleCount, ...] = Field(max_length=64)
    dependencies: tuple[UUID, ...] = Field(max_length=10000)


class ExpectedDecision(ExpectedResult):
    sequence: int = Field(ge=1)
    execution_id: UUID
    action: Code
    stage: Code
    recorded_effect: Code
    mode: Code
    settlement_tier: str | None = Field(default=None, max_length=200)


class ExpectedCandidateDecision(ExpectedResult):
    sequence: int = Field(ge=1)
    differences: tuple[str, ...] = Field(max_length=16)


class ExpectedBaseline(StrictModel):
    complete: bool
    issues: tuple[str, ...] = Field(max_length=256)
    decisions: tuple[ExpectedDecision, ...] = Field(max_length=10000)


class ExpectedCandidate(StrictModel):
    candidate_hash: Digest
    complete: bool
    issues: tuple[str, ...] = Field(max_length=256)
    decisions: tuple[ExpectedCandidateDecision, ...] = Field(max_length=10000)


class Expected(StrictModel):
    baseline: ExpectedBaseline
    candidates: tuple[ExpectedCandidate, ...] = Field(max_length=MAX_CANDIDATES)


class Sanitization(StrictModel):
    """How many distinct values the sanitizer replaced. The mapping itself is never kept.

    Version 2 also names, for each kind of signed record the history retains, the published
    key it is now signed under (`fixture_keys.SIGNERS`): a version 2 fixture carries evidence
    an external executor, a connector or a checkpoint's provider settled, which version 1
    refused (#819). Version 1 names none, and is still written for a history that holds only
    journals of operations ExecBound dispatched, so its fixtures stay byte for byte.
    """

    version: Literal[1, 2]
    identifiers: int = Field(ge=0)
    labels: int = Field(ge=0)
    digests: int = Field(ge=0)
    signatures: dict[str, str] | None = None

    @model_validator(mode="after")
    def declared(self) -> "Sanitization":
        if (self.version == 1) != (self.signatures is None):
            raise ValueError("Invalid sanitization")
        if self.signatures is not None and any(
            SIGNERS.get(kind) != key for kind, key in self.signatures.items()
        ):
            raise ValueError("Invalid sanitization")
        return self


class ReplayFixture(StrictModel):
    format: Literal["execbound.replay-fixture"]
    version: Literal[1, 2]
    sanitization: Sanitization
    trusted_head: TrustedHead
    export: ReplayExport
    candidates: tuple[BundleContent, ...] = Field(max_length=MAX_CANDIDATES)
    expected: Expected

    @model_validator(mode="after")
    def one_version(self) -> "ReplayFixture":
        if self.version != self.sanitization.version:
            raise ValueError("Invalid fixture version")
        return self


def _result(result: EvaluationResult) -> dict[str, Any]:
    return {
        "effect": result.effect,
        "reasons": result.reasons,
        "obligation_ids": result.obligation_ids,
        "outcome": result.outcome,
        "provenance": result.provenance,
        "counts": result.counts,
        "dependencies": result.dependencies,
    }


def _baseline_row(row: DecisionComparison) -> ExpectedDecision:
    return ExpectedDecision(
        sequence=row.sequence,
        execution_id=row.execution_id,
        action=row.action,
        stage=row.stage,
        recorded_effect=row.recorded_effect,
        mode=row.mode,
        settlement_tier=row.settlement_tier,
        **_result(row.baseline),
    )


def _candidate_row(row: DecisionComparison) -> ExpectedCandidateDecision:
    if row.candidate is None:
        raise FixtureError()
    return ExpectedCandidateDecision(
        sequence=row.sequence, differences=row.differences, **_result(row.candidate)
    )


def expected_outcomes(history: VerifiedHistory, candidates: Sequence[BundleContent]) -> Expected:
    """Replay the baseline and each candidate and keep the classification of every decision."""
    baseline: ReplayReport = simulate(history)
    runs = [simulate(history, candidate) for candidate in candidates]
    return Expected(
        baseline=ExpectedBaseline(
            complete=baseline.complete,
            issues=baseline.issues,
            decisions=tuple(_baseline_row(row) for row in baseline.decisions),
        ),
        candidates=tuple(
            ExpectedCandidate(
                candidate_hash=candidate.content_hash,
                complete=run.complete,
                issues=run.issues,
                decisions=tuple(_candidate_row(row) for row in run.decisions),
            )
            for candidate, run in zip(candidates, runs, strict=True)
        ),
    )


def render(fixture: ReplayFixture) -> bytes:
    """The one serialization: sorted keys and one-space indentation, so a re-recorded
    expectation reads as an ordinary diff and an unchanged one is byte-identical."""
    document = fixture.model_dump(mode="json")
    if document["sanitization"]["signatures"] is None:
        # Version 1 never wrote the member, so its fixtures stay the bytes they were.
        del document["sanitization"]["signatures"]
    text = json.dumps(document, indent=1, sort_keys=True, ensure_ascii=False)
    raw = (text + "\n").encode("utf-8")
    if len(raw) > MAX_FIXTURE_BYTES:
        raise FixtureError()
    return raw


def parse(raw: bytes) -> ReplayFixture:
    """Strict JSON, a known format and version, every bound the parts already have, no
    secret anywhere, and the shape a build writes: every identifier a pseudonym and every
    label position holding one.

    The screen is the build's own (`find_secrets`) over the whole fixture, candidates and
    expectations included, so a secret typed into a candidate's policy text is neither checked
    nor re-recorded into a new fixture. The shape is what keeps a history the build would
    refuse, such as an export wrapped by hand, from being checked, re-recorded or committed as
    a fixture. Neither can tell a tenant's free text added by hand to policy text from any
    other: without the source there is nothing to compare it with, so an edited candidate is
    held by review of the fixture's diff.
    """
    fixture = document = None
    try:
        if type(raw) is not bytes or not 0 < len(raw) <= MAX_FIXTURE_BYTES:
            raise ValueError()
        strict_json(raw)
        fixture = ReplayFixture.model_validate_json(raw)
        document = json.loads(raw)
    except (ValueError, TypeError, RecursionError):
        pass
    if fixture is None or document is None:
        raise FixtureError()
    if find_secrets(document, limit=1):
        raise FixtureError("PRIVATE_DATA")
    # A record still signed by the key that signed it at the source would let anyone holding
    # that key's public half test guesses of what the pseudonyms replaced.
    if not is_sanitized(document) or not signed_by_fixture_keys(document):
        raise FixtureError("FIXTURE_NOT_SANITIZED")
    kinds, external = evidence_kinds(document)
    signatures = fixture.sanitization.signatures
    # Version 2 is written for what version 1 refused, and only for that.
    if (fixture.version == 1) == external or (signatures is not None and set(signatures) != kinds):
        raise FixtureError()
    return fixture


def verified(fixture: ReplayFixture) -> VerifiedHistory:
    """The embedded export, verified against the head that travels with it.

    That head proves internal consistency only, which is all a regression fixture needs: it
    is evidence about the engine, never about the tenant the history came from.
    """
    try:
        history = verify_export(fixture.export, fixture.trusted_head)
        for candidate in fixture.candidates:
            if candidate.tenant_id != fixture.export.tenant_id:
                raise FixtureError("INVALID_CANDIDATE")
        return history
    except ReplayValidationError as refusal:
        raise FixtureError(refusal.code) from None


def _flat(row: StrictModel) -> dict[str, Any]:
    return row.model_dump(mode="json")


def _rows(
    run: str,
    recorded: Sequence[StrictModel],
    replayed: Sequence[StrictModel],
) -> list[str]:
    """Rows matched by sequence. Replay records one decision per sequence, so a sequence with
    a row missing, or a row too many, however alike, is named as a decision difference."""
    found: list[str] = []
    before: dict[int, list[dict[str, Any]]] = {}
    after: dict[int, list[dict[str, Any]]] = {}
    for rows, side in ((recorded, before), (replayed, after)):
        for row in rows:
            flat = _flat(row)
            side.setdefault(flat["sequence"], []).append(flat)
    for sequence in sorted(set(before) | set(after)):
        if len(before.get(sequence, ())) != len(after.get(sequence, ())):
            found.append(f"{run} sequence {sequence} decision")
            continue
        for old, new in zip(before[sequence], after[sequence], strict=True):
            found.extend(
                f"{run} sequence {sequence} {field}"
                for field in sorted(set(old) | set(new))
                if old.get(field) != new.get(field)
            )
    return found


def differences(recorded: Expected, replayed: Expected) -> list[str]:
    """Each run, sequence and field that differs, as codes and numbers only."""
    found: list[str] = []
    for field in ("complete", "issues"):
        if getattr(recorded.baseline, field) != getattr(replayed.baseline, field):
            found.append(f"baseline {field}")
    found.extend(_rows("baseline", recorded.baseline.decisions, replayed.baseline.decisions))
    if len(recorded.candidates) != len(replayed.candidates):
        found.append("candidates")
    for index, (old, new) in enumerate(zip(recorded.candidates, replayed.candidates, strict=False)):
        run = f"candidate {index + 1}"
        for field in ("candidate_hash", "complete", "issues"):
            if getattr(old, field) != getattr(new, field):
                found.append(f"{run} {field}")
        found.extend(_rows(run, old.decisions, new.decisions))
    return found


def replay(fixture: ReplayFixture) -> Expected:
    """What the current engine classifies for the fixture's own history and candidates."""
    try:
        return expected_outcomes(verified(fixture), fixture.candidates)
    except ReplayValidationError as refusal:
        raise FixtureError(refusal.code) from None


def check(raw: bytes) -> tuple[ReplayFixture, list[str]]:
    """Replay a fixture and return what differs from its expectations; empty is a match."""
    fixture = parse(raw)
    return fixture, differences(fixture.expected, replay(fixture))


def rerecord(raw: bytes) -> bytes:
    """The same fixture with its expectations recorded again by the current engine.

    Only `expected` can change. An unchanged engine writes the same bytes, and an intended
    change of decision appears as an ordinary diff of the expectations it moved.
    """
    fixture = parse(raw)
    return render(fixture.model_copy(update={"expected": replay(fixture)}))


def _fresh(output: Path, inputs: Sequence[Path]) -> Path:
    output = Path(output)
    if os.path.lexists(output) or any(output.resolve() == Path(path).resolve() for path in inputs):
        raise FixtureError()
    return output


def write_fixture(output: Path, raw: bytes, inputs: Sequence[Path]) -> None:
    """Write a new file exclusively and readable by its owner alone, as the export a fixture
    may come from is; a failed write removes only what this call created."""
    try:
        write_new(_fresh(output, inputs), raw, mode=0o600)
    except FixtureError:
        raise
    except OSError:
        pass
    else:
        return
    raise FixtureError()


def read_file(path: Path) -> bytes:
    try:
        return read_bounded(Path(path), MAX_FIXTURE_BYTES)
    except (OSError, ValueError):
        pass
    raise FixtureError()


def run_rerecord(source: Path, output: Path) -> ReplayFixture:
    raw = rerecord(read_file(source))
    write_fixture(output, raw, (source,))
    return parse(raw)


def run_check(path: Path) -> tuple[ReplayFixture, list[str]]:
    return check(read_file(path))
