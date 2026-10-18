# SPDX-License-Identifier: AGPL-3.0-only
"""TG16: the live trial's captured wire bodies, parsed by the gateway's own models.

Captured from the final allow case of the 2026-09-24 live Tines Gate trial
(``docs/trials/2026-09-24-tines-gate.md``, reference
``GATE-TRIAL-allow-final-story-32265e1e``): the decision request the Gate story's Execute
action sent to the gateway, and the outcome report its Report journal action sent back. The
report's ``report_secret`` was already replaced with a placeholder at capture, before either
fixture was committed. The trial's third piece of evidence, an ES256 attestation, is
deliberately not committed alongside these, because a compact JWS is credential-shaped.
These tests carry no signature verification, because the trial's private keys are not
committed either; they only prove that the bodies a real Tines run produced are ones the
gateway's own request parser and outcome-report model still accept.
"""

import json
from pathlib import Path

from execbound.execution.outcomes import OutcomeReport, parse_report
from execbound.provider.models import ProviderCommand, SignedJournal
from execbound.requests import ActionRequest, parse_request

FIXTURES = Path(__file__).resolve().parent / "fixtures"
DECISION_BODY = FIXTURES / "tines-gate-decision-body.json"
JOURNAL_REPORT = FIXTURES / "tines-gate-journal-report.json"


def test_the_captured_decision_body_parses_as_the_gates_action_request():
    """The Gate story's Execute action sends the Execute story's own wire body, unchanged."""
    request = parse_request(DECISION_BODY.read_bytes())
    assert isinstance(request, ActionRequest)
    assert request.operation_ref == "gate.endpoint.isolate"
    assert request.target.kind == "provider_id"
    assert request.target.value == "gate-workstation-10"
    assert request.arguments.root == {}
    assert request.external_case is None
    assert request.claimed_context.incident_id is not None
    assert request.reference == "GATE-TRIAL-allow-final-story-32265e1e"
    # The gateway derives the key from the reference; the story never sends its own.
    assert request.idempotency_key


def test_the_captured_journal_report_parses_as_an_outcome_report_carrying_one_journal():
    report = parse_report(JOURNAL_REPORT.read_bytes())
    assert isinstance(report, OutcomeReport)
    assert report.outcome == "EXECUTED"
    assert report.reason == "EXECUTED"
    assert report.signed == ("journal",)
    assert report.attestation is None
    assert report.record is None
    assert report.reported_at is None
    assert report.report_secret.startswith("REDACTED")


def test_the_reports_journal_is_a_signed_journal_for_a_contain_command():
    report = parse_report(JOURNAL_REPORT.read_bytes())
    # Strict models take exact Python types (UUID, datetime), not the strings a dict decoded
    # from JSON carries; re-serializing and parsing as JSON is what the gateway itself does.
    journal = SignedJournal.model_validate_json(json.dumps(report.journal))
    assert journal.key_id == "gate-journal-v1"
    command = journal.record.command
    assert isinstance(command, ProviderCommand)
    assert command.provider == "mock_crowdstrike"
    assert command.action == "endpoint.isolate"
    assert command.provider_operation == "contain"
    assert journal.record.outcome == "EXECUTED"
    assert journal.record.mutation_count == 1
    assert journal.record.command_hash == command.command_hash


def test_neither_fixture_carries_a_real_secret_or_signature():
    """Only the placeholder secret and the redacted HMAC digest are here, never live values."""
    decision = json.loads(DECISION_BODY.read_text())
    report = json.loads(JOURNAL_REPORT.read_text())
    assert set(decision) == {
        "arguments",
        "claimed_context",
        "external_case",
        "operation_ref",
        "reference",
        "target",
    }
    assert report["report_secret"] == "REDACTED_REPORT_SECRET_REDACTED_REDACTED_000"
    assert "attestation" not in report
    assert "record" not in report
