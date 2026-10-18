# SPDX-License-Identifier: AGPL-3.0-only
"""Frozen signal evidence: additive, outside the binding hash."""

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import UUID

import pytest
from pydantic import TypeAdapter, ValidationError

from execbound.audit import canonical_json
from execbound.execution.models import DispatchCommand
from execbound.policy.models import BundleContent
from execbound.resolution import models as resolution
from execbound.resolution.models import (
    SignalEvidence,
    SignalRecord,
    TrustedFact,
    binding_hash,
    plan_hash,
)
from execbound.secrets import find_secrets
from execbound.signals import envelope

RETAINED = json.loads(
    (Path(__file__).parent / "fixtures/endpoint-contract-v1.json").read_text(encoding="utf-8")
)
AT = datetime(2026, 9, 28, 12, 0, tzinfo=UTC)
SOURCE = UUID(int=900)


def record(**changes: object) -> SignalRecord:
    values: dict[str, object] = {
        "source_id": SOURCE,
        "registration_version": 1,
        "attests_liveness": False,
        "source_event_id": "device-1:1727524800",
        "record_digest": "a" * 64,
        "producer_name": "execbound-mde-producer",
        "producer_version": "0.1.0",
        "verdict": "Medium",
        "confidence": 1000,
        "observed_at": AT,
        "received_at": AT + timedelta(seconds=1),
    }
    values.update(changes)
    return SignalRecord(**values)


def signal_fact(evidence: SignalEvidence | None, *, value: str = "compromised") -> TrustedFact:
    return TrustedFact(
        name="compromise",
        value=value,
        origin="RESOLVED",
        source_id=SOURCE,
        source_kind="signal",
        source_object_id="device-01",
        source_version="1",
        permitted_writers=("signal_mappings",),
        observed_at=AT,
        valid_until=AT + timedelta(seconds=300),
        signal=evidence,
    )


def retained_plan():
    return DispatchCommand.model_validate_json(json.dumps(RETAINED["dispatch"])).frozen


def with_fact(fact: TrustedFact):
    frozen = retained_plan()
    return frozen.model_copy(update={"facts": (*frozen.facts, fact)})


def test_a_plan_frozen_before_signals_keeps_its_bytes_and_binding():
    frozen = retained_plan()
    dumped = frozen.model_dump(mode="json")
    assert all("signal" not in fact for fact in dumped["facts"])
    assert canonical_json(dumped) == RETAINED["resolved_canonical"]
    assert binding_hash(frozen) == RETAINED["binding_hash"]


def test_a_re_report_of_the_same_verdict_keeps_the_binding_and_changes_the_plan():
    bundle = BundleContent.model_validate_json(json.dumps(RETAINED["bundle"]))
    first = with_fact(
        signal_fact(SignalEvidence(capability="resource_compromise.v1", records=(record(),)))
    )
    later = record(
        source_event_id="device-1:1727524860",
        record_digest="b" * 64,
        observed_at=AT + timedelta(seconds=60),
        received_at=AT + timedelta(seconds=61),
    )
    second = with_fact(
        signal_fact(SignalEvidence(capability="resource_compromise.v1", records=(later,)))
    )
    assert binding_hash(first) == binding_hash(second)
    assert plan_hash(first, bundle.security_versions) != plan_hash(second, bundle.security_versions)
    changed = with_fact(
        signal_fact(
            SignalEvidence(capability="resource_compromise.v1", records=(later,)), value="suspect"
        )
    )
    assert binding_hash(changed) != binding_hash(first)


def test_records_are_canonical_bounded_and_one_per_source():
    other = UUID(int=899)
    evidence = SignalEvidence(
        capability="resource_compromise.v1",
        records=(record(), record(source_id=other, source_event_id="other-1")),
    )
    assert [item.source_id for item in evidence.records] == [other, SOURCE]
    with pytest.raises(ValidationError):
        SignalEvidence(capability="resource_compromise.v1", records=(record(), record()))
    with pytest.raises(ValidationError):
        SignalEvidence(capability="resource_compromise.v1", records=())
    with pytest.raises(ValidationError):
        SignalEvidence(
            capability="resource_compromise.v1",
            records=tuple(
                record(source_id=UUID(int=index), source_event_id=f"e{index}") for index in range(5)
            ),
        )
    with pytest.raises(ValidationError):
        SignalEvidence(capability="content_integrity.v1", records=(record(),))


@pytest.mark.parametrize(
    "changes",
    [
        {"confidence": 1001},
        {"confidence": True},
        {"confidence": 999.0},
        {"producer_version": "1.0"},
        {"record_digest": "A" * 64},
        {"verdict": ""},
        {"source_event_id": "has space"},
        {"observed_at": datetime(2026, 9, 28, 12, 0)},
        {"received_at": datetime(2026, 9, 28, 12, 0)},
        {"registration_version": 0},
        {"producer_name": "MDE"},
        {"confidence": -1},
        {"verdict": " High"},
        {"verdict": "High "},
        {"verdict": " "},
        {"verdict": "x" * 65},
        {"attests_liveness": 1},
        {"attests_liveness": "true"},
        {"attests_liveness": None},
    ],
)
def test_a_malformed_record_is_refused(changes):
    with pytest.raises(ValidationError):
        record(**changes)


@pytest.mark.parametrize("verdict", ["x" * 64, "Not Detected"])
def test_a_verdict_at_the_length_ceiling_or_with_an_inner_space_is_accepted(verdict):
    assert record(verdict=verdict).verdict == verdict


def test_a_signal_fact_with_records_out_of_order_round_trips_to_the_same_bytes():
    other = UUID(int=899)
    given = (record(), record(source_id=other, source_event_id="other-1"))
    evidence = SignalEvidence(capability="resource_compromise.v1", records=given)
    assert [item.source_id for item in evidence.records] != [item.source_id for item in given]
    fact = signal_fact(evidence)
    round_tripped = TrustedFact.model_validate_json(fact.model_dump_json())
    assert canonical_json(round_tripped.model_dump(mode="json")) == canonical_json(
        fact.model_dump(mode="json")
    )


def test_a_record_must_say_whether_its_source_attests_liveness():
    # Only a source that attests liveness may make a record read as clean, and that rule is
    # applied from this field wherever frozen records are re-read, so it is required and
    # always serialized: a record that does not say is refused, never read as False.
    values = record().model_dump()
    del values["attests_liveness"]
    with pytest.raises(ValidationError):
        SignalRecord(**values)
    assert record().model_dump(mode="json")["attests_liveness"] is False


def test_an_expiry_is_serialized_only_when_the_producer_sent_one():
    assert "expires_at" not in record().model_dump(mode="json")
    assert "expires_at" in record(expires_at=AT + timedelta(seconds=120)).model_dump(mode="json")


def test_a_signal_fact_carries_no_key_the_export_guard_would_refuse():
    fact = signal_fact(SignalEvidence(capability="resource_compromise.v1", records=(record(),)))
    assert find_secrets(fact.model_dump(mode="json")) == []


def pattern(annotated: object) -> str:
    return TypeAdapter(annotated).json_schema()["pattern"]


@pytest.mark.parametrize(
    ("ours", "frozen"),
    [
        (envelope.Label, resolution.Verdict),
        (envelope.EventId, resolution.SignalEventId),
        (envelope.ProducerName, resolution.ProducerName),
        (envelope.ProducerVersion, resolution.ProducerVersion),
        (envelope.Digest, resolution.Digest),
    ],
    ids=["verdict", "source_event_id", "producer_name", "producer_version", "digest"],
)
def test_each_envelope_field_a_record_carries_has_the_records_own_pattern(ours, frozen):
    """An admitted envelope's fields always validate as the `SignalRecord` a plan freezes."""
    assert pattern(ours) == pattern(frozen)
