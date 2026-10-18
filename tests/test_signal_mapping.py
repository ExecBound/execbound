# SPDX-License-Identifier: AGPL-3.0-only
"""Applying a mapping entry to records (docs/SIGNALS.md, "Map its verdicts")."""

import subprocess
import sys
from datetime import UTC, datetime, timedelta
from uuid import UUID
from zoneinfo import ZoneInfo

import pytest

from execbound.resolution.models import SignalRecord
from execbound.signals.mapping import UnmappedSignal, combine, fact_window, mapped_value
from execbound.signals.models import SignalMapping, SignalThreshold

AT = datetime(2026, 9, 28, 12, 0, tzinfo=UTC)
A, B = UUID(int=701), UUID(int=702)
MDE = (
    SignalThreshold(verdict="None", value="no_detection"),
    SignalThreshold(verdict="Informational", value="no_detection"),
    SignalThreshold(verdict="Low", value="suspect"),
    SignalThreshold(verdict="Medium", value="compromised"),
    SignalThreshold(verdict="High", value="compromised"),
)


def record(source: UUID = A, verdict: str = "Medium", **changes: object) -> SignalRecord:
    values: dict[str, object] = {
        "source_id": source,
        "registration_version": 1,
        "attests_liveness": False,
        "source_event_id": f"{source.int}-1",
        "record_digest": "a" * 64,
        "producer_name": "execbound-mde-producer",
        "producer_version": "0.1.0",
        "verdict": verdict,
        "confidence": 1000,
        "observed_at": AT,
        "received_at": AT,
    }
    values.update(changes)
    return SignalRecord(**values)


# The operator table with a quiet host read as `clean`, which only a live sensor may say.
CLEAN = (SignalThreshold(verdict="None", value="clean"), *MDE[1:])


def mapping(*sources: UUID, thresholds: tuple[SignalThreshold, ...] = MDE) -> SignalMapping:
    return SignalMapping(
        context_contract_version="endpoint-isolation.v2",
        capability="resource_compromise.v1",
        admitted_sources=sources or (A,),
        thresholds=thresholds,
    )


@pytest.mark.parametrize(
    "verdict,value",
    [
        ("None", "no_detection"),
        ("Informational", "no_detection"),
        ("Low", "suspect"),
        ("Medium", "compromised"),
        ("High", "compromised"),
    ],
)
def test_the_decided_table_maps_each_risk_score(verdict, value):
    assert mapped_value(mapping(), record(verdict=verdict)) == value


def test_an_unmapped_verdict_is_refused_not_read_as_quiet():
    with pytest.raises(UnmappedSignal):
        mapped_value(mapping(), record(verdict="Critical"))


def test_verdict_matching_is_case_sensitive():
    with pytest.raises(UnmappedSignal):
        mapped_value(mapping(), record(verdict="high"))


def test_the_highest_floor_the_confidence_reaches_wins():
    rows = (
        SignalThreshold(verdict="injection", minimum_confidence=0, value="suspect"),
        SignalThreshold(verdict="injection", minimum_confidence=900, value="compromised"),
    )
    table = mapping(thresholds=rows)
    assert mapped_value(table, record(verdict="injection", confidence=899)) == "suspect"
    assert mapped_value(table, record(verdict="injection", confidence=900)) == "compromised"
    floor = mapping(thresholds=rows[1:])
    with pytest.raises(UnmappedSignal):
        mapped_value(floor, record(verdict="injection", confidence=899))


def test_the_most_restrictive_value_wins_and_names_its_source():
    both = mapping(A, B)
    combined = combine(both, (record(A, "None"), record(B, "Low")))
    assert (combined.value, combined.source_id) == ("suspect", B)
    tie = combine(both, (record(B, "High"), record(A, "Medium")))
    assert (tie.value, tie.source_id) == ("compromised", A)


def test_compromised_outranks_suspect_whatever_the_text_order():
    # Alphabetically "compromised" < "suspect", the opposite of the capability's own order
    # (clean, no_detection, suspect, compromised). The combination must use the domain order.
    combined = combine(mapping(A, B), (record(A, "Low"), record(B, "High")))
    assert (combined.value, combined.source_id) == ("compromised", B)


def test_clean_needs_every_record_from_a_source_that_attests_liveness():
    # Silence, or a sensor that stopped reporting, never reads as clean. Each record says
    # whether its source attests liveness, so every reader that re-applies a mapping to frozen
    # records (evaluation, replay) refuses exactly as resolution does.
    with pytest.raises(UnmappedSignal):
        combine(mapping(thresholds=CLEAN), (record(A, "None"),))
    watching = record(A, "None", attests_liveness=True)
    with pytest.raises(UnmappedSignal):
        combine(mapping(A, B, thresholds=CLEAN), (watching, record(B, "None")))
    both = combine(
        mapping(A, B, thresholds=CLEAN), (watching, record(B, "None", attests_liveness=True))
    )
    assert (both.value, both.source_id) == ("clean", A)


def test_a_source_without_liveness_may_still_raise_the_fact():
    # Only `clean` needs liveness: a more restrictive value from any source stands.
    combined = combine(
        mapping(A, B, thresholds=CLEAN),
        (record(A, "None", attests_liveness=True), record(B, "Low")),
    )
    assert (combined.value, combined.source_id) == ("suspect", B)


def test_one_unmapped_record_refuses_the_whole_fact():
    with pytest.raises(UnmappedSignal):
        combine(mapping(A, B), (record(A, "Critical"), record(B, "None")))
    rows = (
        SignalThreshold(verdict="High", minimum_confidence=900, value="compromised"),
        SignalThreshold(verdict="None", value="no_detection"),
    )
    with pytest.raises(UnmappedSignal):
        combine(
            mapping(A, B, thresholds=rows),
            (record(A, "High", confidence=899), record(B, "None")),
        )


@pytest.mark.parametrize(
    "records",
    [
        (),
        (record(A),),
        (record(A), record(UUID(int=703))),
        (record(A), record(B), record(UUID(int=703))),
        (record(A), record(B), record(B, "None")),
    ],
)
def test_every_admitted_source_must_contribute_exactly_once(records):
    with pytest.raises(UnmappedSignal):
        combine(mapping(A, B), records)


def test_an_unregistered_capability_refuses_rather_than_raising_capabilityerror():
    # Bypasses field validation (model_construct), the way a stale bundle or a hand-built
    # fixture could, to prove combine() never lets CapabilityError leak past its own contract.
    bad = SignalMapping.model_construct(
        context_contract_version="endpoint-isolation.v2",
        capability="unknown.v1",
        admitted_sources=(A,),
        minimum_correlation="resource",
        thresholds=(SignalThreshold(verdict="Medium", value="compromised"),),
        combination="most_restrictive",
        mode="required",
    )
    with pytest.raises(UnmappedSignal):
        combine(bad, (record(A, "Medium"),))


def test_a_threshold_value_outside_the_domain_refuses_too():
    # The threshold's own value pattern accepts "bogus"; only values_in_domain (skipped by
    # model_construct) would normally catch it before combine() ever sees the row.
    bad = SignalMapping.model_construct(
        context_contract_version="endpoint-isolation.v2",
        capability="resource_compromise.v1",
        admitted_sources=(A,),
        minimum_correlation="resource",
        thresholds=(SignalThreshold(verdict="Medium", value="bogus"),),
        combination="most_restrictive",
        mode="required",
    )
    with pytest.raises(UnmappedSignal):
        combine(bad, (record(A, "Medium"),))


def test_an_empty_mapping_refuses_rather_than_indexerror():
    empty = SignalMapping.model_construct(
        context_contract_version="endpoint-isolation.v2",
        capability="resource_compromise.v1",
        admitted_sources=(),
        minimum_correlation="resource",
        thresholds=(SignalThreshold(verdict="Medium", value="compromised"),),
        combination="most_restrictive",
        mode="required",
    )
    with pytest.raises(UnmappedSignal):
        combine(empty, ())


def test_the_window_is_the_earliest_observation_and_the_earliest_expiry():
    early = record(A, observed_at=AT - timedelta(seconds=30))
    late = record(B, observed_at=AT, expires_at=AT + timedelta(seconds=100))
    observed, valid_until = fact_window((early, late), max_age_seconds=300)
    assert observed == AT - timedelta(seconds=30)
    assert valid_until == AT + timedelta(seconds=100)
    observed, valid_until = fact_window((early,), max_age_seconds=300)
    assert valid_until == AT + timedelta(seconds=270)


def test_a_producer_expiry_never_lengthens_and_each_record_ages_on_its_own():
    long = record(A, observed_at=AT, expires_at=AT + timedelta(seconds=3600))
    assert fact_window((long,), max_age_seconds=300) == (AT, AT + timedelta(seconds=300))
    early = record(A, observed_at=AT - timedelta(seconds=30))
    assert fact_window((early, record(B)), max_age_seconds=300) == (
        AT - timedelta(seconds=30),
        AT + timedelta(seconds=270),
    )


def test_a_dst_fall_back_does_not_stretch_the_window():
    # 2026-11-01 01:58 America/New_York falls in the hour the fall-back repeats; fold=0, the
    # first (EDT) 01:58. Naively adding 300 seconds of wall-clock time crosses the fall-back
    # at 02:00 and lands 65 real minutes later, not 5.
    ny = ZoneInfo("America/New_York")
    observed = datetime(2026, 11, 1, 1, 58, tzinfo=ny)
    _, valid_until = fact_window((record(A, observed_at=observed),), max_age_seconds=300)
    assert valid_until == observed.astimezone(UTC) + timedelta(seconds=300)

    # Two records in the same zone can straddle the repeated hour: 01:30 EDT (fold=0) is
    # 05:30 UTC, earlier than 01:10 EST (fold=1) at 06:10 UTC, even though 01:10 reads earlier
    # on the wall clock they share. The earliest observation must be picked by instant.
    early = datetime(2026, 11, 1, 1, 30, tzinfo=ny, fold=0)
    late = datetime(2026, 11, 1, 1, 10, tzinfo=ny, fold=1)
    observed_at, _ = fact_window(
        (record(A, observed_at=early), record(B, observed_at=late)), max_age_seconds=300
    )
    assert observed_at == datetime(2026, 11, 1, 5, 30, tzinfo=UTC)


def test_a_producer_expiry_is_compared_by_instant_not_a_shared_wall_clock():
    # Two producers can hand back expires_at values built from the same process-wide ZoneInfo
    # instance. If _end returned a raw, un-converted expires_at, fact_window's cross-record min
    # would compare those two returned values by the wall clock they share rather than by
    # instant (`_end`'s own internal min already compares by instant here, since it weighs a
    # UTC `end` against a differently-offset zoned value; the shared-tzinfo hazard only shows
    # up one level up, once two such raw values meet each other). Pick expires_at over the age
    # limit for both records, so each _end() call is decided by expires_at, then let the two
    # raw expiries collide in fact_window's own min.
    ny = ZoneInfo("America/New_York")
    early_expiry = datetime(2026, 11, 1, 1, 30, tzinfo=ny, fold=0)  # 05:30 UTC
    late_expiry = datetime(2026, 11, 1, 1, 10, tzinfo=ny, fold=1)  # 06:10 UTC, later in reality
    records = (
        record(A, observed_at=AT, expires_at=early_expiry),
        record(B, observed_at=AT, expires_at=late_expiry),
    )
    _, valid_until = fact_window(records, max_age_seconds=5_000_000)
    assert valid_until == datetime(2026, 11, 1, 5, 30, tzinfo=UTC)


def test_fact_window_of_no_records_is_refused_not_a_bare_valueerror():
    with pytest.raises(UnmappedSignal):
        fact_window((), max_age_seconds=300)


@pytest.mark.parametrize(
    "module", ["execbound.signals.models", "execbound.signals.mapping", "execbound.signals.resolve"]
)
def test_each_signals_module_imports_first_in_a_fresh_interpreter(module):
    # Each of these reaches execbound.resolution, whose package imports its fact builder; a
    # module-level import back into execbound.signals there finds this module half-initialized.
    result = subprocess.run(
        [sys.executable, "-c", f"import {module}"], capture_output=True, text=True, check=False
    )
    assert result.returncode == 0, result.stderr
