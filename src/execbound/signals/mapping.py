# SPDX-License-Identifier: AGPL-3.0-only
"""Apply an operator's mapping entry to normalized records; pure, and the only such code.

Resolution freezes what `combine` returns, evaluation calls it again over the frozen records
and refuses a plan it does not reproduce, and replay calls it with a candidate's entry. One
implementation is what makes those three agree.
"""

from collections.abc import Sequence
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from uuid import UUID

from execbound.resolution.models import SignalRecord
from execbound.signals.capabilities import CapabilityError, capability
from execbound.signals.models import SignalMapping


class UnmappedSignal(ValueError):
    """No row maps a record, or the records do not satisfy the entry. Never a default."""


@dataclass(frozen=True, slots=True)
class Combined:
    value: str
    source_id: UUID


def mapped_value(mapping: SignalMapping, record: SignalRecord) -> str:
    """The value of the matching row with the highest confidence floor the record reaches."""
    rows = [
        row
        for row in mapping.thresholds
        if row.verdict == record.verdict and row.minimum_confidence <= record.confidence
    ]
    if not rows:
        raise UnmappedSignal("No threshold maps this record")
    return max(rows, key=lambda row: row.minimum_confidence).value


def combine(mapping: SignalMapping, records: Sequence[SignalRecord]) -> Combined:
    """The most restrictive mapped value over exactly one record per admitted source.

    A missing source is refused rather than skipped: the source that stayed silent is the one
    that might have said `compromised`. Ties go to the lowest source id as text, so the
    named source is deterministic. A mapping naming a capability or a value outside the
    closed vocabulary refuses the same way as an unmapped record: never a default. So does
    `clean` resting on any record whose source does not attest liveness, here rather than
    only in resolution, so that evaluation and replay apply it to frozen records.
    """
    if not records:
        raise UnmappedSignal("Every admitted source must contribute exactly once")
    if sorted((item.source_id for item in records), key=str) != list(mapping.admitted_sources):
        raise UnmappedSignal("Every admitted source must contribute exactly once")
    try:
        order = capability(mapping.capability)
        pairs = [(mapped_value(mapping, item), item) for item in records]
        pairs.sort(key=lambda pair: (-order.rank(pair[0]), str(pair[1].source_id)))
    except CapabilityError as exc:
        raise UnmappedSignal("Mapping names a value outside the capability domain") from exc
    value, winner = pairs[0]
    if value == order.clean and not all(item.attests_liveness for item in records):
        raise UnmappedSignal("Only a source that attests liveness may report clean")
    return Combined(value, winner.source_id)


def _end(record: SignalRecord, max_age_seconds: int) -> datetime:
    """When one record stops counting: its age limit, or the producer's earlier expiry.

    Both bounds, and the value returned, are always in UTC. A duration added straight to a
    wall-clock time that crosses a fall-back transition would count more real seconds than the
    duration names, and two aware datetimes that share one DST-observing zone compare by wall
    clock, not by instant, so within the repeated hour they can rank backwards. Converting each
    side before comparing, and before returning, keeps every later comparison safe too.
    """
    end = record.observed_at.astimezone(UTC) + timedelta(seconds=max_age_seconds)
    if record.expires_at is None:
        return end
    return min(end, record.expires_at.astimezone(UTC))


def earliest_observation(records: Sequence[SignalRecord]) -> datetime:
    """The fact's observation: the earliest record's, as an instant in UTC.

    Resolution freezes it through `fact_window`, and replay re-derives it for a candidate
    that reads fewer of the frozen records, so both take it from here.
    """
    if not records:
        raise UnmappedSignal("No records to compute an observation from")
    return min(item.observed_at.astimezone(UTC) for item in records)


def fact_window(
    records: Sequence[SignalRecord], *, max_age_seconds: int
) -> tuple[datetime, datetime]:
    """The fact's observation and validity: the earliest of each, over every record."""
    if not records:
        raise UnmappedSignal("No records to compute a window from")
    return earliest_observation(records), min(_end(item, max_age_seconds) for item in records)
