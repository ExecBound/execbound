# SPDX-License-Identifier: AGPL-3.0-only
"""Build one frozen signal fact from the records the coherent statement read.

The statement has already applied the three-part applicability check and the exact
correlation: a row here belongs to this tenant and resource, to an admitted source the
agent's space may use, and to a source whose principal scope holds the agent. What is left is
re-checked from each row, the mapping applied, and the result frozen. Every failure is
`INVALID_CONTEXT`, which denies, and no approval rescues it.
"""

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any
from uuid import UUID

from pydantic import ValidationError

from execbound.contracts import (
    SIGNAL_WRITER,
    ContextContract,
    ContractError,
    FactSpec,
    Signal,
    SourceSetting,
    effective_source,
    value_matches,
)
from execbound.resolution.models import SignalEvidence, SignalRecord, TrustedFact
from execbound.resolution.registry import ResolutionError
from execbound.signals.capabilities import CapabilityError
from execbound.signals.capabilities import capability as signal_capability
from execbound.signals.mapping import UnmappedSignal, combine, fact_window
from execbound.signals.models import SignalMapping, mapping_for


@dataclass(frozen=True, slots=True)
class SignalScope:
    """What resolution needs from the decision: the bundle's mappings and the agent's space."""

    mappings: tuple[SignalMapping, ...] | None
    space: UUID

    def mapping(self, version: str, capability: str) -> SignalMapping | None:
        return mapping_for(self.mappings, version, capability)


def reader_arguments(
    contract: ContextContract, scope: SignalScope | None
) -> tuple[list[str], list[str], int]:
    """The capabilities and admitted source ids the statement reads, empty when none apply,
    and how far back it reads: the contract's signal ceiling in seconds, which no setting can
    exceed, or 0 for a contract with no signal fact."""
    capabilities: list[str] = []
    sources: set[str] = set()
    for spec in contract.facts:
        if not isinstance(spec.storage, Signal) or scope is None:
            continue
        entry = scope.mapping(contract.version, spec.storage.capability)
        if entry is not None:
            capabilities.append(spec.storage.capability)
            sources.update(str(source) for source in entry.admitted_sources)
    defaults = contract.sources.get("signal")
    ceiling = defaults.ceiling_seconds if defaults is not None else 0
    return sorted(capabilities), sorted(sources), ceiling


def _instant(value: object) -> datetime:
    parsed = value if isinstance(value, datetime) else datetime.fromisoformat(str(value))
    return parsed.astimezone(UTC)


def _record(row: Mapping[str, Any]) -> SignalRecord:
    return SignalRecord(
        source_id=UUID(str(row["source_id"])),
        registration_version=row["registration_version"],
        attests_liveness=row["attests_liveness"],
        source_event_id=row["source_event_id"],
        record_digest=row["record_digest"],
        producer_name=row["producer_name"],
        producer_version=row["producer_version"],
        verdict=row["verdict"],
        confidence=row["confidence"],
        observed_at=_instant(row["observed_at"]),
        received_at=_instant(row["received_at"]),
        expires_at=_instant(row["expires_at"]) if row["expires_at"] is not None else None,
    )


def signal_fact(
    spec: FactSpec,
    contract: ContextContract,
    settings: Sequence[SourceSetting] | None,
    scope: SignalScope | None,
    rows: Sequence[Mapping[str, Any]],
    *,
    provider_id: str,
    now: datetime,
) -> TrustedFact:
    if not isinstance(spec.storage, Signal) or scope is None:
        raise ResolutionError()
    entry = scope.mapping(contract.version, spec.storage.capability)
    if entry is None:
        raise ResolutionError()
    try:
        declared = signal_capability(spec.storage.capability)
        defaults = effective_source(contract, settings, "signal")
    except (CapabilityError, ContractError):
        raise ResolutionError() from None
    admitted = set(entry.admitted_sources)
    chosen: list[tuple[Mapping[str, Any], SignalRecord]] = []
    for row in rows:
        if row["capability"] != spec.storage.capability:
            continue
        if UUID(str(row["source_id"])) not in admitted:
            continue
        # Revocation is immediate, and a required mapping admits only an independent source;
        # both re-checked from the row the statement read. So are the space, the host and the
        # principal scope the statement filtered on: spaces have no row-level security beneath
        # the statement's predicate, a record about another host must never be counted, and a
        # source scoped to other agents never speaks for this one.
        if (
            not row["source_active"]
            or row["source_revoked_at"] is not None
            or row["input_path"] != "independent"
            or (
                UUID(str(row["space_id"])) != scope.space and row["offered_tenant_wide"] is not True
            )
            or row["subject_provider_id"] != provider_id
            or row["in_scope"] is not True
        ):
            raise ResolutionError()
        try:
            chosen.append((row, _record(row)))
        except ValidationError:
            raise ResolutionError() from None
    records = tuple(record for _, record in chosen)
    try:
        combined = combine(entry, records)
        observed, valid_until = fact_window(records, max_age_seconds=defaults.max_age_seconds)
        # The entry was found by this capability; its field carries the closed type.
        evidence = SignalEvidence(capability=entry.capability, records=records)
    except (UnmappedSignal, ValidationError):
        raise ResolutionError() from None
    if combined.value == declared.clean and not all(row["attests_liveness"] for row, _ in chosen):
        raise ResolutionError()
    # Evaluation refuses a record observed or received after the decision, so resolution does
    # too, rather than freeze a plan evaluation would deny. Compared as instants, in UTC.
    moment = now.astimezone(UTC)
    if (
        any(
            record.observed_at.astimezone(UTC) > moment
            or record.received_at.astimezone(UTC) > moment
            for record in records
        )
        or valid_until <= now
        or not value_matches(spec, combined.value)
    ):
        raise ResolutionError()
    determining = next(record for record in records if record.source_id == combined.source_id)
    return TrustedFact(
        name=spec.name,
        value=combined.value,
        origin="RESOLVED",
        source_id=combined.source_id,
        source_kind="signal",
        source_object_id=provider_id,
        source_version=str(determining.registration_version),
        permitted_writers=(SIGNAL_WRITER,),
        observed_at=observed,
        valid_until=valid_until,
        signal=evidence,
    )
