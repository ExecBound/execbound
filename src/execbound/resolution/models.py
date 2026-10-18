# SPDX-License-Identifier: AGPL-3.0-only
"""Immutable authority evidence, separate from caller claims and execution decisions."""

import hashlib
from datetime import UTC, datetime
from typing import Annotated, Literal, Protocol, Self
from uuid import UUID

from execbound_protocol.strict import Digest as Digest
from execbound_protocol.strict import Version as Version
from pydantic import AwareDatetime, ConfigDict, Field, field_validator, model_validator

from execbound.audit import canonical_json
from execbound.domains import ScalarValue
from execbound.operations import ActionName, ProviderName, ProviderOperation, ResourceType
from execbound.requests import ActionRequest, Arguments, StrictModel
from execbound.signals.capabilities import CapabilityName

FactName = Annotated[str, Field(pattern=r"^[a-z][a-z0-9_]{0,62}$")]
ContractVersion = Annotated[
    str, Field(min_length=1, max_length=80, pattern=r"^[a-z][a-z0-9_.-]{0,79}$")
]
SignalEventId = Annotated[str, Field(pattern=r"^[A-Za-z0-9._:-]{1,128}$")]
ProducerName = Annotated[str, Field(pattern=r"^[a-z][a-z0-9_.-]{0,63}$")]
# Three integer components; ranges compare them as integers, never as text.
ProducerVersion = Annotated[
    str, Field(pattern=r"^(0|[1-9][0-9]{0,5})\.(0|[1-9][0-9]{0,5})\.(0|[1-9][0-9]{0,5})$")
]
Verdict = Annotated[
    str, Field(pattern=r"^[A-Za-z0-9_.:-](?:[A-Za-z0-9 _.:-]{0,62}[A-Za-z0-9_.:-])?$")
]
MAX_SIGNAL_RECORDS = 4


class SignalRecord(StrictModel):
    """One normalized record a signal fact rested on, frozen for replay.

    It carries what re-applying a mapping needs and what identifies the stored record.
    Attributes, severity and the evidence reference stay with that stored record and never
    enter a plan.
    """

    source_id: UUID
    registration_version: int = Field(ge=1, le=2**31 - 1)
    # Whether the source's registration attested liveness when the record was read. Every
    # reader that re-applies a mapping (evaluation, replay) needs it to apply the liveness
    # rule itself: only such a source may produce `clean`. Required, so a record that does
    # not say is refused.
    attests_liveness: bool
    source_event_id: SignalEventId
    record_digest: Digest
    producer_name: ProducerName
    producer_version: ProducerVersion
    verdict: Verdict
    confidence: int = Field(ge=0, le=1000)
    observed_at: AwareDatetime
    received_at: AwareDatetime
    # Serialized only when the producer sent one; it may shorten freshness, never extend it.
    expires_at: AwareDatetime | None = Field(default=None, exclude_if=lambda value: value is None)


class SignalEvidence(StrictModel):
    """The records one signal fact was mapped from: one per admitted source."""

    capability: CapabilityName
    records: tuple[SignalRecord, ...] = Field(min_length=1, max_length=MAX_SIGNAL_RECORDS)

    @field_validator("records")
    @classmethod
    def one_per_source(cls, value: tuple[SignalRecord, ...]) -> tuple[SignalRecord, ...]:
        sources = [item.source_id for item in value]
        if len(set(sources)) != len(sources):
            raise ValueError("Two records from one source")
        return tuple(sorted(value, key=lambda item: str(item.source_id)))


class Clock(Protocol):
    def now(self) -> datetime: ...


class SystemClock:
    def now(self) -> datetime:
        return datetime.now(UTC)


class CanonicalIntent(StrictModel):
    model_config = ConfigDict(revalidate_instances="always")
    version: Literal[1] = 1
    tenant_id: UUID
    principal_id: UUID
    account_id: UUID
    provider: ProviderName = "mock_crowdstrike"
    provider_operation: ProviderOperation = "contain"
    action: ActionName = "endpoint.isolate"
    resource_type: ResourceType = "endpoint"
    target_id: UUID
    arguments: Arguments


class TrustedFact(StrictModel):
    name: FactName
    value: str | int | bool
    origin: Literal["RESOLVED", "DERIVED"]
    source_id: UUID
    source_kind: Literal["inventory", "incident", "signal"]
    source_object_id: str
    source_version: Version
    permitted_writers: tuple[str, ...]
    observed_at: AwareDatetime
    valid_until: AwareDatetime
    dependencies: tuple[FactName, ...] = ()
    # The records a signal fact was mapped from. Serialized only when set, so every plan
    # frozen before signals existed keeps its bytes.
    signal: SignalEvidence | None = Field(default=None, exclude_if=lambda value: value is None)


class ResolvedRequest(StrictModel):
    model_config = ConfigDict(revalidate_instances="always")
    request: ActionRequest
    intent: CanonicalIntent
    resource_provider_id: str
    resource_version: Version
    mapping_version: Version
    schema_version: Literal["action.v1"] = "action.v1"
    context_contract_version: ContractVersion = "endpoint-isolation.v1"
    facts: tuple[TrustedFact, ...]
    resolved_at: AwareDatetime
    valid_until: AwareDatetime
    alias_id: UUID | None = None

    @model_validator(mode="after")
    def operation_contract(self) -> Self:
        if self.intent.resource_type == "identity" and self.request.target.kind == "hostname":
            raise ValueError("Identity selectors must be canonical or provider IDs")
        return self

    def fact(self, name: str) -> TrustedFact:
        return next(fact for fact in self.facts if fact.name == name)


class SecurityVersions(StrictModel):
    bundle: Version
    authorization: Version
    approval: Version
    limits: Version


def intent_hash(intent: CanonicalIntent) -> str:
    return hashlib.sha256(canonical_json(intent.model_dump(mode="json")).encode()).hexdigest()


def plan_hash(resolved: ResolvedRequest, versions: SecurityVersions) -> str:
    envelope = resolved.model_dump(mode="json", exclude={"request", "resolved_at"})
    envelope.update({"version": 1, "security_versions": versions.model_dump(mode="json")})
    return hashlib.sha256(canonical_json(envelope).encode()).hexdigest()


def scalar_facts(resolved: ResolvedRequest) -> dict[str, ScalarValue]:
    """The frozen plan's facts by name; the same object Cedar entities and limits read."""
    return {fact.name: fact.value for fact in resolved.facts}


def binding_hash(resolved: ResolvedRequest) -> str:
    """Reattestation checks value/authority/version without extending frozen validity.

    A signal fact's records are left out with its times: a producer re-reporting the same
    verdict must not make a pending approval stale, and a changed value still does, because
    the value is bound.
    """
    envelope = resolved.model_dump(
        mode="json", exclude={"request", "resolved_at", "valid_until", "facts"}
    )
    envelope["facts"] = [
        fact.model_dump(mode="json", exclude={"observed_at", "valid_until", "signal"})
        for fact in resolved.facts
    ]
    return hashlib.sha256(canonical_json(envelope).encode()).hexdigest()
