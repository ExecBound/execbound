# SPDX-License-Identifier: AGPL-3.0-only
"""The operator's reading of a producer: the `signal_mappings` bundle component.

A mapping is authority data. It lives in the bundle, so it is reviewed, hashed and activated
with the policy that uses it, and changing a threshold is a new bundle that makes pending
plans and approvals stale exactly as a changed context setting does.
"""

from collections.abc import Iterable
from typing import Literal, Self
from uuid import UUID

from pydantic import Field, field_validator, model_validator

from execbound.requests import StrictModel
from execbound.resolution.models import MAX_SIGNAL_RECORDS, ContractVersion, Verdict
from execbound.signals.capabilities import CapabilityName, capability

MAX_THRESHOLDS = 32


class SignalThreshold(StrictModel):
    """One row: a record with this verdict whose confidence reaches this floor, and no higher
    floor for the verdict, reads as this value."""

    verdict: Verdict
    minimum_confidence: int = Field(default=0, ge=0, le=1000)
    value: str = Field(pattern=r"^[a-z][a-z0-9_]{0,31}$")


class SignalMapping(StrictModel):
    """How one contract version's fact for one capability is read from admitted sources."""

    context_contract_version: ContractVersion
    capability: CapabilityName
    # Up to four, because a frozen fact carries one record per admitted source and every
    # record travels in the audit payload (16 KiB) that replay reads.
    admitted_sources: tuple[UUID, ...] = Field(min_length=1, max_length=MAX_SIGNAL_RECORDS)
    # The only subject supported; a principal or run subject would arrive with its capability.
    minimum_correlation: Literal["resource"] = "resource"
    thresholds: tuple[SignalThreshold, ...] = Field(min_length=1, max_length=MAX_THRESHOLDS)
    # The only rule until #479 has a second real producer.
    combination: Literal["most_restrictive"] = "most_restrictive"
    # Advisory mode is not in version one.
    mode: Literal["required"] = "required"

    @field_validator("admitted_sources")
    @classmethod
    def canonical_sources(cls, value: tuple[UUID, ...]) -> tuple[UUID, ...]:
        if len(set(value)) != len(value):
            raise ValueError("Duplicate admitted source")
        return tuple(sorted(value, key=str))

    @field_validator("thresholds")
    @classmethod
    def canonical_thresholds(
        cls, value: tuple[SignalThreshold, ...]
    ) -> tuple[SignalThreshold, ...]:
        keys = [(row.verdict, row.minimum_confidence) for row in value]
        if len(set(keys)) != len(keys):
            raise ValueError("Duplicate threshold")
        return tuple(sorted(value, key=lambda row: (row.verdict, row.minimum_confidence)))

    @model_validator(mode="after")
    def values_in_domain(self) -> Self:
        domain = capability(self.capability).values
        if any(row.value not in domain for row in self.thresholds):
            raise ValueError("Threshold value outside the capability domain")
        return self


def mapping_for(
    entries: Iterable[SignalMapping] | None, version: str, capability: str
) -> SignalMapping | None:
    """The one entry for this contract version and capability, if there is one.

    The one lookup the bundle (`BundleContent.signal_mapping`) and resolution
    (`SignalScope.mapping`) share, so the store, evaluation, replay and resolution always find
    the same entry. The bundle holds at most one per pair.
    """
    return next(
        (
            item
            for item in entries or ()
            if item.context_contract_version == version and item.capability == capability
        ),
        None,
    )
