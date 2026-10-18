# SPDX-License-Identifier: AGPL-3.0-only
"""The closed capability vocabulary a producer's verdict is mapped onto.

A producer's own labels never reach policy. Each capability answers one question about one
kind of subject, and its domain is listed from least to most restrictive: that order is what a
mapping's most-restrictive combination means. A changed domain is a new capability version,
never an edit to an existing one.
"""

from dataclasses import dataclass
from types import MappingProxyType
from typing import Literal

from execbound.domains import DomainError, StringDomain, validate_domain

SubjectKind = Literal["resource"]
CapabilityName = Literal["resource_compromise.v1"]


class CapabilityError(ValueError):
    """An unknown capability, a malformed declaration or a value outside a domain."""


@dataclass(frozen=True, slots=True)
class Capability:
    name: str
    subject: SubjectKind
    # Least to most restrictive.
    values: tuple[str, ...]
    # The value only a source registered as attesting liveness may produce.
    clean: str
    # What a source that cannot attest liveness reports instead of `clean`; a capability
    # without one cannot take such a source as a required input.
    no_detection: str | None

    def __post_init__(self) -> None:
        if (
            len(self.values) < 2
            or len(set(self.values)) != len(self.values)
            or self.values[0] != self.clean
            or (self.no_detection is not None and self.no_detection not in self.values[1:])
        ):
            raise CapabilityError("Malformed capability")
        try:
            validate_domain("String", self.domain)
        except DomainError as exc:
            raise CapabilityError("Value outside the domain the kernel can check") from exc

    @property
    def domain(self) -> StringDomain:
        return StringDomain(frozenset(self.values))

    def rank(self, value: str) -> int:
        try:
            return self.values.index(value)
        except ValueError:
            raise CapabilityError("Value outside the capability domain") from None


RESOURCE_COMPROMISE_V1 = Capability(
    name="resource_compromise.v1",
    subject="resource",
    values=("clean", "no_detection", "suspect", "compromised"),
    clean="clean",
    no_detection="no_detection",
)
CAPABILITIES = MappingProxyType({RESOURCE_COMPROMISE_V1.name: RESOURCE_COMPROMISE_V1})


def capability(name: object) -> Capability:
    found = CAPABILITIES.get(name) if type(name) is str else None
    if found is None:
        raise CapabilityError("Unknown capability")
    return found
