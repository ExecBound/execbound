# SPDX-License-Identifier: Apache-2.0
"""Closed scalar value domains shared by the action catalog and context contracts."""

from dataclasses import dataclass
from typing import Literal

CedarType = Literal["String", "Long", "Boolean"]
ScalarValue = str | int | bool
LONG_MIN, LONG_MAX = -(2**63), 2**63 - 1
MAX_ARGUMENTS = 16


class DomainError(ValueError):
    """A domain declaration is not one the kernel can check exactly."""


@dataclass(frozen=True, slots=True)
class StringDomain:
    values: frozenset[str]


@dataclass(frozen=True, slots=True)
class IntegerDomain:
    minimum: int
    maximum: int


@dataclass(frozen=True, slots=True)
class BooleanDomain:
    pass


Domain = StringDomain | IntegerDomain | BooleanDomain


def _python_type(cedar_type: CedarType) -> type:
    return {"String": str, "Long": int, "Boolean": bool}[cedar_type]


def validate_domain(cedar_type: CedarType, domain: Domain) -> None:
    """Raise DomainError unless the domain is one the kernel can check exactly for this Cedar
    type.
    """
    if cedar_type == "String":
        valid = (
            isinstance(domain, StringDomain)
            and bool(domain.values)
            and all(type(v) is str and 1 <= len(v) <= 254 for v in domain.values)
        )
    elif cedar_type == "Long":
        valid = isinstance(domain, IntegerDomain) and (
            type(domain.minimum) is int
            and type(domain.maximum) is int
            and LONG_MIN <= domain.minimum <= domain.maximum <= LONG_MAX
        )
    elif cedar_type == "Boolean":
        valid = isinstance(domain, BooleanDomain)
    else:
        raise DomainError("Unsupported Cedar type")
    if not valid:
        raise DomainError("Invalid domain")


def value_in_domain(cedar_type: CedarType, domain: Domain, value: object) -> bool:
    """True when value has the exact Python type for the Cedar type and lies inside the domain."""
    if type(value) is not _python_type(cedar_type):
        return False
    if isinstance(domain, StringDomain):
        return value in domain.values
    if isinstance(domain, IntegerDomain):
        return isinstance(value, int) and domain.minimum <= value <= domain.maximum
    return True
