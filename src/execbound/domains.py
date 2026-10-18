# SPDX-License-Identifier: AGPL-3.0-only
"""Closed scalar value domains, now defined in `execbound_protocol.domains` (#496).

The catalog and the context contracts both read them, and the provider protocol checks a
command's arguments against them, so they have one definition, in the protocol. This module
keeps the names importable where they always were.
"""

from execbound_protocol.domains import (
    LONG_MAX,
    LONG_MIN,
    MAX_ARGUMENTS,
    BooleanDomain,
    CedarType,
    Domain,
    DomainError,
    IntegerDomain,
    ScalarValue,
    StringDomain,
    validate_domain,
    value_in_domain,
)

__all__ = [
    "BooleanDomain",
    "CedarType",
    "Domain",
    "DomainError",
    "IntegerDomain",
    "LONG_MAX",
    "LONG_MIN",
    "MAX_ARGUMENTS",
    "ScalarValue",
    "StringDomain",
    "validate_domain",
    "value_in_domain",
]
