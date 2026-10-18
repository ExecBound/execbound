# SPDX-License-Identifier: AGPL-3.0-only
"""Shared scalar domains check exact types and declared bounds."""

import pytest

from execbound.domains import (
    LONG_MAX,
    LONG_MIN,
    BooleanDomain,
    DomainError,
    IntegerDomain,
    StringDomain,
    validate_domain,
    value_in_domain,
)


@pytest.mark.parametrize(
    "cedar_type,domain",
    [
        ("String", StringDomain(frozenset())),
        ("String", StringDomain(frozenset({""}))),
        ("String", StringDomain(frozenset({"x" * 255}))),
        ("String", IntegerDomain(0, 1)),
        ("Long", IntegerDomain(5, 1)),
        ("Long", IntegerDomain(0, LONG_MAX + 1)),
        ("Long", BooleanDomain()),
        ("Boolean", StringDomain(frozenset({"true"}))),
        ("Set", BooleanDomain()),
    ],
)
def test_invalid_domains_are_rejected(cedar_type, domain):
    with pytest.raises(DomainError):
        validate_domain(cedar_type, domain)


def test_valid_domains_pass():
    validate_domain("String", StringDomain(frozenset({"a"})))
    validate_domain("Long", IntegerDomain(-1, 1))
    validate_domain("Boolean", BooleanDomain())
    validate_domain("String", StringDomain(frozenset({"x" * 254})))
    validate_domain("Long", IntegerDomain(LONG_MIN, LONG_MAX))
    validate_domain("Long", IntegerDomain(3, 3))


@pytest.mark.parametrize(
    "cedar_type,domain,value,expected",
    [
        ("String", StringDomain(frozenset({"a"})), "a", True),
        ("String", StringDomain(frozenset({"a"})), "b", False),
        ("Long", IntegerDomain(0, 4), 4, True),
        ("Long", IntegerDomain(0, 4), 5, False),
        ("Long", IntegerDomain(0, 4), True, False),
        ("Long", IntegerDomain(0, 4), "4", False),
        ("Boolean", BooleanDomain(), False, True),
        ("Boolean", BooleanDomain(), 0, False),
    ],
)
def test_value_in_domain_requires_exact_type(cedar_type, domain, value, expected):
    assert value_in_domain(cedar_type, domain, value) is expected
