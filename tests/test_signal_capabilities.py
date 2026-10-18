# SPDX-License-Identifier: AGPL-3.0-only
"""The closed capability vocabulary: one usable capability, its order pinned."""

import typing

import pytest

from execbound.signals.capabilities import (
    CAPABILITIES,
    RESOURCE_COMPROMISE_V1,
    Capability,
    CapabilityError,
    CapabilityName,
    capability,
)


def test_resource_compromise_is_the_only_capability_and_its_order_is_the_spec():
    assert set(CAPABILITIES) == {"resource_compromise.v1"}
    assert RESOURCE_COMPROMISE_V1.values == ("clean", "no_detection", "suspect", "compromised")
    assert RESOURCE_COMPROMISE_V1.subject == "resource"
    assert RESOURCE_COMPROMISE_V1.clean == "clean"
    assert RESOURCE_COMPROMISE_V1.no_detection == "no_detection"
    assert RESOURCE_COMPROMISE_V1.domain.values == frozenset(RESOURCE_COMPROMISE_V1.values)


def test_rank_is_restrictiveness():
    ranks = [RESOURCE_COMPROMISE_V1.rank(value) for value in RESOURCE_COMPROMISE_V1.values]
    assert ranks == [0, 1, 2, 3]
    with pytest.raises(CapabilityError):
        RESOURCE_COMPROMISE_V1.rank("unobserved")


@pytest.mark.parametrize(
    "name",
    ["content_integrity.v1", "resource_compromise.v2", "", 1, None, ["resource_compromise.v1"]],
)
def test_unknown_capabilities_are_refused(name):
    with pytest.raises(CapabilityError):
        capability(name)


def test_known_capability_resolves_to_the_singleton():
    assert capability("resource_compromise.v1") is RESOURCE_COMPROMISE_V1


def test_capability_name_literal_matches_the_registry():
    assert set(typing.get_args(CapabilityName)) == set(CAPABILITIES)


@pytest.mark.parametrize(
    "values,clean,no_detection",
    [
        (("clean", "clean"), "clean", None),
        (("clean", "compromised"), "fine", None),
        (("clean", "compromised"), "clean", "quiet"),
        (("clean", "compromised"), "compromised", None),
        ((), "clean", None),
        (("clean", "compromised"), "clean", "clean"),
        (("clean",), "clean", None),
        (("clean", ""), "clean", None),
    ],
)
def test_a_malformed_capability_cannot_be_declared(values, clean, no_detection):
    with pytest.raises(CapabilityError):
        Capability("x.v1", "resource", values, clean, no_detection)
