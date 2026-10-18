# SPDX-License-Identifier: AGPL-3.0-only
"""The signal_mappings bundle component (docs/SIGNALS.md, "Map its verdicts")."""

import json
from pathlib import Path
from uuid import UUID

import pytest
from pydantic import ValidationError

from execbound.audit import canonical_json
from execbound.policy.models import BundleContent
from execbound.signals.models import SignalMapping, SignalThreshold, mapping_for
from execbound.signals.resolve import SignalScope

RETAINED = json.loads(
    (Path(__file__).parent / "fixtures/endpoint-contract-v1.json").read_text(encoding="utf-8")
)
A, B = UUID(int=701), UUID(int=702)
# The operator table for Defender for Endpoint's verdicts (#478).
MDE = (
    SignalThreshold(verdict="None", value="no_detection"),
    SignalThreshold(verdict="Informational", value="no_detection"),
    SignalThreshold(verdict="Low", value="suspect"),
    SignalThreshold(verdict="Medium", value="compromised"),
    SignalThreshold(verdict="High", value="compromised"),
)
# Two floors on one verdict: below 900, "High" reads as suspect; at or above, compromised.
# The pair pins that the canonical order breaks a tie on `minimum_confidence`, not only on
# `verdict`, and that two rows sharing a verdict are not read as a duplicate.
TWO_FLOORS = (
    SignalThreshold(verdict="High", value="suspect"),
    SignalThreshold(verdict="High", minimum_confidence=900, value="compromised"),
    SignalThreshold(verdict="Low", value="suspect"),
    SignalThreshold(verdict="Medium", value="compromised"),
)


def mapping(**changes: object) -> SignalMapping:
    values: dict[str, object] = {
        "context_contract_version": "endpoint-isolation.v2",
        "capability": "resource_compromise.v1",
        "admitted_sources": (A,),
        "thresholds": MDE,
    }
    values.update(changes)
    return SignalMapping(**values)


def test_a_bundle_without_mappings_keeps_its_bytes_and_hash():
    bundle = BundleContent.model_validate_json(json.dumps(RETAINED["bundle"]))
    assert "signal_mappings" not in bundle.model_dump(mode="json")
    assert canonical_json(bundle.model_dump(mode="json")) == RETAINED["bundle_canonical"]
    assert bundle.content_hash == RETAINED["bundle_hash"]
    explicit = BundleContent.model_validate_json(
        json.dumps({**RETAINED["bundle"], "signal_mappings": None})
    )
    assert explicit.content_hash == bundle.content_hash


def test_a_mapping_is_part_of_the_hash_and_stored_canonically():
    bundle = BundleContent.model_validate_json(json.dumps(RETAINED["bundle"]))
    # JSON mode, as the store reads bundles back: strict validation still admits UUID text.
    first = BundleContent.model_validate_json(
        json.dumps(
            {
                **bundle.model_dump(mode="json"),
                "signal_mappings": [mapping().model_dump(mode="json")],
            }
        )
    )
    assert first.content_hash != bundle.content_hash
    reordered = mapping(admitted_sources=(B, A), thresholds=tuple(reversed(MDE)))
    stored = mapping(admitted_sources=(A, B))
    assert reordered == stored
    assert [row.verdict for row in stored.thresholds] == [
        "High",
        "Informational",
        "Low",
        "Medium",
        "None",
    ]
    assert first.signal_mapping("endpoint-isolation.v2", "resource_compromise.v1") == mapping()
    assert first.signal_mapping("endpoint-isolation.v1", "resource_compromise.v1") is None
    two_floors = mapping(thresholds=TWO_FLOORS)
    two_floors_reordered = mapping(thresholds=tuple(reversed(TWO_FLOORS)))
    assert two_floors == two_floors_reordered
    assert two_floors.model_dump(mode="json") == two_floors_reordered.model_dump(mode="json")


def test_two_floors_on_one_verdict_are_accepted_and_ranked_by_confidence():
    value = mapping(thresholds=TWO_FLOORS)
    assert [(row.verdict, row.minimum_confidence) for row in value.thresholds] == [
        ("High", 0),
        ("High", 900),
        ("Low", 0),
        ("Medium", 0),
    ]


def test_mapping_entries_sort_by_version_and_capability_for_the_hash():
    bundle = BundleContent.model_validate_json(json.dumps(RETAINED["bundle"]))
    body = bundle.model_dump(mode="json")
    v1 = mapping(context_contract_version="endpoint-isolation.v1").model_dump(mode="json")
    v2 = mapping().model_dump(mode="json")
    first = BundleContent.model_validate_json(json.dumps({**body, "signal_mappings": [v1, v2]}))
    second = BundleContent.model_validate_json(json.dumps({**body, "signal_mappings": [v2, v1]}))
    assert first.signal_mappings == second.signal_mappings
    assert first.content_hash == second.content_hash


@pytest.mark.parametrize(
    "changes",
    [
        {"admitted_sources": ()},
        {"admitted_sources": (A, A)},
        {"admitted_sources": tuple(UUID(int=index) for index in range(5))},
        {"thresholds": ()},
        {"thresholds": (*MDE, SignalThreshold(verdict="High", value="suspect"))},
        {"thresholds": (SignalThreshold(verdict="High", value="unobserved"),)},
        {
            "thresholds": tuple(
                SignalThreshold(verdict=f"v{index}", value="no_detection") for index in range(33)
            )
        },
        {"capability": "content_integrity.v1"},
        {"minimum_correlation": "principal"},
        {"combination": "majority"},
        {"mode": "advisory"},
    ],
)
def test_a_malformed_mapping_is_refused(changes):
    with pytest.raises(ValidationError):
        mapping(**changes)


def test_the_bundle_and_resolution_find_an_entry_through_one_lookup():
    """`BundleContent.signal_mapping` and `SignalScope.mapping` share `mapping_for`, so the
    store, evaluation and replay find exactly the entry resolution reads."""
    bundle = BundleContent.model_validate_json(json.dumps(RETAINED["bundle"]))
    v1 = mapping(context_contract_version="endpoint-isolation.v1", admitted_sources=(B,))
    v2 = mapping()
    body = bundle.model_dump(mode="json")
    body["signal_mappings"] = [v1.model_dump(mode="json"), v2.model_dump(mode="json")]
    mapped = BundleContent.model_validate_json(json.dumps(body))
    scope = SignalScope(mapped.signal_mappings, UUID(int=9))
    for version, capability, expected in [
        ("endpoint-isolation.v1", "resource_compromise.v1", v1),
        ("endpoint-isolation.v2", "resource_compromise.v1", v2),
        ("endpoint-isolation.v2", "content_integrity.v1", None),
        ("endpoint-recovery.v1", "resource_compromise.v1", None),
    ]:
        found = mapping_for(mapped.signal_mappings, version, capability)
        assert found == expected
        assert mapped.signal_mapping(version, capability) == found
        assert scope.mapping(version, capability) == found
    for entries in (None, ()):
        assert mapping_for(entries, "endpoint-isolation.v2", "resource_compromise.v1") is None
    assert bundle.signal_mapping("endpoint-isolation.v2", "resource_compromise.v1") is None
    assert SignalScope(None, UUID(int=9)).mapping("endpoint-isolation.v2", "x") is None


def test_one_entry_per_contract_version_and_capability():
    bundle = BundleContent.model_validate_json(json.dumps(RETAINED["bundle"]))
    body = bundle.model_dump(mode="json")
    entry = mapping().model_dump(mode="json")
    with pytest.raises(ValidationError):
        BundleContent.model_validate_json(json.dumps({**body, "signal_mappings": [entry, entry]}))
    with pytest.raises(ValidationError):
        BundleContent.model_validate_json(json.dumps({**body, "signal_mappings": []}))


def test_bundle_rejects_more_than_thirty_two_signal_mappings():
    bundle = BundleContent.model_validate_json(json.dumps(RETAINED["bundle"]))
    body = bundle.model_dump(mode="json")
    entries = [
        mapping(context_contract_version=f"test-version-{index}").model_dump(mode="json")
        for index in range(33)
    ]
    with pytest.raises(ValidationError):
        BundleContent.model_validate_json(json.dumps({**body, "signal_mappings": entries}))


@pytest.mark.parametrize(
    "row",
    [
        {"verdict": "High", "value": "compromised", "minimum_confidence": 1001},
        {"verdict": "High", "value": "compromised", "minimum_confidence": 0.5},
        {"verdict": "High", "value": "compromised", "minimum_confidence": -1},
        {"verdict": "High", "value": "compromised", "minimum_confidence": True},
        {"verdict": "", "value": "compromised"},
        {"verdict": "High", "value": "Compromised"},
        {"verdict": " High", "value": "compromised"},
        {"verdict": "High ", "value": "compromised"},
        {"verdict": " ", "value": "compromised"},
        {"verdict": "x" * 65, "value": "compromised"},
    ],
)
def test_a_malformed_threshold_is_refused(row):
    with pytest.raises(ValidationError):
        SignalThreshold.model_validate(row)


@pytest.mark.parametrize("verdict", ["x" * 64, "Not Detected"])
def test_a_verdict_at_the_length_ceiling_or_with_an_inner_space_is_accepted(verdict):
    assert SignalThreshold(verdict=verdict, value="compromised").verdict == verdict
