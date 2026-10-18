# SPDX-License-Identifier: AGPL-3.0-only
"""The signal source kind in the contract catalog (docs/SIGNALS.md)."""

from dataclasses import replace
from types import MappingProxyType

import pytest

from execbound.contracts import (
    ENDPOINT_ISOLATION_V1,
    ENDPOINT_ISOLATION_V2,
    PRODUCTION_CATALOG,
    SIGNAL_WRITER,
    BooleanDomain,
    Catalog,
    Column,
    ContextContract,
    ContractError,
    Equals,
    FactSpec,
    Signal,
    SourceDefaults,
    StringDomain,
    effective_source,
)
from execbound.policy.models import ContextSetting
from execbound.signals.capabilities import RESOURCE_COMPROMISE_V1


def test_v2_is_v1_plus_the_compromise_fact_and_binds_the_incident_claim():
    assert ENDPOINT_ISOLATION_V2.version == "endpoint-isolation.v2"
    assert ENDPOINT_ISOLATION_V2.actions == frozenset({"endpoint.isolate"})
    assert ENDPOINT_ISOLATION_V2.cedar_entity_type == "Endpoint"
    assert ENDPOINT_ISOLATION_V2.bind_incident_claim is True
    assert ENDPOINT_ISOLATION_V2.facts[:-1] == ENDPOINT_ISOLATION_V1.facts
    compromise = ENDPOINT_ISOLATION_V2.fact("compromise")
    assert compromise == FactSpec(
        "compromise",
        "String",
        RESOURCE_COMPROMISE_V1.domain,
        "signal",
        Signal("resource_compromise.v1"),
    )
    assert ENDPOINT_ISOLATION_V2.sources["signal"] == SourceDefaults(300, 3600, (SIGNAL_WRITER,))
    assert (
        PRODUCTION_CATALOG.for_operation("endpoint-isolation.v2", "endpoint.isolate", "endpoint")
        is ENDPOINT_ISOLATION_V2
    )


def _with(fact: FactSpec, **sources: SourceDefaults) -> ContextContract:
    return replace(
        ENDPOINT_ISOLATION_V2,
        version="endpoint-isolation.test",
        facts=(*ENDPOINT_ISOLATION_V1.facts, fact),
        sources=MappingProxyType({**ENDPOINT_ISOLATION_V2.sources, **sources}),
    )


_RC = Signal("resource_compromise.v1")
_DOMAIN = RESOURCE_COMPROMISE_V1.domain
# v1's sources alone (no "signal" key): a fact whose own kind is not "signal" needs this, or
# the unrelated "sources differ from the kinds facts declare" check would refuse it first and
# the case would no longer be pinned to the check it names.
_NON_SIGNAL_KIND = replace(
    _with(FactSpec("x", "String", _DOMAIN, "inventory", _RC)),
    sources=ENDPOINT_ISOLATION_V1.sources,
)


@pytest.mark.parametrize(
    "contract,expected",
    [
        # Signal storage on a non-signal kind.
        (_NON_SIGNAL_KIND, "Signal storage needs the signal kind"),
        # An unknown capability.
        (
            _with(FactSpec("x", "String", _DOMAIN, "signal", Signal("content_integrity.v1"))),
            "Unknown capability",
        ),
        # A domain that is not the capability's.
        (
            _with(
                FactSpec(
                    "x",
                    "String",
                    StringDomain(frozenset({"clean", "compromised"})),
                    "signal",
                    _RC,
                )
            ),
            "Signal fact domain differs from its capability",
        ),
        # A non-String type: the domain/type mismatch is caught by the existing domain check
        # before the signal-specific checks ever run.
        (_with(FactSpec("x", "Boolean", _DOMAIN, "signal", _RC)), "Invalid domain"),
        # A column cannot back a signal fact: `COLUMNS["signal"]` is empty.
        (_with(FactSpec("x", "String", _DOMAIN, "signal", Column("role"))), "Unsupported column"),
    ],
)
def test_a_malformed_signal_fact_is_refused(contract, expected):
    with pytest.raises(ContractError, match=expected):
        Catalog((contract,))


def test_two_facts_for_one_capability_are_refused():
    second = replace(ENDPOINT_ISOLATION_V2.fact("compromise"), name="compromise_again")
    contract = replace(
        ENDPOINT_ISOLATION_V2,
        version="endpoint-isolation.test",
        facts=(*ENDPOINT_ISOLATION_V2.facts, second),
    )
    with pytest.raises(ContractError):
        Catalog((contract,))


def test_a_fact_cannot_be_derived_from_a_signal():
    # A well-formed Boolean derivation, so the only thing wrong with it is its dependency.
    derived = FactSpec(
        "is_compromised",
        "Boolean",
        BooleanDomain(),
        "signal",
        None,
        Equals("compromise", "compromised"),
    )
    contract = replace(
        ENDPOINT_ISOLATION_V2,
        version="endpoint-isolation.test",
        facts=(*ENDPOINT_ISOLATION_V2.facts, derived),
    )
    with pytest.raises(ContractError):
        Catalog((contract,))


def test_signal_writers_are_only_the_mapping_label():
    wrong = SourceDefaults(300, 3600, ("edr",))
    with pytest.raises(ContractError):
        Catalog((_with(ENDPOINT_ISOLATION_V2.fact("compromise"), signal=wrong),))


def test_a_signal_setting_tunes_freshness_but_not_writers():
    tuned = ContextSetting(
        context_contract_version="endpoint-isolation.v2",
        source_kind="signal",
        max_age_seconds=900,
        permitted_writers=(SIGNAL_WRITER,),
    )
    assert effective_source(ENDPOINT_ISOLATION_V2, (tuned,), "signal") == SourceDefaults(
        900, 3600, (SIGNAL_WRITER,)
    )
    relabelled = tuned.model_copy(update={"permitted_writers": ("edr",)})
    with pytest.raises(ContractError):
        effective_source(ENDPOINT_ISOLATION_V2, (relabelled,), "signal")
    beyond = tuned.model_copy(update={"max_age_seconds": 3601})
    with pytest.raises(ContractError):
        effective_source(ENDPOINT_ISOLATION_V2, (beyond,), "signal")


def test_every_contract_of_a_resource_type_declares_the_same_inventory_columns():
    # Whole specs, not just (name, column): a future contract that reused a column under a
    # narrower domain would otherwise pass this check while `administration._facts` (which
    # picks the first contract of a resource type as good as any) silently used the wrong one.
    by_type: dict[str, set[frozenset[FactSpec]]] = {}
    for version in PRODUCTION_CATALOG.versions:
        contract = PRODUCTION_CATALOG.contract(version)
        columns = frozenset(
            spec
            for spec in contract.facts
            if spec.source_kind == "inventory" and isinstance(spec.storage, Column)
        )
        by_type.setdefault(contract.resource_type, set()).add(columns)
    assert all(len(shapes) == 1 for shapes in by_type.values())
