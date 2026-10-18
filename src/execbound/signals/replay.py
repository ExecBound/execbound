# SPDX-License-Identifier: AGPL-3.0-only
"""Re-derive a frozen plan's signal facts under a candidate bundle's mapping.

Replay asks what a candidate bundle would have decided, and a signal fact is a reading of
records through the bundle's mapping, so the candidate's entry is re-applied to the records
the plan froze. Nothing is read from the database and no detector re-runs: today's detector
is not historical evidence. Validity is left as frozen, so a candidate's stricter freshness
denies in evaluation exactly as it does for an inventory fact.
"""

from execbound.contracts import Catalog, ContextContract, ContractError, Signal
from execbound.policy.models import BundleContent
from execbound.resolution.models import ResolvedRequest, SignalEvidence, TrustedFact
from execbound.signals.capabilities import capability
from execbound.signals.mapping import UnmappedSignal, combine, earliest_observation, mapped_value


class SignalEvidenceUnavailable(ValueError):
    """The candidate needs a record, or an attestation, the plan did not freeze."""


def _reading(
    fact: TrustedFact, spec_capability: str, candidate: BundleContent, version: str
) -> TrustedFact:
    entry = candidate.signal_mapping(version, spec_capability)
    if entry is None:
        # The candidate cannot produce this fact. Evaluation refuses the plan, as the live
        # kernel would refuse the request, and replay invents nothing.
        return fact
    if fact.signal is None:
        raise SignalEvidenceUnavailable("No frozen records")
    if fact.signal.capability != spec_capability:
        # Records labelled for another capability are not records for this fact, so the
        # records the candidate would read were never frozen.
        raise SignalEvidenceUnavailable("The frozen records are for another capability")
    by_source = {record.source_id: record for record in fact.signal.records}
    if not set(entry.admitted_sources) <= set(by_source):
        raise SignalEvidenceUnavailable("The candidate admits a source the plan did not freeze")
    records = tuple(by_source[source] for source in entry.admitted_sources)
    clean = capability(entry.capability).clean
    if any(row.value == clean for row in entry.thresholds) and not all(
        record.attests_liveness for record in records
    ):
        # The store's own rule: a mapping with any row reading a verdict as clean admits
        # only sources that attest liveness, so this candidate could never have been activated
        # over these sources, whatever it reads this particular verdict as. Whether a source
        # attests liveness now is not historical evidence, so replay reports the candidate
        # unreadable rather than decide it.
        raise SignalEvidenceUnavailable("The candidate reads clean from a source without liveness")
    try:
        for record in records:
            mapped_value(entry, record)
    except UnmappedSignal:
        # A verdict the candidate's table does not map: evaluation denies, as live would.
        return fact
    # Every admitted source contributes, every verdict maps and a clean reading rests only on
    # sources attesting liveness, so nothing is left for `combine` to refuse.
    combined = combine(entry, records)
    return fact.model_copy(
        update={
            "value": combined.value,
            "source_id": combined.source_id,
            "source_version": str(by_source[combined.source_id].registration_version),
            "observed_at": earliest_observation(records),
            "signal": SignalEvidence(capability=fact.signal.capability, records=records),
        }
    )


def signal_facts(contract: ContextContract) -> dict[str, str]:
    """The contract's signal facts by name, each with the capability it is stored under."""
    return {
        spec.name: spec.storage.capability
        for spec in contract.facts
        if isinstance(spec.storage, Signal)
    }


def unknown_facts(frozen: ResolvedRequest, catalog: Catalog) -> frozenset[str]:
    """The facts of a plan that a candidate whose reading is unavailable leaves unknown.

    Its signal facts, which are all that depend on the mapping (no contract derives a fact
    from one; `rederive` would have to recompute it if one did). A contract the catalog does
    not know leaves nothing unknown, because `rederive` hands such a plan back as it is.
    """
    try:
        contract = catalog.contract(frozen.context_contract_version)
    except ContractError:
        return frozenset()
    return frozenset(signal_facts(contract))


def rederive(
    frozen: ResolvedRequest, candidate: BundleContent, catalog: Catalog
) -> ResolvedRequest:
    """The plan with each signal fact read through the candidate's entry.

    A plan with no signal fact, including every plan frozen before signals existed, is
    returned as the very object passed in. Raises `SignalEvidenceUnavailable` when the
    candidate needs a record or an attestation the plan did not freeze.
    """
    try:
        contract = catalog.contract(frozen.context_contract_version)
    except ContractError:
        return frozen
    specs = signal_facts(contract)
    if not specs:
        return frozen
    facts = tuple(
        _reading(fact, specs[fact.name], candidate, contract.version)
        if fact.name in specs
        else fact
        for fact in frozen.facts
    )
    return frozen.model_copy(update={"facts": facts})
