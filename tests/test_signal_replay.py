# SPDX-License-Identifier: AGPL-3.0-only
"""Replay of signal decisions (docs/SIGNALS.md, "Replay")."""

from datetime import datetime, timedelta, timezone
from uuid import uuid4

import pytest
from signal_fixtures import (
    MDE_THRESHOLDS,
    SIGNAL_RULES,
    insert_source,
    post_signal,
    register,
    signal_bundle,
)
from signal_fixtures import signal_world as signal_world
from test_execution import request
from test_execution import world as world
from test_migration_without_bypass import fenced
from test_protected_path import connector as connector
from test_protected_path import live_provider as live_provider
from test_resolution import registry as registry
from test_runtime import api as api
from test_runtime import runtime as runtime
from test_signal_evaluation import CLEAN, decide, frozen, with_fact

from execbound.audit import canonical_json
from execbound.contracts import PRODUCTION_CATALOG
from execbound.execution.modes import set_enforcement_mode
from execbound.policy.models import Condition, LimitRule, LimitSelector, Rule, Ruleset
from execbound.policy.store import activate_bundle, create_bundle, validate_bundle
from execbound.replay.export import export_history
from execbound.replay.models import (
    MAX_EVENT_PAYLOAD_BYTES,
    ApprovalCapture,
    DecisionCapture,
    HistoricalIdentity,
)
from execbound.replay.simulate import _attributes, simulate
from execbound.replay.verify import verify_export
from execbound.resolution.models import MAX_SIGNAL_RECORDS, SignalEvidence, SignalRecord
from execbound.signals.models import SignalThreshold
from execbound.signals.replay import SignalEvidenceUnavailable, rederive, unknown_facts


def history_of(db, world):
    export = export_history(db, world["admin"], world["clock"])
    return verify_export(export, export.head)


def reading(world, *, thresholds=MDE_THRESHOLDS, sources=None, rules=SIGNAL_RULES):
    return signal_bundle(
        world["identity"].tenant_id,
        world["account"],
        sources or (world["source"],),
        thresholds=thresholds,
        rules=rules,
    )


MEDIUM_IS_SUSPECT = tuple(
    SignalThreshold(verdict=row.verdict, value="suspect") if row.verdict == "Medium" else row
    for row in MDE_THRESHOLDS
)
# A reading of Medium as `clean`, which only a source attesting liveness may produce.
MEDIUM_IS_CLEAN = tuple(
    SignalThreshold(verdict=row.verdict, value="clean") if row.verdict == "Medium" else row
    for row in MDE_THRESHOLDS
)
# A table with no row for Medium, so a frozen Medium record maps to nothing.
MEDIUM_UNMAPPED = tuple(row for row in MDE_THRESHOLDS if row.verdict != "Medium")
# The scenario without its review rule, and at most one isolation of a suspect host an hour:
# a budget over the signal fact itself.
SUSPECT_CAP = Ruleset(
    rules=tuple(
        rule for rule in SIGNAL_RULES.rules if rule.id != "isolate-review-unless-compromised"
    ),
    budgets=(
        LimitRule(
            rule_id="suspect-cap",
            action="endpoint.isolate",
            scope="selector",
            selector=LimitSelector(fact="compromise", equals="suspect"),
            window_seconds=3600,
            max_targets=1,
            budget="total",
            on_exceed="DENY",
        ),
    ),
)


def execute(api, world, **changes):
    return api.post("/v1/execute", json=request(world, **changes).model_dump(mode="json")).json()


def admissions(report):
    return [
        item
        for item in report.decisions
        if item.action == "endpoint.isolate" and item.stage == "ADMISSION"
    ]


def counted(result, rule_id):
    [count] = [item for item in result.counts if item.rule_id == rule_id]
    return count.confirmed_targets, count.unresolved_targets


def test_rederive_reads_the_frozen_records_through_the_candidate(db, signal_world):
    resolved = frozen(db, signal_world, "Medium")
    candidate = reading(signal_world, thresholds=MEDIUM_IS_SUSPECT)
    rederived = rederive(resolved, candidate, PRODUCTION_CATALOG)
    assert rederived.fact("compromise").value == "suspect"
    assert rederived.fact("compromise").valid_until == resolved.fact("compromise").valid_until
    assert decide(signal_world, rederived, candidate).effect == "REQUIRE_APPROVAL"
    assert rederive(resolved, signal_world["signal_bundle"], PRODUCTION_CATALOG) == resolved


def test_a_candidate_admitting_fewer_sources_reads_only_the_one_it_admits(
    db, signal_world, admin_engine
):
    # The frozen fact rests on two sources: the first, observed earlier, says High and
    # determines it. A candidate admitting only the second reads that source's record alone,
    # so the value, the source, its registration version, the observation and the evidence all
    # move to it, and evaluation under the candidate accepts exactly that reading.
    tenant, now = signal_world["identity"].tenant_id, signal_world["clock"].now()
    with admin_engine.begin() as conn:
        fenced(conn, tenant)
        second, token = insert_source(
            conn, tenant, signal_world["identity"].principal_id, now, registration_version=3
        )
    post_signal(db, {**signal_world, "source": second, "token": token}, "Low")
    both = reading(signal_world, sources=(signal_world["source"], second))
    resolved = frozen(
        db, signal_world, "High", bundle=both, observed_at=now - timedelta(seconds=10)
    )
    fact = resolved.fact("compromise")
    assert (fact.value, fact.source_id, fact.source_version) == (
        "compromised",
        signal_world["source"],
        "1",
    )
    assert fact.observed_at == now - timedelta(seconds=10)
    candidate = reading(signal_world, sources=(second,))
    reread = rederive(resolved, candidate, PRODUCTION_CATALOG).fact("compromise")
    [record] = [item for item in fact.signal.records if item.source_id == second]
    assert (reread.value, reread.source_id, reread.source_version) == ("suspect", second, "3")
    assert reread.observed_at == record.observed_at == now
    assert reread.signal.records == (record,)
    assert reread.valid_until == fact.valid_until
    rederived = rederive(resolved, candidate, PRODUCTION_CATALOG)
    assert decide(signal_world, rederived, candidate).effect == "REQUIRE_APPROVAL"


def test_a_candidate_admitting_an_unfrozen_source_cannot_be_read(db, signal_world):
    resolved = frozen(db, signal_world, "Medium")
    candidate = reading(signal_world, sources=(signal_world["source"], uuid4()))
    with pytest.raises(SignalEvidenceUnavailable):
        rederive(resolved, candidate, PRODUCTION_CATALOG)


def test_a_signal_fact_without_frozen_records_cannot_be_read(db, signal_world):
    resolved = frozen(db, signal_world, "Medium")
    stripped = with_fact(resolved, "compromise", signal=None)
    with pytest.raises(SignalEvidenceUnavailable):
        rederive(stripped, reading(signal_world), PRODUCTION_CATALOG)


def test_evidence_for_another_capability_cannot_be_read(db, signal_world):
    # One capability exists today, so the model refuses any other name; a copy skips that
    # validation. Records labelled for another capability are not records for this fact.
    resolved = frozen(db, signal_world, "Medium")
    evidence = resolved.fact("compromise").signal
    foreign = evidence.model_copy(update={"capability": "resource_compromise.v2"})
    with pytest.raises(SignalEvidenceUnavailable):
        rederive(
            with_fact(resolved, "compromise", signal=foreign),
            reading(signal_world),
            PRODUCTION_CATALOG,
        )


def test_a_candidate_reading_clean_from_a_source_without_liveness_cannot_be_read(db, signal_world):
    # The candidate reads a quiet host as clean, which needs liveness the frozen records say
    # this source never attested. The store would never activate that candidate over
    # this source, so replay reports it unreadable rather than inventing a value.
    resolved = frozen(db, signal_world, "None")
    assert resolved.fact("compromise").value == "no_detection"
    with pytest.raises(SignalEvidenceUnavailable):
        rederive(resolved, reading(signal_world, thresholds=CLEAN), PRODUCTION_CATALOG)


def test_a_candidate_reading_clean_from_a_source_attesting_liveness_is_rederived(
    db, signal_world, admin_engine, tmp_path
):
    watching, token = register(
        admin_engine, signal_world, tmp_path / "watching", attests_liveness=True
    )
    live = {**signal_world, "source": watching, "token": token}
    original = reading(live)
    resolved = frozen(db, live, "None", bundle=original)
    assert resolved.fact("compromise").value == "no_detection"
    candidate = reading(live, thresholds=CLEAN)
    rederived = rederive(resolved, candidate, PRODUCTION_CATALOG)
    assert rederived.fact("compromise").value == "clean"
    # Clean is not compromised, so the scenario's review rule still applies.
    assert decide(signal_world, rederived, candidate).effect == "REQUIRE_APPROVAL"


@pytest.mark.parametrize("change", ["verdict_unmapped", "no_entry"])
def test_a_candidate_that_cannot_produce_the_fact_is_left_to_evaluation(db, signal_world, change):
    # Replay invents nothing: the frozen fact is passed on, and evaluation under the
    # candidate denies it exactly as the live kernel would refuse the request.
    resolved = frozen(db, signal_world, "Medium")
    if change == "verdict_unmapped":
        candidate = reading(signal_world, thresholds=MEDIUM_UNMAPPED)
    else:
        candidate = signal_bundle(
            signal_world["identity"].tenant_id,
            signal_world["account"],
            (signal_world["source"],),
            signal_mappings=(),
        )
    assert rederive(resolved, candidate, PRODUCTION_CATALOG) == resolved
    assert decide(signal_world, resolved, candidate).reasons == ("INVALID_CONTEXT",)


@pytest.mark.parametrize("contract", ["endpoint-isolation.v1", "endpoint-isolation.v9"])
def test_a_plan_with_no_signal_fact_is_returned_untouched(db, signal_world, contract):
    # History recorded before signals (v1), and a contract the catalog does not know (which
    # evaluation refuses), are handed back as the very object replay read.
    resolved = frozen(db, signal_world, "Medium")
    plan = resolved.model_copy(
        update={
            "context_contract_version": contract,
            "facts": tuple(fact for fact in resolved.facts if fact.name != "compromise"),
        }
    )
    candidate = reading(signal_world, thresholds=MEDIUM_IS_SUSPECT)
    assert rederive(plan, candidate, PRODUCTION_CATALOG) is plan
    # Nor does a candidate's reading leave any of such a plan's facts unknown.
    assert unknown_facts(plan, PRODUCTION_CATALOG) == frozenset()
    assert unknown_facts(resolved, PRODUCTION_CATALOG) == {"compromise"}


def test_the_original_bundle_reproduces_every_decision_with_no_producer(
    api, db, signal_world, live_provider
):
    post_signal(db, signal_world, "Medium")
    assert (
        api.post("/v1/execute", json=request(signal_world).model_dump(mode="json")).json()["state"]
        == "EXECUTED"
    )
    report = simulate(history_of(db, signal_world))
    signal_decisions = [item for item in report.decisions if item.action == "endpoint.isolate"]
    assert signal_decisions
    for item in signal_decisions:
        assert item.baseline.effect == item.recorded_effect
        assert "RECORDED_DECISION_MISMATCH" not in item.baseline.reasons


def test_a_candidate_reading_is_replayed_and_an_unreadable_one_is_unresolved(
    api, db, signal_world, live_provider
):
    post_signal(db, signal_world, "Medium")
    api.post("/v1/execute", json=request(signal_world).model_dump(mode="json"))
    history = history_of(db, signal_world)
    # A candidate that denies what it reads as suspect: a DENY is certain at any usage, so
    # replay reports it rather than hedging, and it proves the reading was re-derived.
    denying = Ruleset(
        rules=(
            *SIGNAL_RULES.rules,
            Rule(
                id="isolate-never-suspect",
                action="endpoint.isolate",
                effect="DENY",
                when=(
                    Condition(kind="fact", name="compromise", operator="is", values=("suspect",)),
                ),
            ),
        )
    )
    candidate = reading(signal_world, thresholds=MEDIUM_IS_SUSPECT, rules=denying)
    [compared] = [
        item for item in simulate(history, candidate).decisions if item.action == "endpoint.isolate"
    ]
    assert compared.candidate is not None
    assert compared.candidate.effect == "DENY"
    assert "INVALID_CONTEXT" not in compared.candidate.reasons
    unreadable = reading(signal_world, sources=(signal_world["source"], uuid4()))
    [compared] = [
        item
        for item in simulate(history, unreadable).decisions
        if item.action == "endpoint.isolate"
    ]
    assert compared.candidate is not None
    assert compared.candidate.effect == "UNRESOLVED"
    assert "SIGNAL_EVIDENCE_UNAVAILABLE" in compared.candidate.reasons


def test_each_candidate_reading_is_replayed_as_the_live_kernel_would_decide(
    api, db, signal_world, live_provider
):
    post_signal(db, signal_world, "Medium")
    api.post("/v1/execute", json=request(signal_world).model_dump(mode="json"))
    history = history_of(db, signal_world)
    tenant, account = signal_world["identity"].tenant_id, signal_world["account"]
    expectations = (
        # Read as suspect, the scenario asks for review. Both usage bounds are evaluated on
        # the candidate's reading, so the limit is certain and only the approval nobody gave
        # this candidate is unknown.
        (
            reading(signal_world, thresholds=MEDIUM_IS_SUSPECT),
            "UNRESOLVED",
            ("APPROVAL_REQUIRED", "UNKNOWN_HUMAN_APPROVAL"),
        ),
        # Clean over a source that never attested liveness: unreadable, never a value.
        (
            reading(signal_world, thresholds=MEDIUM_IS_CLEAN),
            "UNRESOLVED",
            ("SIGNAL_EVIDENCE_UNAVAILABLE",),
        ),
        # A table that does not map the frozen verdict, and a bundle with no entry at all:
        # evaluation denies, as the live kernel would refuse the request.
        (reading(signal_world, thresholds=MEDIUM_UNMAPPED), "DENY", ("INVALID_CONTEXT",)),
        (
            signal_bundle(tenant, account, (signal_world["source"],), signal_mappings=()),
            "DENY",
            ("INVALID_CONTEXT",),
        ),
    )
    unreadable = reading(signal_world, sources=(signal_world["source"], uuid4()))
    # A limit over an action the catalog does not know: the candidate is invalid, and that
    # is the more basic problem than the record it cannot read.
    unserved = LimitRule(
        rule_id="unserved",
        action="endpoint.isolate",
        actions=("endpoint.isolate", "endpoint.unplug"),
        scope="principal",
        window_seconds=3600,
        max_targets=1,
        budget="total",
        on_exceed="DENY",
    )
    elsewhere = tuple(
        reference.model_copy(update={"mapping_version": "map-v2"})
        for reference in unreadable.mappings
    )
    expectations += (
        (
            unreadable.model_copy(update={"limits": (*unreadable.limits, unserved)}),
            "DENY",
            ("POLICY_ERROR",),
        ),
        # One that cannot even be compared with the recorded bundle says so first.
        (
            unreadable.model_copy(
                update={"limits": (*unreadable.limits, unserved), "mappings": elsewhere}
            ),
            "UNRESOLVED",
            ("SIGNAL_EVIDENCE_UNAVAILABLE", "UNSUPPORTED_CANDIDATE_CONTEXT"),
        ),
    )
    for candidate, effect, reasons in expectations:
        [compared] = [
            item
            for item in simulate(history, candidate).decisions
            if item.action == "endpoint.isolate"
        ]
        assert compared.candidate is not None
        assert (compared.candidate.effect, compared.candidate.reasons) == (effect, reasons)


def test_a_candidate_that_could_never_be_activated_over_the_records_is_unreadable(
    api, db, signal_world, live_provider
):
    # Any row reading a verdict as clean needs every admitted source to attest liveness, or
    # the store refuses the candidate. So over this source it is unreadable even for a
    # decision its table reads as something else: High is compromised in this table too.
    post_signal(db, signal_world, "High")
    assert execute(api, signal_world)["state"] == "EXECUTED"
    [compared] = admissions(
        simulate(history_of(db, signal_world), reading(signal_world, thresholds=MEDIUM_IS_CLEAN))
    )
    assert compared.recorded_effect == "ELIGIBLE"
    assert (compared.candidate.effect, compared.candidate.reasons) == (
        "UNRESOLVED",
        ("SIGNAL_EVIDENCE_UNAVAILABLE",),
    )


# The recorded bundle's own budget over the signal fact: one isolation of a compromised host
# an hour. It makes the baseline's count, and so its agreement with the recorded decision,
# depend on the recorded reading.
COMPROMISED_CAP = Ruleset(
    rules=SIGNAL_RULES.rules,
    budgets=(
        LimitRule(
            rule_id="compromised-cap",
            action="endpoint.isolate",
            scope="selector",
            selector=LimitSelector(fact="compromise", equals="compromised"),
            window_seconds=3600,
            max_targets=1,
            budget="total",
            on_exceed="DENY",
        ),
    ),
)


@pytest.mark.parametrize("mode", ["ENFORCE", "OBSERVE"])
def test_a_candidate_budget_counts_earlier_units_by_the_candidates_reading(
    api, db, signal_world, live_provider, mode
):
    # Two isolations on Medium, recorded as compromised. The recorded bundle caps compromised
    # hosts at one an hour, so the second was denied. The candidate reads Medium as suspect
    # and caps suspect hosts instead, so the kernel under it would have retained the first
    # unit as suspect and denied the second on its own budget. Observed decisions are
    # retained the same way, and counted by an observed evaluation.
    recorded = reading(signal_world, rules=COMPROMISED_CAP)
    for step in (create_bundle, validate_bundle, activate_bundle):
        target = recorded if step is create_bundle else recorded.bundle_id
        step(db, signal_world["admin"], target, signal_world["clock"])
    if mode == "OBSERVE":
        set_enforcement_mode(db, signal_world["admin"], mode, "Tuning", signal_world["clock"])
    post_signal(db, signal_world, "Medium")
    assert execute(api, signal_world)["state"] == ("EXECUTED" if mode == "ENFORCE" else "OBSERVED")
    signal_world["clock"].value += timedelta(seconds=5)
    execute(api, signal_world, idempotency_key="second")
    candidate = reading(signal_world, thresholds=MEDIUM_IS_SUSPECT, rules=SUSPECT_CAP)
    first, second = admissions(simulate(history_of(db, signal_world), candidate))
    assert (first.recorded_effect, second.recorded_effect) == ("ELIGIBLE", "DENY")
    # The baseline retains the first unit by the recorded reading, so it reproduces the
    # recorded denial on the recorded budget.
    assert (second.baseline.effect, second.baseline.reasons) == (
        "DENY",
        ("HARD_LIMIT:compromised-cap",),
    )
    assert counted(second.baseline, "compromised-cap") == (1, 0)
    assert first.candidate.effect == "ELIGIBLE"
    assert (second.candidate.effect, second.candidate.reasons) == (
        "DENY",
        ("HARD_LIMIT:suspect-cap",),
    )
    assert counted(second.candidate, "suspect-cap") == (1, 0)


def test_an_earlier_unit_the_candidate_cannot_read_leaves_a_signal_budget_unknown(
    api, db, signal_world, live_provider, admin_engine, tmp_path
):
    # The first isolation rests on one source. The operator then admits a second, and the
    # next isolation rests on both. A candidate admitting both cannot read the first unit, so
    # it cannot say whether that unit counts toward a budget over the signal fact: the
    # second decision's room is only a lower bound, never an answer.
    tenant, account = signal_world["identity"].tenant_id, signal_world["account"]
    post_signal(db, signal_world, "Medium")
    assert execute(api, signal_world)["state"] == "EXECUTED"
    second, token = register(admin_engine, signal_world, tmp_path / "second")
    both = signal_bundle(tenant, account, (signal_world["source"], second))
    for step in (create_bundle, validate_bundle, activate_bundle):
        target = both if step is create_bundle else both.bundle_id
        step(db, signal_world["admin"], target, signal_world["clock"])
    signal_world["clock"].value += timedelta(seconds=5)
    post_signal(db, signal_world, "Medium")
    post_signal(db, {**signal_world, "source": second, "token": token}, "Medium")
    execute(api, signal_world, idempotency_key="second")
    candidate = reading(
        signal_world,
        thresholds=MEDIUM_IS_SUSPECT,
        sources=(signal_world["source"], second),
        rules=SUSPECT_CAP,
    )
    history = history_of(db, signal_world)
    first, later = admissions(simulate(history, candidate))
    assert (first.recorded_effect, later.recorded_effect) == ("ELIGIBLE", "ELIGIBLE")
    assert (first.candidate.effect, first.candidate.reasons) == (
        "UNRESOLVED",
        ("SIGNAL_EVIDENCE_UNAVAILABLE",),
    )
    # Unknown for the unit it cannot read, and changed on the target that unit may have
    # acted on.
    assert (later.candidate.effect, later.candidate.reasons) == (
        "UNRESOLVED",
        ("CHANGED_PREREQUISITE", "SIGNAL_EVIDENCE_UNAVAILABLE"),
    )
    # Counted as neither reading: the lower bound leaves the unit out.
    assert counted(later.candidate, "suspect-cap") == (0, 0)
    # The unit is retained with its signal fact unknown, and without the recorded reading.
    [recorded] = [
        entry.capture
        for entry in history.events
        if entry.capture is not None and entry.capture.execution_id == first.execution_id
    ]
    retained = _attributes(recorded, None, PRODUCTION_CATALOG)
    assert retained["unknown_facts"] == {"compromise"}
    assert "compromise" not in retained["facts"]
    # A budget that does not apply to the later decision, which this candidate reads as
    # compromised, is not made unknown by the unit nobody can read.
    unaffected = reading(signal_world, sources=(signal_world["source"], second), rules=SUSPECT_CAP)
    _, later = admissions(simulate(history, unaffected))
    assert (later.candidate.effect, later.candidate.reasons) == (
        "UNRESOLVED",
        ("CHANGED_PREREQUISITE",),
    )


# The widest serialization each record field allows: an offset rather than `Z`, microseconds,
# and every string at its pattern's longest.
WIDEST_TIME = datetime(
    2026, 9, 29, 23, 59, 59, 999999, tzinfo=timezone(-timedelta(hours=9, minutes=30))
)


def widest_record() -> SignalRecord:
    return SignalRecord(
        source_id=uuid4(),
        registration_version=2**31 - 1,
        attests_liveness=False,
        source_event_id="e" * 128,
        record_digest="f" * 64,
        producer_name="p" * 64,
        producer_version="999999.999999.999999",
        verdict="V" * 64,
        confidence=1000,
        observed_at=WIDEST_TIME,
        received_at=WIDEST_TIME,
        expires_at=WIDEST_TIME,
    )


def human(capture: DecisionCapture) -> HistoricalIdentity:
    return HistoricalIdentity(
        tenant_id=capture.identity.tenant_id,
        principal_id=uuid4(),
        credential_id=uuid4(),
        kind="HUMAN_APPROVER",
        issued_at=WIDEST_TIME - timedelta(days=1),
        expires_at=WIDEST_TIME,
    )


def test_four_records_at_maximum_width_fit_the_decision_capture(
    api, db, signal_world, live_provider
):
    # Replay reads the records from `execution.evaluated`, whose payload the audit writer and
    # replay's reader both bound at 16 KiB. The recorded capture of a real decision, widened
    # to the most records a fact may carry at the widest each field allows, to the most groups
    # an identity may record, and to a verified approval by the largest quorum, must still fit.
    post_signal(db, signal_world, "Medium")
    api.post("/v1/execute", json=request(signal_world).model_dump(mode="json"))
    [capture] = [
        entry.capture
        for entry in history_of(db, signal_world).events
        if entry.capture is not None and entry.capture.frozen.intent.action == "endpoint.isolate"
    ]
    records = tuple(widest_record() for _ in range(MAX_SIGNAL_RECORDS))
    widened = with_fact(
        capture.frozen,
        "compromise",
        value="no_detection",
        source_id=records[0].source_id,
        source_version=str(2**31 - 1),
        signal=SignalEvidence(capability="resource_compromise.v1", records=records),
    )
    identity = HistoricalIdentity.model_validate(
        {
            **capture.identity.model_dump(),
            "groups": tuple(sorted((uuid4() for _ in range(64)), key=str)),
        }
    )
    approval = ApprovalCapture(
        status="VERIFIED",
        approval_id=uuid4(),
        tenant_id=capture.identity.tenant_id,
        principal_id=capture.identity.principal_id,
        bundle_id=capture.bundle_id,
        plan_hash="0" * 64,
        obligation_ids=("policy:" + "o" * 153,),
        expires_at=WIDEST_TIME,
        approver=human(capture),
        canonical_target_id=capture.canonical_target_id,
        action=capture.frozen.intent.action,
        required_approvers=5,
        approvers=tuple(human(capture) for _ in range(5)),
    )
    payload = DecisionCapture.model_validate(
        {**capture.model_dump(), "frozen": widened, "identity": identity, "approval": approval}
    ).model_dump(mode="json")
    encoded = canonical_json(payload).encode("utf-8")
    assert len(encoded) <= MAX_EVENT_PAYLOAD_BYTES
    # And replay's reader parses it back to the same four records.
    parsed = DecisionCapture.model_validate_json(encoded)
    assert (
        parsed.frozen.fact("compromise").signal.records == widened.fact("compromise").signal.records
    )
