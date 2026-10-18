# SPDX-License-Identifier: AGPL-3.0-only
"""Evaluation recomputes a signal fact from its frozen records."""

from datetime import timedelta
from uuid import uuid4

import pytest
from signal_fixtures import (
    MDE_THRESHOLDS,
    SIGNAL_RULES,
    V2,
    post_signal,
    register,
    signal_bundle,
)
from signal_fixtures import signal_world as signal_world
from sqlalchemy import text
from test_execution import request
from test_execution import world as world
from test_migration_without_bypass import fenced
from test_resolution import registry as registry

from execbound.execution.snapshot import resolve_snapshot
from execbound.policy.evaluate import evaluate
from execbound.policy.models import ContextSetting, UsageSnapshot
from execbound.policy.rulesets import ruleset_bundle
from execbound.signals.models import SignalThreshold
from execbound.signals.resolve import SignalScope

# The operator table with a quiet host read as `clean`, which only a live sensor may say.
CLEAN = (SignalThreshold(verdict="None", value="clean"), *MDE_THRESHOLDS[1:])


def frozen(db, world, verdict, *, bundle=None, **changes):
    post_signal(db, world, verdict, **changes)
    tenant = world["identity"].tenant_id
    with db.transaction(tenant, snapshot=True) as conn:
        space = conn.execute(
            text(
                "SELECT space_id FROM execbound.principals WHERE tenant_id = :t "
                "AND principal_id = :p"
            ),
            {"t": tenant, "p": world["identity"].principal_id},
        ).scalar_one()
        resolved, _ = resolve_snapshot(
            conn,
            world["identity"],
            request(world),
            world["clock"],
            signals=SignalScope((bundle or world["signal_bundle"]).signal_mappings, space),
        )
    return resolved


def decide(world, resolved, bundle=None):
    bundle = bundle or world["signal_bundle"]
    usage = UsageSnapshot(
        tenant_id=world["identity"].tenant_id,
        principal_id=world["identity"].principal_id,
        bundle_id=bundle.bundle_id,
        account_id=resolved.intent.account_id,
        counts=(),
    )
    return evaluate(
        bundle=bundle,
        identity=world["identity"],
        resolved=resolved,
        usage=usage,
        clock=world["clock"],
    )


def with_fact(resolved, name, **changes):
    facts = tuple(
        fact.model_copy(update=changes) if fact.name == name else fact for fact in resolved.facts
    )
    return resolved.model_copy(update={"facts": facts})


@pytest.mark.parametrize(
    "verdict,effect",
    [
        ("High", "ELIGIBLE"),
        ("Medium", "ELIGIBLE"),
        ("Low", "REQUIRE_APPROVAL"),
        ("Informational", "REQUIRE_APPROVAL"),
        ("None", "REQUIRE_APPROVAL"),
    ],
)
def test_isolation_without_review_happens_only_on_compromised(db, signal_world, verdict, effect):
    assert decide(signal_world, frozen(db, signal_world, verdict)).effect == effect


def test_a_domain_controller_is_denied_whatever_the_edr_says(db, signal_world, admin_engine):
    with admin_engine.begin() as conn:
        fenced(conn, signal_world["identity"].tenant_id)
        conn.execute(
            text(
                "UPDATE execbound.resources SET role = 'domain_controller' "
                "WHERE tenant_id = :t AND resource_id = :r"
            ),
            {"t": signal_world["identity"].tenant_id, "r": signal_world["target"]},
        )
    assert decide(signal_world, frozen(db, signal_world, "High")).effect == "DENY"


@pytest.mark.parametrize(
    "changes",
    [
        {"value": "no_detection"},
        {"signal": None},
        {"source_id": uuid4()},
        {"source_version": "2"},
        {"source_object_id": "device-02"},
    ],
)
def test_a_fact_its_records_do_not_reproduce_is_denied(db, signal_world, changes):
    resolved = frozen(db, signal_world, "High")
    decision = decide(signal_world, with_fact(resolved, "compromise", **changes))
    assert (decision.effect, decision.reasons) == ("DENY", ("INVALID_CONTEXT",))


def test_an_observation_its_records_do_not_reproduce_is_denied(db, signal_world):
    # Observed ten seconds before the decision, so a later observation that is still before
    # it, and still within the age limit of the frozen validity, passes every generic check.
    now = signal_world["clock"].now()
    resolved = frozen(db, signal_world, "High", observed_at=now - timedelta(seconds=10))
    fact = resolved.fact("compromise")
    shifted = with_fact(resolved, "compromise", observed_at=fact.observed_at + timedelta(seconds=5))
    assert decide(signal_world, shifted).reasons == ("INVALID_CONTEXT",)


def test_validity_beyond_what_the_records_support_is_denied(db, signal_world):
    # With no producer expiry the records support exactly the age limit, so the generic age
    # bound refuses this before `_signal_evidence` is reached. The producer-expiry test below
    # is the one that pins `_signal_evidence`'s own validity check.
    resolved = frozen(db, signal_world, "High")
    fact = resolved.fact("compromise")
    stretched = with_fact(
        resolved, "compromise", valid_until=fact.valid_until + timedelta(seconds=1)
    )
    assert decide(signal_world, stretched).reasons == ("INVALID_CONTEXT",)


def test_validity_beyond_the_producers_expiry_is_denied(db, signal_world):
    # The producer's expiry ends the record well inside the age limit, so only the records
    # themselves, and not the generic age check, bound this validity.
    now = signal_world["clock"].now()
    resolved = frozen(db, signal_world, "High", expires_at=now + timedelta(seconds=100))
    fact = resolved.fact("compromise")
    assert fact.valid_until == now + timedelta(seconds=100)
    stretched = with_fact(
        resolved, "compromise", valid_until=fact.valid_until + timedelta(seconds=1)
    )
    assert decide(signal_world, stretched).reasons == ("INVALID_CONTEXT",)


def test_a_bundle_allowing_a_longer_age_accepts_the_shorter_frozen_validity(db, signal_world):
    # The evaluated bundle lets a signal age 600 seconds; the plan was frozen under the 300
    # second default. A validity shorter than the records support is sound, so only one that
    # is longer is refused.
    resolved = frozen(db, signal_world, "High")
    base = signal_world["signal_bundle"]
    longer = ruleset_bundle(
        SIGNAL_RULES,
        tenant_id=base.tenant_id,
        bundle_id=uuid4(),
        mappings=base.mappings,
        context_settings=(
            ContextSetting(
                context_contract_version=V2,
                source_kind="signal",
                max_age_seconds=600,
                permitted_writers=("signal_mappings",),
            ),
        ),
        signal_mappings=base.signal_mappings,
    )
    fact = resolved.fact("compromise")
    assert fact.valid_until == fact.observed_at + timedelta(seconds=300)
    assert decide(signal_world, resolved, longer).effect == "ELIGIBLE"


def test_records_on_a_fact_that_is_not_a_signal_are_refused(db, signal_world):
    resolved = frozen(db, signal_world, "High")
    smuggled = with_fact(resolved, "role", signal=resolved.fact("compromise").signal)
    assert decide(signal_world, smuggled).reasons == ("INVALID_CONTEXT",)


def test_evidence_for_another_capability_is_refused(db, signal_world):
    # One capability exists today, so the model refuses any other name; a copy skips that
    # validation, as an internal object that reached evaluation unchecked could. Nothing in
    # the records names their capability, so only the evidence's own field can refuse them.
    resolved = frozen(db, signal_world, "High")
    evidence = resolved.fact("compromise").signal
    foreign = evidence.model_copy(update={"capability": "resource_compromise.v2"})
    decision = decide(signal_world, with_fact(resolved, "compromise", signal=foreign))
    assert decision.reasons == ("INVALID_CONTEXT",)


def test_a_record_observed_after_the_decision_is_refused(db, signal_world, admin_engine, tmp_path):
    # Two sources, so the record moved past the decision is neither the earliest observation
    # nor the determining source: the value, source, observation and validity it leaves are
    # exactly the frozen ones, and only the record's own time can refuse it.
    second, token = register(admin_engine, signal_world, tmp_path / "second")
    both = signal_bundle(
        signal_world["identity"].tenant_id,
        signal_world["account"],
        (signal_world["source"], second),
    )
    post_signal(db, {**signal_world, "source": second, "token": token}, "High")
    resolved = frozen(db, signal_world, "Low", bundle=both)
    fact = resolved.fact("compromise")
    assert (fact.value, fact.source_id) == ("compromised", second)
    assert decide(signal_world, resolved, both).effect == "ELIGIBLE"
    records = tuple(
        record.model_copy(update={"observed_at": resolved.resolved_at + timedelta(seconds=1)})
        if record.source_id == signal_world["source"]
        else record
        for record in fact.signal.records
    )
    ahead = with_fact(
        resolved, "compromise", signal=fact.signal.model_copy(update={"records": records})
    )
    assert decide(signal_world, ahead, both).reasons == ("INVALID_CONTEXT",)


def test_a_record_received_after_the_decision_is_refused(db, signal_world):
    # Nothing else reads a record's receipt time, so only this check can refuse it.
    resolved = frozen(db, signal_world, "High")
    fact = resolved.fact("compromise")
    records = tuple(
        record.model_copy(update={"received_at": resolved.resolved_at + timedelta(seconds=1)})
        for record in fact.signal.records
    )
    late = with_fact(
        resolved, "compromise", signal=fact.signal.model_copy(update={"records": records})
    )
    assert decide(signal_world, late).reasons == ("INVALID_CONTEXT",)


def test_a_forged_clean_over_a_source_without_liveness_is_refused(db, signal_world):
    # Silence is never clean, even under a mapping that reads a quiet host as clean. That
    # bundle cannot be validated over this source, but evaluation (and replay's candidate)
    # takes a bundle as given, so the frozen records must refuse it themselves: this source
    # never attested liveness.
    resolved = frozen(db, signal_world, "None")
    assert resolved.fact("compromise").value == "no_detection"
    quiet = signal_bundle(
        signal_world["identity"].tenant_id,
        signal_world["account"],
        (signal_world["source"],),
        thresholds=CLEAN,
    )
    forged = with_fact(resolved, "compromise", value="clean")
    assert decide(signal_world, forged, quiet).reasons == ("INVALID_CONTEXT",)


def test_a_clean_from_a_source_that_attests_liveness_is_evaluated(
    db, signal_world, admin_engine, tmp_path
):
    watching, token = register(
        admin_engine, signal_world, tmp_path / "watching", attests_liveness=True
    )
    alive = signal_bundle(
        signal_world["identity"].tenant_id, signal_world["account"], (watching,), thresholds=CLEAN
    )
    resolved = frozen(
        db, {**signal_world, "source": watching, "token": token}, "None", bundle=alive
    )
    assert resolved.fact("compromise").value == "clean"
    # Clean is not compromised, so the scenario's review rule still applies.
    assert decide(signal_world, resolved, alive).effect == "REQUIRE_APPROVAL"


def test_a_plan_is_invalid_under_a_bundle_without_its_mapping(db, signal_world):
    resolved = frozen(db, signal_world, "High")
    unmapped = signal_bundle(
        signal_world["identity"].tenant_id,
        signal_world["account"],
        (signal_world["source"],),
        signal_mappings=(),
    )
    assert unmapped.signal_mappings is None
    assert decide(signal_world, resolved, unmapped).reasons == ("INVALID_CONTEXT",)


@pytest.mark.parametrize("change", ["verdict_unmapped", "source_not_admitted"])
def test_records_the_evaluated_mapping_cannot_read_are_refused(db, signal_world, change):
    resolved = frozen(db, signal_world, "High")
    tenant, account = signal_world["identity"].tenant_id, signal_world["account"]
    if change == "verdict_unmapped":
        candidate = signal_bundle(
            tenant,
            account,
            (signal_world["source"],),
            thresholds=tuple(row for row in MDE_THRESHOLDS if row.verdict != "High"),
        )
    else:
        candidate = signal_bundle(tenant, account, (uuid4(),))
    assert decide(signal_world, resolved, candidate).reasons == ("INVALID_CONTEXT",)


def test_a_plan_is_invalid_under_a_bundle_that_reads_its_records_differently(db, signal_world):
    # Why replay re-derives the fact before evaluating a candidate: evaluation never accepts
    # a value the evaluated bundle's own mapping does not produce.
    resolved = frozen(db, signal_world, "Medium")
    stricter = signal_bundle(
        signal_world["identity"].tenant_id,
        signal_world["account"],
        (signal_world["source"],),
        thresholds=tuple(
            SignalThreshold(verdict=row.verdict, value="suspect")
            if row.verdict == "Medium"
            else row
            for row in MDE_THRESHOLDS
        ),
    )
    assert decide(signal_world, resolved, stricter).reasons == ("INVALID_CONTEXT",)
