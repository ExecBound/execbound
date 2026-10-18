# SPDX-License-Identifier: AGPL-3.0-only
"""Resolution of a signal fact (docs/SIGNALS.md, "How a decision reads it")."""

import inspect
import json
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from types import MappingProxyType
from uuid import uuid4

import pytest
from signal_fixtures import (
    CAPABILITY,
    MDE_THRESHOLDS,
    PRODUCER,
    V2,
    VERSION,
    register,
    signal_bundle,
)
from signal_fixtures import post_signal as admit_signal
from signal_fixtures import signal_world as signal_world
from sqlalchemy import text
from test_execution import request
from test_execution import world as world
from test_migration_without_bypass import fenced
from test_resolution import registry as registry
from test_resolution import resolve as resolve_test_path

from execbound.contracts import (
    ENDPOINT_ISOLATION_V1,
    ENDPOINT_ISOLATION_V2,
    PRODUCTION_CATALOG,
    SIGNAL_WRITER,
    Catalog,
    SourceDefaults,
)
from execbound.execution import snapshot
from execbound.execution.snapshot import resolve_snapshot
from execbound.policy.models import ContextSetting
from execbound.requests import parse_request
from execbound.resolution.registry import ResolutionError
from execbound.signals.models import SignalMapping, SignalThreshold
from execbound.signals.resolve import SignalScope, reader_arguments, signal_fact


def post_signal(db, world, verdict, **changes):
    """Admit one record and insist it was accepted, so no refusal below is an intake one."""
    result = admit_signal(db, world, verdict, **changes)
    assert result.get("accepted") is True, result
    return result


def scope_of(world, bundle=None):
    return SignalScope((bundle or world["signal_bundle"]).signal_mappings, world["space"])


@pytest.fixture
def live(signal_world, db, admin_engine):
    with admin_engine.begin() as conn:
        fenced(conn, signal_world["identity"].tenant_id)
        space = conn.execute(
            text(
                "SELECT space_id FROM execbound.principals WHERE tenant_id = :t "
                "AND principal_id = :p"
            ),
            {"t": signal_world["identity"].tenant_id, "p": signal_world["identity"].principal_id},
        ).scalar_one()
    return {**signal_world, "space": space}


def resolve(db, world, *, scope="default", wire=None, settings=None, **changes):
    sent = (
        parse_request(json.dumps(wire).encode()) if wire is not None else request(world, **changes)
    )
    with db.transaction(world["identity"].tenant_id, snapshot=True) as conn:
        resolved, _ = resolve_snapshot(
            conn,
            world["identity"],
            sent,
            world["clock"],
            settings=settings,
            signals=scope_of(world) if scope == "default" else scope,
        )
    return resolved


@pytest.mark.parametrize(
    "verdict,value",
    [
        ("None", "no_detection"),
        ("Low", "suspect"),
        ("Medium", "compromised"),
        ("High", "compromised"),
    ],
)
def test_the_newest_record_is_mapped_and_frozen(db, live, verdict, value):
    post_signal(db, live, verdict)
    fact = resolve(db, live).fact("compromise")
    assert (fact.value, fact.source_kind, fact.source_id) == (value, "signal", live["source"])
    assert fact.source_object_id == "device-01" and fact.source_version == "1"
    assert fact.permitted_writers == ("signal_mappings",)
    assert fact.signal is not None and fact.signal.capability == CAPABILITY
    [record] = fact.signal.records
    assert record.verdict == verdict and record.source_id == live["source"]
    assert record.attests_liveness is False
    assert fact.valid_until == fact.observed_at + timedelta(seconds=300)


def test_a_later_observation_supersedes_an_earlier_one_whatever_the_arrival_order(db, live):
    # The earlier observation arrives last: it is received ten seconds after the later one.
    t0 = live["clock"].now()
    post_signal(db, live, "High", observed_at=t0 - timedelta(seconds=5))
    live["clock"].value = t0 + timedelta(seconds=10)
    post_signal(db, live, "None", observed_at=t0 - timedelta(seconds=30))
    assert resolve(db, live).fact("compromise").value == "compromised"


def test_a_newer_record_narrowed_to_the_action_replaces_a_general_one(db, live):
    # Narrowing to the action does not make a record a second voice from the same source: the
    # newest applicable record is the source's word, whatever it names.
    now = live["clock"].now()
    post_signal(db, live, "None", observed_at=now - timedelta(seconds=20), event_id="device-01:g")
    post_signal(
        db,
        live,
        "High",
        observed_at=now - timedelta(seconds=5),
        action="endpoint.isolate",
        event_id="device-01:n",
    )
    fact = resolve(db, live).fact("compromise")
    assert fact.value == "compromised"
    assert [record.source_event_id for record in fact.signal.records] == ["device-01:n"]


def test_the_later_receipt_wins_a_tie_on_observation(db, live):
    # Same observation, received ten seconds apart. The earlier receipt's event id sorts
    # higher, so the event-id tie-break alone would pick the wrong one.
    t0 = live["clock"].now()
    observed = t0 - timedelta(seconds=5)
    post_signal(db, live, "None", observed_at=observed, event_id="device-01:b")
    live["clock"].value = t0 + timedelta(seconds=10)
    post_signal(db, live, "High", observed_at=observed, event_id="device-01:a")
    fact = resolve(db, live).fact("compromise")
    assert fact.value == "compromised"
    assert [record.source_event_id for record in fact.signal.records] == ["device-01:a"]


def test_a_tie_is_broken_by_event_id_in_byte_order(db, live):
    # Same observation, same receipt: the event id decides, compared byte by byte whatever the
    # database's collation, so every deployment picks the same record. Under a linguistic
    # collation "B" sorts after "a"; in byte order it sorts before.
    now = live["clock"].now()
    post_signal(db, live, "High", observed_at=now, event_id="device-01:B")
    post_signal(db, live, "None", observed_at=now, event_id="device-01:a")
    fact = resolve(db, live).fact("compromise")
    assert [record.source_event_id for record in fact.signal.records] == ["device-01:a"]


@pytest.mark.parametrize(
    "setup",
    [
        "no_record",
        "stale",
        "expired_by_producer",
        "unmapped_verdict",
        "inactive",
        "revoked",
        "other_resource",
        "other_action",
        "other_reference",
        "no_scope",
        "no_entry",
    ],
)
def test_every_way_the_fact_is_not_there_is_invalid_context(db, live, admin_engine, setup):
    now = live["clock"].now()
    scope = "default"
    if setup == "stale":
        post_signal(db, live, "High", observed_at=now - timedelta(seconds=301))
    elif setup == "expired_by_producer":
        post_signal(
            db,
            live,
            "High",
            observed_at=now - timedelta(seconds=20),
            expires_at=now - timedelta(seconds=1),
        )
    elif setup == "unmapped_verdict":
        post_signal(db, live, "Critical")
    elif setup == "inactive":
        post_signal(db, live, "High")
        with admin_engine.begin() as conn:
            fenced(conn, live["identity"].tenant_id)
            conn.execute(
                text("UPDATE execbound.signal_sources SET active = false WHERE source_id = :s"),
                {"s": live["source"]},
            )
    elif setup == "revoked":
        post_signal(db, live, "High")
        with admin_engine.begin() as conn:
            fenced(conn, live["identity"].tenant_id)
            conn.execute(
                text(
                    "UPDATE execbound.signal_sources SET active = false, revoked_at = now(), "
                    "revoked_by = created_by WHERE source_id = :s"
                ),
                {"s": live["source"]},
            )
    elif setup == "other_resource":
        post_signal(db, live, "High", subject_provider_id="device-02")
    elif setup == "other_action":
        post_signal(db, live, "High", action="endpoint.lift_isolation")
    elif setup == "other_reference":
        post_signal(db, live, "High", request_reference="ticket-9")
    elif setup == "no_scope":
        post_signal(db, live, "High")
        scope = None
    elif setup == "no_entry":
        post_signal(db, live, "High")
        scope = SignalScope(None, live["space"])
    with pytest.raises(ResolutionError) as caught:
        resolve(db, live, scope=scope)
    assert caught.value.code == "INVALID_CONTEXT"  # denies, and no approval rescues it


def naming(live, reference):
    """A request that names `reference`. A request carries a key or a reference, never an
    explicit empty key, so this one is built with only the reference (`ActionRequest.one_key`).
    """
    return {
        "operation_ref": "endpoint.isolate",
        "target": {"kind": "hostname", "value": "WS01.EXAMPLE."},
        "arguments": {},
        "reference": reference,
        "claimed_context": {"incident_id": str(live["incident"]), "severity": "LOW"},
    }


def test_a_request_scoped_record_never_applies_even_to_the_request_it_names(db, live):
    """A request's `reference` is the agent's own string, so it never chooses the records.

    The intake refuses a request reference, but the writer beneath it stores one, so a row
    carrying it is written here straight through `signal_admit`. The producer scoped a newer
    `compromised` to `ticket-9`; any agent in the source's scope could name `ticket-9` and, were
    that row read, isolate without review on a verdict meant for another request. Resolution
    reads only unscoped records, so the older unscoped one is the source's word whatever the
    request names.
    """
    now = live["clock"].now()
    post_signal(db, live, "None", observed_at=now - timedelta(seconds=20), event_id="device-01:u")
    post_signal(
        db,
        live,
        "High",
        observed_at=now - timedelta(seconds=5),
        request_reference="ticket-9",
        event_id="device-01:r",
    )
    for wire in (naming(live, "ticket-9"), naming(live, "ticket-10"), None):
        fact = resolve(db, live, wire=wire).fact("compromise")
        assert fact.value == "no_detection"
        assert [record.source_event_id for record in fact.signal.records] == ["device-01:u"]


def test_a_request_scoped_record_alone_is_no_record(db, live):
    post_signal(db, live, "High", request_reference="ticket-9")
    with pytest.raises(ResolutionError) as caught:
        resolve(db, live, wire=naming(live, "ticket-9"))
    assert caught.value.code == "INVALID_CONTEXT"


@pytest.mark.parametrize("function", [snapshot.resolve_snapshot, snapshot.attest_snapshot])
def test_every_resolution_names_its_signal_scope(function):
    """`signals` has no default, so a caller that forgets the bundle's mappings and the agent's
    space is a type error, not a request resolved without its signal facts."""
    parameter = inspect.signature(function).parameters["signals"]
    assert parameter.kind is inspect.Parameter.KEYWORD_ONLY
    assert parameter.default is inspect.Parameter.empty


def test_every_admitted_source_must_speak(db, live, admin_engine, tmp_path):
    second, _ = register(admin_engine, live, tmp_path / "second")
    both = signal_bundle(live["identity"].tenant_id, live["account"], (live["source"], second))
    post_signal(db, live, "Low")
    with pytest.raises(ResolutionError):
        resolve(db, live, scope=SignalScope(both.signal_mappings, live["space"]))


def test_the_most_restrictive_source_names_the_fact_and_every_record_is_frozen(
    db, live, admin_engine, tmp_path
):
    second, token = register(admin_engine, live, tmp_path / "second")
    both = signal_bundle(live["identity"].tenant_id, live["account"], (live["source"], second))
    post_signal(db, live, "Low")
    post_signal(db, {**live, "source": second, "token": token}, "High")
    fact = resolve(db, live, scope=SignalScope(both.signal_mappings, live["space"])).fact(
        "compromise"
    )
    assert (fact.value, fact.source_id) == ("compromised", second)
    assert [record.source_id for record in fact.signal.records] == sorted(
        (live["source"], second), key=str
    )


@pytest.mark.parametrize("subject", ["account", "resource_type"])
def test_the_correlation_is_exact(db, live, admin_engine, subject):
    """A record about the same provider id under another account or resource type is another
    subject. The provider is fixed by the account (one provider per account, and the record's
    foreign key names both), so it has no case of its own."""
    tenant = live["identity"].tenant_id
    if subject == "account":
        other = uuid4()
        with admin_engine.begin() as conn:
            fenced(conn, tenant)
            conn.execute(
                text(
                    "INSERT INTO execbound.connector_accounts(tenant_id, account_id, provider, "
                    "space_id) VALUES (:t, :a, 'mock_crowdstrike', :s)"
                ),
                {"t": tenant, "a": other, "s": live["space"]},
            )
        post_signal(db, live, "High", subject_account=other)
    else:
        post_signal(db, live, "High", subject_resource_type="identity")
    with pytest.raises(ResolutionError) as caught:
        resolve(db, live)
    assert caught.value.code == "INVALID_CONTEXT"


def test_the_bundles_signal_setting_bounds_the_age(db, live):
    now = live["clock"].now()
    setting = ContextSetting(
        context_contract_version=V2,
        source_kind="signal",
        max_age_seconds=60,
        permitted_writers=("signal_mappings",),
    )
    post_signal(db, live, "High", observed_at=now - timedelta(seconds=100))
    with pytest.raises(ResolutionError) as caught:
        resolve(db, live, settings=(setting,))
    assert caught.value.code == "INVALID_CONTEXT"
    post_signal(db, live, "High", observed_at=now - timedelta(seconds=30))
    fact = resolve(db, live, settings=(setting,)).fact("compromise")
    assert fact.valid_until == fact.observed_at + timedelta(seconds=60)


def test_the_test_only_path_fails_closed_for_v2(db, live):
    post_signal(db, live, "High")
    with pytest.raises(ResolutionError) as caught:
        resolve_test_path(db, live)
    assert caught.value.code == "INVALID_CONTEXT"


def test_a_source_scoped_to_another_agent_does_not_apply(db, live, admin_engine, tmp_path):
    from test_execution import provision_identity

    other = provision_identity(
        admin_engine, db, live["identity"].tenant_id, "AGENT", live["clock"].now()
    )
    stranger, token = register(
        admin_engine, live, tmp_path / "stranger", principals=(other.principal_id,)
    )
    bundle = signal_bundle(live["identity"].tenant_id, live["account"], (stranger,))
    post_signal(db, {**live, "source": stranger, "token": token}, "High")
    with pytest.raises(ResolutionError):
        resolve(db, live, scope=SignalScope(bundle.signal_mappings, live["space"]))


def test_a_source_of_another_space_does_not_apply_unless_offered(db, live, admin_engine, tmp_path):
    tenant = live["identity"].tenant_id
    other_space = uuid4()
    with admin_engine.begin() as conn:
        fenced(conn, tenant)
        conn.execute(
            text(
                "INSERT INTO execbound.spaces (tenant_id, space_id, name, created_at, created_by) "
                "VALUES (:t, :s, 'Customer B', now(), :p)"
            ),
            {"t": tenant, "s": other_space, "p": live["admin"].principal_id},
        )
    foreign, token = register(admin_engine, live, tmp_path / "foreign", space=other_space)
    bundle = signal_bundle(tenant, live["account"], (foreign,))
    post_signal(db, {**live, "source": foreign, "token": token}, "High")
    with pytest.raises(ResolutionError):
        resolve(db, live, scope=SignalScope(bundle.signal_mappings, live["space"]))
    with admin_engine.begin() as conn:
        fenced(conn, tenant)
        conn.execute(
            text(
                "UPDATE execbound.signal_sources SET offered_tenant_wide = true "
                "WHERE source_id = :s"
            ),
            {"s": foreign},
        )
    fact = resolve(db, live, scope=SignalScope(bundle.signal_mappings, live["space"])).fact(
        "compromise"
    )
    assert fact.value == "compromised"


def test_a_record_for_another_resource_never_reaches_the_fact(db, live):
    # The other host's record is newer and more restrictive: were it read, it would win.
    now = live["clock"].now()
    post_signal(db, live, "None", observed_at=now - timedelta(seconds=10), event_id="device-01:a")
    post_signal(db, live, "High", observed_at=now, subject_provider_id="device-02")
    fact = resolve(db, live).fact("compromise")
    assert fact.value == "no_detection"
    assert [record.source_event_id for record in fact.signal.records] == ["device-01:a"]


def test_the_statement_reads_only_this_capability_resource_and_admitted_source(
    db, live, admin_engine, monkeypatch, tmp_path
):
    """The rows handed to resolution are already filtered by the statement itself.

    A row for another capability cannot pass `signal_admit`, so the owner writes one
    directly: same source, same host, newer. A source the bundle does not admit reports the
    same host too. The Python re-check would skip both, which is why this test looks at what
    the statement returned rather than at the fact.
    """
    now = live["clock"].now()
    tenant = live["identity"].tenant_id
    post_signal(db, live, "None", observed_at=now - timedelta(seconds=10), event_id="device-01:a")
    post_signal(db, live, "High", observed_at=now, subject_provider_id="device-02")
    outsider, token = register(admin_engine, live, tmp_path / "outsider")
    post_signal(db, {**live, "source": outsider, "token": token}, "High", observed_at=now)
    with admin_engine.begin() as conn:
        fenced(conn, tenant)
        conn.execute(
            text(
                "INSERT INTO execbound.security_signals (tenant_id, source_id, source_event_id, "
                "record_digest, registration_version, producer_name, producer_version, "
                "capability, verdict, confidence, subject_kind, subject_account_id, "
                "subject_provider, subject_resource_type, subject_provider_id, observed_at, "
                "received_at) VALUES (:t, :s, 'device-01:other', :d, 1, :name, :version, "
                "'resource_other.v1', 'High', 1000, 'resource', :a, 'mock_crowdstrike', "
                "'endpoint', 'device-01', :now, :now)"
            ),
            {
                "t": tenant,
                "s": live["source"],
                "d": "b" * 64,
                "name": PRODUCER,
                "version": VERSION,
                "a": live["account"],
                "now": now,
            },
        )
    read = []
    original = snapshot.resolve_facts

    def spy(*args, **kwargs):
        read.append(kwargs["signal_rows"])
        return original(*args, **kwargs)

    monkeypatch.setattr(snapshot, "resolve_facts", spy)
    assert resolve(db, live).fact("compromise").value == "no_detection"
    [rows] = read
    assert [(row["capability"], row["source_event_id"]) for row in rows] == [
        (CAPABILITY, "device-01:a")
    ]
    # The statement also hands over the principal scope it filtered on, for the row check.
    assert [row["in_scope"] for row in rows] == [True]


def rows_read(monkeypatch):
    """What the statement hands `resolve_facts`, one list per resolution."""
    read = []
    original = snapshot.resolve_facts

    def spy(*args, **kwargs):
        read.append([row["source_event_id"] for row in kwargs["signal_rows"]])
        return original(*args, **kwargs)

    monkeypatch.setattr(snapshot, "resolve_facts", spy)
    return read


def test_the_statement_reads_back_to_the_contracts_ceiling_and_no_further(db, live, monkeypatch):
    """3,600 seconds today, `endpoint-isolation.v2`'s signal ceiling: a record observed exactly
    that long before the decision is not read. It would be refused as stale anyway; the bound
    only keeps the statement from reading what can never apply."""
    t0 = live["clock"].now()
    post_signal(db, live, "High", observed_at=t0 - timedelta(seconds=3599), event_id="device-01:o")
    read = rows_read(monkeypatch)
    with pytest.raises(ResolutionError):
        resolve(db, live)
    live["clock"].value = t0 + timedelta(seconds=1)
    with pytest.raises(ResolutionError):
        resolve(db, live)
    assert read == [["device-01:o"], []]


def test_the_statement_takes_its_bound_from_the_contract(db, live, monkeypatch):
    """A contract whose signal ceiling is shorter bounds the read with it, not with 3,600."""
    shorter = replace(
        ENDPOINT_ISOLATION_V2,
        sources=MappingProxyType(
            {**ENDPOINT_ISOLATION_V2.sources, "signal": SourceDefaults(300, 1000, (SIGNAL_WRITER,))}
        ),
    )
    catalog = Catalog((ENDPOINT_ISOLATION_V1, shorter))
    now = live["clock"].now()
    post_signal(db, live, "High", observed_at=now - timedelta(seconds=1200), event_id="device-01:o")
    read = rows_read(monkeypatch)
    for chosen in (PRODUCTION_CATALOG, catalog):
        with (
            pytest.raises(ResolutionError),
            db.transaction(live["identity"].tenant_id, snapshot=True) as conn,
        ):
            resolve_snapshot(
                conn,
                live["identity"],
                request(live),
                live["clock"],
                catalog=chosen,
                signals=scope_of(live),
            )
    assert read == [["device-01:o"], []]


def test_the_reader_bound_is_the_contracts_signal_ceiling():
    scope = unit_scope()
    assert reader_arguments(ENDPOINT_ISOLATION_V2, scope)[2] == 3600
    # A contract with no signal fact reads nothing, from any time.
    assert reader_arguments(ENDPOINT_ISOLATION_V1, scope) == ([], [], 0)


def test_the_statement_never_reads_a_source_of_another_space(
    db, live, admin_engine, monkeypatch, tmp_path
):
    """The space predicate on its own, beneath `signal_fact`'s second check."""
    tenant = live["identity"].tenant_id
    other_space = uuid4()
    with admin_engine.begin() as conn:
        fenced(conn, tenant)
        conn.execute(
            text(
                "INSERT INTO execbound.spaces (tenant_id, space_id, name, created_at, created_by) "
                "VALUES (:t, :s, 'Customer B', now(), :p)"
            ),
            {"t": tenant, "s": other_space, "p": live["admin"].principal_id},
        )
    foreign, token = register(admin_engine, live, tmp_path / "foreign", space=other_space)
    both = signal_bundle(tenant, live["account"], (live["source"], foreign))
    post_signal(db, live, "Low", event_id="device-01:home")
    post_signal(db, {**live, "source": foreign, "token": token}, "High")
    read = []
    original = snapshot.resolve_facts

    def spy(*args, **kwargs):
        read.append(kwargs["signal_rows"])
        return original(*args, **kwargs)

    monkeypatch.setattr(snapshot, "resolve_facts", spy)
    with pytest.raises(ResolutionError):
        resolve(db, live, scope=SignalScope(both.signal_mappings, live["space"]))
    [rows] = read
    assert [row["source_event_id"] for row in rows] == ["device-01:home"]


def test_an_agent_forwarded_source_is_refused_in_a_required_mapping(
    db, live, admin_engine, tmp_path
):
    forwarded, token = register(
        admin_engine, live, tmp_path / "forwarded", input_path="agent_forwarded"
    )
    bundle = signal_bundle(live["identity"].tenant_id, live["account"], (forwarded,))
    post_signal(db, {**live, "source": forwarded, "token": token}, "High")
    with pytest.raises(ResolutionError) as caught:
        resolve(db, live, scope=SignalScope(bundle.signal_mappings, live["space"]))
    assert caught.value.code == "INVALID_CONTEXT"


CLEAN = (SignalThreshold(verdict="None", value="clean"), *MDE_THRESHOLDS[1:])


def test_clean_needs_a_source_that_attests_liveness(db, live, admin_engine, tmp_path):
    tenant = live["identity"].tenant_id
    quiet = signal_bundle(tenant, live["account"], (live["source"],), thresholds=CLEAN)
    post_signal(db, live, "None")
    with pytest.raises(ResolutionError) as caught:
        resolve(db, live, scope=SignalScope(quiet.signal_mappings, live["space"]))
    assert caught.value.code == "INVALID_CONTEXT"
    watching, token = register(admin_engine, live, tmp_path / "watching", attests_liveness=True)
    alive = signal_bundle(tenant, live["account"], (watching,), thresholds=CLEAN)
    post_signal(db, {**live, "source": watching, "token": token}, "None")
    fact = resolve(db, live, scope=SignalScope(alive.signal_mappings, live["space"])).fact(
        "compromise"
    )
    assert fact.value == "clean"
    assert [record.attests_liveness for record in fact.signal.records] == [True]


def test_a_record_observed_after_the_decision_refuses(db, live):
    # The source's newest word replaced its earlier one. Skipping it would decide on the
    # replaced verdict, so it refuses rather than falling back.
    now = live["clock"].now()
    post_signal(db, live, "High", observed_at=now - timedelta(seconds=10))
    post_signal(db, live, "None", observed_at=now + timedelta(seconds=30))
    with pytest.raises(ResolutionError) as caught:
        resolve(db, live)
    assert caught.value.code == "INVALID_CONTEXT"


def test_a_record_received_after_the_decision_refuses(db, live):
    # The intake's clock ran 50 ms ahead of the decision's. Evaluation refuses a record received
    # after the decision, so resolution must too, rather than freeze a plan that is then denied.
    now = live["clock"].now()
    live["clock"].value = now + timedelta(milliseconds=50)
    post_signal(db, live, "High", observed_at=now - timedelta(seconds=10))
    live["clock"].value = now
    with pytest.raises(ResolutionError) as caught:
        resolve(db, live)
    assert caught.value.code == "INVALID_CONTEXT"


def test_a_group_scoped_source_applies_only_to_its_members(db, live, admin_engine, tmp_path):
    from test_execution import provision_identity

    tenant, group, elsewhere = live["identity"].tenant_id, uuid4(), uuid4()
    other = provision_identity(admin_engine, db, tenant, "AGENT", live["clock"].now())
    member = text(
        "INSERT INTO execbound.principal_group_members "
        "(tenant_id, group_id, principal_id, assigned_at) VALUES (:t, :g, :p, now())"
    )
    with admin_engine.begin() as conn:
        fenced(conn, tenant)
        for name, created in (("Responders", group), ("Elsewhere", elsewhere)):
            conn.execute(
                text(
                    "INSERT INTO execbound.principal_groups (tenant_id, group_id, name, "
                    "created_at) VALUES (:t, :g, :n, now())"
                ),
                {"t": tenant, "g": created, "n": name},
            )
        # Another agent is in the source's group, and this agent is in another group: neither
        # membership is this agent's in this group.
        conn.execute(member, {"t": tenant, "g": group, "p": other.principal_id})
        conn.execute(member, {"t": tenant, "g": elsewhere, "p": live["identity"].principal_id})
    grouped, token = register(admin_engine, live, tmp_path / "grouped", principals=(), group=group)
    bundle = signal_bundle(tenant, live["account"], (grouped,))
    post_signal(db, {**live, "source": grouped, "token": token}, "High")
    scope = SignalScope(bundle.signal_mappings, live["space"])
    with pytest.raises(ResolutionError):
        resolve(db, live, scope=scope)
    with admin_engine.begin() as conn:
        fenced(conn, tenant)
        conn.execute(member, {"t": tenant, "g": group, "p": live["identity"].principal_id})
    assert resolve(db, live, scope=scope).fact("compromise").value == "compromised"


# `signal_fact` re-checks each row the statement read. Some of those checks cannot be reached
# through the statement (a revoked source is always inactive, a stale record is refused again
# by the plan's own expiry, and a foreign space, host or principal scope is never read), so
# they are held here, row by row, against a baseline that resolves.
SOURCE = uuid4()
SPACE = uuid4()
COMPROMISE = ENDPOINT_ISOLATION_V2.fact("compromise")


def unit_scope(thresholds=MDE_THRESHOLDS):
    entry = SignalMapping(
        context_contract_version=V2,
        capability=CAPABILITY,
        admitted_sources=(SOURCE,),
        thresholds=thresholds,
    )
    return SignalScope((entry,), SPACE)


def unit_row(now, **changes):
    row = {
        "source_id": str(SOURCE),
        "source_event_id": "device-01:1",
        "record_digest": "a" * 64,
        "registration_version": 1,
        "producer_name": PRODUCER,
        "producer_version": VERSION,
        "capability": CAPABILITY,
        "verdict": "High",
        "confidence": 1000,
        "observed_at": (now - timedelta(seconds=10)).isoformat(),
        "received_at": (now - timedelta(seconds=9)).isoformat(),
        "expires_at": None,
        "source_active": True,
        "source_revoked_at": None,
        "input_path": "independent",
        "attests_liveness": False,
        "space_id": str(SPACE),
        "offered_tenant_wide": False,
        "subject_provider_id": "device-01",
        "in_scope": True,
    }
    row.update(changes)
    return row


def unit_fact(rows, now, scope=None):
    return signal_fact(
        COMPROMISE,
        ENDPOINT_ISOLATION_V2,
        None,
        scope or unit_scope(),
        rows,
        provider_id="device-01",
        now=now,
    )


def test_the_unit_baseline_resolves():
    now = datetime.now(UTC)
    fact = unit_fact([unit_row(now)], now)
    assert (fact.value, fact.source_id) == ("compromised", SOURCE)


def test_a_row_of_another_capability_or_source_is_skipped():
    now = datetime.now(UTC)
    rows = [
        unit_row(now),
        unit_row(now, capability="resource_other.v1", source_event_id="device-01:2"),
        unit_row(now, source_id=str(uuid4()), verdict="None"),
    ]
    fact = unit_fact(rows, now)
    assert [record.source_event_id for record in fact.signal.records] == ["device-01:1"]


@pytest.mark.parametrize(
    "change",
    [
        {"source_active": False},
        {"source_revoked_at": "2026-09-29T00:00:00+00:00"},
        {"input_path": "agent_forwarded"},
        {"verdict": "Critical"},
        {"observed_at": "FUTURE"},
        {"observed_at": "STALE"},
        {"observed_at": "AT_MAX_AGE"},
        {"expires_at": "EXPIRED"},
        {"space_id": "ELSEWHERE"},
        {"subject_provider_id": "device-02"},
        {"in_scope": False},
        {"in_scope": None},
    ],
    ids=lambda change: next(iter(change)) + "=" + str(next(iter(change.values()))),
)
def test_each_row_check_refuses_on_its_own(change):
    now = datetime.now(UTC)
    moments = {
        "FUTURE": (now + timedelta(seconds=5)).isoformat(),
        "STALE": (now - timedelta(seconds=301)).isoformat(),
        "AT_MAX_AGE": (now - timedelta(seconds=300)).isoformat(),
        "EXPIRED": now.isoformat(),
        "ELSEWHERE": str(uuid4()),
    }
    changed = {key: moments.get(value, value) for key, value in change.items()}
    with pytest.raises(ResolutionError) as caught:
        unit_fact([unit_row(now, **changed)], now)
    assert caught.value.code == "INVALID_CONTEXT"


def test_clean_without_liveness_refuses_on_its_own():
    now = datetime.now(UTC)
    scope = unit_scope(CLEAN)
    with pytest.raises(ResolutionError):
        unit_fact([unit_row(now, verdict="None")], now, scope)
    fact = unit_fact([unit_row(now, verdict="None", attests_liveness=True)], now, scope)
    assert fact.value == "clean"
    assert [record.attests_liveness for record in fact.signal.records] == [True]


def test_an_offered_source_of_another_space_passes_the_second_check():
    now = datetime.now(UTC)
    row = unit_row(now, space_id=str(uuid4()), offered_tenant_wide=True)
    assert unit_fact([row], now).value == "compromised"
