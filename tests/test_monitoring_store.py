# SPDX-License-Identifier: AGPL-3.0-only
"""Real PostgreSQL proofs for the separate, non-authorizing observation domain."""

import importlib
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from threading import Barrier, Event
from uuid import uuid4

import pytest
from pydantic import ValidationError
from sqlalchemy import event as sa_event
from sqlalchemy import text

from execbound.identity import AuthenticationFailed, authenticate
from execbound.surfaces import sessions


class FixedClock:
    def __init__(self, value):
        self.value = value

    def now(self):
        return self.value


@pytest.fixture
def api():
    return (
        importlib.import_module("execbound.monitoring.models"),
        importlib.import_module("execbound.monitoring.store"),
    )


@pytest.fixture
def admins(db, admin_engine, seeded):
    with admin_engine.begin() as conn:
        conn.execute(text("UPDATE execbound.principals SET kind='ADMIN', space_id = NULL"))
    return [authenticate(db, token) for token in seeded["tokens"]]


@pytest.fixture
def setup_monitor(api, db, admins):
    models, store = api
    clock = FixedClock(datetime.now(UTC))
    source = store.create_source(
        db,
        admins[0],
        label="Synthetic story",
        story_id="story-1",
        expires_at=clock.now() + timedelta(hours=2),
        clock=clock,
    )
    grant = sessions.issue_session(db, admins[0], clock=clock)
    session = sessions.load_session(db, grant.token, clock=clock)
    return models, store, clock, source, session


def observation(models, clock, **changes):
    data = {
        "event_id": "event-1",
        "story_id": "story-1",
        "occurred_at": clock.now(),
        "kind": "tool_result",
        "action": "identity.disable",
        "target_ref": "user-1",
        "outcome": "success",
    }
    data.update(changes)
    return models.ObservationEvent.model_validate(data)


@pytest.mark.parametrize(
    "changes",
    [
        {"version": True},
        {"version": 1.0},
        {"version": "1"},
        {"version": 2},
        {"tenant_id": str(uuid4())},
        {"metadata": {"secret": "test"}},
        {"event_id": ""},
        {"event_id": "x" * 97},
        {"story_id": "story/escape"},
        {"action": "a" * 65},
        {"target_ref": "https://external.example"},
        {"outcome": "allowed"},
        {"action": None},
        {"outcome": None},
        {"occurred_at": datetime(2026, 9, 14)},
        {"kind": "heartbeat"},
    ],
)
def test_strict_event_envelope_rejects_untrusted_shapes(api, changes):
    models, _ = api
    with pytest.raises(ValidationError):
        observation(models, FixedClock(datetime.now(UTC)), **changes)


def test_time_normalization_and_unknown_semantics(api):
    models, _ = api
    value = models.ObservationEvent.model_validate_json(
        '{"event_id":"e","story_id":"s","occurred_at":"2026-09-14T10:00:00-04:00",'
        '"kind":"tool_result","action":"unmapped.action","outcome":"unknown"}'
    )
    assert value.occurred_at == datetime(2026, 9, 14, 14, tzinfo=UTC)
    assert value.occurred_at.tzinfo is UTC


def test_source_binding_secrets_and_protected_state_unchanged(db, setup_monitor, admins):
    models, store, clock, source, session = setup_monitor
    with db.transaction(source.tenant_id) as conn:
        before = conn.execute(text("SELECT kind,event_hash FROM execbound.audit_events")).all()
    assert source.token.startswith(f"mo1.{source.tenant_id}.{source.source_id}.")
    assert source.token not in repr(source)
    accepted = store.ingest(db, source.token, observation(models, clock), clock=clock)
    assert accepted["duplicate"] is False
    with pytest.raises(AuthenticationFailed):
        authenticate(db, source.token)
    assert store.evaluate_pending(db, admins[0], clock=clock) == 1
    state = store.snapshot(db, session, clock=clock)
    assert set(state) == {
        "sources",
        "observations",
        "findings",
        "counts",
        "deliveries",
        "profile",
        "connections",
        "inventory",
        "coverage",
        # Who acknowledged each finding, by kind, label and number (#678): no secret.
        "acknowledgers",
        # Who asked for each waiting collection, the same way (#678).
        "requesters",
    }
    assert len(state["findings"]) == len(state["deliveries"]) == 1
    assert state["observations"][0]["evaluation_result"] == "MATCH"
    assert "token_hash" not in repr(state) and "lease_token" not in repr(state)
    assert source.token not in repr(state)
    with db.transaction(source.tenant_id) as conn:
        assert (
            conn.execute(text("SELECT kind,event_hash FROM execbound.audit_events")).all() == before
        )
        for table in ("executions", "execution_impact", "execution_events", "approvals"):
            assert conn.execute(text(f"SELECT count(*) FROM execbound.{table}")).scalar_one() == 0


def test_findings_show_their_exact_source_observation_without_cross_tenant_rows(
    db,
    setup_monitor,
    admins,
):
    models, store, clock, source, session = setup_monitor
    second = store.create_source(
        db,
        admins[0],
        label="Second story",
        story_id="story-2",
        expires_at=clock.now() + timedelta(hours=1),
        clock=clock,
    )
    foreign = store.create_source(
        db,
        admins[1],
        label="Foreign story",
        story_id="story-3",
        expires_at=clock.now() + timedelta(hours=1),
        clock=clock,
    )
    expected = {}
    for grant, story, action, target, outcome in (
        (source, "story-1", "identity.disable", "user-1", "success"),
        (second, "story-2", "endpoint.isolate", "endpoint-2", "error"),
        (foreign, "story-3", "identity.enable", "foreign-user", "unknown"),
    ):
        receipt = store.ingest(
            db,
            grant.token,
            observation(
                models, clock, story_id=story, action=action, target_ref=target, outcome=outcome
            ),
            clock=clock,
        )
        if grant.tenant_id == source.tenant_id:
            expected[str(grant.source_id)] = {
                "observation_id": receipt["observation_id"],
                "story_id": story,
                "action": action,
                "target_ref": target,
                "outcome": outcome,
            }
    for admin in admins:
        store.evaluate_pending(db, admin, clock=clock)
    findings = store.snapshot(db, session, clock=clock)["findings"]
    assert len(findings) == 2
    assert {
        str(finding["source_id"]): {
            "observation_id": str(finding["observation_id"]),
            **{key: finding[key] for key in ("story_id", "action", "target_ref", "outcome")},
        }
        for finding in findings
    } == expected


@pytest.mark.parametrize(
    "change", ["tenant", "source", "secret", "prefix", "expired", "revoked", "inactive"]
)
def test_source_authority_is_current_and_selector_tampering_is_safe(
    db,
    setup_monitor,
    seeded,
    admin_engine,
    change,
):
    models, store, clock, source, _ = setup_monitor
    token = source.token
    parts = token.split(".")
    if change in {"tenant", "source", "secret", "prefix"}:
        index = {"tenant": 1, "source": 2, "secret": 3, "prefix": 0}[change]
        parts[index] = {
            "tenant": str(seeded["tenants"][1]),
            "source": str(uuid4()),
            "secret": "a" * 43,
            "prefix": "eb1",
        }[change]
        token = ".".join(parts)
    else:
        assignment = {
            "expired": "expires_at=created_at + interval '1 second'",
            "revoked": "revoked_at=created_at",
            "inactive": "active=false",
        }[change]
        with admin_engine.begin() as conn:
            conn.execute(text(f"UPDATE execbound.monitor_sources SET {assignment}"))
        clock.value += timedelta(seconds=2)
    with pytest.raises(models.MonitorError) as exc:
        store.ingest(db, token, observation(models, clock), clock=clock)
    assert exc.value.code == "INVALID_SOURCE"
    assert token not in str(exc.value)


def test_body_story_cannot_switch_source_and_existing_roles_cannot_ingest(
    db,
    setup_monitor,
    seeded,
):
    models, store, clock, source, session = setup_monitor
    with pytest.raises(models.MonitorError, match="Monitoring unavailable"):
        store.ingest(db, source.token, observation(models, clock, story_id="story-2"), clock=clock)
    for token in (seeded["tokens"][0], "hs1.bad.bad.bad", None, 42, "x" * 1000):
        with pytest.raises(models.MonitorError) as exc:
            store.ingest(db, token, observation(models, clock), clock=clock)
        assert exc.value.code == "INVALID_SOURCE"
    assert not store.snapshot(db, session, clock=clock)["observations"]


def test_same_event_is_idempotent_conflict_retains_original_and_one_integrity_finding(
    db,
    setup_monitor,
    admins,
):
    models, store, clock, source, session = setup_monitor
    original = observation(models, clock)
    first = store.ingest(db, source.token, original, clock=clock)
    duplicate = store.ingest(db, source.token, original, clock=clock)
    assert duplicate == {"observation_id": first["observation_id"], "duplicate": True}
    for _ in range(2):
        with pytest.raises(models.MonitorError) as exc:
            store.ingest(db, source.token, observation(models, clock, outcome="error"), clock=clock)
        assert exc.value.code == "EVENT_CONFLICT"
    store.evaluate_pending(db, admins[0], clock=clock)
    state = store.snapshot(db, session, clock=clock)
    assert len(state["observations"]) == 1
    assert state["observations"][0]["outcome"] == "success"
    assert state["observations"][0]["integrity_conflict_at"] == clock.now()
    assert {f["rule_version"] for f in state["findings"]} == {
        "source-event-integrity.v1",
        "sensitive-action.v2",
    }
    assert len(state["deliveries"]) == 2
    assert store.evaluate_pending(db, admins[0], clock=clock) == 0


def test_concurrent_duplicates_have_one_receipt_and_one_outbox(db, setup_monitor, admins):
    models, store, clock, source, session = setup_monitor
    gate = Barrier(4)

    def submit(_):
        gate.wait(timeout=5)
        return store.ingest(db, source.token, observation(models, clock), clock=clock)

    with ThreadPoolExecutor(max_workers=4) as pool:
        results = list(pool.map(submit, range(4)))
    assert sum(not r["duplicate"] for r in results) == 1
    with ThreadPoolExecutor(max_workers=2) as pool:
        counts = list(
            pool.map(lambda _: store.evaluate_pending(db, admins[0], clock=clock), range(2))
        )
    assert sum(counts) == 1
    assert len(store.snapshot(db, session, clock=clock)["deliveries"]) == 1


@pytest.mark.parametrize(
    "action",
    ["endpoint.isolate", "identity.disable", "identity.enable", "identity.revoke_sessions"],
)
def test_sensitive_error_is_still_an_observed_attempt(db, setup_monitor, admins, action):
    models, store, clock, source, session = setup_monitor
    store.ingest(
        db, source.token, observation(models, clock, action=action, outcome="error"), clock=clock
    )
    store.evaluate_pending(db, admins[0], clock=clock)
    assert (
        store.snapshot(db, session, clock=clock)["observations"][0]["evaluation_result"] == "MATCH"
    )


def test_unknown_action_and_heartbeat_do_not_create_false_findings(db, setup_monitor, admins):
    models, store, clock, source, session = setup_monitor
    store.ingest(db, source.token, observation(models, clock, action="future.action"), clock=clock)
    store.ingest(
        db,
        source.token,
        observation(
            models,
            clock,
            event_id="heartbeat",
            kind="heartbeat",
            action=None,
            target_ref=None,
            outcome=None,
        ),
        clock=clock,
    )
    assert store.evaluate_pending(db, admins[0], clock=clock) == 1
    state = store.snapshot(db, session, clock=clock)
    assert {o["evaluation_result"] for o in state["observations"]} == {
        "INSUFFICIENT_EVIDENCE",
    }
    assert state["findings"] == state["deliveries"] == []
    assert state["sources"][0]["last_heartbeat_at"] == clock.now()


def heartbeat(models, clock, **changes):
    return observation(
        models,
        clock,
        kind="heartbeat",
        action=None,
        target_ref=None,
        outcome=None,
        **changes,
    )


def test_heartbeats_update_freshness_without_retained_events(db, setup_monitor, admins):
    models, store, clock, source, session = setup_monitor
    beat = heartbeat(models, clock)
    for _ in range(3):
        clock.value += timedelta(seconds=1)
        assert store.ingest(db, source.token, beat, clock=clock) == {
            "observation_id": None,
            "duplicate": False,
        }
    state = store.snapshot(db, session, clock=clock)
    assert state["observations"] == state["findings"] == state["deliveries"] == []
    assert state["sources"][0]["accepted_count"] == 0
    assert state["sources"][0]["last_event_at"] is None
    assert state["sources"][0]["last_heartbeat_at"] == clock.now()
    assert store.evaluate_pending(db, admins[0], clock=clock) == 0
    assert store.evaluate_health(db, admins[0], clock=clock) == 1
    assert store.snapshot(db, session, clock=clock)["sources"][0]["health_state"] == "REPORTING"


def test_full_source_can_heartbeat_and_rotate_without_resetting_its_event_cap(
    db, setup_monitor, admins, monkeypatch
):
    models, store, clock, source, session = setup_monitor
    monkeypatch.setattr(store, "MAX_SOURCE_EVENTS", 1)
    store.ingest(db, source.token, observation(models, clock), clock=clock)
    clock.value += timedelta(seconds=1)
    store.ingest(db, source.token, heartbeat(models, clock, event_id="beat"), clock=clock)
    rotated = store.rotate_source(
        db,
        admins[0],
        source.source_id,
        expires_at=clock.now() + timedelta(days=1),
        grace_seconds=0,
        clock=clock,
    )
    store.ingest(db, rotated.token, heartbeat(models, clock, event_id="new-beat"), clock=clock)
    with pytest.raises(models.MonitorError) as refused:
        store.ingest(db, rotated.token, observation(models, clock, event_id="second"), clock=clock)
    assert refused.value.code == "SOURCE_CAPACITY"
    with pytest.raises(models.MonitorError) as refused:
        store.ingest(db, source.token, heartbeat(models, clock), clock=clock)
    assert refused.value.code == "INVALID_SOURCE"
    state = store.snapshot(db, session, clock=clock)
    assert len(state["observations"]) == state["sources"][0]["accepted_count"] == 1
    assert state["sources"][0]["last_event_at"] == clock.now() - timedelta(seconds=1)
    assert state["sources"][0]["last_heartbeat_at"] == clock.now()


def test_heartbeats_share_the_source_rate_limit(db, setup_monitor, monkeypatch):
    models, store, clock, source, session = setup_monitor
    monkeypatch.setattr(store, "MAX_EVENTS_PER_MINUTE", 2)
    beat = heartbeat(models, clock)
    store.ingest(db, source.token, beat, clock=clock)
    store.ingest(db, source.token, beat, clock=clock)
    clock.value += timedelta(seconds=1)
    with pytest.raises(models.MonitorError) as refused:
        store.ingest(db, source.token, beat, clock=clock)
    assert refused.value.code == "SOURCE_RATE_LIMIT"
    with pytest.raises(models.MonitorError) as refused:
        store.ingest(db, source.token, observation(models, clock), clock=clock)
    assert refused.value.code == "SOURCE_RATE_LIMIT"
    state = store.snapshot(db, session, clock=clock)
    assert not state["observations"]
    assert state["sources"][0]["last_heartbeat_at"] == clock.now() - timedelta(seconds=1)
    clock.value += timedelta(minutes=1)
    store.ingest(db, source.token, beat, clock=clock)


def test_heartbeats_kept_by_an_older_release_remain_counted(db, setup_monitor):
    models, store, clock, source, session = setup_monitor
    legacy = uuid4()
    with db.transaction(source.tenant_id) as conn:
        conn.execute(
            text("""
                INSERT INTO execbound.monitor_observations
                (tenant_id, observation_id, source_id, event_id, story_id, version,
                 occurred_at, received_at, kind, content_hash, rule_version, space_id)
                SELECT tenant_id, :o, source_id, 'legacy-beat', story_id, 1,
                       :now, :now, 'heartbeat', :hash, :rule, space_id
                FROM execbound.monitor_sources WHERE source_id=:s
            """),
            {
                "o": legacy,
                "s": source.source_id,
                "now": clock.now(),
                "hash": "0" * 64,
                "rule": store.RULE_VERSION,
            },
        )
        conn.execute(text("UPDATE execbound.monitor_sources SET accepted_count=1"))
    clock.value += timedelta(seconds=1)
    store.ingest(db, source.token, heartbeat(models, clock, event_id="legacy-beat"), clock=clock)
    state = store.snapshot(db, session, clock=clock)
    assert [row["observation_id"] for row in state["observations"]] == [legacy]
    assert state["sources"][0]["accepted_count"] == 1
    assert state["sources"][0]["last_heartbeat_at"] == clock.now()
    assert state["findings"] == []


@pytest.mark.parametrize("refusal", ["story", "expired", "revoked", "inactive"])
def test_refused_heartbeat_cannot_refresh_a_source(
    db, setup_monitor, admins, admin_engine, refusal
):
    models, store, clock, source, _ = setup_monitor
    beat = heartbeat(models, clock, story_id="foreign" if refusal == "story" else "story-1")
    if refusal == "expired":
        clock.value += timedelta(hours=3)
    elif refusal == "revoked":
        store.revoke_source(db, admins[0], source.source_id, clock=clock)
    elif refusal == "inactive":
        with admin_engine.begin() as conn:
            conn.execute(
                text("UPDATE execbound.tenants SET active=false WHERE tenant_id=:t"),
                {"t": source.tenant_id},
            )
    with pytest.raises(models.MonitorError) as refused:
        store.ingest(db, source.token, beat, clock=clock)
    assert refused.value.code == "INVALID_SOURCE"
    with db.transaction(source.tenant_id) as conn:
        assert conn.execute(
            text("SELECT last_heartbeat_at, accepted_count FROM execbound.monitor_sources")
        ).one() == (None, 0)


def test_failed_evaluation_rolls_back_completion_finding_and_outbox(db, setup_monitor, admins):
    models, store, clock, source, session = setup_monitor
    store.ingest(db, source.token, observation(models, clock), clock=clock)

    def fail_outbox(conn, cursor, statement, parameters, context, executemany):
        if "INSERT INTO execbound.monitor_deliveries" in statement:
            raise RuntimeError("injected crash")

    sa_event.listen(db.engine, "before_cursor_execute", fail_outbox)
    try:
        with pytest.raises(RuntimeError, match="injected crash"):
            store.evaluate_pending(db, admins[0], clock=clock)
    finally:
        sa_event.remove(db.engine, "before_cursor_execute", fail_outbox)
    state = store.snapshot(db, session, clock=clock)
    assert state["observations"][0]["evaluation_state"] == "PENDING"
    assert not state["findings"] and not state["deliveries"]
    assert store.evaluate_pending(db, admins[0], clock=clock) == 1


def test_failed_receipt_has_no_hidden_pending_or_source_progress(db, setup_monitor):
    models, store, clock, source, session = setup_monitor

    def fail_receipt(conn, cursor, statement, parameters, context, executemany):
        if "INSERT INTO execbound.monitor_observations" in statement:
            raise RuntimeError("injected crash")

    sa_event.listen(db.engine, "before_cursor_execute", fail_receipt)
    try:
        with pytest.raises(RuntimeError, match="injected crash"):
            store.ingest(db, source.token, observation(models, clock), clock=clock)
    finally:
        sa_event.remove(db.engine, "before_cursor_execute", fail_receipt)
    state = store.snapshot(db, session, clock=clock)
    assert not state["observations"]
    assert state["sources"][0]["last_event_at"] is None
    assert (
        store.ingest(db, source.token, observation(models, clock), clock=clock)["duplicate"]
        is False
    )


def test_admin_reads_ack_and_source_events_stay_tenant_scoped(db, setup_monitor, admins):
    models, store, clock, source, session = setup_monitor
    other = store.create_source(
        db,
        admins[1],
        label="Other",
        story_id="story-1",
        expires_at=clock.now() + timedelta(hours=1),
        clock=clock,
    )
    store.ingest(db, source.token, observation(models, clock), clock=clock)
    store.ingest(db, other.token, observation(models, clock), clock=clock)
    store.evaluate_pending(db, admins[0], clock=clock)
    state = store.snapshot(db, session, clock=clock)
    assert len(state["sources"]) == len(state["observations"]) == len(state["findings"]) == 1
    finding_id = state["findings"][0]["finding_id"]
    store.acknowledge(db, session, finding_id, clock=clock)
    store.acknowledge(db, session, finding_id, clock=clock)
    assert (
        store.snapshot(db, session, clock=clock)["findings"][0]["acknowledged_by"]
        == admins[0].principal_id
    )
    grant = sessions.issue_session(db, admins[1], clock=clock)
    other_session = sessions.load_session(db, grant.token, clock=clock)
    with pytest.raises(models.MonitorError) as exc:
        store.acknowledge(db, other_session, finding_id, clock=clock)
    assert exc.value.code == "FINDING_UNAVAILABLE"


@pytest.mark.parametrize("change", ["role", "credential", "principal", "tenant", "session"])
def test_admin_authority_is_rechecked_for_reads_and_ack(db, setup_monitor, admin_engine, change):
    models, store, clock, source, session = setup_monitor
    statements = {
        "role": "UPDATE execbound.principals SET kind='HUMAN_APPROVER', space_id = NULL",
        "credential": "UPDATE execbound.credentials SET revoked_at=now()",
        "principal": "UPDATE execbound.principals SET active=false",
        "tenant": "UPDATE execbound.tenants SET active=false",
        "session": "UPDATE execbound.human_sessions SET revoked_at=now()",
    }
    with admin_engine.begin() as conn:
        conn.execute(text(statements[change]))
    for call in (
        lambda: store.snapshot(db, session, clock=clock),
        lambda: store.acknowledge(db, session, uuid4(), clock=clock),
    ):
        with pytest.raises(models.MonitorError):
            call()


def test_no_approver_scope_inheritance_or_forged_admin_identity(db, api, seeded):
    models, store = api
    agent = authenticate(db, seeded["tokens"][0])
    for identity in (agent, replace(agent, kind="ADMIN"), replace(agent, kind="HUMAN_APPROVER")):
        with pytest.raises(models.MonitorError):
            store.create_source(db, identity, label="x", story_id="s", expires_at=agent.expires_at)
        with pytest.raises(models.MonitorError):
            store.evaluate_pending(db, identity)


@pytest.mark.parametrize("limit", [0, -1, True, 501, "5"])
def test_worker_batch_bounds_are_strict(db, setup_monitor, admins, limit):
    models, store, clock, _, _ = setup_monitor
    with pytest.raises(models.MonitorError) as exc:
        store.evaluate_pending(db, admins[0], limit=limit, clock=clock)
    assert exc.value.code == "INVALID_INPUT"


def test_rate_and_storage_caps_report_refusal_without_inventing_observations(
    db,
    setup_monitor,
    monkeypatch,
):
    models, store, clock, source, session = setup_monitor
    monkeypatch.setattr(store, "MAX_EVENTS_PER_MINUTE", 1)
    monkeypatch.setattr(store, "MAX_SOURCE_EVENTS", 2)
    store.ingest(db, source.token, observation(models, clock), clock=clock)
    with pytest.raises(models.MonitorError) as exc:
        store.ingest(db, source.token, observation(models, clock, event_id="e2"), clock=clock)
    assert exc.value.code == "SOURCE_RATE_LIMIT"
    assert (
        store.snapshot(db, session, clock=clock)["sources"][0]["last_refusal_code"]
        == "SOURCE_RATE_LIMIT"
    )
    clock.value += timedelta(minutes=1)
    store.ingest(db, source.token, observation(models, clock, event_id="e2"), clock=clock)
    clock.value += timedelta(minutes=1)
    with pytest.raises(models.MonitorError) as exc:
        store.ingest(db, source.token, observation(models, clock, event_id="e3"), clock=clock)
    assert exc.value.code == "SOURCE_CAPACITY"
    state = store.snapshot(db, session, clock=clock)
    assert len(state["observations"]) == 2
    assert state["sources"][0]["last_refusal_code"] == "SOURCE_CAPACITY"


def test_concurrent_new_events_cannot_oversubscribe_capacity(db, setup_monitor, monkeypatch):
    models, store, clock, source, session = setup_monitor
    monkeypatch.setattr(store, "MAX_SOURCE_EVENTS", 1)
    gate = Barrier(2)

    def submit(number):
        gate.wait(timeout=5)
        try:
            return store.ingest(
                db, source.token, observation(models, clock, event_id=f"e-{number}"), clock=clock
            )
        except models.MonitorError as exc:
            return exc.code

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(submit, range(2)))
    assert sum(isinstance(result, dict) for result in results) == 1
    assert "SOURCE_CAPACITY" in results
    state = store.snapshot(db, session, clock=clock)
    assert len(state["observations"]) == state["sources"][0]["accepted_count"] == 1


def test_waiting_ingress_rechecks_source_revocation_after_lock(db, setup_monitor, admin_engine):
    models, store, clock, source, session = setup_monitor
    reached_lock = Event()

    def observe_lock(conn, cursor, statement, parameters, context, executemany):
        if "SELECT * FROM execbound.monitor_sources" in statement:
            reached_lock.set()

    sa_event.listen(db.engine, "before_cursor_execute", observe_lock)
    try:
        with ThreadPoolExecutor(max_workers=1) as pool:
            with admin_engine.begin() as conn:
                conn.execute(text("UPDATE execbound.monitor_sources SET revoked_at=now()"))
                pending = pool.submit(
                    store.ingest, db, source.token, observation(models, clock), clock=clock
                )
                assert reached_lock.wait(timeout=3)
            with pytest.raises(models.MonitorError) as exc:
                pending.result(timeout=5)
            assert exc.value.code == "INVALID_SOURCE"
    finally:
        sa_event.remove(db.engine, "before_cursor_execute", observe_lock)
    assert not store.snapshot(db, session, clock=clock)["observations"]


def test_authority_revoked_during_evaluation_rolls_back_all_results(
    db,
    setup_monitor,
    admins,
    admin_engine,
):
    models, store, clock, source, session = setup_monitor
    store.ingest(db, source.token, observation(models, clock), clock=clock)

    def revoke_during_insert(conn, cursor, statement, parameters, context, executemany):
        if "INSERT INTO execbound.monitor_deliveries" in statement:
            with admin_engine.begin() as owner:
                owner.execute(text("UPDATE execbound.credentials SET revoked_at=now()"))

    sa_event.listen(db.engine, "before_cursor_execute", revoke_during_insert)
    try:
        with pytest.raises(models.MonitorError) as exc:
            store.evaluate_pending(db, admins[0], clock=clock)
        assert exc.value.code == "INVALID_ADMIN"
    finally:
        sa_event.remove(db.engine, "before_cursor_execute", revoke_during_insert)
    with admin_engine.begin() as conn:
        assert (
            conn.execute(
                text("SELECT evaluation_state FROM execbound.monitor_observations")
            ).scalar_one()
            == "PENDING"
        )
        assert (
            conn.execute(text("SELECT count(*) FROM execbound.monitor_findings")).scalar_one() == 0
        )
        assert (
            conn.execute(text("SELECT count(*) FROM execbound.monitor_deliveries")).scalar_one()
            == 0
        )
