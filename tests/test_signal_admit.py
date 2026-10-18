# SPDX-License-Identifier: AGPL-3.0-only
"""The fenced writer that admits a signal envelope, called as the runtime role: the
credential, the registration's scope, duplicates and conflicts, and the rate and time
bounds (docs/SIGNALS.md)."""

import json
import time
from datetime import timedelta
from threading import Thread
from uuid import uuid4

import pytest
from signal_fixtures import ADMIT, admit_params, admit_raw, insert_source, signal_fields
from sqlalchemy import text
from sqlalchemy.exc import DBAPIError
from test_migration_without_bypass import fenced
from test_resolution import registry as registry
from test_signal_envelope import LONGEST_PRODUCER, bounds

from execbound.signals.envelope import MAX_ENVELOPE_BYTES, parse_signal, record_digest
from execbound.signals.tokens import digest, new_token

# The instant before a boundary: PostgreSQL keeps microseconds, so this is the last one inside.
JUST = timedelta(microseconds=1)
MISMATCH = {"refused": "INVALID_SOURCE", "reason": "MISMATCH"}


@pytest.fixture
def source(registry, admin_engine, seeded):
    now = registry["clock"].now()
    tenant = registry["identity"].tenant_id
    with admin_engine.begin() as conn:
        fenced(conn, tenant)
        source_id, token = insert_source(conn, tenant, registry["identity"].principal_id, now)
    return {**registry, "tenant": tenant, "source": source_id, "token": token, "now": now}


def admit(db, source, **changes):
    fields = signal_fields(source["account"], source["now"], **changes)
    return admit_raw(
        db, source["tenant"], source["source"], source["token"], source["now"], **fields
    )


def health(admin_engine, source):
    with admin_engine.begin() as conn:
        fenced(conn, source["tenant"])
        return (
            conn.execute(
                text(
                    "SELECT rate_count, record_count, conflict_count, rate_refusal_count, "
                    "last_accepted_at, last_refused_at, last_refusal_code "
                    "FROM execbound.signal_sources WHERE source_id = :s"
                ),
                {"s": source["source"]},
            )
            .mappings()
            .one()
        )


def records(admin_engine, source):
    with admin_engine.begin() as conn:
        fenced(conn, source["tenant"])
        return (
            conn.execute(
                text(
                    "SELECT source_event_id, verdict, observed_at, received_at, "
                    "registration_version FROM execbound.security_signals "
                    "WHERE source_id = :s ORDER BY received_at"
                ),
                {"s": source["source"]},
            )
            .mappings()
            .all()
        )


def test_an_accepted_record_is_stored_with_the_intake_clock(db, source, admin_engine):
    # A registration past its first version and an observation older than its receipt, so the
    # stored version and each of the two times is seen to come from its own place.
    with admin_engine.begin() as conn:
        fenced(conn, source["tenant"])
        conn.execute(
            text(
                "UPDATE execbound.signal_sources SET registration_version = 3 WHERE source_id = :s"
            ),
            {"s": source["source"]},
        )
    observed = source["now"] - timedelta(seconds=10)
    result = admit(db, source, observed_at=observed)
    assert (result["accepted"], result["duplicate"], result["registration_version"]) == (
        True,
        False,
        3,
    )
    stored = [
        (row["verdict"], row["registration_version"], row["observed_at"], row["received_at"])
        for row in records(admin_engine, source)
    ]
    assert stored == [("Medium", 3, observed, source["now"])]
    state = health(admin_engine, source)
    assert (state["record_count"], state["last_accepted_at"]) == (1, source["now"])


@pytest.mark.parametrize(
    "tamper,reason",
    [
        ("unknown", "UNKNOWN"),
        ("mismatch", "MISMATCH"),
        ("revoked", "REVOKED"),
        ("inactive", "REVOKED"),
        ("expired", "EXPIRED"),
        ("early", "EXPIRED"),
        ("tenant", "INACTIVE"),
    ],
)
def test_an_unauthenticated_call_stores_and_records_nothing(
    db, source, admin_engine, tamper, reason
):
    target = dict(source)
    with admin_engine.begin() as conn:
        fenced(conn, source["tenant"])
        if tamper == "unknown":
            target["source"] = uuid4()
        elif tamper == "mismatch":
            target["token"] = source["token"][:-1] + ("A" if source["token"][-1] != "A" else "B")
        elif tamper == "revoked":
            conn.execute(
                text(
                    "UPDATE execbound.signal_sources SET active = false, revoked_at = :n, "
                    "revoked_by = created_by WHERE source_id = :s"
                ),
                {"n": source["now"], "s": source["source"]},
            )
        elif tamper == "inactive":
            # Deactivated without a revocation: `active` alone is enough to refuse.
            conn.execute(
                text("UPDATE execbound.signal_sources SET active = false WHERE source_id = :s"),
                {"s": source["source"]},
            )
        elif tamper == "expired":
            conn.execute(
                text("UPDATE execbound.signal_sources SET expires_at = :n WHERE source_id = :s"),
                {"n": source["now"], "s": source["source"]},
            )
        elif tamper == "early":
            # A registration not yet valid at the call's time is outside its lifetime too.
            conn.execute(
                text("UPDATE execbound.signal_sources SET created_at = :n WHERE source_id = :s"),
                {"n": source["now"] + timedelta(seconds=1), "s": source["source"]},
            )
        else:
            conn.execute(
                text("UPDATE execbound.tenants SET active = false WHERE tenant_id = :t"),
                {"t": source["tenant"]},
            )
    assert admit(db, target) == {"refused": "INVALID_SOURCE", "reason": reason}
    assert records(admin_engine, source) == []
    state = health(admin_engine, source)
    assert (state["rate_count"], state["last_refused_at"]) == (0, None)


def test_another_tenants_fence_never_finds_the_source(db, source, seeded):
    other = next(tenant for tenant in seeded["tenants"] if tenant != source["tenant"])
    fields = signal_fields(source["account"], source["now"])
    result = admit_raw(db, other, source["source"], source["token"], source["now"], **fields)
    assert result == {"refused": "INVALID_SOURCE", "reason": "UNKNOWN"}


def test_the_previous_token_works_only_inside_its_grace(db, source, admin_engine):
    fresh, _ = new_token(source["tenant"], source["source"])
    grace_ends = source["now"] + timedelta(seconds=30)
    with admin_engine.begin() as conn:
        fenced(conn, source["tenant"])
        conn.execute(
            text(
                "UPDATE execbound.signal_sources SET previous_token_hash = token_hash, "
                "previous_valid_until = :until, token_hash = :fresh, rotated_at = :now, "
                "rotated_by = created_by WHERE source_id = :s"
            ),
            {
                "until": grace_ends,
                "fresh": digest(fresh),
                "now": source["now"],
                "s": source["source"],
            },
        )
    assert admit(db, source)["accepted"] is True
    last = {**source, "now": grace_ends - JUST}
    assert admit(db, last, event_id="last-instant")["accepted"] is True
    # `previous_valid_until` is the first instant the previous token no longer works.
    ended = {**source, "now": grace_ends}
    assert admit(db, ended, event_id="after-grace") == MISMATCH
    assert admit(db, {**ended, "token": fresh}, event_id="after-grace")["accepted"] is True


def blocked_by(admin_engine, pid):
    """Whether a backend comes to wait on a lock the backend `pid` holds, within 30 seconds.

    Polled in autocommit, one statement per transaction: PostgreSQL reads `pg_stat_activity`
    once per transaction, so a poll inside one never sees a caller whose connection opened
    after its first read.
    """
    deadline = time.monotonic() + 30
    with admin_engine.connect().execution_options(isolation_level="AUTOCOMMIT") as conn:
        while time.monotonic() < deadline:
            waiting = conn.execute(
                text(
                    "SELECT EXISTS (SELECT 1 FROM pg_stat_activity "
                    "WHERE :pid = ANY(pg_blocking_pids(pid)))"
                ),
                {"pid": pid},
            ).scalar_one()
            if waiting:
                return True
            time.sleep(0.02)
    return False


@pytest.mark.parametrize("pool", ["warm", "cold"])
def test_a_rotation_committed_between_the_two_reads_refuses_the_old_token(
    db, source, admin_engine, pool
):
    """The locked second read checks the token again, not only the unlocked first one.

    The owner locks the row and writes a rotation with no grace, and holds it uncommitted. The
    caller's first, unlocked read sees the committed row, so the old token passes it; its
    second read waits on the owner's lock, which it can only reach by passing the first. Once
    the rotation commits, the second read sees the rotated row, and the old token is refused
    there, before anything is counted or stored.

    The caller sets its own lock and statement timeouts of 60 seconds, twice the poll's 30, so
    however slowly this machine runs it is still waiting when the poll finds it. With a cold
    pool its connection opens only after the poll has begun.
    """
    if pool == "cold":
        db.engine.dispose()
    fresh, _ = new_token(source["tenant"], source["source"])
    fields = signal_fields(source["account"], source["now"], event_id="between-reads")
    outcome = {}

    def caller():
        try:
            with db.transaction(source["tenant"]) as conn:
                conn.execute(text("SELECT set_config('lock_timeout', '60s', true)"))
                conn.execute(text("SELECT set_config('statement_timeout', '60s', true)"))
                outcome["result"] = conn.execute(
                    ADMIT, admit_params(source["source"], source["token"], source["now"], **fields)
                ).scalar_one()
        except Exception as error:  # reported by the assertion below, not lost in the thread
            outcome["error"] = error

    owner = admin_engine.connect()
    transaction = owner.begin()
    fenced(owner, source["tenant"])
    pid = owner.execute(text("SELECT pg_backend_pid()")).scalar_one()
    owner.execute(
        text("SELECT 1 FROM execbound.signal_sources WHERE source_id = :s FOR UPDATE"),
        {"s": source["source"]},
    )
    # A grace of zero: the previous digest's window closes at the rotation itself.
    owner.execute(
        text(
            "UPDATE execbound.signal_sources SET previous_token_hash = token_hash, "
            "previous_valid_until = :now, token_hash = :fresh, rotated_at = :now, "
            "rotated_by = created_by WHERE source_id = :s"
        ),
        {"now": source["now"], "fresh": digest(fresh), "s": source["source"]},
    )
    thread = Thread(target=caller, daemon=True)
    thread.start()
    try:
        waited = blocked_by(admin_engine, pid)
        still_waiting = thread.is_alive()
        transaction.commit()
    finally:
        if transaction.is_active:
            transaction.rollback()
        owner.close()
        thread.join(70)
    assert (waited, still_waiting) == (True, True)
    assert outcome == {"result": MISMATCH}
    assert records(admin_engine, source) == []
    state = health(admin_engine, source)
    assert (state["rate_count"], state["last_refused_at"]) == (0, None)


def test_the_rate_limit_refuses_commits_and_resets(db, source, admin_engine):
    with admin_engine.begin() as conn:
        fenced(conn, source["tenant"])
        conn.execute(
            text(
                "UPDATE execbound.signal_sources SET rate_count = 600, rate_window_at = :n "
                "WHERE source_id = :s"
            ),
            {"n": source["now"], "s": source["source"]},
        )
    assert admit(db, source) == {"refused": "SOURCE_RATE_LIMIT"}
    state = health(admin_engine, source)
    assert (state["rate_refusal_count"], state["last_refusal_code"]) == (1, "SOURCE_RATE_LIMIT")
    # The window is a whole minute: its last instant still refuses, and the next one resets.
    last = {**source, "now": source["now"] + timedelta(minutes=1) - JUST}
    assert admit(db, last) == {"refused": "SOURCE_RATE_LIMIT"}
    later = {**source, "now": source["now"] + timedelta(minutes=1)}
    assert admit(db, later)["accepted"] is True


def test_a_retry_answers_its_receipt_and_a_conflict_keeps_the_first(db, source, admin_engine):
    # Accepted one second inside the ceiling; the retry arrives two seconds later, when the
    # same observation would be stale on arrival. The receipt still answers. The event id is
    # named, because the fixture's default is derived from the clock the retry moves.
    edge = source["now"] - timedelta(seconds=3599)
    first = admit(db, source, event_id="edge", observed_at=edge)
    assert first["accepted"] is True
    retry = admit(
        db,
        {**source, "now": source["now"] + timedelta(seconds=2)},
        event_id="edge",
        observed_at=edge,
    )
    assert retry["duplicate"] is True
    assert retry["received_at"] == first["received_at"]
    conflicting = {**source, "now": source["now"] + timedelta(seconds=1)}
    conflict = admit(
        db, conflicting, event_id="edge", observed_at=edge, record_digest="b" * 64, verdict="High"
    )
    assert conflict == {"refused": "CONFLICTING_DUPLICATE"}
    assert [row["verdict"] for row in records(admin_engine, source)] == ["Medium"]
    state = health(admin_engine, source)
    assert (state["conflict_count"], state["last_refusal_code"], state["last_refused_at"]) == (
        1,
        "CONFLICTING_DUPLICATE",
        conflicting["now"],
    )


@pytest.mark.parametrize(
    "changes",
    [
        {"event_id": "has space"},
        {"event_id": None},
        {"record_digest": "short"},
        # The identity is judged before any field against the registration.
        {"event_id": "has space", "capability": "content_integrity.v1"},
    ],
)
def test_a_malformed_record_identity_is_a_recorded_refusal(db, source, admin_engine, changes):
    assert admit(db, source, **changes) == {"refused": "INVALID_SIGNAL"}
    assert records(admin_engine, source) == []
    state = health(admin_engine, source)
    assert (state["rate_count"], state["last_refusal_code"]) == (1, "INVALID_SIGNAL")


@pytest.mark.parametrize("malformed", ["short", None])
def test_a_malformed_digest_on_a_known_event_is_no_conflict(db, source, admin_engine, malformed):
    assert admit(db, source, event_id="known")["accepted"] is True
    assert admit(db, source, event_id="known", record_digest=malformed) == {
        "refused": "INVALID_SIGNAL"
    }
    state = health(admin_engine, source)
    assert (state["conflict_count"], state["last_refusal_code"]) == (0, "INVALID_SIGNAL")


@pytest.mark.parametrize(
    "changes,code",
    [
        ({"capability": "content_integrity.v1"}, "CAPABILITY_REFUSED"),
        ({"subject_kind": "run"}, "SUBJECT_REFUSED"),
        ({"producer_name": "someone-else"}, "INCOMPATIBLE_PRODUCER"),
        ({"producer_version": "1.0.0"}, "INCOMPATIBLE_PRODUCER"),
        ({"producer_version": "0.0.9"}, "INCOMPATIBLE_PRODUCER"),
        # Inside the range as text, above 0.9.9 as numbers: versions compare numerically.
        ({"producer_version": "0.10.0"}, "INCOMPATIBLE_PRODUCER"),
        # Malformed, though inside the range if it were read as one.
        ({"producer_version": "0.5"}, "INCOMPATIBLE_PRODUCER"),
        ({"producer_version": "0.1.0-rc1"}, "INCOMPATIBLE_PRODUCER"),
        ({"subject_account": uuid4()}, "INVALID_SUBJECT"),
        ({"subject_provider": "mock_okta"}, "INVALID_SUBJECT"),
    ],
)
def test_a_field_outside_the_registration_is_refused_and_recorded(
    db, source, admin_engine, changes, code
):
    assert admit(db, source, **changes) == {"refused": code}
    assert records(admin_engine, source) == []
    state = health(admin_engine, source)
    assert (state["last_refusal_code"], state["last_refused_at"]) == (code, source["now"])


def test_another_tenants_account_is_an_invalid_subject(db, source, admin_engine, seeded):
    index = next(i for i, tenant in enumerate(seeded["tenants"]) if tenant != source["tenant"])
    other, foreign = seeded["tenants"][index], uuid4()
    with admin_engine.begin() as conn:
        fenced(conn, other)
        conn.execute(
            text(
                "INSERT INTO execbound.connector_accounts (tenant_id, account_id, provider, "
                "space_id) VALUES (:t, :a, 'mock_crowdstrike', :s)"
            ),
            {"t": other, "a": foreign, "s": seeded["spaces"][index]},
        )
    assert admit(db, source, subject_account=foreign) == {"refused": "INVALID_SUBJECT"}
    assert records(admin_engine, source) == []
    state = health(admin_engine, source)
    assert (state["rate_count"], state["last_refusal_code"]) == (1, "INVALID_SUBJECT")


def test_another_tenant_reads_no_admitted_record(db, source, seeded):
    """The tenant fence on `security_signals` itself, read as the runtime role (#155): an
    admitted record is there for its own workspace and absent under another's fence."""
    assert admit(db, source)["accepted"] is True
    other = next(tenant for tenant in seeded["tenants"] if tenant != source["tenant"])
    with db.transaction(other) as conn:
        assert (
            conn.execute(text("SELECT count(*) FROM execbound.security_signals")).scalar_one() == 0
        )
    with db.transaction(source["tenant"]) as conn:
        assert conn.execute(
            text("SELECT source_id FROM execbound.security_signals")
        ).scalars().all() == [source["source"]]


def test_time_bounds(db, source, admin_engine):
    now = source["now"]
    assert admit(db, source, event_id="at-60", observed_at=now + timedelta(seconds=60))["accepted"]
    assert admit(db, source, event_id="at-61", observed_at=now + timedelta(seconds=61)) == {
        "refused": "FUTURE_OBSERVATION"
    }
    assert admit(db, source, event_id="old", observed_at=now - timedelta(seconds=3600)) == {
        "refused": "STALE_ON_ARRIVAL"
    }
    assert admit(
        db, source, event_id="inverted", observed_at=now, expires_at=now - timedelta(seconds=1)
    ) == {"refused": "INVALID_SIGNAL"}
    assert admit(
        db, source, event_id="short", observed_at=now, expires_at=now + timedelta(seconds=30)
    )["accepted"]


def test_the_retention_cap_refuses(db, source, admin_engine):
    with admin_engine.begin() as conn:
        fenced(conn, source["tenant"])
        conn.execute(
            text("UPDATE execbound.signal_sources SET record_count = 500000 WHERE source_id = :s"),
            {"s": source["source"]},
        )
    assert admit(db, source) == {"refused": "SOURCE_CAPACITY"}
    assert records(admin_engine, source) == []
    state = health(admin_engine, source)
    assert (state["record_count"], state["last_refusal_code"]) == (500000, "SOURCE_CAPACITY")


@pytest.mark.parametrize("minutes", [6, -6])
def test_a_clock_the_database_does_not_agree_with_is_refused(db, source, minutes):
    skewed = {**source, "now": source["now"] + timedelta(minutes=minutes)}
    with pytest.raises(DBAPIError, match="INVALID_CLOCK"):
        admit(db, skewed)


def test_a_call_with_no_clock_is_refused(db, source):
    fields = signal_fields(source["account"], source["now"])
    with pytest.raises(DBAPIError, match="INVALID_CLOCK"):
        admit_raw(db, source["tenant"], source["source"], source["token"], None, **fields)


# Each envelope field at the edges of what the parser accepts (test_signal_envelope's `bounds`),
# sent through the fenced writer: none meets a CHECK of `security_signals`, and each is stored
# as parsed. tests/test_signal_evidence.py holds the fields a frozen record carries to the
# record's own patterns.
PARAMETERS = {"event_id": "source_event_id", "subject_account": "subject_account_id"}


@pytest.fixture
def wide(registry, admin_engine, seeded):
    """A source accepting the longest producer name and every version the pattern allows."""
    now = registry["clock"].now()
    tenant = registry["identity"].tenant_id
    with admin_engine.begin() as conn:
        fenced(conn, tenant)
        source, token = insert_source(
            conn,
            tenant,
            registry["identity"].principal_id,
            now,
            producer_name=LONGEST_PRODUCER,
            producer_version_min="0.0.0",
            producer_version_max="999999.999999.999999",
        )
    return {"tenant": tenant, "source": source, "token": token, "now": now}


def test_every_accepted_envelope_is_stored_whole_without_meeting_a_check(db, wide, admin_engine):
    for value in bounds(wide["now"]):
        payload = json.dumps(value, ensure_ascii=False).encode()
        assert len(payload) <= MAX_ENVELOPE_BYTES
        signal = parse_signal(payload)
        subject = signal.subject
        fields = {
            "event_id": signal.source_event_id,
            "record_digest": record_digest(signal),
            "producer_name": signal.producer.name,
            "producer_version": signal.producer.version,
            "capability": signal.capability,
            "verdict": signal.verdict,
            "confidence": signal.confidence,
            "severity": signal.severity,
            "subject_kind": subject.kind,
            "subject_account": subject.account_id,
            "subject_provider": subject.provider,
            "subject_resource_type": subject.resource_type,
            "subject_provider_id": subject.provider_id,
            "action": signal.action,
            "request_reference": signal.request_reference,
            "observed_at": signal.observed_at,
            "expires_at": signal.expires_at,
            "attributes": signal.attributes,
            "evidence_ref": signal.evidence_ref,
            "evidence_digest": signal.evidence_digest,
        }
        # signal_admit answers INVALID_SIGNAL for any CHECK the insert meets.
        result = admit_raw(db, wide["tenant"], wide["source"], wide["token"], wide["now"], **fields)
        assert result["accepted"] is True and result["duplicate"] is False, result
        with admin_engine.begin() as conn:
            fenced(conn, wide["tenant"])
            stored = (
                conn.execute(
                    text(
                        "SELECT * FROM execbound.security_signals "
                        "WHERE source_id = :s AND source_event_id = :e"
                    ),
                    {"s": wide["source"], "e": signal.source_event_id},
                )
                .mappings()
                .one()
            )
        assert {PARAMETERS.get(name, name): value for name, value in fields.items()} == {
            PARAMETERS.get(name, name): stored[PARAMETERS.get(name, name)] for name in fields
        }
