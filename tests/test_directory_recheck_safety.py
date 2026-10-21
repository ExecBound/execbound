# SPDX-License-Identifier: AGPL-3.0-only
"""The directory recheck fails closed while it is in flight and when it cannot be claimed (#863).

A directory session in a workspace that requires its directory is refused once its verification
is older than `RECHECK_GRACE`, and the first request back rechecks it instead (#859). Three gaps
the final review of #859 found, closed by migration 0102:

* The claim that makes one request of several the one that calls the directory moved
  `verified_at` itself, so the others read a fresh verification and were served, changes
  included, before the directory had answered. The claim is now a column of its own,
  `recheck_claimed_at`, and only the directory's yes moves `verified_at`; a request that finds
  another's claim waits for it to settle and then loads, or is refused, on what it left.
* A claim the database could not write skipped the recheck silently. A stale session is now
  refused `PROVIDER_UNAVAILABLE` when its claim cannot be made.
* The claim and the recheck stamped the database's `now()` while the sign-in stamped the
  application's clock. Every writer now takes the application's clock, so a clock that drifts
  from the database's cannot leave a verification in its future.
"""

import time
from concurrent.futures import ThreadPoolExecutor
from datetime import timedelta
from threading import Event

import pytest
from alembic import command
from sqlalchemy import event, text
from sqlalchemy.exc import DBAPIError, OperationalError
from test_directory_store import RING, StandIn, directory_key
from test_directory_store import cast as cast
from test_directory_store import clock as clock
from test_directory_store import runtime as runtime
from test_dormant_catalog import alembic_config, empty_schema
from test_longer_sessions import away, refreshes, verified_at

from execbound import directory_store as store
from execbound.directory_store import DirectoryConfig
from execbound.surfaces.sessions import SessionError, load_session

pytestmark = pytest.mark.integration

BEFORE = "0101_trusted_browsers"
TARGET = "0102_directory_recheck_claim"
FUNCTIONS = ("directory_recheck", "directory_recheck_claim", "directory_recheck_release")


def held_directory(clock):
    """A stand-in whose token call waits at `release` once `entered` is set: a recheck held in
    flight for as long as a test needs."""
    stand_in = StandIn(directory_key(), now=lambda: clock.value.timestamp())
    original = stand_in.handle
    entered, release = Event(), Event()

    def held(request):
        if b"refresh_token" in request.content:
            entered.set()
            assert release.wait(timeout=20), "the test never released the directory"
        return original(request)

    stand_in.handle = held
    return stand_in, entered, release


def claim_row(admin_engine, session):
    """`verified_at` and `recheck_claimed_at` as the row holds them."""
    with admin_engine.begin() as conn:
        conn.execute(
            text("SELECT set_config('execbound.tenant_id', :t, true)"),
            {"t": str(session.identity.tenant_id)},
        )
        return (
            conn.execute(
                text(
                    "SELECT verified_at, recheck_claimed_at FROM execbound.federated_sign_ins "
                    "WHERE tenant_id=:t AND credential_id=:c"
                ),
                {"t": session.identity.tenant_id, "c": session.identity.credential_id},
            )
            .mappings()
            .one()
        )


def test_rs1_a_request_beside_a_recheck_in_flight_waits_and_is_refused_with_it(
    db, cast, clock, runtime, admin_engine
):
    """An hour away, two requests: the first claims the recheck and the directory takes its
    time. The second is not served on the claim: it waits, the directory refuses the account,
    and both are refused. Before #863 the claim moved `verified_at`, so the second request read
    a fresh verification and was served, changes included, while the directory had not yet
    said no."""
    from test_directory_store import _session

    stand_in, entered, release = held_directory(clock)
    settings = DirectoryConfig(RING, "https://app.example", stand_in.client())
    provider, session, granted = _session(db, settings, cast, clock, stand_in)
    away(admin_engine, provider, session, clock, timedelta(hours=1))
    before = verified_at(admin_engine, session)
    stand_in.refresh_status, stand_in.refresh_body = 400, {"error": "invalid_grant"}
    with ThreadPoolExecutor(max_workers=2) as pool:
        first = pool.submit(store.load_rechecked, runtime, settings, granted.token)
        assert entered.wait(timeout=10)
        # The claim is its own column: the verification the second request reads is the old one.
        assert claim_row(admin_engine, session)["verified_at"] == before
        second = pool.submit(store.load_rechecked, runtime, settings, granted.token)
        time.sleep(0.5)
        assert not second.done(), "a request was served on a recheck still in flight"
        release.set()
        for future in (first, second):
            with pytest.raises(SessionError):
                future.result(timeout=20)
    assert len(refreshes(stand_in)) == 1
    with pytest.raises(SessionError) as ended:
        load_session(db, granted.token, clock=clock)
    assert ended.value.code == "INVALID_SESSION"


def test_rs2_a_request_beside_a_recheck_in_flight_loads_once_the_directory_says_yes(
    db, cast, clock, runtime, admin_engine
):
    """The same two requests, and the directory confirms the account: the second loads, after
    the directory's answer and not before it, and the refresh token is presented once."""
    from test_directory_store import _session

    stand_in, entered, release = held_directory(clock)
    settings = DirectoryConfig(RING, "https://app.example", stand_in.client())
    provider, session, granted = _session(db, settings, cast, clock, stand_in)
    away(admin_engine, provider, session, clock, timedelta(hours=1))
    with ThreadPoolExecutor(max_workers=2) as pool:
        first = pool.submit(store.load_rechecked, runtime, settings, granted.token)
        assert entered.wait(timeout=10)
        second = pool.submit(store.load_rechecked, runtime, settings, granted.token)
        time.sleep(0.5)
        assert not second.done(), "a request was served on a recheck still in flight"
        release.set()
        loaded = [future.result(timeout=20) for future in (first, second)]
    assert [item.session_id for item in loaded] == [session.session_id] * 2
    assert len(refreshes(stand_in)) == 1
    row = claim_row(admin_engine, session)
    assert row["verified_at"] == clock.value and row["recheck_claimed_at"] is None


def test_rs3_a_claim_still_unsettled_after_the_wait_leaves_the_session_refused(
    db, cast, clock, runtime, admin_engine, monkeypatch
):
    """A claim another request holds and never settles within the wait: the stale request is
    refused, without calling the directory and without touching the verification."""
    from test_directory_store import _session

    monkeypatch.setattr(store, "SETTLE_WAIT", timedelta(milliseconds=600))
    stand_in = StandIn(directory_key(), now=lambda: clock.value.timestamp())
    settings = DirectoryConfig(RING, "https://app.example", stand_in.client())
    provider, session, granted = _session(db, settings, cast, clock, stand_in)
    away(admin_engine, provider, session, clock, timedelta(hours=1))
    before = verified_at(admin_engine, session)
    with admin_engine.begin() as conn:
        conn.execute(
            text(
                "UPDATE execbound.federated_sign_ins SET recheck_claimed_at=:at "
                "WHERE tenant_id=:t AND credential_id=:c"
            ),
            {
                "at": clock.value - timedelta(seconds=5),
                "t": session.identity.tenant_id,
                "c": session.identity.credential_id,
            },
        )
    started = time.monotonic()
    with pytest.raises(SessionError) as refused:
        store.load_rechecked(runtime, settings, granted.token)
    assert refused.value.code == "DIRECTORY_REQUIRED"
    assert time.monotonic() - started >= 0.5, "it did not wait for the claim to settle"
    assert refreshes(stand_in) == []
    assert verified_at(admin_engine, session) == before


def test_rs4_a_claim_left_past_its_lease_is_taken_over(db, cast, clock, runtime, admin_engine):
    """A request that claimed the recheck and died never settles it. Past `CLAIM_LEASE` the
    claim no longer stands, so the next request rechecks and the session goes on."""
    from test_directory_store import _session

    stand_in = StandIn(directory_key(), now=lambda: clock.value.timestamp())
    settings = DirectoryConfig(RING, "https://app.example", stand_in.client())
    provider, session, granted = _session(db, settings, cast, clock, stand_in)
    away(admin_engine, provider, session, clock, timedelta(hours=1))
    with admin_engine.begin() as conn:
        conn.execute(
            text(
                "UPDATE execbound.federated_sign_ins SET recheck_claimed_at=:at "
                "WHERE tenant_id=:t AND credential_id=:c"
            ),
            {
                "at": clock.value - store.CLAIM_LEASE - timedelta(seconds=1),
                "t": session.identity.tenant_id,
                "c": session.identity.credential_id,
            },
        )
    assert store.load_rechecked(runtime, settings, granted.token).session_id == session.session_id
    assert len(refreshes(stand_in)) == 1


def test_rs5_a_claim_the_database_refuses_fails_a_stale_session_closed(
    db, cast, clock, runtime, admin_engine
):
    """The claim cannot be written. A stale session is refused `PROVIDER_UNAVAILABLE` rather
    than passed over, and the directory is not asked; one whose verification is still inside
    the grace is tolerated, as an unreachable directory is."""
    from test_directory_store import _session

    stand_in = StandIn(directory_key(), now=lambda: clock.value.timestamp())
    settings = DirectoryConfig(RING, "https://app.example", stand_in.client())
    provider, session, granted = _session(db, settings, cast, clock, stand_in)

    @event.listens_for(db.engine, "before_cursor_execute")
    def refuse(conn, cursor, statement, parameters, context, executemany):
        if "directory_recheck_claim" in statement:
            raise OperationalError(statement, parameters, Exception("the claim cannot be written"))

    try:
        # Inside the grace: tolerated, nothing asked.
        clock.value += store.RECHECK_INTERVAL + timedelta(seconds=1)
        store.recheck_session(runtime, settings, session)
        # Past it: refused.
        clock.value += store.RECHECK_GRACE
        with pytest.raises(SessionError) as refused:
            store.recheck_session(runtime, settings, session)
        assert refused.value.code == "PROVIDER_UNAVAILABLE"
    finally:
        event.remove(db.engine, "before_cursor_execute", refuse)
    assert refreshes(stand_in) == []


def test_rs6_the_claim_and_the_recheck_stamp_the_applications_clock(
    db, cast, clock, runtime, admin_engine
):
    """The application's clock an hour ahead of the database's, as a test clock or a drifting
    host can be. The claim stamps the application's present and so does the recheck, so the
    verification the recheck writes is fresh to the session check and the session loads. Before
    #863 both stamped the database's `now()`, which to the application was already an hour
    old, past the grace, and the session was refused straight after the directory said yes."""
    from test_directory_store import _session

    stand_in, entered, release = held_directory(clock)
    settings = DirectoryConfig(RING, "https://app.example", stand_in.client())
    provider, session, granted = _session(db, settings, cast, clock, stand_in)
    # An hour away, and the application's clock an hour ahead of the database's: a verification
    # the database stamped with its own present would already be past the grace here.
    away(admin_engine, provider, session, clock, timedelta(hours=1))
    clock.value += timedelta(hours=1)
    with ThreadPoolExecutor(max_workers=1) as pool:
        back = pool.submit(store.load_rechecked, runtime, settings, granted.token)
        assert entered.wait(timeout=10)
        assert claim_row(admin_engine, session)["recheck_claimed_at"] == clock.value
        release.set()
        assert back.result(timeout=20).session_id == session.session_id
    assert claim_row(admin_engine, session)["verified_at"] == clock.value


def recheck_catalog(conn):
    """Each recheck function's arguments, definition and ACL, and whether the claim column is
    there."""
    functions = {
        name: (arguments, definition, acl)
        for name, arguments, definition, acl in conn.execute(
            text(
                "SELECT p.proname, pg_get_function_identity_arguments(p.oid), "
                "pg_get_functiondef(p.oid), CAST(p.proacl AS text) "
                "FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace "
                "WHERE n.nspname = 'execbound' AND p.proname = ANY(:names)"
            ),
            {"names": list(FUNCTIONS)},
        ).all()
    }
    column = conn.execute(
        text(
            "SELECT count(*) FROM information_schema.columns WHERE table_schema = 'execbound' "
            "AND table_name = 'federated_sign_ins' AND column_name = 'recheck_claimed_at'"
        )
    ).scalar_one()
    return functions, column


def test_rs7_the_migration_and_its_downgrade(admin_engine):
    """0102 adds the claim column, replaces the claim and the release with ones that take the
    application's clock and leave `verified_at` alone, and replaces the recheck with one that
    stamps `p_now` and records a yes only under the caller's claim; its downgrade restores
    0101's three functions, grants included, and drops the column."""
    empty_schema(admin_engine)
    config = alembic_config()
    command.downgrade(config, BEFORE)
    try:
        with admin_engine.connect() as conn:
            before, column = recheck_catalog(conn)
        assert set(before) == set(FUNCTIONS) and column == 0
        assert "verified_at = now()" in before["directory_recheck"][1]
        command.upgrade(config, TARGET)
        with admin_engine.connect() as conn:
            after, column = recheck_catalog(conn)
        assert column == 1
        assert after["directory_recheck_claim"][0] == (
            "p_credential uuid, p_seen timestamp with time zone, p_now timestamp with time zone"
        )
        assert after["directory_recheck_release"][0] == (
            "p_credential uuid, p_claimed timestamp with time zone"
        )
        for name in ("directory_recheck_claim", "directory_recheck_release"):
            assert "execbound_app=X/execbound_owner" in after[name][2], name
            assert "SECURITY DEFINER" in after[name][1], name
            assert "SET verified_at" not in after[name][1], name
            assert "now()" not in after[name][1], name
        assert "interval '60 seconds'" in after["directory_recheck_claim"][1]
        assert store.CLAIM_LEASE == timedelta(seconds=60)
        recheck = after["directory_recheck"]
        assert recheck[0] == before["directory_recheck"][0] + ", p_claimed timestamp with time zone"
        assert "execbound_app=X/execbound_owner" in recheck[2]
        assert "verified_at = p_now" in recheck[1] and "recheck_claimed_at = NULL" in recheck[1]
        assert "recheck_claimed_at = p_claimed" in recheck[1]
        assert "now()" not in recheck[1]
        command.downgrade(config, BEFORE)
        with admin_engine.connect() as conn:
            restored, column = recheck_catalog(conn)
        assert restored == before and column == 0
    finally:
        empty_schema(admin_engine)
        command.upgrade(config, "head")


def fenced(conn, session):
    conn.execute(
        text("SELECT set_config('execbound.tenant_id', :t, true)"),
        {"t": str(session.identity.tenant_id)},
    )


def stamp_claim(admin_engine, session, at):
    with admin_engine.begin() as conn:
        conn.execute(
            text(
                "UPDATE execbound.federated_sign_ins SET recheck_claimed_at=:at "
                "WHERE tenant_id=:t AND credential_id=:c"
            ),
            {"at": at, "t": session.identity.tenant_id, "c": session.identity.credential_id},
        )


def test_rs8_a_release_or_a_late_yes_never_touches_a_claim_not_its_own(
    db, cast, clock, admin_engine
):
    """A request whose directory call outlived its lease, after the next request took the claim
    over: its release leaves the newer claim alone, and its late yes is not recorded, so it
    neither clears that claim nor overwrites the refresh token stored under it."""
    from test_directory_store import _session

    settings = DirectoryConfig(RING, "https://app.example")
    _, session, _ = _session(db, settings, cast, clock)
    old, newer = clock.value - timedelta(minutes=2), clock.value - timedelta(seconds=5)
    stamp_claim(admin_engine, session, newer)
    with admin_engine.begin() as conn:
        fenced(conn, session)
        before = conn.execute(
            text(
                "SELECT refresh_ciphertext, verified_at FROM execbound.federated_sign_ins "
                "WHERE tenant_id=:t AND credential_id=:c"
            ),
            {"t": session.identity.tenant_id, "c": session.identity.credential_id},
        ).one()
    with db.transaction(session.identity.tenant_id) as conn:
        conn.execute(
            text("SELECT execbound.directory_recheck_release(:c,:claimed)"),
            {"c": session.identity.credential_id, "claimed": old},
        )
    assert claim_row(admin_engine, session)["recheck_claimed_at"] == newer
    with pytest.raises(DBAPIError, match="INVALID_CREDENTIAL"):
        with db.transaction(session.identity.tenant_id) as conn:
            conn.execute(
                text("SELECT execbound.directory_recheck(:c,:x,:k,:now,:claimed)"),
                {
                    "c": session.identity.credential_id,
                    "x": "ab" * 40,
                    "k": "dir-v1",
                    "now": clock.value,
                    "claimed": old,
                },
            )
    with admin_engine.begin() as conn:
        fenced(conn, session)
        after = conn.execute(
            text(
                "SELECT refresh_ciphertext, verified_at, recheck_claimed_at "
                "FROM execbound.federated_sign_ins WHERE tenant_id=:t AND credential_id=:c"
            ),
            {"t": session.identity.tenant_id, "c": session.identity.credential_id},
        ).one()
    assert tuple(after) == (*before, newer)


def test_rs9_a_yes_the_database_cannot_record_lets_the_claim_go_and_stays_refused(
    db, cast, clock, runtime, admin_engine
):
    """The directory confirms the account but the yes cannot be written. Nothing is served on
    it: the claim is let go at once, rather than standing for its lease, and the stale session
    is refused, the verification unmoved."""
    from test_directory_store import _session

    stand_in = StandIn(directory_key(), now=lambda: clock.value.timestamp())
    settings = DirectoryConfig(RING, "https://app.example", stand_in.client())
    provider, session, granted = _session(db, settings, cast, clock, stand_in)
    away(admin_engine, provider, session, clock, timedelta(hours=1))
    before = verified_at(admin_engine, session)

    @event.listens_for(db.engine, "before_cursor_execute")
    def refuse(conn, cursor, statement, parameters, context, executemany):
        if "directory_recheck(" in statement:
            raise OperationalError(statement, parameters, Exception("the yes cannot be written"))

    try:
        with pytest.raises(SessionError) as refused:
            store.load_rechecked(runtime, settings, granted.token)
    finally:
        event.remove(db.engine, "before_cursor_execute", refuse)
    assert refused.value.code == "DIRECTORY_REQUIRED"
    assert len(refreshes(stand_in)) == 1
    assert tuple(claim_row(admin_engine, session).values()) == (before, None)


def test_rs10_a_request_inside_the_grace_that_loses_the_claim_goes_on_at_once(
    db, cast, clock, runtime, admin_engine, monkeypatch
):
    """A renewal whose verification is old enough to recheck but still inside the grace finds
    another's claim: it goes on with the verification it has and waits for nothing."""
    from test_directory_store import _session

    monkeypatch.setattr(store, "SETTLE_WAIT", timedelta(seconds=10))
    stand_in = StandIn(directory_key(), now=lambda: clock.value.timestamp())
    settings = DirectoryConfig(RING, "https://app.example", stand_in.client())
    _, session, _ = _session(db, settings, cast, clock, stand_in)
    clock.value += store.RECHECK_INTERVAL + timedelta(seconds=1)
    stamp_claim(admin_engine, session, clock.value - timedelta(seconds=5))
    started = time.monotonic()
    store.recheck_session(runtime, settings, session)
    assert time.monotonic() - started < 2
    assert refreshes(stand_in) == []


def test_rs11_with_every_waiting_place_taken_a_stale_request_is_refused_at_once(
    db, cast, clock, runtime, admin_engine, monkeypatch
):
    """The process's waiting places (`MAX_WAITERS`) are all taken, as a workspace whose
    directory answers slowly can make them: the next stale request finding a claim is refused
    at once, holding no request slot for the wait."""
    from threading import BoundedSemaphore

    from test_directory_store import _session

    monkeypatch.setattr(store, "SETTLE_WAIT", timedelta(seconds=10))
    monkeypatch.setattr(store, "_WAITERS", BoundedSemaphore(1))
    assert store._WAITERS.acquire(blocking=False)
    stand_in = StandIn(directory_key(), now=lambda: clock.value.timestamp())
    settings = DirectoryConfig(RING, "https://app.example", stand_in.client())
    provider, session, granted = _session(db, settings, cast, clock, stand_in)
    away(admin_engine, provider, session, clock, timedelta(hours=1))
    stamp_claim(admin_engine, session, clock.value - timedelta(seconds=5))
    started = time.monotonic()
    with pytest.raises(SessionError) as refused:
        store.load_rechecked(runtime, settings, granted.token)
    assert refused.value.code == "DIRECTORY_REQUIRED"
    assert time.monotonic() - started < 2
    assert refreshes(stand_in) == []
