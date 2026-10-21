# SPDX-License-Identifier: AGPL-3.0-only
"""A sign-in lasts two days and a console session twelve hours between activity (#859).

The session ends after twelve idle hours and two days after sign-in whatever renews it. Renewal
keeps its seven-and-a-half-minute cadence, so a directory session is still rechecked that often.
The database holds the same bounds: the table's ceiling, the sign-in credential's lifetime
and the account session functions. Migration 0100 patches four functions and one constraint in
place, and its downgrade restores every one of them.
"""

import importlib.util
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from datetime import timedelta
from pathlib import Path
from threading import Barrier
from types import SimpleNamespace
from uuid import uuid4

import pytest
from alembic import command
from alembic.script import ScriptDirectory
from console_api_fixtures import API, ORIGIN
from fastapi import Response
from fastapi.testclient import TestClient
from sqlalchemy import event, text
from sqlalchemy.exc import DBAPIError
from test_directory_store import RING, StandIn, directory_key
from test_directory_store import cast as cast
from test_directory_store import clock as clock
from test_directory_store import runtime as runtime
from test_directory_store import settings as settings
from test_dormant_catalog import alembic_config, empty_schema
from test_human_sessions import humans as humans
from test_mfa_sessions import RING as MFA_RING
from test_mfa_sessions import enrolled
from test_session_end import built as built
from test_workspace_switching import member_pair

from execbound import db as database
from execbound import directory_store as store
from execbound import mfa
from execbound.app import create_app
from execbound.directory_store import DirectoryConfig
from execbound.passwords import SIGN_IN_LIFETIME, mint_session_credential
from execbound.surfaces import sessions
from execbound.surfaces.human import HumanConfig, _session_cookies
from execbound.surfaces.sessions import (
    PENDING_LIFETIME,
    RENEW_AFTER,
    SESSION_ABSOLUTE,
    SESSION_LIFETIME,
    SessionError,
    issue_session,
    load_session,
)
from execbound.surfaces.tokens import TokenKeys

pytestmark = pytest.mark.integration

BEFORE = "0099_scout_agents_page"
TARGET = "0100_longer_sessions"
PATCHED = (
    "sign_in_credential",
    "directory_sign_in",
    "account_session_open",
    "account_session_touch",
)
# Left at fifteen minutes on purpose: the destination session it opens owes the second factor
# unless the source's verification was carried.
UNCHANGED = ("account_switch",)
ADDED = ("directory_recheck_claim", "directory_recheck_release")
OPEN_ANCHOR = "p_now+interval '8 hours',a.version,proof.method,t,p_session);"


def issued(db, cast, clock, count=1):
    """`count` sessions of one approver's sign-in, all issued at the clock's present."""
    identity = mint_session_credential(
        db, cast["tenant"], cast["approver"], "password", clock=clock
    )
    return identity, [issue_session(db, identity, clock=clock) for _ in range(count)]


def test_ls_a_session_lasts_twelve_hours_idle_and_two_days_at_most(db, cast, clock):
    assert SESSION_LIFETIME == timedelta(hours=12)
    assert SESSION_ABSOLUTE == SIGN_IN_LIFETIME == timedelta(days=2)
    start = clock.value
    identity, (used, idle) = issued(db, cast, clock, 2)
    assert identity.expires_at == start + timedelta(days=2)

    clock.value = start + timedelta(hours=11, minutes=59)
    assert load_session(db, used.token, clock=clock).session_id == used.session_id
    clock.value = start + timedelta(hours=12, minutes=1)
    with pytest.raises(SessionError) as ended:
        load_session(db, idle.token, clock=clock)
    assert ended.value.code == "INVALID_SESSION"

    # Kept active every six hours, the other session outlives twelve hours, then reaches the
    # two-day end and no further, though it was read a minute before.
    clock.value = start
    kept = issue_session(db, identity, clock=clock)
    for hours in range(6, 43, 6):
        clock.value = start + timedelta(hours=hours)
        assert load_session(db, kept.token, clock=clock).session_id == kept.session_id
    clock.value = start + timedelta(hours=47)
    last = load_session(db, kept.token, clock=clock)
    assert last.expires_at == start + timedelta(days=2)
    clock.value = start + timedelta(hours=48, minutes=1)
    with pytest.raises(SessionError) as ended:
        load_session(db, kept.token, clock=clock)
    assert ended.value.code == "INVALID_SESSION"


def test_ls_renewal_runs_every_seven_and_a_half_minutes(db, cast, clock):
    assert RENEW_AFTER == timedelta(minutes=7, seconds=30)
    start = clock.value
    _, (granted,) = issued(db, cast, clock)
    clock.value = start + timedelta(minutes=7)
    early = load_session(db, granted.token, clock=clock)
    assert not early.renewed and early.expires_at == start + SESSION_LIFETIME
    clock.value = start + timedelta(minutes=8)
    renewed = load_session(db, granted.token, clock=clock)
    assert renewed.renewed
    assert renewed.expires_at == start + timedelta(minutes=8) + SESSION_LIFETIME
    # The next renewal is a cadence away from the renewed row, not from the start.
    clock.value = start + timedelta(minutes=15)
    assert not load_session(db, granted.token, clock=clock).renewed
    clock.value = start + timedelta(minutes=16)
    assert load_session(db, granted.token, clock=clock).renewed


def directory_client(db, runtime, settings, granted):
    """The real app, signed in as a directory session by its two cookies."""
    config = HumanConfig(ORIGIN, TokenKeys("state-v1", {"state-v1": b"k" * 32}), directory=settings)
    client = TestClient(create_app(db, runtime=runtime, human=config), base_url=ORIGIN)
    client.cookies.set(config.cookie("session"), granted.token, domain="127.0.0.1")
    client.cookies.set(config.cookie("csrf"), granted.csrf_token, domain="127.0.0.1")
    return client


def test_ls_the_directory_recheck_keeps_its_cadence(db, cast, clock, runtime):
    """Disabled at the provider, a person loses the console on the first request once a renewal
    is due, which is `RENEW_AFTER` after the last, and not before it."""
    from test_directory_store import _session

    stand_in = StandIn(directory_key(), now=lambda: clock.value.timestamp())
    settings = DirectoryConfig(RING, "https://app.example", stand_in.client())
    _, _, granted = _session(db, settings, cast, clock, stand_in)
    with directory_client(db, runtime, settings, granted) as client:
        stand_in.refresh_status, stand_in.refresh_body = 400, {"error": "invalid_grant"}
        # The directory has refused, but no renewal is due, so nothing has asked it yet.
        clock.value += RENEW_AFTER - timedelta(seconds=30)
        assert client.get(API + "/session").status_code == 200
        clock.value += timedelta(seconds=31)
        assert client.get(API + "/session").status_code == 401
    with pytest.raises(SessionError) as ended:
        load_session(db, granted.token, clock=clock)
    assert ended.value.code == "INVALID_SESSION"


def test_ls_a_directory_session_at_its_two_day_end_is_still_rechecked(db, cast, clock, runtime):
    """Once the renewal reaches the two-day cap the row cannot move and the renewal is no
    longer what a recheck waits on: a person disabled at the directory forty hours in is
    refused within the recheck bound, and the capped session sends no renewal statement."""
    from test_directory_store import _session

    start = clock.value
    stand_in = StandIn(directory_key(), now=lambda: clock.value.timestamp())
    settings = DirectoryConfig(RING, "https://app.example", stand_in.client())
    _, _, granted = _session(db, settings, cast, clock, stand_in)
    renewals = []

    @event.listens_for(db.engine, "before_cursor_execute")
    def count(conn, cursor, statement, parameters, context, executemany):
        if "renew_human_session" in statement:
            renewals.append(statement)

    try:
        with directory_client(db, runtime, settings, granted) as client:
            for hours in (6, 12, 18, 24, 30, 36, 40):
                clock.value = start + timedelta(hours=hours)
                r = client.get(API + "/session")
                assert r.status_code == 200, (hours, r.text)
            capped = load_session(db, granted.token, clock=clock)
            assert capped.expires_at == capped.ends_at == start + timedelta(days=2)
            assert capped.renewal_due and not capped.renewed
            sent = len(renewals)
            load_session(db, granted.token, clock=clock)
            assert len(renewals) == sent, "a session at its end sent a renewal statement"
            verified_after = stand_in.seen.copy()
            # Disabled at the directory; the next request past the recheck interval ends it.
            stand_in.refresh_status, stand_in.refresh_body = 400, {"error": "invalid_grant"}
            clock.value += store.RECHECK_INTERVAL + timedelta(seconds=1)
            assert len(stand_in.seen) == len(verified_after)
            assert client.get(API + "/session").status_code == 401
            assert len(stand_in.seen) > len(verified_after)
    finally:
        event.remove(db.engine, "before_cursor_execute", count)
    with pytest.raises(SessionError) as ended:
        load_session(db, granted.token, clock=clock)
    assert ended.value.code == "INVALID_SESSION"


def test_ls_simultaneous_rechecks_call_the_directory_once(db, cast, clock, runtime, admin_engine):
    """Two requests that find the verification old at the same moment: one claims the recheck
    and calls the directory, the other carries on, so a refresh token is never presented twice."""
    from test_directory_store import _session

    stand_in = StandIn(directory_key(), now=lambda: clock.value.timestamp())
    original = stand_in.handle

    def slow(request):
        # Long enough that the second request is certainly in flight beside the first.
        if b"refresh_token" in request.content:
            time.sleep(0.6)
        return original(request)

    stand_in.handle = slow
    settings = DirectoryConfig(RING, "https://app.example", stand_in.client())
    _, session, _ = _session(db, settings, cast, clock, stand_in)
    # The verification is made old by moving it back, not by moving the clock on: the claim
    # stamps the database's own time, which the injected clock would otherwise leave behind.
    with admin_engine.begin() as conn:
        conn.execute(
            text(
                "UPDATE execbound.federated_sign_ins SET verified_at = verified_at - :age "
                "WHERE tenant_id=:t AND credential_id=:c"
            ),
            {
                "age": store.RECHECK_INTERVAL + timedelta(seconds=1),
                "t": session.identity.tenant_id,
                "c": session.identity.credential_id,
            },
        )
    before = len(stand_in.seen)
    start = Barrier(2)

    def recheck():
        start.wait(timeout=5)
        store.recheck_session(runtime, settings, session)

    with ThreadPoolExecutor(max_workers=2) as pool:
        for future in [pool.submit(recheck), pool.submit(recheck)]:
            future.result(timeout=20)
    refreshes = [r for r in stand_in.seen[before:] if b"refresh_token" in r.content]
    assert len(refreshes) == 1, len(refreshes)


def test_ls_the_console_shell_rechecks_a_directory_session(db, cast, clock, runtime, built):
    """A page load uses up the renewal that is due, so it rechecks as the API does: a person
    disabled at the directory who only reloads the shell is refused there."""
    from test_directory_store import _session

    stand_in = StandIn(directory_key(), now=lambda: clock.value.timestamp())
    settings = DirectoryConfig(RING, "https://app.example", stand_in.client())
    _, _, granted = _session(db, settings, cast, clock, stand_in)
    with directory_client(db, runtime, settings, granted) as client:
        client.follow_redirects = False
        stand_in.refresh_status, stand_in.refresh_body = 400, {"error": "invalid_grant"}
        clock.value += RENEW_AFTER - timedelta(seconds=30)
        assert client.get("/activity").status_code == 200
        clock.value += timedelta(seconds=31)
        shell = client.get("/activity")
        assert shell.status_code == 303 and shell.headers["location"].startswith("/login")
    with pytest.raises(SessionError) as ended:
        load_session(db, granted.token, clock=clock)
    assert ended.value.code == "INVALID_SESSION"


def away(admin_engine, provider, session, clock, gone):
    """The workspace requires its directory, and the person signed in `gone` ago and has made
    no request since: the session's row and its directory verification are moved back rather
    than the clock on, because the claim and the recheck stamp the database's own time, which
    a clock moved on would leave behind. The clock is put a minute past the database's present,
    so a verification the database stamps during the test is never ahead of it."""
    tenant, credential = session.identity.tenant_id, session.identity.credential_id
    with admin_engine.begin() as conn:
        conn.execute(text("SELECT set_config('execbound.tenant_id', :t, true)"), {"t": str(tenant)})
        conn.execute(
            text(
                "UPDATE execbound.identity_providers SET require_sign_in=true "
                "WHERE tenant_id=:t AND provider_id=:p"
            ),
            {"t": tenant, "p": provider},
        )
        conn.execute(
            text(
                "UPDATE execbound.human_sessions SET created_at=created_at-:g, "
                "expires_at=expires_at-:g WHERE tenant_id=:t AND session_id=:s"
            ),
            {"g": gone, "t": tenant, "s": session.session_id},
        )
        conn.execute(
            text(
                "UPDATE execbound.federated_sign_ins SET created_at=created_at-:g, "
                "verified_at=verified_at-:g WHERE tenant_id=:t AND credential_id=:c"
            ),
            {"g": gone, "t": tenant, "c": credential},
        )
        clock.value = conn.execute(
            text("SELECT clock_timestamp() + interval '1 minute'")
        ).scalar_one()


def verified_at(admin_engine, session):
    with admin_engine.begin() as conn:
        conn.execute(
            text("SELECT set_config('execbound.tenant_id', :t, true)"),
            {"t": str(session.identity.tenant_id)},
        )
        return conn.execute(
            text(
                "SELECT verified_at FROM execbound.federated_sign_ins "
                "WHERE tenant_id=:t AND credential_id=:c"
            ),
            {"t": session.identity.tenant_id, "c": session.identity.credential_id},
        ).scalar_one()


def refreshes(stand_in):
    return [r for r in stand_in.seen if b"refresh_token" in r.content]


def test_ls_a_directory_required_session_back_after_an_hour_is_rechecked_not_ended(
    db, cast, clock, runtime, admin_engine
):
    """In a workspace that requires its directory, a person away for an hour, longer than the
    fifteen-minute grace, still has their session: the first request back rechecks the
    directory first, and the directory's yes lets the session load, as twelve idle hours
    promise. Before #859's final review that request was refused `DIRECTORY_REQUIRED`."""
    from test_directory_store import _session

    stand_in = StandIn(directory_key(), now=lambda: clock.value.timestamp())
    settings = DirectoryConfig(RING, "https://app.example", stand_in.client())
    provider, session, granted = _session(db, settings, cast, clock, stand_in)
    away(admin_engine, provider, session, clock, timedelta(hours=1))
    # The bare load, which no request makes without the recheck, refuses as before.
    with pytest.raises(SessionError) as refused:
        load_session(db, granted.token, clock=clock)
    assert refused.value.code == "DIRECTORY_REQUIRED"
    assert refreshes(stand_in) == []
    with directory_client(db, runtime, settings, granted) as client:
        back = client.get(API + "/session")
        assert back.status_code == 200, back.text
        assert len(refreshes(stand_in)) == 1
        assert verified_at(admin_engine, session) > clock.value - timedelta(minutes=2)
        # The verification is fresh again, so the next request asks the directory nothing.
        assert client.get(API + "/session").status_code == 200
        assert len(refreshes(stand_in)) == 1
    assert load_session(db, granted.token, clock=clock).identity == session.identity


def test_ls_a_directory_required_session_disabled_while_away_is_refused(
    db, cast, clock, runtime, admin_engine
):
    """The same hour away, but the directory has disabled the account meanwhile: the recheck
    hears `invalid_grant`, ends the credential and every session under it, and the request is
    refused."""
    from test_directory_store import _session

    stand_in = StandIn(directory_key(), now=lambda: clock.value.timestamp())
    settings = DirectoryConfig(RING, "https://app.example", stand_in.client())
    provider, session, granted = _session(db, settings, cast, clock, stand_in)
    away(admin_engine, provider, session, clock, timedelta(hours=1))
    stand_in.refresh_status, stand_in.refresh_body = 400, {"error": "invalid_grant"}
    with directory_client(db, runtime, settings, granted) as client:
        back = client.get(API + "/session")
        assert back.status_code == 403, back.text
        assert back.json()["code"] == "DIRECTORY_REQUIRED"
        assert len(refreshes(stand_in)) == 1
        # Ended, not merely refused: the next request is no session at all.
        assert client.get(API + "/session").status_code == 401
    with pytest.raises(SessionError) as ended:
        load_session(db, granted.token, clock=clock)
    assert ended.value.code == "INVALID_SESSION"


def test_ls_a_directory_required_session_is_refused_while_the_directory_is_unreachable(
    db, cast, clock, runtime, admin_engine
):
    """Fail closed: an hour away and the directory cannot answer. The request is refused, the
    verification is put back as it was, so the claim never stands in for a yes, and nothing is
    revoked: once the directory answers again, the same session goes on."""
    from test_directory_store import _session

    stand_in = StandIn(directory_key(), now=lambda: clock.value.timestamp())
    settings = DirectoryConfig(RING, "https://app.example", stand_in.client())
    provider, session, granted = _session(db, settings, cast, clock, stand_in)
    away(admin_engine, provider, session, clock, timedelta(hours=1))
    before = verified_at(admin_engine, session)
    stand_in.refresh_status, stand_in.refresh_body = 503, {"error": "temporarily_unavailable"}
    with directory_client(db, runtime, settings, granted) as client:
        back = client.get(API + "/session")
        assert back.status_code == 403, back.text
        assert back.json()["code"] == "DIRECTORY_REQUIRED"
        assert verified_at(admin_engine, session) == before
        stand_in.refresh_status, stand_in.refresh_body = 200, None
        assert client.get(API + "/session").status_code == 200
    assert len(refreshes(stand_in)) == 2


def test_ls_two_requests_back_after_an_hour_call_the_directory_once(
    db, cast, clock, runtime, admin_engine
):
    """Two requests arrive together after an hour away: one claims the recheck and calls the
    directory, and the other reads the row as the claim left it, as a renewal that loses the
    claim does, so the refresh token is presented once and both load."""
    from test_directory_store import _session

    stand_in = StandIn(directory_key(), now=lambda: clock.value.timestamp())
    original = stand_in.handle

    def slow(request):
        if b"refresh_token" in request.content:
            time.sleep(0.6)
        return original(request)

    stand_in.handle = slow
    settings = DirectoryConfig(RING, "https://app.example", stand_in.client())
    provider, session, granted = _session(db, settings, cast, clock, stand_in)
    away(admin_engine, provider, session, clock, timedelta(hours=1))
    start = Barrier(2)

    def back():
        start.wait(timeout=5)
        return store.load_rechecked(runtime, settings, granted.token)

    with ThreadPoolExecutor(max_workers=2) as pool:
        loaded = [f.result(timeout=20) for f in [pool.submit(back), pool.submit(back)]]
    assert [item.session_id for item in loaded] == [session.session_id] * 2
    assert len(refreshes(stand_in)) == 1


def test_ls_a_page_load_rechecks_a_directory_required_session_back_after_an_hour(
    db, cast, clock, runtime, admin_engine, built
):
    """The console shell and the sign-in factor's pages load the session as the API does, so a
    person who comes back by reloading the page keeps it too."""
    from test_directory_store import _session

    stand_in = StandIn(directory_key(), now=lambda: clock.value.timestamp())
    settings = DirectoryConfig(RING, "https://app.example", stand_in.client())
    provider, session, granted = _session(db, settings, cast, clock, stand_in)
    away(admin_engine, provider, session, clock, timedelta(hours=1))
    with directory_client(db, runtime, settings, granted) as client:
        client.follow_redirects = False
        shell = client.get("/activity")
        assert shell.status_code == 200, shell.headers.get("location")
        assert len(refreshes(stand_in)) == 1


def test_ls_a_session_owing_its_second_factor_stands_fifteen_minutes(db, humans):
    clock, _, codes = enrolled(db, humans)
    assert PENDING_LIFETIME == timedelta(minutes=15)
    start = clock.value
    unverified = issue_session(db, humans[0], clock=clock)
    verified = issue_session(db, humans[0], clock=clock)
    assert unverified.mfa_required and verified.mfa_required
    assert unverified.expires_at == verified.expires_at == start + PENDING_LIFETIME
    pending = load_session(db, verified.token, clock=clock, allow_pending_mfa=True)
    assert pending.expires_at == start + PENDING_LIFETIME and not pending.renewed
    # Verifying the factor rotates the session; the next load extends it to a full one.
    assert mfa.verify_factor(db, pending, MFA_RING, codes[0], clock=clock)
    clock.value = start + timedelta(minutes=8)
    full = load_session(db, verified.token, clock=clock)
    assert full.renewed and full.expires_at == clock.value + SESSION_LIFETIME
    # The one never verified is gone after fifteen minutes, as every session once was.
    clock.value = start + PENDING_LIFETIME + timedelta(seconds=1)
    with pytest.raises(SessionError) as ended:
        load_session(db, unverified.token, clock=clock, allow_pending_mfa=True)
    assert ended.value.code == "INVALID_SESSION"


def test_ls_the_database_refuses_a_session_or_credential_longer_than_two_days(
    db, cast, clock, admin_engine, seeded
):
    identity, (granted,) = issued(db, cast, clock)
    row = {
        "t": identity.tenant_id,
        "p": identity.principal_id,
        "c": identity.credential_id,
        "k": identity.kind,
        "ce": identity.expires_at + timedelta(days=1),
        "n": clock.value,
    }
    insert = text(
        "INSERT INTO execbound.human_sessions(tenant_id,session_id,principal_id,credential_id,"
        "kind,credential_expires_at,token_hash,csrf_hash,created_at,expires_at) "
        "VALUES(:t,:s,:p,:c,:k,:ce,:th,:ch,:n,:e)"
    )
    digest = "a" * 64
    with admin_engine.begin() as conn:
        conn.execute(
            insert,
            {
                **row,
                "s": uuid4(),
                "th": "b" * 64,
                "ch": digest,
                "e": clock.value + timedelta(days=2),
            },
        )
    with pytest.raises(DBAPIError) as refused:
        with admin_engine.begin() as conn:
            conn.execute(
                insert,
                {
                    **row,
                    "s": uuid4(),
                    "th": "c" * 64,
                    "ch": digest,
                    "e": clock.value + timedelta(days=2, minutes=1),
                },
            )
    assert type(refused.value.orig).__name__ == "CheckViolation"

    # The credential function bounds its lifetime to the same two days.
    def credential(lifetime):
        with db.transaction(cast["tenant"]) as conn:
            conn.execute(
                text("SELECT execbound.sign_in_credential(:p,:c,:h,'password',:i,:e)"),
                {
                    "p": cast["second"],
                    "c": uuid4(),
                    "h": "d" * 64,
                    "i": clock.value,
                    "e": clock.value + lifetime,
                },
            )

    credential(timedelta(days=2))
    with pytest.raises(DBAPIError, match="INVALID_LIFETIME"):
        credential(timedelta(days=2, minutes=1))


def test_ls_an_account_session_opens_for_twelve_hours_inside_two_days(db, admin_engine, seeded):
    grant, current, _, _ = member_pair(db, admin_engine, seeded)
    with admin_engine.begin() as conn:
        opened = (
            conn.execute(
                text(
                    "SELECT created_at, expires_at, absolute_expires_at "
                    "FROM execbound.account_sessions WHERE session_id=:s"
                ),
                {"s": grant.session_id},
            )
            .mappings()
            .one()
        )
    # `created_at` defaults to the statement's own time, a few milliseconds before `p_now`.
    skew = timedelta(seconds=5)
    assert abs(opened["expires_at"] - opened["created_at"] - timedelta(hours=12)) < skew
    assert abs(opened["absolute_expires_at"] - opened["created_at"] - timedelta(days=2)) < skew
    # A touch extends it by the same twelve hours, never past the absolute end.
    load_session(db, grant.token)
    with admin_engine.begin() as conn:
        after = (
            conn.execute(
                text(
                    "SELECT created_at, expires_at, absolute_expires_at "
                    "FROM execbound.account_sessions WHERE session_id=:s"
                ),
                {"s": grant.session_id},
            )
            .mappings()
            .one()
        )
    assert after["expires_at"] - after["created_at"] > timedelta(hours=11)
    assert after["expires_at"] <= after["absolute_expires_at"]


def switched_rows(admin_engine, tenant, session_id):
    with admin_engine.begin() as conn:
        return (
            conn.execute(
                text(
                    "SELECT created_at, expires_at FROM execbound.human_sessions "
                    "WHERE tenant_id=:t AND session_id=:s"
                ),
                {"t": tenant, "s": session_id},
            )
            .mappings()
            .one()
        )


def test_ls_a_switch_that_owes_the_factor_stands_fifteen_minutes(db, admin_engine, seeded):
    """The destination starts without assurance when the source's verification is older than
    the step-up window, so it owes the factor and is never extended."""
    from test_console_api_step_up import stale
    from test_workspace_switching import verified_pair

    from execbound import workspaces

    a, b = seeded["tenants"]
    grant, current, _, _, _ = verified_pair(db, admin_engine, seeded)
    stale(admin_engine, a, current.session_id, minutes=40)
    switched = workspaces.switch_workspace(db, current, grant.account_token, b)
    assert switched.mfa_required
    row = switched_rows(admin_engine, b, switched.session_id)
    assert row["expires_at"] - row["created_at"] == PENDING_LIFETIME
    pending = load_session(db, switched.token, allow_pending_mfa=True)
    assert pending.mfa_required and not pending.renewed
    assert switched_rows(admin_engine, b, switched.session_id)["expires_at"] == row["expires_at"]


def test_ls_a_carried_switch_reaches_twelve_hours_on_its_next_load(db, admin_engine, seeded):
    from test_console_api_step_up import stale
    from test_workspace_switching import verified_pair

    from execbound import workspaces

    a, b = seeded["tenants"]
    grant, current, _, _, _ = verified_pair(db, admin_engine, seeded)
    stale(admin_engine, a, current.session_id, minutes=10)
    switched = workspaces.switch_workspace(db, current, grant.account_token, b)
    assert not switched.mfa_required
    row = switched_rows(admin_engine, b, switched.session_id)
    assert row["expires_at"] - row["created_at"] == PENDING_LIFETIME
    loaded = load_session(db, switched.token)
    assert loaded.renewed
    row = switched_rows(admin_engine, b, switched.session_id)
    skew = timedelta(seconds=10)
    assert abs(row["expires_at"] - row["created_at"] - SESSION_LIFETIME) < skew


def test_ls_a_session_opened_before_the_migration_keeps_its_end(db, cast, clock, monkeypatch):
    """Rows written under 0099's bounds, a fifteen-minute expiry, load until it and no longer."""
    monkeypatch.setattr(sessions, "SESSION_LIFETIME", timedelta(minutes=15))
    start = clock.value
    _, (used, idle) = issued(db, cast, clock, 2)
    monkeypatch.undo()
    clock.value = start + timedelta(minutes=14)
    assert load_session(db, used.token, clock=clock).session_id == used.session_id
    # The one not read before its own end is refused at it, whatever the new limit would say.
    clock.value = start + timedelta(minutes=16)
    with pytest.raises(SessionError) as ended:
        load_session(db, idle.token, clock=clock)
    assert ended.value.code == "INVALID_SESSION"


def test_ls_the_account_cookie_lives_as_long_as_the_sign_in(db, cast, clock):
    _, (granted,) = issued(db, cast, clock)
    config = HumanConfig("http://127.0.0.1", TokenKeys("state-v1", {"state-v1": b"k" * 32}))
    grant = replace(granted, account_token="as1.token", account_bound=True)
    response = _session_cookies(Response(), config, SimpleNamespace(clock=clock), grant)
    cookies = response.headers.getlist("set-cookie")
    account = next(c for c in cookies if c.startswith(config.cookie("account") + "="))
    assert "Max-Age=172800" in account


# ---- the migration ---------------------------------------------------------------------------


def migration():
    path = Path(__file__).parents[1] / "migrations" / "versions" / f"{TARGET}.py"
    spec = importlib.util.spec_from_file_location(TARGET, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def catalog(conn):
    """Each patched function's definition and ACL, and the table's constraint, as held."""
    functions = {
        name: (definition, acl)
        for name, definition, acl in conn.execute(
            text(
                "SELECT p.proname, pg_get_functiondef(p.oid), CAST(p.proacl AS text) "
                "FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace "
                "WHERE n.nspname = 'execbound' AND p.proname = ANY(:names)"
            ),
            {"names": list(PATCHED + UNCHANGED + ADDED)},
        ).all()
    }
    check = conn.execute(
        text(
            "SELECT pg_get_constraintdef(oid), convalidated FROM pg_constraint "
            "WHERE conrelid = 'execbound.human_sessions'::regclass "
            "AND conname = 'human_sessions_check'"
        )
    ).one()
    return functions, tuple(check)


def test_ls_the_migration_downgrade_restores_every_interval(admin_engine):
    # Later migrations move the head past this one, so the test holds to its place in history.
    history = ScriptDirectory.from_config(alembic_config()).iterate_revisions(
        database.SCHEMA_REVISION, "base"
    )
    assert TARGET in {script.revision for script in history}
    assert migration().down_revision == BEFORE
    empty_schema(admin_engine)
    config = alembic_config()
    command.downgrade(config, BEFORE)
    try:
        with admin_engine.connect() as conn:
            before_functions, before_check = catalog(conn)
        # 0082's downgrade anchors on this text, and it occurs once in the parent's definition.
        assert before_functions["account_session_open"][0].count(OPEN_ANCHOR) == 1
        command.upgrade(config, TARGET)
        with admin_engine.connect() as conn:
            functions, check = catalog(conn)
        assert set(before_functions) == set(PATCHED + UNCHANGED)
        assert set(functions) == set(PATCHED + UNCHANGED + ADDED)
        for name in UNCHANGED:
            assert functions[name] == before_functions[name], name
        for name in ADDED:
            assert "execbound_app=X/execbound_owner" in functions[name][1], name
        for name in PATCHED:
            assert functions[name][1] == before_functions[name][1], name
            assert functions[name][0] != before_functions[name][0], name
        assert "interval '2 days'" in functions["sign_in_credential"][0]
        assert "interval '2 days'" in functions["directory_sign_in"][0]
        assert "interval '12 hours'" in functions["account_session_touch"][0]
        assert "interval '15 minutes'" in functions["account_switch"][0]
        assert "p_now+interval '12 hours'" in functions["account_session_open"][0]
        assert "p_now+interval '2 days'" in functions["account_session_open"][0]
        assert "'2 days'" in check[0] and check[1] is True
        assert check != before_check
        command.downgrade(config, BEFORE)
        with admin_engine.connect() as conn:
            restored_functions, restored_check = catalog(conn)
        assert restored_functions == before_functions
        assert restored_check == before_check
        assert restored_functions["account_session_open"][0].count(OPEN_ANCHOR) == 1
    finally:
        empty_schema(admin_engine)
        command.upgrade(config, "head")


def test_ls_the_downgrade_ends_a_session_that_would_break_the_old_ceiling(
    db, cast, clock, admin_engine, monkeypatch
):
    """A session longer than eight hours is revoked and cut back before the old check returns."""
    config = alembic_config()
    monkeypatch.setattr(sessions, "SESSION_LIFETIME", timedelta(hours=30))
    _, (long,) = issued(db, cast, clock)
    monkeypatch.setattr(sessions, "SESSION_LIFETIME", timedelta(minutes=15))
    _, (short,) = issued(db, cast, clock)
    monkeypatch.undo()
    command.downgrade(config, BEFORE)
    try:
        with admin_engine.begin() as conn:
            conn.execute(text("SET LOCAL row_security = off"))
            rows = {
                row["session_id"]: row
                for row in conn.execute(
                    text(
                        "SELECT session_id, created_at, expires_at, revoked_at "
                        "FROM execbound.human_sessions"
                    )
                ).mappings()
            }
        cut = rows[long.session_id]
        assert cut["revoked_at"] is not None
        assert cut["expires_at"] == cut["created_at"] + timedelta(hours=8)
        assert rows[short.session_id]["revoked_at"] is None
        assert rows[short.session_id]["expires_at"] == rows[short.session_id]["created_at"] + (
            timedelta(minutes=15)
        )
    finally:
        command.upgrade(config, "head")
