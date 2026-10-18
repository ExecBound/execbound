# SPDX-License-Identifier: AGPL-3.0-only
"""MC13, MC14, MC15 and MC22: reporting sources minted, read, rotated and revoked from the
console API (#678).

`POST /monitor/sources` registers one Tines story and answers its reporting token once, with
`Cache-Control: no-store` set by the route itself; `GET /monitor/sources/{source_id}` reads a
source and never its token; `/rotate` mints a replacement and keeps the previous token for a
bounded grace; `/revoke` stops every token at once. Every route is an administrator's, behind
the session, the exact Origin and CSRF; minting, rotating and revoking ask for a recently
verified factor and refuse a personal access token. Minting and rotation answer
`CONNECT_UNAVAILABLE` wherever the deployment has not configured console connect, so console
minting is never live where console connect is not; reading and revoking a source made earlier
still work. A token lives 1, 7 or 30 days. Real PostgreSQL; nothing here touches the audit
chain.
"""

import hashlib
import json
import re
import secrets
import typing
from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import uuid4

import pytest
from console_api_fixtures import (
    API,
    ORIGIN,
    assert_no_secrets,
    console_client,
    console_config,
    every_log_line,
    refusals,
)
from fastapi.testclient import TestClient
from secret_shapes import AGENT_TOKEN, FREE_TEXT, FREE_TEXT_IDS
from space_fixtures import make_space, seat
from sqlalchemy import text
from test_console_api_monitoring_connect import collector as collector
from test_console_api_monitoring_connect import configured, stepped_down
from test_console_api_step_up import VERIFY, step
from test_console_api_tokens import auth, bearer, minted, post
from test_execution import provision_identity
from test_execution import registry as registry
from test_execution import world as world
from test_human_surface import credential, form_values
from test_monitor_connect_store import every_text
from test_protected_path import connector as connector
from test_protected_path import live_provider as live_provider
from test_runtime import runtime as runtime

import execbound.app as application
from execbound import mfa
from execbound.monitoring import store as monitor_store
from execbound.monitoring.models import ObservationEvent
from execbound.replay.verify import ReplayValidationError, reject_secrets
from execbound.surfaces.console_api import monitoring_sources as sources_api
from execbound.surfaces.human import HumanConfig, ScoutConfig
from execbound.surfaces.tokens import TokenKeys

pytestmark = pytest.mark.integration

SOURCES = API + "/monitor/sources"
CONNECT = API + "/monitor/connect"
ZERO = "00000000-0000-0000-0000-000000000000"
# A value no answer or log line may ever repeat.
SENTINEL = "SENTINEL-console-source-field-41c9e2"
MINT = {
    "label": "Disable a user",
    "story_id": "story-41",
    "lifetime_days": 30,
    "heartbeat_seconds": 300,
}


def one(source):
    return SOURCES + f"/{source}"


def rotate(source):
    return SOURCES + f"/{source}/rotate"


def revoke(source):
    return SOURCES + f"/{source}/revoke"


ROUTES = [
    (SOURCES, "POST"),
    (one(ZERO), "GET"),
    (rotate(ZERO), "POST"),
    (revoke(ZERO), "POST"),
]
STEPPED = (SOURCES, rotate(ZERO), revoke(ZERO))


def fenced(conn, tenant):
    conn.execute(text("SELECT set_config('execbound.tenant_id', :t, true)"), {"t": str(tenant)})


def source_row(admin_engine, tenant, source):
    with admin_engine.connect() as conn:
        return dict(
            conn.execute(
                text(
                    "SELECT * FROM execbound.monitor_sources "
                    "WHERE tenant_id = :t AND source_id = :s"
                ),
                {"t": tenant, "s": source},
            )
            .mappings()
            .one()
        )


def sources(admin_engine, tenant):
    with admin_engine.connect() as conn:
        return conn.execute(
            text("SELECT count(*) FROM execbound.monitor_sources WHERE tenant_id = :t"),
            {"t": tenant},
        ).scalar_one()


def chain(admin_engine, tenant):
    with admin_engine.connect() as conn:
        return (
            conn.execute(
                text(
                    "SELECT kind FROM execbound.audit_events WHERE tenant_id = :t ORDER BY sequence"
                ),
                {"t": tenant},
            )
            .scalars()
            .all()
        )


def heartbeat(story_id, event_id=None):
    return {
        "version": 1,
        "event_id": event_id or f"heartbeat-{uuid4()}",
        "story_id": story_id,
        "occurred_at": datetime.now(UTC).isoformat(),
        "kind": "heartbeat",
    }


def report(client, token, story_id):
    """One heartbeat posted to the intake with a source token, as a Tines story sends it."""
    return client.client.post(
        "/v1/monitor/events",
        content=json.dumps(heartbeat(story_id)).encode(),
        headers={"Authorization": "Bearer " + token, "Content-Type": "application/json"},
    )


def later(world, hours=2):
    return world["clock"].now() + timedelta(hours=hours)


def stored_source(db, world, **changes):
    """A source made through the store, as the command line makes one."""
    return monitor_store.create_source(
        db,
        world["admin"],
        label=changes.get("label", "Command line story"),
        story_id=changes.get("story_id", "story-cli"),
        expires_at=world["clock"].now() + timedelta(hours=2),
        clock=world["clock"],
    )


def test_mc13_every_source_route_is_an_administrators(db, runtime, admin_engine, world, collector):
    with console_client(
        db, runtime, admin_engine, world["human"], config=configured(collector)
    ) as approver:
        for path, method in ROUTES:
            response = approver.get(path) if method == "GET" else approver.post(path, MINT)
            assert (response.status_code, response.json()["code"]) == (403, "FORBIDDEN"), path
    assert sources(admin_engine, world["admin"].tenant_id) == 0


@pytest.mark.parametrize("path,method", ROUTES)
def test_mc13_every_source_route_refuses_a_bearer_credential_and_a_missing_session(
    db, runtime, seeded, admin_engine, world, path, method
):
    results = refusals(db, runtime, seeded, admin_engine, world, path, method)
    assert results["bearer"].status_code == 403 and results["audited"] == 1, path
    assert results["no_session"].status_code == 401, path


def test_mc13_every_source_change_needs_the_token_and_the_exact_origin(
    db, runtime, admin_engine, world, collector
):
    source = stored_source(db, world)
    with console_client(
        db, runtime, admin_engine, world["admin"], config=configured(collector)
    ) as client:
        for path, body in (
            (SOURCES, MINT),
            (rotate(source.source_id), {"lifetime_days": 7, "grace_minutes": 10}),
            (revoke(source.source_id), {}),
        ):
            missing = client.post(path, body, csrf=None)
            assert (missing.status_code, missing.json()["code"]) == (403, "INVALID_CSRF"), path
            elsewhere = client.post(path, body, origin="https://elsewhere.example")
            assert elsewhere.status_code == 403, path
    row = source_row(admin_engine, world["admin"].tenant_id, source.source_id)
    assert (row["active"], row["rotated_at"]) == (True, None)
    assert sources(admin_engine, world["admin"].tenant_id) == 1


def test_mc13_minting_rotating_and_revoking_ask_for_a_recent_factor(
    db, runtime, admin_engine, world, collector
):
    tenant = world["admin"].tenant_id
    source = stored_source(db, world)
    with stepped_down(db, runtime, admin_engine, world, collector) as (client, seed):
        before = source_row(admin_engine, tenant, source.source_id)
        for path in STEPPED:
            refused = client.post(path, {})
            assert (refused.status_code, refused.json()["code"]) == (401, "MFA_REQUIRED"), path
        refused = client.post(SOURCES, MINT)
        assert refused.json()["code"] == "MFA_REQUIRED"
        assert sources(admin_engine, tenant) == 1
        assert source_row(admin_engine, tenant, source.source_id) == before
        # Reading a source asks for nothing.
        assert client.get(one(source.source_id)).status_code == 200
        verified = client.post(VERIFY, {"code": mfa.totp(seed, step(runtime))})
        assert verified.status_code == 200, verified.text
        client.csrf = verified.json()["csrf_token"]
        assert client.post(SOURCES, MINT).status_code == 201
        rotated = client.post(rotate(source.source_id), {"lifetime_days": 1, "grace_minutes": 0})
        assert rotated.status_code == 200, rotated.text
        assert client.post(revoke(source.source_id), {}).status_code == 200


def test_mc13_a_token_may_read_a_source_but_never_mint_rotate_or_revoke(
    db, runtime, admin_engine, world, collector
):
    source = stored_source(db, world)
    token = minted(runtime, world)
    with console_client(
        db, runtime, admin_engine, world["admin"], config=configured(collector)
    ) as console:
        with bearer(console, token) as client:
            for path, body in (
                (SOURCES, MINT),
                (rotate(source.source_id), {"lifetime_days": 7, "grace_minutes": 10}),
                (revoke(source.source_id), {}),
            ):
                refused = post(client, path, token, body)
                assert (refused.status_code, refused.json()["code"]) == (
                    403,
                    "TOKEN_NOT_ALLOWED",
                ), path
            read = client.get(one(source.source_id), headers=auth(token))
            assert read.status_code == 200, read.text
            assert read.json()["source_id"] == str(source.source_id)
    row = source_row(admin_engine, world["admin"].tenant_id, source.source_id)
    assert (row["active"], row["rotated_at"]) == (True, None)
    assert sources(admin_engine, world["admin"].tenant_id) == 1


def test_mc14_a_minted_token_is_shown_once_and_reports_for_its_story_only(
    db, runtime, admin_engine, world, collector
):
    tenant = world["admin"].tenant_id
    with console_client(
        db, runtime, admin_engine, world["admin"], config=configured(collector)
    ) as client:
        before = chain(admin_engine, tenant)
        created = client.post(SOURCES, MINT)
        assert created.status_code == 201, created.text
        assert created.headers["cache-control"] == "no-store"
        minted_source = created.json()
        token = minted_source["token"]
        assert set(minted_source) == {
            "source_id",
            "story_id",
            "label",
            "token",
            "expires_at",
            "heartbeat_seconds",
            "previous_valid_until",
            "intake_url",
        }
        assert token.startswith(f"mo1.{tenant}.{minted_source['source_id']}.")
        assert (minted_source["story_id"], minted_source["label"]) == ("story-41", "Disable a user")
        assert minted_source["heartbeat_seconds"] == 300
        assert minted_source["previous_valid_until"] is None
        assert minted_source["intake_url"] == ORIGIN + "/v1/monitor/events"
        expires = datetime.fromisoformat(minted_source["expires_at"])
        assert expires - world["clock"].now() == timedelta(days=30)
        # The answer's one secret is the token.
        with pytest.raises(ReplayValidationError):
            reject_secrets(minted_source)
        reject_secrets({key: value for key, value in minted_source.items() if key != "token"})
        # Every read of it afterwards carries the source and never the token.
        snapshot = client.get(API + "/monitor")
        read = client.get(one(minted_source["source_id"]))
        assert read.status_code == 200, read.text
        for answer in (snapshot, read):
            assert token not in answer.text
            assert_no_secrets(answer)
        assert read.json()["coverage"] == "No heartbeat"
        assert report(client, token, "story-41").status_code == 202
        refused = report(client, token, "story-42")
        assert refused.status_code == 401
        assert client.get(one(minted_source["source_id"])).json()["coverage"] == "Reporting"
    row = source_row(admin_engine, tenant, minted_source["source_id"])
    assert row["created_by"] == world["admin"].principal_id
    assert row["expires_at"] == expires
    # Minting appends nothing to the audit chain.
    assert chain(admin_engine, tenant) == before


def test_mc20_no_source_token_is_in_a_table_a_log_line_or_an_audit_payload(
    db, runtime, admin_engine, world, collector
):
    """A token minted and one rotated from the console, each then used at the intake for a
    heartbeat and for an event the intake stores, are in no table but as their SHA-256, in no
    log line and in no audit payload: neither whole nor the secret part after the selectors.
    The log lines are every logger's at every level, and ExecBound's own as a deployment writes
    them, field values included (`every_log_line`)."""
    tenant = world["admin"].tenant_id
    with (
        console_client(
            db, runtime, admin_engine, world["admin"], config=configured(collector)
        ) as client,
        every_log_line() as logged,
    ):
        first = client.post(SOURCES, MINT).json()
        second = client.post(
            rotate(first["source_id"]), {"lifetime_days": 7, "grace_minutes": 10}
        ).json()
        for minted_source in (first, second):
            assert report(client, minted_source["token"], "story-41").status_code == 202
            # A heartbeat stores nothing, so an event the intake keeps is posted too.
            stored = client.client.post(
                "/v1/monitor/events",
                content=json.dumps(
                    {
                        "version": 1,
                        "event_id": f"result-{uuid4()}",
                        "story_id": "story-41",
                        "occurred_at": datetime.now(UTC).isoformat(),
                        "kind": "tool_result",
                        "action": "identity.disable",
                        "target_ref": "lab-user-17",
                        "outcome": "success",
                    }
                ).encode(),
                headers={
                    "Authorization": "Bearer " + minted_source["token"],
                    "Content-Type": "application/json",
                },
            )
            assert stored.status_code == 202, stored.text
            assert stored.json()["observation_id"] is not None
        lines = logged()
    tokens = [first["token"], second["token"]]
    sought = tokens + [token.rsplit(".", 1)[1] for token in tokens]
    assert [
        (table, column)
        for table, column, value in every_text(admin_engine)
        if any(part in value for part in sought)
    ] == []
    # Each half of the capture holds ExecBound's own intake line with the value of its field,
    # the half that is handed every record as well as the one the formatter writes.
    assert logged.holds("monitor.intake", first["source_id"])
    assert not any(part in lines for part in sought)
    with admin_engine.connect() as conn:
        payloads = json.dumps(
            conn.execute(
                text("SELECT payload FROM execbound.audit_events WHERE tenant_id = :t"),
                {"t": tenant},
            )
            .scalars()
            .all(),
            default=str,
        )
    assert not any(part in payloads for part in sought)
    # The database holds each token's digest, which is how the intake knew them.
    row = source_row(admin_engine, tenant, first["source_id"])
    assert row["token_hash"] == hashlib.sha256(first["token"].encode()).hexdigest()
    assert row["current_token_hash"] == hashlib.sha256(second["token"].encode()).hexdigest()
    assert row["previous_token_hash"] == hashlib.sha256(first["token"].encode()).hexdigest()


@pytest.mark.parametrize(
    "body,fields",
    [
        ({**MINT, "lifetime_days": 2}, ["lifetime_days"]),
        ({**MINT, "lifetime_days": 90}, ["lifetime_days"]),
        ({**MINT, "lifetime_days": "30"}, ["lifetime_days"]),
        ({**MINT, "lifetime_days": True}, ["lifetime_days"]),
        ({**MINT, "heartbeat_seconds": 30}, ["heartbeat_seconds"]),
        ({**MINT, "heartbeat_seconds": 60}, ["heartbeat_seconds"]),
        ({**MINT, "heartbeat_seconds": 120}, ["heartbeat_seconds"]),
        ({**MINT, "story_id": "story 41"}, ["story_id"]),
        ({**MINT, "story_id": AGENT_TOKEN}, ["story_id"]),
        ({**MINT, "label": ""}, ["label"]),
        ({**MINT, "label": "   "}, ["label"]),
        ({**MINT, "label": "line\nbreak"}, ["label"]),
        ({key: value for key, value in MINT.items() if key != "lifetime_days"}, ["lifetime_days"]),
    ],
    ids=[
        "two-days",
        "ninety-days",
        "text-days",
        "true-days",
        "thirty-seconds",
        "one-minute",
        "two-minutes",
        "story-space",
        "story-credential",
        "empty-label",
        "blank-label",
        "label-newline",
        "no-lifetime",
    ],
)
def test_mc14_a_malformed_source_is_refused_by_field_with_nothing_written(
    db, runtime, admin_engine, world, collector, body, fields
):
    with console_client(
        db, runtime, admin_engine, world["admin"], config=configured(collector)
    ) as client:
        refused = client.post(SOURCES, body)
        assert (refused.status_code, refused.json()["code"]) == (400, "INVALID_BODY")
        assert refused.json()["fields"] == fields
    assert sources(admin_engine, world["admin"].tenant_id) == 0


@pytest.mark.parametrize("value", FREE_TEXT, ids=FREE_TEXT_IDS)
def test_mc14_a_label_shaped_like_a_secret_is_refused_and_never_repeated(
    db, runtime, admin_engine, world, collector, value
):
    with (
        console_client(
            db, runtime, admin_engine, world["admin"], config=configured(collector)
        ) as client,
        every_log_line() as logged,
    ):
        refused = client.post(SOURCES, {**MINT, "label": value})
        assert (refused.status_code, refused.json()["code"]) == (400, "INVALID_BODY")
        assert refused.json()["fields"] == ["label"]
        assert value not in refused.text
        lines = logged()
    assert logged.holds("request.completed")
    assert value not in lines
    assert sources(admin_engine, world["admin"].tenant_id) == 0


ECHOES = [
    (
        SOURCES,
        {
            "label": SENTINEL,
            "story_id": SENTINEL + " x",
            "lifetime_days": SENTINEL,
            "heartbeat_seconds": SENTINEL,
        },
    ),
    (SOURCES, {**MINT, "unknown": SENTINEL}),
    ("rotate", {"lifetime_days": SENTINEL, "grace_minutes": SENTINEL}),
    ("rotate", {"lifetime_days": 7, "grace_minutes": 10, "unknown": SENTINEL}),
    ("revoke", {"unknown": SENTINEL}),
]


def test_mc14_a_malformed_body_never_echoes_what_it_carried(
    db, runtime, admin_engine, world, collector
):
    source = stored_source(db, world)
    paths = {"rotate": rotate, "revoke": revoke}
    with (
        console_client(
            db, runtime, admin_engine, world["admin"], config=configured(collector)
        ) as client,
        every_log_line() as logged,
    ):
        for path, body in ECHOES:
            target = paths[path](source.source_id) if path in paths else path
            refused = client.post(target, body)
            assert (refused.status_code, refused.json()["code"]) == (400, "INVALID_BODY"), path
            assert SENTINEL not in refused.text, path
        lines = logged()
    assert logged.holds("request.completed")
    assert SENTINEL not in lines
    row = source_row(admin_engine, world["admin"].tenant_id, source.source_id)
    assert (row["active"], row["rotated_at"]) == (True, None)


def test_mc14_a_full_workspace_mints_no_more_sources(db, runtime, admin_engine, world, collector):
    tenant = world["admin"].tenant_id
    with admin_engine.begin() as conn:
        space = conn.execute(
            text("SELECT space_id FROM execbound.spaces WHERE tenant_id = :t"), {"t": tenant}
        ).scalar_one()
        now = datetime.now(UTC)
        for index in range(monitor_store.MAX_SOURCES):
            conn.execute(
                text(
                    "INSERT INTO execbound.monitor_sources (tenant_id, source_id, label, "
                    "story_id, token_hash, created_at, expires_at, heartbeat_seconds, "
                    "rate_window_at, space_id, active, revoked_at) VALUES (:t, :s, :l, :story, "
                    ":h, :now, :expiry, 300, :now, :space, false, :now)"
                ),
                {
                    "t": tenant,
                    "s": uuid4(),
                    "l": f"Filler {index}",
                    "story": f"filler-{index}",
                    "h": f"{index:064x}",
                    "now": now,
                    "expiry": now + timedelta(days=1),
                    "space": space,
                },
            )
    with console_client(
        db, runtime, admin_engine, world["admin"], config=configured(collector)
    ) as client:
        full = client.post(SOURCES, MINT)
        assert (full.status_code, full.json()["code"]) == (409, "SOURCE_CAPACITY")
        assert "token" not in full.json()
    assert sources(admin_engine, tenant) == monitor_store.MAX_SOURCES


def test_mc14_minting_a_story_again_is_refused_and_adds_no_second_source(
    db, runtime, admin_engine, world, collector
):
    """An administrator whose answer was lost and who mints the same story again is told the
    story already has a source in the Space, so they find it among the sources and rotate it
    rather than leave a second one nobody holds a token for. The refusal is its code and its
    sentence: it names no source and carries no token."""
    tenant = world["admin"].tenant_id
    with console_client(
        db, runtime, admin_engine, world["admin"], config=configured(collector)
    ) as client:
        first = client.post(SOURCES, MINT)
        assert first.status_code == 201, first.text
        again = client.post(SOURCES, MINT)
        assert (again.status_code, again.json()["code"]) == (409, "SOURCE_EXISTS")
        assert again.json() == {
            "code": "SOURCE_EXISTS",
            "detail": "This Space already has a reporting source for that story.",
        }
        assert first.json()["token"] not in again.text
        listed = client.get(API + "/monitor").json()["sources"]
        assert [row["source_id"] for row in listed] == [first.json()["source_id"]]
    assert sources(admin_engine, tenant) == 1


def test_mc14_a_story_whose_source_has_kept_its_events_is_added_again_before_it_is_revoked(
    db, runtime, admin_engine, world, collector, monkeypatch
):
    """The console's way back for a story whose source has kept its 10,000 events, which
    rotating does not reset: add the story again while that source stands, then revoke it. In a
    full workspace the add is refused `SOURCE_CAPACITY` and the full source still takes its
    heartbeats; with room it is made, and a further add is refused `SOURCE_EXISTS`."""
    tenant = world["admin"].tenant_id
    room = monitor_store.MAX_SOURCES
    with console_client(
        db, runtime, admin_engine, world["admin"], config=configured(collector)
    ) as client:
        first = client.post(SOURCES, MINT).json()
        with admin_engine.begin() as conn:
            conn.execute(
                text(
                    "UPDATE execbound.monitor_sources SET accepted_count = :events "
                    "WHERE tenant_id = :t AND source_id = :s"
                ),
                {"events": monitor_store.MAX_SOURCE_EVENTS, "t": tenant, "s": first["source_id"]},
            )
        monkeypatch.setattr(monitor_store, "MAX_SOURCES", 1)
        full = client.post(SOURCES, MINT)
        assert (full.status_code, full.json()["code"]) == (409, "SOURCE_CAPACITY")
        assert report(client, first["token"], "story-41").status_code == 202
        monkeypatch.setattr(monitor_store, "MAX_SOURCES", room)
        second = client.post(SOURCES, MINT)
        assert second.status_code == 201, second.text
        third = client.post(SOURCES, MINT)
        assert (third.status_code, third.json()["code"]) == (409, "SOURCE_EXISTS")
        listed = {row["source_id"]: row for row in client.get(API + "/monitor").json()["sources"]}
        assert set(listed) == {first["source_id"], second.json()["source_id"]}
        assert listed[first["source_id"]]["revoked_at"] is None
        assert listed[first["source_id"]]["accepted_count"] == monitor_store.MAX_SOURCE_EVENTS
        # Once the story reports through the new token, the full source is revoked.
        assert report(client, second.json()["token"], "story-41").status_code == 202
        assert client.post(revoke(first["source_id"]), {}).status_code == 200
        assert report(client, first["token"], "story-41").status_code == 401
        assert report(client, second.json()["token"], "story-41").status_code == 202
    assert sources(admin_engine, tenant) == 2


def test_mc14_a_source_is_minted_only_in_a_space_its_creator_may_mint_in(
    db, runtime, admin_engine, world, collector
):
    tenant = world["admin"].tenant_id
    admin = world["admin"]
    with console_client(db, runtime, admin_engine, admin, config=configured(collector)) as client:
        with admin_engine.begin() as conn:
            fenced(conn, tenant)
            other = make_space(conn, tenant, "Customer B", created_by=admin.principal_id)
            archived = make_space(conn, tenant, "Archived", created_by=admin.principal_id)
            conn.execute(
                text("UPDATE execbound.spaces SET archived_at = now() WHERE space_id = :s"),
                {"s": archived},
            )
        # Several spaces and none chosen: the console never guesses.
        unplaced = client.post(SOURCES, MINT)
        assert (unplaced.status_code, unplaced.json()["code"]) == (422, "SPACE_REQUIRED")
        assert client.post(API + "/session/space", {"space_id": str(archived)}).status_code == 200
        closed = client.post(SOURCES, MINT)
        assert (closed.status_code, closed.json()["code"]) == (409, "SPACE_ARCHIVED")
        assert sources(admin_engine, tenant) == 0
        assert client.post(API + "/session/space", {"space_id": str(other)}).status_code == 200
        placed = client.post(SOURCES, MINT)
        assert placed.status_code == 201, placed.text
        assert source_row(admin_engine, tenant, placed.json()["source_id"])["space_id"] == other
        # Narrowed to administering another space, this administrator mints nothing here.
        with admin_engine.begin() as conn:
            fenced(conn, tenant)
            mine = make_space(conn, tenant, "Mine", created_by=admin.principal_id)
            seat(conn, tenant, mine, admin.principal_id, "ADMIN")
            seat(conn, tenant, other, admin.principal_id, "HUMAN_APPROVER")
        narrowed = client.post(SOURCES, {**MINT, "story_id": "story-narrowed"})
        assert (narrowed.status_code, narrowed.json()["code"]) == (403, "FORBIDDEN")
    assert sources(admin_engine, tenant) == 1


def test_mc15_a_source_says_whether_this_administrator_may_change_it(
    db, runtime, admin_engine, world, collector
):
    """An administrator reads every source in the Spaces they see, reviewer seats included, and
    changes only those in a Space they administer: each source, the snapshot's and the read's,
    says which, and the connect options say whether the session's own Space takes a new one, so
    the console offers no change the server refuses."""
    tenant = world["admin"].tenant_id
    admin = world["admin"]
    with admin_engine.begin() as conn:
        fenced(conn, tenant)
        reviewed = make_space(conn, tenant, "Customer B", created_by=admin.principal_id)
        mine = make_space(conn, tenant, "Mine", created_by=admin.principal_id)
    theirs = monitor_store.create_source(
        db, admin, label="Theirs", story_id="story-b", expires_at=later(world), space=reviewed
    )
    ours = monitor_store.create_source(
        db, admin, label="Ours", story_id="story-mine", expires_at=later(world), space=mine
    )
    with console_client(db, runtime, admin_engine, admin, config=configured(collector)) as client:
        with admin_engine.begin() as conn:
            fenced(conn, tenant)
            seat(conn, tenant, mine, admin.principal_id, "ADMIN")
            seat(conn, tenant, reviewed, admin.principal_id, "HUMAN_APPROVER")
        listed = {
            row["label"]: row["administered"]
            for row in client.get(API + "/monitor").json()["sources"]
        }
        assert listed == {"Theirs": False, "Ours": True}
        assert client.get(one(theirs.source_id)).json()["administered"] is False
        assert client.get(one(ours.source_id)).json()["administered"] is True
        # Two Spaces seen and none chosen: nowhere to place a new one until one is chosen.
        assert client.get(CONNECT).json()["placement"] is None
        assert client.post(API + "/session/space", {"space_id": str(reviewed)}).status_code == 200
        assert client.get(CONNECT).json()["placement"] == {
            "space_id": str(reviewed),
            "name": "Customer B",
            "archived": False,
            "administered": False,
        }
        assert client.post(API + "/session/space", {"space_id": str(mine)}).status_code == 200
        assert client.get(CONNECT).json()["placement"] == {
            "space_id": str(mine),
            "name": "Mine",
            "archived": False,
            "administered": True,
        }


def test_mc14_the_options_name_the_one_space_a_narrowed_administrator_writes_in(
    db, runtime, admin_engine, world, collector
):
    """An administrator seated in one Space of several, looking at "All spaces", writes in that
    Space, not the workspace's first: the options name it, and say when it is archived."""
    tenant = world["admin"].tenant_id
    admin = world["admin"]
    with console_client(db, runtime, admin_engine, admin, config=configured(collector)) as client:
        with admin_engine.begin() as conn:
            fenced(conn, tenant)
            theirs = make_space(conn, tenant, "Customer B", created_by=admin.principal_id)
            seat(conn, tenant, theirs, admin.principal_id, "ADMIN")
        assert client.get(CONNECT).json()["placement"] == {
            "space_id": str(theirs),
            "name": "Customer B",
            "archived": False,
            "administered": True,
        }
        placed = client.post(SOURCES, MINT)
        assert placed.status_code == 201, placed.text
        assert source_row(admin_engine, tenant, placed.json()["source_id"])["space_id"] == theirs
        with admin_engine.begin() as conn:
            conn.execute(
                text("UPDATE execbound.spaces SET archived_at = now() WHERE space_id = :s"),
                {"s": theirs},
            )
        assert client.get(CONNECT).json()["placement"]["archived"] is True


def test_mc22_without_console_connect_sources_are_read_and_revoked_but_never_minted(
    db, runtime, admin_engine, world
):
    source = stored_source(db, world)
    tenant = world["admin"].tenant_id
    with console_client(db, runtime, admin_engine, world["admin"]) as client:
        options = client.get(CONNECT)
        assert options.status_code == 200
        assert options.json()["sources"] == "unconfigured"
        assert options.json()["intake_url"] == ORIGIN + "/v1/monitor/events"
        for path, body in (
            (SOURCES, MINT),
            (rotate(source.source_id), {"lifetime_days": 7, "grace_minutes": 10}),
        ):
            refused = client.post(path, body)
            assert (refused.status_code, refused.json()["code"]) == (
                409,
                "CONNECT_UNAVAILABLE",
            ), path
        assert sources(admin_engine, tenant) == 1
        assert source_row(admin_engine, tenant, source.source_id)["rotated_at"] is None
        read = client.get(one(source.source_id))
        assert read.status_code == 200, read.text
        revoked = client.post(revoke(source.source_id), {})
        assert revoked.status_code == 200, revoked.text
        assert revoked.json()["coverage"] == "Disabled"
        assert revoked.json()["revoked_at"] is not None
    assert source_row(admin_engine, tenant, source.source_id)["revoked_by"] == (
        world["admin"].principal_id
    )


def test_mc22_console_connect_makes_sources_available(db, runtime, admin_engine, world, collector):
    with console_client(
        db, runtime, admin_engine, world["admin"], config=configured(collector)
    ) as client:
        options = client.get(CONNECT).json()
        assert (options["tines"], options["sources"]) == ("available", "available")


class At:
    def __init__(self, value):
        self.value = value

    def now(self):
        return self.value


def accepted(db, token, story_id, at):
    """Whether the intake takes one heartbeat from this token at this instant."""
    event = ObservationEvent.model_validate_json(
        json.dumps(heartbeat(story_id) | {"occurred_at": at.isoformat()})
    )
    try:
        monitor_store.ingest(db, token, event, clock=At(at))
    except monitor_store.MonitorError:
        return False
    return True


# How long the console's card waits for a new source's first heartbeat (`SourceWaiting.tsx`).
WAITING = timedelta(minutes=10)


def health(admin_engine, tenant):
    """Each source's heartbeat interval and health, and how many source-health findings exist."""
    with admin_engine.connect() as conn:
        states = conn.execute(
            text(
                "SELECT heartbeat_seconds, health_state FROM execbound.monitor_sources "
                "WHERE tenant_id = :t ORDER BY heartbeat_seconds"
            ),
            {"t": tenant},
        ).all()
        raised = conn.execute(
            text(
                "SELECT count(*) FROM execbound.monitor_findings "
                "WHERE tenant_id = :t AND rule_version = :rule"
            ),
            {"t": tenant, "rule": monitor_store.HEALTH_RULE},
        ).scalar_one()
    return [tuple(state) for state in states], raised


def test_mc16_no_offered_heartbeat_calls_a_new_source_silent_within_ten_minutes_of_its_mint(
    db, runtime, admin_engine, world, collector
):
    """The health pass calls a source that never reported silent twice its heartbeat interval
    after registration. At every heartbeat the console offers, a pass ten minutes after the mint
    finds no new source silent and raises nothing, and that bound is all it holds: a pass a second
    later calls the five-minute source silent and raises its finding. The card's own ten minutes
    start later, when the token dialog closes, so that verdict can come while the card still
    reads, and the card then says no heartbeat came (`SourceWaiting.test.tsx`)."""
    tenant = world["admin"].tenant_id
    offered = typing.get_args(sources_api.CreateSource.model_fields["heartbeat_seconds"].annotation)
    assert offered == (300, 900, 3600)
    with console_client(
        db, runtime, admin_engine, world["admin"], config=configured(collector)
    ) as client:
        for seconds in offered:
            created = client.post(
                SOURCES, {**MINT, "story_id": f"story-{seconds}", "heartbeat_seconds": seconds}
            )
            assert created.status_code == 201, created.text
    minted_at = world["clock"].now()
    monitor_store.evaluate_health(db, world["admin"], clock=At(minted_at + WAITING))
    states, raised = health(admin_engine, tenant)
    assert [seconds for seconds, _ in states] == list(offered)
    assert all(state != "STALE" for _, state in states), states
    assert raised == 0
    monitor_store.evaluate_health(
        db, world["admin"], clock=At(minted_at + WAITING + timedelta(seconds=1))
    )
    states, raised = health(admin_engine, tenant)
    assert [state == "STALE" for _, state in states] == [True, False, False], states
    assert raised == 1


def test_mc14_a_source_registered_every_minute_before_keeps_its_interval(
    db, runtime, admin_engine, world, collector
):
    """The console once offered a heartbeat every minute. A source registered so keeps that
    interval: it is read, rotated from the console and reported through as before, and the health
    pass still holds it to its own minute."""
    tenant = world["admin"].tenant_id
    made = monitor_store.create_source(
        db,
        world["admin"],
        label="Every minute",
        story_id="story-60",
        expires_at=later(world),
        heartbeat_seconds=60,
        clock=world["clock"],
    )
    source_id = str(made.source_id)
    with console_client(
        db, runtime, admin_engine, world["admin"], config=configured(collector)
    ) as client:
        read = client.get(one(source_id))
        assert read.status_code == 200, read.text
        assert read.json()["heartbeat_seconds"] == 60
        rotated = client.post(rotate(source_id), {"lifetime_days": 7, "grace_minutes": 0})
        assert rotated.status_code == 200, rotated.text
        assert rotated.json()["heartbeat_seconds"] == 60
    now = world["clock"].now()
    assert accepted(db, rotated.json()["token"], "story-60", now + timedelta(seconds=1)) is True
    assert source_row(admin_engine, tenant, source_id)["heartbeat_seconds"] == 60
    monitor_store.evaluate_health(db, world["admin"], clock=At(now + timedelta(minutes=3)))
    assert health(admin_engine, tenant) == ([(60, "STALE")], 1)


CONNECT_TS = Path(__file__).resolve().parents[1] / "console/src/components/monitor/connect.ts"


def console_numbers(name):
    """A `export const NAME = [...] as const` list, or `export const NAME = 10_000`, from the
    console's connect copy, as a tuple of its numbers; a name not found fails."""
    found = re.search(
        rf"export const {name} = (\[[^\]]*\]|[0-9_]+)", CONNECT_TS.read_text(encoding="utf-8")
    )
    assert found is not None, name
    return tuple(int(number.replace("_", "")) for number in re.findall(r"[0-9_]+", found[1]))


def test_mc15_the_console_holds_the_servers_source_bounds():
    """The console offers the lifetimes, heartbeats and graces the routes admit, and says a source
    has kept all its events at the store's own limit, so a source card never calls a source full
    that intake still takes events for, or stays silent about one it refuses."""
    admitted = sources_api.CreateSource.model_fields
    graces = sources_api.RotateSource.model_fields["grace_minutes"].annotation
    assert console_numbers("LIFETIMES") == typing.get_args(admitted["lifetime_days"].annotation)
    assert console_numbers("HEARTBEATS") == typing.get_args(
        admitted["heartbeat_seconds"].annotation
    )
    assert console_numbers("GRACES") == typing.get_args(graces)
    assert console_numbers("SOURCE_EVENTS") == (monitor_store.MAX_SOURCE_EVENTS,)


def test_mc15_rotation_keeps_the_previous_token_for_the_grace_and_no_longer(
    db, runtime, admin_engine, world, collector
):
    tenant = world["admin"].tenant_id
    with console_client(
        db, runtime, admin_engine, world["admin"], config=configured(collector)
    ) as client:
        first = client.post(SOURCES, MINT).json()
        rotated = client.post(rotate(first["source_id"]), {"lifetime_days": 7, "grace_minutes": 10})
        assert rotated.status_code == 200, rotated.text
        assert rotated.headers["cache-control"] == "no-store"
        second = rotated.json()
        assert second["source_id"] == first["source_id"] and second["token"] != first["token"]
        assert second["intake_url"] == ORIGIN + "/v1/monitor/events"
        now = world["clock"].now()
        assert datetime.fromisoformat(second["expires_at"]) - now == timedelta(days=7)
        until = datetime.fromisoformat(second["previous_valid_until"])
        assert until - now == timedelta(minutes=10)
        assert token_free(client.get(one(first["source_id"])), first, second)
        # Without a grace the previous token stops at once.
        third = client.post(
            rotate(first["source_id"]), {"lifetime_days": 1, "grace_minutes": 0}
        ).json()
        assert third["previous_valid_until"] is None
    assert accepted(db, first["token"], "story-41", until - timedelta(seconds=1)) is False
    assert accepted(db, second["token"], "story-41", now + timedelta(seconds=1)) is False
    assert accepted(db, third["token"], "story-41", now + timedelta(seconds=1)) is True
    row = source_row(admin_engine, tenant, first["source_id"])
    assert row["rotated_by"] == world["admin"].principal_id


def test_mc15_the_previous_token_reports_until_its_grace_ends(
    db, runtime, admin_engine, world, collector
):
    with console_client(
        db, runtime, admin_engine, world["admin"], config=configured(collector)
    ) as client:
        first = client.post(SOURCES, MINT).json()
        second = client.post(
            rotate(first["source_id"]), {"lifetime_days": 30, "grace_minutes": 30}
        ).json()
    until = datetime.fromisoformat(second["previous_valid_until"])
    assert accepted(db, first["token"], "story-41", until - timedelta(seconds=1)) is True
    assert accepted(db, first["token"], "story-41", until + timedelta(seconds=1)) is False
    assert accepted(db, second["token"], "story-41", until + timedelta(seconds=1)) is True


def token_free(answer, *minted_sources):
    return all(source["token"] not in answer.text for source in minted_sources)


def test_mc15_revocation_refuses_every_token_at_once_and_cannot_be_undone(
    db, runtime, admin_engine, world, collector
):
    tenant = world["admin"].tenant_id
    with console_client(
        db, runtime, admin_engine, world["admin"], config=configured(collector)
    ) as client:
        first = client.post(SOURCES, MINT).json()
        second = client.post(
            rotate(first["source_id"]), {"lifetime_days": 30, "grace_minutes": 60}
        ).json()
        assert report(client, first["token"], "story-41").status_code == 202
        revoked = client.post(revoke(first["source_id"]), {})
        assert revoked.status_code == 200, revoked.text
        assert revoked.json()["coverage"] == "Disabled"
        assert token_free(revoked, first, second)
        for token in (first["token"], second["token"]):
            assert report(client, token, "story-41").status_code == 401
        again = client.post(rotate(first["source_id"]), {"lifetime_days": 7, "grace_minutes": 0})
        assert (again.status_code, again.json()["code"]) == (409, "CONFLICT")
        assert "token" not in again.json()
        twice = client.post(revoke(first["source_id"]), {})
        assert (twice.status_code, twice.json()["code"]) == (409, "CONFLICT")
    row = source_row(admin_engine, tenant, first["source_id"])
    assert row["revoked_by"] == world["admin"].principal_id and row["active"] is False


def test_mc15_a_source_in_a_space_this_administrator_only_reviews_is_seen_but_never_changed(
    db, runtime, admin_engine, world, collector
):
    """An administrator seated as a reviewer in the source's Space and as an administrator in
    another reads the source and neither rotates nor revokes it: each is refused `FORBIDDEN`
    after the step-up, with the source unchanged."""
    tenant = world["admin"].tenant_id
    admin = world["admin"]
    with admin_engine.begin() as conn:
        fenced(conn, tenant)
        reviewed = make_space(conn, tenant, "Customer B", created_by=admin.principal_id)
        mine = make_space(conn, tenant, "Mine", created_by=admin.principal_id)
    theirs = monitor_store.create_source(
        db, admin, label="Theirs", story_id="story-b", expires_at=later(world), space=reviewed
    )
    with console_client(db, runtime, admin_engine, admin, config=configured(collector)) as client:
        with admin_engine.begin() as conn:
            fenced(conn, tenant)
            seat(conn, tenant, mine, admin.principal_id, "ADMIN")
            seat(conn, tenant, reviewed, admin.principal_id, "HUMAN_APPROVER")
        before = source_row(admin_engine, tenant, theirs.source_id)
        assert client.get(one(theirs.source_id)).status_code == 200
        for answer in (
            client.post(rotate(theirs.source_id), {"lifetime_days": 7, "grace_minutes": 0}),
            client.post(revoke(theirs.source_id), {}),
        ):
            assert (answer.status_code, answer.json()["code"]) == (403, "FORBIDDEN")
            assert "token" not in answer.json()
    assert source_row(admin_engine, tenant, theirs.source_id) == before


def test_mc15_a_revocation_answers_what_it_did_from_its_own_transaction(
    db, runtime, admin_engine, world, collector, monkeypatch
):
    """The revocation's answer is read in the transaction that revoked, so a read that would
    fail afterwards, on a dropped connection or a session ended in another tab, cannot answer an
    error for a revocation that took effect."""
    tenant = world["admin"].tenant_id
    with console_client(
        db, runtime, admin_engine, world["admin"], config=configured(collector)
    ) as client:
        minted_source = client.post(SOURCES, MINT).json()

        def unread(*args, **kwargs):
            raise monitor_store.MonitorError()

        monkeypatch.setattr(monitor_store, "source", unread)
        revoked = client.post(revoke(minted_source["source_id"]), {})
    assert revoked.status_code == 200, revoked.text
    assert revoked.json()["revoked_at"] is not None
    assert revoked.json()["coverage"] == "Disabled"
    assert minted_source["token"] not in revoked.text
    assert source_row(admin_engine, tenant, minted_source["source_id"])["active"] is False


def test_mc15_a_source_elsewhere_is_one_that_does_not_exist(
    db, runtime, admin_engine, world, collector, seeded
):
    """Another tenant's source, a source in a space the session does not see, an unknown one
    and a malformed identifier all answer 404 and change nothing."""
    tenant = world["admin"].tenant_id
    other_tenant = seeded["tenants"][1]
    other_admin = provision_identity(admin_engine, db, other_tenant, "ADMIN", datetime.now(UTC))
    foreign = monitor_store.create_source(
        db,
        other_admin,
        label="Foreign",
        story_id="story-foreign",
        expires_at=datetime.now(UTC) + timedelta(hours=1),
    )
    hidden = stored_source(db, world, story_id="story-hidden")
    with console_client(
        db, runtime, admin_engine, world["admin"], config=configured(collector)
    ) as client:
        with admin_engine.begin() as conn:
            fenced(conn, tenant)
            elsewhere = make_space(
                conn, tenant, "Elsewhere", created_by=world["admin"].principal_id
            )
            conn.execute(
                text(
                    "UPDATE execbound.monitor_sources SET space_id = :s "
                    "WHERE tenant_id = :t AND source_id = :id"
                ),
                {"s": elsewhere, "t": tenant, "id": hidden.source_id},
            )
            # A membership narrows what this administrator sees to the spaces they belong to.
            mine = make_space(conn, tenant, "Mine", created_by=world["admin"].principal_id)
            seat(conn, tenant, mine, world["admin"].principal_id, "ADMIN")
        for source in (foreign.source_id, hidden.source_id, uuid4(), "not-a-source"):
            for answer in (
                client.get(one(source)),
                client.post(rotate(source), {"lifetime_days": 7, "grace_minutes": 0}),
                client.post(revoke(source), {}),
            ):
                assert (answer.status_code, answer.json()["code"]) == (404, "NOT_FOUND"), source
    for owner, source in ((other_tenant, foreign.source_id), (tenant, hidden.source_id)):
        row = source_row(admin_engine, owner, source)
        assert (row["active"], row["rotated_at"]) == (True, None)


# A deployment whose configured origin differs from the address a request arrives on in its
# scheme, as behind a proxy that terminates or rewrites TLS: the Host still matches, so the
# request is served, and an intake address built from the request would differ from this one.
CONFIGURED = "http://127.0.0.1:8080"
ARRIVED = "https://127.0.0.1:8080"
FORGED = {
    "X-Forwarded-Host": "attacker.example",
    "X-Forwarded-Proto": "https",
    "X-Forwarded-Port": "8443",
    "Forwarded": "host=attacker.example;proto=https",
}


def test_mc14_the_intake_address_comes_from_the_configured_origin(
    db, runtime, admin_engine, world, collector
):
    """The minting answer and the connect options name the configured origin's intake, never
    one built from the address the request arrived on or from a forwarding header."""
    keys = TokenKeys("state-v1", {"state-v1": secrets.token_bytes(32)})
    config = HumanConfig(CONFIGURED, keys, scout=ScoutConfig(collector=collector[0]))
    app = application.create_app(db, runtime=runtime, human=config)
    with TestClient(app, base_url=ARRIVED, follow_redirects=False) as client:
        _, values = form_values(client.get("/login").text, "/session")
        values["credential"] = credential(admin_engine, world["admin"])
        signed = client.post("/session", data=values, headers={"Origin": CONFIGURED})
        assert signed.status_code == 303, signed.text
        csrf = client.get(API + "/session").json()["csrf_token"]
        created = client.post(
            SOURCES,
            content=json.dumps(MINT).encode(),
            headers={
                **FORGED,
                "Origin": CONFIGURED,
                "X-CSRF-Token": csrf,
                "Content-Type": "application/json",
            },
        )
        options = client.get(CONNECT, headers=FORGED)
    assert created.status_code == 201, created.text
    assert options.status_code == 200, options.text
    for answer in (created, options):
        assert "attacker.example" not in answer.text
        assert answer.json()["intake_url"] == CONFIGURED + "/v1/monitor/events"


def test_mc14_minting_and_rotation_answer_no_store_on_their_own(
    db, runtime, admin_engine, world, collector, monkeypatch
):
    """The two answers that carry a token set `Cache-Control: no-store` themselves, so the
    header holds even if the console's default for every other answer changes."""
    monkeypatch.setattr(application, "_default_no_store", lambda response: None)
    with console_client(
        db, runtime, admin_engine, world["admin"], config=configured(collector)
    ) as client:
        # The default is gone: an ordinary read now carries no directive at all.
        assert "cache-control" not in client.get(CONNECT).headers
        created = client.post(SOURCES, MINT)
        assert created.headers["cache-control"] == "no-store"
        rotated = client.post(
            rotate(created.json()["source_id"]), {"lifetime_days": 7, "grace_minutes": 0}
        )
        assert rotated.headers["cache-control"] == "no-store"


def test_mc14_the_console_options_name_the_intake_for_every_deployment(
    db, runtime, admin_engine, world
):
    with console_client(
        db, runtime, admin_engine, world["admin"], config=console_config()
    ) as client:
        answer = client.get(CONNECT).json()
    assert answer["intake_url"] == ORIGIN + "/v1/monitor/events"
