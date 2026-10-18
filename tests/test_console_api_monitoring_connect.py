# SPDX-License-Identifier: AGPL-3.0-only
"""MC2, MC12 and MC13: connecting Tines and acting on a connection from the console API (#678).

`GET /monitor/connect` says whether console connect is configured. `POST
/monitor/connections/tines` seals a pasted Tines key to the collector's public key; `/key`
replaces it, `/collect` asks for a collection, `/schedule` sets the intervals and `/revoke` stops
collection. Every route is an administrator's behind the session, the exact Origin and CSRF;
connecting, replacing a key and revoking ask for a recently verified factor and refuse a
personal access token, while asking for a collection and changing a schedule do neither. Real
PostgreSQL; no key reaches an answer, a table but its ciphertext, the chain or a log line.
"""

import json
import logging
from contextlib import contextmanager
from datetime import timedelta
from uuid import uuid4

import pytest
from console_api_fixtures import (
    API,
    ORIGIN,
    assert_no_secrets,
    console_client,
    console_config,
    refusals,
)
from secret_shapes import BEARER, FREE_TEXT, FREE_TEXT_IDS
from space_fixtures import make_space
from sqlalchemy import text
from test_console_api_step_up import RING, VERIFY, stale, step
from test_console_api_tokens import auth, bearer, minted, post
from test_execution import registry as registry
from test_execution import world as world
from test_monitor_connect_store import every_text
from test_protected_path import connector as connector
from test_protected_path import live_provider as live_provider
from test_runtime import runtime as runtime

from execbound import mfa
from execbound.monitoring import collection, sealing
from execbound.monitoring import store as monitor_store
from execbound.spaces import default_space
from execbound.surfaces.human import ScoutConfig
from execbound.surfaces.sessions import load_session
from execbound_harness.fake_tines import BASE_URL

pytestmark = pytest.mark.integration

# A key no answer, table but `sealed_ct`, audit payload or log line may ever repeat.
SENTINEL = "SENTINEL-console-route-key-6b2f04"
ZERO = "00000000-0000-0000-0000-000000000000"
CONNECT = API + "/monitor/connect"
TINES = API + "/monitor/connections/tines"
ENTRA_START = API + "/monitor/connections/entra/start"


def key(connection):
    return API + f"/monitor/connections/{connection}/key"


def collect(connection):
    return API + f"/monitor/connections/{connection}/collect"


def schedule(connection):
    return API + f"/monitor/connections/{connection}/schedule"


def revoke(connection):
    return API + f"/monitor/connections/{connection}/revoke"


def egress(connection):
    return API + f"/monitor/connections/{connection}/egress"


ROUTES = [
    (CONNECT, "GET"),
    (TINES, "POST"),
    (key(ZERO), "POST"),
    (collect(ZERO), "POST"),
    (schedule(ZERO), "POST"),
    (revoke(ZERO), "POST"),
    (egress(ZERO), "POST"),
    (ENTRA_START, "POST"),
]
STEPPED = (TINES, key(ZERO), revoke(ZERO), egress(ZERO), ENTRA_START)
UNSTEPPED = (collect(ZERO), schedule(ZERO))
PASTE = {"label": "Synthetic Tines tenant", "base_url": BASE_URL, "api_key": SENTINEL}
# Where a connection or source made now lands for the world's administrator: the tenant's one
# Space, which they administer, by its id too, so the console can tell a placement read before
# the session moved to another Space.
PLACED = {"name": "Default", "archived": False, "administered": True}


def placed(db, world):
    with db.transaction(world["admin"].tenant_id) as conn:
        space = default_space(conn, world["admin"].tenant_id)
    return {"space_id": str(space), **PLACED}


@pytest.fixture
def collector(tmp_path):
    public = sealing.generate(tmp_path / "collector")
    return public, sealing.read_private_file(tmp_path / "collector" / sealing.PRIVATE_FILE)


def configured(collector, **changes):
    return console_config(scout=ScoutConfig(collector=collector[0]), **changes)


def connection_row(admin_engine, tenant, connection):
    with admin_engine.connect() as conn:
        return dict(
            conn.execute(
                text(
                    "SELECT * FROM execbound.monitor_connections "
                    "WHERE tenant_id = :t AND connection_id = :c"
                ),
                {"t": tenant, "c": connection},
            )
            .mappings()
            .one()
        )


def connections(admin_engine, tenant):
    with admin_engine.connect() as conn:
        return conn.execute(
            text("SELECT count(*) FROM execbound.monitor_connections WHERE tenant_id = :t"),
            {"t": tenant},
        ).scalar_one()


def monitoring_events(admin_engine, tenant):
    with admin_engine.connect() as conn:
        return [
            dict(row)
            for row in conn.execute(
                text(
                    "SELECT kind, payload FROM execbound.audit_events WHERE tenant_id = :t "
                    "AND kind LIKE 'monitor.%' ORDER BY sequence"
                ),
                {"t": tenant},
            ).mappings()
        ]


def key_file_connection(db, world):
    return monitor_store.create_connection(
        db,
        world["admin"],
        label="Operator's Tines",
        base_url=BASE_URL,
        key_fingerprint=collection.fingerprint(SENTINEL),
        clock=world["clock"],
    )


def test_mc13_every_route_is_an_administrators(db, runtime, admin_engine, world, collector):
    with console_client(
        db, runtime, admin_engine, world["human"], config=configured(collector)
    ) as approver:
        for path, method in ROUTES:
            response = approver.get(path) if method == "GET" else approver.post(path, {})
            assert (response.status_code, response.json()["code"]) == (403, "FORBIDDEN"), path


@pytest.mark.parametrize("path,method", ROUTES)
def test_mc13_every_route_refuses_a_bearer_credential_and_a_missing_session(
    db, runtime, seeded, admin_engine, world, path, method
):
    results = refusals(db, runtime, seeded, admin_engine, world, path, method)
    assert results["bearer"].status_code == 403 and results["audited"] == 1, path
    assert results["no_session"].status_code == 401, path


def test_mc13_every_change_needs_the_token_and_the_exact_origin(
    db, runtime, admin_engine, world, collector
):
    connection = key_file_connection(db, world)
    with console_client(
        db, runtime, admin_engine, world["admin"], config=configured(collector)
    ) as client:
        for path in (
            TINES,
            key(connection),
            collect(connection),
            schedule(connection),
            egress(connection),
            ENTRA_START,
        ):
            missing = client.post(path, PASTE, csrf=None)
            assert (missing.status_code, missing.json()["code"]) == (403, "INVALID_CSRF"), path
            elsewhere = client.post(path, PASTE, origin="https://elsewhere.example")
            assert elsewhere.status_code == 403, path
        missing = client.post(revoke(connection), {}, csrf=None)
        assert missing.json()["code"] == "INVALID_CSRF"
    assert connection_row(admin_engine, world["admin"].tenant_id, connection)["active"] is True
    assert [
        event["kind"] for event in monitoring_events(admin_engine, world["admin"].tenant_id)
    ] == ["monitor.connection_created"]


@contextmanager
def stepped_down(db, runtime, admin_engine, world, collector):
    """The administrator, signed in with an authenticator whose last verification is more
    than thirty minutes old, on a deployment where console connect is configured for Tines
    and Microsoft Entra."""
    with console_client(
        db, runtime, admin_engine, world["admin"], config=with_entra(collector, mfa=RING)
    ) as client:
        session = load_session(db, client.client.cookies.get("eb_session"), clock=runtime.clock)
        seed = mfa.begin_enrollment(db, session, RING, clock=runtime.clock)
        mfa.confirm_enrollment(
            db, session, RING, mfa.totp(seed, step(runtime)), clock=runtime.clock
        )
        stale(admin_engine, world["admin"].tenant_id, session.session_id)
        runtime.clock.value += timedelta(seconds=30)
        yield client, seed


def test_mc13_connecting_replacing_a_key_and_revoking_ask_for_a_recent_factor(
    db, runtime, admin_engine, world, collector
):
    """Creating a credentialed connection, replacing its key and silencing it ask for the
    step-up before the body is read; asking for a collection and changing a schedule do not."""
    tenant = world["admin"].tenant_id
    with stepped_down(db, runtime, admin_engine, world, collector) as (client, seed):
        before = (connections(admin_engine, tenant), monitoring_events(admin_engine, tenant))
        for path in STEPPED:
            refused = client.post(path, {})
            assert (refused.status_code, refused.json()["code"]) == (401, "MFA_REQUIRED"), path
        refused = client.post(TINES, PASTE)
        assert refused.json()["code"] == "MFA_REQUIRED"
        assert (
            connections(admin_engine, tenant),
            monitoring_events(admin_engine, tenant),
        ) == before
        for path in UNSTEPPED:
            answered = client.post(path, {})
            assert answered.json().get("code") != "MFA_REQUIRED", (path, answered.text)
        verified = client.post(VERIFY, {"code": mfa.totp(seed, step(runtime))})
        assert verified.status_code == 200, verified.text
        client.csrf = verified.json()["csrf_token"]
        created = client.post(TINES, PASTE)
        assert created.status_code == 201, created.text
        started = client.post(ENTRA_START, {"label": "Directory"})
        assert started.status_code == 200, started.text
        assert set(started.json()) == {"authorize_url"}
        for path in STEPPED[1:]:
            answered = client.post(path, {})
            assert answered.json().get("code") != "MFA_REQUIRED", (path, answered.text)


def test_mc13_a_token_may_ask_and_schedule_but_never_connect_replace_or_revoke(
    db, runtime, admin_engine, world, collector
):
    connection = key_file_connection(db, world)
    token = minted(runtime, world)
    with console_client(
        db, runtime, admin_engine, world["admin"], config=configured(collector)
    ) as console:
        with bearer(console, token) as client:
            for path, body in ((TINES, PASTE), (key(connection), {"api_key": SENTINEL})):
                refused = post(client, path, token, body)
                assert (refused.status_code, refused.json()["code"]) == (
                    403,
                    "TOKEN_NOT_ALLOWED",
                ), path
            refused = post(client, revoke(connection), token, {})
            assert refused.json()["code"] == "TOKEN_NOT_ALLOWED"
            # Recording a Tines tenant's egress changes what a directory's actors are
            # attributed to (#355).
            refused = post(client, egress(connection), token, {"addresses": ["18.200.10.20"]})
            assert refused.json()["code"] == "TOKEN_NOT_ALLOWED"
            # Starting a consent creates a credentialed connection when it completes.
            refused = post(client, ENTRA_START, token, {"label": "Directory"})
            assert (refused.status_code, refused.json()["code"]) == (403, "TOKEN_NOT_ALLOWED")
            options = client.get(CONNECT, headers=auth(token))
            assert options.status_code == 200, options.text
            asked = post(client, collect(connection), token, {})
            assert asked.status_code == 200, asked.text
            scheduled = post(
                client, schedule(connection), token, {"activity_interval_seconds": 1800}
            )
            assert scheduled.status_code == 200, scheduled.text
    row = connection_row(admin_engine, world["admin"].tenant_id, connection)
    assert row["active"] is True and row["activity_interval_seconds"] == 1800
    assert row["collect_requested_by"] == world["admin"].principal_id


def test_mc13_connect_options_follow_the_configuration(db, runtime, admin_engine, world, collector):
    with console_client(db, runtime, admin_engine, world["admin"]) as client:
        answered = client.get(CONNECT)
        assert answered.status_code == 200
        assert answered.json() == {
            "tines": "unconfigured",
            "entra": "unconfigured",
            "sources": "unconfigured",
            "intake_url": ORIGIN + "/v1/monitor/events",
            "entra_display_name": None,
            "entra_client_id": None,
            "last_attempt": None,
            "placement": placed(db, world),
        }
        refused = client.post(TINES, PASTE)
        assert (refused.status_code, refused.json()["code"]) == (409, "CONNECT_UNAVAILABLE")
        assert SENTINEL not in refused.text
    assert connections(admin_engine, world["admin"].tenant_id) == 0
    with console_client(
        db, runtime, admin_engine, world["admin"], config=configured(collector)
    ) as client:
        answered = client.get(CONNECT)
        assert answered.json() == {
            "tines": "available",
            "entra": "unconfigured",
            "sources": "available",
            "intake_url": ORIGIN + "/v1/monitor/events",
            "entra_display_name": None,
            "entra_client_id": None,
            "last_attempt": None,
            "placement": placed(db, world),
        }
        assert_no_secrets(answered)


def test_mc2_a_pasted_key_is_sealed_and_appears_nowhere_else(
    db, runtime, admin_engine, world, collector, caplog
):
    caplog.set_level(logging.DEBUG)
    tenant = world["admin"].tenant_id
    with console_client(
        db, runtime, admin_engine, world["admin"], config=configured(collector)
    ) as client:
        created = client.post(TINES, {**PASTE, "team_id": "7"})
        assert created.status_code == 201, created.text
        answer = created.json()
        assert_no_secrets(created)
        snapshot = client.get(API + "/monitor")
        assert snapshot.status_code == 200
    assert answer["credential_mode"] == "sealed" and answer["kind"] == "tines"
    assert answer["label"] == "Synthetic Tines tenant" and answer["team_id"] == "7"
    assert answer["collect_requested_by"]["principal_id"] == str(world["admin"].principal_id)
    row = connection_row(admin_engine, tenant, answer["connection_id"])
    assert row["key_fingerprint"] == collection.fingerprint(SENTINEL)
    assert sealing.open_for_collector(collector[1], row) == SENTINEL
    # The answer and the snapshot carry no key, ciphertext, collector key or fingerprint.
    for text_out in (created.text, snapshot.text):
        assert SENTINEL not in text_out
        assert row["key_fingerprint"] not in text_out
        assert row["sealed_key_id"] not in text_out
        for field in ("sealed_ct", "sealed_key_id", "key_fingerprint", "collecting_lease"):
            assert field not in text_out
    hexed = SENTINEL.encode().hex()
    assert [
        (table, column)
        for table, column, value in every_text(admin_engine)
        if SENTINEL in value or hexed in value
    ] == []
    assert SENTINEL not in caplog.text
    events = monitoring_events(admin_engine, tenant)
    assert [event["kind"] for event in events] == ["monitor.connection_created"]
    assert SENTINEL not in json.dumps([event["payload"] for event in events])


def test_mc2_each_place_rule_is_its_own_refusal(db, runtime, admin_engine, world, collector):
    tenant = world["admin"].tenant_id
    with console_client(
        db, runtime, admin_engine, world["admin"], config=configured(collector)
    ) as client:
        assert client.post(TINES, PASTE).status_code == 201
        again = client.post(TINES, PASTE)
        assert (again.status_code, again.json()["code"]) == (409, "CONNECTION_EXISTS")
        with admin_engine.begin() as conn:
            conn.execute(
                text("SELECT set_config('execbound.tenant_id', :t, true)"), {"t": str(tenant)}
            )
            other = make_space(conn, tenant, "Customer B", created_by=world["admin"].principal_id)
            archived = make_space(conn, tenant, "Archived", created_by=world["admin"].principal_id)
            conn.execute(
                text("UPDATE execbound.spaces SET archived_at = now() WHERE space_id = :s"),
                {"s": archived},
            )
        unplaced = client.post(TINES, PASTE)
        assert (unplaced.status_code, unplaced.json()["code"]) == (422, "SPACE_REQUIRED")
        assert client.post(API + "/session/space", {"space_id": str(archived)}).status_code == 200
        closed = client.post(TINES, PASTE)
        assert (closed.status_code, closed.json()["code"]) == (409, "SPACE_ARCHIVED")
        assert client.post(API + "/session/space", {"space_id": str(other)}).status_code == 200
        assert client.post(TINES, PASTE).status_code == 201
    assert [event["kind"] for event in monitoring_events(admin_engine, tenant)] == [
        "monitor.connection_created",
        "monitor.connection_created",
    ]


def test_mc2_a_full_workspace_is_refused_at_capacity(db, runtime, admin_engine, world, collector):
    tenant = world["admin"].tenant_id
    with admin_engine.begin() as conn:
        space = conn.execute(
            text("SELECT space_id FROM execbound.spaces WHERE tenant_id = :t"), {"t": tenant}
        ).scalar_one()
        for index in range(monitor_store.MAX_CONNECTIONS):
            conn.execute(
                text(
                    "INSERT INTO execbound.monitor_connections (tenant_id, connection_id, label, "
                    "base_url, key_fingerprint, created_at, created_by, space_id, active) "
                    "VALUES (:t, :c, :l, :u, :k, now(), :p, :s, false)"
                ),
                {
                    "t": tenant,
                    "c": uuid4(),
                    "l": f"Filler {index}",
                    "u": BASE_URL,
                    "k": "0" * 64,
                    "p": world["admin"].principal_id,
                    "s": space,
                },
            )
    with console_client(
        db, runtime, admin_engine, world["admin"], config=configured(collector)
    ) as client:
        full = client.post(TINES, PASTE)
        assert (full.status_code, full.json()["code"]) == (409, "CONNECTION_CAPACITY")
    assert monitoring_events(admin_engine, tenant) == []


# Each new body with the sentinel in every field it has, and in one it does not.
ECHOES = [
    (TINES, {"label": SENTINEL, "base_url": SENTINEL, "team_id": SENTINEL, "api_key": SENTINEL}),
    (TINES, {**PASTE, "unknown": SENTINEL}),
    ("key", {"api_key": SENTINEL, "unknown": SENTINEL}),
    ("key", {"api_key": "has space " + SENTINEL}),
    ("collect", {"unknown": SENTINEL}),
    ("schedule", {"collect_interval_seconds": SENTINEL, "activity_interval_seconds": SENTINEL}),
    ("revoke", {"unknown": SENTINEL}),
    ("egress", {"addresses": [SENTINEL]}),
    ("egress", {"addresses": [], "unknown": SENTINEL}),
    ("egress", {"addresses": ["10.0.0.1"]}),
]


def test_mc2_a_malformed_body_never_echoes_what_it_carried(
    db, runtime, admin_engine, world, collector, caplog
):
    caplog.set_level(logging.DEBUG)
    connection = key_file_connection(db, world)
    paths = {
        "key": key,
        "collect": collect,
        "schedule": schedule,
        "revoke": revoke,
        "egress": egress,
    }
    with console_client(
        db, runtime, admin_engine, world["admin"], config=configured(collector)
    ) as client:
        for path, body in ECHOES:
            target = paths[path](connection) if path in paths else path
            refused = client.post(target, body)
            assert (refused.status_code, refused.json()["code"]) == (400, "INVALID_BODY"), path
            assert SENTINEL not in refused.text, path
    assert SENTINEL not in caplog.text
    assert connection_row(admin_engine, world["admin"].tenant_id, connection)["active"] is True


def test_mc12_collect_now_and_schedule_serve_an_operators_key_file_connection(
    db, runtime, admin_engine, world, collector
):
    tenant = world["admin"].tenant_id
    connection = key_file_connection(db, world)
    with console_client(db, runtime, admin_engine, world["admin"]) as client:
        asked = client.post(collect(connection), {})
        assert asked.status_code == 200, asked.text
        first = asked.json()
        assert first["collect_requested_at"] is not None
        assert first["collect_requested_by"]["principal_id"] == str(world["admin"].principal_id)
        assert first["next_due_at"] <= first["collect_requested_at"]
        again = client.post(collect(connection), {})
        assert again.json()["collect_requested_at"] == first["collect_requested_at"]
        scheduled = client.post(schedule(connection), {"activity_interval_seconds": 1800})
        assert scheduled.status_code == 200, scheduled.text
        assert scheduled.json()["activity_interval_seconds"] == 1800
        for body in (
            {"activity_interval_seconds": 299},
            {"activity_interval_seconds": 3601},
            {"collect_interval_seconds": 3600},
        ):
            refused = client.post(schedule(connection), body)
            assert (refused.status_code, refused.json()["code"]) == (400, "INVALID_BODY"), body
        # A pasted key is only for a sealed connection.
        refused = client.post(key(connection), {"api_key": SENTINEL})
        assert refused.json()["code"] == "CONNECT_UNAVAILABLE"
    with console_client(
        db, runtime, admin_engine, world["admin"], config=configured(collector)
    ) as client:
        refused = client.post(key(connection), {"api_key": SENTINEL})
        assert (refused.status_code, refused.json()["code"]) == (409, "CONFLICT")
        unknown = client.post(collect(uuid4()), {})
        assert (unknown.status_code, unknown.json()["code"]) == (404, "NOT_FOUND")
        malformed = client.post(API + "/monitor/connections/not-an-id/collect", {})
        assert malformed.status_code == 404
        revoked = client.post(revoke(connection), {})
        assert revoked.status_code == 200, revoked.text
        assert revoked.json()["revoked_at"] is not None and revoked.json()["collecting"] is False
        for path in (collect(connection), schedule(connection), revoke(connection)):
            refused = client.post(path, {})
            assert (refused.status_code, refused.json()["code"]) == (409, "CONFLICT"), path
    assert [event["kind"] for event in monitoring_events(admin_engine, tenant)] == [
        "monitor.connection_created",
        "monitor.collection_requested",
        "monitor.schedule_changed",
        "monitor.connection_revoked",
    ]


def test_mc12_a_sealed_connections_key_is_replaced_from_the_console(
    db, runtime, admin_engine, world, collector
):
    tenant = world["admin"].tenant_id
    with console_client(
        db, runtime, admin_engine, world["admin"], config=configured(collector)
    ) as client:
        connection = client.post(TINES, PASTE).json()["connection_id"]
        before = connection_row(admin_engine, tenant, connection)
        replaced = client.post(key(connection), {"api_key": "replacement-" + SENTINEL})
        assert replaced.status_code == 200, replaced.text
        assert SENTINEL not in replaced.text
    row = connection_row(admin_engine, tenant, connection)
    assert row["sealed_ct"] != before["sealed_ct"]
    assert sealing.open_for_collector(collector[1], row) == "replacement-" + SENTINEL
    assert [event["kind"] for event in monitoring_events(admin_engine, tenant)] == [
        "monitor.connection_created",
        "monitor.key_replaced",
    ]


def test_mc2_a_secret_shaped_label_is_refused_by_name(db, runtime, admin_engine, world, collector):
    with console_client(
        db, runtime, admin_engine, world["admin"], config=configured(collector)
    ) as client:
        refused = client.post(TINES, {**PASTE, "label": BEARER})
        assert (refused.status_code, refused.json()["code"]) == (400, "INVALID_BODY")
        assert refused.json()["fields"] == ["label"]
        assert BEARER not in refused.text
    assert connections(admin_engine, world["admin"].tenant_id) == 0


def test_mc13_the_answers_origin_is_the_consoles(db, runtime, admin_engine, world, collector):
    """The routes are served on the console's own origin only; nothing here names another."""
    with console_client(
        db, runtime, admin_engine, world["admin"], config=configured(collector)
    ) as client:
        answered = client.get(CONNECT)
    assert answered.headers.get("access-control-allow-origin") in {None, ORIGIN}


def test_mc13_starting_entra_consent_needs_the_platform_app_and_a_valid_body(
    db, runtime, admin_engine, world, collector
):
    with console_client(
        db, runtime, admin_engine, world["admin"], config=configured(collector)
    ) as client:
        refused = client.post(ENTRA_START, {"label": "Directory"})
        assert (refused.status_code, refused.json()["code"]) == (409, "CONNECT_UNAVAILABLE")
        for body in ({}, {"label": "Directory", "connection_id": ZERO}, {"label": ""}):
            malformed = client.post(ENTRA_START, body)
            assert malformed.status_code in {400, 409}, (body, malformed.text)
    with admin_engine.connect() as conn:
        assert (
            conn.execute(
                text("SELECT count(*) FROM execbound.monitor_connect_attempts")
            ).scalar_one()
            == 0
        )


ENTRA_CLIENT = "0a1b2c3d-4e5f-4a6b-8c7d-9e0f1a2b3c4d"
ENTRA_NAME = "Synthetic Scout"


def attempt_count(admin_engine):
    with admin_engine.connect() as conn:
        return conn.execute(
            text("SELECT count(*) FROM execbound.monitor_connect_attempts")
        ).scalar_one()


def test_mc13_a_start_body_is_checked_where_entra_is_configured(
    db, runtime, admin_engine, world, collector
):
    """Neither a name and a connection together, nor neither, nor an empty name: each is
    `INVALID_BODY` where the platform app is configured, and no attempt is recorded."""
    with console_client(
        db, runtime, admin_engine, world["admin"], config=with_entra(collector)
    ) as client:
        for body in ({}, {"label": "Directory", "connection_id": ZERO}, {"label": ""}):
            malformed = client.post(ENTRA_START, body)
            assert (malformed.status_code, malformed.json()["code"]) == (400, "INVALID_BODY"), (
                body,
                malformed.text,
            )
    assert attempt_count(admin_engine) == 0


# The start body with the sentinel in every field it has, and in one it does not.
ENTRA_ECHOES = [
    {"label": SENTINEL, "connection_id": SENTINEL},
    {"label": "x", "unknown": SENTINEL},
    {"connection_id": SENTINEL},
]


def test_mc2_a_malformed_start_body_never_echoes_what_it_carried(
    db, runtime, admin_engine, world, collector, caplog
):
    caplog.set_level(logging.DEBUG)
    with console_client(
        db, runtime, admin_engine, world["admin"], config=with_entra(collector)
    ) as client:
        for body in ENTRA_ECHOES:
            refused = client.post(ENTRA_START, body)
            assert (refused.status_code, refused.json()["code"]) == (400, "INVALID_BODY"), body
            assert SENTINEL not in refused.text, body
    assert SENTINEL not in caplog.text
    assert attempt_count(admin_engine) == 0


@pytest.mark.parametrize("label", FREE_TEXT, ids=FREE_TEXT_IDS)
def test_mc2_a_secret_shaped_directory_name_is_refused_by_name(
    db, runtime, admin_engine, world, collector, caplog, label
):
    caplog.set_level(logging.DEBUG)
    with console_client(
        db, runtime, admin_engine, world["admin"], config=with_entra(collector)
    ) as client:
        refused = client.post(ENTRA_START, {"label": label})
        assert (refused.status_code, refused.json()["code"]) == (400, "INVALID_BODY")
        assert refused.json()["fields"] == ["label"]
        assert label not in refused.text
    assert label not in caplog.text
    assert attempt_count(admin_engine) == 0


def with_entra(collector, **changes):
    from execbound.surfaces.human import ScoutEntra

    return console_config(
        scout=ScoutConfig(
            collector=collector[0],
            entra=ScoutEntra(ENTRA_CLIENT, "organizations", ENTRA_NAME),
        ),
        **changes,
    )


def test_mc13_connect_options_name_the_platform_app_where_it_is_configured(
    db, runtime, admin_engine, world, collector
):
    with console_client(
        db, runtime, admin_engine, world["admin"], config=with_entra(collector)
    ) as client:
        answered = client.get(CONNECT)
    assert answered.status_code == 200, answered.text
    assert answered.json() == {
        "tines": "available",
        "entra": "available",
        "sources": "available",
        "intake_url": ORIGIN + "/v1/monitor/events",
        "entra_display_name": ENTRA_NAME,
        "entra_client_id": ENTRA_CLIENT,
        "last_attempt": None,
        "placement": placed(db, world),
    }


def test_mc13_the_start_answer_carries_exactly_one_secret_its_state(
    db, runtime, admin_engine, world, collector
):
    from urllib.parse import parse_qsl, urlsplit

    from execbound.replay.verify import ReplayValidationError, reject_secrets

    with console_client(
        db, runtime, admin_engine, world["admin"], config=with_entra(collector)
    ) as client:
        answered = client.post(ENTRA_START, {"label": "Directory"})
    assert answered.status_code == 200, answered.text
    assert set(answered.json()) == {"authorize_url"}
    with pytest.raises(ReplayValidationError):
        reject_secrets(answered.json())
    url = urlsplit(answered.json()["authorize_url"])
    query = [(key, value) for key, value in parse_qsl(url.query) if key != "state"]
    reject_secrets({"authorize_url": url._replace(query="").geturl(), "query": query})


def attempt_row(admin_engine, world, principal, *, state, step=None, minutes=1, connection=None):
    """One ended attempt of `principal`'s, consumed `minutes` ago, written by the owner."""
    tenant = world["admin"].tenant_id
    attempt = uuid4()
    with admin_engine.begin() as conn:
        conn.execute(text("SELECT set_config('execbound.tenant_id', :t, true)"), {"t": str(tenant)})
        space = conn.execute(
            text("SELECT space_id FROM execbound.spaces WHERE tenant_id = :t"), {"t": tenant}
        ).scalar_one()
        conn.execute(
            text(
                "INSERT INTO execbound.monitor_connect_attempts (tenant_id, attempt_id, "
                "principal_id, space_id, connection_id, label, state_hash, binding_hash, "
                "nonce_hash, state, directory_ref, created_at, expires_at, consumed_at, "
                "refusal_code, refused_step) VALUES (:t, :a, :p, :s, :c, 'Directory', :h, "
                ":h, :h, :state, :d, now() - make_interval(mins => :m + 1), "
                "now() - make_interval(mins => :m + 1) + interval '10 minutes', "
                "now() - make_interval(mins => :m), :code, :step)"
            ),
            {
                "t": tenant,
                "a": attempt,
                "p": principal,
                "s": space,
                "c": connection,
                "h": uuid4().hex * 2,
                "state": state,
                "d": "c0ffee00-1111-4222-8333-444455556666",
                "m": minutes,
                "code": "DIRECTORY_UNAVAILABLE" if state == "refused" else None,
                "step": step,
            },
        )
    return attempt


def test_mc13_the_last_attempt_is_the_session_principals_own_and_recent_and_never_a_code(
    db, runtime, admin_engine, world, collector
):
    admin = world["admin"]

    def read():
        with console_client(
            db, runtime, admin_engine, admin, config=with_entra(collector)
        ) as client:
            answered = client.get(CONNECT)
        assert answered.status_code == 200, answered.text
        assert "DIRECTORY_UNAVAILABLE" not in answered.text
        return answered.json()["last_attempt"]

    assert read() is None
    # Older than ten minutes is no return from Microsoft at all.
    attempt_row(
        admin_engine, world, admin.principal_id, state="refused", step="consented", minutes=11
    )
    assert read() is None
    attempt_row(
        admin_engine, world, admin.principal_id, state="refused", step="signed_in", minutes=3
    )
    assert read() == {"outcome": "refused", "refused_after_consent": False, "connection_id": None}
    attempt_row(
        admin_engine, world, admin.principal_id, state="refused", step="consented", minutes=2
    )
    assert read() == {"outcome": "refused", "refused_after_consent": True, "connection_id": None}
    # Another person's attempt, however recent, is theirs.
    attempt_row(
        admin_engine,
        world,
        world["human"].principal_id,
        state="refused",
        step="signed_in",
        minutes=0,
    )
    assert read()["refused_after_consent"] is True


def consented_connection(admin_engine, world, *, consented_minutes_ago):
    """A connection a directory consented to, written by the owner."""
    tenant = world["admin"].tenant_id
    connection = uuid4()
    with admin_engine.begin() as conn:
        conn.execute(text("SELECT set_config('execbound.tenant_id', :t, true)"), {"t": str(tenant)})
        conn.execute(
            text(
                "INSERT INTO execbound.monitor_connections (tenant_id, connection_id, label, "
                "base_url, key_fingerprint, created_at, created_by, kind, directory_ref, "
                "client_ref, space_id, credential_mode, consented_at, consented_by) VALUES "
                "(:t, :c, 'Consented directory', 'https://graph.microsoft.com', NULL, now(), :p, "
                "'entra_agent_id', 'c0ffee00-1111-4222-8333-444455556666', :client, "
                "(SELECT space_id FROM execbound.spaces WHERE tenant_id = :t), 'platform_app', "
                "now() - make_interval(mins => :m), :p)"
            ),
            {
                "t": tenant,
                "c": connection,
                "p": world["admin"].principal_id,
                "client": ENTRA_CLIENT,
                "m": consented_minutes_ago,
            },
        )
    return connection


def test_mc11_a_permission_refused_after_consent_reads_consent_needs_updating(
    db, runtime, admin_engine, world, collector
):
    admin = world["admin"]
    connection = consented_connection(admin_engine, world, consented_minutes_ago=60)
    now = runtime.clock.now().isoformat()

    def probe(state):
        monitor_store.record_capabilities(
            db,
            admin,
            connection,
            {
                "agent_identities": {"state": "available", "at": now},
                "directory_roles": {"state": state, "at": now},
            },
            clock=runtime.clock,
        )

    def snapshot_row():
        with console_client(
            db, runtime, admin_engine, admin, config=with_entra(collector)
        ) as client:
            answered = client.get(API + "/monitor")
        assert answered.status_code == 200, answered.text
        [row] = [
            row for row in answered.json()["connections"] if row["connection_id"] == str(connection)
        ]
        return row

    probe("available")
    row = snapshot_row()
    assert row["credential_mode"] == "platform_app" and row["consent_needs_update"] is False
    assert row["consented_at"] is not None
    assert row["consented_by"]["principal_id"] == str(admin.principal_id)
    probe("forbidden")
    assert snapshot_row()["consent_needs_update"] is True
    # A consent recorded after the permission was lost may be the update it needed, so the
    # line waits for the first probe after it.
    with admin_engine.begin() as conn:
        conn.execute(
            text(
                "UPDATE execbound.monitor_connections "
                "SET consented_at = now() + interval '1 minute' "
                "WHERE tenant_id = :t AND connection_id = :c"
            ),
            {"t": admin.tenant_id, "c": connection},
        )
    assert snapshot_row()["consent_needs_update"] is False
    # That probe still finds the permission refused: forbidden to forbidden raises no new
    # finding, and the new consent still needs updating.
    runtime.clock.value += timedelta(minutes=5)
    probe("forbidden")
    assert snapshot_row()["consent_needs_update"] is True
    # Once a probe finds it granted again, nothing needs updating.
    runtime.clock.value += timedelta(minutes=5)
    probe("available")
    assert snapshot_row()["consent_needs_update"] is False


def test_mc11_the_consent_rule_names_the_finding_a_lost_capability_raises():
    """The snapshot's SQL names the rule and title `record_capabilities` raises, literally."""
    assert monitor_store.HEALTH_TITLES["CAPABILITY_LOST"] in monitor_store.CONSENT_NEEDS_UPDATE
    assert monitor_store.COLLECTION_HEALTH_RULE in monitor_store.CONSENT_NEEDS_UPDATE


def test_sr27_the_egress_route_records_a_tines_tenant_s_addresses_and_answers_the_connection(
    db, runtime, admin_engine, world, collector
):
    """An administrator records the addresses a Tines tenant's requests leave from; the answer is
    the connection as the server now holds it, the change is audited with the count alone, and
    another platform's catalogued range, a repeat and more than eight are refused by field
    (#355)."""
    tenant = world["admin"].tenant_id
    connection = key_file_connection(db, world)
    with console_client(db, runtime, admin_engine, world["admin"]) as client:
        recorded = client.post(egress(connection), {"addresses": ["18.200.10.21", "18.200.10.20"]})
        assert recorded.status_code == 200, recorded.text
        answer = recorded.json()
        assert answer["egress_addresses"] == ["18.200.10.20", "18.200.10.21"]
        assert answer["egress_recorded_by"]["principal_id"] == str(world["admin"].principal_id)
        assert answer["egress_recorded_at"] is not None
        for body in (
            {"addresses": ["160.79.104.20"]},
            {"addresses": [f"18.200.10.{n}" for n in range(30, 39)]},
            {"addresses": ["18.200.10.20", "18.200.10.20"]},
        ):
            refused = client.post(egress(connection), body)
            assert (refused.status_code, refused.json()["code"]) == (400, "INVALID_BODY"), body
            assert refused.json()["fields"] == ["addresses"], body
        cleared = client.post(egress(connection), {"addresses": []})
        assert cleared.json()["egress_addresses"] == []
        unknown = client.post(egress(uuid4()), {"addresses": []})
        assert (unknown.status_code, unknown.json()["code"]) == (404, "NOT_FOUND")
        # A directory connection has no egress of its own to record.
        entra = consented_connection(admin_engine, world, consented_minutes_ago=0)
        conflict = client.post(egress(entra), {"addresses": ["18.200.10.20"]})
        assert (conflict.status_code, conflict.json()["code"]) == (409, "CONFLICT")
    events = [
        e for e in monitoring_events(admin_engine, tenant) if e["kind"] == "monitor.egress_recorded"
    ]
    assert [event["payload"]["addresses"] for event in events] == [2, 0]
    assert "18.200.10.20" not in json.dumps([event["payload"] for event in events])
