# SPDX-License-Identifier: AGPL-3.0-only
"""MC2 and MC12: monitoring connections changed from the console, in the store (#678).

An administrator's session creates a sealed Tines connection from a pasted key, replaces its
key, asks for a collection, sets its schedule and revokes it. Each change lands through a
definer function in the session's space, rechecks the administrator before and after, and
appends one informational audit event as its last write, naming the connection and the
credential that acted and never the key. The operator's `create-connection` and
`revoke-connection` append the same events, because the store's own functions do. A tenant
that has never executed anything gains its audit head and nothing else.
"""

import json
import logging
import os
import sys
from datetime import UTC, datetime
from uuid import uuid4

import pytest
from secret_shapes import FREE_TEXT, FREE_TEXT_IDS
from space_fixtures import make_space, seat
from sqlalchemy import text
from test_monitoring_store import FixedClock
from test_monitoring_store import admins as admins

from execbound.monitoring import collection, commands, connect, sealing
from execbound.monitoring import store as monitor_store
from execbound.monitoring.models import MonitorError
from execbound.replay.verify import reject_secrets
from execbound.spaces import set_current_space
from execbound.surfaces.sessions import issue_session, load_session
from execbound_harness.fake_tines import BASE_URL

pytestmark = pytest.mark.integration

# A key no table but `sealed_ct`, log line or audit payload may ever repeat.
SENTINEL = "SENTINEL-console-pasted-key-9d41b7"
KINDS = (
    "monitor.connection_created",
    "monitor.key_replaced",
    "monitor.collection_requested",
    "monitor.schedule_changed",
    "monitor.connection_revoked",
)


def fenced(conn, tenant):
    conn.execute(text("SELECT set_config('execbound.tenant_id', :t, true)"), {"t": str(tenant)})


@pytest.fixture
def clock():
    return FixedClock(datetime.now(UTC))


@pytest.fixture
def public(tmp_path):
    return sealing.generate(tmp_path / "collector")


@pytest.fixture
def ring(public, tmp_path):
    return sealing.read_private_file(tmp_path / "collector" / sealing.PRIVATE_FILE)


def session_for(db, identity, clock):
    return load_session(db, issue_session(db, identity, clock=clock).token, clock=clock)


def events(admin_engine, tenant):
    with admin_engine.begin() as conn:
        fenced(conn, tenant)
        return [
            dict(row)
            for row in conn.execute(
                text(
                    "SELECT kind, actor_id, payload, space_id FROM execbound.audit_events "
                    "WHERE tenant_id = :t AND kind LIKE 'monitor.%' ORDER BY sequence"
                ),
                {"t": tenant},
            ).mappings()
        ]


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


def create(db, session, public, clock, **changes):
    values = {
        "label": "Synthetic Tines tenant",
        "base_url": BASE_URL,
        "team_id": "7",
        "api_key": SENTINEL,
        **changes,
    }
    return connect.create_sealed_connection(db, session, public=public, clock=clock, **values)


def test_mc2_a_pasted_key_becomes_a_sealed_connection_in_the_sessions_space(
    db, admin_engine, admins, public, ring, clock
):
    admin = admins[0]
    tenant = admin.tenant_id
    with admin_engine.begin() as conn:
        fenced(conn, tenant)
        other = make_space(conn, tenant, "Customer B", created_by=admin.principal_id)
    session = session_for(db, admin, clock)
    with db.transaction(tenant) as conn:
        set_current_space(conn, session, other)
    connection = create(db, session, public, clock)
    row = connection_row(admin_engine, tenant, connection)
    assert (row["credential_mode"], row["kind"], row["space_id"]) == ("sealed", "tines", other)
    assert row["key_fingerprint"] == collection.fingerprint(SENTINEL)
    assert row["sealed_key_id"] == public.key_id
    assert (row["collect_interval_seconds"], row["activity_interval_seconds"]) == (None, None)
    assert row["collect_requested_by"] == admin.principal_id
    # The collector's key opens it, for this row.
    assert sealing.open_for_collector(ring, row) == SENTINEL
    [event] = events(admin_engine, tenant)
    assert event["kind"] == "monitor.connection_created"
    assert event["actor_id"] == admin.principal_id and event["space_id"] == other
    assert event["payload"] == {
        "connection_id": str(connection),
        "space_id": str(other),
        "kind": "tines",
        "credential_mode": "sealed",
        "label": "Synthetic Tines tenant",
        "actor_credential_id": str(admin.credential_id),
    }


def every_text(admin_engine):
    """Every text-like and bytea column of every product table, as text, outside the one place
    a sealed key may be."""
    with admin_engine.connect() as conn:
        columns = conn.execute(
            text(
                "SELECT c.table_name, c.column_name FROM information_schema.columns c "
                "JOIN information_schema.tables t ON t.table_schema = c.table_schema "
                "AND t.table_name = c.table_name AND t.table_type = 'BASE TABLE' "
                "WHERE c.table_schema = 'execbound' AND c.data_type IN "
                "('text', 'character varying', 'jsonb', 'json', 'bytea', 'ARRAY') "
                "AND NOT (c.table_name = 'monitor_connections' AND c.column_name = 'sealed_ct')"
            )
        ).all()
        found = []
        for table, column in columns:
            values = conn.execute(
                text(
                    f'SELECT CAST("{column}" AS text) FROM execbound."{table}"'  # nosec B608 - catalog names
                    f' WHERE "{column}" IS NOT NULL'  # nosec B608 - catalog names
                )
            ).scalars()
            found.extend((table, column, value) for value in values)
        return found


def test_mc2_the_key_is_in_no_table_log_or_event_but_its_ciphertext(
    db, admin_engine, admins, public, clock, caplog
):
    caplog.set_level(logging.DEBUG)
    session = session_for(db, admins[0], clock)
    create(db, session, public, clock)
    hexed = SENTINEL.encode().hex()
    leaks = [
        (table, column)
        for table, column, value in every_text(admin_engine)
        if SENTINEL in value or hexed in value
    ]
    assert leaks == []
    assert SENTINEL not in caplog.text
    for event in events(admin_engine, admins[0].tenant_id):
        assert SENTINEL not in json.dumps(event["payload"])


def test_mc2_a_refused_connection_writes_nothing_and_appends_nothing(
    db, admin_engine, admins, public, clock
):
    admin = admins[0]
    tenant = admin.tenant_id

    def nothing_changed(before, call, code):
        with pytest.raises(MonitorError) as refused:
            call()
        assert refused.value.code == code
        assert SENTINEL not in str(refused.value)
        assert (counts(admin_engine, tenant), events(admin_engine, tenant)) == before

    session = session_for(db, admin, clock)
    create(db, session, public, clock)
    before = (counts(admin_engine, tenant), events(admin_engine, tenant))
    # One Tines connection per space.
    nothing_changed(before, lambda: create(db, session, public, clock), "CONNECTION_EXISTS")
    # Several spaces and none chosen: the place is the administrator's to choose.
    with admin_engine.begin() as conn:
        fenced(conn, tenant)
        other = make_space(conn, tenant, "Customer B", created_by=admin.principal_id)
        archived = make_space(conn, tenant, "Archived", created_by=admin.principal_id)
        conn.execute(
            text("UPDATE execbound.spaces SET archived_at = now() WHERE space_id = :s"),
            {"s": archived},
        )
    nothing_changed(before, lambda: create(db, session, public, clock), "SPACE_REQUIRED")
    with db.transaction(tenant) as conn:
        set_current_space(conn, session, archived)
    nothing_changed(before, lambda: create(db, session, public, clock), "SPACE_ARCHIVED")
    # An administrator narrowed to another space administers nothing here.
    third = None
    with admin_engine.begin() as conn:
        fenced(conn, tenant)
        third = make_space(conn, tenant, "Customer C", created_by=admin.principal_id)
        seat(conn, tenant, other, admin.principal_id, "ADMIN")
        seat(conn, tenant, third, admin.principal_id, "HUMAN_APPROVER")
    with db.transaction(tenant) as conn:
        set_current_space(conn, session, third)
    nothing_changed(before, lambda: create(db, session, public, clock), "INVALID_ADMIN")
    with admin_engine.begin() as conn:
        conn.execute(
            text("DELETE FROM execbound.space_members WHERE tenant_id = :t"), {"t": tenant}
        )
        # A full workspace takes no more.
        fenced(conn, tenant)
        present = conn.execute(
            text("SELECT count(*) FROM execbound.monitor_connections WHERE tenant_id = :t"),
            {"t": tenant},
        ).scalar_one()
        for index in range(monitor_store.MAX_CONNECTIONS - present):
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
                    "p": admin.principal_id,
                    "s": third,
                },
            )
    before = (counts(admin_engine, tenant), events(admin_engine, tenant))
    nothing_changed(before, lambda: create(db, session, public, clock), "CONNECTION_CAPACITY")


@pytest.mark.parametrize("value", FREE_TEXT, ids=FREE_TEXT_IDS)
def test_mc2_a_secret_shaped_label_or_team_is_refused_before_anything_is_written(
    db, admin_engine, admins, public, clock, value
):
    tenant = admins[0].tenant_id
    session = session_for(db, admins[0], clock)
    before = (counts(admin_engine, tenant), events(admin_engine, tenant))
    for field, code in (("label", "INVALID_LABEL"), ("team_id", "INVALID_TEAM")):
        with pytest.raises(MonitorError) as refused:
            create(db, session, public, clock, **{field: value})
        assert refused.value.code == code
        assert value not in str(refused.value)
    assert (counts(admin_engine, tenant), events(admin_engine, tenant)) == before


def counts(admin_engine, tenant):
    with admin_engine.connect() as conn:
        return {
            table: conn.execute(
                text(f"SELECT count(*) FROM execbound.{table} WHERE tenant_id = :t"),  # nosec B608 - literals
                {"t": tenant},
            ).scalar_one()
            for table in (
                "monitor_connections",
                "audit_heads",
                "tenant_policy_control",
                "executions",
                "execution_events",
                "approvals",
                "execution_impact",
            )
        }


def test_mc12_each_connection_change_appends_its_own_event(
    db, admin_engine, admins, public, ring, clock
):
    admin = admins[0]
    tenant = admin.tenant_id
    session = session_for(db, admin, clock)
    before = counts(admin_engine, tenant)
    connection = create(db, session, public, clock)
    first = connection_row(admin_engine, tenant, connection)
    # A replaced key: new ciphertext and fingerprint, and a collection asked for.
    with admin_engine.begin() as conn:
        conn.execute(
            text(
                "UPDATE execbound.monitor_connections SET collect_requested_at = NULL, "
                "collect_requested_by = NULL WHERE tenant_id = :t AND connection_id = :c"
            ),
            {"t": tenant, "c": connection},
        )
    connect.replace_sealed_key(
        db, session, connection, api_key="replacement-" + SENTINEL, public=public, clock=clock
    )
    replaced = connection_row(admin_engine, tenant, connection)
    assert replaced["sealed_ct"] != first["sealed_ct"]
    assert replaced["key_fingerprint"] == collection.fingerprint("replacement-" + SENTINEL)
    assert replaced["collect_requested_by"] == admin.principal_id
    assert sealing.open_for_collector(ring, replaced) == "replacement-" + SENTINEL
    # A request waiting already: a second changes nothing and appends nothing.
    connect.request_collection(db, session, connection, clock=clock)
    with admin_engine.begin() as conn:
        conn.execute(
            text(
                "UPDATE execbound.monitor_connections SET collect_requested_at = NULL, "
                "collect_requested_by = NULL WHERE tenant_id = :t AND connection_id = :c"
            ),
            {"t": tenant, "c": connection},
        )
    connect.request_collection(db, session, connection, clock=clock)
    connect.set_schedule(db, session, connection, collect=None, activity=1800, clock=clock)
    # Revocation keeps the row and its evidence, and clears a lease a run held.
    lease = uuid4()
    with db.transaction(tenant) as conn:
        assert conn.execute(
            text("SELECT execbound.collector_claim(:c, :l, 600)"), {"c": connection, "l": lease}
        ).scalar_one() == {"claimed": True}
    connect.revoke_connection(db, session, connection, clock=clock)
    revoked = connection_row(admin_engine, tenant, connection)
    assert revoked["active"] is False and revoked["revoked_at"] is not None
    assert (revoked["collecting_until"], revoked["collecting_lease"]) == (None, None)
    assert revoked["sealed_ct"] == replaced["sealed_ct"]
    recorded = events(admin_engine, tenant)
    acted = {"actor_credential_id": str(admin.credential_id)}
    assert [(event["kind"], event["payload"]) for event in recorded] == [
        (
            "monitor.connection_created",
            {
                "connection_id": str(connection),
                "space_id": str(first["space_id"]),
                "kind": "tines",
                "credential_mode": "sealed",
                "label": "Synthetic Tines tenant",
                **acted,
            },
        ),
        ("monitor.key_replaced", {"connection_id": str(connection), **acted}),
        ("monitor.collection_requested", {"connection_id": str(connection), **acted}),
        (
            "monitor.schedule_changed",
            {
                "connection_id": str(connection),
                "collect_interval_seconds": None,
                "activity_interval_seconds": 1800,
                **acted,
            },
        ),
        ("monitor.connection_revoked", {"connection_id": str(connection), **acted}),
    ]
    for event in recorded:
        assert event["space_id"] == first["space_id"]
        assert event["actor_id"] == admin.principal_id
        # Each passes the export's secret check, and carries no key, fingerprint or cipher.
        reject_secrets(event["payload"])
        serialized = json.dumps(event["payload"])
        assert SENTINEL not in serialized and first["key_fingerprint"] not in serialized
    # Nothing an execution, an approval or the tenant control would own.
    after = counts(admin_engine, tenant)
    assert after == {**before, "monitor_connections": before["monitor_connections"] + 1}
    # A revoked connection takes nothing more.
    for change in (
        lambda: connect.request_collection(db, session, connection, clock=clock),
        lambda: connect.set_schedule(
            db, session, connection, collect=None, activity=900, clock=clock
        ),
        lambda: connect.replace_sealed_key(
            db, session, connection, api_key=SENTINEL, public=public, clock=clock
        ),
        lambda: connect.revoke_connection(db, session, connection, clock=clock),
    ):
        with pytest.raises(MonitorError) as refused:
            change()
        assert refused.value.code == "CONNECTION_REVOKED"
    assert len(events(admin_engine, tenant)) == len(recorded)


def test_mc12_a_connection_outside_the_sessions_spaces_does_not_exist_for_it(
    db, admin_engine, admins, public, clock
):
    admin = admins[0]
    tenant = admin.tenant_id
    session = session_for(db, admin, clock)
    connection = create(db, session, public, clock)
    with admin_engine.begin() as conn:
        fenced(conn, tenant)
        other = make_space(conn, tenant, "Customer B", created_by=admin.principal_id)
        seat(conn, tenant, other, admin.principal_id, "ADMIN")
    before = events(admin_engine, tenant)
    for change in (
        lambda: connect.request_collection(db, session, connection, clock=clock),
        lambda: connect.set_schedule(
            db, session, connection, collect=None, activity=900, clock=clock
        ),
        lambda: connect.replace_sealed_key(
            db, session, connection, api_key=SENTINEL, public=public, clock=clock
        ),
        lambda: connect.revoke_connection(db, session, connection, clock=clock),
        lambda: connect.request_collection(db, session, uuid4(), clock=clock),
    ):
        with pytest.raises(MonitorError) as refused:
            change()
        assert refused.value.code == "CONNECTION_UNAVAILABLE"
    assert events(admin_engine, tenant) == before


def test_mc12_schedule_and_requests_serve_an_operators_key_file_connection(
    db, admin_engine, admins, public, clock
):
    admin = admins[0]
    tenant = admin.tenant_id
    filed = monitor_store.create_connection(
        db,
        admin,
        label="Operator's Tines",
        base_url=BASE_URL,
        key_fingerprint=collection.fingerprint(SENTINEL),
        clock=clock,
    )
    session = session_for(db, admin, clock)
    connect.request_collection(db, session, filed, clock=clock)
    connect.set_schedule(db, session, filed, collect=86400, activity=300, clock=clock)
    row = connection_row(admin_engine, tenant, filed)
    assert row["collect_requested_by"] == admin.principal_id
    assert (row["collect_interval_seconds"], row["activity_interval_seconds"]) == (86400, 300)
    # Out of range, or another kind's interval: refused, with nothing written.
    for collect, activity in ((3600, None), (None, 299), (None, 3601)):
        with pytest.raises(MonitorError) as refused:
            connect.set_schedule(
                db, session, filed, collect=collect, activity=activity, clock=clock
            )
        assert refused.value.code == "INVALID_SCHEDULE"
    # Only a sealed connection takes a pasted key.
    with pytest.raises(MonitorError) as refused:
        connect.replace_sealed_key(db, session, filed, api_key=SENTINEL, public=public, clock=clock)
    assert refused.value.code == "CONNECTION_NOT_SEALED"
    assert [event["kind"] for event in events(admin_engine, tenant)] == [
        "monitor.connection_created",
        "monitor.collection_requested",
        "monitor.schedule_changed",
    ]


def test_mc12_the_operators_create_and_revoke_commands_append_the_same_events(
    db, admin_engine, admins, seeded, tmp_path, monkeypatch, capsys
):
    admin = admins[0]
    credential = tmp_path / "admin.token"
    credential.write_text(seeded["tokens"][0] + "\n", encoding="utf-8")
    key_file = tmp_path / "tines.env"
    key_file.write_text(f"TINES_BASE_URL={BASE_URL}\nTINES_API_KEY={SENTINEL}\n", encoding="utf-8")
    monkeypatch.setenv("DATABASE_URL", os.environ["TEST_DATABASE_URL"])
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "commands",
            "create-connection",
            "--credential-file",
            str(credential),
            "--label",
            "Operator's Tines",
            "--key-file",
            str(key_file),
        ],
    )
    commands.main()
    connection = json.loads(capsys.readouterr().out)["connection_id"]
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "commands",
            "revoke-connection",
            "--credential-file",
            str(credential),
            "--connection",
            connection,
        ],
    )
    commands.main()
    recorded = events(admin_engine, admin.tenant_id)
    row = connection_row(admin_engine, admin.tenant_id, connection)
    assert [(event["kind"], event["payload"]) for event in recorded] == [
        (
            "monitor.connection_created",
            {
                "connection_id": connection,
                "space_id": str(row["space_id"]),
                "kind": "tines",
                "credential_mode": "key_file",
                "label": "Operator's Tines",
                "actor_credential_id": str(admin.credential_id),
            },
        ),
        (
            "monitor.connection_revoked",
            {"connection_id": connection, "actor_credential_id": str(admin.credential_id)},
        ),
    ]
    assert SENTINEL not in json.dumps([event["payload"] for event in recorded])


def test_mc12_the_events_follow_the_administrators_recheck(db, admin_engine, admins, public, clock):
    """An administrator deactivated between the request and the write changes nothing."""
    admin = admins[0]
    session = session_for(db, admin, clock)
    with admin_engine.begin() as conn:
        conn.execute(
            text("UPDATE execbound.principals SET active = false WHERE principal_id = :p"),
            {"p": admin.principal_id},
        )
    with pytest.raises(MonitorError) as refused:
        create(db, session, public, clock)
    assert refused.value.code == "INVALID_ADMIN"
    assert events(admin_engine, admin.tenant_id) == []


def test_mc12_a_tenant_that_never_executed_gains_its_audit_head_and_nothing_else(
    db, admin_engine, admins, clock
):
    """The first connection change of a tenant with no history creates the tenant's audit
    head, and no tenant control, execution, approval or impact row (`audit.append_event`)."""
    admin = admins[0]
    before = counts(admin_engine, admin.tenant_id)
    assert before["audit_heads"] == 0 and before["tenant_policy_control"] == 0
    connection = monitor_store.create_connection(
        db,
        admin,
        label="Operator's Tines",
        base_url=BASE_URL,
        key_fingerprint=collection.fingerprint(SENTINEL),
        clock=clock,
    )
    monitor_store.revoke_connection(db, admin, connection, clock=clock)
    assert counts(admin_engine, admin.tenant_id) == {
        **before,
        "monitor_connections": 1,
        "audit_heads": 1,
    }
    assert [event["kind"] for event in events(admin_engine, admin.tenant_id)] == [
        "monitor.connection_created",
        "monitor.connection_revoked",
    ]


def test_mc12_an_administrator_deactivated_during_the_change_changes_nothing(
    db, admin_engine, admins, public, clock, monkeypatch
):
    """The session is checked again after the definer function writes: an administrator
    deactivated after the function's own check, before the commit, leaves no row and no
    event."""
    admin = admins[0]
    tenant = admin.tenant_id
    session = session_for(db, admin, clock)
    with admin_engine.begin() as conn:
        fenced(conn, tenant)
        other = make_space(conn, tenant, "Customer B", created_by=admin.principal_id)
        here = conn.execute(
            text("SELECT space_id FROM execbound.spaces WHERE tenant_id = :t AND space_id <> :o"),
            {"t": tenant, "o": other},
        ).scalar_one()
    with db.transaction(tenant) as conn:
        set_current_space(conn, session, here)
    filed = monitor_store.create_connection(
        db,
        admin,
        label="Operator's Tines",
        base_url=BASE_URL,
        key_fingerprint=collection.fingerprint(SENTINEL),
        clock=clock,
        space=other,
    )
    checked = connect._session
    calls = {"count": 0}

    def deactivating_before_the_second_check(conn, current, clock):
        calls["count"] += 1
        if calls["count"] == 2:
            with admin_engine.begin() as other:
                other.execute(
                    text("UPDATE execbound.principals SET active = false WHERE principal_id = :p"),
                    {"p": admin.principal_id},
                )
        checked(conn, current, clock)

    monkeypatch.setattr(connect, "_session", deactivating_before_the_second_check)
    before = (counts(admin_engine, tenant), events(admin_engine, tenant))
    filed_before = connection_row(admin_engine, tenant, filed)
    for change in (
        lambda: create(db, session, public, clock, label="Another"),
        lambda: connect.request_collection(db, session, filed, clock=clock),
        lambda: connect.set_schedule(db, session, filed, collect=None, activity=600, clock=clock),
    ):
        calls["count"] = 0
        with admin_engine.begin() as conn:
            conn.execute(
                text("UPDATE execbound.principals SET active = true WHERE principal_id = :p"),
                {"p": admin.principal_id},
            )
        with pytest.raises(MonitorError) as refused:
            change()
        assert refused.value.code == "INVALID_ADMIN"
    assert (counts(admin_engine, tenant), events(admin_engine, tenant)) == before
    assert connection_row(admin_engine, tenant, filed) == filed_before
