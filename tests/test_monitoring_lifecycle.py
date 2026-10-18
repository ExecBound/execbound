# SPDX-License-Identifier: AGPL-3.0-only
"""Monitoring source token rotation and revocation: SL1 to SL10 on real PostgreSQL.

MC14's store half (#678): a source records who minted it, lands in a space its creator
administers and that is not archived, lives at most thirty days whoever mints it, and is refused
a label or story ID shaped like a secret. Minting, like rotation and revocation, stays off the
execution audit chain.
"""

import hashlib
import json
import os
import sys
import threading
import time
from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest
from alembic import command
from alembic.config import Config
from secret_shapes import AGENT_TOKEN, FREE_TEXT, FREE_TEXT_IDS
from space_fixtures import make_space, seat
from sqlalchemy import text
from test_execution import provision_identity
from test_human_surface import credential
from test_monitoring_http import monitor_web as monitor_web
from test_monitoring_http import post_event

from execbound.db import UPDATE_COLUMNS, check_runtime
from execbound.identity import authenticate
from execbound.monitoring import commands, store
from execbound.monitoring.models import MonitorError
from execbound.replay.export import export_history
from execbound.replay.verify import verify_export

TOKEN_COLUMNS = (
    "token_hash, current_token_hash, previous_token_hash, previous_valid_until, expires_at, "
    "active, revoked_at, rotated_at, rotated_by, revoked_by"
)


def digest(token):
    return hashlib.sha256(token.encode("ascii")).hexdigest()


def source_row(engine, tenant, source_id):
    with engine.begin() as conn:
        conn.execute(text("SELECT set_config('execbound.tenant_id', :t, true)"), {"t": str(tenant)})
        return (
            conn.execute(
                text(
                    f"SELECT {TOKEN_COLUMNS} FROM execbound.monitor_sources "
                    "WHERE tenant_id=:t AND source_id=:s"
                ),
                {"t": tenant, "s": source_id},
            )
            .mappings()
            .one()
        )


def audit_kinds(engine, tenant):
    with engine.begin() as conn:
        conn.execute(text("SELECT set_config('execbound.tenant_id', :t, true)"), {"t": str(tenant)})
        return (
            conn.execute(
                text(
                    "SELECT kind FROM execbound.audit_events WHERE tenant_id=:t ORDER BY sequence"
                ),
                {"t": tenant},
            )
            .scalars()
            .all()
        )


def execution_counts(engine):
    with engine.begin() as conn:
        return {
            table: conn.execute(text(f"SELECT count(*) FROM execbound.{table}")).scalar_one()
            for table in ("executions", "execution_events", "execution_impact", "approvals")
        }


def later(hours=2):
    return datetime.now(UTC) + timedelta(hours=hours)


def test_sl1_rotation_issues_a_new_token_and_keeps_the_old_one_for_the_grace_window(
    monitor_web, db, admin_engine
):
    client, admin, source, _ = monitor_web
    rotated = store.rotate_source(
        db, admin, source.source_id, expires_at=later(), grace_seconds=600
    )
    assert rotated.source_id == source.source_id and rotated.token != source.token
    assert rotated.token.startswith(f"mo1.{admin.tenant_id}.{source.source_id}.")
    row = source_row(admin_engine, admin.tenant_id, source.source_id)
    # The registration digest is immutable evidence; the active digest sits beside it.
    assert row["token_hash"] == digest(source.token)
    assert row["current_token_hash"] == digest(rotated.token)
    assert row["previous_token_hash"] == digest(source.token)
    assert (
        timedelta(minutes=9)
        < row["previous_valid_until"] - datetime.now(UTC)
        <= timedelta(minutes=10)
    )
    assert post_event(client, source).status_code == 202
    assert post_event(client, rotated, event_id=str(uuid4())).status_code == 202
    again = store.rotate_source(db, admin, source.source_id, expires_at=later(), grace_seconds=600)
    row = source_row(admin_engine, admin.tenant_id, source.source_id)
    assert row["token_hash"] == digest(source.token)
    assert row["current_token_hash"] == digest(again.token)
    assert row["previous_token_hash"] == digest(rotated.token)
    assert post_event(client, source, event_id=str(uuid4())).status_code == 401
    assert post_event(client, rotated, event_id=str(uuid4())).status_code == 202
    assert post_event(client, again, event_id=str(uuid4())).status_code == 202


def test_sl2_the_old_token_stops_working_when_the_grace_window_ends(monitor_web, db, admin_engine):
    client, admin, source, _ = monitor_web
    rotated = store.rotate_source(db, admin, source.source_id, expires_at=later(), grace_seconds=60)
    with admin_engine.begin() as conn:
        conn.execute(
            text("SELECT set_config('execbound.tenant_id', :t, true)"), {"t": str(admin.tenant_id)}
        )
        conn.execute(
            text(
                "UPDATE execbound.monitor_sources SET previous_valid_until=:when "
                "WHERE tenant_id=:t AND source_id=:s"
            ),
            {
                "when": datetime.now(UTC) - timedelta(seconds=1),
                "t": admin.tenant_id,
                "s": source.source_id,
            },
        )
    refused = post_event(client, source)
    assert refused.status_code == 401 and refused.json()["code"] == "INVALID_SOURCE"
    assert post_event(client, rotated).status_code == 202
    with admin_engine.begin() as conn:
        conn.execute(
            text("SELECT set_config('execbound.tenant_id', :t, true)"), {"t": str(admin.tenant_id)}
        )
        failures = conn.execute(
            text(
                "SELECT surface, reason, subject_id, count FROM execbound.authentication_failures "
                "WHERE tenant_id=:t"
            ),
            {"t": admin.tenant_id},
        ).all()
    assert failures == [("monitor", "MISMATCH", source.source_id, 1)]


def test_sl3_revocation_refuses_every_token_and_cannot_be_undone_by_rotation(
    monitor_web, db, admin_engine
):
    client, admin, source, _ = monitor_web
    rotated = store.rotate_source(
        db, admin, source.source_id, expires_at=later(), grace_seconds=600
    )
    store.revoke_source(db, admin, source.source_id)
    for token in (source, rotated):
        refused = post_event(client, token)
        assert refused.status_code == 401 and refused.json()["code"] == "INVALID_SOURCE"
    row = source_row(admin_engine, admin.tenant_id, source.source_id)
    assert row["active"] is False and row["revoked_at"] is not None
    assert row["previous_token_hash"] is None and row["previous_valid_until"] is None
    view = client.get("/api/console/v1/monitor")
    assert view.status_code == 200
    assert any(row["coverage"] == "Disabled" for row in view.json()["sources"])
    for call in (
        lambda: store.revoke_source(db, admin, source.source_id),
        lambda: store.rotate_source(db, admin, source.source_id, expires_at=later()),
    ):
        with pytest.raises(MonitorError) as refused:
            call()
        assert refused.value.code == "INVALID_STATE"


def test_sl4_an_expired_source_can_be_reissued_without_a_grace_window(
    monitor_web, db, admin_engine
):
    client, admin, source, _ = monitor_web
    with admin_engine.begin() as conn:
        conn.execute(
            text("SELECT set_config('execbound.tenant_id', :t, true)"), {"t": str(admin.tenant_id)}
        )
        conn.execute(
            text(
                "UPDATE execbound.monitor_sources SET created_at=:earlier, expires_at=:when "
                "WHERE tenant_id=:t AND source_id=:s"
            ),
            {
                "earlier": datetime.now(UTC) - timedelta(hours=2),
                "when": datetime.now(UTC) - timedelta(seconds=1),
                "t": admin.tenant_id,
                "s": source.source_id,
            },
        )
    assert post_event(client, source).status_code == 401
    rotated = store.rotate_source(
        db, admin, source.source_id, expires_at=later(), grace_seconds=600
    )
    row = source_row(admin_engine, admin.tenant_id, source.source_id)
    assert row["previous_token_hash"] is None and row["expires_at"] > datetime.now(UTC)
    assert post_event(client, source).status_code == 401
    assert post_event(client, rotated).status_code == 202


def test_sl5_rotation_and_revocation_are_scoped_to_the_tenant_and_source(
    monitor_web, db, admin_engine, seeded
):
    client, admin, source, _ = monitor_web
    other_tenant = seeded["tenants"][1]
    other_admin = provision_identity(admin_engine, db, other_tenant, "ADMIN", datetime.now(UTC))
    other_source = store.create_source(
        db, other_admin, label="Other", story_id="story-2", expires_at=later()
    )
    for call in (
        lambda: store.rotate_source(db, other_admin, source.source_id, expires_at=later()),
        lambda: store.revoke_source(db, other_admin, source.source_id),
        lambda: store.rotate_source(db, admin, uuid4(), expires_at=later()),
    ):
        with pytest.raises(MonitorError) as refused:
            call()
        assert refused.value.code == "SOURCE_UNAVAILABLE"
    before = source_row(admin_engine, other_tenant, other_source.source_id)
    rotated = store.rotate_source(
        db, admin, source.source_id, expires_at=later(), grace_seconds=600
    )
    assert source_row(admin_engine, other_tenant, other_source.source_id) == before
    # A rotated token of one source never reports for another story.
    foreign = post_event(client, rotated, story_id="story-2")
    assert foreign.status_code == 401 and foreign.json()["code"] == "INVALID_SOURCE"
    assert post_event(client, other_source).status_code == 401


def test_sl6_only_a_current_admin_of_the_tenant_may_rotate_or_revoke(
    monitor_web, db, admin_engine, seeded
):
    _, admin, source, _ = monitor_web
    agent = authenticate(db, seeded["tokens"][0])
    human = provision_identity(
        admin_engine, db, admin.tenant_id, "HUMAN_APPROVER", datetime.now(UTC)
    )
    for actor in (agent, human):
        for call in (
            lambda actor=actor: store.rotate_source(
                db, actor, source.source_id, expires_at=later()
            ),
            lambda actor=actor: store.revoke_source(db, actor, source.source_id),
        ):
            with pytest.raises(MonitorError) as refused:
                call()
            assert refused.value.code == "INVALID_ADMIN"
    with admin_engine.begin() as conn:
        conn.execute(
            text("SELECT set_config('execbound.tenant_id', :t, true)"), {"t": str(admin.tenant_id)}
        )
        conn.execute(
            text("UPDATE execbound.credentials SET revoked_at=now() WHERE credential_id=:c"),
            {"c": admin.credential_id},
        )
    with pytest.raises(MonitorError) as stale:
        store.rotate_source(db, admin, source.source_id, expires_at=later())
    assert stale.value.code == "INVALID_ADMIN"
    row = source_row(admin_engine, admin.tenant_id, source.source_id)
    assert row["current_token_hash"] is None and row["revoked_at"] is None


def test_sl7_sl8_lifecycle_is_recorded_on_the_source_and_touches_nothing_else(
    monitor_web, db, admin_engine
):
    _, admin, source, _ = monitor_web
    before = execution_counts(admin_engine)
    chain = audit_kinds(admin_engine, admin.tenant_id)
    store.rotate_source(db, admin, source.source_id, expires_at=later(), grace_seconds=600)
    row = source_row(admin_engine, admin.tenant_id, source.source_id)
    assert row["rotated_by"] == admin.principal_id and row["rotated_at"] is not None
    assert row["revoked_by"] is None
    store.revoke_source(db, admin, source.source_id)
    row = source_row(admin_engine, admin.tenant_id, source.source_id)
    assert row["revoked_by"] == admin.principal_id and row["revoked_at"] is not None
    # Monitoring history stays outside the execution audit chain and execution state.
    assert execution_counts(admin_engine) == before
    assert audit_kinds(admin_engine, admin.tenant_id) == chain
    export = export_history(db, admin)
    assert verify_export(export, export.head).complete


def test_sl9_migration_round_trip_and_runtime_catalog(monitor_web, db, admin_engine):
    _, admin, source, _ = monitor_web
    assert "token_hash" not in UPDATE_COLUMNS["monitor_sources"]
    assert {
        "current_token_hash",
        "expires_at",
        "previous_token_hash",
        "previous_valid_until",
        "rotated_at",
        "rotated_by",
        "revoked_by",
    } <= UPDATE_COLUMNS["monitor_sources"]
    with db.transaction(admin.tenant_id) as conn:
        check_runtime(conn)
    config = Config("alembic.ini")
    config.attributes["database_url"] = os.environ["TEST_MIGRATION_DATABASE_URL"]
    command.downgrade(config, "0011_tenant_stop")
    command.upgrade(config, "head")
    with db.transaction(admin.tenant_id) as conn:
        check_runtime(conn)
    assert (
        source_row(admin_engine, admin.tenant_id, source.source_id)["previous_token_hash"] is None
    )


def test_sl10_cli_rotates_and_revokes_with_an_admin_credential_file(
    monitor_web, db, admin_engine, tmp_path, monkeypatch, capsys
):
    client, admin, source, _ = monitor_web
    monkeypatch.setenv("DATABASE_URL", os.environ["TEST_DATABASE_URL"])
    admin_file = tmp_path / "admin.token"
    admin_file.write_text(credential(admin_engine, admin), encoding="utf-8")
    output = tmp_path / "rotated.json"
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "monitoring",
            "rotate-source",
            "--credential-file",
            str(admin_file),
            "--source",
            str(source.source_id),
            "--hours",
            "2",
            "--grace-minutes",
            "5",
            "--output",
            str(output),
        ],
    )
    commands.main()
    assert "rotated" in capsys.readouterr().out.lower()
    issued = json.loads(output.read_text(encoding="utf-8"))
    assert issued["source_id"] == str(source.source_id)
    if os.name != "nt":
        assert oct(output.stat().st_mode & 0o777) == "0o600"
    assert post_event(client, source).status_code == 202
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "monitoring",
            "revoke-source",
            "--credential-file",
            str(admin_file),
            "--source",
            str(source.source_id),
        ],
    )
    commands.main()
    assert "revoked" in capsys.readouterr().out.lower()
    assert post_event(client, source).status_code == 401
    with pytest.raises(SystemExit) as caught:
        commands.main()
    assert caught.value.code == 2


class FixedClock:
    def __init__(self, value):
        self.value = value

    def now(self):
        return self.value


def fenced(conn, tenant):
    conn.execute(text("SELECT set_config('execbound.tenant_id', :t, true)"), {"t": str(tenant)})


def minted_row(engine, tenant, source_id):
    with engine.begin() as conn:
        fenced(conn, tenant)
        return (
            conn.execute(
                text(
                    "SELECT created_by, space_id, expires_at FROM execbound.monitor_sources "
                    "WHERE tenant_id=:t AND source_id=:s"
                ),
                {"t": tenant, "s": source_id},
            )
            .mappings()
            .one()
        )


def source_count(engine, tenant):
    with engine.begin() as conn:
        fenced(conn, tenant)
        return conn.execute(
            text("SELECT count(*) FROM execbound.monitor_sources WHERE tenant_id=:t"),
            {"t": tenant},
        ).scalar_one()


def test_mc14_a_source_records_who_minted_it_in_the_space_it_was_given(
    monitor_web, db, admin_engine
):
    _, admin, source, _ = monitor_web
    tenant = admin.tenant_id
    assert minted_row(admin_engine, tenant, source.source_id)["created_by"] == admin.principal_id
    with admin_engine.begin() as conn:
        fenced(conn, tenant)
        other = make_space(conn, tenant, "Customer B", created_by=admin.principal_id)
    before = execution_counts(admin_engine)
    chain = audit_kinds(admin_engine, tenant)
    placed = store.create_source(
        db, admin, label="Placed", story_id="story-placed", expires_at=later(), space=other
    )
    row = minted_row(admin_engine, tenant, placed.source_id)
    assert (row["created_by"], row["space_id"]) == (admin.principal_id, other)
    # Minting stays off the execution audit chain and out of execution state, as rotating and
    # revoking do.
    assert execution_counts(admin_engine) == before
    assert audit_kinds(admin_engine, tenant) == chain


def test_mc14_a_source_is_minted_only_where_its_creator_may_mint(monitor_web, db, admin_engine):
    """An archived space, a space that is not the tenant's, and a space the administrator does
    not administer (a membership narrows an administrator to the spaces they administer) are
    each refused with nothing written."""
    _, admin, _, _ = monitor_web
    tenant = admin.tenant_id
    with admin_engine.begin() as conn:
        fenced(conn, tenant)
        archived = make_space(conn, tenant, "Archived", created_by=admin.principal_id)
        conn.execute(
            text("UPDATE execbound.spaces SET archived_at = now() WHERE space_id = :s"),
            {"s": archived},
        )
        narrowed = make_space(conn, tenant, "Narrowed", created_by=admin.principal_id)
        elsewhere = make_space(conn, tenant, "Administered", created_by=admin.principal_id)
        seat(conn, tenant, elsewhere, admin.principal_id, "ADMIN")
    count = source_count(admin_engine, tenant)
    for space, code in (
        (archived, "SPACE_ARCHIVED"),
        (uuid4(), "INVALID_SPACE"),
        (narrowed, "INVALID_ADMIN"),
    ):
        with pytest.raises(MonitorError) as refused:
            store.create_source(
                db,
                admin,
                label="Refused",
                story_id="story-refused",
                expires_at=later(),
                space=space,
            )
        assert refused.value.code == code, space
    assert source_count(admin_engine, tenant) == count
    allowed = store.create_source(
        db, admin, label="Allowed", story_id="story-allowed", expires_at=later(), space=elsewhere
    )
    assert minted_row(admin_engine, tenant, allowed.source_id)["space_id"] == elsewhere


def test_mc14_no_token_lives_beyond_thirty_days_whoever_mints_it(monitor_web, db, admin_engine):
    _, admin, source, _ = monitor_web
    now = datetime.now(UTC)
    clock = FixedClock(now)
    ceiling = now + timedelta(days=30)
    count = source_count(admin_engine, admin.tenant_id)
    for call in (
        lambda: store.create_source(
            db,
            admin,
            label="Long",
            story_id="story-long",
            expires_at=ceiling + timedelta(seconds=1),
            clock=clock,
        ),
        lambda: store.rotate_source(
            db, admin, source.source_id, expires_at=ceiling + timedelta(seconds=1), clock=clock
        ),
    ):
        with pytest.raises(MonitorError) as refused:
            call()
        assert refused.value.code == "INVALID_INPUT"
    assert source_count(admin_engine, admin.tenant_id) == count
    assert source_row(admin_engine, admin.tenant_id, source.source_id)["rotated_at"] is None
    kept = store.create_source(
        db, admin, label="Month", story_id="story-month", expires_at=ceiling, clock=clock
    )
    assert minted_row(admin_engine, admin.tenant_id, kept.source_id)["expires_at"] == ceiling
    store.rotate_source(db, admin, kept.source_id, expires_at=ceiling, clock=clock)


@pytest.mark.parametrize("value", FREE_TEXT, ids=FREE_TEXT_IDS)
def test_mc14_a_label_shaped_like_a_secret_is_refused(monitor_web, db, admin_engine, value):
    _, admin, _, _ = monitor_web
    count = source_count(admin_engine, admin.tenant_id)
    with pytest.raises(MonitorError) as refused:
        store.create_source(db, admin, label=value, story_id="story-x", expires_at=later())
    assert refused.value.code == "INVALID_INPUT"
    assert source_count(admin_engine, admin.tenant_id) == count


def test_mc14_a_story_id_shaped_like_a_credential_is_refused(monitor_web, db, admin_engine):
    """ExecBound's own credential fits the story ID's characters; it is refused, not stored."""
    _, admin, _, _ = monitor_web
    count = source_count(admin_engine, admin.tenant_id)
    with pytest.raises(MonitorError) as refused:
        store.create_source(db, admin, label="Story", story_id=AGENT_TOKEN, expires_at=later())
    assert refused.value.code == "INVALID_INPUT"
    assert source_count(admin_engine, admin.tenant_id) == count


@pytest.mark.parametrize("hours", ["0", "25"])
def test_mc14_the_command_line_mints_for_one_to_twenty_four_hours(
    monitor_web, db, admin_engine, tmp_path, monkeypatch, hours
):
    _, admin, _, _ = monitor_web
    monkeypatch.setenv("DATABASE_URL", os.environ["TEST_DATABASE_URL"])
    admin_file = tmp_path / "admin.token"
    admin_file.write_text(credential(admin_engine, admin), encoding="utf-8")
    count = source_count(admin_engine, admin.tenant_id)
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "monitoring",
            "create-source",
            "--credential-file",
            str(admin_file),
            "--label",
            "Story",
            "--story-id",
            "story-cli",
            "--hours",
            hours,
            "--output",
            str(tmp_path / "source.json"),
        ],
    )
    with pytest.raises(SystemExit) as caught:
        commands.main()
    assert caught.value.code == 2
    assert source_count(admin_engine, admin.tenant_id) == count


def test_mc14_the_command_line_records_who_minted_a_source(
    monitor_web, db, admin_engine, tmp_path, monkeypatch, capsys
):
    _, admin, _, _ = monitor_web
    monkeypatch.setenv("DATABASE_URL", os.environ["TEST_DATABASE_URL"])
    admin_file = tmp_path / "admin.token"
    admin_file.write_text(credential(admin_engine, admin), encoding="utf-8")
    output = tmp_path / "source.json"
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "monitoring",
            "create-source",
            "--credential-file",
            str(admin_file),
            "--label",
            "Story",
            "--story-id",
            "story-cli",
            "--hours",
            "24",
            "--output",
            str(output),
        ],
    )
    commands.main()
    assert "created" in capsys.readouterr().out.lower()
    issued = json.loads(output.read_text(encoding="utf-8"))
    row = minted_row(admin_engine, admin.tenant_id, issued["source_id"])
    assert row["created_by"] == admin.principal_id
    assert timedelta(hours=23) < row["expires_at"] - datetime.now(UTC) <= timedelta(hours=24)


def test_mc15_an_administrator_narrowed_to_other_spaces_neither_rotates_nor_revokes(
    monitor_web, db, admin_engine
):
    """A membership narrows an administrator to the spaces they administer, for a source as for
    a connection: rotating or revoking one in another space is refused and changes nothing."""
    _, admin, source, _ = monitor_web
    tenant = admin.tenant_id
    with admin_engine.begin() as conn:
        fenced(conn, tenant)
        mine = make_space(conn, tenant, "Mine", created_by=admin.principal_id)
        seat(conn, tenant, mine, admin.principal_id, "ADMIN")
    before = source_row(admin_engine, tenant, source.source_id)
    for call in (
        lambda: store.rotate_source(db, admin, source.source_id, expires_at=later()),
        lambda: store.revoke_source(db, admin, source.source_id),
    ):
        with pytest.raises(MonitorError) as refused:
            call()
        assert refused.value.code == "INVALID_ADMIN"
    assert source_row(admin_engine, tenant, source.source_id) == before


def test_mc14_a_story_has_one_unrevoked_source_in_a_space(monitor_web, db, admin_engine):
    """A second source for a story that already has an unrevoked one in the space, expired or
    not, is refused `SOURCE_EXISTS` with nothing written, so minting again after an answer that
    was lost leaves one source to rotate rather than two. Another space registers its own, and
    once the first is revoked the story may be registered again."""
    _, admin, source, _ = monitor_web
    tenant = admin.tenant_id
    count = source_count(admin_engine, tenant)

    def again(**changes):
        return store.create_source(
            db, admin, label="Again", story_id="story-1", expires_at=later(), **changes
        )

    with pytest.raises(MonitorError) as refused:
        again()
    assert refused.value.code == "SOURCE_EXISTS"
    with admin_engine.begin() as conn:
        fenced(conn, tenant)
        conn.execute(
            text(
                "UPDATE execbound.monitor_sources SET created_at = :made, expires_at = :past "
                "WHERE tenant_id = :t AND source_id = :s"
            ),
            {
                "made": datetime.now(UTC) - timedelta(hours=2),
                "past": datetime.now(UTC) - timedelta(minutes=1),
                "t": tenant,
                "s": source.source_id,
            },
        )
        other = make_space(conn, tenant, "Customer B", created_by=admin.principal_id)
    # An expired source is rotated, not replaced.
    with pytest.raises(MonitorError) as refused:
        again()
    assert refused.value.code == "SOURCE_EXISTS"
    assert source_count(admin_engine, tenant) == count
    elsewhere = again(space=other)
    assert minted_row(admin_engine, tenant, elsewhere.source_id)["space_id"] == other
    store.revoke_source(db, admin, source.source_id)
    replaced = again()
    assert replaced.source_id != source.source_id
    assert source_count(admin_engine, tenant) == count + 2


def test_mc14_a_story_whose_source_has_kept_its_events_is_registered_again_beside_it(
    monitor_web, db, admin_engine, monkeypatch
):
    """A source that has kept its 10,000 events takes no more of its story's, and rotating it
    keeps that count, so the story is registered again while that source stands: a full
    workspace refuses the new one `SOURCE_CAPACITY` with nothing changed, and the full source
    still takes its story's heartbeats, so nothing is given up before there is room. A source
    one event short of the limit still refuses a second, and once the new source is made it
    refuses a third."""
    client, admin, source, _ = monitor_web
    tenant = admin.tenant_id
    room = store.MAX_SOURCES

    def kept(events):
        with admin_engine.begin() as conn:
            fenced(conn, tenant)
            conn.execute(
                text(
                    "UPDATE execbound.monitor_sources SET accepted_count = :events "
                    "WHERE tenant_id = :t AND source_id = :s"
                ),
                {"events": events, "t": tenant, "s": source.source_id},
            )

    def again():
        return store.create_source(db, admin, label="Again", story_id="story-1", expires_at=later())

    kept(store.MAX_SOURCE_EVENTS - 1)
    with pytest.raises(MonitorError) as refused:
        again()
    assert refused.value.code == "SOURCE_EXISTS"
    kept(store.MAX_SOURCE_EVENTS)
    count = source_count(admin_engine, tenant)
    before = source_row(admin_engine, tenant, source.source_id)
    monkeypatch.setattr(store, "MAX_SOURCES", count)
    with pytest.raises(MonitorError) as refused:
        again()
    assert refused.value.code == "SOURCE_CAPACITY"
    assert source_count(admin_engine, tenant) == count
    assert source_row(admin_engine, tenant, source.source_id) == before
    beat = client.post(
        "/v1/monitor/events",
        json={
            "version": 1,
            "event_id": "beat-at-capacity",
            "story_id": "story-1",
            "kind": "heartbeat",
            "occurred_at": datetime.now(UTC).isoformat(),
        },
        headers={"Authorization": "Bearer " + source.token},
    )
    assert beat.status_code == 202, beat.text
    monkeypatch.setattr(store, "MAX_SOURCES", room)
    replaced = again()
    assert replaced.source_id != source.source_id
    with pytest.raises(MonitorError) as refused:
        again()
    assert refused.value.code == "SOURCE_EXISTS"
    assert source_count(admin_engine, tenant) == count + 1
    # The full source stands until its administrator revokes it.
    assert source_row(admin_engine, tenant, source.source_id)["revoked_at"] is None


def mints_waiting(engine, count, *, within=4.0):
    """Wait until `count` backends of this database wait on another transaction's lock, inside
    the five seconds `Database.transaction` allows a lock wait."""
    deadline = time.monotonic() + within
    with engine.connect() as conn:
        while time.monotonic() < deadline:
            found = conn.execute(
                text(
                    "SELECT count(*) FROM pg_stat_activity WHERE datname = current_database() "
                    "AND state = 'active' AND wait_event_type = 'Lock'"
                )
            ).scalar_one()
            conn.rollback()
            if found >= count:
                return
            time.sleep(0.02)
    raise AssertionError(f"{count} mints never waited together")


def test_mc14_two_mints_of_one_story_at_once_make_one_source(monitor_web, db, admin_engine):
    """Two administrators' requests for the same story, on two connections at the same moment,
    make one source: the registry lock orders them and the second is refused.

    Each mints as its own administrator. A share lock on the sources table, held until both
    mints wait, stops whichever checks first between its check and its insert, so the other
    checks while the first is still uncommitted: under the registry lock it waits for the first
    to commit and is refused; under a lock taken per administrator, or none, both pass the
    check and the space holds two unrevoked sources."""
    _, admin, _, _ = monitor_web
    tenant = admin.tenant_id
    second = provision_identity(admin_engine, db, tenant, "ADMIN", datetime.now(UTC))
    assert second.principal_id != admin.principal_id
    count = source_count(admin_engine, tenant)
    outcomes: list[tuple[object, str]] = []

    def mint(identity):
        try:
            store.create_source(
                db, identity, label="Raced", story_id="story-raced", expires_at=later()
            )
        except MonitorError as exc:
            outcomes.append((identity.principal_id, exc.code))
        else:
            outcomes.append((identity.principal_id, "created"))

    threads = [threading.Thread(target=mint, args=(who,)) for who in (admin, second)]
    with admin_engine.connect() as gate:
        with gate.begin():
            # Reads pass a share lock and inserts wait on it: neither mint can write until both
            # are waiting, one on the insert and the other on the registry lock or its insert.
            gate.execute(text("LOCK TABLE execbound.monitor_sources IN SHARE MODE"))
            for thread in threads:
                thread.start()
            mints_waiting(admin_engine, 2)
    for thread in threads:
        thread.join(timeout=60)
    assert sorted(outcome for _, outcome in outcomes) == ["SOURCE_EXISTS", "created"]
    assert {who for who, _ in outcomes} == {admin.principal_id, second.principal_id}
    assert source_count(admin_engine, tenant) == count + 1
    (winner,) = (who for who, outcome in outcomes if outcome == "created")
    with admin_engine.begin() as conn:
        fenced(conn, tenant)
        made = (
            conn.execute(
                text(
                    "SELECT created_by FROM execbound.monitor_sources "
                    "WHERE tenant_id=:t AND story_id='story-raced'"
                ),
                {"t": tenant},
            )
            .scalars()
            .all()
        )
    assert made == [winner]
