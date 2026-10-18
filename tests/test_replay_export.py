# SPDX-License-Identifier: AGPL-3.0-only
"""Coherent, read-only exports and exclusive publication on guarded PostgreSQL."""

import hashlib
from dataclasses import replace
from pathlib import Path
from unittest.mock import patch

import pytest
from sqlalchemy import event, text
from test_execution import registry as registry
from test_execution import world as world

from execbound.audit import append_event
from execbound.db import TABLES
from execbound.provider.connector import MockConnector
from execbound.replay import export as exporter
from execbound.replay.export import ExportError, export_history, publish_export
from execbound.replay.verify import parse_export, verify_export

pytestmark = pytest.mark.integration


def fingerprint(engine):
    with engine.connect() as conn:
        rows = [
            conn.execute(
                text(
                    f"SELECT count(*),string_agg(md5(to_jsonb(r)::text),',' "
                    f"ORDER BY to_jsonb(r)::text) FROM execbound.{table} r"
                )
            ).one()
            for table in TABLES
        ]
    return hashlib.sha256(repr(rows).encode()).hexdigest()


def append(db, world, **payload):
    with db.transaction(world["identity"].tenant_id) as conn:
        return append_event(
            conn,
            world["identity"].tenant_id,
            world["identity"].principal_id,
            "test.recorded",
            payload,
        )


def publish(db, world, tmp_path, history=None):
    history = history or export_history(db, world["admin"], world["clock"])
    output, checkpoint = tmp_path / "history.json", tmp_path / "checkpoint.json"
    publish_export(
        db, world["admin"], history, output=output, checkpoint=checkpoint, clock=world["clock"]
    )
    return output, checkpoint


def test_export_publishes_full_prefix_and_referenced_immutable_bundle_without_writes(
    db,
    world,
    admin_engine,
    tmp_path,
    monkeypatch,
):
    def no_provider(*args, **kwargs):
        raise AssertionError("Tenant export cannot invoke providers")

    for method in ("__init__", "dispatch", "lookup", "cancel"):
        monkeypatch.setattr(MockConnector, method, no_provider)
    append(db, world, index=1)
    before = fingerprint(admin_engine)
    history = export_history(db, world["admin"], world["clock"])
    assert tuple(e.sequence for e in history.events) == tuple(range(1, history.head.sequence + 1))
    assert [b.bundle_id for b in history.bundles] == [world["bundle"].bundle_id]
    assert history.bundles[0].content_hash == world["bundle"].content_hash
    output, checkpoint = publish(db, world, tmp_path, history)
    parsed = parse_export(output.read_bytes())
    assert parsed == history
    assert checkpoint.read_text("utf-8") == history.head.model_dump_json() + "\n"
    verify_export(parsed, history.head)
    assert fingerprint(admin_engine) == before
    assert sorted(p.name for p in tmp_path.iterdir()) == ["checkpoint.json", "history.json"]


def test_empty_history_does_not_create_a_head_or_export_unreferenced_current_policy(
    db,
    world,
    admin_engine,
):
    with admin_engine.begin() as conn:
        conn.execute(text("DELETE FROM execbound.audit_events"))
        conn.execute(text("DELETE FROM execbound.audit_heads"))
    before = fingerprint(admin_engine)
    history = export_history(db, world["admin"], world["clock"])
    assert history.head.sequence == 0 and history.head.event_hash == "0" * 64
    assert history.events == () and history.bundles == ()
    assert fingerprint(admin_engine) == before


def test_current_inventory_and_policy_lifecycle_do_not_rewrite_history(db, world, admin_engine):
    before = export_history(db, world["admin"], world["clock"])
    with admin_engine.begin() as conn:
        conn.execute(text("UPDATE execbound.policy_bundle_lifecycle SET state='RETIRED'"))
        conn.execute(text("DELETE FROM execbound.space_policy_selection"))
        conn.execute(text("UPDATE execbound.resources SET role='domain_controller',version='new'"))
    assert export_history(db, world["admin"], world["clock"]) == before


@pytest.mark.parametrize("actor", ["identity", "human"])
def test_export_requires_current_admin(db, world, actor):
    with pytest.raises(ExportError):
        export_history(db, world[actor], world["clock"])


@pytest.mark.parametrize(
    "change", ["revoked", "expired", "kind", "principal", "tenant", "expiry_snapshot"]
)
def test_current_authority_changes_reject_export(db, world, admin_engine, change):
    admin = world["admin"]
    with admin_engine.begin() as conn:
        statement = {
            "revoked": "UPDATE execbound.credentials SET revoked_at=now() WHERE credential_id=:c",
            "expired": "UPDATE execbound.credentials SET expires_at=now()-interval '1 day' "
            "WHERE credential_id=:c",
            "kind": (
                "UPDATE execbound.principals SET kind='AGENT', space_id="
                "(SELECT space_id FROM execbound.spaces s "
                "WHERE s.tenant_id = principals.tenant_id) WHERE principal_id=:p"
            ),
            "principal": "UPDATE execbound.principals SET active=false WHERE principal_id=:p",
            "tenant": "UPDATE execbound.tenants SET active=false WHERE tenant_id=:t",
            "expiry_snapshot": "UPDATE execbound.credentials "
            "SET expires_at=expires_at+interval '1 minute' WHERE credential_id=:c",
        }[change]
        conn.execute(
            text(statement),
            {"c": admin.credential_id, "p": admin.principal_id, "t": admin.tenant_id},
        )
    with pytest.raises(ExportError):
        export_history(db, admin, world["clock"])


def test_export_clock_expiry_rejects_without_artifacts(db, world, tmp_path):
    world["clock"].value = world["admin"].expires_at
    with pytest.raises(ExportError):
        publish(db, world, tmp_path)
    assert list(tmp_path.iterdir()) == []


def test_foreign_tenant_bundle_id_collision_cannot_enter_export(db, world, seeded, admin_engine):
    foreign = world["bundle"].model_copy(update={"tenant_id": seeded["tenants"][1]})
    with admin_engine.begin() as conn:
        conn.execute(
            text(
                "INSERT INTO execbound.policy_bundle_contents "
                "(tenant_id,bundle_id,content_hash,content,created_at,created_by, space_id) "
                "VALUES (:t,:b,:h,CAST(:v AS jsonb),now(),:p, "
                "(SELECT space_id FROM execbound.spaces WHERE tenant_id = :t))"
            ),
            {
                "t": foreign.tenant_id,
                "b": foreign.bundle_id,
                "h": foreign.content_hash,
                "v": foreign.model_dump_json(),
                "p": seeded["principals"][1],
            },
        )
    with db.transaction(foreign.tenant_id) as conn:
        append_event(
            conn,
            foreign.tenant_id,
            seeded["principals"][1],
            "policy.bundle_created",
            {"bundle_id": str(foreign.bundle_id), "content_hash": foreign.content_hash},
        )
    history = export_history(db, world["admin"], world["clock"])
    assert all(e.tenant_id == world["admin"].tenant_id for e in history.events)
    assert [b.content_hash for b in history.bundles] == [world["bundle"].content_hash]
    with pytest.raises(ExportError):
        export_history(db, replace(world["admin"], tenant_id=foreign.tenant_id), world["clock"])


def test_append_after_head_read_keeps_one_repeatable_read_prefix(db, world):
    appended = []

    def concurrent_append(conn, cursor, statement, parameters, context, executemany):
        if "FROM execbound.audit_heads" in statement and not appended:
            appended.append(True)
            append(db, world, during_export=True)

    event.listen(db.engine, "after_cursor_execute", concurrent_append)
    try:
        history = export_history(db, world["admin"], world["clock"])
    finally:
        event.remove(db.engine, "after_cursor_execute", concurrent_append)
    assert appended == [True]
    assert not any(e.payload.get("during_export") for e in history.events)
    verify_export(history, history.head)
    later = export_history(db, world["admin"], world["clock"])
    assert later.head.sequence == history.head.sequence + 1


@pytest.mark.parametrize(
    "corruption",
    ["payload", "head", "missing_head", "bundle_hash", "bundle_content", "missing_bundle"],
)
def test_corrupt_or_missing_history_and_bundle_fail_closed(db, world, admin_engine, corruption):
    with admin_engine.begin() as conn:
        if corruption == "payload":
            conn.execute(
                text("UPDATE execbound.audit_events SET payload='{}'::jsonb WHERE sequence=1")
            )
        elif corruption == "head":
            conn.execute(text("UPDATE execbound.audit_heads SET sequence=sequence+1"))
        elif corruption == "missing_head":
            conn.execute(text("DELETE FROM execbound.audit_heads"))
        elif corruption == "bundle_hash":
            conn.execute(
                text(
                    "UPDATE execbound.policy_bundle_contents SET content=content||"
                    "jsonb_build_object('authorization_policies','permit(principal,action,resource);')"
                )
            )
        elif corruption == "bundle_content":
            conn.execute(text("UPDATE execbound.policy_bundle_contents SET content='{}'::jsonb"))
        else:
            conn.execute(text("DELETE FROM execbound.space_policy_selection"))
            conn.execute(text("DELETE FROM execbound.tenant_policy_control"))
            conn.execute(text("DELETE FROM execbound.policy_bundle_lifecycle"))
            conn.execute(text("DELETE FROM execbound.policy_bundle_contents"))
    with pytest.raises(ExportError):
        export_history(db, world["admin"], world["clock"])


@pytest.mark.parametrize(
    "limit,value", [("MAX_EVENTS", 1), ("MAX_EXPORT_BYTES", 100), ("MAX_BUNDLES", 0)]
)
def test_export_limits_refuse_instead_of_truncating(db, world, monkeypatch, limit, value):
    monkeypatch.setattr(exporter, limit, value)
    with pytest.raises(ExportError):
        export_history(db, world["admin"], world["clock"])


def test_export_transaction_prevents_accidental_database_write(db, world, admin_engine):
    before = fingerprint(admin_engine)
    attempted = []

    def try_write(conn, cursor, statement, parameters, context, executemany):
        if "FROM execbound.audit_heads" in statement and not attempted:
            attempted.append(True)
            conn.execute(
                text(
                    "INSERT INTO execbound.audit_heads(tenant_id) VALUES (:t) "
                    "ON CONFLICT (tenant_id) DO UPDATE SET sequence=999"
                ),
                {"t": world["admin"].tenant_id},
            )

    event.listen(db.engine, "before_cursor_execute", try_write)
    try:
        with pytest.raises(ExportError):
            export_history(db, world["admin"], world["clock"])
    finally:
        event.remove(db.engine, "before_cursor_execute", try_write)
    assert attempted == [True]
    assert fingerprint(admin_engine) == before


def test_fresh_authority_check_rejects_revocation_after_snapshot_and_staging(
    db,
    world,
    admin_engine,
    tmp_path,
    monkeypatch,
):
    history = export_history(db, world["admin"], world["clock"])
    original = exporter._stage
    staged = []

    def revoke_after_stage(data, destination):
        result = original(data, destination)
        staged.append(result)
        if len(staged) == 2:
            with admin_engine.begin() as conn:
                conn.execute(
                    text(
                        "UPDATE execbound.credentials SET revoked_at=now() WHERE credential_id=:c"
                    ),
                    {"c": world["admin"].credential_id},
                )
        return result

    monkeypatch.setattr(exporter, "_stage", revoke_after_stage)
    with pytest.raises(ExportError):
        publish(db, world, tmp_path, history)
    assert len(staged) == 2
    assert list(tmp_path.iterdir()) == []


@pytest.mark.parametrize("existing", ["history.json", "checkpoint.json"])
def test_publication_never_overwrites_existing_output(db, world, tmp_path, existing):
    path = tmp_path / existing
    path.write_bytes(b"private pre-existing canary")
    with pytest.raises(ExportError):
        publish(db, world, tmp_path)
    assert path.read_bytes() == b"private pre-existing canary"
    assert list(tmp_path.iterdir()) == [path]


def test_publication_rejects_alias_paths(db, world, tmp_path):
    history = export_history(db, world["admin"], world["clock"])
    path = tmp_path / "history.json"
    with pytest.raises(ExportError):
        publish_export(
            db, world["admin"], history, output=path, checkpoint=path, clock=world["clock"]
        )
    assert list(tmp_path.iterdir()) == []


def test_partial_publication_failure_cleans_only_owned_files(db, world, tmp_path):
    original = exporter.os.link
    linked = []

    def fail_second(source, destination):
        if linked:
            raise OSError("private failure canary")
        original(source, destination)
        linked.append(Path(destination))

    with patch.object(exporter.os, "link", fail_second), pytest.raises(ExportError) as error:
        publish(db, world, tmp_path)
    assert "canary" not in str(error.value)
    assert error.value.__context__ is None
    assert linked == [tmp_path / "checkpoint.json"]
    assert list(tmp_path.iterdir()) == []


def test_publication_rechecks_tampered_model_and_tenant(db, world, tmp_path):
    history = export_history(db, world["admin"], world["clock"])
    forged = history.model_copy(update={"head": history.head.model_copy(update={"sequence": 0})})
    with pytest.raises(ExportError):
        publish(db, world, tmp_path, forged)
    assert list(tmp_path.iterdir()) == []


def test_revocation_during_checkpoint_publication_prevents_complete_export(
    db,
    world,
    admin_engine,
    tmp_path,
):
    original = exporter.os.link
    linked = []

    def revoke_after_checkpoint(source, destination):
        original(source, destination)
        linked.append(Path(destination))
        if len(linked) == 1:
            with admin_engine.begin() as conn:
                conn.execute(
                    text(
                        "UPDATE execbound.credentials SET revoked_at=now() WHERE credential_id=:c"
                    ),
                    {"c": world["admin"].credential_id},
                )

    with patch.object(exporter.os, "link", revoke_after_checkpoint), pytest.raises(ExportError):
        publish(db, world, tmp_path)
    assert linked == [tmp_path / "checkpoint.json"]
    assert list(tmp_path.iterdir()) == []


@pytest.mark.parametrize(
    "payload",
    [
        {"token_hash": "a" * 64},
        {"nested": {"owner_hash": "b" * 64}},
        {"authorization": "Bearer eb1.private-canary"},
    ],
)
def test_secret_bearing_history_is_refused_without_redacting_its_chain(db, world, payload):
    append(db, world, **payload)
    with pytest.raises(ExportError):
        export_history(db, world["admin"], world["clock"])
