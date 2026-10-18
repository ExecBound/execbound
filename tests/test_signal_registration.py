# SPDX-License-Identifier: AGPL-3.0-only
"""Owner registration of signal sources (docs/SIGNALS.md, "Register a producer")."""

import os
import stat
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta
from uuid import UUID, uuid4

import pytest
from conftest import assert_secret_free
from signal_fixtures import ADMIT, admit_params, admit_raw, insert_source, signal_fields
from sqlalchemy import event, text
from test_context_provisioning import cli_env as cli_env
from test_context_provisioning import owner as owner
from test_context_provisioning import refused_cli, run_cli
from test_execution import world as world
from test_migration_without_bypass import fenced
from test_resolution import registry as registry

from execbound import provisioning
from execbound.provisioning import (
    ProvisioningError,
    create_signal_source,
    list_signal_sources,
    revoke_signal_source,
    rotate_signal_source,
)
from execbound.replay.verify import _INFORMATIONAL
from execbound.signals.tokens import digest, selectors


def register(owner, world, tmp_path, **changes):
    values = {
        "label": "MDE lab",
        "producer": "execbound-mde-producer",
        "version_min": "0.1.0",
        "version_max": "0.9.9",
        "capabilities": ("resource_compromise.v1",),
        "principals": (world["identity"].principal_id,),
        "lifetime": timedelta(hours=8),
        "output": tmp_path / "token",
    }
    values.update(changes)
    return create_signal_source(
        owner, world["identity"].tenant_id, world["admin"].principal_id, **values
    )


def token_of(grant):
    return grant.output.read_text(encoding="ascii").strip()


def admit(db, world, grant, token, now, **changes):
    fields = signal_fields(world["account"], now, **changes)
    return admit_raw(db, world["identity"].tenant_id, grant.source_id, token, now, **fields)


def source_row(admin_engine, tenant, source):
    with admin_engine.begin() as conn:
        fenced(conn, tenant)
        return (
            conn.execute(
                text("SELECT * FROM execbound.signal_sources WHERE source_id = :s"),
                {"s": source},
            )
            .mappings()
            .one()
        )


def signal_audit(admin_engine, tenant):
    with admin_engine.begin() as conn:
        fenced(conn, tenant)
        return (
            conn.execute(
                text(
                    "SELECT kind, payload, space_id FROM execbound.audit_events "
                    "WHERE tenant_id = :t AND kind LIKE 'signal_source.%' ORDER BY sequence"
                ),
                {"t": tenant},
            )
            .mappings()
            .all()
        )


def test_registration_writes_the_token_once_privately_and_audits_without_it(
    owner, world, tmp_path, admin_engine
):
    grant = register(owner, world, tmp_path)
    token = token_of(grant)
    assert stat.S_IMODE(os.stat(grant.output).st_mode) == 0o600
    assert selectors(token) == (world["identity"].tenant_id, grant.source_id)
    with admin_engine.begin() as conn:
        fenced(conn, world["identity"].tenant_id)
        row = (
            conn.execute(
                text(
                    "SELECT token_hash, input_path, attests_liveness, principal_ids, "
                    "subject_kinds, placement FROM execbound.signal_sources "
                    "WHERE source_id = :s"
                ),
                {"s": grant.source_id},
            )
            .mappings()
            .one()
        )
        payload = conn.execute(
            text(
                "SELECT payload FROM execbound.audit_events "
                "WHERE tenant_id = :t AND kind = 'signal_source.created'"
            ),
            {"t": world["identity"].tenant_id},
        ).scalar_one()
    assert row["token_hash"] == digest(token)
    assert (row["input_path"], row["attests_liveness"], row["placement"]) == (
        "independent",
        False,
        "out_of_process",
    )
    assert row["subject_kinds"] == ["resource"]
    assert [str(value) for value in row["principal_ids"]] == [str(world["identity"].principal_id)]
    assert_secret_free(payload, known=(token, digest(token)))


@pytest.mark.parametrize(
    "changes,code",
    [
        ({"label": " "}, "INVALID_LABEL"),
        ({"label": None}, "INVALID_LABEL"),
        ({"producer": "Bad Name"}, "INVALID_PRODUCER"),
        ({"producer": None}, "INVALID_PRODUCER"),
        ({"version_min": "1.0"}, "INVALID_VERSION"),
        ({"version_max": "0.9"}, "INVALID_VERSION"),
        ({"version_min": "1.0.0", "version_max": "0.9.9"}, "INVALID_VERSION"),
        ({"capabilities": ("content_integrity.v1",)}, "INVALID_CAPABILITY"),
        ({"capabilities": ()}, "INVALID_CAPABILITY"),
        (
            {"capabilities": ("resource_compromise.v1", "resource_compromise.v1")},
            "INVALID_CAPABILITY",
        ),
        ({"input_path": "sideways"}, "INVALID_INPUT_PATH"),
        ({"offered": "yes"}, "INVALID_INPUT"),
        ({"attests_liveness": 1}, "INVALID_INPUT"),
        ({"lifetime": timedelta(hours=721)}, "INVALID_LIFETIME"),
        ({"lifetime": timedelta(minutes=59)}, "INVALID_LIFETIME"),
        ({"principals": ()}, "INVALID_SCOPE"),
        ({"group": uuid4()}, "INVALID_SCOPE"),
        ({"principals": tuple(uuid4() for _ in range(65))}, "INVALID_SCOPE"),
        ({"now": datetime(2026, 9, 28, 12)}, "INVALID_CLOCK"),
    ],
)
def test_a_malformed_registration_is_refused_before_any_file_exists(
    owner, world, tmp_path, changes, code
):
    with pytest.raises(ProvisioningError) as caught:
        register(owner, world, tmp_path, **changes)
    assert caught.value.code == code
    assert not (tmp_path / "token").exists()


def test_a_principal_named_twice_is_refused(owner, world, tmp_path):
    agent = world["identity"].principal_id
    with pytest.raises(ProvisioningError) as caught:
        register(owner, world, tmp_path, principals=(agent, agent))
    assert caught.value.code == "INVALID_SCOPE"
    assert not (tmp_path / "token").exists()


@pytest.mark.parametrize("who", ["admin", "unknown", "foreign", "deactivated"])
def test_a_scope_that_is_not_the_tenants_agents_is_refused_and_leaves_no_file(
    owner, world, seeded, tmp_path, admin_engine, who
):
    principal = {
        "admin": world["admin"].principal_id,
        "unknown": uuid4(),
        # The other seeded tenant's agent.
        "foreign": seeded["principals"][1],
        "deactivated": uuid4(),
    }[who]
    if who == "deactivated":
        tenant = world["identity"].tenant_id
        with admin_engine.begin() as conn:
            fenced(conn, tenant)
            conn.execute(
                text(
                    "INSERT INTO execbound.principals (tenant_id, principal_id, kind, space_id, "
                    "active, deactivated_at) VALUES (:t, :p, 'AGENT', "
                    "(SELECT space_id FROM execbound.spaces WHERE tenant_id = :t), false, now())"
                ),
                {"t": tenant, "p": principal},
            )
    with pytest.raises(ProvisioningError) as caught:
        register(owner, world, tmp_path, principals=(principal,))
    assert caught.value.code == "INVALID_PRINCIPAL"
    assert not (tmp_path / "token").exists()


def test_an_unknown_group_and_a_non_admin_actor_are_refused(owner, world, tmp_path):
    with pytest.raises(ProvisioningError) as caught:
        register(owner, world, tmp_path, principals=(), group=uuid4())
    assert caught.value.code == "INVALID_GROUP"
    with pytest.raises(ProvisioningError) as caught:
        create_signal_source(
            owner,
            world["identity"].tenant_id,
            world["identity"].principal_id,
            label="MDE lab",
            producer="execbound-mde-producer",
            version_min="0.1.0",
            version_max="0.9.9",
            capabilities=("resource_compromise.v1",),
            principals=(world["identity"].principal_id,),
            lifetime=timedelta(hours=8),
            output=tmp_path / "token",
        )
    assert caught.value.code == "INVALID_ACTOR"
    assert not (tmp_path / "token").exists()


def test_a_group_scope_is_stored_without_a_principal_list(owner, world, tmp_path, admin_engine):
    tenant, group = world["identity"].tenant_id, uuid4()
    with admin_engine.begin() as conn:
        fenced(conn, tenant)
        conn.execute(
            text(
                "INSERT INTO execbound.principal_groups (tenant_id, group_id, name, created_at) "
                "VALUES (:t, :g, 'Responders', now())"
            ),
            {"t": tenant, "g": group},
        )
    grant = register(owner, world, tmp_path, principals=(), group=group)
    row = source_row(admin_engine, tenant, grant.source_id)
    assert (row["principal_ids"], row["principal_group_id"]) == (None, group)


def test_a_space_must_be_named_when_the_tenant_has_several(
    owner, world, seeded, tmp_path, admin_engine
):
    tenant = world["identity"].tenant_id
    with pytest.raises(ProvisioningError) as caught:
        register(owner, world, tmp_path, space=uuid4())
    assert caught.value.code == "INVALID_SPACE"
    # Another tenant's space is not this tenant's.
    with pytest.raises(ProvisioningError) as caught:
        register(owner, world, tmp_path, space=seeded["spaces"][1])
    assert caught.value.code == "INVALID_SPACE"
    second = uuid4()
    with admin_engine.begin() as conn:
        fenced(conn, tenant)
        conn.execute(
            text(
                "INSERT INTO execbound.spaces (tenant_id, space_id, name, created_at, created_by) "
                "VALUES (:t, :s, 'Second', now(), :p)"
            ),
            {"t": tenant, "s": second, "p": world["admin"].principal_id},
        )
    with pytest.raises(ProvisioningError) as caught:
        register(owner, world, tmp_path)
    assert caught.value.code == "INVALID_SPACE"
    assert not (tmp_path / "token").exists()
    grant = register(owner, world, tmp_path, space=second)
    assert source_row(admin_engine, tenant, grant.source_id)["space_id"] == second


def test_an_existing_output_file_is_never_overwritten(owner, world, tmp_path):
    (tmp_path / "token").write_text("keep me")
    with pytest.raises(ProvisioningError) as caught:
        register(owner, world, tmp_path)
    assert caught.value.code == "OUTPUT_UNAVAILABLE"
    assert (tmp_path / "token").read_text() == "keep me"


def test_rotation_keeps_the_old_token_only_through_its_grace(
    db, owner, world, tmp_path, admin_engine
):
    grant = register(owner, world, tmp_path)
    old = token_of(grant)
    now = datetime.now(UTC)
    rotated = rotate_signal_source(
        owner,
        world["identity"].tenant_id,
        grant.source_id,
        world["admin"].principal_id,
        lifetime=timedelta(hours=8),
        grace_seconds=30,
        output=tmp_path / "rotated",
        now=now,
    )
    new = token_of(rotated)
    assert stat.S_IMODE(os.stat(rotated.output).st_mode) == 0o600
    assert selectors(new) == (world["identity"].tenant_id, grant.source_id)
    assert admit(db, world, grant, old, now + timedelta(seconds=10))["accepted"]
    assert admit(db, world, grant, old, now + timedelta(seconds=31), event_id="late") == {
        "refused": "INVALID_SOURCE",
        "reason": "MISMATCH",
    }
    assert admit(db, world, grant, new, now + timedelta(seconds=31), event_id="late")["accepted"]
    events = signal_audit(admin_engine, world["identity"].tenant_id)
    assert [event["kind"] for event in events] == [
        "signal_source.created",
        "signal_source.rotated",
    ]
    assert_secret_free(
        [event["payload"] for event in events], known=(old, new, digest(old), digest(new))
    )


def test_rotation_without_grace_stops_the_old_token_at_once(
    db, owner, world, tmp_path, admin_engine
):
    grant = register(owner, world, tmp_path)
    old = token_of(grant)
    now = datetime.now(UTC)
    rotated = rotate_signal_source(
        owner,
        world["identity"].tenant_id,
        grant.source_id,
        world["admin"].principal_id,
        lifetime=timedelta(hours=8),
        grace_seconds=0,
        output=tmp_path / "rotated",
        now=now,
    )
    row = source_row(admin_engine, world["identity"].tenant_id, grant.source_id)
    assert (row["previous_token_hash"], row["previous_valid_until"]) == (None, None)
    assert admit(db, world, grant, old, now) == {"refused": "INVALID_SOURCE", "reason": "MISMATCH"}
    assert admit(db, world, grant, token_of(rotated), now)["accepted"]


def test_the_grace_never_outlasts_the_old_tokens_expiry(owner, world, tmp_path, admin_engine):
    now = datetime.now(UTC)
    # Registered almost an hour ago for an hour, so the old token has seconds left.
    grant = register(
        owner, world, tmp_path, lifetime=timedelta(hours=1), now=now - timedelta(minutes=59)
    )
    rotate_signal_source(
        owner,
        world["identity"].tenant_id,
        grant.source_id,
        world["admin"].principal_id,
        lifetime=timedelta(hours=8),
        grace_seconds=600,
        output=tmp_path / "rotated",
        now=now,
    )
    row = source_row(admin_engine, world["identity"].tenant_id, grant.source_id)
    assert row["previous_valid_until"] == now - timedelta(minutes=59) + timedelta(hours=1)
    assert row["expires_at"] == now + timedelta(hours=8)


@pytest.mark.parametrize(
    "changes,code",
    [
        ({"grace_seconds": -1}, "INVALID_GRACE"),
        ({"grace_seconds": 3601}, "INVALID_GRACE"),
        ({"grace_seconds": True}, "INVALID_GRACE"),
        ({"lifetime": timedelta(hours=721)}, "INVALID_LIFETIME"),
        ({"lifetime": timedelta(minutes=59)}, "INVALID_LIFETIME"),
        ({"source": "unknown"}, "INVALID_SOURCE"),
        ({"source": "foreign"}, "INVALID_SOURCE"),
    ],
)
def test_a_malformed_rotation_is_refused_and_leaves_no_file(
    owner, world, seeded, tmp_path, admin_engine, changes, code
):
    grant = register(owner, world, tmp_path)
    before = source_row(admin_engine, world["identity"].tenant_id, grant.source_id)
    source = changes.pop("source", None)
    if source == "unknown":
        source = uuid4()
    elif source == "foreign":
        # A source registered in the other seeded tenant.
        with admin_engine.begin() as conn:
            fenced(conn, seeded["tenants"][1])
            source, _ = insert_source(
                conn, seeded["tenants"][1], seeded["principals"][1], datetime.now(UTC)
            )
    values = {"lifetime": timedelta(hours=8), "output": tmp_path / "rotated", **changes}
    with pytest.raises(ProvisioningError) as caught:
        rotate_signal_source(
            owner,
            world["identity"].tenant_id,
            source or grant.source_id,
            world["admin"].principal_id,
            **values,
        )
    assert caught.value.code == code
    assert not (tmp_path / "rotated").exists()
    assert source_row(admin_engine, world["identity"].tenant_id, grant.source_id) == before


def test_revocation_is_immediate_and_final(db, owner, world, tmp_path, admin_engine):
    grant = register(owner, world, tmp_path)
    token = token_of(grant)
    revoke_signal_source(
        owner, world["identity"].tenant_id, grant.source_id, world["admin"].principal_id
    )
    assert admit(db, world, grant, token, datetime.now(UTC)) == {
        "refused": "INVALID_SOURCE",
        "reason": "REVOKED",
    }
    with pytest.raises(ProvisioningError) as caught:
        rotate_signal_source(
            owner,
            world["identity"].tenant_id,
            grant.source_id,
            world["admin"].principal_id,
            lifetime=timedelta(hours=8),
            output=tmp_path / "again",
        )
    assert caught.value.code == "INVALID_STATE"
    assert not (tmp_path / "again").exists()
    with pytest.raises(ProvisioningError) as caught:
        revoke_signal_source(
            owner, world["identity"].tenant_id, grant.source_id, world["admin"].principal_id
        )
    assert caught.value.code == "INVALID_STATE"
    assert [event["kind"] for event in signal_audit(admin_engine, world["identity"].tenant_id)] == [
        "signal_source.created",
        "signal_source.revoked",
    ]


def test_revoking_an_unknown_or_foreign_source_is_refused(owner, world, seeded, admin_engine):
    with admin_engine.begin() as conn:
        fenced(conn, seeded["tenants"][1])
        foreign, _ = insert_source(
            conn, seeded["tenants"][1], seeded["principals"][1], datetime.now(UTC)
        )
    for source in (uuid4(), foreign):
        with pytest.raises(ProvisioningError) as caught:
            revoke_signal_source(
                owner, world["identity"].tenant_id, source, world["admin"].principal_id
            )
        assert caught.value.code == "INVALID_SOURCE"
    assert source_row(admin_engine, seeded["tenants"][1], foreign)["active"] is True


def test_revocation_inside_a_grace_window_ends_the_previous_token_too(
    db, owner, world, tmp_path, admin_engine
):
    tenant, actor = world["identity"].tenant_id, world["admin"].principal_id
    grant = register(owner, world, tmp_path)
    old = token_of(grant)
    rotated = rotate_signal_source(
        owner,
        tenant,
        grant.source_id,
        actor,
        lifetime=timedelta(hours=8),
        grace_seconds=600,
        output=tmp_path / "rotated",
    )
    row = source_row(admin_engine, tenant, grant.source_id)
    assert row["previous_token_hash"] == digest(old) and row["previous_valid_until"] is not None
    revoke_signal_source(owner, tenant, grant.source_id, actor)
    row = source_row(admin_engine, tenant, grant.source_id)
    assert (row["previous_token_hash"], row["previous_valid_until"]) == (None, None)
    now = datetime.now(UTC)
    assert admit(db, world, grant, old, now) == {"refused": "INVALID_SOURCE", "reason": "MISMATCH"}
    assert admit(db, world, grant, token_of(rotated), now) == {
        "refused": "INVALID_SOURCE",
        "reason": "REVOKED",
    }


def test_every_change_to_a_source_is_audited_in_its_space(owner, world, tmp_path, admin_engine):
    tenant, actor = world["identity"].tenant_id, world["admin"].principal_id
    grant = register(owner, world, tmp_path)
    rotated = rotate_signal_source(
        owner,
        tenant,
        grant.source_id,
        actor,
        lifetime=timedelta(hours=8),
        output=tmp_path / "rotated",
    )
    revoke_signal_source(owner, tenant, grant.source_id, actor)
    space = source_row(admin_engine, tenant, grant.source_id)["space_id"]
    events = signal_audit(admin_engine, tenant)
    assert [(event["kind"], event["space_id"]) for event in events] == [
        ("signal_source.created", space),
        ("signal_source.rotated", space),
        ("signal_source.revoked", space),
    ]
    old, new = token_of(grant), token_of(rotated)
    assert_secret_free(
        [event["payload"] for event in events], known=(old, new, digest(old), digest(new))
    )


@pytest.mark.parametrize(
    "call,argument",
    [
        ("create", "tenant"),
        ("rotate", "tenant"),
        ("rotate", "source"),
        ("revoke", "tenant"),
        ("revoke", "source"),
    ],
)
def test_an_id_that_is_not_a_uuid_is_refused(owner, world, tmp_path, admin_engine, call, argument):
    """The database would match an id given as text, even in capitals; the token parser would
    not, so a token minted from one would never open `/v1/signals`."""
    tenant, actor = world["identity"].tenant_id, world["admin"].principal_id
    grant = register(owner, world, tmp_path)
    before = source_row(admin_engine, tenant, grant.source_id)
    ids = {"tenant": tenant, "source": grant.source_id}
    ids[argument] = str(ids[argument]).upper()
    with pytest.raises(ProvisioningError) as caught:
        if call == "create":
            create_signal_source(
                owner,
                ids["tenant"],
                actor,
                label="MDE lab",
                producer="execbound-mde-producer",
                version_min="0.1.0",
                version_max="0.9.9",
                capabilities=("resource_compromise.v1",),
                principals=(world["identity"].principal_id,),
                lifetime=timedelta(hours=8),
                output=tmp_path / "other",
            )
        elif call == "rotate":
            rotate_signal_source(
                owner,
                ids["tenant"],
                ids["source"],
                actor,
                lifetime=timedelta(hours=8),
                output=tmp_path / "other",
            )
        else:
            revoke_signal_source(owner, ids["tenant"], ids["source"], actor)
    assert caught.value.code == "INVALID_INPUT"
    assert not (tmp_path / "other").exists()
    assert source_row(admin_engine, tenant, grant.source_id) == before
    assert len(list_signal_sources(owner, tenant)) == 1


def failing_commit(engine):
    """A listener that raises as the transaction commits, which the command cannot tell apart
    from a commit whose reply was lost."""

    def fail(connection):
        raise OSError("the reply was lost")

    event.listen(engine, "commit", fail)
    return lambda: event.remove(engine, "commit", fail)


def test_a_failed_commit_leaves_no_token_file(owner, world, tmp_path):
    """The token is written before the commit; a commit that fails takes the file with it."""
    undo = failing_commit(owner)
    try:
        with pytest.raises(OSError):
            register(owner, world, tmp_path)
    finally:
        undo()
    assert not (tmp_path / "token").exists()
    assert list_signal_sources(owner, world["identity"].tenant_id) == []


def test_a_failed_rotation_commit_leaves_no_token_file_and_the_old_token(
    db, owner, world, tmp_path, admin_engine
):
    tenant = world["identity"].tenant_id
    grant = register(owner, world, tmp_path)
    before = source_row(admin_engine, tenant, grant.source_id)
    undo = failing_commit(owner)
    try:
        with pytest.raises(OSError):
            rotate_signal_source(
                owner,
                tenant,
                grant.source_id,
                world["admin"].principal_id,
                lifetime=timedelta(hours=8),
                output=tmp_path / "rotated",
            )
    finally:
        undo()
    assert not (tmp_path / "rotated").exists()
    assert source_row(admin_engine, tenant, grant.source_id) == before
    assert admit(db, world, grant, token_of(grant), datetime.now(UTC))["accepted"]


@pytest.mark.parametrize("change", ["rotate", "revoke"])
def test_a_change_waits_for_an_admission_holding_the_source(
    db, owner, world, tmp_path, monkeypatch, change
):
    """Rotation and revocation lock the source row, as `signal_admit` does, so they serialize.

    An admission not yet committed holds the row; the change waits for it and, past its lock
    timeout, is refused with nothing written, and no token file left behind.
    """
    grant = register(owner, world, tmp_path)
    token, tenant = token_of(grant), world["identity"].tenant_id
    now = datetime.now(UTC)
    monkeypatch.setattr(provisioning, "LOCK_TIMEOUT_MS", 200)
    with db.transaction(tenant) as holder:
        fields = signal_fields(world["account"], now)
        assert holder.execute(
            ADMIT, admit_params(grant.source_id, token, now, **fields)
        ).scalar_one()["accepted"]
        with pytest.raises(ProvisioningError) as caught:
            if change == "rotate":
                rotate_signal_source(
                    owner,
                    tenant,
                    grant.source_id,
                    world["admin"].principal_id,
                    lifetime=timedelta(hours=8),
                    output=tmp_path / "rotated",
                )
            else:
                revoke_signal_source(owner, tenant, grant.source_id, world["admin"].principal_id)
        assert caught.value.code == "PROVISIONING_UNAVAILABLE"
    assert not (tmp_path / "rotated").exists()
    assert admit(db, world, grant, token, now, event_id="after")["accepted"]


@pytest.mark.parametrize("change", ["rotate", "revoke"])
def test_a_change_decides_on_the_committed_row_never_a_stale_read(
    owner, world, tmp_path, admin_engine, change
):
    """A revocation in flight is seen, not overwritten: the change reads the row it locked.

    Read without a lock, the row would still say active, and the change's own write would
    then land on a source revoked a moment before it: a new token for a revoked producer, or
    a second revocation over the first.
    """
    grant = register(owner, world, tmp_path)
    tenant, actor = world["identity"].tenant_id, world["admin"].principal_id

    def run():
        if change == "rotate":
            return rotate_signal_source(
                owner,
                tenant,
                grant.source_id,
                actor,
                lifetime=timedelta(hours=8),
                output=tmp_path / "rotated",
            )
        return revoke_signal_source(owner, tenant, grant.source_id, actor)

    with ThreadPoolExecutor(max_workers=1) as pool:
        with admin_engine.begin() as holder:
            fenced(holder, tenant)
            holder.execute(
                text(
                    "UPDATE execbound.signal_sources SET active = false, revoked_at = now(), "
                    "revoked_by = :a WHERE source_id = :s"
                ),
                {"a": actor, "s": grant.source_id},
            )
            pending = pool.submit(run)
            deadline = time.monotonic() + 5
            with admin_engine.connect() as watcher:
                while not watcher.execute(
                    text(
                        "SELECT EXISTS (SELECT 1 FROM pg_stat_activity "
                        "WHERE datname = current_database() AND wait_event_type = 'Lock')"
                    )
                ).scalar_one():
                    assert time.monotonic() < deadline and not pending.done()
                    time.sleep(0.02)
        with pytest.raises(ProvisioningError) as caught:
            pending.result(timeout=10)
    assert caught.value.code == "INVALID_STATE"
    assert not (tmp_path / "rotated").exists()
    row = source_row(admin_engine, tenant, grant.source_id)
    assert (row["rotated_at"], row["token_hash"]) == (None, digest(token_of(grant)))


def test_the_list_shows_registration_and_health_and_no_digest(
    db, owner, world, tmp_path, admin_engine
):
    grant = register(owner, world, tmp_path)
    old = token_of(grant)
    admit(db, world, grant, old, datetime.now(UTC))
    rotated = rotate_signal_source(
        owner,
        world["identity"].tenant_id,
        grant.source_id,
        world["admin"].principal_id,
        lifetime=timedelta(hours=8),
        grace_seconds=30,
        output=tmp_path / "rotated",
    )
    new = token_of(rotated)
    (listed,) = list_signal_sources(owner, world["identity"].tenant_id)
    assert listed["source_id"] == str(grant.source_id)
    assert listed["record_count"] == 1
    assert listed["last_accepted_at"] is not None
    # When the previous token stops working is the operator's to see; its digest is not.
    row = source_row(admin_engine, world["identity"].tenant_id, grant.source_id)
    assert listed["previous_valid_until"] == str(row["previous_valid_until"])
    assert not {"token_hash", "previous_token_hash"} & set(listed)
    assert_secret_free(listed, known=(old, new, digest(old), digest(new)))


def cli_arguments(world, *, version_min: str, output) -> list[str]:
    return [
        "signal-source-create",
        "--tenant", str(world["identity"].tenant_id),
        "--actor", str(world["admin"].principal_id),
        "--label", "MDE lab",
        "--producer", "execbound-mde-producer",
        "--version-min", version_min,
        "--version-max", "0.9.9",
        "--principal", str(world["identity"].principal_id),
        "--output", str(output),
    ]  # fmt: skip


def read_token(path):
    token = path.read_text(encoding="ascii").strip()
    return token, digest(token)


def test_the_cli_registers_and_refuses(cli_env, monkeypatch, capsys, world, tmp_path):
    created = run_cli(
        monkeypatch, capsys, *cli_arguments(world, version_min="0.1.0", output=tmp_path / "t")
    )
    known = read_token(tmp_path / "t")
    assert_secret_free(created, known=known)
    assert selectors(known[0])[1] == UUID(created["source_id"])
    refused = refused_cli(
        monkeypatch, capsys, *cli_arguments(world, version_min="1.0", output=tmp_path / "u")
    )
    assert "Provisioning refused: INVALID_VERSION." in refused
    assert_secret_free(refused, known=known)
    assert not (tmp_path / "u").exists()


def test_the_cli_lists_rotates_and_revokes(cli_env, monkeypatch, capsys, world, tmp_path):
    tenant, actor = str(world["identity"].tenant_id), str(world["admin"].principal_id)
    created = run_cli(
        monkeypatch, capsys, *cli_arguments(world, version_min="0.1.0", output=tmp_path / "t")
    )
    source = created["source_id"]
    known = read_token(tmp_path / "t")
    assert_secret_free(created, known=known)
    (listed,) = run_cli(monkeypatch, capsys, "signal-source-list", "--tenant", tenant)
    assert_secret_free(listed, known=known)
    assert (listed["source_id"], listed["active"]) == (source, True)
    rotated = run_cli(
        monkeypatch, capsys,
        "signal-source-rotate", "--tenant", tenant, "--source", source, "--actor", actor,
        "--hours", "8", "--grace-seconds", "30", "--output", str(tmp_path / "r"),
    )  # fmt: skip
    known += read_token(tmp_path / "r")
    assert_secret_free(rotated, known=known)
    assert rotated["source_id"] == source
    assert selectors(known[2])[1] == UUID(source)
    (listed,) = run_cli(monkeypatch, capsys, "signal-source-list", "--tenant", tenant)
    assert_secret_free(listed, known=known)
    assert listed["previous_valid_until"] is not None
    revoked = run_cli(
        monkeypatch, capsys,
        "signal-source-revoke", "--tenant", tenant, "--source", source, "--actor", actor,
    )  # fmt: skip
    assert_secret_free(revoked, known=known)
    assert revoked == {"source_id": source, "active": False}
    (listed,) = run_cli(monkeypatch, capsys, "signal-source-list", "--tenant", tenant)
    assert_secret_free(listed, known=known)
    assert listed["active"] is False and listed["rotated_at"] is not None
    assert listed["previous_valid_until"] is None
    refused = refused_cli(
        monkeypatch, capsys,
        "signal-source-revoke", "--tenant", tenant, "--source", source, "--actor", actor,
    )  # fmt: skip
    assert "Provisioning refused: INVALID_STATE." in refused


# Past what a timedelta holds, past the 720-hour bound, and none at all.
@pytest.mark.parametrize("hours", ["1000000000000", "721", "0"])
def test_the_cli_refuses_a_lifetime_out_of_bounds_as_a_refusal(
    cli_env, monkeypatch, capsys, world, tmp_path, hours
):
    refused = refused_cli(
        monkeypatch,
        capsys,
        *cli_arguments(world, version_min="0.1.0", output=tmp_path / "t"),
        "--hours",
        hours,
    )
    assert "Provisioning refused: INVALID_LIFETIME." in refused
    assert not (tmp_path / "t").exists()
    created = run_cli(
        monkeypatch, capsys, *cli_arguments(world, version_min="0.1.0", output=tmp_path / "t")
    )
    refused = refused_cli(
        monkeypatch, capsys,
        "signal-source-rotate", "--tenant", str(world["identity"].tenant_id),
        "--source", created["source_id"], "--actor", str(world["admin"].principal_id),
        "--hours", hours, "--output", str(tmp_path / "r"),
    )  # fmt: skip
    assert "Provisioning refused: INVALID_LIFETIME." in refused
    assert not (tmp_path / "r").exists()


def test_the_three_audit_kinds_decide_nothing_for_replay():
    assert {"signal_source.created", "signal_source.rotated", "signal_source.revoked"} <= set(
        _INFORMATIONAL
    )
