# SPDX-License-Identifier: AGPL-3.0-only
"""The reviewer group an invitation names: the migration (AR1).

The column, the definer function that sets it and the three patches to the acceptance, from
the previous head and back, on real PostgreSQL. The function is the runtime's to call and not
PUBLIC's; the acceptance carries each new fragment exactly once beside every fragment 0061
patched; the downgrade refuses while a pending invitation names a group, and otherwise restores
the acceptance byte for byte and drops the column and the function.
"""

import importlib.util
from pathlib import Path
from uuid import uuid4

import pytest
from alembic import command
from sqlalchemy import text
from test_dormant_catalog import alembic_config, empty_schema, revision_of
from test_migration_without_bypass import fenced
from test_teammate_invitations import invite, workspace

pytestmark = pytest.mark.integration

BEFORE = "0082_workspace_entry"
TARGET = "0083_invitation_reviewer_group"
VERSIONS = Path(__file__).resolve().parents[1] / "migrations" / "versions"
SET_GROUP = "workspace_invitation_set_group"
ACCEPT = "workspace_invitation_accept"


def migration(name):
    """A migration module itself, so a test reads the fragments it patches rather than copies."""
    spec = importlib.util.spec_from_file_location(name, VERSIONS / f"{name}.py")
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def definition(engine, name):
    with engine.connect() as conn:
        return conn.execute(
            text(
                "SELECT pg_get_functiondef(p.oid) FROM pg_proc p "
                "JOIN pg_namespace n ON n.oid = p.pronamespace "
                "WHERE n.nspname = 'execbound' AND p.proname = :n"
            ),
            {"n": name},
        ).scalar_one_or_none()


def column_exists(engine):
    with engine.connect() as conn:
        return bool(
            conn.execute(
                text(
                    "SELECT count(*) FROM pg_attribute "
                    "WHERE attrelid = CAST('execbound.workspace_invitations' AS regclass) "
                    "AND attname = 'reviewer_group_id' AND NOT attisdropped"
                )
            ).scalar_one()
        )


def invitations_forced(engine) -> bool:
    with engine.connect() as conn:
        return conn.execute(
            text(
                "SELECT relforcerowsecurity FROM pg_class "
                "WHERE oid = CAST('execbound.workspace_invitations' AS regclass)"
            )
        ).scalar_one()


def pending_with_group(db, admin_engine):
    """A pending invitation that names a group, written by the owner under the fence."""
    where = workspace(admin_engine)
    invitation, _ = invite(db, where, grants=[{"role": "approver", "space_id": None}])
    group = uuid4()
    with admin_engine.begin() as conn:
        fenced(conn, where["tenant_id"])
        conn.execute(
            text(
                "INSERT INTO execbound.access_groups(tenant_id, group_id, name) "
                "VALUES (:t, :g, 'Reviewers')"
            ),
            {"t": where["tenant_id"], "g": group},
        )
        conn.execute(
            text(
                "UPDATE execbound.workspace_invitations SET reviewer_group_id = :g "
                "WHERE invitation_id = :i"
            ),
            {"g": group, "i": invitation},
        )
    return where, invitation


def test_ar1_the_set_group_function_is_the_runtimes_and_not_publics(admin_engine, seeded):
    signature = "execbound.workspace_invitation_set_group(uuid, uuid, uuid, timestamptz)"
    with admin_engine.connect() as conn:
        definer, owner, acl = conn.execute(
            text(
                "SELECT prosecdef, pg_get_userbyid(proowner), CAST(proacl AS text) "
                "FROM pg_proc WHERE oid = CAST(:s AS regprocedure)"
            ),
            {"s": signature},
        ).one()
        runtime = conn.execute(
            text(
                "SELECT has_function_privilege("
                "'execbound_app', CAST(:s AS regprocedure), 'EXECUTE')"
            ),
            {"s": signature},
        ).scalar_one()
    assert definer is True
    assert runtime is True
    # After REVOKE ALL FROM PUBLIC only the owner's own entry and the runtime's remain.
    assert set(acl.strip("{}").split(",")) == {f"{owner}=X/{owner}", f"execbound_app=X/{owner}"}


def test_ar1_the_acceptance_gains_step_8b_exactly_once(admin_engine, seeded):
    body = definition(admin_engine, ACCEPT)
    this = migration(TARGET)
    for _, _, after in this.PATCHES:
        assert body.count(after) == 1
    for name, _, after in migration("0061_replaced_principals").PATCHES:
        if name == ACCEPT:
            assert body.count(after) == 1
    for reason in ("GROUP_GONE", "GROUP_ROLES", "GROUP_SCOPE", "GROUP_FULL"):
        assert body.count(f"'{reason}'") == 1


def test_ar1_downgrade_refuses_a_pending_invitation_with_a_group(db, admin_engine, seeded):
    config = alembic_config()
    empty_schema(admin_engine)
    # Later revisions move the head past this one; the refusal is this revision's own.
    command.downgrade(config, TARGET)
    try:
        pending_with_group(db, admin_engine)
        before = definition(admin_engine, ACCEPT)
        # The refused downgrade rolls back whole, so the schema stays at TARGET
        # (0083_invitation_reviewer_group).
        head = revision_of(admin_engine)
        with pytest.raises(RuntimeError, match="reviewer groups"):
            command.downgrade(config, BEFORE)
        assert revision_of(admin_engine) == head
        assert column_exists(admin_engine)
        assert definition(admin_engine, SET_GROUP) is not None
        assert definition(admin_engine, ACCEPT) == before
        assert invitations_forced(admin_engine) is True
    finally:
        empty_schema(admin_engine)
        command.upgrade(config, "head")


def test_ar1_downgrade_restores_the_acceptance_byte_for_byte(db, admin_engine, seeded):
    config = alembic_config()
    head = definition(admin_engine, ACCEPT)
    empty_schema(admin_engine)
    try:
        command.downgrade(config, BEFORE)
        previous = definition(admin_engine, ACCEPT)
        assert definition(admin_engine, SET_GROUP) is None
        assert not column_exists(admin_engine)
        command.upgrade(config, TARGET)
        upgraded = definition(admin_engine, ACCEPT)
        assert upgraded != previous
        expected = previous
        for _, before, after in migration(TARGET).PATCHES:
            assert expected.count(before) == 1
            expected = expected.replace(before, after)
        assert upgraded == expected
        command.downgrade(config, BEFORE)
        assert definition(admin_engine, ACCEPT) == previous
        assert definition(admin_engine, SET_GROUP) is None
        assert not column_exists(admin_engine)
        assert invitations_forced(admin_engine) is True
        command.upgrade(config, TARGET)
        assert definition(admin_engine, ACCEPT) == upgraded
    finally:
        empty_schema(admin_engine)
        command.upgrade(config, "head")
    assert definition(admin_engine, ACCEPT) == head
