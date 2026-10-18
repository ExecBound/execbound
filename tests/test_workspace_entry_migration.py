# SPDX-License-Identifier: AGPL-3.0-only
"""Migration 0082: the two functions that enter a workspace record when they did.

Real PostgreSQL. The upgrade adds `workspace_memberships.last_entered_at` and one stamp to each of
`account_session_open` and `account_switch`, keeps each function's grants, and the downgrade
restores both bodies byte for byte and drops the column. Under an owner that does not bypass row
security, as the hosted owner does not, a sign-in stamps the membership it opens and a switch
stamps the destination's.
"""

import importlib.util
from pathlib import Path
from uuid import uuid4

import pytest
from alembic import command
from alembic.script import ScriptDirectory
from signup_fixtures import stack as stack
from sqlalchemy import text
from test_dormant_catalog import alembic_config, empty_schema
from test_migration_without_bypass import fenced
from test_migration_without_bypass import restricted as restricted
from test_workspace_accounts import adopt, enroll

from execbound import db as database
from execbound import workspaces
from execbound.passwords import sign_in_with_password
from execbound.surfaces.sessions import issue_session, load_session

pytestmark = pytest.mark.integration

BEFORE = "0081_finding_acknowledgement"
TARGET = "0082_workspace_entry"
PATCHED = ("account_session_open", "account_switch")


def migration():
    path = Path(__file__).parents[1] / "migrations" / "versions" / f"{TARGET}.py"
    spec = importlib.util.spec_from_file_location(TARGET, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def catalog(conn):
    """Each patched function's definition and ACL, as the catalog holds them."""
    return {
        name: (definition, acl)
        for name, definition, acl in conn.execute(
            text(
                "SELECT p.proname, pg_get_functiondef(p.oid), CAST(p.proacl AS text) "
                "FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace "
                "WHERE n.nspname = 'execbound' AND p.proname = ANY(:names)"
            ),
            {"names": list(PATCHED)},
        ).all()
    }


def column(conn):
    return conn.execute(
        text(
            "SELECT data_type, is_nullable, column_default FROM information_schema.columns "
            "WHERE table_schema = 'execbound' AND table_name = 'workspace_memberships' "
            "AND column_name = 'last_entered_at'"
        )
    ).one_or_none()


def test_sn9_only_the_fragments_change_and_the_downgrade_restores_them(admin_engine):
    # Later migrations move the head past this one, so the test holds to its place in history.
    history = ScriptDirectory.from_config(alembic_config()).iterate_revisions(
        database.SCHEMA_REVISION, "base"
    )
    assert TARGET in {script.revision for script in history}
    module = migration()
    assert module.down_revision == BEFORE
    patches = {name: (before, after) for name, before, after in module.PATCHES}
    assert set(patches) == set(PATCHED)
    empty_schema(admin_engine)
    config = alembic_config()
    command.downgrade(config, BEFORE)
    try:
        with admin_engine.connect() as conn:
            before = catalog(conn)
            assert column(conn) is None
        for name, (anchor, _) in patches.items():
            # Each anchor occurs exactly once in the parent's definition; an anchor that looked
            # unique and was not would patch the wrong place.
            assert before[name][0].count(anchor) == 1, name
        command.upgrade(config, TARGET)
        with admin_engine.connect() as conn:
            after = catalog(conn)
            assert tuple(column(conn)) == ("timestamp with time zone", "YES", None)
            grants = conn.execute(
                text(
                    "SELECT privilege_type FROM information_schema.column_privileges "
                    "WHERE table_schema = 'execbound' AND table_name = 'workspace_memberships' "
                    "AND column_name = 'last_entered_at' AND grantee = 'execbound_app'"
                )
            ).scalars()
            # The runtime reads the column as it reads the rest of the row, and writes nothing.
            assert set(grants) == {"SELECT"}
        assert set(before) == set(after) == set(PATCHED)
        for name in PATCHED:
            old, acl = before[name]
            new, kept = after[name]
            assert kept == acl, name
            assert "execbound_app=X/execbound_owner" in kept, name
            anchor, replacement = patches[name]
            assert new == old.replace(anchor, replacement), name
            assert new.count("last_entered_at=p_now") == 1, name
        command.downgrade(config, BEFORE)
        with admin_engine.connect() as conn:
            assert catalog(conn) == before
            assert column(conn) is None
    finally:
        empty_schema(admin_engine)
        command.upgrade(config, "head")


def stamps(engine, account):
    with engine.begin() as conn:
        conn.execute(
            text("SELECT set_config('execbound.account_id', :a, true)"), {"a": str(account)}
        )
        return dict(
            conn.execute(
                text(
                    "SELECT tenant_id, last_entered_at FROM execbound.workspace_memberships "
                    "WHERE account_id = :a"
                ),
                {"a": account},
            ).all()
        )


def two_workspaces(engine, db):
    """An administrator of A adopted into an account that is also an approver in B, written
    fenced as the product writes, so an owner without bypass admits every row."""
    first, second = uuid4(), uuid4()
    for tenant in (first, second):
        with engine.begin() as conn:
            fenced(conn, tenant)
            conn.execute(
                text(
                    "INSERT INTO execbound.tenants(tenant_id, name, active) VALUES (:t, :n, true)"
                ),
                {"t": tenant, "n": f"tenant-{tenant.hex[:8]}"},
            )
    principal, _ = enroll(engine, first, kind="ADMIN")
    account = adopt(db, first, principal)
    other = uuid4()
    with engine.begin() as conn:
        fenced(conn, second)
        conn.execute(
            text("SELECT set_config('execbound.account_id', :a, true)"), {"a": str(account)}
        )
        conn.execute(
            text("UPDATE execbound.user_accounts SET email_verified_at=now() WHERE account_id=:a"),
            {"a": account},
        )
        conn.execute(
            text(
                "INSERT INTO execbound.principals(tenant_id,principal_id,kind) "
                "VALUES(:t,:p,'HUMAN_APPROVER')"
            ),
            {"t": second, "p": other},
        )
        conn.execute(
            text(
                "INSERT INTO execbound.workspace_memberships(account_id,tenant_id,principal_id) "
                "VALUES(:a,:t,:p)"
            ),
            {"a": account, "t": second, "p": other},
        )
        conn.execute(
            text("INSERT INTO execbound.access_principals(tenant_id,principal_id) VALUES(:t,:p)"),
            {"t": second, "p": other},
        )
        conn.execute(
            text(
                "INSERT INTO execbound.access_role_grants(tenant_id,grant_id,principal_id,role) "
                "VALUES(:t,:g,:p,'viewer')"
            ),
            {"t": second, "p": other, "g": uuid4()},
        )
    return first, second, account


def test_sn9_an_owner_without_bypass_stamps_the_entry(stack):
    engine, db = stack
    first, second, account = two_workspaces(engine, db)
    assert stamps(engine, account) == {first: None, second: None}

    grant = issue_session(
        db, sign_in_with_password(db, "member@example.test", "a retained example passphrase")
    )
    signed_in = stamps(engine, account)
    # The sign-in opened A, and stamped A alone.
    assert signed_in[first] is not None
    assert signed_in[second] is None

    switched = workspaces.switch_workspace(
        db, load_session(db, grant.token), grant.account_token, second
    )
    assert load_session(db, switched.token).identity.tenant_id == second
    after = stamps(engine, account)
    assert after[first] == signed_in[first]
    assert after[second] is not None and after[second] >= after[first]
