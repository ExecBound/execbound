# SPDX-License-Identifier: AGPL-3.0-only
"""Migration 0089: a workspace switch carries a recent verification and records its source.

Real PostgreSQL. The upgrade adds four nullable source and destination columns to
`user_security_events`, held by the check `user_security_events_carry` to the `assurance_carried`
kind, and patches `account_switch` in four places: a declaration, the read of the source's
verification while the tenant setting is still the source's, the carried row and the account's
record under the destination's, and three keys in the returned object. The function keeps its
grants, and the downgrade restores the parent's body byte for byte and drops the check and the
columns. Under an owner that does not bypass row security, as the hosted owner does not, a switch
writes both rows and reads them back, and only the account's own setting reads its record.
"""

import importlib.util
from datetime import UTC, datetime
from pathlib import Path
from uuid import uuid4

import pytest
from alembic import command
from alembic.script import ScriptDirectory
from signup_fixtures import stack as stack
from sqlalchemy import text
from sqlalchemy.exc import IntegrityError
from test_dormant_catalog import alembic_config, empty_schema
from test_migration_without_bypass import fenced
from test_migration_without_bypass import restricted as restricted
from test_workspace_entry_migration import two_workspaces
from test_workspace_switching import member_pair

from execbound import db as database
from execbound import mfa, workspaces
from execbound.envelope import KeyRing
from execbound.passwords import sign_in_with_password
from execbound.surfaces.sessions import issue_session, load_session

pytestmark = pytest.mark.integration

BEFORE = "0088_monitor_entra_consent"
TARGET = "0089_assurance_carry"
COLUMNS = (
    "source_tenant_id",
    "source_session_id",
    "destination_tenant_id",
    "destination_session_id",
)
RING = KeyRing("test", {"test": b"m" * 32})


def migration():
    path = Path(__file__).parents[1] / "migrations" / "versions" / f"{TARGET}.py"
    spec = importlib.util.spec_from_file_location(TARGET, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def switch_function(conn):
    """`account_switch`'s definition and ACL, as the catalog holds them."""
    return conn.execute(
        text(
            "SELECT pg_get_functiondef(p.oid), CAST(p.proacl AS text) "
            "FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace "
            "WHERE n.nspname = 'execbound' AND p.proname = 'account_switch'"
        )
    ).one()


def columns(conn):
    return {
        name: (data_type, nullable)
        for name, data_type, nullable in conn.execute(
            text(
                "SELECT column_name, data_type, is_nullable FROM information_schema.columns "
                "WHERE table_schema = 'execbound' AND table_name = 'user_security_events' "
                "AND column_name = ANY(:names)"
            ),
            {"names": list(COLUMNS)},
        ).all()
    }


def check(conn):
    return conn.execute(
        text(
            "SELECT pg_get_constraintdef(c.oid) FROM pg_constraint c "
            "JOIN pg_class r ON r.oid = c.conrelid "
            "JOIN pg_namespace n ON n.oid = r.relnamespace "
            "WHERE n.nspname = 'execbound' AND r.relname = 'user_security_events' "
            "AND c.conname = 'user_security_events_carry'"
        )
    ).scalar_one_or_none()


def test_sn22_only_the_fragments_change_and_the_downgrade_restores_them(admin_engine):
    # Later migrations move the head past this one, so the test holds to its place in history.
    history = ScriptDirectory.from_config(alembic_config()).iterate_revisions(
        database.SCHEMA_REVISION, "base"
    )
    assert TARGET in {script.revision for script in history}
    module = migration()
    assert module.down_revision == BEFORE
    assert len(module.PATCHES) == 4
    empty_schema(admin_engine)
    config = alembic_config()
    command.downgrade(config, BEFORE)
    try:
        with admin_engine.connect() as conn:
            old, acl = switch_function(conn)
            assert columns(conn) == {}
            assert check(conn) is None
        expected = old
        for before, after in module.PATCHES:
            # Each anchor occurs exactly once in the parent's definition; an anchor that looked
            # unique and was not would patch the wrong place.
            assert old.count(before) == 1, before
            assert expected.count(before) == 1, before
            expected = expected.replace(before, after)
        command.upgrade(config, TARGET)
        with admin_engine.connect() as conn:
            new, kept = switch_function(conn)
            assert columns(conn) == {name: ("uuid", "YES") for name in COLUMNS}
            assert check(conn) is not None
            grants = set(
                conn.execute(
                    text(
                        "SELECT privilege_type FROM information_schema.column_privileges "
                        "WHERE table_schema = 'execbound' "
                        "AND table_name = 'user_security_events' "
                        "AND column_name = ANY(:names) AND grantee = 'execbound_app'"
                    ),
                    {"names": list(COLUMNS)},
                ).scalars()
            )
            # The runtime reads the columns as it reads the rest of the row, and writes nothing.
            assert grants == {"SELECT"}
        assert kept == acl
        assert "execbound_app=X/execbound_owner" in kept
        # Only the four fragments changed, in the places they name.
        assert new == expected
        assert new.count("carried") > 0 and old.count("carried") == 0
        command.downgrade(config, BEFORE)
        with admin_engine.connect() as conn:
            assert switch_function(conn) == (old, acl)
            assert columns(conn) == {}
            assert check(conn) is None
    finally:
        empty_schema(admin_engine)
        command.upgrade(config, "head")


def assurance(engine, tenant, session):
    with engine.begin() as conn:
        fenced(conn, tenant)
        return (
            conn.execute(
                text(
                    "SELECT version, verified_at, method FROM execbound.session_assurance "
                    "WHERE tenant_id = :t AND session_id = :s"
                ),
                {"t": tenant, "s": session},
            )
            .mappings()
            .one_or_none()
        )


def carried_records(engine, account):
    with engine.begin() as conn:
        conn.execute(
            text("SELECT set_config('execbound.account_id', :a, true)"), {"a": str(account)}
        )
        return [
            dict(row)
            for row in conn.execute(
                text(
                    "SELECT kind, " + ", ".join(COLUMNS) + " FROM execbound.user_security_events "
                    "WHERE account_id = :a AND kind = 'assurance_carried'"
                ),
                {"a": account},
            ).mappings()
        ]


def verified(db, session):
    """The account's authenticator confirmed on this session, which verifies it there now."""
    seed = mfa.begin_enrollment(db, session, RING)
    mfa.confirm_enrollment(
        db, session, RING, mfa.totp(seed, int(datetime.now(UTC).timestamp()) // 30)
    )


def test_sn22_an_owner_without_bypass_carries_and_records_the_source(stack):
    engine, db = stack
    first, second, account = two_workspaces(engine, db)
    grant = issue_session(
        db, sign_in_with_password(db, "member@example.test", "a retained example passphrase")
    )
    current = load_session(db, grant.token)
    verified(db, current)
    source = assurance(engine, first, current.session_id)
    assert source is not None

    switched = workspaces.switch_workspace(
        db, load_session(db, grant.token), grant.account_token, second
    )
    # The destination opens with the source's own verification, read back through the owner.
    assert not switched.mfa_required
    assert load_session(db, switched.token).identity.tenant_id == second
    assert assurance(engine, second, switched.session_id) == source
    assert carried_records(engine, account) == [
        {
            "kind": "assurance_carried",
            "source_tenant_id": first,
            "source_session_id": current.session_id,
            "destination_tenant_id": second,
            "destination_session_id": switched.session_id,
        }
    ]


def test_sn22_only_the_account_reads_the_source(db, admin_engine, seeded):
    grant, current, account, _ = member_pair(db, admin_engine, seeded)
    first, second = seeded["tenants"]
    verified(db, current)
    switched = workspaces.switch_workspace(
        db, load_session(db, grant.token), grant.account_token, second
    )
    read = text(
        "SELECT " + ", ".join(COLUMNS) + " FROM execbound.user_security_events "
        "WHERE kind = 'assurance_carried'"
    )

    def as_runtime(**settings):
        with db.engine.begin() as conn:
            for name, value in settings.items():
                conn.execute(
                    text("SELECT set_config(:n, :v, true)"),
                    {"n": f"execbound.{name}", "v": str(value)},
                )
            return [tuple(row) for row in conn.execute(read).all()]

    assert as_runtime(account_id=account) == [
        (first, current.session_id, second, switched.session_id)
    ]
    # Another account, and either workspace's own setting alone, read nothing of it.
    assert as_runtime(account_id=uuid4()) == []
    assert as_runtime(tenant_id=first) == []
    assert as_runtime(tenant_id=second) == []
    assert as_runtime(tenant_id=second, account_id=uuid4()) == []

    # Source and destination columns belong to a carry alone, and a carry names all four.
    for kind, values in (
        ("password.changed", (first, None, None, None)),
        ("assurance_carried", (first, current.session_id, second, None)),
    ):
        with pytest.raises(IntegrityError, match="user_security_events_carry"):
            with admin_engine.begin() as conn:
                conn.execute(
                    text(
                        "INSERT INTO execbound.user_security_events"
                        "(account_id, kind, occurred_at, " + ", ".join(COLUMNS) + ") "
                        "VALUES (:a, :k, now(), :st, :ss, :dt, :ds)"
                    ),
                    {
                        "a": account,
                        "k": kind,
                        **dict(zip(("st", "ss", "dt", "ds"), values, strict=True)),
                    },
                )
