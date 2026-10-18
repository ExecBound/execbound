# SPDX-License-Identifier: AGPL-3.0-only
"""An agent key's last use, a recorded rotation, and who has a second factor (0079).

Every case runs on real PostgreSQL as the runtime role, inside the tenant fence the product
sets. The three definer functions are called directly here; authentication's own stamp and
the console routes that call the other two have tests of their own.
"""

import os
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import timedelta
from uuid import UUID, uuid4

import pytest
from alembic import command
from conftest import local_test_url
from sqlalchemy import text
from sqlalchemy.exc import DBAPIError
from test_dormant_catalog import alembic_config, empty_schema
from test_execution import provision_credential, provision_identity
from test_protected_path import request
from test_runtime import api as api
from test_runtime import connector as connector
from test_runtime import live_provider as live_provider
from test_runtime import registry as registry
from test_runtime import runtime as runtime
from test_runtime import world as world

from execbound import identity
from execbound.db import Database, check_runtime
from execbound.identity import AuthenticationFailed, authenticate

pytestmark = pytest.mark.integration

BEFORE = "0078_weekly_summary"
TARGET = "0079_key_last_used"
FUNCTIONS = ("credential_used", "admin_credential_replaces", "admin_member_factors")
STAMP = "SELECT execbound.credential_used(:c, :n)"
REPLACES = "SELECT execbound.admin_credential_replaces(:a, :c, :r)"
FACTORS = (
    "SELECT principal_id, enrolled FROM execbound.admin_member_factors(:a, CAST(:ids AS uuid[]))"
)


def database_now(admin_engine):
    with admin_engine.connect() as conn:
        return conn.execute(text("SELECT statement_timestamp()")).scalar_one()


def credential_of(token: str) -> UUID:
    return UUID(token.split(".")[2])


def new_agent(admin_engine, tenant) -> UUID:
    principal = uuid4()
    with admin_engine.begin() as conn:
        conn.execute(
            text(
                "INSERT INTO execbound.principals(tenant_id, principal_id, kind, space_id) "
                "VALUES (:t, :p, 'AGENT', "
                "(SELECT space_id FROM execbound.spaces WHERE tenant_id = :t))"
            ),
            {"t": tenant, "p": principal},
        )
    return principal


def new_key(admin_engine, tenant, principal, issued_at, lifetime=timedelta(days=30)) -> UUID:
    with admin_engine.begin() as conn:
        token = provision_credential(conn, tenant, principal, issued_at, lifetime)
    return credential_of(token)


def key_row(admin_engine, tenant, credential):
    with admin_engine.connect() as conn:
        return (
            conn.execute(
                text(
                    "SELECT last_used_at, replaces_credential_id FROM execbound.credentials "
                    "WHERE tenant_id = :t AND credential_id = :c"
                ),
                {"t": tenant, "c": credential},
            )
            .mappings()
            .one()
        )


def stamp(db, tenant, credential, at):
    with db.transaction(tenant) as conn:
        conn.execute(text(STAMP), {"c": credential, "n": at})


def definitions(conn):
    return {
        row.proname: (row.prosecdef, row.owner, row.acl)
        for row in conn.execute(
            text(
                "SELECT p.proname, p.prosecdef, CAST(p.proowner AS regrole) AS owner, "
                "CAST(p.proacl AS text[]) AS acl FROM pg_proc p "
                "JOIN pg_namespace n ON n.oid = p.pronamespace "
                "WHERE n.nspname = 'execbound' AND p.proname = ANY(:names)"
            ),
            {"names": list(FUNCTIONS)},
        )
    }


def columns(conn):
    return set(
        conn.execute(
            text(
                "SELECT column_name FROM information_schema.columns "
                "WHERE table_schema = 'execbound' AND table_name = 'credentials' "
                "AND column_name IN ('last_used_at', 'replaces_credential_id')"
            )
        ).scalars()
    )


def index_exists(conn) -> bool:
    return bool(
        conn.execute(
            text(
                "SELECT 1 FROM pg_indexes WHERE schemaname = 'execbound' "
                "AND indexname = 'credentials_replaces_idx'"
            )
        ).scalar()
    )


def test_ak4_the_migration_adds_both_columns_and_three_functions_and_the_downgrade_removes_them(
    admin_engine,
):
    empty_schema(admin_engine)
    config = alembic_config()
    command.downgrade(config, BEFORE)
    try:
        with admin_engine.connect() as conn:
            assert definitions(conn) == {}
            assert columns(conn) == set()
            assert not index_exists(conn)
        command.upgrade(config, TARGET)
        with admin_engine.connect() as conn:
            found = definitions(conn)
            assert set(found) == set(FUNCTIONS)
            for prosecdef, owner, acl in found.values():
                assert prosecdef
                assert owner == "execbound_owner"
                # After REVOKE ALL FROM PUBLIC the owner's own entry is explicit.
                assert set(acl) == {
                    "execbound_owner=X/execbound_owner",
                    "execbound_app=X/execbound_owner",
                }
            assert columns(conn) == {"last_used_at", "replaces_credential_id"}
            assert index_exists(conn)
            for column in ("last_used_at", "replaces_credential_id"):
                assert conn.execute(
                    text(
                        "SELECT has_column_privilege('execbound_app', 'execbound.credentials', "
                        ":c, 'SELECT')"
                    ),
                    {"c": column},
                ).scalar_one()
            assert not conn.execute(
                text(
                    "SELECT has_any_column_privilege('execbound_app', 'execbound.credentials', "
                    "'UPDATE')"
                )
            ).scalar_one()
            checks = conn.execute(
                text(
                    "SELECT pg_get_constraintdef(oid) FROM pg_constraint "
                    "WHERE conrelid = 'execbound.credentials'::regclass AND contype = 'c'"
                )
            ).scalars()
            assert not any("last_used_at" in check for check in checks)
        command.downgrade(config, BEFORE)
        with admin_engine.connect() as conn:
            assert definitions(conn) == {}
            assert columns(conn) == set()
            assert not index_exists(conn)
    finally:
        empty_schema(admin_engine)
        command.upgrade(config, "head")


def test_ak4_check_runtime_accepts_the_migrated_schema(db, seeded):
    with db.transaction(seeded["tenants"][0]) as conn:
        check_runtime(conn)


def test_ak2_credential_used_stamps_once_a_minute_and_only_a_live_key(db, admin_engine, seeded):
    tenant, other_tenant = seeded["tenants"]
    now = database_now(admin_engine)
    agent = new_agent(admin_engine, tenant)
    key = new_key(admin_engine, tenant, agent, now - timedelta(minutes=2))

    stamp(db, tenant, key, now)
    assert key_row(admin_engine, tenant, key)["last_used_at"] == now
    stamp(db, tenant, key, now + timedelta(seconds=30))
    assert key_row(admin_engine, tenant, key)["last_used_at"] == now
    stamp(db, tenant, key, now + timedelta(seconds=61))
    assert key_row(admin_engine, tenant, key)["last_used_at"] == now + timedelta(seconds=61)

    # An application clock ahead of the database's: the key's issued_at is after this use.
    ahead = new_key(admin_engine, tenant, agent, now + timedelta(seconds=60))
    stamp(db, tenant, ahead, now)
    assert key_row(admin_engine, tenant, ahead)["last_used_at"] is None

    revoked = new_key(admin_engine, tenant, agent, now - timedelta(minutes=2))
    expired = new_key(
        admin_engine, tenant, agent, now - timedelta(minutes=2), lifetime=timedelta(minutes=1)
    )
    deleted = new_key(admin_engine, tenant, agent, now - timedelta(minutes=2))
    with admin_engine.begin() as conn:
        conn.execute(
            text(
                "UPDATE execbound.credentials SET revoked_at = :n "
                "WHERE tenant_id = :t AND credential_id IN (:r, :d)"
            ),
            {"n": now - timedelta(minutes=1), "t": tenant, "r": revoked, "d": deleted},
        )
        conn.execute(
            text(
                "UPDATE execbound.credentials SET deleted_at = :n "
                "WHERE tenant_id = :t AND credential_id = :d"
            ),
            {"n": now - timedelta(seconds=30), "t": tenant, "d": deleted},
        )
    for credential in (revoked, expired, deleted):
        stamp(db, tenant, credential, now)
        assert key_row(admin_engine, tenant, credential)["last_used_at"] is None

    # Another tenant's key, named under this tenant's fence, is not this tenant's to stamp.
    stranger = new_key(
        admin_engine, other_tenant, new_agent(admin_engine, other_tenant), now - timedelta(hours=1)
    )
    stamp(db, tenant, stranger, now)
    assert key_row(admin_engine, other_tenant, stranger)["last_used_at"] is None

    with db.engine.connect() as conn, conn.begin():
        with pytest.raises(DBAPIError, match="INVALID_TENANT"):
            conn.execute(text(STAMP), {"c": key, "n": now})
    with pytest.raises(DBAPIError, match="INVALID_CLOCK"):
        stamp(db, tenant, key, now + timedelta(seconds=301))


def test_ak3_credential_used_skips_a_locked_row(db, admin_engine, seeded):
    tenant = seeded["tenants"][0]
    now = database_now(admin_engine)
    key = new_key(admin_engine, tenant, new_agent(admin_engine, tenant), now - timedelta(hours=1))
    with admin_engine.connect() as holder, holder.begin():
        holder.execute(
            text(
                "SELECT 1 FROM execbound.credentials "
                "WHERE tenant_id = :t AND credential_id = :c FOR UPDATE"
            ),
            {"t": tenant, "c": key},
        )
        with db.transaction(tenant) as conn:
            conn.execute(text("SET LOCAL lock_timeout = '1s'"))
            conn.execute(text(STAMP), {"c": key, "n": database_now(admin_engine)})
    assert key_row(admin_engine, tenant, key)["last_used_at"] is None


def actors(admin_engine, db, seeded):
    tenant, other_tenant = seeded["tenants"]
    now = database_now(admin_engine)
    admin = provision_identity(admin_engine, db, tenant, "ADMIN", now).principal_id
    approver = provision_identity(admin_engine, db, tenant, "HUMAN_APPROVER", now).principal_id
    retired = provision_identity(admin_engine, db, tenant, "ADMIN", now).principal_id
    stranger = provision_identity(admin_engine, db, other_tenant, "ADMIN", now).principal_id
    with admin_engine.begin() as conn:
        conn.execute(
            text(
                "UPDATE execbound.principals SET active = false "
                "WHERE tenant_id = :t AND principal_id = :p"
            ),
            {"t": tenant, "p": retired},
        )
    return {"admin": admin, "approver": approver, "retired": retired, "stranger": stranger}


def test_ak5_admin_credential_replaces_records_a_rotation_and_refuses_the_rest(
    db, admin_engine, seeded
):
    tenant = seeded["tenants"][0]
    who = actors(admin_engine, db, seeded)
    now = database_now(admin_engine)
    agent, other = new_agent(admin_engine, tenant), new_agent(admin_engine, tenant)
    old = new_key(admin_engine, tenant, agent, now - timedelta(hours=1))
    new = new_key(admin_engine, tenant, agent, now)

    def replaces(credential, replaced, actor=who["admin"], fence=tenant):
        with db.transaction(fence) as conn:
            conn.execute(text(REPLACES), {"a": actor, "c": credential, "r": replaced})

    others_key = new_key(admin_engine, tenant, other, now - timedelta(hours=1))
    revoked = new_key(admin_engine, tenant, agent, now - timedelta(hours=1))
    deleted = new_key(admin_engine, tenant, agent, now - timedelta(hours=1))
    expired = new_key(
        admin_engine, tenant, agent, now - timedelta(hours=1), lifetime=timedelta(minutes=5)
    )
    with admin_engine.begin() as conn:
        conn.execute(
            text(
                "UPDATE execbound.credentials SET revoked_at = :n "
                "WHERE tenant_id = :t AND credential_id IN (:r, :d)"
            ),
            {"n": now - timedelta(minutes=10), "t": tenant, "r": revoked, "d": deleted},
        )
        conn.execute(
            text(
                "UPDATE execbound.credentials SET deleted_at = :n "
                "WHERE tenant_id = :t AND credential_id = :d"
            ),
            {"n": now - timedelta(minutes=5), "t": tenant, "d": deleted},
        )
    for replaced in (others_key, revoked, deleted, expired, new):
        with pytest.raises(DBAPIError, match="INVALID_REPLACEMENT"):
            replaces(new, replaced)
        assert key_row(admin_engine, tenant, new)["replaces_credential_id"] is None

    with pytest.raises(DBAPIError, match="INVALID_ACTOR"):
        replaces(new, old, actor=who["approver"])
    with db.engine.connect() as conn, conn.begin():
        with pytest.raises(DBAPIError, match="INVALID_TENANT"):
            conn.execute(text(REPLACES), {"a": who["admin"], "c": new, "r": old})
    assert key_row(admin_engine, tenant, new)["replaces_credential_id"] is None

    replaces(new, old)
    assert key_row(admin_engine, tenant, new)["replaces_credential_id"] == old

    # A key that already names one names nothing else, and a key a live key already names
    # cannot be named again.
    spare = new_key(admin_engine, tenant, agent, now - timedelta(hours=1))
    with pytest.raises(DBAPIError, match="INVALID_REPLACEMENT"):
        replaces(new, spare)
    third = new_key(admin_engine, tenant, agent, now)
    with pytest.raises(DBAPIError, match="INVALID_REPLACEMENT"):
        replaces(third, old)
    assert key_row(admin_engine, tenant, new)["replaces_credential_id"] == old
    assert key_row(admin_engine, tenant, third)["replaces_credential_id"] is None


def person(admin_engine, tenant, kind="HUMAN_APPROVER") -> UUID:
    principal = uuid4()
    with admin_engine.begin() as conn:
        conn.execute(
            text(
                "INSERT INTO execbound.principals(tenant_id, principal_id, kind) "
                "VALUES (:t, :p, :k)"
            ),
            {"t": tenant, "p": principal, "k": kind},
        )
    return principal


def legacy_factor(admin_engine, tenant, principal, *, enabled: bool) -> None:
    with admin_engine.begin() as conn:
        conn.execute(
            text(
                "INSERT INTO execbound.account_factors"
                "(tenant_id, principal_id, sealed, key_id, enabled_at) "
                "VALUES (:t, :p, :s, :k, CASE WHEN :e THEN now() END)"
            ),
            {
                "t": tenant,
                "p": principal,
                "s": "sealed" if enabled else None,
                "k": "key" if enabled else None,
                "e": enabled,
            },
        )


def member_factor(admin_engine, tenant, principal, *, enabled: bool | None) -> UUID:
    """A membership account for the person, with an enabled or disabled factor, or none."""
    account = uuid4()
    with admin_engine.begin() as conn:
        conn.execute(
            text("INSERT INTO execbound.user_accounts(account_id, email) VALUES (:a, :e)"),
            {"a": account, "e": f"{account.hex}@example.test"},
        )
        conn.execute(
            text(
                "INSERT INTO execbound.workspace_memberships(account_id, tenant_id, principal_id) "
                "VALUES (:a, :t, :p)"
            ),
            {"a": account, "t": tenant, "p": principal},
        )
        if enabled is not None:
            conn.execute(
                text(
                    "INSERT INTO execbound.user_factors"
                    "(account_id, tenant_id, principal_id, sealed, key_id, enabled_at) "
                    "VALUES (:a, :t, :p, :s, :k, CASE WHEN :e THEN now() END)"
                ),
                {
                    "a": account,
                    "t": tenant,
                    "p": principal,
                    "s": "sealed" if enabled else None,
                    "k": "key" if enabled else None,
                    "e": enabled,
                },
            )
    return account


def test_ak9_member_factors_answers_an_administrator_one_boolean_per_person(
    db, admin_engine, seeded
):
    tenant, other_tenant = seeded["tenants"]
    who = actors(admin_engine, db, seeded)
    a, b, c, d = (person(admin_engine, tenant) for _ in range(4))
    legacy_factor(admin_engine, tenant, a, enabled=True)
    member_factor(admin_engine, tenant, b, enabled=True)
    member_factor(admin_engine, tenant, d, enabled=False)
    # A stale enabled legacy row beside the membership's disabled factor: enforcement reads
    # the membership's account, so D is not enrolled.
    legacy_factor(admin_engine, tenant, d, enabled=True)
    agent = new_agent(admin_engine, tenant)
    stranger = person(admin_engine, other_tenant)
    legacy_factor(admin_engine, other_tenant, stranger, enabled=True)
    listed = [str(x) for x in (a, b, c, d, agent, stranger)]
    known = str(uuid4())

    with db.transaction(tenant) as conn:
        conn.execute(text("SELECT set_config('execbound.account_id', :a, true)"), {"a": known})
        rows = dict(conn.execute(text(FACTORS), {"a": who["admin"], "ids": listed}).all())
        assert (
            conn.execute(text("SELECT current_setting('execbound.account_id', true)")).scalar_one()
            == known
        )
    assert rows == {a: True, b: True, c: False, d: False}

    for actor in (who["approver"], who["retired"], who["stranger"]):
        with pytest.raises(DBAPIError, match="INVALID_ACTOR"):
            with db.transaction(tenant) as conn:
                conn.execute(text(FACTORS), {"a": actor, "ids": listed})
    with pytest.raises(DBAPIError, match="INVALID_REQUEST"):
        with db.transaction(tenant) as conn:
            conn.execute(
                text(FACTORS), {"a": who["admin"], "ids": [str(uuid4()) for _ in range(501)]}
            )


# Authentication's own stamp. A key is provisioned two minutes before the database's clock so
# that every use below is after its `issued_at`; the 61-second case backdates the stamp.


def backdate(admin_engine, tenant, credential, seconds=61):
    with admin_engine.begin() as conn:
        conn.execute(
            text(
                "UPDATE execbound.credentials "
                "SET last_used_at = last_used_at - make_interval(secs => :s) "
                "WHERE tenant_id = :t AND credential_id = :c"
            ),
            {"s": seconds, "t": tenant, "c": credential},
        )


def agent_token(admin_engine, tenant, issued_at, lifetime=timedelta(days=30), principal=None):
    principal = principal or new_agent(admin_engine, tenant)
    with admin_engine.begin() as conn:
        return provision_credential(conn, tenant, principal, issued_at, lifetime)


def test_ak2_authenticate_stamps_after_every_check_and_never_on_a_refusal(db, admin_engine, seeded):
    tenant, other_tenant = seeded["tenants"]
    now = database_now(admin_engine)
    token = agent_token(admin_engine, tenant, now - timedelta(minutes=2))
    key = credential_of(token)

    authenticate(db, token)
    first = key_row(admin_engine, tenant, key)["last_used_at"]
    assert first is not None
    authenticate(db, token)
    authenticate(db, token)
    assert key_row(admin_engine, tenant, key)["last_used_at"] == first
    backdate(admin_engine, tenant, key)
    authenticate(db, token)
    assert key_row(admin_engine, tenant, key)["last_used_at"] > first

    wrong = token[:-4] + ("AAAA" if not token.endswith("AAAA") else "BBBB")
    with pytest.raises(AuthenticationFailed):
        authenticate(db, wrong)
    assert key_row(admin_engine, tenant, key)["last_used_at"] > first

    revoked = agent_token(admin_engine, tenant, now - timedelta(minutes=2))
    expired = agent_token(
        admin_engine, tenant, now - timedelta(minutes=2), lifetime=timedelta(minutes=1)
    )
    inactive = agent_token(admin_engine, tenant, now - timedelta(minutes=2))
    asleep = agent_token(admin_engine, other_tenant, now - timedelta(minutes=2))
    with admin_engine.begin() as conn:
        conn.execute(
            text(
                "UPDATE execbound.credentials SET revoked_at = :n "
                "WHERE tenant_id = :t AND credential_id = :c"
            ),
            {"n": now - timedelta(minutes=1), "t": tenant, "c": credential_of(revoked)},
        )
        conn.execute(
            text(
                "UPDATE execbound.principals SET active = false WHERE tenant_id = :t "
                "AND principal_id = (SELECT principal_id FROM execbound.credentials "
                "WHERE tenant_id = :t AND credential_id = :c)"
            ),
            {"t": tenant, "c": credential_of(inactive)},
        )
        conn.execute(
            text("UPDATE execbound.tenants SET active = false WHERE tenant_id = :t"),
            {"t": other_tenant},
        )
    # A person's or an owner tool's credential is not an agent key and is never stamped.
    person_token = agent_token(
        admin_engine,
        tenant,
        now - timedelta(minutes=2),
        principal=provision_identity(admin_engine, db, tenant, "ADMIN", now).principal_id,
    )
    authenticate(db, person_token)
    assert key_row(admin_engine, tenant, credential_of(person_token))["last_used_at"] is None
    for refused, fence in (
        (revoked, tenant),
        (expired, tenant),
        (inactive, tenant),
        (asleep, other_tenant),
    ):
        with pytest.raises(AuthenticationFailed):
            authenticate(db, refused)
        assert key_row(admin_engine, fence, credential_of(refused))["last_used_at"] is None


def test_ak2_a_key_issued_ahead_of_the_database_clock_authenticates_and_stamps_nothing(
    db, admin_engine, seeded
):
    tenant = seeded["tenants"][0]
    token = agent_token(admin_engine, tenant, database_now(admin_engine) + timedelta(seconds=60))
    assert authenticate(db, token).credential_id == credential_of(token)
    assert key_row(admin_engine, tenant, credential_of(token))["last_used_at"] is None


def test_ak2_a_stamp_that_raises_never_changes_authentication(
    db, admin_engine, seeded, monkeypatch
):
    tenant = seeded["tenants"][0]
    token = agent_token(admin_engine, tenant, database_now(admin_engine) - timedelta(minutes=2))
    monkeypatch.setattr(
        identity,
        "_STAMP",
        text("SELECT execbound.credential_used(:c, CAST(:n AS timestamptz) + interval '1 hour')"),
    )
    assert authenticate(db, token).credential_id == credential_of(token)
    assert key_row(admin_engine, tenant, credential_of(token))["last_used_at"] is None
    # The authentication transaction committed rather than aborting: the next one succeeds.
    assert authenticate(db, token).credential_id == credential_of(token)


def test_ak3_a_share_lock_from_an_open_execution_does_not_delay_the_stamp(db, admin_engine, seeded):
    tenant = seeded["tenants"][0]
    token = agent_token(admin_engine, tenant, database_now(admin_engine) - timedelta(minutes=2))
    key = credential_of(token)
    with admin_engine.connect() as holder, holder.begin():
        # The lock an uncommitted execution, approval or session insert holds on the key
        # through its foreign key.
        holder.execute(
            text(
                "SELECT 1 FROM execbound.credentials "
                "WHERE tenant_id = :t AND credential_id = :c FOR KEY SHARE"
            ),
            {"t": tenant, "c": key},
        )
        started = time.monotonic()
        authenticate(db, token)
        elapsed = time.monotonic() - started
        # Stamped and committed while the share lock is still held.
        assert key_row(admin_engine, tenant, key)["last_used_at"] is not None
    assert elapsed < 1.0


def test_ak3_a_locked_key_authenticates_at_once_without_a_stamp(db, admin_engine, seeded):
    tenant = seeded["tenants"][0]
    token = agent_token(admin_engine, tenant, database_now(admin_engine) - timedelta(minutes=2))
    key = credential_of(token)
    with admin_engine.connect() as holder, holder.begin():
        # A revocation holds the row this way until it commits.
        holder.execute(
            text(
                "SELECT 1 FROM execbound.credentials "
                "WHERE tenant_id = :t AND credential_id = :c FOR UPDATE"
            ),
            {"t": tenant, "c": key},
        )
        started = time.monotonic()
        assert authenticate(db, token).credential_id == key
        assert time.monotonic() - started < 1.0
    assert key_row(admin_engine, tenant, key)["last_used_at"] is None


def test_ak3_two_authentications_at_once_stamp_once(admin_engine, seeded):
    tenant = seeded["tenants"][0]
    token = agent_token(admin_engine, tenant, database_now(admin_engine) - timedelta(minutes=2))
    key = credential_of(token)
    before = database_now(admin_engine)
    # Two pools, so the two transactions really are concurrent.
    url = local_test_url(os.environ["TEST_DATABASE_URL"], "execbound_app")
    pools = [Database(url, pool_size=1) for _ in range(2)]
    try:
        with ThreadPoolExecutor(max_workers=2) as pool:
            found = list(pool.map(lambda database: authenticate(database, token), pools))
    finally:
        for database in pools:
            database.close()
    assert [one.credential_id for one in found] == [key, key]
    stamped = key_row(admin_engine, tenant, key)["last_used_at"]
    assert stamped is not None and before <= stamped <= database_now(admin_engine)


def test_ak2_the_gateway_path_is_unchanged(api, admin_engine, world, seeded):
    tenant, key = seeded["tenants"][0], seeded["credentials"][0]
    # The fixtures authenticated this key moments ago; take the stamp out of the window.
    with admin_engine.begin() as conn:
        conn.execute(
            text(
                "UPDATE execbound.credentials SET last_used_at = NULL "
                "WHERE tenant_id = :t AND credential_id = :c"
            ),
            {"t": tenant, "c": key},
        )
    answer = api.post("/v1/execute", json=request(world).model_dump(mode="json"))
    assert answer.status_code in {200, 202}, answer.text
    assert key_row(admin_engine, tenant, key)["last_used_at"] is not None
