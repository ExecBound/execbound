# SPDX-License-Identifier: AGPL-3.0-only
"""The scheduled jobs' directory and scheduler principal at the schema (#503).

SJ1, SJ8's database half, SJ9's catalog half and SJ15; SJ1's signup case and SJ14, which meet
a plugin's code, are in that plugin's tests. Every test runs on real
PostgreSQL. The `restricted` fixture builds a database whose owner has the hosted owner's
attributes (neither superuser nor BYPASSRLS), so a policy or a fence that silently stopped
working shows up as a missing row or a missed refusal rather than a passing test.
"""

import importlib.util
import re
from pathlib import Path
from uuid import UUID, uuid4

import pytest
from alembic import command
from sqlalchemy import text
from sqlalchemy.exc import DBAPIError
from test_migration_without_bypass import fenced
from test_migration_without_bypass import restricted as restricted

from execbound import administration
from execbound.db import SCHEMA_REVISION, check_runtime
from execbound.principal_columns import GUARDED, UNGUARDED

pytestmark = pytest.mark.integration

# Every uuid column whose name says it holds a principal, in every execbound table. Every
# foreign key to `principals` is one of these (the test asserts it), and the few without a key
# are found by name, so a new principal column cannot hide behind a missing constraint.
NAMED = """
SELECT c.relname, a.attname
  FROM pg_attribute a JOIN pg_class c ON c.oid = a.attrelid
  JOIN pg_namespace n ON n.oid = c.relnamespace
 WHERE n.nspname = 'execbound' AND c.relkind = 'r' AND a.attnum > 0 AND NOT a.attisdropped
   AND a.atttypid = 'uuid'::regtype
   AND (a.attname ~ '(^|_)principal_id$' OR a.attname ~ '_by$'
        OR a.attname IN ('actor_id', 'approver_id', 'inviter_id'))
   AND NOT (c.relname = 'principals' AND a.attname = 'principal_id')
"""

# Principal columns whose names do not say so and which no foreign key to `principals` names.
# `authentication_failures.subject_id` holds a principal's id when `subject_kind` is
# 'principal' (0040) and a credential's or a source's otherwise, so no key can constrain it.
EXTRA = {("authentication_failures", "subject_id")}

KEYED = """
SELECT k.conrelid::regclass::text, a.attname
  FROM pg_constraint k
  JOIN LATERAL unnest(k.conkey) AS key(attnum) ON true
  JOIN pg_attribute a ON a.attrelid = k.conrelid AND a.attnum = key.attnum
 WHERE k.contype = 'f' AND k.confrelid = 'execbound.principals'::regclass
   AND a.attname <> 'tenant_id'
"""

GUARDS = """
SELECT c.relname, t.tgname, pg_get_triggerdef(t.oid) AS definition
  FROM pg_trigger t JOIN pg_class c ON c.oid = t.tgrelid
  JOIN pg_namespace n ON n.oid = c.relnamespace
 WHERE n.nspname = 'execbound' AND NOT t.tgisinternal
   AND t.tgfoid = 'execbound.principal_guard()'::regprocedure
"""


def directory(engine) -> list[UUID]:
    """Every row of `job_tenants`, read by the test owner, which bypasses row security here."""
    with engine.begin() as conn:
        return [
            UUID(str(value))
            for value in conn.execute(
                text("SELECT tenant_id FROM execbound.job_tenants ORDER BY tenant_id")
            ).scalars()
        ]


def page(db, after=None, limit=500) -> list[UUID]:
    """What the runtime role sees through the definer function, fenced to no tenant it lists."""
    with db.transaction(uuid4()) as conn:
        return [
            UUID(str(value))
            for value in conn.execute(
                text("SELECT tenant_id FROM execbound.job_tenants_page(:a, :n)"),
                {"a": after, "n": limit},
            ).scalars()
        ]


def scheduler(engine, tenant) -> UUID:
    """The tenant's scheduler principal, made the way the scheduled pass makes it."""
    with engine.begin() as conn:
        fenced(conn, tenant)
        answer = conn.execute(text("SELECT execbound.scheduler_actor()")).scalar_one()
    return UUID(answer["principal_id"])


def derived(engine, tenant) -> UUID:
    with engine.connect() as conn:
        return UUID(
            str(
                conn.execute(
                    text("SELECT md5('execbound.scheduler:' || CAST(:t AS text))::uuid"),
                    {"t": str(tenant)},
                ).scalar_one()
            )
        )


def refused(engine, tenant, statement, params) -> str:
    """Run one statement fenced to `tenant` and return the error it raised."""
    with pytest.raises(DBAPIError) as caught:
        with engine.begin() as conn:
            fenced(conn, tenant)
            conn.execute(text(statement), params)
    return str(caught.value.orig)


def administrator(engine, tenant, principal) -> None:
    """Make one of `seeded`'s agents an ADMIN person: no space, a person's number."""
    with engine.begin() as conn:
        fenced(conn, tenant)
        conn.execute(
            text(
                "UPDATE execbound.principals SET kind = 'ADMIN', space_id = NULL "
                "WHERE tenant_id = :t AND principal_id = :p"
            ),
            {"t": tenant, "p": principal},
        )


def completed_turn(engine, tenant, principal, days_ago) -> UUID:
    """One completed turn, written directly, completed `days_ago` by the database's clock."""
    turn = uuid4()
    with engine.begin() as conn:
        fenced(conn, tenant)
        conn.execute(
            text(
                "INSERT INTO execbound.assistant_turns"
                "(tenant_id, turn_id, principal_id, context_kind, question, state, model, "
                "created_at, completed_at) "
                "VALUES (:t, :u, :p, 'question', 'What happened?', 'COMPLETED', 'test-model', "
                "now() - make_interval(days => :d), now() - make_interval(days => :d))"
            ),
            {"t": tenant, "u": turn, "p": principal, "d": days_ago},
        )
    return turn


def retire_due(engine, tenant) -> int:
    with engine.begin() as conn:
        fenced(conn, tenant)
        return int(conn.execute(text("SELECT execbound.assistant_turn_retire_due()")).scalar_one())


def test_sj1_every_tenant_is_in_the_directory_exactly_once(db, admin_engine, seeded):
    made = administration.create_tenant(admin_engine, "Directory check")
    with admin_engine.connect() as conn:
        tenants = [
            UUID(str(value))
            for value in conn.execute(
                text("SELECT tenant_id FROM execbound.tenants ORDER BY tenant_id")
            ).scalars()
        ]
    listed = directory(admin_engine)
    # Exactly the tenants, read as the owner; once each, because `tenant_id` is the key.
    assert listed == tenants
    assert set(seeded["tenants"]) | {made} <= set(listed)
    # The runtime role reaches every one of them through the function, and only through it.
    assert set(page(db)) == set(listed)


def test_sj1_the_page_is_ordered_and_bounded(db, admin_engine, seeded):
    everything = page(db)
    assert everything == sorted(everything)
    first = page(db, limit=1)
    assert first == everything[:1]
    assert page(db, after=first[0], limit=500) == everything[1:]
    # Only 501 tests the bound: `LIMIT 0` returns nothing with or without it.
    assert page(db, limit=501) == []


def test_sj1_the_runtime_role_cannot_read_the_directory(db, seeded):
    with pytest.raises(DBAPIError) as caught:
        with db.transaction(seeded["tenants"][0]) as conn:
            conn.execute(text("SELECT count(*) FROM execbound.job_tenants")).scalar_one()
    # Refused for want of a privilege, not because the table is missing.
    assert "permission denied" in str(caught.value.orig)
    with db.transaction(seeded["tenants"][0]) as conn:
        check_runtime(conn)


def test_sj1_the_backfill_and_the_list_work_for_an_owner_without_bypass(restricted):
    engine, config_, _role = restricted
    command.upgrade(config_, "0063_personal_access_tokens")
    before = uuid4()
    with engine.begin() as conn:
        fenced(conn, before)
        conn.execute(
            text("INSERT INTO execbound.tenants(tenant_id, name) VALUES (:t, 'Before')"),
            {"t": before},
        )
    command.upgrade(config_, "head")
    after = uuid4()
    with engine.begin() as conn:
        fenced(conn, after)
        conn.execute(
            text("INSERT INTO execbound.tenants(tenant_id, name) VALUES (:t, 'After')"),
            {"t": after},
        )
    with engine.begin() as conn:
        # Fenced to neither tenant: without `owner_list`, an owner that does not bypass row
        # security would list nothing, and the scheduled pass would silently do nothing.
        fenced(conn, uuid4())
        listed = {
            UUID(str(value))
            for value in conn.execute(
                text("SELECT tenant_id FROM execbound.job_tenants_page(NULL, 500)")
            ).scalars()
        }
    assert listed == {before, after}
    command.downgrade(config_, "0063_personal_access_tokens")


def test_sj8_the_guard_needs_no_fence_for_an_owner_without_bypass(restricted):
    """The guard recognises the scheduler principal by its derived id, so it refuses it even
    in a table whose rows are fenced by account, written with no tenant fence at all: the
    case in which a lookup of `principals` would have seen nothing and let it through."""
    engine, config_, _role = restricted
    command.upgrade(config_, "head")
    tenant, account = uuid4(), uuid4()
    with engine.begin() as conn:
        fenced(conn, tenant)
        conn.execute(
            text("INSERT INTO execbound.tenants(tenant_id, name) VALUES (:t, 'Guarded')"),
            {"t": tenant},
        )
    system = scheduler(engine, tenant)
    with pytest.raises(DBAPIError) as caught:
        with engine.begin() as conn:
            conn.execute(
                text("SELECT set_config('execbound.account_id', :a, true)"), {"a": str(account)}
            )
            conn.execute(
                text(
                    "INSERT INTO execbound.user_accounts(account_id, email) "
                    "VALUES (:a, 'guard@example.org')"
                ),
                {"a": account},
            )
            conn.execute(
                text(
                    "INSERT INTO execbound.user_passkeys(tenant_id, principal_id, credential_id, "
                    "public_key, sign_count, created_at, account_id) "
                    "VALUES (:t, :p, 'ab', 'cd', 0, now(), :a)"
                ),
                {"t": tenant, "p": system, "a": account},
            )
    assert "SYSTEM_PRINCIPAL" in str(caught.value.orig)
    # The audit chain names the scheduler principal, so the downgrade refuses while it exists.
    # It finds it unfenced only because it lifts FORCE on `principals` for the count, which
    # this owner, like the hosted one, needs; the refusal rolls the whole downgrade back,
    # the later revisions' steps with it, so the database stays at the head.
    with pytest.raises(RuntimeError, match="Scheduler principals require"):
        command.downgrade(config_, "0063_personal_access_tokens")
    with engine.connect() as conn:
        assert (
            conn.execute(text("SELECT version_num FROM execbound.alembic_version")).scalar_one()
            == SCHEMA_REVISION
        )


def test_sj9_every_principal_column_is_classified(admin_engine):
    with admin_engine.connect() as conn:
        named = {(row[0], row[1]) for row in conn.execute(text(NAMED))}
        keyed = {(row[0].removeprefix("execbound."), row[1]) for row in conn.execute(text(KEYED))}
        columns = {
            (row[0], row[1])
            for row in conn.execute(
                text(
                    "SELECT table_name, column_name FROM information_schema.columns "
                    "WHERE table_schema = 'execbound'"
                )
            )
        }
    # An EXTRA column that no longer exists would otherwise stay classified unnoticed.
    assert EXTRA <= columns, EXTRA - columns
    named |= EXTRA
    assert keyed <= named, keyed - named
    assert not GUARDED & set(UNGUARDED)
    assert named == GUARDED | set(UNGUARDED), {
        "unclassified": named - GUARDED - set(UNGUARDED),
        "gone": (GUARDED | set(UNGUARDED)) - named,
    }


def migration(path: Path):
    spec = importlib.util.spec_from_file_location(f"migration_{path.stem}", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_sj9_every_guarded_column_has_the_guard_and_the_migration_agrees(admin_engine):
    """Every guarded column carries its trigger, and the migrations that attach the triggers
    hold between them exactly `GUARDED`: 0064's copy, together with the `GUARDED_ADDED` of
    every later migration that guards a column of its own.

    A later table's column cannot join 0064's own list, because 0064 attaches a trigger to each
    column it names and on a fresh database that table does not exist yet when 0064 runs. So a
    migration guards its own columns and keeps its own copy, and this reads every copy.
    """
    with admin_engine.connect() as conn:
        rows = conn.execute(text(GUARDS)).mappings().all()
    # The column is the trigger's one argument: `... principal_guard('principal_id')`.
    columns = [re.search(r"principal_guard\('([a-z_]+)'\)", row["definition"]) for row in rows]
    assert all(columns)
    pairs = list(zip(rows, columns, strict=True))
    assert {(row["relname"], found.group(1)) for row, found in pairs} == GUARDED
    for row, found in pairs:
        column = found.group(1)
        assert row["tgname"] == f"system_guard_{column}"
        assert (
            f"BEFORE INSERT OR UPDATE OF {column} ON execbound.{row['relname']}"
            in (row["definition"])
        )
    versions = Path("migrations/versions")
    copies = [frozenset(migration(versions / "0064_scheduled_jobs.py").GUARDED)]
    for path in sorted(versions.glob("0*.py")):
        if path.stem > "0064" and "GUARDED_ADDED" in path.read_text(encoding="utf-8"):
            copies.append(frozenset(migration(path).GUARDED_ADDED))
    # No column is guarded twice, and between them the copies are the application's.
    assert sum(len(copy) for copy in copies) == len(frozenset().union(*copies))
    assert frozenset().union(*copies) == GUARDED


def test_sj8_the_scheduler_principal_is_made_once_and_is_nobody(db, admin_engine, seeded):
    tenant = seeded["tenants"][0]
    first = scheduler(admin_engine, tenant)
    assert first == derived(admin_engine, tenant)
    assert scheduler(admin_engine, tenant) == first
    with admin_engine.begin() as conn:
        fenced(conn, tenant)
        row = (
            conn.execute(
                text(
                    "SELECT kind, active, label, number, space_id, "
                    "execbound.access_effective_kind(principal_id) AS effective, "
                    "execbound.access_has_permission("
                    "principal_id, 'workspace.manage', NULL, true) AS manages, "
                    "execbound.access_has_permission("
                    "principal_id, 'console.read', NULL, true) AS reads "
                    "FROM execbound.principals WHERE tenant_id = :t AND kind = 'SYSTEM'"
                ),
                {"t": tenant},
            )
            .mappings()
            .one()
        )
    assert (row["kind"], row["active"], row["label"], row["number"]) == (
        "SYSTEM",
        True,
        "ExecBound scheduler",
        1,
    )
    assert row["space_id"] is None
    assert (row["effective"], row["manages"], row["reads"]) == ("SYSTEM", False, False)


def test_sj8_the_scheduler_principal_refuses_an_unfenced_or_inactive_tenant(admin_engine, seeded):
    with pytest.raises(DBAPIError) as unfenced:
        with admin_engine.begin() as conn:
            conn.execute(text("SELECT execbound.scheduler_actor()")).scalar_one()
    assert "INVALID_TENANT" in str(unfenced.value.orig)
    tenant = seeded["tenants"][1]
    with admin_engine.begin() as conn:
        fenced(conn, tenant)
        conn.execute(
            text("UPDATE execbound.tenants SET active = false WHERE tenant_id = :t"),
            {"t": tenant},
        )
    with pytest.raises(DBAPIError) as inactive:
        scheduler(admin_engine, tenant)
    assert "INVALID_TENANT" in str(inactive.value.orig)


def test_sj8_no_change_to_the_scheduler_principal_is_accepted(admin_engine, seeded):
    tenant, agent = seeded["tenants"][0], seeded["principals"][0]
    system = scheduler(admin_engine, tenant)
    where = "WHERE tenant_id = :t AND principal_id = :p"
    for change in ("active = false", "label = 'Me'", "kind = 'ADMIN'"):
        statement = f"UPDATE execbound.principals SET {change} {where}"
        assert "SYSTEM_PRINCIPAL" in refused(
            admin_engine, tenant, statement, {"t": tenant, "p": system}
        )
    # Nor may anyone become one.
    assert "SYSTEM_PRINCIPAL" in refused(
        admin_engine,
        tenant,
        f"UPDATE execbound.principals SET kind = 'SYSTEM' {where}",
        {"t": tenant, "p": agent},
    )


def test_sj8_the_guard_refuses_the_scheduler_principal_in_a_credential_and_a_replacement(
    admin_engine, seeded
):
    tenant, agent = seeded["tenants"][0], seeded["principals"][0]
    system = scheduler(admin_engine, tenant)
    assert "SYSTEM_PRINCIPAL" in refused(
        admin_engine,
        tenant,
        "INSERT INTO execbound.credentials"
        "(tenant_id, credential_id, principal_id, token_hash, expires_at) "
        "VALUES (:t, :c, :p, :h, now() + interval '1 hour')",
        {"t": tenant, "c": uuid4(), "p": system, "h": "a" * 64},
    )
    # UPDATE OF the column is guarded too: a principal replaced by the scheduler is refused.
    assert "SYSTEM_PRINCIPAL" in refused(
        admin_engine,
        tenant,
        "UPDATE execbound.principals SET active = false, replaced_by = :s "
        "WHERE tenant_id = :t AND principal_id = :p",
        {"t": tenant, "p": agent, "s": system},
    )


def test_sj8_kind_system_and_the_derived_id_go_together(admin_engine, seeded):
    tenant = seeded["tenants"][0]
    # A SYSTEM principal under any other id would pass every guard, which knows it by its id.
    assert "principals_system_id" in refused(
        admin_engine,
        tenant,
        "INSERT INTO execbound.principals(tenant_id, principal_id, kind, label, number) "
        "VALUES (:t, :p, 'SYSTEM', 'Impostor', 1)",
        {"t": tenant, "p": uuid4()},
    )
    # A person holding the derived id would be what `scheduler_actor` returned as the scheduler.
    assert "principals_system_id" in refused(
        admin_engine,
        tenant,
        "INSERT INTO execbound.principals(tenant_id, principal_id, kind, label) "
        "VALUES (:t, :p, 'HUMAN_APPROVER', 'Impostor')",
        {"t": tenant, "p": derived(admin_engine, tenant)},
    )


def test_sj8_an_administrator_grant_gives_the_scheduler_principal_nothing(admin_engine, seeded):
    """The access functions refuse the kind itself, not only a principal without grants.

    A SYSTEM principal with no grant and no membership gets false from `access_has_permission`
    even without the kind check, so the test grants it one, past the guard that refuses the
    grant: the owner disables that one trigger for a single transaction and rolls the
    transaction back, so nothing persists.
    """
    tenant = seeded["tenants"][0]
    system = scheduler(admin_engine, tenant)
    with admin_engine.connect() as conn:
        transaction = conn.begin()
        try:
            fenced(conn, tenant)
            conn.execute(
                text(
                    "ALTER TABLE execbound.access_role_grants "
                    "DISABLE TRIGGER system_guard_principal_id"
                )
            )
            granted = conn.execute(
                text(
                    "INSERT INTO execbound.access_role_grants"
                    "(tenant_id, grant_id, principal_id, role) "
                    "VALUES (:t, :g, :p, 'administrator')"
                ),
                {"t": tenant, "g": uuid4(), "p": system},
            )
            assert granted.rowcount == 1
            row = (
                conn.execute(
                    text(
                        "SELECT execbound.access_has_permission("
                        "CAST(:p AS uuid), 'workspace.manage', NULL, true) AS manages, "
                        "execbound.access_effective_kind(CAST(:p AS uuid)) AS effective"
                    ),
                    {"p": system},
                )
                .mappings()
                .one()
            )
        finally:
            transaction.rollback()
    assert (row["manages"], row["effective"]) == (False, "SYSTEM")


def test_sj15_retirement_due_takes_no_time_and_needs_an_active_fenced_tenant(admin_engine, seeded):
    with admin_engine.connect() as conn:
        arguments = (
            conn.execute(
                text(
                    "SELECT pg_get_function_identity_arguments(p.oid) FROM pg_proc p "
                    "JOIN pg_namespace n ON n.oid = p.pronamespace "
                    "WHERE n.nspname = 'execbound' "
                    "AND p.proname IN ('assistant_turn_retire_due', 'scheduler_actor')"
                )
            )
            .scalars()
            .all()
        )
    assert arguments == ["", ""]
    with pytest.raises(DBAPIError) as unfenced:
        with admin_engine.begin() as conn:
            conn.execute(text("SELECT execbound.assistant_turn_retire_due()")).scalar_one()
    assert "INVALID_TENANT" in str(unfenced.value.orig)
    # Fenced to a deactivated tenant, it refuses too, rather than retiring nothing and
    # answering zero.
    tenant = seeded["tenants"][1]
    with admin_engine.begin() as conn:
        fenced(conn, tenant)
        conn.execute(
            text("UPDATE execbound.tenants SET active = false WHERE tenant_id = :t"),
            {"t": tenant},
        )
    with pytest.raises(DBAPIError) as inactive:
        retire_due(admin_engine, tenant)
    assert "INVALID_TENANT" in str(inactive.value.orig)


def test_sj15_retirement_due_keeps_29_days_and_retires_31(admin_engine, seeded):
    tenant, person = seeded["tenants"][0], seeded["principals"][0]
    administrator(admin_engine, tenant, person)
    kept = completed_turn(admin_engine, tenant, person, 29)
    gone = completed_turn(admin_engine, tenant, person, 31)
    assert retire_due(admin_engine, tenant) == 1
    assert retire_due(admin_engine, tenant) == 0
    with admin_engine.begin() as conn:
        fenced(conn, tenant)
        rows = dict(
            conn.execute(
                text(
                    "SELECT turn_id, question IS NULL FROM execbound.assistant_turns "
                    "WHERE tenant_id = :t"
                ),
                {"t": tenant},
            ).all()
        )
    assert rows == {kept: False, gone: True}
