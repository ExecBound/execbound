# SPDX-License-Identifier: AGPL-3.0-only
import os
import re

import pytest
from conftest import current_test_database
from sqlalchemy import text
from sqlalchemy.engine import URL
from sqlalchemy.exc import DBAPIError

from execbound.db import TABLES, UnsafeDatabaseRole, check_runtime

pytestmark = pytest.mark.integration


def test_runtime_is_restricted(db):
    with db.engine.connect() as conn:
        check_runtime(conn)


def test_review_scope_view_must_use_the_runtime_rls_boundary(db, admin_engine):
    with admin_engine.begin() as conn:
        conn.execute(
            text("ALTER VIEW execbound.effective_approval_scopes SET (security_invoker=false)")
        )
    try:
        with db.engine.connect() as conn, pytest.raises(UnsafeDatabaseRole):
            check_runtime(conn)
    finally:
        with admin_engine.begin() as conn:
            conn.execute(
                text("ALTER VIEW execbound.effective_approval_scopes SET (security_invoker=true)")
            )


def test_owner_is_rejected(admin_engine):
    with admin_engine.connect() as conn, pytest.raises(UnsafeDatabaseRole):
        check_runtime(conn)


@pytest.mark.parametrize(
    "grant",
    [
        "UPDATE(kind) ON execbound.principals",
        "UPDATE(kind) ON execbound.audit_events",
        "INSERT(tenant_id) ON execbound.credentials",
        "INSERT(tenant_id) ON execbound.canonical_targets",
        "INSERT(tenant_id) ON execbound.resource_identities",
        "INSERT(tenant_id) ON execbound.approval_scopes",
        "INSERT(tenant_id) ON execbound.principal_groups",
        "INSERT(tenant_id) ON execbound.principal_group_members",
        "INSERT(tenant_id) ON execbound.executor_keys",
        "UPDATE(public_key) ON execbound.executor_keys",
        "INSERT(tenant_id) ON execbound.onboarding_slots",
        "UPDATE(claimed_at) ON execbound.onboarding_slots",
        "INSERT(tenant_id) ON execbound.onboarding_invitations",
        "UPDATE(failure_count) ON execbound.onboarding_invitations",
        "UPDATE(intent_hash) ON execbound.executions",
        "UPDATE(report_expires_at) ON execbound.executions",
        "UPDATE(intent_hash) ON execbound.execution_keys",
        "UPDATE(to_state) ON execbound.execution_events",
        "UPDATE(plan_hash) ON execbound.approvals",
        "UPDATE(approved) ON execbound.execution_impact",
        "UPDATE(account_id) ON execbound.execution_impact",
        "UPDATE(canonical_target_id) ON execbound.resource_claims",
        # The correlation row's own identity and the tool it names are written at the
        # insert and never moved: a grant that could repoint either would let a later
        # delivery rewrite which Arcade execution a settled ExecBound one belongs to.
        "UPDATE(arcade_execution_id) ON execbound.arcade_hooks",
        "UPDATE(idempotency_key) ON execbound.arcade_hooks",
        "UPDATE(toolkit) ON execbound.arcade_hooks",
        "UPDATE(reported_metadata) ON execbound.arcade_hooks",
        "UPDATE(created_at) ON execbound.arcade_hooks",
    ],
)
def test_accidental_column_grants_fail_closed(db, admin_engine, grant):
    with admin_engine.begin() as conn:
        conn.execute(text(f"GRANT {grant} TO execbound_app"))
    try:
        with db.engine.connect() as conn, pytest.raises(UnsafeDatabaseRole):
            check_runtime(conn)
    finally:
        with admin_engine.begin() as conn:
            conn.execute(text(f"REVOKE {grant} FROM execbound_app"))


def test_a_table_the_catalog_does_not_name_fails_closed(db, admin_engine):
    """A migration that creates a table without adding it to `TABLES` fails the runtime check.

    This, and not a count, holds the catalog to the schema: `check_runtime` refuses unless the
    `execbound` tables are exactly `TABLES`, so a schema test asserts that its own tables are
    in the catalog and none pins `len(TABLES)`, a literal every migration that added a table
    had to move in ten files at once. The stray table is forced under row security and granted
    nothing, so the catalog is the one check it fails.
    """
    with admin_engine.begin() as conn:
        conn.execute(text("CREATE TABLE execbound.stray (id int)"))
        conn.execute(text("ALTER TABLE execbound.stray ENABLE ROW LEVEL SECURITY"))
        conn.execute(text("ALTER TABLE execbound.stray FORCE ROW LEVEL SECURITY"))
    try:
        with (
            db.engine.connect() as conn,
            pytest.raises(UnsafeDatabaseRole, match="^Incomplete database schema$"),
        ):
            check_runtime(conn)
    finally:
        with admin_engine.begin() as conn:
            conn.execute(text("DROP TABLE IF EXISTS execbound.stray"))
    with db.engine.connect() as conn:
        check_runtime(conn)


@pytest.mark.parametrize(
    "catalog",
    [
        # A table the schema holds and the catalog lost.
        pytest.param(TABLES[1:], id="a-table-left-out"),
        # A table the catalog names and no migration created.
        pytest.param((*TABLES, "never_created"), id="a-table-never-created"),
    ],
)
def test_a_catalog_that_is_not_the_schema_fails_closed(db, monkeypatch, catalog):
    """Equality, not containment: each case would pass a containment check one way round."""
    monkeypatch.setattr("execbound.db.TABLES", catalog)
    with (
        db.engine.connect() as conn,
        pytest.raises(UnsafeDatabaseRole, match="^Incomplete database schema$"),
    ):
        check_runtime(conn)


def test_rls_denies_missing_context_and_resets_after_pool_reuse(db, seeded):
    for tenant in seeded["tenants"]:
        with db.transaction(tenant) as conn:
            assert conn.execute(
                text("SELECT tenant_id FROM execbound.principals")
            ).scalars().all() == [tenant]
        with db.engine.begin() as conn:
            assert conn.execute(text("SELECT count(*) FROM execbound.principals")).scalar_one() == 0
    with pytest.raises(ValueError):
        with db.transaction(seeded["tenants"][0]):
            raise ValueError("rollback")
    with db.engine.begin() as conn:
        assert conn.execute(text("SELECT count(*) FROM execbound.principals")).scalar_one() == 0


@pytest.mark.parametrize(
    "statement",
    [
        "UPDATE execbound.audit_events SET kind = 'tampered'",
        "DELETE FROM execbound.audit_events",
        "TRUNCATE execbound.audit_events",
        "UPDATE execbound.principals SET kind = 'ADMIN', space_id = NULL",
        "CREATE TABLE execbound.backdoor (id int)",
        "SET ROLE execbound_owner",
        "UPDATE execbound.executions SET plan_hash = repeat('0', 64)",
        # The report window is written once at admission; the runtime holds no UPDATE on it.
        "UPDATE execbound.executions SET report_expires_at = now()",
        "UPDATE execbound.executor_keys SET public_key = repeat('0', 64)",
        "DELETE FROM execbound.executor_keys",
        "UPDATE execbound.execution_keys SET intent_hash = repeat('0', 64)",
        "UPDATE execbound.execution_events SET to_state = 'EXECUTED'",
        "UPDATE execbound.approvals SET expires_at = now()",
        "UPDATE execbound.execution_impact SET approved = true",
        "UPDATE execbound.execution_impact SET group_ids = '[]'",
        "UPDATE execbound.resource_claims SET canonical_target_id = gen_random_uuid()",
        "UPDATE execbound.approval_scopes SET active = true",
        "UPDATE execbound.resource_identities SET canonical_target_id = gen_random_uuid()",
        "DELETE FROM execbound.execution_events",
        "TRUNCATE execbound.executions",
    ],
)
def test_runtime_cannot_rewrite_history_or_escalate(db, seeded, statement):
    with pytest.raises(DBAPIError), db.transaction(seeded["tenants"][0]) as conn:
        conn.execute(text(statement))


def test_cross_tenant_head_insert_and_update(db, seeded):
    first, second = seeded["tenants"]
    with db.transaction(second) as conn:
        conn.execute(
            text("INSERT INTO execbound.audit_heads(tenant_id) VALUES (:t)"), {"t": second}
        )
    with db.transaction(first) as conn:
        assert (
            conn.execute(
                text("UPDATE execbound.audit_heads SET sequence = 5 WHERE tenant_id = :t"),
                {"t": second},
            ).rowcount
            == 0
        )
    with pytest.raises(DBAPIError), db.transaction(first) as conn:
        conn.execute(
            text("INSERT INTO execbound.audit_heads(tenant_id) VALUES (:t)"), {"t": second}
        )


def test_tenant_setting_is_evaluated_once_per_statement(db, seeded):
    # One relation proves the mechanism; every policy's expression is checked from the
    # catalog below, which is deterministic where a plan shape is not.
    with db.transaction(seeded["tenants"][0]) as conn:
        plan = conn.execute(
            text("EXPLAIN (ANALYZE, FORMAT JSON) SELECT * FROM execbound.principals")
        ).scalar_one()[0]["Plan"]

    def initplans(node):
        if node.get("Parent Relationship") == "InitPlan":
            yield node
        for child in node.get("Plans", []):
            yield from initplans(child)

    settings = list(initplans(plan))
    # `principals` carries two since 0039: the tenant fence, and the single-row
    # `sign_in_email` policy that resolves an address before any tenant is known. Both are
    # permissive policies ORed together, so Postgres short-circuits: a row whose tenant
    # already matches the fence never needs the `sign_in_email` side of the OR, and when
    # every row's email is NULL (the ordinary case, seeded here) that side's AND never
    # reaches the marker either. An uncorrelated InitPlan is cached after its first
    # evaluation, so it cannot run more than once per statement, but the planner is free to
    # never reach it at all, which shows up as zero loops and is the policy working, not a
    # per-row read. Whether Postgres takes that path also depends on the table's
    # statistics: with `execbound.principals` freshly ANALYZEd, the planner picks a Seq
    # Scan whose Filter short-circuits exactly this way; with stale statistics it instead
    # picks a Bitmap Heap Scan that happens to evaluate both markers up front. So the
    # property this test protects is "at most once per statement", never "once per row",
    # and it holds regardless of which plan shape Postgres chooses.
    assert settings
    loops = [(node["Subplan Name"], node["Actual Loops"]) for node in settings]
    assert all(count <= 1 for _, count in loops), loops


def test_prepared_query_uses_each_transactions_tenant(db, seeded):
    # Reuse the same prepared plan and physical connection across tenant changes.
    with db.engine.connect() as conn:
        conn.execute(
            text("PREPARE scoped_principals AS SELECT tenant_id FROM execbound.principals")
        )
        conn.commit()
        try:
            for tenant in seeded["tenants"] * 3:
                with conn.begin():
                    conn.execute(
                        text("SELECT set_config('execbound.tenant_id', :t, true)"),
                        {"t": str(tenant)},
                    )
                    assert conn.execute(text("EXECUTE scoped_principals")).scalars().all() == [
                        tenant
                    ]
                with conn.begin():
                    assert conn.execute(text("EXECUTE scoped_principals")).all() == []
        finally:
            conn.execute(text("DEALLOCATE scoped_principals"))
            conn.commit()


def test_foreign_keys_have_covering_indexes(admin_engine):
    with admin_engine.connect() as conn:
        missing = conn.execute(
            text("""
            SELECT c.conrelid::regclass::text, c.conname
            FROM pg_constraint c
            WHERE c.contype = 'f'
              AND c.connamespace = 'execbound'::regnamespace
              AND NOT EXISTS (
                SELECT 1 FROM pg_index i
                WHERE i.indrelid = c.conrelid AND i.indisvalid AND i.indisready
                  AND i.indpred IS NULL AND i.indexprs IS NULL
                  AND i.indnkeyatts >= cardinality(c.conkey)
                  AND ARRAY(SELECT unnest(i.indkey::smallint[])
                            LIMIT cardinality(c.conkey)) @> c.conkey
              )
        """)
        ).all()
    assert missing == []


# pg_policies renders the subquery with its own spacing, so match the shape, not the text.
ONCE_PER_STATEMENT = re.compile(r"\(\s*SELECT\s+current_setting", re.IGNORECASE)


def test_no_policy_reads_the_tenant_setting_once_per_row(admin_engine):
    """A new table must not reintroduce the per-row predicate 0003 removed (#171)."""
    with admin_engine.begin() as conn:
        policies = (
            conn.execute(
                text(
                    "SELECT tablename, policyname, qual, with_check FROM pg_policies "
                    "WHERE schemaname = 'execbound'"
                )
            )
            .mappings()
            .all()
        )
    assert policies, "no row-level security policies found"
    per_row = sorted(
        f"{policy['tablename']}.{policy['policyname']} ({clause})"
        for policy in policies
        for clause, expression in (("USING", policy["qual"]), ("WITH CHECK", policy["with_check"]))
        if expression
        and "current_setting" in expression
        and not ONCE_PER_STATEMENT.search(expression)
    )
    assert per_row == []


# A restored copy is read by changing one name, never by rendering a second connection
# string with its password (#262).
@pytest.mark.parametrize(
    "name",
    ["execbound_restore", "a", "e1", "a_b_9", "a" * 63],
)
def test_with_database_name_accepts_a_postgresql_identifier(name, admin_engine):
    from execbound.connection import with_database_name

    changed = with_database_name(os.environ["TEST_MIGRATION_DATABASE_URL"], name)
    assert isinstance(changed, URL)
    assert changed.database == name
    # The object is never rendered with its password, and SQLAlchemy hides it by default,
    # so neither str() nor repr() of what this returns can carry one.
    assert os.environ["POSTGRES_PASSWORD"] not in f"{changed}{changed!r}"


@pytest.mark.parametrize(
    "name",
    ["", "Execbound", "a/b", "a" * 64, "has space", "1leading", "_leading", "trailing-dash"],
)
def test_with_database_name_refuses_anything_else(name, admin_engine):
    from execbound.connection import with_database_name

    with pytest.raises(ValueError) as refused:
        with_database_name(os.environ["TEST_MIGRATION_DATABASE_URL"], name)
    # The refusal names the code and never echoes the value it was given.
    assert str(refused.value) == "INVALID_DATABASE"
    if name.strip():
        assert name not in str(refused.value)


def test_database_accepts_a_url_object_and_runs_check_runtime(admin_engine):
    from execbound.connection import with_database_name
    from execbound.db import Database

    # This process's own database, not the literal name: under xdist the rows live in the
    # worker's copy and the plain one is created but never migrated, so a literal here finds
    # no `execbound` schema. It passed locally only because a developer's single database
    # has been migrated by every earlier run.
    parsed = with_database_name(os.environ["TEST_DATABASE_URL"], current_test_database())
    database = Database(parsed, pool_size=1)
    try:
        with database.engine.connect() as conn:
            check_runtime(conn)
    finally:
        database.close()
