"""Shared limit scopes: principal groups and the impact attributes scopes count over."""

from alembic import op
from sqlalchemy import text

revision = "0022_limit_scopes"
down_revision = "0021_admin_functions"
branch_labels = None
depends_on = None

TENANT = "nullif((SELECT current_setting('execbound.tenant_id', true)), '')::uuid"
GROUP_TABLES = ("principal_groups", "principal_group_members")
# The backfill and the downgrade guard read every tenant, so RLS is lifted on the tables
# they read for the transaction and restored before it ends.
INSPECTED = ("policy_bundle_contents", *GROUP_TABLES)
SCOPED_RULE = (
    '$.limits[*] ? (@.scope == "group" || @.scope == "account" '
    '|| @.scope == "selector" || exists(@.actions))'
)


def _lift_rls(tables: tuple[str, ...]) -> None:
    op.execute(
        "LOCK TABLE " + ", ".join(f"execbound.{t}" for t in tables) + " IN ACCESS EXCLUSIVE MODE"
    )
    for table in tables:
        op.execute(f"ALTER TABLE execbound.{table} NO FORCE ROW LEVEL SECURITY")
    op.execute("SET LOCAL row_security = off")


def _restore_rls(tables: tuple[str, ...]) -> None:
    for table in tables:
        op.execute(f"ALTER TABLE execbound.{table} FORCE ROW LEVEL SECURITY")
    op.execute("SET LOCAL row_security = on")


def _protect(table: str) -> None:
    op.execute(f"ALTER TABLE execbound.{table} ENABLE ROW LEVEL SECURITY")
    op.execute(f"ALTER TABLE execbound.{table} FORCE ROW LEVEL SECURITY")
    op.execute(f"""
        CREATE POLICY tenant_isolation ON execbound.{table}
        USING (tenant_id = {TENANT}) WITH CHECK (tenant_id = {TENANT})
    """)
    for role in ("PUBLIC", "anon", "authenticated", "service_role", "execbound_app"):
        if (
            role != "PUBLIC"
            and not op.get_bind()
            .execute(text("SELECT 1 FROM pg_roles WHERE rolname = :role"), {"role": role})
            .scalar()
        ):
            continue
        op.execute(f"REVOKE ALL ON execbound.{table} FROM {role}")
    # Groups are owner-provisioned authority data like approval scopes: runtime reads only.
    op.execute(f"GRANT SELECT ON execbound.{table} TO execbound_app")


def upgrade() -> None:
    op.execute("""
        CREATE TABLE execbound.principal_groups (
            tenant_id uuid NOT NULL,
            group_id uuid NOT NULL,
            name text NOT NULL CHECK (length(name) BETWEEN 1 AND 80),
            created_at timestamptz NOT NULL,
            PRIMARY KEY (tenant_id, group_id),
            FOREIGN KEY (tenant_id) REFERENCES execbound.tenants,
            UNIQUE (tenant_id, name)
        )
    """)
    op.execute("""
        CREATE TABLE execbound.principal_group_members (
            tenant_id uuid NOT NULL,
            group_id uuid NOT NULL,
            principal_id uuid NOT NULL,
            assigned_at timestamptz NOT NULL,
            PRIMARY KEY (tenant_id, group_id, principal_id),
            FOREIGN KEY (tenant_id, group_id) REFERENCES execbound.principal_groups,
            FOREIGN KEY (tenant_id, principal_id) REFERENCES execbound.principals
        )
    """)
    op.execute(
        "CREATE INDEX principal_group_members_principal "
        "ON execbound.principal_group_members (tenant_id, principal_id)"
    )
    for table in GROUP_TABLES:
        _protect(table)
    op.execute("""
        ALTER TABLE execbound.execution_impact
            ADD COLUMN account_id uuid,
            ADD COLUMN group_ids jsonb
                CHECK (group_ids IS NULL OR jsonb_typeof(group_ids) = 'array'),
            ADD COLUMN facts jsonb
                CHECK (facts IS NULL OR jsonb_typeof(facts) = 'object')
    """)
    op.execute(
        "CREATE INDEX execution_impact_account ON execbound.execution_impact "
        "(tenant_id, account_id, action, state, confirmed_at)"
    )
    op.execute(
        "CREATE INDEX execution_impact_groups ON execbound.execution_impact USING GIN (group_ids)"
    )
    # Retained rows learn their account and facts from the frozen plan they were charged
    # for. Membership at that time was never recorded, so group_ids stays null and such
    # rows never count toward a group scope. A plan without facts leaves facts null,
    # so the row never matches a selector either.
    _lift_rls(("executions", "execution_impact"))
    op.execute("""
        UPDATE execbound.execution_impact i
        SET account_id = (e.frozen -> 'intent' ->> 'account_id')::uuid,
            facts = (
                SELECT jsonb_object_agg(f ->> 'name', f -> 'value')
                FROM jsonb_array_elements(e.frozen -> 'facts') AS f
            )
        FROM execbound.executions e
        WHERE e.tenant_id = i.tenant_id AND e.execution_id = i.execution_id
          AND jsonb_typeof(e.frozen -> 'facts') = 'array'
    """)
    _restore_rls(("executions", "execution_impact"))


def downgrade() -> None:
    # A group, a membership or a rule with a new scope cannot be represented by 0020;
    # backfilled account and facts are re-derivable from executions.frozen and may go.
    _lift_rls(INSPECTED)
    bind = op.get_bind()
    predicates = {
        "principal_groups": "true",
        "principal_group_members": "true",
        "policy_bundle_contents": f"jsonb_path_exists(content, '{SCOPED_RULE}')",
    }
    for table, predicate in predicates.items():
        retained = bind.execute(
            text(f"SELECT EXISTS (SELECT 1 FROM execbound.{table} WHERE {predicate})")
        )
        if retained.scalar_one():
            raise RuntimeError("Cannot downgrade while groups or scoped limit rules exist")
    _restore_rls(INSPECTED)
    op.execute("DROP INDEX execbound.execution_impact_groups")
    op.execute("DROP INDEX execbound.execution_impact_account")
    op.execute(
        "ALTER TABLE execbound.execution_impact "
        "DROP COLUMN facts, DROP COLUMN group_ids, DROP COLUMN account_id"
    )
    op.execute("DROP TABLE execbound.principal_group_members")
    op.execute("DROP TABLE execbound.principal_groups")
