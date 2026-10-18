"""Evaluate the tenant setting once per statement in the monitoring policies."""

from alembic import op

revision = "0024_monitor_rls_initplan"
down_revision = "0023_monitor_collection"
branch_labels = None
depends_on = None

# The monitoring tables kept the per-row predicate that 0003_database_tuning replaced
# everywhere else, so their policies re-read the setting for every row scanned. The
# isolation they enforce is identical either way; only the plan differs.
TABLES = (
    "monitor_sources",
    "monitor_observations",
    "monitor_findings",
    "monitor_deliveries",
    "monitor_connections",
    "monitor_inventory",
)


def upgrade() -> None:
    # The setting is stable within a statement, not across statements or tenants.
    # An uncorrelated subquery makes PostgreSQL use an InitPlan for this lookup.
    for table in TABLES:
        op.execute(f"""
            ALTER POLICY tenant_isolation ON execbound.{table}
            USING (tenant_id = nullif(
                (SELECT current_setting('execbound.tenant_id', true)), ''
            )::uuid)
            WITH CHECK (tenant_id = nullif(
                (SELECT current_setting('execbound.tenant_id', true)), ''
            )::uuid)
        """)


def downgrade() -> None:
    for table in TABLES:
        op.execute(f"""
            ALTER POLICY tenant_isolation ON execbound.{table}
            USING (tenant_id = nullif(current_setting('execbound.tenant_id', true), '')::uuid)
            WITH CHECK (tenant_id = nullif(current_setting('execbound.tenant_id', true), '')::uuid)
        """)
