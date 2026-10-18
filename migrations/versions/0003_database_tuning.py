"""Evaluate tenant context once per statement and cover foreign key lookups."""

from alembic import op

revision = "0003_database_tuning"
down_revision = "0002_identity_context"
branch_labels = None
depends_on = None

TABLES = (
    "tenants",
    "principals",
    "credentials",
    "audit_heads",
    "audit_events",
    "connector_accounts",
    "context_sources",
    "operation_mappings",
    "resources",
    "resource_aliases",
    "incidents",
    "agent_runs",
)

INDEXES = (
    ("credentials_principal", "credentials", "tenant_id, principal_id"),
    ("audit_events_actor", "audit_events", "tenant_id, actor_id"),
    ("agent_runs_principal", "agent_runs", "tenant_id, principal_id"),
    ("operation_mappings_account", "operation_mappings", "tenant_id, account_id, provider"),
    ("resources_source", "resources", "tenant_id, account_id, source_id"),
    (
        "resource_aliases_resource",
        "resource_aliases",
        "tenant_id, account_id, provider, resource_type, resource_id",
    ),
    (
        "incidents_resource",
        "incidents",
        "tenant_id, account_id, provider, resource_type, resource_id",
    ),
    ("incidents_source", "incidents", "tenant_id, account_id, source_id"),
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
    for name, table, columns in INDEXES:
        op.execute(f"CREATE INDEX {name} ON execbound.{table} ({columns})")


def downgrade() -> None:
    for name, _, _ in reversed(INDEXES):
        op.execute(f"DROP INDEX execbound.{name}")
    for table in TABLES:
        op.execute(f"""
            ALTER POLICY tenant_isolation ON execbound.{table}
            USING (tenant_id = nullif(current_setting('execbound.tenant_id', true), '')::uuid)
            WITH CHECK (tenant_id = nullif(current_setting('execbound.tenant_id', true), '')::uuid)
        """)
