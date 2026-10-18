"""Scoped operation registry and independently maintained context records."""

from alembic import op
from sqlalchemy import text

revision = "0002_identity_context"
down_revision = "0001_foundation"
branch_labels = None
depends_on = None

TABLES = (
    "connector_accounts",
    "context_sources",
    "operation_mappings",
    "resources",
    "resource_aliases",
    "incidents",
    "agent_runs",
)


def upgrade() -> None:
    op.execute("""
        CREATE TABLE execbound.connector_accounts (
            tenant_id uuid NOT NULL REFERENCES execbound.tenants,
            account_id uuid NOT NULL,
            provider text NOT NULL CHECK (length(provider) BETWEEN 1 AND 80),
            active boolean NOT NULL DEFAULT true,
            PRIMARY KEY (tenant_id, account_id),
            UNIQUE (tenant_id, account_id, provider)
        )
    """)
    op.execute("""
        CREATE TABLE execbound.context_sources (
            tenant_id uuid NOT NULL,
            account_id uuid NOT NULL,
            source_id uuid NOT NULL,
            kind text NOT NULL CHECK (kind IN ('inventory', 'incident')),
            allowed_writers text[] NOT NULL CHECK (cardinality(allowed_writers) BETWEEN 1 AND 16),
            active boolean NOT NULL DEFAULT true,
            PRIMARY KEY (tenant_id, account_id, source_id),
            FOREIGN KEY (tenant_id, account_id) REFERENCES execbound.connector_accounts
        )
    """)
    op.execute("""
        CREATE TABLE execbound.operation_mappings (
            tenant_id uuid NOT NULL,
            operation_ref text NOT NULL CHECK (operation_ref ~ '^[a-z][a-z0-9_.-]{0,79}$'),
            account_id uuid NOT NULL,
            provider text NOT NULL,
            resource_type text NOT NULL,
            action text NOT NULL,
            provider_operation text NOT NULL,
            mapping_version text NOT NULL CHECK (length(mapping_version) BETWEEN 1 AND 80),
            schema_version text NOT NULL CHECK (length(schema_version) BETWEEN 1 AND 80),
            context_contract_version text NOT NULL,
            active boolean NOT NULL DEFAULT true,
            PRIMARY KEY (tenant_id, operation_ref),
            FOREIGN KEY (tenant_id, account_id, provider)
                REFERENCES execbound.connector_accounts(tenant_id, account_id, provider)
        )
    """)
    op.execute("""
        CREATE TABLE execbound.resources (
            tenant_id uuid NOT NULL,
            account_id uuid NOT NULL,
            provider text NOT NULL,
            resource_type text NOT NULL,
            resource_id uuid NOT NULL,
            provider_id text NOT NULL CHECK (length(provider_id) BETWEEN 1 AND 128),
            version text NOT NULL CHECK (length(version) BETWEEN 1 AND 80),
            source_id uuid NOT NULL,
            role text CHECK (role IN ('workstation', 'server', 'domain_controller')),
            environment text CHECK (environment IN ('development', 'staging', 'production')),
            criticality integer CHECK (criticality BETWEEN 0 AND 4),
            observed_at timestamptz NOT NULL,
            active boolean NOT NULL DEFAULT true,
            PRIMARY KEY (tenant_id, account_id, provider, resource_type, resource_id),
            UNIQUE (tenant_id, account_id, provider, resource_type, provider_id),
            FOREIGN KEY (tenant_id, account_id, provider)
                REFERENCES execbound.connector_accounts(tenant_id, account_id, provider),
            FOREIGN KEY (tenant_id, account_id, source_id) REFERENCES execbound.context_sources
        )
    """)
    op.execute("""
        CREATE TABLE execbound.resource_aliases (
            tenant_id uuid NOT NULL,
            alias_id uuid NOT NULL,
            account_id uuid NOT NULL,
            provider text NOT NULL,
            resource_type text NOT NULL,
            kind text NOT NULL CHECK (kind IN ('hostname', 'provider_id')),
            normalized_value text NOT NULL CHECK (length(normalized_value) BETWEEN 1 AND 253),
            resource_id uuid NOT NULL,
            valid_from timestamptz NOT NULL,
            expires_at timestamptz NOT NULL,
            PRIMARY KEY (tenant_id, alias_id),
            CHECK (expires_at > valid_from),
            FOREIGN KEY (tenant_id, account_id, provider, resource_type, resource_id)
                REFERENCES execbound.resources
        )
    """)
    op.execute(
        "CREATE INDEX alias_lookup ON execbound.resource_aliases "
        "(tenant_id, account_id, provider, resource_type, kind, normalized_value)"
    )
    op.execute("""
        CREATE TABLE execbound.incidents (
            tenant_id uuid NOT NULL,
            account_id uuid NOT NULL,
            provider text NOT NULL,
            resource_type text NOT NULL,
            incident_id uuid NOT NULL,
            resource_id uuid NOT NULL,
            source_id uuid NOT NULL,
            version text NOT NULL CHECK (length(version) BETWEEN 1 AND 80),
            status text CHECK (status IN ('OPEN', 'CLOSED')),
            severity text CHECK (severity IN ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL')),
            observed_at timestamptz NOT NULL,
            PRIMARY KEY (tenant_id, account_id, incident_id),
            FOREIGN KEY (tenant_id, account_id, provider, resource_type, resource_id)
                REFERENCES execbound.resources,
            FOREIGN KEY (tenant_id, account_id, source_id) REFERENCES execbound.context_sources
        )
    """)
    op.execute("""
        CREATE TABLE execbound.agent_runs (
            tenant_id uuid NOT NULL,
            run_id uuid NOT NULL,
            principal_id uuid NOT NULL,
            issued_at timestamptz NOT NULL,
            expires_at timestamptz NOT NULL CHECK (expires_at > issued_at),
            PRIMARY KEY (tenant_id, run_id),
            FOREIGN KEY (tenant_id, principal_id) REFERENCES execbound.principals
        )
    """)
    for table in TABLES:
        op.execute(f"ALTER TABLE execbound.{table} ENABLE ROW LEVEL SECURITY")
        op.execute(f"ALTER TABLE execbound.{table} FORCE ROW LEVEL SECURITY")
        op.execute(f"""
            CREATE POLICY tenant_isolation ON execbound.{table}
            USING (tenant_id = nullif(current_setting('execbound.tenant_id', true), '')::uuid)
            WITH CHECK (tenant_id = nullif(current_setting('execbound.tenant_id', true), '')::uuid)
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
        op.execute(f"GRANT SELECT ON execbound.{table} TO execbound_app")
    op.execute("GRANT INSERT ON execbound.agent_runs TO execbound_app")


def downgrade() -> None:
    for table in reversed(TABLES):
        op.execute(f"DROP TABLE execbound.{table}")
