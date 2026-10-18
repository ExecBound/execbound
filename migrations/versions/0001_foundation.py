"""Private tenant identity and audit foundation."""

from alembic import op
from sqlalchemy import text

revision = "0001_foundation"
down_revision = None
branch_labels = None
depends_on = None

TABLES = ("tenants", "principals", "credentials", "audit_heads", "audit_events")


def upgrade() -> None:
    op.execute("""
        CREATE TABLE execbound.tenants (
            tenant_id uuid PRIMARY KEY,
            name text NOT NULL CHECK (length(name) BETWEEN 1 AND 200),
            active boolean NOT NULL DEFAULT true
        )
    """)
    op.execute("""
        CREATE TABLE execbound.principals (
            tenant_id uuid NOT NULL REFERENCES execbound.tenants(tenant_id),
            principal_id uuid NOT NULL,
            kind text NOT NULL CHECK (kind IN ('AGENT', 'HUMAN_APPROVER', 'ADMIN')),
            active boolean NOT NULL DEFAULT true,
            PRIMARY KEY (tenant_id, principal_id)
        )
    """)
    op.execute("""
        CREATE TABLE execbound.credentials (
            tenant_id uuid NOT NULL,
            credential_id uuid NOT NULL,
            principal_id uuid NOT NULL,
            token_hash text NOT NULL CHECK (token_hash ~ '^[0-9a-f]{64}$'),
            issued_at timestamptz NOT NULL DEFAULT now(),
            expires_at timestamptz NOT NULL,
            revoked_at timestamptz,
            PRIMARY KEY (tenant_id, credential_id),
            FOREIGN KEY (tenant_id, principal_id)
                REFERENCES execbound.principals(tenant_id, principal_id)
        )
    """)
    op.execute("""
        CREATE TABLE execbound.audit_heads (
            tenant_id uuid PRIMARY KEY REFERENCES execbound.tenants(tenant_id),
            sequence bigint NOT NULL DEFAULT 0 CHECK (sequence >= 0),
            event_hash text NOT NULL DEFAULT repeat('0', 64)
                CHECK (event_hash ~ '^[0-9a-f]{64}$')
        )
    """)
    op.execute("""
        CREATE TABLE execbound.audit_events (
            tenant_id uuid NOT NULL,
            sequence bigint NOT NULL CHECK (sequence > 0),
            event_id uuid NOT NULL,
            actor_id uuid NOT NULL,
            kind text NOT NULL CHECK (kind ~ '^[a-z][a-z0-9_.]{0,79}$'),
            occurred_at timestamptz NOT NULL,
            payload jsonb NOT NULL CHECK (jsonb_typeof(payload) = 'object'),
            previous_hash text NOT NULL CHECK (previous_hash ~ '^[0-9a-f]{64}$'),
            event_hash text NOT NULL CHECK (event_hash ~ '^[0-9a-f]{64}$'),
            PRIMARY KEY (tenant_id, sequence),
            UNIQUE (tenant_id, event_id),
            FOREIGN KEY (tenant_id, actor_id)
                REFERENCES execbound.principals(tenant_id, principal_id)
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
    # Supabase may install broader default grants for its API roles. Remove them
    # explicitly on these objects, including the private migration version table.
    for role in ("PUBLIC", "anon", "authenticated", "service_role"):
        if (
            role != "PUBLIC"
            and not op.get_bind()
            .execute(text("SELECT 1 FROM pg_roles WHERE rolname = :role"), {"role": role})
            .scalar()
        ):
            continue
        op.execute(f"REVOKE ALL ON SCHEMA execbound FROM {role}")
        op.execute(f"REVOKE ALL ON ALL TABLES IN SCHEMA execbound FROM {role}")
        op.execute(f"ALTER DEFAULT PRIVILEGES IN SCHEMA execbound REVOKE ALL ON TABLES FROM {role}")
    op.execute("GRANT USAGE ON SCHEMA execbound TO execbound_app")
    op.execute("GRANT SELECT ON ALL TABLES IN SCHEMA execbound TO execbound_app")
    op.execute("GRANT INSERT ON execbound.audit_events TO execbound_app")
    op.execute("GRANT INSERT, UPDATE ON execbound.audit_heads TO execbound_app")


def downgrade() -> None:
    for table in reversed(TABLES):
        op.execute(f"DROP TABLE execbound.{table}")
