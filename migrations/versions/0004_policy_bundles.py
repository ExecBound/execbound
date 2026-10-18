"""Immutable policy content with separate tenant lifecycle and active selection."""

from alembic import op
from sqlalchemy import text

revision = "0004_policy_bundles"
down_revision = "0003_database_tuning"
branch_labels = None
depends_on = None

# Migration history must not depend on the current application's table catalog.
TABLES = ("policy_bundle_contents", "policy_bundle_lifecycle", "tenant_policy_control")


def upgrade() -> None:
    op.execute("""
        CREATE TABLE execbound.policy_bundle_contents (
            tenant_id uuid NOT NULL REFERENCES execbound.tenants,
            bundle_id uuid NOT NULL,
            content_hash text NOT NULL CHECK (content_hash ~ '^[0-9a-f]{64}$'),
            content jsonb NOT NULL CHECK (jsonb_typeof(content) = 'object'),
            created_at timestamptz NOT NULL,
            created_by uuid NOT NULL,
            PRIMARY KEY (tenant_id, bundle_id),
            UNIQUE (tenant_id, bundle_id, content_hash),
            FOREIGN KEY (tenant_id, created_by) REFERENCES execbound.principals
        )
    """)
    op.execute(
        "CREATE INDEX policy_bundle_contents_creator "
        "ON execbound.policy_bundle_contents (tenant_id, created_by)"
    )
    op.execute("""
        CREATE TABLE execbound.policy_bundle_lifecycle (
            tenant_id uuid NOT NULL,
            bundle_id uuid NOT NULL,
            content_hash text NOT NULL,
            state text NOT NULL CHECK (state IN ('DRAFT', 'VALIDATED', 'ACTIVE', 'RETIRED')),
            changed_at timestamptz NOT NULL,
            PRIMARY KEY (tenant_id, bundle_id),
            FOREIGN KEY (tenant_id, bundle_id, content_hash)
                REFERENCES execbound.policy_bundle_contents(tenant_id, bundle_id, content_hash)
        )
    """)
    op.execute(
        "CREATE INDEX policy_bundle_lifecycle_content "
        "ON execbound.policy_bundle_lifecycle (tenant_id, bundle_id, content_hash)"
    )
    op.execute(
        "CREATE UNIQUE INDEX policy_bundle_one_active "
        "ON execbound.policy_bundle_lifecycle (tenant_id) WHERE state = 'ACTIVE'"
    )
    op.execute("""
        CREATE TABLE execbound.tenant_policy_control (
            tenant_id uuid PRIMARY KEY REFERENCES execbound.tenants,
            active_bundle_id uuid,
            changed_at timestamptz NOT NULL,
            FOREIGN KEY (tenant_id, active_bundle_id)
                REFERENCES execbound.policy_bundle_lifecycle(tenant_id, bundle_id)
        )
    """)
    op.execute(
        "CREATE INDEX tenant_policy_control_bundle "
        "ON execbound.tenant_policy_control (tenant_id, active_bundle_id)"
    )
    for table in TABLES:
        op.execute(f"ALTER TABLE execbound.{table} ENABLE ROW LEVEL SECURITY")
        op.execute(f"ALTER TABLE execbound.{table} FORCE ROW LEVEL SECURITY")
        op.execute(f"""
            CREATE POLICY tenant_isolation ON execbound.{table}
            USING (tenant_id = nullif(
                (SELECT current_setting('execbound.tenant_id', true)), ''
            )::uuid)
            WITH CHECK (tenant_id = nullif(
                (SELECT current_setting('execbound.tenant_id', true)), ''
            )::uuid)
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
        op.execute(f"GRANT SELECT, INSERT ON execbound.{table} TO execbound_app")
    op.execute(
        "GRANT UPDATE (state, changed_at) ON execbound.policy_bundle_lifecycle TO execbound_app"
    )
    op.execute(
        "GRANT UPDATE (active_bundle_id, changed_at) "
        "ON execbound.tenant_policy_control TO execbound_app"
    )


def downgrade() -> None:
    for table in reversed(TABLES):
        op.execute(f"DROP TABLE execbound.{table}")
