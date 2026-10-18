"""Bounded, attributed authentication failure counters for every external surface."""

from alembic import op
from sqlalchemy import text

revision = "0010_authentication_failures"
down_revision = "0009_context_contracts"
branch_labels = None
depends_on = None

TENANT = "nullif((SELECT current_setting('execbound.tenant_id', true)), '')::uuid"


def upgrade() -> None:
    op.execute("""
        CREATE TABLE execbound.authentication_failures (
            failure_id uuid PRIMARY KEY,
            surface text NOT NULL CHECK (surface IN ('http', 'mcp', 'human', 'monitor')),
            reason text NOT NULL CHECK (
                reason IN ('MALFORMED', 'UNKNOWN', 'MISMATCH', 'EXPIRED', 'REVOKED', 'INACTIVE')
            ),
            window_start timestamptz NOT NULL,
            tenant_id uuid REFERENCES execbound.tenants,
            subject_kind text CHECK (subject_kind IN ('credential', 'source')),
            subject_id uuid,
            count integer NOT NULL CHECK (count >= 1),
            first_at timestamptz NOT NULL,
            last_at timestamptz NOT NULL CHECK (last_at >= first_at),
            CHECK (
                (tenant_id IS NULL) = (subject_id IS NULL)
                AND (subject_id IS NULL) = (subject_kind IS NULL)
            ),
            UNIQUE NULLS NOT DISTINCT
                (surface, reason, window_start, tenant_id, subject_kind, subject_id)
        )
    """)
    op.execute(
        "CREATE INDEX authentication_failures_tenant_window "
        "ON execbound.authentication_failures (tenant_id, window_start)"
    )
    op.execute("ALTER TABLE execbound.authentication_failures ENABLE ROW LEVEL SECURITY")
    op.execute("ALTER TABLE execbound.authentication_failures FORCE ROW LEVEL SECURITY")
    op.execute(f"""
        CREATE POLICY tenant_isolation ON execbound.authentication_failures
        USING (tenant_id = {TENANT}) WITH CHECK (tenant_id = {TENANT})
    """)
    # Unattributed rows carry no tenant, subject kind or subject; any role may count them.
    op.execute("""
        CREATE POLICY unattributed_counters ON execbound.authentication_failures
        USING (tenant_id IS NULL) WITH CHECK (tenant_id IS NULL)
    """)
    for role in ("PUBLIC", "anon", "authenticated", "service_role", "execbound_app"):
        if (
            role != "PUBLIC"
            and not op.get_bind()
            .execute(text("SELECT 1 FROM pg_roles WHERE rolname = :role"), {"role": role})
            .scalar()
        ):
            continue
        op.execute(f"REVOKE ALL ON execbound.authentication_failures FROM {role}")
    op.execute("GRANT SELECT, INSERT ON execbound.authentication_failures TO execbound_app")
    op.execute(
        "GRANT UPDATE (count, last_at) ON execbound.authentication_failures TO execbound_app"
    )


def downgrade() -> None:
    # Counters are telemetry, not evidence, but discarding them silently is still not a
    # recovery procedure: refuse while any row remains.
    op.execute("ALTER TABLE execbound.authentication_failures NO FORCE ROW LEVEL SECURITY")
    op.execute("SET LOCAL row_security = off")
    retained = op.get_bind().execute(
        text("SELECT EXISTS (SELECT 1 FROM execbound.authentication_failures)")
    )
    if retained.scalar_one():
        raise RuntimeError("Cannot downgrade while authentication failure records are retained")
    op.execute("DROP TABLE execbound.authentication_failures")
