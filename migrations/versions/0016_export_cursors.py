"""Per-destination cursors for the security event export."""

from alembic import op
from sqlalchemy import text

revision = "0016_export_cursors"
down_revision = "0015_approval_notifications"
branch_labels = None
depends_on = None

TENANT = "nullif((SELECT current_setting('execbound.tenant_id', true)), '')::uuid"
CURSOR_COLUMNS = (
    "last_sequence, last_event_hash, last_failure_window, attempts, next_attempt_at, "
    "lease_until, lease_token, state, last_error"
)


def upgrade() -> None:
    op.execute("""
        CREATE TABLE execbound.export_cursors (
            tenant_id uuid NOT NULL REFERENCES execbound.tenants,
            destination_id text NOT NULL CHECK (destination_id ~ '^[A-Za-z0-9_.-]{1,64}$'),
            last_sequence bigint NOT NULL DEFAULT 0 CHECK (last_sequence >= 0),
            last_event_hash text CHECK (last_event_hash ~ '^[0-9a-f]{64}$'),
            last_failure_window timestamptz,
            attempts integer NOT NULL DEFAULT 0 CHECK (attempts BETWEEN 0 AND 5),
            next_attempt_at timestamptz NOT NULL,
            lease_until timestamptz,
            lease_token uuid,
            state text NOT NULL DEFAULT 'ACTIVE' CHECK (state IN ('ACTIVE', 'FAILED')),
            last_error text CHECK (last_error ~ '^[A-Z][A-Z0-9_]{0,63}$'),
            PRIMARY KEY (tenant_id, destination_id),
            CHECK ((last_sequence = 0) = (last_event_hash IS NULL)),
            CHECK ((lease_until IS NULL) = (lease_token IS NULL))
        )
    """)
    op.execute("ALTER TABLE execbound.export_cursors ENABLE ROW LEVEL SECURITY")
    op.execute("ALTER TABLE execbound.export_cursors FORCE ROW LEVEL SECURITY")
    op.execute(f"""
        CREATE POLICY tenant_isolation ON execbound.export_cursors
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
        op.execute(f"REVOKE ALL ON execbound.export_cursors FROM {role}")
    op.execute("GRANT SELECT, INSERT ON execbound.export_cursors TO execbound_app")
    op.execute(f"GRANT UPDATE ({CURSOR_COLUMNS}) ON execbound.export_cursors TO execbound_app")


def downgrade() -> None:
    # A cursor that advanced records what a destination has already received.
    op.execute("ALTER TABLE execbound.export_cursors NO FORCE ROW LEVEL SECURITY")
    op.execute("SET LOCAL row_security = off")
    advanced = op.get_bind().execute(
        text("SELECT EXISTS (SELECT 1 FROM execbound.export_cursors WHERE last_sequence > 0)")
    )
    if advanced.scalar_one():
        raise RuntimeError("Cannot downgrade while an export cursor has advanced")
    op.execute("DROP TABLE execbound.export_cursors")
