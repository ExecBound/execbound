"""Per-tenant emergency stop recorded on the tenant control row."""

from alembic import op
from sqlalchemy import text

revision = "0011_tenant_stop"
down_revision = "0010_authentication_failures"
branch_labels = None
depends_on = None

STOP_COLUMNS = "stop_id, stopped_at, stopped_by, stop_reason"


def upgrade() -> None:
    op.execute("""
        ALTER TABLE execbound.tenant_policy_control
            ADD COLUMN stop_id uuid,
            ADD COLUMN stopped_at timestamptz,
            ADD COLUMN stopped_by uuid,
            ADD COLUMN stop_reason text
                CHECK (stop_reason IS NULL OR length(stop_reason) BETWEEN 1 AND 500),
            ADD CONSTRAINT stop_columns_together CHECK (
                (stop_id IS NULL) = (stopped_at IS NULL)
                AND (stop_id IS NULL) = (stopped_by IS NULL)
                AND (stop_id IS NULL) = (stop_reason IS NULL)
            ),
            ADD CONSTRAINT tenant_policy_control_stopped_by_fkey
                FOREIGN KEY (tenant_id, stopped_by) REFERENCES execbound.principals
    """)
    op.execute(
        "CREATE INDEX tenant_policy_control_stopped_by "
        "ON execbound.tenant_policy_control (tenant_id, stopped_by)"
    )
    # The stop is written only by the fence-taking activation and release functions.
    op.execute(f"GRANT UPDATE ({STOP_COLUMNS}) ON execbound.tenant_policy_control TO execbound_app")


def downgrade() -> None:
    # Dropping an active stop would silently resume a halted tenant: refuse instead.
    op.execute("ALTER TABLE execbound.tenant_policy_control NO FORCE ROW LEVEL SECURITY")
    op.execute("SET LOCAL row_security = off")
    active = op.get_bind().execute(
        text(
            "SELECT EXISTS (SELECT 1 FROM execbound.tenant_policy_control "
            "WHERE stop_id IS NOT NULL)"
        )
    )
    if active.scalar_one():
        raise RuntimeError("Cannot downgrade while a tenant emergency stop is active")
    op.execute("""
        ALTER TABLE execbound.tenant_policy_control
            DROP CONSTRAINT tenant_policy_control_stopped_by_fkey,
            DROP CONSTRAINT stop_columns_together,
            DROP COLUMN stop_reason,
            DROP COLUMN stopped_by,
            DROP COLUMN stopped_at,
            DROP COLUMN stop_id
    """)
    op.execute("ALTER TABLE execbound.tenant_policy_control FORCE ROW LEVEL SECURITY")
