"""Transactional outbox for approval notifications to operator destinations."""

from alembic import op
from sqlalchemy import text

revision = "0015_approval_notifications"
down_revision = "0014_detection_profiles"
branch_labels = None
depends_on = None

TENANT = "nullif((SELECT current_setting('execbound.tenant_id', true)), '')::uuid"
DELIVERY_COLUMNS = (
    "state, attempts, next_attempt_at, lease_until, lease_token, delivered_at, last_error"
)


def upgrade() -> None:
    op.execute("""
        CREATE TABLE execbound.approval_notifications (
            tenant_id uuid NOT NULL,
            notification_id uuid NOT NULL,
            approval_id uuid NOT NULL,
            destination_id text NOT NULL CHECK (destination_id ~ '^[A-Za-z0-9_.-]{1,64}$'),
            created_at timestamptz NOT NULL,
            state text NOT NULL DEFAULT 'PENDING'
                CHECK (state IN ('PENDING', 'IN_FLIGHT', 'DELIVERED', 'FAILED')),
            attempts integer NOT NULL DEFAULT 0 CHECK (attempts BETWEEN 0 AND 5),
            next_attempt_at timestamptz NOT NULL,
            lease_until timestamptz,
            lease_token uuid,
            delivered_at timestamptz,
            last_error text CHECK (last_error ~ '^[A-Z][A-Z0-9_]{0,63}$'),
            PRIMARY KEY (tenant_id, notification_id),
            UNIQUE (tenant_id, approval_id, destination_id),
            FOREIGN KEY (tenant_id, approval_id) REFERENCES execbound.approvals,
            CHECK ((state = 'IN_FLIGHT' AND lease_until IS NOT NULL AND lease_token IS NOT NULL)
                OR (state <> 'IN_FLIGHT' AND lease_until IS NULL AND lease_token IS NULL)),
            CHECK ((state = 'DELIVERED') = (delivered_at IS NOT NULL))
        )
    """)
    op.execute("""
        CREATE INDEX approval_notifications_pending ON execbound.approval_notifications
            (tenant_id, next_attempt_at, notification_id) WHERE state IN ('PENDING', 'IN_FLIGHT')
    """)
    op.execute("ALTER TABLE execbound.approval_notifications ENABLE ROW LEVEL SECURITY")
    op.execute("ALTER TABLE execbound.approval_notifications FORCE ROW LEVEL SECURITY")
    op.execute(f"""
        CREATE POLICY tenant_isolation ON execbound.approval_notifications
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
        op.execute(f"REVOKE ALL ON execbound.approval_notifications FROM {role}")
    op.execute("GRANT SELECT, INSERT ON execbound.approval_notifications TO execbound_app")
    op.execute(
        f"GRANT UPDATE ({DELIVERY_COLUMNS}) ON execbound.approval_notifications TO execbound_app"
    )


def downgrade() -> None:
    # Delivery history explains why an approver did or did not learn of an approval.
    op.execute("ALTER TABLE execbound.approval_notifications NO FORCE ROW LEVEL SECURITY")
    op.execute("SET LOCAL row_security = off")
    retained = op.get_bind().execute(
        text("SELECT EXISTS (SELECT 1 FROM execbound.approval_notifications)")
    )
    if retained.scalar_one():
        raise RuntimeError("Cannot downgrade while approval notifications are retained")
    op.execute("DROP TABLE execbound.approval_notifications")
