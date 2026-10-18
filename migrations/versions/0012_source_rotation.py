"""Monitoring source token rotation with a bounded grace window, and revocation attribution.

The registration digest stays immutable evidence; after a rotation the active digest lives in
current_token_hash and the retiring one in previous_token_hash until its deadline.
"""

from alembic import op

revision = "0012_source_rotation"
down_revision = "0011_tenant_stop"
branch_labels = None
depends_on = None

ROTATION_COLUMNS = (
    "current_token_hash, expires_at, previous_token_hash, previous_valid_until, "
    "rotated_at, rotated_by, revoked_by"
)


def upgrade() -> None:
    op.execute("""
        ALTER TABLE execbound.monitor_sources
            ADD COLUMN current_token_hash text
                CHECK (current_token_hash ~ '^[0-9a-f]{64}$'),
            ADD COLUMN previous_token_hash text
                CHECK (previous_token_hash ~ '^[0-9a-f]{64}$'),
            ADD COLUMN previous_valid_until timestamptz,
            ADD COLUMN rotated_at timestamptz,
            ADD COLUMN rotated_by uuid,
            ADD COLUMN revoked_by uuid,
            ADD CONSTRAINT monitor_sources_previous_together
                CHECK ((previous_token_hash IS NULL) = (previous_valid_until IS NULL)),
            ADD CONSTRAINT monitor_sources_previous_distinct CHECK (
                previous_token_hash IS NULL
                OR previous_token_hash <> COALESCE(current_token_hash, token_hash)
            ),
            ADD CONSTRAINT monitor_sources_rotation_together
                CHECK ((rotated_at IS NULL) = (rotated_by IS NULL)),
            ADD CONSTRAINT monitor_sources_rotated_by_fkey
                FOREIGN KEY (tenant_id, rotated_by) REFERENCES execbound.principals,
            ADD CONSTRAINT monitor_sources_revoked_by_fkey
                FOREIGN KEY (tenant_id, revoked_by) REFERENCES execbound.principals
    """)
    op.execute(
        "CREATE INDEX monitor_sources_rotated_by "
        "ON execbound.monitor_sources (tenant_id, rotated_by)"
    )
    op.execute(
        "CREATE INDEX monitor_sources_revoked_by "
        "ON execbound.monitor_sources (tenant_id, revoked_by)"
    )
    # Rotation and revocation are the only writers of these columns; both are ADMIN flows
    # that recheck current authority inside the monitoring registry lock.
    op.execute(f"GRANT UPDATE ({ROTATION_COLUMNS}) ON execbound.monitor_sources TO execbound_app")


def downgrade() -> None:
    # Ending every grace window early only refuses old tokens; nothing is lost.
    op.execute("REVOKE UPDATE (expires_at) ON execbound.monitor_sources FROM execbound_app")
    op.execute("""
        ALTER TABLE execbound.monitor_sources
            DROP CONSTRAINT monitor_sources_revoked_by_fkey,
            DROP CONSTRAINT monitor_sources_rotated_by_fkey,
            DROP CONSTRAINT monitor_sources_rotation_together,
            DROP CONSTRAINT monitor_sources_previous_distinct,
            DROP CONSTRAINT monitor_sources_previous_together,
            DROP COLUMN revoked_by,
            DROP COLUMN rotated_by,
            DROP COLUMN rotated_at,
            DROP COLUMN previous_valid_until,
            DROP COLUMN previous_token_hash,
            DROP COLUMN current_token_hash
    """)
