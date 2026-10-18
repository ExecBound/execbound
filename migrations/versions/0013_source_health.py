"""Persisted monitoring source health and clock-skew detections.

Health findings describe receipt-time gaps and bind to a source, not an observation;
clock-skew findings bind to the observation whose reported time is implausible.
"""

from alembic import op
from sqlalchemy import text

revision = "0013_source_health"
down_revision = "0012_source_rotation"
branch_labels = None
depends_on = None

RULES = "'sensitive-action.v1', 'source-event-integrity.v1', 'source-health.v1', 'clock-skew.v1'"
HEALTH_COLUMNS = "health_state, health_changed_at, health_checked_at"


def upgrade() -> None:
    op.execute("""
        ALTER TABLE execbound.monitor_findings
            ALTER COLUMN observation_id DROP NOT NULL,
            DROP CONSTRAINT monitor_findings_rule_version_check
    """)
    op.execute(f"""
        ALTER TABLE execbound.monitor_findings
            ADD CONSTRAINT monitor_findings_rule_version_check
                CHECK (rule_version IN ({RULES})),
            ADD CONSTRAINT monitor_findings_health_without_observation
                CHECK ((observation_id IS NULL) = (rule_version = 'source-health.v1'))
    """)
    op.execute("""
        ALTER TABLE execbound.monitor_sources
            ADD COLUMN health_state text NOT NULL DEFAULT 'UNKNOWN'
                CHECK (health_state IN ('UNKNOWN', 'REPORTING', 'STALE')),
            ADD COLUMN health_changed_at timestamptz,
            ADD COLUMN health_checked_at timestamptz,
            ADD CONSTRAINT monitor_sources_health_change
                CHECK ((health_state = 'UNKNOWN') = (health_changed_at IS NULL))
    """)
    op.execute(f"GRANT UPDATE ({HEALTH_COLUMNS}) ON execbound.monitor_sources TO execbound_app")


def downgrade() -> None:
    # Health and skew findings are retained detective history; refuse to drop them.
    op.execute("ALTER TABLE execbound.monitor_findings NO FORCE ROW LEVEL SECURITY")
    op.execute("SET LOCAL row_security = off")
    retained = op.get_bind().execute(
        text(
            "SELECT EXISTS (SELECT 1 FROM execbound.monitor_findings "
            "WHERE rule_version IN ('source-health.v1', 'clock-skew.v1'))"
        )
    )
    if retained.scalar_one():
        raise RuntimeError("Cannot downgrade while health or clock-skew findings are retained")
    op.execute("ALTER TABLE execbound.monitor_findings FORCE ROW LEVEL SECURITY")
    op.execute(f"REVOKE UPDATE ({HEALTH_COLUMNS}) ON execbound.monitor_sources FROM execbound_app")
    op.execute("""
        ALTER TABLE execbound.monitor_sources
            DROP CONSTRAINT monitor_sources_health_change,
            DROP COLUMN health_checked_at,
            DROP COLUMN health_changed_at,
            DROP COLUMN health_state
    """)
    op.execute("""
        ALTER TABLE execbound.monitor_findings
            DROP CONSTRAINT monitor_findings_health_without_observation,
            DROP CONSTRAINT monitor_findings_rule_version_check,
            ADD CONSTRAINT monitor_findings_rule_version_check
                CHECK (rule_version IN ('sensitive-action.v1', 'source-event-integrity.v1')),
            ALTER COLUMN observation_id SET NOT NULL
    """)
