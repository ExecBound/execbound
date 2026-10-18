"""Per-tenant detection profiles and the M1 rule set over normalized observations.

Profiles are immutable versions: a change inserts the next version and retires the current one.
Findings record the profile version that produced them so history stays explainable.
"""

from alembic import op
from sqlalchemy import text

revision = "0014_detection_profiles"
down_revision = "0013_source_health"
branch_labels = None
depends_on = None

TENANT = "nullif((SELECT current_setting('execbound.tenant_id', true)), '')::uuid"
FINDING_RULES = (
    "'sensitive-action.v1', 'sensitive-action.v2', 'source-event-integrity.v1', "
    "'source-health.v1', 'clock-skew.v1', 'restricted-target.v1', 'observed-rate.v1'"
)
NEW_RULES = "'sensitive-action.v2', 'restricted-target.v1', 'observed-rate.v1'"


def upgrade() -> None:
    op.execute("""
        CREATE TABLE execbound.monitor_profiles (
            tenant_id uuid NOT NULL REFERENCES execbound.tenants,
            profile_id uuid NOT NULL,
            version integer NOT NULL CHECK (version >= 1),
            sensitive_actions jsonb NOT NULL CHECK (jsonb_typeof(sensitive_actions) = 'array'),
            restricted_targets jsonb NOT NULL CHECK (jsonb_typeof(restricted_targets) = 'array'),
            burst_threshold integer CHECK (burst_threshold BETWEEN 2 AND 10000),
            burst_window_seconds integer CHECK (burst_window_seconds BETWEEN 60 AND 86400),
            created_at timestamptz NOT NULL,
            created_by uuid NOT NULL,
            retired_at timestamptz,
            PRIMARY KEY (tenant_id, profile_id),
            UNIQUE (tenant_id, version),
            FOREIGN KEY (tenant_id, created_by) REFERENCES execbound.principals,
            CHECK ((burst_threshold IS NULL) = (burst_window_seconds IS NULL))
        )
    """)
    op.execute(
        "CREATE UNIQUE INDEX monitor_profiles_active ON execbound.monitor_profiles (tenant_id) "
        "WHERE retired_at IS NULL"
    )
    op.execute(
        "CREATE INDEX monitor_profiles_created_by "
        "ON execbound.monitor_profiles (tenant_id, created_by)"
    )
    op.execute("ALTER TABLE execbound.monitor_profiles ENABLE ROW LEVEL SECURITY")
    op.execute("ALTER TABLE execbound.monitor_profiles FORCE ROW LEVEL SECURITY")
    op.execute(f"""
        CREATE POLICY tenant_isolation ON execbound.monitor_profiles
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
        op.execute(f"REVOKE ALL ON execbound.monitor_profiles FROM {role}")
    op.execute("GRANT SELECT, INSERT ON execbound.monitor_profiles TO execbound_app")
    op.execute("GRANT UPDATE (retired_at) ON execbound.monitor_profiles TO execbound_app")
    op.execute("""
        ALTER TABLE execbound.monitor_findings
            ADD COLUMN profile_id uuid,
            ADD COLUMN profile_version integer CHECK (profile_version >= 1),
            ADD CONSTRAINT monitor_findings_profile_together
                CHECK ((profile_id IS NULL) = (profile_version IS NULL)),
            ADD CONSTRAINT monitor_findings_profile_fkey
                FOREIGN KEY (tenant_id, profile_id) REFERENCES execbound.monitor_profiles,
            DROP CONSTRAINT monitor_findings_rule_version_check
    """)
    op.execute(f"""
        ALTER TABLE execbound.monitor_findings
            ADD CONSTRAINT monitor_findings_rule_version_check
                CHECK (rule_version IN ({FINDING_RULES}))
    """)
    op.execute(
        "CREATE INDEX monitor_findings_profile "
        "ON execbound.monitor_findings (tenant_id, profile_id)"
    )
    op.execute("""
        ALTER TABLE execbound.monitor_observations
            DROP CONSTRAINT monitor_observations_rule_version_check,
            ADD CONSTRAINT monitor_observations_rule_version_check
                CHECK (rule_version IN ('sensitive-action.v1', 'sensitive-action.v2'))
    """)


def downgrade() -> None:
    # Profiles and the findings they explain are retained detective history.
    for table in ("monitor_profiles", "monitor_findings", "monitor_observations"):
        op.execute(f"ALTER TABLE execbound.{table} NO FORCE ROW LEVEL SECURITY")
    op.execute("SET LOCAL row_security = off")
    retained = op.get_bind().execute(
        text(
            "SELECT EXISTS (SELECT 1 FROM execbound.monitor_profiles) "
            "OR EXISTS (SELECT 1 FROM execbound.monitor_findings "
            f"WHERE rule_version IN ({NEW_RULES})) "
            "OR EXISTS (SELECT 1 FROM execbound.monitor_observations "
            "WHERE rule_version = 'sensitive-action.v2')"
        )
    )
    if retained.scalar_one():
        raise RuntimeError(
            "Cannot downgrade while monitoring data or history "
            "(detection profiles or their findings) is retained"
        )
    for table in ("monitor_profiles", "monitor_findings", "monitor_observations"):
        op.execute(f"ALTER TABLE execbound.{table} FORCE ROW LEVEL SECURITY")
    op.execute("""
        ALTER TABLE execbound.monitor_observations
            DROP CONSTRAINT monitor_observations_rule_version_check,
            ADD CONSTRAINT monitor_observations_rule_version_check
                CHECK (rule_version = 'sensitive-action.v1')
    """)
    op.execute("""
        ALTER TABLE execbound.monitor_findings
            DROP CONSTRAINT monitor_findings_profile_fkey,
            DROP CONSTRAINT monitor_findings_profile_together,
            DROP CONSTRAINT monitor_findings_rule_version_check,
            ADD CONSTRAINT monitor_findings_rule_version_check CHECK (rule_version IN (
                'sensitive-action.v1', 'source-event-integrity.v1',
                'source-health.v1', 'clock-skew.v1'
            )),
            DROP COLUMN profile_version,
            DROP COLUMN profile_id
    """)
    op.execute("DROP TABLE execbound.monitor_profiles")
