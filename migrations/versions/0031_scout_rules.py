"""Scout findings: the three agent rules, their episodes and the agent a finding names."""

from alembic import op
from sqlalchemy import text

revision = "0031_scout_rules"
down_revision = "0030_scout_agents"
branch_labels = None
depends_on = None

SCOUT_RULES = "'ungoverned-reach.v1', 'sponsorless-agent.v1', 'new-agent.v1'"
COLLECTION_RULES = "'instrumentation-gap.v1', 'collection-health.v1'"
WITHOUT_OBSERVATION = "'source-health.v1', " + COLLECTION_RULES + ", " + SCOUT_RULES
FINDING_RULES = (
    "'sensitive-action.v1', 'sensitive-action.v2', 'source-event-integrity.v1', "
    "'source-health.v1', 'clock-skew.v1', 'restricted-target.v1', 'observed-rate.v1', "
    "'monitored-path-change.v1', 'instrumentation-gap.v1', 'collection-health.v1', " + SCOUT_RULES
)
PRIOR_WITHOUT_OBSERVATION = "'source-health.v1', " + COLLECTION_RULES
PRIOR_FINDING_RULES = (
    "'sensitive-action.v1', 'sensitive-action.v2', 'source-event-integrity.v1', "
    "'source-health.v1', 'clock-skew.v1', 'restricted-target.v1', 'observed-rate.v1', "
    "'monitored-path-change.v1', 'instrumentation-gap.v1', 'collection-health.v1'"
)


def upgrade() -> None:
    # One open episode per agent per rule, marked on the agent the way an uninstrumented
    # story marks its own row: the finding stays for a person to read, the episode closes.
    op.execute("""
        ALTER TABLE execbound.monitor_agents
            ADD COLUMN reach_gap_opened_at timestamptz,
            ADD COLUMN sponsor_gap_opened_at timestamptz
    """)
    op.execute(
        "GRANT UPDATE (reach_gap_opened_at, sponsor_gap_opened_at) "
        "ON execbound.monitor_agents TO execbound_app"
    )
    op.execute(f"""
        ALTER TABLE execbound.monitor_findings
            ADD COLUMN agent_id uuid,
            ADD CONSTRAINT monitor_findings_agent_fkey
                FOREIGN KEY (tenant_id, agent_id)
                REFERENCES execbound.monitor_agents(tenant_id, agent_id),
            -- An agent rule names its agent; nothing else may, so a finding cannot quietly
            -- acquire an owner it did not come from.
            ADD CONSTRAINT monitor_findings_agent_rule
                CHECK ((agent_id IS NOT NULL) = (rule_version IN ({SCOUT_RULES}))),
            DROP CONSTRAINT monitor_findings_health_without_observation,
            ADD CONSTRAINT monitor_findings_health_without_observation
                CHECK ((observation_id IS NULL) = (rule_version IN ({WITHOUT_OBSERVATION}))),
            DROP CONSTRAINT monitor_findings_rule_version_check,
            ADD CONSTRAINT monitor_findings_rule_version_check
                CHECK (rule_version IN ({FINDING_RULES}))
    """)
    op.execute(
        "CREATE INDEX monitor_findings_agent ON execbound.monitor_findings (tenant_id, agent_id)"
    )


def downgrade() -> None:
    op.execute(
        "LOCK TABLE execbound.monitor_findings, execbound.monitor_agents IN ACCESS EXCLUSIVE MODE"
    )
    for table in ("monitor_findings", "monitor_agents"):
        op.execute(f"ALTER TABLE execbound.{table} NO FORCE ROW LEVEL SECURITY")
    op.execute("SET LOCAL row_security = off")
    if (
        op.get_bind()
        .execute(
            text(
                "SELECT EXISTS (SELECT 1 FROM execbound.monitor_findings "
                f"WHERE rule_version IN ({SCOUT_RULES}) OR agent_id IS NOT NULL)"
            )
        )
        .scalar_one()
    ):
        raise RuntimeError("Cannot downgrade while agent findings are retained")
    op.execute("DROP INDEX execbound.monitor_findings_agent")
    op.execute(f"""
        ALTER TABLE execbound.monitor_findings
            DROP CONSTRAINT monitor_findings_agent_rule,
            DROP CONSTRAINT monitor_findings_agent_fkey,
            DROP COLUMN agent_id,
            DROP CONSTRAINT monitor_findings_health_without_observation,
            ADD CONSTRAINT monitor_findings_health_without_observation
                CHECK ((observation_id IS NULL) = (rule_version IN ({PRIOR_WITHOUT_OBSERVATION}))),
            DROP CONSTRAINT monitor_findings_rule_version_check,
            ADD CONSTRAINT monitor_findings_rule_version_check
                CHECK (rule_version IN ({PRIOR_FINDING_RULES}))
    """)
    op.execute("""
        ALTER TABLE execbound.monitor_agents
            DROP COLUMN sponsor_gap_opened_at,
            DROP COLUMN reach_gap_opened_at
    """)
    for table in ("monitor_findings", "monitor_agents"):
        op.execute(f"ALTER TABLE execbound.{table} FORCE ROW LEVEL SECURITY")
