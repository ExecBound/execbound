"""Read-only platform collection: connections, inventory and collected observations."""

from alembic import op
from sqlalchemy import text

revision = "0023_monitor_collection"
down_revision = "0022_limit_scopes"
branch_labels = None
depends_on = None

TABLES = ("monitor_connections", "monitor_inventory")
UPDATES = {
    "monitor_connections": (
        "active, revoked_at, capabilities, capabilities_at, health_state, health_changed_at, "
        "audit_cursor, platform_tenant_ref, last_run_at, last_run_id, last_outcome, "
        "last_error_code, last_sync_at, "
        "retry_after_seconds, consecutive_rate_limited, consecutive_backlog"
    ),
    "monitor_inventory": (
        "name, name_truncated, item_type, disabled, outbound, last_seen_at, gone_at, "
        "source_updated_at, gap_opened_at, coverage_class"
    ),
}
HEALTH = "'NEVER_COLLECTED', 'COLLECTING', 'AUTH_LOST', 'RATE_LIMITED', 'RETENTION_GAP', 'ERROR'"
OUTCOMES = "'COMPLETE', 'BACKLOG', 'RATE_LIMITED', 'AUTH_LOST', 'RETENTION_GAP', 'ERROR'"
KINDS = "'tool_result', 'heartbeat', 'config_change', 'ai_model_run', 'ai_tool_run'"
OBSERVATION_RULES = "'sensitive-action.v1', 'sensitive-action.v2', 'monitored-path-change.v1'"
COLLECTION_RULES = "'instrumentation-gap.v1', 'collection-health.v1'"
WITHOUT_OBSERVATION = "'source-health.v1', " + COLLECTION_RULES
FINDING_RULES = (
    "'sensitive-action.v1', 'sensitive-action.v2', 'source-event-integrity.v1', "
    "'source-health.v1', 'clock-skew.v1', 'restricted-target.v1', 'observed-rate.v1', "
    "'monitored-path-change.v1', 'instrumentation-gap.v1', 'collection-health.v1'"
)
# The kinds only platform collection produces; a reported event can never claim them.
COLLECTED_KINDS = "'config_change', 'ai_model_run', 'ai_tool_run'"


def upgrade() -> None:
    op.execute(f"""
        CREATE TABLE execbound.monitor_connections (
            tenant_id uuid NOT NULL REFERENCES execbound.tenants(tenant_id),
            connection_id uuid NOT NULL,
            label text NOT NULL CHECK (length(label) BETWEEN 1 AND 96),
            base_url text NOT NULL CHECK (
                base_url ~ '^https://[A-Za-z0-9-]{{1,63}}'
                           '(\\.[A-Za-z0-9-]{{1,63}})*\\.tines\\.(com|io)$'
            ),
            team_id text CHECK (team_id ~ '^[A-Za-z0-9._:-]{{1,64}}$'),
            key_fingerprint text NOT NULL CHECK (key_fingerprint ~ '^[0-9a-f]{{64}}$'),
            created_at timestamptz NOT NULL,
            created_by uuid NOT NULL,
            active boolean NOT NULL DEFAULT true,
            revoked_at timestamptz,
            capabilities jsonb NOT NULL DEFAULT '{{}}'::jsonb CHECK (
                jsonb_typeof(capabilities) = 'object' AND pg_column_size(capabilities) <= 4096
            ),
            capabilities_at timestamptz,
            health_state text NOT NULL DEFAULT 'NEVER_COLLECTED'
                CHECK (health_state IN ({HEALTH})),
            health_changed_at timestamptz,
            audit_cursor timestamptz,
            -- The vendor tenant identifier this connection first collected from; every later
            -- record must agree with it, so a response can never move rows between tenants.
            platform_tenant_ref text CHECK (platform_tenant_ref ~ '^[A-Za-z0-9._:-]{{1,96}}$'),
            last_run_at timestamptz,
            last_run_id uuid,
            last_outcome text CHECK (last_outcome IN ({OUTCOMES})),
            last_error_code text CHECK (last_error_code ~ '^[A-Z_]{{1,48}}$'),
            last_sync_at timestamptz,
            retry_after_seconds integer CHECK (retry_after_seconds BETWEEN 0 AND 86400),
            consecutive_rate_limited integer NOT NULL DEFAULT 0
                CHECK (consecutive_rate_limited BETWEEN 0 AND 1000000),
            consecutive_backlog integer NOT NULL DEFAULT 0
                CHECK (consecutive_backlog BETWEEN 0 AND 1000000),
            PRIMARY KEY (tenant_id, connection_id),
            FOREIGN KEY (tenant_id, created_by)
                REFERENCES execbound.principals(tenant_id, principal_id),
            CHECK (revoked_at IS NULL OR NOT active)
        )
    """)
    # One tenant collects from one Tines tenant at a time; history stays as revoked rows.
    op.execute(
        "CREATE UNIQUE INDEX monitor_connections_one_active "
        "ON execbound.monitor_connections (tenant_id) WHERE active"
    )
    op.execute(
        "CREATE INDEX monitor_connections_created_by "
        "ON execbound.monitor_connections (tenant_id, created_by)"
    )
    op.execute("""
        CREATE TABLE execbound.monitor_inventory (
            tenant_id uuid NOT NULL,
            connection_id uuid NOT NULL,
            item_kind text NOT NULL CHECK (item_kind IN ('story', 'action', 'credential')),
            external_id text NOT NULL CHECK (external_id ~ '^[A-Za-z0-9._:-]{1,96}$'),
            story_external_id text CHECK (story_external_id ~ '^[A-Za-z0-9._:-]{1,96}$'),
            name text NOT NULL CHECK (length(name) BETWEEN 1 AND 96),
            name_truncated boolean NOT NULL DEFAULT false,
            item_type text CHECK (item_type ~ '^[A-Za-z0-9._:-]{1,96}$'),
            disabled boolean,
            outbound boolean,
            first_seen_at timestamptz NOT NULL,
            last_seen_at timestamptz NOT NULL,
            gone_at timestamptz,
            source_updated_at timestamptz,
            -- When the current uninstrumented-story episode opened; cleared when it closes.
            gap_opened_at timestamptz,
            -- The class the last reconciliation assigned, so the pages show what the rule saw.
            coverage_class text CHECK (coverage_class IN ('instrumented', 'registered_stale',
                'discovered_only', 'no_outbound', 'coverage_unknown', 'disabled')),
            PRIMARY KEY (tenant_id, connection_id, item_kind, external_id),
            FOREIGN KEY (tenant_id, connection_id)
                REFERENCES execbound.monitor_connections(tenant_id, connection_id),
            CHECK ((item_kind = 'action') = (story_external_id IS NOT NULL)),
            -- Only an action carries an outbound classification; NULL is "not recognized".
            CHECK (outbound IS NULL OR item_kind = 'action'),
            CHECK (gap_opened_at IS NULL OR item_kind = 'story'),
            CHECK (coverage_class IS NULL OR item_kind = 'story'),
            CHECK (last_seen_at >= first_seen_at)
        )
    """)
    op.execute(f"""
        ALTER TABLE execbound.monitor_observations
            ALTER COLUMN source_id DROP NOT NULL,
            ALTER COLUMN story_id DROP NOT NULL,
            ADD COLUMN connection_id uuid,
            ADD COLUMN operation_name text
                CHECK (operation_name ~ '^[A-Za-z0-9._:-]{{1,96}}$'),
            ADD COLUMN external_ref text CHECK (external_ref ~ '^[A-Za-z0-9._:-]{{1,96}}$'),
            ADD COLUMN evidence text NOT NULL DEFAULT 'reported'
                CHECK (evidence IN ('reported', 'collected')),
            ADD COLUMN actor_ref text CHECK (actor_ref ~ '^[A-Za-z0-9._:-]{{1,96}}$'),
            ADD COLUMN input_tokens integer CHECK (input_tokens BETWEEN 0 AND 1000000000),
            ADD COLUMN output_tokens integer CHECK (output_tokens BETWEEN 0 AND 1000000000),
            ADD CONSTRAINT monitor_observations_one_origin
                CHECK (num_nonnulls(source_id, connection_id) = 1),
            ADD CONSTRAINT monitor_observations_evidence_origin
                CHECK ((evidence = 'reported') = (source_id IS NOT NULL)),
            ADD CONSTRAINT monitor_observations_reported_story
                CHECK (evidence = 'collected' OR story_id IS NOT NULL),
            ADD CONSTRAINT monitor_observations_collected_shape
                CHECK (evidence = 'reported'
                    OR (operation_name IS NOT NULL AND external_ref IS NOT NULL
                        AND target_ref IS NULL)),
            ADD CONSTRAINT monitor_observations_collected_kinds
                CHECK ((kind IN ({COLLECTED_KINDS})) = (evidence = 'collected')),
            ADD CONSTRAINT monitor_observations_tokens_kind
                CHECK ((input_tokens IS NULL AND output_tokens IS NULL) OR kind = 'ai_model_run'),
            ADD CONSTRAINT monitor_observations_connection_event
                UNIQUE (tenant_id, connection_id, event_id),
            ADD CONSTRAINT monitor_observations_connection_observation
                UNIQUE (tenant_id, connection_id, observation_id),
            ADD CONSTRAINT monitor_observations_connection_fkey
                FOREIGN KEY (tenant_id, connection_id)
                REFERENCES execbound.monitor_connections(tenant_id, connection_id),
            DROP CONSTRAINT monitor_observations_kind_check,
            ADD CONSTRAINT monitor_observations_kind_check CHECK (kind IN ({KINDS})),
            DROP CONSTRAINT monitor_observations_check,
            ADD CONSTRAINT monitor_observations_shape CHECK (
                (kind = 'tool_result' AND action IS NOT NULL AND outcome IS NOT NULL)
                OR (kind IN ('heartbeat', 'config_change')
                    AND action IS NULL AND target_ref IS NULL AND outcome IS NULL)
                OR (kind = 'ai_model_run' AND target_ref IS NULL AND outcome IS NULL)
                OR (kind = 'ai_tool_run' AND action IS NOT NULL AND target_ref IS NULL)
            ),
            DROP CONSTRAINT monitor_observations_rule_version_check,
            ADD CONSTRAINT monitor_observations_rule_version_check
                CHECK (rule_version IN ({OBSERVATION_RULES}))
    """)
    op.execute(f"""
        ALTER TABLE execbound.monitor_findings
            ALTER COLUMN source_id DROP NOT NULL,
            ADD COLUMN connection_id uuid,
            ADD CONSTRAINT monitor_findings_one_origin
                CHECK (num_nonnulls(source_id, connection_id) = 1),
            ADD CONSTRAINT monitor_findings_connection_fkey
                FOREIGN KEY (tenant_id, connection_id)
                REFERENCES execbound.monitor_connections(tenant_id, connection_id),
            ADD CONSTRAINT monitor_findings_connection_observation_fkey
                FOREIGN KEY (tenant_id, connection_id, observation_id)
                REFERENCES execbound.monitor_observations(
                    tenant_id, connection_id, observation_id),
            DROP CONSTRAINT monitor_findings_health_without_observation,
            ADD CONSTRAINT monitor_findings_health_without_observation
                CHECK ((observation_id IS NULL) = (rule_version IN ({WITHOUT_OBSERVATION}))),
            DROP CONSTRAINT monitor_findings_rule_version_check,
            ADD CONSTRAINT monitor_findings_rule_version_check
                CHECK (rule_version IN ({FINDING_RULES}))
    """)
    op.execute("""
        ALTER TABLE execbound.monitor_profiles
            ADD COLUMN ai_tool_actions jsonb NOT NULL DEFAULT '{}'::jsonb CHECK (
                jsonb_typeof(ai_tool_actions) = 'object'
                AND pg_column_size(ai_tool_actions) <= 8192
            )
    """)
    # Covers both the connection foreign key and the connection/observation one.
    op.execute(
        "CREATE INDEX monitor_findings_connection "
        "ON execbound.monitor_findings (tenant_id, connection_id, observation_id)"
    )
    for table in TABLES:
        op.execute(f"ALTER TABLE execbound.{table} ENABLE ROW LEVEL SECURITY")
        op.execute(f"ALTER TABLE execbound.{table} FORCE ROW LEVEL SECURITY")
        op.execute(f"""
            CREATE POLICY tenant_isolation ON execbound.{table}
            USING (tenant_id = nullif(current_setting('execbound.tenant_id', true), '')::uuid)
            WITH CHECK (tenant_id = nullif(current_setting('execbound.tenant_id', true), '')::uuid)
        """)
        op.execute(f"REVOKE ALL ON execbound.{table} FROM PUBLIC")
        for role in ("anon", "authenticated", "service_role", "execbound_app"):
            if (
                op.get_bind()
                .execute(
                    text("SELECT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = :role)"),
                    {"role": role},
                )
                .scalar_one()
            ):
                op.execute(f"REVOKE ALL ON execbound.{table} FROM {role}")
        op.execute(f"GRANT SELECT, INSERT ON execbound.{table} TO execbound_app")
        op.execute(f"GRANT UPDATE ({UPDATES[table]}) ON execbound.{table} TO execbound_app")


def downgrade() -> None:
    op.execute(
        "LOCK TABLE execbound.monitor_connections, execbound.monitor_inventory, "
        "execbound.monitor_observations, execbound.monitor_findings, "
        "execbound.monitor_profiles IN ACCESS EXCLUSIVE MODE"
    )
    for table in (*TABLES, "monitor_observations", "monitor_findings", "monitor_profiles"):
        op.execute(f"ALTER TABLE execbound.{table} NO FORCE ROW LEVEL SECURITY")
    op.execute("SET LOCAL row_security = off")
    if (
        op.get_bind()
        .execute(
            text(
                "SELECT EXISTS (SELECT 1 FROM execbound.monitor_connections) "
                "OR EXISTS (SELECT 1 FROM execbound.monitor_inventory) "
                "OR EXISTS (SELECT 1 FROM execbound.monitor_observations "
                "WHERE evidence = 'collected') "
                "OR EXISTS (SELECT 1 FROM execbound.monitor_findings "
                f"WHERE rule_version IN ({COLLECTION_RULES}) OR connection_id IS NOT NULL) "
                "OR EXISTS (SELECT 1 FROM execbound.monitor_profiles "
                "WHERE ai_tool_actions <> '{}'::jsonb)"
            )
        )
        .scalar_one()
    ):
        raise RuntimeError("Cannot downgrade while collected monitoring evidence is retained")
    op.execute("DROP INDEX execbound.monitor_findings_connection")
    op.execute("ALTER TABLE execbound.monitor_profiles DROP COLUMN ai_tool_actions")
    op.execute("""
        ALTER TABLE execbound.monitor_findings
            DROP CONSTRAINT monitor_findings_connection_observation_fkey,
            DROP CONSTRAINT monitor_findings_connection_fkey,
            DROP CONSTRAINT monitor_findings_one_origin,
            DROP COLUMN connection_id,
            ALTER COLUMN source_id SET NOT NULL,
            DROP CONSTRAINT monitor_findings_health_without_observation,
            ADD CONSTRAINT monitor_findings_health_without_observation
                CHECK ((observation_id IS NULL) = (rule_version = 'source-health.v1')),
            DROP CONSTRAINT monitor_findings_rule_version_check,
            ADD CONSTRAINT monitor_findings_rule_version_check CHECK (rule_version IN (
                'sensitive-action.v1', 'sensitive-action.v2', 'source-event-integrity.v1',
                'source-health.v1', 'clock-skew.v1', 'restricted-target.v1', 'observed-rate.v1'))
    """)
    op.execute("""
        ALTER TABLE execbound.monitor_observations
            DROP CONSTRAINT monitor_observations_connection_fkey,
            DROP CONSTRAINT monitor_observations_connection_observation,
            DROP CONSTRAINT monitor_observations_connection_event,
            DROP CONSTRAINT monitor_observations_tokens_kind,
            DROP CONSTRAINT monitor_observations_collected_kinds,
            DROP CONSTRAINT monitor_observations_collected_shape,
            DROP CONSTRAINT monitor_observations_reported_story,
            DROP CONSTRAINT monitor_observations_evidence_origin,
            DROP CONSTRAINT monitor_observations_one_origin,
            DROP COLUMN output_tokens,
            DROP COLUMN input_tokens,
            DROP COLUMN actor_ref,
            DROP COLUMN evidence,
            DROP COLUMN external_ref,
            DROP COLUMN operation_name,
            DROP COLUMN connection_id,
            ALTER COLUMN story_id SET NOT NULL,
            ALTER COLUMN source_id SET NOT NULL,
            DROP CONSTRAINT monitor_observations_shape,
            ADD CONSTRAINT monitor_observations_check CHECK (
                (kind = 'tool_result' AND action IS NOT NULL AND outcome IS NOT NULL)
                OR (kind = 'heartbeat' AND action IS NULL
                    AND target_ref IS NULL AND outcome IS NULL)),
            DROP CONSTRAINT monitor_observations_kind_check,
            ADD CONSTRAINT monitor_observations_kind_check
                CHECK (kind IN ('tool_result', 'heartbeat')),
            DROP CONSTRAINT monitor_observations_rule_version_check,
            ADD CONSTRAINT monitor_observations_rule_version_check
                CHECK (rule_version IN ('sensitive-action.v1', 'sensitive-action.v2'))
    """)
    for table in reversed(TABLES):
        op.execute(f"DROP TABLE execbound.{table}")
    for table in ("monitor_observations", "monitor_findings", "monitor_profiles"):
        op.execute(f"ALTER TABLE execbound.{table} FORCE ROW LEVEL SECURITY")
