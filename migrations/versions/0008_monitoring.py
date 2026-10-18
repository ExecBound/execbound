"""Separate tenant-isolated observation, finding and delivery history."""

from alembic import op
from sqlalchemy import text

revision = "0008_monitoring"
down_revision = "0007_identity_context"
branch_labels = None
depends_on = None

TABLES = ("monitor_sources", "monitor_observations", "monitor_findings", "monitor_deliveries")
UPDATES = {
    "monitor_sources": (
        "active, revoked_at, last_event_at, last_heartbeat_at, last_refusal_code, "
        "last_refusal_at, rate_window_at, rate_count, accepted_count"
    ),
    "monitor_observations": (
        "evaluation_state, evaluation_result, evaluated_at, integrity_conflict_at"
    ),
    "monitor_findings": "acknowledged_at, acknowledged_by",
    "monitor_deliveries": (
        "state, attempts, next_attempt_at, lease_until, lease_token, delivered_at, last_error"
    ),
}


def upgrade() -> None:
    op.execute("""
        CREATE TABLE execbound.monitor_sources (
            tenant_id uuid NOT NULL REFERENCES execbound.tenants(tenant_id),
            source_id uuid NOT NULL,
            label text NOT NULL CHECK (length(label) BETWEEN 1 AND 96),
            story_id text NOT NULL CHECK (story_id ~ '^[A-Za-z0-9._:-]{1,96}$'),
            token_hash text NOT NULL CHECK (token_hash ~ '^[0-9a-f]{64}$'),
            created_at timestamptz NOT NULL,
            expires_at timestamptz NOT NULL CHECK (expires_at > created_at),
            active boolean NOT NULL DEFAULT true,
            revoked_at timestamptz,
            heartbeat_seconds integer NOT NULL CHECK (heartbeat_seconds BETWEEN 30 AND 86400),
            last_event_at timestamptz,
            last_heartbeat_at timestamptz,
            last_refusal_code text CHECK (
                last_refusal_code IN ('SOURCE_RATE_LIMIT', 'SOURCE_CAPACITY', 'EVENT_CONFLICT')
            ),
            last_refusal_at timestamptz,
            rate_window_at timestamptz NOT NULL,
            rate_count integer NOT NULL DEFAULT 0 CHECK (rate_count BETWEEN 0 AND 1000000),
            accepted_count integer NOT NULL DEFAULT 0 CHECK (accepted_count BETWEEN 0 AND 10000),
            PRIMARY KEY (tenant_id, source_id),
            UNIQUE (tenant_id, source_id, story_id),
            CHECK ((last_refusal_code IS NULL) = (last_refusal_at IS NULL))
        )
    """)
    op.execute("""
        CREATE TABLE execbound.monitor_observations (
            tenant_id uuid NOT NULL,
            observation_id uuid NOT NULL,
            source_id uuid NOT NULL,
            event_id text NOT NULL CHECK (event_id ~ '^[A-Za-z0-9._:-]{1,96}$'),
            story_id text NOT NULL,
            version integer NOT NULL CHECK (version = 1),
            occurred_at timestamptz NOT NULL,
            received_at timestamptz NOT NULL,
            kind text NOT NULL CHECK (kind IN ('tool_result', 'heartbeat')),
            action text CHECK (action ~ '^[A-Za-z0-9._:-]{1,64}$'),
            target_ref text CHECK (target_ref ~ '^[A-Za-z0-9._:-]{1,96}$'),
            outcome text CHECK (outcome IN ('success', 'error', 'unknown')),
            content_hash text NOT NULL CHECK (content_hash ~ '^[0-9a-f]{64}$'),
            rule_version text NOT NULL CHECK (rule_version = 'sensitive-action.v1'),
            evaluation_state text NOT NULL DEFAULT 'PENDING'
                CHECK (evaluation_state IN ('PENDING', 'COMPLETED')),
            evaluation_result text
                CHECK (evaluation_result IN ('MATCH', 'NO_MATCH', 'INSUFFICIENT_EVIDENCE')),
            evaluated_at timestamptz,
            integrity_conflict_at timestamptz,
            PRIMARY KEY (tenant_id, observation_id),
            UNIQUE (tenant_id, source_id, event_id),
            UNIQUE (tenant_id, source_id, observation_id),
            FOREIGN KEY (tenant_id, source_id, story_id)
                REFERENCES execbound.monitor_sources(tenant_id, source_id, story_id),
            CHECK ((kind = 'tool_result' AND action IS NOT NULL AND outcome IS NOT NULL)
                OR (kind = 'heartbeat' AND action IS NULL
                    AND target_ref IS NULL AND outcome IS NULL)),
            CHECK ((evaluation_state = 'PENDING'
                    AND evaluation_result IS NULL AND evaluated_at IS NULL)
                OR (evaluation_state = 'COMPLETED' AND evaluation_result IS NOT NULL
                    AND evaluated_at IS NOT NULL))
        )
    """)
    op.execute("""
        CREATE TABLE execbound.monitor_findings (
            tenant_id uuid NOT NULL,
            finding_id uuid NOT NULL,
            source_id uuid NOT NULL,
            observation_id uuid NOT NULL,
            rule_version text NOT NULL
                CHECK (rule_version IN ('sensitive-action.v1', 'source-event-integrity.v1')),
            title text NOT NULL CHECK (length(title) BETWEEN 1 AND 160),
            created_at timestamptz NOT NULL,
            acknowledged_at timestamptz,
            acknowledged_by uuid,
            PRIMARY KEY (tenant_id, finding_id),
            UNIQUE (tenant_id, observation_id, rule_version),
            FOREIGN KEY (tenant_id, source_id, observation_id)
                REFERENCES execbound.monitor_observations(tenant_id, source_id, observation_id),
            FOREIGN KEY (tenant_id, acknowledged_by)
                REFERENCES execbound.principals(tenant_id, principal_id),
            CHECK ((acknowledged_at IS NULL) = (acknowledged_by IS NULL))
        )
    """)
    op.execute("""
        CREATE TABLE execbound.monitor_deliveries (
            tenant_id uuid NOT NULL,
            delivery_id uuid NOT NULL,
            finding_id uuid NOT NULL,
            created_at timestamptz NOT NULL,
            state text NOT NULL DEFAULT 'PENDING'
                CHECK (state IN ('PENDING', 'IN_FLIGHT', 'DELIVERED', 'FAILED')),
            attempts integer NOT NULL DEFAULT 0 CHECK (attempts BETWEEN 0 AND 5),
            next_attempt_at timestamptz NOT NULL,
            lease_until timestamptz,
            lease_token uuid,
            delivered_at timestamptz,
            last_error text CHECK (last_error ~ '^[A-Z][A-Z0-9_]{0,63}$'),
            PRIMARY KEY (tenant_id, delivery_id),
            UNIQUE (tenant_id, finding_id),
            FOREIGN KEY (tenant_id, finding_id)
                REFERENCES execbound.monitor_findings(tenant_id, finding_id),
            CHECK ((state = 'IN_FLIGHT' AND lease_until IS NOT NULL AND lease_token IS NOT NULL)
                OR (state <> 'IN_FLIGHT' AND lease_until IS NULL AND lease_token IS NULL)),
            CHECK ((state = 'DELIVERED') = (delivered_at IS NOT NULL))
        )
    """)
    op.execute("""
        CREATE INDEX monitor_observations_pending ON execbound.monitor_observations
            (tenant_id, received_at, observation_id) WHERE evaluation_state = 'PENDING'
    """)
    op.execute("""
        CREATE INDEX monitor_observations_story ON execbound.monitor_observations
            (tenant_id, source_id, story_id)
    """)
    op.execute("""
        CREATE INDEX monitor_findings_observation ON execbound.monitor_findings
            (tenant_id, source_id, observation_id)
    """)
    op.execute("""
        CREATE INDEX monitor_findings_acknowledger ON execbound.monitor_findings
            (tenant_id, acknowledged_by)
    """)
    op.execute("""
        CREATE INDEX monitor_deliveries_pending ON execbound.monitor_deliveries
            (tenant_id, next_attempt_at, delivery_id) WHERE state IN ('PENDING', 'IN_FLIGHT')
    """)
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
        "LOCK TABLE " + ", ".join(f"execbound.{t}" for t in TABLES) + " IN ACCESS EXCLUSIVE MODE"
    )
    for table in TABLES:
        op.execute(f"ALTER TABLE execbound.{table} NO FORCE ROW LEVEL SECURITY")
    op.execute("SET LOCAL row_security = off")
    for table in TABLES:
        if (
            op.get_bind()
            .execute(text(f"SELECT EXISTS (SELECT 1 FROM execbound.{table})"))
            .scalar_one()
        ):
            raise RuntimeError("Cannot downgrade while monitoring data or history is retained")
    for table in reversed(TABLES):
        op.execute(f"DROP TABLE execbound.{table}")
