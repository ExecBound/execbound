"""Scout: external agents, their grants, their reach and accepted exceptions."""

from alembic import op
from sqlalchemy import text

revision = "0030_scout_agents"
# Re-parented onto the head the other session merged first, as the project rule requires.
down_revision = "0029_claim_clock"
branch_labels = None
depends_on = None

TABLES = (
    "monitor_agents",
    "monitor_agent_grants",
    "monitor_agent_reach",
    "monitor_reach_exceptions",
)
UPDATES = {
    "monitor_agents": (
        "display_name, display_name_truncated, enabled, blueprint_ref, blueprint_object_ref, "
        "credential_kinds, sponsors, sponsor_state, sponsor_group_count, owner_count, tags, "
        "linked_principal_id, observed_at, gone_at"
    ),
    "monitor_agent_grants": "path_ref, observed_at, gone_at",
    "monitor_agent_reach": (
        "certainty, enforcement_mode, catalog_version, computed_at, valid_until, gone_at"
    ),
    "monitor_reach_exceptions": "withdrawn_at",
}
KINDS = "'tines', 'entra_agent_id'"
CLASSES = "'agent_identity', 'service_principal', 'tines_story'"
# 'not_read' is a run that has not looked yet; 'unreadable' is a read the directory
# refused. Neither is 'absent', which is the only one that is an accountability gap.
SPONSOR_STATES = "'present', 'absent', 'unreadable', 'not_read'"
CREDENTIAL_KINDS = "'federated', 'certificate', 'secret', 'managed_identity'"
GRANT_KINDS = (
    "'graph_role', 'graph_scope', 'directory_role', "
    "'inherited_roles', 'inherited_scopes', 'tines_credential'"
)
INHERITED_KINDS = "'inherited_roles', 'inherited_scopes'"
PATH_KINDS = "'grant', 'role', 'inherited', 'execbound', 'observation'"
CERTAINTIES = "'verified', 'observed', 'inferred', 'unknown'"
MODES = "'native', 'integrated', 'embedded', 'advisory', 'observed', 'unknown'"
# The kernel's own action shape; a reach row can only ever name a catalog action.
ACTION = r"^[a-z][a-z0-9_]{0,31}\.[a-z][a-z0-9_]{0,31}$"
REF = "^[A-Za-z0-9._:-]{1,96}$"
# A grant value is an app role identifier, a scope string or a role template identifier.
VALUE = "^[A-Za-z0-9._:-]{1,128}$"
TINES_ORIGIN = r"^https://[A-Za-z0-9-]{1,63}(\.[A-Za-z0-9-]{1,63})*\.tines\.(com|io)$"
GRAPH_ORIGIN = "https://graph.microsoft.com"


def upgrade() -> None:
    # A connection now says which platform it speaks for, and its origin is checked against
    # that kind. Every existing row is a Tines connection and satisfies the new constraint
    # unchanged, so no row is rewritten.
    op.execute(f"""
        ALTER TABLE execbound.monitor_connections
            ADD COLUMN kind text NOT NULL DEFAULT 'tines' CHECK (kind IN ({KINDS})),
            ADD COLUMN directory_ref text CHECK (directory_ref ~ '{REF}'),
            ADD COLUMN client_ref text CHECK (client_ref ~ '{REF}'),
            DROP CONSTRAINT monitor_connections_base_url_check,
            ADD CONSTRAINT monitor_connections_base_url_check CHECK (
                (kind = 'tines' AND base_url ~ '{TINES_ORIGIN}')
                OR (kind = 'entra_agent_id' AND base_url = '{GRAPH_ORIGIN}')
            ),
            -- The directory and the app registration are known at registration, because the
            -- token request needs both before any read; a Tines connection has neither.
            ADD CONSTRAINT monitor_connections_directory_kind CHECK (
                (kind = 'entra_agent_id')
                = (directory_ref IS NOT NULL AND client_ref IS NOT NULL)
            ),
            -- A team scope is a Tines concept; Graph has no equivalent on this connection.
            ADD CONSTRAINT monitor_connections_team_kind
                CHECK (team_id IS NULL OR kind = 'tines')
    """)
    # A tenant runs one connection per platform at a time, not one in total.
    op.execute("DROP INDEX execbound.monitor_connections_one_active")
    op.execute(
        "CREATE UNIQUE INDEX monitor_connections_one_active "
        "ON execbound.monitor_connections (tenant_id, kind) WHERE active"
    )
    op.execute(f"""
        CREATE TABLE execbound.monitor_agents (
            tenant_id uuid NOT NULL,
            agent_id uuid NOT NULL,
            connection_id uuid NOT NULL,
            -- The directory object identifier, which is what the platform calls this agent.
            platform_ref text NOT NULL CHECK (platform_ref ~ '{REF}'),
            identity_class text NOT NULL CHECK (identity_class IN ({CLASSES})),
            display_name text NOT NULL CHECK (length(display_name) BETWEEN 1 AND 96),
            display_name_truncated boolean NOT NULL DEFAULT false,
            enabled boolean,
            -- The blueprint's application identifier, and the object it resolves to. Only an
            -- agent identity has one; a classic service principal holds its own credentials.
            blueprint_ref text CHECK (blueprint_ref ~ '{REF}'),
            blueprint_object_ref text CHECK (blueprint_object_ref ~ '{REF}'),
            credential_kinds text[] NOT NULL DEFAULT '{{}}'::text[] CHECK (
                credential_kinds <@ ARRAY[{CREDENTIAL_KINDS}]::text[]
                AND cardinality(credential_kinds) <= 4
            ),
            -- Object identifiers only. A sponsor is a person or a group; neither one's name,
            -- address nor any other attribute is collected or stored.
            sponsors jsonb NOT NULL DEFAULT '[]'::jsonb CHECK (
                jsonb_typeof(sponsors) = 'array'
                AND jsonb_array_length(sponsors) <= 100
                AND pg_column_size(sponsors) <= 8192
            ),
            sponsor_state text NOT NULL CHECK (sponsor_state IN ({SPONSOR_STATES})),
            sponsor_group_count integer NOT NULL DEFAULT 0
                CHECK (sponsor_group_count BETWEEN 0 AND 100),
            -- Null when the owners collection could not be read, which is not "no owner".
            owner_count integer CHECK (owner_count BETWEEN 0 AND 10000),
            -- What the platform labelled this principal. Evidence shown beside a class,
            -- never a reason to call a classic service principal an agent.
            tags jsonb NOT NULL DEFAULT '[]'::jsonb CHECK (
                jsonb_typeof(tags) = 'array'
                AND jsonb_array_length(tags) <= 32
                AND pg_column_size(tags) <= 4096
            ),
            -- Set by an ADMIN and never inferred; verified reach depends on it.
            linked_principal_id uuid,
            first_seen_at timestamptz NOT NULL,
            observed_at timestamptz NOT NULL,
            gone_at timestamptz,
            PRIMARY KEY (tenant_id, agent_id),
            UNIQUE (tenant_id, connection_id, platform_ref),
            FOREIGN KEY (tenant_id, connection_id)
                REFERENCES execbound.monitor_connections(tenant_id, connection_id),
            FOREIGN KEY (tenant_id, linked_principal_id)
                REFERENCES execbound.principals(tenant_id, principal_id),
            CHECK (observed_at >= first_seen_at),
            CHECK (gone_at IS NULL OR gone_at >= first_seen_at),
            -- "Has no sponsor" and "could not read the sponsors" are different facts.
            CHECK ((sponsor_state = 'present') = (jsonb_array_length(sponsors) > 0)),
            CHECK (sponsor_group_count <= jsonb_array_length(sponsors)),
            CHECK (blueprint_ref IS NULL OR identity_class = 'agent_identity'),
            CHECK (blueprint_object_ref IS NULL OR blueprint_ref IS NOT NULL)
        )
    """)
    op.execute(
        "CREATE INDEX monitor_agents_connection "
        "ON execbound.monitor_agents (tenant_id, connection_id, identity_class)"
    )
    # Full, not partial: a partial index does not cover a foreign key.
    op.execute(
        "CREATE INDEX monitor_agents_linked "
        "ON execbound.monitor_agents (tenant_id, linked_principal_id)"
    )
    op.execute(f"""
        CREATE TABLE execbound.monitor_agent_grants (
            tenant_id uuid NOT NULL,
            agent_id uuid NOT NULL,
            grant_kind text NOT NULL CHECK (grant_kind IN ({GRANT_KINDS})),
            -- The resource application a grant applies to; empty for a directory role,
            -- which is not scoped to one resource application.
            resource_ref text NOT NULL CHECK (resource_ref ~ '^[A-Za-z0-9._:-]{{0,96}}$'),
            value text NOT NULL CHECK (value ~ '{VALUE}'),
            inherited boolean NOT NULL DEFAULT false,
            -- The object the grant actually sits on: the agent, or the blueprint it
            -- inherits from. An inherited grant that named the agent would hide where to fix it.
            path_ref text NOT NULL CHECK (path_ref ~ '{REF}'),
            observed_at timestamptz NOT NULL,
            gone_at timestamptz,
            PRIMARY KEY (tenant_id, agent_id, grant_kind, resource_ref, value),
            FOREIGN KEY (tenant_id, agent_id)
                REFERENCES execbound.monitor_agents(tenant_id, agent_id),
            CHECK (inherited = (grant_kind IN ({INHERITED_KINDS}))),
            CHECK (gone_at IS NULL OR gone_at >= observed_at)
        )
    """)
    op.execute(f"""
        CREATE TABLE execbound.monitor_agent_reach (
            tenant_id uuid NOT NULL,
            agent_id uuid NOT NULL,
            action text NOT NULL CHECK (action ~ '{ACTION}'),
            path_kind text NOT NULL CHECK (path_kind IN ({PATH_KINDS})),
            path_ref text NOT NULL CHECK (path_ref ~ '{VALUE}'),
            certainty text NOT NULL CHECK (certainty IN ({CERTAINTIES})),
            enforcement_mode text NOT NULL CHECK (enforcement_mode IN ({MODES})),
            catalog_version text NOT NULL CHECK (catalog_version ~ '^[a-z][a-z0-9_.-]{{0,31}}$'),
            computed_at timestamptz NOT NULL,
            valid_until timestamptz NOT NULL,
            gone_at timestamptz,
            PRIMARY KEY (tenant_id, agent_id, action, path_kind, path_ref),
            FOREIGN KEY (tenant_id, agent_id)
                REFERENCES execbound.monitor_agents(tenant_id, agent_id),
            CHECK (valid_until > computed_at),
            CHECK (gone_at IS NULL OR gone_at >= computed_at),
            -- A path can only carry the certainty it is able to establish. A grant never
            -- proves an execution happened, and an observation never proves prevention.
            CHECK (
                (path_kind IN ('grant', 'role', 'inherited')
                    AND certainty IN ('inferred', 'unknown'))
                OR (path_kind = 'observation' AND certainty = 'observed')
                OR (path_kind = 'execbound' AND certainty IN ('inferred', 'verified'))
            ),
            -- Nothing ExecBound operates stands between an agent and its own grant, so a
            -- grant path can never claim an enforced mode.
            CHECK (
                (path_kind IN ('grant', 'role', 'inherited')
                    AND enforcement_mode IN ('advisory', 'unknown'))
                OR (path_kind = 'observation' AND enforcement_mode = 'observed')
                OR (path_kind = 'execbound'
                    AND enforcement_mode IN ('native', 'integrated', 'embedded'))
            )
        )
    """)
    op.execute(
        "CREATE INDEX monitor_agent_reach_action "
        "ON execbound.monitor_agent_reach (tenant_id, action, certainty) WHERE gone_at IS NULL"
    )
    op.execute(f"""
        CREATE TABLE execbound.monitor_reach_exceptions (
            tenant_id uuid NOT NULL,
            agent_id uuid NOT NULL,
            action text NOT NULL CHECK (action ~ '{ACTION}'),
            path_kind text NOT NULL CHECK (path_kind IN ({PATH_KINDS})),
            path_ref text NOT NULL CHECK (path_ref ~ '{VALUE}'),
            accepted_by uuid NOT NULL,
            accepted_at timestamptz NOT NULL,
            expires_at timestamptz,
            withdrawn_at timestamptz,
            reason_code text NOT NULL CHECK (reason_code ~ '^[A-Z_]{{1,48}}$'),
            PRIMARY KEY (tenant_id, agent_id, action, path_kind, path_ref),
            FOREIGN KEY (tenant_id, agent_id)
                REFERENCES execbound.monitor_agents(tenant_id, agent_id),
            FOREIGN KEY (tenant_id, accepted_by)
                REFERENCES execbound.principals(tenant_id, principal_id),
            CHECK (expires_at IS NULL OR expires_at > accepted_at),
            CHECK (withdrawn_at IS NULL OR withdrawn_at >= accepted_at)
        )
    """)
    op.execute(
        "CREATE INDEX monitor_reach_exceptions_accepted_by "
        "ON execbound.monitor_reach_exceptions (tenant_id, accepted_by)"
    )
    for table in TABLES:
        op.execute(f"ALTER TABLE execbound.{table} ENABLE ROW LEVEL SECURITY")
        op.execute(f"ALTER TABLE execbound.{table} FORCE ROW LEVEL SECURITY")
        # The subselect makes the setting an InitPlan read once per statement, which is what
        # 0024 established for every monitoring table; a bare call is read once per row.
        op.execute(f"""
            CREATE POLICY tenant_isolation ON execbound.{table}
            USING (tenant_id = nullif(
                (SELECT current_setting('execbound.tenant_id', true)), ''
            )::uuid)
            WITH CHECK (tenant_id = nullif(
                (SELECT current_setting('execbound.tenant_id', true)), ''
            )::uuid)
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
        "LOCK TABLE execbound.monitor_agents, execbound.monitor_agent_grants, "
        "execbound.monitor_agent_reach, execbound.monitor_reach_exceptions, "
        "execbound.monitor_connections IN ACCESS EXCLUSIVE MODE"
    )
    for table in (*TABLES, "monitor_connections"):
        op.execute(f"ALTER TABLE execbound.{table} NO FORCE ROW LEVEL SECURITY")
    op.execute("SET LOCAL row_security = off")
    if (
        op.get_bind()
        .execute(
            text(
                "SELECT EXISTS (SELECT 1 FROM execbound.monitor_agents) "
                "OR EXISTS (SELECT 1 FROM execbound.monitor_connections "
                "WHERE kind <> 'tines')"
            )
        )
        .scalar_one()
    ):
        raise RuntimeError("Cannot downgrade while collected agent evidence is retained")
    for table in reversed(TABLES):
        op.execute(f"DROP TABLE execbound.{table}")
    op.execute("DROP INDEX execbound.monitor_connections_one_active")
    op.execute(f"""
        ALTER TABLE execbound.monitor_connections
            DROP CONSTRAINT monitor_connections_team_kind,
            DROP CONSTRAINT monitor_connections_directory_kind,
            DROP CONSTRAINT monitor_connections_base_url_check,
            ADD CONSTRAINT monitor_connections_base_url_check
                CHECK (base_url ~ '{TINES_ORIGIN}'),
            DROP COLUMN client_ref,
            DROP COLUMN directory_ref,
            DROP COLUMN kind
    """)
    op.execute(
        "CREATE UNIQUE INDEX monitor_connections_one_active "
        "ON execbound.monitor_connections (tenant_id) WHERE active"
    )
    for table in (*TABLES[:0], "monitor_connections"):
        op.execute(f"ALTER TABLE execbound.{table} FORCE ROW LEVEL SECURITY")
