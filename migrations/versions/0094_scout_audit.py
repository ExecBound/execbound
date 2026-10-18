# SPDX-License-Identifier: AGPL-3.0-only
"""Scout's directory audit-log observations and the activity baseline (#355).

`monitor_observations` admits a new collected kind, `entra_audit`: one entry of a Microsoft Entra
directory's audit log that an application initiated and the reviewed activity map covers. It
names the action, the outcome and its target by object id, a GUID, and it is the one collected
kind that names a target at all; every other collected kind still names none. Its external
reference is the entry's own id, which Microsoft writes with underscores; the reference check
0023 wrote admits them already, so it is left as it is.

`monitor_connections` gains, for an Entra connection only, `audit_baseline_at`: the moment the
connection's first audit read that caught up with the log stored what it found. What that read
and the reads before it found is the actors' habit rather than news, so no `entra_audit`
observation received at or before it raises `first-consequential-action.v1`. It also gains
`audit_behind_since`, Entra only too: the moment from which the connection's audit reads have
not caught up, cleared by one that does or by a run that skips the read its probe found
refused, which dates the episode a health finding is raised for. The runtime gains column
`UPDATE` on both and no `INSERT`, so `check_runtime`'s insertable set is unchanged. No table,
policy or index is added.

The downgrade refuses `SCOUT_AUDIT_OBSERVATIONS_RETAINED` while any `entra_audit` observation is
retained, because the earlier checks cannot hold one, looking with row security off for the look
alone because an owner that does not bypass it would otherwise see nothing. It otherwise drops the
columns and restores the earlier checks; an activity baseline and a lag are state rather than
evidence.
"""

from alembic import op
from sqlalchemy import text

revision = "0094_scout_audit"
down_revision = "0093_scout_delta"
branch_labels = None
depends_on = None

GUID = "^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
PRIOR_KINDS = "'tool_result', 'heartbeat', 'config_change', 'ai_model_run', 'ai_tool_run'"
PRIOR_COLLECTED = "'config_change', 'ai_model_run', 'ai_tool_run'"
PRIOR_SHAPE = """
    (kind = 'tool_result' AND action IS NOT NULL AND outcome IS NOT NULL)
    OR (kind IN ('heartbeat', 'config_change')
        AND action IS NULL AND target_ref IS NULL AND outcome IS NULL)
    OR (kind = 'ai_model_run' AND target_ref IS NULL AND outcome IS NULL)
    OR (kind = 'ai_tool_run' AND action IS NOT NULL AND target_ref IS NULL)
"""
SHAPE = (
    PRIOR_SHAPE
    + f"""    OR (kind = 'entra_audit' AND action IS NOT NULL AND outcome IS NOT NULL
        AND target_ref IS NOT NULL AND target_ref ~ '{GUID}')
"""
)
PRIOR_COLLECTED_SHAPE = """evidence = 'reported'
    OR (operation_name IS NOT NULL AND external_ref IS NOT NULL AND target_ref IS NULL)"""
COLLECTED_SHAPE = """evidence = 'reported'
    OR (operation_name IS NOT NULL AND external_ref IS NOT NULL
        AND (target_ref IS NULL OR kind = 'entra_audit'))"""


def _checks(kinds: str, collected: str, shape: str, collected_shape: str) -> str:
    return f"""
        ALTER TABLE execbound.monitor_observations
            DROP CONSTRAINT monitor_observations_kind_check,
            ADD CONSTRAINT monitor_observations_kind_check CHECK (kind IN ({kinds})),
            DROP CONSTRAINT monitor_observations_collected_kinds,
            ADD CONSTRAINT monitor_observations_collected_kinds
                CHECK ((kind IN ({collected})) = (evidence = 'collected')),
            DROP CONSTRAINT monitor_observations_shape,
            ADD CONSTRAINT monitor_observations_shape CHECK ({shape}),
            DROP CONSTRAINT monitor_observations_collected_shape,
            ADD CONSTRAINT monitor_observations_collected_shape CHECK ({collected_shape})
    """


def upgrade() -> None:
    op.execute(
        _checks(
            PRIOR_KINDS + ", 'entra_audit'",
            PRIOR_COLLECTED + ", 'entra_audit'",
            SHAPE,
            COLLECTED_SHAPE,
        )
    )
    op.execute("""
        ALTER TABLE execbound.monitor_connections
            ADD COLUMN audit_baseline_at timestamptz,
            ADD COLUMN audit_behind_since timestamptz,
            ADD CONSTRAINT monitor_connections_audit_baseline_kind
                CHECK (audit_baseline_at IS NULL OR kind = 'entra_agent_id'),
            ADD CONSTRAINT monitor_connections_audit_behind_kind
                CHECK (audit_behind_since IS NULL OR kind = 'entra_agent_id')
    """)
    op.execute(
        "GRANT UPDATE (audit_baseline_at, audit_behind_since) "
        "ON execbound.monitor_connections TO execbound_app"
    )


def downgrade() -> None:
    op.execute(
        "LOCK TABLE execbound.monitor_observations, execbound.monitor_connections "
        "IN ACCESS EXCLUSIVE MODE"
    )
    # The look sees every tenant: the hosted owner does not bypass row security.
    op.execute("ALTER TABLE execbound.monitor_observations NO FORCE ROW LEVEL SECURITY")
    op.execute("SET LOCAL row_security = off")
    retained = (
        op.get_bind()
        .execute(
            text(
                "SELECT EXISTS (SELECT 1 FROM execbound.monitor_observations "
                "WHERE kind = 'entra_audit')"
            )
        )
        .scalar_one()
    )
    op.execute("SET LOCAL row_security = on")
    op.execute("ALTER TABLE execbound.monitor_observations FORCE ROW LEVEL SECURITY")
    if retained:
        raise RuntimeError(
            "SCOUT_AUDIT_OBSERVATIONS_RETAINED: directory audit-log observations are retained, "
            "and the earlier observation checks cannot hold them"
        )
    op.execute(_checks(PRIOR_KINDS, PRIOR_COLLECTED, PRIOR_SHAPE, PRIOR_COLLECTED_SHAPE))
    op.execute(
        "ALTER TABLE execbound.monitor_connections "
        "DROP CONSTRAINT monitor_connections_audit_behind_kind, "
        "DROP CONSTRAINT monitor_connections_audit_baseline_kind, "
        "DROP COLUMN audit_behind_since, "
        "DROP COLUMN audit_baseline_at"
    )
