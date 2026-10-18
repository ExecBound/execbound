"""Observe-only mode: a per-tenant enforcement mode and the terminal OBSERVED execution state."""

from alembic import op
from sqlalchemy import text

revision = "0019_observe_mode"
down_revision = "0018_soc_actions"
branch_labels = None
depends_on = None

ENFORCED_STATES = (
    "'ATTEMPTED', 'DENIED', 'PENDING_APPROVAL', 'RESERVED', 'DISPATCH_COMMITTED', "
    "'EXECUTED', 'FAILED_NOT_EXECUTED', 'INDETERMINATE', 'STALE_AUTHORIZATION'"
)
IMPACT_STATES = "'UNRESOLVED', 'CONFIRMED', 'NONEXECUTION'"
RLS_TABLES = ("tenant_policy_control", "executions", "execution_impact")


def _state_checks(execution_states: str, impact_states: str) -> None:
    for table, column in (
        ("executions", "state"),
        ("execution_events", "from_state"),
        ("execution_events", "to_state"),
    ):
        op.execute(
            f"ALTER TABLE execbound.{table} DROP CONSTRAINT {table}_{column}_check, "
            f"ADD CONSTRAINT {table}_{column}_check CHECK ({column} IN ({execution_states}))"
        )
    op.execute(
        "ALTER TABLE execbound.execution_impact DROP CONSTRAINT execution_impact_state_check, "
        f"ADD CONSTRAINT execution_impact_state_check CHECK (state IN ({impact_states}))"
    )


def upgrade() -> None:
    op.execute("""
        ALTER TABLE execbound.tenant_policy_control
            ADD COLUMN enforcement_mode text NOT NULL DEFAULT 'ENFORCE'
                CHECK (enforcement_mode IN ('ENFORCE', 'OBSERVE'))
    """)
    _state_checks(ENFORCED_STATES + ", 'OBSERVED'", IMPACT_STATES + ", 'OBSERVED'")
    # The mode is written only by the fence-taking mode change function.
    op.execute(
        "GRANT UPDATE (enforcement_mode) ON execbound.tenant_policy_control TO execbound_app"
    )


def downgrade() -> None:
    # Dropping the mode would silently enforce an observing tenant, and dropping the
    # state would orphan recorded observations: refuse instead.
    for table in RLS_TABLES:
        op.execute(f"ALTER TABLE execbound.{table} NO FORCE ROW LEVEL SECURITY")
    op.execute("SET LOCAL row_security = off")
    bind = op.get_bind()
    observing = bind.execute(
        text(
            "SELECT EXISTS (SELECT 1 FROM execbound.tenant_policy_control "
            "WHERE enforcement_mode <> 'ENFORCE')"
        )
    ).scalar_one()
    observed = bind.execute(
        text(
            "SELECT EXISTS (SELECT 1 FROM execbound.executions WHERE state = 'OBSERVED') "
            "OR EXISTS (SELECT 1 FROM execbound.execution_impact WHERE state = 'OBSERVED')"
        )
    ).scalar_one()
    if observing or observed:
        raise RuntimeError("Cannot downgrade while a tenant observes or observed rows remain")
    _state_checks(ENFORCED_STATES, IMPACT_STATES)
    op.execute("ALTER TABLE execbound.tenant_policy_control DROP COLUMN enforcement_mode")
    for table in RLS_TABLES:
        op.execute(f"ALTER TABLE execbound.{table} FORCE ROW LEVEL SECURITY")
