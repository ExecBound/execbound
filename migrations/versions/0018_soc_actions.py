"""Widen the action check constraints for the SOC action catalog."""

from alembic import op
from sqlalchemy import text

revision = "0018_soc_actions"
down_revision = "0017_approval_quorum"
branch_labels = None
depends_on = None

# Applied history is independent of the current application's action catalog.
ORIGINAL = "'endpoint.isolate', 'identity.disable', 'identity.enable', 'identity.revoke_sessions'"
ADDED_NAMES = ("endpoint.lift_isolation", "identity.reset_password")
ACTION_TABLES = ("approval_scopes", "execution_impact")
HISTORY_TABLES = (
    "operation_mappings",
    "approval_scopes",
    "execution_impact",
    "executions",
    "execution_events",
    "policy_bundle_contents",
    "audit_events",
)
# The stored action list and the retained-evidence regex are derived from one tuple so a
# later name cannot be added to the check constraints without widening the guard as well.
ADDED = ", ".join(f"'{name}'" for name in ADDED_NAMES)
EVIDENCE_PATTERN = "|".join(name.replace(".", "[.]") for name in ADDED_NAMES)
# Retained JSON evidence can outlive an action column, so these tables are inspected with
# the regex rather than an exact name; the rest compare their stored action directly.
PATTERN_TABLES = ("executions", "execution_events", "policy_bundle_contents", "audit_events")


def _constrain(actions: str) -> None:
    for table in ACTION_TABLES:
        op.execute(f"ALTER TABLE execbound.{table} DROP CONSTRAINT {table}_action_check")
        op.execute(
            f"ALTER TABLE execbound.{table} ADD CONSTRAINT {table}_action_check "
            f"CHECK (action IN ({actions}))"
        )


def upgrade() -> None:
    _constrain(f"{ORIGINAL}, {ADDED}")


def downgrade() -> None:
    # Follow 0007 and 0009: lock, inspect every tenant without RLS filtering, refuse when
    # any row names an action revision 0013 cannot store, then restore the four-name checks.
    op.execute(
        "LOCK TABLE "
        + ", ".join(f"execbound.{table}" for table in HISTORY_TABLES)
        + " IN ACCESS EXCLUSIVE MODE"
    )
    for table in HISTORY_TABLES:
        op.execute(f"ALTER TABLE execbound.{table} NO FORCE ROW LEVEL SECURITY")
    op.execute("SET LOCAL row_security = off")
    predicates = {
        "operation_mappings": f"action IN ({ADDED})",
        "approval_scopes": f"action IN ({ADDED})",
        "execution_impact": f"action IN ({ADDED})",
        "executions": (
            f"(frozen -> 'intent' ->> 'action') IN ({ADDED}) "
            "OR frozen::text ~ :pattern OR result::text ~ :pattern"
        ),
        "execution_events": "payload::text ~ :pattern",
        "policy_bundle_contents": "content::text ~ :pattern",
        "audit_events": "payload::text ~ :pattern",
    }
    for table, predicate in predicates.items():
        params = {"pattern": EVIDENCE_PATTERN} if table in PATTERN_TABLES else {}
        retained = op.get_bind().execute(
            text(f"SELECT EXISTS (SELECT 1 FROM execbound.{table} WHERE {predicate})"), params
        )
        if retained.scalar_one():
            raise RuntimeError("Cannot downgrade while SOC action data or history is retained")
    for table in HISTORY_TABLES:
        op.execute(f"ALTER TABLE execbound.{table} FORCE ROW LEVEL SECURITY")
    _constrain(ORIGINAL)
