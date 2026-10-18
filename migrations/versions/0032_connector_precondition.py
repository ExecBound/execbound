"""What each dispatch's precondition was worth, and the window the connector measured."""

from alembic import op
from sqlalchemy import text

revision = "0032_connector_precondition"
down_revision = "0031_scout_rules"
branch_labels = None
depends_on = None

# The downgrade guard reads every tenant's executions, so RLS is lifted on the one table it
# reads for the transaction and restored before it ends, exactly as 0025 does.
INSPECTED = ("executions",)

# The four classes `execution.models.PreconditionClass` allows. NULL is a row written before
# this column existed: the only providers then were mocks that enforce the frozen version
# atomically, so a reader renders NULL as ENFORCED_BY_PROVIDER rather than as unknown. It is
# deliberately not defaulted to that string, because a default would make a row that was
# never declared indistinguishable from one that was.
CLASSES = (
    "precondition_class IS NULL OR precondition_class IN "
    "('ENFORCED_BY_PROVIDER', 'ASSERTED_BY_EXECUTOR', 'CHECKED_BY_CONNECTOR', 'UNAVAILABLE')"
)

# Only CHECKED_BY_CONNECTOR measures a window: it is the one class where ExecBound itself
# reads, compares and then writes, so it is the one class with a time-of-check-to-time-of-use
# gap it owns. A window recorded under any other class would be describing something nobody
# measured, and the schema refuses it rather than leaving a reader to wonder. The hour is a
# sanity bound, not a policy: a longer gap is a bug in the connector, not a slow vendor, and
# the connector never refuses on elapsed time.
# IS NOT DISTINCT FROM, not `=`: a CHECK constraint rejects only an explicit FALSE, and
# `NULL = 'CHECKED_BY_CONNECTOR'` is NULL, so `=` would let a window through on a row whose
# class was never declared. The first spelling of this constraint did exactly that, and the
# undeclared-with-a-window case is the regression that caught it.
WINDOW = (
    "precondition_window_ms IS NULL "
    "OR (precondition_class IS NOT DISTINCT FROM 'CHECKED_BY_CONNECTOR' "
    "AND precondition_window_ms BETWEEN 0 AND 3600000)"
)


def _lift_rls(tables: tuple[str, ...]) -> None:
    op.execute(
        "LOCK TABLE " + ", ".join(f"execbound.{t}" for t in tables) + " IN ACCESS EXCLUSIVE MODE"
    )
    for table in tables:
        op.execute(f"ALTER TABLE execbound.{table} NO FORCE ROW LEVEL SECURITY")
    op.execute("SET LOCAL row_security = off")


def _restore_rls(tables: tuple[str, ...]) -> None:
    for table in tables:
        op.execute(f"ALTER TABLE execbound.{table} FORCE ROW LEVEL SECURITY")
    op.execute("SET LOCAL row_security = on")


def upgrade() -> None:
    op.execute(
        "ALTER TABLE execbound.executions "
        "ADD COLUMN precondition_class text, "
        "ADD COLUMN precondition_window_ms integer, "
        f"ADD CONSTRAINT executions_precondition_class_check CHECK ({CLASSES}), "
        f"ADD CONSTRAINT executions_precondition_window_check CHECK ({WINDOW})"
    )
    # The dispatch path writes both, in the same statement that records the attempt. No
    # other role gains anything: the runtime already holds UPDATE on this table's named
    # columns and this adds exactly two more.
    op.execute(
        "GRANT UPDATE (precondition_class, precondition_window_ms) "
        "ON execbound.executions TO execbound_app"
    )


def downgrade() -> None:
    # What a downgrade must not silently discard is a dispatch whose precondition was
    # weaker than the atomic one every provider offered before this column existed. Dropping
    # CHECKED_BY_CONNECTOR, or the window measured under it, would leave a non-atomic
    # dispatch indistinguishable from the historical default a reader assumes for a NULL.
    #
    # The other three classes are not blocked, and the distinction matters: once dispatch
    # records a class on every attempt, a guard on "any class at all" fires in every
    # database where anything has ever been dispatched, which is a wall rather than a guard.
    # 0025 keys its guard on the exceptional row — a settled tier or an open report window —
    # for the same reason. ENFORCED_BY_PROVIDER, ASSERTED_BY_EXECUTOR and UNAVAILABLE carry
    # no more than the deployment's own declaration, which the configuration still holds and
    # which 0031 simply does not record.
    _lift_rls(INSPECTED)
    retained = op.get_bind().execute(
        text(
            "SELECT EXISTS (SELECT 1 FROM execbound.executions "
            "WHERE precondition_class = 'CHECKED_BY_CONNECTOR' "
            "OR precondition_window_ms IS NOT NULL)"
        )
    )
    if retained.scalar_one():
        raise RuntimeError("Cannot downgrade while a dispatch records a connector-side check")
    _restore_rls(INSPECTED)
    op.execute(
        "ALTER TABLE execbound.executions "
        "DROP CONSTRAINT executions_precondition_window_check, "
        "DROP CONSTRAINT executions_precondition_class_check, "
        "DROP COLUMN precondition_window_ms, "
        "DROP COLUMN precondition_class"
    )
