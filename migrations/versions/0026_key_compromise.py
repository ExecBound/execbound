"""Why an executor key was revoked: an ordinary retirement, or a compromise that cuts it off."""

from alembic import op
from sqlalchemy import text

revision = "0026_key_compromise"
down_revision = "0025_checkpoint"
branch_labels = None
depends_on = None

# The backfill and the downgrade guard read every tenant's keys, so row-level security is
# lifted on that one table around each of them and restored before the transaction ends,
# following 0025. The constraint the backfill prepares for is added after the restore and
# needs no lift: ALTER TABLE ... ADD CONSTRAINT validates every existing row whatever the
# session's row-level security says, which is why a row the backfill could not see would
# have made it fail rather than pass.
INSPECTED = ("executor_keys",)
# A retirement is backward-permissive: a proof for a grant issued while the key was
# current still verifies, which is what makes an ordinary rotation safe. A compromise is
# retroactive: the verifier refuses the key whatever the grant instant. The column is the
# only place that distinction is recorded, so it is NOT NULL exactly when the key is
# revoked and nothing can retire a key without saying which kind of revocation it was.
RETIRED, COMPROMISED = "RETIRED", "COMPROMISED"
REVOCATION_REASON = (
    "(revoked_at IS NULL) = (revocation_reason IS NULL) AND "
    f"(revocation_reason IS NULL OR revocation_reason IN ('{RETIRED}', '{COMPROMISED}'))"
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
    op.execute("ALTER TABLE execbound.executor_keys ADD COLUMN revocation_reason text")
    # Every revocation that exists was an ordinary one: nothing could have recorded a
    # compromise before this column did. A tenant predicate that hid one of those rows
    # would leave it with no reason and the constraint below would then refuse to add, so
    # the backfill reads the whole table rather than whatever the session's tenant is.
    _lift_rls(INSPECTED)
    op.execute(
        f"UPDATE execbound.executor_keys SET revocation_reason = '{RETIRED}' "
        "WHERE revoked_at IS NOT NULL"
    )
    _restore_rls(INSPECTED)
    op.execute(
        "ALTER TABLE execbound.executor_keys "
        f"ADD CONSTRAINT executor_keys_revocation_reason CHECK ({REVOCATION_REASON})"
    )
    # The runtime's grant on this table is SELECT and nothing else, which already covers
    # every column of it, so the new column needs no grant and leaves none to revoke.


def downgrade() -> None:
    # A key cut off as compromised has no representation in 0025, where every revocation is
    # backward-permissive: dropping the column would silently hand that key back its
    # authority over every grant issued while it was current, which is the whole of what
    # this revision exists to refuse. A retirement downgrades losslessly, because 0025
    # reads a revoked key exactly as this revision reads a retired one.
    _lift_rls(INSPECTED)
    retained = op.get_bind().execute(
        text(
            "SELECT EXISTS (SELECT 1 FROM execbound.executor_keys "
            f"WHERE revocation_reason = '{COMPROMISED}')"
        )
    )
    if retained.scalar_one():
        raise RuntimeError("Cannot downgrade while a compromised executor key exists")
    _restore_rls(INSPECTED)
    # The CHECK constraint names this column, so dropping the column drops it too.
    op.execute("ALTER TABLE execbound.executor_keys DROP COLUMN revocation_reason")
