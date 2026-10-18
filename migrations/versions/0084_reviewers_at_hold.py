# SPDX-License-Identifier: AGPL-3.0-only
"""How many people could decide a held request when it was held (#678).

`approvals.reviewers_at_hold` is written once, by admission, in the same statement that inserts
the `PENDING` approval: the number of distinct people `store.scope_check` would let decide it at
that instant, for its Space, canonical target and action. It is a presentation hint for the
console, which tells a workspace administrator when a held request had fewer people who could
decide it than it needs. No decision, resume, consume, journal, export or replay reads it, and
`approval_binding` names its own keys, so the frozen approval binding does not change. The
runtime's table-level `INSERT` covers the column; its `UPDATE` grant on `approvals` is
column-level and does not, so `check_runtime` keeps refusing a database that lets the runtime
rewrite the count. Rows held before this revision keep `NULL`, which the console reads as "not
recorded".

`executions_created` indexes executions by tenant and creation time, so the coverage read's
30-day window is an index range rather than a scan of a tenant's whole history.
"""

from alembic import op

revision = "0084_reviewers_at_hold"
down_revision = "0083_invitation_reviewer_group"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute(
        "ALTER TABLE execbound.approvals ADD COLUMN reviewers_at_hold integer "
        "CONSTRAINT approvals_reviewers_at_hold_count "
        "CHECK (reviewers_at_hold IS NULL OR reviewers_at_hold >= 0)"
    )
    op.execute("CREATE INDEX executions_created ON execbound.executions (tenant_id, created_at)")


def downgrade() -> None:
    # Dropping the count loses no authority and no retained uncertainty: it is a hint written
    # beside the approval, never evidence, and nothing that decides or replays reads it.
    op.execute("DROP INDEX execbound.executions_created")
    op.execute("ALTER TABLE execbound.approvals DROP COLUMN reviewers_at_hold")
