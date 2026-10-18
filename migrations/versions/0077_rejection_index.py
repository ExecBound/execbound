# SPDX-License-Identifier: AGPL-3.0-only
"""A partial index for counting the requests refused before a decision (#678).

The value report counts admission's `execution.rejected` events over up to 31 days, on every
Home load and window focus. `audit_events` is indexed by its key, `(tenant_id, sequence)`,
by actor and by space, so that count would read a tenant's whole chain. This index holds only
the rejections, by tenant and time, and is what the count reads.

It changes no table, column, grant or policy; nothing in `check_runtime`'s catalog moves but
`SCHEMA_REVISION`. The downgrade drops it.
"""

from alembic import op

revision = "0077_rejection_index"
down_revision = "0076_policy_activation_index"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute(
        "CREATE INDEX audit_events_rejected ON execbound.audit_events (tenant_id, occurred_at) "
        "WHERE kind = 'execution.rejected'"
    )


def downgrade() -> None:
    op.execute("DROP INDEX execbound.audit_events_rejected")
