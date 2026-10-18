# SPDX-License-Identifier: AGPL-3.0-only
"""Approval notifications gain a kind, one message of each kind per approval and destination.

Until now a destination received exactly one message per approval, the `approval.pending`
announcement. Approval delivery (#678) adds two opt-in follow-ups:
`approval.closed`, which tells a destination how an approval it was told of ended, and
`approval.reminder`, which a later change sends once before an approval lapses. Each is a row
of this same outbox, so the queueing, leasing, retry and visibility rules stay one.

- `kind` names the message, defaulting to `approval.pending`, so every existing row reads as
  what it always was and keeps its `notification_id`.
- `outcome` and `closed_at` are a close-out's fixed report, set when it is queued, so a retry
  says the same thing and a later change of the approval's state changes nothing. The
  `approval_notifications_closed_fields` check holds them to close-outs only.
- The unique key widens from (tenant, approval, destination) to the same plus `kind`
  (`approval_notifications_one_per_kind`): at most one message of each kind per approval and
  destination is a schema fact, so at most one reminder and one close-out.
- Three partial indexes serve the drain's close-out scan
  (`approval_notifications_followup`), its reminder scan (`approvals_pending_expiry`) and the
  workspace settings' seven-day delivery read (`approval_notifications_pending_created`).

Forced row-level security and the `tenant_isolation` policy cover the new columns unchanged.
The runtime's table-level `INSERT` covers them, and its `UPDATE` stays the seven delivery
columns 0015 granted, so the runtime can never rewrite a row's kind, outcome or time; nothing
is granted here, and `check_runtime` refuses any later grant of those columns.

The downgrade refuses while any reminder or close-out is retained, because delivery history
explains what an approver was told; otherwise it restores 0015's key and drops the rest.
"""

from alembic import op
from sqlalchemy import text

revision = "0080_notification_kinds"
down_revision = "0079_key_last_used"
branch_labels = None
depends_on = None

OLD_KEY = "approval_notifications_tenant_id_approval_id_destination_id_key"


def upgrade() -> None:
    op.execute("""
        ALTER TABLE execbound.approval_notifications
            ADD COLUMN kind text NOT NULL DEFAULT 'approval.pending'
                CHECK (kind IN ('approval.pending', 'approval.reminder', 'approval.closed')),
            ADD COLUMN outcome text
                CHECK (outcome IN ('APPROVED', 'REFUSED', 'LAPSED', 'WITHDRAWN')),
            ADD COLUMN closed_at timestamptz,
            ADD CONSTRAINT approval_notifications_closed_fields CHECK (
                ((kind = 'approval.closed') = (outcome IS NOT NULL))
                AND ((outcome IS NULL) = (closed_at IS NULL))
            )
    """)
    op.execute(f"ALTER TABLE execbound.approval_notifications DROP CONSTRAINT {OLD_KEY}")
    op.execute("""
        ALTER TABLE execbound.approval_notifications
            ADD CONSTRAINT approval_notifications_one_per_kind
            UNIQUE (tenant_id, approval_id, destination_id, kind)
    """)
    op.execute("""
        CREATE INDEX approval_notifications_followup ON execbound.approval_notifications
            (tenant_id, delivered_at)
            WHERE state = 'DELIVERED' AND kind <> 'approval.closed'
    """)
    op.execute("""
        CREATE INDEX approvals_pending_expiry ON execbound.approvals (tenant_id, expires_at)
            WHERE state = 'PENDING'
    """)
    op.execute("""
        CREATE INDEX approval_notifications_pending_created ON execbound.approval_notifications
            (tenant_id, created_at)
            WHERE kind = 'approval.pending'
    """)


def downgrade() -> None:
    # Delivery history explains what an approver was told: a reminder or a close-out is never
    # dropped to make a downgrade possible.
    op.execute("ALTER TABLE execbound.approval_notifications NO FORCE ROW LEVEL SECURITY")
    op.execute("SET LOCAL row_security = off")
    retained = (
        op.get_bind()
        .execute(
            text(
                "SELECT EXISTS (SELECT 1 FROM execbound.approval_notifications "
                "WHERE kind <> 'approval.pending')"
            )
        )
        .scalar_one()
    )
    op.execute("ALTER TABLE execbound.approval_notifications FORCE ROW LEVEL SECURITY")
    if retained:
        raise RuntimeError("Cannot downgrade while approval reminders or close-outs are retained")
    op.execute("DROP INDEX execbound.approval_notifications_pending_created")
    op.execute("DROP INDEX execbound.approvals_pending_expiry")
    op.execute("DROP INDEX execbound.approval_notifications_followup")
    op.execute(
        "ALTER TABLE execbound.approval_notifications "
        "DROP CONSTRAINT approval_notifications_one_per_kind"
    )
    op.execute(
        f"ALTER TABLE execbound.approval_notifications "
        f"ADD CONSTRAINT {OLD_KEY} UNIQUE (tenant_id, approval_id, destination_id)"
    )
    op.execute(
        "ALTER TABLE execbound.approval_notifications "
        "DROP CONSTRAINT approval_notifications_closed_fields, "
        "DROP COLUMN closed_at, DROP COLUMN outcome, DROP COLUMN kind"
    )
