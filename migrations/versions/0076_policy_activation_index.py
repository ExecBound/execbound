# SPDX-License-Identifier: AGPL-3.0-only
"""A partial index for reading a policy's activation notes back.

The console shows, beside each policy version, the reason its latest activation recorded
(the `reason` key of `policy.bundle_activated`, #678). That read in
`surfaces/console_api/policy.py` (`_activation_notes`) picks, per listed bundle, the latest
activation event in a Space the reader can see. No index covered the event's `kind` or its
payload's `bundle_id`: `audit_events` has its primary key `(tenant_id, sequence)`, the unique
`(tenant_id, event_id)` and `audit_events_space (tenant_id, space_id)`, so without this index
the read walks every event of the tenant on each list and detail load.

The index is partial on the one kind the read asks for, so it holds activations only, and is
ordered so each listed bundle is one short index range read newest first. It changes no grant,
no row-level security policy and no `check_runtime` catalog entry: an index carries none of
them, and the runtime role already reads `audit_events` under the tenant fence. It is a plain
`CREATE INDEX` inside the migration's transaction.
"""

from alembic import op

revision = "0076_policy_activation_index"
down_revision = "0075_workspace_requests_admin"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute(
        "CREATE INDEX audit_events_policy_activation ON execbound.audit_events "
        "(tenant_id, (payload ->> 'bundle_id'), sequence DESC) "
        "WHERE kind = 'policy.bundle_activated'"
    )


def downgrade() -> None:
    op.execute("DROP INDEX execbound.audit_events_policy_activation")
