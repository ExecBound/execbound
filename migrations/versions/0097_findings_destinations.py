# SPDX-License-Identifier: AGPL-3.0-only
"""Findings delivery: a destination for each monitoring delivery (#31).

Until now a finding had one `monitor_deliveries` row, the intent its store writes in the same
transaction as the finding, and only the loopback test receiver drained it. Findings delivery
routes each intent, at drain time, to every configured destination that asks for findings, as
one row per finding and destination:

- `destination_id` names a delivery's destination; the intent has none. It is set only on
  insert: the runtime's table-level `INSERT` covers it, and its `UPDATE` stays the seven
  delivery columns 0008 granted, so the runtime can never rewrite a delivery's destination. It
  carries `approval_notifications`'s identifier check.
- `ROUTED` is an intent's state once the router has written its deliveries, or found none to
  write; `monitor_deliveries_routed_intent` holds it to rows with no destination. A delivery
  keeps the four states every row always had. No check keeps `IN_FLIGHT` or `DELIVERED` off an
  intent, because the loopback worker before this one left intents in both.
- `UNIQUE (tenant_id, finding_id)` becomes two partial unique indexes: one intent per finding
  (`monitor_deliveries_one_intent`) and one delivery per finding and destination
  (`monitor_deliveries_one_per_destination`), so a router that runs twice, or two at once,
  writes nothing more. The old key was also the foreign key's index to the finding, which
  neither partial index can be, so `monitor_deliveries_finding` takes that over.

Every intent already written keeps its row, its id and its state. Forced row-level security and
the `tenant_isolation` policy cover the new column unchanged, nothing is granted, and
`check_runtime` refuses any later `UPDATE` grant of `destination_id`.

The downgrade refuses `FINDINGS_DELIVERIES_RETAINED` while any delivery or routed intent is
retained, because delivery history says what a destination was sent, looking with row security
off for the look alone because an owner that does not bypass it would otherwise see nothing. It
otherwise restores 0008's key and state check and drops the column.
"""

from alembic import op
from sqlalchemy import text

revision = "0097_findings_destinations"
down_revision = "0096_approval_email"
branch_labels = None
depends_on = None

OLD_KEY = "monitor_deliveries_tenant_id_finding_id_key"
STATES = "'PENDING', 'IN_FLIGHT', 'DELIVERED', 'FAILED'"


def upgrade() -> None:
    op.execute(
        f"""
        ALTER TABLE execbound.monitor_deliveries
            ADD COLUMN destination_id text
                CONSTRAINT monitor_deliveries_destination_id_check
                CHECK (destination_id ~ '^[A-Za-z0-9_.-]{{1,64}}$'),
            DROP CONSTRAINT {OLD_KEY},
            DROP CONSTRAINT monitor_deliveries_state_check,
            ADD CONSTRAINT monitor_deliveries_state_check CHECK (state IN ({STATES}, 'ROUTED')),
            ADD CONSTRAINT monitor_deliveries_routed_intent
                CHECK (state <> 'ROUTED' OR destination_id IS NULL)
        """
    )
    op.execute(
        "CREATE UNIQUE INDEX monitor_deliveries_one_intent ON execbound.monitor_deliveries "
        "(tenant_id, finding_id) WHERE destination_id IS NULL"
    )
    op.execute(
        "CREATE UNIQUE INDEX monitor_deliveries_one_per_destination "
        "ON execbound.monitor_deliveries (tenant_id, finding_id, destination_id) "
        "WHERE destination_id IS NOT NULL"
    )
    # Every foreign key has a covering index of its own; the partial ones above cover only the
    # intents or only the deliveries.
    op.execute(
        "CREATE INDEX monitor_deliveries_finding ON execbound.monitor_deliveries "
        "(tenant_id, finding_id)"
    )


def downgrade() -> None:
    op.execute("LOCK TABLE execbound.monitor_deliveries IN ACCESS EXCLUSIVE MODE")
    # The look sees every tenant: the hosted owner does not bypass row security.
    op.execute("ALTER TABLE execbound.monitor_deliveries NO FORCE ROW LEVEL SECURITY")
    op.execute("SET LOCAL row_security = off")
    retained = (
        op.get_bind()
        .execute(
            text(
                "SELECT EXISTS (SELECT 1 FROM execbound.monitor_deliveries "
                "WHERE destination_id IS NOT NULL OR state = 'ROUTED')"
            )
        )
        .scalar_one()
    )
    op.execute("SET LOCAL row_security = on")
    op.execute("ALTER TABLE execbound.monitor_deliveries FORCE ROW LEVEL SECURITY")
    if retained:
        raise RuntimeError(
            "FINDINGS_DELIVERIES_RETAINED: finding deliveries or routed intents are retained, "
            "and the earlier table cannot hold them"
        )
    op.execute("DROP INDEX execbound.monitor_deliveries_finding")
    op.execute("DROP INDEX execbound.monitor_deliveries_one_per_destination")
    op.execute("DROP INDEX execbound.monitor_deliveries_one_intent")
    op.execute(
        f"""
        ALTER TABLE execbound.monitor_deliveries
            DROP CONSTRAINT monitor_deliveries_routed_intent,
            DROP CONSTRAINT monitor_deliveries_state_check,
            ADD CONSTRAINT monitor_deliveries_state_check CHECK (state IN ({STATES})),
            DROP COLUMN destination_id,
            ADD CONSTRAINT {OLD_KEY} UNIQUE (tenant_id, finding_id)
        """
    )
