# SPDX-License-Identifier: AGPL-3.0-only
"""Who minted a reporting source.

`monitor_sources.created_by` names the administrator who created a source, the way
`rotated_by` and `revoked_by` (0012) name who rotated and revoked it, now that an administrator
can mint one from the console as well as from the command line (#678). It is null on every
source created before this revision, because nothing recorded who made those. A source's
lifecycle stays on its own row and off the execution audit chain, as it always has.

The runtime inserts it with the row, through its existing table-level `INSERT`, and cannot
change it afterwards: it is not among the columns the runtime may update. The foreign key holds
it to a principal of the source's own tenant.

The downgrade drops the column and keeps every source; the schema below this revision has no
place to say who minted one.
"""

from alembic import op

revision = "0090_monitor_source_creator"
down_revision = "0089_assurance_carry"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("""
        ALTER TABLE execbound.monitor_sources
            ADD COLUMN created_by uuid,
            ADD CONSTRAINT monitor_sources_created_by_fkey
                FOREIGN KEY (tenant_id, created_by) REFERENCES execbound.principals
    """)
    op.execute(
        "CREATE INDEX monitor_sources_created_by "
        "ON execbound.monitor_sources (tenant_id, created_by)"
    )


def downgrade() -> None:
    op.execute("DROP INDEX execbound.monitor_sources_created_by")
    op.execute("""
        ALTER TABLE execbound.monitor_sources
            DROP CONSTRAINT monitor_sources_created_by_fkey,
            DROP COLUMN created_by
    """)
