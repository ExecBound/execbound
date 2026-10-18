"""Stable, tenant-unique human request numbers; no change to execution identity."""

from alembic import op

revision = "0046_request_references"
down_revision = "0045_review_permissions"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("ALTER TABLE execbound.executions ADD COLUMN request_number bigint")
    # The table owner cannot see forced-RLS rows on hosted PostgreSQL. This transaction
    # holds ALTER TABLE's exclusive lock until FORCE is restored and the backfill commits.
    op.execute("ALTER TABLE execbound.executions NO FORCE ROW LEVEL SECURITY")
    op.execute("""
        UPDATE execbound.executions e SET request_number = n.number
        FROM (SELECT tenant_id, execution_id, row_number() OVER (
            PARTITION BY tenant_id ORDER BY created_at, execution_id) AS number
            FROM execbound.executions) n
        WHERE e.tenant_id=n.tenant_id AND e.execution_id=n.execution_id
    """)
    op.execute("ALTER TABLE execbound.executions FORCE ROW LEVEL SECURITY")
    op.execute("ALTER TABLE execbound.executions ALTER COLUMN request_number SET NOT NULL")
    op.execute(
        "ALTER TABLE execbound.executions ADD CONSTRAINT execution_request_positive "
        "CHECK (request_number > 0)"
    )
    op.execute(
        "CREATE UNIQUE INDEX execution_request_number "
        "ON execbound.executions (tenant_id, request_number)"
    )
    op.execute(
        "CREATE INDEX execution_external_case ON execbound.executions "
        "(tenant_id, (frozen->'request'->'external_case'->>'source'), "
        "(frozen->'request'->'external_case'->>'case_id'))"
    )


def downgrade() -> None:
    op.execute("DROP INDEX execbound.execution_external_case")
    op.execute("ALTER TABLE execbound.executions DROP COLUMN request_number")
