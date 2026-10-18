"""Approval quorum: a frozen requirement per approval and one decision row per approver."""

from alembic import op
from sqlalchemy import text

revision = "0017_approval_quorum"
down_revision = "0016_export_cursors"
branch_labels = None
depends_on = None

TENANT = "nullif((SELECT current_setting('execbound.tenant_id', true)), '')::uuid"


def upgrade() -> None:
    op.execute("""
        ALTER TABLE execbound.approvals
            ADD COLUMN required_approvers integer NOT NULL DEFAULT 1
                CHECK (required_approvers BETWEEN 1 AND 5)
    """)
    op.execute("""
        CREATE TABLE execbound.approval_decisions (
            tenant_id uuid NOT NULL,
            approval_id uuid NOT NULL,
            principal_id uuid NOT NULL,
            credential_id uuid NOT NULL,
            decision text NOT NULL CHECK (decision IN ('APPROVE', 'DENY')),
            decided_at timestamptz NOT NULL,
            PRIMARY KEY (tenant_id, approval_id, principal_id),
            FOREIGN KEY (tenant_id, approval_id) REFERENCES execbound.approvals,
            FOREIGN KEY (tenant_id, principal_id) REFERENCES execbound.principals,
            FOREIGN KEY (tenant_id, credential_id) REFERENCES execbound.credentials
        )
    """)
    op.execute(
        "CREATE INDEX approval_decisions_principal "
        "ON execbound.approval_decisions (tenant_id, principal_id)"
    )
    op.execute(
        "CREATE INDEX approval_decisions_credential "
        "ON execbound.approval_decisions (tenant_id, credential_id)"
    )
    op.execute("ALTER TABLE execbound.approval_decisions ENABLE ROW LEVEL SECURITY")
    op.execute("ALTER TABLE execbound.approval_decisions FORCE ROW LEVEL SECURITY")
    op.execute(f"""
        CREATE POLICY tenant_isolation ON execbound.approval_decisions
        USING (tenant_id = {TENANT}) WITH CHECK (tenant_id = {TENANT})
    """)
    for role in ("PUBLIC", "anon", "authenticated", "service_role", "execbound_app"):
        if (
            role != "PUBLIC"
            and not op.get_bind()
            .execute(text("SELECT 1 FROM pg_roles WHERE rolname = :role"), {"role": role})
            .scalar()
        ):
            continue
        op.execute(f"REVOKE ALL ON execbound.approval_decisions FROM {role}")
    # Decisions are immutable evidence: the runtime inserts and never updates or deletes.
    op.execute("GRANT SELECT, INSERT ON execbound.approval_decisions TO execbound_app")


def downgrade() -> None:
    op.execute("ALTER TABLE execbound.approval_decisions NO FORCE ROW LEVEL SECURITY")
    op.execute("SET LOCAL row_security = off")
    retained = op.get_bind().execute(
        text("SELECT EXISTS (SELECT 1 FROM execbound.approval_decisions)")
    )
    if retained.scalar_one():
        raise RuntimeError("Cannot downgrade while approval decisions are retained")
    op.execute("DROP TABLE execbound.approval_decisions")
    op.execute("ALTER TABLE execbound.approvals DROP COLUMN required_approvers")
