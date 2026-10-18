"""Bounded human sessions with retained digests and current credential bindings."""

from alembic import op
from sqlalchemy import text

revision = "0006_human_sessions"
down_revision = "0005_execution_state"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("""
        CREATE TABLE execbound.human_sessions (
            tenant_id uuid NOT NULL,
            session_id uuid NOT NULL,
            principal_id uuid NOT NULL,
            credential_id uuid NOT NULL,
            kind text NOT NULL CHECK (kind IN ('HUMAN_APPROVER', 'ADMIN')),
            credential_expires_at timestamptz NOT NULL,
            token_hash text NOT NULL CHECK (token_hash ~ '^[0-9a-f]{64}$'),
            csrf_hash text NOT NULL CHECK (csrf_hash ~ '^[0-9a-f]{64}$'),
            created_at timestamptz NOT NULL,
            expires_at timestamptz NOT NULL,
            revoked_at timestamptz,
            PRIMARY KEY (tenant_id, session_id),
            FOREIGN KEY (tenant_id, principal_id) REFERENCES execbound.principals,
            FOREIGN KEY (tenant_id, credential_id) REFERENCES execbound.credentials,
            CHECK (expires_at > created_at AND expires_at <= credential_expires_at
                   AND expires_at <= created_at + interval '15 minutes'),
            CHECK (revoked_at IS NULL OR revoked_at >= created_at)
        )
    """)
    op.execute(
        "CREATE INDEX human_sessions_credential "
        "ON execbound.human_sessions (tenant_id, credential_id, expires_at)"
    )
    op.execute(
        "CREATE INDEX human_sessions_principal "
        "ON execbound.human_sessions (tenant_id, principal_id)"
    )
    op.execute("ALTER TABLE execbound.human_sessions ENABLE ROW LEVEL SECURITY")
    op.execute("ALTER TABLE execbound.human_sessions FORCE ROW LEVEL SECURITY")
    op.execute("""
        CREATE POLICY tenant_isolation ON execbound.human_sessions
        USING (tenant_id = nullif(
            (SELECT current_setting('execbound.tenant_id', true)), ''
        )::uuid)
        WITH CHECK (tenant_id = nullif(
            (SELECT current_setting('execbound.tenant_id', true)), ''
        )::uuid)
    """)
    for role in ("PUBLIC", "anon", "authenticated", "service_role", "execbound_app"):
        if (
            role != "PUBLIC"
            and not op.get_bind()
            .execute(text("SELECT 1 FROM pg_roles WHERE rolname = :role"), {"role": role})
            .scalar()
        ):
            continue
        op.execute(f"REVOKE ALL ON execbound.human_sessions FROM {role}")
    op.execute("GRANT SELECT, INSERT ON execbound.human_sessions TO execbound_app")
    op.execute("GRANT UPDATE (revoked_at) ON execbound.human_sessions TO execbound_app")


def downgrade() -> None:
    op.execute("DROP TABLE execbound.human_sessions")
