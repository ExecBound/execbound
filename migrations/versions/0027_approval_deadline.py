"""Per-tenant approval deadline, and console session renewal through a definer function."""

from alembic import op
from sqlalchemy import text

revision = "0027_approval_deadline"
down_revision = "0026_key_compromise"
branch_labels = None
depends_on = None

# 120 is the deadline every tenant had before this column existed, so every existing and
# every new control row starts there. NULL is "off": the approval then expires with the
# frozen plan's own validity and nothing else. Only the fence-taking setting function
# writes the column, so a NULL is always a recorded decision, never an unset default.
DEADLINE = "approval_deadline_seconds IS NULL OR approval_deadline_seconds BETWEEN 120 AND 3600"

# The runtime role still cannot write a session's expiry: a reviewer who keeps reading is
# kept signed in by this function alone, which extends only a live, unrevoked session whose
# token the caller holds, never past the credential's expiry or the absolute cap the caller
# names, and only forwards. A session that cannot be extended answers NULL.
RENEW = """
CREATE FUNCTION execbound.renew_human_session(
    p_session uuid, p_token_hash text, p_now timestamptz, p_lifetime interval,
    p_absolute interval)
RETURNS timestamptz
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    v_tenant uuid := nullif(current_setting('execbound.tenant_id', true), '')::uuid;
    v_expires timestamptz;
BEGIN
    IF v_tenant IS NULL OR p_session IS NULL OR p_token_hash IS NULL OR p_now IS NULL
       OR p_lifetime IS NULL OR p_absolute IS NULL
       OR p_lifetime <= interval '0' OR p_absolute <= interval '0' THEN
        RAISE EXCEPTION 'INVALID_RENEWAL';
    END IF;
    UPDATE execbound.human_sessions s
       SET expires_at = LEAST(p_now + p_lifetime, s.created_at + p_absolute,
                              s.credential_expires_at)
     WHERE s.tenant_id = v_tenant AND s.session_id = p_session
       AND s.token_hash = p_token_hash AND s.revoked_at IS NULL
       AND s.created_at <= p_now AND p_now < s.expires_at
       AND LEAST(p_now + p_lifetime, s.created_at + p_absolute, s.credential_expires_at)
           > s.expires_at
    RETURNING s.expires_at INTO v_expires;
    RETURN v_expires;
END $$
"""
RENEW_SIGNATURE = "renew_human_session(uuid, text, timestamptz, interval, interval)"

# The table itself bounds a session's life. The idle lifetime stays fifteen minutes in the
# application; the schema's ceiling becomes the absolute cap a renewed session may reach.
IDLE_BOUND = (
    "expires_at > created_at AND expires_at <= credential_expires_at "
    "AND expires_at <= created_at + interval '15 minutes'"
)
ABSOLUTE_BOUND = (
    "expires_at > created_at AND expires_at <= credential_expires_at "
    "AND expires_at <= created_at + interval '8 hours'"
)


def upgrade() -> None:
    op.execute(
        "ALTER TABLE execbound.tenant_policy_control "
        "ADD COLUMN approval_deadline_seconds integer DEFAULT 120 "
        f"CHECK ({DEADLINE})"
    )
    op.execute(
        "GRANT UPDATE (approval_deadline_seconds) ON execbound.tenant_policy_control "
        "TO execbound_app"
    )
    op.execute(
        "ALTER TABLE execbound.human_sessions DROP CONSTRAINT human_sessions_check, "
        f"ADD CONSTRAINT human_sessions_check CHECK ({ABSOLUTE_BOUND})"
    )
    op.execute(RENEW)
    op.execute(f"REVOKE ALL ON FUNCTION execbound.{RENEW_SIGNATURE} FROM PUBLIC")
    for role in ("anon", "authenticated", "service_role"):
        if (
            op.get_bind()
            .execute(text("SELECT 1 FROM pg_roles WHERE rolname = :role"), {"role": role})
            .scalar()
        ):
            op.execute(f"REVOKE ALL ON FUNCTION execbound.{RENEW_SIGNATURE} FROM {role}")
    op.execute(f"GRANT EXECUTE ON FUNCTION execbound.{RENEW_SIGNATURE} TO execbound_app")


def downgrade() -> None:
    # Dropping the column returns every tenant to the fixed 120 seconds; approvals already
    # created keep the expiry they were created with, which is all their readers consult.
    # Sessions already extended keep their expiry and simply stop being renewable.
    op.execute(f"DROP FUNCTION execbound.{RENEW_SIGNATURE}")
    # Sessions extended beyond the idle lifetime are cut back to it before the old
    # ceiling returns; a signed-in reviewer signs in again. Row-level security is lifted
    # around that one statement, as 0019 did, so every tenant's rows are reached.
    op.execute("ALTER TABLE execbound.human_sessions NO FORCE ROW LEVEL SECURITY")
    op.execute("SET LOCAL row_security = off")
    op.execute(
        "UPDATE execbound.human_sessions SET expires_at = LEAST(expires_at, "
        "created_at + interval '15 minutes')"
    )
    op.execute("ALTER TABLE execbound.human_sessions FORCE ROW LEVEL SECURITY")
    op.execute(
        "ALTER TABLE execbound.human_sessions DROP CONSTRAINT human_sessions_check, "
        f"ADD CONSTRAINT human_sessions_check CHECK ({IDLE_BOUND})"
    )
    op.execute("ALTER TABLE execbound.tenant_policy_control DROP COLUMN approval_deadline_seconds")
