"""Counting numbers for agents and their API keys, and deleting a spent API key.

A person reads "Agent 3" and "Key 12" instead of the first characters of a UUID. Each workspace
counts its agents and its agents' keys upward from one, in the order they were created; a
person's principal and credential get no number. The numbers are display handles only: every
reference, authorization and audit record keeps the UUID.

A revoked or expired agent key can be deleted. The row stays, stamped `deleted_at`, so the
executions and audit events that name it still resolve; every list leaves it out.
"""

from alembic import op
from sqlalchemy import text

revision = "0058_api_key_numbers"
down_revision = "0057_api_key_never"
branch_labels = None
depends_on = None

TABLES = ("principals", "credentials")
DELETE = "admin_delete_credential(uuid, uuid, timestamptz)"

# One writer per workspace takes the next number: a transaction-scoped advisory lock keyed on
# the tenant serialises two concurrent inserts, and the unique index refuses anything that
# slipped past it rather than numbering two rows alike. The functions run as the inserting
# role inside its tenant fence, which is how every principal and credential is written. A
# principal whose kind changes keeps the rule that only an agent has a number: it drops its
# number when it stops being an agent and takes the next one when it becomes one.
NUMBER_AGENT = """
CREATE FUNCTION execbound.number_agent() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, pg_temp AS $$
BEGIN
    IF NEW.kind <> 'AGENT' THEN
        NEW.number := NULL;
    ELSIF NEW.number IS NULL THEN
        PERFORM pg_advisory_xact_lock(
            hashtextextended('execbound.agent_number:' || NEW.tenant_id::text, 0));
        SELECT coalesce(max(p.number), 0) + 1 INTO NEW.number
        FROM execbound.principals p WHERE p.tenant_id = NEW.tenant_id;
    END IF;
    RETURN NEW;
END $$
"""

NUMBER_KEY = """
CREATE FUNCTION execbound.number_agent_key() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, pg_temp AS $$
BEGIN
    IF NEW.number IS NULL AND EXISTS (
        SELECT 1 FROM execbound.principals p
        WHERE p.tenant_id = NEW.tenant_id AND p.principal_id = NEW.principal_id
          AND p.kind = 'AGENT'
    ) THEN
        PERFORM pg_advisory_xact_lock(
            hashtextextended('execbound.key_number:' || NEW.tenant_id::text, 0));
        SELECT coalesce(max(c.number), 0) + 1 INTO NEW.number
        FROM execbound.credentials c WHERE c.tenant_id = NEW.tenant_id;
    END IF;
    RETURN NEW;
END $$
"""

# Deleting is for a key that can no longer authenticate: revoked, or past its expiry. The
# actor check is `admin_revoke_credential`'s, and a person's credential is never an API key.
DELETE_FUNCTION = """
CREATE FUNCTION execbound.admin_delete_credential(
    p_actor uuid, p_credential uuid, p_deleted_at timestamptz)
RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    v_tenant uuid := nullif(current_setting('execbound.tenant_id', true), '')::uuid;
BEGIN
    IF v_tenant IS NULL OR NOT EXISTS (
        SELECT 1 FROM execbound.tenants t WHERE t.tenant_id = v_tenant AND t.active
    ) THEN
        RAISE EXCEPTION 'INVALID_TENANT';
    END IF;
    IF p_actor IS NULL OR NOT EXISTS (
        SELECT 1 FROM execbound.principals p
        WHERE p.tenant_id = v_tenant AND p.principal_id = p_actor
          AND p.active AND execbound.access_effective_kind(p_actor) = 'ADMIN'
    ) THEN
        RAISE EXCEPTION 'INVALID_ACTOR';
    END IF;
    IF p_deleted_at IS NULL OR abs(extract(epoch FROM (p_deleted_at - now()))) > 300 THEN
        RAISE EXCEPTION 'INVALID_CLOCK';
    END IF;
    UPDATE execbound.credentials c SET deleted_at = p_deleted_at
    FROM execbound.principals p
    WHERE c.tenant_id = v_tenant AND c.credential_id = p_credential AND c.deleted_at IS NULL
      AND (c.revoked_at IS NOT NULL OR c.expires_at <= p_deleted_at)
      AND p.tenant_id = c.tenant_id AND p.principal_id = c.principal_id AND p.kind = 'AGENT';
    IF NOT FOUND THEN
        RAISE EXCEPTION 'INVALID_CREDENTIAL';
    END IF;
END $$
"""


def _lift_rls() -> None:
    op.execute(
        "LOCK TABLE " + ", ".join(f"execbound.{t}" for t in TABLES) + " IN ACCESS EXCLUSIVE MODE"
    )
    for table in TABLES:
        op.execute(f"ALTER TABLE execbound.{table} NO FORCE ROW LEVEL SECURITY")
    op.execute("SET LOCAL row_security = off")


def _restore_rls() -> None:
    for table in TABLES:
        op.execute(f"ALTER TABLE execbound.{table} FORCE ROW LEVEL SECURITY")
    op.execute("SET LOCAL row_security = on")


def _role_exists(role: str) -> bool:
    return bool(
        op.get_bind()
        .execute(text("SELECT 1 FROM pg_roles WHERE rolname = :role"), {"role": role})
        .scalar()
    )


def upgrade() -> None:
    op.execute("ALTER TABLE execbound.principals ADD COLUMN number integer CHECK (number > 0)")
    op.execute("ALTER TABLE execbound.credentials ADD COLUMN number integer CHECK (number > 0)")
    op.execute(
        "ALTER TABLE execbound.credentials ADD COLUMN deleted_at timestamptz "
        "CHECK (deleted_at IS NULL OR deleted_at >= issued_at)"
    )
    # The backfill reads every tenant's rows, so row-level security is lifted on the two
    # tables under an exclusive lock and restored before the transaction ends (0056's way):
    # the hosted owner does not bypass it, and an unfenced UPDATE would touch nothing.
    _lift_rls()
    op.execute("""
        UPDATE execbound.principals p SET number = n.number
        FROM (SELECT tenant_id, principal_id, row_number() OVER (
                  PARTITION BY tenant_id ORDER BY created_at NULLS FIRST, principal_id) AS number
              FROM execbound.principals WHERE kind = 'AGENT') n
        WHERE p.tenant_id = n.tenant_id AND p.principal_id = n.principal_id
    """)
    op.execute("""
        UPDATE execbound.credentials c SET number = n.number
        FROM (SELECT c.tenant_id, c.credential_id, row_number() OVER (
                  PARTITION BY c.tenant_id ORDER BY c.issued_at, c.credential_id) AS number
              FROM execbound.credentials c JOIN execbound.principals p
                USING (tenant_id, principal_id)
              WHERE p.kind = 'AGENT') n
        WHERE c.tenant_id = n.tenant_id AND c.credential_id = n.credential_id
    """)
    _restore_rls()
    op.execute(
        "ALTER TABLE execbound.principals ADD CONSTRAINT principals_number_kind "
        "CHECK ((kind = 'AGENT') = (number IS NOT NULL))"
    )
    op.execute(
        "CREATE UNIQUE INDEX principals_number ON execbound.principals (tenant_id, number) "
        "WHERE number IS NOT NULL"
    )
    op.execute(
        "CREATE UNIQUE INDEX credentials_number ON execbound.credentials (tenant_id, number) "
        "WHERE number IS NOT NULL"
    )
    op.execute(NUMBER_AGENT)
    op.execute(NUMBER_KEY)
    op.execute(
        "CREATE TRIGGER principals_number BEFORE INSERT OR UPDATE OF kind "
        "ON execbound.principals "
        "FOR EACH ROW EXECUTE FUNCTION execbound.number_agent()"
    )
    op.execute(
        "CREATE TRIGGER credentials_number BEFORE INSERT ON execbound.credentials "
        "FOR EACH ROW EXECUTE FUNCTION execbound.number_agent_key()"
    )
    for name in ("number_agent()", "number_agent_key()"):
        op.execute(f"REVOKE ALL ON FUNCTION execbound.{name} FROM PUBLIC")
    op.execute(DELETE_FUNCTION)
    op.execute(f"REVOKE ALL ON FUNCTION execbound.{DELETE} FROM PUBLIC")
    for role in ("anon", "authenticated", "service_role"):
        if _role_exists(role):
            op.execute(f"REVOKE ALL ON FUNCTION execbound.{DELETE} FROM {role}")
    op.execute(f"GRANT EXECUTE ON FUNCTION execbound.{DELETE} TO execbound_app")


def downgrade() -> None:
    op.execute(f"DROP FUNCTION execbound.{DELETE}")
    op.execute("DROP TRIGGER credentials_number ON execbound.credentials")
    op.execute("DROP TRIGGER principals_number ON execbound.principals")
    op.execute("DROP FUNCTION execbound.number_agent_key()")
    op.execute("DROP FUNCTION execbound.number_agent()")
    # A deleted key's row comes back into every list; its revocation or expiry still holds.
    op.execute("ALTER TABLE execbound.credentials DROP COLUMN deleted_at")
    op.execute("ALTER TABLE execbound.credentials DROP COLUMN number")
    op.execute("ALTER TABLE execbound.principals DROP COLUMN number")
