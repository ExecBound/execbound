"""People: a label, a creation time and a deactivation time on principals, and the three
SECURITY DEFINER functions the People page writes through.

The runtime role still cannot insert, update or delete principals, credentials or sessions
by itself. Each function reads the tenant from the fence setting, verifies the acting ADMIN
inside the database exactly as migration 0021 does, and refuses to deactivate or reactivate
an administrator or the actor, so the console still cannot create or change administrators.
Deactivation revokes the person's live credentials and unrevoked sessions in the same
statement sequence and returns their identifiers, so the caller appends one audit event per
row inside the same transaction. Nothing is deleted.
"""

from alembic import op
from sqlalchemy import text

revision = "0036_people"
down_revision = "0035_session_label"
branch_labels = None
depends_on = None

SIGNATURES = (
    "admin_label_principal(uuid, uuid, text)",
    "admin_deactivate_principal(uuid, uuid, text)",
    "admin_reactivate_principal(uuid, uuid)",
)

# The 0021 preamble, restated: the tenant comes from the fence setting; the actor must be an
# active ADMIN of that active tenant.
ACTOR_CHECK = """
    IF v_tenant IS NULL THEN
        RAISE EXCEPTION 'INVALID_TENANT';
    END IF;
    IF NOT EXISTS (
        SELECT 1 FROM execbound.tenants t WHERE t.tenant_id = v_tenant AND t.active
    ) THEN
        RAISE EXCEPTION 'INVALID_TENANT';
    END IF;
    IF p_actor IS NULL OR NOT EXISTS (
        SELECT 1 FROM execbound.principals p
        WHERE p.tenant_id = v_tenant AND p.principal_id = p_actor
          AND p.active AND p.kind = 'ADMIN'
    ) THEN
        RAISE EXCEPTION 'INVALID_ACTOR';
    END IF;
"""

# A person who may be deactivated or reactivated from the console: a principal of the tenant
# that is not an administrator and is not the actor.
TARGET_CHECK = """
    IF p_principal IS NULL OR p_principal = p_actor OR NOT EXISTS (
        SELECT 1 FROM execbound.principals p
        WHERE p.tenant_id = v_tenant AND p.principal_id = p_principal AND p.kind <> 'ADMIN'
    ) THEN
        RAISE EXCEPTION 'INVALID_PRINCIPAL';
    END IF;
"""

FUNCTIONS = (
    f"""
CREATE FUNCTION execbound.admin_label_principal(p_actor uuid, p_principal uuid, p_label text)
RETURNS text
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    v_tenant uuid := nullif(current_setting('execbound.tenant_id', true), '')::uuid;
    v_label text := btrim(p_label);
BEGIN
    {ACTOR_CHECK}
    IF v_label IS NULL OR char_length(v_label) < 1 OR char_length(v_label) > 80 THEN
        RAISE EXCEPTION 'INVALID_LABEL';
    END IF;
    UPDATE execbound.principals SET label = v_label
    WHERE tenant_id = v_tenant AND principal_id = p_principal;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'INVALID_PRINCIPAL';
    END IF;
    RETURN v_label;
END $$
""",
    f"""
CREATE FUNCTION execbound.admin_deactivate_principal(
    p_actor uuid, p_principal uuid, p_reason text)
RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    v_tenant uuid := nullif(current_setting('execbound.tenant_id', true), '')::uuid;
    v_now timestamptz := now();
    v_credentials jsonb;
    v_sessions jsonb;
BEGIN
    {ACTOR_CHECK}
    IF p_reason IS NULL OR char_length(btrim(p_reason)) < 1 OR char_length(p_reason) > 500 THEN
        RAISE EXCEPTION 'INVALID_REASON';
    END IF;
    {TARGET_CHECK}
    UPDATE execbound.principals SET active = false, deactivated_at = v_now
    WHERE tenant_id = v_tenant AND principal_id = p_principal AND active;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'INVALID_STATE';
    END IF;
    WITH revoked AS (
        UPDATE execbound.credentials SET revoked_at = v_now
        WHERE tenant_id = v_tenant AND principal_id = p_principal AND revoked_at IS NULL
        RETURNING credential_id
    )
    SELECT COALESCE(jsonb_agg(credential_id), '[]'::jsonb) INTO v_credentials FROM revoked;
    WITH ended AS (
        UPDATE execbound.human_sessions SET revoked_at = v_now
        WHERE tenant_id = v_tenant AND principal_id = p_principal AND revoked_at IS NULL
        RETURNING session_id
    )
    SELECT COALESCE(jsonb_agg(session_id), '[]'::jsonb) INTO v_sessions FROM ended;
    RETURN jsonb_build_object('credentials', v_credentials, 'sessions', v_sessions);
END $$
""",
    f"""
CREATE FUNCTION execbound.admin_reactivate_principal(p_actor uuid, p_principal uuid)
RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    v_tenant uuid := nullif(current_setting('execbound.tenant_id', true), '')::uuid;
BEGIN
    {ACTOR_CHECK}
    {TARGET_CHECK}
    UPDATE execbound.principals SET active = true, deactivated_at = NULL
    WHERE tenant_id = v_tenant AND principal_id = p_principal AND NOT active;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'INVALID_STATE';
    END IF;
END $$
""",
)


def upgrade() -> None:
    op.execute(
        "ALTER TABLE execbound.principals ADD COLUMN label text "
        "CHECK (label IS NULL OR char_length(label) BETWEEN 1 AND 80)"
    )
    # Added without a default and given one afterwards, so rows that predate the column
    # keep a null and read "before labels" rather than a fabricated time.
    op.execute("ALTER TABLE execbound.principals ADD COLUMN created_at timestamptz")
    op.execute("ALTER TABLE execbound.principals ALTER COLUMN created_at SET DEFAULT now()")
    op.execute(
        "ALTER TABLE execbound.principals ADD COLUMN deactivated_at timestamptz "
        "CHECK (deactivated_at IS NULL OR NOT active)"
    )
    for body in FUNCTIONS:
        op.execute(body)
    for signature in SIGNATURES:
        op.execute(f"REVOKE ALL ON FUNCTION execbound.{signature} FROM PUBLIC")
        for role in ("anon", "authenticated", "service_role"):
            if (
                op.get_bind()
                .execute(text("SELECT 1 FROM pg_roles WHERE rolname = :role"), {"role": role})
                .scalar()
            ):
                op.execute(f"REVOKE ALL ON FUNCTION execbound.{signature} FROM {role}")
        op.execute(f"GRANT EXECUTE ON FUNCTION execbound.{signature} TO execbound_app")


def downgrade() -> None:
    for signature in SIGNATURES:
        op.execute(f"DROP FUNCTION execbound.{signature}")
    op.execute("ALTER TABLE execbound.principals DROP COLUMN deactivated_at")
    op.execute("ALTER TABLE execbound.principals DROP COLUMN created_at")
    op.execute("ALTER TABLE execbound.principals DROP COLUMN label")
