"""SECURITY DEFINER administration functions for the credential and approver pages.

The runtime role gains EXECUTE on five functions and nothing else: it still cannot
insert, update or delete principals, credentials or approval scopes. Each function reads
the tenant from the transaction setting that forced row-level security uses, verifies
the acting ADMIN inside the database, refuses ADMIN principals and credentials, and
writes exactly the row shape the owner tooling writes.
"""

from alembic import op
from sqlalchemy import text

revision = "0021_admin_functions"
down_revision = "0020_resource_facts_long"
branch_labels = None
depends_on = None

SIGNATURES = (
    "admin_create_principal(uuid, text)",
    "admin_issue_credential(uuid, uuid, uuid, text, timestamptz, timestamptz)",
    "admin_revoke_credential(uuid, uuid, timestamptz)",
    "admin_assign_approver(uuid, uuid, uuid, text)",
    "admin_unassign_approver(uuid, uuid, uuid, text)",
)
# Shared preamble: the tenant comes from the fence setting; the actor must be an active
# ADMIN of that active tenant. Row-level security is forced for the owner as well, so the
# explicit tenant predicates are a second fence, not the only one.
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
FUNCTIONS = (
    f"""
CREATE FUNCTION execbound.admin_create_principal(p_actor uuid, p_kind text)
RETURNS uuid
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    v_tenant uuid := nullif(current_setting('execbound.tenant_id', true), '')::uuid;
    v_principal uuid := gen_random_uuid();
BEGIN
    {ACTOR_CHECK}
    IF p_kind IS NULL OR p_kind NOT IN ('AGENT', 'HUMAN_APPROVER') THEN
        RAISE EXCEPTION 'INVALID_KIND';
    END IF;
    INSERT INTO execbound.principals (tenant_id, principal_id, kind)
    VALUES (v_tenant, v_principal, p_kind);
    RETURN v_principal;
END $$
""",
    f"""
CREATE FUNCTION execbound.admin_issue_credential(
    p_actor uuid, p_principal uuid, p_credential uuid, p_token_hash text,
    p_issued_at timestamptz, p_expires_at timestamptz)
RETURNS text
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    v_tenant uuid := nullif(current_setting('execbound.tenant_id', true), '')::uuid;
    v_kind text;
BEGIN
    {ACTOR_CHECK}
    SELECT p.kind INTO v_kind FROM execbound.principals p
    WHERE p.tenant_id = v_tenant AND p.principal_id = p_principal AND p.active;
    IF v_kind IS NULL OR v_kind = 'ADMIN' THEN
        RAISE EXCEPTION 'INVALID_PRINCIPAL';
    END IF;
    IF p_credential IS NULL OR p_token_hash IS NULL OR p_token_hash !~ '^[0-9a-f]{{64}}$' THEN
        RAISE EXCEPTION 'INVALID_DIGEST';
    END IF;
    IF p_issued_at IS NULL OR abs(extract(epoch FROM (p_issued_at - now()))) > 300 THEN
        RAISE EXCEPTION 'INVALID_CLOCK';
    END IF;
    IF p_expires_at IS NULL
       OR p_expires_at - p_issued_at < interval '1 minute'
       OR p_expires_at - p_issued_at > interval '90 days' THEN
        RAISE EXCEPTION 'INVALID_LIFETIME';
    END IF;
    INSERT INTO execbound.credentials
        (tenant_id, credential_id, principal_id, token_hash, issued_at, expires_at)
    VALUES (v_tenant, p_credential, p_principal, p_token_hash, p_issued_at, p_expires_at);
    RETURN v_kind;
END $$
""",
    f"""
CREATE FUNCTION execbound.admin_revoke_credential(
    p_actor uuid, p_credential uuid, p_revoked_at timestamptz)
RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    v_tenant uuid := nullif(current_setting('execbound.tenant_id', true), '')::uuid;
BEGIN
    {ACTOR_CHECK}
    IF p_revoked_at IS NULL OR abs(extract(epoch FROM (p_revoked_at - now()))) > 300 THEN
        RAISE EXCEPTION 'INVALID_CLOCK';
    END IF;
    UPDATE execbound.credentials c SET revoked_at = p_revoked_at
    FROM execbound.principals p
    WHERE c.tenant_id = v_tenant AND c.credential_id = p_credential AND c.revoked_at IS NULL
      AND p.tenant_id = c.tenant_id AND p.principal_id = c.principal_id AND p.kind <> 'ADMIN';
    IF NOT FOUND THEN
        RAISE EXCEPTION 'INVALID_CREDENTIAL';
    END IF;
END $$
""",
    f"""
CREATE FUNCTION execbound.admin_assign_approver(
    p_actor uuid, p_approver uuid, p_target uuid, p_action text)
RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    v_tenant uuid := nullif(current_setting('execbound.tenant_id', true), '')::uuid;
BEGIN
    {ACTOR_CHECK}
    IF NOT EXISTS (
        SELECT 1 FROM execbound.principals p
        WHERE p.tenant_id = v_tenant AND p.principal_id = p_approver
          AND p.active AND p.kind = 'HUMAN_APPROVER'
    ) THEN
        RAISE EXCEPTION 'INVALID_PRINCIPAL';
    END IF;
    IF NOT EXISTS (
        SELECT 1 FROM execbound.canonical_targets ct
        WHERE ct.tenant_id = v_tenant AND ct.canonical_target_id = p_target
    ) THEN
        RAISE EXCEPTION 'INVALID_TARGET';
    END IF;
    BEGIN
        INSERT INTO execbound.approval_scopes
            (tenant_id, approver_id, canonical_target_id, action, active)
        VALUES (v_tenant, p_approver, p_target, p_action, true)
        ON CONFLICT (tenant_id, approver_id, canonical_target_id, action)
        DO UPDATE SET active = true;
    EXCEPTION WHEN check_violation OR not_null_violation THEN
        RAISE EXCEPTION 'INVALID_ACTION';
    END;
END $$
""",
    f"""
CREATE FUNCTION execbound.admin_unassign_approver(
    p_actor uuid, p_approver uuid, p_target uuid, p_action text)
RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    v_tenant uuid := nullif(current_setting('execbound.tenant_id', true), '')::uuid;
BEGIN
    {ACTOR_CHECK}
    UPDATE execbound.approval_scopes SET active = false
    WHERE tenant_id = v_tenant AND approver_id = p_approver
      AND canonical_target_id = p_target AND action = p_action AND active;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'INVALID_SCOPE';
    END IF;
END $$
""",
)


def upgrade() -> None:
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
    # The functions hold no data; dropping them returns every write to owner tooling.
    for signature in SIGNATURES:
        op.execute(f"DROP FUNCTION execbound.{signature}")
