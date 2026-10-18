"""Allow existing human accounts to hold action/target review assignments.

No accounts or automatic grants are created. CREATE OR REPLACE preserves the existing
owner and execute grants; tenant, actor and space checks remain unchanged.
"""

from alembic import op

revision = "0045_review_permissions"
down_revision = "0044_hosted_free"
branch_labels = None
depends_on = None

ASSIGN = """
CREATE OR REPLACE FUNCTION execbound.admin_assign_approver(
    p_actor uuid, p_approver uuid, p_target uuid, p_action text, p_space uuid)
RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    v_tenant uuid := nullif(current_setting('execbound.tenant_id', true), '')::uuid;
BEGIN
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
    IF NOT EXISTS (
        SELECT 1 FROM execbound.principals p
        WHERE p.tenant_id = v_tenant AND p.principal_id = p_approver
          AND p.active AND p.kind IN ('HUMAN_APPROVER', 'ADMIN')
    ) THEN
        RAISE EXCEPTION 'INVALID_PRINCIPAL';
    END IF;
    IF NOT EXISTS (
        SELECT 1 FROM execbound.canonical_targets ct
        WHERE ct.tenant_id = v_tenant AND ct.canonical_target_id = p_target
    ) THEN
        RAISE EXCEPTION 'INVALID_TARGET';
    END IF;
    IF p_space IS NULL OR NOT EXISTS (
        SELECT 1 FROM execbound.spaces s
        WHERE s.tenant_id = v_tenant AND s.space_id = p_space
    ) THEN
        RAISE EXCEPTION 'INVALID_SPACE';
    END IF;
    -- An administrator narrowed to spaces assigns scopes in those spaces only.
    IF EXISTS (
        SELECT 1 FROM execbound.space_members m
        WHERE m.tenant_id = v_tenant AND m.principal_id = p_actor
    ) AND NOT EXISTS (
        SELECT 1 FROM execbound.space_members m
        WHERE m.tenant_id = v_tenant AND m.principal_id = p_actor
          AND m.space_id = p_space AND m.role = 'ADMIN'
    ) THEN
        RAISE EXCEPTION 'INVALID_SPACE';
    END IF;
    BEGIN
        INSERT INTO execbound.approval_scopes
            (tenant_id, approver_id, canonical_target_id, action, active, space_id)
        VALUES (v_tenant, p_approver, p_target, p_action, true, p_space)
        ON CONFLICT (tenant_id, approver_id, canonical_target_id, action)
        DO UPDATE SET active = true, space_id = excluded.space_id;
    EXCEPTION WHEN check_violation OR not_null_violation THEN
        RAISE EXCEPTION 'INVALID_ACTION';
    END;
END $$
"""


def upgrade() -> None:
    op.execute(ASSIGN)


def downgrade() -> None:
    op.execute(ASSIGN.replace("p.kind IN ('HUMAN_APPROVER', 'ADMIN')", "p.kind = 'HUMAN_APPROVER'"))
