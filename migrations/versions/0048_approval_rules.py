"""Group-based approval routing resolved against current membership and roles."""

from alembic import op
from sqlalchemy import text

revision = "0048_approval_rules"
down_revision = "0047_access_control"
branch_labels = None
depends_on = None

TABLES = ("approval_rules", "approval_rule_actions", "approval_rule_targets")
SIGNATURE = "approval_rule_change(uuid, uuid, jsonb)"

CHANGE = """
CREATE FUNCTION execbound.approval_rule_change(p_actor uuid,p_rule uuid,p_body jsonb)
RETURNS uuid LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE
    v_tenant uuid:=nullif(current_setting('execbound.tenant_id',true),'')::uuid;
    v_rule uuid:=coalesce(p_rule,gen_random_uuid());
    v_space uuid;
    v_group uuid;
    v_action text;
    v_target uuid;
BEGIN
    IF v_tenant IS NULL THEN RAISE EXCEPTION 'INVALID_TENANT'; END IF;
    INSERT INTO execbound.tenant_policy_control(tenant_id,changed_at)
        VALUES(v_tenant,now()) ON CONFLICT(tenant_id) DO NOTHING;
    PERFORM 1 FROM execbound.tenant_policy_control WHERE tenant_id=v_tenant FOR UPDATE;
    IF NOT execbound.access_has_permission(p_actor,'access.manage',NULL,false)
        THEN RAISE EXCEPTION 'INVALID_ACTOR'; END IF;
    IF p_rule IS NOT NULL AND NOT EXISTS(SELECT 1 FROM execbound.approval_rules
        WHERE tenant_id=v_tenant AND rule_id=p_rule) THEN RAISE EXCEPTION 'NOT_FOUND'; END IF;
    IF p_body->>'operation'='disable' THEN
        IF p_rule IS NULL THEN RAISE EXCEPTION 'NOT_FOUND'; END IF;
        UPDATE execbound.approval_rules SET active=false,changed_at=now()
            WHERE tenant_id=v_tenant AND rule_id=p_rule;
        RETURN p_rule;
    END IF;
    IF p_body->>'operation' IS DISTINCT FROM 'save'
        OR jsonb_typeof(p_body->'actions') IS DISTINCT FROM 'array'
        OR jsonb_typeof(p_body->'targets') IS DISTINCT FROM 'array'
        OR char_length(btrim(coalesce(p_body->>'name',''))) NOT BETWEEN 1 AND 80
        THEN RAISE EXCEPTION 'INVALID_BODY'; END IF;
    IF jsonb_array_length(p_body->'actions') NOT BETWEEN 1 AND 20
        OR jsonb_array_length(p_body->'targets') NOT BETWEEN 1 AND 100
        THEN RAISE EXCEPTION 'INVALID_BODY'; END IF;
    v_space:=(p_body->>'space_id')::uuid;
    v_group:=(p_body->>'group_id')::uuid;
    IF NOT EXISTS(SELECT 1 FROM execbound.spaces WHERE tenant_id=v_tenant
        AND space_id=v_space AND archived_at IS NULL) THEN RAISE EXCEPTION 'INVALID_SPACE'; END IF;
    IF NOT EXISTS(SELECT 1 FROM execbound.access_groups WHERE tenant_id=v_tenant
        AND group_id=v_group) THEN RAISE EXCEPTION 'NOT_FOUND'; END IF;
    IF p_rule IS NULL AND (SELECT count(*) FROM execbound.approval_rules
        WHERE tenant_id=v_tenant)>=500 THEN RAISE EXCEPTION 'LIMIT_REACHED'; END IF;
    INSERT INTO execbound.approval_rules(tenant_id,rule_id,name,space_id,group_id,active)
        VALUES(v_tenant,v_rule,btrim(p_body->>'name'),v_space,v_group,true)
        ON CONFLICT(tenant_id,rule_id) DO UPDATE SET name=excluded.name,
            space_id=excluded.space_id,group_id=excluded.group_id,active=true,changed_at=now();
    DELETE FROM execbound.approval_rule_actions WHERE tenant_id=v_tenant AND rule_id=v_rule;
    DELETE FROM execbound.approval_rule_targets WHERE tenant_id=v_tenant AND rule_id=v_rule;
    FOR v_action IN SELECT jsonb_array_elements_text(p_body->'actions') LOOP
        IF v_action NOT IN ('endpoint.isolate','endpoint.lift_isolation',
                            'identity.disable','identity.enable','identity.revoke_sessions','identity.reset_password')
            THEN RAISE EXCEPTION 'INVALID_ACTION'; END IF;
        INSERT INTO execbound.approval_rule_actions VALUES(v_tenant,v_rule,v_action)
            ON CONFLICT DO NOTHING;
    END LOOP;
    FOR v_target IN SELECT value::uuid FROM jsonb_array_elements_text(p_body->'targets') LOOP
        IF NOT EXISTS(SELECT 1 FROM execbound.canonical_targets
            WHERE tenant_id=v_tenant AND canonical_target_id=v_target)
            THEN RAISE EXCEPTION 'INVALID_TARGET'; END IF;
        INSERT INTO execbound.approval_rule_targets VALUES(v_tenant,v_rule,v_target)
            ON CONFLICT DO NOTHING;
    END LOOP;
    RETURN v_rule;
EXCEPTION WHEN invalid_text_representation OR not_null_violation OR check_violation
    THEN RAISE EXCEPTION 'INVALID_BODY';
END $$
"""

VIEW = """
CREATE VIEW execbound.effective_approval_scopes WITH (security_invoker=true) AS
SELECT s.tenant_id,s.approver_id,s.canonical_target_id,s.action,s.space_id,true AS active
FROM execbound.approval_scopes s
WHERE s.active AND s.tenant_id=nullif(current_setting('execbound.tenant_id',true),'')::uuid
  AND execbound.access_has_permission(s.approver_id,'approvals.decide',s.space_id,false)
UNION
SELECT r.tenant_id,m.principal_id,t.canonical_target_id,a.action,r.space_id,true AS active
FROM execbound.approval_rules r
JOIN execbound.approval_rule_actions a USING(tenant_id,rule_id)
JOIN execbound.approval_rule_targets t USING(tenant_id,rule_id)
JOIN execbound.access_group_members m ON m.tenant_id=r.tenant_id AND m.group_id=r.group_id
WHERE r.active AND r.tenant_id=nullif(current_setting('execbound.tenant_id',true),'')::uuid
  AND execbound.access_has_permission(m.principal_id,'approvals.decide',r.space_id,false)
"""


def upgrade() -> None:
    op.execute("""
        CREATE TABLE execbound.approval_rules(
            tenant_id uuid NOT NULL,rule_id uuid NOT NULL,
            name text NOT NULL CHECK(char_length(name) BETWEEN 1 AND 80),
            space_id uuid NOT NULL,group_id uuid NOT NULL,active boolean NOT NULL DEFAULT true,
            changed_at timestamptz NOT NULL DEFAULT now(),PRIMARY KEY(tenant_id,rule_id),
            FOREIGN KEY(tenant_id,space_id) REFERENCES execbound.spaces(tenant_id,space_id),
            FOREIGN KEY(tenant_id,group_id) REFERENCES execbound.access_groups(tenant_id,group_id));
        CREATE TABLE execbound.approval_rule_actions(
            tenant_id uuid NOT NULL,rule_id uuid NOT NULL,action text NOT NULL,
            CHECK(action IN ('endpoint.isolate','endpoint.lift_isolation','identity.disable',
                'identity.enable','identity.revoke_sessions','identity.reset_password')),
            PRIMARY KEY(tenant_id,rule_id,action),
            FOREIGN KEY(tenant_id,rule_id) REFERENCES execbound.approval_rules(tenant_id,rule_id));
        CREATE TABLE execbound.approval_rule_targets(
            tenant_id uuid NOT NULL,rule_id uuid NOT NULL,canonical_target_id uuid NOT NULL,
            PRIMARY KEY(tenant_id,rule_id,canonical_target_id),
            FOREIGN KEY(tenant_id,rule_id) REFERENCES execbound.approval_rules(tenant_id,rule_id),
            FOREIGN KEY(tenant_id,canonical_target_id)
                REFERENCES execbound.canonical_targets(tenant_id,canonical_target_id));
        CREATE INDEX approval_rules_space ON execbound.approval_rules(tenant_id,space_id);
        CREATE INDEX approval_rules_group ON execbound.approval_rules(tenant_id,group_id);
        CREATE INDEX approval_rule_targets_target
            ON execbound.approval_rule_targets(tenant_id,canonical_target_id);
    """)
    for table in TABLES:
        op.execute(f"ALTER TABLE execbound.{table} ENABLE ROW LEVEL SECURITY")
        op.execute(f"ALTER TABLE execbound.{table} FORCE ROW LEVEL SECURITY")
        op.execute(f"""CREATE POLICY tenant_isolation ON execbound.{table}
            USING(tenant_id=nullif((SELECT current_setting('execbound.tenant_id',true)),'')::uuid)
            WITH CHECK(tenant_id=nullif(
                (SELECT current_setting('execbound.tenant_id',true)),'')::uuid)""")
        op.execute(f"REVOKE ALL ON execbound.{table} FROM PUBLIC,execbound_app")
        op.execute(f"GRANT SELECT ON execbound.{table} TO execbound_app")
    op.execute(CHANGE)
    op.execute(f"REVOKE ALL ON FUNCTION execbound.{SIGNATURE} FROM PUBLIC")
    op.execute(f"GRANT EXECUTE ON FUNCTION execbound.{SIGNATURE} TO execbound_app")
    op.execute(VIEW)
    op.execute("REVOKE ALL ON execbound.effective_approval_scopes FROM PUBLIC,execbound_app")
    op.execute("GRANT SELECT ON execbound.effective_approval_scopes TO execbound_app")
    for role in ("anon", "authenticated", "service_role"):
        if (
            op.get_bind()
            .execute(text("SELECT 1 FROM pg_roles WHERE rolname=:r"), {"r": role})
            .scalar()
        ):
            for table in (*TABLES, "effective_approval_scopes"):
                op.execute(f"REVOKE ALL ON execbound.{table} FROM {role}")
            op.execute(f"REVOKE ALL ON FUNCTION execbound.{SIGNATURE} FROM {role}")


def downgrade() -> None:
    for table in TABLES:
        op.execute(f"ALTER TABLE execbound.{table} NO FORCE ROW LEVEL SECURITY")
        if op.get_bind().execute(text(f"SELECT 1 FROM execbound.{table} LIMIT 1")).scalar():
            raise RuntimeError("Approval rules require an explicit export and rollback plan")
    op.execute("DROP VIEW execbound.effective_approval_scopes")
    op.execute(f"DROP FUNCTION execbound.{SIGNATURE}")
    for table in reversed(TABLES):
        op.execute(f"DROP TABLE execbound.{table}")
