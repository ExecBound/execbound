"""Live human roles and groups, separate from agent policy and review scopes."""

import importlib.util
import re
from pathlib import Path

from alembic import op
from sqlalchemy import text

revision = "0047_access_control"
down_revision = "0046_request_references"
branch_labels = None
depends_on = None

TABLES = ("access_principals", "access_groups", "access_group_members", "access_role_grants")
SIGNATURES = (
    "access_has_permission(uuid, text, uuid, boolean)",
    "access_effective_kind(uuid)",
    "access_change(uuid, text, uuid, jsonb)",
)
FENCE = (
    "    IF v_tenant IS NOT NULL AND EXISTS (SELECT 1 FROM execbound.tenants "
    "WHERE tenant_id=v_tenant AND active) THEN\n"
    "    INSERT INTO execbound.tenant_policy_control(tenant_id,changed_at) "
    "VALUES(v_tenant,now()) ON CONFLICT(tenant_id) DO NOTHING;\n"
    "    PERFORM 1 FROM execbound.tenant_policy_control "
    "WHERE tenant_id=v_tenant FOR UPDATE;\n"
    "    END IF;\n"
)

PERMISSION = """
CREATE FUNCTION execbound.access_has_permission(
    p_principal uuid, p_permission text, p_space uuid, p_any boolean)
RETURNS boolean LANGUAGE plpgsql STABLE SECURITY DEFINER
SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    v_tenant uuid := nullif(current_setting('execbound.tenant_id', true), '')::uuid;
    v_kind text;
    v_managed boolean;
    v_member boolean;
BEGIN
    IF p_permission IS NULL OR p_permission NOT IN
       ('console.read','policy.manage','approvals.decide','access.manage','workspace.manage')
       OR v_tenant IS NULL THEN RETURN false; END IF;
    SELECT p.kind INTO v_kind FROM execbound.principals p
    JOIN execbound.tenants t USING (tenant_id)
    WHERE p.tenant_id=v_tenant AND p.principal_id=p_principal AND p.active AND t.active;
    IF v_kind IS NULL OR v_kind='AGENT' THEN RETURN false; END IF;
    IF p_space IS NOT NULL AND NOT EXISTS (
        SELECT 1 FROM execbound.spaces WHERE tenant_id=v_tenant AND space_id=p_space
    ) THEN RETURN false; END IF;
    SELECT EXISTS(SELECT 1 FROM execbound.access_principals
        WHERE tenant_id=v_tenant AND principal_id=p_principal) INTO v_managed;
    IF NOT v_managed THEN
        SELECT EXISTS(SELECT 1 FROM execbound.space_members
            WHERE tenant_id=v_tenant AND principal_id=p_principal) INTO v_member;
        IF p_permission IN ('access.manage','workspace.manage') AND v_kind='ADMIN'
           AND (NOT v_member OR p_any) THEN RETURN true; END IF;
        IF p_permission IN ('console.read','approvals.decide','policy.manage')
           AND (p_permission<>'policy.manage' OR v_kind='ADMIN') THEN
            IF v_kind='ADMIN' AND NOT v_member THEN RETURN true; END IF;
            IF EXISTS(SELECT 1 FROM execbound.space_members m
                WHERE m.tenant_id=v_tenant AND m.principal_id=p_principal
                AND (m.space_id=p_space OR p_any)
                AND (p_permission<>'policy.manage' OR m.role='ADMIN')) THEN RETURN true; END IF;
        END IF;
    END IF;
    RETURN EXISTS (
        SELECT 1 FROM execbound.access_role_grants g
        WHERE g.tenant_id=v_tenant
          AND (g.principal_id=p_principal OR EXISTS (
              SELECT 1 FROM execbound.access_group_members m
              WHERE m.tenant_id=g.tenant_id AND m.group_id=g.group_id
                AND m.principal_id=p_principal))
          AND (g.space_id IS NULL OR g.space_id=p_space OR p_any)
          AND (p_permission='console.read'
               OR (p_permission IN ('access.manage','workspace.manage') AND g.role='administrator')
               OR (p_permission='policy.manage' AND g.role IN ('administrator','policy_manager'))
               OR (p_permission='approvals.decide' AND g.role='approver'))
    );
END $$
"""

EFFECTIVE_KIND = """
CREATE FUNCTION execbound.access_effective_kind(p_principal uuid)
RETURNS text LANGUAGE sql STABLE SECURITY DEFINER
SET search_path = pg_catalog, pg_temp AS $$
    SELECT CASE WHEN p.kind='AGENT' THEN 'AGENT'
                WHEN execbound.access_has_permission(p_principal,'workspace.manage',NULL,true)
                THEN 'ADMIN' ELSE 'HUMAN_APPROVER' END
    FROM execbound.principals p
    WHERE p.tenant_id=nullif(current_setting('execbound.tenant_id',true),'')::uuid
      AND p.principal_id=p_principal
$$
"""

CHANGE = """
CREATE FUNCTION execbound.access_change(
    p_actor uuid, p_operation text, p_subject uuid, p_body jsonb)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    v_tenant uuid := nullif(current_setting('execbound.tenant_id',true),'')::uuid;
    v_id uuid := coalesce(p_subject,gen_random_uuid());
    v_item jsonb;
    v_space uuid;
    v_principal uuid;
    v_count integer;
    v_before uuid[];
    v_promoted uuid[];
    v_credentials jsonb;
    v_sessions jsonb;
    v_resets jsonb;
    v_invitations jsonb;
BEGIN
    IF v_tenant IS NULL THEN RAISE EXCEPTION 'INVALID_TENANT'; END IF;
    INSERT INTO execbound.tenant_policy_control(tenant_id,changed_at)
        VALUES(v_tenant,now()) ON CONFLICT(tenant_id) DO NOTHING;
    PERFORM 1 FROM execbound.tenant_policy_control WHERE tenant_id=v_tenant FOR UPDATE;
    IF NOT execbound.access_has_permission(p_actor,'access.manage',NULL,false)
       THEN RAISE EXCEPTION 'FORBIDDEN'; END IF;
    SELECT coalesce(array_agg(p.principal_id),'{}'::uuid[]) INTO v_before
    FROM execbound.principals p WHERE p.tenant_id=v_tenant
      AND execbound.access_has_permission(p.principal_id,'access.manage',NULL,false);
    IF p_operation IN ('create_group','update_group') THEN
        IF jsonb_typeof(p_body->'name') IS DISTINCT FROM 'string'
           OR char_length(btrim(p_body->>'name')) NOT BETWEEN 1 AND 80
           OR coalesce(char_length(p_body->>'description'),0)>240
           THEN RAISE EXCEPTION 'INVALID_NAME'; END IF;
        IF p_operation='create_group' THEN
            INSERT INTO execbound.access_groups(tenant_id,group_id,name,description)
            VALUES(v_tenant,v_id,btrim(p_body->>'name'),nullif(btrim(p_body->>'description'),''));
        ELSE
            UPDATE execbound.access_groups SET name=btrim(p_body->>'name'),
                description=nullif(btrim(p_body->>'description'),'')
            WHERE tenant_id=v_tenant AND group_id=v_id;
            IF NOT FOUND THEN RAISE EXCEPTION 'NOT_FOUND'; END IF;
        END IF;
    ELSIF p_operation='set_members' THEN
        IF NOT EXISTS(SELECT 1 FROM execbound.access_groups
            WHERE tenant_id=v_tenant AND group_id=v_id) THEN RAISE EXCEPTION 'NOT_FOUND'; END IF;
        IF jsonb_typeof(p_body->'members') IS DISTINCT FROM 'array'
            OR jsonb_array_length(p_body->'members')>100
            THEN RAISE EXCEPTION 'INVALID_MEMBERS'; END IF;
        DELETE FROM execbound.access_group_members WHERE tenant_id=v_tenant AND group_id=v_id;
        FOR v_item IN SELECT value FROM jsonb_array_elements(p_body->'members') LOOP
            v_principal := (v_item#>>'{}')::uuid;
            IF NOT EXISTS(SELECT 1 FROM execbound.principals
                WHERE tenant_id=v_tenant AND principal_id=v_principal
                  AND kind IN ('ADMIN','HUMAN_APPROVER') AND active)
                THEN RAISE EXCEPTION 'INVALID_PRINCIPAL'; END IF;
            INSERT INTO execbound.access_group_members(tenant_id,group_id,principal_id)
                VALUES(v_tenant,v_id,v_principal) ON CONFLICT DO NOTHING;
        END LOOP;
    ELSIF p_operation IN ('set_user_roles','set_group_roles') THEN
        IF p_operation='set_user_roles' THEN
            IF NOT EXISTS(SELECT 1 FROM execbound.principals WHERE tenant_id=v_tenant
                AND principal_id=v_id AND kind IN ('ADMIN','HUMAN_APPROVER') AND active)
                THEN RAISE EXCEPTION 'INVALID_PRINCIPAL'; END IF;
            INSERT INTO execbound.access_principals(tenant_id,principal_id)
                VALUES(v_tenant,v_id) ON CONFLICT DO NOTHING;
        ELSIF NOT EXISTS(SELECT 1 FROM execbound.access_groups
            WHERE tenant_id=v_tenant AND group_id=v_id)
            THEN RAISE EXCEPTION 'NOT_FOUND'; END IF;
        IF jsonb_typeof(p_body->'grants') IS DISTINCT FROM 'array'
            OR jsonb_array_length(p_body->'grants')>100
            THEN RAISE EXCEPTION 'INVALID_ROLES'; END IF;
        DELETE FROM execbound.access_role_grants WHERE tenant_id=v_tenant
            AND ((p_operation='set_user_roles' AND principal_id=v_id)
              OR (p_operation='set_group_roles' AND group_id=v_id));
        FOR v_item IN SELECT value FROM jsonb_array_elements(p_body->'grants') LOOP
            IF v_item->>'role' IS NULL OR v_item->>'role' NOT IN
                ('administrator','policy_manager','approver','viewer')
                THEN RAISE EXCEPTION 'INVALID_ROLE'; END IF;
            v_space := (v_item->>'space_id')::uuid;
            IF v_item->>'role'='administrator' AND v_space IS NOT NULL
                THEN RAISE EXCEPTION 'INVALID_ROLE_SCOPE'; END IF;
            IF v_space IS NOT NULL AND NOT EXISTS(SELECT 1 FROM execbound.spaces
                WHERE tenant_id=v_tenant AND space_id=v_space AND archived_at IS NULL)
                THEN RAISE EXCEPTION 'INVALID_SPACE'; END IF;
            INSERT INTO execbound.access_role_grants
                (tenant_id,grant_id,principal_id,group_id,role,space_id)
            VALUES(v_tenant,gen_random_uuid(),
                CASE WHEN p_operation='set_user_roles' THEN v_id END,
                CASE WHEN p_operation='set_group_roles' THEN v_id END,v_item->>'role',v_space);
        END LOOP;
    ELSE RAISE EXCEPTION 'INVALID_OPERATION'; END IF;
    SELECT count(*) INTO v_count FROM execbound.principals p
    WHERE p.tenant_id=v_tenant AND p.active
      AND execbound.access_has_permission(p.principal_id,'access.manage',NULL,false);
    IF v_count=0 THEN RAISE EXCEPTION 'LAST_ADMINISTRATOR'; END IF;
    SELECT coalesce(array_agg(p.principal_id),'{}'::uuid[]) INTO v_promoted
    FROM execbound.principals p WHERE p.tenant_id=v_tenant
      AND NOT p.principal_id=ANY(v_before)
      AND execbound.access_has_permission(p.principal_id,'access.manage',NULL,false);
    -- Credentials issued while a person was less privileged must not become an
    -- administrator credential. Passwords and established directory bindings survive
    -- so their owner can authenticate again after this atomic transition.
    WITH revoked AS (
        UPDATE execbound.credentials SET revoked_at=greatest(clock_timestamp(),issued_at)
        WHERE tenant_id=v_tenant AND principal_id=ANY(v_promoted) AND revoked_at IS NULL
        RETURNING credential_id,principal_id
    ) SELECT coalesce(jsonb_agg(to_jsonb(revoked)),'[]'::jsonb)
        INTO v_credentials FROM revoked;
    WITH revoked AS (
        UPDATE execbound.human_sessions SET revoked_at=greatest(clock_timestamp(),created_at)
        WHERE tenant_id=v_tenant AND principal_id=ANY(v_promoted) AND revoked_at IS NULL
        RETURNING session_id,credential_id,principal_id
    ) SELECT coalesce(jsonb_agg(to_jsonb(revoked)),'[]'::jsonb)
        INTO v_sessions FROM revoked;
    WITH revoked AS (
        UPDATE execbound.password_resets SET revoked_at=greatest(clock_timestamp(),created_at)
        WHERE tenant_id=v_tenant AND principal_id=ANY(v_promoted)
          AND revoked_at IS NULL AND redeemed_at IS NULL
        RETURNING reset_id,principal_id
    ) SELECT coalesce(jsonb_agg(to_jsonb(revoked)),'[]'::jsonb)
        INTO v_resets FROM revoked;
    WITH revoked AS (
        UPDATE execbound.identity_invitations SET revoked_at=greatest(clock_timestamp(),created_at)
        WHERE tenant_id=v_tenant AND principal_id=ANY(v_promoted)
          AND revoked_at IS NULL AND redeemed_at IS NULL
        RETURNING invitation_id,principal_id
    ) SELECT coalesce(jsonb_agg(to_jsonb(revoked)),'[]'::jsonb)
        INTO v_invitations FROM revoked;
    RETURN jsonb_build_object('subject_id',v_id,'credentials',v_credentials,
        'sessions',v_sessions,'resets',v_resets,'invitations',v_invitations);
EXCEPTION WHEN unique_violation THEN RAISE EXCEPTION 'CONFLICT';
END $$
"""


def upgrade() -> None:
    op.execute("""
        CREATE TABLE execbound.access_principals (
            tenant_id uuid NOT NULL, principal_id uuid NOT NULL,
            PRIMARY KEY(tenant_id,principal_id),
            FOREIGN KEY(tenant_id,principal_id)
                REFERENCES execbound.principals(tenant_id,principal_id));
        CREATE TABLE execbound.access_groups (
            tenant_id uuid NOT NULL REFERENCES execbound.tenants,
            group_id uuid NOT NULL, name text NOT NULL CHECK(char_length(name) BETWEEN 1 AND 80),
            description text CHECK(char_length(description)<=240),
            created_at timestamptz NOT NULL DEFAULT now(), PRIMARY KEY(tenant_id,group_id));
        CREATE UNIQUE INDEX access_group_name ON execbound.access_groups(tenant_id,lower(name));
        CREATE TABLE execbound.access_group_members (
            tenant_id uuid NOT NULL, group_id uuid NOT NULL, principal_id uuid NOT NULL,
            PRIMARY KEY(tenant_id,group_id,principal_id),
            FOREIGN KEY(tenant_id,group_id) REFERENCES execbound.access_groups(tenant_id,group_id),
            FOREIGN KEY(tenant_id,principal_id)
                REFERENCES execbound.principals(tenant_id,principal_id));
        CREATE INDEX access_members_principal
            ON execbound.access_group_members(tenant_id,principal_id);
        CREATE TABLE execbound.access_role_grants (
            tenant_id uuid NOT NULL, grant_id uuid NOT NULL, principal_id uuid, group_id uuid,
            role text NOT NULL
                CHECK(role IN ('administrator','policy_manager','approver','viewer')),
            space_id uuid, PRIMARY KEY(tenant_id,grant_id),
            CHECK ((principal_id IS NULL)<>(group_id IS NULL)),
            CHECK(role<>'administrator' OR space_id IS NULL),
            FOREIGN KEY(tenant_id,principal_id)
                REFERENCES execbound.principals(tenant_id,principal_id),
            FOREIGN KEY(tenant_id,group_id) REFERENCES execbound.access_groups(tenant_id,group_id),
            FOREIGN KEY(tenant_id,space_id) REFERENCES execbound.spaces(tenant_id,space_id));
        CREATE UNIQUE INDEX access_grant_subject ON execbound.access_role_grants
            (tenant_id,principal_id,group_id,role,space_id) NULLS NOT DISTINCT;
        CREATE INDEX access_grant_group ON execbound.access_role_grants(tenant_id,group_id);
        CREATE INDEX access_grant_space ON execbound.access_role_grants(tenant_id,space_id);
    """)
    for table in TABLES:
        op.execute(f"ALTER TABLE execbound.{table} ENABLE ROW LEVEL SECURITY")
        op.execute(f"ALTER TABLE execbound.{table} FORCE ROW LEVEL SECURITY")
        op.execute(f"""CREATE POLICY tenant_isolation ON execbound.{table}
            USING(tenant_id=nullif((SELECT current_setting('execbound.tenant_id',true)),'')::uuid)
            WITH CHECK(tenant_id=nullif(
                (SELECT current_setting('execbound.tenant_id',true)),'')::uuid)
        """)
        op.execute(f"REVOKE ALL ON execbound.{table} FROM PUBLIC, execbound_app")
        for role in ("anon", "authenticated", "service_role"):
            if (
                op.get_bind()
                .execute(text("SELECT 1 FROM pg_roles WHERE rolname=:r"), {"r": role})
                .scalar()
            ):
                op.execute(f"REVOKE ALL ON execbound.{table} FROM {role}")
        op.execute(f"GRANT SELECT ON execbound.{table} TO execbound_app")
    for definition in (PERMISSION, EFFECTIVE_KIND, CHANGE):
        op.execute(definition)
    for signature in SIGNATURES:
        op.execute(f"REVOKE ALL ON FUNCTION execbound.{signature} FROM PUBLIC")
        for role in ("anon", "authenticated", "service_role"):
            if (
                op.get_bind()
                .execute(text("SELECT 1 FROM pg_roles WHERE rolname=:r"), {"r": role})
                .scalar()
            ):
                op.execute(f"REVOKE ALL ON FUNCTION execbound.{signature} FROM {role}")
        op.execute(f"GRANT EXECUTE ON FUNCTION execbound.{signature} TO execbound_app")
    # Existing definer paths must consume current authority as well: a managed human may
    # be promoted without changing its identity class; an original ADMIN may be demoted.
    # Only the known administration functions with their explicit actor predicate change.
    rows = (
        op.get_bind()
        .execute(
            text("""
        SELECT p.oid, p.proname, pg_get_functiondef(p.oid) AS definition
        FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace
        WHERE n.nspname='execbound' AND p.prosecdef
          AND (p.proname LIKE 'admin_%' OR p.proname LIKE 'directory_%'
               OR p.proname LIKE 'space_%'
               OR p.proname IN (
                   'sandbox_reattest','sandbox_fallback','sandbox_expire','agents_sleep',
                   'password_redeem')
               OR p.proname LIKE 'assistant_%')
    """)
        )
        .mappings()
        .all()
    )
    for row in rows:
        definition = row["definition"]
        # Preserve all existing target/bootstrap restrictions, and substitute only the
        # acting principal's legacy ADMIN predicate.
        updated = re.sub(
            r"(p\.principal_id\s*=\s*p_actor\s+AND p\.active AND )p\.kind = 'ADMIN'",
            r"\1execbound.access_effective_kind(p_actor) = 'ADMIN'",
            definition,
        )
        if row["proname"] in {"sandbox_fallback", "sandbox_expire", "agents_sleep"}:
            updated = updated.replace(
                "p.kind = 'ADMIN' AND p.active",
                "execbound.access_has_permission(p.principal_id,'access.manage',NULL,false) "
                "AND p.active",
            )
        # Issuing a recoverable credential or reset to a newly promoted administrator
        # must retain the restrictions that protect bootstrap administrator accounts.
        if row["proname"] in {
            "admin_issue_credential",
            "admin_revoke_credential",
            "admin_deactivate_principal",
            "admin_set_email",
            "admin_reset_password",
            "directory_link",
            "directory_unlink",
            "directory_invite",
        }:
            updated = updated.replace(
                "p.kind <> 'ADMIN'",
                "p.kind <> 'ADMIN' AND execbound.access_effective_kind(p.principal_id) <> 'ADMIN'",
            )
            updated = updated.replace(
                "p.kind = 'HUMAN_APPROVER'",
                "p.kind = 'HUMAN_APPROVER' "
                "AND execbound.access_effective_kind(p.principal_id) <> 'ADMIN'",
            )
            updated = updated.replace(
                "IF v_kind IS NULL OR v_kind = 'ADMIN' THEN",
                "IF v_kind IS NULL OR v_kind = 'ADMIN' "
                "OR execbound.access_effective_kind(p_principal) = 'ADMIN' THEN",
            )
        # A workspace role acquired through RBAC is not narrowed by a legacy Space
        # membership. Unmanaged Space administrators retain the previous restriction.
        updated = re.sub(
            r"IF EXISTS \((\s+SELECT 1 FROM execbound\.space_members m\s+"
            r"WHERE m\.tenant_id = v_tenant AND m\.principal_id = p_actor\s*)\)",
            r"IF NOT execbound.access_has_permission(p_actor,'access.manage',NULL,false) "
            r"AND EXISTS (\1)",
            updated,
        )
        if row["proname"] == "directory_sign_in":
            updated = updated.replace(
                "v_principal := v_row.principal_id;",
                "v_principal := v_row.principal_id;\n"
                "        IF execbound.access_effective_kind(v_principal) = 'ADMIN' THEN\n"
                "            RAISE EXCEPTION 'INVALID_PRINCIPAL';\n"
                "        END IF;",
            )
        if updated != definition or row["proname"] == "password_redeem":
            updated = updated.replace("BEGIN\n", "BEGIN\n" + FENCE, 1)
            op.execute(updated)
    # session_set_space must use the same current visibility as list reads.
    op.execute("""
        CREATE OR REPLACE FUNCTION execbound.session_set_space(p_session uuid,p_space uuid)
        RETURNS void LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
        DECLARE v_tenant uuid:=nullif(current_setting('execbound.tenant_id',true),'')::uuid;
                v_principal uuid;
        BEGIN
            SELECT principal_id INTO v_principal FROM execbound.human_sessions
            WHERE tenant_id=v_tenant AND session_id=p_session AND revoked_at IS NULL
              AND expires_at>now();
            IF NOT FOUND THEN RAISE EXCEPTION 'INVALID_SESSION'; END IF;
            IF p_space IS NOT NULL AND NOT execbound.access_has_permission(
                v_principal,'console.read',p_space,false)
                THEN RAISE EXCEPTION 'INVALID_SPACE'; END IF;
            UPDATE execbound.human_sessions SET current_space_id=p_space
            WHERE tenant_id=v_tenant AND session_id=p_session;
        END $$
    """)
    op.execute("""
        CREATE FUNCTION execbound.access_protect_last_admin() RETURNS trigger
        LANGUAGE plpgsql SET search_path=pg_catalog,pg_temp AS $$
        DECLARE v_tenant uuid; v_principal uuid;
        BEGIN
            v_tenant := NEW.tenant_id;
            v_principal := NEW.principal_id;
            -- Legacy-only tenants keep their existing definer protections. Once role
            -- data exists, raw principal kind can no longer count administrators.
            IF NOT EXISTS(SELECT 1 FROM execbound.access_principals WHERE tenant_id=v_tenant)
                AND NOT EXISTS(SELECT 1 FROM execbound.access_role_grants WHERE tenant_id=v_tenant)
                THEN RETURN NEW; END IF;
            PERFORM 1 FROM execbound.tenant_policy_control WHERE tenant_id=v_tenant FOR UPDATE;
            IF TG_TABLE_NAME='principals' THEN
                IF NOT OLD.active OR NEW.active THEN RETURN NEW; END IF;
            ELSE
                IF EXISTS(SELECT 1 FROM execbound.access_principals
                    WHERE tenant_id=v_tenant AND principal_id=v_principal)
                    OR EXISTS(SELECT 1 FROM execbound.access_role_grants g
                        WHERE g.tenant_id=v_tenant AND g.role='administrator'
                        AND (g.principal_id=v_principal OR EXISTS (
                            SELECT 1 FROM execbound.access_group_members m
                            WHERE m.tenant_id=v_tenant AND m.group_id=g.group_id
                              AND m.principal_id=v_principal))) THEN RETURN NEW; END IF;
            END IF;
            IF execbound.access_has_permission(v_principal,'access.manage',NULL,false)
                AND NOT EXISTS(SELECT 1 FROM execbound.principals p
                    WHERE p.tenant_id=v_tenant AND p.principal_id<>v_principal AND p.active
                    AND execbound.access_has_permission(p.principal_id,'access.manage',NULL,false))
                THEN
                    IF TG_TABLE_NAME='space_members' THEN
                        RAISE EXCEPTION 'LAST_TENANT_ADMIN';
                    END IF;
                    RAISE EXCEPTION 'LAST_ADMINISTRATOR';
                END IF;
            RETURN NEW;
        END $$;
        REVOKE ALL ON FUNCTION execbound.access_protect_last_admin() FROM PUBLIC;
        CREATE TRIGGER access_last_active_admin BEFORE UPDATE OF active ON execbound.principals
            FOR EACH ROW EXECUTE FUNCTION execbound.access_protect_last_admin();
        CREATE TRIGGER access_last_workspace_admin BEFORE INSERT ON execbound.space_members
            FOR EACH ROW EXECUTE FUNCTION execbound.access_protect_last_admin();
    """)


def downgrade() -> None:
    # Never erase retained grants silently. Empty installations can still exercise the
    # complete migration round trip; ALTER holds its lock until FORCE is restored or dropped.
    for table in TABLES:
        op.execute(f"ALTER TABLE execbound.{table} NO FORCE ROW LEVEL SECURITY")
        if op.get_bind().execute(text(f"SELECT 1 FROM execbound.{table} LIMIT 1")).scalar():
            raise RuntimeError("Access data requires an explicit export and rollback plan")
    op.execute("DROP TRIGGER access_last_active_admin ON execbound.principals")
    op.execute("DROP TRIGGER access_last_workspace_admin ON execbound.space_members")
    op.execute("DROP FUNCTION execbound.access_protect_last_admin()")
    rows = (
        op.get_bind()
        .execute(
            text("""
        SELECT pg_get_functiondef(p.oid) AS definition
        FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace
        WHERE n.nspname='execbound' AND p.prosecdef AND p.proname NOT LIKE 'access_%'
    """)
        )
        .scalars()
        .all()
    )
    for definition in rows:
        updated = definition.replace(FENCE, "")
        updated = updated.replace(
            "execbound.access_effective_kind(p_actor) = 'ADMIN'", "p.kind = 'ADMIN'"
        )
        updated = updated.replace(
            "execbound.access_has_permission(p.principal_id,'access.manage',NULL,false) "
            "AND p.active",
            "p.kind = 'ADMIN' AND p.active",
        )
        updated = updated.replace(
            " AND execbound.access_effective_kind(p.principal_id) <> 'ADMIN'", ""
        )
        updated = updated.replace(" OR execbound.access_effective_kind(p_principal) = 'ADMIN'", "")
        updated = updated.replace(
            "NOT execbound.access_has_permission(p_actor,'access.manage',NULL,false) AND ", ""
        )
        updated = updated.replace(
            "v_principal := v_row.principal_id;\n"
            "        IF execbound.access_effective_kind(v_principal) = 'ADMIN' THEN\n"
            "            RAISE EXCEPTION 'INVALID_PRINCIPAL';\n"
            "        END IF;",
            "v_principal := v_row.principal_id;",
        )
        if updated != definition:
            op.execute(updated)
    spec = importlib.util.spec_from_file_location(
        "access_rollback_spaces", Path(__file__).with_name("0041_spaces.py")
    )
    assert spec is not None and spec.loader is not None
    old = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(old)
    op.execute(old.SET_SPACE.replace("CREATE FUNCTION", "CREATE OR REPLACE FUNCTION"))
    for signature in reversed(SIGNATURES):
        op.execute(f"DROP FUNCTION execbound.{signature}")
    for table in reversed(TABLES):
        op.execute(f"DROP TABLE execbound.{table}")
