"""Personal preferences, actionable privacy requests, and aggregate product counts."""

from alembic import op
from sqlalchemy import text

revision = "0052_account_experience"
down_revision = "0051_passkeys"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("""
      CREATE TABLE execbound.account_preferences(
        tenant_id uuid NOT NULL,principal_id uuid NOT NULL,
        analytics_consent boolean NOT NULL DEFAULT false,updated_at timestamptz NOT NULL,
        PRIMARY KEY(tenant_id,principal_id),
        FOREIGN KEY(tenant_id,principal_id) REFERENCES execbound.principals
      );
      CREATE TABLE execbound.account_requests(
        tenant_id uuid NOT NULL,request_id uuid NOT NULL,principal_id uuid NOT NULL,
        kind text NOT NULL CHECK(kind IN ('data_access','close_account','close_workspace')),
        state text NOT NULL DEFAULT 'pending' CHECK(state IN ('pending','completed','declined')),
        requested_at timestamptz NOT NULL,closed_at timestamptz,closed_by uuid,
        response text CHECK(length(response) BETWEEN 1 AND 1000),
        PRIMARY KEY(tenant_id,request_id),
        FOREIGN KEY(tenant_id,principal_id) REFERENCES execbound.principals,
        FOREIGN KEY(tenant_id,closed_by) REFERENCES execbound.principals,
        CHECK((state='pending')=(closed_at IS NULL)),
        CHECK((closed_at IS NULL)=(closed_by IS NULL)),
        CHECK((closed_at IS NULL)=(response IS NULL))
      );
      CREATE UNIQUE INDEX account_requests_pending ON execbound.account_requests
        (tenant_id,principal_id,kind) WHERE state='pending';
      CREATE INDEX account_requests_principal ON execbound.account_requests
        (tenant_id,principal_id);
      CREATE INDEX account_requests_reviewer ON execbound.account_requests
        (tenant_id,closed_by);
      CREATE TABLE execbound.product_counts(
        tenant_id uuid NOT NULL REFERENCES execbound.tenants,day date NOT NULL,
        event text NOT NULL CHECK(event IN ('page_view','start_signup','contact_sales',
          'account_opened','agent_connected','request_verified','approval_completed')),
        page text NOT NULL CHECK(page IN ('home','integrations','privacy','terms','help',
          'security','status','storage','plans','console')),
        total bigint NOT NULL CHECK(total BETWEEN 1 AND 1000000),
        PRIMARY KEY(tenant_id,day,event,page)
      );
    """)
    for table in ("account_preferences", "account_requests", "product_counts"):
        op.execute(f"ALTER TABLE execbound.{table} ENABLE ROW LEVEL SECURITY")
        op.execute(f"ALTER TABLE execbound.{table} FORCE ROW LEVEL SECURITY")
        op.execute(f"""CREATE POLICY tenant_isolation ON execbound.{table}
          USING(tenant_id=nullif((SELECT current_setting('execbound.tenant_id',true)),'')::uuid)
          WITH CHECK(tenant_id=nullif(
                (SELECT current_setting('execbound.tenant_id',true)),'')::uuid)
        """)
        op.execute(f"REVOKE ALL ON execbound.{table} FROM PUBLIC,execbound_app")
        op.execute(f"GRANT SELECT ON execbound.{table} TO execbound_app")
    op.execute("""
      CREATE FUNCTION execbound.account_change(
        p_session uuid,p_now timestamptz,p_operation text,p_data jsonb
      ) RETURNS void LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,execbound AS $$
      DECLARE
        t uuid := nullif(current_setting('execbound.tenant_id',true),'')::uuid;
        s execbound.human_sessions;
      BEGIN
        SELECT * INTO s FROM execbound.human_sessions WHERE tenant_id=t AND session_id=p_session;
        IF s.session_id IS NULL OR s.revoked_at IS NOT NULL OR p_now<s.created_at
          OR p_now>=s.expires_at OR NOT EXISTS(
            SELECT 1 FROM execbound.credentials c JOIN execbound.principals p USING(tenant_id,
                principal_id)
            WHERE c.tenant_id=t AND c.credential_id=s.credential_id AND p.active
              AND c.revoked_at IS NULL AND c.expires_at>p_now AND p.kind=s.kind
          ) THEN RAISE EXCEPTION 'INVALID_SESSION'; END IF;
        IF p_operation='preferences' THEN
          INSERT INTO execbound.account_preferences(tenant_id,principal_id,analytics_consent,
              updated_at)
            VALUES(t,s.principal_id,(p_data->>'analytics_consent')::boolean,p_now)
            ON CONFLICT(tenant_id,principal_id) DO UPDATE
              SET analytics_consent=excluded.analytics_consent,updated_at=excluded.updated_at;
        ELSIF p_operation='profile' THEN
          IF length(trim(p_data->>'name')) NOT BETWEEN 1 AND 80
            THEN RAISE EXCEPTION 'INVALID_NAME'; END IF;
          UPDATE execbound.principals SET label=trim(p_data->>'name')
            WHERE tenant_id=t AND principal_id=s.principal_id;
        ELSIF p_operation='request' THEN
          IF p_data->>'kind'='close_workspace' AND s.kind<>'ADMIN'
            THEN RAISE EXCEPTION 'FORBIDDEN'; END IF;
          INSERT INTO execbound.account_requests(tenant_id,request_id,principal_id,kind,
              requested_at)
            VALUES(t,(p_data->>'request_id')::uuid,s.principal_id,p_data->>'kind',p_now)
            ON CONFLICT(tenant_id,principal_id,kind) WHERE state='pending' DO NOTHING;
        ELSIF p_operation='resolve' THEN
          IF s.kind<>'ADMIN' OR p_data->>'state' NOT IN ('completed','declined')
            THEN RAISE EXCEPTION 'FORBIDDEN'; END IF;
          UPDATE execbound.account_requests SET state=p_data->>'state',closed_at=p_now,
            closed_by=s.principal_id,response=p_data->>'response'
            WHERE tenant_id=t AND request_id=(p_data->>'request_id')::uuid AND state='pending';
          IF NOT FOUND THEN RAISE EXCEPTION 'NOT_FOUND'; END IF;
        ELSE RAISE EXCEPTION 'INVALID_OPERATION'; END IF;
      END $$;
      CREATE FUNCTION execbound.product_count(p_event text,p_page text)
        RETURNS void LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,execbound AS $$
      DECLARE
        t uuid := nullif(current_setting('execbound.tenant_id',true),'')::uuid;
        d date := (clock_timestamp() AT TIME ZONE 'UTC')::date;
      BEGIN
        DELETE FROM execbound.product_counts WHERE tenant_id=t AND day<d-90;
        INSERT INTO execbound.product_counts(tenant_id,day,event,page,total)
          VALUES(t,d,p_event,p_page,1)
          ON CONFLICT(tenant_id,day,event,page) DO UPDATE
            SET total=least(execbound.product_counts.total+1,1000000);
      END $$;
      REVOKE ALL ON FUNCTION execbound.account_change(uuid,timestamptz,text,jsonb) FROM PUBLIC;
      REVOKE ALL ON FUNCTION execbound.product_count(text,text) FROM PUBLIC;
      GRANT EXECUTE ON FUNCTION execbound.account_change(uuid,timestamptz,text,jsonb) TO
          execbound_app;
      GRANT EXECUTE ON FUNCTION execbound.product_count(text,text) TO execbound_app;
    """)
    # Hosted default grants must not expose factors, preferences or counts via PostgREST.
    for role in ("anon", "authenticated", "service_role"):
        if (
            op.get_bind()
            .execute(text("SELECT 1 FROM pg_roles WHERE rolname=:r"), {"r": role})
            .scalar()
        ):
            for table in (
                "account_factors",
                "session_assurance",
                "account_security_policy",
                "account_passkeys",
                "passkey_challenges",
                "account_preferences",
                "account_requests",
                "product_counts",
            ):
                op.execute(f"REVOKE ALL ON execbound.{table} FROM {role}")
            for signature in (
                "account_security_change(uuid,timestamptz,text,jsonb)",
                "account_change(uuid,timestamptz,text,jsonb)",
                "product_count(text,text)",
            ):
                op.execute(f"REVOKE ALL ON FUNCTION execbound.{signature} FROM {role}")


def downgrade() -> None:
    op.execute("DROP FUNCTION execbound.account_change(uuid,timestamptz,text,jsonb)")
    op.execute("DROP FUNCTION execbound.product_count(text,text)")
    for table in ("account_preferences", "account_requests", "product_counts"):
        op.execute(f"DROP TABLE execbound.{table}")
