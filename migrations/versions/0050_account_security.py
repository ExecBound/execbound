"""Human factors and session assurance under the existing tenant boundary."""

from alembic import op

revision = "0050_account_security"
down_revision = "0049_unused_groups"
branch_labels = None
depends_on = None

CHANGE = """
CREATE FUNCTION execbound.account_security_change(
    p_session uuid, p_now timestamptz, p_operation text, p_data jsonb
) RETURNS void LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,execbound AS $$
DECLARE
    t uuid := nullif(current_setting('execbound.tenant_id',true),'')::uuid;
    s execbound.human_sessions; f execbound.account_factors;
    fresh boolean; needed boolean; step bigint;
BEGIN
    SELECT * INTO s FROM execbound.human_sessions WHERE tenant_id=t AND session_id=p_session;
    IF s.session_id IS NULL OR s.revoked_at IS NOT NULL OR p_now<s.created_at
        OR p_now>=s.expires_at OR NOT EXISTS(
          SELECT 1 FROM execbound.credentials c JOIN execbound.principals p USING(tenant_id,
              principal_id)
          WHERE c.tenant_id=t AND c.credential_id=s.credential_id AND p.active
            AND c.revoked_at IS NULL AND c.expires_at>p_now AND p.kind=s.kind
        ) THEN RAISE EXCEPTION 'INVALID_SESSION'; END IF;
    SELECT * INTO f FROM execbound.account_factors WHERE tenant_id=t AND
        principal_id=s.principal_id;
    fresh := EXISTS(SELECT 1 FROM execbound.session_assurance a WHERE a.tenant_id=t
        AND a.session_id=p_session AND a.version=coalesce(f.version,0)
        AND a.verified_at<=p_now AND a.verified_at>p_now-interval '5 minutes');
    needed := EXISTS(SELECT 1 FROM execbound.account_security_policy p WHERE p.tenant_id=t
        AND (p.requirement='all' OR (p.requirement='admins' AND s.kind='ADMIN')));
    IF p_operation='stage' THEN
        IF (f.enabled_at IS NOT NULL AND NOT fresh)
            OR (f.enabled_at IS NULL AND s.created_at<=p_now-interval '5 minutes')
            THEN RAISE EXCEPTION 'RECENT_AUTH_REQUIRED'; END IF;
        INSERT INTO execbound.account_factors(tenant_id,principal_id,pending_sealed,pending_key,
            pending_session,pending_expires)
        VALUES(t,s.principal_id,p_data->>'sealed',p_data->>'key',p_session,p_now+interval
            '5 minutes')
        ON CONFLICT(tenant_id,principal_id) DO UPDATE SET pending_sealed=excluded.pending_sealed,
            pending_key=excluded.pending_key,pending_session=excluded.pending_session,
            pending_expires=excluded.pending_expires;
    ELSIF p_operation='enable' THEN
        IF f.pending_session IS DISTINCT FROM p_session OR f.pending_expires<=p_now
            OR f.pending_sealed IS NULL OR (f.enabled_at IS NOT NULL AND NOT fresh)
            THEN RAISE EXCEPTION 'INVALID_ENROLLMENT'; END IF;
        UPDATE execbound.account_factors SET sealed=pending_sealed,key_id=pending_key,
            pending_sealed=NULL,pending_key=NULL,pending_session=NULL,pending_expires=NULL,
            enabled_at=p_now,version=version+1,last_step=(p_data->>'step')::bigint,
            recovery_hashes=p_data->'recovery',failures=0,locked_until=NULL
            WHERE tenant_id=t AND principal_id=s.principal_id RETURNING * INTO f;
    ELSIF p_operation='verify' THEN
        IF f.enabled_at IS NULL OR f.locked_until>p_now THEN RAISE EXCEPTION
            'INVALID_FACTOR'; END IF;
        IF p_data->>'method'='totp' THEN
            step := (p_data->>'step')::bigint;
            IF step IS NULL OR step<=f.last_step OR abs(step-floor(extract(epoch FROM p_now)/30))>1
                THEN RAISE EXCEPTION 'INVALID_FACTOR'; END IF;
            UPDATE execbound.account_factors SET last_step=step,failures=0,locked_until=NULL
                WHERE tenant_id=t AND principal_id=s.principal_id;
        ELSIF p_data->>'method'='recovery' THEN
            IF NOT (f.recovery_hashes ? (p_data->>'digest')) THEN RAISE EXCEPTION
                'INVALID_FACTOR'; END IF;
            UPDATE execbound.account_factors SET
                recovery_hashes=recovery_hashes-(p_data->>'digest'),
                failures=0,locked_until=NULL WHERE tenant_id=t AND principal_id=s.principal_id;
        ELSE RAISE EXCEPTION 'INVALID_FACTOR'; END IF;
    ELSIF p_operation='fail' THEN
        UPDATE execbound.account_factors SET failures=CASE WHEN locked_until<=p_now THEN 1
                ELSE least(failures+1,5) END,
            locked_until=CASE WHEN locked_until>p_now THEN locked_until
                WHEN locked_until<=p_now THEN NULL
                WHEN failures>=4 THEN p_now+interval '15 minutes' ELSE NULL END
            WHERE tenant_id=t AND principal_id=s.principal_id;
    ELSIF p_operation='disable' THEN
        IF NOT fresh OR needed THEN RAISE EXCEPTION 'MFA_REQUIRED'; END IF;
        UPDATE execbound.account_factors SET sealed=NULL,key_id=NULL,enabled_at=NULL,
            recovery_hashes='[]',version=version+1,pending_sealed=NULL,pending_key=NULL,
            pending_session=NULL,pending_expires=NULL,last_step=-1
            WHERE tenant_id=t AND principal_id=s.principal_id;
        DELETE FROM execbound.session_assurance WHERE tenant_id=t AND session_id=p_session;
    ELSIF p_operation='recovery' THEN
        IF NOT fresh OR f.enabled_at IS NULL THEN RAISE EXCEPTION 'RECENT_AUTH_REQUIRED'; END IF;
        UPDATE execbound.account_factors SET recovery_hashes=p_data->'recovery'
            WHERE tenant_id=t AND principal_id=s.principal_id;
    ELSIF p_operation='policy' THEN
        IF s.kind<>'ADMIN' OR NOT fresh THEN RAISE EXCEPTION 'RECENT_AUTH_REQUIRED'; END IF;
        INSERT INTO execbound.account_security_policy(tenant_id,requirement,changed_at,changed_by)
            VALUES(t,p_data->>'requirement',p_now,s.principal_id)
            ON CONFLICT(tenant_id) DO UPDATE SET requirement=excluded.requirement,
                changed_at=excluded.changed_at,changed_by=excluded.changed_by;
    ELSE RAISE EXCEPTION 'INVALID_OPERATION'; END IF;
    IF p_operation IN ('enable','verify') THEN
        INSERT INTO execbound.session_assurance(tenant_id,session_id,version,verified_at,method)
        VALUES(t,p_session,f.version,p_now,coalesce(p_data->>'method','totp'))
        ON CONFLICT(tenant_id,session_id) DO UPDATE SET version=excluded.version,
            verified_at=excluded.verified_at,method=excluded.method;
    END IF;
END $$;
"""


def upgrade() -> None:
    op.execute("""
      CREATE TABLE execbound.account_factors(
        tenant_id uuid NOT NULL,principal_id uuid NOT NULL,
        sealed text,key_id text,enabled_at timestamptz,version integer NOT NULL DEFAULT 0,
        last_step bigint NOT NULL DEFAULT -1,recovery_hashes jsonb NOT NULL DEFAULT '[]',
        pending_sealed text,pending_key text,pending_session uuid,pending_expires timestamptz,
        failures integer NOT NULL DEFAULT 0 CHECK(failures BETWEEN 0 AND 5),locked_until
            timestamptz,
        PRIMARY KEY(tenant_id,principal_id),FOREIGN KEY(tenant_id,principal_id) REFERENCES
            execbound.principals,
        CHECK((sealed IS NULL)=(key_id IS NULL)),CHECK((sealed IS NULL)=(enabled_at IS NULL)),
        CHECK(jsonb_typeof(recovery_hashes)='array' AND jsonb_array_length(recovery_hashes)<=10),
        CHECK(sealed IS NULL OR length(sealed)<=1024),CHECK(pending_sealed IS NULL OR
            length(pending_sealed)<=1024)
      );
      CREATE TABLE execbound.session_assurance(
        tenant_id uuid NOT NULL,session_id uuid NOT NULL,version integer NOT NULL,
        verified_at timestamptz NOT NULL,method text NOT NULL CHECK(method IN ('totp',
            'recovery','passkey')),
        PRIMARY KEY(tenant_id,session_id),FOREIGN KEY(tenant_id,session_id) REFERENCES
            execbound.human_sessions
      );
      CREATE TABLE execbound.account_security_policy(
        tenant_id uuid PRIMARY KEY REFERENCES execbound.tenants,
        requirement text NOT NULL CHECK(requirement IN ('optional','admins','all')),
        changed_at timestamptz NOT NULL,changed_by uuid NOT NULL,
        FOREIGN KEY(tenant_id,changed_by) REFERENCES execbound.principals
      );
      CREATE INDEX account_security_policy_actor ON execbound.account_security_policy
        (tenant_id,changed_by);
    """)
    for table in ("account_factors", "session_assurance", "account_security_policy"):
        op.execute(f"ALTER TABLE execbound.{table} ENABLE ROW LEVEL SECURITY")
        op.execute(f"ALTER TABLE execbound.{table} FORCE ROW LEVEL SECURITY")
        op.execute(f"""CREATE POLICY tenant_isolation ON execbound.{table}
            USING(tenant_id=nullif((SELECT current_setting('execbound.tenant_id',true)),'')::uuid)
            WITH CHECK(tenant_id=nullif(
                (SELECT current_setting('execbound.tenant_id',true)),'')::uuid)""")
        op.execute(f"REVOKE ALL ON execbound.{table} FROM PUBLIC,execbound_app")
        op.execute(f"GRANT SELECT ON execbound.{table} TO execbound_app")
    op.execute(CHANGE)
    op.execute(
        "REVOKE ALL ON FUNCTION "
        "execbound.account_security_change(uuid,timestamptz,text,jsonb) FROM "
        "PUBLIC"
    )
    op.execute(
        "GRANT EXECUTE ON FUNCTION "
        "execbound.account_security_change(uuid,timestamptz,text,jsonb) TO "
        "execbound_app"
    )


def downgrade() -> None:
    op.execute("DROP FUNCTION execbound.account_security_change(uuid,timestamptz,text,jsonb)")
    for table in ("session_assurance", "account_factors", "account_security_policy"):
        op.execute(f"DROP TABLE execbound.{table}")
